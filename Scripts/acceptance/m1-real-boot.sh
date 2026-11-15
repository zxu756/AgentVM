#!/usr/bin/env bash
# AgentVM Milestone M1 Real-Boot Acceptance Script.
#
# Covers M1 acceptance table Rows 1-25 and Row 27 (Rows 26 and 28 are verified outside this script).
#
# Hard invariants:
#   * Without AGENTVM_REAL_VM=1, prints "没跑" and exits 2 immediately without creating anything.
#   * Never launches the desktop UI (.app, window, or bare executable without a CLI subcommand).
#   * Runs the product with an isolated HOME / CFFIXED_USER_HOME and workspaces inside mktemp -d.
#   * Never deletes or mutates existing files in the image cache; Row 4 mutates a `cp -c` clone in TMP_ROOT.
#   * Tracks baseline com.apple.Virtualization.VirtualMachine PIDs at startup; never signals foreign VMs.
#   * Every product command has a 300-second deadlock guard and no wall-clock pass/fail thresholds.
#   * Scrubs host home-directory paths from all output.
set -euo pipefail

if [[ "${AGENTVM_REAL_VM:-}" != "1" ]]; then
    echo "没跑：未设置 AGENTVM_REAL_VM=1（M1 真机启动验收未执行）"
    exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

REAL_HOME="${HOME:?}"
REAL_HOME="${REAL_HOME%/}"

SWIFT_JOBS_ARGS=()
if [[ -n "${AGENTVM_BUILD_JOBS:-}" ]]; then
    SWIFT_JOBS_ARGS=(-j "$AGENTVM_BUILD_JOBS")
fi

EXPECTED_DEBIAN_ID="debian-12-bookworm-arm64"
UNSUPPORTED_SAMPLE_ID="ubuntu-24.04-noble-arm64"
EXPECTED_DEBIAN_SIZE="3221225472"
EXPECTED_DEBIAN_SHA512="708a1a19d3aa4f5441c8160f6493aafccd3c36bfee3113869fa9248965223b8d263a3fbb86b7cf282723fb011180ade0c4a75d331b1addc8d4d1687c897de58b"
SIMULATED_UNAME_R="6.8.0-agentvm-arm64"
CMD_TIMEOUT_SEC=300

TMP_ROOT=""
IMAGE_CACHE_DIR=""
TEST_BIN=""
ISOLATED_HOME=""
WS=""
CLEANUP_DONE=0
OWN_AGENTVM_PIDS=()

# Literal substring replacement compatible with macOS /bin/bash 3.2.
replace_literal() {
    local text="$1"
    local needle="$2"
    local repl="$3"
    if [[ -z "$needle" ]]; then
        printf '%s' "$text"
        return 0
    fi
    local out=""
    while [[ "$text" == *"$needle"* ]]; do
        out="${out}${text%%"$needle"*}${repl}"
        text="${text#*"$needle"}"
    done
    printf '%s' "${out}${text}"
}

sanitize_text() {
    local msg="$1"
    msg="$(replace_literal "$msg" "$TMP_ROOT" '$TMP_ROOT')"
    msg="$(replace_literal "$msg" "$IMAGE_CACHE_DIR" '$AGENTVM_IMAGE_CACHE')"
    msg="$(replace_literal "$msg" "$ROOT_DIR" '.')"
    msg="$(replace_literal "$msg" "$REAL_HOME" '$HOME')"
    printf '%s' "$msg"
}

emit_out() {
    local msg
    msg="$(sanitize_text "$*")"
    printf '%s\n' "$msg"
}

emit_err() {
    local msg
    msg="$(sanitize_text "$*")"
    printf '%s\n' "$msg" >&2
}

now_sec() {
    /usr/bin/python3 -c 'import time; print("{:.3f}".format(time.time()))'
}

diff_sec() {
    /usr/bin/python3 -c 'import sys; print("{:.3f}".format(float(sys.argv[2]) - float(sys.argv[1])))' "$1" "$2"
}

SCRIPT_START_SEC="$(now_sec)"

# Compute shared image cache path BEFORE replacing HOME.
IMAGE_CACHE_DIR="$(
    /usr/bin/python3 - "$REAL_HOME" "${AGENTVM_IMAGE_CACHE:-}" <<'PY'
import os
import sys

real_home = sys.argv[1]
raw_override = sys.argv[2].strip()
if raw_override:
    if raw_override == "~":
        resolved = real_home
    elif raw_override.startswith("~/"):
        resolved = os.path.join(real_home, raw_override[2:])
    else:
        resolved = raw_override
else:
    resolved = os.path.join(real_home, "Library", "Caches", "AgentVM", "images")
print(os.path.abspath(resolved))
PY
)"

has_virtualization_entitlement() {
    local bin_path="$1"
    /usr/bin/python3 - "$bin_path" <<'PY'
import plistlib
import subprocess
import sys

path = sys.argv[1]
proc = subprocess.run(
    ["codesign", "-d", "--entitlements", ":-", path],
    capture_output=True,
)
if proc.returncode != 0 or not proc.stdout:
    sys.exit(1)
try:
    ent = plistlib.loads(proc.stdout)
except Exception:
    sys.exit(1)
if isinstance(ent, dict) and ent.get("com.apple.security.virtualization") is True:
    sys.exit(0)
sys.exit(1)
PY
}

# If AGENTVM_BIN is supplied externally, validate it with codesign BEFORE creating any temp directory.
USER_SUPPLIED_BIN=0
if [[ -n "${AGENTVM_BIN:-}" ]]; then
    USER_SUPPLIED_BIN=1
    RESOLVED_USER_BIN="$(
        /usr/bin/python3 - "${AGENTVM_BIN}" <<'PY'
import os, sys
print(os.path.abspath(sys.argv[1]))
PY
    )"
    if [[ ! -f "$RESOLVED_USER_BIN" || ! -x "$RESOLVED_USER_BIN" ]]; then
        emit_err "ERROR: AGENTVM_BIN does not exist or is not executable: \$AGENTVM_BIN"
        exit 1
    fi
    if ! has_virtualization_entitlement "$RESOLVED_USER_BIN"; then
        emit_err "REFUSED: AGENTVM_BIN lacks com.apple.security.virtualization entitlement (verified via codesign)."
        exit 1
    fi
    TEST_BIN="$RESOLVED_USER_BIN"
fi

# Snapshot pre-existing VirtualMachine PIDs so we never touch foreign VMs.
BASELINE_VZ_PIDS="$(pgrep -f 'com.apple.Virtualization.VirtualMachine' || true)"

is_baseline_vz_pid() {
    local candidate="$1"
    local p
    for p in $BASELINE_VZ_PIDS; do
        if [[ "$p" == "$candidate" ]]; then
            return 0
        fi
    done
    return 1
}

list_extra_vz_pids() {
    local current p
    current="$(pgrep -f 'com.apple.Virtualization.VirtualMachine' || true)"
    local extras=()
    for p in $current; do
        if ! is_baseline_vz_pid "$p"; then
            extras+=("$p")
        fi
    done
    if [[ ${#extras[@]} -gt 0 ]]; then
        printf '%s\n' "${extras[@]}"
    fi
}

wait_for_no_extra_vz_pids() {
    local max_wait_sec="${1:-30}"
    local max_ticks=$(( max_wait_sec * 20 ))
    local tick=0
    local rem=""
    while (( tick <= max_ticks )); do
        rem="$(list_extra_vz_pids || true)"
        if [[ -z "$rem" ]]; then
            return 0
        fi
        sleep 0.05
        tick=$((tick + 1))
    done
    return 1
}

snapshot_real_home_agentvm_entries() {
    /usr/bin/python3 - "$REAL_HOME" <<'PY'
import json
import os
import sys

real_home = sys.argv[1]
result = {"preferences": [], "app_support": []}

prefs_dir = os.path.join(real_home, "Library", "Preferences")
if os.path.isdir(prefs_dir):
    items = []
    for root, dirs, files in os.walk(prefs_dir):
        for name in dirs + files:
            if "agentvm" in name.lower():
                rel = os.path.relpath(os.path.join(root, name), prefs_dir)
                items.append(rel)
    result["preferences"] = sorted(set(items))

app_sup_dir = os.path.join(real_home, "Library", "Application Support")
if os.path.isdir(app_sup_dir):
    items = []
    for root, dirs, files in os.walk(app_sup_dir):
        for name in dirs + files:
            if "agentvm" in name.lower():
                rel = os.path.relpath(os.path.join(root, name), app_sup_dir)
                items.append(rel)
    result["app_support"] = sorted(set(items))

print(json.dumps(result, sort_keys=True))
PY
}

snapshot_cache_directory() {
    /usr/bin/python3 - "$IMAGE_CACHE_DIR" <<'PY'
import json
import os
import sys

cache_dir = sys.argv[1]
if not os.path.exists(cache_dir):
    print(json.dumps({"exists": False, "files": {}}, sort_keys=True))
    sys.exit(0)

files = {}
for root, dirs, filenames in os.walk(cache_dir):
    dirs.sort()
    for name in sorted(filenames):
        full = os.path.join(root, name)
        rel = os.path.relpath(full, cache_dir)
        st = os.lstat(full)
        files[rel] = [int(st.st_ino), int(st.st_size), int(st.st_mtime_ns), int(st.st_mode)]

print(json.dumps({"exists": True, "files": files}, sort_keys=True))
PY
}

HOME_ENTRIES_BEFORE="$(snapshot_real_home_agentvm_entries)"
CACHE_SNAPSHOT_BEFORE="$(snapshot_cache_directory)"

confirm_pid_is_test_bin() {
    local target_pid="$1"
    if [[ -z "$TEST_BIN" || -z "$target_pid" ]]; then
        return 1
    fi
    local expected_base
    expected_base="$(basename "$TEST_BIN")"
    local attempt=0
    local comm_out=""
    while (( attempt < 40 )); do
        if ! kill -0 "$target_pid" 2>/dev/null; then
            return 1
        fi
        comm_out="$(ps -p "$target_pid" -o comm= 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' || true)"
        if [[ "$comm_out" == "$TEST_BIN" || "$comm_out" == *"/${expected_base}" || "$comm_out" == "$expected_base" ]]; then
            return 0
        fi
        sleep 0.05
        attempt=$((attempt + 1))
    done
    return 1
}

is_pid_currently_test_bin() {
    local target_pid="$1"
    if [[ -z "$TEST_BIN" || -z "$target_pid" ]]; then
        return 1
    fi
    if ! kill -0 "$target_pid" 2>/dev/null; then
        return 1
    fi
    local expected_base comm_out
    expected_base="$(basename "$TEST_BIN")"
    comm_out="$(ps -p "$target_pid" -o comm= 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' || true)"
    [[ "$comm_out" == "$TEST_BIN" || "$comm_out" == *"/${expected_base}" || "$comm_out" == "$expected_base" ]]
}

terminate_own_agentvm_processes() {
    local pid
    for pid in "${OWN_AGENTVM_PIDS[@]+"${OWN_AGENTVM_PIDS[@]}"}"; do
        if is_pid_currently_test_bin "$pid"; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done

    local wait_tick=0
    while (( wait_tick < 150 )); do
        local any_alive=0
        for pid in "${OWN_AGENTVM_PIDS[@]+"${OWN_AGENTVM_PIDS[@]}"}"; do
            if is_pid_currently_test_bin "$pid"; then
                any_alive=1
                break
            fi
        done
        if [[ $any_alive -eq 0 ]]; then
            break
        fi
        sleep 0.1
        wait_tick=$((wait_tick + 1))
    done

    for pid in "${OWN_AGENTVM_PIDS[@]+"${OWN_AGENTVM_PIDS[@]}"}"; do
        if is_pid_currently_test_bin "$pid"; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
    done

    wait_for_no_extra_vz_pids 15 || true
}

cleanup() {
    if [[ $CLEANUP_DONE -eq 1 ]]; then
        return 0
    fi
    CLEANUP_DONE=1
    terminate_own_agentvm_processes
    if [[ -n "$TMP_ROOT" && -d "$TMP_ROOT" ]]; then
        rm -rf "$TMP_ROOT"
    fi
}

on_sigint() {
    cleanup
    exit 130
}

on_sigterm() {
    cleanup
    exit 143
}

trap cleanup EXIT
trap on_sigint INT
trap on_sigterm TERM

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/agentvm-m1-real-boot.XXXXXX")"
ISOLATED_HOME="$TMP_ROOT/home"
WS="$TMP_ROOT/ws.agentvm"
mkdir -p "$ISOLATED_HOME"

emit_out "=================================================================="
emit_out " AgentVM Milestone M1 Real-Boot Acceptance Suite (Rows 1-25, 27)"
emit_out "=================================================================="
if [[ -n "$BASELINE_VZ_PIDS" ]]; then
    emit_out "Baseline VirtualMachine PIDs preserved (untouched): [${BASELINE_VZ_PIDS//$'\n'/ }]"
else
    emit_out "Baseline VirtualMachine PIDs: none"
fi

BUILD_ARTIFACT_SHA_BEFORE=""
if [[ $USER_SUPPLIED_BIN -eq 0 ]]; then
    emit_out "Building debug AgentVM binary and ad-hoc signing an isolated copy..."
    BUILD_LOG="$TMP_ROOT/swift-build.log"
    if ! swift build "${SWIFT_JOBS_ARGS[@]+"${SWIFT_JOBS_ARGS[@]}"}" --product AgentVM >"$BUILD_LOG" 2>&1; then
        emit_err "ERROR: swift build --product AgentVM failed:"
        while IFS= read -r line; do
            emit_err "  $line"
        done < <(tail -n 40 "$BUILD_LOG")
        exit 1
    fi
    BUILT_DEBUG_BIN="$ROOT_DIR/.build/debug/AgentVM"
    BUILD_ARTIFACT_SHA_BEFORE="$(/usr/bin/shasum -a 256 "$BUILT_DEBUG_BIN" | awk '{print $1}')"
    mkdir -p "$TMP_ROOT/bin"
    TEST_BIN="$TMP_ROOT/bin/AgentVM"
    cp "$BUILT_DEBUG_BIN" "$TEST_BIN"
    chmod 0755 "$TEST_BIN"
    if ! codesign --force --sign - --entitlements "$ROOT_DIR/Scripts/entitlements.plist" "$TEST_BIN" >"$TMP_ROOT/codesign.log" 2>&1; then
        emit_err "ERROR: codesign with Scripts/entitlements.plist failed"
        exit 1
    fi
    if ! has_virtualization_entitlement "$TEST_BIN"; then
        emit_err "ERROR: temporary signed binary still lacks com.apple.security.virtualization"
        exit 1
    fi
else
    emit_out "Using caller-supplied entitled AGENTVM_BIN."
fi

PASSED_ROWS=0
FAILED_ROWS=0
UNRUN_ROWS=0

pass_row() {
    local row="$1"
    shift
    PASSED_ROWS=$((PASSED_ROWS + 1))
    emit_out "PASS [Row $row]: $*"
}

fail_row() {
    local row="$1"
    shift
    FAILED_ROWS=$((FAILED_ROWS + 1))
    emit_out "FAIL [Row $row]: $*"
}

unrun_row() {
    local row="$1"
    shift
    UNRUN_ROWS=$((UNRUN_ROWS + 1))
    emit_out "没跑 [Row $row]: $*"
}

ensure_cli_subcommand() {
    local has_subcommand=0
    local token
    for token in "$@"; do
        [[ "$token" == "--" ]] && break
        case "$token" in
            doctor|init|ps|list|image|create|run|up|boot|start|pause|resume|halt|stop|branch|fork|snapshot|restore|exec|pcap|policy|plugin|export-hcl|export-html|help|version|mcp)
                has_subcommand=1
                break
                ;;
        esac
    done
    if [[ $has_subcommand -ne 1 ]]; then
        emit_err "REFUSED: invocation has no CLI subcommand and would launch the desktop UI."
        exit 97
    fi
}

SPAWNED_PID=""
# Spawns AgentVM directly via subshell `exec` + perl signal reset so `$!` is AgentVM itself
# and SIGINT/SIGTERM start with DEFAULT disposition even in a non-interactive background job.
_spawn_agentvm_process() {
    local cache_dir="$1"
    local out_file="$2"
    local err_file="$3"
    shift 3
    ensure_cli_subcommand "$@"
    : >"$out_file"
    : >"$err_file"

    (
        exec /usr/bin/env -u AGENTVM_WORKSPACE -u AGENTVM_REAL_VM -u AGENTVM_LANG \
            HOME="$ISOLATED_HOME" \
            CFFIXED_USER_HOME="$ISOLATED_HOME" \
            AGENTVM_IMAGE_CACHE="$cache_dir" \
            /usr/bin/perl -e '$SIG{INT}="DEFAULT"; $SIG{TERM}="DEFAULT"; exec @ARGV or die "exec failed: $!\n";' \
            "$TEST_BIN" "$@"
    ) </dev/null >"$out_file" 2>"$err_file" &
    SPAWNED_PID=$!
    OWN_AGENTVM_PIDS+=("$SPAWNED_PID")
}

WATCHDOG_PID=""
_start_watchdog() {
    local target_pid="$1"
    local timeout_sec="$2"
    local flag_file="$3"
    local expected_base
    expected_base="$(basename "$TEST_BIN")"
    rm -f "$flag_file"
    /usr/bin/perl -e '
        my ($sec, $pid, $flag, $full, $base) = @ARGV;
        $SIG{TERM} = sub { exit 0 };
        $SIG{INT}  = sub { exit 0 };
        sleep($sec);
        if (kill(0, $pid)) {
            my $comm = qx(ps -p $pid -o comm= 2>/dev/null);
            chomp($comm);
            $comm =~ s/^\s+|\s+$//g;
            if ($comm eq $full || $comm eq $base || $comm =~ m{/\Q$base\E$}) {
                if (open(my $fh, ">", $flag)) { print $fh "timeout\n"; close($fh); }
                kill("TERM", $pid);
                for (1..50) {
                    last unless kill(0, $pid);
                    select(undef, undef, undef, 0.1);
                }
                kill("KILL", $pid) if kill(0, $pid);
            }
        }
    ' "$timeout_sec" "$target_pid" "$flag_file" "$TEST_BIN" "$expected_base" </dev/null >/dev/null 2>&1 &
    WATCHDOG_PID=$!
}

_stop_watchdog() {
    local wd_pid="$1"
    if [[ -n "$wd_pid" ]]; then
        kill -TERM "$wd_pid" 2>/dev/null || true
        { wait "$wd_pid"; } 2>/dev/null || true
    fi
}

CMD_SEQ=0
LAST_RC=0
LAST_OUT=""
LAST_ERR=""
LAST_ELAPSED="0.000"
LAST_TIMED_OUT=0

invoke_agentvm() {
    local cache_dir="$1"
    shift
    CMD_SEQ=$((CMD_SEQ + 1))
    LAST_OUT="$TMP_ROOT/cmd-${CMD_SEQ}.out"
    LAST_ERR="$TMP_ROOT/cmd-${CMD_SEQ}.err"
    local flag_file="$TMP_ROOT/cmd-${CMD_SEQ}.timeout"
    LAST_TIMED_OUT=0

    local t0 t1 pid wd_pid rc
    t0="$(now_sec)"
    _spawn_agentvm_process "$cache_dir" "$LAST_OUT" "$LAST_ERR" "$@"
    pid="$SPAWNED_PID"
    _start_watchdog "$pid" "$CMD_TIMEOUT_SEC" "$flag_file"
    wd_pid="$WATCHDOG_PID"

    set +e
    { wait "$pid"; } 2>/dev/null
    rc=$?
    set -e

    _stop_watchdog "$wd_pid"
    t1="$(now_sec)"
    LAST_ELAPSED="$(diff_sec "$t0" "$t1")"
    if [[ -f "$flag_file" ]]; then
        LAST_TIMED_OUT=1
        LAST_RC=124
    else
        LAST_RC=$rc
    fi
    return 0
}

wait_for_started_line() {
    local out_file="$1"
    local bg_pid="$2"
    local max_wait_sec="${3:-300}"
    local max_ticks=$(( max_wait_sec * 20 ))
    local tick=0
    while (( tick <= max_ticks )); do
        if LC_ALL=C grep -q '^started$' "$out_file" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$bg_pid" 2>/dev/null; then
            if LC_ALL=C grep -q '^started$' "$out_file" 2>/dev/null; then
                return 0
            fi
            return 1
        fi
        sleep 0.05
        tick=$((tick + 1))
    done
    return 1
}

is_vm_lock_free() {
    local workspace_dir="$1"
    local vm_id="$2"
    local lock_file="$workspace_dir/locks/${vm_id}.lock"
    /usr/bin/python3 - "$lock_file" <<'PY'
import fcntl
import os
import sys

path = sys.argv[1]
if not os.path.exists(path):
    sys.exit(0)
fd = os.open(path, os.O_RDWR)
try:
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.exit(1)
    fcntl.flock(fd, fcntl.LOCK_UN)
finally:
    os.close(fd)
sys.exit(0)
PY
}

# Row 23 accumulator: checked after EVERY `run` invocation in this script.
POST_RUN_CHECKS_TOTAL=0
POST_RUN_CHECKS_FAILED=0
POST_RUN_FAILURE_NOTES=""

record_post_run_hygiene() {
    local label="$1"
    local vm_id="$2"
    POST_RUN_CHECKS_TOTAL=$((POST_RUN_CHECKS_TOTAL + 1))

    if ! wait_for_no_extra_vz_pids 30; then
        local lingering
        lingering="$(list_extra_vz_pids || true)"
        POST_RUN_CHECKS_FAILED=$((POST_RUN_CHECKS_FAILED + 1))
        POST_RUN_FAILURE_NOTES="${POST_RUN_FAILURE_NOTES}[$label: lingering VirtualMachine PIDs ${lingering//$'\n'/,}] "
        return 1
    fi

    if [[ -n "$vm_id" ]] && ! is_vm_lock_free "$WS" "$vm_id"; then
        POST_RUN_CHECKS_FAILED=$((POST_RUN_CHECKS_FAILED + 1))
        POST_RUN_FAILURE_NOTES="${POST_RUN_FAILURE_NOTES}[$label: lock for $vm_id still held] "
        return 1
    fi
    return 0
}

vm_json_field() {
    local vm_name="$1"
    local field_expr="$2"
    invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" ps --json
    if [[ $LAST_RC -ne 0 ]]; then
        return 1
    fi
    /usr/bin/python3 - "$LAST_OUT" "$vm_name" "$field_expr" <<'PY'
import json
import sys

arr = json.load(open(sys.argv[1], encoding="utf-8"))
target = sys.argv[2]
expr = sys.argv[3]
for item in arr:
    if item["spec"]["name"] == target:
        if expr == "id":
            print(item["spec"]["id"])
        elif expr == "state":
            print(item["telemetry"]["state"])
        elif expr == "mac":
            print(item["spec"]["networkInterfaces"][0]["macAddress"].lower())
        elif expr == "disk_path":
            print(item["spec"]["blockDevices"][0]["imagePath"])
        sys.exit(0)
sys.exit(1)
PY
}

# Initialize isolated workspace.
invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" init
if [[ $LAST_RC -ne 0 ]]; then
    emit_err "ERROR: failed to initialize temporary workspace (exit $LAST_RC): $(cat "$LAST_ERR")"
    exit 1
fi

# ------------------------------------------------------------------
# Row 1: `image list`; `image pull` on an unsupported entry
# ------------------------------------------------------------------
invoke_agentvm "$IMAGE_CACHE_DIR" --lang zh --workspace "$WS" image list
r1_zh_rc=$LAST_RC
r1_zh_out="$LAST_OUT"

invoke_agentvm "$IMAGE_CACHE_DIR" --lang en --workspace "$WS" image list
r1_en_rc=$LAST_RC
r1_en_out="$LAST_OUT"

invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" image list --json
r1_json_rc=$LAST_RC
r1_json_out="$LAST_OUT"

invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" image pull "$UNSUPPORTED_SAMPLE_ID"
r1_pull_rc=$LAST_RC
r1_pull_err="$(cat "$LAST_ERR")"

if [[ $r1_zh_rc -eq 0 && $r1_en_rc -eq 0 && $r1_json_rc -eq 0 && $r1_pull_rc -ne 0 ]] \
    && [[ "$r1_pull_err" == *"ERR_IMAGE_UNSUPPORTED"* ]] \
    && /usr/bin/python3 - "$r1_zh_out" "$r1_en_out" "$r1_json_out" "$EXPECTED_DEBIAN_ID" <<'PY'
import json
import sys

zh_lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
en_lines = open(sys.argv[2], encoding="utf-8").read().splitlines()
items = json.load(open(sys.argv[3], encoding="utf-8"))
deb_id = sys.argv[4]

deb_items = [x for x in items if x["id"] == deb_id]
other_items = [x for x in items if x["id"] != deb_id]
assert len(deb_items) == 1 and deb_items[0]["supported"] is True
assert len(other_items) >= 1 and all(x["supported"] is False for x in other_items)

for x in items:
    zh_match = [ln for ln in zh_lines if x["id"] in ln]
    en_match = [ln for ln in en_lines if x["id"] in ln]
    assert len(zh_match) == 1 and len(en_match) == 1
    if x["id"] == deb_id:
        assert "可用" in zh_match[0] and "暂不支持" not in zh_match[0]
        assert "SUPPORTED" in en_match[0] and "UNSUPPORTED" not in en_match[0]
    else:
        assert "暂不支持" in zh_match[0] and "可用" not in zh_match[0]
        assert "UNSUPPORTED" in en_match[0]
PY
then
    pass_row 1 "'image list' marks $EXPECTED_DEBIAN_ID supported and all other entries unsupported; 'image pull $UNSUPPORTED_SAMPLE_ID' exited $r1_pull_rc."
else
    fail_row 1 "image list / unsupported pull check failed (zh_rc=$r1_zh_rc, en_rc=$r1_en_rc, json_rc=$r1_json_rc, pull_rc=$r1_pull_rc)"
fi

# ------------------------------------------------------------------
# Row 2: `image pull debian-12-bookworm-arm64` -> exit 0, 3221225472 bytes, shasum -a 512 matches spec
# ------------------------------------------------------------------
DEBIAN_RAW_FILE="$IMAGE_CACHE_DIR/${EXPECTED_DEBIAN_ID}.raw"
invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" image pull "$EXPECTED_DEBIAN_ID"
r2_rc=$LAST_RC
if [[ $r2_rc -eq 0 && -f "$DEBIAN_RAW_FILE" ]]; then
    r2_size="$(/usr/bin/python3 -c 'import os,sys; print(os.stat(sys.argv[1]).st_size)' "$DEBIAN_RAW_FILE")"
    r2_sha512="$(/usr/bin/shasum -a 512 "$DEBIAN_RAW_FILE" | awk '{print tolower($1)}')"
    if [[ "$r2_size" == "$EXPECTED_DEBIAN_SIZE" && "$r2_sha512" == "$EXPECTED_DEBIAN_SHA512" ]]; then
        pass_row 2 "'image pull $EXPECTED_DEBIAN_ID' exited 0; size=$r2_size bytes and independent 'shasum -a 512' matched documented SHA-512."
    else
        fail_row 2 "cached image mismatch (size=$r2_size expected=$EXPECTED_DEBIAN_SIZE, sha512=$r2_sha512)"
    fi
else
    fail_row 2 "'image pull $EXPECTED_DEBIAN_ID' failed (exit $r2_rc): $(cat "$LAST_ERR")"
fi

# ------------------------------------------------------------------
# Row 3: `image pull` again -> exit 0, inode and mtime unchanged
# ------------------------------------------------------------------
if [[ -f "$DEBIAN_RAW_FILE" ]]; then
    r3_stat_before="$(/usr/bin/python3 -c 'import os,sys; st=os.stat(sys.argv[1]); print(f"{st.st_ino}:{st.st_mtime_ns}")' "$DEBIAN_RAW_FILE")"
    invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" image pull "$EXPECTED_DEBIAN_ID"
    r3_rc=$LAST_RC
    r3_stat_after="$(/usr/bin/python3 -c 'import os,sys; st=os.stat(sys.argv[1]); print(f"{st.st_ino}:{st.st_mtime_ns}")' "$DEBIAN_RAW_FILE")"
    if [[ $r3_rc -eq 0 && "$r3_stat_before" == "$r3_stat_after" ]]; then
        pass_row 3 "second 'image pull $EXPECTED_DEBIAN_ID' exited 0 with identical inode and mtime_ns ($r3_stat_after)."
    else
        fail_row 3 "second 'image pull' exited $r3_rc or altered stat (before=$r3_stat_before, after=$r3_stat_after)"
    fi
else
    unrun_row 3 "skipped because cached image file from Row 2 is absent"
fi

# ------------------------------------------------------------------
# Row 4: `cp -c` clone to temp dir, flip 1 byte in clone, `image verify` clone (non-zero checksum mismatch) and original (0)
# ------------------------------------------------------------------
if [[ -f "$DEBIAN_RAW_FILE" ]]; then
    TAMPER_CACHE="$TMP_ROOT/tampered-cache"
    mkdir -p "$TAMPER_CACHE"
    if [[ -f "$IMAGE_CACHE_DIR/catalog-index.json" ]]; then
        cp -c "$IMAGE_CACHE_DIR/catalog-index.json" "$TAMPER_CACHE/catalog-index.json"
    fi
    if cp -c "$DEBIAN_RAW_FILE" "$TAMPER_CACHE/${EXPECTED_DEBIAN_ID}.raw"; then
        orig_ino="$(/usr/bin/python3 -c 'import os,sys; print(os.stat(sys.argv[1]).st_ino)' "$DEBIAN_RAW_FILE")"
        clone_ino="$(/usr/bin/python3 -c 'import os,sys; print(os.stat(sys.argv[1]).st_ino)' "$TAMPER_CACHE/${EXPECTED_DEBIAN_ID}.raw")"
        if [[ "$orig_ino" == "$clone_ino" ]]; then
            rm -rf "$TAMPER_CACHE"
            fail_row 4 "cp -c produced identical inode; refused to mutate"
        else
            chmod u+w "$TAMPER_CACHE/${EXPECTED_DEBIAN_ID}.raw"
            /usr/bin/python3 - "$TAMPER_CACHE/${EXPECTED_DEBIAN_ID}.raw" <<'PY'
import os
import sys

p = sys.argv[1]
with open(p, "r+b") as fh:
    fh.seek(4096)
    b = fh.read(1)
    fh.seek(4096)
    fh.write(bytes([b[0] ^ 0xFF]))
    fh.flush()
    os.fsync(fh.fileno())
PY
            chmod 0444 "$TAMPER_CACHE/${EXPECTED_DEBIAN_ID}.raw"
            invoke_agentvm "$TAMPER_CACHE" --workspace "$WS" image verify "$EXPECTED_DEBIAN_ID"
            r4_bad_rc=$LAST_RC
            r4_bad_msg="$(cat "$LAST_OUT" "$LAST_ERR")"
            rm -rf "$TAMPER_CACHE"

            invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" image verify "$EXPECTED_DEBIAN_ID"
            r4_orig_rc=$LAST_RC

            if [[ $r4_bad_rc -ne 0 && $r4_orig_rc -eq 0 ]] \
                && [[ "$r4_bad_msg" == *"ERR_IMAGE_CHECKSUM_MISMATCH"* ]] \
                && [[ "$r4_bad_msg" == *"校验和不符"* || "$r4_bad_msg" == *"checksum mismatch"* ]]; then
                pass_row 4 "1-byte tampered 'cp -c' clone failed 'image verify' (exit $r4_bad_rc, ERR_IMAGE_CHECKSUM_MISMATCH); original cache verified (exit 0)."
            else
                fail_row 4 "verify results unexpected (clone_rc=$r4_bad_rc, orig_rc=$r4_orig_rc, clone_msg=$r4_bad_msg)"
            fi
        fi
    else
        rm -rf "$TAMPER_CACHE"
        fail_row 4 "cp -c failed when cloning cached image into temporary directory"
    fi
else
    unrun_row 4 "skipped because cached image file from Row 2 is absent"
fi

# ------------------------------------------------------------------
# Row 5: Empty AGENTVM_IMAGE_CACHE -> `create x --image debian-12-bookworm-arm64` fails without downloading
# ------------------------------------------------------------------
EMPTY_CACHE="$TMP_ROOT/empty-cache"
mkdir -p "$EMPTY_CACHE"
invoke_agentvm "$EMPTY_CACHE" --workspace "$WS" create x --image "$EXPECTED_DEBIAN_ID"
r5_rc=$LAST_RC
r5_err="$(cat "$LAST_ERR")"
r5_cache_entries="$(ls -1A "$EMPTY_CACHE" | wc -l | tr -d ' ')"
if [[ $r5_rc -ne 0 && "$r5_cache_entries" == "0" ]] \
    && [[ "$r5_err" == *"ERR_IMAGE_NOT_CACHED"* && "$r5_err" == *"image pull"* ]]; then
    pass_row 5 "with empty AGENTVM_IMAGE_CACHE, 'create x --image $EXPECTED_DEBIAN_ID' exited $r5_rc, hinted 'image pull', and created 0 files in cache."
else
    fail_row 5 "empty-cache create behaved unexpectedly (rc=$r5_rc, cache_entries=$r5_cache_entries, err=$r5_err)"
fi

# ------------------------------------------------------------------
# Row 6: `create t1 --image debian-12-bookworm-arm64` -> exit 0, root disk logical size >= 3221225472
# ------------------------------------------------------------------
T1_READY=0
T1_ID=""
T1_MAC=""
invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" create t1 --image "$EXPECTED_DEBIAN_ID"
r6_rc=$LAST_RC
if [[ $r6_rc -eq 0 ]]; then
    T1_ID="$(vm_json_field "t1" "id" || true)"
    T1_MAC="$(vm_json_field "t1" "mac" || true)"
    t1_disk="$(vm_json_field "t1" "disk_path" || true)"
    if [[ -n "$T1_ID" && -n "$t1_disk" && -f "$t1_disk" ]]; then
        t1_disk_bytes="$(/usr/bin/python3 -c 'import os,sys; print(os.stat(sys.argv[1]).st_size)' "$t1_disk")"
        if /usr/bin/python3 -c 'import sys; sys.exit(0 if int(sys.argv[1]) >= int(sys.argv[2]) else 1)' "$t1_disk_bytes" "$EXPECTED_DEBIAN_SIZE"; then
            T1_READY=1
            pass_row 6 "'create t1 --image $EXPECTED_DEBIAN_ID' exited 0; root disk logical size is $t1_disk_bytes bytes (>= $EXPECTED_DEBIAN_SIZE)."
        else
            fail_row 6 "t1 root disk logical size $t1_disk_bytes < $EXPECTED_DEBIAN_SIZE"
        fi
    else
        fail_row 6 "could not locate t1 metadata or root disk after create"
    fi
else
    fail_row 6 "'create t1' failed (exit $r6_rc): $(cat "$LAST_ERR")"
fi

# ------------------------------------------------------------------
# Row 7: `run t1 -- uname -r` -> 1 stdout line matching ^6\.1\.\d+-\d+-(cloud-)?arm64$, != simulated string, empty stderr
# ------------------------------------------------------------------
FIRST_BOOT_SEC=""
if [[ $T1_READY -eq 1 ]]; then
    invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" run t1 -- uname -r
    r7_rc=$LAST_RC
    FIRST_BOOT_SEC="$LAST_ELAPSED"
    r7_out="$LAST_OUT"
    r7_err="$LAST_ERR"
    record_post_run_hygiene "row7-uname" "$T1_ID" || true

    if [[ $r7_rc -eq 0 ]] && /usr/bin/python3 - "$r7_out" "$r7_err" "$SIMULATED_UNAME_R" <<'PY'
import re
import sys

raw_out = open(sys.argv[1], "rb").read()
raw_err = open(sys.argv[2], "rb").read()
sim_str = sys.argv[3]

if len(raw_err) != 0:
    sys.exit(1)
if not raw_out.endswith(b"\n") or raw_out.count(b"\n") != 1:
    sys.exit(1)
line = raw_out[:-1].decode("utf-8", errors="strict")
if line == sim_str:
    sys.exit(1)
if not re.fullmatch(r"^6\.1\.\d+-\d+-(cloud-)?arm64$", line):
    sys.exit(1)
sys.exit(0)
PY
    then
        r7_kernel="$(tr -d '\r\n' < "$r7_out")"
        pass_row 7 "'run t1 -- uname -r' exited 0 with single line '$r7_kernel' (empty stderr, first boot ${FIRST_BOOT_SEC}s)."
    else
        fail_row 7 "'run t1 -- uname -r' failed check (rc=$r7_rc, stdout=$(cat "$r7_out"), stderr=$(cat "$r7_err"))"
    fi
else
    unrun_row 7 "skipped because t1 was not created in Row 6"
fi

# ------------------------------------------------------------------
# Row 8: `run t1 -- cat /etc/os-release` -> contains `Debian GNU/Linux 12`
# ------------------------------------------------------------------
if [[ $T1_READY -eq 1 ]]; then
    invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" run t1 -- cat /etc/os-release
    r8_rc=$LAST_RC
    r8_out_str="$(cat "$LAST_OUT")"
    r8_err_len="$(wc -c < "$LAST_ERR" | tr -d ' ')"
    record_post_run_hygiene "row8-os-release" "$T1_ID" || true
    if [[ $r8_rc -eq 0 && "$r8_err_len" == "0" && "$r8_out_str" == *"Debian GNU/Linux 12"* ]]; then
        pass_row 8 "'run t1 -- cat /etc/os-release' exited 0 and contains 'Debian GNU/Linux 12'."
    else
        fail_row 8 "os-release check failed (rc=$r8_rc, stderr_bytes=$r8_err_len)"
    fi
else
    unrun_row 8 "skipped because t1 was not created in Row 6"
fi

# ------------------------------------------------------------------
# Row 9: `run t1 -- sh -c 'exit 7'` -> 7; `run t1 -- sh -c 'kill -9 $$'` -> 137
# ------------------------------------------------------------------
if [[ $T1_READY -eq 1 ]]; then
    invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" run t1 -- sh -c 'exit 7'
    r9_rc1=$LAST_RC
    record_post_run_hygiene "row9-exit7" "$T1_ID" || true

    invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" run t1 -- sh -c 'kill -9 $$'
    r9_rc2=$LAST_RC
    record_post_run_hygiene "row9-kill9" "$T1_ID" || true

    if [[ $r9_rc1 -eq 7 && $r9_rc2 -eq 137 ]]; then
        pass_row 9 "guest exit codes preserved verbatim: 'exit 7' -> $r9_rc1, 'kill -9 \$\$' -> $r9_rc2."
    else
        fail_row 9 "expected exit codes 7 and 137, got $r9_rc1 and $r9_rc2"
    fi
else
    unrun_row 9 "skipped because t1 was not created in Row 6"
fi

# ------------------------------------------------------------------
# Row 10: `run t1 -- sh -c 'echo out; echo err >&2'` -> stdout is `out\n`, stderr is `err\n`
# ------------------------------------------------------------------
if [[ $T1_READY -eq 1 ]]; then
    invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" run t1 -- sh -c 'echo out; echo err >&2'
    r10_rc=$LAST_RC
    r10_out="$LAST_OUT"
    r10_err="$LAST_ERR"
    record_post_run_hygiene "row10-streams" "$T1_ID" || true

    if [[ $r10_rc -eq 0 ]] && /usr/bin/python3 - "$r10_out" "$r10_err" <<'PY'
import sys
assert open(sys.argv[1], "rb").read() == b"out\n"
assert open(sys.argv[2], "rb").read() == b"err\n"
PY
    then
        pass_row 10 "stdout is exactly 'out' (1 line) and stderr is exactly 'err' (1 line)."
    else
        fail_row 10 "stream separation mismatch (rc=$r10_rc)"
    fi
else
    unrun_row 10 "skipped because t1 was not created in Row 6"
fi

# ------------------------------------------------------------------
# Row 11: 1 MiB random binary stdout + guest SHA-256 == host SHA-256
# ------------------------------------------------------------------
if [[ $T1_READY -eq 1 ]]; then
    invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" run t1 -- sh -c \
        'dd if=/dev/urandom bs=1048576 count=1 of=/tmp/m1-1m.bin status=none && sha256sum /tmp/m1-1m.bin >&2 && cat /tmp/m1-1m.bin && rm -f /tmp/m1-1m.bin'
    r11_rc=$LAST_RC
    r11_out="$LAST_OUT"
    r11_err="$LAST_ERR"
    record_post_run_hygiene "row11-1mib" "$T1_ID" || true

    r11_bytes="$(/usr/bin/python3 -c 'import os,sys; print(os.stat(sys.argv[1]).st_size)' "$r11_out")"
    r11_guest_sha="$(awk 'NR==1 {print tolower($1)}' "$r11_err")"
    r11_host_sha="$(/usr/bin/shasum -a 256 "$r11_out" | awk '{print tolower($1)}')"
    if [[ $r11_rc -eq 0 && "$r11_bytes" == "1048576" && ${#r11_guest_sha} -eq 64 && "$r11_guest_sha" == "$r11_host_sha" ]]; then
        pass_row 11 "received exactly 1048576 random bytes on stdout; SHA-256 matched guest ($r11_host_sha)."
    else
        fail_row 11 "1 MiB binary transfer mismatch (rc=$r11_rc, bytes=$r11_bytes, guest_sha=$r11_guest_sha, host_sha=$r11_host_sha)"
    fi
else
    unrun_row 11 "skipped because t1 was not created in Row 6"
fi

# ------------------------------------------------------------------
# Row 12: Write random token to /var/tmp/m1 in one `run`, read back in next `run`
# ------------------------------------------------------------------
if [[ $T1_READY -eq 1 ]]; then
    R12_TOKEN="m1-$(uuidgen | tr 'A-Z' 'a-z')"
    invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" run t1 -- sh -c "printf '%s\n' '$R12_TOKEN' > /var/tmp/m1 && sync"
    r12_w_rc=$LAST_RC
    record_post_run_hygiene "row12-write" "$T1_ID" || true

    invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" run t1 -- cat /var/tmp/m1
    r12_r_rc=$LAST_RC
    r12_r_out="$LAST_OUT"
    r12_r_err="$LAST_ERR"
    record_post_run_hygiene "row12-read" "$T1_ID" || true

    if [[ $r12_w_rc -eq 0 && $r12_r_rc -eq 0 ]] && /usr/bin/python3 - "$r12_r_out" "$r12_r_err" "$R12_TOKEN" <<'PY'
import sys
assert open(sys.argv[1], "rb").read() == (sys.argv[3] + "\n").encode("utf-8")
assert len(open(sys.argv[2], "rb").read()) == 0
PY
    then
        pass_row 12 "persisted random token '$R12_TOKEN' across two separate 'run t1' boots."
    else
        fail_row 12 "disk persistence check failed (w_rc=$r12_w_rc, r_rc=$r12_r_rc)"
    fi
else
    unrun_row 12 "skipped because t1 was not created in Row 6"
fi

# ------------------------------------------------------------------
# Row 13: `run t1 -- curl -sI https://deb.debian.org` -> first line is HTTP status line
# ------------------------------------------------------------------
if [[ $T1_READY -eq 1 ]]; then
    invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" run t1 -- curl -sI https://deb.debian.org
    r13_rc=$LAST_RC
    r13_out="$LAST_OUT"
    record_post_run_hygiene "row13-curl" "$T1_ID" || true

    r13_first_line="$(head -n 1 "$r13_out" | tr -d '\r\n')"
    if [[ $r13_rc -eq 0 ]] && /usr/bin/python3 - "$r13_first_line" <<'PY'
import re
import sys
sys.exit(0 if re.match(r"^HTTP/\d+(?:\.\d+)?\s+[1-5]\d\d(?:\s+.*)?$", sys.argv[1]) else 1)
PY
    then
        pass_row 13 "'run t1 -- curl -sI https://deb.debian.org' exited 0; first line: '$r13_first_line'."
    else
        fail_row 13 "guest curl check failed (rc=$r13_rc, first_line='$r13_first_line')"
    fi
else
    unrun_row 13 "skipped because t1 was not created in Row 6"
fi

# ------------------------------------------------------------------
# Row 14: `run t1 -- ip -o link` -> contains configured MAC of t1
# ------------------------------------------------------------------
if [[ $T1_READY -eq 1 ]]; then
    invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" run t1 -- ip -o link
    r14_rc=$LAST_RC
    r14_out_lower="$(tr 'A-Z' 'a-z' < "$LAST_OUT")"
    record_post_run_hygiene "row14-mac" "$T1_ID" || true

    if [[ $r14_rc -eq 0 && -n "$T1_MAC" && "$r14_out_lower" == *"$T1_MAC"* ]]; then
        pass_row 14 "'run t1 -- ip -o link' contains configured MAC $T1_MAC."
    else
        fail_row 14 "guest NIC MAC mismatch (rc=$r14_rc, expected_mac=$T1_MAC)"
    fi
else
    unrun_row 14 "skipped because t1 was not created in Row 6"
fi

# ------------------------------------------------------------------
# Row 15: `create t2 --image debian-12-bookworm-arm64 --disk-size 8G` && `run t2 -- df -B1 --output=size /` > 7000000000
# ------------------------------------------------------------------
invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" create t2 --image "$EXPECTED_DEBIAN_ID" --disk-size 8G
r15_c_rc=$LAST_RC
if [[ $r15_c_rc -eq 0 ]]; then
    T2_ID="$(vm_json_field "t2" "id" || true)"
    invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" run t2 -- df -B1 --output=size /
    r15_r_rc=$LAST_RC
    r15_out="$LAST_OUT"
    r15_err_len="$(wc -c < "$LAST_ERR" | tr -d ' ')"
    record_post_run_hygiene "row15-df8g" "$T2_ID" || true

    r15_root_size="$(/usr/bin/python3 - "$r15_out" <<'PY'
import sys
nums = [ln.strip() for ln in open(sys.argv[1], encoding="utf-8", errors="replace") if ln.strip().isdigit()]
print(nums[-1] if nums else "0")
PY
)"
    if [[ $r15_r_rc -eq 0 && "$r15_err_len" == "0" ]] \
        && /usr/bin/python3 -c 'import sys; sys.exit(0 if int(sys.argv[1]) > 7000000000 else 1)' "$r15_root_size"; then
        pass_row 15 "'create t2 --disk-size 8G' and 'df -B1 --output=size /' reported $r15_root_size bytes (> 7000000000)."
    else
        fail_row 15 "t2 8G rootfs check failed (rc=$r15_r_rc, stderr_bytes=$r15_err_len, size=$r15_root_size)"
    fi
else
    fail_row 15 "'create t2 --disk-size 8G' failed (exit $r15_c_rc): $(cat "$LAST_ERR")"
fi

# ------------------------------------------------------------------
# Row 16: `run e1 -- uname -r` on empty VM -> exit 125, empty stdout, stderr explains no bootable system
# ------------------------------------------------------------------
invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" create e1
r16_c_rc=$LAST_RC
if [[ $r16_c_rc -eq 0 ]]; then
    E1_ID="$(vm_json_field "e1" "id" || true)"
    invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" run e1 -- uname -r
    r16_r_rc=$LAST_RC
    r16_out_len="$(wc -c < "$LAST_OUT" | tr -d ' ')"
    r16_err_str="$(cat "$LAST_ERR")"
    record_post_run_hygiene "row16-empty" "$E1_ID" || true

    if [[ $r16_r_rc -eq 125 && "$r16_out_len" == "0" && "$r16_err_str" == *"ERR_NO_BOOTABLE_SYSTEM"* ]] \
        && [[ "$r16_err_str" == *"没有可引导的客户机系统"* || "$r16_err_str" == *"no bootable guest OS"* ]]; then
        pass_row 16 "'run e1 -- uname -r' on empty disk exited 125 with empty stdout and ERR_NO_BOOTABLE_SYSTEM."
    else
        fail_row 16 "empty disk run check failed (rc=$r16_r_rc, stdout_bytes=$r16_out_len, stderr=$r16_err_str)"
    fi
else
    fail_row 16 "'create e1' failed (exit $r16_c_rc)"
fi

# ------------------------------------------------------------------
# Row 17: `up t1` -> non-zero, hints `run`, `ps --json` t1 != running, 0 new VM processes
# ------------------------------------------------------------------
if [[ $T1_READY -eq 1 ]]; then
    invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" up t1
    r17_rc=$LAST_RC
    r17_out_len="$(wc -c < "$LAST_OUT" | tr -d ' ')"
    r17_err_str="$(cat "$LAST_ERR")"
    r17_state="$(vm_json_field "t1" "state" || true)"
    r17_extra_vz="$(list_extra_vz_pids || true)"

    if [[ $r17_rc -ne 0 && "$r17_out_len" == "0" && "$r17_state" != "running" && -z "$r17_extra_vz" ]] \
        && [[ "$r17_err_str" == *"ERR_DAEMON_REQUIRED"* && "$r17_err_str" == *"agentvm run"* ]]; then
        pass_row 17 "'up t1' exited $r17_rc, hinted 'agentvm run', left state='$r17_state', and spawned 0 VM processes."
    else
        fail_row 17 "'up t1' check failed (rc=$r17_rc, state=$r17_state, extra_vz=$r17_extra_vz, err=$r17_err_str)"
    fi
else
    unrun_row 17 "skipped because t1 was not created in Row 6"
fi

# ------------------------------------------------------------------
# Row 18: Concurrent `run t1` -> second returns 125 (VM busy), first finishes cleanly with 0
# ------------------------------------------------------------------
if [[ $T1_READY -eq 1 ]]; then
    r18_bg_out="$TMP_ROOT/r18-bg.out"
    r18_bg_err="$TMP_ROOT/r18-bg.err"
    r18_bg_flag="$TMP_ROOT/r18-bg.timeout"
    _spawn_agentvm_process "$IMAGE_CACHE_DIR" "$r18_bg_out" "$r18_bg_err" \
        --workspace "$WS" run t1 -- sh -c 'echo started; sleep 20'
    r18_bg_pid="$SPAWNED_PID"
    _start_watchdog "$r18_bg_pid" "$CMD_TIMEOUT_SEC" "$r18_bg_flag"
    r18_wd_pid="$WATCHDOG_PID"

    if wait_for_started_line "$r18_bg_out" "$r18_bg_pid" "$CMD_TIMEOUT_SEC" && confirm_pid_is_test_bin "$r18_bg_pid"; then
        invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" run t1 -- true
        r18_second_rc=$LAST_RC
        r18_second_out_len="$(wc -c < "$LAST_OUT" | tr -d ' ')"
        r18_second_err="$(cat "$LAST_ERR")"

        set +e
        { wait "$r18_bg_pid"; } 2>/dev/null
        r18_first_rc=$?
        set -e
        _stop_watchdog "$r18_wd_pid"
        r18_first_err_len="$(wc -c < "$r18_bg_err" | tr -d ' ')"
        record_post_run_hygiene "row18-flock" "$T1_ID" || true

        if [[ ! -f "$r18_bg_flag" && $r18_second_rc -eq 125 && "$r18_second_out_len" == "0" && $r18_first_rc -eq 0 && "$r18_first_err_len" == "0" ]] \
            && [[ "$r18_second_err" == *"ERR_VM_LOCKED"* ]]; then
            pass_row 18 "concurrent 'run t1 -- true' exited 125 (ERR_VM_LOCKED); first 'run t1' completed cleanly with exit 0."
        else
            fail_row 18 "concurrency check failed (second_rc=$r18_second_rc, first_rc=$r18_first_rc, second_err=$r18_second_err)"
        fi
    else
        kill -TERM "$r18_bg_pid" 2>/dev/null || true
        { wait "$r18_bg_pid"; } 2>/dev/null || true
        _stop_watchdog "$r18_wd_pid"
        record_post_run_hygiene "row18-abort" "$T1_ID" || true
        fail_row 18 "background 'run t1' did not emit 'started' or PID did not match AgentVM"
    fi
else
    unrun_row 18 "skipped because t1 was not created in Row 6"
fi

# ------------------------------------------------------------------
# Row 19: `run t1 -- sh -c 'echo started; sleep 600'` + SIGINT (130) [and SIGTERM (143)],
#         0 leftover VM processes, state != running, follow-up `run t1 -- true` -> 0
# ------------------------------------------------------------------
run_signal_test() {
    local sig_name="$1"
    local expected_rc="$2"
    local tag="$3"

    local bg_out="$TMP_ROOT/${tag}.out"
    local bg_err="$TMP_ROOT/${tag}.err"
    local bg_flag="$TMP_ROOT/${tag}.timeout"

    _spawn_agentvm_process "$IMAGE_CACHE_DIR" "$bg_out" "$bg_err" \
        --workspace "$WS" run t1 -- sh -c 'echo started; sleep 600'
    local bg_pid="$SPAWNED_PID"
    _start_watchdog "$bg_pid" "$CMD_TIMEOUT_SEC" "$bg_flag"
    local wd_pid="$WATCHDOG_PID"

    if ! wait_for_started_line "$bg_out" "$bg_pid" "$CMD_TIMEOUT_SEC"; then
        kill -TERM "$bg_pid" 2>/dev/null || true
        { wait "$bg_pid"; } 2>/dev/null || true
        _stop_watchdog "$wd_pid"
        record_post_run_hygiene "${tag}-nostart" "$T1_ID" || true
        SIGNAL_TEST_DETAIL="$sig_name: never saw 'started'"
        return 1
    fi

    if ! confirm_pid_is_test_bin "$bg_pid"; then
        _stop_watchdog "$wd_pid"
        SIGNAL_TEST_DETAIL="$sig_name: PID $bg_pid was not confirmed as AgentVM via ps"
        return 1
    fi

    kill "-${sig_name}" "$bg_pid"
    set +e
    { wait "$bg_pid"; } 2>/dev/null
    local sig_rc=$?
    set -e
    _stop_watchdog "$wd_pid"

    if ! record_post_run_hygiene "${tag}-after-sig" "$T1_ID"; then
        SIGNAL_TEST_DETAIL="$sig_name: lingering VM process or lock after exit"
        return 1
    fi

    local st
    st="$(vm_json_field "t1" "state" || true)"
    invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" run t1 -- true
    local follow_rc=$LAST_RC
    record_post_run_hygiene "${tag}-followup" "$T1_ID" || true

    if [[ -f "$bg_flag" || $sig_rc -ne $expected_rc || "$st" == "running" || $follow_rc -ne 0 ]]; then
        SIGNAL_TEST_DETAIL="$sig_name: expected rc=$expected_rc/state!=running/follow=0, got rc=$sig_rc/state=$st/follow=$follow_rc"
        return 1
    fi
    return 0
}

SIGNAL_TEST_DETAIL=""
if [[ $T1_READY -eq 1 ]]; then
    if run_signal_test "INT" 130 "r19-int" && run_signal_test "TERM" 143 "r19-term"; then
        pass_row 19 "SIGINT exited 130 and SIGTERM exited 143; 0 leftover VM processes, state != running, and subsequent 'run t1 -- true' exited 0."
    else
        fail_row 19 "$SIGNAL_TEST_DETAIL"
    fi
else
    unrun_row 19 "skipped because t1 was not created in Row 6"
fi

# ------------------------------------------------------------------
# Row 20: `run t1 -- sh -c 'echo started; sleep 600'`, see `started`, `kill -9` AgentVM ->
#         new VirtualMachine process exits on its own (poll <= 30s), state != running, next `run t1 -- true` -> 0
# ------------------------------------------------------------------
if [[ $T1_READY -eq 1 ]]; then
    r20_out="$TMP_ROOT/r20.out"
    r20_err="$TMP_ROOT/r20.err"
    r20_flag="$TMP_ROOT/r20.timeout"
    _spawn_agentvm_process "$IMAGE_CACHE_DIR" "$r20_out" "$r20_err" \
        --workspace "$WS" run t1 -- sh -c 'echo started; sleep 600'
    r20_pid="$SPAWNED_PID"
    _start_watchdog "$r20_pid" "$CMD_TIMEOUT_SEC" "$r20_flag"
    r20_wd="$WATCHDOG_PID"

    if wait_for_started_line "$r20_out" "$r20_pid" "$CMD_TIMEOUT_SEC" && confirm_pid_is_test_bin "$r20_pid"; then
        r20_active_vz="$(list_extra_vz_pids || true)"
        t_k9_start="$(now_sec)"
        kill -9 "$r20_pid"
        set +e
        { wait "$r20_pid"; } 2>/dev/null
        set -e
        _stop_watchdog "$r20_wd"

        r20_vz_reaped=0
        if wait_for_no_extra_vz_pids 30; then
            r20_vz_reaped=1
        fi
        t_k9_end="$(now_sec)"
        r20_reap_sec="$(diff_sec "$t_k9_start" "$t_k9_end")"
        record_post_run_hygiene "row20-after-kill9" "$T1_ID" || true

        r20_state="$(vm_json_field "t1" "state" || true)"
        invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" ps
        r20_plain_ps="$(cat "$LAST_OUT")"

        invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" run t1 -- true
        r20_follow_rc=$LAST_RC
        record_post_run_hygiene "row20-followup" "$T1_ID" || true

        if [[ -n "$r20_active_vz" && $r20_vz_reaped -eq 1 && "$r20_state" != "running" && "$r20_plain_ps" != *"running"* && "$r20_plain_ps" != *"运行中"* && $r20_follow_rc -eq 0 ]]; then
            pass_row 20 "after 'kill -9' on AgentVM, VirtualMachine process self-exited in ${r20_reap_sec}s (<= 30s), state='$r20_state', and follow-up 'run t1 -- true' exited 0."
        else
            fail_row 20 "kill -9 recovery failed (active_vz='$r20_active_vz', reaped=$r20_vz_reaped, state=$r20_state, follow_rc=$r20_follow_rc)"
        fi
    else
        kill -TERM "$r20_pid" 2>/dev/null || true
        { wait "$r20_pid"; } 2>/dev/null || true
        _stop_watchdog "$r20_wd"
        record_post_run_hygiene "row20-abort" "$T1_ID" || true
        fail_row 20 "background 'run t1' did not emit 'started' or PID check failed before kill -9"
    fi
else
    unrun_row 20 "skipped because t1 was not created in Row 6"
fi

# ------------------------------------------------------------------
# Row 21: `policy airgap` -> `run t1 -- true` exits 125; `policy strict` -> `run t1 -- true` exits 0
# ------------------------------------------------------------------
if [[ $T1_READY -eq 1 ]]; then
    invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" policy airgap
    r21_pa_rc=$LAST_RC

    invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" run t1 -- true
    r21_airgap_rc=$LAST_RC
    r21_airgap_out_len="$(wc -c < "$LAST_OUT" | tr -d ' ')"
    r21_airgap_err="$(cat "$LAST_ERR")"
    record_post_run_hygiene "row21-airgap" "$T1_ID" || true

    invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" policy strict
    r21_ps_rc=$LAST_RC

    invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" run t1 -- true
    r21_strict_rc=$LAST_RC
    r21_strict_out_len="$(wc -c < "$LAST_OUT" | tr -d ' ')"
    r21_strict_err_len="$(wc -c < "$LAST_ERR" | tr -d ' ')"
    record_post_run_hygiene "row21-strict" "$T1_ID" || true

    if [[ $r21_pa_rc -eq 0 && $r21_airgap_rc -eq 125 && "$r21_airgap_out_len" == "0" && $r21_ps_rc -eq 0 && $r21_strict_rc -eq 0 && "$r21_strict_out_len" == "0" && "$r21_strict_err_len" == "0" ]] \
        && [[ "$r21_airgap_err" == *"ERR_AIRGAP_UNSUPPORTED"* && "$r21_airgap_err" == *"M5"* ]]; then
        pass_row 21 "under 'policy airgap', 'run t1 -- true' exited 125 (ERR_AIRGAP_UNSUPPORTED); after 'policy strict', 'run t1 -- true' exited 0."
    else
        fail_row 21 "policy airgap/strict check failed (airgap_rc=$r21_airgap_rc, strict_rc=$r21_strict_rc, err=$r21_airgap_err)"
    fi
else
    unrun_row 21 "skipped because t1 was not created in Row 6"
fi

# ------------------------------------------------------------------
# Row 22: `--backend simulation run t1 -- uname -r` -> non-zero, emits no kernel string
# ------------------------------------------------------------------
if [[ $T1_READY -eq 1 ]]; then
    invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" --backend simulation run t1 -- uname -r
    r22_rc=$LAST_RC
    r22_out_len="$(wc -c < "$LAST_OUT" | tr -d ' ')"
    r22_combined="$(cat "$LAST_OUT" "$LAST_ERR")"
    record_post_run_hygiene "row22-simulation" "$T1_ID" || true

    if [[ $r22_rc -ne 0 && "$r22_out_len" == "0" ]] \
        && [[ "$r22_combined" != *"6.8.0"* && "$r22_combined" != *"6.1."* && "$r22_combined" != *"Linux"* && "$r22_combined" != *"aarch64"* && "$r22_combined" != *"agent-sandbox"* ]]; then
        pass_row 22 "'--backend simulation run t1 -- uname -r' exited $r22_rc with zero kernel strings."
    else
        fail_row 22 "simulation run check failed (rc=$r22_rc, combined=$r22_combined)"
    fi
else
    unrun_row 22 "skipped because t1 was not created in Row 6"
fi

# Collect the 5 subsequent `run t1 -- uname -r` timings before printing Rows 23-25 so Row 23 covers ALL `run` calls.
R25_TIMES=()
R25_ALL_OK=1
if [[ $T1_READY -eq 1 ]]; then
    for iter in 1 2 3 4 5; do
        invoke_agentvm "$IMAGE_CACHE_DIR" --workspace "$WS" run t1 -- uname -r
        iter_rc=$LAST_RC
        iter_sec="$LAST_ELAPSED"
        iter_out="$(tr -d '\r\n' < "$LAST_OUT")"
        record_post_run_hygiene "row25-uname-${iter}" "$T1_ID" || true
        if [[ $iter_rc -ne 0 || -z "$iter_out" ]]; then
            R25_ALL_OK=0
        fi
        R25_TIMES+=("${iter_sec}s")
    done
fi

# ------------------------------------------------------------------
# Row 23: After EVERY `run` -> 0 new VirtualMachine processes, VM lock is free
# ------------------------------------------------------------------
if [[ $POST_RUN_CHECKS_TOTAL -gt 0 && $POST_RUN_CHECKS_FAILED -eq 0 ]]; then
    pass_row 23 "after every 'run' ($POST_RUN_CHECKS_TOTAL/$POST_RUN_CHECKS_TOTAL checks): 0 leftover VirtualMachine processes and VM execution lock released."
elif [[ $POST_RUN_CHECKS_TOTAL -eq 0 ]]; then
    unrun_row 23 "no 'run' invocations executed"
else
    fail_row 23 "$POST_RUN_CHECKS_FAILED/$POST_RUN_CHECKS_TOTAL post-run checks failed: $POST_RUN_FAILURE_NOTES"
fi

# ------------------------------------------------------------------
# Row 24: `<workspace>/logs/t1.console.log` exists and is non-empty; print observed boot output
# ------------------------------------------------------------------
CONSOLE_LOG="$WS/logs/t1.console.log"
if [[ $T1_READY -eq 1 ]]; then
    if [[ -s "$CONSOLE_LOG" ]]; then
        r24_summary="$(
            /usr/bin/python3 - "$CONSOLE_LOG" <<'PY'
import re
import sys

raw = open(sys.argv[1], "rb").read()
text = raw.decode("utf-8", errors="replace").replace("\r", "")
lines = text.splitlines()
patterns = [
    r"Linux version 6\.1\.",
    r"efi: EFI ",
    r"ACPI: .*Apple Vz",
    r"virtio_vsock|virtio_console|virtio-pci",
    r"Cloud-init v\.",
    r"AgentVM guest .* ready",
    r"Debian GNU/Linux 12 .* hvc0",
    r"login:",
]
picked = []
for pat in patterns:
    rx = re.compile(pat)
    for ln in lines:
        s = ln.strip()
        if s and rx.search(s) and s not in picked:
            picked.append(s[:160])
            break
print(f"bytes={len(raw)} lines={len(lines)}")
for item in picked:
    print(f"  [console] {item}")
PY
        )"
        r24_header="$(printf '%s\n' "$r24_summary" | head -n 1)"
        emit_out "--- [Row 24 console log observations ($r24_header)] ---"
        while IFS= read -r cline; do
            [[ -z "$cline" ]] && continue
            emit_out "$cline"
        done < <(printf '%s\n' "$r24_summary" | tail -n +2)
        pass_row 24 "<workspace>/logs/t1.console.log exists and is non-empty ($r24_header); observed boot lines printed above."
    else
        fail_row 24 "<workspace>/logs/t1.console.log is missing or empty"
    fi
else
    unrun_row 24 "skipped because t1 was not created in Row 6"
fi

# ------------------------------------------------------------------
# Row 25: Record first-boot time and 5 subsequent `run t1 -- uname -r` times (no upper bound)
# ------------------------------------------------------------------
if [[ $T1_READY -eq 1 && -n "$FIRST_BOOT_SEC" && ${#R25_TIMES[@]} -eq 5 && $R25_ALL_OK -eq 1 ]]; then
    emit_out "--- [Row 25 timing measurements (no wall-clock threshold)] ---"
    emit_out "  first boot ('run t1 -- uname -r' in Row 7) : ${FIRST_BOOT_SEC}s"
    for idx in 0 1 2 3 4; do
        run_num=$((idx + 1))
        emit_out "  subsequent 'run t1 -- uname -r' #${run_num}         : ${R25_TIMES[$idx]}"
    done
    pass_row 25 "first boot=${FIRST_BOOT_SEC}s; 5 subsequent 'run t1 -- uname -r'=[${R25_TIMES[*]}]."
elif [[ $T1_READY -eq 0 ]]; then
    unrun_row 25 "skipped because t1 was not created in Row 6"
else
    fail_row 25 "one or more timing runs failed (first_boot='${FIRST_BOOT_SEC}', ok=$R25_ALL_OK)"
fi

# ------------------------------------------------------------------
# Row 27: Cleanup temporary directory; verify ~/Library/Preferences & ~/Library/Application Support
#         gained 0 AgentVM files and pre-existing cache files (plus .build binary) are untouched.
# ------------------------------------------------------------------
DELETED_TMP_PATH="$TMP_ROOT"
cleanup

r27_tmp_gone=0
if [[ ! -e "$DELETED_TMP_PATH" ]]; then
    r27_tmp_gone=1
fi

HOME_ENTRIES_AFTER="$(snapshot_real_home_agentvm_entries)"
CACHE_SNAPSHOT_AFTER="$(snapshot_cache_directory)"

r27_home_clean=0
if /usr/bin/python3 - "$HOME_ENTRIES_BEFORE" "$HOME_ENTRIES_AFTER" <<'PY'
import json
import sys

before = json.loads(sys.argv[1])
after = json.loads(sys.argv[2])
new_prefs = sorted(set(after["preferences"]) - set(before["preferences"]))
new_appsup = sorted(set(after["app_support"]) - set(before["app_support"]))
if new_prefs or new_appsup:
    print(f"new_prefs={new_prefs} new_app_support={new_appsup}", file=sys.stderr)
    sys.exit(1)
sys.exit(0)
PY
then
    r27_home_clean=1
fi

r27_cache_clean=0
if /usr/bin/python3 - "$CACHE_SNAPSHOT_BEFORE" "$CACHE_SNAPSHOT_AFTER" <<'PY'
import json
import sys

before = json.loads(sys.argv[1])
after = json.loads(sys.argv[2])
if before["exists"]:
    if not after["exists"]:
        sys.exit(1)
    for rel, meta in before["files"].items():
        if after["files"].get(rel) != meta:
            print(f"cache file mutated or removed: {rel}: before={meta} after={after['files'].get(rel)}", file=sys.stderr)
            sys.exit(1)
sys.exit(0)
PY
then
    r27_cache_clean=1
fi

r27_build_clean=1
if [[ -n "$BUILD_ARTIFACT_SHA_BEFORE" ]]; then
    build_sha_after="$(/usr/bin/shasum -a 256 "$ROOT_DIR/.build/debug/AgentVM" | awk '{print $1}')"
    if [[ "$build_sha_after" != "$BUILD_ARTIFACT_SHA_BEFORE" ]]; then
        r27_build_clean=0
    fi
fi

r27_extra_vz="$(list_extra_vz_pids || true)"

if [[ $r27_tmp_gone -eq 1 && $r27_home_clean -eq 1 && $r27_cache_clean -eq 1 && $r27_build_clean -eq 1 && -z "$r27_extra_vz" ]]; then
    pass_row 27 "temp dir removed; 0 new AgentVM files in \$HOME/Library/Preferences or \$HOME/Library/Application Support; pre-existing cache files and .build binary untouched."
else
    fail_row 27 "post-run hygiene failed (tmp_gone=$r27_tmp_gone, home_clean=$r27_home_clean, cache_clean=$r27_cache_clean, build_clean=$r27_build_clean, extra_vz='$r27_extra_vz')"
fi

SCRIPT_END_SEC="$(now_sec)"
TOTAL_ELAPSED_SEC="$(diff_sec "$SCRIPT_START_SEC" "$SCRIPT_END_SEC")"

emit_out "=================================================================="
emit_out " Summary: $PASSED_ROWS passed, $FAILED_ROWS failed, $UNRUN_ROWS unrun (total ${TOTAL_ELAPSED_SEC}s)"
emit_out "=================================================================="

if [[ $FAILED_ROWS -gt 0 || $UNRUN_ROWS -gt 0 ]]; then
    exit 1
fi
exit 0
