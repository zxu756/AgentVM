#!/usr/bin/env bash
# AgentVM Milestone M2 Workspace Daemon Acceptance Script.
#
# Stage 2 implements non-VM Rows 1-9 against the unsigned `.build/debug/AgentVM` binary
# (or caller-supplied AGENTVM_BIN). Stage 3a adds real-VM lifecycle and lock Rows 10, 22, 23,
# 25, 26 (except `exec t1 -- true`), and 29 when AGENTVM_REAL_VM=1 and AGENTVM_BIN carries
# `com.apple.security.virtualization`; rows that require `exec` via daemon (Stage 4) or later
# stages remain marked "没跑".
#
# Hard invariants:
#   * Never launches the desktop UI (.app, window, or bare executable without a CLI subcommand).
#   * Runs the product with an isolated HOME / CFFIXED_USER_HOME and workspaces inside mktemp -d.
#   * Discovers workspace daemons strictly by matching argv `daemon run --workspace <abs-path>`
#     AND verifying `ps -p <pid> -o comm=` equals AGENTVM_BIN (never fuzzy pgrep/pkill).
#   * Snapshots all host agentvm daemons before start and after cleanup; fails if any leaked.
#   * Every product command has a 300-second deadlock guard.
#   * Scrubs host home-directory paths from all output.
set -euo pipefail

CALLER_PWD="$(pwd)"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

REAL_HOME="${HOME:?}"
REAL_HOME="${REAL_HOME%/}"

SWIFT_JOBS_ARGS=()
if [[ -n "${AGENTVM_BUILD_JOBS:-}" ]]; then
    SWIFT_JOBS_ARGS=(-j "$AGENTVM_BUILD_JOBS")
fi

CMD_TIMEOUT_SEC=300
RAW_TMP_ROOT=""
TMP_ROOT=""
IMAGE_CACHE_DIR=""
AGENTVM_BIN_RESOLVED=""
ISOLATED_HOME=""
WS=""
CLEANUP_DONE=0
TRACKED_WORKSPACES=()
OWN_CLIENT_PIDS=()

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
    if [[ -n "$TMP_ROOT" ]]; then
        msg="$(replace_literal "$msg" "$TMP_ROOT" '$TMP_ROOT')"
    fi
    if [[ -n "$RAW_TMP_ROOT" ]]; then
        msg="$(replace_literal "$msg" "$RAW_TMP_ROOT" '$TMP_ROOT')"
    fi
    if [[ -n "$IMAGE_CACHE_DIR" ]]; then
        msg="$(replace_literal "$msg" "$IMAGE_CACHE_DIR" '$AGENTVM_IMAGE_CACHE')"
    fi
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

# Enumerate Virtualization.framework guest processes via `ps -axww -o pid=,comm=` (never fuzzy pgrep).
list_host_vz_vm_pids() {
    /usr/bin/python3 - <<'PY'
import os
import subprocess
import sys

proc = subprocess.run(["ps", "-axww", "-o", "pid=,comm="], capture_output=True, text=True)
if proc.returncode != 0:
    sys.exit(0)

pids = []
for raw_line in proc.stdout.splitlines():
    line = raw_line.strip()
    if not line:
        continue
    parts = line.split(None, 1)
    if len(parts) < 2 or not parts[0].isdigit():
        continue
    comm_val = parts[1].strip()
    if os.path.basename(comm_val) == "com.apple.Virtualization.VirtualMachine":
        pids.append(int(parts[0]))

for pid in sorted(set(pids)):
    print(pid)
PY
}

# Enumerate all host processes running `<AgentVM-executable> daemon run --workspace <abs-path>`
# strictly via `ps -axww -o pid=,command=` + `ps -ww -p <pid> -o comm=` realpath check (never fuzzy pgrep/pkill).
list_all_host_agentvm_daemons() {
    /usr/bin/python3 - "${AGENTVM_BIN_RESOLVED:-}" <<'PY'
import os
import shlex
import subprocess
import sys

expected_bin_raw = sys.argv[1].strip()
expected_bin = os.path.realpath(expected_bin_raw) if expected_bin_raw else ""

proc = subprocess.run(["ps", "-axww", "-o", "pid=,command="], capture_output=True, text=True)
if proc.returncode != 0:
    sys.exit(0)

found = []
for raw_line in proc.stdout.splitlines():
    line = raw_line.strip()
    if not line:
        continue
    parts = line.split(None, 1)
    if len(parts) < 2:
        continue
    pid_str, cmd_str = parts[0], parts[1]
    if not pid_str.isdigit():
        continue
    if "daemon" not in cmd_str or "--workspace" not in cmd_str:
        continue
    try:
        tokens = shlex.split(cmd_str)
    except ValueError:
        tokens = cmd_str.split()
    if len(tokens) != 5:
        continue
    if tokens[1:4] != ["daemon", "run", "--workspace"] or not tokens[4].startswith("/"):
        continue
    comm_proc = subprocess.run(["ps", "-ww", "-p", pid_str, "-o", "comm="], capture_output=True, text=True)
    if comm_proc.returncode != 0:
        continue
    comm_val = comm_proc.stdout.strip()
    if not comm_val:
        continue
    comm_real = os.path.realpath(comm_val)
    if os.path.basename(comm_real).lower() == "agentvm" or (expected_bin and comm_real == expected_bin):
        ws_real = os.path.realpath(tokens[4])
        found.append(f"{pid_str}\t{comm_real}\t{ws_real}")

for item in sorted(found):
    print(item)
PY
}

# Find daemon PID(s) for one specific workspace whose `ps -ww -p <pid> -o comm=` realpath equals AGENTVM_BIN_RESOLVED.
find_workspace_daemon_pids() {
    local target_ws="$1"
    if [[ -z "$AGENTVM_BIN_RESOLVED" || -z "$target_ws" ]]; then
        return 0
    fi
    /usr/bin/python3 - "$target_ws" "$AGENTVM_BIN_RESOLVED" <<'PY'
import os
import shlex
import subprocess
import sys

target_ws = os.path.realpath(sys.argv[1])
expected_bin = os.path.realpath(sys.argv[2])

proc = subprocess.run(["ps", "-axww", "-o", "pid=,command="], capture_output=True, text=True)
if proc.returncode != 0:
    sys.exit(0)

matches = []
for raw_line in proc.stdout.splitlines():
    line = raw_line.strip()
    if not line:
        continue
    parts = line.split(None, 1)
    if len(parts) < 2:
        continue
    pid_str, cmd_str = parts[0], parts[1]
    if not pid_str.isdigit():
        continue
    if "daemon" not in cmd_str or "--workspace" not in cmd_str:
        continue
    try:
        tokens = shlex.split(cmd_str)
    except ValueError:
        tokens = cmd_str.split()
    if len(tokens) != 5:
        continue
    if tokens[1:4] != ["daemon", "run", "--workspace"] or not tokens[4].startswith("/"):
        continue
    ws_arg = os.path.realpath(tokens[4])
    if ws_arg != target_ws:
        continue
    comm_proc = subprocess.run(["ps", "-ww", "-p", pid_str, "-o", "comm="], capture_output=True, text=True)
    if comm_proc.returncode != 0:
        continue
    comm_val = comm_proc.stdout.strip()
    if not comm_val:
        continue
    comm_real = os.path.realpath(comm_val)
    if comm_real == expected_bin:
        matches.append(int(pid_str))

for pid in sorted(set(matches)):
    print(pid)
PY
}

USER_SUPPLIED_BIN=0
if [[ -n "${AGENTVM_BIN:-}" ]]; then
    USER_SUPPLIED_BIN=1
    AGENTVM_BIN_RESOLVED="$(
        /usr/bin/python3 - "$CALLER_PWD" "$ROOT_DIR" "${AGENTVM_BIN}" <<'PY'
import os, sys

caller_pwd, root_dir, raw_bin = sys.argv[1], sys.argv[2], sys.argv[3]
if os.path.isabs(raw_bin):
    candidate = raw_bin
else:
    from_caller = os.path.join(caller_pwd, raw_bin)
    candidate = from_caller if os.path.exists(from_caller) else os.path.join(root_dir, raw_bin)
print(os.path.realpath(candidate))
PY
    )"
    if [[ ! -f "$AGENTVM_BIN_RESOLVED" || ! -x "$AGENTVM_BIN_RESOLVED" ]]; then
        emit_err "ERROR: AGENTVM_BIN does not exist or is not executable: \$AGENTVM_BIN"
        exit 1
    fi
    if [[ "${AGENTVM_REAL_VM:-}" == "1" ]] && ! has_virtualization_entitlement "$AGENTVM_BIN_RESOLVED"; then
        emit_err "REFUSED: AGENTVM_BIN lacks com.apple.security.virtualization entitlement required for AGENTVM_REAL_VM=1."
        exit 1
    fi
fi

# Record host-wide AgentVM daemon baseline BEFORE touching anything.
HOST_DAEMONS_BEFORE="$(list_all_host_agentvm_daemons)"
HOST_DAEMON_COUNT_BEFORE=0
if [[ -n "$HOST_DAEMONS_BEFORE" ]]; then
    HOST_DAEMON_COUNT_BEFORE="$(printf '%s\n' "$HOST_DAEMONS_BEFORE" | wc -l | tr -d ' ')"
fi

BASELINE_VZ_PIDS="$(list_host_vz_vm_pids)"

list_extra_vz_pids() {
    local current_pids
    current_pids="$(list_host_vz_vm_pids)"
    /usr/bin/python3 - "$BASELINE_VZ_PIDS" "$current_pids" <<'PY'
import sys

base = set(int(x.strip()) for x in sys.argv[1].splitlines() if x.strip().isdigit())
curr = set(int(x.strip()) for x in sys.argv[2].splitlines() if x.strip().isdigit())
for pid in sorted(curr - base):
    print(pid)
PY
}

count_extra_vz_pids() {
    local extras
    extras="$(list_extra_vz_pids)"
    if [[ -z "$extras" ]]; then
        echo 0
    else
        printf '%s\n' "$extras" | wc -l | tr -d ' '
    fi
}

wait_for_extra_vz_count() {
    local expected_count="$1"
    local max_wait_sec="${2:-30}"
    local max_ticks=$(( max_wait_sec * 10 ))
    local tick=0
    local current_count=""
    while (( tick <= max_ticks )); do
        current_count="$(count_extra_vz_pids)"
        if [[ "$current_count" == "$expected_count" ]]; then
            return 0
        fi
        sleep 0.1
        tick=$((tick + 1))
    done
    return 1
}

resolve_pid_comm_realpath() {
    local target_pid="$1"
    /usr/bin/python3 - "$target_pid" <<'PY'
import os, subprocess, sys

pid_str = sys.argv[1].strip()
if not pid_str.isdigit():
    sys.exit(0)
proc = subprocess.run(["ps", "-ww", "-p", pid_str, "-o", "comm="], capture_output=True, text=True)
if proc.returncode != 0:
    sys.exit(0)
comm_val = proc.stdout.strip()
if comm_val:
    print(os.path.realpath(comm_val))
PY
}

is_pid_currently_agentvm_bin() {
    local target_pid="$1"
    if [[ -z "$AGENTVM_BIN_RESOLVED" || -z "$target_pid" ]]; then
        return 1
    fi
    if ! kill -0 "$target_pid" 2>/dev/null; then
        return 1
    fi
    local comm_real
    comm_real="$(resolve_pid_comm_realpath "$target_pid")"
    [[ -n "$comm_real" && "$comm_real" == "$AGENTVM_BIN_RESOLVED" ]]
}

stop_tracked_workspaces_and_daemons() {
    local ws pid
    # 1. Politely stop each workspace daemon via `agentvm daemon stop` first.
    if [[ -n "$AGENTVM_BIN_RESOLVED" && -x "$AGENTVM_BIN_RESOLVED" ]]; then
        for ws in "${TRACKED_WORKSPACES[@]+"${TRACKED_WORKSPACES[@]}"}"; do
            if [[ -n "$ws" ]]; then
                /usr/bin/env -u AGENTVM_WORKSPACE -u AGENTVM_REAL_VM -u AGENTVM_LANG \
                    HOME="${ISOLATED_HOME:-$REAL_HOME}" \
                    CFFIXED_USER_HOME="${ISOLATED_HOME:-$REAL_HOME}" \
                    /usr/bin/perl -e 'alarm 65; exec @ARGV' \
                    "$AGENTVM_BIN_RESOLVED" --lang en --workspace "$ws" daemon stop >/dev/null 2>&1 || true
            fi
        done
    fi

    # 2. Terminate any remaining client processes spawned directly by this script.
    for pid in "${OWN_CLIENT_PIDS[@]+"${OWN_CLIENT_PIDS[@]}"}"; do
        if is_pid_currently_agentvm_bin "$pid"; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done

    # 3. Strictly check each tracked workspace for any lingering daemon matching `daemon run --workspace <ws>` + `comm == AGENTVM_BIN`.
    local lingering_pids=()
    for ws in "${TRACKED_WORKSPACES[@]+"${TRACKED_WORKSPACES[@]}"}"; do
        while IFS= read -r pid; do
            if [[ -n "$pid" ]]; then
                lingering_pids+=("$pid")
            fi
        done < <(find_workspace_daemon_pids "$ws")
    done

    for pid in "${lingering_pids[@]+"${lingering_pids[@]}"}"; do
        if is_pid_currently_agentvm_bin "$pid"; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done

    local tick=0
    while (( tick < 50 )); do
        local any_left=0
        for pid in "${lingering_pids[@]+"${lingering_pids[@]}"}"; do
            if is_pid_currently_agentvm_bin "$pid"; then
                any_left=1
                break
            fi
        done
        if [[ $any_left -eq 0 ]]; then
            break
        fi
        sleep 0.1
        tick=$((tick + 1))
    done

    for pid in "${lingering_pids[@]+"${lingering_pids[@]}"}"; do
        if is_pid_currently_agentvm_bin "$pid"; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
    done

    if [[ "${AGENTVM_REAL_VM:-}" == "1" ]]; then
        wait_for_extra_vz_count 0 30 || true
    fi
}

sweep_own_darwin_temp_symlinks() {
    if [[ -z "$TMP_ROOT" && -z "$RAW_TMP_ROOT" ]]; then
        return 0
    fi
    local user_tmp_dir
    user_tmp_dir="$(getconf DARWIN_USER_TEMP_DIR 2>/dev/null || true)"
    if [[ -z "$user_tmp_dir" ]]; then
        return 0
    fi
    /usr/bin/python3 - "$user_tmp_dir" "$TMP_ROOT" "$RAW_TMP_ROOT" <<'PY'
import os, sys

user_tmp = os.path.realpath(sys.argv[1])
roots = []
for r in sys.argv[2:]:
    r = r.strip()
    if r:
        roots.append(r.rstrip("/"))
        roots.append(os.path.realpath(r).rstrip("/"))
roots = sorted(set(x for x in roots if x))

if roots and os.path.isdir(user_tmp):
    for name in os.listdir(user_tmp):
        if not name.startswith("avm-"):
            continue
        full = os.path.join(user_tmp, name)
        if not os.path.islink(full):
            continue
        try:
            raw_target = os.readlink(full)
        except OSError:
            continue
        resolved = os.path.realpath(os.path.join(user_tmp, raw_target))
        if any(
            raw_target == root
            or raw_target.startswith(root + "/")
            or resolved == root
            or resolved.startswith(root + "/")
            for root in roots
        ):
            try:
                os.unlink(full)
            except OSError:
                pass
PY
}

cleanup() {
    if [[ $CLEANUP_DONE -eq 1 ]]; then
        return 0
    fi
    CLEANUP_DONE=1
    stop_tracked_workspaces_and_daemons
    sweep_own_darwin_temp_symlinks
    if [[ -n "$TMP_ROOT" && -d "$TMP_ROOT" ]]; then
        rm -rf "$TMP_ROOT"
    fi
    if [[ -n "$RAW_TMP_ROOT" && -d "$RAW_TMP_ROOT" ]]; then
        rm -rf "$RAW_TMP_ROOT"
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

RAW_TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/agentvm-m2-daemon.XXXXXX")"
TMP_ROOT="$(
    /usr/bin/python3 - "$RAW_TMP_ROOT" <<'PY'
import os, sys
print(os.path.realpath(sys.argv[1]))
PY
)"
ISOLATED_HOME="$TMP_ROOT/home"
WS="$TMP_ROOT/ws.agentvm"
mkdir -p "$ISOLATED_HOME"
TRACKED_WORKSPACES+=("$WS")

emit_out "=================================================================="
emit_out " AgentVM Milestone M2 Workspace Daemon Acceptance Suite"
emit_out "=================================================================="
emit_out "Host AgentVM daemon count before run: $HOST_DAEMON_COUNT_BEFORE"
if [[ -n "$BASELINE_VZ_PIDS" ]]; then
    emit_out "Baseline VirtualMachine PIDs preserved (untouched): [${BASELINE_VZ_PIDS//$'\n'/ }]"
else
    emit_out "Baseline VirtualMachine PIDs: none"
fi

if [[ $USER_SUPPLIED_BIN -eq 0 ]]; then
    emit_out "Building debug AgentVM binary..."
    BUILD_LOG="$TMP_ROOT/swift-build.log"
    if ! swift build "${SWIFT_JOBS_ARGS[@]+"${SWIFT_JOBS_ARGS[@]}"}" --product AgentVM >"$BUILD_LOG" 2>&1; then
        emit_err "ERROR: swift build --product AgentVM failed:"
        while IFS= read -r line; do
            emit_err "  $line"
        done < <(tail -n 40 "$BUILD_LOG")
        exit 1
    fi
    BUILT_DEBUG_BIN="$(
        /usr/bin/python3 - "$ROOT_DIR/.build/debug/AgentVM" <<'PY'
import os, sys
print(os.path.realpath(sys.argv[1]))
PY
    )"
    if [[ "${AGENTVM_REAL_VM:-}" == "1" ]]; then
        mkdir -p "$TMP_ROOT/bin"
        SIGNED_COPY="$TMP_ROOT/bin/AgentVM"
        cp "$BUILT_DEBUG_BIN" "$SIGNED_COPY"
        chmod 0755 "$SIGNED_COPY"
        if ! codesign --force --sign - --entitlements "$ROOT_DIR/Scripts/entitlements.plist" "$SIGNED_COPY" >"$TMP_ROOT/codesign.log" 2>&1; then
            emit_err "ERROR: codesign with Scripts/entitlements.plist failed"
            exit 1
        fi
        AGENTVM_BIN_RESOLVED="$(
            /usr/bin/python3 - "$SIGNED_COPY" <<'PY'
import os, sys
print(os.path.realpath(sys.argv[1]))
PY
        )"
        if ! has_virtualization_entitlement "$AGENTVM_BIN_RESOLVED"; then
            emit_err "ERROR: temporary signed binary still lacks com.apple.security.virtualization"
            exit 1
        fi
    else
        # Non-VM rows run directly against the unsigned `.build/debug/AgentVM` product.
        AGENTVM_BIN_RESOLVED="$BUILT_DEBUG_BIN"
    fi
fi
export AGENTVM_BIN="$AGENTVM_BIN_RESOLVED"

PASSED_ROWS=0
FAILED_ROWS=0
UNRUN_ROWS=0
ROW_START_SEC="$(now_sec)"

pass_row() {
    local row="$1"
    shift
    local now_t elapsed_t
    now_t="$(now_sec)"
    elapsed_t="$(diff_sec "$ROW_START_SEC" "$now_t")"
    ROW_START_SEC="$now_t"
    PASSED_ROWS=$((PASSED_ROWS + 1))
    emit_out "PASS [Row $row]: (${elapsed_t}s) $*"
}

fail_row() {
    local row="$1"
    shift
    local now_t elapsed_t
    now_t="$(now_sec)"
    elapsed_t="$(diff_sec "$ROW_START_SEC" "$now_t")"
    ROW_START_SEC="$now_t"
    FAILED_ROWS=$((FAILED_ROWS + 1))
    emit_out "FAIL [Row $row]: (${elapsed_t}s) $*"
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
            doctor|init|ps|list|image|create|run|daemon|events|up|boot|start|pause|resume|halt|stop|branch|fork|snapshot|restore|exec|pcap|policy|plugin|export-hcl|export-html|help|version|mcp)
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

LAST_RC=0
LAST_ELAPSED_SEC="0.000"
LAST_CMD_PID=""

run_cli() {
    local out_file="$1"
    local err_file="$2"
    shift 2
    ensure_cli_subcommand "$@"
    : >"$out_file"
    : >"$err_file"

    local t0 t1 cmd_pid watchdog_pid timed_out_file
    timed_out_file="$TMP_ROOT/watchdog.$$.$RANDOM.timeout"
    rm -f "$timed_out_file"
    t0="$(now_sec)"

    (
        exec /usr/bin/env -u AGENTVM_WORKSPACE -u AGENTVM_REAL_VM -u AGENTVM_LANG \
            HOME="$ISOLATED_HOME" \
            CFFIXED_USER_HOME="$ISOLATED_HOME" \
            AGENTVM_IMAGE_CACHE="$IMAGE_CACHE_DIR" \
            /usr/bin/perl -e '$SIG{INT}="DEFAULT"; $SIG{TERM}="DEFAULT"; exec @ARGV or die "exec failed: $!\n";' \
            "$AGENTVM_BIN_RESOLVED" "$@"
    ) </dev/null >"$out_file" 2>"$err_file" &
    cmd_pid=$!
    LAST_CMD_PID="$cmd_pid"
    OWN_CLIENT_PIDS+=("$cmd_pid")

    (
        sleep "$CMD_TIMEOUT_SEC"
        if kill -0 "$cmd_pid" 2>/dev/null; then
            echo "timed_out" >"$timed_out_file"
            kill -TERM "$cmd_pid" 2>/dev/null || true
            sleep 3
            kill -KILL "$cmd_pid" 2>/dev/null || true
        fi
    ) &
    watchdog_pid=$!

    local rc=0
    wait "$cmd_pid" 2>/dev/null || rc=$?

    kill "$watchdog_pid" 2>/dev/null || true
    wait "$watchdog_pid" 2>/dev/null || true

    t1="$(now_sec)"
    LAST_ELAPSED_SEC="$(diff_sec "$t0" "$t1")"

    if [[ -f "$timed_out_file" ]]; then
        rm -f "$timed_out_file"
        emit_err "TIMEOUT: command exceeded ${CMD_TIMEOUT_SEC}s deadlock guard: $*"
        LAST_RC=124
        return 0
    fi
    LAST_RC=$rc
    return 0
}

count_lines_nonempty() {
    local text="$1"
    if [[ -z "$text" ]]; then
        echo 0
    else
        printf '%s\n' "$text" | wc -l | tr -d ' '
    fi
}

# ------------------------------------------------------------------
# Row 1: `daemon status` in a fresh workspace -> exits 3, states not running, 0 new daemons
# ------------------------------------------------------------------
run_cli "$TMP_ROOT/r1-init.out" "$TMP_ROOT/r1-init.err" --lang en --workspace "$WS" init
r1_init_rc=$LAST_RC

run_cli "$TMP_ROOT/r1-status-en.out" "$TMP_ROOT/r1-status-en.err" --lang en --workspace "$WS" daemon status
r1_en_rc=$LAST_RC
r1_en_out="$(cat "$TMP_ROOT/r1-status-en.out")"

run_cli "$TMP_ROOT/r1-status-zh.out" "$TMP_ROOT/r1-status-zh.err" --lang zh --workspace "$WS" daemon status
r1_zh_rc=$LAST_RC
r1_zh_out="$(cat "$TMP_ROOT/r1-status-zh.out")"

r1_ws_daemons="$(find_workspace_daemon_pids "$WS")"
r1_host_daemons="$(list_all_host_agentvm_daemons)"
r1_host_count="$(count_lines_nonempty "$r1_host_daemons")"

if [[ $r1_init_rc -eq 0 && $r1_en_rc -eq 3 && $r1_zh_rc -eq 3 \
    && "$r1_en_out" == *"not running"* && "$r1_zh_out" == *"守护进程未运行"* \
    && -z "$r1_ws_daemons" && "$r1_host_count" -le "$HOST_DAEMON_COUNT_BEFORE" ]]; then
    pass_row 1 "fresh workspace 'daemon status' exited 3 (en & zh), reported not running, 0 daemons spawned."
else
    fail_row 1 "unexpected Row 1 result (init_rc=$r1_init_rc, en_rc=$r1_en_rc, zh_rc=$r1_zh_rc, ws_daemons='$r1_ws_daemons', host_count=$r1_host_count)"
fi

# ------------------------------------------------------------------
# Row 2: Provision empty-disk VM `a`; sequentially run `ps`, `ps --json`, `events --json`,
#        `exec a -- true`, `halt a`, `pause a`, `daemon stop` -> exit codes 0, 0, 0, 125
#        (ERR_LIFECYCLE_STATE hinting `up`), 0, 1, 0; 0 daemons spawned; no `run/daemon.sock`
# ------------------------------------------------------------------
run_cli "$TMP_ROOT/r2-create.out" "$TMP_ROOT/r2-create.err" --lang en --workspace "$WS" create a
r2_create_rc=$LAST_RC

r2_sock_appeared=0
r2_daemon_appeared=0
check_r2_no_daemon() {
    if [[ -e "$WS/run/daemon.sock" ]]; then
        r2_sock_appeared=1
    fi
    local d
    d="$(find_workspace_daemon_pids "$WS")"
    if [[ -n "$d" ]]; then
        r2_daemon_appeared=1
    fi
}

run_cli "$TMP_ROOT/r2-ps.out" "$TMP_ROOT/r2-ps.err" --lang en --workspace "$WS" ps
r2_ps_rc=$LAST_RC
check_r2_no_daemon

run_cli "$TMP_ROOT/r2-psj.out" "$TMP_ROOT/r2-psj.err" --lang en --workspace "$WS" ps --json
r2_psj_rc=$LAST_RC
check_r2_no_daemon

run_cli "$TMP_ROOT/r2-evj.out" "$TMP_ROOT/r2-evj.err" --lang en --workspace "$WS" events --json
r2_evj_rc=$LAST_RC
check_r2_no_daemon

run_cli "$TMP_ROOT/r2-exec.out" "$TMP_ROOT/r2-exec.err" --lang en --workspace "$WS" exec a -- true
r2_exec_rc=$LAST_RC
r2_exec_err="$(cat "$TMP_ROOT/r2-exec.err")"
check_r2_no_daemon

run_cli "$TMP_ROOT/r2-halt.out" "$TMP_ROOT/r2-halt.err" --lang en --workspace "$WS" halt a
r2_halt_rc=$LAST_RC
check_r2_no_daemon

run_cli "$TMP_ROOT/r2-pause.out" "$TMP_ROOT/r2-pause.err" --lang en --workspace "$WS" pause a
r2_pause_rc=$LAST_RC
check_r2_no_daemon

run_cli "$TMP_ROOT/r2-stop.out" "$TMP_ROOT/r2-stop.err" --lang en --workspace "$WS" daemon stop
r2_stop_rc=$LAST_RC
check_r2_no_daemon

if [[ $r2_create_rc -eq 0 \
    && $r2_ps_rc -eq 0 && $r2_psj_rc -eq 0 && $r2_evj_rc -eq 0 \
    && $r2_exec_rc -eq 125 && "$r2_exec_err" == *"ERR_LIFECYCLE_STATE"* && "$r2_exec_err" == *"up"* \
    && $r2_halt_rc -eq 0 && $r2_pause_rc -eq 1 && $r2_stop_rc -eq 0 \
    && $r2_sock_appeared -eq 0 && $r2_daemon_appeared -eq 0 ]]; then
    pass_row 2 "exit codes [0, 0, 0, 125 (ERR_LIFECYCLE_STATE + up hint), 0, 1, 0]; 0 daemons spawned; run/daemon.sock absent."
else
    fail_row 2 "codes=[$r2_ps_rc,$r2_psj_rc,$r2_evj_rc,$r2_exec_rc,$r2_halt_rc,$r2_pause_rc,$r2_stop_rc], sock=$r2_sock_appeared, daemon=$r2_daemon_appeared, exec_err='$r2_exec_err'"
fi

# ------------------------------------------------------------------
# Row 3: `up a` on empty disk -> exits 1 with `ERR_NO_BOOTABLE_SYSTEM`, 0 daemons spawned
# ------------------------------------------------------------------
run_cli "$TMP_ROOT/r3-up.out" "$TMP_ROOT/r3-up.err" --lang en --workspace "$WS" up a
r3_rc=$LAST_RC
r3_err="$(cat "$TMP_ROOT/r3-up.err")"
r3_daemons="$(find_workspace_daemon_pids "$WS")"

if [[ $r3_rc -eq 1 && "$r3_err" == *"ERR_NO_BOOTABLE_SYSTEM"* && -z "$r3_daemons" && ! -e "$WS/run/daemon.sock" ]]; then
    pass_row 3 "'up a' on empty disk exited 1 with ERR_NO_BOOTABLE_SYSTEM; 0 daemons spawned."
else
    fail_row 3 "'up a' exited $r3_rc (daemons='$r3_daemons', err='$r3_err')"
fi

# ------------------------------------------------------------------
# Row 4: `out=$(agentvm daemon start)` -> exits 0 in < 5s; `daemon status --json` gives pid;
#        `ps -o ppid=,pgid=,comm= -p <pid>` shows ppid=1, pgid==pid, realpath(comm)==AGENTVM_BIN
# ------------------------------------------------------------------
ensure_cli_subcommand --lang en --workspace "$WS" daemon start
r4_t0="$(now_sec)"
r4_rc=0
r4_sub_out="$(
    /usr/bin/env -u AGENTVM_WORKSPACE -u AGENTVM_REAL_VM -u AGENTVM_LANG \
        HOME="$ISOLATED_HOME" \
        CFFIXED_USER_HOME="$ISOLATED_HOME" \
        AGENTVM_IMAGE_CACHE="$IMAGE_CACHE_DIR" \
        /usr/bin/perl -e 'alarm $ARGV[0]; shift @ARGV; exec @ARGV' \
        "$CMD_TIMEOUT_SEC" \
        "$AGENTVM_BIN_RESOLVED" --lang en --workspace "$WS" daemon start
)" || r4_rc=$?
r4_t1="$(now_sec)"
r4_elapsed="$(diff_sec "$r4_t0" "$r4_t1")"
r4_under_5s="$(/usr/bin/python3 -c 'import sys; print(1 if float(sys.argv[1]) < 5.0 else 0)' "$r4_elapsed")"

run_cli "$TMP_ROOT/r4-status.json" "$TMP_ROOT/r4-status.err" --lang en --workspace "$WS" daemon status --json
r4_status_rc=$LAST_RC
r4_pid=""
if [[ $r4_status_rc -eq 0 ]]; then
    r4_pid="$(
        /usr/bin/python3 - "$TMP_ROOT/r4-status.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
print(data.get("pid", ""))
PY
    )"
fi

r4_ppid=""
r4_pgid=""
r4_comm_real=""
if [[ -n "$r4_pid" ]] && kill -0 "$r4_pid" 2>/dev/null; then
    r4_ps_line="$(ps -ww -o ppid=,pgid=,comm= -p "$r4_pid" 2>/dev/null || true)"
    r4_ppid="$(printf '%s\n' "$r4_ps_line" | awk '{print $1}')"
    r4_pgid="$(printf '%s\n' "$r4_ps_line" | awk '{print $2}')"
    r4_comm_real="$(resolve_pid_comm_realpath "$r4_pid")"
fi

if [[ $r4_rc -eq 0 && $r4_under_5s -eq 1 && $r4_status_rc -eq 0 \
    && -n "$r4_pid" && "$r4_ppid" == "1" && "$r4_pgid" == "$r4_pid" \
    && "$r4_comm_real" == "$AGENTVM_BIN_RESOLVED" ]]; then
    pass_row 4 "command substitution returned in ${r4_elapsed}s (<5s); pid=$r4_pid has ppid=1, pgid=$r4_pgid, realpath(comm)==AGENTVM_BIN."
else
    fail_row 4 "rc=$r4_rc, elapsed=${r4_elapsed}s, status_rc=$r4_status_rc, pid='$r4_pid', ppid='$r4_ppid', pgid='$r4_pgid', comm_real='$r4_comm_real', expected='$AGENTVM_BIN_RESOLVED', out='$r4_sub_out'"
fi

# ------------------------------------------------------------------
# Row 5: Socket & run/ directory permissions (`srw-------` and `drwx------`)
# ------------------------------------------------------------------
r5_sock_perm="$(stat -f '%Sp' "$WS/run/daemon.sock" 2>/dev/null || echo 'missing')"
r5_dir_perm="$(stat -f '%Sp' "$WS/run" 2>/dev/null || echo 'missing')"

if [[ "$r5_sock_perm" == "srw-------" && "$r5_dir_perm" == "drwx------" ]]; then
    pass_row 5 "permissions verified: daemon.sock=$r5_sock_perm, run/=$r5_dir_perm."
else
    fail_row 5 "unexpected permissions: daemon.sock='$r5_sock_perm' (expected srw-------), run/='$r5_dir_perm' (expected drwx------)"
fi

# ------------------------------------------------------------------
# Row 6: `daemon stop`, then 5 concurrent `daemon start` -> all 5 exit 0, report identical pid,
#        and workspace has exactly 1 daemon process
# ------------------------------------------------------------------
run_cli "$TMP_ROOT/r6-prestop.out" "$TMP_ROOT/r6-prestop.err" --lang en --workspace "$WS" daemon stop
r6_prestop_rc=$LAST_RC

ensure_cli_subcommand --lang en --workspace "$WS" daemon start --json
r6_bg_pids=()
for k in 1 2 3 4 5; do
    (
        /usr/bin/env -u AGENTVM_WORKSPACE -u AGENTVM_REAL_VM -u AGENTVM_LANG \
            HOME="$ISOLATED_HOME" \
            CFFIXED_USER_HOME="$ISOLATED_HOME" \
            AGENTVM_IMAGE_CACHE="$IMAGE_CACHE_DIR" \
            /usr/bin/perl -e 'alarm $ARGV[0]; shift @ARGV; exec @ARGV' \
            "$CMD_TIMEOUT_SEC" \
            "$AGENTVM_BIN_RESOLVED" --lang en --workspace "$WS" daemon start --json \
            >"$TMP_ROOT/r6-$k.json" 2>"$TMP_ROOT/r6-$k.err"
    ) &
    r6_bg_pids+=("$!")
done

r6_all_zero=1
for bg in "${r6_bg_pids[@]}"; do
    bg_rc=0
    wait "$bg" 2>/dev/null || bg_rc=$?
    if [[ $bg_rc -ne 0 ]]; then
        r6_all_zero=0
    fi
done

r6_reported_pid="$(
    /usr/bin/python3 - "$TMP_ROOT" <<'PY'
import json, os, sys

tmp = sys.argv[1]
pids = []
for k in range(1, 6):
    p = os.path.join(tmp, f"r6-{k}.json")
    if not os.path.isfile(p):
        sys.exit(1)
    data = json.load(open(p, encoding="utf-8"))
    val = data.get("pid")
    if not isinstance(val, int) or val <= 0:
        sys.exit(1)
    pids.append(val)

if len(set(pids)) == 1:
    print(pids[0])
    sys.exit(0)
sys.exit(1)
PY
)" || r6_reported_pid=""

r6_live_daemons="$(find_workspace_daemon_pids "$WS")"
r6_live_count="$(count_lines_nonempty "$r6_live_daemons")"

if [[ $r6_prestop_rc -eq 0 && $r6_all_zero -eq 1 && -n "$r6_reported_pid" \
    && "$r6_live_count" == "1" && "$r6_live_daemons" == "$r6_reported_pid" ]]; then
    pass_row 6 "all 5 concurrent 'daemon start' exited 0 reporting pid=$r6_reported_pid; workspace has exactly 1 daemon."
else
    fail_row 6 "prestop_rc=$r6_prestop_rc, all_zero=$r6_all_zero, reported_pid='$r6_reported_pid', live_count=$r6_live_count, live='$r6_live_daemons'"
fi

# ------------------------------------------------------------------
# Row 7: `kill -9` daemon -> stale socket remains -> `daemon status` exits 3 ->
#        `daemon start` exits 0 with a new pid -> `daemon status` exits 0
# ------------------------------------------------------------------
r7_old_pid="$r6_reported_pid"
if [[ -n "$r7_old_pid" ]] && is_pid_currently_agentvm_bin "$r7_old_pid"; then
    kill -KILL "$r7_old_pid" 2>/dev/null || true
    r7_wait=0
    while (( r7_wait < 50 )); do
        if ! kill -0 "$r7_old_pid" 2>/dev/null; then
            break
        fi
        sleep 0.05
        r7_wait=$((r7_wait + 1))
    done
fi

r7_stale_sock_present=0
if [[ -S "$WS/run/daemon.sock" || -e "$WS/run/daemon.sock" ]]; then
    r7_stale_sock_present=1
fi

run_cli "$TMP_ROOT/r7-status1.out" "$TMP_ROOT/r7-status1.err" --lang en --workspace "$WS" daemon status
r7_status1_rc=$LAST_RC

run_cli "$TMP_ROOT/r7-start.json" "$TMP_ROOT/r7-start.err" --lang en --workspace "$WS" daemon start --json
r7_start_rc=$LAST_RC
r7_new_pid=""
if [[ $r7_start_rc -eq 0 ]]; then
    r7_new_pid="$(
        /usr/bin/python3 - "$TMP_ROOT/r7-start.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8")).get("pid", ""))
PY
    )"
fi

run_cli "$TMP_ROOT/r7-status2.out" "$TMP_ROOT/r7-status2.err" --lang en --workspace "$WS" daemon status
r7_status2_rc=$LAST_RC

if [[ $r7_stale_sock_present -eq 1 && $r7_status1_rc -eq 3 && $r7_start_rc -eq 0 \
    && -n "$r7_new_pid" && "$r7_new_pid" != "$r7_old_pid" && $r7_status2_rc -eq 0 ]]; then
    pass_row 7 "after SIGKILL ($r7_old_pid): stale socket remained, status exited 3, start exited 0 with new pid=$r7_new_pid, status exited 0."
else
    fail_row 7 "stale_sock=$r7_stale_sock_present, status1_rc=$r7_status1_rc, start_rc=$r7_start_rc, old='$r7_old_pid', new='$r7_new_pid', status2_rc=$r7_status2_rc"
fi

# ------------------------------------------------------------------
# Row 8: `daemon stop` -> exits 0; daemon exits within 10s; socket gone; `daemon status` exits 3
# ------------------------------------------------------------------
run_cli "$TMP_ROOT/r8-stop.out" "$TMP_ROOT/r8-stop.err" --lang en --workspace "$WS" daemon stop
r8_stop_rc=$LAST_RC

r8_gone_within_10s=0
r8_ticks=0
while (( r8_ticks <= 100 )); do
    r8_rem="$(find_workspace_daemon_pids "$WS")"
    if [[ -z "$r8_rem" ]] && { [[ -z "$r7_new_pid" ]] || ! kill -0 "$r7_new_pid" 2>/dev/null; }; then
        r8_gone_within_10s=1
        break
    fi
    sleep 0.1
    r8_ticks=$((r8_ticks + 1))
done

r8_sock_gone=0
if [[ ! -e "$WS/run/daemon.sock" ]]; then
    r8_sock_gone=1
fi

run_cli "$TMP_ROOT/r8-status.out" "$TMP_ROOT/r8-status.err" --lang en --workspace "$WS" daemon status
r8_status_rc=$LAST_RC

if [[ $r8_stop_rc -eq 0 && $r8_gone_within_10s -eq 1 && $r8_sock_gone -eq 1 && $r8_status_rc -eq 3 ]]; then
    pass_row 8 "'daemon stop' exited 0; daemon exited cleanly; daemon.sock removed; subsequent 'daemon status' exited 3."
else
    fail_row 8 "stop_rc=$r8_stop_rc, gone_10s=$r8_gone_within_10s, sock_gone=$r8_sock_gone, status_rc=$r8_status_rc"
fi

# ------------------------------------------------------------------
# Row 9: Workspace absolute path >= 120 bytes -> `init`, `daemon start`, `daemon status`, `daemon stop`
#        all succeed; afterward `getconf DARWIN_USER_TEMP_DIR` has no `avm-*` symlink to this workspace
# ------------------------------------------------------------------
LONG_WS="$TMP_ROOT/long-path-segment-alpha-0123456789abcdef/long-path-segment-beta-0123456789abcdef/long-path-segment-gamma-0123456789abcdef/ws-long.agentvm"
TRACKED_WORKSPACES+=("$LONG_WS")
r9_len="${#LONG_WS}"

run_cli "$TMP_ROOT/r9-init.out" "$TMP_ROOT/r9-init.err" --lang en --workspace "$LONG_WS" init
r9_init_rc=$LAST_RC

run_cli "$TMP_ROOT/r9-start.out" "$TMP_ROOT/r9-start.err" --lang en --workspace "$LONG_WS" daemon start
r9_start_rc=$LAST_RC

run_cli "$TMP_ROOT/r9-status.out" "$TMP_ROOT/r9-status.err" --lang en --workspace "$LONG_WS" daemon status
r9_status_rc=$LAST_RC

run_cli "$TMP_ROOT/r9-stop.out" "$TMP_ROOT/r9-stop.err" --lang en --workspace "$LONG_WS" daemon stop
r9_stop_rc=$LAST_RC

DARWIN_USER_TMP_DIR="$(getconf DARWIN_USER_TEMP_DIR)"
r9_leaked_symlinks="$(
    /usr/bin/python3 - "$DARWIN_USER_TMP_DIR" "$LONG_WS" <<'PY'
import os, sys

user_tmp = os.path.realpath(sys.argv[1])
long_ws = os.path.realpath(sys.argv[2])
long_run = os.path.join(long_ws, "run")

leaked = []
if os.path.isdir(user_tmp):
    for name in sorted(os.listdir(user_tmp)):
        if not name.startswith("avm-"):
            continue
        full = os.path.join(user_tmp, name)
        if os.path.islink(full):
            raw_target = os.readlink(full)
            resolved = os.path.abspath(os.path.join(user_tmp, raw_target))
            if raw_target == long_run or raw_target.startswith(long_ws) or resolved == long_run or resolved.startswith(long_ws):
                leaked.append(f"{full}->{raw_target}")

for item in leaked:
    print(item)
PY
)"

r9_rem_daemons="$(find_workspace_daemon_pids "$LONG_WS")"

if [[ $r9_len -ge 120 && $r9_init_rc -eq 0 && $r9_start_rc -eq 0 && $r9_status_rc -eq 0 && $r9_stop_rc -eq 0 \
    && -z "$r9_leaked_symlinks" && -z "$r9_rem_daemons" ]]; then
    pass_row 9 "long workspace (${r9_len} bytes >= 120) init/start/status/stop all succeeded; 0 avm-* symlinks left in DARWIN_USER_TEMP_DIR."
else
    fail_row 9 "len=$r9_len, rcs=[$r9_init_rc,$r9_start_rc,$r9_status_rc,$r9_stop_rc], leaked_symlinks='$r9_leaked_symlinks', rem_daemons='$r9_rem_daemons'"
fi

# ------------------------------------------------------------------
# Rows 10-39: Real-VM rows (Stage 3a runs 10, 22, 23, 25, 26 [except exec], 29 when
#             AGENTVM_REAL_VM=1 and AGENTVM_BIN carries virtualization entitlement;
#             rows requiring `exec` via daemon [Stage 4] or later stages remain "没跑")
# ------------------------------------------------------------------
CAN_RUN_REAL_VM=0
if [[ "${AGENTVM_REAL_VM:-}" == "1" ]] && has_virtualization_entitlement "$AGENTVM_BIN_RESOLVED"; then
    CAN_RUN_REAL_VM=1
fi

if [[ $CAN_RUN_REAL_VM -ne 1 ]]; then
    for row_no in $(seq 10 34); do
        unrun_row "$row_no" "未设置 AGENTVM_REAL_VM=1（真机验收行未执行）"
    done
    unrun_row 35 "待第 7 段 milestone 2 收尾脚本串联执行"
    unrun_row 36 "未设置 AGENTVM_REAL_VM=1（m1-real-boot.sh 回归行未执行）"
    unrun_row 37 "待第 7 段全量跑完收尾检查"
    unrun_row 38 "调度方独立变异验收行（第 8 段）"
    unrun_row 39 "调度方独立变异验收行（第 8 段）"
else
    # --------------------------------------------------------------
    # Row 10: `create t1 --image debian-12-bookworm-arm64`, `up t1`
    #   Expect: exit 0; `ps --json` has t1 running & guestAgentConnected=true;
    #           exactly 1 new VirtualMachine process; `up` client process exited.
    # --------------------------------------------------------------
    ROW_START_SEC="$(now_sec)"
    run_cli "$TMP_ROOT/r10-create.out" "$TMP_ROOT/r10-create.err" --lang en --workspace "$WS" create t1 --image debian-12-bookworm-arm64
    r10_create_rc=$LAST_RC
    r10_create_elapsed="$LAST_ELAPSED_SEC"

    run_cli "$TMP_ROOT/r10-up.out" "$TMP_ROOT/r10-up.err" --lang en --workspace "$WS" up t1
    r10_up_rc=$LAST_RC
    r10_up_elapsed="$LAST_ELAPSED_SEC"
    r10_up_pid="$LAST_CMD_PID"
    r10_up_err="$(cat "$TMP_ROOT/r10-up.err")"

    r10_up_exited=0
    if [[ -n "$r10_up_pid" ]] && ! is_pid_currently_agentvm_bin "$r10_up_pid"; then
        r10_up_exited=1
    fi

    run_cli "$TMP_ROOT/r10-ps.json" "$TMP_ROOT/r10-ps.err" --lang en --workspace "$WS" ps --json
    r10_ps_rc=$LAST_RC

    T1_ID=""
    T1_SNAP_ID=""
    T1_DISK_PATH=""
    r10_t1_ok=0
    if [[ $r10_ps_rc -eq 0 ]]; then
        r10_meta="$(
            /usr/bin/python3 - "$TMP_ROOT/r10-ps.json" <<'PY'
import json, sys

vms = json.load(open(sys.argv[1], encoding="utf-8"))
t1_list = [v for v in vms if v.get("spec", {}).get("name") == "t1"]
if len(t1_list) != 1:
    sys.exit(1)
t1 = t1_list[0]
tel = t1.get("telemetry", {})
if tel.get("state") != "running" or tel.get("guestAgentConnected") is not True or tel.get("simulated") is not False:
    sys.exit(1)
vm_id = t1.get("spec", {}).get("id", "")
snap_id = t1.get("currentHeadSnapshotID", "")
blocks = t1.get("spec", {}).get("blockDevices", [])
disk_path = blocks[0].get("imagePath", "") if blocks else ""
print(vm_id)
print(snap_id)
print(disk_path)
PY
        )" && r10_t1_ok=1 || r10_t1_ok=0
        if [[ $r10_t1_ok -eq 1 ]]; then
            T1_ID="$(printf '%s\n' "$r10_meta" | sed -n '1p')"
            T1_SNAP_ID="$(printf '%s\n' "$r10_meta" | sed -n '2p')"
            T1_DISK_PATH="$(printf '%s\n' "$r10_meta" | sed -n '3p')"
        fi
    fi

    r10_extra_vz="$(list_extra_vz_pids)"
    r10_extra_vz_count="$(count_lines_nonempty "$r10_extra_vz")"
    T1_VZ_PID=""
    if [[ "$r10_extra_vz_count" == "1" ]]; then
        T1_VZ_PID="$r10_extra_vz"
    fi

    if [[ $r10_create_rc -eq 0 && $r10_up_rc -eq 0 && $r10_up_exited -eq 1 \
        && $r10_ps_rc -eq 0 && $r10_t1_ok -eq 1 && "$r10_extra_vz_count" == "1" ]]; then
        pass_row 10 "create (${r10_create_elapsed}s) & 'up t1' (${r10_up_elapsed}s) exited 0; ps --json state=running & guestAgentConnected=true; extra VirtualMachine PIDs=1 (pid=$T1_VZ_PID); 'up' client process exited."
    else
        fail_row 10 "create_rc=$r10_create_rc, up_rc=$r10_up_rc, up_exited=$r10_up_exited, ps_rc=$r10_ps_rc, t1_ok=$r10_t1_ok, extra_vz_count=$r10_extra_vz_count (pids='${r10_extra_vz//$'\n'/,}'), up_err='$r10_up_err'"
    fi

    # Rows 11-21 require `exec` via daemon (Stage 4) and/or guest agent v2 & telemetry (Stages 5-6).
    unrun_row 11 "exec 经守护进程是第 4 段"
    unrun_row 12 "exec 经守护进程是第 4 段"
    unrun_row 13 "exec 经守护进程是第 4 段"
    unrun_row 14 "exec 经守护进程是第 4 段"
    unrun_row 15 "exec 经守护进程是第 4 段"
    unrun_row 16 "exec 经守护进程是第 4 段"
    unrun_row 17 "exec 经守护进程是第 4 段（客户机进程组取消是第 5 段）"
    unrun_row 18 "exec 经守护进程是第 4 段（遥测映射是第 6 段）"
    unrun_row 19 "exec 经守护进程是第 4 段（CPU 遥测是第 5-6 段）"
    unrun_row 20 "exec 经守护进程是第 4 段（内存遥测是第 6 段）"
    unrun_row 21 "遥测刷新与过期是第 6 段"

    # --------------------------------------------------------------
    # Row 22: While daemon holds `t1`, `run t1 -- true`
    #   Expect: exits 125 with ERR_VM_LOCKED; t1 still running (same VirtualMachine PID).
    # --------------------------------------------------------------
    ROW_START_SEC="$(now_sec)"
    run_cli "$TMP_ROOT/r22-run.out" "$TMP_ROOT/r22-run.err" --lang en --workspace "$WS" run t1 -- true
    r22_rc=$LAST_RC
    r22_out="$(cat "$TMP_ROOT/r22-run.out")"
    r22_err="$(cat "$TMP_ROOT/r22-run.err")"

    run_cli "$TMP_ROOT/r22-ps.json" "$TMP_ROOT/r22-ps.err" --lang en --workspace "$WS" ps --json
    r22_ps_rc=$LAST_RC
    r22_t1_running=0
    if [[ $r22_ps_rc -eq 0 ]]; then
        /usr/bin/python3 - "$TMP_ROOT/r22-ps.json" <<'PY' && r22_t1_running=1 || r22_t1_running=0
import json, sys

vms = json.load(open(sys.argv[1], encoding="utf-8"))
t1 = [v for v in vms if v.get("spec", {}).get("name") == "t1"]
if len(t1) != 1:
    sys.exit(1)
tel = t1[0].get("telemetry", {})
if tel.get("state") != "running" or tel.get("guestAgentConnected") is not True:
    sys.exit(1)
PY
    fi

    r22_extra_vz="$(list_extra_vz_pids)"
    r22_extra_vz_count="$(count_lines_nonempty "$r22_extra_vz")"

    if [[ $r22_rc -eq 125 && -z "$r22_out" && "$r22_err" == *"ERR_VM_LOCKED"* \
        && $r22_t1_running -eq 1 && "$r22_extra_vz_count" == "1" \
        && -n "$T1_VZ_PID" && "$r22_extra_vz" == "$T1_VZ_PID" ]]; then
        pass_row 22 "'run t1 -- true' exited 125 with ERR_VM_LOCKED; t1 still running on unchanged VirtualMachine pid=$T1_VZ_PID (exec 读 boot_id 待第 4 段)."
    else
        fail_row 22 "rc=$r22_rc, out_len=${#r22_out}, t1_running=$r22_t1_running, extra_vz='${r22_extra_vz//$'\n'/,}' (expected '$T1_VZ_PID'), err='$r22_err'"
    fi

    # --------------------------------------------------------------
    # Row 23: While `t1` is running, `snapshot t1` and `restore <t1 snapshot>`
    #   Expect: both exit 1 with ERR_VM_LOCKED mentioning M3; t1 root disk inode unchanged; t1 still running.
    # --------------------------------------------------------------
    ROW_START_SEC="$(now_sec)"
    r23_ino_before=""
    if [[ -n "$T1_DISK_PATH" && -f "$T1_DISK_PATH" ]]; then
        r23_ino_before="$(stat -f '%i' "$T1_DISK_PATH" 2>/dev/null || true)"
    fi

    run_cli "$TMP_ROOT/r23-snap.out" "$TMP_ROOT/r23-snap.err" --lang en --workspace "$WS" snapshot t1
    r23_snap_rc=$LAST_RC
    r23_snap_err="$(cat "$TMP_ROOT/r23-snap.err")"

    r23_restore_rc=99
    r23_restore_err=""
    if [[ -n "$T1_SNAP_ID" ]]; then
        run_cli "$TMP_ROOT/r23-restore.out" "$TMP_ROOT/r23-restore.err" --lang en --workspace "$WS" restore "$T1_SNAP_ID"
        r23_restore_rc=$LAST_RC
        r23_restore_err="$(cat "$TMP_ROOT/r23-restore.err")"
    fi

    r23_ino_after=""
    if [[ -n "$T1_DISK_PATH" && -f "$T1_DISK_PATH" ]]; then
        r23_ino_after="$(stat -f '%i' "$T1_DISK_PATH" 2>/dev/null || true)"
    fi

    run_cli "$TMP_ROOT/r23-ps.json" "$TMP_ROOT/r23-ps.err" --lang en --workspace "$WS" ps --json
    r23_ps_rc=$LAST_RC
    r23_t1_running=0
    if [[ $r23_ps_rc -eq 0 ]]; then
        /usr/bin/python3 - "$TMP_ROOT/r23-ps.json" <<'PY' && r23_t1_running=1 || r23_t1_running=0
import json, sys

vms = json.load(open(sys.argv[1], encoding="utf-8"))
t1 = [v for v in vms if v.get("spec", {}).get("name") == "t1"]
if len(t1) != 1:
    sys.exit(1)
tel = t1[0].get("telemetry", {})
if tel.get("state") != "running" or tel.get("guestAgentConnected") is not True:
    sys.exit(1)
PY
    fi

    r23_extra_vz="$(list_extra_vz_pids)"

    if [[ $r23_snap_rc -eq 1 && "$r23_snap_err" == *"ERR_VM_LOCKED"* && "$r23_snap_err" == *"M3"* \
        && $r23_restore_rc -eq 1 && "$r23_restore_err" == *"ERR_VM_LOCKED"* && "$r23_restore_err" == *"M3"* \
        && -n "$r23_ino_before" && "$r23_ino_before" == "$r23_ino_after" \
        && $r23_t1_running -eq 1 && -n "$T1_VZ_PID" && "$r23_extra_vz" == "$T1_VZ_PID" ]]; then
        pass_row 23 "'snapshot t1' and 'restore $T1_SNAP_ID' both exited 1 with ERR_VM_LOCKED mentioning M3; disk inode unchanged ($r23_ino_after); t1 still running on pid=$T1_VZ_PID (exec 读 boot_id 待第 4 段)."
    else
        fail_row 23 "snap_rc=$r23_snap_rc, restore_rc=$r23_restore_rc, ino='$r23_ino_before'->'$r23_ino_after', t1_running=$r23_t1_running, extra_vz='${r23_extra_vz//$'\n'/,}', snap_err='$r23_snap_err', restore_err='$r23_restore_err'"
    fi

    # Row 24 requires `exec` via daemon (Stage 4) and telemetry expiry (Stage 6).
    unrun_row 24 "exec 经守护进程是第 4 段"

    # --------------------------------------------------------------
    # Row 25: `create t2 --image debian-12-bookworm-arm64`; while daemon is running (t1 running),
    #         `policy airgap` -> `up t2` exits 1 (ERR_AIRGAP_UNSUPPORTED / M5, 0 new VMs);
    #         `policy strict` -> `up t2` exits 0; then `halt t2`.
    # --------------------------------------------------------------
    ROW_START_SEC="$(now_sec)"
    run_cli "$TMP_ROOT/r25-dstatus1.json" "$TMP_ROOT/r25-dstatus1.err" --lang en --workspace "$WS" daemon status --json
    r25_d1_rc=$LAST_RC
    r25_d1_pid=""
    if [[ $r25_d1_rc -eq 0 ]]; then
        r25_d1_pid="$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get("pid", ""))' "$TMP_ROOT/r25-dstatus1.json" 2>/dev/null || true)"
    fi

    run_cli "$TMP_ROOT/r25-create.out" "$TMP_ROOT/r25-create.err" --lang en --workspace "$WS" create t2 --image debian-12-bookworm-arm64
    r25_create_rc=$LAST_RC

    run_cli "$TMP_ROOT/r25-airgap.out" "$TMP_ROOT/r25-airgap.err" --lang en --workspace "$WS" policy airgap
    r25_airgap_rc=$LAST_RC

    run_cli "$TMP_ROOT/r25-up1.out" "$TMP_ROOT/r25-up1.err" --lang en --workspace "$WS" up t2
    r25_up1_rc=$LAST_RC
    r25_up1_err="$(cat "$TMP_ROOT/r25-up1.err")"
    r25_vz_after_airgap="$(list_extra_vz_pids)"
    r25_vz_after_airgap_count="$(count_lines_nonempty "$r25_vz_after_airgap")"

    run_cli "$TMP_ROOT/r25-strict.out" "$TMP_ROOT/r25-strict.err" --lang en --workspace "$WS" policy strict
    r25_strict_rc=$LAST_RC

    run_cli "$TMP_ROOT/r25-up2.out" "$TMP_ROOT/r25-up2.err" --lang en --workspace "$WS" up t2
    r25_up2_rc=$LAST_RC
    r25_up2_elapsed="$LAST_ELAPSED_SEC"
    r25_vz_during_t2="$(count_extra_vz_pids)"

    run_cli "$TMP_ROOT/r25-dstatus2.json" "$TMP_ROOT/r25-dstatus2.err" --lang en --workspace "$WS" daemon status --json
    r25_d2_rc=$LAST_RC
    r25_d2_pid=""
    if [[ $r25_d2_rc -eq 0 ]]; then
        r25_d2_pid="$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get("pid", ""))' "$TMP_ROOT/r25-dstatus2.json" 2>/dev/null || true)"
    fi

    run_cli "$TMP_ROOT/r25-halt.out" "$TMP_ROOT/r25-halt.err" --lang en --workspace "$WS" halt t2
    r25_halt_rc=$LAST_RC
    r25_t2_vz_exited=0
    if wait_for_extra_vz_count 1 30; then
        r25_t2_vz_exited=1
    fi

    if [[ $r25_d1_rc -eq 0 && -n "$r25_d1_pid" && $r25_create_rc -eq 0 && $r25_airgap_rc -eq 0 \
        && $r25_up1_rc -eq 1 && "$r25_up1_err" == *"ERR_AIRGAP_UNSUPPORTED"* && "$r25_up1_err" == *"M5"* \
        && "$r25_vz_after_airgap_count" == "1" && "$r25_vz_after_airgap" == "$T1_VZ_PID" \
        && $r25_strict_rc -eq 0 && $r25_up2_rc -eq 0 && "$r25_vz_during_t2" == "2" \
        && $r25_d2_rc -eq 0 && "$r25_d2_pid" == "$r25_d1_pid" \
        && $r25_halt_rc -eq 0 && $r25_t2_vz_exited -eq 1 ]]; then
        pass_row 25 "live daemon (pid=$r25_d1_pid) re-read airgap policy: 'up t2' exited 1 (ERR_AIRGAP_UNSUPPORTED / M5, 0 new VM processes); after 'policy strict', 'up t2' (${r25_up2_elapsed}s) exited 0 (extra VMs=2); 'halt t2' exited 0."
    else
        fail_row 25 "create=$r25_create_rc, airgap=$r25_airgap_rc, up1=$r25_up1_rc, vz_airgap='$r25_vz_after_airgap_count', strict=$r25_strict_rc, up2=$r25_up2_rc, vz_t2='$r25_vz_during_t2', pids='$r25_d1_pid'->'$r25_d2_pid', halt=$r25_halt_rc, t2_exited=$r25_t2_vz_exited, up1_err='$r25_up1_err'"
    fi

    # --------------------------------------------------------------
    # Row 26 (except `exec t1 -- true`): `halt t1`
    #   Expect: exits 0; within 30s t1's VirtualMachine process exits; `ps --json` is stopped;
    #           plain `ps` CPU and MEMORY columns are '—'; daemon still running (`daemon status` exits 0).
    #           (`exec t1 -- true` deferred until Stage 4).
    # --------------------------------------------------------------
    ROW_START_SEC="$(now_sec)"
    r26_t0="$(now_sec)"
    run_cli "$TMP_ROOT/r26-halt.out" "$TMP_ROOT/r26-halt.err" --lang en --workspace "$WS" halt t1
    r26_halt_rc=$LAST_RC

    r26_vz_gone=0
    if wait_for_extra_vz_count 0 30; then
        r26_vz_gone=1
    fi
    r26_t1="$(now_sec)"
    r26_vz_elapsed="$(diff_sec "$r26_t0" "$r26_t1")"

    run_cli "$TMP_ROOT/r26-ps.json" "$TMP_ROOT/r26-psj.err" --lang en --workspace "$WS" ps --json
    r26_psj_rc=$LAST_RC
    r26_psj_ok=0
    if [[ $r26_psj_rc -eq 0 ]]; then
        /usr/bin/python3 - "$TMP_ROOT/r26-ps.json" <<'PY' && r26_psj_ok=1 || r26_psj_ok=0
import json, sys

vms = json.load(open(sys.argv[1], encoding="utf-8"))
t1 = [v for v in vms if v.get("spec", {}).get("name") == "t1"]
if len(t1) != 1:
    sys.exit(1)
tel = t1[0].get("telemetry", {})
if tel.get("state") != "stopped" or tel.get("guestAgentConnected") is not False:
    sys.exit(1)
PY
    fi

    run_cli "$TMP_ROOT/r26-ps.txt" "$TMP_ROOT/r26-pst.err" --lang en --workspace "$WS" ps
    r26_pst_rc=$LAST_RC
    r26_pst_ok=0
    if [[ $r26_pst_rc -eq 0 ]]; then
        /usr/bin/python3 - "$TMP_ROOT/r26-ps.txt" "$T1_ID" <<'PY' && r26_pst_ok=1 || r26_pst_ok=0
import sys

lines = [ln.rstrip("\r\n") for ln in open(sys.argv[1], encoding="utf-8") if ln.strip()]
t1_id = sys.argv[2].strip()
if len(lines) < 2:
    sys.exit(1)
header = lines[0]
for col in ("STATE", "CPU", "MEMORY", "IPV4"):
    if col not in header:
        sys.exit(1)
state_idx = header.index("STATE")
cpu_idx = header.index("CPU")
mem_idx = header.index("MEMORY")
ip_idx = header.index("IPV4")

matched = [ln for ln in lines[1:] if (t1_id and ln.startswith(t1_id + " ")) or (" t1 " in ln)]
if len(matched) != 1:
    sys.exit(1)
row = matched[0]
state_val = row[state_idx:cpu_idx].strip()
cpu_val = row[cpu_idx:mem_idx].strip()
mem_val = row[mem_idx:ip_idx].strip()
if state_val != "stopped" or cpu_val != "—" or mem_val != "—":
    sys.exit(1)
PY
    fi

    run_cli "$TMP_ROOT/r26-dstatus.out" "$TMP_ROOT/r26-dstatus.err" --lang en --workspace "$WS" daemon status
    r26_dstatus_rc=$LAST_RC
    r26_daemon_pids="$(find_workspace_daemon_pids "$WS")"
    r26_daemon_count="$(count_lines_nonempty "$r26_daemon_pids")"

    if [[ $r26_halt_rc -eq 0 && $r26_vz_gone -eq 1 && $r26_psj_ok -eq 1 \
        && $r26_pst_ok -eq 1 && $r26_dstatus_rc -eq 0 && "$r26_daemon_count" == "1" ]]; then
        pass_row 26 "'halt t1' exited 0; t1 VirtualMachine process exited in ${r26_vz_elapsed}s (<30s); ps --json=stopped; plain ps CPU='—' & MEMORY='—'; daemon still alive ('daemon status' exited 0) ['exec t1 -- true' 没跑：exec 经守护进程是第 4 段]."
    else
        fail_row 26 "halt_rc=$r26_halt_rc, vz_gone=$r26_vz_gone, psj_ok=$r26_psj_ok, pst_ok=$r26_pst_ok, dstatus_rc=$r26_dstatus_rc, daemon_count=$r26_daemon_count"
    fi

    # Rows 27-28 require `exec` via daemon (Stage 4) and guest stop observation A33 (Stage 3b).
    unrun_row 27 "exec 经守护进程是第 4 段"
    unrun_row 28 "exec 经守护进程是第 4 段（停机观察 A33 是第 3b 段）"

    # --------------------------------------------------------------
    # Row 29: `up t1`, `up t2`
    #   Expect: 2 extra VirtualMachine processes; `daemon status --json` lists both t1 and t2.
    # --------------------------------------------------------------
    ROW_START_SEC="$(now_sec)"
    run_cli "$TMP_ROOT/r29-up1.out" "$TMP_ROOT/r29-up1.err" --lang en --workspace "$WS" up t1
    r29_up1_rc=$LAST_RC
    r29_up1_elapsed="$LAST_ELAPSED_SEC"

    run_cli "$TMP_ROOT/r29-up2.out" "$TMP_ROOT/r29-up2.err" --lang en --workspace "$WS" up t2
    r29_up2_rc=$LAST_RC
    r29_up2_elapsed="$LAST_ELAPSED_SEC"

    r29_extra_vz="$(list_extra_vz_pids)"
    r29_extra_vz_count="$(count_lines_nonempty "$r29_extra_vz")"

    run_cli "$TMP_ROOT/r29-dstatus.json" "$TMP_ROOT/r29-dstatus.err" --lang en --workspace "$WS" daemon status --json
    r29_dstatus_rc=$LAST_RC
    r29_status_ok=0
    if [[ $r29_dstatus_rc -eq 0 ]]; then
        /usr/bin/python3 - "$TMP_ROOT/r29-dstatus.json" <<'PY' && r29_status_ok=1 || r29_status_ok=0
import json, sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
if data.get("running") is not True:
    sys.exit(1)
vms = data.get("vms") or []
names = sorted(v.get("spec", {}).get("name", "") for v in vms)
if names != ["t1", "t2"]:
    sys.exit(1)
for v in vms:
    tel = v.get("telemetry", {})
    if tel.get("state") != "running" or tel.get("guestAgentConnected") is not True:
        sys.exit(1)
PY
    fi

    if [[ $r29_up1_rc -eq 0 && $r29_up2_rc -eq 0 && "$r29_extra_vz_count" == "2" \
        && $r29_dstatus_rc -eq 0 && $r29_status_ok -eq 1 ]]; then
        pass_row 29 "'up t1' (${r29_up1_elapsed}s) & 'up t2' (${r29_up2_elapsed}s) exited 0; extra VirtualMachine PIDs=2; 'daemon status --json' lists [t1, t2] running."
    else
        fail_row 29 "up1_rc=$r29_up1_rc, up2_rc=$r29_up2_rc, extra_vz_count=$r29_extra_vz_count (pids='${r29_extra_vz//$'\n'/,}'), dstatus_rc=$r29_dstatus_rc, status_ok=$r29_status_ok"
    fi

    # Rows 30-34 require `exec` via daemon (Stage 4) and Stage 3b stop observation/reconnection.
    unrun_row 30 "exec 经守护进程是第 4 段（第 30-31 行断电恢复组在第 3b 段）"
    unrun_row 31 "exec 经守护进程是第 4 段"
    unrun_row 32 "exec 经守护进程是第 4 段"
    unrun_row 33 "exec 经守护进程是第 4 段（VM_STOPPED 停机原因与第 34 行 dmesg 核对在第 3b 段）"
    unrun_row 34 "exec 经守护进程是第 4 段"

    unrun_row 35 "待第 7 段 milestone 2 收尾脚本串联执行"
    unrun_row 36 "待第 7 段更新 m1-real-boot.sh 第 17 行后执行"
    unrun_row 37 "待第 7 段全量跑完收尾检查"
    unrun_row 38 "调度方独立变异验收行（第 8 段）"
    unrun_row 39 "调度方独立变异验收行（第 8 段）"
fi

# ------------------------------------------------------------------
# Post-Run Cleanup & Host-Wide AgentVM Daemon Leak Gate
# ------------------------------------------------------------------
cleanup

HOST_DAEMONS_AFTER="$(list_all_host_agentvm_daemons)"
HOST_DAEMON_COUNT_AFTER=0
if [[ -n "$HOST_DAEMONS_AFTER" ]]; then
    HOST_DAEMON_COUNT_AFTER="$(printf '%s\n' "$HOST_DAEMONS_AFTER" | wc -l | tr -d ' ')"
fi

NEW_HOST_DAEMONS="$(
    /usr/bin/python3 - "$HOST_DAEMONS_BEFORE" "$HOST_DAEMONS_AFTER" <<'PY'
import sys
before = set(line.strip() for line in sys.argv[1].splitlines() if line.strip())
after = set(line.strip() for line in sys.argv[2].splitlines() if line.strip())
extra = sorted(after - before)
for item in extra:
    print(item)
PY
)"

emit_out "Host AgentVM daemon count after cleanup: $HOST_DAEMON_COUNT_AFTER (before: $HOST_DAEMON_COUNT_BEFORE)"
if [[ "$HOST_DAEMON_COUNT_AFTER" -gt "$HOST_DAEMON_COUNT_BEFORE" || -n "$NEW_HOST_DAEMONS" ]]; then
    emit_err "FAIL: leaked AgentVM daemon process(es) detected after cleanup: $NEW_HOST_DAEMONS"
    FAILED_ROWS=$((FAILED_ROWS + 1))
fi

EXTRA_VZ_AFTER="$(list_extra_vz_pids)"
EXTRA_VZ_COUNT_AFTER="$(count_lines_nonempty "$EXTRA_VZ_AFTER")"
emit_out "Extra VirtualMachine PIDs after cleanup: $EXTRA_VZ_COUNT_AFTER"
if [[ "$EXTRA_VZ_COUNT_AFTER" != "0" ]]; then
    emit_err "FAIL: leaked VirtualMachine process(es) detected after cleanup: ${EXTRA_VZ_AFTER//$'\n'/ }"
    FAILED_ROWS=$((FAILED_ROWS + 1))
fi

SCRIPT_END_SEC="$(now_sec)"
TOTAL_ELAPSED_SEC="$(diff_sec "$SCRIPT_START_SEC" "$SCRIPT_END_SEC")"

emit_out "=================================================================="
emit_out " Summary: $PASSED_ROWS passed, $FAILED_ROWS failed, $UNRUN_ROWS unrun (total ${TOTAL_ELAPSED_SEC}s)"
emit_out "=================================================================="

if [[ $FAILED_ROWS -gt 0 ]]; then
    exit 1
fi
if [[ $UNRUN_ROWS -gt 0 ]]; then
    exit 2
fi
exit 0
