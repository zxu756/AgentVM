#!/usr/bin/env bash
# AgentVM Milestone M2 Workspace Daemon Acceptance Script.
#
# Stage 2 implements non-VM Rows 1-9 against the unsigned `.build/debug/AgentVM` binary
# (or caller-supplied AGENTVM_BIN). Stages 3a, 4, and 3b run real-VM Rows 10-16 and 22-34
# when AGENTVM_REAL_VM=1 and AGENTVM_BIN carries `com.apple.security.virtualization`; rows
# scheduled for Stage 5 (17), Stage 6 (18-21), or Stages 7-8 (35-39) remain marked "没跑".
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

    # --------------------------------------------------------------
    # Row 11: Two separate processes sequentially run `exec t1 -- cat /proc/sys/kernel/random/boot_id`
    #         at least 5s apart, each followed by `exec t1 -- cat /proc/uptime`.
    #   Expect: all exit 0; both boot_id values match and have UUID format; second uptime > first.
    # --------------------------------------------------------------
    ROW_START_SEC="$(now_sec)"
    run_cli "$TMP_ROOT/r11-boot1.out" "$TMP_ROOT/r11-boot1.err" --lang en --workspace "$WS" exec t1 -- cat /proc/sys/kernel/random/boot_id
    r11_b1_rc=$LAST_RC
    run_cli "$TMP_ROOT/r11-up1.out" "$TMP_ROOT/r11-up1.err" --lang en --workspace "$WS" exec t1 -- cat /proc/uptime
    r11_u1_rc=$LAST_RC

    sleep 5.2

    run_cli "$TMP_ROOT/r11-boot2.out" "$TMP_ROOT/r11-boot2.err" --lang en --workspace "$WS" exec t1 -- cat /proc/sys/kernel/random/boot_id
    r11_b2_rc=$LAST_RC
    run_cli "$TMP_ROOT/r11-up2.out" "$TMP_ROOT/r11-up2.err" --lang en --workspace "$WS" exec t1 -- cat /proc/uptime
    r11_u2_rc=$LAST_RC

    R11_BOOT_ID=""
    r11_ok=0
    r11_detail=""
    if [[ $r11_b1_rc -eq 0 && $r11_u1_rc -eq 0 && $r11_b2_rc -eq 0 && $r11_u2_rc -eq 0 ]]; then
        r11_parsed="$(
            /usr/bin/python3 - \
                "$TMP_ROOT/r11-boot1.out" "$TMP_ROOT/r11-boot1.err" \
                "$TMP_ROOT/r11-up1.out" "$TMP_ROOT/r11-up1.err" \
                "$TMP_ROOT/r11-boot2.out" "$TMP_ROOT/r11-boot2.err" \
                "$TMP_ROOT/r11-up2.out" "$TMP_ROOT/r11-up2.err" <<'PY'
import os, re, sys

b1_out, b1_err, u1_out, u1_err, b2_out, b2_err, u2_out, u2_err = sys.argv[1:9]
for err_p in (b1_err, u1_err, b2_err, u2_err):
    if os.path.getsize(err_p) != 0:
        sys.exit(1)

boot1 = open(b1_out, encoding="utf-8").read().strip()
boot2 = open(b2_out, encoding="utf-8").read().strip()
uuid_re = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
if not boot1 or boot1 != boot2 or not uuid_re.match(boot1):
    sys.exit(1)

u1_parts = open(u1_out, encoding="utf-8").read().strip().split()
u2_parts = open(u2_out, encoding="utf-8").read().strip().split()
if not u1_parts or not u2_parts:
    sys.exit(1)
u1 = float(u1_parts[0])
u2 = float(u2_parts[0])
if not (u2 > u1):
    sys.exit(1)

print(boot1)
print(f"uptime {u1:.2f}s -> {u2:.2f}s")
PY
        )" && r11_ok=1 || r11_ok=0
        if [[ $r11_ok -eq 1 ]]; then
            R11_BOOT_ID="$(printf '%s\n' "$r11_parsed" | sed -n '1p')"
            r11_detail="$(printf '%s\n' "$r11_parsed" | sed -n '2p')"
        fi
    fi

    if [[ $r11_ok -eq 1 && -n "$R11_BOOT_ID" ]]; then
        pass_row 11 "two separate exec calls >5s apart returned identical UUID boot_id=$R11_BOOT_ID ($r11_detail)."
    else
        fail_row 11 "rcs=[$r11_b1_rc,$r11_u1_rc,$r11_b2_rc,$r11_u2_rc], b1='$(cat "$TMP_ROOT/r11-boot1.out" 2>/dev/null | tr -d '\n')', b2='$(cat "$TMP_ROOT/r11-boot2.out" 2>/dev/null | tr -d '\n')', err='$(cat "$TMP_ROOT/r11-boot1.err" 2>/dev/null | tr '\n' ' ')'"
    fi

    # --------------------------------------------------------------
    # Row 12: Run `up t1` again while already running
    #   Expect: exits 0; boot_id unchanged; VirtualMachine process count unchanged.
    # --------------------------------------------------------------
    ROW_START_SEC="$(now_sec)"
    run_cli "$TMP_ROOT/r12-up.out" "$TMP_ROOT/r12-up.err" --lang en --workspace "$WS" up t1
    r12_up_rc=$LAST_RC
    r12_up_elapsed="$LAST_ELAPSED_SEC"

    run_cli "$TMP_ROOT/r12-boot.out" "$TMP_ROOT/r12-boot.err" --lang en --workspace "$WS" exec t1 -- cat /proc/sys/kernel/random/boot_id
    r12_boot_rc=$LAST_RC
    r12_boot_id="$(tr -d '[:space:]' < "$TMP_ROOT/r12-boot.out" 2>/dev/null || true)"
    r12_boot_err="$(cat "$TMP_ROOT/r12-boot.err" 2>/dev/null || true)"

    r12_extra_vz="$(list_extra_vz_pids)"
    r12_extra_vz_count="$(count_lines_nonempty "$r12_extra_vz")"

    if [[ $r12_up_rc -eq 0 && $r12_boot_rc -eq 0 && -z "$r12_boot_err" \
        && -n "$R11_BOOT_ID" && "$r12_boot_id" == "$R11_BOOT_ID" \
        && "$r12_extra_vz_count" == "1" && -n "$T1_VZ_PID" && "$r12_extra_vz" == "$T1_VZ_PID" ]]; then
        pass_row 12 "idempotent 'up t1' (${r12_up_elapsed}s) exited 0; boot_id unchanged ($r12_boot_id); extra VirtualMachine PIDs=1 (pid=$T1_VZ_PID)."
    else
        fail_row 12 "up_rc=$r12_up_rc, boot_rc=$r12_boot_rc, boot_id='$r12_boot_id' (expected '$R11_BOOT_ID'), extra_vz='${r12_extra_vz//$'\n'/,}' (expected '$T1_VZ_PID'), boot_err='$r12_boot_err'"
    fi

    # --------------------------------------------------------------
    # Row 13: Two concurrent background `exec t1 -- sleep 3`
    #   Expect: both exit 0; total wall-clock from spawning first to both finishing < 5s.
    # --------------------------------------------------------------
    ROW_START_SEC="$(now_sec)"
    ensure_cli_subcommand --lang en --workspace "$WS" exec t1 -- sleep 3
    : >"$TMP_ROOT/r13-1.out"; : >"$TMP_ROOT/r13-1.err"
    : >"$TMP_ROOT/r13-2.out"; : >"$TMP_ROOT/r13-2.err"
    r13_t0="$(now_sec)"

    (
        exec /usr/bin/env -u AGENTVM_WORKSPACE -u AGENTVM_REAL_VM -u AGENTVM_LANG \
            HOME="$ISOLATED_HOME" \
            CFFIXED_USER_HOME="$ISOLATED_HOME" \
            AGENTVM_IMAGE_CACHE="$IMAGE_CACHE_DIR" \
            /usr/bin/perl -e 'alarm $ARGV[0]; shift @ARGV; exec @ARGV' \
            "$CMD_TIMEOUT_SEC" \
            "$AGENTVM_BIN_RESOLVED" --lang en --workspace "$WS" exec t1 -- sleep 3
    ) </dev/null >"$TMP_ROOT/r13-1.out" 2>"$TMP_ROOT/r13-1.err" &
    r13_pid1=$!
    OWN_CLIENT_PIDS+=("$r13_pid1")

    (
        exec /usr/bin/env -u AGENTVM_WORKSPACE -u AGENTVM_REAL_VM -u AGENTVM_LANG \
            HOME="$ISOLATED_HOME" \
            CFFIXED_USER_HOME="$ISOLATED_HOME" \
            AGENTVM_IMAGE_CACHE="$IMAGE_CACHE_DIR" \
            /usr/bin/perl -e 'alarm $ARGV[0]; shift @ARGV; exec @ARGV' \
            "$CMD_TIMEOUT_SEC" \
            "$AGENTVM_BIN_RESOLVED" --lang en --workspace "$WS" exec t1 -- sleep 3
    ) </dev/null >"$TMP_ROOT/r13-2.out" 2>"$TMP_ROOT/r13-2.err" &
    r13_pid2=$!
    OWN_CLIENT_PIDS+=("$r13_pid2")

    r13_rc1=0; wait "$r13_pid1" 2>/dev/null || r13_rc1=$?
    r13_rc2=0; wait "$r13_pid2" 2>/dev/null || r13_rc2=$?
    r13_t1="$(now_sec)"
    r13_elapsed="$(diff_sec "$r13_t0" "$r13_t1")"
    r13_under_5s="$(/usr/bin/python3 -c 'import sys; print(1 if float(sys.argv[1]) < 5.0 else 0)' "$r13_elapsed")"

    if [[ $r13_rc1 -eq 0 && $r13_rc2 -eq 0 && $r13_under_5s -eq 1 \
        && ! -s "$TMP_ROOT/r13-1.out" && ! -s "$TMP_ROOT/r13-1.err" \
        && ! -s "$TMP_ROOT/r13-2.out" && ! -s "$TMP_ROOT/r13-2.err" ]]; then
        pass_row 13 "two concurrent 'exec t1 -- sleep 3' both exited 0 in ${r13_elapsed}s (<5.0s)."
    else
        fail_row 13 "rc1=$r13_rc1, rc2=$r13_rc2, elapsed=${r13_elapsed}s, err1='$(cat "$TMP_ROOT/r13-1.err" 2>/dev/null)', err2='$(cat "$TMP_ROOT/r13-2.err" 2>/dev/null)'"
    fi

    # --------------------------------------------------------------
    # Row 14: Concurrent `exec t1 -- sh -c 'yes A | head -c 1048576'` and `yes B | head -c 1048576`
    #   Expect: both exit 0; each stdout is exactly 1048576 bytes containing only its own letter + newline.
    # --------------------------------------------------------------
    ROW_START_SEC="$(now_sec)"
    ensure_cli_subcommand --lang en --workspace "$WS" exec t1 -- sh -c 'true'
    : >"$TMP_ROOT/r14-a.out"; : >"$TMP_ROOT/r14-a.err"
    : >"$TMP_ROOT/r14-b.out"; : >"$TMP_ROOT/r14-b.err"
    r14_t0="$(now_sec)"

    (
        exec /usr/bin/env -u AGENTVM_WORKSPACE -u AGENTVM_REAL_VM -u AGENTVM_LANG \
            HOME="$ISOLATED_HOME" \
            CFFIXED_USER_HOME="$ISOLATED_HOME" \
            AGENTVM_IMAGE_CACHE="$IMAGE_CACHE_DIR" \
            /usr/bin/perl -e 'alarm $ARGV[0]; shift @ARGV; exec @ARGV' \
            "$CMD_TIMEOUT_SEC" \
            "$AGENTVM_BIN_RESOLVED" --lang en --workspace "$WS" exec t1 -- sh -c 'yes A | head -c 1048576'
    ) </dev/null >"$TMP_ROOT/r14-a.out" 2>"$TMP_ROOT/r14-a.err" &
    r14_pida=$!
    OWN_CLIENT_PIDS+=("$r14_pida")

    (
        exec /usr/bin/env -u AGENTVM_WORKSPACE -u AGENTVM_REAL_VM -u AGENTVM_LANG \
            HOME="$ISOLATED_HOME" \
            CFFIXED_USER_HOME="$ISOLATED_HOME" \
            AGENTVM_IMAGE_CACHE="$IMAGE_CACHE_DIR" \
            /usr/bin/perl -e 'alarm $ARGV[0]; shift @ARGV; exec @ARGV' \
            "$CMD_TIMEOUT_SEC" \
            "$AGENTVM_BIN_RESOLVED" --lang en --workspace "$WS" exec t1 -- sh -c 'yes B | head -c 1048576'
    ) </dev/null >"$TMP_ROOT/r14-b.out" 2>"$TMP_ROOT/r14-b.err" &
    r14_pidb=$!
    OWN_CLIENT_PIDS+=("$r14_pidb")

    r14_rca=0; wait "$r14_pida" 2>/dev/null || r14_rca=$?
    r14_rcb=0; wait "$r14_pidb" 2>/dev/null || r14_rcb=$?
    r14_t1="$(now_sec)"
    r14_elapsed="$(diff_sec "$r14_t0" "$r14_t1")"

    r14_streams_ok=0
    if [[ $r14_rca -eq 0 && $r14_rcb -eq 0 ]]; then
        /usr/bin/python3 - \
            "$TMP_ROOT/r14-a.out" "$TMP_ROOT/r14-a.err" \
            "$TMP_ROOT/r14-b.out" "$TMP_ROOT/r14-b.err" <<'PY' && r14_streams_ok=1 || r14_streams_ok=0
import os, sys

a_out, a_err, b_out, b_err = sys.argv[1:5]
if os.path.getsize(a_err) != 0 or os.path.getsize(b_err) != 0:
    sys.exit(1)
da = open(a_out, "rb").read()
db = open(b_out, "rb").read()
if len(da) != 1048576 or len(db) != 1048576:
    sys.exit(1)
if da != (b"A\n" * 524288) or db != (b"B\n" * 524288):
    sys.exit(1)
PY
    fi

    if [[ $r14_streams_ok -eq 1 ]]; then
        pass_row 14 "concurrent 1 MiB streams A & B both exited 0 in ${r14_elapsed}s (1048576 bytes each, zero interleaving)."
    else
        fail_row 14 "rca=$r14_rca, rcb=$r14_rcb, len_a=$(wc -c < "$TMP_ROOT/r14-a.out" | tr -d ' '), len_b=$(wc -c < "$TMP_ROOT/r14-b.out" | tr -d ' '), erra='$(cat "$TMP_ROOT/r14-a.err" 2>/dev/null)', errb='$(cat "$TMP_ROOT/r14-b.err" 2>/dev/null)'"
    fi

    # --------------------------------------------------------------
    # Row 15: `exec t1 -- sh -c 'head -c 1048576 /dev/urandom > /tmp/r; sha256sum /tmp/r >&2; cat /tmp/r'`
    #   Expect: stdout is exactly 1048576 bytes and host SHA-256 equals guest SHA-256 printed on stderr.
    # --------------------------------------------------------------
    ROW_START_SEC="$(now_sec)"
    run_cli "$TMP_ROOT/r15.out" "$TMP_ROOT/r15.err" --lang en --workspace "$WS" \
        exec t1 -- sh -c 'head -c 1048576 /dev/urandom > /tmp/r; sha256sum /tmp/r >&2; cat /tmp/r'
    r15_rc=$LAST_RC
    r15_elapsed="$LAST_ELAPSED_SEC"

    r15_ok=0
    r15_sha=""
    if [[ $r15_rc -eq 0 ]]; then
        r15_sha="$(
            /usr/bin/python3 - "$TMP_ROOT/r15.out" "$TMP_ROOT/r15.err" <<'PY'
import hashlib, re, sys

raw = open(sys.argv[1], "rb").read()
if len(raw) != 1048576:
    sys.exit(1)
host_sha = hashlib.sha256(raw).hexdigest().lower()

err_txt = open(sys.argv[2], encoding="utf-8", errors="replace").read().strip()
m = re.match(r"^([0-9a-fA-F]{64})\s+/tmp/r$", err_txt)
if not m:
    sys.exit(1)
guest_sha = m.group(1).lower()
if host_sha != guest_sha:
    sys.exit(1)
print(host_sha)
PY
        )" && r15_ok=1 || r15_ok=0
    fi

    if [[ $r15_ok -eq 1 && -n "$r15_sha" ]]; then
        pass_row 15 "1 MiB random binary stream (${r15_elapsed}s) matched guest SHA-256 ($r15_sha)."
    else
        fail_row 15 "rc=$r15_rc, out_bytes=$(wc -c < "$TMP_ROOT/r15.out" | tr -d ' '), stderr='$(cat "$TMP_ROOT/r15.err" 2>/dev/null | tr '\n' ' ')'"
    fi

    # --------------------------------------------------------------
    # Row 16: `exec t1 -- sh -c 'echo out; echo err >&2; exit 7'`; `exec t1 -- sh -c 'kill -9 $$'`
    #   Expect: first has exact stdout `out\n`, exact stderr `err\n`, exit code 7; second has exit code 137.
    # --------------------------------------------------------------
    ROW_START_SEC="$(now_sec)"
    run_cli "$TMP_ROOT/r16-1.out" "$TMP_ROOT/r16-1.err" --lang en --workspace "$WS" \
        exec t1 -- sh -c 'echo out; echo err >&2; exit 7'
    r16_rc1=$LAST_RC

    run_cli "$TMP_ROOT/r16-2.out" "$TMP_ROOT/r16-2.err" --lang en --workspace "$WS" \
        exec t1 -- sh -c 'kill -9 $$'
    r16_rc2=$LAST_RC

    r16_exact=0
    if [[ $r16_rc1 -eq 7 && $r16_rc2 -eq 137 ]]; then
        /usr/bin/python3 - \
            "$TMP_ROOT/r16-1.out" "$TMP_ROOT/r16-1.err" \
            "$TMP_ROOT/r16-2.out" <<'PY' && r16_exact=1 || r16_exact=0
import sys

o1 = open(sys.argv[1], "rb").read()
e1 = open(sys.argv[2], "rb").read()
o2 = open(sys.argv[3], "rb").read()
if o1 != b"out\n" or e1 != b"err\n" or o2 != b"":
    sys.exit(1)
PY
    fi

    if [[ $r16_exact -eq 1 ]]; then
        pass_row 16 "first exec returned exact stdout='out\\n', stderr='err\\n', exit=7; second exec (SIGKILL) returned exit=137."
    else
        fail_row 16 "rc1=$r16_rc1 (expected 7), rc2=$r16_rc2 (expected 137), out1='$(cat "$TMP_ROOT/r16-1.out" 2>/dev/null)', err1='$(cat "$TMP_ROOT/r16-1.err" 2>/dev/null)'"
    fi

    # Row 17 requires guest daemon v2 RST process-group termination (Stage 5); Rows 18-21 require telemetry (Stages 5-6).
    unrun_row 17 "客户机脚本处理 RST 是第 5 段"
    unrun_row 18 "遥测映射（guestMemTotalBytes）是第 6 段"
    unrun_row 19 "客户机 CPU 占用率遥测是第 5-6 段"
    unrun_row 20 "客户机内存驻留遥测是第 6 段"
    unrun_row 21 "遥测刷新与过期是第 6 段"

    # --------------------------------------------------------------
    # Row 22: While daemon holds `t1`, `run t1 -- true`
    #   Expect: exits 125 with ERR_VM_LOCKED; t1 still running and boot_id unchanged.
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

    run_cli "$TMP_ROOT/r22-boot.out" "$TMP_ROOT/r22-boot.err" --lang en --workspace "$WS" exec t1 -- cat /proc/sys/kernel/random/boot_id
    r22_boot_rc=$LAST_RC
    r22_boot_id="$(tr -d '[:space:]' < "$TMP_ROOT/r22-boot.out" 2>/dev/null || true)"

    r22_extra_vz="$(list_extra_vz_pids)"
    r22_extra_vz_count="$(count_lines_nonempty "$r22_extra_vz")"

    if [[ $r22_rc -eq 125 && -z "$r22_out" && "$r22_err" == *"ERR_VM_LOCKED"* \
        && $r22_t1_running -eq 1 && $r22_boot_rc -eq 0 \
        && -n "$R11_BOOT_ID" && "$r22_boot_id" == "$R11_BOOT_ID" \
        && "$r22_extra_vz_count" == "1" && -n "$T1_VZ_PID" && "$r22_extra_vz" == "$T1_VZ_PID" ]]; then
        pass_row 22 "'run t1 -- true' exited 125 with ERR_VM_LOCKED; t1 still running on pid=$T1_VZ_PID with unchanged boot_id=$r22_boot_id."
    else
        fail_row 22 "rc=$r22_rc, out_len=${#r22_out}, t1_running=$r22_t1_running, boot_rc=$r22_boot_rc, boot_id='$r22_boot_id' (expected '$R11_BOOT_ID'), extra_vz='${r22_extra_vz//$'\n'/,}' (expected '$T1_VZ_PID'), err='$r22_err'"
    fi

    # --------------------------------------------------------------
    # Row 23: While `t1` is running, `snapshot t1` and `restore <t1 snapshot>`
    #   Expect: both exit 1 with ERR_VM_LOCKED mentioning M3; t1 root disk inode unchanged; boot_id unchanged.
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

    run_cli "$TMP_ROOT/r23-boot.out" "$TMP_ROOT/r23-boot.err" --lang en --workspace "$WS" exec t1 -- cat /proc/sys/kernel/random/boot_id
    r23_boot_rc=$LAST_RC
    r23_boot_id="$(tr -d '[:space:]' < "$TMP_ROOT/r23-boot.out" 2>/dev/null || true)"

    r23_extra_vz="$(list_extra_vz_pids)"

    if [[ $r23_snap_rc -eq 1 && "$r23_snap_err" == *"ERR_VM_LOCKED"* && "$r23_snap_err" == *"M3"* \
        && $r23_restore_rc -eq 1 && "$r23_restore_err" == *"ERR_VM_LOCKED"* && "$r23_restore_err" == *"M3"* \
        && -n "$r23_ino_before" && "$r23_ino_before" == "$r23_ino_after" \
        && $r23_t1_running -eq 1 && $r23_boot_rc -eq 0 \
        && -n "$R11_BOOT_ID" && "$r23_boot_id" == "$R11_BOOT_ID" \
        && -n "$T1_VZ_PID" && "$r23_extra_vz" == "$T1_VZ_PID" ]]; then
        pass_row 23 "'snapshot t1' and 'restore $T1_SNAP_ID' both exited 1 with ERR_VM_LOCKED mentioning M3; disk inode unchanged ($r23_ino_after); boot_id unchanged ($r23_boot_id)."
    else
        fail_row 23 "snap_rc=$r23_snap_rc, restore_rc=$r23_restore_rc, ino='$r23_ino_before'->'$r23_ino_after', t1_running=$r23_t1_running, boot_rc=$r23_boot_rc, boot_id='$r23_boot_id' (expected '$R11_BOOT_ID'), extra_vz='${r23_extra_vz//$'\n'/,}'"
    fi

    # --------------------------------------------------------------
    # Row 24: `pause t1`; `exec t1 -- true`; `resume t1`; `exec t1 -- cat /proc/sys/kernel/random/boot_id`
    #   Expect: `pause` exits 0, `ps --json` is paused, after 15s telemetry is '—';
    #           `exec` while paused exits 125 (ERR_LIFECYCLE_STATE, hints resume);
    #           `resume` exits 0; boot_id equals Row 11.
    # --------------------------------------------------------------
    ROW_START_SEC="$(now_sec)"
    run_cli "$TMP_ROOT/r24-pause.out" "$TMP_ROOT/r24-pause.err" --lang en --workspace "$WS" pause t1
    r24_pause_rc=$LAST_RC

    run_cli "$TMP_ROOT/r24-ps1.json" "$TMP_ROOT/r24-ps1.err" --lang en --workspace "$WS" ps --json
    r24_ps1_rc=$LAST_RC
    r24_paused_ok=0
    if [[ $r24_ps1_rc -eq 0 ]]; then
        /usr/bin/python3 - "$TMP_ROOT/r24-ps1.json" <<'PY' && r24_paused_ok=1 || r24_paused_ok=0
import json, sys

vms = json.load(open(sys.argv[1], encoding="utf-8"))
t1 = [v for v in vms if v.get("spec", {}).get("name") == "t1"]
if len(t1) != 1 or t1[0].get("telemetry", {}).get("state") != "paused":
    sys.exit(1)
PY
    fi

    sleep 15.5

    run_cli "$TMP_ROOT/r24-ps2.json" "$TMP_ROOT/r24-ps2.err" --lang en --workspace "$WS" ps --json
    r24_ps2_rc=$LAST_RC
    run_cli "$TMP_ROOT/r24-ps2.txt" "$TMP_ROOT/r24-ps2t.err" --lang en --workspace "$WS" ps
    r24_ps2t_rc=$LAST_RC
    r24_tel_dash_ok=0
    if [[ $r24_ps2_rc -eq 0 && $r24_ps2t_rc -eq 0 ]]; then
        /usr/bin/python3 - "$TMP_ROOT/r24-ps2.json" "$TMP_ROOT/r24-ps2.txt" "$T1_ID" <<'PY' && r24_tel_dash_ok=1 || r24_tel_dash_ok=0
import json, sys

vms = json.load(open(sys.argv[1], encoding="utf-8"))
t1 = [v for v in vms if v.get("spec", {}).get("name") == "t1"]
if len(t1) != 1:
    sys.exit(1)
tel = t1[0].get("telemetry", {})
if tel.get("state") != "paused" or tel.get("hasLiveGuestTelemetry") is not False:
    sys.exit(1)

lines = [ln.rstrip("\r\n") for ln in open(sys.argv[2], encoding="utf-8") if ln.strip()]
t1_id = sys.argv[3].strip()
if len(lines) < 2:
    sys.exit(1)
header = lines[0]
state_idx = header.index("STATE")
cpu_idx = header.index("CPU")
mem_idx = header.index("MEMORY")
ip_idx = header.index("IPV4")
matched = [ln for ln in lines[1:] if (t1_id and ln.startswith(t1_id + " ")) or (" t1 " in ln)]
if len(matched) != 1:
    sys.exit(1)
row = matched[0]
if row[state_idx:cpu_idx].strip() != "paused" or row[cpu_idx:mem_idx].strip() != "—" or row[mem_idx:ip_idx].strip() != "—":
    sys.exit(1)
PY
    fi

    run_cli "$TMP_ROOT/r24-exec-paused.out" "$TMP_ROOT/r24-exec-paused.err" --lang en --workspace "$WS" exec t1 -- true
    r24_exec_paused_rc=$LAST_RC
    r24_exec_paused_out="$(cat "$TMP_ROOT/r24-exec-paused.out")"
    r24_exec_paused_err="$(cat "$TMP_ROOT/r24-exec-paused.err")"

    run_cli "$TMP_ROOT/r24-resume.out" "$TMP_ROOT/r24-resume.err" --lang en --workspace "$WS" resume t1
    r24_resume_rc=$LAST_RC

    run_cli "$TMP_ROOT/r24-boot.out" "$TMP_ROOT/r24-boot.err" --lang en --workspace "$WS" exec t1 -- cat /proc/sys/kernel/random/boot_id
    r24_boot_rc=$LAST_RC
    r24_boot_id="$(tr -d '[:space:]' < "$TMP_ROOT/r24-boot.out" 2>/dev/null || true)"

    if [[ $r24_pause_rc -eq 0 && $r24_paused_ok -eq 1 && $r24_tel_dash_ok -eq 1 \
        && $r24_exec_paused_rc -eq 125 && -z "$r24_exec_paused_out" \
        && "$r24_exec_paused_err" == *"ERR_LIFECYCLE_STATE"* \
        && "$r24_exec_paused_err" == *"paused"* \
        && "$r24_exec_paused_err" == *"resume"* \
        && $r24_resume_rc -eq 0 && $r24_boot_rc -eq 0 \
        && -n "$R11_BOOT_ID" && "$r24_boot_id" == "$R11_BOOT_ID" ]]; then
        pass_row 24 "'pause t1' exited 0; ps --json=paused & >15s telemetry='—'; 'exec t1 -- true' exited 125 (ERR_LIFECYCLE_STATE + resume hint); 'resume t1' exited 0; boot_id unchanged ($r24_boot_id)."
    else
        fail_row 24 "pause=$r24_pause_rc, paused_ok=$r24_paused_ok, tel_dash=$r24_tel_dash_ok, exec_paused=$r24_exec_paused_rc, resume=$r24_resume_rc, boot_rc=$r24_boot_rc, boot_id='$r24_boot_id' (expected '$R11_BOOT_ID'), exec_err='$r24_exec_paused_err'"
    fi

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
    # Row 26: `halt t1`
    #   Expect: exits 0; within 30s t1's VirtualMachine process exits; `ps --json` is stopped;
    #           plain `ps` CPU and MEMORY columns are '—'; `exec t1 -- true` exits 125
    #           (ERR_LIFECYCLE_STATE, stopped, hints up); daemon still running (`daemon status` exits 0).
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

    run_cli "$TMP_ROOT/r26-exec.out" "$TMP_ROOT/r26-exec.err" --lang en --workspace "$WS" exec t1 -- true
    r26_exec_rc=$LAST_RC
    r26_exec_out="$(cat "$TMP_ROOT/r26-exec.out")"
    r26_exec_err="$(cat "$TMP_ROOT/r26-exec.err")"

    run_cli "$TMP_ROOT/r26-dstatus.out" "$TMP_ROOT/r26-dstatus.err" --lang en --workspace "$WS" daemon status
    r26_dstatus_rc=$LAST_RC
    r26_daemon_pids="$(find_workspace_daemon_pids "$WS")"
    r26_daemon_count="$(count_lines_nonempty "$r26_daemon_pids")"

    if [[ $r26_halt_rc -eq 0 && $r26_vz_gone -eq 1 && $r26_psj_ok -eq 1 \
        && $r26_pst_ok -eq 1 \
        && $r26_exec_rc -eq 125 && -z "$r26_exec_out" \
        && "$r26_exec_err" == *"ERR_LIFECYCLE_STATE"* \
        && "$r26_exec_err" == *"stopped"* \
        && "$r26_exec_err" == *"up"* \
        && $r26_dstatus_rc -eq 0 && "$r26_daemon_count" == "1" ]]; then
        pass_row 26 "'halt t1' exited 0; t1 VirtualMachine process exited in ${r26_vz_elapsed}s (<30s); ps --json=stopped; plain ps CPU='—' & MEMORY='—'; 'exec t1 -- true' exited 125 (ERR_LIFECYCLE_STATE + up hint); daemon still alive ('daemon status' exited 0)."
    else
        fail_row 26 "halt_rc=$r26_halt_rc, vz_gone=$r26_vz_gone, psj_ok=$r26_psj_ok, pst_ok=$r26_pst_ok, exec_rc=$r26_exec_rc, exec_err='$r26_exec_err', dstatus_rc=$r26_dstatus_rc, daemon_count=$r26_daemon_count"
    fi

    # --------------------------------------------------------------
    # Row 27: Boot `t1` again via `up t1` and read `boot_id`
    #   Expect: exits 0; new boot_id is a valid UUID and differs from Row 11.
    # --------------------------------------------------------------
    ROW_START_SEC="$(now_sec)"
    run_cli "$TMP_ROOT/r27-up.out" "$TMP_ROOT/r27-up.err" --lang en --workspace "$WS" up t1
    r27_up_rc=$LAST_RC
    r27_up_elapsed="$LAST_ELAPSED_SEC"

    r27_extra_vz="$(list_extra_vz_pids)"
    r27_extra_vz_count="$(count_lines_nonempty "$r27_extra_vz")"
    if [[ "$r27_extra_vz_count" == "1" ]]; then
        T1_VZ_PID="$r27_extra_vz"
    fi

    run_cli "$TMP_ROOT/r27-boot.out" "$TMP_ROOT/r27-boot.err" --lang en --workspace "$WS" exec t1 -- cat /proc/sys/kernel/random/boot_id
    r27_boot_rc=$LAST_RC
    r27_boot_id=""
    r27_boot_ok=0
    if [[ $r27_boot_rc -eq 0 && ! -s "$TMP_ROOT/r27-boot.err" ]]; then
        r27_boot_id="$(
            /usr/bin/python3 - "$TMP_ROOT/r27-boot.out" "$R11_BOOT_ID" <<'PY'
import re, sys

new_id = open(sys.argv[1], encoding="utf-8").read().strip()
old_id = sys.argv[2].strip()
uuid_re = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
if not new_id or not old_id or not uuid_re.match(new_id) or new_id == old_id:
    sys.exit(1)
print(new_id)
PY
        )" && r27_boot_ok=1 || r27_boot_ok=0
    fi

    if [[ $r27_up_rc -eq 0 && $r27_boot_ok -eq 1 && "$r27_extra_vz_count" == "1" ]]; then
        pass_row 27 "'up t1' (${r27_up_elapsed}s) exited 0; new boot_id=$r27_boot_id differs from Row 11 ($R11_BOOT_ID)."
    else
        fail_row 27 "up_rc=$r27_up_rc, boot_rc=$r27_boot_rc, boot_ok=$r27_boot_ok, old_boot='$R11_BOOT_ID', new_boot='$(cat "$TMP_ROOT/r27-boot.out" 2>/dev/null | tr -d '\n')', extra_vz_count=$r27_extra_vz_count"
    fi

    # --------------------------------------------------------------
    # Row 28: `exec t1 -- systemctl poweroff` (ignore its exit code)
    #   Expect: within 30s t1's VirtualMachine process exits; `ps --json` is stopped;
    #           `events --vm t1 --json` has `VM_STOPPED_BY_GUEST`; lock released so subsequent
    #           `run t1 -- true` exits 0.
    # --------------------------------------------------------------
    ROW_START_SEC="$(now_sec)"
    r28_t0="$(now_sec)"
    run_cli "$TMP_ROOT/r28-poweroff.out" "$TMP_ROOT/r28-poweroff.err" --lang en --workspace "$WS" exec t1 -- systemctl poweroff
    r28_exec_rc=$LAST_RC

    r28_vz_gone=0
    if wait_for_extra_vz_count 0 30; then
        r28_vz_gone=1
    fi
    r28_t1="$(now_sec)"
    r28_vz_elapsed="$(diff_sec "$r28_t0" "$r28_t1")"

    r28_ps_stopped=0
    r28_ps_ticks=0
    while (( r28_ps_ticks <= 50 )); do
        run_cli "$TMP_ROOT/r28-ps.json" "$TMP_ROOT/r28-ps.err" --lang en --workspace "$WS" ps --json
        if [[ $LAST_RC -eq 0 ]]; then
            if /usr/bin/python3 - "$TMP_ROOT/r28-ps.json" <<'PY'
import json, sys

vms = json.load(open(sys.argv[1], encoding="utf-8"))
t1 = [v for v in vms if v.get("spec", {}).get("name") == "t1"]
if len(t1) != 1:
    sys.exit(1)
tel = t1[0].get("telemetry", {})
if tel.get("state") != "stopped" or tel.get("guestAgentConnected") is not False:
    sys.exit(1)
PY
            then
                r28_ps_stopped=1
                break
            fi
        fi
        sleep 0.1
        r28_ps_ticks=$((r28_ps_ticks + 1))
    done

    run_cli "$TMP_ROOT/r28-events.json" "$TMP_ROOT/r28-events.err" --lang en --workspace "$WS" events --vm t1 --json
    r28_ev_rc=$LAST_RC
    r28_ev_ok=0
    if [[ $r28_ev_rc -eq 0 ]]; then
        /usr/bin/python3 - "$TMP_ROOT/r28-events.json" "$T1_ID" <<'PY' && r28_ev_ok=1 || r28_ev_ok=0
import json, sys

events = json.load(open(sys.argv[1], encoding="utf-8"))
t1_id = sys.argv[2].strip()
matched = [
    ev for ev in events
    if ev.get("code") == "VM_STOPPED_BY_GUEST" and (not t1_id or ev.get("vmID") == t1_id)
]
if not matched:
    sys.exit(1)
PY
    fi

    run_cli "$TMP_ROOT/r28-run.out" "$TMP_ROOT/r28-run.err" --lang en --workspace "$WS" run t1 -- true
    r28_run_rc=$LAST_RC
    r28_run_elapsed="$LAST_ELAPSED_SEC"
    r28_run_out="$(cat "$TMP_ROOT/r28-run.out")"
    r28_run_err="$(cat "$TMP_ROOT/r28-run.err")"
    r28_post_run_vz_gone=0
    if wait_for_extra_vz_count 0 30; then
        r28_post_run_vz_gone=1
    fi

    if [[ $r28_vz_gone -eq 1 && $r28_ps_stopped -eq 1 && $r28_ev_ok -eq 1 \
        && $r28_run_rc -eq 0 && -z "$r28_run_out" && -z "$r28_run_err" && $r28_post_run_vz_gone -eq 1 ]]; then
        pass_row 28 "'exec t1 -- systemctl poweroff' (rc=$r28_exec_rc): VirtualMachine exited in ${r28_vz_elapsed}s (<30s); ps --json=stopped; events has VM_STOPPED_BY_GUEST; lock released ('run t1 -- true' exited 0 in ${r28_run_elapsed}s)."
    else
        fail_row 28 "vz_gone=$r28_vz_gone (${r28_vz_elapsed}s), ps_stopped=$r28_ps_stopped, ev_ok=$r28_ev_ok, run_rc=$r28_run_rc, run_err='$r28_run_err'"
    fi

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

    # --------------------------------------------------------------
    # Row 30: `kill -9` workspace daemon while both `t1` and `t2` are running
    #   Expect: within 30s both VirtualMachine processes exit; `ps --json` reports both
    #           t1 and t2 as `stopped` without spawning a new daemon; `events --json` has
    #           1 new `VM_RUNTIME_LOST` for t1 and 1 new `VM_RUNTIME_LOST` for t2.
    # --------------------------------------------------------------
    ROW_START_SEC="$(now_sec)"
    run_cli "$TMP_ROOT/r30-ps-pre.json" "$TMP_ROOT/r30-ps-pre.err" --lang en --workspace "$WS" ps --json
    if [[ $LAST_RC -eq 0 ]]; then
        T2_ID="$(
            /usr/bin/python3 - "$TMP_ROOT/r30-ps-pre.json" <<'PY'
import json, sys
vms = json.load(open(sys.argv[1], encoding="utf-8"))
t2 = [v for v in vms if v.get("spec", {}).get("name") == "t2"]
print(t2[0].get("spec", {}).get("id", "") if len(t2) == 1 else "")
PY
        )"
    fi

    run_cli "$TMP_ROOT/r30-ev-pre.json" "$TMP_ROOT/r30-ev-pre.err" --lang en --workspace "$WS" events --json
    r30_ev_pre_rc=$LAST_RC

    r30_daemon_pids="$(find_workspace_daemon_pids "$WS")"
    r30_daemon_count="$(count_lines_nonempty "$r30_daemon_pids")"
    r30_killed_pid=""
    if [[ "$r30_daemon_count" == "1" ]] && is_pid_currently_agentvm_bin "$r30_daemon_pids"; then
        r30_killed_pid="$r30_daemon_pids"
    fi

    r30_t0="$(now_sec)"
    if [[ -n "$r30_killed_pid" ]]; then
        kill -KILL "$r30_killed_pid" 2>/dev/null || true
        r30_wait=0
        while (( r30_wait < 50 )); do
            if ! kill -0 "$r30_killed_pid" 2>/dev/null; then
                break
            fi
            sleep 0.05
            r30_wait=$((r30_wait + 1))
        done
    fi

    r30_vz_gone=0
    if [[ -n "$r30_killed_pid" ]] && wait_for_extra_vz_count 0 30; then
        r30_vz_gone=1
    fi
    r30_t1="$(now_sec)"
    r30_vz_elapsed="$(diff_sec "$r30_t0" "$r30_t1")"

    run_cli "$TMP_ROOT/r30-ps.json" "$TMP_ROOT/r30-ps.err" --lang en --workspace "$WS" ps --json
    r30_ps_rc=$LAST_RC
    r30_daemons_after_ps="$(find_workspace_daemon_pids "$WS")"
    run_cli "$TMP_ROOT/r30-dstatus.out" "$TMP_ROOT/r30-dstatus.err" --lang en --workspace "$WS" daemon status
    r30_dstatus_rc=$LAST_RC

    r30_ps_stopped_ok=0
    if [[ $r30_ps_rc -eq 0 ]]; then
        /usr/bin/python3 - "$TMP_ROOT/r30-ps.json" <<'PY' && r30_ps_stopped_ok=1 || r30_ps_stopped_ok=0
import json, sys

vms = json.load(open(sys.argv[1], encoding="utf-8"))
by_name = {v.get("spec", {}).get("name"): v for v in vms}
for name in ("t1", "t2"):
    v = by_name.get(name)
    if not v:
        sys.exit(1)
    tel = v.get("telemetry", {})
    if tel.get("state") != "stopped" or tel.get("guestAgentConnected") is not False:
        sys.exit(1)
PY
    fi

    run_cli "$TMP_ROOT/r30-ev-post.json" "$TMP_ROOT/r30-ev-post.err" --lang en --workspace "$WS" events --json
    r30_ev_post_rc=$LAST_RC
    r30_daemons_after_ev="$(find_workspace_daemon_pids "$WS")"

    r30_lost_ok=0
    if [[ $r30_ev_pre_rc -eq 0 && $r30_ev_post_rc -eq 0 && -n "$T1_ID" && -n "$T2_ID" ]]; then
        /usr/bin/python3 - \
            "$TMP_ROOT/r30-ev-pre.json" \
            "$TMP_ROOT/r30-ev-post.json" \
            "$T1_ID" \
            "$T2_ID" <<'PY' && r30_lost_ok=1 || r30_lost_ok=0
import json, sys

pre = json.load(open(sys.argv[1], encoding="utf-8"))
post = json.load(open(sys.argv[2], encoding="utf-8"))
t1_id = sys.argv[3].strip()
t2_id = sys.argv[4].strip()

pre_ids = {ev.get("id") for ev in pre if ev.get("id")}
new_lost = [
    ev for ev in post
    if ev.get("id") not in pre_ids and ev.get("code") == "VM_RUNTIME_LOST"
]
t1_lost = [ev for ev in new_lost if ev.get("vmID") == t1_id]
t2_lost = [ev for ev in new_lost if ev.get("vmID") == t2_id]
if len(t1_lost) != 1 or len(t2_lost) != 1:
    sys.exit(1)
PY
    fi

    if [[ -n "$r30_killed_pid" && $r30_vz_gone -eq 1 \
        && $r30_ps_stopped_ok -eq 1 && -z "$r30_daemons_after_ps" && -z "$r30_daemons_after_ev" \
        && $r30_dstatus_rc -eq 3 && $r30_lost_ok -eq 1 ]]; then
        pass_row 30 "after SIGKILL daemon (pid=$r30_killed_pid): both VirtualMachine processes exited in ${r30_vz_elapsed}s (<30s); ps --json reported t1 & t2 stopped without spawning daemon; events recorded 1 VM_RUNTIME_LOST each for t1 & t2."
    else
        fail_row 30 "killed_pid='$r30_killed_pid', vz_gone=$r30_vz_gone (${r30_vz_elapsed}s), ps_stopped=$r30_ps_stopped_ok, daemons_ps='$r30_daemons_after_ps', dstatus_rc=$r30_dstatus_rc, lost_ok=$r30_lost_ok"
    fi

    # --------------------------------------------------------------
    # Row 31: Boot `t1` (`up t1`) and run `exec t1 -- dmesg`
    #   Expect: `up` exits 0; guest `dmesg` contains ext4 `recovery complete`.
    # --------------------------------------------------------------
    ROW_START_SEC="$(now_sec)"
    run_cli "$TMP_ROOT/r31-up.out" "$TMP_ROOT/r31-up.err" --lang en --workspace "$WS" up t1
    r31_up_rc=$LAST_RC
    r31_up_elapsed="$LAST_ELAPSED_SEC"

    run_cli "$TMP_ROOT/r31-dmesg.out" "$TMP_ROOT/r31-dmesg.err" --lang en --workspace "$WS" exec t1 -- dmesg
    r31_dmesg_rc=$LAST_RC

    r31_recovery_ok=0
    r31_ext4_summary=""
    if [[ $r31_up_rc -eq 0 && $r31_dmesg_rc -eq 0 && ! -s "$TMP_ROOT/r31-dmesg.err" ]]; then
        r31_ext4_summary="$(
            /usr/bin/python3 - "$TMP_ROOT/r31-dmesg.out" <<'PY'
import re, sys

text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
ext4_lines = [ln.strip() for ln in text.splitlines() if re.search(r"EXT4-fs|recovery|orphan", ln, re.IGNORECASE)]
has_recovery = any("recovery complete" in ln.lower() for ln in ext4_lines)
if not has_recovery:
    sys.exit(1)
print(" | ".join(ext4_lines))
PY
        )" && r31_recovery_ok=1 || r31_recovery_ok=0
    fi

    if [[ $r31_up_rc -eq 0 && $r31_dmesg_rc -eq 0 && $r31_recovery_ok -eq 1 ]]; then
        pass_row 31 "'up t1' (${r31_up_elapsed}s) & 'exec t1 -- dmesg' exited 0; ext4 journal recovery confirmed: [$r31_ext4_summary]."
    else
        fail_row 31 "up_rc=$r31_up_rc, dmesg_rc=$r31_dmesg_rc, recovery_ok=$r31_recovery_ok, err='$(cat "$TMP_ROOT/r31-dmesg.err" 2>/dev/null | tr '\n' ' ')'"
    fi

    # --------------------------------------------------------------
    # Row 32: Run `exec t1 -- true` 10 times and `exec t1 -- uname -r` 10 times
    #   Expect: all 20 exit 0; record each individual timing (no upper bound; compare vs M1 ~7s `run`).
    # --------------------------------------------------------------
    ROW_START_SEC="$(now_sec)"
    r32_all_ok=1
    r32_true_times=()
    r32_uname_times=()
    r32_kernel_val=""

    for idx in $(seq 1 10); do
        run_cli "$TMP_ROOT/r32-true-$idx.out" "$TMP_ROOT/r32-true-$idx.err" --lang en --workspace "$WS" exec t1 -- true
        r32_true_times+=("${LAST_ELAPSED_SEC}s")
        if [[ $LAST_RC -ne 0 || -s "$TMP_ROOT/r32-true-$idx.out" || -s "$TMP_ROOT/r32-true-$idx.err" ]]; then
            r32_all_ok=0
        fi
    done

    for idx in $(seq 1 10); do
        run_cli "$TMP_ROOT/r32-uname-$idx.out" "$TMP_ROOT/r32-uname-$idx.err" --lang en --workspace "$WS" exec t1 -- uname -r
        r32_uname_times+=("${LAST_ELAPSED_SEC}s")
        if [[ $LAST_RC -ne 0 || -s "$TMP_ROOT/r32-uname-$idx.err" ]]; then
            r32_all_ok=0
        else
            r32_k="$(
                /usr/bin/python3 - "$TMP_ROOT/r32-uname-$idx.out" <<'PY'
import re, sys

lines = open(sys.argv[1], encoding="utf-8", errors="replace").read().splitlines()
if len(lines) != 1:
    sys.exit(1)
val = lines[0].strip()
if not re.match(r"^6\.1\.\d+-\d+-(cloud-)?arm64$", val):
    sys.exit(1)
print(val)
PY
            )" || r32_k=""
            if [[ -z "$r32_k" ]]; then
                r32_all_ok=0
            else
                r32_kernel_val="$r32_k"
            fi
        fi
    done

    if [[ $r32_all_ok -eq 1 ]]; then
        pass_row 32 "all 20 exec calls exited 0 (kernel=$r32_kernel_val); 'exec t1 -- true' x10=[${r32_true_times[*]}]; 'exec t1 -- uname -r' x10=[${r32_uname_times[*]}]."
    else
        fail_row 32 "one or more of the 20 exec calls failed; true_times=[${r32_true_times[*]}], uname_times=[${r32_uname_times[*]}]"
    fi

    # --------------------------------------------------------------
    # Row 33: `up t2`, then `daemon stop`
    #   Expect: exits 0; within 60s both VirtualMachine processes exit; in `events`,
    #           both t1 and t2 have new `VM_STOPPED` events with reason `guest-shutdown`
    #           (not `hard-stop`); socket file absent; 0 workspace daemons running.
    # --------------------------------------------------------------
    ROW_START_SEC="$(now_sec)"
    run_cli "$TMP_ROOT/r33-up2.out" "$TMP_ROOT/r33-up2.err" --lang en --workspace "$WS" up t2
    r33_up2_rc=$LAST_RC
    r33_up2_elapsed="$LAST_ELAPSED_SEC"

    run_cli "$TMP_ROOT/r33-ps-before.json" "$TMP_ROOT/r33-ps-before.err" --lang en --workspace "$WS" ps --json
    T2_ID=""
    if [[ $LAST_RC -eq 0 ]]; then
        T2_ID="$(
            /usr/bin/python3 - "$TMP_ROOT/r33-ps-before.json" <<'PY'
import json, sys
vms = json.load(open(sys.argv[1], encoding="utf-8"))
t2 = [v for v in vms if v.get("spec", {}).get("name") == "t2"]
print(t2[0].get("spec", {}).get("id", "") if len(t2) == 1 else "")
PY
        )"
    fi

    r33_vz_before="$(count_extra_vz_pids)"

    run_cli "$TMP_ROOT/r33-ev-before.json" "$TMP_ROOT/r33-ev-before.err" --lang en --workspace "$WS" events --json
    r33_ev_before_rc=$LAST_RC

    r33_t0="$(now_sec)"
    run_cli "$TMP_ROOT/r33-stop.out" "$TMP_ROOT/r33-stop.err" --lang en --workspace "$WS" daemon stop
    r33_stop_rc=$LAST_RC

    r33_vz_gone=0
    if wait_for_extra_vz_count 0 60; then
        r33_vz_gone=1
    fi
    r33_t1="$(now_sec)"
    r33_stop_elapsed="$(diff_sec "$r33_t0" "$r33_t1")"

    r33_sock_gone=0
    if [[ ! -e "$WS/run/daemon.sock" ]]; then
        r33_sock_gone=1
    fi

    r33_daemons_after="$(find_workspace_daemon_pids "$WS")"
    run_cli "$TMP_ROOT/r33-dstatus.out" "$TMP_ROOT/r33-dstatus.err" --lang en --workspace "$WS" daemon status
    r33_dstatus_rc=$LAST_RC

    run_cli "$TMP_ROOT/r33-ev-after.json" "$TMP_ROOT/r33-ev-after.err" --lang en --workspace "$WS" events --json
    r33_ev_after_rc=$LAST_RC
    r33_daemons_post_events="$(find_workspace_daemon_pids "$WS")"

    r33_events_ok=0
    if [[ $r33_ev_before_rc -eq 0 && $r33_ev_after_rc -eq 0 && -n "$T1_ID" && -n "$T2_ID" ]]; then
        /usr/bin/python3 - \
            "$TMP_ROOT/r33-ev-before.json" \
            "$TMP_ROOT/r33-ev-after.json" \
            "$T1_ID" \
            "$T2_ID" <<'PY' && r33_events_ok=1 || r33_events_ok=0
import json, sys

before = json.load(open(sys.argv[1], encoding="utf-8"))
after = json.load(open(sys.argv[2], encoding="utf-8"))
t1_id = sys.argv[3].strip()
t2_id = sys.argv[4].strip()

before_ids = {ev.get("id") for ev in before if ev.get("id")}
new_stopped = [
    ev for ev in after
    if ev.get("id") not in before_ids and ev.get("code") == "VM_STOPPED"
]

def check_vm(vm_id):
    matches = [ev for ev in new_stopped if ev.get("vmID") == vm_id]
    if len(matches) != 1:
        return False
    ev = matches[0]
    meta_reason = (ev.get("metadata") or {}).get("reason", "")
    msg = ev.get("message") or ""
    if meta_reason != "guest-shutdown":
        return False
    if "guest-shutdown" not in msg or "hard-stop" in msg:
        return False
    return True

if not (check_vm(t1_id) and check_vm(t2_id)):
    sys.exit(1)
PY
    fi

    if [[ $r33_up2_rc -eq 0 && "$r33_vz_before" == "2" \
        && $r33_stop_rc -eq 0 && $r33_vz_gone -eq 1 \
        && $r33_sock_gone -eq 1 && -z "$r33_daemons_after" && -z "$r33_daemons_post_events" \
        && $r33_dstatus_rc -eq 3 && $r33_events_ok -eq 1 ]]; then
        pass_row 33 "'up t2' (${r33_up2_elapsed}s) & 'daemon stop' exited 0; both VirtualMachine processes exited in ${r33_stop_elapsed}s (<60s); t1 & t2 recorded VM_STOPPED reason=guest-shutdown; daemon.sock removed; 0 daemons running."
    else
        fail_row 33 "up2_rc=$r33_up2_rc, vz_before='$r33_vz_before', stop_rc=$r33_stop_rc, vz_gone=$r33_vz_gone (${r33_stop_elapsed}s), sock_gone=$r33_sock_gone, daemons='$r33_daemons_after', dstatus_rc=$r33_dstatus_rc, events_ok=$r33_events_ok"
    fi

    # --------------------------------------------------------------
    # Row 34: Boot `t1` again (`up t1`), run `exec t1 -- dmesg`, then `daemon stop`
    #   Expect: `dmesg` has NO `recovery complete` (proving Row 33 `daemon stop` shut down cleanly).
    # --------------------------------------------------------------
    ROW_START_SEC="$(now_sec)"
    run_cli "$TMP_ROOT/r34-up.out" "$TMP_ROOT/r34-up.err" --lang en --workspace "$WS" up t1
    r34_up_rc=$LAST_RC
    r34_up_elapsed="$LAST_ELAPSED_SEC"

    run_cli "$TMP_ROOT/r34-dmesg.out" "$TMP_ROOT/r34-dmesg.err" --lang en --workspace "$WS" exec t1 -- dmesg
    r34_dmesg_rc=$LAST_RC

    r34_clean_dmesg_ok=0
    r34_ext4_summary=""
    if [[ $r34_up_rc -eq 0 && $r34_dmesg_rc -eq 0 && ! -s "$TMP_ROOT/r34-dmesg.err" ]]; then
        r34_ext4_summary="$(
            /usr/bin/python3 - "$TMP_ROOT/r34-dmesg.out" <<'PY'
import re, sys

text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
if not text.strip():
    sys.exit(1)
if "recovery complete" in text.lower():
    sys.exit(1)
ext4_lines = [ln.strip() for ln in text.splitlines() if re.search(r"EXT4-fs|recovery|orphan", ln, re.IGNORECASE)]
if not ext4_lines:
    sys.exit(1)
print(" | ".join(ext4_lines))
PY
        )" && r34_clean_dmesg_ok=1 || r34_clean_dmesg_ok=0
    fi

    run_cli "$TMP_ROOT/r34-stop.out" "$TMP_ROOT/r34-stop.err" --lang en --workspace "$WS" daemon stop
    r34_stop_rc=$LAST_RC
    r34_vz_gone=0
    if wait_for_extra_vz_count 0 60; then
        r34_vz_gone=1
    fi
    r34_sock_gone=0
    if [[ ! -e "$WS/run/daemon.sock" ]]; then
        r34_sock_gone=1
    fi
    r34_daemons_after="$(find_workspace_daemon_pids "$WS")"

    if [[ $r34_up_rc -eq 0 && $r34_dmesg_rc -eq 0 && $r34_clean_dmesg_ok -eq 1 \
        && $r34_stop_rc -eq 0 && $r34_vz_gone -eq 1 && $r34_sock_gone -eq 1 && -z "$r34_daemons_after" ]]; then
        pass_row 34 "'up t1' (${r34_up_elapsed}s), 'exec t1 -- dmesg' confirmed zero 'recovery complete' [$r34_ext4_summary], and 'daemon stop' exited 0 cleanly."
    else
        fail_row 34 "up_rc=$r34_up_rc, dmesg_rc=$r34_dmesg_rc, clean_dmesg=$r34_clean_dmesg_ok, stop_rc=$r34_stop_rc, vz_gone=$r34_vz_gone, sock_gone=$r34_sock_gone, daemons='$r34_daemons_after'"
    fi

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
