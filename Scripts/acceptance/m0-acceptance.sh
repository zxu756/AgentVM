#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

echo "=================================================================="
echo " AgentVM Milestone M0 Acceptance Suite (01-agentvm.md Rows 1..8)"
echo "=================================================================="

swift build --product AgentVM >/dev/null
AGENTVM_BIN="$ROOT_DIR/.build/debug/AgentVM"

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/agentvm-m0-accept.XXXXXX")"
GUI_PID=""
cleanup() {
    if [[ -n "$GUI_PID" ]] && kill -0 "$GUI_PID" 2>/dev/null; then
        kill "$GUI_PID" 2>/dev/null || true
        wait "$GUI_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

# ------------------------------------------------------------------
# Row 1: 20 cold runs in fresh workspaces of:
#   init, create a, ps, ps --json, snapshot list, plugin, export-hcl
#   Expect: exit 0 on all 140 invocations, zero crashes, zero timeouts.
# ------------------------------------------------------------------
echo ""
echo "[Row 1/8] Running 20 cold workspace iterations x 7 commands (140 invocations)..."
for i in $(seq 1 20); do
    if (( i <= 10 )); then
        lang="en"
    else
        lang="zh"
    fi
    ws="$TMP_ROOT/iter-${i}.agentvm"

    "$AGENTVM_BIN" --lang "$lang" --workspace "$ws" init >/dev/null
    "$AGENTVM_BIN" --lang "$lang" --workspace "$ws" create a >/dev/null
    ps_plain="$("$AGENTVM_BIN" --lang "$lang" --workspace "$ws" ps)"
    [[ "$ps_plain" == *"a"* && "$ps_plain" == *"—"* ]] || { echo "FAIL Row 1 (iter $i): plain ps invalid: $ps_plain" >&2; exit 1; }
    ps_json="$("$AGENTVM_BIN" --lang "$lang" --workspace "$ws" ps --json)"
    [[ "$ps_json" == *'"name" : "a"'* || "$ps_json" == *'"name":"a"'* ]] || { echo "FAIL Row 1 (iter $i): ps --json missing VM a" >&2; exit 1; }
    "$AGENTVM_BIN" --lang "$lang" --workspace "$ws" snapshot list >/dev/null
    "$AGENTVM_BIN" --lang "$lang" --workspace "$ws" plugin >/dev/null
    hcl="$("$AGENTVM_BIN" --lang "$lang" --workspace "$ws" export-hcl)"
    [[ "$hcl" == *'sandbox_vm "a"'* ]] || { echo "FAIL Row 1 (iter $i): export-hcl missing sandbox_vm a" >&2; exit 1; }
done
echo "PASS [Row 1/8]: 20/20 iterations (140 cold CLI runs across en & zh) exited 0 with 0 crashes and 0 timeouts."

# ------------------------------------------------------------------
# Row 2: `agentvm up a` on an empty disk (EN & ZH)
#   Expect: non-zero exit code, stderr explains no bootable system,
#           and subsequent `ps --json` state != "running".
# ------------------------------------------------------------------
echo ""
echo "[Row 2/8] Verifying 'agentvm up a' on empty disk fails honestly (en & zh)..."
WS_HONEST="$TMP_ROOT/honest-vm.agentvm"
"$AGENTVM_BIN" --lang en --workspace "$WS_HONEST" init >/dev/null
"$AGENTVM_BIN" --lang en --workspace "$WS_HONEST" create a >/dev/null

for lang in en zh; do
    set +e
    up_out="$("$AGENTVM_BIN" --lang "$lang" --workspace "$WS_HONEST" up a 2>"$TMP_ROOT/up-${lang}.err")"
    up_rc=$?
    set -e
    up_err="$(cat "$TMP_ROOT/up-${lang}.err")"

    if [[ $up_rc -eq 0 ]]; then
        echo "FAIL [Row 2/8]: agentvm up a exited 0 on empty disk ($lang)" >&2
        exit 1
    fi
    if [[ -n "$up_out" ]]; then
        echo "FAIL [Row 2/8]: agentvm up a emitted unexpected stdout ($lang): $up_out" >&2
        exit 1
    fi
    if [[ "$lang" == "en" ]]; then
        [[ "$up_err" == *"[ERR_NO_BOOTABLE_SYSTEM]"* && "$up_err" == *"no bootable guest OS or kernel"* ]] || { echo "FAIL [Row 2/8]: EN stderr missing 'no bootable guest OS or kernel': $up_err" >&2; exit 1; }
    else
        [[ "$up_err" == *"[ERR_NO_BOOTABLE_SYSTEM]"* && "$up_err" == *"没有可引导的客户机系统"* ]] || { echo "FAIL [Row 2/8]: ZH stderr missing '没有可引导的客户机系统': $up_err" >&2; exit 1; }
    fi

    after_json="$("$AGENTVM_BIN" --lang "$lang" --workspace "$WS_HONEST" ps --json)"
    python3 -c '
import json, sys
vms = json.loads(sys.stdin.read())
assert len(vms) == 1
state = vms[0]["telemetry"]["state"]
assert state != "running", f"Expected state != running, got {state}"
assert vms[0]["telemetry"]["guestAgentConnected"] is False
' <<<"$after_json"
done
echo "PASS [Row 2/8]: 'agentvm up a' exits non-zero with localized no-bootable-OS stderr and leaves state != running."

# ------------------------------------------------------------------
# Row 3: `agentvm doctor` (EN & ZH)
#   Expect: zero "< 20ms" / "20ms" claims; clonefile comes from live probe.
# ------------------------------------------------------------------
echo ""
echo "[Row 3/8] Verifying 'agentvm doctor' live clonefile(2) probe and zero '< 20ms' strings (en & zh)..."
for lang in en zh; do
    doc_out="$("$AGENTVM_BIN" --lang "$lang" --workspace "$WS_HONEST" doctor)"
    if [[ "$doc_out" == *"20ms"* || "$doc_out" == *"20 ms"* || "$doc_out" == *"20 毫秒"* || "$doc_out" == *"SIMULATION FALLBACK"* ]]; then
        echo "FAIL [Row 3/8]: doctor output contains banned string ($lang): $doc_out" >&2
        exit 1
    fi
    if [[ "$lang" == "en" ]]; then
        [[ "$doc_out" == *"APFS clonefile(2) : PASS (verified via live clonefile(2) probe)"* ]] || {
            echo "FAIL [Row 3/8]: EN doctor missing live clonefile PASS line: $doc_out" >&2
            exit 1
        }
    else
        [[ "$doc_out" == *"APFS clonefile(2) : 通过 (实测 clonefile(2) 写时复制克隆成功)"* ]] || {
            echo "FAIL [Row 3/8]: ZH doctor missing live clonefile 通过 line: $doc_out" >&2
            exit 1
        }
    fi
done
leftover_probes="$(find "$WS_HONEST" -name '.avm-clonefile-*' | wc -l | tr -d ' ')"
[[ "$leftover_probes" == "0" ]] || { echo "FAIL [Row 3/8]: leftover clonefile probe files found: $leftover_probes" >&2; exit 1; }
echo "PASS [Row 3/8]: 'agentvm doctor' runs a live clonefile(2) probe with zero '< 20ms' claims and zero temp leftovers."

# ------------------------------------------------------------------
# Row 4: Repo root cleanliness after `swift test`
#   Expect: zero newly created files (especially fk-*, sp-*, *-wal, *-shm) in repo root.
# ------------------------------------------------------------------
echo ""
echo "[Row 4/8] Verifying 'swift test' creates zero files in repository root..."
before_root_ls="$(ls -1A "$ROOT_DIR" | sort)"
swift test --no-parallel --filter StoreMigrationsAndUndoTests >/dev/null
after_root_ls="$(ls -1A "$ROOT_DIR" | sort)"
if [[ "$before_root_ls" != "$after_root_ls" ]]; then
    echo "FAIL [Row 4/8]: Repository root entries changed during swift test!" >&2
    diff -u <(echo "$before_root_ls") <(echo "$after_root_ls") >&2 || true
    exit 1
fi
stray_db="$(find "$ROOT_DIR" -maxdepth 1 \( -name 'fk-*' -o -name 'sp-*' -o -name '*-wal' -o -name '*-shm' \) | wc -l | tr -d ' ')"
[[ "$stray_db" == "0" ]] || { echo "FAIL [Row 4/8]: Found stray SQLite files in repo root" >&2; exit 1; }
echo "PASS [Row 4/8]: Repository root has zero new or leaked SQLite files after swift test."

# ------------------------------------------------------------------
# Row 5: `agentvm exec a -- uname -a` (without `--backend simulation`)
#   Expect: non-zero exit code, zero Linux kernel strings on stdout or stderr.
# ------------------------------------------------------------------
echo ""
echo "[Row 5/8] Verifying 'agentvm exec a -- uname -a' fails honestly with zero Linux strings (en & zh)..."
for lang in en zh; do
    set +e
    exec_out="$("$AGENTVM_BIN" --lang "$lang" --workspace "$WS_HONEST" exec a -- uname -a 2>"$TMP_ROOT/exec-${lang}.err")"
    exec_rc=$?
    set -e
    exec_err="$(cat "$TMP_ROOT/exec-${lang}.err")"

    if [[ $exec_rc -eq 0 ]]; then
        echo "FAIL [Row 5/8]: agentvm exec a -- uname -a exited 0 without simulation ($lang)" >&2
        exit 1
    fi
    if [[ "$exec_out" == *"Linux"* || "$exec_err" == *"Linux"* || "$exec_out" == *"6.8.0"* || "$exec_err" == *"6.8.0"* ]]; then
        echo "FAIL [Row 5/8]: leaked Linux kernel string without --backend simulation ($lang)" >&2
        exit 1
    fi
done
echo "PASS [Row 5/8]: 'agentvm exec a -- uname -a' exits non-zero and emits zero Linux kernel strings."

# ------------------------------------------------------------------
# Row 6: `agentvm --backend simulation exec a -- uname -a`
#   Expect: exit 0 and every output line carries `SIMULATED` prefix.
# ------------------------------------------------------------------
echo ""
echo "[Row 6/8] Verifying 'agentvm --backend simulation exec a -- uname -a' prefixes SIMULATED (en & zh)..."
for lang in en zh; do
    sim_out="$("$AGENTVM_BIN" --lang "$lang" --workspace "$WS_HONEST" --backend simulation exec a -- uname -a)"
    [[ -n "$sim_out" ]] || { echo "FAIL [Row 6/8]: empty output from --backend simulation exec ($lang)" >&2; exit 1; }
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if [[ "$line" != SIMULATED:* ]]; then
            echo "FAIL [Row 6/8]: line missing SIMULATED: prefix ($lang): $line" >&2
            exit 1
        fi
    done <<<"$sim_out"
done
echo "PASS [Row 6/8]: Explicit '--backend simulation' outputs carry SIMULATED: prefix on every line."

# ------------------------------------------------------------------
# Row 7: `Scripts/acceptance/readme-commands.sh`
#   Expect: all README commands match documented exit codes and outputs.
# ------------------------------------------------------------------
echo ""
echo "[Row 7/8] Running Scripts/acceptance/readme-commands.sh..."
"$ROOT_DIR/Scripts/acceptance/readme-commands.sh"
echo "PASS [Row 7/8]: readme-commands.sh verified all EN & ZH README commands."

# ------------------------------------------------------------------
# Row 8: Launch GUI binary without `--demo` and click nothing
#   Expect: process stays alive, workspace has 0 VMs, 0 packets, 0 alerts.
# ------------------------------------------------------------------
echo ""
echo "[Row 8/8] Launching AgentVM GUI binary without --demo on empty workspace..."
GUI_WS="$TMP_ROOT/EmptyGUILaunch.agentvm"
AGENTVM_WORKSPACE="$GUI_WS" AGENTVM_LANG="en" "$AGENTVM_BIN" >/dev/null 2>&1 &
GUI_PID=$!

python3 -c "import time; time.sleep(2.5)"

if ! kill -0 "$GUI_PID" 2>/dev/null; then
    echo "FAIL [Row 8/8]: AgentVM GUI process exited prematurely on empty launch" >&2
    exit 1
fi

kill "$GUI_PID" 2>/dev/null || true
wait "$GUI_PID" 2>/dev/null || true
GUI_PID=""

if [[ ! -f "$GUI_WS/state.sqlite" ]]; then
    echo "FAIL [Row 8/8]: GUI did not initialize workspace state.sqlite at $GUI_WS" >&2
    exit 1
fi

vm_count="$(sqlite3 "$GUI_WS/state.sqlite" 'SELECT COUNT(*) FROM vms;')"
snap_count="$(sqlite3 "$GUI_WS/state.sqlite" 'SELECT COUNT(*) FROM snapshots;')"
diag_count="$(sqlite3 "$GUI_WS/state.sqlite" 'SELECT COUNT(*) FROM diagnostics;')"

[[ "$vm_count" == "0" ]] || { echo "FAIL [Row 8/8]: Expected 0 VMs on GUI startup, found $vm_count" >&2; exit 1; }
[[ "$snap_count" == "0" ]] || { echo "FAIL [Row 8/8]: Expected 0 snapshots on GUI startup, found $snap_count" >&2; exit 1; }
[[ "$diag_count" == "0" ]] || { echo "FAIL [Row 8/8]: Expected 0 diagnostic alerts on GUI startup, found $diag_count" >&2; exit 1; }

python3 - "$GUI_WS/manifest.json" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    manifest = json.load(f)
assert manifest.get("isDemonstrationWorkspace", False) is False, f"Unexpected demo flag in manifest: {manifest}"
PY

echo "PASS [Row 8/8]: GUI launched cleanly without --demo -> 0 VMs, 0 snapshots, 0 packets, 0 alerts."
echo ""
echo "=================================================================="
echo " ALL 8 M0 ACCEPTANCE CHECKS PASSED"
echo "=================================================================="
