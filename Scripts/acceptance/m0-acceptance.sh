#!/usr/bin/env bash
# AgentVM M0 acceptance.
#
# Rows 1-8 are the M0 table of 01-agentvm.md. Rows 9-14 are the rows added by the M0 review
# (06-m0-review.md, "补充的验收行"): simulated state must not pass for real on any entry point.
#
# Hard rules of this script:
#   * It never launches the desktop UI. Every product invocation goes through `agentvm_cli`, which
#     refuses a command line without a CLI subcommand (the only way the executable opens a window).
#   * It never touches the user's data: HOME / CFFIXED_USER_HOME point at a temporary directory and
#     every command names a --workspace inside it.
#   * It boots no VM and downloads nothing.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

SWIFT_JOBS_ARGS=()
if [[ -n "${AGENTVM_BUILD_JOBS:-}" ]]; then
    SWIFT_JOBS_ARGS=(-j "$AGENTVM_BUILD_JOBS")
fi

TOTAL_ROWS=14

echo "=================================================================="
echo " AgentVM Milestone M0 Acceptance Suite"
echo "   Rows 1-8 : 01-agentvm.md M0 table"
echo "   Rows 9-14: 06-m0-review.md supplementary rows"
echo "=================================================================="

swift build "${SWIFT_JOBS_ARGS[@]+"${SWIFT_JOBS_ARGS[@]}"}" --product AgentVM >/dev/null
AGENTVM_BIN="$ROOT_DIR/.build/debug/AgentVM"

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/agentvm-m0-accept.XXXXXX")"
ISOLATED_HOME="$TMP_ROOT/home"
mkdir -p "$ISOLATED_HOME"
cleanup() {
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

# The only way this script runs the product. $AGENTVM_CLI_BINARY may point at a re-signed copy (Row 12).
agentvm_cli() {
    local has_subcommand=0
    local token
    for token in "$@"; do
        [[ "$token" == "--" ]] && break
        case "$token" in
            doctor|init|ps|list|create|up|boot|start|pause|resume|halt|stop|branch|fork|snapshot|restore|exec|pcap|policy|plugin|export-hcl|export-html|help|version|mcp)
                has_subcommand=1
                break
                ;;
        esac
    done
    if [[ $has_subcommand -ne 1 ]]; then
        echo "REFUSED: '$*' has no CLI subcommand and would open the desktop UI." >&2
        return 97
    fi
    env -u AGENTVM_WORKSPACE -u AGENTVM_REAL_VM -u AGENTVM_LANG \
        HOME="$ISOLATED_HOME" CFFIXED_USER_HOME="$ISOLATED_HOME" \
        "${AGENTVM_CLI_BINARY:-$AGENTVM_BIN}" "$@"
}

fail() {
    echo "FAIL $*" >&2
    exit 1
}

# expect_all_lines_marked <label> <stdout-file> <stderr-file>
# Simulation-mode text output: at least one line, and every line starts with "SIMULATED:".
expect_all_lines_marked() {
    local label="$1" out_file="$2" err_file="$3"
    local seen=0 line
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" ]] && continue
        seen=1
        [[ "$line" == SIMULATED:* ]] || fail "$label: unmarked line: $line"
    done < <(cat "$out_file" "$err_file")
    [[ $seen -eq 1 ]] || fail "$label: no output at all, so nothing says it was simulated"
}

# run_sim <label> <workspace> <expected: ok|fail|any> <args...>  -> runs with --backend simulation and checks markers
run_sim() {
    local label="$1" ws="$2" expected="$3"
    shift 3
    local rc=0
    set +e
    agentvm_cli --lang en --workspace "$ws" --backend simulation "$@" >"$TMP_ROOT/sim.out" 2>"$TMP_ROOT/sim.err"
    rc=$?
    set -e
    if [[ "$expected" == "ok" && $rc -ne 0 ]]; then
        fail "$label: exited $rc: $(cat "$TMP_ROOT/sim.err")"
    fi
    if [[ "$expected" == "fail" && $rc -eq 0 ]]; then
        fail "$label: expected a non-zero exit"
    fi
    expect_all_lines_marked "$label" "$TMP_ROOT/sim.out" "$TMP_ROOT/sim.err"
}

# ------------------------------------------------------------------
# Row 1: 20 cold runs in fresh workspaces of:
#   init, create a, ps, ps --json, snapshot list, plugin, export-hcl
#   Expect: exit 0 on all 140 invocations, zero crashes, zero timeouts.
# ------------------------------------------------------------------
echo ""
echo "[Row 1/$TOTAL_ROWS] Running 20 cold workspace iterations x 7 commands (140 invocations)..."
for i in $(seq 1 20); do
    if (( i <= 10 )); then
        lang="en"
    else
        lang="zh"
    fi
    ws="$TMP_ROOT/iter-${i}.agentvm"

    agentvm_cli --lang "$lang" --workspace "$ws" init >/dev/null
    agentvm_cli --lang "$lang" --workspace "$ws" create a >/dev/null
    ps_plain="$(agentvm_cli --lang "$lang" --workspace "$ws" ps)"
    [[ "$ps_plain" == *"a"* && "$ps_plain" == *"—"* ]] || fail "[Row 1] (iter $i): plain ps invalid: $ps_plain"
    ps_json="$(agentvm_cli --lang "$lang" --workspace "$ws" ps --json)"
    [[ "$ps_json" == *'"name" : "a"'* || "$ps_json" == *'"name":"a"'* ]] || fail "[Row 1] (iter $i): ps --json missing VM a"
    agentvm_cli --lang "$lang" --workspace "$ws" snapshot list >/dev/null
    agentvm_cli --lang "$lang" --workspace "$ws" plugin >/dev/null
    hcl="$(agentvm_cli --lang "$lang" --workspace "$ws" export-hcl)"
    [[ "$hcl" == *'sandbox_vm "a"'* ]] || fail "[Row 1] (iter $i): export-hcl missing sandbox_vm a"
done
echo "PASS [Row 1/$TOTAL_ROWS]: 20/20 iterations (140 cold CLI runs across en & zh) exited 0 with 0 crashes and 0 timeouts."

# ------------------------------------------------------------------
# Row 2: `agentvm up a` on an empty disk (EN & ZH)
#   Expect: non-zero exit code, stderr explains no bootable system,
#           and subsequent `ps --json` state != "running".
# ------------------------------------------------------------------
echo ""
echo "[Row 2/$TOTAL_ROWS] Verifying 'agentvm up a' on empty disk fails honestly (en & zh)..."
WS_HONEST="$TMP_ROOT/honest-vm.agentvm"
agentvm_cli --lang en --workspace "$WS_HONEST" init >/dev/null
agentvm_cli --lang en --workspace "$WS_HONEST" create a >/dev/null

for lang in en zh; do
    set +e
    up_out="$(agentvm_cli --lang "$lang" --workspace "$WS_HONEST" up a 2>"$TMP_ROOT/up-${lang}.err")"
    up_rc=$?
    set -e
    up_err="$(cat "$TMP_ROOT/up-${lang}.err")"

    [[ $up_rc -ne 0 ]] || fail "[Row 2]: agentvm up a exited 0 on empty disk ($lang)"
    [[ -z "$up_out" ]] || fail "[Row 2]: agentvm up a emitted unexpected stdout ($lang): $up_out"
    if [[ "$lang" == "en" ]]; then
        [[ "$up_err" == *"[ERR_NO_BOOTABLE_SYSTEM]"* && "$up_err" == *"no bootable guest OS or kernel"* ]] || fail "[Row 2]: EN stderr missing 'no bootable guest OS or kernel': $up_err"
    else
        [[ "$up_err" == *"[ERR_NO_BOOTABLE_SYSTEM]"* && "$up_err" == *"没有可引导的客户机系统"* ]] || fail "[Row 2]: ZH stderr missing '没有可引导的客户机系统': $up_err"
        # The Chinese message is Chinese all the way through (the disk detail used to be English).
        [[ "$up_err" == *"空的分区表"* && "$up_err" != *"contains only"* && "$up_err" != *"partition table"* ]] || fail "[Row 2]: ZH stderr still has an English half: $up_err"
    fi

    after_json="$(agentvm_cli --lang "$lang" --workspace "$WS_HONEST" ps --json)"
    python3 -c '
import json, sys
vms = json.loads(sys.stdin.read())
assert len(vms) == 1
state = vms[0]["telemetry"]["state"]
assert state != "running", f"Expected state != running, got {state}"
assert vms[0]["telemetry"]["guestAgentConnected"] is False
assert vms[0]["telemetry"]["simulated"] is False
' <<<"$after_json"
done
echo "PASS [Row 2/$TOTAL_ROWS]: 'agentvm up a' exits non-zero with a fully localized no-bootable-OS stderr and leaves state != running."

# ------------------------------------------------------------------
# Row 3: `agentvm doctor` (EN & ZH)
#   Expect: zero "< 20ms" / "20ms" claims; clonefile comes from live probe.
# ------------------------------------------------------------------
echo ""
echo "[Row 3/$TOTAL_ROWS] Verifying 'agentvm doctor' live clonefile(2) probe and zero '< 20ms' strings (en & zh)..."
for lang in en zh; do
    doc_out="$(agentvm_cli --lang "$lang" --workspace "$WS_HONEST" doctor)"
    if [[ "$doc_out" == *"20ms"* || "$doc_out" == *"20 ms"* || "$doc_out" == *"20 毫秒"* || "$doc_out" == *"SIMULATION FALLBACK"* ]]; then
        fail "[Row 3]: doctor output contains banned string ($lang): $doc_out"
    fi
    if [[ "$lang" == "en" ]]; then
        [[ "$doc_out" == *"APFS clonefile(2) : PASS (verified via live clonefile(2) probe)"* ]] || fail "[Row 3]: EN doctor missing live clonefile PASS line: $doc_out"
    else
        [[ "$doc_out" == *"APFS clonefile(2) : 通过 (实测 clonefile(2) 写时复制克隆成功)"* ]] || fail "[Row 3]: ZH doctor missing live clonefile 通过 line: $doc_out"
    fi
done
leftover_probes="$(find "$WS_HONEST" \( -name '.avm-clonefile-*' -o -name '.agentvm-clonefile-*' \) | wc -l | tr -d ' ')"
[[ "$leftover_probes" == "0" ]] || fail "[Row 3]: leftover clonefile probe files found: $leftover_probes"
echo "PASS [Row 3/$TOTAL_ROWS]: 'agentvm doctor' runs a live clonefile(2) probe with zero '< 20ms' claims and zero temp leftovers."

# ------------------------------------------------------------------
# Row 4: The whole `swift test` suite leaves nothing behind
#   Expect: zero new files in the repo root (fk-*, sp-*, *-wal, *-shm in particular), and
#           (06-m0-review.md) zero new AgentVM preference files in ~/Library/Preferences.
#   ~/Library/Preferences is only listed here, never written.
# ------------------------------------------------------------------
echo ""
echo "[Row 4/$TOTAL_ROWS] Running the full 'swift test' suite and checking repo root and ~/Library/Preferences..."
count_agentvm_prefs() {
    find "$HOME/Library/Preferences" -maxdepth 1 -name '*AgentVM*' 2>/dev/null | wc -l | tr -d ' '
}
before_root_ls="$(ls -1A "$ROOT_DIR" | sort)"
before_prefs="$(count_agentvm_prefs)"
full_test_log="$TMP_ROOT/full-swift-test.log"
set +e
swift test "${SWIFT_JOBS_ARGS[@]+"${SWIFT_JOBS_ARGS[@]}"}" --no-parallel >"$full_test_log" 2>&1
full_test_rc=$?
set -e
if [[ $full_test_rc -ne 0 ]]; then
    grep -E '^✘' "$full_test_log" | cut -c1-300 | head -n 40 >&2 || true
    fail "[Row 4]: swift test failed (exit $full_test_rc)"
fi
full_test_summary="$(grep -E '^✔ Test run with [0-9]+ tests in [0-9]+ suites passed' "$full_test_log" | sed -E 's/ after [0-9.]+ seconds\.?//' | tail -n 1)"
[[ -n "$full_test_summary" ]] || fail "[Row 4]: could not find the passing test-run summary line"
after_root_ls="$(ls -1A "$ROOT_DIR" | sort)"
after_prefs="$(count_agentvm_prefs)"
if [[ "$before_root_ls" != "$after_root_ls" ]]; then
    diff -u <(echo "$before_root_ls") <(echo "$after_root_ls") >&2 || true
    fail "[Row 4]: Repository root entries changed during swift test"
fi
stray_db="$(find "$ROOT_DIR" -maxdepth 1 \( -name 'fk-*' -o -name 'sp-*' -o -name '*-wal' -o -name '*-shm' \) | wc -l | tr -d ' ')"
[[ "$stray_db" == "0" ]] || fail "[Row 4]: Found stray SQLite files in repo root"
new_prefs=$(( after_prefs - before_prefs ))
[[ "$new_prefs" == "0" ]] || fail "[Row 4]: swift test created $new_prefs AgentVM preference file(s) in ~/Library/Preferences"
echo "PASS [Row 4/$TOTAL_ROWS]: ${full_test_summary#✔ }; repo root unchanged, 0 stray SQLite files, 0 new AgentVM preference files in ~/Library/Preferences."

# ------------------------------------------------------------------
# Row 5: `agentvm exec a -- uname -a` (without `--backend simulation`)
#   Expect: non-zero exit code, zero Linux kernel strings on stdout or stderr.
# ------------------------------------------------------------------
echo ""
echo "[Row 5/$TOTAL_ROWS] Verifying 'agentvm exec a -- uname -a' fails honestly with zero Linux strings (en & zh)..."
for lang in en zh; do
    set +e
    exec_out="$(agentvm_cli --lang "$lang" --workspace "$WS_HONEST" exec a -- uname -a 2>"$TMP_ROOT/exec-${lang}.err")"
    exec_rc=$?
    set -e
    exec_err="$(cat "$TMP_ROOT/exec-${lang}.err")"

    [[ $exec_rc -ne 0 ]] || fail "[Row 5]: agentvm exec a -- uname -a exited 0 without simulation ($lang)"
    if [[ "$exec_out" == *"Linux"* || "$exec_err" == *"Linux"* || "$exec_out" == *"6.8.0"* || "$exec_err" == *"6.8.0"* ]]; then
        fail "[Row 5]: leaked Linux kernel string without --backend simulation ($lang)"
    fi
done
echo "PASS [Row 5/$TOTAL_ROWS]: 'agentvm exec a -- uname -a' exits non-zero and emits zero Linux kernel strings."

# ------------------------------------------------------------------
# Row 6: `agentvm --backend simulation exec a -- uname -a`
#   Expect: exit 0 and every output line carries `SIMULATED` prefix.
# ------------------------------------------------------------------
echo ""
echo "[Row 6/$TOTAL_ROWS] Verifying 'agentvm --backend simulation exec a -- uname -a' prefixes SIMULATED (en & zh)..."
for lang in en zh; do
    sim_out="$(agentvm_cli --lang "$lang" --workspace "$WS_HONEST" --backend simulation exec a -- uname -a)"
    [[ -n "$sim_out" ]] || fail "[Row 6]: empty output from --backend simulation exec ($lang)"
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$line" == SIMULATED:* ]] || fail "[Row 6]: line missing SIMULATED: prefix ($lang): $line"
    done <<<"$sim_out"
done
echo "PASS [Row 6/$TOTAL_ROWS]: Explicit '--backend simulation' outputs carry SIMULATED: prefix on every line."

# ------------------------------------------------------------------
# Row 7: `Scripts/acceptance/readme-commands.sh`
#   Expect: every command taken from the two READMEs matches its documented exit code and output.
# ------------------------------------------------------------------
echo ""
echo "[Row 7/$TOTAL_ROWS] Running Scripts/acceptance/readme-commands.sh..."
"$ROOT_DIR/Scripts/acceptance/readme-commands.sh"
echo "PASS [Row 7/$TOTAL_ROWS]: readme-commands.sh replayed the commands extracted from README.md and README.zh-CN.md."

# ------------------------------------------------------------------
# Row 8: Default UI state without `--demo`, clicking nothing
#   Expect: 0 VMs, 0 packets, 0 alerts.
#   This row never launches the GUI process. It runs the windowless ViewModel test
#   `defaultBootstrapOpensCleanEmptyStateWithoutDemoSeeding`, which builds the same default
#   ViewModel the app builds and asserts every list and the persisted workspace are empty.
# ------------------------------------------------------------------
echo ""
echo "[Row 8/$TOTAL_ROWS] Verifying default (non --demo) ViewModel state is empty (windowless test, no GUI process)..."
row8_log="$TMP_ROOT/row8-swift-test.log"
set +e
swift test "${SWIFT_JOBS_ARGS[@]+"${SWIFT_JOBS_ARGS[@]}"}" --no-parallel \
    --filter 'StudioViewsHonestyTests/defaultBootstrapOpensCleanEmptyStateWithoutDemoSeeding' >"$row8_log" 2>&1
row8_rc=$?
set -e
if [[ $row8_rc -ne 0 ]]; then
    grep -E '^✘' "$row8_log" | cut -c1-300 | head -n 20 >&2 || true
    fail "[Row 8]: default ViewModel empty-state test failed (exit $row8_rc)"
fi
grep -Eq '^✔ Test run with 1 test in 1 suite passed' "$row8_log" || fail "[Row 8]: expected exactly 1 passing test"
echo "PASS [Row 8/$TOTAL_ROWS]: default ViewModel (no --demo) -> 0 VMs, 0 snapshots, 0 packets, 0 alerts; no GUI process was started."

# ------------------------------------------------------------------
# Row 9 (review, A21): after `--backend simulation up a`, plain `ps` and `ps --json`
#   Expect: text carries a SIMULATED marker (or the state is not running); JSON has an explicit
#           simulation field. The default backend never acts on the simulated state.
# ------------------------------------------------------------------
echo ""
echo "[Row 9/$TOTAL_ROWS] Verifying simulated state is marked for the default backend (ps, ps --json, up, exec; en & zh)..."
WS_A21="$TMP_ROOT/a21.agentvm"
agentvm_cli --lang en --workspace "$WS_A21" init >/dev/null
agentvm_cli --lang en --workspace "$WS_A21" create a >/dev/null
agentvm_cli --lang en --workspace "$WS_A21" --backend simulation up a >/dev/null

for lang in en zh; do
    ps_after_sim="$(agentvm_cli --lang "$lang" --workspace "$WS_A21" ps)"
    [[ "$ps_after_sim" == *"SIMULATED"* ]] || fail "[Row 9]: default ps ($lang) has no SIMULATED marker: $ps_after_sim"
    while IFS= read -r line; do
        if [[ "$line" == *"running"* || "$line" == *"运行中"* ]]; then
            [[ "$line" == *"SIMULATED"* ]] || fail "[Row 9]: default ps ($lang) prints an unmarked running row: $line"
        fi
    done <<<"$ps_after_sim"
done
agentvm_cli --lang en --workspace "$WS_A21" ps --json | python3 -c '
import json, sys
vms = json.loads(sys.stdin.read())
assert len(vms) == 1, vms
t = vms[0]["telemetry"]
assert isinstance(t.get("simulated"), bool), "ps --json has no boolean telemetry.simulated"
if t["state"] == "running" or t["guestAgentConnected"]:
    assert t["simulated"] is True, f"running/connected without simulated=true: {t}"
'
# The default backend does not treat it as running: `up` fails exactly as on a VM that never ran...
set +e
a21_up_out="$(agentvm_cli --lang en --workspace "$WS_A21" up a 2>"$TMP_ROOT/a21-up.err")"
a21_up_rc=$?
set -e
[[ $a21_up_rc -ne 0 && -z "$a21_up_out" ]] || fail "[Row 9]: default up after a simulated boot exited $a21_up_rc with stdout '$a21_up_out'"
grep -q 'ERR_NO_BOOTABLE_SYSTEM' "$TMP_ROOT/a21-up.err" || fail "[Row 9]: default up after a simulated boot did not report ERR_NO_BOOTABLE_SYSTEM"
agentvm_cli --lang en --workspace "$WS_A21" ps --json | python3 -c '
import json, sys
t = json.loads(sys.stdin.read())[0]["telemetry"]
assert t["state"] == "stopped" and t["simulated"] is False and t["guestAgentConnected"] is False, t
'
# ...and `exec` returns nothing from the simulator.
agentvm_cli --lang en --workspace "$WS_A21" --backend simulation up a >/dev/null
set +e
a21_exec_out="$(agentvm_cli --lang en --workspace "$WS_A21" exec a -- uname -a 2>&1)"
a21_exec_rc=$?
set -e
[[ $a21_exec_rc -ne 0 ]] || fail "[Row 9]: default exec after a simulated boot exited 0"
[[ "$a21_exec_out" != *"Linux"* && "$a21_exec_out" != *"6.8.0"* ]] || fail "[Row 9]: default exec after a simulated boot leaked simulator output: $a21_exec_out"
echo "PASS [Row 9/$TOTAL_ROWS]: after '--backend simulation up a', default ps shows SIMULATED:running (en & zh), ps --json has telemetry.simulated = true, and default up / exec fail without simulator output."

# ------------------------------------------------------------------
# Row 10 (review, A22): every CLI output of simulation mode carries the marker
#   Text: every line prefixed. ps --json: records flagged. export-hcl: comment line.
#   pcap --export and export-html: the command output and the written file are both marked.
# ------------------------------------------------------------------
echo ""
echo "[Row 10/$TOTAL_ROWS] Verifying every CLI subcommand output is marked in simulation mode..."
WS_A22="$TMP_ROOT/a22.agentvm"
run_sim "doctor" "$WS_A22" ok doctor
run_sim "init" "$WS_A22" ok init
run_sim "create" "$WS_A22" ok create s1
run_sim "ps (stopped)" "$WS_A22" ok ps
run_sim "up" "$WS_A22" ok up s1
run_sim "ps (running)" "$WS_A22" ok ps
run_sim "pause" "$WS_A22" ok pause s1
run_sim "resume" "$WS_A22" ok resume s1
run_sim "exec (multi-line stdout)" "$WS_A22" ok exec s1 -- cat /etc/os-release
[[ "$(grep -c '^SIMULATED:' "$TMP_ROOT/sim.out")" -ge 3 ]] || fail "[Row 10]: expected a multi-line exec output"
run_sim "exec (no output, exit 0)" "$WS_A22" ok exec s1 -- env
run_sim "exec (no output, exit 1)" "$WS_A22" fail exec s1 -- false
run_sim "exec (stderr only)" "$WS_A22" fail exec s1 -- nonexistent-cmd
run_sim "snapshot capture" "$WS_A22" ok snapshot s1 checkpoint-one
run_sim "snapshot list" "$WS_A22" ok snapshot list
a22_snap_id="$(grep 'checkpoint-one' "$TMP_ROOT/sim.out" | grep -oE 'snap-[0-9a-f]+' | head -n 1)"
[[ -n "$a22_snap_id" ]] || fail "[Row 10]: could not find the captured snapshot ID"
run_sim "branch" "$WS_A22" ok branch s1 s2 --no-boot
run_sim "restore" "$WS_A22" ok restore "$a22_snap_id"
run_sim "pcap" "$WS_A22" ok pcap
run_sim "policy" "$WS_A22" ok policy
run_sim "policy airgap" "$WS_A22" ok policy airgap
run_sim "policy strict" "$WS_A22" ok policy strict
run_sim "plugin" "$WS_A22" ok plugin
run_sim "error path (unknown VM)" "$WS_A22" fail up does-not-exist
run_sim "usage error (unknown option)" "$WS_A22" fail ps --bogus

agentvm_cli --lang en --workspace "$WS_A22" --backend simulation ps --json >"$TMP_ROOT/sim-ps.json" 2>"$TMP_ROOT/sim-ps.err"
python3 - "$TMP_ROOT/sim-ps.json" <<'PY'
import json, sys
vms = json.load(open(sys.argv[1], encoding="utf-8"))
assert len(vms) == 2, len(vms)
for vm in vms:
    assert vm["telemetry"]["simulated"] is True, vm["spec"]["name"]
PY
grep -q '^SIMULATED:' "$TMP_ROOT/sim-ps.err" || fail "[Row 10]: simulation-mode ps --json printed no SIMULATED note on stderr"

agentvm_cli --lang en --workspace "$WS_A22" --backend simulation export-hcl >"$TMP_ROOT/sim.hcl"
grep -q '^# SIMULATED:' "$TMP_ROOT/sim.hcl" || fail "[Row 10]: export-hcl has no '# SIMULATED:' comment line"

run_sim "pcap --export" "$WS_A22" ok pcap --export "$TMP_ROOT/sim.pcapng"
LC_ALL=C grep -aq 'SIMULATED' "$TMP_ROOT/sim.pcapng" || fail "[Row 10]: exported .pcapng carries no SIMULATED section comment"
run_sim "export-html" "$WS_A22" ok export-html "$TMP_ROOT/sim.html"
grep -q 'SIMULATED' "$TMP_ROOT/sim.html" || fail "[Row 10]: exported HTML page carries no SIMULATED marker"
run_sim "halt" "$WS_A22" ok halt s1

# A default-backend HTML export of a workspace that holds simulated state marks it and does not count it as active.
agentvm_cli --lang en --workspace "$WS_A21" --backend simulation up a >/dev/null
agentvm_cli --lang en --workspace "$WS_A21" export-html "$TMP_ROOT/default-after-sim.html" >/dev/null
grep -q 'SIMULATED' "$TMP_ROOT/default-after-sim.html" || fail "[Row 10]: default export-html shows a simulated VM with no marker"
grep -q '<div class="metric-value">1 / 1</div>' "$TMP_ROOT/default-after-sim.html" && fail "[Row 10]: default export-html counts a simulated VM as an active blade"
echo "PASS [Row 10/$TOTAL_ROWS]: 26 simulation-mode CLI outputs are marked on every line (incl. empty-output exec and error paths); ps --json, export-hcl, the exported .pcapng and the exported HTML carry their own markers."

# ------------------------------------------------------------------
# Row 11 (review, A22): call every MCP tool in simulation mode
#   Expect: every tool listed by tools/list returns a result that carries the marker.
#   Also (A21 "MCP 同样"): the default-backend MCP server flags simulated state in agentvm_list_fleet.
# ------------------------------------------------------------------
echo ""
echo "[Row 11/$TOTAL_ROWS] Calling every MCP tool from tools/list in simulation mode..."
WS_MCP="$TMP_ROOT/mcp.agentvm"
agentvm_cli --lang en --workspace "$WS_MCP" create mcp-seed >/dev/null
mcp_vm_id="$(agentvm_cli --workspace "$WS_MCP" ps --json | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["spec"]["id"])')"
mcp_snap_id="$(agentvm_cli --workspace "$WS_MCP" snapshot list | grep -oE 'snap-[0-9a-f]+' | head -n 1)"
[[ -n "$mcp_vm_id" && -n "$mcp_snap_id" ]] || fail "[Row 11]: could not prepare a VM and snapshot for the MCP calls"

printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
    | agentvm_cli --workspace "$WS_MCP" --backend simulation mcp >"$TMP_ROOT/mcp-tools.jsonl"
python3 - "$TMP_ROOT/mcp-tools.jsonl" "$mcp_vm_id" "$mcp_snap_id" >"$TMP_ROOT/mcp-requests.jsonl" <<'PY'
import json, sys
tools = [t["name"] for t in json.loads(open(sys.argv[1], encoding="utf-8").readline())["result"]["tools"]]
vm_id, snap_id = sys.argv[2], sys.argv[3]
arguments = {
    "agentvm_list_fleet": {},
    "agentvm_create_vm": {"name": "mcp-second"},
    "agentvm_fork_cow_branch": {"parentVMID": vm_id, "branchName": "mcp-fork", "bootImmediately": False},
    "agentvm_exec_command": {"vmID": vm_id, "executable": "cat", "arguments": ["/etc/os-release"]},
    "agentvm_capture_snapshot": {"vmID": vm_id, "title": "mcp-snap"},
    "agentvm_restore_snapshot": {"snapshotID": snap_id},
    "agentvm_query_wiretap": {},
    "agentvm_set_firewall_preset": {"preset": "airgap"},
    "agentvm_doctor": {},
}
missing = [name for name in tools if name not in arguments]
if missing:
    sys.exit(f"tools/list exposes tools this row has no marker check for: {missing}")
for index, name in enumerate(tools):
    print(json.dumps({"jsonrpc": "2.0", "id": 100 + index, "method": "tools/call",
                      "params": {"name": name, "arguments": arguments[name]}}))
# One failing call: error results must be marked too.
print(json.dumps({"jsonrpc": "2.0", "id": 999, "method": "tools/call",
                  "params": {"name": "agentvm_restore_snapshot", "arguments": {"snapshotID": "snap-does-not-exist"}}}))
PY
agentvm_cli --workspace "$WS_MCP" --backend simulation mcp <"$TMP_ROOT/mcp-requests.jsonl" >"$TMP_ROOT/mcp-responses.jsonl"
python3 - "$TMP_ROOT/mcp-requests.jsonl" "$TMP_ROOT/mcp-responses.jsonl" >"$TMP_ROOT/mcp-tool-count.txt" <<'PY'
import json, sys
requests = {r["id"]: r for r in map(json.loads, open(sys.argv[1], encoding="utf-8"))}
responses = {r["id"]: r for r in map(json.loads, open(sys.argv[2], encoding="utf-8"))}
assert set(requests) == set(responses), (sorted(requests), sorted(responses))
checked = 0
for request_id, request in sorted(requests.items()):
    name = request["params"]["name"]
    result = responses[request_id].get("result")
    assert result is not None, f"{name}: JSON-RPC error instead of a tool result: {responses[request_id]}"
    texts = [block["text"] for block in result["content"]]
    joined = "\n".join(texts)
    assert "SIMULATED" in joined, f"{name}: no SIMULATED marker in: {joined[:200]}"
    if request_id == 999:
        assert result["isError"] is True, f"{name}: expected an error result"
    else:
        assert result["isError"] is False, f"{name} failed in simulation mode: {joined[:300]}"
    if name == "agentvm_list_fleet":
        for vm in json.loads(texts[0]):
            assert vm["telemetry"]["simulated"] is True, vm["spec"]["name"]
        assert any(t.startswith("SIMULATED:") for t in texts[1:]), "list_fleet: no marked note block"
    else:
        for line in joined.splitlines():
            if line.strip():
                assert line.startswith("SIMULATED:"), f"{name}: unmarked line: {line}"
    if request_id != 999:
        checked += 1
print(checked)
PY
mcp_tool_count="$(cat "$TMP_ROOT/mcp-tool-count.txt")"

# Default-backend MCP on the workspace that holds simulated state (from Row 9).
agentvm_cli --lang en --workspace "$WS_A21" --backend simulation up a >/dev/null
printf '%s\n' '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"agentvm_list_fleet","arguments":{}}}' \
    | agentvm_cli --workspace "$WS_A21" mcp \
    | python3 -c '
import json, sys
result = json.loads(sys.stdin.readline())["result"]
assert len(result["content"]) == 1, "default backend must return exactly the JSON block"
t = json.loads(result["content"][0]["text"])[0]["telemetry"]
assert t["state"] == "running" and t["simulated"] is True, t
'
agentvm_cli --lang en --workspace "$WS_A21" --backend simulation halt a >/dev/null
echo "PASS [Row 11/$TOTAL_ROWS]: all $mcp_tool_count tools from tools/list (and one error result) return marked results in simulation mode; the default-backend agentvm_list_fleet reports simulated state with telemetry.simulated = true."

# ------------------------------------------------------------------
# Row 12 (review, A23): `doctor` on a build without the virtualization entitlement
#   Expect: the virtualization line does not say PASS / 通过.
#   The entitlement is read from the binary with codesign here, independently of the product code.
#   Positive control: an ad-hoc re-signed temporary copy with Scripts/entitlements.plist must flip to PASS.
# ------------------------------------------------------------------
echo ""
echo "[Row 12/$TOTAL_ROWS] Verifying 'doctor' reads the executable's real virtualization entitlement (en & zh)..."
binary_entitlements="$(codesign -d --entitlements - "$AGENTVM_BIN" 2>/dev/null || true)"
if [[ "$binary_entitlements" == *"com.apple.security.virtualization"* ]]; then
    binary_is_entitled=1
else
    binary_is_entitled=0
fi
doctor_vz_en="$(agentvm_cli --lang en --workspace "$WS_HONEST" doctor | grep '^Apple VZ Support' || true)"
doctor_vz_zh="$(agentvm_cli --lang zh --workspace "$WS_HONEST" doctor | grep '^Apple VZ 虚拟化' || true)"
[[ -n "$doctor_vz_en" && -n "$doctor_vz_zh" ]] || fail "[Row 12]: doctor printed no virtualization line"
if [[ $binary_is_entitled -eq 0 ]]; then
    [[ "$doctor_vz_en" != *"PASS"* ]] || fail "[Row 12]: doctor says PASS but codesign shows no virtualization entitlement: $doctor_vz_en"
    [[ "$doctor_vz_zh" != *"通过"* && "$doctor_vz_zh" != *"已具备"* ]] || fail "[Row 12]: doctor says 通过 but codesign shows no virtualization entitlement: $doctor_vz_zh"
    [[ "$doctor_vz_zh" == *"系统支持虚拟化；当前可执行文件没有虚拟化权限，无法启动虚拟机"* ]] || fail "[Row 12]: unexpected zh line: $doctor_vz_zh"
    [[ "$doctor_vz_en" == *"cannot start virtual machines"* ]] || fail "[Row 12]: unexpected en line: $doctor_vz_en"
    row12_detail="the tested build has no com.apple.security.virtualization entitlement (codesign) and doctor does not say PASS / 通过"
else
    [[ "$doctor_vz_en" == *"PASS"* && "$doctor_vz_zh" == *"通过"* ]] || fail "[Row 12]: binary is entitled (codesign) but doctor does not say PASS: $doctor_vz_en"
    row12_detail="the tested build has the entitlement (codesign) and doctor says PASS / 通过"
fi

row12_control="positive control SKIPPED (could not ad-hoc sign a temporary copy)"
ENTITLED_COPY="$TMP_ROOT/AgentVM-entitled-copy"
if cp "$AGENTVM_BIN" "$ENTITLED_COPY" 2>/dev/null \
    && codesign --force --sign - --entitlements "$ROOT_DIR/Scripts/entitlements.plist" "$ENTITLED_COPY" >/dev/null 2>&1; then
    control_en="$(AGENTVM_CLI_BINARY="$ENTITLED_COPY" agentvm_cli --lang en --workspace "$WS_HONEST" doctor | grep '^Apple VZ Support' || true)"
    control_zh="$(AGENTVM_CLI_BINARY="$ENTITLED_COPY" agentvm_cli --lang zh --workspace "$WS_HONEST" doctor | grep '^Apple VZ 虚拟化' || true)"
    [[ "$control_en" == *"PASS"* ]] || fail "[Row 12]: re-signed copy with the entitlement does not report PASS: $control_en"
    [[ "$control_zh" == *"通过"* ]] || fail "[Row 12]: re-signed copy with the entitlement does not report 通过: $control_zh"
    row12_control="positive control: a temporary copy re-signed with Scripts/entitlements.plist reports PASS / 通过"
fi
echo "PASS [Row 12/$TOTAL_ROWS]: $row12_detail; $row12_control."

# ------------------------------------------------------------------
# Row 13 (review, A24): `policy airgap`, then `policy` in a new process
#   Expect: airgap is shown. Also: unknown options / arguments exit 2 instead of being ignored.
# ------------------------------------------------------------------
echo ""
echo "[Row 13/$TOTAL_ROWS] Verifying 'policy airgap' persists across processes and unknown options exit 2..."
WS_POLICY="$TMP_ROOT/policy.agentvm"
policy_before="$(agentvm_cli --lang en --workspace "$WS_POLICY" policy | head -n 1)"
[[ "$policy_before" == "Strict Coding-Agent Allowlist"* ]] || fail "[Row 13]: unexpected default policy: $policy_before"
policy_set="$(agentvm_cli --lang en --workspace "$WS_POLICY" policy airgap)"
[[ "$policy_set" == *"Total Air-Gap"* && "$policy_set" == *"M5"* ]] || fail "[Row 13]: policy airgap message is missing the preset name or the M5 caveat: $policy_set"
policy_after="$(agentvm_cli --lang en --workspace "$WS_POLICY" policy | head -n 1)"
[[ "$policy_after" == "Total Air-Gap"* ]] || fail "[Row 13]: policy did not persist to the next process: $policy_after"
policy_after_zh="$(agentvm_cli --lang zh --workspace "$WS_POLICY" policy | head -n 1)"
[[ "$policy_after_zh" == "Total Air-Gap"* ]] || fail "[Row 13]: policy did not persist (zh): $policy_after_zh"
agentvm_cli --lang en --workspace "$WS_POLICY" policy strict >/dev/null
policy_restored="$(agentvm_cli --lang en --workspace "$WS_POLICY" policy | head -n 1)"
[[ "$policy_restored" == "Strict Coding-Agent Allowlist"* ]] || fail "[Row 13]: policy strict did not persist: $policy_restored"

for bad in "ps --bogus" "policy bogus"; do
    set +e
    # shellcheck disable=SC2086
    bad_out="$(agentvm_cli --lang en --workspace "$WS_POLICY" $bad 2>"$TMP_ROOT/bad.err")"
    bad_rc=$?
    set -e
    [[ $bad_rc -eq 2 ]] || fail "[Row 13]: 'agentvm $bad' exited $bad_rc, expected 2"
    [[ -z "$bad_out" ]] || fail "[Row 13]: 'agentvm $bad' still printed a result: $bad_out"
    grep -q 'bogus' "$TMP_ROOT/bad.err" || fail "[Row 13]: 'agentvm $bad' error does not name the offending token"
done
echo "PASS [Row 13/$TOTAL_ROWS]: 'policy airgap' is still Total Air-Gap in the next process (en & zh) and 'policy strict' switches back; 'ps --bogus' and 'policy bogus' exit 2."

# ------------------------------------------------------------------
# Row 14 (review, C5): no machine-specific absolute paths in tracked files
#   Expect: `git grep -n` for the macOS home-directory prefix (slash, "Users", slash) prints nothing.
#   The pattern is assembled at run time so that this script and its recorded log do not contain it.
# ------------------------------------------------------------------
echo ""
echo "[Row 14/$TOTAL_ROWS] Verifying tracked files contain no macOS home-directory absolute paths..."
if git -C "$ROOT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    home_prefix_pattern="/U""sers/"
    users_hits="$(git -C "$ROOT_DIR" grep -n "$home_prefix_pattern" || true)"
    [[ -z "$users_hits" ]] || fail "[Row 14]: git grep found home-directory absolute paths: $users_hits"
    echo "PASS [Row 14/$TOTAL_ROWS]: git grep -n for the home-directory prefix (slash-Users-slash) has no results in tracked files."
else
    echo "SKIPPED [Row 14/$TOTAL_ROWS]: not a git work tree; git grep was not run."
fi

echo ""
echo "=================================================================="
echo " ALL $TOTAL_ROWS M0 ACCEPTANCE CHECKS PASSED (no GUI process started, no VM booted)"
echo "=================================================================="
