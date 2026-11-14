#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

swift build --product AgentVM >/dev/null
AGENTVM_BIN="$ROOT_DIR/.build/debug/AgentVM"

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/agentvm-readme-check.XXXXXX")"
cleanup() {
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

echo "==> [readme-commands] Checking README.md & README.zh-CN.md for banned claims..."
if grep -rnEi "sub-20|20\s*ms|20\s*毫秒|under 20|不到\s*20|wireshark-grade|wireshark\s*级|industrial-grade|工业级|hardware-isolated|硬件级隔离|硬件隔离|every outbound packet|每一帧出站|destructive guest commands|破坏性客户机命令" "$ROOT_DIR/README.md" "$ROOT_DIR/README.zh-CN.md"; then
    echo "FAIL: Found banned unverified claim in README files" >&2
    exit 1
fi
echo "PASS: Zero banned claims in README.md and README.zh-CN.md"

replay_quick_start() {
    local lang="$1"
    local ws="$TMP_ROOT/demo-check-${lang}.agentvm"
    echo "==> [readme-commands] Replaying Quick-Start workflow (--lang $lang) in isolated temp workspace"

    local doc_out
    doc_out="$("$AGENTVM_BIN" --lang "$lang" --workspace "$ws" doctor)"
    [[ "$doc_out" == *"APFS clonefile(2)"* ]] || { echo "FAIL: doctor missing clonefile line ($lang)" >&2; exit 1; }
    [[ "$doc_out" != *"20ms"* && "$doc_out" != *"20 ms"* && "$doc_out" != *"20 毫秒"* ]] || { echo "FAIL: doctor contains 20ms claim ($lang)" >&2; exit 1; }

    local init_out
    init_out="$("$AGENTVM_BIN" --lang "$lang" --workspace "$ws" init)"
    [[ -n "$init_out" ]] || { echo "FAIL: init produced empty stdout ($lang)" >&2; exit 1; }

    local create_out
    create_out="$("$AGENTVM_BIN" --lang "$lang" --workspace "$ws" create sandbox-a)"
    [[ "$create_out" == *"sandbox-a"* ]] || { echo "FAIL: create missing sandbox-a ($lang)" >&2; exit 1; }

    local ps_out
    ps_out="$("$AGENTVM_BIN" --lang "$lang" --workspace "$ws" ps)"
    [[ "$ps_out" == *"sandbox-a"* && "$ps_out" == *"—"* ]] || { echo "FAIL: ps missing sandbox-a or em-dash telemetry ($lang)" >&2; exit 1; }

    local ps_json
    ps_json="$("$AGENTVM_BIN" --lang "$lang" --workspace "$ws" ps --json)"
    python3 -c '
import json, sys
vms = json.loads(sys.stdin.read())
assert len(vms) == 1 and vms[0]["spec"]["name"] == "sandbox-a", vms
assert vms[0]["telemetry"]["state"] == "stopped", vms[0]["telemetry"]
assert vms[0]["telemetry"]["hasLiveGuestTelemetry"] is False, vms[0]["telemetry"]
' <<<"$ps_json"

    local branch_out
    branch_out="$("$AGENTVM_BIN" --lang "$lang" --workspace "$ws" branch sandbox-a sandbox-b --no-boot)"
    [[ "$branch_out" == *"sandbox-b"* ]] || { echo "FAIL: branch missing sandbox-b ($lang)" >&2; exit 1; }

    local snap_out
    snap_out="$("$AGENTVM_BIN" --lang "$lang" --workspace "$ws" snapshot list)"
    [[ "$snap_out" == *"snap-"* ]] || { echo "FAIL: snapshot list missing snapshot ID ($lang)" >&2; exit 1; }

    local plugin_out
    plugin_out="$("$AGENTVM_BIN" --lang "$lang" --workspace "$ws" plugin)"
    [[ "$plugin_out" == *"builtin.secret-leak-guard"* ]] || { echo "FAIL: plugin missing builtin.secret-leak-guard ($lang)" >&2; exit 1; }
    [[ "$plugin_out" != *"20ms"* && "$plugin_out" != *"20 毫秒"* ]] || { echo "FAIL: plugin contains 20ms claim ($lang)" >&2; exit 1; }

    local hcl_out
    hcl_out="$("$AGENTVM_BIN" --lang "$lang" --workspace "$ws" export-hcl)"
    [[ "$hcl_out" == *'sandbox_vm "sandbox-a"'* && "$hcl_out" == *'sandbox_vm "sandbox-b"'* ]] || { echo "FAIL: export-hcl missing VM blocks ($lang)" >&2; exit 1; }

    # Step 5: Honest non-zero exit on empty disk `up` and `exec`
    set +e
    local up_err
    up_err="$("$AGENTVM_BIN" --lang "$lang" --workspace "$ws" up sandbox-a 2>&1 >/dev/null)"
    local up_rc=$?
    local exec_combined
    exec_combined="$("$AGENTVM_BIN" --lang "$lang" --workspace "$ws" exec sandbox-a -- uname -a 2>&1)"
    local exec_rc=$?
    set -e

    if [[ $up_rc -eq 0 ]]; then
        echo "FAIL: up sandbox-a unexpectedly succeeded on empty disk ($lang)" >&2
        exit 1
    fi
    if [[ "$lang" == "en" ]]; then
        [[ "$up_err" == *"[ERR_NO_BOOTABLE_SYSTEM] VM 'sandbox-a' has no bootable guest OS or kernel"* ]] || { echo "FAIL: unexpected EN up stderr: $up_err" >&2; exit 1; }
    else
        [[ "$up_err" == *"[ERR_NO_BOOTABLE_SYSTEM] 虚拟机「sandbox-a」磁盘上没有可引导的客户机系统"* ]] || { echo "FAIL: unexpected ZH up stderr: $up_err" >&2; exit 1; }
    fi

    if [[ $exec_rc -eq 0 ]]; then
        echo "FAIL: exec sandbox-a unexpectedly succeeded without --backend simulation ($lang)" >&2
        exit 1
    fi
    if [[ "$exec_combined" == *"Linux"* || "$exec_combined" == *"GNU/Linux"* ]]; then
        echo "FAIL: exec sandbox-a leaked Linux kernel output without --backend simulation ($lang): $exec_combined" >&2
        exit 1
    fi

    # Step 6: Explicit `--backend simulation` prefixes every line with `SIMULATED:`
    local sim_out
    sim_out="$("$AGENTVM_BIN" --lang "$lang" --workspace "$ws" --backend simulation exec sandbox-a -- uname -a)"
    [[ -n "$sim_out" ]] || { echo "FAIL: simulation exec returned empty output ($lang)" >&2; exit 1; }
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if [[ "$line" != SIMULATED:* ]]; then
            echo "FAIL: simulation output line missing SIMULATED: prefix ($lang): $line" >&2
            exit 1
        fi
    done <<<"$sim_out"

    echo "PASS: README Quick-Start verified for --lang $lang"
}

replay_quick_start "en"
replay_quick_start "zh"
echo "ALL README COMMAND CHECKS PASSED."
