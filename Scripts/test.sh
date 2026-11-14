#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
    cat >&2 <<'EOF'
Usage:
  Scripts/test.sh scope <Module...>
  Scripts/test.sh milestone <0|1|2|3|4|5|6>
  Scripts/test.sh release

Modules:
  AgentVMModels
  AgentVMStore
  AgentVMStorageCoW
  AgentVMNetSwitch
  AgentVMVsockRPC
  AgentVMPluginHost
  AgentVMHypervisor
  AgentVMCLIAndMCP
  AgentVMWorkbenchShell
  AgentVMStudioViews
EOF
    exit 64
}

map_module_to_filters() {
    local mod="$1"
    case "$mod" in
        AgentVMModels|Models)
            echo "ModelsAndBinaryPrimitivesTests"
            echo "BilingualLocalizationTests"
            ;;
        AgentVMStore|Store)
            echo "StoreMigrationsAndUndoTests"
            ;;
        AgentVMStorageCoW|StorageCoW)
            echo "StorageCoWIsoAndGPTTests"
            ;;
        AgentVMNetSwitch|NetSwitch)
            echo "NetSwitchDissectorAndPCAPTests"
            ;;
        AgentVMVsockRPC|VsockRPC)
            echo "VsockRPCAndTerminalTests"
            ;;
        AgentVMPluginHost|PluginHost)
            echo "PluginSandboxAndIACTests"
            ;;
        AgentVMHypervisor|Hypervisor)
            echo "HypervisorCoordinatorTests"
            ;;
        AgentVMCLIAndMCP|CLIAndMCP)
            echo "CLIAndMCPTests"
            echo "BilingualLocalizationTests"
            ;;
        AgentVMWorkbenchShell|WorkbenchShell)
            echo "WorkbenchShellTests"
            ;;
        AgentVMStudioViews|StudioViews)
            echo "StudioViewsHonestyTests"
            ;;
        AgentVM)
            echo "CLIAndMCPTests"
            echo "StudioViewsHonestyTests"
            ;;
        *)
            echo "ERROR: Unknown module '$mod'" >&2
            exit 64
            ;;
    esac
}

run_scope() {
    if [[ $# -eq 0 ]]; then
        usage
    fi

    local filters=()
    local mod
    for mod in "$@"; do
        while IFS= read -r f; do
            [[ -n "$f" ]] || continue
            local seen=0
            local existing
            for existing in "${filters[@]+"${filters[@]}"}"; do
                if [[ "$existing" == "$f" ]]; then
                    seen=1
                    break
                fi
            done
            if [[ $seen -eq 0 ]]; then
                filters+=("$f")
            fi
        done < <(map_module_to_filters "$mod")
    done

    local filter_args=()
    local f
    for f in "${filters[@]}"; do
        filter_args+=(--filter "$f")
    done

    echo "==> [AgentVM] Scoped unit tests: ${filters[*]}"
    swift test --no-parallel "${filter_args[@]}"
}

run_milestone() {
    local m="${1:-}"
    case "$m" in
        0)
            echo "==> [AgentVM] Milestone M0: touched module unit scopes"
            run_scope \
                AgentVMModels \
                AgentVMStore \
                AgentVMPluginHost \
                AgentVMHypervisor \
                AgentVMCLIAndMCP \
                AgentVMWorkbenchShell \
                AgentVMStudioViews
            if [[ -x "$ROOT_DIR/Scripts/acceptance/m0-acceptance.sh" ]]; then
                echo "==> [AgentVM] Milestone M0: m0-acceptance.sh"
                "$ROOT_DIR/Scripts/acceptance/m0-acceptance.sh"
            else
                echo "ERROR: Scripts/acceptance/m0-acceptance.sh not found or not executable" >&2
                exit 1
            fi
            if [[ -x "$ROOT_DIR/Scripts/acceptance/readme-commands.sh" ]]; then
                echo "==> [AgentVM] Milestone M0: readme-commands.sh"
                "$ROOT_DIR/Scripts/acceptance/readme-commands.sh"
            else
                echo "ERROR: Scripts/acceptance/readme-commands.sh not found or not executable" >&2
                exit 1
            fi
            ;;
        1|2|3|4|5|6)
            echo "SKIPPED: Milestone M${m} acceptance script is scheduled for M${m} (current branch is M0)."
            exit 1
            ;;
        *)
            usage
            ;;
    esac
}

run_release() {
    echo "==> [AgentVM] Release gate: full unit test suite (--no-parallel)"
    swift test --no-parallel

    if [[ -x "$ROOT_DIR/Scripts/acceptance/m0-acceptance.sh" ]]; then
        echo "==> [AgentVM] Release gate: m0-acceptance.sh"
        "$ROOT_DIR/Scripts/acceptance/m0-acceptance.sh"
    else
        echo "ERROR: Scripts/acceptance/m0-acceptance.sh missing" >&2
        exit 1
    fi

    if [[ -x "$ROOT_DIR/Scripts/acceptance/readme-commands.sh" ]]; then
        echo "==> [AgentVM] Release gate: readme-commands.sh"
        "$ROOT_DIR/Scripts/acceptance/readme-commands.sh"
    else
        echo "ERROR: Scripts/acceptance/readme-commands.sh missing" >&2
        exit 1
    fi

    if [[ "${AGENTVM_REAL_VM:-0}" == "1" ]]; then
        echo "==> [AgentVM] AGENTVM_REAL_VM=1: checking real-VM milestone scripts"
        local found_real=0
        local script
        for script in "$ROOT_DIR"/Scripts/acceptance/m[1-6]-acceptance.sh; do
            if [[ -x "$script" ]]; then
                found_real=1
                "$script"
            fi
        done
        if [[ $found_real -eq 0 ]]; then
            echo "SKIPPED: No M1-M6 real-VM acceptance scripts present in M0."
        fi
    else
        echo "SKIPPED (AGENTVM_REAL_VM!=1): Real Virtualization.framework guest VM tests (M1-M6) were not run."
    fi
}

cmd="${1:-}"
shift || true

case "$cmd" in
    scope)
        run_scope "$@"
        ;;
    milestone)
        run_milestone "$@"
        ;;
    release)
        run_release
        ;;
    *)
        usage
        ;;
esac
