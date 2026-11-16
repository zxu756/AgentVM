#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Build parallelism: set AGENTVM_BUILD_JOBS=N to pass `-j N` to every swift build/test this script starts.
SWIFT_JOBS_ARGS=()
if [[ -n "${AGENTVM_BUILD_JOBS:-}" ]]; then
    SWIFT_JOBS_ARGS=(-j "$AGENTVM_BUILD_JOBS")
fi

usage() {
    cat >&2 <<'EOF'
Usage:
  Scripts/test.sh scope <Module...>
  Scripts/test.sh milestone <0|1|2|3|4|5|6> [--record]
  Scripts/test.sh release

  milestone <N> writes the acceptance logs to a temporary directory and leaves the working tree untouched.
  Pass --record to copy them into reports/ (the committed evidence the README refers to).
  milestone 1 requires AGENTVM_REAL_VM=1; without it, the real-VM portion is reported unrun and exits non-zero.
  No mode of this script launches the desktop UI.

Environment:
  AGENTVM_REAL_VM=1      enable real Virtualization.framework guest VM acceptance (m1-real-boot.sh)
  AGENTVM_BUILD_JOBS=N   pass `-j N` to swift build / swift test

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
            echo "CLIAndMCPSimulationHonestyTests"
            echo "BilingualLocalizationTests"
            echo "CLIAndMCPDaemonRPCTests"
            ;;
        AgentVMWorkbenchShell|WorkbenchShell)
            echo "WorkbenchShellTests"
            ;;
        AgentVMStudioViews|StudioViews)
            echo "StudioViewsHonestyTests"
            ;;
        AgentVM)
            echo "CLIAndMCPTests"
            echo "CLIAndMCPSimulationHonestyTests"
            echo "CLIAndMCPDaemonRPCTests"
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
    swift test "${SWIFT_JOBS_ARGS[@]+"${SWIFT_JOBS_ARGS[@]}"}" --no-parallel "${filter_args[@]}"
}

# Runs one acceptance script, showing its output and keeping a copy in "$2".
run_logged() {
    local script="$1"
    local log_file="$2"
    if [[ ! -x "$script" ]]; then
        echo "ERROR: $script not found or not executable" >&2
        exit 1
    fi
    set +e
    "$script" 2>&1 | tee "$log_file"
    local rc=${PIPESTATUS[0]}
    set -e
    if [[ $rc -ne 0 ]]; then
        echo "ERROR: $(basename "$script") failed (exit $rc); log kept at $log_file" >&2
        exit "$rc"
    fi
}

run_milestone() {
    local m="${1:-}"
    local record=0
    local extra
    for extra in "${@:2}"; do
        case "$extra" in
            --record) record=1 ;;
            *) echo "ERROR: Unknown milestone option '$extra'" >&2; usage ;;
        esac
    done
    case "$m" in
        0)
            echo "==> [AgentVM] Milestone M0: touched module unit scopes"
            run_scope \
                AgentVMModels \
                AgentVMStore \
                AgentVMNetSwitch \
                AgentVMPluginHost \
                AgentVMHypervisor \
                AgentVMCLIAndMCP \
                AgentVMWorkbenchShell \
                AgentVMStudioViews

            # Acceptance logs go to a temporary directory. reports/ is only rewritten on --record,
            # so a plain run never dirties the working tree.
            local log_dir
            log_dir="$(mktemp -d "${TMPDIR:-/tmp}/agentvm-m0-logs.XXXXXX")"
            echo "==> [AgentVM] Milestone M0: m0-acceptance.sh"
            run_logged "$ROOT_DIR/Scripts/acceptance/m0-acceptance.sh" "$log_dir/m0-acceptance.txt"
            echo "==> [AgentVM] Milestone M0: readme-commands.sh"
            run_logged "$ROOT_DIR/Scripts/acceptance/readme-commands.sh" "$log_dir/readme-commands.txt"

            if [[ $record -eq 1 ]]; then
                mkdir -p "$ROOT_DIR/reports"
                cp "$log_dir/m0-acceptance.txt" "$ROOT_DIR/reports/m0-acceptance.txt"
                cp "$log_dir/readme-commands.txt" "$ROOT_DIR/reports/readme-commands.txt"
                rm -rf "$log_dir"
                echo "==> [AgentVM] Recorded reports/m0-acceptance.txt and reports/readme-commands.txt"
            else
                echo "==> [AgentVM] Acceptance logs: $log_dir (reports/ left untouched; pass --record to update it)"
            fi
            ;;
        1)
            echo "==> [AgentVM] Milestone M1: touched module unit scopes"
            run_scope \
                AgentVMModels \
                AgentVMStore \
                AgentVMStorageCoW \
                AgentVMVsockRPC \
                AgentVMHypervisor \
                AgentVMCLIAndMCP \
                AgentVMStudioViews \
                AgentVM

            local log_dir
            log_dir="$(mktemp -d "${TMPDIR:-/tmp}/agentvm-m1-logs.XXXXXX")"
            echo "==> [AgentVM] Milestone M1: m0-acceptance.sh"
            run_logged "$ROOT_DIR/Scripts/acceptance/m0-acceptance.sh" "$log_dir/m0-acceptance.txt"
            echo "==> [AgentVM] Milestone M1: readme-commands.sh"
            run_logged "$ROOT_DIR/Scripts/acceptance/readme-commands.sh" "$log_dir/readme-commands.txt"

            if [[ "${AGENTVM_REAL_VM:-}" != "1" ]]; then
                echo "==> [AgentVM] Milestone M1: m1-real-boot.sh"
                set +e
                "$ROOT_DIR/Scripts/acceptance/m1-real-boot.sh" 2>&1 | tee "$log_dir/m1-real-boot.txt"
                local real_rc=${PIPESTATUS[0]}
                set -e
                [[ $real_rc -ne 0 ]] || real_rc=2
                echo "UNRUN: Milestone M1 real-VM acceptance (m1-real-boot.sh) did not run because AGENTVM_REAL_VM=1 is not set; milestone 1 does not pass without real-VM verification (logs at $log_dir)." >&2
                exit "$real_rc"
            fi

            echo "==> [AgentVM] Milestone M1: m1-real-boot.sh"
            run_logged "$ROOT_DIR/Scripts/acceptance/m1-real-boot.sh" "$log_dir/m1-real-boot.txt"

            if [[ $record -eq 1 ]]; then
                mkdir -p "$ROOT_DIR/reports"
                cp "$log_dir/m0-acceptance.txt" "$ROOT_DIR/reports/m0-acceptance.txt"
                cp "$log_dir/readme-commands.txt" "$ROOT_DIR/reports/readme-commands.txt"
                cp "$log_dir/m1-real-boot.txt" "$ROOT_DIR/reports/m1-real-boot.txt"
                rm -rf "$log_dir"
                echo "==> [AgentVM] Recorded reports/m0-acceptance.txt, reports/readme-commands.txt, and reports/m1-real-boot.txt"
            else
                echo "==> [AgentVM] Acceptance logs: $log_dir (reports/ left untouched; pass --record to update it)"
            fi
            ;;
        2|3|4|5|6)
            echo "SKIPPED: Milestone M${m} acceptance script is scheduled for M${m} (current branch is M1)."
            exit 1
            ;;
        *)
            usage
            ;;
    esac
}

run_release() {
    echo "==> [AgentVM] Release gate: full unit test suite (--no-parallel)"
    swift test "${SWIFT_JOBS_ARGS[@]+"${SWIFT_JOBS_ARGS[@]}"}" --no-parallel

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
        echo "==> [AgentVM] AGENTVM_REAL_VM=1: running real-VM milestone scripts"
        local found_real=0
        local script
        for script in "$ROOT_DIR"/Scripts/acceptance/m[1-6]-*.sh; do
            if [[ -x "$script" ]]; then
                found_real=1
                echo "==> [AgentVM] Release gate: $(basename "$script")"
                "$script"
            fi
        done
        if [[ $found_real -eq 0 ]]; then
            echo "ERROR: No M1-M6 real-VM acceptance scripts found." >&2
            exit 1
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
