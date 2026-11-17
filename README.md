**English** | **[简体中文](README.zh-CN.md)**

# AgentVM `v1.4.0`

> **Current Status (M2 — Per-Workspace Daemon & Live Guest Telemetry)**: APFS Copy-on-Write (`clonefile(2)`) sparse disk & offline snapshot lineage management, SQLite WAL workspace persistence, pure-Swift NoCloud `cidata` ISO-9660 generation, and sandboxed `JavaScriptCore` policy evaluation work locally today. Ethernet/IPv4/DNS/TLS frame dissection and `.pcapng` reading/writing exist as a library (`AgentVMNetSwitch`, covered by unit tests); neither the CLI nor the desktop UI can open a capture file yet. `agentvm image pull debian-12-bookworm-arm64` downloads a pinned Debian 12 arm64 cloud image and verifies its SHA-512; `agentvm run <vm> -- <cmd>` runs a one-shot command on `VZVirtualMachine` and shuts the guest down; and in M2 a per-workspace background daemon (`daemon start|status|stop`, `events`) holds running `VZVirtualMachine` instances across separate CLI invocations so `up`, `exec` (concurrent `AF_VSOCK` stdout/stderr/exit-code streaming with `SIGINT`/`SIGTERM` cancellation on newly created VMs; stdin is `/dev/null`), `pause`, `resume`, and `halt` operate real guests and report live guest `/proc` CPU, memory, and uptime heartbeats in `ps`. Booting needs a binary carrying `com.apple.security.virtualization`, which a plain `swift build` binary lacks. Live snapshot/branch/restore on a running VM is refused until M3; the desktop UI and MCP server read state and telemetry from SQLite and refuse to mutate daemon-held VMs until M4; guest networking uses system NAT with no egress enforcement or live packet capture until M5.

[![Version](https://img.shields.io/badge/version-v1.4.0-D97724)](https://github.com/zxu756/AgentVM/releases)
[![Platform](https://img.shields.io/badge/platform-macOS%2014%2B%20(Apple%20Silicon)-141517)](https://github.com/zxu756/AgentVM)
[![Swift](https://img.shields.io/badge/Swift-6.0%20Strict%20Concurrency-D97724)](https://swift.org)
[![Bilingual](https://img.shields.io/badge/UI-中文%20%7C%20EN-2A9D6F)](README.zh-CN.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-2A9D6F)](LICENSE)

`AgentVM` is a macOS (Apple Silicon) workspace manager and APFS Copy-on-Write disk & snapshot lineage tool with a CLI, a stdio MCP server and a desktop workbench, written in Swift 6, with live `中文 | EN` bilingual switching across the desktop UI and CLI (`--lang en` / `--lang zh`). Persistent real VMs are held by one background daemon per workspace (`agentvm up` / `exec` / `pause` / `resume` / `halt`), one-shot VMs run via `agentvm run`, and the workbench's packet and firewall views have no real traffic to show before M5.

By default, launching the desktop app or initializing a `.agentvm` workspace starts completely empty (0 VMs, 0 packets, 0 alerts) and never fabricates guest execution or telemetry:

- Creating a VM provisions a sparse GPT disk image and a NoCloud `cidata` ISO-9660 seed image. Without `--image` no guest OS is installed; with `--image debian-12-bookworm-arm64` the root disk is a clone of the cached image.
- Running `agentvm up <vm>` on an empty disk, or `agentvm exec <vm> -- ...` on an empty disk or a VM that is not running, exits non-zero with an explicit error instead of silently falling back to a simulator (a failed `up` preflight does not start a background daemon). `agentvm up` on a stopped VM that has a guest OS boots it. `agentvm run` on an empty disk exits 125.
- One background daemon per workspace (`<workspace>/run/daemon.sock`, started on demand by `up` or `daemon start` via double-fork `setsid`, not `launchd`) holds running VMs. Logging out of macOS or rebooting the host is **not** guaranteed to preserve running VMs; if the daemon exits or is killed, VMs exit and subsequent reads reconcile stale `running` records to `stopped` (`VM_RUNTIME_LOST`).
- The guest agent script (`agentvm-guestd.py` v2) is written into the guest via `cloud-init` only when a new VM boots for the first time. VMs created before M2 keep the older `1.0.0` guest script: `SIGINT`/`SIGTERM` cancellation of `exec` has no effect on the guest child process on those older VMs, and their heartbeats omit CPU usage so `ps` shows `—` in the CPU column (recreate the VM from `--image debian-12-bookworm-arm64` to pick up the v2 script).
- Host-side protocol & wire-session simulation is available only when explicitly requested via `--backend simulation` or in UI demonstration mode (`--demo` / **Load Demo**, labeled `[DEMO]`). Every output of a simulation run is marked: text lines are prefixed with `SIMULATED:`, `ps --json` and MCP `agentvm_list_fleet` records carry `"simulated": true`, `export-hcl` gets a `# SIMULATED:` comment line, and exported `.pcapng` and HTML files are marked inside the file.
- State the simulator leaves in a workspace stays marked for everyone who reads it later: a default `agentvm ps` prints `SIMULATED:running`, `ps --json` shows `"simulated": true` next to `"state": "running"`, and the default backend never acts on it (`up`, `exec`, `pause` discard the simulated state and fail as they would on a VM that never ran).
- Unmeasured or stale CPU and memory fields (no heartbeat within 15 seconds, paused, or stopped) are displayed as `—`.
- A guest started with `agentvm up` or `agentvm run` uses the system NAT, and nothing controls its egress before M5: `agentvm policy strict|airgap` only selects and saves a preset and enforces nothing on real traffic, and with `airgap` selected `agentvm up` exits 1 and `agentvm run` exits 125 because booting without a network is not possible before M5. The user-space switch has no route to the outside network before M5. The Wiretap and Firewall views display `Not connected to live traffic yet (scheduled for M5)`.
- `agentvm doctor` reports whether the running executable actually carries the `com.apple.security.virtualization` entitlement. A plain `swift build` binary does not, and `doctor` says so instead of printing `PASS`.

---

## Status & Milestone Roadmap

| Milestone | Capability | Status |
|---|---|---|
| **M0** | Honest baseline: plain `agentvm ps` fix, real `clonefile(2)` probe and real entitlement check in `doctor`, empty default UI, explicit `--backend simulation` with `SIMULATED` markers on every output and on stored state, `[DEMO]` gating, `—` for unmeasured telemetry, preemptive `JavaScriptCore` hook watchdog | **Implemented** |
| **M1** | `agentvm image pull debian-12-bookworm-arm64` + single-command `agentvm run` booting a real Linux kernel/rootfs on `VZVirtualMachine` with live `AF_VSOCK` stdout/stderr/exit-code streaming | **Implemented** |
| **M2** | One background daemon per workspace so `up`, `exec`, `pause`, `resume`, `halt`, `daemon`, and `events` work across separate CLI invocations, plus live guest `/proc` CPU, memory, and uptime telemetry | **Implemented** |
| **M3** | Measured APFS CoW branching (`branch`) and snapshot restore (`snapshot` / `restore`) against real Linux root filesystems, including live running VMs (measured latency and dirty-byte delta to be reported after M3) | Planned |
| **M4** | Desktop UI and MCP server wired as clients of the workspace daemon, directory sharing, port forwarding, `exec` stdin streaming, and interactive terminal | Planned |
| **M5** | Live guest NIC attachment to the user-space Layer-2 switch, outbound DNS/TLS SNI policy enforcement, and real guest `.pcapng` capture | Planned (under evaluation) |

---

## Verified CLI Quick Start

Build the `AgentVM` executable from source and run all commands against an isolated `.agentvm` workspace. Lines starting with `# ->` show the documented result; `...` stands for text that varies (IDs, paths, timings). `Scripts/acceptance/readme-commands.sh` reads this block and fails if a command or one of these results no longer matches.

```bash
swift build --product AgentVM
alias agentvm="$(pwd)/.build/debug/AgentVM"

# 1. Host readiness check (live APFS clonefile(2) probe on the workspace volume; reads this executable's virtualization entitlement)
agentvm --lang en --workspace ./demo-check.agentvm doctor
# -> APFS clonefile(2) : PASS (verified via live clonefile(2) probe)

# 2. Initialize an empty workspace and create an empty sparse GPT VM record
agentvm --lang en --workspace ./demo-check.agentvm init
# -> Initialized workspace 'demo-check' (...) at ...
agentvm --lang en --workspace ./demo-check.agentvm create sandbox-a
# -> Created VM 'sandbox-a' (...) with root snapshot ... (empty sparse GPT disk, no guest OS installed)

# 3. List VMs in table or JSON form (unmeasured CPU/RAM shown as —)
agentvm --lang en --workspace ./demo-check.agentvm ps
# -> sandbox-a ... stopped
agentvm --lang en --workspace ./demo-check.agentvm ps --json
# -> "state" : "stopped"

# 4. Fork an APFS Copy-on-Write disk branch, list snapshots, inspect plugins, and export HCL
agentvm --lang en --workspace ./demo-check.agentvm branch sandbox-a sandbox-b --no-boot
# -> Forked CoW branch 'sandbox-b' (...) in ... ms from snapshot ...
agentvm --lang en --workspace ./demo-check.agentvm snapshot list
# -> Golden Base (sandbox-a) ... Branch Fork -> sandbox-b ... CoW Head (sandbox-b)
agentvm --lang en --workspace ./demo-check.agentvm plugin
# -> builtin.secret-leak-guard ... ENABLED
agentvm --lang en --workspace ./demo-check.agentvm export-hcl
# -> sandbox_vm "sandbox-a" ... sandbox_vm "sandbox-b"

# 5. Booting or executing on an empty/stopped disk fails honestly; halt, daemon status/stop, and events work without spawning a daemon
agentvm --lang en --workspace ./demo-check.agentvm up sandbox-a
# -> exits non-zero: [ERR_NO_BOOTABLE_SYSTEM] VM 'sandbox-a' has no bootable guest OS or kernel on its disk...
agentvm --lang en --workspace ./demo-check.agentvm exec sandbox-a -- uname -a
# -> exits non-zero: [ERR_LIFECYCLE_STATE] Cannot perform 'exec' on VM 'sandbox-a' (...) while in state 'stopped' (guest is not running). Run 'agentvm up sandbox-a' first.
agentvm --lang en --workspace ./demo-check.agentvm halt sandbox-a
# -> VM 'sandbox-a' (...) -> stopped
agentvm --lang en --workspace ./demo-check.agentvm daemon status
# -> exits non-zero: Daemon is not running (workspace: ...).
agentvm --lang en --workspace ./demo-check.agentvm daemon stop
# -> Daemon is not running; nothing to stop.
agentvm --lang en --workspace ./demo-check.agentvm events --json
# -> "code" : "COW_BRANCH_FORKED"

# 6. Explicit host-side simulation requires --backend simulation and prefixes every line with SIMULATED:
#    (the simulator answers with a fixed hostname, "agent-sandbox", whatever the VM is called)
agentvm --lang en --workspace ./demo-check.agentvm --backend simulation exec sandbox-a -- uname -a
# -> SIMULATED: Linux agent-sandbox 6.8.0-agentvm-arm64 #1 SMP PREEMPT_DYNAMIC aarch64 GNU/Linux

# 7. What the simulator left behind stays marked for the default backend, in text and in JSON
agentvm --lang en --workspace ./demo-check.agentvm ps
# -> sandbox-a ... SIMULATED:running
# -> SIMULATED: 1 VM state(s) above were written by --backend simulation; no real guest is running.
agentvm --lang en --workspace ./demo-check.agentvm ps --json
# -> "simulated" : true
agentvm --lang en --workspace ./demo-check.agentvm --backend simulation halt sandbox-a
# -> SIMULATED: VM 'sandbox-a' (...) -> stopped
```

Unknown options are errors, not ignored: `agentvm ps --bogus` exits with code 2. With an entitled binary and a cached Debian 12 image (`agentvm image pull debian-12-bookworm-arm64`), `agentvm create t1 --image debian-12-bookworm-arm64`, `agentvm up t1`, `agentvm exec t1 -- uname -r`, `agentvm halt t1`, `agentvm daemon status`, `agentvm daemon stop`, and `agentvm events --vm t1` manage a real running guest through the workspace daemon (exercised by `AGENTVM_REAL_VM=1 ./Scripts/test.sh milestone 2`).

Every command also supports Simplified Chinese output via `--lang zh` (or `AGENTVM_LANG=zh`):

```bash
agentvm --lang zh --workspace ./demo-check.agentvm doctor
agentvm --lang zh --workspace ./demo-check.agentvm ps
```

---

## Desktop Workbench Preview (`[DEMO]` Synthetic Dataset)

> **Demonstration Data Notice**: All screenshots below were rendered in explicit `--demo` mode (`DEMO · SYNTHETIC DATA`). The VMs, CoW branches, Ethernet/TLS frames, and policy counters shown in these captures are synthetic demonstration fixtures, not captures from live running guest VMs. Launching `AgentVM` normally opens an empty workspace. These images were rendered before the status bar was corrected: in them it reads `Hypervisor: Apple VZ`, while the demonstration fleet runs on the host-side simulator. Current builds show `Hypervisor: SIMULATED` in demonstration mode and `SIMULATED · Running` on each demonstration VM; the images have not been re-rendered yet.

### Overview & Snapshot Lineage DAG (`[DEMO]` Synthetic Data)
![AgentVM Overview & CoW Lineage DAG — Synthetic Demo Data](docs/screenshot-overview-dag.png)

### Offline Packet Dissector & Hex View (`[DEMO]` Synthetic Data — Live Traffic Scheduled for M5)
![AgentVM Packet Dissector — Synthetic Demo Data](docs/screenshot-packet-inspector.png)

### APFS Sparse Extent Map & NoCloud ISO-9660 Inspector (`[DEMO]` Synthetic Data)
![AgentVM APFS Extents & Cloud-Init Inspector — Synthetic Demo Data](docs/screenshot-storage-cloudinit.png)

### Policy Rule Simulator & JavaScriptCore Plugin Host (`[DEMO]` Synthetic Data — Live Traffic Scheduled for M5)
![AgentVM Firewall Simulator & JS Plugin Host — Synthetic Demo Data](docs/screenshot-plugins-policy.png)

---

## Testing & Verification Scripts

```bash
# Scoped unit tests for specific SwiftPM modules
./Scripts/test.sh scope AgentVMStore AgentVMHypervisor AgentVMCLIAndMCP

# Replay all documented README commands in a temporary workspace
./Scripts/acceptance/readme-commands.sh

# Run full M0 acceptance suite (20x cold CLI stability, honest failure checks, simulation-marker checks for CLI and MCP,
# doctor entitlement check, policy persistence, clean repo check, default-UI empty-state check).
# No script launches the desktop UI: the UI row is a windowless ViewModel test.
./Scripts/test.sh milestone 0

# Run the M1 acceptance suite. With AGENTVM_REAL_VM=1 it downloads the pinned Debian 12 arm64 image if it is not
# cached, signs a copy of the CLI with the virtualization entitlement and boots real guests without opening a window.
# Without the variable it prints that the real-VM part did not run and exits non-zero.
AGENTVM_REAL_VM=1 ./Scripts/test.sh milestone 1

# Run the M2 workspace daemon acceptance suite (scoped unit tests, M0 & README checks, m2-daemon.sh, and M1 regression).
# Without AGENTVM_REAL_VM=1, non-VM daemon checks run and real-VM rows are reported unrun (exit code 2).
AGENTVM_REAL_VM=1 ./Scripts/test.sh milestone 2
```

---

## Building the macOS App Bundle

```bash
./Scripts/build-app.sh
# Launch empty default workbench (0 VMs, 0 packets, 0 alerts):
open build/AgentVM.app
# Or launch with synthetic demonstration data explicitly enabled:
./build/AgentVM.app/Contents/MacOS/AgentVM --demo
```

`Scripts/build-app.sh` ad-hoc signs `AgentVM.app` with `com.apple.security.virtualization` on Apple Silicon (`macOS 14+`). The `.build/debug/AgentVM` binary produced by `swift build` is not signed with that entitlement; `agentvm doctor` reports this.

---

## License

Released under the [MIT License](LICENSE).
