**English** | **[简体中文](README.zh-CN.md)**

# AgentVM `v1.4.0`

> Boot real Linux virtual machines for coding agents on a Mac: `agentvm exec` and MCP `agentvm_exec_command` output comes from the guest itself, VirtioFS shares host project directories into `/workspace`, localhost TCP ports forward over `AF_VSOCK`, and forking a data-bearing VM takes **32.49 ms** (median wall-clock; nearest-rank p95 **58.26 ms**) and adds **0 B** of APFS private disk data bytes.
>
> *Fork benchmark measured on `2026-11-21` via `Scripts/acceptance/m3-branch-bench.sh` (`reports/m3-branch-bench.json`, reproduced by `AGENTVM_REAL_VM=1 ./Scripts/test.sh milestone 3 --record`) on `Mac16,10` (`Apple M4`, 10 cores, 16 GiB RAM), macOS `27.0.1` (`26A434`), APFS, with host `uptime` 1m/5m/15m load averages `1.77 2.24 2.39` at start and `1.98 2.53 2.51` at end, against an `8 GiB` `debian-12-bookworm-arm64` disk populated with `1 GiB` of random guest data (`/var/tmp/bench-data.bin`) and synced: 16 stopped `agentvm branch` invocations had a process wall-clock median of `32.49 ms` (min `26.48 ms`, p95 `58.26 ms`; CLI lock-to-SQLite median `13.52 ms`); 16 live running `agentvm branch` invocations via the workspace daemon had a wall-clock median of `115.31 ms` (min `102.90 ms`, p95 `164.82 ms`), pausing the parent guest for a median of `0.603 ms` (p95 `0.796 ms`; pre-pause guest `sync` median `1.004 ms`). Every newly cloned `.raw` / `.nvram` file reported `0 B` of unshared APFS private bytes via Darwin `getattrlist(ATTR_CMNEXT_PRIVATESIZE)` (excludes APFS filesystem metadata and newly generated `114688 B` `cidata` ISO + `70 B` `.machineid` files; host-wide `df -k` available-space delta across the 16 stopped / 16 live forks was `7256 KB` / `7936 KB`, an upper bound under concurrent host load). After booting each of the 32 children once to verify guest identities (all 5 persistent identity items pairwise distinct across all 33 VMs; 0 concurrent IPv4 collisions) and halting, median child root-disk APFS private bytes was `6131712 B` (`5.85 MiB`, p95 `6922240 B` / `6.60 MiB`).*
>
> *M4 coding-agent acceptance measured on `2026-11-21` via `AGENTVM_REAL_VM=1 ./Scripts/acceptance/m4-agent.sh` (`reports/AgentVM-M4.md`; pass `--record` on a clean tree to write `reports/m4-agent.json` and `reports/m4-agent.txt`) on the same `Mac16,10` (`Apple M4`, 10 cores, 16 GiB RAM, macOS `27.0.1` `26A434`, APFS) against a real `debian-12-bookworm-arm64` (`6.1.0-54-cloud-arm64`, `8 GiB` disk) guest `t1` (host `uptime` load averages `3.65 3.96 4.47` at start, `4.23 4.01 4.45` at end; total suite `55.70 s`): `64 MiB` VirtioFS sequential write (`fsync` included) measured `862.7 MiB/s` and guest sequential read measured `1726.8 MiB/s` with exact host/guest SHA-256 parity; localhost TCP port forwarding (`127.0.0.1:<hostPort>` -> `vsock` -> guest `:8000`) measured `1.004 ms` median HTTP GET latency across `50` sequential requests (min `0.794 ms`, p95 `1.467 ms`) and `79.02 MiB/s` over a `64 MiB` download while `5/5` concurrent `agentvm exec` calls succeeded (independent single-stage verification on a quieter host recorded `0.485 ms` median / `0.559 ms` p95 latency and ~`295 MiB/s` `64 MiB` download); MCP `agentvm_fork_cow_branch(bootImmediately: true)` booted a live branch to `running` in `4.40 s` and `agentvm_restore_snapshot` rolled back a running VM in `7.52 s`; guest `systemctl reboot` reconnected `vsock` with VirtioFS mounts and port forwards intact in `7.18 s`; and a real external stdlib Python project (`code-review/evals`) passed `60/60` `unittest` cases identically on host and guest.*

> **Current Status (M4 — Coding-Agent MCP Daemon Wiring, VirtioFS Directory Sharing, Localhost Port Forwarding & `agent-relay` Integration)**: `agentvm mcp` connects to the per-workspace background daemon over Unix domain sockets so coding agents can create, boot, fork, snapshot, restore, inspect, and execute commands inside real `VZVirtualMachine` guests over stdio JSON-RPC 2.0; `create --mount <host-dir>:<guest-abs-path>[:ro]` shares host directories into guests via VirtioFS and NoCloud `cloud-init` (`branch --no-mounts` opts out of inheriting parent shares); `forward <vm> <host-port>:<guest-port> [--foreground]`, `forward list`, and `forward stop` relay localhost TCP ports over `AF_VSOCK` with write half-close (`SHUT_WR`) propagation and automatic recovery across guest reboots; and `agent-relay` (`relay.sh verify`) wraps `agentvm exec` directly to run project tests in a real VM and log structured evidence to `.relay/LOG.md`. Booting needs a binary carrying `com.apple.security.virtualization`, which a plain `swift build` binary lacks. Desktop UI daemon integration, VM/snapshot `rm`, and interactive TTY / `exec` stdin streaming remain unimplemented; guest networking uses system NAT with no egress enforcement or live packet capture until M5 (`agentvm_query_wiretap` and `agentvm_set_firewall_preset` return `isError: true` `[ERR_UNIMPLEMENTED_BEFORE_M5]` on the default backend).

[![Version](https://img.shields.io/badge/version-v1.4.0-D97724)](https://github.com/zxu756/AgentVM/releases)
[![Platform](https://img.shields.io/badge/platform-macOS%2014%2B%20(Apple%20Silicon)-141517)](https://github.com/zxu756/AgentVM)
[![Swift](https://img.shields.io/badge/Swift-6.0%20Strict%20Concurrency-D97724)](https://swift.org)
[![Bilingual](https://img.shields.io/badge/UI-中文%20%7C%20EN-2A9D6F)](README.zh-CN.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-2A9D6F)](LICENSE)

`AgentVM` is a macOS (Apple Silicon) workspace manager and APFS Copy-on-Write disk & snapshot lineage tool with a CLI, a stdio MCP server, and a desktop workbench, written in Swift 6, with live `中文 | EN` bilingual switching across the desktop UI and CLI (`--lang en` / `--lang zh`). Persistent real VMs are held by one background daemon per workspace (`agentvm up` / `exec` / `forward` / `pause` / `resume` / `halt` / `branch` / `snapshot` / `restore` and `agentvm mcp`), one-shot VMs run via `agentvm run`, and the workbench's packet and firewall views have no real traffic to show before M5.

By default, launching the desktop app or initializing a `.agentvm` workspace starts completely empty (0 VMs, 0 packets, 0 alerts) and never fabricates guest execution or telemetry:

- **VirtioFS directory sharing (`create --mount` & `branch --no-mounts`)**: `agentvm create <name> ... --mount <host-dir>:<guest-abs-path>[:ro]` may be repeated to attach multiple host directories via `VZVirtioFileSystemDeviceConfiguration` (`VZSharedDirectory(url:readOnly:)`), writing mount-point creation into `cloud-init` `bootcmd` and `virtiofs` entries (`rw,nofail,x-systemd.before=local-fs.target` or `ro,nofail,x-systemd.before=local-fs.target`) into `user-data` `mounts:`. Both `create` and pre-boot `up` fail explicitly with `[ERR_SHARED_DIR_INVALID]` (exit code `1`) if a configured host path does not exist or is not a directory, rather than silently skipping the share. Files created inside a read-write share by either guest `root` or unprivileged `agent` belong to the current host user (`stat -f '%u' == id -u`); read-only (`:ro`) shares reject guest writes, deletes, and `rw` remounts. `branch` inherits the parent's `virtioFSMounts` and `cloud-init` `mounts:` by default; pass `branch <src> <dst> --no-mounts` to strip inherited shares from the child's spec and `cidata` ISO.
- **Daemon-managed localhost port forwarding (`forward`)**: `agentvm forward <vm> <host-port>:<guest-port>` binds `127.0.0.1:<host-port>` inside the workspace daemon, persists the rule on the VM spec, and multiplexes TCP streams over the existing `AF_VSOCK` channel (`CHAN_TCP_PORT_FORWARD`) to `127.0.0.1:<guest-port>` in the guest (`agentvm-guestd.py` v2). Client write half-close (`shutdown(SHUT_WR)`) is forwarded as `FLAG_FIN` without closing the return stream early, so delayed guest responses arrive intact; port conflicts or privileged-port failures return exit code `1` (`[ERR_PORT_FORWARD_BIND]`) with localized `errno` reasons. Active rules automatically re-bind across guest `reboot`, release on `halt`, can be inspected via `agentvm forward list [--vm <vm>] [--json]` or removed via `agentvm forward stop <vm> <host-port>`, and support `--foreground` (blocks until `SIGINT` / `SIGTERM`, then unbinds and exits `0`).
- **Stdio MCP server wired to the workspace daemon (`agentvm mcp`)**: Keeps the 9 MCP tool names unchanged (`agentvm_list_fleet`, `agentvm_create_vm`, `agentvm_fork_cow_branch`, `agentvm_exec_command`, `agentvm_capture_snapshot`, `agentvm_restore_snapshot`, `agentvm_query_wiretap`, `agentvm_set_firewall_preset`, `agentvm_doctor`) and routes live queries, command execution, and boot operations to the workspace daemon without instantiating `VZVirtualMachine` inside the MCP process:
  - `agentvm_create_vm` adds optional `image` (`string`), `diskSize` (`string`, requires `image`), `mounts` (`[{hostPath, guestPath, readOnly?}]`), and `bootImmediately` (`boolean`, launches/connects to the workspace daemon and boots the VM).
  - `agentvm_fork_cow_branch` resolves VM names or `vm-...` IDs in `parentVMID` and supports `inheritMounts` (`boolean`, default `true`) plus `bootImmediately` (`boolean`, boots the child in the workspace daemon).
  - `agentvm_exec_command` resolves VM names or IDs in `vmID`, accepts optional `workingDirectory` (default `"/"`), `runAsUser` (default `"root"`), `timeoutSeconds` (default `3600`), and `environment` (`{string: string}`), streams output from the daemon (capped at `16 MiB` client-side with `[ERR_EXEC_OUTPUT_OVERFLOW]`), returns `isError: false` with `exitCode=<N>` for non-zero guest exit codes, and returns `isError: true` (`[ERR_LIFECYCLE_STATE]`) when the VM is stopped.
  - `agentvm_list_fleet` queries live daemon state first and falls back to lock-reconciled SQLite state when the daemon is not running; `agentvm_capture_snapshot` and `agentvm_restore_snapshot` route running VMs through the daemon.
  - `agentvm_query_wiretap` and `agentvm_set_firewall_preset` return `isError: true` with `[ERR_UNIMPLEMENTED_BEFORE_M5]` on the default hardware backend without altering workspace policy, while retaining `SIMULATED:`-prefixed demonstration behavior under explicit `--backend simulation`.
- **APFS CoW disk cloning, per-child guest identity & live snapshots**: Creating a VM provisions a sparse GPT disk image and a NoCloud `cidata` ISO-9660 seed image (`clonefile(2)` when `--image debian-12-bookworm-arm64` is used; `ps` and `snapshot list` report unshared APFS private bytes via `getattrlist(ATTR_CMNEXT_PRIVATESIZE)`). `branch` synthesizes a per-child `cidata` ISO (`instance-id`, RFC 1123 hostname, `dhcp-identifier: mac`, `cloud-init-per instance avm-machine-id`) plus a new MAC and `VZGenericMachineIdentifier`. Live `branch`, `snapshot`, and automatic pre-destructive-`exec` checkpoints (`auto-pre-cmd` before commands such as `rm -rf`, `apt-get install`, `mkfs`, or `dd of=/dev/...`) run guest `/bin/sync` over `AF_VSOCK`, `pause` briefly to `clonefile(2)`, and `resume`; memory-state forks are intentionally omitted because `Virtualization.framework` requires identical MAC and machine identifier on state restore. Every `restore` saves a `cold-disk` `auto: before restore <snapshot-id>` safety snapshot before swapping the root disk.
- **Explicit simulation & honest telemetry**: Host-side simulation runs only with explicit `--backend simulation` or UI `--demo` (`[DEMO]`), marking every output (`SIMULATED:` text prefix, `"simulated": true` in JSON, `# SIMULATED:` in HCL, section markers in `.pcapng` and HTML). Stale or unmeasured CPU/memory telemetry displays as `—`. `agentvm doctor` checks live `clonefile(2)` support and whether the running binary carries `com.apple.security.virtualization`.

---

## Current Boundaries & Planned Work

- **Desktop UI is not wired to the workspace daemon yet**: The desktop workbench reads workspace state on disk and cannot start, stop, or run commands against daemon-held VMs; its Wiretap and Firewall panels also show `Not connected to live traffic yet (scheduled for M5)`.
- **No `rm` deletion commands or interactive TTY terminal yet**: VM deletion (`rm`), snapshot deletion (`snapshot rm`), interactive terminal sessions, and `exec` stdin streaming (`exec` stdin is `/dev/null`) are not implemented yet; repeated branching or auto-checkpoints keep snapshot files in the workspace (`0 B` private bytes initially, growing as blocks diverge), and stopping VMs created via MCP uses CLI `agentvm halt` or `agentvm daemon stop`.
- **Two M5 network tools are unimplemented before M5**: On the default hardware backend, MCP `agentvm_query_wiretap` and `agentvm_set_firewall_preset` return `isError: true` (`[ERR_UNIMPLEMENTED_BEFORE_M5]`). Real guests use macOS system NAT with no user-space switch attachment, outbound domain filtering, or live `.pcapng` capture before M5 (`agentvm policy strict|airgap` only saves a preset; selecting `airgap` makes `up` exit `1` and `run` exit `125`).
- **Concurrent forked branches sharing one read-write directory will overwrite each other**: Because `branch` inherits the parent VM's `--mount` shares by default, running multiple forked VMs concurrently against the same read-write host directory causes them to read and modify the same host files without isolation. Pass `branch <src> <dst> --no-mounts` (or create separate VMs mounted to separate host directories/clones) when running parallel branches.
- **Per-workspace user daemon scope**: Each workspace daemon (`<workspace>/run/daemon.sock`) is started on demand via double-fork `setsid` rather than `launchd`; logging out of macOS or rebooting the host does not preserve running VMs.

---

## Status & Milestone Roadmap

| Milestone | Capability | Status |
|---|---|---|
| **M0** | Honest baseline: plain `agentvm ps` fix, real `clonefile(2)` probe and real entitlement check in `doctor`, empty default UI, explicit `--backend simulation` with `SIMULATED` markers on every output and on stored state, `[DEMO]` gating, `—` for unmeasured telemetry, preemptive `JavaScriptCore` hook watchdog | **Implemented** |
| **M1** | `agentvm image pull debian-12-bookworm-arm64` + single-command `agentvm run` booting a real Linux kernel/rootfs on `VZVirtualMachine` with live `AF_VSOCK` stdout/stderr/exit-code streaming | **Implemented** |
| **M2** | One background daemon per workspace so `up`, `exec`, `pause`, `resume`, `halt`, `daemon`, and `events` work across separate CLI invocations, plus live guest `/proc` CPU, memory, and uptime telemetry | **Implemented** |
| **M3** | Stopped & live APFS CoW branching (`branch` / `branch --boot`), per-child `cidata` guest identity re-seeding, live `sync`+`pause` snapshots (`snapshot`), pre-restore safety snapshots & live rollback (`restore`), pre-destructive `exec` auto-checkpoints, and APFS private-bytes accounting (`32.49 ms` stopped fork median, `115.31 ms` live fork median, `0 B` cloned private bytes) | **Implemented** |
| **M4** | Coding-agent integration: `agentvm mcp` wired to the workspace daemon (`create_vm`, `fork_cow_branch`, `exec_command`, `list_fleet`, `capture_snapshot`, `restore_snapshot`; M5 tools gated with `ERR_UNIMPLEMENTED_BEFORE_M5`), VirtioFS directory sharing (`create --mount`, `branch --no-mounts`), daemon-managed localhost port forwarding (`forward`, `list`, `stop`, `--foreground` with `SHUT_WR` half-close), and `agent-relay verify` integration | **Implemented** |
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

# 2. Initialize an empty workspace and create empty sparse GPT VM records (including repeatable --mount shares)
agentvm --lang en --workspace ./demo-check.agentvm init
# -> Initialized workspace 'demo-check' (...) at ...
agentvm --lang en --workspace ./demo-check.agentvm create sandbox-a
# -> Created VM 'sandbox-a' (...) with root snapshot ... (empty sparse GPT disk, no guest OS installed)
agentvm --lang en --workspace ./demo-check.agentvm create mount-a --mount .:/workspace --mount .:/mnt/ro:ro
# -> Created VM 'mount-a' (...) with root snapshot ... (empty sparse GPT disk, no guest OS installed)

# 3. List VMs in table or JSON form (unmeasured CPU/RAM shown as —; virtioFSMounts recorded in JSON)
agentvm --lang en --workspace ./demo-check.agentvm ps
# -> sandbox-a ... stopped
agentvm --lang en --workspace ./demo-check.agentvm ps --json
# -> "guestMountPoint" : "\/workspace"

# 4. Fork APFS Copy-on-Write branches (inheriting mounts by default, or stripping shares with --no-mounts), capture snapshots, inspect plugins, and export HCL
agentvm --lang en --workspace ./demo-check.agentvm branch sandbox-a sandbox-b --no-boot
# -> Forked CoW branch 'sandbox-b' (...) in ... ms from snapshot ...
agentvm --lang en --workspace ./demo-check.agentvm branch mount-a mount-b --no-mounts
# -> Forked CoW branch 'mount-b' (...) in ... ms from snapshot ...
agentvm --lang en --workspace ./demo-check.agentvm snapshot sandbox-a before-experiment
# -> Captured snapshot snap-... ('before-experiment') for vm-...
agentvm --lang en --workspace ./demo-check.agentvm snapshot list
# -> Golden Base (sandbox-a) ... Branch Fork -> sandbox-b ... CoW Head (sandbox-b) ... before-experiment
agentvm --lang en --workspace ./demo-check.agentvm plugin
# -> builtin.secret-leak-guard ... ENABLED
agentvm --lang en --workspace ./demo-check.agentvm export-hcl
# -> sandbox_vm "sandbox-a" ... sandbox_vm "sandbox-b"

# 5. Inspect port-forward rules and verify honest failures on empty/stopped VMs without spawning a daemon
agentvm --lang en --workspace ./demo-check.agentvm forward list
# -> No active port forwards.
agentvm --lang en --workspace ./demo-check.agentvm forward list --json
# -> [
agentvm --lang en --workspace ./demo-check.agentvm forward sandbox-a 18080:8000
# -> exits non-zero: [ERR_LIFECYCLE_STATE] Cannot forward ports for VM 'sandbox-a' (...): current state is 'stopped' (VM must be running).
agentvm --lang en --workspace ./demo-check.agentvm up sandbox-a
# -> exits non-zero: [ERR_NO_BOOTABLE_SYSTEM] VM 'sandbox-a' has no bootable guest OS or kernel on its disk...
agentvm --lang en --workspace ./demo-check.agentvm branch sandbox-a sandbox-c --boot
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

Unknown options are errors, not ignored: `agentvm ps --bogus` exits with code 2. Every command also supports Simplified Chinese output via `--lang zh` (or `AGENTVM_LANG=zh`):

```bash
agentvm --lang zh --workspace ./demo-check.agentvm doctor
agentvm --lang zh --workspace ./demo-check.agentvm ps
```

---

## Running Verification Steps in a Real VM with `agent-relay`

With an entitled `agentvm` binary and a cached `debian-12-bookworm-arm64` image (`agentvm image pull debian-12-bookworm-arm64`), `agent-relay`'s `relay.sh verify` subcommand wraps `agentvm exec` directly (executes `--` arguments as an `argv` array without invoking external agent CLIs, propagates guest exit codes verbatim, forwards `SIGTERM` cancellation, and appends structured pass/fail logs to `$PROJECT_DIR/.relay/LOG.md`; exercised end-to-end by `Scripts/acceptance/m4-agent.sh` Row 12):

```bash
# 1. Create a VM mounting host $PROJECT_DIR into /workspace and boot it in the background daemon
agentvm --workspace ./relay-demo.agentvm create t1 --image debian-12-bookworm-arm64 --mount "$PROJECT_DIR:/workspace"
agentvm --workspace ./relay-demo.agentvm up t1

# 2. Run the project's test suite inside the guest VM via agent-relay verify and record .relay/LOG.md evidence
~/.agents/skills/agent-relay/scripts/relay.sh verify "$PROJECT_DIR" "run-tests-in-vm" -- agentvm --workspace ./relay-demo.agentvm exec t1 -- python3 -B -m unittest discover -s /workspace -v

# 3. Halt the VM when done
agentvm --workspace ./relay-demo.agentvm halt t1
```

If the test command requires shell syntax such as `cd /workspace && ...`, pass `-- /bin/sh -c 'cd /workspace && python3 -B -m unittest discover -v'` after `exec t1`.

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

# Replay all documented README commands in a temporary workspace (non-VM commands only)
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

# Run the M3 CoW fork, guest identity, live snapshot/restore, and benchmark suite (m3-fork.sh, m3-branch-bench.sh, plus M1 & M2 regression).
# Without AGENTVM_REAL_VM=1, non-VM rows run and real-VM rows are reported unrun (exit code 2); pass --record to write reports/m3-branch-bench.{json,md}.
AGENTVM_REAL_VM=1 ./Scripts/test.sh milestone 3

# Run the M4 coding-agent acceptance suite (scoped unit tests, build, README replay, and m4-agent.sh Rows 1-14).
# Without AGENTVM_REAL_VM=1, non-VM Rows 1-3 & 14 run and real-VM Rows 4-13 are reported unrun (exit code 2); pass --record on a clean tree to write reports/m4-agent.{txt,json}.
AGENTVM_REAL_VM=1 ./Scripts/test.sh milestone 4

# Run an isolated M4 source-mutation check (1, 2, or 3 -> Rows 15-17) in a temporary copy of the repository without dirtying Sources/
AGENTVM_REAL_VM=1 ./Scripts/acceptance/m4-agent.sh --mutation 1
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
