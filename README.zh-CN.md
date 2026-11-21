**[English](README.md)** | **简体中文**

# AgentVM `v1.4.0`

> 在 Mac 上给 coding agent 开真实的 Linux 虚拟机：`agentvm exec` 的输出来自客户机本身；分叉一台带数据的虚拟机用时 **32.49 毫秒**（停机分叉墙钟中位数；最近秩 95 分位 **58.26 毫秒**）、多占 **0 字节**（APFS 克隆私有字节）。
>
> *实测于 `2026-11-21`，由 `Scripts/acceptance/m3-branch-bench.sh`（结果文件 `reports/m3-branch-bench.json`，可通过 `AGENTVM_REAL_VM=1 ./Scripts/test.sh milestone 3 --record` 复现）在 `Mac16,10`（`Apple M4`，10 核，16 GiB 内存）、macOS `27.0.1`（`26A434`）、APFS 卷上测得，宿主机 `uptime` 1m/5m/15m 负载开始为 `1.77 2.24 2.39`、结束为 `1.98 2.53 2.51`；父机为扩容至 `8 GiB` 的 `debian-12-bookworm-arm64` 磁盘，客户机内写入 `1 GiB` 随机数据（`/var/tmp/bench-data.bin`）并 `sync`：16 次停机 `agentvm branch` 进程墙钟中位数为 `32.49 ms`（最小 `26.48 ms`，95 分位 `58.26 ms`；命令行内部从拿锁到写入 SQLite 中位数 `13.52 ms`）；16 次经工作区守护进程执行的运行中 `agentvm branch` 进程墙钟中位数为 `115.31 ms`（最小 `102.90 ms`，95 分位 `164.82 ms`），父机暂停时长（`VM_PAUSED_FOR_SNAPSHOT`）中位数为 `0.603 ms`（95 分位 `0.796 ms`；暂停前客户机 `sync` 中位数 `1.004 ms`）。每次分叉新建的克隆文件（`.raw` / `.nvram`）由独立脚本经 Darwin `getattrlist(ATTR_CMNEXT_PRIVATESIZE)` 读取的不与其他克隆共享的私有字节均为 `0 B`（不含 APFS 文件系统元数据及新生成的 `114688 B` `cidata` ISO 与 `70 B` `.machineid` 文件；16 次停机 / 16 次运行中分叉前后的整卷 `df -k` 可用空间差值为 `7256 KB` / `7936 KB`，宿主机有并发任务时仅作上限参考）。32 台子机依次开机核对客户机身份（与父机共 33 台机器的五项持久身份全部两两不同、并发 IPv4 零冲突）并关机后，子机根盘 APFS 私有字节中位数为 `6131712 B`（`5.85 MiB`，95 分位 `6922240 B` / `6.60 MiB`）。*

> **当前状态（M3 — APFS 写时复制分叉、子机独立身份与运行中快照回滚）**：APFS 写时复制（`clonefile(2)`）磁盘分叉（`branch`）、快照捕获（`snapshot`）与回滚（`restore`）现已同时支持已停止和运行中的 `VZVirtualMachine` 真实客户机，配合 SQLite WAL 工作区持久化、纯 Swift NoCloud `cidata` ISO-9660 镜像生成以及 `JavaScriptCore` 策略沙盒在本地运行。以太网/IPv4/DNS/TLS 报文拆解和 `.pcapng` 读写目前只是库层面的能力（`AgentVMNetSwitch`，有单元测试覆盖）；命令行和桌面界面都还没有打开抓包文件的入口。`agentvm image pull debian-12-bookworm-arm64` 会下载固定版本的 Debian 12 arm64 云镜像并校验 SHA-512；`agentvm run <vm> -- <命令>` 用 `VZVirtualMachine` 执行一次性命令并关机；每个工作区一个后台常驻守护进程（`daemon start|status|stop`、`events`）跨独立命令行进程持有运行中的 `VZVirtualMachine`，使 `up`、`exec`（多路并发 `AF_VSOCK` 输出/退出码回传，v2 客户机支持 `SIGINT`/`SIGTERM` 取消；标准输入固定为 `/dev/null`）、`pause`、`resume`、`halt`、`branch`、`snapshot`、`restore` 操作真实客户机，并在 `ps` 中汇报客户机 `/proc` 实时 CPU、内存、运行时长心跳与 APFS 私有字节。启动虚拟机需要带 `com.apple.security.virtualization` 权限的二进制，直接 `swift build` 编出来的没有。MCP 的 `agentvm_capture_snapshot`、`agentvm_fork_cow_branch`、`agentvm_restore_snapshot` 在机器由守护进程持有时会转发给守护进程执行，其余 MCP 生命周期/`exec` 工具与桌面界面在 M4 之前仍拒绝改动守护进程持有的机器；客户机网络走系统 NAT，用户态出站防火墙拦截与实时抓包排在 M5。

[![Version](https://img.shields.io/badge/version-v1.4.0-D97724)](https://github.com/zxu756/AgentVM/releases)
[![Platform](https://img.shields.io/badge/platform-macOS%2014%2B%20(Apple%20Silicon)-141517)](https://github.com/zxu756/AgentVM)
[![Swift](https://img.shields.io/badge/Swift-6.0%20Strict%20Concurrency-D97724)](https://swift.org)
[![Bilingual](https://img.shields.io/badge/界面语言-中文%20%7C%20EN-2A9D6F)](README.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-2A9D6F)](LICENSE)

`AgentVM` 是面向 macOS（Apple Silicon）的本地工作区管理器和 APFS 写时复制磁盘与快照血统工具，带命令行、stdio MCP 服务和桌面工作台，基于 Swift 6 编写，桌面端与命令行（`--lang zh` / `--lang en`）均支持 `中文 | EN` 双语切换。常驻真实虚拟机由每个工作区一个后台守护进程持有（`agentvm up` / `exec` / `pause` / `resume` / `halt` / `branch` / `snapshot` / `restore`），一次性执行仍可走 `agentvm run`；工作台里的抓包与防火墙视图在 M5 之前没有真实流量可看。

默认情况下，启动桌面应用或初始化 `.agentvm` 工作区均显示干净的空状态（0 台虚拟机、0 条数据包、0 条告警），绝不伪造客户机执行结果或遥测数值：

- `create` 会创建一块带 GPT 分区表的空稀疏磁盘与一张 NoCloud `cidata` ISO-9660 配置盘。不带 `--image` 时磁盘内没有客户机操作系统；带 `--image debian-12-bookworm-arm64` 时，根磁盘是缓存镜像的 APFS `clonefile(2)` 克隆（在非 APFS 卷上会回退为完整复制并在标准错误说明）。`ps` 与 `snapshot list` 的空间列通过 `getattrlist(ATTR_CMNEXT_PRIVATESIZE)` 报告不与其他克隆共享的私有字节，不再在关键路径做全盘逐块比对。
- **`branch` 子机如何更换独立身份**：每次分叉都会为子机单独生成一张 NoCloud `cidata` ISO（`isos/<子机名>-<vmID>-cidata.iso`）：`instance-id` 设为子机自己的 VM ID，`hostname` / `local-hostname` / `fqdn` 按 RFC 1123 规整为子机名，`network-config` 写入 `dhcp-identifier: mac`，`user-data` 保留创建 `/workspace` 的 `bootcmd` 并加入 `cloud-init-per instance avm-machine-id`，在首次开机时重建 `/etc/machine-id`（及 `/var/lib/dbus/machine-id` 软链），SSH 主机密钥由 `cloud-init` 按新实例重新生成，同时分配新的网卡 MAC 与 `VZGenericMachineIdentifier`。子机默认保持 `stopped`（等价于 `--no-boot`）；显式传 `--boot` 时会先做与 `up` 相同的预检（不通过则不建子机），建好后经工作区守护进程启动。若将子机 `restore` 回首次开机之前的初始 `CoW Head` 快照再开机，`cloud-init` 会再次按新实例运行并重新生成一套新的 `machine-id` 与 SSH 主机密钥。
- **只做磁盘写时复制分叉与快照（为什么不做带内存状态的分叉）**：对运行中的虚拟机执行 `branch` 或 `snapshot` 时，守护进程先经 `AF_VSOCK` 在客户机内执行 `/bin/sync`（30 秒超时），再 `pause` 几毫秒完成根磁盘（及分叉时的 EFI NVRAM）`clonefile(2)`，随即 `resume` 恢复运行，快照类型记为 `live-disk`，并写入带精确暂停毫秒数的 `VM_PAUSED_FOR_SNAPSHOT` 事件。M3 不做带内存状态（`saveMachineStateTo` / `restoreMachineStateFrom`）的分叉：实测 `Virtualization.framework` 恢复内存状态时要求网卡 MAC 与 `VZGenericMachineIdentifier` 必须与保存时完全相同（改动任一项即报 `VZErrorDomain` `invalid argument`），这会使子机沿用父机的 MAC、DHCP IPv4 租约、主机名和 `machine-id`，无法与父机同时运行。
- **`restore` 自动留存回滚前快照与运行中回滚**：任何 `agentvm restore <快照ID>` 在替换根磁盘前都会先把当前根磁盘克隆为一份标题为 `auto: before restore <快照ID>` 的 `cold-disk` 快照，并在标准输出打印该快照 ID，避免未拍快照的改动静默丢失。对运行中的虚拟机执行 `restore` 时，守护进程按顺序优雅关机（30 秒超时后强制停）→ 留回滚前快照 → 原子替换根盘（不动 `cidata` ISO、MAC 与机器标识）→ 重新开机并等待 `guestd` 连上后返回。
- **破坏性客户机命令前自动拍检查点**：对运行中的虚拟机执行命中内置守卫规则的破坏性命令（如 `rm -rf`、`apt-get install`、`mkfs`、`dd of=/dev/...`）前，守护进程会自动走运行中快照流程（客户机 `sync` → 短暂 `pause` → `clonefile(2)` → `resume`）拍下一条 `auto-pre-cmd`（`autoPreCommandCheckpoint`）快照。当前尚未提供删除虚拟机或快照的命令（排在 M4），反复分叉或触发检查点会在工作区内累积快照文件（初始私有字节为 `0 B`，随磁盘块写入差异增长）。
- 对空磁盘执行 `agentvm up <vm>`、`agentvm branch <src> <dst> --boot`，或对空磁盘、未运行的虚拟机执行 `agentvm exec <vm> -- ...`，会以非零退出码返回明确错误，不会静默回退到模拟器或拉起守护进程。对装有系统、已停止的虚拟机执行 `agentvm up` 会开机。对空磁盘执行 `agentvm run` 退出码为 125。
- 每个工作区至多运行一个后台守护进程（`<工作区>/run/daemon.sock`，由 `up`、`branch --boot` 或 `daemon start` 按需通过双 fork + `setsid` 启动，不注册 `launchd`）。注销 macOS 会话或重启宿主机后**不保证**虚拟机仍在运行；守护进程退出或被强杀后虚拟机会退出，后续读取会把残留的 `running` 对账回 `stopped`（记录 `VM_RUNTIME_LOST`）。
- 客户机守护脚本（`agentvm-guestd.py` v2）会在新建虚拟机或 `branch` 分叉出的子机首次开机时经 `cloud-init` 写入。M2 之前创建的旧父机本身仍运行旧版 `1.0.0` 脚本（重新 `create --image` 可升级），但从旧父机 `branch` 分叉出的子机首次开机后即会拿到新版 v2 脚本。
- 主机侧协议与会话模拟仅在显式传入 `--backend simulation` 时启用，或在桌面端显式传入 `--demo` / 点击「载入演示」（带 `[演示数据]` 标记）时载入。模拟运行的每一种输出都带标记：文本逐行加 `SIMULATED:` 前缀，`ps --json` 和 MCP `agentvm_list_fleet` 的记录里有 `"simulated": true`，`export-hcl` 多一行 `# SIMULATED:` 注释，导出的 `.pcapng` 和 HTML 文件内部也写有标记。
- 模拟器留在工作区里的状态，之后谁来读都带着标记：默认的 `agentvm ps` 显示 `SIMULATED:运行中`，`ps --json` 在 `"state": "running"` 旁边是 `"simulated": true`；默认后端不会把它当真（`up`、`exec`、`pause` 会丢弃模拟状态，然后像对一台从没运行过的虚拟机那样报错）。
- 未实测或已过期的 CPU 与内存指标（15 秒内无新心跳、已暂停或已停止）统一显示为 `—`。
- 用 `agentvm up` 或 `agentvm run` 启动的客户机走系统 NAT，M5 之前没有任何出站管控：`agentvm policy strict|airgap` 只是选择并保存一个预设，对真实流量不做任何拦截；选了 `airgap` 时 `agentvm up` 退出码为 1、`agentvm run` 退出码为 125，因为 M5 之前做不到断网启动。用户态交换机在 M5 之前没有通往外网的路径。界面上的抓包与防火墙面板均明确显示「尚未接入真实流量（排在 M5）」。
- `agentvm doctor` 会如实报告当前可执行文件有没有 `com.apple.security.virtualization` 权限。直接用 `swift build` 编出来的二进制没有这项权限，`doctor` 会明说，不写「通过」。

---

## 当前状态与里程碑路线图

| 里程碑 | 能力范围 | 状态 |
|---|---|---|
| **M0** | 诚实基线止血：修复普通模式 `agentvm ps` 崩溃、`doctor` 实测执行 `clonefile(2)` 探测并真实读取虚拟化权限、界面默认空状态、显式 `--backend simulation`（每一种输出和落盘的状态都带 `SIMULATED` 标记）、`[演示数据]` 隔离、未实测遥测显示 `—`、`JavaScriptCore` 插件抢占式超时看门狗 | **已完成** |
| **M1** | `agentvm image pull debian-12-bookworm-arm64` 与单命令 `agentvm run`：基于 `VZVirtualMachine` 启动真实 Debian 12 Linux 客户机，通过真实 `AF_VSOCK` 回传标准输出/标准错误/退出码 | **已完成** |
| **M2** | 每个工作区一个后台常驻守护进程，使 `up`、`exec`、`pause`、`resume`、`halt`、`daemon`、`events` 可跨独立命令行进程协同工作，并接入客户机 `/proc` 实时 CPU、内存与运行时长遥测 | **已完成** |
| **M3** | 停机与运行中 APFS CoW 分叉（`branch` / `branch --boot`）、子机独立 `cidata` 身份重建、运行中 `sync`+`pause` 快照（`snapshot`）、自动留存回滚前快照与运行中回滚（`restore`）、破坏性命令前自动检查点及 APFS 私有字节统计（停机分叉中位数 `32.49 ms`、运行中分叉中位数 `115.31 ms`、新建克隆私有字节 `0 B`） | **已完成** |
| **M4** | 桌面界面与完整 MCP 生命周期/`exec` 工具接入工作区守护进程、虚拟机与快照删除命令（`rm`）、目录共享、端口转发、`exec` 标准输入透传与交互终端 | 规划中 |
| **M5** | 真实客户机网卡接入用户态二层交换机、DNS/TLS SNI 出站访问控制与真实流量 `.pcapng` 导出 | 规划中（待 M4 后评估） |

---

## 已验证命令行示例

从源码编译 `AgentVM` 后，可在独立 `.agentvm` 工作区中直接复现以下命令。以 `# ->` 开头的行是文档记录的结果，`...` 代表每次不同的内容（ID、路径、耗时）。`Scripts/acceptance/readme-commands.sh` 直接读取这个代码块，命令或这些结果对不上时会失败。

```bash
swift build --product AgentVM
alias agentvm="$(pwd)/.build/debug/AgentVM"

# 1. 宿主机就绪自检（在工作区所在卷上执行一次真实的 APFS clonefile(2) 临时克隆探测；读取当前可执行文件的虚拟化权限）
agentvm --lang zh --workspace ./demo-check.agentvm doctor
# -> APFS clonefile(2) : 通过 (实测 clonefile(2) 写时复制克隆成功)

# 2. 初始化空工作区并创建一台空稀疏 GPT 磁盘虚拟机记录
agentvm --lang zh --workspace ./demo-check.agentvm init
# -> 已初始化空工作区「demo-check」（...）：...
agentvm --lang zh --workspace ./demo-check.agentvm create sandbox-a
# -> 已创建虚拟机「sandbox-a」（...），根快照 ...（空稀疏 GPT 磁盘，未安装客户机系统）

# 3. 查看虚拟机表格或 JSON 输出（未实测的 CPU/内存统一显示为 —；私有字节列显示不与其他克隆共享的字节数）
agentvm --lang zh --workspace ./demo-check.agentvm ps
# -> sandbox-a ... 已停止
agentvm --lang zh --workspace ./demo-check.agentvm ps --json
# -> "state" : "stopped"

# 4. 派生 APFS 写时复制磁盘分支、捕获快照、列出快照、查看插件并导出 HCL 清单
agentvm --lang zh --workspace ./demo-check.agentvm branch sandbox-a sandbox-b --no-boot
# -> 已通过 clonefile(2) 派生 CoW 分支「sandbox-b」（...），耗时 ... ms，父快照 ...
agentvm --lang zh --workspace ./demo-check.agentvm snapshot sandbox-a before-experiment
# -> 已为 vm-... 捕获快照 snap-...（「before-experiment」）
agentvm --lang zh --workspace ./demo-check.agentvm snapshot list
# -> Golden Base (sandbox-a) ... Branch Fork -> sandbox-b ... CoW Head (sandbox-b) ... before-experiment
agentvm --lang zh --workspace ./demo-check.agentvm plugin
# -> builtin.secret-leak-guard ... 已启用
agentvm --lang zh --workspace ./demo-check.agentvm export-hcl
# -> sandbox_vm "sandbox-a" ... sandbox_vm "sandbox-b"

# 5. 对无操作系统或已停止的磁盘执行 up、branch --boot、exec 诚实报错；halt、daemon status/stop 与 events 无需拉起守护进程即可执行
agentvm --lang zh --workspace ./demo-check.agentvm up sandbox-a
# -> 非零退出码：[ERR_NO_BOOTABLE_SYSTEM] 虚拟机「sandbox-a」磁盘上没有可引导的客户机系统（内核或根文件系统缺失）...
agentvm --lang zh --workspace ./demo-check.agentvm branch sandbox-a sandbox-c --boot
# -> 非零退出码：[ERR_NO_BOOTABLE_SYSTEM] 虚拟机「sandbox-a」磁盘上没有可引导的客户机系统（内核或根文件系统缺失）...
agentvm --lang zh --workspace ./demo-check.agentvm exec sandbox-a -- uname -a
# -> 非零退出码：[ERR_LIFECYCLE_STATE] 虚拟机「sandbox-a」（...）当前处于「stopped」状态（客户机未在运行），无法在客户机中执行命令。请先运行 'agentvm up sandbox-a' 启动虚拟机。
agentvm --lang zh --workspace ./demo-check.agentvm halt sandbox-a
# -> 虚拟机「sandbox-a」（...）-> 已停止
agentvm --lang zh --workspace ./demo-check.agentvm daemon status
# -> 非零退出码：守护进程未运行（工作区：...）。
agentvm --lang zh --workspace ./demo-check.agentvm daemon stop
# -> 守护进程未运行，无需停止。
agentvm --lang zh --workspace ./demo-check.agentvm events --json
# -> "code" : "COW_BRANCH_FORKED"

# 6. 仅当显式指定 --backend simulation 时才运行主机侧模拟，且输出强制带 SIMULATED: 前缀
#    （不管虚拟机叫什么，模拟器回的主机名都是固定的 "agent-sandbox"）
agentvm --lang zh --workspace ./demo-check.agentvm --backend simulation exec sandbox-a -- uname -a
# -> SIMULATED: Linux agent-sandbox 6.8.0-agentvm-arm64 #1 SMP PREEMPT_DYNAMIC aarch64 GNU/Linux

# 7. 模拟器留下的状态，默认后端读到时仍然带标记，文本和 JSON 都是
agentvm --lang zh --workspace ./demo-check.agentvm ps
# -> sandbox-a ... SIMULATED:运行中
# -> SIMULATED: 上面有 1 台虚拟机的状态是 --backend simulation 写入的模拟状态，没有真实的客户机在运行。
agentvm --lang zh --workspace ./demo-check.agentvm ps --json
# -> "simulated" : true
agentvm --lang zh --workspace ./demo-check.agentvm --backend simulation halt sandbox-a
# -> SIMULATED: 虚拟机「sandbox-a」（...）-> 已停止
```

不认识的选项会报错，不会被忽略：`agentvm ps --bogus` 的退出码是 2。使用带虚拟化权限签名的二进制与缓存的 Debian 12 镜像（`agentvm image pull debian-12-bookworm-arm64`）时，可通过 `agentvm create p --image debian-12-bookworm-arm64 --disk-size 8G`、`agentvm up p`、`agentvm branch p c1`、`agentvm branch p c3 --boot`、`agentvm snapshot p s1`、`agentvm restore <快照ID>`、`agentvm exec p -- uname -r`、`agentvm halt p`、`agentvm daemon status`、`agentvm daemon stop` 与 `agentvm events --vm p` 经工作区守护进程管理已停止和运行中的真实客户机（由 `AGENTVM_REAL_VM=1 ./Scripts/test.sh milestone 3` 完整验证）。

所有命令同样支持 `--lang en`（或环境变量 `AGENTVM_LANG=en`）输出英文：

```bash
agentvm --lang en --workspace ./demo-check.agentvm doctor
agentvm --lang en --workspace ./demo-check.agentvm ps
```

---

## 桌面工作台界面预览（`[演示数据]` 合成样本）

> **演示数据说明**：下方截图均通过显式 `--demo` 模式渲染（顶部带有 `演示数据 · 合成样本` 标识）。图中的虚拟机、CoW 分支、以太网/TLS 数据帧与策略计数均为离线合成演示样本，并非采集自真实运行中的客户机。正常启动 `AgentVM` 默认显示空工作区。这些图是在状态栏修正之前渲染的：图里状态栏写着 `虚拟化: Apple VZ`，而演示集群实际运行在主机侧模拟器上。当前版本在演示模式下状态栏显示 `虚拟化: SIMULATED 模拟`，每台演示虚拟机的状态显示为 `SIMULATED 模拟 · 运行中`；截图还没有重新渲染。

### 总览与快照血统拓扑图（`[演示数据]` 合成样本）
![AgentVM 快照与写时复制分支血统图 — 合成演示数据](docs/screenshot-overview-dag-zh.png)

### 离线协议拆解与十六进制视图（`[演示数据]` 合成样本 — 真实流量排在 M5）
![AgentVM 协议拆解器 — 合成演示数据](docs/screenshot-packet-inspector-zh.png)

### APFS 稀疏区段图谱与 NoCloud ISO-9660 检视器（`[演示数据]` 合成样本）
![AgentVM APFS 区段与 Cloud-Init 检视器 — 合成演示数据](docs/screenshot-storage-cloudinit-zh.png)

### 防火墙规则干跑模拟与 JavaScriptCore 扩展宿主（`[演示数据]` 合成样本 — 真实流量排在 M5）
![AgentVM 防火墙模拟与 JS 插件宿主 — 合成演示数据](docs/screenshot-plugins-policy-zh.png)

---

## 测试与验收脚本

```bash
# 按模块运行范围单元测试
./Scripts/test.sh scope AgentVMStore AgentVMHypervisor AgentVMCLIAndMCP

# 在临时工作区中逐条回放 README 中的全部命令（仅包含不需要真机的命令）
./Scripts/acceptance/readme-commands.sh

# 运行完整 M0 验收套件（20 次冷启动稳定性、诚实报错检查、命令行和 MCP 的模拟标记检查、
# doctor 权限检查、策略持久化、仓库零残留、界面默认空状态检查）。
# 任何脚本都不启动桌面界面：界面那一行是不带窗口的 ViewModel 测试。
./Scripts/test.sh milestone 0

# 运行 M1 验收套件。带 AGENTVM_REAL_VM=1 时，它会在缓存里没有镜像时下载固定版本的 Debian 12 arm64 镜像，
# 给命令行的一份副本签上虚拟化权限，然后不开窗口地启动真实客户机。
# 不带这个变量时，它会说明真机部分没有跑，并以非零退出码结束。
AGENTVM_REAL_VM=1 ./Scripts/test.sh milestone 1

# 运行 M2 工作区守护进程验收套件（改动模块范围测试、M0 与 README 回放、m2-daemon.sh 及 M1 回归检查）。
# 不带 AGENTVM_REAL_VM=1 时，非真机守护进程检查照常运行，真机行记为“没跑”并以退出码 2 结束。
AGENTVM_REAL_VM=1 ./Scripts/test.sh milestone 2

# 运行 M3 写时复制分叉、子机独立身份、运行中快照/回滚与分叉基准套件（m3-fork.sh、m3-branch-bench.sh 及 M1/M2 回归检查）。
# 不带 AGENTVM_REAL_VM=1 时，非真机行照常运行，真机行记为“没跑”并以退出码 2 结束；加 --record 可写入 reports/m3-branch-bench.{json,md}。
AGENTVM_REAL_VM=1 ./Scripts/test.sh milestone 3
```

---

## 构建 macOS 应用包

```bash
./Scripts/build-app.sh
# 正常启动（默认空状态：0 台虚拟机、0 条数据包、0 条告警）：
open build/AgentVM.app
# 或显式启用合成演示模式启动：
./build/AgentVM.app/Contents/MacOS/AgentVM --demo
```

`Scripts/build-app.sh` 会在 Apple Silicon（`macOS 14+`）上使用 `com.apple.security.virtualization` 权限对 `AgentVM.app` 执行本地 Ad-Hoc 签名。`swift build` 产出的 `.build/debug/AgentVM` 没有用这项权限签名，`agentvm doctor` 会如实报告。

---

## 开源许可

本项目基于 [MIT License](LICENSE) 开源发布。
