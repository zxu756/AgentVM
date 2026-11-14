**[English](README.md)** | **简体中文**

# AgentVM `v1.1.0`

> **当前状态（M0 — 止血与诚实基线）**：APFS 写时复制（`clonefile(2)`）稀疏磁盘与快照血统管理、SQLite WAL 工作区持久化、纯 Swift NoCloud `cidata` ISO-9660 镜像生成、离线以太网/IPv4/DNS/TLS 报文拆解（`.pcapng`）以及 `JavaScriptCore` 策略沙盒现已在本地可用。真实 Linux 镜像下载、`VZVirtualMachine` 客户机启动与 `AF_VSOCK` 实时命令执行正在开发中（排在 M1–M3）。用户态出站防火墙拦截与实时抓包尚未接入客户机真实流量（排在 M5）。

[![Version](https://img.shields.io/badge/version-v1.1.0-D97724)](https://github.com/zxu756/AgentVM/releases)
[![Platform](https://img.shields.io/badge/platform-macOS%2014%2B%20(Apple%20Silicon)-141517)](https://github.com/zxu756/AgentVM)
[![Swift](https://img.shields.io/badge/Swift-6.0%20Strict%20Concurrency-D97724)](https://swift.org)
[![Bilingual](https://img.shields.io/badge/界面语言-中文%20%7C%20EN-2A9D6F)](README.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-2A9D6F)](LICENSE)

`AgentVM` 是面向 macOS（Apple Silicon）的本地工作区管理器、APFS 写时复制磁盘与快照血统工具及协议检视工作台，基于 Swift 6 编写，桌面端与命令行（`--lang zh` / `--lang en`）均支持 `中文 | EN` 双语切换。

默认情况下，启动桌面应用或初始化 `.agentvm` 工作区均显示干净的空状态（0 台虚拟机、0 条数据包、0 条告警），绝不伪造客户机执行结果或遥测数值：

- 在当前 M0 阶段，`create` 会创建一块带 GPT 分区表的空稀疏磁盘与一张 NoCloud `cidata` ISO-9660 配置盘，磁盘内尚未安装客户机操作系统。
- 对空磁盘执行 `agentvm up <vm>` 或 `agentvm exec <vm> -- ...` 会以非零退出码返回明确错误，不会静默回退到模拟器或把状态标为 `running`。
- 主机侧协议与会话模拟仅在显式传入 `--backend simulation` 时启用（所有输出行均带 `SIMULATED:` 前缀），或在桌面端显式传入 `--demo` / 点击「载入演示」（带 `[演示数据]` 标记）时载入。
- 未接入真实客户机 `/proc` 数据源的 CPU 与内存指标统一显示为 `—`。
- 在 M5 通过之前，客户机网络走系统 NAT，没有出口管控；界面上的抓包与防火墙面板均明确显示「尚未接入真实流量（排在 M5）」。

---

## 当前状态与里程碑路线图

| 里程碑 | 能力范围 | 状态 |
|---|---|---|
| **M0** | 诚实基线止血：修复普通模式 `agentvm ps` 崩溃、`doctor` 实测执行 `clonefile(2)` 探测、界面默认空状态、显式 `--backend simulation`（`SIMULATED:`）与 `[演示数据]` 隔离、未实测遥测显示 `—`、`JavaScriptCore` 插件抢占式超时看门狗 | **已在 `m0/honest` 完成** |
| **M1** | `agentvm image pull debian-12-bookworm-arm64` 与单命令 `agentvm run`：基于 `VZVirtualMachine` 启动真实 Debian 12 Linux 客户机，通过真实 `AF_VSOCK` 回传标准输出/标准错误/退出码并采集 `/proc` 遥测 | 规划中 |
| **M2** | 每台虚拟机独立后台常驻守护进程，使 `up`、`exec`、`pause`、`resume`、`halt` 可跨独立命令行进程协同工作 | 规划中 |
| **M3** | 基于真实装有操作系统的虚拟机验证 APFS CoW 分叉（`branch`）与快照恢复（`snapshot` / `restore`），并在完成后公布实测耗时与增量字节数 | 规划中 |
| **M4** | 桌面界面完整对接真实运行中的虚拟机、串口输出与工作区状态 | 规划中 |
| **M5** | 真实客户机网卡接入用户态二层交换机、DNS/TLS SNI 出站访问控制与真实流量 `.pcapng` 导出 | 规划中（待 M4 后评估） |

---

## 已验证命令行示例

从源码编译 `AgentVM` 后，可在独立 `.agentvm` 工作区中直接复现以下命令：

```bash
swift build --product AgentVM
alias agentvm="$(pwd)/.build/debug/AgentVM"

# 1. 宿主机就绪自检（在工作区所在卷上执行一次真实的 APFS clonefile(2) 临时克隆探测）
agentvm --lang zh --workspace ./demo-check.agentvm doctor

# 2. 初始化空工作区并创建一台空稀疏 GPT 磁盘虚拟机记录
agentvm --lang zh --workspace ./demo-check.agentvm init
agentvm --lang zh --workspace ./demo-check.agentvm create sandbox-a

# 3. 查看虚拟机表格或 JSON 输出（未实测的 CPU/内存统一显示为 —）
agentvm --lang zh --workspace ./demo-check.agentvm ps
agentvm --lang zh --workspace ./demo-check.agentvm ps --json

# 4. 派生 APFS 写时复制磁盘分支、列出快照、查看插件并导出 HCL 清单
agentvm --lang zh --workspace ./demo-check.agentvm branch sandbox-a sandbox-b --no-boot
agentvm --lang zh --workspace ./demo-check.agentvm snapshot list
agentvm --lang zh --workspace ./demo-check.agentvm plugin
agentvm --lang zh --workspace ./demo-check.agentvm export-hcl

# 5. 对无操作系统的空磁盘执行 up 或 exec 会诚实返回非零退出码与错误说明
agentvm --lang zh --workspace ./demo-check.agentvm up sandbox-a
# -> 非零退出码：[ERR_NO_BOOTABLE_SYSTEM] 虚拟机「sandbox-a」磁盘上没有可引导的客户机系统（内核或根文件系统缺失）...
agentvm --lang zh --workspace ./demo-check.agentvm exec sandbox-a -- uname -a
# -> 非零退出码：[ERR_NO_BOOTABLE_SYSTEM] 虚拟机「sandbox-a」磁盘上没有可引导的客户机系统（内核或根文件系统缺失）...

# 6. 仅当显式指定 --backend simulation 时才运行主机侧模拟，且输出强制带 SIMULATED: 前缀
agentvm --lang zh --workspace ./demo-check.agentvm --backend simulation exec sandbox-a -- uname -a
# -> SIMULATED: Linux sandbox-a 6.8.0-agentvm-arm64 #1 SMP PREEMPT_DYNAMIC aarch64 GNU/Linux
```

所有命令同样支持 `--lang en`（或环境变量 `AGENTVM_LANG=en`）输出英文：

```bash
agentvm --lang en --workspace ./demo-check.agentvm doctor
agentvm --lang en --workspace ./demo-check.agentvm ps
```

---

## 桌面工作台界面预览（`[演示数据]` 合成样本）

> **演示数据说明**：下方截图均通过显式 `--demo` 模式渲染（顶部带有 `演示数据 · 合成样本` 标识）。图中的虚拟机、CoW 分支、以太网/TLS 数据帧与策略计数均为离线合成演示样本，并非采集自真实运行中的客户机。正常启动 `AgentVM` 默认显示空工作区。

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

# 在临时工作区中逐条回放 README 中的全部命令
./Scripts/acceptance/readme-commands.sh

# 运行完整 M0 验收套件（20 次冷启动稳定性、诚实报错检查、doctor 真实克隆探测、仓库零残留、GUI 空状态启动检查）
./Scripts/test.sh milestone 0
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

`Scripts/build-app.sh` 会在 Apple Silicon（`macOS 14+`）上使用 `com.apple.security.virtualization` 权限对 `AgentVM.app` 执行本地 Ad-Hoc 签名。

---

## 开源许可

本项目基于 [MIT License](LICENSE) 开源发布。
