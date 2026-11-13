import Combine
import Foundation

// MARK: - Bilingual Interface Language & Live Localization Engine (`中文` / `EN`)

public enum AppLanguage: String, Codable, Hashable, CaseIterable, Sendable, Identifiable {
    case zhHans = "zh-Hans"
    case en = "en"

    public var id: String { rawValue }

    public var badge: String {
        switch self {
        case .zhHans: return "中文"
        case .en: return "EN"
        }
    }

    public var displayName: String {
        switch self {
        case .zhHans: return "简体中文"
        case .en: return "English"
        }
    }

    public var cliCode: String {
        switch self {
        case .zhHans: return "zh"
        case .en: return "en"
        }
    }

    public var toggled: AppLanguage {
        switch self {
        case .zhHans: return .en
        case .en: return .zhHans
        }
    }

    public static func parse(_ rawValue: String?) -> AppLanguage? {
        guard let rawValue else { return nil }
        let normalized = rawValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !normalized.isEmpty else { return nil }
        if normalized == "zh"
            || normalized == "cn"
            || normalized == "chs"
            || normalized.hasPrefix("zh-")
            || normalized.hasPrefix("zh_") {
            return .zhHans
        }
        if normalized == "en"
            || normalized.hasPrefix("en-")
            || normalized.hasPrefix("en_") {
            return .en
        }
        return nil
    }

    public static func extractCLILanguage(from arguments: [String]) -> AppLanguage? {
        var idx = 0
        while idx < arguments.count {
            let arg = arguments[idx]
            if arg == "--lang" {
                if idx + 1 < arguments.count, let parsed = parse(arguments[idx + 1]) {
                    return parsed
                }
                idx += 2
                continue
            }
            if arg.hasPrefix("--lang=") {
                let value = String(arg.dropFirst("--lang=".count))
                if let parsed = parse(value) {
                    return parsed
                }
            }
            idx += 1
        }
        return nil
    }

    public static func strippingLanguageArguments(from arguments: [String]) -> [String] {
        var remaining: [String] = []
        remaining.reserveCapacity(arguments.count)
        var idx = 0
        while idx < arguments.count {
            let arg = arguments[idx]
            if arg == "--lang" {
                idx += (idx + 1 < arguments.count) ? 2 : 1
                continue
            }
            if arg.hasPrefix("--lang=") {
                idx += 1
                continue
            }
            remaining.append(arg)
            idx += 1
        }
        return remaining
    }

    /// Resolution priority:
    /// 1. CLI `--lang zh|en` (or `--lang=zh|en`)
    /// 2. Environment `AGENTVM_LANG=zh|en`
    /// 3. `UserDefaults` (`io.github.zxu756.AgentVM.language`)
    /// 4. `Locale.preferredLanguages.first` starting with `"zh"` -> `.zhHans`, else `.en`
    public static func resolve(
        arguments: [String] = Array(CommandLine.arguments.dropFirst()),
        environment: [String: String] = ProcessInfo.processInfo.environment,
        userDefaults: UserDefaults = .standard,
        preferredLanguages: [String] = Locale.preferredLanguages
    ) -> AppLanguage {
        if let cliLang = extractCLILanguage(from: arguments) {
            return cliLang
        }
        if let envLang = parse(environment["AGENTVM_LANG"]) {
            return envLang
        }
        if let stored = parse(userDefaults.string(forKey: AgentVMLocalizer.userDefaultsKey)) {
            return stored
        }
        if let primaryLocale = preferredLanguages.first,
           primaryLocale.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().hasPrefix("zh") {
            return .zhHans
        }
        return .en
    }
}

@MainActor
public final class AgentVMLocalizer: ObservableObject {
    nonisolated public static let userDefaultsKey = "io.github.zxu756.AgentVM.language"

    public static let shared = AgentVMLocalizer()

    private let userDefaults: UserDefaults
    private var suppressPersistence = false

    @Published public var language: AppLanguage {
        didSet {
            guard !suppressPersistence else { return }
            userDefaults.set(language.rawValue, forKey: Self.userDefaultsKey)
        }
    }

    public init(
        arguments: [String] = Array(CommandLine.arguments.dropFirst()),
        environment: [String: String] = ProcessInfo.processInfo.environment,
        userDefaults: UserDefaults = .standard,
        preferredLanguages: [String] = Locale.preferredLanguages
    ) {
        self.userDefaults = userDefaults
        self.language = AppLanguage.resolve(
            arguments: arguments,
            environment: environment,
            userDefaults: userDefaults,
            preferredLanguages: preferredLanguages
        )
    }

    public var isChinese: Bool {
        language == .zhHans
    }

    public func setLanguage(_ newLanguage: AppLanguage, persist: Bool = true) {
        if !persist {
            suppressPersistence = true
            language = newLanguage
            suppressPersistence = false
        } else {
            if language != newLanguage {
                language = newLanguage
            } else {
                userDefaults.set(newLanguage.rawValue, forKey: Self.userDefaultsKey)
            }
        }
    }

    @discardableResult
    public func toggleLanguage(persist: Bool = true) -> AppLanguage {
        let next = language.toggled
        setLanguage(next, persist: persist)
        return next
    }

    public func L(_ en: String, _ zh: String) -> String {
        language == .zhHans ? zh : en
    }
}

@MainActor
public func L(_ en: String, _ zh: String) -> String {
    AgentVMLocalizer.shared.L(en, zh)
}

// MARK: - Domain Model Localization Extensions

extension VMLifecycleState {
    @MainActor
    public var localizedBadge: String {
        switch self {
        case .stopped: return L("Stopped", "已停止")
        case .booting: return L("Booting", "启动中")
        case .running: return L("Running", "运行中")
        case .pausing: return L("Pausing", "暂停中")
        case .paused: return L("Paused", "已暂停")
        case .savingState: return L("Saving RAM", "保存内存")
        case .restoringState: return L("Restoring", "恢复中")
        case .branching: return L("CoW Forking", "CoW 分叉中")
        case .stopping: return L("Stopping", "停止中")
        case .crashed: return L("Faulted", "故障")
        }
    }
}

extension GuestOSType {
    @MainActor
    public var localizedDisplayName: String {
        switch self {
        case .linuxARM64: return L("Linux (ARM64 Native)", "Linux (ARM64 原生)")
        case .linuxX86_64ViaRosetta: return L("Linux (ARM64 + Rosetta x86_64)", "Linux (ARM64 + Rosetta 转译)")
        case .macOSARM64: return L("macOS Guest (Apple Silicon)", "macOS 客户机 (Apple Silicon)")
        case .freebsdARM64: return L("FreeBSD (ARM64 EFI)", "FreeBSD (ARM64 EFI)")
        }
    }
}

extension BootLoaderSpec {
    @MainActor
    public var localizedSummaryLabel: String {
        switch self {
        case .linuxKernel: return L("Direct Linux Kernel (VZLinuxBootLoader)", "Linux 内核直启 (VZLinuxBootLoader)")
        case .efiBoot: return L("UEFI Firmware (VZEFIBootLoader)", "UEFI 固件引导 (VZEFIBootLoader)")
        case .macOSBoot: return L("Apple Silicon BootROM (VZMacOSBootLoader)", "Apple Silicon 引导 (VZMacOSBootLoader)")
        }
    }
}

extension NetworkAttachmentMode {
    @MainActor
    public var localizedDisplayName: String {
        switch self {
        case .userSpaceSwitch: return L("User-Space L2 Switch + DPI Firewall", "用户态二层交换机 + DPI 防火墙")
        case .systemNAT: return L("macOS System NAT (VZNATNetworkDevice)", "macOS 系统 NAT (VZNATNetworkDevice)")
        case .isolatedAirgap: return L("Air-Gapped Zero-Egress Sandbox", "气隙零出站隔离沙盒")
        }
    }

    @MainActor
    public var localizedInspectorBadge: String {
        switch self {
        case .userSpaceSwitch: return L("User-Space L2 DPI", "用户态二层 DPI")
        case .systemNAT: return L("System NAT", "系统 NAT")
        case .isolatedAirgap: return L("Air-Gap Loopback", "气隙回环")
        }
    }
}

extension SnapshotKind {
    @MainActor
    public var localizedDisplayName: String {
        switch self {
        case .baseGoldenImage: return L("Golden Base", "黄金基线")
        case .coldDiskOnly: return L("Cold Disk Snapshot", "冷磁盘快照")
        case .liveMemoryAndDisk: return L("Live RAM + Disk", "实时内存 + 磁盘")
        case .branchForkPoint: return L("CoW Branch Fork", "CoW 分支点")
        case .autoPreCommandCheckpoint: return L("Pre-Exec Checkpoint", "执行前自动快照")
        case .budgetCircuitBreaker: return L("Circuit-Breaker Freeze", "预算熔断冻结")
        }
    }

    @MainActor
    public var localizedShortBadge: String {
        switch self {
        case .baseGoldenImage: return L("BASE", "基线")
        case .coldDiskOnly: return L("DISK", "磁盘")
        case .liveMemoryAndDisk: return L("LIVE", "内存")
        case .branchForkPoint: return L("FORK", "分叉")
        case .autoPreCommandCheckpoint: return L("AUTO", "自动")
        case .budgetCircuitBreaker: return L("HALT", "熔断")
        }
    }
}

extension WorkbenchDocumentKind {
    @MainActor
    public var localizedDefaultTitle: String {
        switch self {
        case .fleetRackOverview: return L("Fleet Rack Matrix", "集群机架矩阵")
        case .snapshotBranchDAG: return L("Snapshot & CoW DAG", "快照与 CoW 血缘图")
        case .packetWiretap: return L("L2 Packet Wiretap", "二层抓包与解析")
        case .vt100SerialConsole: return L("Vsock / PTY Console", "Vsock 终端控制台")
        case .firewallPolicyStudio: return L("Firewall Policy Studio", "防火墙策略工坊")
        case .storageAndCloudInit: return L("CoW Extents & Cloud-Init", "CoW 区间与 Cloud-Init")
        case .pluginExtensionStudio: return L("JS Plugin Host", "JS 插件沙盒")
        case .auditJournalLedger: return L("Audit & Undo Ledger", "审计与撤销账本")
        }
    }

    @MainActor
    public var localizedCompactTitle: String {
        switch self {
        case .snapshotBranchDAG: return L("Lineage DAG", "血缘拓扑")
        case .packetWiretap: return L("Wiretap", "二层抓包")
        case .vt100SerialConsole: return L("Console", "终端控制台")
        case .firewallPolicyStudio: return L("Firewall", "防火墙策略")
        case .storageAndCloudInit: return L("Storage & ISO", "存储与镜像")
        case .pluginExtensionStudio: return L("Plugins", "JS 插件")
        case .fleetRackOverview: return L("Fleet Matrix", "机架矩阵")
        case .auditJournalLedger: return L("Audit Ledger", "审计账本")
        }
    }
}

extension BottomDrawerChannel {
    @MainActor
    public var localizedTitle: String {
        switch self {
        case .serialTTY: return L("Serial & Vsock Stream", "串口与 Vsock 流")
        case .firewallAlerts: return L("Firewall Alerts", "防火墙告警")
        case .undoHistory: return L("Undo / Redo Stack", "撤销 / 重做栈")
        case .pluginLogs: return L("Plugin Host Logs", "插件宿主日志")
        }
    }
}

extension CommandCategory {
    @MainActor
    public var localizedTitle: String {
        switch self {
        case .vmLifecycle: return L("VM Lifecycle", "虚拟机生命周期")
        case .cowBranching: return L("Snapshots & CoW", "快照与写时复制")
        case .networkFirewall: return L("Switch & Firewall", "交换机与防火墙")
        case .workspaceView: return L("Workbench Layout", "工作台布局")
        case .pluginsAndAutomation: return L("Plugins & Export", "插件与导出")
        }
    }
}

extension PluginCapability {
    @MainActor
    public var localizedDescription: String {
        switch self {
        case .networkInspect: return L("Read dissected Ethernet/IPv4/TLS metadata", "读取解析后的 Ethernet/IPv4/TLS 元数据")
        case .networkVerdictOverride: return L("Drop or sinkhole live network packets", "丢弃或黑洞重定向实时网络数据包")
        case .vmLifecycleControl: return L("Pause, resume, or halt virtual machines", "暂停、恢复或停止虚拟机")
        case .snapshotCheckpoint: return L("Create CoW branches and RAM snapshots", "创建 CoW 分支与内存快照点")
        case .commandExecInterception: return L("Inspect or veto guest exec invocations", "审计或拦截客户机命令执行")
        case .topologyImportExport: return L("Import/export multi-VM topology manifests", "导入或导出多虚拟机拓扑清单")
        case .workbenchCommand: return L("Register actions in Cmd+K Command Palette", "向 ⌘K 命令面板注册快捷动作")
        case .pluginKVStore: return L("Persist plugin key-value state in SQLite", "在 SQLite 中持久化插件键值状态")
        }
    }
}

extension PluginManifest {
    @MainActor
    public var localizedName: String {
        switch id.rawValue {
        case "builtin.secret-leak-guard":
            return L(name, "密钥与 DNS 隧道外泄守卫")
        case "builtin.runaway-budget-breaker":
            return L(name, "失控智能体预算熔断器")
        case "builtin.auto-git-checkpoint":
            return L(name, "高危执行前 CoW 自动快照")
        case "builtin.iac-compose-bridge":
            return L(name, "IaC Compose 与 HCL 拓扑桥接")
        default:
            return name
        }
    }

    @MainActor
    public var localizedSummary: String {
        switch id.rawValue {
        case "builtin.secret-leak-guard":
            return L(summary, "深度检测出站 HTTP 载荷、高熵 DNS 隧道标签及客户机命令中的 API 密钥与私钥。")
        case "builtin.runaway-budget-breaker":
            return L(summary, "当自治循环超出 CoW 脏盘配额、触发防火墙丢包风暴或运行超时时自动冻结虚拟机。")
        case "builtin.auto-git-checkpoint":
            return L(summary, "在执行破坏性 Shell、软件包变更或数据库删表命令前自动分叉 <20ms APFS 快照。")
        case "builtin.iac-compose-bridge":
            return L(summary, "将多虚拟机沙盒集群导入或导出为声明式 .avm.hcl 规范或 Docker Compose 清单。")
        default:
            return summary
        }
    }
}

extension FirewallVerdict {
    @MainActor
    public var localizedBadge: String {
        switch self {
        case .allow: return L("ALLOW", "放行")
        case .drop: return L("DROP", "丢弃")
        case .rejectRST: return L("REJECT_RST", "拒绝 RST")
        case .dnsSinkhole: return L("DNS_SINKHOLE", "DNS 黑洞")
        case .rateLimited: return L("RATE_LIMITED", "限速")
        case .pluginBlocked: return L("PLUGIN_DROP", "插件拦截")
        }
    }
}

extension FirewallRule {
    @MainActor
    public var localizedName: String {
        switch id.rawValue {
        case "rule-allow-switch-dhcp":
            return L(name, "允许虚拟交换机 ARP 与 DHCP 租约")
        case "rule-allow-dns":
            return L(name, "允许交换机审计 DNS 解析")
        case "rule-block-cloud-metadata":
            return L(name, "阻断云实例元数据 SSRF (169.254.169.254)")
        case "rule-allow-github":
            return L(name, "允许 GitHub TLS (*.github.com, *.githubusercontent.com)")
        case "rule-allow-registries":
            return L(name, "允许开源包仓库 (PyPI, npm, crates.io)")
        case "rule-allow-llm-apis":
            return L(name, "允许前沿模型 API (Anthropic & OpenAI)")
        case "rule-sinkhole-pastebin":
            return L(name, "DNS 黑洞拦截外泄站点与 Webhook 接收端")
        default:
            if name.hasPrefix("Allow TLS SNI (") {
                let suffix = String(name.dropFirst("Allow TLS SNI ".count))
                return L(name, "允许 TLS SNI \(suffix)")
            }
            return name
        }
    }

    @MainActor
    public static func localizeRuleTitle(_ rawName: String) -> String {
        switch rawName {
        case "Allow Virtual Switch ARP & DHCP":
            return L(rawName, "允许虚拟交换机 ARP 与 DHCP 租约")
        case "Allow Switch DNS Resolver":
            return L(rawName, "允许交换机审计 DNS 解析")
        case "Block Cloud Instance Metadata (169.254.169.254)":
            return L(rawName, "阻断云实例元数据 SSRF (169.254.169.254)")
        case "Allow GitHub TLS (*.github.com, *.githubusercontent.com)":
            return L(rawName, "允许 GitHub TLS (*.github.com, *.githubusercontent.com)")
        case "Allow Package Registries (PyPI, npm, crates.io)":
            return L(rawName, "允许开源包仓库 (PyPI, npm, crates.io)")
        case "Allow Frontier Model APIs (Anthropic & OpenAI)":
            return L(rawName, "允许前沿模型 API (Anthropic & OpenAI)")
        case "Sinkhole Exfiltration Pastebins & Webhook Sinks":
            return L(rawName, "DNS 黑洞拦截外泄站点与 Webhook 接收端")
        default:
            if rawName.hasPrefix("Allow TLS SNI (") {
                let suffix = String(rawName.dropFirst("Allow TLS SNI ".count))
                return L(rawName, "允许 TLS SNI \(suffix)")
            }
            return rawName
        }
    }
}

extension FirewallPolicySet {
    @MainActor
    public var localizedName: String {
        switch id.rawValue {
        case "pol-strict-agent-allowlist":
            return L(name, "编程智能体严格出站白名单")
        case "pol-airgap":
            return L(name, "全气隙零出站隔离沙盒")
        default:
            return name
        }
    }
}

extension DiagnosticSeverity {
    @MainActor
    public var localizedBadge: String {
        switch self {
        case .trace: return L("TRACE", "追踪")
        case .info: return L("INFO", "信息")
        case .notice: return L("NOTICE", "提示")
        case .warning: return L("WARNING", "警告")
        case .error: return L("ERROR", "错误")
        case .critical: return L("CRITICAL", "严重")
        }
    }
}

extension DiagnosticEvent {
    @MainActor
    public var localizedMessage: String {
        guard AgentVMLocalizer.shared.isChinese else { return message }
        if message == "Credential leak blocked (Anthropic Key)" {
            return "已阻断出站凭证外泄 (Anthropic 密钥)"
        }
        if message.hasPrefix("Plugin created pre-exec CoW snapshot ") {
            return message
                .replacingOccurrences(of: "Plugin created pre-exec CoW snapshot ", with: "插件已在执行前创建 CoW 快照 ")
                .replacingOccurrences(of: " before ", with: " · 触发命令 ")
        }
        if message.hasPrefix("Frame #") {
            return message
                .replacingOccurrences(of: "Frame #", with: "数据帧 #")
                .replacingOccurrences(of: " -> PLUGIN_DROP (", with: " -> 插件拦截 (")
                .replacingOccurrences(of: " -> DROP (", with: " -> 丢弃 (")
                .replacingOccurrences(of: " -> DNS_SINKHOLE (", with: " -> DNS 黑洞 (")
                .replacingOccurrences(of: "Plugin secret-leak-guard: Credential leak blocked (Anthropic Key)", with: "secret-leak-guard: 已阻断 Anthropic 密钥外泄")
                .replacingOccurrences(of: "Matched rule 'Block Cloud Instance Metadata (169.254.169.254)'", with: "命中规则「阻断云实例元数据 SSRF (169.254.169.254)」")
                .replacingOccurrences(of: "Matched rule 'Sinkhole Exfiltration Pastebins & Webhook Sinks'", with: "命中规则「DNS 黑洞拦截外泄站点与 Webhook」")
        }
        if message.hasPrefix("Paused ") {
            return message
                .replacingOccurrences(of: "Paused VM ", with: "已暂停虚拟机 ")
                .replacingOccurrences(of: "Paused ", with: "已暂停 ")
                .replacingOccurrences(of: ": Idle quota cooldown", with: " · 空闲配额自动冷却")
                .replacingOccurrences(of: "(Idle quota cooldown)", with: "(空闲配额冷却)")
                .replacingOccurrences(of: "(Operator paused from Studio)", with: "(操作员手动暂停)")
        }
        if message.hasPrefix("Snapshot 'Pre-Migration Checkpoint'") {
            return message
                .replacingOccurrences(of: "Snapshot 'Pre-Migration Checkpoint'", with: "已捕获快照「迁移前内存检查点」")
                .replacingOccurrences(of: " on ", with: " · 节点 ")
        }
        if message.hasPrefix("Forked CoW branch ") {
            return message
                .replacingOccurrences(of: "Forked CoW branch ", with: "已分叉 CoW 分支 ")
                .replacingOccurrences(of: " in ", with: " · 耗时 ")
                .replacingOccurrences(of: " unique dirty pages).", with: " 独有脏块)")
        }
        if message.hasPrefix("VM ") && message.contains("entered RUNNING state") {
            return message
                .replacingOccurrences(of: "VM ", with: "虚拟机 ")
                .replacingOccurrences(of: " entered RUNNING state with AVM1 Guest Agent connected.", with: " 已进入运行态 (AVM1 客户机代理已连接)")
        }
        if message.hasPrefix("Booted VM ") {
            return message.replacingOccurrences(of: "Booted VM ", with: "已启动虚拟机 ")
        }
        return message
    }
}
