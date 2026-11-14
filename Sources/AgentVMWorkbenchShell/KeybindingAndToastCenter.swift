import AgentVMModels
import Combine
import Foundation
import SwiftUI

// MARK: - Toast Notification Center & Status Bar / Multi-Tab Preferences

public struct WorkbenchToast: Identifiable, Hashable, Sendable {
    public var id: UUID
    public var title: String
    public var detail: String
    public var severity: DiagnosticSeverity
    public var createdAt: Date

    public init(
        id: UUID = UUID(),
        title: String,
        detail: String,
        severity: DiagnosticSeverity = .info,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.title = title
        self.detail = detail
        self.severity = severity
        self.createdAt = createdAt
    }
}

@MainActor
public final class WorkbenchToastCenter: ObservableObject {
    @Published public private(set) var activeToasts: [WorkbenchToast] = []

    public init() {}

    public func post(
        title: String,
        detail: String,
        severity: DiagnosticSeverity = .info,
        autoDismissSeconds: TimeInterval = 4.0
    ) {
        let toast = WorkbenchToast(title: title, detail: detail, severity: severity)
        withAnimation(.easeOut(duration: 0.18)) {
            activeToasts.append(toast)
            if activeToasts.count > 4 {
                activeToasts.removeFirst(activeToasts.count - 4)
            }
        }

        guard autoDismissSeconds > 0 else { return }
        let toastID = toast.id
        Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(autoDismissSeconds * 1_000_000_000))
            self?.dismiss(id: toastID)
        }
    }

    public func dismiss(id: UUID) {
        withAnimation(.easeOut(duration: 0.16)) {
            activeToasts.removeAll { $0.id == id }
        }
    }
}

public struct WorkbenchToastStackOverlay: View {
    @ObservedObject public var center: WorkbenchToastCenter

    public init(center: WorkbenchToastCenter) {
        self.center = center
    }

    public var body: some View {
        VStack(alignment: .trailing, spacing: 8) {
            ForEach(center.activeToasts) { toast in
                HStack(alignment: .top, spacing: 10) {
                    Circle()
                        .fill(RackTheme.severityColor(for: toast.severity))
                        .frame(width: 8, height: 8)
                        .padding(.top, 4)

                    VStack(alignment: .leading, spacing: 2) {
                        Text(toast.title)
                            .font(RackTheme.labelFont)
                            .foregroundStyle(RackTheme.inkPrimary)
                            .lineLimit(1)
                        Text(toast.detail)
                            .font(RackTheme.captionFont)
                            .foregroundStyle(RackTheme.inkSecondary)
                            .lineLimit(2)
                    }

                    Button {
                        center.dismiss(id: toast.id)
                    } label: {
                        Image(systemName: "xmark")
                            .font(.system(size: 9, weight: .bold))
                            .foregroundStyle(RackTheme.inkMuted)
                    }
                    .buttonStyle(.plain)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 9)
                .frame(width: 330, alignment: .leading)
                .background(
                    RoundedRectangle(cornerRadius: RackTheme.outerCornerRadius, style: .continuous)
                        .fill(RackTheme.moduleElevated)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: RackTheme.outerCornerRadius, style: .continuous)
                        .strokeBorder(RackTheme.hairlineStrong, lineWidth: 1)
                )
                .shadow(color: Color.black.opacity(0.4), radius: 12, x: 0, y: 6)
                .transition(.scale(scale: 0.96, anchor: .bottomTrailing).combined(with: .opacity))
            }
        }
        .padding(.trailing, 16)
        .padding(.bottom, 36)
    }
}

// MARK: - Bottom Telemetry Status Bar

public struct WorkbenchTelemetryStatusBar: View {
    @ObservedObject private var localizer = AgentVMLocalizer.shared
    public let hostCapabilities: HostCapabilityReport
    /// What actually backs the fleet in this window (real Apple VZ, the simulator, or nothing usable).
    /// Supplied by the view model; the bar never derives it from `VZVirtualMachine.isSupported` alone.
    public let hypervisorStatusText: String
    public let isHypervisorReady: Bool
    public let runningVMCount: Int
    public let totalVMCount: Int
    public let totalDirtyCoWBytes: UInt64
    public let capturedPacketCount: Int
    public let droppedPacketCount: Int
    public let activePluginsCount: Int
    public let canUndo: Bool
    public let canRedo: Bool
    public let onOpenCommandPalette: () -> Void
    public let onToggleBottomDrawer: () -> Void

    public init(
        hostCapabilities: HostCapabilityReport,
        hypervisorStatusText: String,
        isHypervisorReady: Bool,
        runningVMCount: Int,
        totalVMCount: Int,
        totalDirtyCoWBytes: UInt64,
        capturedPacketCount: Int,
        droppedPacketCount: Int,
        activePluginsCount: Int,
        canUndo: Bool,
        canRedo: Bool,
        onOpenCommandPalette: @escaping () -> Void,
        onToggleBottomDrawer: @escaping () -> Void
    ) {
        self.hostCapabilities = hostCapabilities
        self.hypervisorStatusText = hypervisorStatusText
        self.isHypervisorReady = isHypervisorReady
        self.runningVMCount = runningVMCount
        self.totalVMCount = totalVMCount
        self.totalDirtyCoWBytes = totalDirtyCoWBytes
        self.capturedPacketCount = capturedPacketCount
        self.droppedPacketCount = droppedPacketCount
        self.activePluginsCount = activePluginsCount
        self.canUndo = canUndo
        self.canRedo = canRedo
        self.onOpenCommandPalette = onOpenCommandPalette
        self.onToggleBottomDrawer = onToggleBottomDrawer
    }

    public var body: some View {
        HStack(spacing: 14) {
            HStack(spacing: 6) {
                Circle()
                    .fill(isHypervisorReady ? RackTheme.linkGreen : RackTheme.amberAccent)
                    .frame(width: 7, height: 7)
                Text(hypervisorStatusText)
                    .font(RackTheme.monoSmallFont)
                    .foregroundStyle(RackTheme.inkPrimary)
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)
            }

            statusDivider

            Text(localizer.L("Fleet: \(runningVMCount)/\(totalVMCount) Active", "集群: \(runningVMCount)/\(totalVMCount) 运行中"))
                .font(RackTheme.monoSmallFont)
                .monospacedDigit()
                .foregroundStyle(RackTheme.inkSecondary)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)

            statusDivider

            Text(localizer.L("CoW Delta: \(ByteMetricsFormatter.formatBytes(totalDirtyCoWBytes))", "CoW 增量: \(ByteMetricsFormatter.formatBytes(totalDirtyCoWBytes))"))
                .font(RackTheme.monoSmallFont)
                .monospacedDigit()
                .foregroundStyle(RackTheme.amberAccent)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)

            statusDivider

            Text(localizer.L("Wiretap: \(capturedPacketCount) pkts (\(droppedPacketCount) dropped)", "抓包: \(capturedPacketCount) 帧 (\(droppedPacketCount) 拦截)"))
                .font(RackTheme.monoSmallFont)
                .monospacedDigit()
                .foregroundStyle(droppedPacketCount > 0 ? RackTheme.dropCrimson : RackTheme.inkSecondary)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)

            statusDivider

            Text(localizer.L("JS Plugins: \(activePluginsCount) enabled", "JS 插件: \(activePluginsCount) 已启用"))
                .font(RackTheme.monoSmallFont)
                .monospacedDigit()
                .foregroundStyle(RackTheme.vsockBlue)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)

            Spacer(minLength: 8)

            Button(action: onToggleBottomDrawer) {
                Label(localizer.L("Drawer", "日志抽屉"), systemImage: "rectangle.bottomhalf.inset.filled")
            }
            .buttonStyle(RackActionButtonStyle(prominence: .subtleGhost, compact: true))

            Button(action: onOpenCommandPalette) {
                HStack(spacing: 5) {
                    Text(localizer.L("Command Palette", "命令面板"))
                    RackKeyCapBadge("⌘K")
                }
            }
            .buttonStyle(RackActionButtonStyle(prominence: .subtleGhost, compact: true))
        }
        .padding(.horizontal, 12)
        .frame(height: 27)
        .background(RackTheme.bladeRecessed)
        .overlay(alignment: .top) {
            Rectangle()
                .fill(RackTheme.hairline)
                .frame(height: 1)
        }
    }

    private var statusDivider: some View {
        Rectangle()
            .fill(RackTheme.hairlineStrong)
            .frame(width: 1, height: 12)
    }
}

// MARK: - Multi-Tab Preferences Window (Cmd+,)

public struct WorkbenchPreferencesView: View {
    @ObservedObject private var localizer = AgentVMLocalizer.shared
    @Binding public var preferences: WorkspacePreferences
    public let onSave: (WorkspacePreferences) -> Void
    @State private var selectedSection: PrefSection = .hypervisor

    public enum PrefSection: String, CaseIterable, Identifiable {
        case hypervisor = "Hypervisor & Quota"
        case storage = "APFS CoW Pool"
        case network = "L2 Switch & DNS"
        case security = "Plugins & Guardrails"

        public var id: String { rawValue }
        public var icon: String {
            switch self {
            case .hypervisor: return "cpu"
            case .storage: return "internaldrive"
            case .network: return "network"
            case .security: return "lock.shield"
            }
        }

        @MainActor
        public var localizedTitle: String {
            switch self {
            case .hypervisor: return L("Hypervisor & Quota", "虚拟化与配额")
            case .storage: return L("APFS CoW Pool", "APFS 写时复制池")
            case .network: return L("L2 Switch & DNS", "二层交换机与 DNS")
            case .security: return L("Plugins & Guardrails", "插件与安全护栏")
            }
        }
    }

    public init(
        preferences: Binding<WorkspacePreferences>,
        onSave: @escaping (WorkspacePreferences) -> Void
    ) {
        self._preferences = preferences
        self.onSave = onSave
    }

    public var body: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text(localizer.L("AgentVM Preferences", "AgentVM 偏好设置"))
                    .font(RackTheme.sectionHeaderFont)
                    .foregroundStyle(RackTheme.inkPrimary)
                    .padding(.horizontal, 10)
                    .padding(.bottom, 6)

                ForEach(PrefSection.allCases) { section in
                    let active = selectedSection == section
                    Button {
                        selectedSection = section
                    } label: {
                        HStack(spacing: 8) {
                            Image(systemName: section.icon)
                                .frame(width: 16)
                                .foregroundStyle(active ? RackTheme.amberAccent : RackTheme.inkSecondary)
                            Text(section.localizedTitle)
                                .font(RackTheme.labelFont)
                                .foregroundStyle(active ? RackTheme.inkPrimary : RackTheme.inkSecondary)
                                .lineLimit(1)
                            Spacer(minLength: 0)
                        }
                        .padding(.horizontal, 10)
                        .padding(.vertical, 7)
                        .background(
                            RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                                .fill(active ? RackTheme.moduleSurface : Color.clear)
                        )
                    }
                    .buttonStyle(.plain)
                }
                Spacer()

                VStack(alignment: .leading, spacing: 6) {
                    Text(localizer.L("Interface Language", "界面语言"))
                        .font(RackTheme.captionFont)
                        .foregroundStyle(RackTheme.inkMuted)
                    RackLanguageTogglePill(localizer: localizer)
                }
                .padding(.horizontal, 10)
                .padding(.top, 8)
            }
            .padding(12)
            .frame(width: 210)
            .background(RackTheme.bladeRecessed)

            Rectangle()
                .fill(RackTheme.hairline)
                .frame(width: 1)

            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    Text(selectedSection.localizedTitle)
                        .font(RackTheme.displayTitleFont)
                        .foregroundStyle(RackTheme.inkPrimary)
                    Spacer()
                    RackLanguageTogglePill(localizer: localizer)
                }

                switch selectedSection {
                case .hypervisor:
                    LabeledContent(localizer.L("Interface Language (⇧⌘L)", "界面显示语言 (⇧⌘L)")) {
                        Picker("", selection: Binding(
                            get: { localizer.language },
                            set: { localizer.setLanguage($0) }
                        )) {
                            ForEach(AppLanguage.allCases) { lang in
                                Text("\(lang.displayName) (\(lang.badge))").tag(lang)
                            }
                        }
                        .labelsHidden()
                        .pickerStyle(.segmented)
                        .frame(width: 220)
                    }
                    Stepper(
                        localizer.L("Default Guest vCPUs: \(preferences.defaultVCPUs)", "默认客户机 vCPU 核数: \(preferences.defaultVCPUs)"),
                        value: $preferences.defaultVCPUs,
                        in: 1...16
                    )
                    Stepper(
                        localizer.L("Max Concurrent Running VMs: \(preferences.maxConcurrentRunningVMs)", "最大并发运行虚拟机数: \(preferences.maxConcurrentRunningVMs)"),
                        value: $preferences.maxConcurrentRunningVMs,
                        in: 1...32
                    )
                    Stepper(
                        localizer.L("Host RAM Ceiling: \(preferences.maxTotalFleetRAMPercent)%", "宿主机内存占用上限: \(preferences.maxTotalFleetRAMPercent)%"),
                        value: $preferences.maxTotalFleetRAMPercent,
                        in: 25...90,
                        step: 5
                    )
                    Stepper(
                        localizer.L("Auto-Pause Idle Branches After: \(preferences.autoPauseIdleMinutes) min", "空闲分支自动暂停阈值: \(preferences.autoPauseIdleMinutes) 分钟"),
                        value: $preferences.autoPauseIdleMinutes,
                        in: 5...240,
                        step: 5
                    )
                case .storage:
                    LabeledContent(localizer.L("Storage Pool Folder", "存储池相对目录")) {
                        TextField("StoragePool", text: $preferences.storagePoolRelativeDir)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 240)
                    }
                    Stepper(
                        localizer.L("Max Dirty CoW Pool Quota: \(preferences.maxCoWDirtyQuotaGB) GB", "CoW 脏块存储池配额上限: \(preferences.maxCoWDirtyQuotaGB) GB"),
                        value: $preferences.maxCoWDirtyQuotaGB,
                        in: 8...512,
                        step: 8
                    )
                    Toggle(
                        localizer.L("Auto-Snapshot Before Destructive Guest Exec", "执行高危客户机命令前自动创建 CoW 快照"),
                        isOn: $preferences.enablePreExecAutoSnapshot
                    )
                case .network:
                    LabeledContent(localizer.L("Switch Subnet CIDR", "虚拟交换机网段 CIDR")) {
                        TextField("10.211.55.0/24", text: $preferences.switchSubnetCIDR)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 220)
                    }
                    LabeledContent(localizer.L("Switch Gateway IPv4", "虚拟交换机网关 IPv4")) {
                        TextField("10.211.55.1", text: $preferences.switchGatewayIP)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 220)
                    }
                    LabeledContent(localizer.L("Upstream DNS Resolver", "上游 DNS 解析服务器")) {
                        TextField("1.1.1.1", text: $preferences.upstreamDNSServer)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 220)
                    }
                    Toggle(
                        localizer.L("Continuous Ring-Buffer PCAPNG Capture", "持续环形缓冲区 PCAPNG 抓包记录"),
                        isOn: $preferences.autoCapturePCAPNG
                    )
                case .security:
                    Toggle(
                        localizer.L("Enable Secret-Leak DPI Plugin by Default", "默认启用密钥外泄 DPI 检测插件"),
                        isOn: $preferences.enableSecretLeakPluginByDefault
                    )
                    Stepper(
                        localizer.L("PCAP Ring Buffer Capacity: \(preferences.maxPCAPRingBufferPackets) pkts", "PCAP 环形缓冲区容量: \(preferences.maxPCAPRingBufferPackets) 帧"),
                        value: $preferences.maxPCAPRingBufferPackets,
                        in: 5_000...200_000,
                        step: 5_000
                    )
                }

                Spacer()

                HStack {
                    Spacer()
                    Button(localizer.L("Apply & Persist Preferences", "应用并保存偏好设置")) {
                        onSave(preferences)
                    }
                    .buttonStyle(RackActionButtonStyle(prominence: .primaryAmber))
                }
            }
            .font(RackTheme.bodyFont)
            .foregroundStyle(RackTheme.inkPrimary)
            .padding(20)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .background(RackTheme.chassisBackground)
        }
        .frame(width: 660, height: 410)
        .preferredColorScheme(.dark)
    }
}
