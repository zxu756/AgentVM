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
    public let hostCapabilities: HostCapabilityReport
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
                    .fill(hostCapabilities.isVirtualizationFrameworkSupported ? RackTheme.linkGreen : RackTheme.amberAccent)
                    .frame(width: 7, height: 7)
                Text(hostCapabilities.isVirtualizationFrameworkSupported ? "Hypervisor: Apple VZ (\(hostCapabilities.architecture))" : "Hypervisor: Simulation Mode")
                    .font(RackTheme.monoSmallFont)
                    .foregroundStyle(RackTheme.inkPrimary)
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)
            }

            statusDivider

            Text("Fleet: \(runningVMCount)/\(totalVMCount) Active")
                .font(RackTheme.monoSmallFont)
                .monospacedDigit()
                .foregroundStyle(RackTheme.inkSecondary)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)

            statusDivider

            Text("CoW Delta: \(ByteMetricsFormatter.formatBytes(totalDirtyCoWBytes))")
                .font(RackTheme.monoSmallFont)
                .monospacedDigit()
                .foregroundStyle(RackTheme.amberAccent)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)

            statusDivider

            Text("Wiretap: \(capturedPacketCount) pkts (\(droppedPacketCount) dropped)")
                .font(RackTheme.monoSmallFont)
                .monospacedDigit()
                .foregroundStyle(droppedPacketCount > 0 ? RackTheme.dropCrimson : RackTheme.inkSecondary)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)

            statusDivider

            Text("JS Plugins: \(activePluginsCount) enabled")
                .font(RackTheme.monoSmallFont)
                .monospacedDigit()
                .foregroundStyle(RackTheme.vsockBlue)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)

            Spacer(minLength: 8)

            Button(action: onToggleBottomDrawer) {
                Label("Drawer", systemImage: "rectangle.bottomhalf.inset.filled")
            }
            .buttonStyle(RackActionButtonStyle(prominence: .subtleGhost, compact: true))

            Button(action: onOpenCommandPalette) {
                HStack(spacing: 5) {
                    Text("Command Palette")
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
                Text("AgentVM Preferences")
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
                            Text(section.rawValue)
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
            }
            .padding(12)
            .frame(width: 200)
            .background(RackTheme.bladeRecessed)

            Rectangle()
                .fill(RackTheme.hairline)
                .frame(width: 1)

            VStack(alignment: .leading, spacing: 16) {
                Text(selectedSection.rawValue)
                    .font(RackTheme.displayTitleFont)
                    .foregroundStyle(RackTheme.inkPrimary)

                switch selectedSection {
                case .hypervisor:
                    Stepper("Default Guest vCPUs: \(preferences.defaultVCPUs)", value: $preferences.defaultVCPUs, in: 1...16)
                    Stepper("Max Concurrent Running VMs: \(preferences.maxConcurrentRunningVMs)", value: $preferences.maxConcurrentRunningVMs, in: 1...32)
                    Stepper("Host RAM Ceiling: \(preferences.maxTotalFleetRAMPercent)%", value: $preferences.maxTotalFleetRAMPercent, in: 25...90, step: 5)
                    Stepper("Auto-Pause Idle Branches After: \(preferences.autoPauseIdleMinutes) min", value: $preferences.autoPauseIdleMinutes, in: 5...240, step: 5)
                case .storage:
                    LabeledContent("Storage Pool Folder") {
                        TextField("StoragePool", text: $preferences.storagePoolRelativeDir)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 240)
                    }
                    Stepper("Max Dirty CoW Pool Quota: \(preferences.maxCoWDirtyQuotaGB) GB", value: $preferences.maxCoWDirtyQuotaGB, in: 8...512, step: 8)
                    Toggle("Auto-Snapshot Before Destructive Guest Exec", isOn: $preferences.enablePreExecAutoSnapshot)
                case .network:
                    LabeledContent("Switch Subnet CIDR") {
                        TextField("10.211.55.0/24", text: $preferences.switchSubnetCIDR)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 220)
                    }
                    LabeledContent("Switch Gateway IPv4") {
                        TextField("10.211.55.1", text: $preferences.switchGatewayIP)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 220)
                    }
                    LabeledContent("Upstream DNS Resolver") {
                        TextField("1.1.1.1", text: $preferences.upstreamDNSServer)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 220)
                    }
                    Toggle("Continuous Ring-Buffer PCAPNG Capture", isOn: $preferences.autoCapturePCAPNG)
                case .security:
                    Toggle("Enable Secret-Leak DPI Plugin by Default", isOn: $preferences.enableSecretLeakPluginByDefault)
                    Stepper("PCAP Ring Buffer Capacity: \(preferences.maxPCAPRingBufferPackets) pkts", value: $preferences.maxPCAPRingBufferPackets, in: 5_000...200_000, step: 5_000)
                }

                Spacer()

                HStack {
                    Spacer()
                    Button("Apply & Persist Preferences") {
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
        .frame(width: 640, height: 380)
        .preferredColorScheme(.dark)
    }
}
