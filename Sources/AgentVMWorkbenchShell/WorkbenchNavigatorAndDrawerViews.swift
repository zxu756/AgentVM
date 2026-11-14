import AgentVMModels
import SwiftUI

// MARK: - Left Collapsible Fleet & CoW Lineage Navigator Rail

public struct FleetNavigatorRailView: View {
    @ObservedObject private var localizer = AgentVMLocalizer.shared
    public let vms: [VMInstanceRecord]
    public let snapshots: [SnapshotNode]
    public let selectedVMID: VMID?
    public let onSelectVM: (VMID) -> Void
    public let onForkBranch: (VMID) -> Void
    public let onToggleRunState: (VMID) -> Void
    public let onCreateNewVM: () -> Void
    @State private var filterText: String = ""

    public init(
        vms: [VMInstanceRecord],
        snapshots: [SnapshotNode],
        selectedVMID: VMID?,
        onSelectVM: @escaping (VMID) -> Void,
        onForkBranch: @escaping (VMID) -> Void,
        onToggleRunState: @escaping (VMID) -> Void,
        onCreateNewVM: @escaping () -> Void
    ) {
        self.vms = vms
        self.snapshots = snapshots
        self.selectedVMID = selectedVMID
        self.onSelectVM = onSelectVM
        self.onForkBranch = onForkBranch
        self.onToggleRunState = onToggleRunState
        self.onCreateNewVM = onCreateNewVM
    }

    private var filteredVMs: [VMInstanceRecord] {
        let q = filterText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !q.isEmpty else { return vms }
        return vms.filter {
            $0.spec.name.lowercased().contains(q)
                || $0.spec.agentOwnerTag.lowercased().contains(q)
                || $0.spec.id.rawValue.lowercased().contains(q)
        }
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: "server.rack")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(RackTheme.amberAccent)
                Text(localizer.L("Sandbox Fleet", "沙盒集群"))
                    .font(RackTheme.sectionHeaderFont)
                    .foregroundStyle(RackTheme.inkPrimary)
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)
                Spacer(minLength: 4)
                Button(action: onCreateNewVM) {
                    Image(systemName: "plus")
                        .font(.system(size: 11, weight: .semibold))
                }
                .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
                .help(localizer.L("Provision New Sandbox VM (⌘N)", "新建沙盒虚拟机 (⌘N)"))
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)

            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .font(.system(size: 11))
                    .foregroundStyle(RackTheme.inkMuted)
                TextField(localizer.L("Filter blades or agents", "筛选刀片或智能体"), text: $filterText)
                    .textFieldStyle(.plain)
                    .font(RackTheme.captionFont)
                    .foregroundStyle(RackTheme.inkPrimary)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 5)
            .background(
                RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                    .fill(RackTheme.chassisBackground)
            )
            .overlay(
                RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                    .strokeBorder(RackTheme.hairline, lineWidth: 1)
            )
            .padding(.horizontal, 10)
            .padding(.bottom, 8)

            Rectangle()
                .fill(RackTheme.hairline)
                .frame(height: 1)

            ScrollView {
                LazyVStack(spacing: 6) {
                    ForEach(filteredVMs) { vm in
                        let isSelected = vm.id == selectedVMID
                        let snapCount = snapshots.filter { $0.vmID == vm.id }.count
                        FleetBladeRowCard(
                            vm: vm,
                            snapshotCount: snapCount,
                            isSelected: isSelected,
                            onSelect: { onSelectVM(vm.id) },
                            onFork: { onForkBranch(vm.id) },
                            onToggleRun: { onToggleRunState(vm.id) }
                        )
                    }
                }
                .padding(8)
            }
        }
        .background(RackTheme.bladeRecessed)
    }

    private struct FleetBladeRowCard: View {
        @ObservedObject private var localizer = AgentVMLocalizer.shared
        let vm: VMInstanceRecord
        let snapshotCount: Int
        let isSelected: Bool
        let onSelect: () -> Void
        let onFork: () -> Void
        let onToggleRun: () -> Void
        @State private var isHovered = false

        var body: some View {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 7) {
                    Circle()
                        .fill(RackTheme.signalColor(for: vm.telemetry.state))
                        .frame(width: 8, height: 8)

                    Text(vm.spec.name)
                        .font(.system(size: 12.5, weight: .semibold))
                        .foregroundStyle(RackTheme.inkPrimary)
                        .lineLimit(1)

                    Spacer(minLength: 4)

                    Text(vm.telemetry.state.localizedBadge)
                        .font(RackTheme.monoSmallFont)
                        .foregroundStyle(RackTheme.signalColor(for: vm.telemetry.state))
                        .lineLimit(1)
                        .fixedSize(horizontal: true, vertical: false)
                }

                HStack(spacing: 8) {
                    Text("@\(vm.spec.agentOwnerTag)")
                        .font(RackTheme.monoSmallFont)
                        .foregroundStyle(RackTheme.amberAccent)
                        .lineLimit(1)

                    Text("\(vm.spec.compute.vcpuCount)c / \(vm.spec.compute.memoryMB / 1024)G")
                        .font(RackTheme.monoSmallFont)
                        .monospacedDigit()
                        .foregroundStyle(RackTheme.inkMuted)
                        .lineLimit(1)
                        .fixedSize(horizontal: true, vertical: false)

                    Spacer(minLength: 0)

                    Text(localizer.L("\(snapshotCount) snaps", "\(snapshotCount) 快照"))
                        .font(RackTheme.monoSmallFont)
                        .monospacedDigit()
                        .foregroundStyle(RackTheme.inkMuted)
                        .lineLimit(1)
                        .fixedSize(horizontal: true, vertical: false)
                }

                HStack(spacing: 6) {
                    Text(vm.telemetry.hasLiveGuestTelemetry ? "CPU \(Int(vm.telemetry.cpuUsagePercent.rounded()))%" : "CPU —")
                        .font(RackTheme.monoSmallFont)
                        .monospacedDigit()
                        .foregroundStyle(RackTheme.inkSecondary)
                        .lineLimit(1)
                        .fixedSize(horizontal: true, vertical: false)

                    Text("CoW \(ByteMetricsFormatter.formatBytes(vm.telemetry.cowDirtyBytes))")
                        .font(RackTheme.monoSmallFont)
                        .monospacedDigit()
                        .foregroundStyle(RackTheme.inkSecondary)
                        .lineLimit(1)
                        .fixedSize(horizontal: true, vertical: false)

                    Spacer(minLength: 4)

                    Button(action: onFork) {
                        Image(systemName: "arrow.triangle.branch")
                            .font(.system(size: 10, weight: .semibold))
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(RackTheme.amberAccent)
                    .help(localizer.L("Instant APFS CoW Branch", "即时 APFS CoW 分叉"))

                    Button(action: onToggleRun) {
                        Image(systemName: vm.telemetry.state == .running ? "pause.fill" : "play.fill")
                            .font(.system(size: 10, weight: .semibold))
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(vm.telemetry.state == .running ? RackTheme.checkpointGold : RackTheme.linkGreen)
                    .help(localizer.L("Start or Pause VM", "启动或暂停虚拟机"))
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
            .background(
                RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                    .fill(isSelected ? RackTheme.moduleElevated : (isHovered ? RackTheme.moduleSurface : RackTheme.chassisBackground.opacity(0.65)))
            )
            .overlay(
                RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                    .strokeBorder(isSelected ? RackTheme.amberAccent : RackTheme.hairline, lineWidth: 1)
            )
            .contentShape(Rectangle())
            .onTapGesture(perform: onSelect)
            .onHover { isHovered = $0 }
        }
    }
}

// MARK: - Right Hardware & Security Topology Inspector Rail

public struct VMHardwareInspectorRailView: View {
    @ObservedObject private var localizer = AgentVMLocalizer.shared
    public let vm: VMInstanceRecord?
    public let activePortForwardsCount: Int
    public let onSnapshotNow: () -> Void
    public let onForkCoW: () -> Void

    public init(
        vm: VMInstanceRecord?,
        activePortForwardsCount: Int,
        onSnapshotNow: @escaping () -> Void,
        onForkCoW: @escaping () -> Void
    ) {
        self.vm = vm
        self.activePortForwardsCount = activePortForwardsCount
        self.onSnapshotNow = onSnapshotNow
        self.onForkCoW = onForkCoW
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 7) {
                Image(systemName: "slider.horizontal.below.rectangle")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(RackTheme.amberAccent)
                Text(localizer.L("Blade Inspector", "刀片检查器"))
                    .font(RackTheme.sectionHeaderFont)
                    .foregroundStyle(RackTheme.inkPrimary)
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)
                Spacer()
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)

            Rectangle()
                .fill(RackTheme.hairline)
                .frame(height: 1)

            if let vm {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        VStack(alignment: .leading, spacing: 6) {
                            HStack {
                                Text(vm.spec.name)
                                    .font(.system(size: 14, weight: .semibold))
                                    .foregroundStyle(RackTheme.inkPrimary)
                                    .lineLimit(1)
                                Spacer()
                                RackStatusPill(
                                    label: vm.telemetry.state.localizedBadge,
                                    color: RackTheme.signalColor(for: vm.telemetry.state),
                                    monospaced: true
                                )
                            }
                            Text(vm.spec.guestOS.localizedDisplayName)
                                .font(RackTheme.captionFont)
                                .foregroundStyle(RackTheme.inkSecondary)
                                .lineLimit(1)
                        }

                        HStack(spacing: 6) {
                            Button(action: onForkCoW) {
                                Label(localizer.L("Fork CoW", "分叉 CoW"), systemImage: "arrow.triangle.branch")
                            }
                            .buttonStyle(RackActionButtonStyle(prominence: .primaryAmber, compact: true))

                            Button(action: onSnapshotNow) {
                                Label(localizer.L("Checkpoint", "捕获快照"), systemImage: "camera.metering.matrix")
                            }
                            .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
                        }

                        inspectorGroup(title: localizer.L("Compute & Memory", "计算与内存")) {
                            kvRow(localizer.L("vCPU Topology", "vCPU 拓扑"), localizer.L("\(vm.spec.compute.vcpuCount) Apple VZ Cores", "\(vm.spec.compute.vcpuCount) 核 Apple VZ"))
                            kvRow(localizer.L("Allocated RAM", "分配内存"), "\(vm.spec.compute.memoryMB) MB")
                            kvRow(localizer.L("Resident RSS", "常驻内存"), vm.telemetry.formattedMemoryResident)
                            kvRow(localizer.L("Balloon Reclaim", "气球回收"), vm.telemetry.formattedBalloonReclaimed)
                            kvRow(
                                localizer.L("Guest Agent", "客户机代理"),
                                vm.telemetry.guestAgentConnected
                                    ? (vm.telemetry.hasLiveGuestTelemetry
                                        ? localizer.L("AVM1 Connected", "AVM1 已连接")
                                        : localizer.L("Simulated (AVM1)", "模拟连接 (AVM1)"))
                                    : localizer.L("Standby", "待命")
                            )
                        }

                        inspectorGroup(title: localizer.L("APFS Storage & VirtioFS", "APFS 存储与 VirtioFS")) {
                            kvRow(localizer.L("Block Volumes", "块存储卷"), localizer.L("\(vm.spec.blockDevices.count) attached", "\(vm.spec.blockDevices.count) 块已挂载"))
                            kvRow(localizer.L("Dirty CoW Delta", "CoW 脏块"), ByteMetricsFormatter.formatBytes(vm.telemetry.cowDirtyBytes))
                            kvRow(localizer.L("Disk Read / Write", "磁盘读写"), "\(ByteMetricsFormatter.formatBytes(vm.telemetry.diskReadBytesTotal)) / \(ByteMetricsFormatter.formatBytes(vm.telemetry.diskWriteBytesTotal))")
                            ForEach(vm.spec.virtioFSMounts) { mount in
                                kvRow(localizer.L("Mount [\(mount.mountTag)]", "挂载 [\(mount.mountTag)]"), mount.guestMountPoint)
                            }
                        }

                        inspectorGroup(title: localizer.L("L2 Switch & Vsock Tunnels", "二层交换与 Vsock 隧道")) {
                            if let nic = vm.spec.networkInterfaces.first {
                                kvRow(localizer.L("NIC Mode", "网卡模式"), nic.mode.localizedInspectorBadge)
                                kvRow(localizer.L("Guest IPv4", "客户机 IPv4"), nic.ipv4Address)
                                kvRow(localizer.L("Guest MAC", "客户机 MAC"), nic.macAddress)
                            }
                            kvRow(localizer.L("Active TCP Flows", "活跃 TCP 流"), "\(vm.telemetry.activeTCPFlows)")
                            kvRow(localizer.L("Firewall Drops", "防火墙拦截"), localizer.L("\(vm.telemetry.firewallDroppedPackets) pkts", "\(vm.telemetry.firewallDroppedPackets) 帧"))
                            kvRow(localizer.L("Port Forwards", "端口转发"), localizer.L("\(activePortForwardsCount) bound", "\(activePortForwardsCount) 已绑定"))
                        }
                    }
                    .padding(12)
                }
            } else {
                VStack(spacing: 6) {
                    Text(localizer.L("No virtual machine selected", "未选择虚拟机"))
                        .font(RackTheme.labelFont)
                        .foregroundStyle(RackTheme.inkMuted)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .background(RackTheme.bladeRecessed)
    }

    private func inspectorGroup<Content: View>(title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(RackTheme.labelFont)
                .foregroundStyle(RackTheme.amberAccent)
                .lineLimit(1)
            VStack(spacing: 5) {
                content()
            }
            .padding(9)
            .background(
                RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                    .fill(RackTheme.moduleSurface)
            )
            .overlay(
                RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                    .strokeBorder(RackTheme.hairline, lineWidth: 1)
            )
        }
    }

    private func kvRow(_ key: String, _ value: String) -> some View {
        HStack(spacing: 6) {
            Text(key)
                .font(RackTheme.captionFont)
                .foregroundStyle(RackTheme.inkMuted)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
            Spacer(minLength: 6)
            Text(value)
                .font(RackTheme.monoSmallFont)
                .monospacedDigit()
                .foregroundStyle(RackTheme.inkPrimary)
                .lineLimit(1)
        }
    }
}

// MARK: - Bottom 4-Channel Workbench Drawer

public struct WorkbenchBottomDrawerView: View {
    @ObservedObject private var localizer = AgentVMLocalizer.shared
    @Binding public var activeChannel: BottomDrawerChannel
    public let serialLines: [String]
    public let diagnostics: [DiagnosticEvent]
    public let undoTitles: [String]
    public let redoTitles: [String]
    public let pluginLogs: [PluginHookConsoleEntry]
    public let onUndo: () -> Void
    public let onRedo: () -> Void
    public let onCloseDrawer: () -> Void

    public init(
        activeChannel: Binding<BottomDrawerChannel>,
        serialLines: [String],
        diagnostics: [DiagnosticEvent],
        undoTitles: [String],
        redoTitles: [String],
        pluginLogs: [PluginHookConsoleEntry],
        onUndo: @escaping () -> Void,
        onRedo: @escaping () -> Void,
        onCloseDrawer: @escaping () -> Void
    ) {
        self._activeChannel = activeChannel
        self.serialLines = serialLines
        self.diagnostics = diagnostics
        self.undoTitles = undoTitles
        self.redoTitles = redoTitles
        self.pluginLogs = pluginLogs
        self.onUndo = onUndo
        self.onRedo = onRedo
        self.onCloseDrawer = onCloseDrawer
    }

    public var body: some View {
        VStack(spacing: 0) {
            Rectangle()
                .fill(RackTheme.hairlineStrong)
                .frame(height: 1)

            HStack(spacing: 4) {
                ForEach(BottomDrawerChannel.allCases, id: \.self) { channel in
                    let selected = channel == activeChannel
                    Button {
                        activeChannel = channel
                    } label: {
                        Text(channel.localizedTitle)
                            .font(RackTheme.labelFont)
                            .foregroundStyle(selected ? RackTheme.inkPrimary : RackTheme.inkMuted)
                            .lineLimit(1)
                            .fixedSize(horizontal: true, vertical: false)
                            .padding(.horizontal, 9)
                            .padding(.vertical, 4)
                            .background(
                                RoundedRectangle(cornerRadius: RackTheme.badgeCornerRadius, style: .continuous)
                                    .fill(selected ? RackTheme.moduleSurface : Color.clear)
                            )
                    }
                    .buttonStyle(.plain)
                }

                Spacer(minLength: 8)

                if activeChannel == .undoHistory {
                    Button(action: onUndo) {
                        Label(localizer.L("Undo", "撤销"), systemImage: "arrow.uturn.backward")
                    }
                    .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
                    .disabled(undoTitles.isEmpty)

                    Button(action: onRedo) {
                        Label(localizer.L("Redo", "重做"), systemImage: "arrow.uturn.forward")
                    }
                    .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
                    .disabled(redoTitles.isEmpty)
                }

                Button(action: onCloseDrawer) {
                    Image(systemName: "chevron.down")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundStyle(RackTheme.inkMuted)
                        .frame(width: 20, height: 20)
                }
                .buttonStyle(.plain)
            }
            .padding(.horizontal, 10)
            .frame(height: 31)
            .background(RackTheme.bladeRecessed)

            Rectangle()
                .fill(RackTheme.hairline)
                .frame(height: 1)

            ScrollView {
                VStack(alignment: .leading, spacing: 4) {
                    switch activeChannel {
                    case .serialTTY:
                        ForEach(Array(serialLines.suffix(60).enumerated()), id: \.offset) { _, line in
                            Text(line)
                                .font(RackTheme.monoSmallFont)
                                .foregroundStyle(RackTheme.inkPrimary)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    case .firewallAlerts:
                        ForEach(diagnostics.prefix(40)) { event in
                            HStack(spacing: 8) {
                                RackStatusPill(
                                    label: event.severity.localizedBadge,
                                    color: RackTheme.severityColor(for: event.severity),
                                    monospaced: true
                                )
                                Text("[\(event.code)]")
                                    .font(RackTheme.monoSmallFont)
                                    .foregroundStyle(RackTheme.amberAccent)
                                    .lineLimit(1)
                                    .fixedSize(horizontal: true, vertical: false)
                                Text(event.localizedMessage)
                                    .font(RackTheme.captionFont)
                                    .foregroundStyle(RackTheme.inkPrimary)
                                    .lineLimit(1)
                                Spacer(minLength: 0)
                            }
                        }
                    case .undoHistory:
                        if undoTitles.isEmpty && redoTitles.isEmpty {
                            Text(localizer.L(
                                "Undo journal clean — perform any VM, Snapshot, or Policy mutation to record reversible transactions.",
                                "撤销日志为空 — 执行任意虚拟机、快照或防火墙策略变更后将自动记录可逆事务。"
                            ))
                                .font(RackTheme.captionFont)
                                .foregroundStyle(RackTheme.inkMuted)
                        } else {
                            ForEach(Array(undoTitles.enumerated()), id: \.offset) { idx, item in
                                HStack(spacing: 8) {
                                    Text("#\(undoTitles.count - idx)")
                                        .font(RackTheme.monoSmallFont)
                                        .foregroundStyle(RackTheme.amberAccent)
                                    Text(item)
                                        .font(RackTheme.captionFont)
                                        .foregroundStyle(RackTheme.inkPrimary)
                                    Spacer()
                                }
                            }
                        }
                    case .pluginLogs:
                        ForEach(pluginLogs.prefix(40)) { entry in
                            HStack(spacing: 8) {
                                Text(entry.pluginID.rawValue)
                                    .font(RackTheme.monoSmallFont)
                                    .foregroundStyle(RackTheme.vsockBlue)
                                    .lineLimit(1)
                                    .fixedSize(horizontal: true, vertical: false)
                                Text("[\(entry.hookName)]")
                                    .font(RackTheme.monoSmallFont)
                                    .foregroundStyle(RackTheme.inkMuted)
                                    .lineLimit(1)
                                    .fixedSize(horizontal: true, vertical: false)
                                Text(entry.message)
                                    .font(RackTheme.captionFont)
                                    .foregroundStyle(RackTheme.inkPrimary)
                                    .lineLimit(1)
                                Spacer()
                                Text("\(entry.durationMicros) µs")
                                    .font(RackTheme.monoSmallFont)
                                    .monospacedDigit()
                                    .foregroundStyle(RackTheme.inkMuted)
                            }
                        }
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
            }
            .background(RackTheme.terminalWell)
        }
    }
}
