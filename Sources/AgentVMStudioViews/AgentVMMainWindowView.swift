import AgentVMModels
import AgentVMStore
import AgentVMWorkbenchShell
import SwiftUI

// MARK: - Complete Industrial macOS Workbench Window Assembly

public struct AgentVMMainWindowView: View {
    @ObservedObject public var viewModel: AgentVMStudioViewModel
    @ObservedObject private var localizer = AgentVMLocalizer.shared

    public init(viewModel: AgentVMStudioViewModel) {
        self.viewModel = viewModel
    }

    public var body: some View {
        ZStack {
            VStack(spacing: 0) {
                topWorkbenchToolbar

                HStack(spacing: 0) {
                    if viewModel.docking.showLeftNavigator {
                        FleetNavigatorRailView(
                            vms: viewModel.vms,
                            snapshots: viewModel.snapshots,
                            selectedVMID: viewModel.selectedVM?.id,
                            onSelectVM: { vmID in
                                viewModel.selectVM(vmID)
                            },
                            onForkBranch: { vmID in
                                viewModel.forkCoWBranch(from: vmID)
                            },
                            onToggleRunState: { vmID in
                                viewModel.toggleRunState(for: vmID)
                            },
                            onCreateNewVM: {
                                viewModel.createNewSandboxBlade()
                            }
                        )
                        .frame(width: viewModel.docking.leftRailWidth)

                        Rectangle()
                            .fill(RackTheme.hairlineStrong)
                            .frame(width: 1)
                    }

                    centerDockingWorkspace
                        .frame(maxWidth: .infinity, maxHeight: .infinity)

                    if viewModel.docking.showRightInspector {
                        Rectangle()
                            .fill(RackTheme.hairlineStrong)
                            .frame(width: 1)

                        VMHardwareInspectorRailView(
                            vm: viewModel.selectedVM,
                            activePortForwardsCount: viewModel.activePortForwardCountForSelectedVM,
                            onSnapshotNow: {
                                viewModel.captureCheckpoint()
                            },
                            onForkCoW: {
                                viewModel.forkCoWBranch()
                            }
                        )
                        .frame(width: viewModel.docking.rightRailWidth)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)

                WorkbenchTelemetryStatusBar(
                    hostCapabilities: viewModel.hostCapabilities,
                    hypervisorStatusText: viewModel.hypervisorStatusText,
                    isHypervisorReady: viewModel.isHypervisorReadyForRealGuests,
                    runningVMCount: viewModel.runningVMCount,
                    totalVMCount: viewModel.vms.count,
                    totalDirtyCoWBytes: viewModel.totalDirtyCoWBytes,
                    capturedPacketCount: viewModel.allPackets.count,
                    droppedPacketCount: viewModel.droppedPacketCount,
                    activePluginsCount: viewModel.activePluginsCount,
                    canUndo: viewModel.canUndo,
                    canRedo: viewModel.canRedo,
                    onOpenCommandPalette: {
                        viewModel.commandPalette.toggleInstant()
                    },
                    onToggleBottomDrawer: {
                        viewModel.docking.showBottomDrawer.toggle()
                    }
                )
            }
            .background(RackTheme.chassisBackground)

            // Non-blocking bottom-trailing toast stack
            VStack {
                Spacer()
                HStack {
                    Spacer()
                    WorkbenchToastStackOverlay(center: viewModel.toastCenter)
                }
            }
            .allowsHitTesting(!viewModel.toastCenter.activeToasts.isEmpty)

            // Instant Cmd+K Command Palette modal
            CommandPaletteOverlayView(controller: viewModel.commandPalette)
        }
        .preferredColorScheme(.dark)
        .task {
            await viewModel.bootstrapWorkspace()
        }
    }

    // MARK: - Top Machined Chassis Toolbar

    private var topWorkbenchToolbar: some View {
        HStack(spacing: 8) {
            // Chassis Brand + Workspace Title
            HStack(spacing: 8) {
                ZStack {
                    RoundedRectangle(cornerRadius: 5, style: .continuous)
                        .fill(RackTheme.amberSoft)
                        .frame(width: 24, height: 24)
                    RoundedRectangle(cornerRadius: 5, style: .continuous)
                        .strokeBorder(RackTheme.amberAccent.opacity(0.65), lineWidth: 1)
                        .frame(width: 24, height: 24)
                    Image(systemName: "cpu.fill")
                        .font(.system(size: 11.5, weight: .bold))
                        .foregroundStyle(RackTheme.amberAccent)
                }

                Text("AgentVM")
                    .font(.system(size: 13.5, weight: .bold))
                    .foregroundStyle(RackTheme.inkPrimary)
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)

                Text(viewModel.localizedWorkspaceTitle)
                    .font(RackTheme.labelFont)
                    .foregroundStyle(RackTheme.inkSecondary)
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)

                if viewModel.isDemoMode {
                    RackStatusPill(
                        label: localizer.L("DEMO · SYNTHETIC DATA", "演示数据 · 合成样本"),
                        color: RackTheme.amberAccent,
                        monospaced: true
                    )
                }

                if let vm = viewModel.selectedVM {
                    RackStatusPill(
                        label: "\(vm.spec.name) · \(vm.telemetry.localizedStateBadge)",
                        color: RackTheme.signalColor(for: vm.telemetry.state),
                        monospaced: true
                    )
                }

                if !viewModel.isDemoMode {
                    Button {
                        viewModel.loadDemonstrationFleet()
                    } label: {
                        Label(localizer.L("Load Demo", "载入演示"), systemImage: "sparkles.rectangle.stack")
                    }
                    .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
                    .help(localizer.L("Populate workspace with synthetic [DEMO] VMs and packets", "填充带 [演示数据] 标记的合成演示虚拟机与数据包"))
                }
            }

            Spacer(minLength: 8)

            // Transactional Undo / Redo Cluster
            HStack(spacing: 4) {
                Button {
                    viewModel.performUndo()
                } label: {
                    Label(localizer.L("Undo", "撤销"), systemImage: "arrow.uturn.backward")
                }
                .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
                .disabled(!viewModel.canUndo)
                .help(localizer.L("Undo last reversible topology or firewall mutation (⌘Z)", "撤销上一次可逆拓扑或防火墙变更 (⌘Z)"))

                Button {
                    viewModel.performRedo()
                } label: {
                    Label(localizer.L("Redo", "重做"), systemImage: "arrow.uturn.forward")
                }
                .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
                .disabled(!viewModel.canRedo)
                .help(localizer.L("Redo reverted workspace mutation (⇧⌘Z)", "重做已撤销的工作区变更 (⇧⌘Z)"))
            }

            toolbarDivider

            // Rail & Split Layout Toggles
            HStack(spacing: 4) {
                Button {
                    viewModel.docking.showLeftNavigator.toggle()
                } label: {
                    Image(systemName: "sidebar.left")
                        .font(.system(size: 11.5, weight: .semibold))
                        .foregroundStyle(viewModel.docking.showLeftNavigator ? RackTheme.amberAccent : RackTheme.inkSecondary)
                }
                .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
                .help(localizer.L("Toggle Left Sandbox Fleet Navigator", "显示或隐藏左侧沙盒集群导航栏"))

                Button {
                    if viewModel.docking.splitMode == .singlePane {
                        viewModel.docking.splitCurrentTabRight()
                    } else {
                        viewModel.docking.collapseSplit()
                    }
                } label: {
                    Label(
                        viewModel.docking.splitMode == .singlePane
                            ? localizer.L("Split", "分屏")
                            : localizer.L("Single", "单栏"),
                        systemImage: viewModel.docking.splitMode == .singlePane ? "rectangle.split.2x1" : "rectangle"
                    )
                }
                .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
                .help(localizer.L("Toggle Side-by-Side Split Workbench (⌘\\)", "切换双栏分屏工作台 (⌘\\)"))

                Button {
                    viewModel.docking.showBottomDrawer.toggle()
                } label: {
                    Image(systemName: "rectangle.bottomhalf.inset.filled")
                        .font(.system(size: 11.5, weight: .semibold))
                        .foregroundStyle(viewModel.docking.showBottomDrawer ? RackTheme.amberAccent : RackTheme.inkSecondary)
                }
                .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
                .help(localizer.L("Toggle Bottom Diagnostics & TTY Drawer", "显示或隐藏底部诊断与终端抽屉"))

                Button {
                    viewModel.docking.showRightInspector.toggle()
                } label: {
                    Image(systemName: "sidebar.right")
                        .font(.system(size: 11.5, weight: .semibold))
                        .foregroundStyle(viewModel.docking.showRightInspector ? RackTheme.amberAccent : RackTheme.inkSecondary)
                }
                .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
                .help(localizer.L("Toggle Right Blade Hardware Inspector", "显示或隐藏右侧刀片硬件检查器"))
            }

            toolbarDivider

            // Artifact Exporters
            HStack(spacing: 4) {
                Button {
                    viewModel.exportPCAPNGDefault()
                } label: {
                    Label(".pcapng", systemImage: "waveform.path.ecg")
                }
                .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
                .help(localizer.L("Export Captured Traffic as Wireshark .pcapng (⇧⌘E)", "导出 Wireshark .pcapng 抓包归档 (⇧⌘E)"))

                Button {
                    viewModel.exportHTMLSecurityReportDefault()
                } label: {
                    Label(localizer.L("HTML Audit", "HTML 审计"), systemImage: "doc.richtext")
                }
                .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
                .help(localizer.L("Export Standalone Bilingual HTML Security Dossier", "导出独立双语 HTML 安全审计报告"))
            }

            toolbarDivider

            // Live Bilingual Interface Toggle Pill (`中文 | EN`)
            RackLanguageTogglePill(localizer: localizer)

            toolbarDivider

            // Instant Cmd+K Trigger
            Button {
                viewModel.commandPalette.toggleInstant()
            } label: {
                HStack(spacing: 5) {
                    Image(systemName: "command")
                        .font(.system(size: 10.5, weight: .semibold))
                        .foregroundStyle(RackTheme.amberAccent)
                    Text(localizer.L("Palette", "命令"))
                    RackKeyCapBadge("⌘K")
                }
            }
            .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
            .help(localizer.L("Open Instant Fuzzy Command Palette (⌘K)", "打开模糊检索命令面板 (⌘K)"))
        }
        .padding(.horizontal, 12)
        .frame(height: 42)
        .background(RackTheme.bladeRecessed)
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(RackTheme.hairlineStrong)
                .frame(height: 1)
        }
    }

    private var toolbarDivider: some View {
        Rectangle()
            .fill(RackTheme.hairline)
            .frame(width: 1, height: 18)
    }

    // MARK: - Center Docking Document Workspace + Optional Split + Bottom Drawer

    private var centerDockingWorkspace: some View {
        VStack(spacing: 0) {
            switch viewModel.docking.splitMode {
            case .singlePane:
                primaryDocumentColumn
                    .frame(maxWidth: .infinity, maxHeight: .infinity)

            case .verticalTwoColumn:
                HStack(spacing: 0) {
                    primaryDocumentColumn
                        .frame(maxWidth: .infinity, maxHeight: .infinity)

                    Rectangle()
                        .fill(RackTheme.hairlineStrong)
                        .frame(width: 1)

                    secondaryDocumentColumn
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)

            case .horizontalTwoRow:
                VStack(spacing: 0) {
                    primaryDocumentColumn
                        .frame(maxWidth: .infinity, maxHeight: .infinity)

                    Rectangle()
                        .fill(RackTheme.hairlineStrong)
                        .frame(height: 1)

                    secondaryDocumentColumn
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }

            if viewModel.docking.showBottomDrawer {
                WorkbenchBottomDrawerView(
                    activeChannel: Binding(
                        get: { viewModel.docking.activeBottomChannel },
                        set: { viewModel.docking.activeBottomChannel = $0 }
                    ),
                    serialLines: viewModel.serialPlainLines,
                    diagnostics: viewModel.diagnostics,
                    undoTitles: viewModel.undoSummaries.map(\.title),
                    redoTitles: viewModel.redoSummaries.map(\.title),
                    pluginLogs: viewModel.pluginLogs,
                    onUndo: { viewModel.performUndo() },
                    onRedo: { viewModel.performRedo() },
                    onCloseDrawer: { viewModel.docking.showBottomDrawer = false }
                )
                .frame(height: viewModel.docking.bottomDrawerHeight)
            }
        }
    }

    private var primaryDocumentColumn: some View {
        VStack(spacing: 0) {
            DockingTabStripBar(
                tabs: viewModel.docking.primaryTabs,
                activeTabID: viewModel.docking.activePrimaryTab?.id,
                isSecondaryPane: false,
                splitMode: viewModel.docking.splitMode,
                onSelect: { tabID in
                    viewModel.docking.activePrimaryTabID = tabID
                    viewModel.docking.focusedPaneIndex = 0
                },
                onClose: { tabID in
                    viewModel.docking.closeTab(id: tabID, inSecondaryPane: false)
                },
                onSplitRight: {
                    viewModel.docking.splitCurrentTabRight()
                },
                onCollapseSplit: {
                    viewModel.docking.collapseSplit()
                }
            )

            documentContent(for: viewModel.docking.activePrimaryTab?.kind ?? .snapshotBranchDAG)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private var secondaryDocumentColumn: some View {
        VStack(spacing: 0) {
            DockingTabStripBar(
                tabs: viewModel.docking.secondaryTabs,
                activeTabID: viewModel.docking.activeSecondaryTab?.id,
                isSecondaryPane: true,
                splitMode: viewModel.docking.splitMode,
                onSelect: { tabID in
                    viewModel.docking.activeSecondaryTabID = tabID
                    viewModel.docking.focusedPaneIndex = 1
                },
                onClose: { tabID in
                    viewModel.docking.closeTab(id: tabID, inSecondaryPane: true)
                },
                onSplitRight: {
                    viewModel.docking.splitCurrentTabRight()
                },
                onCollapseSplit: {
                    viewModel.docking.collapseSplit()
                }
            )

            documentContent(for: viewModel.docking.activeSecondaryTab?.kind ?? .pluginExtensionStudio)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    @ViewBuilder
    private func documentContent(for kind: WorkbenchDocumentKind) -> some View {
        switch kind {
        case .snapshotBranchDAG:
            SnapshotLineageDAGCanvasView(viewModel: viewModel)
        case .packetWiretap:
            WiresharkPacketWiretapView(viewModel: viewModel)
        case .vt100SerialConsole:
            VsockVT100ConsoleView(viewModel: viewModel)
        case .firewallPolicyStudio:
            FirewallPolicyStudioView(viewModel: viewModel)
        case .storageAndCloudInit:
            StorageCoWAndCloudInitView(viewModel: viewModel)
        case .pluginExtensionStudio:
            PluginExtensionStudioView(viewModel: viewModel)
        case .fleetRackOverview:
            FleetRackMatrixOverviewPane(viewModel: viewModel)
        case .auditJournalLedger:
            TransactionalAuditLedgerPane(viewModel: viewModel)
        }
    }
}

// MARK: - Fleet Rack Blade Matrix Document Pane (`.fleetRackOverview`)

private struct FleetRackMatrixOverviewPane: View {
    @ObservedObject var viewModel: AgentVMStudioViewModel
    @ObservedObject private var localizer = AgentVMLocalizer.shared

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                RackMetricTile(
                    label: localizer.L("Active Blades", "活跃刀片"),
                    value: "\(viewModel.runningVMCount) / \(viewModel.vms.count)",
                    detail: "Apple Virtualization.framework",
                    accent: RackTheme.linkGreen
                )
                RackMetricTile(
                    label: localizer.L("Virtual Pool", "虚拟存储池"),
                    value: ByteMetricsFormatter.formatBytes(viewModel.totalVirtualPoolBytes),
                    detail: localizer.L("Dirty CoW \(ByteMetricsFormatter.formatBytes(viewModel.totalDirtyCoWBytes))", "CoW 脏块 \(ByteMetricsFormatter.formatBytes(viewModel.totalDirtyCoWBytes))"),
                    accent: RackTheme.amberAccent
                )
                RackMetricTile(
                    label: localizer.L("L2 Wiretap", "二层抓包"),
                    value: localizer.L("\(viewModel.allPackets.count) pkts", "\(viewModel.allPackets.count) 帧"),
                    detail: localizer.L("\(viewModel.droppedPacketCount) blocked frames", "已拦截 \(viewModel.droppedPacketCount) 帧"),
                    accent: RackTheme.vsockBlue
                )
            }

            RackPanelContainer(
                title: localizer.L("Fleet Rack Blade Matrix", "集群机架刀片矩阵"),
                subtitle: localizer.L("Live hypervisor blades, guest NICs, and APFS CoW deltas", "实时虚拟机刀片、客户机网卡与 APFS CoW 增量状态"),
                symbolName: "server.rack",
                headerTrailing: {
                    Button {
                        viewModel.createNewSandboxBlade()
                    } label: {
                        Label(localizer.L("Provision Blade", "新建刀片"), systemImage: "plus")
                    }
                    .buttonStyle(RackActionButtonStyle(prominence: .primaryAmber, compact: true))
                },
                content: {
                    ScrollView {
                        VStack(spacing: 8) {
                            ForEach(viewModel.vms) { vm in
                                HStack(spacing: 12) {
                                    RackStatusPill(
                                        label: vm.telemetry.localizedStateBadge,
                                        color: RackTheme.signalColor(for: vm.telemetry.state),
                                        monospaced: true
                                    )

                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(vm.spec.name)
                                            .font(RackTheme.sectionHeaderFont)
                                            .foregroundStyle(RackTheme.inkPrimary)
                                            .lineLimit(1)
                                        Text("@\(vm.spec.agentOwnerTag) · \(vm.spec.guestOS.localizedDisplayName)")
                                            .font(RackTheme.captionFont)
                                            .foregroundStyle(RackTheme.inkSecondary)
                                            .lineLimit(1)
                                    }

                                    Spacer(minLength: 8)

                                    Text("\(vm.spec.compute.vcpuCount) vCPU · \(vm.spec.compute.memoryMB) MB")
                                        .font(RackTheme.monoSmallFont)
                                        .monospacedDigit()
                                        .foregroundStyle(RackTheme.inkSecondary)
                                        .lineLimit(1)
                                        .fixedSize(horizontal: true, vertical: false)

                                    Text(vm.spec.networkInterfaces.first?.ipv4Address ?? "10.211.55.x")
                                        .font(RackTheme.monoSmallFont)
                                        .foregroundStyle(RackTheme.vsockBlue)
                                        .lineLimit(1)
                                        .fixedSize(horizontal: true, vertical: false)

                                    Text("CoW \(ByteMetricsFormatter.formatBytes(vm.telemetry.cowDirtyBytes))")
                                        .font(RackTheme.monoSmallFont)
                                        .monospacedDigit()
                                        .foregroundStyle(RackTheme.amberAccent)
                                        .lineLimit(1)
                                        .fixedSize(horizontal: true, vertical: false)

                                    Button(localizer.L("Fork CoW", "分叉 CoW")) {
                                        viewModel.forkCoWBranch(from: vm.id)
                                    }
                                    .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))

                                    Button(vm.telemetry.state == .running ? localizer.L("Pause", "暂停") : localizer.L("Boot", "启动")) {
                                        viewModel.toggleRunState(for: vm.id)
                                    }
                                    .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
                                }
                                .padding(10)
                                .background(
                                    RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                                        .fill(RackTheme.bladeRecessed)
                                )
                                .overlay(
                                    RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                                        .strokeBorder(RackTheme.hairline, lineWidth: 1)
                                )
                            }
                        }
                        .padding(12)
                    }
                }
            )
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .padding(12)
        .background(RackTheme.chassisBackground)
    }
}

// MARK: - SQLite Transactional Undo/Redo & Security Audit Ledger Pane (`.auditJournalLedger`)

private struct TransactionalAuditLedgerPane: View {
    @ObservedObject var viewModel: AgentVMStudioViewModel
    @ObservedObject private var localizer = AgentVMLocalizer.shared

    var body: some View {
        HStack(spacing: 12) {
            RackPanelContainer(
                title: localizer.L("SQLite Reversible Undo Journal", "SQLite 可逆撤销事务账本"),
                subtitle: localizer.L("\(viewModel.persistedJournal.count) recorded commands", "已记录 \(viewModel.persistedJournal.count) 条可逆命令"),
                symbolName: "arrow.uturn.backward.circle.fill",
                headerTrailing: {
                    HStack(spacing: 6) {
                        Button(localizer.L("Undo", "撤销")) { viewModel.performUndo() }
                            .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
                            .disabled(!viewModel.canUndo)
                        Button(localizer.L("Redo", "重做")) { viewModel.performRedo() }
                            .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
                            .disabled(!viewModel.canRedo)
                    }
                },
                content: {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 6) {
                            if viewModel.persistedJournal.isEmpty {
                                Text(localizer.L(
                                    "No workspace mutations recorded yet. Fork a CoW branch, capture a snapshot, or toggle a firewall rule to append a reversible journal entry.",
                                    "尚无工作区事务记录。分叉 CoW 分支、捕获快照或切换防火墙规则后将自动追加可逆账本条目。"
                                ))
                                    .font(RackTheme.captionFont)
                                    .foregroundStyle(RackTheme.inkMuted)
                                    .padding(8)
                            } else {
                                ForEach(viewModel.persistedJournal) { entry in
                                    HStack(spacing: 8) {
                                        Text("#\(entry.sequenceID)")
                                            .font(RackTheme.monoSmallFont)
                                            .monospacedDigit()
                                            .foregroundStyle(RackTheme.amberAccent)
                                            .lineLimit(1)
                                            .fixedSize(horizontal: true, vertical: false)

                                        RackStatusPill(
                                            label: entry.state == .applied ? localizer.L("APPLIED", "已应用") : localizer.L("UNDONE", "已撤销"),
                                            color: entry.state == .applied ? RackTheme.linkGreen : RackTheme.checkpointGold,
                                            monospaced: true
                                        )

                                        VStack(alignment: .leading, spacing: 2) {
                                            Text(entry.title)
                                                .font(RackTheme.labelFont)
                                                .foregroundStyle(RackTheme.inkPrimary)
                                                .lineLimit(1)
                                            Text(entry.payloadSummary)
                                                .font(RackTheme.monoSmallFont)
                                                .foregroundStyle(RackTheme.inkMuted)
                                                .lineLimit(1)
                                        }
                                        Spacer()
                                    }
                                    .padding(8)
                                    .background(
                                        RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                                            .fill(RackTheme.bladeRecessed)
                                    )
                                }
                            }
                        }
                        .padding(10)
                    }
                }
            )
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            RackPanelContainer(
                title: localizer.L("Diagnostic & Security Telemetry Feed", "诊断与安全遥测事件流"),
                subtitle: localizer.L("\(viewModel.diagnostics.count) events", "\(viewModel.diagnostics.count) 条事件"),
                symbolName: "exclamationmark.shield.fill",
                content: {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(viewModel.diagnostics) { diag in
                                HStack(alignment: .top, spacing: 8) {
                                    RackStatusPill(
                                        label: diag.severity.localizedBadge,
                                        color: RackTheme.severityColor(for: diag.severity),
                                        monospaced: true
                                    )
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("[\(diag.subsystem)] \(diag.code)")
                                            .font(RackTheme.monoSmallFont)
                                            .foregroundStyle(RackTheme.amberAccent)
                                            .lineLimit(1)
                                        Text(diag.localizedMessage)
                                            .font(RackTheme.captionFont)
                                            .foregroundStyle(RackTheme.inkPrimary)
                                    }
                                    Spacer()
                                }
                                .padding(8)
                                .background(
                                    RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                                        .fill(RackTheme.bladeRecessed)
                                )
                            }
                        }
                        .padding(10)
                    }
                }
            )
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .padding(12)
        .background(RackTheme.chassisBackground)
    }
}

// MARK: - Native macOS Menu Bar Commands (`Virtual Machine`, `Snapshots & CoW`, `Network & DPI`, `Workbench`)

public struct AgentVMCommands: Commands {
    @ObservedObject public var viewModel: AgentVMStudioViewModel
    @ObservedObject private var localizer = AgentVMLocalizer.shared

    public init(viewModel: AgentVMStudioViewModel) {
        self.viewModel = viewModel
    }

    public var body: some Commands {
        CommandGroup(replacing: .undoRedo) {
            Button(localizer.L("Undo Workspace Mutation", "撤销工作区变更")) {
                viewModel.performUndo()
            }
            .keyboardShortcut("z", modifiers: [.command])
            .disabled(!viewModel.canUndo)

            Button(localizer.L("Redo Workspace Mutation", "重做工作区变更")) {
                viewModel.performRedo()
            }
            .keyboardShortcut("z", modifiers: [.command, .shift])
            .disabled(!viewModel.canRedo)
        }

        CommandMenu(localizer.L("Virtual Machine", "虚拟机")) {
            Button(localizer.L("Provision New Sandbox Blade", "新建沙盒刀片")) {
                viewModel.createNewSandboxBlade()
            }
            .keyboardShortcut("n", modifiers: [.command, .shift])

            Divider()

            Button(localizer.L("Boot / Resume Selected VM", "启动或恢复所选虚拟机")) {
                if let id = viewModel.selectedVM?.id {
                    viewModel.bootVM(id)
                }
            }
            .keyboardShortcut("r", modifiers: [.command])
            .disabled(viewModel.selectedVM == nil)

            Button(localizer.L("Pause Selected VM", "暂停所选虚拟机")) {
                if let id = viewModel.selectedVM?.id {
                    viewModel.pauseVM(id)
                }
            }
            .keyboardShortcut("p", modifiers: [.command])
            .disabled(viewModel.selectedVM == nil)

            Button(localizer.L("Halt Selected VM", "停止所选虚拟机")) {
                if let id = viewModel.selectedVM?.id {
                    viewModel.haltVM(id)
                }
            }
            .disabled(viewModel.selectedVM == nil)
        }

        CommandMenu(localizer.L("Snapshots & CoW", "快照与 CoW")) {
            Button(localizer.L("Fork Instant APFS CoW Branch", "即时分叉 APFS CoW 分支")) {
                viewModel.forkCoWBranch()
            }
            .keyboardShortcut("b", modifiers: [.command])

            Button(localizer.L("Capture Live RAM + CoW Checkpoint", "捕获实时内存 + CoW 快照")) {
                viewModel.captureCheckpoint()
            }
            .keyboardShortcut("s", modifiers: [.command, .shift])

            Button(localizer.L("Restore Selected Snapshot", "恢复到所选快照")) {
                if let snapID = viewModel.selectedSnapshot?.id {
                    viewModel.restoreSnapshot(snapID)
                }
            }
            .disabled(viewModel.selectedSnapshot == nil)

            Divider()

            Button(localizer.L("Punch APFS Sparse Zero Holes (F_PUNCHHOLE)", "回收 APFS 零字节稀疏块 (F_PUNCHHOLE)")) {
                viewModel.compactSelectedVMDiskZeroBlocks()
            }

            Button(localizer.L("Rebuild NoCloud 'cidata' ISO-9660", "重构 NoCloud 'cidata' ISO-9660 镜像")) {
                viewModel.rebuildCloudInitISOForSelectedVM()
            }
        }

        CommandMenu(localizer.L("Network & DPI", "网络与 DPI")) {
            Button(localizer.L("Apply Strict Coding-Agent Allowlist", "启用编程智能体严格白名单")) {
                viewModel.applyFirewallPreset(.strictAgentAllowlistPreset())
            }

            Button(localizer.L("Engage Total Air-Gap Mode", "启用全气隙隔离模式")) {
                viewModel.applyFirewallPreset(.airgappedPreset())
            }

            Divider()

            Button(localizer.L("Inject GitHub TLS 1.3 ClientHello Probe", "注入 GitHub TLS 1.3 ClientHello 探测包")) {
                viewModel.injectSyntheticProbePacket(.githubTLS)
            }

            Button(localizer.L("Inject Cloud Metadata SSRF 169.254.169.254 Probe", "注入云元数据 SSRF 169.254.169.254 探测包")) {
                viewModel.injectSyntheticProbePacket(.cloudMetadataSSRF)
            }

            Divider()

            Button(localizer.L("Export Captured Traffic as .pcapng", "导出抓包流量为 .pcapng")) {
                viewModel.exportPCAPNGDefault()
            }
            .keyboardShortcut("e", modifiers: [.command, .shift])

            Button(localizer.L("Export Standalone HTML Security Report", "导出独立 HTML 安全审计报告")) {
                viewModel.exportHTMLSecurityReportDefault()
            }
        }

        CommandMenu(localizer.L("Workbench", "工作台")) {
            Button(localizer.L("Toggle Command Palette", "打开或关闭命令面板")) {
                viewModel.commandPalette.toggleInstant()
            }
            .keyboardShortcut("k", modifiers: [.command])

            Button(localizer.L("切换语言 / Toggle Language (中文 | EN)", "切换语言 / Toggle Language (中文 | EN)")) {
                viewModel.executeCommandPaletteAction("app.language.toggle")
            }
            .keyboardShortcut("l", modifiers: [.command, .shift])

            Divider()

            Button(localizer.L("1 · Snapshot & CoW Lineage DAG", "1 · 快照与 CoW 血缘拓扑")) {
                viewModel.docking.openOrFocus(kind: .snapshotBranchDAG)
            }
            .keyboardShortcut("1", modifiers: [.command])

            Button(localizer.L("2 · L2 Packet Wiretap & Dissector", "2 · 二层抓包与协议解析")) {
                viewModel.docking.openOrFocus(kind: .packetWiretap)
            }
            .keyboardShortcut("2", modifiers: [.command])

            Button(localizer.L("3 · Vsock & VT100 Serial Console", "3 · Vsock 与 VT100 终端")) {
                viewModel.docking.openOrFocus(kind: .vt100SerialConsole)
            }
            .keyboardShortcut("3", modifiers: [.command])

            Button(localizer.L("4 · Firewall Policy Studio", "4 · 防火墙策略工坊")) {
                viewModel.docking.openOrFocus(kind: .firewallPolicyStudio)
            }
            .keyboardShortcut("4", modifiers: [.command])

            Button(localizer.L("5 · APFS CoW Extents & Cloud-Init ISO", "5 · APFS 存储区间与 Cloud-Init")) {
                viewModel.docking.openOrFocus(kind: .storageAndCloudInit)
            }
            .keyboardShortcut("5", modifiers: [.command])

            Button(localizer.L("6 · JavaScriptCore Plugin Host & HCL", "6 · JS 插件沙盒与 HCL")) {
                viewModel.docking.openOrFocus(kind: .pluginExtensionStudio)
            }
            .keyboardShortcut("6", modifiers: [.command])

            Button(localizer.L("7 · Fleet Rack Matrix Overview", "7 · 集群机架矩阵总览")) {
                viewModel.docking.openOrFocus(kind: .fleetRackOverview)
            }
            .keyboardShortcut("7", modifiers: [.command])

            Button(localizer.L("8 · SQLite Undo & Audit Ledger", "8 · SQLite 撤销与审计账本")) {
                viewModel.docking.openOrFocus(kind: .auditJournalLedger)
            }
            .keyboardShortcut("8", modifiers: [.command])

            Divider()

            Button(localizer.L("Toggle Side-by-Side Split View", "切换左右双栏分屏视图")) {
                if viewModel.docking.splitMode == .singlePane {
                    viewModel.docking.splitCurrentTabRight()
                } else {
                    viewModel.docking.collapseSplit()
                }
            }
            .keyboardShortcut("\\", modifiers: [.command])

            Button(localizer.L("Toggle Left Fleet Navigator", "显示或隐藏左侧集群导航栏")) {
                viewModel.docking.showLeftNavigator.toggle()
            }

            Button(localizer.L("Toggle Right Blade Inspector", "显示或隐藏右侧刀片检查器")) {
                viewModel.docking.showRightInspector.toggle()
            }

            Button(localizer.L("Toggle Bottom Telemetry Drawer", "显示或隐藏底部日志抽屉")) {
                viewModel.docking.showBottomDrawer.toggle()
            }
        }
    }
}
