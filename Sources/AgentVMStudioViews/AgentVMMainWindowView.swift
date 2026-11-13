import AgentVMModels
import AgentVMStore
import AgentVMWorkbenchShell
import SwiftUI

// MARK: - Complete Industrial macOS Workbench Window Assembly

public struct AgentVMMainWindowView: View {
    @ObservedObject public var viewModel: AgentVMStudioViewModel

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

                Text(viewModel.manifest.title)
                    .font(RackTheme.labelFont)
                    .foregroundStyle(RackTheme.inkSecondary)
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)

                if let vm = viewModel.selectedVM {
                    RackStatusPill(
                        label: "\(vm.spec.name) · \(vm.telemetry.state.badgeLabel)",
                        color: RackTheme.signalColor(for: vm.telemetry.state),
                        monospaced: true
                    )
                }
            }

            Spacer(minLength: 8)

            // Transactional Undo / Redo Cluster
            HStack(spacing: 4) {
                Button {
                    viewModel.performUndo()
                } label: {
                    Label("Undo", systemImage: "arrow.uturn.backward")
                }
                .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
                .disabled(!viewModel.canUndo)
                .help("Undo last reversible topology or firewall mutation (⌘Z)")

                Button {
                    viewModel.performRedo()
                } label: {
                    Label("Redo", systemImage: "arrow.uturn.forward")
                }
                .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
                .disabled(!viewModel.canRedo)
                .help("Redo reverted workspace mutation (⇧⌘Z)")
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
                .help("Toggle Left Sandbox Fleet Navigator")

                Button {
                    if viewModel.docking.splitMode == .singlePane {
                        viewModel.docking.splitCurrentTabRight()
                    } else {
                        viewModel.docking.collapseSplit()
                    }
                } label: {
                    Label(
                        viewModel.docking.splitMode == .singlePane ? "Split" : "Single",
                        systemImage: viewModel.docking.splitMode == .singlePane ? "rectangle.split.2x1" : "rectangle"
                    )
                }
                .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
                .help("Toggle Side-by-Side Split Workbench (⌘\\)")

                Button {
                    viewModel.docking.showBottomDrawer.toggle()
                } label: {
                    Image(systemName: "rectangle.bottomhalf.inset.filled")
                        .font(.system(size: 11.5, weight: .semibold))
                        .foregroundStyle(viewModel.docking.showBottomDrawer ? RackTheme.amberAccent : RackTheme.inkSecondary)
                }
                .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
                .help("Toggle Bottom Diagnostics & TTY Drawer")

                Button {
                    viewModel.docking.showRightInspector.toggle()
                } label: {
                    Image(systemName: "sidebar.right")
                        .font(.system(size: 11.5, weight: .semibold))
                        .foregroundStyle(viewModel.docking.showRightInspector ? RackTheme.amberAccent : RackTheme.inkSecondary)
                }
                .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
                .help("Toggle Right Blade Hardware Inspector")
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

                Button {
                    viewModel.exportHTMLSecurityReportDefault()
                } label: {
                    Label("HTML Audit", systemImage: "doc.richtext")
                }
                .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
            }

            toolbarDivider

            // Instant Cmd+K Trigger
            Button {
                viewModel.commandPalette.toggleInstant()
            } label: {
                HStack(spacing: 5) {
                    Image(systemName: "command")
                        .font(.system(size: 10.5, weight: .semibold))
                        .foregroundStyle(RackTheme.amberAccent)
                    Text("Palette")
                    RackKeyCapBadge("⌘K")
                }
            }
            .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
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

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                RackMetricTile(
                    label: "Active Blades",
                    value: "\(viewModel.runningVMCount) / \(viewModel.vms.count)",
                    detail: "Apple Virtualization.framework",
                    accent: RackTheme.linkGreen
                )
                RackMetricTile(
                    label: "Virtual Pool",
                    value: ByteMetricsFormatter.formatBytes(viewModel.totalVirtualPoolBytes),
                    detail: "Dirty CoW \(ByteMetricsFormatter.formatBytes(viewModel.totalDirtyCoWBytes))",
                    accent: RackTheme.amberAccent
                )
                RackMetricTile(
                    label: "L2 Wiretap",
                    value: "\(viewModel.allPackets.count) pkts",
                    detail: "\(viewModel.droppedPacketCount) blocked frames",
                    accent: RackTheme.vsockBlue
                )
            }

            RackPanelContainer(
                title: "Fleet Rack Blade Matrix",
                subtitle: "Live hypervisor blades, guest NICs, and APFS CoW deltas",
                symbolName: "server.rack",
                headerTrailing: {
                    Button {
                        viewModel.createNewSandboxBlade()
                    } label: {
                        Label("Provision Blade", systemImage: "plus")
                    }
                    .buttonStyle(RackActionButtonStyle(prominence: .primaryAmber, compact: true))
                },
                content: {
                    ScrollView {
                        VStack(spacing: 8) {
                            ForEach(viewModel.vms) { vm in
                                HStack(spacing: 12) {
                                    RackStatusPill(
                                        label: vm.telemetry.state.badgeLabel,
                                        color: RackTheme.signalColor(for: vm.telemetry.state),
                                        monospaced: true
                                    )

                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(vm.spec.name)
                                            .font(RackTheme.sectionHeaderFont)
                                            .foregroundStyle(RackTheme.inkPrimary)
                                            .lineLimit(1)
                                        Text("@\(vm.spec.agentOwnerTag) · \(vm.spec.guestOS.displayName)")
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

                                    Button("Fork CoW") {
                                        viewModel.forkCoWBranch(from: vm.id)
                                    }
                                    .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))

                                    Button(vm.telemetry.state == .running ? "Pause" : "Boot") {
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

    var body: some View {
        HStack(spacing: 12) {
            RackPanelContainer(
                title: "SQLite Reversible Undo Journal",
                subtitle: "\(viewModel.persistedJournal.count) recorded commands",
                symbolName: "arrow.uturn.backward.circle.fill",
                headerTrailing: {
                    HStack(spacing: 6) {
                        Button("Undo") { viewModel.performUndo() }
                            .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
                            .disabled(!viewModel.canUndo)
                        Button("Redo") { viewModel.performRedo() }
                            .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
                            .disabled(!viewModel.canRedo)
                    }
                },
                content: {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 6) {
                            if viewModel.persistedJournal.isEmpty {
                                Text("No workspace mutations recorded yet. Fork a CoW branch, capture a snapshot, or toggle a firewall rule to append a reversible journal entry.")
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
                                            label: entry.state.rawValue.uppercased(),
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
                title: "Diagnostic & Security Telemetry Feed",
                subtitle: "\(viewModel.diagnostics.count) events",
                symbolName: "exclamationmark.shield.fill",
                content: {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(viewModel.diagnostics) { diag in
                                HStack(alignment: .top, spacing: 8) {
                                    RackStatusPill(
                                        label: diag.severity.rawValue.uppercased(),
                                        color: RackTheme.severityColor(for: diag.severity),
                                        monospaced: true
                                    )
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("[\(diag.subsystem)] \(diag.code)")
                                            .font(RackTheme.monoSmallFont)
                                            .foregroundStyle(RackTheme.amberAccent)
                                            .lineLimit(1)
                                        Text(diag.message)
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

    public init(viewModel: AgentVMStudioViewModel) {
        self.viewModel = viewModel
    }

    public var body: some Commands {
        CommandGroup(replacing: .undoRedo) {
            Button("Undo Workspace Mutation") {
                viewModel.performUndo()
            }
            .keyboardShortcut("z", modifiers: [.command])
            .disabled(!viewModel.canUndo)

            Button("Redo Workspace Mutation") {
                viewModel.performRedo()
            }
            .keyboardShortcut("z", modifiers: [.command, .shift])
            .disabled(!viewModel.canRedo)
        }

        CommandMenu("Virtual Machine") {
            Button("Provision New Sandbox Blade") {
                viewModel.createNewSandboxBlade()
            }
            .keyboardShortcut("n", modifiers: [.command, .shift])

            Divider()

            Button("Boot / Resume Selected VM") {
                if let id = viewModel.selectedVM?.id {
                    viewModel.bootVM(id)
                }
            }
            .keyboardShortcut("r", modifiers: [.command])
            .disabled(viewModel.selectedVM == nil)

            Button("Pause Selected VM") {
                if let id = viewModel.selectedVM?.id {
                    viewModel.pauseVM(id)
                }
            }
            .keyboardShortcut("p", modifiers: [.command])
            .disabled(viewModel.selectedVM == nil)

            Button("Halt Selected VM") {
                if let id = viewModel.selectedVM?.id {
                    viewModel.haltVM(id)
                }
            }
            .disabled(viewModel.selectedVM == nil)
        }

        CommandMenu("Snapshots & CoW") {
            Button("Fork Instant APFS CoW Branch") {
                viewModel.forkCoWBranch()
            }
            .keyboardShortcut("b", modifiers: [.command])

            Button("Capture Live RAM + CoW Checkpoint") {
                viewModel.captureCheckpoint()
            }
            .keyboardShortcut("s", modifiers: [.command, .shift])

            Button("Restore Selected Snapshot") {
                if let snapID = viewModel.selectedSnapshot?.id {
                    viewModel.restoreSnapshot(snapID)
                }
            }
            .disabled(viewModel.selectedSnapshot == nil)

            Divider()

            Button("Punch APFS Sparse Zero Holes (F_PUNCHHOLE)") {
                viewModel.compactSelectedVMDiskZeroBlocks()
            }

            Button("Rebuild NoCloud 'cidata' ISO-9660") {
                viewModel.rebuildCloudInitISOForSelectedVM()
            }
        }

        CommandMenu("Network & DPI") {
            Button("Apply Strict Coding-Agent Allowlist") {
                viewModel.applyFirewallPreset(.strictAgentAllowlistPreset())
            }

            Button("Engage Total Air-Gap Mode") {
                viewModel.applyFirewallPreset(.airgappedPreset())
            }

            Divider()

            Button("Inject GitHub TLS 1.3 ClientHello Probe") {
                viewModel.injectSyntheticProbePacket(.githubTLS)
            }

            Button("Inject Cloud Metadata SSRF 169.254.169.254 Probe") {
                viewModel.injectSyntheticProbePacket(.cloudMetadataSSRF)
            }

            Divider()

            Button("Export Captured Traffic as .pcapng") {
                viewModel.exportPCAPNGDefault()
            }
            .keyboardShortcut("e", modifiers: [.command, .shift])

            Button("Export Standalone HTML Security Report") {
                viewModel.exportHTMLSecurityReportDefault()
            }
        }

        CommandMenu("Workbench") {
            Button("Toggle Command Palette") {
                viewModel.commandPalette.toggleInstant()
            }
            .keyboardShortcut("k", modifiers: [.command])

            Divider()

            Button("1 · Snapshot & CoW Lineage DAG") {
                viewModel.docking.openOrFocus(kind: .snapshotBranchDAG)
            }
            .keyboardShortcut("1", modifiers: [.command])

            Button("2 · L2 Packet Wiretap & Dissector") {
                viewModel.docking.openOrFocus(kind: .packetWiretap)
            }
            .keyboardShortcut("2", modifiers: [.command])

            Button("3 · Vsock & VT100 Serial Console") {
                viewModel.docking.openOrFocus(kind: .vt100SerialConsole)
            }
            .keyboardShortcut("3", modifiers: [.command])

            Button("4 · Firewall Policy Studio") {
                viewModel.docking.openOrFocus(kind: .firewallPolicyStudio)
            }
            .keyboardShortcut("4", modifiers: [.command])

            Button("5 · APFS CoW Extents & Cloud-Init ISO") {
                viewModel.docking.openOrFocus(kind: .storageAndCloudInit)
            }
            .keyboardShortcut("5", modifiers: [.command])

            Button("6 · JavaScriptCore Plugin Host & HCL") {
                viewModel.docking.openOrFocus(kind: .pluginExtensionStudio)
            }
            .keyboardShortcut("6", modifiers: [.command])

            Button("7 · Fleet Rack Matrix Overview") {
                viewModel.docking.openOrFocus(kind: .fleetRackOverview)
            }
            .keyboardShortcut("7", modifiers: [.command])

            Button("8 · SQLite Undo & Audit Ledger") {
                viewModel.docking.openOrFocus(kind: .auditJournalLedger)
            }
            .keyboardShortcut("8", modifiers: [.command])

            Divider()

            Button("Toggle Side-by-Side Split View") {
                if viewModel.docking.splitMode == .singlePane {
                    viewModel.docking.splitCurrentTabRight()
                } else {
                    viewModel.docking.collapseSplit()
                }
            }
            .keyboardShortcut("\\", modifiers: [.command])

            Button("Toggle Left Fleet Navigator") {
                viewModel.docking.showLeftNavigator.toggle()
            }

            Button("Toggle Right Blade Inspector") {
                viewModel.docking.showRightInspector.toggle()
            }

            Button("Toggle Bottom Telemetry Drawer") {
                viewModel.docking.showBottomDrawer.toggle()
            }
        }
    }
}
