import Foundation

// MARK: - Sandboxed Extension / Plugin Contracts

public enum PluginCapability: String, Codable, Hashable, Sendable, CaseIterable {
    case networkInspect = "network.inspect"
    case networkVerdictOverride = "network.verdict"
    case vmLifecycleControl = "vm.lifecycle"
    case snapshotCheckpoint = "snapshot.checkpoint"
    case commandExecInterception = "exec.intercept"
    case topologyImportExport = "topology.io"
    case workbenchCommand = "workbench.command"
    case pluginKVStore = "storage.kv"

    public var riskLevel: DiagnosticSeverity {
        switch self {
        case .networkVerdictOverride, .vmLifecycleControl, .commandExecInterception:
            return .warning
        case .snapshotCheckpoint, .topologyImportExport:
            return .notice
        case .networkInspect, .workbenchCommand, .pluginKVStore:
            return .info
        }
    }

    public var humanDescription: String {
        switch self {
        case .networkInspect: return "Read dissected Ethernet/IPv4/TLS metadata"
        case .networkVerdictOverride: return "Drop or sinkhole live network packets"
        case .vmLifecycleControl: return "Pause, resume, or halt virtual machines"
        case .snapshotCheckpoint: return "Create CoW branches and RAM snapshots"
        case .commandExecInterception: return "Inspect or veto guest exec invocations"
        case .topologyImportExport: return "Import/export multi-VM topology manifests"
        case .workbenchCommand: return "Register actions in Cmd+K Command Palette"
        case .pluginKVStore: return "Persist plugin key-value state in SQLite"
        }
    }
}

public struct PluginConfigField: Codable, Hashable, Sendable, Identifiable {
    public var id: String { key }
    public var key: String
    public var label: String
    public var valueType: String
    public var defaultValue: String
    public var helpText: String

    public init(key: String, label: String, valueType: String = "string", defaultValue: String, helpText: String) {
        self.key = key
        self.label = label
        self.valueType = valueType
        self.defaultValue = defaultValue
        self.helpText = helpText
    }
}

public struct PluginManifest: Codable, Hashable, Sendable, Identifiable {
    public var id: PluginID
    public var name: String
    public var version: SemanticVersion
    public var author: String
    public var summary: String
    public var isBuiltIn: Bool
    public var requestedCapabilities: [PluginCapability]
    public var timeoutMilliseconds: Int
    public var configFields: [PluginConfigField]
    public var entryPointSource: String

    public init(
        id: PluginID,
        name: String,
        version: SemanticVersion = .current,
        author: String,
        summary: String,
        isBuiltIn: Bool = false,
        requestedCapabilities: [PluginCapability],
        timeoutMilliseconds: Int = 250,
        configFields: [PluginConfigField] = [],
        entryPointSource: String
    ) {
        self.id = id
        self.name = name
        self.version = version
        self.author = author
        self.summary = summary
        self.isBuiltIn = isBuiltIn
        self.requestedCapabilities = requestedCapabilities
        self.timeoutMilliseconds = timeoutMilliseconds
        self.configFields = configFields
        self.entryPointSource = entryPointSource
    }
}

public struct PluginRuntimeStatus: Codable, Hashable, Sendable, Identifiable {
    public var id: PluginID { manifest.id }
    public var manifest: PluginManifest
    public var isEnabled: Bool
    public var grantedCapabilities: Set<PluginCapability>
    public var invocationCount: UInt64
    public var blockedActionsCount: UInt64
    public var averageDurationMicros: UInt64
    public var lastError: String?
    public var lastInvokedAt: Date?
    public var configurationValues: [String: String]

    public init(
        manifest: PluginManifest,
        isEnabled: Bool = true,
        grantedCapabilities: Set<PluginCapability>? = nil,
        invocationCount: UInt64 = 0,
        blockedActionsCount: UInt64 = 0,
        averageDurationMicros: UInt64 = 0,
        lastError: String? = nil,
        lastInvokedAt: Date? = nil,
        configurationValues: [String: String] = [:]
    ) {
        self.manifest = manifest
        self.isEnabled = isEnabled
        self.grantedCapabilities = grantedCapabilities ?? Set(manifest.requestedCapabilities)
        self.invocationCount = invocationCount
        self.blockedActionsCount = blockedActionsCount
        self.averageDurationMicros = averageDurationMicros
        self.lastError = lastError
        self.lastInvokedAt = lastInvokedAt
        self.configurationValues = configurationValues
    }
}

public struct PluginHookConsoleEntry: Codable, Hashable, Sendable, Identifiable {
    public var id: UUID
    public var pluginID: PluginID
    public var timestamp: Date
    public var level: DiagnosticSeverity
    public var hookName: String
    public var message: String
    public var durationMicros: UInt64

    public init(
        id: UUID = UUID(),
        pluginID: PluginID,
        timestamp: Date = Date(),
        level: DiagnosticSeverity = .info,
        hookName: String,
        message: String,
        durationMicros: UInt64 = 0
    ) {
        self.id = id
        self.pluginID = pluginID
        self.timestamp = timestamp
        self.level = level
        self.hookName = hookName
        self.message = message
        self.durationMicros = durationMicros
    }
}

// MARK: - Industrial Desktop Workbench Shell Contracts

public enum WorkbenchDocumentKind: String, Codable, Hashable, Sendable, CaseIterable {
    case fleetRackOverview = "fleet-overview"
    case snapshotBranchDAG = "snapshot-dag"
    case packetWiretap = "packet-wiretap"
    case vt100SerialConsole = "serial-console"
    case firewallPolicyStudio = "firewall-policy"
    case storageAndCloudInit = "storage-cloudinit"
    case pluginExtensionStudio = "plugin-studio"
    case auditJournalLedger = "audit-journal"

    public var defaultTitle: String {
        switch self {
        case .fleetRackOverview: return "Fleet Rack Matrix"
        case .snapshotBranchDAG: return "Snapshot & CoW DAG"
        case .packetWiretap: return "L2 Packet Wiretap"
        case .vt100SerialConsole: return "Vsock / PTY Console"
        case .firewallPolicyStudio: return "Firewall Policy Studio"
        case .storageAndCloudInit: return "CoW Extents & Cloud-Init"
        case .pluginExtensionStudio: return "JS Plugin Host"
        case .auditJournalLedger: return "Audit & Undo Ledger"
        }
    }

    public var sfSymbolName: String {
        switch self {
        case .fleetRackOverview: return "server.rack"
        case .snapshotBranchDAG: return "point.3.connected.trianglepath.dotted"
        case .packetWiretap: return "waveform.path.ecg.rectangle"
        case .vt100SerialConsole: return "terminal"
        case .firewallPolicyStudio: return "shield.lefthalf.filled"
        case .storageAndCloudInit: return "externaldrive.connected.to.line.below"
        case .pluginExtensionStudio: return "puzzlepiece.extension"
        case .auditJournalLedger: return "list.bullet.clipboard"
        }
    }
}

public struct WorkbenchTabDescriptor: Codable, Hashable, Sendable, Identifiable {
    public var id: UUID
    public var kind: WorkbenchDocumentKind
    public var title: String
    public var associatedVMID: VMID?
    public var isPinned: Bool
    public var hasUnsavedChanges: Bool

    public init(
        id: UUID = UUID(),
        kind: WorkbenchDocumentKind,
        title: String? = nil,
        associatedVMID: VMID? = nil,
        isPinned: Bool = false,
        hasUnsavedChanges: Bool = false
    ) {
        self.id = id
        self.kind = kind
        self.title = title ?? kind.defaultTitle
        self.associatedVMID = associatedVMID
        self.isPinned = isPinned
        self.hasUnsavedChanges = hasUnsavedChanges
    }
}

public enum BottomDrawerChannel: String, Codable, Hashable, Sendable, CaseIterable {
    case serialTTY = "Serial & Vsock Stream"
    case firewallAlerts = "Firewall Alerts"
    case undoHistory = "Undo / Redo Stack"
    case pluginLogs = "Plugin Host Logs"
}

public enum WorkbenchSplitMode: String, Codable, Hashable, Sendable, CaseIterable {
    case singlePane = "single"
    case verticalTwoColumn = "split-vertical"
    case horizontalTwoRow = "split-horizontal"
}

public struct WorkbenchLayoutSnapshot: Codable, Hashable, Sendable {
    public var workspaceID: WorkspaceID
    public var showLeftFleetNavigator: Bool
    public var showRightInspector: Bool
    public var showBottomDrawer: Bool
    public var activeBottomChannel: BottomDrawerChannel
    public var splitMode: WorkbenchSplitMode
    public var primaryTabs: [WorkbenchTabDescriptor]
    public var activePrimaryTabID: UUID?
    public var secondaryTabs: [WorkbenchTabDescriptor]
    public var activeSecondaryTabID: UUID?
    public var selectedVMID: VMID?
    public var selectedSnapshotID: SnapshotID?
    public var selectedPacketID: PacketID?

    public init(
        workspaceID: WorkspaceID = .generate(prefix: "ws"),
        showLeftFleetNavigator: Bool = true,
        showRightInspector: Bool = true,
        showBottomDrawer: Bool = true,
        activeBottomChannel: BottomDrawerChannel = .firewallAlerts,
        splitMode: WorkbenchSplitMode = .singlePane,
        primaryTabs: [WorkbenchTabDescriptor] = [],
        activePrimaryTabID: UUID? = nil,
        secondaryTabs: [WorkbenchTabDescriptor] = [],
        activeSecondaryTabID: UUID? = nil,
        selectedVMID: VMID? = nil,
        selectedSnapshotID: SnapshotID? = nil,
        selectedPacketID: PacketID? = nil
    ) {
        self.workspaceID = workspaceID
        self.showLeftFleetNavigator = showLeftFleetNavigator
        self.showRightInspector = showRightInspector
        self.showBottomDrawer = showBottomDrawer
        self.activeBottomChannel = activeBottomChannel
        self.splitMode = splitMode
        self.primaryTabs = primaryTabs
        self.activePrimaryTabID = activePrimaryTabID
        self.secondaryTabs = secondaryTabs
        self.activeSecondaryTabID = activeSecondaryTabID
        self.selectedVMID = selectedVMID
        self.selectedSnapshotID = selectedSnapshotID
        self.selectedPacketID = selectedPacketID
    }
}

public enum CommandCategory: String, Codable, Hashable, Sendable, CaseIterable {
    case vmLifecycle = "VM Lifecycle"
    case cowBranching = "Snapshots & CoW"
    case networkFirewall = "Switch & Firewall"
    case workspaceView = "Workbench Layout"
    case pluginsAndAutomation = "Plugins & Export"
}

public struct CommandPaletteActionItem: Codable, Hashable, Sendable, Identifiable {
    public var id: String
    public var title: String
    public var subtitle: String
    public var category: CommandCategory
    public var keyEquivalentDisplay: String?
    public var sfSymbol: String
    public var searchTokens: [String]

    public init(
        id: String,
        title: String,
        subtitle: String,
        category: CommandCategory,
        keyEquivalentDisplay: String? = nil,
        sfSymbol: String,
        searchTokens: [String] = []
    ) {
        self.id = id
        self.title = title
        self.subtitle = subtitle
        self.category = category
        self.keyEquivalentDisplay = keyEquivalentDisplay
        self.sfSymbol = sfSymbol
        self.searchTokens = searchTokens
    }
}

public struct WorkspacePreferences: Codable, Hashable, Sendable {
    public var defaultVCPUs: Int
    public var defaultMemoryMB: UInt64
    public var maxConcurrentRunningVMs: Int
    public var maxTotalFleetRAMPercent: Int
    public var autoPauseIdleMinutes: Int
    public var storagePoolRelativeDir: String
    public var maxCoWDirtyQuotaGB: Int
    public var switchSubnetCIDR: String
    public var switchGatewayIP: String
    public var upstreamDNSServer: String
    public var autoCapturePCAPNG: Bool
    public var maxPCAPRingBufferPackets: Int
    public var enableSecretLeakPluginByDefault: Bool
    public var enablePreExecAutoSnapshot: Bool
    public var terminalFontSize: Double
    public var customKeybindings: [String: String]

    public init(
        defaultVCPUs: Int = 2,
        defaultMemoryMB: UInt64 = 2048,
        maxConcurrentRunningVMs: Int = 8,
        maxTotalFleetRAMPercent: Int = 75,
        autoPauseIdleMinutes: Int = 30,
        storagePoolRelativeDir: String = "StoragePool",
        maxCoWDirtyQuotaGB: Int = 64,
        switchSubnetCIDR: String = "10.211.55.0/24",
        switchGatewayIP: String = "10.211.55.1",
        upstreamDNSServer: String = "1.1.1.1",
        autoCapturePCAPNG: Bool = true,
        maxPCAPRingBufferPackets: Int = 50_000,
        enableSecretLeakPluginByDefault: Bool = true,
        enablePreExecAutoSnapshot: Bool = true,
        terminalFontSize: Double = 12.5,
        customKeybindings: [String: String] = [:]
    ) {
        self.defaultVCPUs = defaultVCPUs
        self.defaultMemoryMB = defaultMemoryMB
        self.maxConcurrentRunningVMs = maxConcurrentRunningVMs
        self.maxTotalFleetRAMPercent = maxTotalFleetRAMPercent
        self.autoPauseIdleMinutes = autoPauseIdleMinutes
        self.storagePoolRelativeDir = storagePoolRelativeDir
        self.maxCoWDirtyQuotaGB = maxCoWDirtyQuotaGB
        self.switchSubnetCIDR = switchSubnetCIDR
        self.switchGatewayIP = switchGatewayIP
        self.upstreamDNSServer = upstreamDNSServer
        self.autoCapturePCAPNG = autoCapturePCAPNG
        self.maxPCAPRingBufferPackets = maxPCAPRingBufferPackets
        self.enableSecretLeakPluginByDefault = enableSecretLeakPluginByDefault
        self.enablePreExecAutoSnapshot = enablePreExecAutoSnapshot
        self.terminalFontSize = terminalFontSize
        self.customKeybindings = customKeybindings
    }
}

public struct AgentVMProjectManifest: Codable, Hashable, Sendable {
    public var formatVersion: Int
    public var workspaceID: WorkspaceID
    public var title: String
    public var createdByVersion: SemanticVersion
    public var createdAt: Date
    public var updatedAt: Date
    public var preferences: WorkspacePreferences

    public init(
        formatVersion: Int = 4,
        workspaceID: WorkspaceID = .generate(prefix: "ws"),
        title: String = "AgentVM Sandbox Fleet",
        createdByVersion: SemanticVersion = .current,
        createdAt: Date = Date(),
        updatedAt: Date = Date(),
        preferences: WorkspacePreferences = WorkspacePreferences()
    ) {
        self.formatVersion = formatVersion
        self.workspaceID = workspaceID
        self.title = title
        self.createdByVersion = createdByVersion
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.preferences = preferences
    }
}
