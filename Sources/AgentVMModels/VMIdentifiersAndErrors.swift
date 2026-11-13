import Foundation

// MARK: - Strongly-Typed Identifiers

public struct TypedIdentifier<Tag>: RawRepresentable, Codable, Hashable, Sendable, CustomStringConvertible, Comparable {
    public let rawValue: String

    public init(rawValue: String) {
        let trimmed = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        self.rawValue = trimmed.isEmpty ? UUID().uuidString.lowercased() : trimmed
    }

    public init(_ value: String) {
        self.init(rawValue: value)
    }

    public static func generate(prefix: String) -> Self {
        let short = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased().prefix(12)
        return Self(rawValue: "\(prefix)-\(short)")
    }

    public var description: String { rawValue }

    public static func < (lhs: Self, rhs: Self) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

public enum VMIDTag: Sendable {}
public enum SnapshotIDTag: Sendable {}
public enum BranchIDTag: Sendable {}
public enum PacketIDTag: Sendable {}
public enum FlowIDTag: Sendable {}
public enum RuleIDTag: Sendable {}
public enum PolicySetIDTag: Sendable {}
public enum PluginIDTag: Sendable {}
public enum WorkspaceIDTag: Sendable {}
public enum BlockDeviceIDTag: Sendable {}
public enum VirtioFSMountIDTag: Sendable {}
public enum NICIDTag: Sendable {}
public enum PortForwardIDTag: Sendable {}

public typealias VMID = TypedIdentifier<VMIDTag>
public typealias SnapshotID = TypedIdentifier<SnapshotIDTag>
public typealias BranchID = TypedIdentifier<BranchIDTag>
public typealias PacketID = TypedIdentifier<PacketIDTag>
public typealias FlowID = TypedIdentifier<FlowIDTag>
public typealias RuleID = TypedIdentifier<RuleIDTag>
public typealias PolicySetID = TypedIdentifier<PolicySetIDTag>
public typealias PluginID = TypedIdentifier<PluginIDTag>
public typealias WorkspaceID = TypedIdentifier<WorkspaceIDTag>
public typealias BlockDeviceID = TypedIdentifier<BlockDeviceIDTag>
public typealias VirtioFSMountID = TypedIdentifier<VirtioFSMountIDTag>
public typealias NICID = TypedIdentifier<NICIDTag>
public typealias PortForwardID = TypedIdentifier<PortForwardIDTag>

// MARK: - Semantic Versioning & Host Capabilities

public struct SemanticVersion: Codable, Hashable, Sendable, Comparable, CustomStringConvertible {
    public let major: Int
    public let minor: Int
    public let patch: Int
    public let prerelease: String?

    public init(major: Int, minor: Int, patch: Int, prerelease: String? = nil) {
        self.major = max(0, major)
        self.minor = max(0, minor)
        self.patch = max(0, patch)
        self.prerelease = prerelease
    }

    public static let current = SemanticVersion(major: 1, minor: 1, patch: 0)

    public init?(parsing text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "^v", with: "", options: .regularExpression)
        let dashParts = trimmed.split(separator: "-", maxSplits: 1, omittingEmptySubsequences: false)
        let coreParts = dashParts[0].split(separator: ".")
        guard coreParts.count == 3,
              let maj = Int(coreParts[0]),
              let min = Int(coreParts[1]),
              let pat = Int(coreParts[2]) else {
            return nil
        }
        let pre = dashParts.count > 1 && !dashParts[1].isEmpty ? String(dashParts[1]) : nil
        self.init(major: maj, minor: min, patch: pat, prerelease: pre)
    }

    public var description: String {
        if let prerelease, !prerelease.isEmpty {
            return "\(major).\(minor).\(patch)-\(prerelease)"
        }
        return "\(major).\(minor).\(patch)"
    }

    public static func < (lhs: SemanticVersion, rhs: SemanticVersion) -> Bool {
        if lhs.major != rhs.major { return lhs.major < rhs.major }
        if lhs.minor != rhs.minor { return lhs.minor < rhs.minor }
        if lhs.patch != rhs.patch { return lhs.patch < rhs.patch }
        switch (lhs.prerelease, rhs.prerelease) {
        case (nil, nil): return false
        case (.some, nil): return true
        case (nil, .some): return false
        case let (.some(a), .some(b)): return a < b
        }
    }
}

public struct HostCapabilityReport: Codable, Hashable, Sendable {
    public var architecture: String
    public var macOSVersion: String
    public var physicalCores: Int
    public var logicalCores: Int
    public var hostMemoryBytes: UInt64
    public var isVirtualizationFrameworkSupported: Bool
    public var isNestedVirtualizationSupported: Bool
    public var isRosettaLinuxShareAvailable: Bool
    public var isAPFSClonefileSupported: Bool
    public var maxSupportedVCPUs: Int
    public var maxSupportedMemoryMB: UInt64
    public var probedAt: Date

    public init(
        architecture: String = "arm64",
        macOSVersion: String,
        physicalCores: Int,
        logicalCores: Int,
        hostMemoryBytes: UInt64,
        isVirtualizationFrameworkSupported: Bool,
        isNestedVirtualizationSupported: Bool = false,
        isRosettaLinuxShareAvailable: Bool = false,
        isAPFSClonefileSupported: Bool = true,
        maxSupportedVCPUs: Int,
        maxSupportedMemoryMB: UInt64,
        probedAt: Date = Date()
    ) {
        self.architecture = architecture
        self.macOSVersion = macOSVersion
        self.physicalCores = physicalCores
        self.logicalCores = logicalCores
        self.hostMemoryBytes = hostMemoryBytes
        self.isVirtualizationFrameworkSupported = isVirtualizationFrameworkSupported
        self.isNestedVirtualizationSupported = isNestedVirtualizationSupported
        self.isRosettaLinuxShareAvailable = isRosettaLinuxShareAvailable
        self.isAPFSClonefileSupported = isAPFSClonefileSupported
        self.maxSupportedVCPUs = maxSupportedVCPUs
        self.maxSupportedMemoryMB = maxSupportedMemoryMB
        self.probedAt = probedAt
    }

    public var hostMemoryGBFormatted: String {
        let gb = Double(hostMemoryBytes) / (1024.0 * 1024.0 * 1024.0)
        return String(format: "%.1f GB", gb)
    }
}

// MARK: - Diagnostics & Structured Error Catalog

public enum DiagnosticSeverity: String, Codable, Hashable, Sendable, CaseIterable, Comparable {
    case trace
    case info
    case notice
    case warning
    case error
    case critical

    private var rank: Int {
        switch self {
        case .trace: return 0
        case .info: return 1
        case .notice: return 2
        case .warning: return 3
        case .error: return 4
        case .critical: return 5
        }
    }

    public static func < (lhs: DiagnosticSeverity, rhs: DiagnosticSeverity) -> Bool {
        lhs.rank < rhs.rank
    }
}

public struct DiagnosticEvent: Codable, Hashable, Sendable, Identifiable {
    public var id: UUID
    public var timestamp: Date
    public var severity: DiagnosticSeverity
    public var subsystem: String
    public var vmID: VMID?
    public var code: String
    public var message: String
    public var metadata: [String: String]

    public init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        severity: DiagnosticSeverity,
        subsystem: String,
        vmID: VMID? = nil,
        code: String,
        message: String,
        metadata: [String: String] = [:]
    ) {
        self.id = id
        self.timestamp = timestamp
        self.severity = severity
        self.subsystem = subsystem
        self.vmID = vmID
        self.code = code
        self.message = message
        self.metadata = metadata
    }
}

public struct ValidationIssue: Codable, Hashable, Sendable, Identifiable {
    public var id: String { "\(fieldPath):\(code)" }
    public var fieldPath: String
    public var code: String
    public var severity: DiagnosticSeverity
    public var message: String
    public var remediation: String

    public init(
        fieldPath: String,
        code: String,
        severity: DiagnosticSeverity = .error,
        message: String,
        remediation: String
    ) {
        self.fieldPath = fieldPath
        self.code = code
        self.severity = severity
        self.message = message
        self.remediation = remediation
    }
}

public enum AgentVMError: Error, LocalizedError, Sendable, Equatable {
    case virtualizationUnsupported(reason: String)
    case invalidConfiguration(issues: [ValidationIssue])
    case vmNotFound(VMID)
    case snapshotNotFound(SnapshotID)
    case invalidLifecycleTransition(vmID: VMID, from: String, requested: String)
    case diskImageOperationFailed(path: String, errnoCode: Int32, detail: String)
    case cowCloneFailed(source: String, destination: String, errnoCode: Int32)
    case iso9660BuildFailed(detail: String)
    case partitionTableInvalid(detail: String)
    case networkFrameMalformed(layer: String, detail: String)
    case pcapCorrupted(detail: String)
    case firewallBlocked(ruleID: RuleID?, reason: String)
    case vsockProtocolViolation(detail: String)
    case vsockCRCMismatch(expected: UInt32, actual: UInt32)
    case portForwardBindFailed(port: UInt16, errnoCode: Int32)
    case snapshotCycleDetected(SnapshotID)
    case storageDatabaseError(code: Int32, sql: String, detail: String)
    case storageMigrationFailed(fromVersion: Int, toVersion: Int, detail: String)
    case bundleIntegrityError(path: String, detail: String)
    case undoStackEmpty
    case redoStackEmpty
    case pluginPermissionDenied(pluginID: PluginID, capability: String)
    case pluginExecutionFailed(pluginID: PluginID, detail: String)
    case pluginTimedOut(pluginID: PluginID, limitMs: Int)
    case cliUsageError(detail: String)
    case ipcDaemonUnavailable(socketPath: String, detail: String)
    case resourceQuotaExceeded(resource: String, requested: String, limit: String)

    public var errorCode: String {
        switch self {
        case .virtualizationUnsupported: return "ERR_VZ_UNSUPPORTED"
        case .invalidConfiguration: return "ERR_INVALID_CONFIG"
        case .vmNotFound: return "ERR_VM_NOT_FOUND"
        case .snapshotNotFound: return "ERR_SNAPSHOT_NOT_FOUND"
        case .invalidLifecycleTransition: return "ERR_LIFECYCLE_STATE"
        case .diskImageOperationFailed: return "ERR_DISK_IO"
        case .cowCloneFailed: return "ERR_APFS_COW_CLONE"
        case .iso9660BuildFailed: return "ERR_ISO9660_BUILD"
        case .partitionTableInvalid: return "ERR_GPT_INVALID"
        case .networkFrameMalformed: return "ERR_NET_FRAME_MALFORMED"
        case .pcapCorrupted: return "ERR_PCAPNG_CORRUPT"
        case .firewallBlocked: return "ERR_FIREWALL_BLOCKED"
        case .vsockProtocolViolation: return "ERR_VSOCK_PROTOCOL"
        case .vsockCRCMismatch: return "ERR_VSOCK_CRC"
        case .portForwardBindFailed: return "ERR_PORT_FORWARD_BIND"
        case .snapshotCycleDetected: return "ERR_SNAPSHOT_CYCLE"
        case .storageDatabaseError: return "ERR_SQLITE_EXEC"
        case .storageMigrationFailed: return "ERR_SQLITE_MIGRATION"
        case .bundleIntegrityError: return "ERR_BUNDLE_INTEGRITY"
        case .undoStackEmpty: return "ERR_UNDO_EMPTY"
        case .redoStackEmpty: return "ERR_REDO_EMPTY"
        case .pluginPermissionDenied: return "ERR_PLUGIN_PERMISSION"
        case .pluginExecutionFailed: return "ERR_PLUGIN_RUNTIME"
        case .pluginTimedOut: return "ERR_PLUGIN_TIMEOUT"
        case .cliUsageError: return "ERR_CLI_USAGE"
        case .ipcDaemonUnavailable: return "ERR_DAEMON_IPC"
        case .resourceQuotaExceeded: return "ERR_QUOTA_EXCEEDED"
        }
    }

    public var errorDescription: String? {
        switch self {
        case let .virtualizationUnsupported(reason):
            return "Apple Virtualization.framework unavailable: \(reason)"
        case let .invalidConfiguration(issues):
            let summary = issues.map { "\($0.fieldPath): \($0.message)" }.joined(separator: "; ")
            return "VM specification failed validation (\(issues.count) issue(s)): \(summary)"
        case let .vmNotFound(id):
            return "Virtual machine '\(id.rawValue)' was not found in workspace."
        case let .snapshotNotFound(id):
            return "Snapshot '\(id.rawValue)' does not exist in lineage DAG."
        case let .invalidLifecycleTransition(vmID, from, requested):
            return "Cannot perform '\(requested)' on VM '\(vmID.rawValue)' while in state '\(from)'."
        case let .diskImageOperationFailed(path, errnoCode, detail):
            return "Disk operation failed on '\(path)' (errno=\(errnoCode)): \(detail)"
        case let .cowCloneFailed(source, destination, errnoCode):
            return "APFS clonefile failed from '\(source)' to '\(destination)' (errno=\(errnoCode))."
        case let .iso9660BuildFailed(detail):
            return "Cloud-Init ISO-9660 image build error: \(detail)"
        case let .partitionTableInvalid(detail):
            return "Disk partition header verification failed: \(detail)"
        case let .networkFrameMalformed(layer, detail):
            return "Malformed \(layer) network frame: \(detail)"
        case let .pcapCorrupted(detail):
            return "PCAPNG capture stream error: \(detail)"
        case let .firewallBlocked(ruleID, reason):
            let tag = ruleID?.rawValue ?? "implicit-deny"
            return "Packet blocked by firewall rule '\(tag)': \(reason)"
        case let .vsockProtocolViolation(detail):
            return "VirtioSocket RPC framing violation: \(detail)"
        case let .vsockCRCMismatch(expected, actual):
            return String(format: "Vsock frame CRC32 mismatch (expected 0x%08X, got 0x%08X).", expected, actual)
        case let .portForwardBindFailed(port, errnoCode):
            return "Failed to bind localhost TCP port \(port) (errno=\(errnoCode))."
        case let .snapshotCycleDetected(id):
            return "Snapshot lineage cycle detected at node '\(id.rawValue)'."
        case let .storageDatabaseError(code, sql, detail):
            return "SQLite error (\(code)) executing '\(sql)': \(detail)"
        case let .storageMigrationFailed(fromVersion, toVersion, detail):
            return "Schema migration v\(fromVersion)->v\(toVersion) failed: \(detail)"
        case let .bundleIntegrityError(path, detail):
            return "Workspace bundle integrity error at '\(path)': \(detail)"
        case .undoStackEmpty:
            return "No reversible operation available to undo."
        case .redoStackEmpty:
            return "No undone operation available to redo."
        case let .pluginPermissionDenied(pluginID, capability):
            return "Plugin '\(pluginID.rawValue)' lacks required capability '\(capability)'."
        case let .pluginExecutionFailed(pluginID, detail):
            return "Plugin '\(pluginID.rawValue)' threw runtime error: \(detail)"
        case let .pluginTimedOut(pluginID, limitMs):
            return "Plugin '\(pluginID.rawValue)' exceeded execution watchdog (\(limitMs) ms)."
        case let .cliUsageError(detail):
            return "CLI argument error: \(detail)"
        case let .ipcDaemonUnavailable(socketPath, detail):
            return "AgentVM daemon socket '\(socketPath)' unreachable: \(detail)"
        case let .resourceQuotaExceeded(resource, requested, limit):
            return "Fleet quota exceeded for \(resource): requested \(requested), limit \(limit)."
        }
    }

    public var remediationHint: String {
        switch self {
        case .virtualizationUnsupported:
            return "Sign the binary with com.apple.security.virtualization entitlement on Apple Silicon macOS 14+."
        case .cowCloneFailed:
            return "Ensure source and destination disk images reside on the same APFS volume."
        case .firewallBlocked:
            return "Add an explicit allow rule in Firewall Policy Studio or switch the NIC policy preset."
        case .pluginPermissionDenied:
            return "Grant the capability in plugin manifest.json and approve it in Plugin Studio."
        case .portForwardBindFailed:
            return "Choose an unprivileged free TCP port >= 1024."
        default:
            return "Inspect the Audit Journal drawer or run 'agentvm doctor' for detailed diagnostics."
        }
    }
}

// MARK: - Byte Formatting Utilities

public enum ByteMetricsFormatter: Sendable {
    public static func formatBytes(_ bytes: UInt64) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var value = Double(bytes)
        var unitIndex = 0
        while value >= 1024.0 && unitIndex < units.count - 1 {
            value /= 1024.0
            unitIndex += 1
        }
        if unitIndex == 0 {
            return "\(bytes) B"
        }
        return String(format: "%.2f %@", value, units[unitIndex])
    }

    public static func formatSignedDeltaBytes(_ delta: Int64) -> String {
        let sign = delta >= 0 ? "+" : "-"
        let mag = UInt64(delta.magnitude)
        return "\(sign)\(formatBytes(mag))"
    }

    public static func scrubHomePath(_ rawPath: String) -> String {
        let home = NSHomeDirectory()
        guard !home.isEmpty, rawPath.hasPrefix(home) else { return rawPath }
        return "~" + rawPath.dropFirst(home.count)
    }
}
