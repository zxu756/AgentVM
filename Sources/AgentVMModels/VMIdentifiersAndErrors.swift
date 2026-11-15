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

    public static let current = SemanticVersion(major: 1, minor: 2, patch: 0)

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
    /// Whether the running executable itself carries the `com.apple.security.virtualization` entitlement,
    /// read from the current process (not inferred from `VZVirtualMachine.isSupported`).
    public var hasVirtualizationEntitlement: Bool
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
        hasVirtualizationEntitlement: Bool = false,
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
        self.hasVirtualizationEntitlement = hasVirtualizationEntitlement
        self.isNestedVirtualizationSupported = isNestedVirtualizationSupported
        self.isRosettaLinuxShareAvailable = isRosettaLinuxShareAvailable
        self.isAPFSClonefileSupported = isAPFSClonefileSupported
        self.maxSupportedVCPUs = maxSupportedVCPUs
        self.maxSupportedMemoryMB = maxSupportedMemoryMB
        self.probedAt = probedAt
    }

    /// The host can start a `VZVirtualMachine` from this executable only when the framework reports support
    /// and the executable is signed with the virtualization entitlement.
    public var canStartVirtualMachines: Bool {
        isVirtualizationFrameworkSupported && hasVirtualizationEntitlement
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

/// Why a VM cannot be booted. Kept structured (instead of a free-form English string) so the whole
/// `ERR_NO_BOOTABLE_SYSTEM` message can be rendered in either language.
public enum NoBootableSystemReason: Sendable, Equatable {
    case kernelImageMissing(path: String)
    case macOSBootArtifactsMissing
    case noBootDeviceConfigured
    case bootDiskImageMissing(fileName: String)
    case emptyPartitionTable(fileName: String)

    public func localizedDetail(in language: AppLanguage) -> String {
        let isZh = (language == .zhHans)
        switch self {
        case let .kernelImageMissing(path):
            return isZh
                ? "在「\(path)」找不到 Linux 内核镜像。"
                : "Linux kernel image not found at '\(path)'."
        case .macOSBootArtifactsMissing:
            return isZh
                ? "缺少 macOS 辅助存储或硬件型号文件。"
                : "macOS auxiliary storage or hardware model missing."
        case .noBootDeviceConfigured:
            return isZh
                ? "没有配置启动用的块设备。"
                : "No boot block device configured."
        case let .bootDiskImageMissing(fileName):
            return isZh
                ? "找不到启动磁盘镜像「\(fileName)」。"
                : "Boot disk image missing at '\(fileName)'."
        case let .emptyPartitionTable(fileName):
            return isZh
                ? "启动磁盘「\(fileName)」只有一张空的分区表，没有安装 EFI 引导程序，也没有根文件系统。"
                : "Boot disk '\(fileName)' contains only an empty partition table with no installed EFI bootloader or root OS filesystem."
        }
    }
}

/// Structured failure reasons for curated base image catalog operations (`image list`, `image pull`, `image verify`).
public enum BaseImageErrorReason: Sendable, Equatable {
    case unknownImage(availableIDs: [String])
    case unsupportedImage
    case missingFromCache
    case insecureDownloadURL(url: String)
    case insecureRedirect(targetURL: String)
    case downloadFailed(detail: String)
    case sizeMismatch(expectedBytes: UInt64, actualBytes: UInt64)
    case checksumMismatch(expectedSHA512: String, actualSHA512: String)
}

public enum AgentVMError: Error, LocalizedError, Sendable, Equatable {
    case virtualizationUnsupported(reason: String)
    case virtualizationEntitlementMissing
    case noBootableSystem(vmName: String, reason: NoBootableSystemReason)
    case baseImageError(imageID: String, reason: BaseImageErrorReason)
    case diskSizeTooSmallForImage(imageID: String, requestedBytes: UInt64, imageBytes: UInt64)
    case vmNameAlreadyExists(name: String, existingID: VMID)
    case guestAgentNotConnected(vmName: String, state: String)
    case guestVsockConnectTimedOut(
        vmName: String,
        port: UInt32,
        timeoutSeconds: Int,
        consoleLogPath: String,
        detail: String
    )
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
        case .virtualizationEntitlementMissing: return "ERR_VZ_ENTITLEMENT_MISSING"
        case .noBootableSystem: return "ERR_NO_BOOTABLE_SYSTEM"
        case let .baseImageError(_, reason):
            switch reason {
            case .unknownImage: return "ERR_IMAGE_NOT_FOUND"
            case .unsupportedImage: return "ERR_IMAGE_UNSUPPORTED"
            case .missingFromCache: return "ERR_IMAGE_NOT_CACHED"
            case .insecureDownloadURL, .insecureRedirect: return "ERR_IMAGE_INSECURE_URL"
            case .downloadFailed: return "ERR_IMAGE_DOWNLOAD_FAILED"
            case .sizeMismatch: return "ERR_IMAGE_SIZE_MISMATCH"
            case .checksumMismatch: return "ERR_IMAGE_CHECKSUM_MISMATCH"
            }
        case .diskSizeTooSmallForImage: return "ERR_DISK_SIZE_TOO_SMALL"
        case .vmNameAlreadyExists: return "ERR_VM_NAME_EXISTS"
        case .guestAgentNotConnected: return "ERR_GUEST_AGENT_UNAVAILABLE"
        case .guestVsockConnectTimedOut: return "ERR_VSOCK_CONNECT_TIMEOUT"
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
        localizedMessage(in: .en)
    }

    public func localizedMessage(in language: AppLanguage) -> String {
        let isZh = (language == .zhHans)
        switch self {
        case let .virtualizationUnsupported(reason):
            return isZh
                ? "Apple Virtualization.framework 不可用：\(reason)"
                : "Apple Virtualization.framework unavailable: \(reason)"
        case .virtualizationEntitlementMissing:
            return isZh
                ? "系统支持虚拟化；当前可执行文件没有虚拟化权限（com.apple.security.virtualization），无法启动虚拟机。"
                : "The host supports virtualization; the current executable does not have the virtualization entitlement (com.apple.security.virtualization) and cannot start virtual machines."
        case let .noBootableSystem(vmName, reason):
            let detail = reason.localizedDetail(in: language)
            return isZh
                ? "虚拟机「\(vmName)」磁盘上没有可引导的客户机系统（内核或根文件系统缺失）：\(detail)若仅需验证主机侧协议演练，请显式传入 --backend simulation。"
                : "VM '\(vmName)' has no bootable guest OS or kernel on its disk: \(detail) Pass --backend simulation explicitly if you want to run the host-side simulation responder."
        case let .baseImageError(imageID, reason):
            switch reason {
            case let .unknownImage(availableIDs):
                if isZh {
                    let avail = availableIDs.isEmpty ? "无" : availableIDs.joined(separator: "、")
                    return "基础镜像目录中未找到条目「\(imageID)」（当前目录包含：\(avail)）。"
                } else {
                    let avail = availableIDs.isEmpty ? "none" : availableIDs.joined(separator: ", ")
                    return "Base image '\(imageID)' was not found in the catalog (available: \(avail))."
                }
            case .unsupportedImage:
                return isZh
                    ? "基础镜像「\(imageID)」当前暂不支持，无法下载或校验；请运行 'agentvm image list' 查看可用条目。"
                    : "Base image '\(imageID)' is currently unsupported and cannot be pulled or verified; run 'agentvm image list' to inspect supported entries."
            case .missingFromCache:
                return isZh
                    ? "基础镜像「\(imageID)」尚未缓存在本地；请先运行 'agentvm image pull \(imageID)' 下载镜像。"
                    : "Base image '\(imageID)' is not present in the local cache; run 'agentvm image pull \(imageID)' first."
            case let .insecureDownloadURL(url):
                return isZh
                    ? "拒绝非 https 下载地址「\(url)」（镜像「\(imageID)」仅允许通过 https 下载）。"
                    : "Refused non-https download URL '\(url)' for image '\(imageID)' (https is required)."
            case let .insecureRedirect(targetURL):
                return isZh
                    ? "下载镜像「\(imageID)」时遇到跳转到非 https 地址「\(targetURL)」，已拒绝连接。"
                    : "Refused insecure redirect to non-https URL '\(targetURL)' while pulling image '\(imageID)'."
            case let .downloadFailed(detail):
                return isZh
                    ? "下载基础镜像「\(imageID)」失败：\(detail)"
                    : "Failed to download base image '\(imageID)': \(detail)"
            case let .sizeMismatch(expectedBytes, actualBytes):
                return isZh
                    ? "基础镜像「\(imageID)」文件大小不符（期望 \(expectedBytes) 字节，实际 \(actualBytes) 字节）。"
                    : "Base image '\(imageID)' size mismatch (expected \(expectedBytes) bytes, got \(actualBytes) bytes)."
            case let .checksumMismatch(expectedSHA512, actualSHA512):
                return isZh
                    ? "基础镜像「\(imageID)」的 SHA-512 校验和不符（期望 \(expectedSHA512)，实际 \(actualSHA512)）。"
                    : "Base image '\(imageID)' SHA-512 checksum mismatch (expected \(expectedSHA512), computed \(actualSHA512))."
            }
        case let .diskSizeTooSmallForImage(imageID, requestedBytes, imageBytes):
            return isZh
                ? "请求的 --disk-size（\(requestedBytes) 字节）小于基础镜像「\(imageID)」的大小（\(imageBytes) 字节），未创建任何文件。"
                : "Requested --disk-size (\(requestedBytes) bytes) is smaller than base image '\(imageID)' (\(imageBytes) bytes); nothing was created."
        case let .vmNameAlreadyExists(name, existingID):
            return isZh
                ? "工作区里已经有一台名为「\(name)」的虚拟机（\(existingID.rawValue)），没有创建新的。请换一个名字。"
                : "A virtual machine named '\(name)' already exists in this workspace (\(existingID.rawValue)); nothing was created. Choose a different name."
        case let .guestAgentNotConnected(vmName, state):
            return isZh
                ? "虚拟机「\(vmName)」当前状态为 \(state)，尚未连接真实客户机代理（agentvm-guestd），无法执行客户机命令。"
                : "VM '\(vmName)' is in state '\(state)' with no live guest agent connection; cannot execute guest command."
        case let .guestVsockConnectTimedOut(vmName, port, timeoutSeconds, consoleLogPath, detail):
            return isZh
                ? "虚拟机「\(vmName)」已启动，但在 \(timeoutSeconds) 秒内未能连上客户机 vsock 端口 \(port)（\(detail)），已停止虚拟机。串口日志：\(consoleLogPath)"
                : "VM '\(vmName)' started, but failed to connect to guest vsock port \(port) within \(timeoutSeconds)s (\(detail)); the VM has been stopped. Serial console log: \(consoleLogPath)"
        case let .invalidConfiguration(issues):
            let summary = issues.map { "\($0.fieldPath): \($0.message)" }.joined(separator: "; ")
            return isZh
                ? "虚拟机配置校验未通过（共 \(issues.count) 项）：\(summary)"
                : "VM specification failed validation (\(issues.count) issue(s)): \(summary)"
        case let .vmNotFound(id):
            return isZh
                ? "工作区中未找到虚拟机「\(id.rawValue)」。"
                : "Virtual machine '\(id.rawValue)' was not found in workspace."
        case let .snapshotNotFound(id):
            return isZh
                ? "血缘 DAG 中不存在快照「\(id.rawValue)」。"
                : "Snapshot '\(id.rawValue)' does not exist in lineage DAG."
        case let .invalidLifecycleTransition(vmID, from, requested):
            return isZh
                ? "虚拟机「\(vmID.rawValue)」处于「\(from)」状态时无法执行「\(requested)」。"
                : "Cannot perform '\(requested)' on VM '\(vmID.rawValue)' while in state '\(from)'."
        case let .diskImageOperationFailed(path, errnoCode, detail):
            return isZh
                ? "磁盘操作失败「\(path)」（errno=\(errnoCode)）：\(detail)"
                : "Disk operation failed on '\(path)' (errno=\(errnoCode)): \(detail)"
        case let .cowCloneFailed(source, destination, errnoCode):
            return isZh
                ? "APFS clonefile 克隆失败：从「\(source)」到「\(destination)」（errno=\(errnoCode)）。"
                : "APFS clonefile failed from '\(source)' to '\(destination)' (errno=\(errnoCode))."
        case let .iso9660BuildFailed(detail):
            return isZh
                ? "Cloud-Init ISO-9660 镜像构建错误：\(detail)"
                : "Cloud-Init ISO-9660 image build error: \(detail)"
        case let .partitionTableInvalid(detail):
            return isZh
                ? "磁盘分区表校验失败：\(detail)"
                : "Disk partition header verification failed: \(detail)"
        case let .networkFrameMalformed(layer, detail):
            return isZh
                ? "\(layer) 网络帧格式错误：\(detail)"
                : "Malformed \(layer) network frame: \(detail)"
        case let .pcapCorrupted(detail):
            return isZh
                ? "PCAPNG 抓包流错误：\(detail)"
                : "PCAPNG capture stream error: \(detail)"
        case let .firewallBlocked(ruleID, reason):
            let tag = ruleID?.rawValue ?? "implicit-deny"
            return isZh
                ? "数据包已被防火墙规则「\(tag)」阻断：\(reason)"
                : "Packet blocked by firewall rule '\(tag)': \(reason)"
        case let .vsockProtocolViolation(detail):
            return isZh
                ? "VirtioSocket RPC 帧协议错误：\(detail)"
                : "VirtioSocket RPC framing violation: \(detail)"
        case let .vsockCRCMismatch(expected, actual):
            return isZh
                ? String(format: "Vsock 帧 CRC32 校验不匹配（期望 0x%08X，实际 0x%08X）。", expected, actual)
                : String(format: "Vsock frame CRC32 mismatch (expected 0x%08X, got 0x%08X).", expected, actual)
        case let .portForwardBindFailed(port, errnoCode):
            return isZh
                ? "绑定本地 TCP 端口 \(port) 失败（errno=\(errnoCode)）。"
                : "Failed to bind localhost TCP port \(port) (errno=\(errnoCode))."
        case let .snapshotCycleDetected(id):
            return isZh
                ? "在节点「\(id.rawValue)」处检测到快照血缘环路。"
                : "Snapshot lineage cycle detected at node '\(id.rawValue)'."
        case let .storageDatabaseError(code, sql, detail):
            return isZh
                ? "执行「\(sql)」时发生 SQLite 错误（\(code)）：\(detail)"
                : "SQLite error (\(code)) executing '\(sql)': \(detail)"
        case let .storageMigrationFailed(fromVersion, toVersion, detail):
            return isZh
                ? "数据库模式迁移 v\(fromVersion)->v\(toVersion) 失败：\(detail)"
                : "Schema migration v\(fromVersion)->v\(toVersion) failed: \(detail)"
        case let .bundleIntegrityError(path, detail):
            return isZh
                ? "工作区包完整性错误「\(path)」：\(detail)"
                : "Workspace bundle integrity error at '\(path)': \(detail)"
        case .undoStackEmpty:
            return isZh ? "当前没有可撤销的操作。" : "No reversible operation available to undo."
        case .redoStackEmpty:
            return isZh ? "当前没有可重做的操作。" : "No undone operation available to redo."
        case let .pluginPermissionDenied(pluginID, capability):
            return isZh
                ? "插件「\(pluginID.rawValue)」缺少所需权限「\(capability)」。"
                : "Plugin '\(pluginID.rawValue)' lacks required capability '\(capability)'."
        case let .pluginExecutionFailed(pluginID, detail):
            return isZh
                ? "插件「\(pluginID.rawValue)」运行时报错：\(detail)"
                : "Plugin '\(pluginID.rawValue)' threw runtime error: \(detail)"
        case let .pluginTimedOut(pluginID, limitMs):
            return isZh
                ? "插件「\(pluginID.rawValue)」超过看门狗执行时限（\(limitMs) ms）。"
                : "Plugin '\(pluginID.rawValue)' exceeded execution watchdog (\(limitMs) ms)."
        case let .cliUsageError(detail):
            return isZh
                ? "命令行参数错误：\(detail)"
                : "CLI argument error: \(detail)"
        case let .ipcDaemonUnavailable(socketPath, detail):
            return isZh
                ? "无法连接 AgentVM 守护套接字「\(socketPath)」：\(detail)"
                : "AgentVM daemon socket '\(socketPath)' unreachable: \(detail)"
        case let .resourceQuotaExceeded(resource, requested, limit):
            return isZh
                ? "超出集群配额（\(resource)）：请求 \(requested)，上限 \(limit)。"
                : "Fleet quota exceeded for \(resource): requested \(requested), limit \(limit)."
        }
    }

    public var remediationHint: String {
        switch self {
        case .virtualizationUnsupported, .virtualizationEntitlementMissing:
            return "Sign the binary with com.apple.security.virtualization entitlement on Apple Silicon macOS 14+."
        case let .baseImageError(imageID, reason):
            switch reason {
            case .unknownImage, .unsupportedImage:
                return "Run 'agentvm image list' to see supported base image IDs."
            default:
                return "Run 'agentvm image pull \(imageID)' over HTTPS to fetch and verify the image."
            }
        case let .diskSizeTooSmallForImage(_, _, imageBytes):
            return "Specify a --disk-size of at least \(ByteMetricsFormatter.formatBytes(imageBytes)) (\(imageBytes) bytes) or omit --disk-size."
        case .vmNameAlreadyExists:
            return "Run 'agentvm ps' to list existing virtual machines."
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
