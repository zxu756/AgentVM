import Foundation

// MARK: - VirtioSocket ("AVM1") Multiplexed Wire Protocol Contracts

public enum VsockChannelKind: UInt8, Codable, Hashable, Sendable, CaseIterable {
    case control = 0
    case execProcess = 1
    case fileTransfer = 2
    case tcpPortForward = 3
    case telemetryHeartbeat = 4
    case interactivePTY = 5
}

public struct VsockFrameFlags: OptionSet, Codable, Hashable, Sendable {
    public let rawValue: UInt16

    public init(rawValue: UInt16) {
        self.rawValue = rawValue
    }

    public static let syn          = VsockFrameFlags(rawValue: 1 << 0)
    public static let ack          = VsockFrameFlags(rawValue: 1 << 1)
    public static let fin          = VsockFrameFlags(rawValue: 1 << 2)
    public static let rst          = VsockFrameFlags(rawValue: 1 << 3)
    public static let windowUpdate = VsockFrameFlags(rawValue: 1 << 4)
    public static let compressed   = VsockFrameFlags(rawValue: 1 << 5)
    public static let endOfMessage = VsockFrameFlags(rawValue: 1 << 6)
    public static let errorFrame   = VsockFrameFlags(rawValue: 1 << 7)
}

public struct VsockFrameHeader: Codable, Hashable, Sendable {
    public static let wireMagic: UInt32 = 0x4156_4D31 // "AVM1"
    public static let currentProtocolVersion: UInt8 = 1
    public static let encodedByteSize: Int = 24

    public var magic: UInt32
    public var version: UInt8
    public var channel: VsockChannelKind
    public var flags: VsockFrameFlags
    public var streamID: UInt32
    public var sequenceNumber: UInt32
    public var windowCredit: UInt32
    public var payloadLength: UInt32
    public var payloadCRC32: UInt32

    public init(
        magic: UInt32 = Self.wireMagic,
        version: UInt8 = Self.currentProtocolVersion,
        channel: VsockChannelKind,
        flags: VsockFrameFlags,
        streamID: UInt32,
        sequenceNumber: UInt32,
        windowCredit: UInt32 = 262_144,
        payloadLength: UInt32,
        payloadCRC32: UInt32
    ) {
        self.magic = magic
        self.version = version
        self.channel = channel
        self.flags = flags
        self.streamID = streamID
        self.sequenceNumber = sequenceNumber
        self.windowCredit = windowCredit
        self.payloadLength = payloadLength
        self.payloadCRC32 = payloadCRC32
    }
}

// MARK: - Guest Command Execution, File Transfer & Telemetry

public struct GuestExecRequest: Codable, Hashable, Sendable, Identifiable {
    public var id: UUID
    public var executable: String
    public var arguments: [String]
    public var workingDirectory: String
    public var environment: [String: String]
    public var stdinPayload: Data?
    public var allocatePTY: Bool
    public var ptyColumns: UInt16
    public var ptyRows: UInt16
    public var runAsUser: String
    public var timeoutSeconds: TimeInterval

    public init(
        id: UUID = UUID(),
        executable: String,
        arguments: [String] = [],
        workingDirectory: String = "/",
        environment: [String: String] = [:],
        stdinPayload: Data? = nil,
        allocatePTY: Bool = false,
        ptyColumns: UInt16 = 120,
        ptyRows: UInt16 = 36,
        runAsUser: String = "root",
        timeoutSeconds: TimeInterval = 3600
    ) {
        self.id = id
        self.executable = executable
        self.arguments = arguments
        self.workingDirectory = workingDirectory
        self.environment = environment
        self.stdinPayload = stdinPayload
        self.allocatePTY = allocatePTY
        self.ptyColumns = ptyColumns
        self.ptyRows = ptyRows
        self.runAsUser = runAsUser
        self.timeoutSeconds = timeoutSeconds
    }

    public var commandLineSummary: String {
        ([executable] + arguments).joined(separator: " ")
    }
}

public enum GuestExecStreamKind: String, Codable, Hashable, Sendable {
    case stdout
    case stderr
    case systemNotice
}

public struct GuestExecOutputChunk: Codable, Hashable, Sendable {
    public var requestID: UUID
    public var stream: GuestExecStreamKind
    public var sequence: UInt32
    public var data: Data
    public var timestamp: Date

    public init(
        requestID: UUID,
        stream: GuestExecStreamKind,
        sequence: UInt32,
        data: Data,
        timestamp: Date = Date()
    ) {
        self.requestID = requestID
        self.stream = stream
        self.sequence = sequence
        self.data = data
        self.timestamp = timestamp
    }
}

public struct GuestExecResult: Codable, Hashable, Sendable {
    public var requestID: UUID
    public var vmID: VMID
    public var commandLine: String
    public var exitCode: Int32
    public var stdoutData: Data
    public var stderrData: Data
    public var durationMilliseconds: Int
    public var timedOut: Bool
    public var preCheckpointSnapshotID: SnapshotID?
    public var completedAt: Date

    public init(
        requestID: UUID,
        vmID: VMID,
        commandLine: String,
        exitCode: Int32,
        stdoutData: Data,
        stderrData: Data,
        durationMilliseconds: Int,
        timedOut: Bool = false,
        preCheckpointSnapshotID: SnapshotID? = nil,
        completedAt: Date = Date()
    ) {
        self.requestID = requestID
        self.vmID = vmID
        self.commandLine = commandLine
        self.exitCode = exitCode
        self.stdoutData = stdoutData
        self.stderrData = stderrData
        self.durationMilliseconds = durationMilliseconds
        self.timedOut = timedOut
        self.preCheckpointSnapshotID = preCheckpointSnapshotID
        self.completedAt = completedAt
    }

    public var stdoutUTF8: String {
        String(decoding: stdoutData, as: UTF8.self)
    }

    public var stderrUTF8: String {
        String(decoding: stderrData, as: UTF8.self)
    }
}

public enum FileTransferDirection: String, Codable, Hashable, Sendable {
    case hostToGuest
    case guestToHost
}

public struct GuestFileTransferManifest: Codable, Hashable, Sendable, Identifiable {
    public var id: UUID
    public var direction: FileTransferDirection
    public var sourcePath: String
    public var destinationPath: String
    public var totalBytes: UInt64
    public var sha256Hex: String
    public var posixPermissions: UInt16
    public var modifiedTimestamp: Int64

    public init(
        id: UUID = UUID(),
        direction: FileTransferDirection,
        sourcePath: String,
        destinationPath: String,
        totalBytes: UInt64,
        sha256Hex: String,
        posixPermissions: UInt16 = 0o644,
        modifiedTimestamp: Int64 = Int64(Date().timeIntervalSince1970)
    ) {
        self.id = id
        self.direction = direction
        self.sourcePath = sourcePath
        self.destinationPath = destinationPath
        self.totalBytes = totalBytes
        self.sha256Hex = sha256Hex
        self.posixPermissions = posixPermissions
        self.modifiedTimestamp = modifiedTimestamp
    }
}

public struct GuestProcessSample: Codable, Hashable, Sendable, Identifiable {
    public var id: Int32 { pid }
    public var pid: Int32
    public var ppid: Int32
    public var user: String
    public var cpuPercent: Double
    public var rssBytes: UInt64
    public var command: String

    public init(pid: Int32, ppid: Int32, user: String, cpuPercent: Double, rssBytes: UInt64, command: String) {
        self.pid = pid
        self.ppid = ppid
        self.user = user
        self.cpuPercent = cpuPercent
        self.rssBytes = rssBytes
        self.command = command
    }
}

public struct GuestHeartbeatPayload: Codable, Hashable, Sendable {
    public var hostname: String
    public var kernelRelease: String
    public var uptimeSeconds: Double
    public var loadAvg1: Double
    public var loadAvg5: Double
    public var loadAvg15: Double
    public var memTotalBytes: UInt64
    public var memAvailableBytes: UInt64
    public var rootFilesystemUsedBytes: UInt64
    public var rootFilesystemTotalBytes: UInt64
    public var topProcesses: [GuestProcessSample]
    public var reportedAt: Date

    public init(
        hostname: String,
        kernelRelease: String,
        uptimeSeconds: Double,
        loadAvg1: Double,
        loadAvg5: Double,
        loadAvg15: Double,
        memTotalBytes: UInt64,
        memAvailableBytes: UInt64,
        rootFilesystemUsedBytes: UInt64,
        rootFilesystemTotalBytes: UInt64,
        topProcesses: [GuestProcessSample] = [],
        reportedAt: Date = Date()
    ) {
        self.hostname = hostname
        self.kernelRelease = kernelRelease
        self.uptimeSeconds = uptimeSeconds
        self.loadAvg1 = loadAvg1
        self.loadAvg5 = loadAvg5
        self.loadAvg15 = loadAvg15
        self.memTotalBytes = memTotalBytes
        self.memAvailableBytes = memAvailableBytes
        self.rootFilesystemUsedBytes = rootFilesystemUsedBytes
        self.rootFilesystemTotalBytes = rootFilesystemTotalBytes
        self.topProcesses = topProcesses
        self.reportedAt = reportedAt
    }
}

// MARK: - Curated Base Image Registry Models

public struct BaseImageCatalogEntry: Codable, Hashable, Sendable, Identifiable {
    public var id: String
    public var displayName: String
    public var distribution: String
    public var version: String
    public var guestOS: GuestOSType
    public var isSupported: Bool
    public var downloadURL: String?
    public var expectedSHA512: String?
    public var expectedSizeBytes: UInt64?
    public var defaultVirtualSizeBytes: UInt64
    public var includesPreinstalledToolchains: [String]
    public var cachedLocalPath: String?

    public init(
        id: String,
        displayName: String,
        distribution: String,
        version: String,
        guestOS: GuestOSType,
        isSupported: Bool = true,
        downloadURL: String? = nil,
        expectedSHA512: String? = nil,
        expectedSizeBytes: UInt64? = nil,
        defaultVirtualSizeBytes: UInt64 = 0,
        includesPreinstalledToolchains: [String] = [],
        cachedLocalPath: String? = nil
    ) {
        self.id = id
        self.displayName = displayName
        self.distribution = distribution
        self.version = version
        self.guestOS = guestOS
        self.isSupported = isSupported
        self.downloadURL = downloadURL
        self.expectedSHA512 = expectedSHA512
        self.expectedSizeBytes = expectedSizeBytes
        self.defaultVirtualSizeBytes = defaultVirtualSizeBytes
        self.includesPreinstalledToolchains = includesPreinstalledToolchains
        self.cachedLocalPath = cachedLocalPath
    }

    /// Canonical filename inside the shared base image cache directory (e.g. `debian-12-bookworm-arm64.raw`).
    public var cacheFileName: String {
        if let downloadURL,
           let url = URL(string: downloadURL) {
            let ext = url.pathExtension.lowercased()
            if !ext.isEmpty {
                return "\(id).\(ext)"
            }
        }
        return "\(id).raw"
    }
}
