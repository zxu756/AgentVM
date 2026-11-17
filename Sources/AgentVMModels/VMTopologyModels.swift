import Foundation

// MARK: - Guest OS & BootLoaders

public enum GuestOSType: String, Codable, Hashable, Sendable, CaseIterable {
    case linuxARM64 = "linux-arm64"
    case linuxX86_64ViaRosetta = "linux-x86_64-rosetta"
    case macOSARM64 = "macos-arm64"
    case freebsdARM64 = "freebsd-arm64"

    public var displayName: String {
        switch self {
        case .linuxARM64: return "Linux (ARM64 Native)"
        case .linuxX86_64ViaRosetta: return "Linux (ARM64 + Rosetta x86_64)"
        case .macOSARM64: return "macOS Guest (Apple Silicon)"
        case .freebsdARM64: return "FreeBSD (ARM64 EFI)"
        }
    }

    public var defaultVCPUs: Int {
        switch self {
        case .macOSARM64: return 4
        default: return 2
        }
    }

    public var defaultMemoryMB: UInt64 {
        switch self {
        case .macOSARM64: return 8192
        case .linuxX86_64ViaRosetta: return 4096
        default: return 2048
        }
    }
}

public enum BootLoaderSpec: Codable, Hashable, Sendable {
    case linuxKernel(
        vmlinuzPath: String,
        initrdPath: String?,
        kernelCommandLine: String
    )
    case efiBoot(
        variableStorePath: String,
        createVariableStoreIfMissing: Bool
    )
    case macOSBoot(
        hardwareModelPath: String,
        machineIdentifierPath: String,
        auxiliaryStoragePath: String
    )

    public var summaryLabel: String {
        switch self {
        case .linuxKernel: return "Direct Linux Kernel (VZLinuxBootLoader)"
        case .efiBoot: return "UEFI Firmware (VZEFIBootLoader)"
        case .macOSBoot: return "Apple Silicon BootROM (VZMacOSBootLoader)"
        }
    }
}

// MARK: - Compute, Storage, VirtioFS & Network Device Specs

public struct CPUAndMemorySpec: Codable, Hashable, Sendable {
    public var vcpuCount: Int
    public var memoryMB: UInt64
    public var enableBalloonDevice: Bool
    public var minBalloonMemoryMB: UInt64
    public var cpuQuotaPercent: Int
    public var enableEntropyDevice: Bool

    public init(
        vcpuCount: Int = 2,
        memoryMB: UInt64 = 2048,
        enableBalloonDevice: Bool = true,
        minBalloonMemoryMB: UInt64 = 512,
        cpuQuotaPercent: Int = 100,
        enableEntropyDevice: Bool = true
    ) {
        self.vcpuCount = vcpuCount
        self.memoryMB = memoryMB
        self.enableBalloonDevice = enableBalloonDevice
        self.minBalloonMemoryMB = minBalloonMemoryMB
        self.cpuQuotaPercent = cpuQuotaPercent
        self.enableEntropyDevice = enableEntropyDevice
    }

    public var memoryBytes: UInt64 { memoryMB * 1024 * 1024 }
}

public enum DiskImageFormat: String, Codable, Hashable, Sendable, CaseIterable {
    case rawSparse = "raw-sparse"
    case qcow2 = "qcow2"
    case iso9660 = "iso9660"
}

public enum BlockDiskCachingMode: String, Codable, Hashable, Sendable, CaseIterable {
    case automatic
    case cached
    case uncached
}

public enum BlockDiskSyncMode: String, Codable, Hashable, Sendable, CaseIterable {
    case full
    case fsyncOnly
    case none
}

public struct BlockDeviceSpec: Codable, Hashable, Sendable, Identifiable {
    public var id: BlockDeviceID
    public var label: String
    public var imagePath: String
    public var virtualSizeBytes: UInt64
    public var format: DiskImageFormat
    public var readOnly: Bool
    public var isBootVolume: Bool
    public var cachingMode: BlockDiskCachingMode
    public var syncMode: BlockDiskSyncMode
    public var parentCoWImagePath: String?

    public init(
        id: BlockDeviceID = .generate(prefix: "blk"),
        label: String,
        imagePath: String,
        virtualSizeBytes: UInt64,
        format: DiskImageFormat = .rawSparse,
        readOnly: Bool = false,
        isBootVolume: Bool = false,
        cachingMode: BlockDiskCachingMode = .automatic,
        syncMode: BlockDiskSyncMode = .fsyncOnly,
        parentCoWImagePath: String? = nil
    ) {
        self.id = id
        self.label = label
        self.imagePath = imagePath
        self.virtualSizeBytes = virtualSizeBytes
        self.format = format
        self.readOnly = readOnly
        self.isBootVolume = isBootVolume
        self.cachingMode = cachingMode
        self.syncMode = syncMode
        self.parentCoWImagePath = parentCoWImagePath
    }
}

public struct VirtioFSMountSpec: Codable, Hashable, Sendable, Identifiable {
    public var id: VirtioFSMountID
    public var mountTag: String
    public var hostDirectoryPath: String
    public var guestMountPoint: String
    public var readOnly: Bool
    public var enableRosettaLinuxBinFmt: Bool

    public init(
        id: VirtioFSMountID = .generate(prefix: "vfs"),
        mountTag: String,
        hostDirectoryPath: String,
        guestMountPoint: String,
        readOnly: Bool = false,
        enableRosettaLinuxBinFmt: Bool = false
    ) {
        self.id = id
        self.mountTag = mountTag
        self.hostDirectoryPath = hostDirectoryPath
        self.guestMountPoint = guestMountPoint
        self.readOnly = readOnly
        self.enableRosettaLinuxBinFmt = enableRosettaLinuxBinFmt
    }
}

public enum NetworkAttachmentMode: String, Codable, Hashable, Sendable, CaseIterable {
    case userSpaceSwitch = "userspace-l2-switch"
    case systemNAT = "apple-vz-nat"
    case isolatedAirgap = "airgap-loopback"

    public var displayName: String {
        switch self {
        case .userSpaceSwitch: return "User-Space L2 Switch + DPI Firewall"
        case .systemNAT: return "macOS System NAT (VZNATNetworkDevice)"
        case .isolatedAirgap: return "Air-Gapped Zero-Egress Sandbox"
        }
    }
}

public struct NetworkInterfaceSpec: Codable, Hashable, Sendable, Identifiable {
    public var id: NICID
    public var interfaceName: String
    public var macAddress: String
    public var mode: NetworkAttachmentMode
    public var ipv4Address: String
    public var subnetCIDR: String
    public var gatewayIPv4: String
    public var dnsServers: [String]
    public var mtu: UInt16
    public var egressRateLimitKbps: Int
    public var firewallPolicyID: PolicySetID?
    public var enablePCAPCapture: Bool

    public init(
        id: NICID = .generate(prefix: "nic"),
        interfaceName: String = "eth0",
        macAddress: String = "52:54:00:10:20:30",
        mode: NetworkAttachmentMode = .userSpaceSwitch,
        ipv4Address: String = "10.211.55.10",
        subnetCIDR: String = "10.211.55.0/24",
        gatewayIPv4: String = "10.211.55.1",
        dnsServers: [String] = ["10.211.55.1", "1.1.1.1"],
        mtu: UInt16 = 1500,
        egressRateLimitKbps: Int = 0,
        firewallPolicyID: PolicySetID? = nil,
        enablePCAPCapture: Bool = true
    ) {
        self.id = id
        self.interfaceName = interfaceName
        self.macAddress = macAddress
        self.mode = mode
        self.ipv4Address = ipv4Address
        self.subnetCIDR = subnetCIDR
        self.gatewayIPv4 = gatewayIPv4
        self.dnsServers = dnsServers
        self.mtu = mtu
        self.egressRateLimitKbps = egressRateLimitKbps
        self.firewallPolicyID = firewallPolicyID
        self.enablePCAPCapture = enablePCAPCapture
    }
}

public enum PortForwardProtocol: String, Codable, Hashable, Sendable, CaseIterable {
    case tcp
    case vsockStream
}

public struct PortForwardRuleSpec: Codable, Hashable, Sendable, Identifiable {
    public var id: PortForwardID
    public var label: String
    public var protocolType: PortForwardProtocol
    public var hostBindAddress: String
    public var hostPort: UInt16
    public var guestPort: UInt16
    public var vsockCID: UInt32
    public var enabled: Bool

    public init(
        id: PortForwardID = .generate(prefix: "fwd"),
        label: String,
        protocolType: PortForwardProtocol = .vsockStream,
        hostBindAddress: String = "127.0.0.1",
        hostPort: UInt16,
        guestPort: UInt16,
        vsockCID: UInt32 = 3,
        enabled: Bool = true
    ) {
        self.id = id
        self.label = label
        self.protocolType = protocolType
        self.hostBindAddress = hostBindAddress
        self.hostPort = hostPort
        self.guestPort = guestPort
        self.vsockCID = vsockCID
        self.enabled = enabled
    }
}

// MARK: - Cloud-Init Specification

public struct CloudInitWriteFile: Codable, Hashable, Sendable, Identifiable {
    public var id: String { guestPath }
    public var guestPath: String
    public var permissionsOctal: String
    public var owner: String
    public var content: String

    public init(
        guestPath: String,
        permissionsOctal: String = "0644",
        owner: String = "root:root",
        content: String
    ) {
        self.guestPath = guestPath
        self.permissionsOctal = permissionsOctal
        self.owner = owner
        self.content = content
    }
}

public struct CloudInitSpec: Codable, Hashable, Sendable {
    public var instanceID: String
    public var hostname: String
    public var defaultUser: String
    public var passwordHash: String?
    public var sshAuthorizedKeys: [String]
    public var aptPackages: [String]
    public var writeFiles: [CloudInitWriteFile]
    public var runCommands: [String]
    public var staticIPv4CIDR: String?
    public var gatewayIPv4: String?
    public var nameservers: [String]
    public var injectGuestVsockAgent: Bool
    public var timezone: String

    public init(
        instanceID: String = UUID().uuidString.lowercased(),
        hostname: String = "agent-sandbox",
        defaultUser: String = "agent",
        passwordHash: String? = nil,
        sshAuthorizedKeys: [String] = [],
        aptPackages: [String] = [],
        writeFiles: [CloudInitWriteFile] = [],
        runCommands: [String] = [],
        staticIPv4CIDR: String? = nil,
        gatewayIPv4: String? = nil,
        nameservers: [String] = [],
        injectGuestVsockAgent: Bool = true,
        timezone: String = "UTC"
    ) {
        self.instanceID = instanceID
        self.hostname = hostname
        self.defaultUser = defaultUser
        self.passwordHash = passwordHash
        self.sshAuthorizedKeys = sshAuthorizedKeys
        self.aptPackages = aptPackages
        self.writeFiles = writeFiles
        self.runCommands = runCommands
        self.staticIPv4CIDR = staticIPv4CIDR
        self.gatewayIPv4 = gatewayIPv4
        self.nameservers = nameservers
        self.injectGuestVsockAgent = injectGuestVsockAgent
        self.timezone = timezone
    }
}

// MARK: - Complete VM Specification & Live Runtime State

public struct SerialAndDisplaySpec: Codable, Hashable, Sendable {
    public var enableVirtioSerialConsole: Bool
    public var serialLogPath: String?
    public var enableVirtioGraphics: Bool
    public var displayWidthPx: Int
    public var displayHeightPx: Int
    public var pixelsPerInch: Int

    public init(
        enableVirtioSerialConsole: Bool = true,
        serialLogPath: String? = nil,
        enableVirtioGraphics: Bool = false,
        displayWidthPx: Int = 1440,
        displayHeightPx: Int = 900,
        pixelsPerInch: Int = 144
    ) {
        self.enableVirtioSerialConsole = enableVirtioSerialConsole
        self.serialLogPath = serialLogPath
        self.enableVirtioGraphics = enableVirtioGraphics
        self.displayWidthPx = displayWidthPx
        self.displayHeightPx = displayHeightPx
        self.pixelsPerInch = pixelsPerInch
    }
}

public struct VMSpec: Codable, Hashable, Sendable, Identifiable {
    public var id: VMID
    public var name: String
    public var agentOwnerTag: String
    public var guestOS: GuestOSType
    public var bootLoader: BootLoaderSpec
    public var compute: CPUAndMemorySpec
    public var blockDevices: [BlockDeviceSpec]
    public var virtioFSMounts: [VirtioFSMountSpec]
    public var networkInterfaces: [NetworkInterfaceSpec]
    public var portForwards: [PortForwardRuleSpec]
    public var serialAndDisplay: SerialAndDisplaySpec
    public var cloudInit: CloudInitSpec?
    public var machineIdentifierPath: String?
    public var cloudInitISOPath: String?
    public var baseImageID: String?
    public var enableVsockDevice: Bool
    public var parentVMID: VMID?
    public var forkedFromSnapshotID: SnapshotID?
    public var maxRuntimeMinutes: Int
    public var labels: [String: String]
    public var createdAt: Date
    public var updatedAt: Date

    public init(
        id: VMID = .generate(prefix: "vm"),
        name: String,
        agentOwnerTag: String = "coordinator",
        guestOS: GuestOSType = .linuxARM64,
        bootLoader: BootLoaderSpec,
        compute: CPUAndMemorySpec = CPUAndMemorySpec(),
        blockDevices: [BlockDeviceSpec] = [],
        virtioFSMounts: [VirtioFSMountSpec] = [],
        networkInterfaces: [NetworkInterfaceSpec] = [NetworkInterfaceSpec()],
        portForwards: [PortForwardRuleSpec] = [],
        serialAndDisplay: SerialAndDisplaySpec = SerialAndDisplaySpec(),
        cloudInit: CloudInitSpec? = CloudInitSpec(),
        machineIdentifierPath: String? = nil,
        cloudInitISOPath: String? = nil,
        baseImageID: String? = nil,
        enableVsockDevice: Bool = true,
        parentVMID: VMID? = nil,
        forkedFromSnapshotID: SnapshotID? = nil,
        maxRuntimeMinutes: Int = 180,
        labels: [String: String] = [:],
        createdAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.name = name
        self.agentOwnerTag = agentOwnerTag
        self.guestOS = guestOS
        self.bootLoader = bootLoader
        self.compute = compute
        self.blockDevices = blockDevices
        self.virtioFSMounts = virtioFSMounts
        self.networkInterfaces = networkInterfaces
        self.portForwards = portForwards
        self.serialAndDisplay = serialAndDisplay
        self.cloudInit = cloudInit
        self.machineIdentifierPath = machineIdentifierPath
        self.cloudInitISOPath = cloudInitISOPath
        self.baseImageID = baseImageID
        self.enableVsockDevice = enableVsockDevice
        self.parentVMID = parentVMID
        self.forkedFromSnapshotID = forkedFromSnapshotID
        self.maxRuntimeMinutes = maxRuntimeMinutes
        self.labels = labels
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    public func validate(maxHostCores: Int = 32, maxHostMemoryMB: UInt64 = 131_072) -> [ValidationIssue] {
        var issues: [ValidationIssue] = []

        if name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            issues.append(ValidationIssue(
                fieldPath: "name",
                code: "EMPTY_VM_NAME",
                message: "Virtual machine name must not be empty.",
                remediation: "Provide a concise identifier such as 'claude-worker-01'."
            ))
        }
        if compute.vcpuCount < 1 || compute.vcpuCount > maxHostCores {
            issues.append(ValidationIssue(
                fieldPath: "compute.vcpuCount",
                code: "INVALID_VCPU_COUNT",
                message: "vCPU count \(compute.vcpuCount) is outside supported range 1...\(maxHostCores).",
                remediation: "Set vCPU count between 1 and \(maxHostCores)."
            ))
        }
        if compute.memoryMB < 256 || compute.memoryMB > maxHostMemoryMB {
            issues.append(ValidationIssue(
                fieldPath: "compute.memoryMB",
                code: "INVALID_MEMORY_MB",
                message: "Memory \(compute.memoryMB) MB is outside supported range 256...\(maxHostMemoryMB) MB.",
                remediation: "Allocate at least 256 MB and no more than host RAM."
            ))
        }
        if compute.enableBalloonDevice && compute.minBalloonMemoryMB > compute.memoryMB {
            issues.append(ValidationIssue(
                fieldPath: "compute.minBalloonMemoryMB",
                code: "BALLOON_EXCEEDS_TOTAL",
                message: "Minimum balloon floor (\(compute.minBalloonMemoryMB) MB) exceeds total memory (\(compute.memoryMB) MB).",
                remediation: "Lower minBalloonMemoryMB below compute.memoryMB."
            ))
        }

        var seenMountTags = Set<String>()
        for (idx, mount) in virtioFSMounts.enumerated() {
            if mount.mountTag.isEmpty || mount.mountTag.utf8.count > 36 {
                issues.append(ValidationIssue(
                    fieldPath: "virtioFSMounts[\(idx)].mountTag",
                    code: "INVALID_VIRTIOFS_TAG",
                    message: "VirtioFS mount tag '\(mount.mountTag)' must be 1...36 UTF-8 bytes.",
                    remediation: "Use a short ASCII mount tag like 'workspace' or 'cache'."
                ))
            }
            if !seenMountTags.insert(mount.mountTag).inserted {
                issues.append(ValidationIssue(
                    fieldPath: "virtioFSMounts[\(idx)].mountTag",
                    code: "DUPLICATE_VIRTIOFS_TAG",
                    message: "Duplicate VirtioFS mount tag '\(mount.mountTag)'.",
                    remediation: "Give each shared directory a unique VirtioFS tag."
                ))
            }
        }

        var seenHostPorts = Set<UInt16>()
        for (idx, fwd) in portForwards.enumerated() where fwd.enabled {
            if fwd.hostPort == 0 || fwd.guestPort == 0 {
                issues.append(ValidationIssue(
                    fieldPath: "portForwards[\(idx)]",
                    code: "ZERO_PORT_FORWARD",
                    message: "Port forward rule '\(fwd.label)' cannot use TCP port 0.",
                    remediation: "Specify non-zero hostPort and guestPort."
                ))
            }
            if !seenHostPorts.insert(fwd.hostPort).inserted {
                issues.append(ValidationIssue(
                    fieldPath: "portForwards[\(idx)].hostPort",
                    code: "DUPLICATE_HOST_PORT",
                    message: "Host TCP port \(fwd.hostPort) is bound more than once.",
                    remediation: "Assign distinct localhost ports to each port-forward rule."
                ))
            }
        }

        for (idx, nic) in networkInterfaces.enumerated() {
            if MACAddress(parsing: nic.macAddress) == nil {
                issues.append(ValidationIssue(
                    fieldPath: "networkInterfaces[\(idx)].macAddress",
                    code: "INVALID_MAC",
                    message: "Invalid MAC address '\(nic.macAddress)'.",
                    remediation: "Use 6-octet hex notation like '52:54:00:10:20:30'."
                ))
            }
            if nic.mtu < 576 || nic.mtu > 9000 {
                issues.append(ValidationIssue(
                    fieldPath: "networkInterfaces[\(idx)].mtu",
                    code: "INVALID_MTU",
                    message: "MTU \(nic.mtu) must be within 576...9000 bytes.",
                    remediation: "Use standard 1500 byte Ethernet MTU."
                ))
            }
        }

        return issues
    }
}

public enum VMLifecycleState: String, Codable, Hashable, Sendable, CaseIterable {
    case stopped
    case booting
    case running
    case pausing
    case paused
    case savingState
    case restoringState
    case branching
    case stopping
    case crashed

    public var isActive: Bool {
        switch self {
        case .booting, .running, .pausing, .savingState, .restoringState, .branching:
            return true
        case .stopped, .paused, .stopping, .crashed:
            return false
        }
    }

    public var badgeLabel: String {
        switch self {
        case .stopped: return "Stopped"
        case .booting: return "Booting"
        case .running: return "Running"
        case .pausing: return "Pausing"
        case .paused: return "Paused"
        case .savingState: return "Saving RAM"
        case .restoringState: return "Restoring"
        case .branching: return "CoW Forking"
        case .stopping: return "Stopping"
        case .crashed: return "Faulted"
        }
    }
}

public struct VMLiveTelemetry: Codable, Hashable, Sendable {
    public var vmID: VMID
    public var state: VMLifecycleState
    public var cpuUsagePercent: Double?
    public var memoryResidentMB: UInt64
    public var guestMemTotalBytes: UInt64?
    public var guestMemAvailableBytes: UInt64?
    public var guestAgentVersion: String?
    public var balloonReclaimedMB: UInt64
    public var diskReadBytesTotal: UInt64
    public var diskWriteBytesTotal: UInt64
    public var cowDirtyBytes: UInt64
    public var netRxBytesTotal: UInt64
    public var netTxBytesTotal: UInt64
    public var netRxPackets: UInt64
    public var netTxPackets: UInt64
    public var firewallDroppedPackets: UInt64
    public var activeTCPFlows: Int
    public var vsockStreamsOpen: Int
    public var guestAgentConnected: Bool
    public var hasLiveGuestTelemetry: Bool
    /// `true` when `state`, `guestAgentConnected` and `vsockStreamsOpen` were written by the explicit
    /// simulation backend (`--backend simulation`, `--seed-demo`, `--demo`) and no real guest exists behind them.
    /// The flag is persisted in the same JSON blob as the state it qualifies, so any reader that sees a
    /// simulated `running` also sees `"simulated": true`. Records written before this field existed decode as `false`.
    public var simulated: Bool
    public var uptimeSeconds: TimeInterval
    public var sampledAt: Date

    /// Marker every text surface prints next to a simulated lifecycle state.
    public static let simulatedStateMarker = "SIMULATED"

    public init(
        vmID: VMID,
        state: VMLifecycleState = .stopped,
        cpuUsagePercent: Double? = nil,
        memoryResidentMB: UInt64 = 0,
        guestMemTotalBytes: UInt64? = nil,
        guestMemAvailableBytes: UInt64? = nil,
        guestAgentVersion: String? = nil,
        balloonReclaimedMB: UInt64 = 0,
        diskReadBytesTotal: UInt64 = 0,
        diskWriteBytesTotal: UInt64 = 0,
        cowDirtyBytes: UInt64 = 0,
        netRxBytesTotal: UInt64 = 0,
        netTxBytesTotal: UInt64 = 0,
        netRxPackets: UInt64 = 0,
        netTxPackets: UInt64 = 0,
        firewallDroppedPackets: UInt64 = 0,
        activeTCPFlows: Int = 0,
        vsockStreamsOpen: Int = 0,
        guestAgentConnected: Bool = false,
        hasLiveGuestTelemetry: Bool = false,
        simulated: Bool = false,
        uptimeSeconds: TimeInterval = 0,
        sampledAt: Date = Date()
    ) {
        self.vmID = vmID
        self.state = state
        self.cpuUsagePercent = cpuUsagePercent
        self.memoryResidentMB = memoryResidentMB
        self.guestMemTotalBytes = guestMemTotalBytes
        self.guestMemAvailableBytes = guestMemAvailableBytes
        self.guestAgentVersion = guestAgentVersion
        self.balloonReclaimedMB = balloonReclaimedMB
        self.diskReadBytesTotal = diskReadBytesTotal
        self.diskWriteBytesTotal = diskWriteBytesTotal
        self.cowDirtyBytes = cowDirtyBytes
        self.netRxBytesTotal = netRxBytesTotal
        self.netTxBytesTotal = netTxBytesTotal
        self.netRxPackets = netRxPackets
        self.netTxPackets = netTxPackets
        self.firewallDroppedPackets = firewallDroppedPackets
        self.activeTCPFlows = activeTCPFlows
        self.vsockStreamsOpen = vsockStreamsOpen
        self.guestAgentConnected = guestAgentConnected
        self.hasLiveGuestTelemetry = hasLiveGuestTelemetry
        self.simulated = simulated
        self.uptimeSeconds = uptimeSeconds
        self.sampledAt = sampledAt
    }

    private enum CodingKeys: String, CodingKey {
        case vmID
        case state
        case cpuUsagePercent
        case memoryResidentMB
        case guestMemTotalBytes
        case guestMemAvailableBytes
        case guestAgentVersion
        case balloonReclaimedMB
        case diskReadBytesTotal
        case diskWriteBytesTotal
        case cowDirtyBytes
        case netRxBytesTotal
        case netTxBytesTotal
        case netRxPackets
        case netTxPackets
        case firewallDroppedPackets
        case activeTCPFlows
        case vsockStreamsOpen
        case guestAgentConnected
        case hasLiveGuestTelemetry
        case simulated
        case uptimeSeconds
        case sampledAt
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.vmID = try container.decode(VMID.self, forKey: .vmID)
        self.state = try container.decode(VMLifecycleState.self, forKey: .state)
        self.cpuUsagePercent = try container.decodeIfPresent(Double.self, forKey: .cpuUsagePercent)
        self.memoryResidentMB = try container.decode(UInt64.self, forKey: .memoryResidentMB)
        self.guestMemTotalBytes = try container.decodeIfPresent(UInt64.self, forKey: .guestMemTotalBytes)
        self.guestMemAvailableBytes = try container.decodeIfPresent(UInt64.self, forKey: .guestMemAvailableBytes)
        self.guestAgentVersion = try container.decodeIfPresent(String.self, forKey: .guestAgentVersion)
        self.balloonReclaimedMB = try container.decode(UInt64.self, forKey: .balloonReclaimedMB)
        self.diskReadBytesTotal = try container.decode(UInt64.self, forKey: .diskReadBytesTotal)
        self.diskWriteBytesTotal = try container.decode(UInt64.self, forKey: .diskWriteBytesTotal)
        self.cowDirtyBytes = try container.decode(UInt64.self, forKey: .cowDirtyBytes)
        self.netRxBytesTotal = try container.decode(UInt64.self, forKey: .netRxBytesTotal)
        self.netTxBytesTotal = try container.decode(UInt64.self, forKey: .netTxBytesTotal)
        self.netRxPackets = try container.decode(UInt64.self, forKey: .netRxPackets)
        self.netTxPackets = try container.decode(UInt64.self, forKey: .netTxPackets)
        self.firewallDroppedPackets = try container.decode(UInt64.self, forKey: .firewallDroppedPackets)
        self.activeTCPFlows = try container.decode(Int.self, forKey: .activeTCPFlows)
        self.vsockStreamsOpen = try container.decode(Int.self, forKey: .vsockStreamsOpen)
        self.guestAgentConnected = try container.decode(Bool.self, forKey: .guestAgentConnected)
        self.hasLiveGuestTelemetry = try container.decodeIfPresent(Bool.self, forKey: .hasLiveGuestTelemetry) ?? false
        self.simulated = try container.decodeIfPresent(Bool.self, forKey: .simulated) ?? false
        self.uptimeSeconds = try container.decode(TimeInterval.self, forKey: .uptimeSeconds)
        self.sampledAt = try container.decode(Date.self, forKey: .sampledAt)
    }

    /// A non-stopped lifecycle state that only exists inside the simulation backend.
    public var isSimulatedActiveState: Bool {
        simulated && state != .stopped
    }

    /// `true` only for a `running` state that was not produced by the simulation backend.
    public var isRunningOutsideSimulation: Bool {
        state == .running && !simulated
    }

    /// Plain-text lifecycle label for tables and logs. A simulated non-stopped state is rendered as
    /// `SIMULATED:<state>` so it can never be read as a real one. Pass a localized state name to translate
    /// the part after the marker; the marker itself is never translated.
    public func markedStateLabel(localizedState: String? = nil) -> String {
        let base = localizedState ?? state.rawValue
        return isSimulatedActiveState ? "\(Self.simulatedStateMarker):\(base)" : base
    }

    public var formattedCPUUsage: String {
        guard hasLiveGuestTelemetry, state == .running, let cpuUsagePercent else { return "—" }
        return String(format: "%.1f%%", cpuUsagePercent)
    }

    public var formattedMemoryResident: String {
        guard hasLiveGuestTelemetry, state == .running else { return "—" }
        return "\(memoryResidentMB) MB"
    }

    public func formattedMemoryResident(ofTotalMB totalMB: UInt64) -> String {
        guard hasLiveGuestTelemetry, state == .running else { return "— / \(totalMB) MB" }
        return "\(memoryResidentMB) / \(totalMB) MB"
    }

    public var formattedBalloonReclaimed: String {
        guard hasLiveGuestTelemetry, state == .running else { return "—" }
        return "\(balloonReclaimedMB) MB"
    }
}

public struct VMInstanceRecord: Codable, Hashable, Sendable, Identifiable {
    public var id: VMID { spec.id }
    public var spec: VMSpec
    public var currentHeadSnapshotID: SnapshotID?
    public var telemetry: VMLiveTelemetry
    public var lastBootedAt: Date?
    public var lastErrorDescription: String?

    public init(
        spec: VMSpec,
        currentHeadSnapshotID: SnapshotID? = nil,
        telemetry: VMLiveTelemetry? = nil,
        lastBootedAt: Date? = nil,
        lastErrorDescription: String? = nil
    ) {
        self.spec = spec
        self.currentHeadSnapshotID = currentHeadSnapshotID
        self.telemetry = telemetry ?? VMLiveTelemetry(vmID: spec.id)
        self.lastBootedAt = lastBootedAt
        self.lastErrorDescription = lastErrorDescription
    }
}
