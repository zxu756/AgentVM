import AgentVMModels
import Darwin
import Foundation
import Security
import Virtualization

// MARK: - Native Apple Silicon Host Capability Probe & VZVirtualMachineConfiguration Builder

public enum HostHypervisorProbe {
    public static func probeCapabilities(probeDirectoryURL: URL? = nil) -> HostCapabilityReport {
        let info = ProcessInfo.processInfo
        let osVer = info.operatingSystemVersion
        let versionString = "\(osVer.majorVersion).\(osVer.minorVersion).\(osVer.patchVersion)"

        var physCores: Int32 = 0
        var size = MemoryLayout<Int32>.size
        sysctlbyname("hw.perflevel0.physicalcpu", &physCores, &size, nil, 0)
        if physCores <= 0 {
            sysctlbyname("hw.physicalcpu", &physCores, &size, nil, 0)
        }
        let logicalCores = info.activeProcessorCount
        let resolvedPhys = physCores > 0 ? Int(physCores) : logicalCores

        let vzSupported = VZVirtualMachine.isSupported
        let vzEntitled = currentProcessHasBooleanEntitlement(virtualizationEntitlementKey)
        let maxCPU = max(1, VZVirtualMachineConfiguration.maximumAllowedCPUCount)
        let maxMemMB = max(512, VZVirtualMachineConfiguration.maximumAllowedMemorySize / (1024 * 1024))

        var rosettaAvailable = false
        #if arch(arm64)
        let availability = VZLinuxRosettaDirectoryShare.availability
        rosettaAvailable = (availability == .installed)
        #endif

        var nestedSupported = false
        if #available(macOS 15.0, *) {
            nestedSupported = VZGenericPlatformConfiguration.isNestedVirtualizationSupported
        }

        let targetDir = probeDirectoryURL ?? FileManager.default.temporaryDirectory
        let clonefileSupported = performRealClonefileProbe(in: targetDir)

        return HostCapabilityReport(
            architecture: currentArchName(),
            macOSVersion: versionString,
            physicalCores: resolvedPhys,
            logicalCores: logicalCores,
            hostMemoryBytes: info.physicalMemory,
            isVirtualizationFrameworkSupported: vzSupported,
            hasVirtualizationEntitlement: vzEntitled,
            isNestedVirtualizationSupported: nestedSupported,
            isRosettaLinuxShareAvailable: rosettaAvailable,
            isAPFSClonefileSupported: clonefileSupported,
            maxSupportedVCPUs: maxCPU,
            maxSupportedMemoryMB: maxMemMB
        )
    }

    public static let virtualizationEntitlementKey = "com.apple.security.virtualization"

    /// Reads one entitlement of the *current process* from its code signature via
    /// `SecTaskCreateFromSelf` + `SecTaskCopyValueForEntitlement`. Returns `true` only when the entitlement
    /// is present with a boolean `true` value. `VZVirtualMachine.isSupported` says nothing about this:
    /// it is `true` on any capable host even when the executable is not entitled to start a VM.
    public static func currentProcessHasBooleanEntitlement(_ key: String) -> Bool {
        guard let task = SecTaskCreateFromSelf(nil) else { return false }
        guard let value = SecTaskCopyValueForEntitlement(task, key as CFString, nil) else { return false }
        guard CFGetTypeID(value) == CFBooleanGetTypeID() else { return false }
        return CFBooleanGetValue((value as! CFBoolean))
    }

    private static func performRealClonefileProbe(in directoryURL: URL) -> Bool {
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: directoryURL.path, isDirectory: &isDir),
              isDir.boolValue else {
            return false
        }
        let token = UUID().uuidString.lowercased()
        let srcURL = directoryURL.appendingPathComponent(".agentvm-clonefile-src-\(token)")
        let dstURL = directoryURL.appendingPathComponent(".agentvm-clonefile-dst-\(token)")
        defer {
            _ = Darwin.unlink(srcURL.path)
            _ = Darwin.unlink(dstURL.path)
        }
        do {
            try Data("avm-clonefile-probe".utf8).write(to: srcURL, options: .atomic)
        } catch {
            return false
        }
        let rc = Darwin.clonefile(srcURL.path, dstURL.path, 0)
        guard rc == 0 else {
            return false
        }
        return FileManager.default.fileExists(atPath: dstURL.path)
    }

    private static func currentArchName() -> String {
        #if arch(arm64)
        return "arm64"
        #elseif arch(x86_64)
        return "x86_64"
        #else
        return "unknown"
        #endif
    }
}

// MARK: - Real Virtualization.framework Configuration Translator

public struct VZConfigurationTranslator: Sendable {
    public init() {}

    /// Builds and validates a real `VZVirtualMachineConfiguration` from `VMSpec`.
    /// When `networkSocketFD` is supplied (from `UserSpaceL2Switch.createPortSocketPair`), attaches
    /// `VZFileHandleNetworkDeviceAttachment` for full user-space L2 packet capture and DPI firewalling.
    public func buildVZConfiguration(
        from spec: VMSpec,
        cloudInitISOURL: URL? = nil,
        networkSocketFD: Int32? = nil,
        serialReadPipe: Pipe? = nil,
        serialWritePipe: Pipe? = nil
    ) throws -> VZVirtualMachineConfiguration {
        let caps = HostHypervisorProbe.probeCapabilities()
        let issues = spec.validate(
            maxHostCores: caps.maxSupportedVCPUs,
            maxHostMemoryMB: caps.maxSupportedMemoryMB
        )
        if !issues.isEmpty {
            throw AgentVMError.invalidConfiguration(issues: issues)
        }

        let config = VZVirtualMachineConfiguration()
        config.cpuCount = max(
            VZVirtualMachineConfiguration.minimumAllowedCPUCount,
            min(spec.compute.vcpuCount, VZVirtualMachineConfiguration.maximumAllowedCPUCount)
        )
        let requestedBytes = spec.compute.memoryBytes
        config.memorySize = max(
            VZVirtualMachineConfiguration.minimumAllowedMemorySize,
            min(requestedBytes, VZVirtualMachineConfiguration.maximumAllowedMemorySize)
        )

        // Platform
        let platform = VZGenericPlatformConfiguration()
        config.platform = platform

        // Bootloader
        switch spec.bootLoader {
        case let .linuxKernel(vmlinuzPath, initrdPath, cmdline):
            let kernelURL = URL(fileURLWithPath: vmlinuzPath)
            guard FileManager.default.fileExists(atPath: kernelURL.path) else {
                throw AgentVMError.diskImageOperationFailed(
                    path: vmlinuzPath,
                    errnoCode: ENOENT,
                    detail: "Linux vmlinuz kernel image does not exist on disk."
                )
            }
            let loader = VZLinuxBootLoader(kernelURL: kernelURL)
            loader.commandLine = cmdline
            if let initrdPath, !initrdPath.isEmpty {
                let initrdURL = URL(fileURLWithPath: initrdPath)
                if FileManager.default.fileExists(atPath: initrdURL.path) {
                    loader.initialRamdiskURL = initrdURL
                }
            }
            config.bootLoader = loader

        case let .efiBoot(variableStorePath, createIfMissing):
            let nvramURL = URL(fileURLWithPath: variableStorePath)
            let store: VZEFIVariableStore
            if FileManager.default.fileExists(atPath: nvramURL.path) {
                store = VZEFIVariableStore(url: nvramURL)
            } else if createIfMissing {
                try FileManager.default.createDirectory(
                    at: nvramURL.deletingLastPathComponent(),
                    withIntermediateDirectories: true
                )
                store = try VZEFIVariableStore(creatingVariableStoreAt: nvramURL)
            } else {
                throw AgentVMError.diskImageOperationFailed(
                    path: variableStorePath,
                    errnoCode: ENOENT,
                    detail: "UEFI NVRAM variable store missing and createVariableStoreIfMissing == false."
                )
            }
            let efi = VZEFIBootLoader()
            efi.variableStore = store
            config.bootLoader = efi

        case let .macOSBoot(_, _, auxPath):
            #if arch(arm64)
            let loader = VZMacOSBootLoader()
            config.bootLoader = loader
            if !FileManager.default.fileExists(atPath: auxPath) {
                throw AgentVMError.diskImageOperationFailed(
                    path: auxPath,
                    errnoCode: ENOENT,
                    detail: "macOS auxiliary storage missing at \(auxPath)."
                )
            }
            #else
            throw AgentVMError.virtualizationUnsupported(reason: "macOS guests require Apple Silicon.")
            #endif
        }

        // Storage Block Devices + Cloud-Init ISO
        var storageDevices: [VZStorageDeviceConfiguration] = []
        for blk in spec.blockDevices {
            let diskURL = URL(fileURLWithPath: blk.imagePath)
            guard FileManager.default.fileExists(atPath: diskURL.path) else {
                throw AgentVMError.diskImageOperationFailed(
                    path: blk.imagePath,
                    errnoCode: ENOENT,
                    detail: "Block device image missing on disk."
                )
            }
            let caching: VZDiskImageCachingMode
            switch blk.cachingMode {
            case .automatic: caching = .automatic
            case .cached: caching = .cached
            case .uncached: caching = .uncached
            }
            let sync: VZDiskImageSynchronizationMode
            switch blk.syncMode {
            case .full: sync = .full
            case .fsyncOnly: sync = .fsync
            case .none: sync = .none
            }
            let attachment = try VZDiskImageStorageDeviceAttachment(
                url: diskURL,
                readOnly: blk.readOnly,
                cachingMode: caching,
                synchronizationMode: sync
            )
            storageDevices.append(VZVirtioBlockDeviceConfiguration(attachment: attachment))
        }

        if let cloudInitISOURL, FileManager.default.fileExists(atPath: cloudInitISOURL.path) {
            let isoAttachment = try VZDiskImageStorageDeviceAttachment(url: cloudInitISOURL, readOnly: true)
            storageDevices.append(VZVirtioBlockDeviceConfiguration(attachment: isoAttachment))
        }
        config.storageDevices = storageDevices

        // VirtioFS Shared Directories & Optional Rosetta x86_64 Translation
        var fsDevices: [VZDirectorySharingDeviceConfiguration] = []
        for mount in spec.virtioFSMounts {
            let dirURL = URL(fileURLWithPath: mount.hostDirectoryPath)
            if FileManager.default.fileExists(atPath: dirURL.path) {
                let sharedDir = VZSharedDirectory(url: dirURL, readOnly: mount.readOnly)
                let singleShare = VZSingleDirectoryShare(directory: sharedDir)
                let dev = VZVirtioFileSystemDeviceConfiguration(tag: mount.mountTag)
                dev.share = singleShare
                fsDevices.append(dev)
            }
            #if arch(arm64)
            if mount.enableRosettaLinuxBinFmt && VZLinuxRosettaDirectoryShare.availability == .installed {
                if let rosettaShare = try? VZLinuxRosettaDirectoryShare() {
                    let rosettaDev = VZVirtioFileSystemDeviceConfiguration(tag: "rosetta")
                    rosettaDev.share = rosettaShare
                    fsDevices.append(rosettaDev)
                }
            }
            #endif
        }
        config.directorySharingDevices = fsDevices

        // Network Interfaces
        var netDevices: [VZNetworkDeviceConfiguration] = []
        for (idx, nic) in spec.networkInterfaces.enumerated() {
            let vzNIC = VZVirtioNetworkDeviceConfiguration()
            if let vzMAC = VZMACAddress(string: nic.macAddress) {
                vzNIC.macAddress = vzMAC
            }
            switch nic.mode {
            case .userSpaceSwitch:
                if idx == 0, let fd = networkSocketFD, fd >= 0 {
                    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
                    vzNIC.attachment = VZFileHandleNetworkDeviceAttachment(fileHandle: handle)
                    netDevices.append(vzNIC)
                } else {
                    vzNIC.attachment = VZNATNetworkDeviceAttachment()
                    netDevices.append(vzNIC)
                }
            case .systemNAT:
                vzNIC.attachment = VZNATNetworkDeviceAttachment()
                netDevices.append(vzNIC)
            case .isolatedAirgap:
                // Zero external attachment -> air-gapped guest
                break
            }
        }
        config.networkDevices = netDevices

        // Entropy & Balloon
        if spec.compute.enableEntropyDevice {
            config.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
        }
        if spec.compute.enableBalloonDevice {
            config.memoryBalloonDevices = [VZVirtioTraditionalMemoryBalloonDeviceConfiguration()]
        }

        // VirtioSocket RPC Channel
        if spec.enableVsockDevice {
            config.socketDevices = [VZVirtioSocketDeviceConfiguration()]
        }

        // Serial Console
        if spec.serialAndDisplay.enableVirtioSerialConsole,
           let readPipe = serialReadPipe,
           let writePipe = serialWritePipe {
            let serialPort = VZVirtioConsoleDeviceSerialPortConfiguration()
            serialPort.attachment = VZFileHandleSerialPortAttachment(
                fileHandleForReading: readPipe.fileHandleForReading,
                fileHandleForWriting: writePipe.fileHandleForWriting
            )
            config.serialPorts = [serialPort]
        }

        // Optional Virtio Graphics Display
        if spec.serialAndDisplay.enableVirtioGraphics {
            let gpu = VZVirtioGraphicsDeviceConfiguration()
            gpu.scanouts = [
                VZVirtioGraphicsScanoutConfiguration(
                    widthInPixels: max(640, spec.serialAndDisplay.displayWidthPx),
                    heightInPixels: max(480, spec.serialAndDisplay.displayHeightPx)
                )
            ]
            config.graphicsDevices = [gpu]
        }

        try config.validate()
        return config
    }
}
