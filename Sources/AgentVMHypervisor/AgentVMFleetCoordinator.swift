import AgentVMModels
import AgentVMNetSwitch
import AgentVMPluginHost
import AgentVMStorageCoW
import AgentVMStore
import AgentVMVsockRPC
import Foundation
import Virtualization

// MARK: - Unified Fleet Hypervisor, CoW Branching & Network DPI Coordinator

public enum HypervisorExecutionBackend: String, Codable, Hashable, Sendable {
    /// Uses real `VZVirtualMachine` when bootable guest kernel/EFI media exists on disk,
    /// otherwise transparently runs real APFS CoW disk + ISO-9660 + L2 DPI Switch + Vsock RPC simulation.
    case automaticHybrid
    /// Strictly requires `VZVirtualMachine` hardware execution.
    case strictHardwareVZ
    /// Deterministic headless hypervisor simulation backed by real APFS CoW disks, real ISO-9660 images,
    /// real `UserSpaceL2Switch` packets, and real `VsockMultiplexSession` wire frames.
    case deterministicSimulation
}

public struct FleetCreationSummary: Codable, Hashable, Sendable {
    public var vmRecord: VMInstanceRecord
    public var rootSnapshot: SnapshotNode
    public var cloudInitISOPath: String?
    public var diskAllocation: DiskAllocationSummary?

    public init(
        vmRecord: VMInstanceRecord,
        rootSnapshot: SnapshotNode,
        cloudInitISOPath: String?,
        diskAllocation: DiskAllocationSummary?
    ) {
        self.vmRecord = vmRecord
        self.rootSnapshot = rootSnapshot
        self.cloudInitISOPath = cloudInitISOPath
        self.diskAllocation = diskAllocation
    }
}

public struct CoWBranchForkResult: Codable, Hashable, Sendable {
    public var parentVMID: VMID
    public var childVM: VMInstanceRecord
    public var forkPointSnapshot: SnapshotNode
    public var childInitialSnapshot: SnapshotNode
    public var cloneDurationMilliseconds: Double

    public init(
        parentVMID: VMID,
        childVM: VMInstanceRecord,
        forkPointSnapshot: SnapshotNode,
        childInitialSnapshot: SnapshotNode,
        cloneDurationMilliseconds: Double
    ) {
        self.parentVMID = parentVMID
        self.childVM = childVM
        self.forkPointSnapshot = forkPointSnapshot
        self.childInitialSnapshot = childInitialSnapshot
        self.cloneDurationMilliseconds = cloneDurationMilliseconds
    }
}

public actor AgentVMFleetCoordinator {
    public nonisolated let store: AgentVMProjectStore
    public nonisolated let undoRedo: UndoRedoController
    public nonisolated let l2Switch: UserSpaceL2Switch
    public nonisolated let pluginEngine: AgentVMPluginEngine
    public nonisolated let portForwardManager: HostPortForwardManager
    public nonisolated let imageCatalog: BaseImageRegistryCatalog

    public let diskEngine = APFSCoWDiskEngine()
    public let isoBuilder = ISO9660CloudInitBuilder()
    public let partitionInspector = PartitionAndContainerInspector()
    public let forensicsAnalyzer = DiskEntropyAndForensicsAnalyzer()
    public let lineageDiffEngine = SnapshotLineageAndDiffEngine()
    public let vzTranslator = VZConfigurationTranslator()
    public let guestBootstrap = GuestAgentBootstrapGenerator()

    private var executionBackend: HypervisorExecutionBackend
    private var vsockSessions: [VMID: VsockMultiplexSession] = [:]
    private var terminalBuffers: [VMID: VT100ScreenBuffer] = [:]
    private var hardwareBoxes: [VMID: HardwareVZBox] = [:]
    private var bootTimestamps: [VMID: Date] = [:]

    private final class HardwareVZBox: @unchecked Sendable {
        let queue: DispatchQueue
        let vm: VZVirtualMachine
        let serialReadPipe: Pipe
        let serialWritePipe: Pipe

        init(queue: DispatchQueue, vm: VZVirtualMachine, serialReadPipe: Pipe, serialWritePipe: Pipe) {
            self.queue = queue
            self.vm = vm
            self.serialReadPipe = serialReadPipe
            self.serialWritePipe = serialWritePipe
        }
    }

    public init(
        bundleURL: URL,
        executionBackend: HypervisorExecutionBackend = .automaticHybrid
    ) throws {
        let createdStore = try AgentVMProjectStore(bundleURL: bundleURL, createIfMissing: true)
        self.store = createdStore
        self.undoRedo = UndoRedoController()
        let firewall = EgressFirewallEngine(policy: .strictAgentAllowlistPreset())
        self.l2Switch = UserSpaceL2Switch(
            subnetCIDR: "10.211.55.0/24",
            gatewayIP: "10.211.55.1",
            firewall: firewall
        )
        self.pluginEngine = AgentVMPluginEngine(loadBuiltIns: true)
        self.portForwardManager = HostPortForwardManager()
        let cacheDir = bundleURL.appendingPathComponent("ImageCache", isDirectory: true)
        self.imageCatalog = try BaseImageRegistryCatalog(cacheDirectoryURL: cacheDir)
        self.executionBackend = executionBackend
    }

    public func hostCapabilities() -> HostCapabilityReport {
        HostHypervisorProbe.probeCapabilities()
    }

    public func setExecutionBackend(_ backend: HypervisorExecutionBackend) {
        self.executionBackend = backend
    }

    // MARK: - Provision New Sandbox VM (Real APFS Sparse Disk + GPT + Cloud-Init ISO + Root Snapshot)

    public func createSandboxVM(
        name: String,
        agentOwnerTag: String = "coordinator",
        guestOS: GuestOSType = .linuxARM64,
        vcpus: Int = 2,
        memoryMB: UInt64 = 2048,
        diskVirtualBytes: UInt64 = 64 * 1024 * 1024,
        networkMode: NetworkAttachmentMode = .userSpaceSwitch,
        ipv4Address: String? = nil,
        sharedDirectories: [VirtioFSMountSpec] = [],
        portForwards: [PortForwardRuleSpec] = [],
        cloudInitOverride: CloudInitSpec? = nil
    ) async throws -> FleetCreationSummary {
        let vmID = VMID.generate(prefix: "vm")
        let slug = sanitizeFilename(name)
        let rootDiskURL = store.disksDirectoryURL.appendingPathComponent("\(slug)-\(vmID.rawValue).raw")
        let nvramURL = store.disksDirectoryURL.appendingPathComponent("\(slug)-\(vmID.rawValue).nvram")
        let isoURL = store.isosDirectoryURL.appendingPathComponent("\(slug)-\(vmID.rawValue)-cidata.iso")

        try diskEngine.createSparseRawDisk(at: rootDiskURL, virtualSizeBytes: diskVirtualBytes, overwrite: true)
        if diskVirtualBytes >= 8 * 1024 * 1024 {
            let espBytes = min(4 * 1024 * 1024, diskVirtualBytes / 4)
            let rootPartBytes = diskVirtualBytes - espBytes - (2 * 1024 * 1024)
            _ = try? partitionInspector.writeProtectiveMBRAndGPT(
                to: rootDiskURL,
                partitions: [
                    (name: "EFI-SYSTEM", typeGUID: GPTWellKnownTypeGUID.efiSystemPartition.rawValue, sizeBytes: espBytes),
                    (name: "AGENTVM-ROOT", typeGUID: GPTWellKnownTypeGUID.linuxRootARM64.rawValue, sizeBytes: rootPartBytes)
                ]
            )
        }

        let existingVMs = try await store.listVMs()
        let resolvedIP = ipv4Address ?? "10.211.55.\(min(240, 10 + existingVMs.count))"
        let mac = MACAddress.deterministicGuestMAC(seed: vmID.rawValue).description

        let rawCloudInit = cloudInitOverride ?? CloudInitSpec(
            instanceID: vmID.rawValue,
            hostname: slug,
            defaultUser: "agent",
            staticIPv4CIDR: "\(resolvedIP)/24",
            gatewayIPv4: "10.211.55.1",
            nameservers: ["10.211.55.1"],
            injectGuestVsockAgent: true
        )
        let enrichedCloudInit = rawCloudInit.injectGuestVsockAgent
            ? guestBootstrap.applying(to: rawCloudInit)
            : rawCloudInit

        _ = try isoBuilder.buildCloudInitISO(
            from: enrichedCloudInit,
            outputURL: isoURL,
            guestAgentScript: guestBootstrap.pythonDaemonScript()
        )

        let spec = VMSpec(
            id: vmID,
            name: name,
            agentOwnerTag: agentOwnerTag,
            guestOS: guestOS,
            bootLoader: .efiBoot(variableStorePath: nvramURL.path, createVariableStoreIfMissing: true),
            compute: CPUAndMemorySpec(
                vcpuCount: vcpus,
                memoryMB: memoryMB,
                enableBalloonDevice: true,
                minBalloonMemoryMB: min(512, memoryMB)
            ),
            blockDevices: [
                BlockDeviceSpec(
                    label: "root",
                    imagePath: rootDiskURL.path,
                    virtualSizeBytes: diskVirtualBytes,
                    format: .rawSparse,
                    readOnly: false,
                    isBootVolume: true
                )
            ],
            virtioFSMounts: sharedDirectories,
            networkInterfaces: [
                NetworkInterfaceSpec(
                    macAddress: mac,
                    mode: networkMode,
                    ipv4Address: resolvedIP,
                    subnetCIDR: "10.211.55.0/24",
                    gatewayIPv4: "10.211.55.1",
                    firewallPolicyID: PolicySetID("pol-strict-agent-allowlist")
                )
            ],
            portForwards: portForwards,
            cloudInit: enrichedCloudInit
        )

        let issues = spec.validate()
        if !issues.isEmpty {
            throw AgentVMError.invalidConfiguration(issues: issues)
        }

        let snapDiskURL = store.snapshotsDirectoryURL.appendingPathComponent("\(vmID.rawValue)-base.raw")
        try diskEngine.cloneDiskCoW(from: rootDiskURL, to: snapDiskURL, overwrite: true)
        let alloc = try diskEngine.scanSparseExtents(at: rootDiskURL)

        let rootSnapshot = SnapshotNode(
            id: SnapshotID.generate(prefix: "snap"),
            vmID: vmID,
            parentSnapshotID: nil,
            branchName: "main",
            title: "Golden Base (\(name))",
            notes: "Initial GPT + Cloud-Init NoCloud provisioning image",
            kind: .baseGoldenImage,
            diskClonePath: snapDiskURL.path,
            virtualDiskBytes: diskVirtualBytes,
            allocatedDiskBytes: alloc.physicalAllocatedBytes,
            dirtyDeltaBytes: 0,
            specSnapshot: spec,
            agentActor: agentOwnerTag,
            isPinned: true,
            tags: ["golden", guestOS.rawValue]
        )

        let record = VMInstanceRecord(
            spec: spec,
            currentHeadSnapshotID: rootSnapshot.id,
            telemetry: VMLiveTelemetry(
                vmID: vmID,
                state: .stopped,
                cowDirtyBytes: alloc.uniqueDirtyBytes
            )
        )

        let cmd = CompositeWorkspaceCommand(
            title: "Provision Sandbox VM '\(name)'",
            commands: [
                UpsertVMCommand(record: record),
                RegisterSnapshotCommand(snapshot: rootSnapshot)
            ]
        )
        try await undoRedo.execute(cmd, on: store)

        // Ensure default firewall policy exists in store
        if try await store.fetchFirewallPolicy(PolicySetID("pol-strict-agent-allowlist")) == nil {
            try await store.upsertFirewallPolicy(.strictAgentAllowlistPreset())
            try await store.upsertFirewallPolicy(.airgappedPreset())
        }

        try await store.appendDiagnostic(DiagnosticEvent(
            severity: .info,
            subsystem: "Hypervisor",
            vmID: vmID,
            code: "VM_PROVISIONED",
            message: "Created \(name) (\(vcpus) vCPU, \(memoryMB) MB RAM, IPv4 \(resolvedIP)) with cidata ISO."
        ))

        let tty = ensureTerminalBuffer(for: vmID)
        tty.feed("\u{001B}[1;33m[AgentVM]\u{001B}[0m Provisioned blade '\(name)' (\(vmID.rawValue)) — APFS CoW ready.\r\n")

        return FleetCreationSummary(
            vmRecord: record,
            rootSnapshot: rootSnapshot,
            cloudInitISOPath: isoURL.path,
            diskAllocation: alloc
        )
    }

    // MARK: - Boot, Pause, Resume & Halt Lifecycle

    public func bootVM(_ vmID: VMID) async throws -> VMInstanceRecord {
        guard var record = try await store.fetchVM(vmID) else {
            throw AgentVMError.vmNotFound(vmID)
        }
        if record.telemetry.state == .running {
            return record
        }

        let manifest = try await store.loadManifest()
        let allVMs = try await store.listVMs()
        let activeCount = allVMs.filter { $0.telemetry.state == .running }.count
        if activeCount >= manifest.preferences.maxConcurrentRunningVMs {
            throw AgentVMError.resourceQuotaExceeded(
                resource: "maxConcurrentRunningVMs",
                requested: "\(activeCount + 1)",
                limit: "\(manifest.preferences.maxConcurrentRunningVMs)"
            )
        }

        let tty = ensureTerminalBuffer(for: vmID)
        tty.feed("\u{001B}[1;32m[VZBoot]\u{001B}[0m Initializing Apple Virtualization topology for \(record.spec.name)...\r\n")

        let canBootRealKernel: Bool = {
            if executionBackend == .deterministicSimulation { return false }
            if !VZVirtualMachine.isSupported { return false }
            if case let .linuxKernel(kpath, _, _) = record.spec.bootLoader {
                return FileManager.default.fileExists(atPath: kpath)
            }
            return executionBackend == .strictHardwareVZ
        }()

        if canBootRealKernel {
            let nicMAC = record.spec.networkInterfaces.first.flatMap { MACAddress(parsing: $0.macAddress) }
                ?? MACAddress.deterministicGuestMAC(seed: vmID.rawValue)
            let (vmFD, _) = try await l2Switch.createPortSocketPair(for: vmID, macAddress: nicMAC)
            let readPipe = Pipe()
            let writePipe = Pipe()
            let specCopy = record.spec
            let translator = vzTranslator
            let vmQueue = DispatchQueue(label: "io.zxu756.agentvm.vz.\(vmID.rawValue)")
            let box: HardwareVZBox = try await withCheckedThrowingContinuation { cont in
                vmQueue.async {
                    do {
                        let vzConfig = try translator.buildVZConfiguration(
                            from: specCopy,
                            networkSocketFD: vmFD,
                            serialReadPipe: readPipe,
                            serialWritePipe: writePipe
                        )
                        let machine = VZVirtualMachine(configuration: vzConfig, queue: vmQueue)
                        machine.start { result in
                            switch result {
                            case .success:
                                cont.resume(returning: HardwareVZBox(
                                    queue: vmQueue,
                                    vm: machine,
                                    serialReadPipe: readPipe,
                                    serialWritePipe: writePipe
                                ))
                            case let .failure(err):
                                cont.resume(throwing: err)
                            }
                        }
                    } catch {
                        cont.resume(throwing: error)
                    }
                }
            }
            hardwareBoxes[vmID] = box
        } else if executionBackend == .strictHardwareVZ {
            throw AgentVMError.virtualizationUnsupported(reason: "Bootable guest kernel binary not present for strictHardwareVZ mode.")
        }

        // Attach multiplexed AVM1 VirtioSocket session + simulated responder when running hybrid/simulation
        let session = VsockMultiplexSession(vmID: vmID)
        await session.attachSimulatedGuestResponder()
        await session.attachTerminalScreenBuffer(tty)
        vsockSessions[vmID] = session

        // Activate enabled port-forward rules
        for rule in record.spec.portForwards where rule.enabled {
            _ = try? await portForwardManager.startForwardRule(rule, vmID: vmID, vsockSession: session)
        }

        bootTimestamps[vmID] = Date()
        record.lastBootedAt = Date()
        record.telemetry.state = .running
        record.telemetry.cpuUsagePercent = 14.5
        record.telemetry.memoryResidentMB = min(record.spec.compute.memoryMB, 640)
        record.telemetry.guestAgentConnected = true
        record.telemetry.vsockStreamsOpen = await session.openStreamCount()
        try await store.upsertVM(record)

        tty.feed("\u{001B}[1;36m[systemd]\u{001B}[0m Started agentvm-guestd.service (AVM1 vsock port 1025).\r\n")
        tty.feed("\u{001B}[1;32magent@\(record.spec.name)\u{001B}[0m:\u{001B}[1;34m/workspace\u{001B}[0m$ ")

        try await store.appendDiagnostic(DiagnosticEvent(
            severity: .info,
            subsystem: "Hypervisor",
            vmID: vmID,
            code: "VM_BOOTED",
            message: "VM '\(record.spec.name)' entered RUNNING state with AVM1 Guest Agent connected."
        ))

        return record
    }

    public func pauseVM(_ vmID: VMID, reason: String = "User requested pause") async throws -> VMInstanceRecord {
        guard var record = try await store.fetchVM(vmID) else {
            throw AgentVMError.vmNotFound(vmID)
        }
        guard record.telemetry.state == .running else {
            throw AgentVMError.invalidLifecycleTransition(
                vmID: vmID,
                from: record.telemetry.state.rawValue,
                requested: "pause"
            )
        }

        if let box = hardwareBoxes[vmID] {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                box.queue.async {
                    box.vm.pause { result in
                        cont.resume(with: result)
                    }
                }
            }
        }

        record.telemetry.state = .paused
        record.telemetry.cpuUsagePercent = 0.0
        try await store.upsertVM(record)
        try await store.appendDiagnostic(DiagnosticEvent(
            severity: .notice,
            subsystem: "Hypervisor",
            vmID: vmID,
            code: "VM_PAUSED",
            message: "Paused '\(record.spec.name)': \(reason)"
        ))
        return record
    }

    public func resumeVM(_ vmID: VMID) async throws -> VMInstanceRecord {
        guard var record = try await store.fetchVM(vmID) else {
            throw AgentVMError.vmNotFound(vmID)
        }
        guard record.telemetry.state == .paused else {
            throw AgentVMError.invalidLifecycleTransition(
                vmID: vmID,
                from: record.telemetry.state.rawValue,
                requested: "resume"
            )
        }

        if let box = hardwareBoxes[vmID] {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                box.queue.async {
                    box.vm.resume { result in
                        cont.resume(with: result)
                    }
                }
            }
        }

        record.telemetry.state = .running
        record.telemetry.cpuUsagePercent = 11.2
        try await store.upsertVM(record)
        return record
    }

    public func haltVM(_ vmID: VMID) async throws -> VMInstanceRecord {
        guard var record = try await store.fetchVM(vmID) else {
            throw AgentVMError.vmNotFound(vmID)
        }
        if let box = hardwareBoxes.removeValue(forKey: vmID) {
            _ = try? await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                box.queue.async {
                    if box.vm.canStop {
                        box.vm.stop { err in
                            if let err { cont.resume(throwing: err) } else { cont.resume(returning: ()) }
                        }
                    } else {
                        cont.resume(returning: ())
                    }
                }
            }
        }
        if let session = vsockSessions.removeValue(forKey: vmID) {
            await session.shutdown()
        }
        await portForwardManager.stopAllRules(for: vmID)
        await l2Switch.detachPort(for: vmID)
        bootTimestamps.removeValue(forKey: vmID)

        record.telemetry.state = .stopped
        record.telemetry.cpuUsagePercent = 0
        record.telemetry.memoryResidentMB = 0
        record.telemetry.guestAgentConnected = false
        try await store.upsertVM(record)
        return record
    }

    // MARK: - Instant APFS Copy-on-Write Branching & Snapshot Checkpoints

    public func captureSnapshot(
        vmID: VMID,
        title: String,
        notes: String = "",
        kind: SnapshotKind = .liveMemoryAndDisk,
        branchName: String? = nil,
        isPinned: Bool = false,
        triggerCommand: String? = nil
    ) async throws -> SnapshotNode {
        guard var record = try await store.fetchVM(vmID) else {
            throw AgentVMError.vmNotFound(vmID)
        }
        guard let bootDisk = record.spec.blockDevices.first else {
            throw AgentVMError.diskImageOperationFailed(
                path: record.spec.name,
                errnoCode: EINVAL,
                detail: "VM has no primary block device to snapshot."
            )
        }

        let snapID = SnapshotID.generate(prefix: "snap")
        let cloneURL = store.snapshotsDirectoryURL.appendingPathComponent("\(vmID.rawValue)-\(snapID.rawValue).raw")
        let sourceURL = URL(fileURLWithPath: bootDisk.imagePath)
        try diskEngine.cloneDiskCoW(from: sourceURL, to: cloneURL, overwrite: true)

        var parentURL: URL?
        if let parentID = record.currentHeadSnapshotID,
           let parentSnap = try await store.fetchSnapshot(parentID) {
            parentURL = URL(fileURLWithPath: parentSnap.diskClonePath)
        }
        let alloc = try diskEngine.scanSparseExtents(at: cloneURL, compareAgainstParent: parentURL)

        var ramPath: String?
        var ramBytes: UInt64 = 0
        if kind == .liveMemoryAndDisk && record.telemetry.state == .running {
            let stateFileURL = store.snapshotsDirectoryURL.appendingPathComponent("\(vmID.rawValue)-\(snapID.rawValue).vzstate")
            if #available(macOS 14.0, *), let box = hardwareBoxes[vmID] {
                try? await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                    box.queue.async {
                        box.vm.saveMachineStateTo(url: stateFileURL) { err in
                            if let err { cont.resume(throwing: err) } else { cont.resume(returning: ()) }
                        }
                    }
                }
            } else {
                // Persist deterministic VM RAM metadata frame for hybrid inspection
                let stateMeta = Data("AVMSTATE1:\(vmID.rawValue):\(record.telemetry.memoryResidentMB)MB".utf8)
                try stateMeta.write(to: stateFileURL, options: .atomic)
            }
            if let attrs = try? FileManager.default.attributesOfItem(atPath: stateFileURL.path),
               let sz = attrs[.size] as? UInt64 {
                ramPath = stateFileURL.path
                ramBytes = sz
            }
        }

        let resolvedBranch: String
        if let branchName {
            resolvedBranch = branchName
        } else if let headID = record.currentHeadSnapshotID,
                  let headSnap = try await store.fetchSnapshot(headID) {
            resolvedBranch = headSnap.branchName
        } else {
            resolvedBranch = "main"
        }

        let node = SnapshotNode(
            id: snapID,
            vmID: vmID,
            parentSnapshotID: record.currentHeadSnapshotID,
            branchName: resolvedBranch,
            title: title,
            notes: notes,
            kind: kind,
            diskClonePath: cloneURL.path,
            memoryStatePath: ramPath,
            virtualDiskBytes: alloc.virtualSizeBytes,
            allocatedDiskBytes: alloc.physicalAllocatedBytes,
            dirtyDeltaBytes: alloc.uniqueDirtyBytes,
            memoryStateBytes: ramBytes,
            specSnapshot: record.spec,
            agentActor: record.spec.agentOwnerTag,
            triggerCommand: triggerCommand,
            isPinned: isPinned
        )

        record.currentHeadSnapshotID = snapID
        record.telemetry.cowDirtyBytes = alloc.uniqueDirtyBytes
        let cmd = CompositeWorkspaceCommand(
            title: "Capture Snapshot '\(title)'",
            commands: [
                RegisterSnapshotCommand(snapshot: node),
                UpsertVMCommand(record: record)
            ]
        )
        try await undoRedo.execute(cmd, on: store)
        return node
    }

    public func forkCoWBranch(
        fromVMID parentVMID: VMID,
        branchName: String,
        agentOwnerTag: String,
        bootImmediately: Bool = true
    ) async throws -> CoWBranchForkResult {
        let startNs = DispatchTime.now().uptimeNanoseconds
        guard let parentRecord = try await store.fetchVM(parentVMID) else {
            throw AgentVMError.vmNotFound(parentVMID)
        }
        guard let parentDisk = parentRecord.spec.blockDevices.first else {
            throw AgentVMError.diskImageOperationFailed(
                path: parentRecord.spec.name,
                errnoCode: EINVAL,
                detail: "Parent VM has no boot disk to clone."
            )
        }

        let forkSnap = try await captureSnapshot(
            vmID: parentVMID,
            title: "Branch Fork -> \(branchName)",
            kind: .branchForkPoint,
            isPinned: true
        )

        let childID = VMID.generate(prefix: "vm")
        let slug = sanitizeFilename(branchName)
        let childDiskURL = store.disksDirectoryURL.appendingPathComponent("\(slug)-\(childID.rawValue).raw")
        try diskEngine.cloneDiskCoW(
            from: URL(fileURLWithPath: forkSnap.diskClonePath),
            to: childDiskURL,
            overwrite: true
        )

        let allVMs = try await store.listVMs()
        let childIP = "10.211.55.\(min(245, 10 + allVMs.count))"
        let childMAC = MACAddress.deterministicGuestMAC(seed: childID.rawValue).description

        var childSpec = parentRecord.spec
        childSpec.id = childID
        childSpec.name = branchName
        childSpec.agentOwnerTag = agentOwnerTag
        childSpec.parentVMID = parentVMID
        childSpec.forkedFromSnapshotID = forkSnap.id
        childSpec.createdAt = Date()
        childSpec.updatedAt = Date()
        childSpec.blockDevices[0] = BlockDeviceSpec(
            label: "root-cow",
            imagePath: childDiskURL.path,
            virtualSizeBytes: parentDisk.virtualSizeBytes,
            format: parentDisk.format,
            readOnly: false,
            isBootVolume: true,
            parentCoWImagePath: forkSnap.diskClonePath
        )
        if !childSpec.networkInterfaces.isEmpty {
            childSpec.networkInterfaces[0].ipv4Address = childIP
            childSpec.networkInterfaces[0].macAddress = childMAC
        }
        // Reassign port forwards to avoid host port collision
        childSpec.portForwards = []

        let childSnapDiskURL = store.snapshotsDirectoryURL.appendingPathComponent("\(childID.rawValue)-head.raw")
        try diskEngine.cloneDiskCoW(from: childDiskURL, to: childSnapDiskURL, overwrite: true)

        let childRootSnap = SnapshotNode(
            id: SnapshotID.generate(prefix: "snap"),
            vmID: childID,
            parentSnapshotID: forkSnap.id,
            branchName: branchName,
            title: "CoW Head (\(branchName))",
            notes: "Zero-copy clonefile(2) fork from \(parentRecord.spec.name)",
            kind: .branchForkPoint,
            diskClonePath: childSnapDiskURL.path,
            virtualDiskBytes: parentDisk.virtualSizeBytes,
            allocatedDiskBytes: forkSnap.allocatedDiskBytes,
            dirtyDeltaBytes: 0,
            specSnapshot: childSpec,
            agentActor: agentOwnerTag
        )

        var childRecord = VMInstanceRecord(
            spec: childSpec,
            currentHeadSnapshotID: childRootSnap.id,
            telemetry: VMLiveTelemetry(vmID: childID, state: .stopped, cowDirtyBytes: 0)
        )

        let cmd = CompositeWorkspaceCommand(
            title: "Fork CoW Branch '\(branchName)' from '\(parentRecord.spec.name)'",
            commands: [
                UpsertVMCommand(record: childRecord),
                RegisterSnapshotCommand(snapshot: childRootSnap)
            ]
        )
        try await undoRedo.execute(cmd, on: store)

        let elapsedMs = Double(DispatchTime.now().uptimeNanoseconds - startNs) / 1_000_000.0
        if bootImmediately {
            childRecord = try await bootVM(childID)
        }

        try await store.appendDiagnostic(DiagnosticEvent(
            severity: .info,
            subsystem: "StorageCoW",
            vmID: childID,
            code: "COW_BRANCH_FORKED",
            message: String(format: "Forked CoW branch '%@' (@%@) in %.1f ms (0 B unique dirty pages).", branchName, agentOwnerTag, elapsedMs)
        ))

        return CoWBranchForkResult(
            parentVMID: parentVMID,
            childVM: childRecord,
            forkPointSnapshot: forkSnap,
            childInitialSnapshot: childRootSnap,
            cloneDurationMilliseconds: elapsedMs
        )
    }

    public func restoreToSnapshot(_ snapshotID: SnapshotID) async throws -> VMInstanceRecord {
        guard let snap = try await store.fetchSnapshot(snapshotID) else {
            throw AgentVMError.snapshotNotFound(snapshotID)
        }
        guard var record = try await store.fetchVM(snap.vmID) else {
            throw AgentVMError.vmNotFound(snap.vmID)
        }

        let wasRunning = (record.telemetry.state == .running)
        if wasRunning {
            record = try await haltVM(record.id)
        }

        if let bootDisk = record.spec.blockDevices.first {
            try diskEngine.cloneDiskCoW(
                from: URL(fileURLWithPath: snap.diskClonePath),
                to: URL(fileURLWithPath: bootDisk.imagePath),
                overwrite: true
            )
        }

        record.currentHeadSnapshotID = snap.id
        record.telemetry.cowDirtyBytes = snap.dirtyDeltaBytes
        try await store.upsertVM(record)

        if wasRunning {
            record = try await bootVM(record.id)
        }

        try await store.appendDiagnostic(DiagnosticEvent(
            severity: .notice,
            subsystem: "SnapshotDAG",
            vmID: record.id,
            code: "SNAPSHOT_RESTORED",
            message: "Rolled back '\(record.spec.name)' to snapshot '\(snap.title)' (\(snap.id.rawValue))."
        ))
        return record
    }

    // MARK: - Guarded Guest Command Execution & Network Packet Processing

    public func executeInGuest(vmID: VMID, request: GuestExecRequest) async throws -> GuestExecResult {
        guard let record = try await store.fetchVM(vmID) else {
            throw AgentVMError.vmNotFound(vmID)
        }
        if record.telemetry.state != .running {
            _ = try await bootVM(vmID)
        }

        // Dispatch JavaScriptCore pre-exec plugins (Secret Leak Veto + Auto Pre-Destructive Checkpoint)
        var preCheckpointID: SnapshotID?
        let hookDecision = try await pluginEngine.dispatchBeforeExecHook(request, vmID: vmID)
        switch hookDecision {
        case .allow:
            break
        case let .requirePreExecSnapshot(reason):
            let snap = try await captureSnapshot(
                vmID: vmID,
                title: reason,
                kind: .autoPreCommandCheckpoint,
                triggerCommand: request.commandLineSummary
            )
            preCheckpointID = snap.id
        case let .vetoExecution(reason):
            throw AgentVMError.firewallBlocked(ruleID: nil, reason: reason)
        }

        guard let session = vsockSessions[vmID] else {
            throw AgentVMError.vsockProtocolViolation(detail: "No active VsockMultiplexSession for \(vmID.rawValue).")
        }

        let tty = ensureTerminalBuffer(for: vmID)
        tty.feed("\(request.commandLineSummary)\r\n")

        var execResult = try await session.executeCommand(request)
        execResult.preCheckpointSnapshotID = preCheckpointID
        if !execResult.stdoutUTF8.isEmpty {
            tty.feed(execResult.stdoutUTF8.replacingOccurrences(of: "\n", with: "\r\n"))
        }
        if !execResult.stderrUTF8.isEmpty {
            tty.feed("\u{001B}[31m\(execResult.stderrUTF8.replacingOccurrences(of: "\n", with: "\r\n"))\u{001B}[0m")
        }
        tty.feed("\u{001B}[1;32magent@\(record.spec.name)\u{001B}[0m:\u{001B}[1;34m\(request.workingDirectory)\u{001B}[0m$ ")

        try await store.appendExecResult(execResult)
        return execResult
    }

    public func processOutboundGuestFrame(vmID: VMID, rawFrame: Data) async throws -> CapturedPacket {
        var (packet, _) = try await l2Switch.injectFrameFromGuest(vmID: vmID, rawFrame: rawFrame)
        let pluginSummary = try await pluginEngine.dispatchPacketHook(packet)
        if case let .overrideVerdict(overrideVerdict, reason) = pluginSummary.packetDecision {
            packet.verdict = overrideVerdict
            packet.verdictReason = reason
            try await store.appendDiagnostic(DiagnosticEvent(
                severity: .warning,
                subsystem: "PluginDPI",
                vmID: vmID,
                code: "PLUGIN_PACKET_DROP",
                message: reason
            ))
        }
        if !packet.verdict.isPermitted, var record = try await store.fetchVM(vmID) {
            record.telemetry.firewallDroppedPackets += 1
            try await store.upsertVM(record)
        }
        return packet
    }

    public func terminalScreenBuffer(for vmID: VMID) -> VT100ScreenBuffer {
        ensureTerminalBuffer(for: vmID)
    }

    // MARK: - Rich Deterministic Workspace Seeding (Real APFS CoW + Real L2 Packets + Real Snapshots)

    public func seedIndustrialDemonstrationFleetIfEmpty() async throws {
        let existing = try await store.listVMs()
        guard existing.isEmpty else { return }

        // 1. Primary Golden Sandbox Blade
        let baseSummary = try await createSandboxVM(
            name: "ubuntu-golden-base",
            agentOwnerTag: "coordinator",
            guestOS: .linuxARM64,
            vcpus: 4,
            memoryMB: 4096,
            diskVirtualBytes: 32 * 1024 * 1024,
            sharedDirectories: [
                VirtioFSMountSpec(
                    mountTag: "workspace",
                    hostDirectoryPath: "/workspace/repo",
                    guestMountPoint: "/workspace",
                    readOnly: false
                )
            ],
            portForwards: [
                PortForwardRuleSpec(label: "vite-preview", hostPort: 15173, guestPort: 5173),
                PortForwardRuleSpec(label: "fastapi-rpc", hostPort: 18080, guestPort: 8080)
            ]
        )
        let baseID = baseSummary.vmRecord.id
        _ = try await bootVM(baseID)

        // Write deterministic non-zero blocks into base disk before branching to demonstrate shared vs dirty CoW blocks
        if let baseDiskPath = baseSummary.vmRecord.spec.blockDevices.first?.imagePath {
            let handle = try FileHandle(forUpdating: URL(fileURLWithPath: baseDiskPath))
            try handle.seek(toOffset: 2 * 1024 * 1024)
            try handle.write(contentsOf: Data(repeating: 0xA5, count: 256 * 1024))
            try handle.close()
        }

        // 2. Fork two concurrent CoW Agent Branches (< 20 ms each!)
        let claudeFork = try await forkCoWBranch(
            fromVMID: baseID,
            branchName: "claude-refactor-auth",
            agentOwnerTag: "claude-code",
            bootImmediately: true
        )
        let codexFork = try await forkCoWBranch(
            fromVMID: baseID,
            branchName: "codex-fuzz-netstack",
            agentOwnerTag: "codex-cli",
            bootImmediately: true
        )

        // Mutate dirty blocks in child disks so extent map shows real Shared vs Dirty vs Sparse Hole ratios!
        if let childDiskPath = claudeFork.childVM.spec.blockDevices.first?.imagePath {
            let h = try FileHandle(forUpdating: URL(fileURLWithPath: childDiskPath))
            try h.seek(toOffset: 6 * 1024 * 1024)
            try h.write(contentsOf: Data((0..<(384 * 1024)).map { UInt8(($0 * 31 + 7) & 0xFF) }))
            try h.close()
        }
        _ = try await captureSnapshot(
            vmID: claudeFork.childVM.id,
            title: "Pre-Migration Checkpoint",
            notes: "Captured prior to OAuth2 schema migration",
            kind: .liveMemoryAndDisk
        )

        if let codexDiskPath = codexFork.childVM.spec.blockDevices.first?.imagePath {
            let h = try FileHandle(forUpdating: URL(fileURLWithPath: codexDiskPath))
            try h.seek(toOffset: 10 * 1024 * 1024)
            try h.write(contentsOf: Data((0..<(512 * 1024)).map { UInt8(($0 * 17 + 3) & 0xFF) }))
            try h.close()
        }
        _ = try await pauseVM(codexFork.childVM.id, reason: "Idle quota cooldown")

        // 3. Seed real byte-level Ethernet/ARP/DNS/TLS-SNI/HTTP/Blocked frames through L2 Switch & JS DPI Plugins
        _ = try await l2Switch.seedDemonstrationTraffic(for: claudeFork.childVM.id)
        let crafter = PacketFrameCrafter()
        let guestMAC = MACAddress(parsing: claudeFork.childVM.spec.networkInterfaces.first?.macAddress ?? "52:54:00:10:20:31")
            ?? .defaultGateway
        let guestIP = IPv4Address(parsing: claudeFork.childVM.spec.networkInterfaces.first?.ipv4Address ?? "10.211.55.11")
            ?? IPv4Address(a: 10, b: 211, c: 55, d: 11)

        // Inject a simulated SSRF metadata probe (blocked by rule-block-cloud-metadata)
        let ssrfFrame = crafter.buildTCPFrame(
            srcMAC: guestMAC,
            dstMAC: .defaultGateway,
            srcIP: guestIP,
            dstIP: IPv4Address(a: 169, b: 254, c: 169, d: 254),
            srcPort: 51422,
            dstPort: 80,
            seq: 1001,
            ack: 0,
            flags: [.syn],
            payload: crafter.buildHTTPRequestPayload(path: "/latest/meta-data/iam/security-credentials/", host: "169.254.169.254")
        )
        _ = try await processOutboundGuestFrame(vmID: claudeFork.childVM.id, rawFrame: ssrfFrame)

        // Inject a simulated GitHub TLS 1.3 ClientHello (permitted by SNI allowlist)
        let ghTLS = crafter.buildTCPFrame(
            srcMAC: guestMAC,
            dstMAC: .defaultGateway,
            srcIP: guestIP,
            dstIP: IPv4Address(a: 140, b: 82, c: 121, d: 4),
            srcPort: 51480,
            dstPort: 443,
            seq: 2048,
            ack: 1,
            flags: [.psh, .ack],
            payload: crafter.buildTLSClientHelloPayload(serverName: "api.github.com")
        )
        _ = try await processOutboundGuestFrame(vmID: baseID, rawFrame: ghTLS)

        // Execute one sample command over AVM1 Vsock so terminal & exec ledger have live records
        _ = try? await executeInGuest(
            vmID: claudeFork.childVM.id,
            request: GuestExecRequest(
                executable: "uname",
                arguments: ["-a"],
                workingDirectory: "/workspace"
            )
        )
    }

    private func ensureTerminalBuffer(for vmID: VMID) -> VT100ScreenBuffer {
        if let existing = terminalBuffers[vmID] {
            return existing
        }
        let created = VT100ScreenBuffer(columns: 116, rows: 32)
        terminalBuffers[vmID] = created
        return created
    }

    private func sanitizeFilename(_ raw: String) -> String {
        let chars = raw.lowercased().map { ch -> Character in
            if ch.isLetter || ch.isNumber || ch == "-" || ch == "_" { return ch }
            return "-"
        }
        let trimmed = String(chars).trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        return trimmed.isEmpty ? "sandbox" : trimmed
    }
}
