import AgentVMModels
import AgentVMNetSwitch
import AgentVMPluginHost
import AgentVMStorageCoW
import AgentVMStore
import AgentVMVsockRPC
import Darwin
import Foundation
import Virtualization

// MARK: - Unified Fleet Hypervisor, CoW Branching & Network DPI Coordinator

public enum HypervisorExecutionBackend: String, Codable, Hashable, Sendable {
    /// Legacy alias preserved for binary/source compatibility; behaves identically to `strictHardwareVZ`
    /// (never silently falls back to `SimulatedGuestEngine`).
    case automaticHybrid
    /// Default honest backend: requires a bootable guest OS/kernel and real `VZVirtualMachine` execution.
    case strictHardwareVZ
    /// Explicit simulation backend (`--backend simulation` or `--demo`): uses `SimulatedGuestEngine`
    /// over `VsockMultiplexSession` wire frames alongside APFS CoW disks and ISO-9660 images.
    case deterministicSimulation
}

public struct FleetCreationSummary: Codable, Hashable, Sendable {
    public var vmRecord: VMInstanceRecord
    public var rootSnapshot: SnapshotNode
    public var cloudInitISOPath: String?
    public var diskAllocation: DiskAllocationSummary?
    public var diskCloneStrategy: DiskCloneStrategyUsed

    public init(
        vmRecord: VMInstanceRecord,
        rootSnapshot: SnapshotNode,
        cloudInitISOPath: String?,
        diskAllocation: DiskAllocationSummary?,
        diskCloneStrategy: DiskCloneStrategyUsed = .apfsClonefile
    ) {
        self.vmRecord = vmRecord
        self.rootSnapshot = rootSnapshot
        self.cloudInitISOPath = cloudInitISOPath
        self.diskAllocation = diskAllocation
        self.diskCloneStrategy = diskCloneStrategy
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

    public let diskEngine: APFSCoWDiskEngine
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
        executionBackend: HypervisorExecutionBackend = .strictHardwareVZ,
        imageCacheDirectoryURL: URL? = nil,
        curatedImageEntries: [BaseImageCatalogEntry]? = nil,
        diskEngine: APFSCoWDiskEngine = APFSCoWDiskEngine()
    ) throws {
        let createdStore = try AgentVMProjectStore(bundleURL: bundleURL, createIfMissing: true)
        self.store = createdStore
        self.undoRedo = UndoRedoController()
        // `agentvm policy <preset>` persists its selection in manifest.json; a new process starts from it.
        let initialPolicy = Self.persistedActiveFirewallPolicy(manifestURL: createdStore.manifestFileURL)
            ?? .strictAgentAllowlistPreset()
        let firewall = EgressFirewallEngine(policy: initialPolicy)
        self.l2Switch = UserSpaceL2Switch(
            subnetCIDR: "10.211.55.0/24",
            gatewayIP: "10.211.55.1",
            firewall: firewall
        )
        self.pluginEngine = AgentVMPluginEngine(loadBuiltIns: true)
        self.portForwardManager = HostPortForwardManager()
        let cacheDir = (imageCacheDirectoryURL ?? BaseImageRegistryCatalog.defaultCacheDirectoryURL()).standardizedFileURL
        self.imageCatalog = try BaseImageRegistryCatalog(
            cacheDirectoryURL: cacheDir,
            curatedEntries: curatedImageEntries,
            createIfMissing: false
        )
        self.diskEngine = diskEngine
        self.executionBackend = executionBackend
    }

    public func hostCapabilities() -> HostCapabilityReport {
        HostHypervisorProbe.probeCapabilities(probeDirectoryURL: store.bundleURL)
    }

    public func currentExecutionBackend() -> HypervisorExecutionBackend {
        executionBackend
    }

    public func setExecutionBackend(_ backend: HypervisorExecutionBackend) {
        self.executionBackend = backend
    }

    private var isSimulationBackend: Bool {
        executionBackend == .deterministicSimulation
    }

    // MARK: - Simulated Runtime State Hygiene

    /// VM records as this process should report them (`ps`, `ps --json`, MCP `agentvm_list_fleet`, HTML export).
    ///
    /// Lifecycle state written by the simulation backend is stored with `telemetry.simulated == true`, so a
    /// hardware-backend process that reads it reports it as simulated. Under the simulation backend every
    /// record's runtime state is, by definition, reported by the simulator, so the flag is set on all of them.
    public func listVMsForReporting() async throws -> [VMInstanceRecord] {
        let vms = try await store.listVMs()
        guard isSimulationBackend else { return vms }
        return vms.map { record in
            var marked = record
            marked.telemetry.simulated = true
            return marked
        }
    }

    /// Loads a VM record for a lifecycle or exec operation.
    ///
    /// The hardware backend never acts on a `running` / `paused` state that only the simulator produced:
    /// such a record is reset to `stopped` (and the reset is persisted and logged) before the operation
    /// proceeds, so `up`, `exec`, `pause`, `resume`, `branch` and `restore` behave exactly as they would
    /// on a VM that was never touched by `--backend simulation`.
    private func loadVMForOperation(_ vmID: VMID) async throws -> VMInstanceRecord {
        guard let record = try await store.fetchVM(vmID) else {
            throw AgentVMError.vmNotFound(vmID)
        }
        guard !isSimulationBackend, record.telemetry.simulated else {
            return record
        }
        var reset = record
        let simulatedState = record.telemetry.state
        reset.telemetry.state = .stopped
        reset.telemetry.simulated = false
        reset.telemetry.guestAgentConnected = false
        reset.telemetry.hasLiveGuestTelemetry = false
        reset.telemetry.vsockStreamsOpen = 0
        reset.telemetry.cpuUsagePercent = 0
        reset.telemetry.memoryResidentMB = 0
        try await store.upsertVM(reset)
        try await store.appendDiagnostic(DiagnosticEvent(
            severity: .notice,
            subsystem: "Hypervisor",
            vmID: vmID,
            code: "SIMULATED_STATE_DISCARDED",
            message: "Hardware backend discarded the SIMULATED '\(simulatedState.rawValue)' state of '\(record.spec.name)' left by the simulation backend; no real guest was running. State is now 'stopped'."
        ))
        return reset
    }

    /// Stamps where a lifecycle state came from. Called every time this coordinator writes a state.
    private func stampRuntimeOrigin(_ record: inout VMInstanceRecord) {
        record.telemetry.simulated = isSimulationBackend && record.telemetry.state != .stopped
    }

    private func rejectDuplicateVMName(_ name: String) async throws {
        let existing = try await store.listVMs()
        if let clash = existing.first(where: { $0.spec.name.caseInsensitiveCompare(name) == .orderedSame }) {
            throw AgentVMError.vmNameAlreadyExists(name: name, existingID: clash.id)
        }
    }

    // MARK: - Firewall Policy Preset Selection (persisted)

    private static func persistedActiveFirewallPolicy(manifestURL: URL) -> FirewallPolicySet? {
        guard let data = try? Data(contentsOf: manifestURL),
              let manifest = try? JSONDecoder().decode(AgentVMProjectManifest.self, from: data),
              let policyID = manifest.activeFirewallPolicyID else {
            return nil
        }
        return FirewallPolicySet.builtInPreset(id: policyID)
    }

    /// Selects `policy` for this workspace: the in-process firewall engine switches to it and the selection is
    /// written to `manifest.json`, so the next process (CLI, MCP, UI) starts from the same preset.
    /// Until guest NICs are attached to the user-space switch (M5) no guest traffic passes through this engine.
    public func activateFirewallPolicy(_ policy: FirewallPolicySet) async throws {
        var manifest = try await store.loadManifest()
        manifest.activeFirewallPolicyID = policy.id
        manifest.updatedAt = Date()
        try await store.saveManifest(manifest)
        await l2Switch.firewall.updatePolicy(policy)
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
        try await rejectDuplicateVMName(name)
        let vmID = VMID.generate(prefix: "vm")
        let slug = sanitizeFilename(name)
        let rootDiskURL = store.disksDirectoryURL.appendingPathComponent("\(slug)-\(vmID.rawValue).raw")
        let nvramURL = store.disksDirectoryURL.appendingPathComponent("\(slug)-\(vmID.rawValue).nvram")
        let machineIDURL = store.disksDirectoryURL.appendingPathComponent("\(slug)-\(vmID.rawValue).machineid")
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

        _ = try VZEFIVariableStore(creatingVariableStoreAt: nvramURL)
        let machineID = VZGenericMachineIdentifier()
        try machineID.dataRepresentation.write(to: machineIDURL, options: [.atomic])

        let existingVMs = try await store.listVMs()
        let resolvedIP = ipv4Address ?? "10.211.55.\(min(240, 10 + existingVMs.count))"
        let mac = MACAddress.deterministicGuestMAC(seed: vmID.rawValue).description

        let rawCloudInit = cloudInitOverride ?? CloudInitSpec(
            instanceID: vmID.rawValue,
            hostname: slug,
            defaultUser: "agent",
            staticIPv4CIDR: ipv4Address.map { "\($0)/24" },
            gatewayIPv4: ipv4Address == nil ? nil : "10.211.55.1",
            nameservers: ipv4Address == nil ? [] : ["10.211.55.1"],
            injectGuestVsockAgent: true
        )
        let enrichedCloudInit = rawCloudInit.injectGuestVsockAgent
            ? guestBootstrap.applying(to: rawCloudInit, includePythonAptPackage: false)
            : rawCloudInit

        _ = try isoBuilder.buildCloudInitISO(
            from: enrichedCloudInit,
            outputURL: isoURL
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
            cloudInit: enrichedCloudInit,
            machineIdentifierPath: machineIDURL.path,
            cloudInitISOPath: isoURL.path
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

    // MARK: - Provision New VM from Verified Cached Base Image (M1: clonefile + ftruncate + NAT/DHCP + Persistent Identity)

    public func createVMFromImage(
        name: String,
        imageID: String,
        requestedDiskBytes: UInt64? = nil,
        agentOwnerTag: String = "coordinator",
        vcpus: Int = 2,
        memoryMB: UInt64 = 2048,
        sharedDirectories: [VirtioFSMountSpec] = [],
        portForwards: [PortForwardRuleSpec] = [],
        cloudInitOverride: CloudInitSpec? = nil
    ) async throws -> FleetCreationSummary {
        try await rejectDuplicateVMName(name)

        // 1. Strict offline cache & index stat verification (never downloads, never touches network)
        let cachedImageURL = try await imageCatalog.verifiedCachedImageURL(forID: imageID)
        guard let imageEntry = await imageCatalog.entry(forID: imageID) else {
            let allIDs = await imageCatalog.allEntries().map(\.id)
            throw AgentVMError.baseImageError(imageID: imageID, reason: .unknownImage(availableIDs: allIDs))
        }

        var cachedStat = Darwin.stat()
        guard stat(cachedImageURL.path, &cachedStat) == 0,
              (cachedStat.st_mode & S_IFMT) == S_IFREG else {
            throw AgentVMError.baseImageError(imageID: imageID, reason: .missingFromCache)
        }
        let imageBytes = UInt64(max(0, cachedStat.st_size))

        // 2. Validate --disk-size before creating ANY file in workspace
        if let requestedDiskBytes, requestedDiskBytes < imageBytes {
            throw AgentVMError.diskSizeTooSmallForImage(
                imageID: imageID,
                requestedBytes: requestedDiskBytes,
                imageBytes: imageBytes
            )
        }
        let targetDiskBytes = requestedDiskBytes ?? imageBytes

        let vmID = VMID.generate(prefix: "vm")
        let slug = sanitizeFilename(name)
        let rootDiskURL = store.disksDirectoryURL.appendingPathComponent("\(slug)-\(vmID.rawValue).raw")
        let nvramURL = store.disksDirectoryURL.appendingPathComponent("\(slug)-\(vmID.rawValue).nvram")
        let machineIDURL = store.disksDirectoryURL.appendingPathComponent("\(slug)-\(vmID.rawValue).machineid")
        let isoURL = store.isosDirectoryURL.appendingPathComponent("\(slug)-\(vmID.rawValue)-cidata.iso")
        let snapDiskURL = store.snapshotsDirectoryURL.appendingPathComponent("\(vmID.rawValue)-base.raw")

        guard rootDiskURL.standardizedFileURL != cachedImageURL.standardizedFileURL else {
            throw AgentVMError.diskImageOperationFailed(
                path: rootDiskURL.path,
                errnoCode: EINVAL,
                detail: "Refusing to attach cached base image directly as a VM disk."
            )
        }

        let randomMAC = VZMACAddress.randomLocallyAdministered().string
        let mac = MACAddress(parsing: randomMAC) != nil
            ? randomMAC
            : MACAddress.deterministicGuestMAC(seed: vmID.rawValue).description

        let rawCloudInit = cloudInitOverride ?? CloudInitSpec(
            instanceID: vmID.rawValue,
            hostname: slug,
            defaultUser: "agent",
            passwordHash: nil,
            sshAuthorizedKeys: [],
            aptPackages: [],
            staticIPv4CIDR: nil,
            gatewayIPv4: nil,
            nameservers: [],
            injectGuestVsockAgent: true
        )
        let enrichedCloudInit = rawCloudInit.injectGuestVsockAgent
            ? guestBootstrap.applying(to: rawCloudInit, includePythonAptPackage: false)
            : rawCloudInit

        let spec = VMSpec(
            id: vmID,
            name: name,
            agentOwnerTag: agentOwnerTag,
            guestOS: imageEntry.guestOS,
            bootLoader: .efiBoot(variableStorePath: nvramURL.path, createVariableStoreIfMissing: false),
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
                    virtualSizeBytes: targetDiskBytes,
                    format: .rawSparse,
                    readOnly: false,
                    isBootVolume: true
                )
            ],
            virtioFSMounts: sharedDirectories,
            networkInterfaces: [
                NetworkInterfaceSpec(
                    macAddress: mac,
                    mode: .systemNAT,
                    ipv4Address: "dhcp",
                    subnetCIDR: "",
                    gatewayIPv4: "",
                    dnsServers: [],
                    firewallPolicyID: PolicySetID("pol-strict-agent-allowlist")
                )
            ],
            portForwards: portForwards,
            cloudInit: enrichedCloudInit,
            machineIdentifierPath: machineIDURL.path,
            cloudInitISOPath: isoURL.path,
            baseImageID: imageEntry.id
        )

        let preflightIssues = spec.validate()
        if !preflightIssues.isEmpty {
            throw AgentVMError.invalidConfiguration(issues: preflightIssues)
        }

        // 3. Materialize cloned root disk, ftruncate expansion, NVRAM, machine-id, cidata ISO, and base snapshot atomically
        var committed = false
        let workspaceArtifacts = [rootDiskURL, nvramURL, machineIDURL, isoURL, snapDiskURL]
        defer {
            if !committed {
                for url in workspaceArtifacts {
                    _ = Darwin.chmod(url.path, 0o644)
                    try? FileManager.default.removeItem(at: url)
                }
            }
        }

        let cloneStrategy = try diskEngine.cloneDiskCoWReportingStrategy(
            from: cachedImageURL,
            to: rootDiskURL,
            overwrite: true
        )
        guard Darwin.chmod(rootDiskURL.path, 0o644) == 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: rootDiskURL.path,
                errnoCode: err,
                detail: "Failed making cloned root disk writable (0644)."
            )
        }
        if targetDiskBytes > imageBytes {
            try diskEngine.resizeSparseRawDisk(
                at: rootDiskURL,
                newSizeBytes: targetDiskBytes,
                allowShrink: false
            )
        }

        try FileManager.default.createDirectory(
            at: nvramURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        _ = try VZEFIVariableStore(creatingVariableStoreAt: nvramURL)

        let machineID = VZGenericMachineIdentifier()
        do {
            try machineID.dataRepresentation.write(to: machineIDURL, options: [.atomic])
        } catch {
            throw AgentVMError.diskImageOperationFailed(
                path: machineIDURL.path,
                errnoCode: Darwin.errno,
                detail: "Failed persisting VZGenericMachineIdentifier: \(error.localizedDescription)"
            )
        }

        _ = try isoBuilder.buildCloudInitISO(
            from: enrichedCloudInit,
            outputURL: isoURL
        )

        try diskEngine.cloneDiskCoW(from: rootDiskURL, to: snapDiskURL, overwrite: true)
        let alloc = try diskEngine.scanSparseExtents(at: rootDiskURL)

        let rootSnapshot = SnapshotNode(
            id: SnapshotID.generate(prefix: "snap"),
            vmID: vmID,
            parentSnapshotID: nil,
            branchName: "main",
            title: "Golden Base (\(name))",
            notes: "Cloned from verified base image '\(imageEntry.id)'",
            kind: .baseGoldenImage,
            diskClonePath: snapDiskURL.path,
            virtualDiskBytes: targetDiskBytes,
            allocatedDiskBytes: alloc.physicalAllocatedBytes,
            dirtyDeltaBytes: 0,
            specSnapshot: spec,
            agentActor: agentOwnerTag,
            isPinned: true,
            tags: ["golden", imageEntry.id, imageEntry.guestOS.rawValue]
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
            title: "Provision VM '\(name)' from image '\(imageEntry.id)'",
            commands: [
                UpsertVMCommand(record: record),
                RegisterSnapshotCommand(snapshot: rootSnapshot)
            ]
        )
        try await undoRedo.execute(cmd, on: store)

        if try await store.fetchFirewallPolicy(PolicySetID("pol-strict-agent-allowlist")) == nil {
            try await store.upsertFirewallPolicy(.strictAgentAllowlistPreset())
            try await store.upsertFirewallPolicy(.airgappedPreset())
        }

        try await store.appendDiagnostic(DiagnosticEvent(
            severity: .info,
            subsystem: "Hypervisor",
            vmID: vmID,
            code: "VM_PROVISIONED_FROM_IMAGE",
            message: "Created \(name) from image '\(imageEntry.id)' (\(vcpus) vCPU, \(memoryMB) MB RAM, disk \(targetDiskBytes) B, clone=\(cloneStrategy.rawValue), system NAT + DHCP)."
        ))

        let tty = ensureTerminalBuffer(for: vmID)
        tty.feed("\u{001B}[1;33m[AgentVM]\u{001B}[0m Provisioned blade '\(name)' (\(vmID.rawValue)) from image '\(imageEntry.id)'.\r\n")

        committed = true
        return FleetCreationSummary(
            vmRecord: record,
            rootSnapshot: rootSnapshot,
            cloudInitISOPath: isoURL.path,
            diskAllocation: alloc,
            diskCloneStrategy: cloneStrategy
        )
    }

    // MARK: - Boot, Pause, Resume & Halt Lifecycle

    public func bootVM(_ vmID: VMID) async throws -> VMInstanceRecord {
        var record = try await loadVMForOperation(vmID)
        if record.telemetry.state == .running {
            if isSimulationBackend && !record.telemetry.simulated {
                // A `running` record the simulator is asked to drive is simulated from here on; say so in the store.
                record.telemetry.simulated = true
                try await store.upsertVM(record)
            }
            return record
        }

        let manifest = try await store.loadManifest()
        let allVMs = try await store.listVMs()
        // Simulated `running` records never count against a hardware-backend quota.
        let activeCount = allVMs.filter {
            $0.telemetry.state == .running && (isSimulationBackend || !$0.telemetry.simulated)
        }.count
        if activeCount >= manifest.preferences.maxConcurrentRunningVMs {
            throw AgentVMError.resourceQuotaExceeded(
                resource: "maxConcurrentRunningVMs",
                requested: "\(activeCount + 1)",
                limit: "\(manifest.preferences.maxConcurrentRunningVMs)"
            )
        }

        let tty = ensureTerminalBuffer(for: vmID)

        if executionBackend == .deterministicSimulation {
            let session = VsockMultiplexSession(vmID: vmID)
            await session.attachSimulatedGuestResponder()
            await session.attachTerminalScreenBuffer(tty)
            vsockSessions[vmID] = session

            for rule in record.spec.portForwards where rule.enabled {
                _ = try? await portForwardManager.startForwardRule(rule, vmID: vmID, vsockSession: session)
            }

            bootTimestamps[vmID] = Date()
            record.lastBootedAt = Date()
            record.telemetry.state = .running
            record.telemetry.cpuUsagePercent = 0.0
            record.telemetry.memoryResidentMB = 0
            record.telemetry.hasLiveGuestTelemetry = false
            record.telemetry.guestAgentConnected = true
            record.telemetry.vsockStreamsOpen = await session.openStreamCount()
            stampRuntimeOrigin(&record)
            try await store.upsertVM(record)

            tty.feed("[SIMULATED] Deterministic host-side simulation responder attached for \(record.spec.name).\r\n")
            tty.feed("\u{001B}[1;32magent@\(record.spec.name)\u{001B}[0m:\u{001B}[1;34m/workspace\u{001B}[0m$ ")

            try await store.appendDiagnostic(DiagnosticEvent(
                severity: .info,
                subsystem: "Hypervisor",
                vmID: vmID,
                code: "VM_BOOTED_SIMULATED",
                message: "[SIMULATED] VM '\(record.spec.name)' entered simulated RUNNING state."
            ))
            return record
        }

        try verifyBootableGuestSystem(for: record.spec)

        guard VZVirtualMachine.isSupported else {
            throw AgentVMError.virtualizationUnsupported(
                reason: "VZVirtualMachine.isSupported returned false (this host cannot run Virtualization.framework guests)."
            )
        }
        guard HostHypervisorProbe.currentProcessHasBooleanEntitlement(HostHypervisorProbe.virtualizationEntitlementKey) else {
            throw AgentVMError.virtualizationEntitlementMissing
        }

        let nicMAC = record.spec.networkInterfaces.first.flatMap { MACAddress(parsing: $0.macAddress) }
            ?? MACAddress.deterministicGuestMAC(seed: vmID.rawValue)
        let (vmFD, _) = try await l2Switch.createPortSocketPair(for: vmID, macAddress: nicMAC)
        let readPipe = Pipe()
        let writePipe = Pipe()
        let specCopy = record.spec
        let translator = vzTranslator
        let vmQueue = DispatchQueue(label: "io.zxu756.agentvm.vz.\(vmID.rawValue)")
        let box: HardwareVZBox
        do {
            box = try await withCheckedThrowingContinuation { cont in
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
        } catch {
            await l2Switch.detachPort(for: vmID)
            throw error
        }
        hardwareBoxes[vmID] = box
        tty.feed("[VZBoot] Started Apple Virtualization.framework guest '\(record.spec.name)'.\r\n")

        bootTimestamps[vmID] = Date()
        record.lastBootedAt = Date()
        record.telemetry.state = .running
        record.telemetry.cpuUsagePercent = 0.0
        record.telemetry.memoryResidentMB = 0
        record.telemetry.hasLiveGuestTelemetry = false
        record.telemetry.guestAgentConnected = false
        record.telemetry.vsockStreamsOpen = 0
        stampRuntimeOrigin(&record)
        try await store.upsertVM(record)

        try await store.appendDiagnostic(DiagnosticEvent(
            severity: .info,
            subsystem: "Hypervisor",
            vmID: vmID,
            code: "VM_BOOTED",
            message: "Booted VM '\(record.spec.name)' via Virtualization.framework."
        ))

        return record
    }

    private func verifyBootableGuestSystem(for spec: VMSpec) throws {
        switch spec.bootLoader {
        case .linuxKernel(let vmlinuzPath, _, _):
            let trimmed = vmlinuzPath.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, FileManager.default.fileExists(atPath: trimmed) else {
                throw AgentVMError.noBootableSystem(
                    vmName: spec.name,
                    reason: .kernelImageMissing(path: trimmed)
                )
            }
        case .macOSBoot(let hardwareModelPath, _, let auxiliaryStoragePath):
            guard FileManager.default.fileExists(atPath: auxiliaryStoragePath),
                  FileManager.default.fileExists(atPath: hardwareModelPath) else {
                throw AgentVMError.noBootableSystem(
                    vmName: spec.name,
                    reason: .macOSBootArtifactsMissing
                )
            }
        case .efiBoot:
            guard let bootDisk = spec.blockDevices.first(where: \.isBootVolume) ?? spec.blockDevices.first else {
                throw AgentVMError.noBootableSystem(
                    vmName: spec.name,
                    reason: .noBootDeviceConfigured
                )
            }
            let diskURL = URL(fileURLWithPath: bootDisk.imagePath)
            guard FileManager.default.fileExists(atPath: diskURL.path) else {
                throw AgentVMError.noBootableSystem(
                    vmName: spec.name,
                    reason: .bootDiskImageMissing(fileName: diskURL.lastPathComponent)
                )
            }
            let forensics = try forensicsAnalyzer.analyzeDiskImage(at: diskURL, maxHeatmapSamples: 1)
            if forensics.detectedFilesystems.isEmpty {
                throw AgentVMError.noBootableSystem(
                    vmName: spec.name,
                    reason: .emptyPartitionTable(fileName: diskURL.lastPathComponent)
                )
            }
        }
    }

    public func pauseVM(_ vmID: VMID, reason: String = "User requested pause") async throws -> VMInstanceRecord {
        var record = try await loadVMForOperation(vmID)
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
        stampRuntimeOrigin(&record)
        try await store.upsertVM(record)
        try await store.appendDiagnostic(DiagnosticEvent(
            severity: .notice,
            subsystem: "Hypervisor",
            vmID: vmID,
            code: isSimulationBackend ? "VM_PAUSED_SIMULATED" : "VM_PAUSED",
            message: "\(isSimulationBackend ? "[SIMULATED] " : "")Paused '\(record.spec.name)': \(reason)"
        ))
        return record
    }

    public func resumeVM(_ vmID: VMID) async throws -> VMInstanceRecord {
        var record = try await loadVMForOperation(vmID)
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
        stampRuntimeOrigin(&record)
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
        record.telemetry.hasLiveGuestTelemetry = false
        record.telemetry.guestAgentConnected = false
        record.telemetry.vsockStreamsOpen = 0
        stampRuntimeOrigin(&record)
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
        var record = try await loadVMForOperation(vmID)
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
            }
            // The simulation backend has no guest RAM. It records a disk-only snapshot and writes no
            // placeholder memory-state file, so nothing simulated ends up in the snapshot lineage.
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

        // "Live RAM + Disk" is recorded only when a guest memory state was actually saved. A request for it
        // on a stopped VM, or under the simulator, yields a disk snapshot and is labelled as one.
        let recordedKind: SnapshotKind = (kind == .liveMemoryAndDisk && ramPath == nil) ? .coldDiskOnly : kind

        let node = SnapshotNode(
            id: snapID,
            vmID: vmID,
            parentSnapshotID: record.currentHeadSnapshotID,
            branchName: resolvedBranch,
            title: title,
            notes: notes,
            kind: recordedKind,
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
        let parentRecord = try await loadVMForOperation(parentVMID)
        try await rejectDuplicateVMName(branchName)
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
        let childNvramURL = store.disksDirectoryURL.appendingPathComponent("\(slug)-\(childID.rawValue).nvram")
        if case let .efiBoot(parentNvramPath, _) = parentRecord.spec.bootLoader {
            if FileManager.default.fileExists(atPath: parentNvramPath) {
                try diskEngine.cloneDiskCoW(
                    from: URL(fileURLWithPath: parentNvramPath),
                    to: childNvramURL,
                    overwrite: true
                )
            } else {
                _ = try VZEFIVariableStore(creatingVariableStoreAt: childNvramURL)
            }
            childSpec.bootLoader = .efiBoot(variableStorePath: childNvramURL.path, createVariableStoreIfMissing: true)
        }
        let childMachineIDURL = store.disksDirectoryURL.appendingPathComponent("\(slug)-\(childID.rawValue).machineid")
        try VZGenericMachineIdentifier().dataRepresentation.write(to: childMachineIDURL, options: [.atomic])
        childSpec.machineIdentifierPath = childMachineIDURL.path
        if !childSpec.networkInterfaces.isEmpty {
            if childSpec.networkInterfaces[0].mode == .systemNAT {
                childSpec.networkInterfaces[0].ipv4Address = "dhcp"
            } else {
                childSpec.networkInterfaces[0].ipv4Address = childIP
            }
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
        var record = try await loadVMForOperation(snap.vmID)

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
        var record = try await loadVMForOperation(vmID)
        if record.telemetry.state != .running {
            _ = try await bootVM(vmID)
        } else if executionBackend == .deterministicSimulation && vsockSessions[vmID] == nil {
            // Only the explicit simulation backend may answer with the simulated responder. A `running`
            // record under the hardware backend with no live session falls through to ERR_GUEST_AGENT_UNAVAILABLE.
            let tty = ensureTerminalBuffer(for: vmID)
            let session = VsockMultiplexSession(vmID: vmID)
            await session.attachSimulatedGuestResponder()
            await session.attachTerminalScreenBuffer(tty)
            vsockSessions[vmID] = session
            if !record.telemetry.simulated {
                record.telemetry.simulated = true
                try await store.upsertVM(record)
            }
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
            throw AgentVMError.guestAgentNotConnected(
                vmName: record.spec.name,
                state: record.telemetry.state.rawValue
            )
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

        // The exec ledger is read by every backend. A simulated result is stored with the marker in the
        // command line itself, the one field every ledger view prints.
        var ledgerEntry = execResult
        if isSimulationBackend {
            ledgerEntry.commandLine = "[SIMULATED] \(execResult.commandLine)"
        }
        try await store.appendExecResult(ledgerEntry)
        return execResult
    }

    public func processOutboundGuestFrame(
        vmID: VMID,
        rawFrame: Data,
        syntheticOriginLabel: String? = nil
    ) async throws -> CapturedPacket {
        var (packet, _) = try await l2Switch.injectFrameFromGuest(
            vmID: vmID,
            rawFrame: rawFrame,
            syntheticOriginLabel: syntheticOriginLabel
        )
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
        var manifest = try await store.loadManifest()
        if !manifest.isDemonstrationWorkspace {
            manifest.isDemonstrationWorkspace = true
            try await store.saveManifest(manifest)
        }

        let existing = try await store.listVMs()
        guard existing.isEmpty else { return }

        let previousBackend = executionBackend
        executionBackend = .deterministicSimulation
        defer { executionBackend = previousBackend }

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

        // 2. Fork two concurrent CoW Agent Branches (demo topology)
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
