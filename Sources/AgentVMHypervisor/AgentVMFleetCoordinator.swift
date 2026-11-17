import AgentVMModels
import AgentVMNetSwitch
import AgentVMPluginHost
import AgentVMStorageCoW
import AgentVMStore
import AgentVMVsockRPC
import Darwin
import Foundation
import Virtualization

@_silgen_name("flock")
private func c_posix_flock(_ fd: Int32, _ operation: Int32) -> Int32

// MARK: - Per-VM Non-Blocking POSIX File Lock (flock)

/// Exclusive non-blocking per-VM file lock (`flock(fd, LOCK_EX | LOCK_NB)`) stored at `<workspace>/locks/<vmID>.lock`.
/// Because BSD `flock(2)` is bound to the kernel open file description (`struct fileglob`), opening two descriptors in the
/// same or separate processes genuinely contends with `EWOULDBLOCK`, and kernel descriptor teardown on process exit
/// (including `SIGKILL` / `kill -9`) releases the lock automatically.
public final class VMExecutionLock: @unchecked Sendable {
    public let lockFileURL: URL
    private let stateLock = NSLock()
    private var fd: Int32

    private init(lockFileURL: URL, fd: Int32) {
        self.lockFileURL = lockFileURL
        self.fd = fd
    }

    deinit {
        release()
    }

    public static func acquire(at lockFileURL: URL, vmName: String) throws -> VMExecutionLock {
        let standardized = lockFileURL.standardizedFileURL
        let parentDir = standardized.deletingLastPathComponent()
        do {
            try FileManager.default.createDirectory(at: parentDir, withIntermediateDirectories: true)
        } catch {
            throw AgentVMError.diskImageOperationFailed(
                path: parentDir.path,
                errnoCode: Darwin.errno,
                detail: "Unable to create locks directory: \(error.localizedDescription)"
            )
        }

        let fd = Darwin.open(standardized.path, O_CREAT | O_RDWR | O_CLOEXEC, 0o644)
        guard fd >= 0 else {
            throw AgentVMError.diskImageOperationFailed(
                path: standardized.path,
                errnoCode: Darwin.errno,
                detail: "Unable to open VM lock file."
            )
        }

        if posixFlock(fd, LOCK_EX | LOCK_NB) != 0 {
            let errCode = Darwin.errno
            if errCode == EWOULDBLOCK || errCode == EAGAIN {
                var holderPID = readHolderPID(fromFD: fd)
                var attempts = 0
                while holderPID == nil && attempts < 10 {
                    Darwin.usleep(5_000)
                    holderPID = readHolderPID(fromFD: fd)
                    attempts += 1
                }
                _ = Darwin.close(fd)
                throw AgentVMError.vmBusy(vmName: vmName, holderPID: holderPID)
            }
            _ = Darwin.close(fd)
            throw AgentVMError.diskImageOperationFailed(
                path: standardized.path,
                errnoCode: errCode,
                detail: "flock(LOCK_EX | LOCK_NB) failed."
            )
        }

        let ownerStamp = Data("pid=\(Darwin.getpid())\nvm=\(vmName)\n".utf8)
        ownerStamp.withUnsafeBytes { rawBuf in
            if let base = rawBuf.baseAddress {
                _ = Darwin.pwrite(fd, base, rawBuf.count, 0)
            }
        }
        _ = Darwin.ftruncate(fd, off_t(ownerStamp.count))

        return VMExecutionLock(lockFileURL: standardized, fd: fd)
    }

    /// Lock-free liveness probe (Fixes A45): reads the recorded holder PID without calling `flock`,
    /// then checks process existence via `kill(pid, 0)` so frequent `ps` / reconciliation probes
    /// never contend with `VMExecutionLock.acquire`.
    public static func isLocked(at lockFileURL: URL) -> Bool {
        readLiveHolderPID(at: lockFileURL) != nil
    }

    public static func readLiveHolderPID(at lockFileURL: URL) -> Int32? {
        let standardized = lockFileURL.standardizedFileURL
        let probeFD = Darwin.open(standardized.path, O_RDONLY | O_CLOEXEC)
        guard probeFD >= 0 else {
            return nil
        }
        defer { _ = Darwin.close(probeFD) }

        let (parsedPID, bytesRead) = readHolderPIDAndByteCount(fromFD: probeFD)
        let candidatePID: Int32?
        if let parsedPID {
            candidatePID = parsedPID
        } else if bytesRead > 0 {
            Darwin.usleep(1_000)
            candidatePID = readHolderPIDAndByteCount(fromFD: probeFD).pid
        } else {
            candidatePID = nil
        }

        guard let pid = candidatePID, pid > 0 else {
            return nil
        }
        if pid == Darwin.getpid() {
            return pid
        }
        if Darwin.kill(pid, 0) == 0 {
            return pid
        }
        if Darwin.errno == EPERM {
            return pid
        }
        return nil
    }

    public func release() {
        let descriptorToClose = stateLock.withLock { () -> Int32 in
            let current = fd
            fd = -1
            return current
        }
        guard descriptorToClose >= 0 else { return }
        _ = Darwin.ftruncate(descriptorToClose, 0)
        _ = Self.posixFlock(descriptorToClose, LOCK_UN)
        _ = Darwin.close(descriptorToClose)
    }

    private static func posixFlock(_ fd: Int32, _ operation: Int32) -> Int32 {
        c_posix_flock(fd, operation)
    }

    private static func readHolderPID(fromFD fd: Int32) -> Int32? {
        readHolderPIDAndByteCount(fromFD: fd).pid
    }

    private static func readHolderPIDAndByteCount(fromFD fd: Int32) -> (pid: Int32?, bytesRead: Int) {
        var scratch = [UInt8](repeating: 0, count: 256)
        let n = Darwin.pread(fd, &scratch, scratch.count, 0)
        guard n > 0 else { return (nil, 0) }
        let text = String(decoding: scratch.prefix(n), as: UTF8.self)
        for line in text.split(whereSeparator: \.isNewline) {
            if line.hasPrefix("pid=") {
                let rawPID = line.dropFirst("pid=".count).trimmingCharacters(in: .whitespaces)
                if let parsed = Int32(rawPID), parsed > 0 {
                    return (parsed, n)
                }
            }
        }
        return (nil, n)
    }
}

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

public struct HardwareVsockFDDescriptor: Sendable {
    public var fileDescriptor: Int32
    public var closeWhenSessionEnds: Bool

    public init(fileDescriptor: Int32, closeWhenSessionEnds: Bool = false) {
        self.fileDescriptor = fileDescriptor
        self.closeWhenSessionEnds = closeWhenSessionEnds
    }
}

public protocol HardwareVMInstanceHandle: Sendable {
    func prematureStopReason() -> String?
    func connectVsock(port: UInt32) async throws -> HardwareVsockFDDescriptor
    func closeVsockConnection() async
    func pause() async throws
    func resume() async throws
    func saveMachineState(to url: URL) async throws
    func shutdown(gracefulTimeoutNanoseconds: UInt64) async
}

public protocol HardwareVMLowLevelBackend: Sendable {
    func startMachine(
        spec: VMSpec,
        networkSocketFD: Int32?,
        consoleLogURL: URL,
        translator: VZConfigurationTranslator
    ) async throws -> any HardwareVMInstanceHandle
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

    public nonisolated let isWorkspaceDaemon: Bool
    private let hardwareBackend: any HardwareVMLowLevelBackend
    private let vsockConnectTimeoutNanoseconds: UInt64
    private let vsockRetryIntervalNanoseconds: UInt64
    private let gracefulStopTimeoutNanoseconds: UInt64

    private var executionBackend: HypervisorExecutionBackend
    private var vsockSessions: [VMID: VsockMultiplexSession] = [:]
    private var terminalBuffers: [VMID: VT100ScreenBuffer] = [:]
    private var hardwareBoxes: [VMID: any HardwareVMInstanceHandle] = [:]
    private var bootTimestamps: [VMID: Date] = [:]
    private var heldExecutionLocks: [VMID: VMExecutionLock] = [:]
    private var activeOneShotLocks: Set<VMID> = []
    private var inFlightHardwareBoots: Set<VMID> = []
    private var vmLifecycleTails: [UUID: Task<Void, Never>] = [:]
    private var vmLifecycleQueueHeads: [VMID: UUID] = [:]

    private final class HardwareVZBox: NSObject, VZVirtualMachineDelegate, HardwareVMInstanceHandle, @unchecked Sendable {
        let queue: DispatchQueue
        var vm: VZVirtualMachine?
        var vsockConnection: VZVirtioSocketConnection?

        private let stateLock = NSLock()
        private var stopReasonStorage: String?
        private var stopWaiters: [UUID: CheckedContinuation<String?, Never>] = [:]

        init(queue: DispatchQueue, vm: VZVirtualMachine? = nil) {
            self.queue = queue
            self.vm = vm
        }

        func guestDidStop(_ virtualMachine: VZVirtualMachine) {
            recordStop(reason: "guestDidStop")
        }

        func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
            recordStop(reason: "didStopWithError: \(error.localizedDescription)")
        }

        private func recordStop(reason: String) {
            let waiters = stateLock.withLock { () -> [CheckedContinuation<String?, Never>] in
                if stopReasonStorage == nil {
                    stopReasonStorage = reason
                }
                let current = Array(stopWaiters.values)
                stopWaiters.removeAll()
                return current
            }
            for waiter in waiters {
                waiter.resume(returning: reason)
            }
        }

        func prematureStopReason() -> String? {
            stateLock.withLock { stopReasonStorage }
        }

        private func waitForStop(timeoutNanoseconds: UInt64) async -> String? {
            let waiterID = UUID()
            return await withTaskCancellationHandler {
                await withCheckedContinuation { (cont: CheckedContinuation<String?, Never>) in
                    let existing = stateLock.withLock { () -> String? in
                        if let already = stopReasonStorage {
                            return already
                        }
                        stopWaiters[waiterID] = cont
                        return nil
                    }
                    if let existing {
                        cont.resume(returning: existing)
                        return
                    }
                    if Task.isCancelled {
                        let removed = stateLock.withLock { stopWaiters.removeValue(forKey: waiterID) }
                        removed?.resume(returning: nil)
                        return
                    }
                    let clampedNs = Int(min(timeoutNanoseconds, UInt64(Int.max)))
                    DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + .nanoseconds(clampedNs)) { [weak self] in
                        guard let self else { return }
                        let expired = self.stateLock.withLock { self.stopWaiters.removeValue(forKey: waiterID) }
                        expired?.resume(returning: nil)
                    }
                }
            } onCancel: { [weak self] in
                guard let self else { return }
                let cancelled = self.stateLock.withLock { self.stopWaiters.removeValue(forKey: waiterID) }
                cancelled?.resume(returning: nil)
            }
        }

        func connectVsock(port: UInt32) async throws -> HardwareVsockFDDescriptor {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<HardwareVsockFDDescriptor, Error>) in
                queue.async {
                    guard let sockDevice = self.vm?.socketDevices.first as? VZVirtioSocketDevice else {
                        cont.resume(throwing: AgentVMError.vsockProtocolViolation(
                            detail: "VZVirtualMachine has no configured VZVirtioSocketDevice."
                        ))
                        return
                    }
                    sockDevice.connect(toPort: port) { result in
                        switch result {
                        case let .success(conn):
                            self.vsockConnection?.close()
                            self.vsockConnection = conn
                            cont.resume(returning: HardwareVsockFDDescriptor(
                                fileDescriptor: conn.fileDescriptor,
                                closeWhenSessionEnds: false
                            ))
                        case let .failure(err):
                            cont.resume(throwing: err)
                        }
                    }
                }
            }
        }

        func closeVsockConnection() async {
            await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                queue.async {
                    self.vsockConnection?.close()
                    self.vsockConnection = nil
                    cont.resume()
                }
            }
        }

        func pause() async throws {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                queue.async {
                    guard let machine = self.vm else {
                        cont.resume()
                        return
                    }
                    machine.pause { result in
                        switch result {
                        case .success: cont.resume()
                        case let .failure(err): cont.resume(throwing: err)
                        }
                    }
                }
            }
        }

        func resume() async throws {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                queue.async {
                    guard let machine = self.vm else {
                        cont.resume()
                        return
                    }
                    machine.resume { result in
                        switch result {
                        case .success: cont.resume()
                        case let .failure(err): cont.resume(throwing: err)
                        }
                    }
                }
            }
        }

        func saveMachineState(to url: URL) async throws {
            if #available(macOS 14.0, *) {
                try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                    queue.async {
                        guard let machine = self.vm else {
                            cont.resume()
                            return
                        }
                        machine.saveMachineStateTo(url: url) { err in
                            if let err {
                                cont.resume(throwing: err)
                            } else {
                                cont.resume()
                            }
                        }
                    }
                }
            }
        }

        func shutdown(gracefulTimeoutNanoseconds: UInt64) async {
            enum StopStep {
                case alreadyStopped
                case requestedGracefulStop
                case needsHardStop
            }

            let step: StopStep = await withCheckedContinuation { cont in
                queue.async {
                    self.vsockConnection?.close()
                    self.vsockConnection = nil
                    guard let machine = self.vm else {
                        self.recordStop(reason: "no-vm")
                        cont.resume(returning: .alreadyStopped)
                        return
                    }
                    if machine.state == .stopped {
                        self.recordStop(reason: "already-stopped")
                        cont.resume(returning: .alreadyStopped)
                        return
                    }
                    if machine.canRequestStop {
                        do {
                            try machine.requestStop()
                            cont.resume(returning: .requestedGracefulStop)
                            return
                        } catch {
                            // Fall through to hard stop
                        }
                    }
                    cont.resume(returning: .needsHardStop)
                }
            }

            var stoppedGracefully = (step == .alreadyStopped)
            if step == .requestedGracefulStop {
                if await waitForStop(timeoutNanoseconds: gracefulTimeoutNanoseconds) != nil {
                    stoppedGracefully = true
                }
            }

            if !stoppedGracefully {
                await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                    queue.async {
                        guard let machine = self.vm, machine.state != .stopped, machine.canStop else {
                            cont.resume()
                            return
                        }
                        machine.stop { _ in
                            self.recordStop(reason: "hard-stop")
                            cont.resume()
                        }
                    }
                }
            }

            await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                queue.async {
                    self.vm?.delegate = nil
                    self.vm = nil
                    cont.resume()
                }
            }
        }
    }

    private struct DefaultVZHardwareBackend: HardwareVMLowLevelBackend {
        func startMachine(
            spec: VMSpec,
            networkSocketFD: Int32?,
            consoleLogURL: URL,
            translator: VZConfigurationTranslator
        ) async throws -> any HardwareVMInstanceHandle {
            guard VZVirtualMachine.isSupported else {
                throw AgentVMError.virtualizationUnsupported(
                    reason: "VZVirtualMachine.isSupported returned false (this host cannot run Virtualization.framework guests)."
                )
            }
            guard HostHypervisorProbe.currentProcessHasBooleanEntitlement(HostHypervisorProbe.virtualizationEntitlementKey) else {
                throw AgentVMError.virtualizationEntitlementMissing
            }
            let vmQueue = DispatchQueue(label: "io.zxu756.agentvm.vz.\(spec.id.rawValue)")
            let box = HardwareVZBox(queue: vmQueue)
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                vmQueue.async {
                    do {
                        let vzConfig = try translator.buildVZConfiguration(
                            from: spec,
                            networkSocketFD: networkSocketFD,
                            serialLogFileURL: consoleLogURL,
                            validateConfiguration: true
                        )
                        let machine = VZVirtualMachine(configuration: vzConfig, queue: vmQueue)
                        machine.delegate = box
                        box.vm = machine
                        machine.start { result in
                            switch result {
                            case .success:
                                cont.resume()
                            case let .failure(err):
                                box.vm?.delegate = nil
                                box.vm = nil
                                cont.resume(throwing: AgentVMError.virtualizationUnsupported(
                                    reason: "VZVirtualMachine.start failed: \(err.localizedDescription)"
                                ))
                            }
                        }
                    } catch {
                        box.vm?.delegate = nil
                        box.vm = nil
                        cont.resume(throwing: error)
                    }
                }
            }
            return box
        }
    }

    public nonisolated func consoleLogURL(forVMName vmName: String) -> URL {
        let sanitizedComponent = vmName
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "..", with: "_")
        let baseName = sanitizedComponent.isEmpty ? "vm" : sanitizedComponent
        return store.logsDirectoryURL.appendingPathComponent("\(baseName).console.log")
    }

    public nonisolated func lockFileURL(for vmID: VMID) -> URL {
        store.locksDirectoryURL.appendingPathComponent("\(vmID.rawValue).lock", isDirectory: false)
    }

    public init(
        bundleURL: URL,
        executionBackend: HypervisorExecutionBackend = .strictHardwareVZ,
        isWorkspaceDaemon: Bool = false,
        imageCacheDirectoryURL: URL? = nil,
        curatedImageEntries: [BaseImageCatalogEntry]? = nil,
        diskEngine: APFSCoWDiskEngine = APFSCoWDiskEngine(),
        hardwareBackendOverride: (any HardwareVMLowLevelBackend)? = nil,
        vsockConnectTimeoutNanoseconds: UInt64 = 180_000_000_000,
        vsockRetryIntervalNanoseconds: UInt64 = 1_000_000_000,
        gracefulStopTimeoutNanoseconds: UInt64 = 30_000_000_000
    ) throws {
        let createdStore = try AgentVMProjectStore(bundleURL: bundleURL, createIfMissing: true)
        self.store = createdStore
        self.isWorkspaceDaemon = isWorkspaceDaemon
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
        self.hardwareBackend = hardwareBackendOverride ?? DefaultVZHardwareBackend()
        self.vsockConnectTimeoutNanoseconds = vsockConnectTimeoutNanoseconds
        self.vsockRetryIntervalNanoseconds = vsockRetryIntervalNanoseconds
        self.gracefulStopTimeoutNanoseconds = gracefulStopTimeoutNanoseconds
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

    // MARK: - Simulated Runtime State Hygiene & Crash Reconciliation (`VM_RUNTIME_LOST`)

    public static func vmRuntimeLostMessage(vmName: String, language: AppLanguage) -> String {
        if language == .zhHans {
            return "上次运行异常中断：持有这台机器的进程没有正常退出（\(vmName)）。"
        }
        return "Previous run terminated unexpectedly: the process holding this VM ('\(vmName)') did not exit cleanly."
    }

    public static func localizedDiagnosticMessage(for event: DiagnosticEvent, in language: AppLanguage) -> String {
        if event.code == "VM_RUNTIME_LOST" {
            if language == .zhHans, let zh = event.metadata["message_zh"], !zh.isEmpty {
                return zh
            }
            if language == .en, let en = event.metadata["message_en"], !en.isEmpty {
                return en
            }
            if let vmName = event.metadata["vmName"], !vmName.isEmpty {
                return vmRuntimeLostMessage(vmName: vmName, language: language)
            }
        }
        return event.message
    }

    private nonisolated func makeVMRuntimeLostDiagnostic(
        for record: VMInstanceRecord,
        language: AppLanguage
    ) -> DiagnosticEvent {
        let zhMsg = Self.vmRuntimeLostMessage(vmName: record.spec.name, language: .zhHans)
        let enMsg = Self.vmRuntimeLostMessage(vmName: record.spec.name, language: .en)
        return DiagnosticEvent(
            severity: .warning,
            subsystem: "Hypervisor",
            vmID: record.id,
            code: "VM_RUNTIME_LOST",
            message: (language == .zhHans) ? zhMsg : enMsg,
            metadata: [
                "vmName": record.spec.name,
                "message_zh": zhMsg,
                "message_en": enMsg
            ]
        )
    }

    /// VM records as this process should report them (`ps`, `ps --json`, `daemon list`, MCP `agentvm_list_fleet`, HTML export).
    ///
    /// Lifecycle state written by the simulation backend is stored with `telemetry.simulated == true`, so a
    /// hardware-backend process that reads it reports it as simulated. Under the simulation backend every
    /// record's runtime state is, by definition, reported by the simulator, so the flag is set on all of them.
    ///
    /// When a non-simulated VM is recorded as `running` in SQLite while neither held in this process nor
    /// locked by a live `VMExecutionLock` holder, it is atomically reconciled to `stopped` and a single
    /// `VM_RUNTIME_LOST` diagnostic is appended for that interruption.
    public func listVMsForReporting(language: AppLanguage = .en) async throws -> [VMInstanceRecord] {
        let vms = try await store.listVMs()
        if isSimulationBackend {
            return vms.map { record in
                var marked = record
                marked.telemetry.simulated = true
                return marked
            }
        }

        var reconciledList: [VMInstanceRecord] = []
        reconciledList.reserveCapacity(vms.count)
        for record in vms {
            if record.telemetry.state == .running,
               !record.telemetry.simulated,
               hardwareBoxes[record.id] == nil,
               !VMExecutionLock.isLocked(at: lockFileURL(for: record.id)) {
                let diag = makeVMRuntimeLostDiagnostic(for: record, language: language)
                if let reconciled = try await store.reconcileLostRunningVM(vmID: record.id, diagnostic: diag).record {
                    reconciledList.append(reconciled)
                } else {
                    var fallback = record
                    fallback.telemetry.state = .stopped
                    fallback.telemetry.guestAgentConnected = false
                    fallback.telemetry.hasLiveGuestTelemetry = false
                    fallback.telemetry.vsockStreamsOpen = 0
                    fallback.telemetry.cpuUsagePercent = 0
                    fallback.telemetry.memoryResidentMB = 0
                    stampRuntimeOrigin(&fallback)
                    reconciledList.append(fallback)
                }
            } else {
                reconciledList.append(record)
            }
        }
        return reconciledList
    }

    /// Startup reconciliation executed by `agentvm daemon run` after acquiring `daemon.lock` and before `bind`/`listen`.
    @discardableResult
    public func reconcileStaleRunningVMs(language: AppLanguage = .en) async throws -> [VMInstanceRecord] {
        try await listVMsForReporting(language: language)
    }

    /// Discards any simulated state (A52) and reconciles any unlocked crashed hardware `running` state
    /// before a disconnected CLI client (`exec`, `pause`, `resume`, `halt`) inspects or reports the VM's state.
    public func prepareDisconnectedVMForClientOperation(
        _ vmID: VMID,
        language: AppLanguage = .en
    ) async throws -> VMInstanceRecord {
        let record = try await loadVMForOperation(vmID)
        if !isSimulationBackend,
           record.telemetry.state == .running,
           !record.telemetry.simulated,
           hardwareBoxes[vmID] == nil,
           !VMExecutionLock.isLocked(at: lockFileURL(for: vmID)) {
            let diag = makeVMRuntimeLostDiagnostic(for: record, language: language)
            if let reconciled = try await store.reconcileLostRunningVM(vmID: vmID, diagnostic: diag).record {
                return reconciled
            }
        }
        return record
    }

    /// Client-side preflight before `agentvm up` may spawn or contact the workspace daemon:
    /// 1. Discards any state left by `--backend simulation` (`loadVMForOperation`).
    /// 2. Verifies a bootable guest OS/kernel exists on disk (`verifyBootableGuestSystem`).
    /// 3. Verifies host Virtualization.framework support and current executable's `com.apple.security.virtualization` entitlement.
    public func preflightPersistentBoot(
        _ vmID: VMID,
        checkProcessEntitlement: Bool = true,
        hasEntitlementOverride: (@Sendable () -> Bool)? = nil
    ) async throws -> VMInstanceRecord {
        let record = try await loadVMForOperation(vmID)
        try verifyBootableGuestSystem(for: record.spec)
        if checkProcessEntitlement {
            guard VZVirtualMachine.isSupported else {
                throw AgentVMError.virtualizationUnsupported(
                    reason: "VZVirtualMachine.isSupported returned false (this host cannot run Virtualization.framework guests)."
                )
            }
            let entitled = hasEntitlementOverride?()
                ?? HostHypervisorProbe.currentProcessHasBooleanEntitlement(HostHypervisorProbe.virtualizationEntitlementKey)
            guard entitled else {
                throw AgentVMError.virtualizationEntitlementMissing
            }
        }
        return record
    }

    /// Returns records for VMs currently held in memory by this daemon process (`daemon status`).
    public func daemonHeldVMs() async throws -> [VMInstanceRecord] {
        guard !hardwareBoxes.isEmpty else { return [] }
        let heldIDs = Set(hardwareBoxes.keys)
        let all = try await store.listVMs()
        return all.filter { heldIDs.contains($0.id) }
    }

    /// Gracefully shuts down all VMs held by this daemon process (`daemon stop` / `SIGTERM` / `SIGINT`).
    public func shutdownAllDaemonHeldVMs() async -> [VMID] {
        let heldIDs = Set(hardwareBoxes.keys).union(heldExecutionLocks.keys).sorted()
        guard !heldIDs.isEmpty else { return [] }
        var stopped: [VMID] = []
        stopped.reserveCapacity(heldIDs.count)
        for vmID in heldIDs {
            if (try? await haltVM(vmID)) != nil {
                stopped.append(vmID)
            }
        }
        return stopped
    }

    private func ownsExecutionLock(for vmID: VMID) -> Bool {
        heldExecutionLocks[vmID] != nil || activeOneShotLocks.contains(vmID)
    }

    /// Serializes lifecycle transitions (`up`, `halt`, `pause`, `resume`) per `vmID` so at most one transition
    /// executes on a given VM at a time (Fixes A38).
    private func enqueueVMLifecycleOperation<T: Sendable>(
        for vmID: VMID,
        _ operation: @Sendable @escaping () async throws -> T
    ) async throws -> T {
        let previousToken = vmLifecycleQueueHeads[vmID]
        let previousTask = previousToken.flatMap { vmLifecycleTails[$0] }
        let myToken = UUID()
        let (stream, continuation) = AsyncStream<Void>.makeStream()
        let gateTask = Task<Void, Never> {
            var iterator = stream.makeAsyncIterator()
            _ = await iterator.next()
        }
        vmLifecycleTails[myToken] = gateTask
        vmLifecycleQueueHeads[vmID] = myToken
        defer {
            continuation.finish()
            vmLifecycleTails.removeValue(forKey: myToken)
            if vmLifecycleQueueHeads[vmID] == myToken {
                vmLifecycleQueueHeads.removeValue(forKey: vmID)
            }
        }
        if let previousTask {
            await previousTask.value
        }
        return try await operation()
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
            serialAndDisplay: SerialAndDisplaySpec(
                enableVirtioSerialConsole: true,
                serialLogPath: consoleLogURL(forVMName: name).path,
                enableVirtioGraphics: false
            ),
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
            serialAndDisplay: SerialAndDisplaySpec(
                enableVirtioSerialConsole: true,
                serialLogPath: consoleLogURL(forVMName: name).path,
                enableVirtioGraphics: false
            ),
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

    public func bootVM(
        _ vmID: VMID,
        onProgress: (@Sendable (String) -> Void)? = nil
    ) async throws -> VMInstanceRecord {
        try await enqueueVMLifecycleOperation(for: vmID) {
            try await self.bootVMInternal(
                vmID,
                persistRunningState: true,
                acquireExecutionLock: true,
                onProgress: onProgress
            )
        }
    }

    /// Boots a VM into a persistent background state (`agentvm up`, `exec` auto-boot, Studio boot).
    /// Under `--backend simulation` or inside the workspace daemon (`isWorkspaceDaemon`), delegates to `bootVM`.
    /// Non-daemon hardware callers verify bootability first and refuse in-process persistent boot.
    public func bootPersistentVM(
        _ vmID: VMID,
        onProgress: (@Sendable (String) -> Void)? = nil
    ) async throws -> VMInstanceRecord {
        if isSimulationBackend || isWorkspaceDaemon {
            return try await bootVM(vmID, onProgress: onProgress)
        }
        let record = try await loadVMForOperation(vmID)
        try verifyBootableGuestSystem(for: record.spec)
        throw AgentVMError.persistentBootRequiresDaemon(vmName: record.spec.name)
    }

    private func bootVMInternal(
        _ vmID: VMID,
        persistRunningState: Bool,
        acquireExecutionLock: Bool,
        onProgress: (@Sendable (String) -> Void)? = nil
    ) async throws -> VMInstanceRecord {
        var record = try await loadVMForOperation(vmID)
        if isSimulationBackend {
            if record.telemetry.state == .running {
                if !record.telemetry.simulated {
                    // A `running` record the simulator is asked to drive is simulated from here on; say so in the store.
                    record.telemetry.simulated = true
                    try await store.upsertVM(record)
                }
                return record
            }
        } else {
            // Fixes A51: under the hardware backend, a VM counts as already running ONLY when SQLite records `running`
            // AND this process holds the live hardware VM instance in memory.
            if record.telemetry.state == .running && hardwareBoxes[vmID] != nil {
                return record
            }
            if record.telemetry.state == .paused && hardwareBoxes[vmID] != nil {
                throw AgentVMError.invalidLifecycleTransition(
                    vmID: vmID,
                    from: record.telemetry.state.rawValue,
                    requested: "up"
                )
            }
            if record.telemetry.state == .running,
               !record.telemetry.simulated,
               hardwareBoxes[vmID] == nil,
               !ownsExecutionLock(for: vmID),
               !VMExecutionLock.isLocked(at: lockFileURL(for: vmID)) {
                let diag = makeVMRuntimeLostDiagnostic(for: record, language: .en)
                if let reconciled = try await store.reconcileLostRunningVM(vmID: vmID, diagnostic: diag).record {
                    record = reconciled
                }
            }
        }

        if !isSimulationBackend {
            try verifyBootableGuestSystem(for: record.spec)
        }

        let manifest = try await store.loadManifest()
        let allVMs = try await store.listVMs()
        // Simulated `running` records never count against a hardware-backend quota; include in-flight hardware boots.
        var activeIDs = Set(
            allVMs.filter {
                $0.id != vmID
                    && $0.telemetry.state == .running
                    && (isSimulationBackend || !$0.telemetry.simulated)
            }.map(\.id)
        )
        if !isSimulationBackend {
            activeIDs.formUnion(inFlightHardwareBoots.subtracting([vmID]))
        }
        let activeCount = activeIDs.count
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

        // Acquire per-VM execution lock BEFORE starting the hardware machine, and keep holding it until
        // the VM stops and `stopped` has been written back to SQLite (Item 2 / Section 4).
        var newlyAcquiredLock = false
        if acquireExecutionLock && heldExecutionLocks[vmID] == nil {
            let freshLock = try VMExecutionLock.acquire(
                at: lockFileURL(for: vmID),
                vmName: record.spec.name
            )
            heldExecutionLocks[vmID] = freshLock
            newlyAcquiredLock = true
        }

        inFlightHardwareBoots.insert(vmID)
        defer { inFlightHardwareBoots.remove(vmID) }

        func rollbackFailedBootAndReleaseLockIfNeeded(vmFD: Int32?) async {
            if let ownedBox = hardwareBoxes.removeValue(forKey: vmID) {
                let stopTimeout = gracefulStopTimeoutNanoseconds
                await Task {
                    await ownedBox.closeVsockConnection()
                    await ownedBox.shutdown(gracefulTimeoutNanoseconds: stopTimeout)
                }.value
            }
            if vmFD != nil {
                await l2Switch.detachPort(for: vmID)
            }
            record.telemetry.state = .stopped
            record.telemetry.guestAgentConnected = false
            record.telemetry.hasLiveGuestTelemetry = false
            record.telemetry.vsockStreamsOpen = 0
            record.telemetry.cpuUsagePercent = 0
            record.telemetry.memoryResidentMB = 0
            stampRuntimeOrigin(&record)
            try? await store.upsertVM(record)
            if newlyAcquiredLock {
                heldExecutionLocks.removeValue(forKey: vmID)?.release()
            }
        }

        var vmFD: Int32? = nil
        do {
            if let primaryNIC = record.spec.networkInterfaces.first, primaryNIC.mode == .userSpaceSwitch {
                let nicMAC = MACAddress(parsing: primaryNIC.macAddress)
                    ?? MACAddress.deterministicGuestMAC(seed: vmID.rawValue)
                let (createdFD, _) = try await l2Switch.createPortSocketPair(for: vmID, macAddress: nicMAC)
                vmFD = createdFD
            }
        } catch {
            await rollbackFailedBootAndReleaseLockIfNeeded(vmFD: vmFD)
            throw error
        }

        let resolvedConsoleLogURL: URL = {
            if let explicitPath = record.spec.serialAndDisplay.serialLogPath?.trimmingCharacters(in: .whitespacesAndNewlines),
               !explicitPath.isEmpty {
                return URL(fileURLWithPath: explicitPath)
            }
            return consoleLogURL(forVMName: record.spec.name)
        }()

        onProgress?("Booting VM '\(record.spec.name)' via Apple Virtualization.framework (console log: \(resolvedConsoleLogURL.path))...")

        let box: any HardwareVMInstanceHandle
        do {
            box = try await hardwareBackend.startMachine(
                spec: record.spec,
                networkSocketFD: vmFD,
                consoleLogURL: resolvedConsoleLogURL,
                translator: vzTranslator
            )
            hardwareBoxes[vmID] = box
        } catch {
            await rollbackFailedBootAndReleaseLockIfNeeded(vmFD: vmFD)
            throw error
        }

        let guestPort = VsockWireConstants.defaultGuestVsockPort
        onProgress?("Waiting for guest agent on vsock port \(guestPort)...")

        let connectStartNs = DispatchTime.now().uptimeNanoseconds
        let deadlineNs = connectStartNs &+ vsockConnectTimeoutNanoseconds
        var connectedDescriptor: HardwareVsockFDDescriptor?
        var lastConnectErrorDetail = "no connection attempt completed"
        var attempt = 0

        do {
            while true {
                try Task.checkCancellation()
                if let stopReason = box.prematureStopReason() {
                    lastConnectErrorDetail = "VM stopped before vsock connected (\(stopReason))"
                    break
                }
                attempt += 1
                do {
                    let desc = try await box.connectVsock(port: guestPort)
                    connectedDescriptor = desc
                    break
                } catch {
                    lastConnectErrorDetail = error.localizedDescription
                }
                try Task.checkCancellation()

                let nowNs = DispatchTime.now().uptimeNanoseconds
                if nowNs >= deadlineNs {
                    break
                }
                let remainingNs = deadlineNs - nowNs
                let sleepNs = min(vsockRetryIntervalNanoseconds, remainingNs)
                if sleepNs > 0 {
                    try await Task.sleep(nanoseconds: sleepNs)
                }
                if DispatchTime.now().uptimeNanoseconds >= deadlineNs {
                    if let stopReason = box.prematureStopReason() {
                        lastConnectErrorDetail = "VM stopped before vsock connected (\(stopReason))"
                    } else {
                        attempt += 1
                        if let desc = try? await box.connectVsock(port: guestPort) {
                            connectedDescriptor = desc
                        }
                    }
                    break
                }
            }
            try Task.checkCancellation()
        } catch {
            await rollbackFailedBootAndReleaseLockIfNeeded(vmFD: vmFD)
            throw error
        }

        guard let connectedDescriptor, connectedDescriptor.fileDescriptor >= 0 else {
            await rollbackFailedBootAndReleaseLockIfNeeded(vmFD: vmFD)
            let timeoutSec = max(1, Int(vsockConnectTimeoutNanoseconds / 1_000_000_000))
            throw AgentVMError.guestVsockConnectTimedOut(
                vmName: record.spec.name,
                port: guestPort,
                timeoutSeconds: timeoutSec,
                consoleLogPath: resolvedConsoleLogURL.path,
                detail: lastConnectErrorDetail
            )
        }

        let session = VsockMultiplexSession(vmID: vmID)
        do {
            try await session.attachPOSIXFileDescriptor(
                connectedDescriptor.fileDescriptor,
                closeWhenDone: connectedDescriptor.closeWhenSessionEnds
            )
        } catch {
            await session.shutdown()
            await rollbackFailedBootAndReleaseLockIfNeeded(vmFD: vmFD)
            throw error
        }

        await session.attachTerminalScreenBuffer(tty)
        hardwareBoxes[vmID] = box
        vsockSessions[vmID] = session

        for rule in record.spec.portForwards where rule.enabled {
            _ = try? await portForwardManager.startForwardRule(rule, vmID: vmID, vsockSession: session)
        }

        onProgress?("Guest agent connected on vsock port \(guestPort) (attempt \(attempt)).")
        tty.feed("[VZBoot] Started Apple Virtualization.framework guest '\(record.spec.name)'.\r\n")

        bootTimestamps[vmID] = Date()
        record.lastBootedAt = Date()
        record.telemetry.state = .running
        record.telemetry.cpuUsagePercent = 0.0
        record.telemetry.memoryResidentMB = 0
        record.telemetry.hasLiveGuestTelemetry = false
        record.telemetry.guestAgentConnected = true
        record.telemetry.vsockStreamsOpen = await session.openStreamCount()
        stampRuntimeOrigin(&record)
        if persistRunningState {
            try await store.upsertVM(record)
        }

        try await store.appendDiagnostic(DiagnosticEvent(
            severity: .info,
            subsystem: "Hypervisor",
            vmID: vmID,
            code: "VM_BOOTED",
            message: "Booted VM '\(record.spec.name)' via Virtualization.framework and connected vsock port \(guestPort)."
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

    public func pauseVM(
        _ vmID: VMID,
        reason: String = "User requested pause",
        language: AppLanguage = .en
    ) async throws -> VMInstanceRecord {
        try await enqueueVMLifecycleOperation(for: vmID) {
            try await self.pauseVMUnlocked(vmID, reason: reason, language: language)
        }
    }

    private func pauseVMUnlocked(
        _ vmID: VMID,
        reason: String,
        language: AppLanguage
    ) async throws -> VMInstanceRecord {
        var record = try await loadVMForOperation(vmID)
        if !isSimulationBackend,
           record.telemetry.state == .running,
           !record.telemetry.simulated,
           hardwareBoxes[vmID] == nil,
           !ownsExecutionLock(for: vmID),
           !VMExecutionLock.isLocked(at: lockFileURL(for: vmID)) {
            let diag = makeVMRuntimeLostDiagnostic(for: record, language: language)
            if let reconciled = try await store.reconcileLostRunningVM(vmID: vmID, diagnostic: diag).record {
                record = reconciled
            }
        }
        guard record.telemetry.state == .running,
              isSimulationBackend || hardwareBoxes[vmID] != nil else {
            let effectiveState = (!isSimulationBackend && hardwareBoxes[vmID] == nil && record.telemetry.state == .running)
                ? VMLifecycleState.stopped.rawValue
                : record.telemetry.state.rawValue
            throw AgentVMError.invalidLifecycleTransition(
                vmID: vmID,
                from: effectiveState,
                requested: "pause"
            )
        }

        if let box = hardwareBoxes[vmID] {
            try await box.pause()
        }

        record.telemetry.state = .paused
        record.telemetry.cpuUsagePercent = 0.0
        record.telemetry.hasLiveGuestTelemetry = false
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

    public func resumeVM(
        _ vmID: VMID,
        language: AppLanguage = .en
    ) async throws -> VMInstanceRecord {
        try await enqueueVMLifecycleOperation(for: vmID) {
            try await self.resumeVMUnlocked(vmID, language: language)
        }
    }

    private func resumeVMUnlocked(
        _ vmID: VMID,
        language: AppLanguage
    ) async throws -> VMInstanceRecord {
        var record = try await loadVMForOperation(vmID)
        if !isSimulationBackend,
           record.telemetry.state == .running,
           !record.telemetry.simulated,
           hardwareBoxes[vmID] == nil,
           !ownsExecutionLock(for: vmID),
           !VMExecutionLock.isLocked(at: lockFileURL(for: vmID)) {
            let diag = makeVMRuntimeLostDiagnostic(for: record, language: language)
            if let reconciled = try await store.reconcileLostRunningVM(vmID: vmID, diagnostic: diag).record {
                record = reconciled
            }
        }
        if !isSimulationBackend && hardwareBoxes[vmID] == nil {
            if record.telemetry.state != .stopped {
                record.telemetry.state = .stopped
                record.telemetry.guestAgentConnected = false
                record.telemetry.hasLiveGuestTelemetry = false
                record.telemetry.vsockStreamsOpen = 0
                record.telemetry.cpuUsagePercent = 0
                record.telemetry.memoryResidentMB = 0
                stampRuntimeOrigin(&record)
                try await store.upsertVM(record)
            }
            throw AgentVMError.invalidLifecycleTransition(
                vmID: vmID,
                from: record.telemetry.state.rawValue,
                requested: "resume"
            )
        }
        guard record.telemetry.state == .paused else {
            throw AgentVMError.invalidLifecycleTransition(
                vmID: vmID,
                from: record.telemetry.state.rawValue,
                requested: "resume"
            )
        }

        if let box = hardwareBoxes[vmID] {
            try await box.resume()
        }

        record.telemetry.state = .running
        stampRuntimeOrigin(&record)
        try await store.upsertVM(record)
        return record
    }

    public func haltVM(
        _ vmID: VMID,
        language: AppLanguage = .en,
        onProgress: (@Sendable (String) -> Void)? = nil
    ) async throws -> VMInstanceRecord {
        try await enqueueVMLifecycleOperation(for: vmID) {
            try await self.haltVMUnlocked(
                vmID,
                releaseHeldLock: true,
                language: language,
                onProgress: onProgress
            )
        }
    }

    private func haltVMUnlocked(
        _ vmID: VMID,
        releaseHeldLock: Bool,
        language: AppLanguage = .en,
        onProgress: (@Sendable (String) -> Void)? = nil
    ) async throws -> VMInstanceRecord {
        var record = try await loadVMForOperation(vmID)
        if !isSimulationBackend,
           record.telemetry.state == .running,
           !record.telemetry.simulated,
           hardwareBoxes[vmID] == nil,
           !ownsExecutionLock(for: vmID),
           !VMExecutionLock.isLocked(at: lockFileURL(for: vmID)) {
            let diag = makeVMRuntimeLostDiagnostic(for: record, language: language)
            if let reconciled = try await store.reconcileLostRunningVM(vmID: vmID, diagnostic: diag).record {
                record = reconciled
            }
        }
        await portForwardManager.stopAllRules(for: vmID)
        if let session = vsockSessions.removeValue(forKey: vmID) {
            await session.shutdown()
        }
        if let box = hardwareBoxes.removeValue(forKey: vmID) {
            onProgress?("Shutting down VM '\(record.spec.name)'...")
            await box.closeVsockConnection()
            await box.shutdown(gracefulTimeoutNanoseconds: gracefulStopTimeoutNanoseconds)
        }
        await l2Switch.detachPort(for: vmID)
        bootTimestamps.removeValue(forKey: vmID)

        record.telemetry.state = .stopped
        record.telemetry.cpuUsagePercent = 0
        record.telemetry.memoryResidentMB = 0
        record.telemetry.hasLiveGuestTelemetry = false
        record.telemetry.guestAgentConnected = false
        record.telemetry.vsockStreamsOpen = 0
        stampRuntimeOrigin(&record)
        defer {
            if releaseHeldLock {
                heldExecutionLocks.removeValue(forKey: vmID)?.release()
            }
        }
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
                try? await box.saveMachineState(to: stateFileURL)
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
        if childSpec.serialAndDisplay.serialLogPath != nil {
            childSpec.serialAndDisplay.serialLogPath = consoleLogURL(forVMName: branchName).path
        }

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
            childRecord = try await bootPersistentVM(childID)
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
            record = try await bootPersistentVM(record.id)
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
            _ = try await bootPersistentVM(vmID)
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

    /// Executes a single guest command in a complete in-process boot -> vsock connect -> exec -> halt lifecycle (`agentvm run`).
    /// Preserves raw `stdoutData` and `stderrData` byte-for-byte without UTF-8 string conversion.
    public func runOneShotCommand(
        vmID: VMID,
        request: GuestExecRequest,
        onProgress: (@Sendable (String) -> Void)? = nil,
        onOutputChunk: (@Sendable (GuestExecOutputChunk) async -> Void)? = nil
    ) async throws -> GuestExecResult {
        if isSimulationBackend {
            let fallbackName = (try? await store.fetchVM(vmID))?.spec.name ?? vmID.rawValue
            throw AgentVMError.runUnsupportedInSimulation(vmName: fallbackName)
        }
        let initialRecord = try await loadVMForOperation(vmID)
        let activePolicy = await l2Switch.firewall.currentPolicy()
        if activePolicy.id == PolicySetID("pol-airgap")
            || initialRecord.spec.networkInterfaces.contains(where: { $0.mode == .isolatedAirgap }) {
            throw AgentVMError.airgapPolicyUnsupportedBeforeM5(vmName: initialRecord.spec.name)
        }

        let vmLock = try VMExecutionLock.acquire(
            at: lockFileURL(for: vmID),
            vmName: initialRecord.spec.name
        )
        activeOneShotLocks.insert(vmID)
        defer {
            activeOneShotLocks.remove(vmID)
            vmLock.release()
        }

        try Task.checkCancellation()
        let bootedRecord = try await bootVMInternal(
            vmID,
            persistRunningState: false,
            acquireExecutionLock: false,
            onProgress: onProgress
        )
        do {
            try Task.checkCancellation()
            guard let session = vsockSessions[vmID] else {
                throw AgentVMError.guestAgentNotConnected(
                    vmName: bootedRecord.spec.name,
                    state: bootedRecord.telemetry.state.rawValue
                )
            }
            onProgress?("Executing command in '\(bootedRecord.spec.name)': \(request.commandLineSummary)")
            let execResult = try await session.executeCommandStreaming(request, onChunk: onOutputChunk)

            var ledgerEntry = execResult
            if isSimulationBackend {
                ledgerEntry.commandLine = "[SIMULATED] \(execResult.commandLine)"
            }
            try? await store.appendExecResult(ledgerEntry)

            _ = try await Task {
                try await self.haltVMUnlocked(vmID, releaseHeldLock: false, onProgress: onProgress)
            }.value
            onProgress?("VM '\(bootedRecord.spec.name)' stopped.")
            return execResult
        } catch {
            _ = await Task {
                try? await self.haltVMUnlocked(vmID, releaseHeldLock: false, onProgress: onProgress)
            }.value
            throw error
        }
    }

    /// Wakes an in-flight `runOneShotCommand` when the CLI receives `SIGINT` or `SIGTERM` so `runOneShotCommand`
    /// can perform an orderly VM shutdown and release the per-VM `flock` before the process exits.
    public func interruptOneShotExecution(_ vmID: VMID) async {
        if let session = vsockSessions[vmID] {
            await session.shutdown()
        }
        if let box = hardwareBoxes[vmID] {
            await box.closeVsockConnection()
        }
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
