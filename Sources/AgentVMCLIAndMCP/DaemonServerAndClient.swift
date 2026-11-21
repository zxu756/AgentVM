import AgentVMHypervisor
import AgentVMModels
import AgentVMStore
import Darwin
import Foundation

// MARK: - Daemon Log File Manager (`<workspace>/logs/daemon.log`)

public final class DaemonLogManager: @unchecked Sendable {
    private let lock = NSLock()
    private var rawFD: Int32
    public let logFileURL: URL

    public init(logFileURL: URL) throws {
        let parentDir = logFileURL.deletingLastPathComponent()
        do {
            try FileManager.default.createDirectory(at: parentDir, withIntermediateDirectories: true)
        } catch {
            throw DaemonSocketError.syscallFailed(
                operation: "mkdir(logs)",
                path: parentDir.path,
                errnoCode: Darwin.errno,
                detail: error.localizedDescription
            )
        }
        let fd = Darwin.open(logFileURL.path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0o600)
        guard fd >= 0 else {
            let code = Darwin.errno
            throw DaemonSocketError.syscallFailed(
                operation: "open(daemon.log)",
                path: logFileURL.path,
                errnoCode: code,
                detail: String(cString: Darwin.strerror(code))
            )
        }
        self.rawFD = fd
        self.logFileURL = logFileURL
    }

    deinit {
        close()
    }

    public func appendLine(_ message: String) {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let timestamp = formatter.string(from: Date())
        let clean = message.replacingOccurrences(of: "\n", with: " ")
        let framed = Data("[\(timestamp)] \(clean)\n".utf8)
        lock.withLock {
            guard rawFD >= 0 else { return }
            framed.withUnsafeBytes { rawBuf in
                guard let base = rawBuf.baseAddress else { return }
                var offset = 0
                while offset < rawBuf.count {
                    let n = Darwin.write(rawFD, base.advanced(by: offset), rawBuf.count - offset)
                    if n > 0 {
                        offset += n
                    } else if n < 0 && Darwin.errno == EINTR {
                        continue
                    } else {
                        break
                    }
                }
            }
        }
    }

    public func close() {
        let fd = lock.withLock { () -> Int32 in
            let current = rawFD
            rawFD = -1
            return current
        }
        if fd >= 0 {
            _ = Darwin.close(fd)
        }
    }

    /// Redirects standard input (fd 0) to `/dev/null` and standard output/error (fds 1, 2) to `daemon.log` (`O_APPEND`).
    public static func redirectProcessStandardStreams(toLogURL logURL: URL) throws {
        let parentDir = logURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: parentDir, withIntermediateDirectories: true)

        let devNullFD = Darwin.open("/dev/null", O_RDONLY)
        guard devNullFD >= 0 else {
            let code = Darwin.errno
            throw DaemonSocketError.syscallFailed(
                operation: "open(/dev/null)",
                path: "/dev/null",
                errnoCode: code,
                detail: String(cString: Darwin.strerror(code))
            )
        }
        defer {
            if devNullFD > STDERR_FILENO {
                _ = Darwin.close(devNullFD)
            }
        }

        let logFD = Darwin.open(logURL.path, O_WRONLY | O_CREAT | O_APPEND, 0o600)
        guard logFD >= 0 else {
            let code = Darwin.errno
            throw DaemonSocketError.syscallFailed(
                operation: "open(daemon.log)",
                path: logURL.path,
                errnoCode: code,
                detail: String(cString: Darwin.strerror(code))
            )
        }
        defer {
            if logFD > STDERR_FILENO {
                _ = Darwin.close(logFD)
            }
        }

        _ = Darwin.dup2(devNullFD, STDIN_FILENO)
        _ = Darwin.dup2(logFD, STDOUT_FILENO)
        _ = Darwin.dup2(logFD, STDERR_FILENO)
    }

    /// Reads the trailing `maxLines` lines of `daemon.log` (up to the last 64 KiB).
    public static func readTailLines(at logURL: URL, maxLines: Int = 20) -> String {
        guard maxLines > 0 else { return "" }
        let fd = Darwin.open(logURL.path, O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else { return "" }
        defer { _ = Darwin.close(fd) }

        let endOffset = Darwin.lseek(fd, 0, SEEK_END)
        guard endOffset > 0 else { return "" }
        let maxWindow: off_t = 64 * 1024
        let startOffset = max(0, endOffset - maxWindow)
        let readLen = Int(endOffset - startOffset)
        var buf = [UInt8](repeating: 0, count: readLen)
        let n = Darwin.pread(fd, &buf, readLen, startOffset)
        guard n > 0 else { return "" }

        let text = String(decoding: buf.prefix(n), as: UTF8.self)
        var lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        if lines.last == "" {
            lines.removeLast()
        }
        let tail = lines.suffix(maxLines)
        return tail.joined(separator: "\n")
    }
}

// MARK: - Lifecycle Error Formatting Helpers Shared Between Daemon & Disconnected CLI Fallback

public enum DaemonLifecycleErrorFormatter {
    public static func execNotRunningRPCError(
        vmName: String,
        vmID: VMID,
        state: VMLifecycleState,
        language: AppLanguage
    ) -> DaemonRPCError {
        DaemonRPCError.from(
            .execRequiresRunningVM(vmName: vmName, vmID: vmID, currentState: state),
            language: language
        )
    }

    public static func formatExecRPCErrorStderr(_ err: DaemonRPCError, vmName: String?, language: AppLanguage) -> String {
        let isZh = (language == .zhHans)
        if err.errorCode == "ERR_LIFECYCLE_STATE" {
            if err.message.contains("agentvm up") || err.message.contains("agentvm resume") {
                return "[\(err.errorCode)] \(err.message)\n"
            }
            let target = vmName ?? "<vm>"
            let hint = isZh
                ? "提示：请先运行 'agentvm up \(target)' 启动虚拟机。"
                : "Hint: Start the VM first with 'agentvm up \(target)'."
            return "[\(err.errorCode)] \(err.message)\n\(hint)\n"
        }
        return "[\(err.errorCode)] \(err.message)\n"
    }
}

// MARK: - Workspace Daemon Server (`agentvm daemon run --workspace <abs-path>`)

public enum WorkspaceDaemonStartOutcome: Sendable {
    case started(WorkspaceDaemonServer)
    case alreadyRunning(holder: DaemonLockHolderInfo?)
}

public final class WorkspaceDaemonServer: @unchecked Sendable {
    public let paths: DaemonWorkspacePaths
    public let coordinator: AgentVMFleetCoordinator
    public let singletonLock: DaemonSingletonLock
    public let listener: DaemonSocketListener
    public let logManager: DaemonLogManager
    public let protocolVersion: Int
    public let semanticVersion: SemanticVersion
    public let executablePath: String
    public let recordedStartupSteps: [String]

    private let onShutdownAllMachines: (@Sendable () async -> Void)?
    private let stopGate = DaemonAsyncStopGate()
    private let stateLock = NSLock()
    private var isStoppingFlag = false
    private var cleanupCompletedFlag = false
    private var stopWaiters: [UUID: CheckedContinuation<Void, Never>] = [:]

    private init(
        paths: DaemonWorkspacePaths,
        coordinator: AgentVMFleetCoordinator,
        singletonLock: DaemonSingletonLock,
        listener: DaemonSocketListener,
        logManager: DaemonLogManager,
        protocolVersion: Int,
        semanticVersion: SemanticVersion,
        executablePath: String,
        recordedStartupSteps: [String],
        onShutdownAllMachines: (@Sendable () async -> Void)?
    ) {
        self.paths = paths
        self.coordinator = coordinator
        self.singletonLock = singletonLock
        self.listener = listener
        self.logManager = logManager
        self.protocolVersion = protocolVersion
        self.semanticVersion = semanticVersion
        self.executablePath = executablePath
        self.recordedStartupSteps = recordedStartupSteps
        self.onShutdownAllMachines = onShutdownAllMachines
    }

    public var holderInfo: DaemonLockHolderInfo {
        singletonLock.holderInfo
    }

    public var address: DaemonResolvedSocketAddress {
        listener.address
    }

    /// Starts the workspace daemon following the exact M2 Item 1 sequence:
    /// 1. Acquire non-blocking `flock` on `<workspace>/run/daemon.lock` (`alreadyRunning` exits 0).
    /// 2. Unlink stale `<workspace>/run/daemon.sock`.
    /// 3. Reconcile any crashed hardware `running` VMs in SQLite (`VM_RUNTIME_LOST`).
    /// 4. Bind (`0600`) & listen on the Unix domain socket (`0700` `run/`).
    /// 5. Write `ready` line to `<workspace>/logs/daemon.log`.
    public static func start(
        workspaceURL: URL,
        pid: Int32 = Darwin.getpid(),
        protocolVersion: Int = DaemonRPCHello.currentProtocolVersion,
        semanticVersion: SemanticVersion = .current,
        executablePath: String = DaemonExecutableLocator.resolveCurrentExecutablePath(),
        startedAt: Date = Date(),
        backlog: Int32 = 32,
        userTempDirectoryOverride: URL? = nil,
        imageCacheDirectoryURL: URL? = nil,
        curatedImageEntries: [BaseImageCatalogEntry]? = nil,
        hardwareBackendOverride: (any HardwareVMLowLevelBackend)? = nil,
        vsockConnectTimeoutNanoseconds: UInt64 = 180_000_000_000,
        vsockRetryIntervalNanoseconds: UInt64 = 1_000_000_000,
        gracefulStopTimeoutNanoseconds: UInt64 = 30_000_000_000,
        onShutdownAllMachines: (@Sendable () async -> Void)? = nil
    ) async throws -> WorkspaceDaemonStartOutcome {
        let paths = DaemonWorkspacePaths(workspaceURL: workspaceURL)
        let logManager = try DaemonLogManager(logFileURL: paths.daemonLogFileURL)
        var steps: [String] = []

        // Step 1: Acquire singleton flock on `<workspace>/run/daemon.lock`.
        let lockOutcome: DaemonSingletonLockAcquireOutcome
        do {
            lockOutcome = try DaemonSingletonLock.tryAcquire(
                workspaceURL: paths.workspaceURL,
                pid: pid,
                version: semanticVersion,
                executablePath: executablePath,
                startedAt: startedAt
            )
        } catch {
            logManager.appendLine("fatal: failed acquiring daemon.lock: \(error.localizedDescription)")
            logManager.close()
            throw error
        }

        let acquiredLock: DaemonSingletonLock
        switch lockOutcome {
        case let .alreadyHeld(holder):
            let holderDesc = holder.map { "pid=\($0.pid)" } ?? "unknown-holder"
            logManager.appendLine("contender exiting 0: daemon.lock already held (\(holderDesc))")
            logManager.close()
            return .alreadyRunning(holder: holder)
        case let .acquired(lock):
            acquiredLock = lock
            steps.append("lock")
        }

        var preparedAddress: DaemonResolvedSocketAddress?
        do {
            // Step 2: Remove stale `<workspace>/run/daemon.sock` only after holding singleton lock.
            if Darwin.unlink(paths.directSocketPath) != 0 {
                let code = Darwin.errno
                if code != ENOENT {
                    throw DaemonSocketError.syscallFailed(
                        operation: "unlink(stale daemon.sock)",
                        path: paths.directSocketPath,
                        errnoCode: code,
                        detail: String(cString: Darwin.strerror(code))
                    )
                }
            }
            steps.append("unlink")

            // Step 3: Reconcile crashed `running` VMs -> `stopped` + `VM_RUNTIME_LOST` BEFORE bind/listen.
            let coordinator = try AgentVMFleetCoordinator(
                bundleURL: paths.workspaceURL,
                executionBackend: .strictHardwareVZ,
                isWorkspaceDaemon: true,
                imageCacheDirectoryURL: imageCacheDirectoryURL,
                curatedImageEntries: curatedImageEntries,
                hardwareBackendOverride: hardwareBackendOverride,
                vsockConnectTimeoutNanoseconds: vsockConnectTimeoutNanoseconds,
                vsockRetryIntervalNanoseconds: vsockRetryIntervalNanoseconds,
                gracefulStopTimeoutNanoseconds: gracefulStopTimeoutNanoseconds
            )
            _ = try await coordinator.reconcileStaleRunningVMs()
            steps.append("reconcile")

            // Step 4: Bind & listen Unix domain socket.
            let (address, sockAddr) = try DaemonSocketAddressResolver.prepareForBind(
                workspaceURL: paths.workspaceURL,
                userTempDirectoryOverride: userTempDirectoryOverride
            )
            preparedAddress = address
            let listener = try DaemonSocketListener.bindResolved(
                address: address,
                sockAddr: sockAddr,
                runDirectoryURL: paths.runDirectoryURL,
                backlog: backlog
            )
            steps.append("bind")

            // Step 5: Write `ready` line to `<workspace>/logs/daemon.log`.
            logManager.appendLine(
                "ready pid=\(acquiredLock.holderInfo.pid) version=\(semanticVersion.description) socket=\(address.connectSocketPath) workspace=\(paths.canonicalWorkspacePath)"
            )
            steps.append("ready")

            let server = WorkspaceDaemonServer(
                paths: paths,
                coordinator: coordinator,
                singletonLock: acquiredLock,
                listener: listener,
                logManager: logManager,
                protocolVersion: protocolVersion,
                semanticVersion: semanticVersion,
                executablePath: executablePath,
                recordedStartupSteps: steps,
                onShutdownAllMachines: onShutdownAllMachines
            )
            server.startAcceptLoop()
            return .started(server)
        } catch {
            logManager.appendLine("fatal startup error: \(error.localizedDescription)")
            if let addr = preparedAddress {
                DaemonSocketAddressResolver.removeSymlinkIfPresent(for: addr)
            }
            acquiredLock.release(clearFile: true)
            logManager.close()
            throw error
        }
    }

    public func handleTerminationSignal(_ signalNumber: Int32) async {
        await stopAndCleanup(reason: "signal-\(signalNumber)")
    }

    public func stopAndCleanup(reason: String = "manual-stop") async {
        _ = await stopGate.runOnce { [self] in
            markStopping()
            logManager.appendLine("stopping (\(reason)): shutting down held machines...")
            if let onShutdownAllMachines {
                await onShutdownAllMachines()
            }
            let stoppedIDs = await coordinator.shutdownAllDaemonHeldVMs()
            listener.close(unlinkSocket: true, removeSymlink: true)
            singletonLock.release(clearFile: true)
            logManager.appendLine("stopped (\(reason), stoppedVMs=\(stoppedIDs.count))")
            logManager.close()
            resumeStopWaiters()
            return stoppedIDs
        }
    }

    public func waitUntilStopped() async {
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            let id = UUID()
            let alreadyStopped = stateLock.withLock { () -> Bool in
                if cleanupCompletedFlag {
                    return true
                }
                stopWaiters[id] = cont
                return false
            }
            if alreadyStopped {
                cont.resume()
            }
        }
    }

    /// Installs process-level signal dispositions required for `agentvm daemon run`:
    /// ignores `SIGHUP` and `SIGPIPE`, and routes `SIGTERM` and `SIGINT` to graceful `daemon stop`.
    public static func installProcessSignalHandlers(for server: WorkspaceDaemonServer) -> [any DispatchSourceSignal] {
        Darwin.signal(SIGHUP, SIG_IGN)
        Darwin.signal(SIGPIPE, SIG_IGN)
        Darwin.signal(SIGTERM, SIG_IGN)
        Darwin.signal(SIGINT, SIG_IGN)

        let queue = DispatchQueue(label: "io.zxu756.agentvm.daemon.signals")
        let termSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: queue)
        termSource.setEventHandler { [weak server] in
            guard let server else { return }
            Task { await server.handleTerminationSignal(SIGTERM) }
        }
        termSource.resume()

        let intSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: queue)
        intSource.setEventHandler { [weak server] in
            guard let server else { return }
            Task { await server.handleTerminationSignal(SIGINT) }
        }
        intSource.resume()

        return [termSource, intSource]
    }

    // MARK: - Private Accept & Single-Request-Per-Connection Dispatch

    private func markStopping() {
        stateLock.withLock {
            isStoppingFlag = true
        }
    }

    private var isStopping: Bool {
        stateLock.withLock { isStoppingFlag }
    }

    private func resumeStopWaiters() {
        let waiters = stateLock.withLock { () -> [CheckedContinuation<Void, Never>] in
            cleanupCompletedFlag = true
            let all = Array(stopWaiters.values)
            stopWaiters.removeAll()
            return all
        }
        for waiter in waiters {
            waiter.resume()
        }
    }

    private func startAcceptLoop() {
        let acceptQueue = DispatchQueue(label: "io.zxu756.agentvm.daemon.accept", qos: .userInitiated)
        acceptQueue.async { [weak self] in
            while let self, !self.isStopping {
                do {
                    let conn = try self.listener.acceptConnection()
                    Task.detached { [weak self] in
                        guard let self else {
                            conn.close()
                            return
                        }
                        await self.serveConnection(conn)
                    }
                } catch let sockErr as DaemonSocketError {
                    if case .unauthorizedPeerUID = sockErr {
                        self.logManager.appendLine("rejected unauthorized peer connection: \(sockErr.localizedDescription)")
                        continue
                    }
                    if self.isStopping || self.listener.listenFD < 0 {
                        break
                    }
                    self.logManager.appendLine("accept loop error: \(sockErr.localizedDescription)")
                    break
                } catch {
                    if self.isStopping || self.listener.listenFD < 0 {
                        break
                    }
                    self.logManager.appendLine("accept loop error: \(error.localizedDescription)")
                    break
                }
            }
        }
    }

    private func serveConnection(_ conn: DaemonSocketConnection) async {
        let reader = conn.makeLineReader()
        let daemonHello = DaemonRPCHello(
            protocolVersion: protocolVersion,
            semanticVersion: semanticVersion,
            executablePath: executablePath
        )

        do {
            try conn.writeLineData(try DaemonRPCCodec.encodeHelloLine(daemonHello))
            guard let clientHelloData = try reader.readLineData() else {
                conn.close()
                return
            }
            _ = try DaemonRPCCodec.decodeHelloLine(clientHelloData)

            guard let reqLineData = try reader.readLineData() else {
                // Client disconnected after inspecting hello (e.g., version mismatch).
                conn.close()
                return
            }

            let envelope: DaemonRPCRequestEnvelope
            do {
                envelope = try DaemonRPCCodec.decodeRequestLine(reqLineData)
            } catch let decodeErr as DaemonRPCRequestDecodeError {
                let errResp = DaemonRPCResponse<DaemonRPCStopResult>.failure(
                    id: decodeErr.requestID,
                    error: decodeErr.rpcError
                )
                try? conn.writeLineData(try DaemonRPCCodec.encodeResponseLine(errResp))
                conn.close()
                return
            }

            switch envelope.call {
            case .status:
                let heldWithVersions = try await coordinator.daemonHeldVMsWithGuestAgentVersions()
                let statusVMs = heldWithVersions.map { entry in
                    DaemonRPCStatusVM(
                        record: entry.record,
                        guestAgentVersion: entry.guestAgentVersion
                    )
                }
                let payload = DaemonRPCStatusResult(
                    pid: holderInfo.pid,
                    startedAt: holderInfo.startedAt,
                    socketPath: address.connectSocketPath,
                    workspacePath: paths.canonicalWorkspacePath,
                    executablePath: executablePath,
                    protocolVersion: protocolVersion,
                    semanticVersion: semanticVersion,
                    vms: statusVMs
                )
                let resp = DaemonRPCResponse<DaemonRPCStatusResult>.success(id: envelope.id, result: payload)
                try? conn.writeLineData(try DaemonRPCCodec.encodeResponseLine(resp))
                conn.close()

            case let .stop(params):
                // Halt all running VMs (writing VM_STOPPED), remove socket & symlink, and clear/unlock daemon.lock
                // strictly in order before returning the RPC response and exiting.
                let stoppedIDs = await stopGate.runOnce { [self] in
                    markStopping()
                    logManager.appendLine("stopping (rpc-stop): shutting down held machines...")
                    if let onShutdownAllMachines {
                        await onShutdownAllMachines()
                    }
                    let halted = await coordinator.shutdownAllDaemonHeldVMs(language: params.lang)
                    listener.close(unlinkSocket: true, removeSymlink: true)
                    singletonLock.release(clearFile: true)
                    return halted
                }
                let resp = DaemonRPCResponse<DaemonRPCStopResult>.success(
                    id: envelope.id,
                    result: DaemonRPCStopResult(stoppedVMIDs: stoppedIDs)
                )
                try? conn.writeLineData(try DaemonRPCCodec.encodeResponseLine(resp))
                conn.close()
                logManager.appendLine("stopped (rpc-stop, stoppedVMs=\(stoppedIDs.count))")
                logManager.close()
                resumeStopWaiters()

            case let .list(params):
                let vms = try await coordinator.listVMsForReporting(language: params.lang)
                let resp = DaemonRPCResponse<DaemonRPCListResult>.success(
                    id: envelope.id,
                    result: DaemonRPCListResult(vms: vms)
                )
                try? conn.writeLineData(try DaemonRPCCodec.encodeResponseLine(resp))
                conn.close()

            case let .up(params):
                await handleLifecycleCall(id: envelope.id, action: "up", params: params, conn: conn)

            case let .halt(params):
                await handleLifecycleCall(id: envelope.id, action: "halt", params: params, conn: conn)

            case let .pause(params):
                await handleLifecycleCall(id: envelope.id, action: "pause", params: params, conn: conn)

            case let .resume(params):
                await handleLifecycleCall(id: envelope.id, action: "resume", params: params, conn: conn)

            case let .exec(params):
                await handleExecCall(id: envelope.id, params: params, conn: conn)

            case let .snapshot(params):
                await handleSnapshotCall(id: envelope.id, params: params, conn: conn)

            case let .branch(params):
                await handleBranchCall(id: envelope.id, params: params, conn: conn)

            case let .restore(params):
                await handleRestoreCall(id: envelope.id, params: params, conn: conn)
            }
        } catch {
            conn.close()
        }
    }

    private func resolveVMID(_ token: String) async throws -> VMID {
        let vms = try await coordinator.store.listVMs()
        if let exact = vms.first(where: { $0.id.rawValue == token }) {
            return exact.id
        }
        if let byName = vms.first(where: { $0.spec.name.caseInsensitiveCompare(token) == .orderedSame }) {
            return byName.id
        }
        throw AgentVMError.vmNotFound(VMID(token))
    }

    private func handleLifecycleCall(
        id: DaemonRPCID,
        action: String,
        params: DaemonRPCVMLifecycleParams,
        conn: DaemonSocketConnection
    ) async {
        defer { conn.close() }
        do {
            let vmID = try await resolveVMID(params.vm)
            let updated: VMInstanceRecord
            switch action {
            case "up":
                updated = try await coordinator.bootPersistentVM(vmID)
            case "halt":
                updated = try await coordinator.haltVM(vmID, language: params.lang)
            case "pause":
                updated = try await coordinator.pauseVM(vmID, language: params.lang)
            default:
                updated = try await coordinator.resumeVM(vmID, language: params.lang)
            }
            let resp = DaemonRPCResponse<DaemonRPCVMLifecycleResult>.success(
                id: id,
                result: DaemonRPCVMLifecycleResult(vm: updated)
            )
            try? conn.writeLineData(try DaemonRPCCodec.encodeResponseLine(resp))
        } catch let err as AgentVMError {
            let resp = DaemonRPCResponse<DaemonRPCVMLifecycleResult>.failure(
                id: id,
                agentVMError: err,
                language: params.lang
            )
            try? conn.writeLineData(try DaemonRPCCodec.encodeResponseLine(resp))
        } catch {
            let rpcErr = DaemonRPCError(
                code: DaemonRPCError.internalErrorCode,
                errorCode: "ERR_DAEMON_INTERNAL",
                message: error.localizedDescription
            )
            let resp = DaemonRPCResponse<DaemonRPCVMLifecycleResult>.failure(id: id, error: rpcErr)
            try? conn.writeLineData(try DaemonRPCCodec.encodeResponseLine(resp))
        }
    }

    private func handleSnapshotCall(
        id: DaemonRPCID,
        params: DaemonRPCSnapshotParams,
        conn: DaemonSocketConnection
    ) async {
        defer { conn.close() }
        do {
            let vmID = try await resolveVMID(params.vm)
            let snapRes = try await coordinator.captureSnapshotInDaemon(
                vmID: vmID,
                title: params.title,
                notes: params.notes,
                kind: params.kind,
                branchName: params.branchName,
                isPinned: params.isPinned,
                triggerCommand: params.triggerCommand
            )
            let resp = DaemonRPCResponse<DaemonRPCSnapshotResult>.success(
                id: id,
                result: DaemonRPCSnapshotResult(
                    snapshot: snapRes.snapshot,
                    diskCloneStrategy: snapRes.diskCloneStrategy,
                    pauseDurationMilliseconds: snapRes.pauseDurationMilliseconds
                )
            )
            try? conn.writeLineData(try DaemonRPCCodec.encodeResponseLine(resp))
        } catch let err as AgentVMError {
            let resp = DaemonRPCResponse<DaemonRPCSnapshotResult>.failure(
                id: id,
                agentVMError: err,
                language: params.lang
            )
            try? conn.writeLineData(try DaemonRPCCodec.encodeResponseLine(resp))
        } catch {
            let rpcErr = DaemonRPCError(
                code: DaemonRPCError.internalErrorCode,
                errorCode: "ERR_DAEMON_INTERNAL",
                message: error.localizedDescription
            )
            let resp = DaemonRPCResponse<DaemonRPCSnapshotResult>.failure(id: id, error: rpcErr)
            try? conn.writeLineData(try DaemonRPCCodec.encodeResponseLine(resp))
        }
    }

    private func handleBranchCall(
        id: DaemonRPCID,
        params: DaemonRPCBranchParams,
        conn: DaemonSocketConnection
    ) async {
        defer { conn.close() }
        do {
            let parentID = try await resolveVMID(params.vm)
            let branchRes = try await coordinator.forkBranchInDaemon(
                fromVMID: parentID,
                branchName: params.branchName,
                agentOwnerTag: params.owner,
                inheritMounts: params.inheritMounts
            )
            let resp = DaemonRPCResponse<DaemonRPCBranchResult>.success(
                id: id,
                result: DaemonRPCBranchResult(
                    fork: branchRes.fork,
                    pauseDurationMilliseconds: branchRes.pauseDurationMilliseconds
                )
            )
            try? conn.writeLineData(try DaemonRPCCodec.encodeResponseLine(resp))
        } catch let err as AgentVMError {
            let resp = DaemonRPCResponse<DaemonRPCBranchResult>.failure(
                id: id,
                agentVMError: err,
                language: params.lang
            )
            try? conn.writeLineData(try DaemonRPCCodec.encodeResponseLine(resp))
        } catch {
            let rpcErr = DaemonRPCError(
                code: DaemonRPCError.internalErrorCode,
                errorCode: "ERR_DAEMON_INTERNAL",
                message: error.localizedDescription
            )
            let resp = DaemonRPCResponse<DaemonRPCBranchResult>.failure(id: id, error: rpcErr)
            try? conn.writeLineData(try DaemonRPCCodec.encodeResponseLine(resp))
        }
    }

    private func handleRestoreCall(
        id: DaemonRPCID,
        params: DaemonRPCRestoreParams,
        conn: DaemonSocketConnection
    ) async {
        defer { conn.close() }
        do {
            let restoreRes = try await coordinator.restoreSnapshotInDaemon(
                SnapshotID(params.snapshotID),
                language: params.lang
            )
            let resp = DaemonRPCResponse<DaemonRPCRestoreResult>.success(
                id: id,
                result: DaemonRPCRestoreResult(
                    vm: restoreRes.record,
                    preRestoreSnapshot: restoreRes.preRestoreSnapshot,
                    diskCloneStrategy: restoreRes.diskCloneStrategy
                )
            )
            try? conn.writeLineData(try DaemonRPCCodec.encodeResponseLine(resp))
        } catch let err as AgentVMError {
            let resp = DaemonRPCResponse<DaemonRPCRestoreResult>.failure(
                id: id,
                agentVMError: err,
                language: params.lang
            )
            try? conn.writeLineData(try DaemonRPCCodec.encodeResponseLine(resp))
        } catch {
            let rpcErr = DaemonRPCError(
                code: DaemonRPCError.internalErrorCode,
                errorCode: "ERR_DAEMON_INTERNAL",
                message: error.localizedDescription
            )
            let resp = DaemonRPCResponse<DaemonRPCRestoreResult>.failure(id: id, error: rpcErr)
            try? conn.writeLineData(try DaemonRPCCodec.encodeResponseLine(resp))
        }
    }

    private func handleExecCall(
        id: DaemonRPCID,
        params: DaemonRPCExecParams,
        conn: DaemonSocketConnection
    ) async {
        let disconnectMonitor = DaemonExecClientDisconnectMonitor(fd: conn.fd)
        let lineWriter = DaemonAbortableSocketLineWriter(fd: conn.fd)
        do {
            let vmID = try await resolveVMID(params.vm)
            let req = GuestExecRequest(
                executable: params.executable,
                arguments: params.arguments,
                workingDirectory: params.workingDirectory,
                environment: params.environment,
                runAsUser: params.runAsUser,
                timeoutSeconds: params.timeoutSeconds
            )
            disconnectMonitor.start { [coordinator] streamID in
                lineWriter.abort()
                Task {
                    await coordinator.cancelDaemonExecStream(
                        vmID: vmID,
                        streamID: streamID,
                        reason: "Exec cancelled by client disconnect."
                    )
                }
            }
            let execResult = try await coordinator.executeInRunningDaemonVM(
                vmID: vmID,
                request: req,
                language: params.lang,
                onStreamOpened: { streamID in
                    disconnectMonitor.bindStreamID(streamID)
                },
                onOutputChunk: { chunk in
                    guard !chunk.data.isEmpty, !disconnectMonitor.isDisconnected, !lineWriter.isAborted else { return }
                    let outStream: DaemonRPCExecStream
                    switch chunk.stream {
                    case .stdout:
                        outStream = .stdout
                    case .stderr, .systemNotice:
                        outStream = .stderr
                    }
                    let notif = DaemonRPCExecOutputParams(stream: outStream, data: chunk.data)
                    guard let encoded = try? DaemonRPCCodec.encodeExecOutputLine(notif) else { return }
                    do {
                        try await lineWriter.writeLine(encoded)
                    } catch {
                        if !lineWriter.isAborted {
                            disconnectMonitor.triggerDisconnect()
                        }
                    }
                }
            )
            await lineWriter.waitForIdle()
            await disconnectMonitor.stop()
            if !disconnectMonitor.isDisconnected {
                let resp = DaemonRPCResponse<DaemonRPCExecResult>.success(
                    id: id,
                    result: DaemonRPCExecResult(
                        exitCode: execResult.exitCode,
                        timedOut: execResult.timedOut
                    )
                )
                if let encodedResp = try? DaemonRPCCodec.encodeResponseLine(resp) {
                    try? await lineWriter.writeLine(encodedResp)
                }
            }
            await lineWriter.waitForIdle()
            conn.close()
        } catch let err as AgentVMError {
            lineWriter.abort()
            await lineWriter.waitForIdle()
            await disconnectMonitor.stop()
            if !disconnectMonitor.isDisconnected {
                let resp = DaemonRPCResponse<DaemonRPCExecResult>.failure(
                    id: id,
                    agentVMError: err,
                    language: params.lang
                )
                if let encodedResp = try? DaemonRPCCodec.encodeResponseLine(resp) {
                    if case .execOutputBufferOverflow = err {
                        if !lineWriter.wrotePartialLine {
                            _ = lineWriter.tryWriteCompleteLineNonBlocking(encodedResp)
                        }
                    } else if !lineWriter.wrotePartialLine {
                        try? conn.writeLineData(encodedResp)
                    }
                }
            }
            conn.close()
        } catch {
            lineWriter.abort()
            await lineWriter.waitForIdle()
            await disconnectMonitor.stop()
            if !disconnectMonitor.isDisconnected && !lineWriter.wrotePartialLine {
                let rpcErr = DaemonRPCError(
                    code: DaemonRPCError.internalErrorCode,
                    errorCode: "ERR_DAEMON_INTERNAL",
                    message: error.localizedDescription
                )
                let resp = DaemonRPCResponse<DaemonRPCExecResult>.failure(id: id, error: rpcErr)
                if let encodedResp = try? DaemonRPCCodec.encodeResponseLine(resp) {
                    try? conn.writeLineData(encodedResp)
                }
            }
            conn.close()
        }
    }
}

/// Non-blocking, abortable per-exec socket line writer running on a dedicated serial GCD queue so slow/stalled
/// `exec` clients never block Swift's cooperative thread pool or `VsockMultiplexSession`, and >2x queue overflow
/// aborts cleanly in <= 20 ms without closing `fd` under an in-flight write.
private final class DaemonAbortableSocketLineWriter: @unchecked Sendable {
    private let lock = NSLock()
    private let fd: Int32
    private let queue: DispatchQueue
    private var aborted = false
    private var partialLineFlag = false
    private var activeWrites = 0
    private var idleWaiters: [CheckedContinuation<Void, Never>] = []

    init(fd: Int32) {
        self.fd = fd
        self.queue = DispatchQueue(label: "io.zxu756.agentvm.daemon.exec-write.\(fd)", qos: .userInitiated)
    }

    var isAborted: Bool {
        lock.withLock { aborted }
    }

    var wrotePartialLine: Bool {
        lock.withLock { partialLineFlag }
    }

    func abort() {
        lock.withLock {
            aborted = true
        }
    }

    func waitForIdle() async {
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            let alreadyIdle = lock.withLock { () -> Bool in
                if activeWrites == 0 {
                    return true
                }
                idleWaiters.append(cont)
                return false
            }
            if alreadyIdle {
                cont.resume()
            }
        }
    }

    func writeLine(
        _ lineData: Data,
        maxLineBytes: Int = DaemonRPCLineFraming.maxLineBytes
    ) async throws {
        guard !lineData.contains(0x0A) else {
            throw DaemonRPCLineFramingError.embeddedNewlineInOutgoingLine
        }
        guard lineData.count <= maxLineBytes else {
            throw DaemonRPCLineFramingError.lineTooLong(limitBytes: maxLineBytes)
        }
        let started = lock.withLock { () -> Bool in
            if aborted || fd < 0 {
                return false
            }
            activeWrites += 1
            return true
        }
        guard started else {
            throw CancellationError()
        }

        var framedBuffer = Data()
        framedBuffer.reserveCapacity(lineData.count + 1)
        framedBuffer.append(lineData)
        framedBuffer.append(0x0A)
        let framed = framedBuffer

        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            queue.async { [self] in
                defer { self.finishOneActiveWrite() }
                let result: Result<Void, Error> = framed.withUnsafeBytes { rawBuf in
                    guard let base = rawBuf.baseAddress else {
                        return .success(())
                    }
                    var offset = 0
                    let total = rawBuf.count
                    while offset < total {
                        if self.isAborted {
                            if offset > 0 {
                                self.lock.withLock { self.partialLineFlag = true }
                            }
                            return .failure(CancellationError())
                        }
                        let n = Darwin.send(self.fd, base.advanced(by: offset), total - offset, Int32(MSG_DONTWAIT))
                        if n > 0 {
                            offset += n
                        } else if n < 0 {
                            let code = Darwin.errno
                            if code == EINTR {
                                continue
                            }
                            if code == EAGAIN || code == EWOULDBLOCK {
                                var pfd = Darwin.pollfd(fd: self.fd, events: Int16(POLLOUT), revents: 0)
                                _ = Darwin.poll(&pfd, 1, 20)
                                continue
                            }
                            if offset > 0 {
                                self.lock.withLock { self.partialLineFlag = true }
                            }
                            return .failure(
                                DaemonRPCLineFramingError.ioError(
                                    errnoCode: code,
                                    detail: String(cString: Darwin.strerror(code))
                                )
                            )
                        } else {
                            if offset > 0 {
                                self.lock.withLock { self.partialLineFlag = true }
                            }
                            return .failure(
                                DaemonRPCLineFramingError.ioError(
                                    errnoCode: EPIPE,
                                    detail: "Zero-byte send on daemon socket."
                                )
                            )
                        }
                    }
                    return .success(())
                }
                cont.resume(with: result)
            }
        }
    }

    /// Best-effort single-shot non-blocking write used only when a clean line boundary exists on overflow teardown.
    func tryWriteCompleteLineNonBlocking(_ lineData: Data) -> Bool {
        guard !lineData.contains(0x0A), fd >= 0 else { return false }
        var framed = Data()
        framed.reserveCapacity(lineData.count + 1)
        framed.append(lineData)
        framed.append(0x0A)
        return framed.withUnsafeBytes { rawBuf -> Bool in
            guard let base = rawBuf.baseAddress else { return false }
            let n = Darwin.send(fd, base, rawBuf.count, Int32(MSG_DONTWAIT))
            return n == rawBuf.count
        }
    }

    private func finishOneActiveWrite() {
        let waiters = lock.withLock { () -> [CheckedContinuation<Void, Never>] in
            activeWrites = max(0, activeWrites - 1)
            if activeWrites == 0 {
                let copy = idleWaiters
                idleWaiters.removeAll()
                return copy
            }
            return []
        }
        for w in waiters {
            w.resume()
        }
    }
}

/// Monitors an `exec` client's Unix socket descriptor for EOF/disconnect without setting `O_NONBLOCK`
/// on the shared open file description (`MSG_DONTWAIT`), guaranteeing `setCancelHandler` completes
/// before `DaemonSocketConnection.close()` closes the descriptor.
private final class DaemonExecClientDisconnectMonitor: @unchecked Sendable {
    private let lock = NSLock()
    private let fd: Int32
    private var source: DispatchSourceRead?
    private var onCancelStream: (@Sendable (UInt32) -> Void)?
    private var boundStreamID: UInt32?
    private var disconnected = false
    private var cancelFired = false
    private var sourceStopped = false
    private var stopWaiters: [CheckedContinuation<Void, Never>] = []

    init(fd: Int32) {
        self.fd = fd
    }

    var isDisconnected: Bool {
        lock.withLock { disconnected }
    }

    func start(onCancelStream: @escaping @Sendable (UInt32) -> Void) {
        guard fd >= 0 else {
            lock.withLock {
                disconnected = true
                sourceStopped = true
            }
            return
        }
        let queue = DispatchQueue(label: "io.zxu756.agentvm.daemon.exec-eof.\(fd)", qos: .userInitiated)
        let readSource = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        let descriptor = fd

        readSource.setEventHandler { [weak self] in
            var scratch = [UInt8](repeating: 0, count: 64)
            let n = Darwin.recv(descriptor, &scratch, scratch.count, MSG_DONTWAIT)
            if n == 0 {
                self?.triggerDisconnect()
                readSource.cancel()
            } else if n < 0 {
                let code = Darwin.errno
                if code != EAGAIN && code != EWOULDBLOCK && code != EINTR {
                    self?.triggerDisconnect()
                    readSource.cancel()
                }
            }
        }

        readSource.setCancelHandler { [weak self] in
            guard let self else { return }
            let waiters = self.lock.withLock { () -> [CheckedContinuation<Void, Never>] in
                self.sourceStopped = true
                let all = self.stopWaiters
                self.stopWaiters.removeAll()
                return all
            }
            for w in waiters {
                w.resume()
            }
        }

        let immediateStreamToCancel: UInt32? = lock.withLock {
            self.onCancelStream = onCancelStream
            self.source = readSource
            if self.disconnected, !self.cancelFired, let sid = self.boundStreamID {
                self.cancelFired = true
                return sid
            }
            return nil
        }
        readSource.resume()
        if let sid = immediateStreamToCancel {
            onCancelStream(sid)
        }
    }

    func bindStreamID(_ streamID: UInt32) {
        let action: ((@Sendable (UInt32) -> Void), UInt32)? = lock.withLock {
            boundStreamID = streamID
            if disconnected, !cancelFired, let cb = onCancelStream {
                cancelFired = true
                return (cb, streamID)
            }
            return nil
        }
        if let (cb, sid) = action {
            cb(sid)
        }
    }

    func triggerDisconnect() {
        let action: ((@Sendable (UInt32) -> Void), UInt32)? = lock.withLock {
            disconnected = true
            if !cancelFired, let sid = boundStreamID, let cb = onCancelStream {
                cancelFired = true
                return (cb, sid)
            }
            return nil
        }
        if let (cb, sid) = action {
            cb(sid)
        }
    }

    func stop() async {
        let (srcToCancel, alreadyDone) = lock.withLock { () -> (DispatchSourceRead?, Bool) in
            if source == nil || sourceStopped {
                return (nil, true)
            }
            return (source, false)
        }
        if alreadyDone {
            return
        }
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            let resumeNow = lock.withLock { () -> Bool in
                if sourceStopped {
                    return true
                }
                stopWaiters.append(cont)
                return false
            }
            if resumeNow {
                cont.resume()
            } else {
                srcToCancel?.cancel()
            }
        }
    }
}

private actor DaemonAsyncStopGate {
    private var completedResult: [VMID]?
    private var inFlightTask: Task<[VMID], Never>?

    func runOnce(_ operation: @Sendable @escaping () async -> [VMID]) async -> [VMID] {
        if let completedResult {
            return completedResult
        }
        if let inFlightTask {
            return await inFlightTask.value
        }
        let task = Task {
            await operation()
        }
        inFlightTask = task
        let result = await task.value
        completedResult = result
        inFlightTask = nil
        return result
    }
}

// MARK: - Daemon Unix Socket RPC Client (Connect-Only & Handshake Verification)

public enum DaemonClientConnectionResult<Payload: Sendable>: Sendable {
    case connected(Payload)
    case daemonNotRunning
}

public enum DaemonClient {
    private static func isDaemonAbsentSocketError(_ error: DaemonSocketError) -> Bool {
        if case let .syscallFailed(op, _, errnoCode, _) = error {
            if op == "connect" && (errnoCode == ENOENT || errnoCode == ECONNREFUSED || errnoCode == ECONNRESET) {
                return true
            }
        }
        return false
    }

    public static func performUnaryCall<ResultPayload: Codable & Sendable>(
        workspaceURL: URL,
        call: DaemonRPCCall,
        resultType: ResultPayload.Type = ResultPayload.self,
        enforceVersionMatch: Bool = true,
        clientHelloOverride: DaemonRPCHello? = nil,
        userTempDirectoryOverride: URL? = nil
    ) throws -> DaemonClientConnectionResult<(daemonHello: DaemonRPCHello, result: ResultPayload)> {
        _ = resultType
        let conn: DaemonSocketConnection
        do {
            conn = try DaemonSocketClient.connectWorkspace(
                workspaceURL: workspaceURL,
                userTempDirectoryOverride: userTempDirectoryOverride
            )
        } catch let sockErr as DaemonSocketError {
            if isDaemonAbsentSocketError(sockErr) {
                return .daemonNotRunning
            }
            throw sockErr
        }
        defer { conn.close() }

        let clientHello = clientHelloOverride ?? DaemonRPCHello(
            executablePath: DaemonExecutableLocator.resolveCurrentExecutablePath()
        )
        let reader = conn.makeLineReader()

        do {
            try conn.writeLineData(try DaemonRPCCodec.encodeHelloLine(clientHello))
            guard let daemonHelloLine = try reader.readLineData() else {
                return .daemonNotRunning
            }
            let daemonHello = try DaemonRPCCodec.decodeHelloLine(daemonHelloLine)
            if enforceVersionMatch {
                try clientHello.verifyCompatibility(withDaemon: daemonHello, language: call.language)
            }

            let envelope = DaemonRPCRequestEnvelope(id: .int(1), call: call)
            try conn.writeLineData(try DaemonRPCCodec.encodeRequestLine(envelope))

            guard let respLine = try reader.readLineData() else {
                throw DaemonSocketError.syscallFailed(
                    operation: "read(response)",
                    path: DaemonWorkspacePaths(workspaceURL: workspaceURL).directSocketPath,
                    errnoCode: ECONNRESET,
                    detail: "Daemon closed connection before sending JSON-RPC response."
                )
            }
            let decoded = try DaemonRPCCodec.decodeResponseLine(ResultPayload.self, from: respLine)
            let payload = try decoded.resultOrThrow()
            return .connected((daemonHello, payload))
        } catch let framingErr as DaemonRPCLineFramingError {
            if case let .ioError(code, _) = framingErr, code == ECONNRESET || code == EPIPE {
                return .daemonNotRunning
            }
            throw framingErr
        }
    }

    public static func performExecCall(
        workspaceURL: URL,
        params: DaemonRPCExecParams,
        enforceVersionMatch: Bool = true,
        clientHelloOverride: DaemonRPCHello? = nil,
        userTempDirectoryOverride: URL? = nil,
        onConnectionEstablished: ((DaemonSocketConnection) -> Void)? = nil,
        onOutputChunk: ((DaemonRPCExecOutputParams) -> Void)? = nil
    ) throws -> DaemonClientConnectionResult<(daemonHello: DaemonRPCHello, result: DaemonRPCExecResult)> {
        let conn: DaemonSocketConnection
        do {
            conn = try DaemonSocketClient.connectWorkspace(
                workspaceURL: workspaceURL,
                userTempDirectoryOverride: userTempDirectoryOverride
            )
        } catch let sockErr as DaemonSocketError {
            if isDaemonAbsentSocketError(sockErr) {
                return .daemonNotRunning
            }
            throw sockErr
        }
        defer { conn.close() }
        onConnectionEstablished?(conn)

        let clientHello = clientHelloOverride ?? DaemonRPCHello(
            executablePath: DaemonExecutableLocator.resolveCurrentExecutablePath()
        )
        let reader = conn.makeLineReader()
        var requestDispatched = false

        do {
            try conn.writeLineData(try DaemonRPCCodec.encodeHelloLine(clientHello))
            guard let daemonHelloLine = try reader.readLineData() else {
                return .daemonNotRunning
            }
            let daemonHello = try DaemonRPCCodec.decodeHelloLine(daemonHelloLine)
            if enforceVersionMatch {
                try clientHello.verifyCompatibility(withDaemon: daemonHello, language: params.lang)
            }

            let envelope = DaemonRPCRequestEnvelope(id: .int(1), call: .exec(params))
            try conn.writeLineData(try DaemonRPCCodec.encodeRequestLine(envelope))
            requestDispatched = true

            while true {
                guard let frameLine = try reader.readLineData() else {
                    throw AgentVMError.ipcDaemonUnavailable(
                        socketPath: DaemonWorkspacePaths(workspaceURL: workspaceURL).directSocketPath,
                        detail: "Daemon closed connection before sending exec response."
                    )
                }
                let serverFrame = try DaemonRPCCodec.decodeServerFrame(DaemonRPCExecResult.self, from: frameLine)
                switch serverFrame {
                case let .execOutput(chunk):
                    onOutputChunk?(chunk)
                case let .response(resp):
                    let payload = try resp.resultOrThrow()
                    return .connected((daemonHello, payload))
                }
            }
        } catch let framingErr as DaemonRPCLineFramingError {
            if !requestDispatched,
               case let .ioError(code, _) = framingErr,
               code == ECONNRESET || code == EPIPE {
                return .daemonNotRunning
            }
            throw framingErr
        }
    }

    public static func queryStatus(
        workspaceURL: URL,
        language: AppLanguage,
        clientHelloOverride: DaemonRPCHello? = nil,
        userTempDirectoryOverride: URL? = nil
    ) throws -> DaemonClientConnectionResult<DaemonRPCStatusResult> {
        let outcome = try performUnaryCall(
            workspaceURL: workspaceURL,
            call: .status(DaemonRPCStatusParams(lang: language)),
            resultType: DaemonRPCStatusResult.self,
            enforceVersionMatch: true,
            clientHelloOverride: clientHelloOverride,
            userTempDirectoryOverride: userTempDirectoryOverride
        )
        switch outcome {
        case .daemonNotRunning:
            return .daemonNotRunning
        case let .connected((_, status)):
            return .connected(status)
        }
    }

    /// Connect-only probe returning `true` iff a workspace daemon is currently running and holding `vmID` in memory.
    /// Never spawns a daemon and never touches `<workspace>/locks/<vmID>.lock`.
    public static func isVMHeldByRunningDaemon(
        workspaceURL: URL,
        vmID: VMID,
        language: AppLanguage
    ) throws -> Bool {
        let statusOutcome = try queryStatus(workspaceURL: workspaceURL, language: language)
        switch statusOutcome {
        case .daemonNotRunning:
            return false
        case let .connected(status):
            return status.vms.contains(where: { $0.id == vmID })
        }
    }

    public static func stopDaemon(
        workspaceURL: URL,
        language: AppLanguage,
        userTempDirectoryOverride: URL? = nil,
        waitTimeoutSeconds: TimeInterval = 65.0
    ) throws -> DaemonClientConnectionResult<(pid: Int32?, result: DaemonRPCStopResult)> {
        let paths = DaemonWorkspacePaths(workspaceURL: workspaceURL)
        let lockHolderBefore = DaemonSingletonLock.readHolderInfo(at: paths.lockFileURL)
        let plan = try? DaemonSocketAddressResolver.computePlan(
            for: workspaceURL,
            userTempDirectoryOverride: userTempDirectoryOverride
        )

        let outcome = try performUnaryCall(
            workspaceURL: workspaceURL,
            call: .stop(DaemonRPCStopParams(lang: language)),
            resultType: DaemonRPCStopResult.self,
            enforceVersionMatch: false,
            userTempDirectoryOverride: userTempDirectoryOverride
        )

        switch outcome {
        case .daemonNotRunning:
            return .daemonNotRunning
        case let .connected((_, stopRes)):
            let targetPID = lockHolderBefore?.pid
            let deadline = DispatchTime.now().uptimeNanoseconds &+ UInt64(max(0.1, waitTimeoutSeconds) * 1_000_000_000)
            while DispatchTime.now().uptimeNanoseconds < deadline {
                var st = Darwin.stat()
                let sockGone = (Darwin.lstat(paths.directSocketPath, &st) != 0 && Darwin.errno == ENOENT)
                let symGone: Bool = {
                    guard let symURL = plan?.symlinkURL else { return true }
                    return Darwin.lstat(symURL.path, &st) != 0 && Darwin.errno == ENOENT
                }()
                let procGone: Bool = {
                    guard let pid = targetPID, pid > 0, pid != Darwin.getpid() else { return true }
                    var reapStatus: Int32 = 0
                    _ = Darwin.waitpid(pid, &reapStatus, WNOHANG)
                    return Darwin.kill(pid, 0) != 0 && Darwin.errno == ESRCH
                }()
                if sockGone && symGone && procGone {
                    break
                }
                    Darwin.usleep(20_000)
                }
                return .connected((targetPID, stopRes))
            }
        }
    }

// MARK: - Detached `posix_spawn` Daemon Launcher (`daemon start` & `up`)

public struct DaemonSpawnCommandOverride: Hashable, Sendable {
    public var executablePath: String
    public var arguments: [String]
    public var environment: [String: String]?

    public init(
        executablePath: String,
        arguments: [String],
        environment: [String: String]? = nil
    ) {
        self.executablePath = executablePath
        self.arguments = arguments
        self.environment = environment
    }
}

public enum DaemonLaunchOutcome: Sendable {
    case started(DaemonRPCStatusResult)
    case alreadyRunning(DaemonRPCStatusResult)

    public var status: DaemonRPCStatusResult {
        switch self {
        case let .started(s), let .alreadyRunning(s):
            return s
        }
    }

    public var wasAlreadyRunning: Bool {
        if case .alreadyRunning = self {
            return true
        }
        return false
    }
}

public enum DaemonLaunchError: Error, LocalizedError, Hashable, Sendable {
    case posixSpawnFailed(executablePath: String, errnoCode: Int32, detail: String)
    case childExitedNonZero(pid: Int32, exitCode: Int32?, signal: Int32?, logFilePath: String, logTail: String)
    case startupTimedOut(timeoutSeconds: TimeInterval, logFilePath: String, logTail: String)

    public var errorCode: String {
        "ERR_DAEMON_IPC"
    }

    public var errorDescription: String? {
        localizedMessage(in: .en)
    }

    public func localizedMessage(in language: AppLanguage) -> String {
        let isZh = (language == .zhHans)
        switch self {
        case let .posixSpawnFailed(executablePath, errnoCode, detail):
            return isZh
                ? "无法通过 posix_spawn 拉起工作区守护进程「\(executablePath)」（errno=\(errnoCode)）：\(detail)"
                : "Failed spawning workspace daemon '\(executablePath)' via posix_spawn (errno=\(errnoCode)): \(detail)"
        case let .childExitedNonZero(pid, exitCode, signal, logFilePath, logTail):
            let statusDesc: String
            if let exitCode {
                statusDesc = isZh ? "退出码 \(exitCode)" : "exit code \(exitCode)"
            } else if let signal {
                statusDesc = isZh ? "信号 \(signal)" : "signal \(signal)"
            } else {
                statusDesc = isZh ? "未知状态" : "unknown status"
            }
            var msg = isZh
                ? "工作区守护进程（PID \(pid)）在就绪前异常退出（\(statusDesc)）。日志「\(logFilePath)」最后 20 行："
                : "Workspace daemon (PID \(pid)) exited before becoming ready (\(statusDesc)). Last 20 lines of '\(logFilePath)':"
            if !logTail.isEmpty {
                msg += "\n" + logTail
            } else {
                msg += isZh ? "（日志为空）" : " (log is empty)"
            }
            return msg
        case let .startupTimedOut(timeoutSeconds, logFilePath, logTail):
            let secs = Int(timeoutSeconds.rounded())
            var msg = isZh
                ? "等待工作区守护进程就绪超时（\(secs) 秒）。日志「\(logFilePath)」最后 20 行："
                : "Timed out after \(secs)s waiting for workspace daemon to become ready. Last 20 lines of '\(logFilePath)':"
            if !logTail.isEmpty {
                msg += "\n" + logTail
            } else {
                msg += isZh ? "（日志为空）" : " (log is empty)"
            }
            return msg
        }
    }
}

public enum DaemonProcessLauncher {
    private enum DecodedWaitStatus {
        case running
        case exited(Int32)
        case signaled(Int32)
    }

    private static func decodeWaitStatus(_ status: Int32) -> DecodedWaitStatus {
        let low7 = status & 0x7f
        if low7 == 0 {
            return .exited((status >> 8) & 0xff)
        }
        if low7 != 0x7f {
            return .signaled(low7)
        }
        return .running
    }

    public static func launchOrConnect(
        workspaceURL: URL,
        language: AppLanguage,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        spawnOverride: DaemonSpawnCommandOverride? = nil,
        pollIntervalMilliseconds: UInt64 = 100,
        timeoutSeconds: TimeInterval = 15.0,
        userTempDirectoryOverride: URL? = nil
    ) async throws -> DaemonLaunchOutcome {
        let paths = DaemonWorkspacePaths(workspaceURL: workspaceURL)

        // 1. If a compatible daemon is already listening on this workspace, return its status immediately.
        if case let .connected(existingStatus) = try DaemonClient.queryStatus(
            workspaceURL: paths.workspaceURL,
            language: language,
            userTempDirectoryOverride: userTempDirectoryOverride
        ) {
            return .alreadyRunning(existingStatus)
        }

        // 2. Ensure `<workspace>/logs` directory exists before opening `daemon.log` in `posix_spawn_file_actions`.
        do {
            try FileManager.default.createDirectory(
                at: paths.logsDirectoryURL,
                withIntermediateDirectories: true
            )
        } catch {
            throw DaemonSocketError.syscallFailed(
                operation: "mkdir(logs)",
                path: paths.logsDirectoryURL.path,
                errnoCode: Darwin.errno,
                detail: error.localizedDescription
            )
        }

        // 3. Resolve executable (`_NSGetExecutablePath` + `realpath`) and construct `daemon run --workspace <abs>`.
        let execPath = spawnOverride?.executablePath ?? DaemonExecutableLocator.resolveCurrentExecutablePath()
        let argTail = spawnOverride?.arguments ?? ["daemon", "run", "--workspace", paths.canonicalWorkspacePath]
        let childEnv = spawnOverride?.environment ?? environment

        let childPID = try spawnDetachedDaemonProcess(
            executablePath: execPath,
            arguments: argTail,
            environment: childEnv,
            logFilePath: paths.daemonLogFileURL.path
        )

        // 4. Poll every 100 ms up to 15 s; check `waitpid(WNOHANG)` on each tick.
        var childReaped = false
        let deadline = DispatchTime.now().uptimeNanoseconds &+ UInt64(max(0.5, timeoutSeconds) * 1_000_000_000)
        let intervalNs = max(10, pollIntervalMilliseconds) * 1_000_000

        while true {
            if case let .connected(status) = try DaemonClient.queryStatus(
                workspaceURL: paths.workspaceURL,
                language: language,
                userTempDirectoryOverride: userTempDirectoryOverride
            ) {
                if !childReaped {
                    var st: Int32 = 0
                    if Darwin.waitpid(childPID, &st, WNOHANG) == childPID {
                        childReaped = true
                    }
                }
                if status.pid == childPID {
                    return .started(status)
                }
                return .alreadyRunning(status)
            }

            if !childReaped {
                var wstatus: Int32 = 0
                let wrc = Darwin.waitpid(childPID, &wstatus, WNOHANG)
                if wrc == childPID {
                    childReaped = true
                    switch decodeWaitStatus(wstatus) {
                    case .exited(0):
                        // Contender lost `daemon.lock` race and exited 0; continue polling winner.
                        break
                    case let .exited(code):
                        let tail = DaemonLogManager.readTailLines(at: paths.daemonLogFileURL, maxLines: 20)
                        throw DaemonLaunchError.childExitedNonZero(
                            pid: childPID,
                            exitCode: code,
                            signal: nil,
                            logFilePath: paths.daemonLogFileURL.path,
                            logTail: tail
                        )
                    case let .signaled(sig):
                        let tail = DaemonLogManager.readTailLines(at: paths.daemonLogFileURL, maxLines: 20)
                        throw DaemonLaunchError.childExitedNonZero(
                            pid: childPID,
                            exitCode: nil,
                            signal: sig,
                            logFilePath: paths.daemonLogFileURL.path,
                            logTail: tail
                        )
                    case .running:
                        break
                    }
                }
            }

            if DispatchTime.now().uptimeNanoseconds >= deadline {
                break
            }
            try? await Task.sleep(nanoseconds: intervalNs)
        }

        let tail = DaemonLogManager.readTailLines(at: paths.daemonLogFileURL, maxLines: 20)
        throw DaemonLaunchError.startupTimedOut(
            timeoutSeconds: timeoutSeconds,
            logFilePath: paths.daemonLogFileURL.path,
            logTail: tail
        )
    }

    private static func spawnDetachedDaemonProcess(
        executablePath: String,
        arguments: [String],
        environment: [String: String],
        logFilePath: String
    ) throws -> pid_t {
        var attr: posix_spawnattr_t?
        let attrInitRC = Darwin.posix_spawnattr_init(&attr)
        guard attrInitRC == 0 else {
            throw DaemonLaunchError.posixSpawnFailed(
                executablePath: executablePath,
                errnoCode: attrInitRC,
                detail: "posix_spawnattr_init failed: \(String(cString: Darwin.strerror(attrInitRC)))"
            )
        }
        defer { _ = Darwin.posix_spawnattr_destroy(&attr) }

        let spawnFlags = Int16(POSIX_SPAWN_SETSID | POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGMASK)
        let setFlagsRC = Darwin.posix_spawnattr_setflags(&attr, spawnFlags)
        guard setFlagsRC == 0 else {
            throw DaemonLaunchError.posixSpawnFailed(
                executablePath: executablePath,
                errnoCode: setFlagsRC,
                detail: "posix_spawnattr_setflags failed: \(String(cString: Darwin.strerror(setFlagsRC)))"
            )
        }

        var emptyMask = sigset_t()
        Darwin.sigemptyset(&emptyMask)
        _ = Darwin.posix_spawnattr_setsigmask(&attr, &emptyMask)

        var fileActions: posix_spawn_file_actions_t?
        let faInitRC = Darwin.posix_spawn_file_actions_init(&fileActions)
        guard faInitRC == 0 else {
            throw DaemonLaunchError.posixSpawnFailed(
                executablePath: executablePath,
                errnoCode: faInitRC,
                detail: "posix_spawn_file_actions_init failed: \(String(cString: Darwin.strerror(faInitRC)))"
            )
        }
        defer { _ = Darwin.posix_spawn_file_actions_destroy(&fileActions) }

        let addStdinRC = Darwin.posix_spawn_file_actions_addopen(
            &fileActions,
            STDIN_FILENO,
            "/dev/null",
            O_RDONLY,
            0
        )
        guard addStdinRC == 0 else {
            throw DaemonLaunchError.posixSpawnFailed(
                executablePath: executablePath,
                errnoCode: addStdinRC,
                detail: "posix_spawn_file_actions_addopen(/dev/null) failed: \(String(cString: Darwin.strerror(addStdinRC)))"
            )
        }

        let logOpenFlags = O_WRONLY | O_CREAT | O_APPEND
        let addStdoutRC = Darwin.posix_spawn_file_actions_addopen(
            &fileActions,
            STDOUT_FILENO,
            logFilePath,
            logOpenFlags,
            mode_t(0o600)
        )
        guard addStdoutRC == 0 else {
            throw DaemonLaunchError.posixSpawnFailed(
                executablePath: executablePath,
                errnoCode: addStdoutRC,
                detail: "posix_spawn_file_actions_addopen(stdout->daemon.log) failed: \(String(cString: Darwin.strerror(addStdoutRC)))"
            )
        }

        let addStderrRC = Darwin.posix_spawn_file_actions_addopen(
            &fileActions,
            STDERR_FILENO,
            logFilePath,
            logOpenFlags,
            mode_t(0o600)
        )
        guard addStderrRC == 0 else {
            throw DaemonLaunchError.posixSpawnFailed(
                executablePath: executablePath,
                errnoCode: addStderrRC,
                detail: "posix_spawn_file_actions_addopen(stderr->daemon.log) failed: \(String(cString: Darwin.strerror(addStderrRC)))"
            )
        }

        let fullArgv = [executablePath] + arguments
        var cArgv: [UnsafeMutablePointer<CChar>?] = fullArgv.map { Darwin.strdup($0) }
        cArgv.append(nil)
        defer {
            for ptr in cArgv where ptr != nil {
                Darwin.free(ptr)
            }
        }

        let envStrings = environment.keys.sorted().map { key in
            "\(key)=\(environment[key] ?? "")"
        }
        var cEnvp: [UnsafeMutablePointer<CChar>?] = envStrings.map { Darwin.strdup($0) }
        cEnvp.append(nil)
        defer {
            for ptr in cEnvp where ptr != nil {
                Darwin.free(ptr)
            }
        }

        var spawnedPID: pid_t = 0
        let spawnRC = executablePath.withCString { cExecPath in
            cArgv.withUnsafeMutableBufferPointer { argvBuf in
                cEnvp.withUnsafeMutableBufferPointer { envpBuf in
                    Darwin.posix_spawn(
                        &spawnedPID,
                        cExecPath,
                        &fileActions,
                        &attr,
                        argvBuf.baseAddress,
                        envpBuf.baseAddress
                    )
                }
            }
        }
        guard spawnRC == 0 else {
            throw DaemonLaunchError.posixSpawnFailed(
                executablePath: executablePath,
                errnoCode: spawnRC,
                detail: String(cString: Darwin.strerror(spawnRC))
            )
        }
        return spawnedPID
    }
}
