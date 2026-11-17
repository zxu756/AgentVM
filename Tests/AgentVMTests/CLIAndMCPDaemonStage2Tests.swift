import AgentVMCLIAndMCP
import AgentVMHypervisor
import AgentVMModels
import AgentVMStorageCoW
import AgentVMStore
import Darwin
import Foundation
import Testing

@Suite("M2 Stage 2: Daemon Skeleton, Spawner, Client Routing, Reconciliation & Events", .timeLimit(.minutes(1)))
struct CLIAndMCPDaemonStage2Tests {

    private func makePrivateTmpDirectory(prefix: String = "avm-s2") throws -> String {
        var cTemplate = Array("/private/tmp/\(prefix).XXXXXX".utf8CString)
        let createdPtr = cTemplate.withUnsafeMutableBufferPointer { buf in
            Darwin.mkdtemp(buf.baseAddress)
        }
        guard let createdPtr else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(Darwin.errno))
        }
        let raw = String(cString: createdPtr)
        return DaemonSocketAddressResolver.canonicalRealPath(of: URL(fileURLWithPath: raw, isDirectory: true))
    }

    // MARK: - Item 0: Canonical Real Path Socket Length Check (`/private/tmp` Existence Independence)

    @Test("Item 0: /private/tmp workspace where stripped path <= 103B and canonical /private/tmp path > 103B resolves identical symlink address before and after daemon.sock exists")
    func privateTmpSocketLengthUsesCanonicalRealPathConsistentlyBeforeAndAfterBind() throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-p0")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        #expect(realBase.hasPrefix("/private/tmp/"))

        let suffix = "/ws.agentvm/run/daemon.sock"
        // Target canonical socket UTF-8 length = 107 (> 103); stripped `/tmp/...` length = 99 (<= 103).
        let targetCanonicalBytes = 107
        let padLen = targetCanonicalBytes - (realBase.utf8.count + 1 + suffix.utf8.count)
        #expect(padLen > 0)
        let pad = String(repeating: "p", count: padLen)

        let privateWSPath = "\(realBase)/\(pad)/ws.agentvm"
        let strippedTmpWSPath = String(privateWSPath.dropFirst("/private".count))
        #expect(strippedTmpWSPath.hasPrefix("/tmp/"))

        let canonicalSockLen = "\(privateWSPath)/run/daemon.sock".utf8.count
        let strippedSockLen = "\(strippedTmpWSPath)/run/daemon.sock".utf8.count
        #expect(canonicalSockLen == 107 && canonicalSockLen > DaemonUnixSocketAddress.maxPathUTF8Bytes)
        #expect(strippedSockLen == 99 && strippedSockLen <= DaemonUnixSocketAddress.maxPathUTF8Bytes)

        let privateWSURL = URL(fileURLWithPath: privateWSPath, isDirectory: true)
        let strippedWSURL = URL(fileURLWithPath: strippedTmpWSPath, isDirectory: true)

        // 1. Daemon computes socket address BEFORE workspace or daemon.sock exists on disk.
        let daemonAddressBeforeSocketExists = try DaemonSocketAddressResolver.computePlan(for: privateWSURL)
        #expect(daemonAddressBeforeSocketExists.mode == .tempDirectorySymlink)

        // 2. Also verify when <workspace>/run ALREADY exists on disk while daemon.sock does NOT exist yet.
        try FileManager.default.createDirectory(
            atPath: "\(privateWSPath)/run",
            withIntermediateDirectories: true
        )
        let daemonAddressWithRunDirNoSock = try DaemonSocketAddressResolver.computePlan(for: privateWSURL)
        #expect(daemonAddressWithRunDirNoSock == daemonAddressBeforeSocketExists)

        // 3. Bind server so daemon.sock NOW exists on disk.
        guard case let .bound(server) = try DaemonWorkspaceServerBootstrap.acquireLockAndBind(workspaceURL: privateWSURL) else {
            Issue.record("Expected acquireLockAndBind to succeed on /private/tmp workspace")
            return
        }
        defer { server.shutdownAndCleanup() }

        var sockStat = Darwin.stat()
        #expect(stat("\(privateWSPath)/run/daemon.sock", &sockStat) == 0)
        #expect(server.address == daemonAddressBeforeSocketExists)

        // 4. Client resolves socket address AFTER daemon.sock exists (both /private/tmp and /tmp spellings).
        let (clientAddressAfterSocketExists, _) = try DaemonSocketAddressResolver.resolveForConnect(workspaceURL: privateWSURL)
        let (clientStrippedAliasAddress, _) = try DaemonSocketAddressResolver.resolveForConnect(workspaceURL: strippedWSURL)
        #expect(clientAddressAfterSocketExists == daemonAddressBeforeSocketExists)
        #expect(clientStrippedAliasAddress == daemonAddressBeforeSocketExists)

        // 5. Verify live client connect succeeds over the resolved address.
        let acceptedSem = DispatchSemaphore(value: 0)
        let acceptedBox = Stage2ResultBox<Result<DaemonSocketConnection, Error>>()
        DispatchQueue.global().async {
            acceptedBox.store(Result { try server.listener.acceptConnection() })
            acceptedSem.signal()
        }
        let clientConn = try DaemonSocketClient.connectWorkspace(workspaceURL: privateWSURL)
        acceptedSem.wait()
        let serverConn = try #require(acceptedBox.load()).get()
        clientConn.close()
        serverConn.close()
        server.shutdownAndCleanup()
    }

    // MARK: - Item 4a (A45): Non-Intrusive `VMExecutionLock.isLocked` Probe

    @Test("Item 4 (A45): concurrent VMExecutionLock.isLocked probes never steal flock from VMExecutionLock.acquire, and dead-PID lock files report unlocked")
    func vmExecutionLockProbeNeverContendsWithAcquireAndHandlesDeadPID() throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-a45")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        let lockURL = URL(fileURLWithPath: "\(realBase)/locks/vm-a45.lock")

        // 1. Spawn a short-lived child (`/usr/bin/true`) and reap it so we have a guaranteed non-running PID,
        //    then write `pid=<deadPID>` to lockURL (simulating untruncated lock file after `kill -9`).
        var deadPID: pid_t = 0
        var cTrue = Array("/usr/bin/true".utf8CString)
        cTrue.withUnsafeMutableBufferPointer { exeBuf in
            var argv: [UnsafeMutablePointer<CChar>?] = [exeBuf.baseAddress, nil]
            _ = Darwin.posix_spawn(&deadPID, exeBuf.baseAddress, nil, nil, &argv, nil)
        }
        if deadPID > 0 {
            var st: Int32 = 0
            _ = Darwin.waitpid(deadPID, &st, 0)
            try FileManager.default.createDirectory(
                at: lockURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try Data("pid=\(deadPID)\nvm=t1\n".utf8).write(to: lockURL)
            #expect(VMExecutionLock.isLocked(at: lockURL) == false)
        }

        // 2. Hammer `VMExecutionLock.isLocked(at:)` from 4 background threads while acquiring & releasing 250 times.
        let stopFlag = Stage2AtomicFlag()
        let probeGroup = DispatchGroup()
        for _ in 0..<4 {
            probeGroup.enter()
            DispatchQueue.global(qos: .userInteractive).async {
                while !stopFlag.isSet() {
                    _ = VMExecutionLock.isLocked(at: lockURL)
                }
                probeGroup.leave()
            }
        }

        var spuriousBusyFailure: AgentVMError?
        for _ in 0..<250 {
            do {
                let handle = try VMExecutionLock.acquire(at: lockURL, vmName: "t1")
                #expect(VMExecutionLock.isLocked(at: lockURL) == true)
                handle.release()
            } catch let err as AgentVMError {
                spuriousBusyFailure = err
                break
            }
        }
        stopFlag.set()
        probeGroup.wait()

        #expect(
            spuriousBusyFailure == nil,
            "VMExecutionLock.isLocked probe caused spurious acquire contention: \(String(describing: spuriousBusyFailure))"
        )
        #expect(VMExecutionLock.isLocked(at: lockURL) == false)
    }

    // MARK: - Item 4b: Crash Reconciliation Emits Exactly One `VM_RUNTIME_LOST` Per Interruption

    @Test("Item 4: reconciling crashed running VMs writes stopped state and emits exactly one localized VM_RUNTIME_LOST diagnostic per interruption")
    func reconciliationWritesStoppedAndSingleVMRuntimeLostPerInterruption() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-reconcile")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        let wsURL = URL(fileURLWithPath: "\(realBase)/Reconcile.agentvm", isDirectory: true)

        let coord1 = try AgentVMFleetCoordinator(bundleURL: wsURL, executionBackend: .strictHardwareVZ)
        let vm1 = try await coord1.createSandboxVM(name: "crashed-1").vmRecord
        let vmSim = try await coord1.createSandboxVM(name: "sim-1").vmRecord

        // Mark `crashed-1` as hardware running (with no lock held) and `sim-1` as simulated running.
        var crashedRec = vm1
        crashedRec.telemetry.state = .running
        crashedRec.telemetry.simulated = false
        crashedRec.telemetry.guestAgentConnected = true
        try await coord1.store.upsertVM(crashedRec)

        var simRec = vmSim
        simRec.telemetry.state = .running
        simRec.telemetry.simulated = true
        simRec.telemetry.guestAgentConnected = true
        try await coord1.store.upsertVM(simRec)

        // Race two separate coordinators reconciling concurrently (e.g., `ps` racing with `daemon start`).
        let coord2 = try AgentVMFleetCoordinator(bundleURL: wsURL, executionBackend: .strictHardwareVZ)
        async let r1 = coord1.listVMsForReporting()
        async let r2 = coord2.listVMsForReporting()
        let (list1, list2) = try await (r1, r2)

        #expect(list1.first(where: { $0.id == vm1.id })?.telemetry.state == .stopped)
        #expect(list2.first(where: { $0.id == vm1.id })?.telemetry.state == .stopped)
        // Simulated running VM is NOT treated as a hardware crash.
        #expect(list1.first(where: { $0.id == vmSim.id })?.telemetry.simulated == true)

        // Subsequent `listVMsForReporting` calls must NOT emit duplicate VM_RUNTIME_LOST events.
        _ = try await coord1.listVMsForReporting()
        _ = try await coord2.listVMsForReporting()

        let eventsForVM1 = try await coord1.store.listDiagnostics(vmID: vm1.id, limit: 50)
        let lostEvents1 = eventsForVM1.filter { $0.code == "VM_RUNTIME_LOST" }
        #expect(lostEvents1.count == 1, "Expected exactly 1 VM_RUNTIME_LOST for first interruption, got \(lostEvents1.count)")
        if let ev = lostEvents1.first {
            #expect(
                ev.message.contains("上次运行异常中断：持有这台机器的进程没有正常退出")
                    || ev.message.contains("Previous run terminated unexpectedly")
            )
            #expect(ev.metadata["message_zh"]?.contains("上次运行异常中断：持有这台机器的进程没有正常退出") == true)
            #expect(ev.metadata["message_en"]?.contains("Previous run terminated unexpectedly") == true)
        }

        let eventsForSim = try await coord1.store.listDiagnostics(vmID: vmSim.id, limit: 50)
        #expect(eventsForSim.filter { $0.code == "VM_RUNTIME_LOST" }.isEmpty)

        // A second distinct crash interruption later emits one more VM_RUNTIME_LOST (total = 2).
        var secondCrash = try #require(try await coord1.store.fetchVM(vm1.id))
        secondCrash.telemetry.state = .running
        secondCrash.telemetry.simulated = false
        try await coord1.store.upsertVM(secondCrash)
        _ = try await coord1.listVMsForReporting()

        let lostEventsAfterSecond = try await coord1.store.listDiagnostics(vmID: vm1.id, limit: 50)
            .filter { $0.code == "VM_RUNTIME_LOST" }
        #expect(lostEventsAfterSecond.count == 2)
    }

    // MARK: - Item 1: Daemon Skeleton (`daemon run|status|stop`, Startup Order, Ready Log, Signals, Version Mismatch)

    @Test("Item 1: WorkspaceDaemonServer enforces lock->unlink->reconcile->bind->ready order, serves status/stop (--json & text, exit 3 when absent), handles SIGTERM like stop with machine-shutdown hook, and rejects hello version mismatch")
    func daemonServerStartupOrderStatusStopSignalsAndVersionMismatch() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-d1")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        let wsURL = URL(fileURLWithPath: "\(realBase)/Daemon1.agentvm", isDirectory: true)
        let cli = AgentVMCLIRunner()
        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = ["HOME": isolatedHome, "CFFIXED_USER_HOME": isolatedHome]

        // 1. `daemon run` without absolute --workspace is rejected with usage error (exit 2).
        let badRelRun = await cli.execute(
            arguments: ["--lang", "en", "--workspace", "./relative.agentvm", "daemon", "run"],
            environment: env
        )
        #expect(badRelRun.exitCode == AgentVMCLIRunner.usageErrorExitCode)

        // 2. When no daemon is running: `daemon status` (en, zh, --json) exits 3; `daemon stop` exits 0 without creating daemon.sock.
        let statusAbsentEn = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "daemon", "status"],
            environment: env
        )
        #expect(statusAbsentEn.exitCode == 3)
        #expect(statusAbsentEn.stdout.lowercased().contains("not running"))

        let statusAbsentZh = await cli.execute(
            arguments: ["--lang", "zh", "--workspace", wsURL.path, "daemon", "status"],
            environment: env
        )
        #expect(statusAbsentZh.exitCode == 3)
        #expect(statusAbsentZh.stdout.contains("守护进程未运行"))

        let statusAbsentJSON = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "daemon", "status", "--json"],
            environment: env
        )
        #expect(statusAbsentJSON.exitCode == 3)
        let absentObj = try #require(
            try JSONSerialization.jsonObject(with: Data(statusAbsentJSON.stdout.utf8)) as? [String: Any]
        )
        #expect(absentObj["running"] as? Bool == false)

        let stopAbsent = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "daemon", "stop", "--json"],
            environment: env
        )
        #expect(stopAbsent.exitCode == 0)
        #expect(!FileManager.default.fileExists(atPath: DaemonWorkspacePaths(workspaceURL: wsURL).directSocketPath))

        // 3. Seed a crashed hardware `running` VM and a stale daemon.sock, then start WorkspaceDaemonServer
        //    and verify exact order: lock -> unlink -> reconcile -> bind -> ready.
        let seedCoord = try AgentVMFleetCoordinator(bundleURL: wsURL, executionBackend: .strictHardwareVZ)
        let crashedVM = try await seedCoord.createSandboxVM(name: "stale-vm").vmRecord
        var staleRunning = crashedVM
        staleRunning.telemetry.state = .running
        staleRunning.telemetry.simulated = false
        try await seedCoord.store.upsertVM(staleRunning)

        let paths = DaemonWorkspacePaths(workspaceURL: wsURL)
        do {
            let staleListener = try DaemonSocketListener.bindDirect(paths: paths)
            staleListener.close(unlinkSocket: false)
        }
        #expect(FileManager.default.fileExists(atPath: paths.directSocketPath))

        let shutdownHookBox = Stage2AtomicFlag()
        let startOutcome = try await WorkspaceDaemonServer.start(
            workspaceURL: wsURL,
            onShutdownAllMachines: {
                shutdownHookBox.set()
            }
        )
        guard case let .started(server) = startOutcome else {
            Issue.record("Expected WorkspaceDaemonServer.start to win singleton lock")
            return
        }
        defer {
            Task { await server.stopAndCleanup() }
        }

        #expect(server.recordedStartupSteps == ["lock", "unlink", "reconcile", "bind", "ready"])

        // Verify daemon.log contains `ready` line and VM_RUNTIME_LOST was recorded before bind.
        let logText = try String(contentsOf: paths.daemonLogFileURL, encoding: .utf8)
        #expect(logText.contains("ready"))
        let diagEvents = try await seedCoord.store.listDiagnostics(vmID: crashedVM.id, limit: 20)
        #expect(diagEvents.filter { $0.code == "VM_RUNTIME_LOST" }.count == 1)

        // Second contender starting on same workspace loses lock cleanly (.alreadyRunning).
        let secondStart = try await WorkspaceDaemonServer.start(workspaceURL: wsURL)
        if case .started(let unexpected) = secondStart {
            await unexpected.stopAndCleanup()
            Issue.record("Second WorkspaceDaemonServer must report alreadyRunning")
        }

        // 4. `daemon status` and `daemon status --json` exit 0 and report live daemon metadata.
        let liveStatusText = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "daemon", "status"],
            environment: env
        )
        #expect(liveStatusText.exitCode == 0)
        #expect(liveStatusText.stdout.contains("\(Darwin.getpid())"))

        let liveStatusJSON = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "daemon", "status", "--json"],
            environment: env
        )
        #expect(liveStatusJSON.exitCode == 0)
        let liveObj = try #require(
            try JSONSerialization.jsonObject(with: Data(liveStatusJSON.stdout.utf8)) as? [String: Any]
        )
        #expect(liveObj["running"] as? Bool == true)
        #expect((liveObj["pid"] as? Int) == Int(Darwin.getpid()))

        // 5. `daemon stop` invokes the "shut down all machines" hook, removes socket, clears lock, and exits 0.
        let stopLive = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "daemon", "stop", "--json"],
            environment: env
        )
        #expect(stopLive.exitCode == 0)
        await server.waitUntilStopped()
        #expect(shutdownHookBox.isSet() == true)
        #expect(!FileManager.default.fileExists(atPath: paths.directSocketPath))

        // 6. Start a daemon advertising an older SemanticVersion (1.2.0) -> client `daemon status` fails with
        //    ERR_DAEMON_VERSION_MISMATCH hinting `agentvm daemon stop`, and SIGTERM stops it cleanly.
        let sigtermHookBox = Stage2AtomicFlag()
        guard case let .started(oldVerServer) = try await WorkspaceDaemonServer.start(
            workspaceURL: wsURL,
            semanticVersion: SemanticVersion(major: 1, minor: 2, patch: 0),
            onShutdownAllMachines: {
                sigtermHookBox.set()
            }
        ) else {
            Issue.record("Expected second daemon server to start after stop")
            return
        }
        defer {
            Task { await oldVerServer.stopAndCleanup() }
        }

        let mismatchEn = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "daemon", "status"],
            environment: env
        )
        #expect(mismatchEn.exitCode == 1)
        #expect(mismatchEn.stderr.contains("ERR_DAEMON_VERSION_MISMATCH"))
        #expect(mismatchEn.stderr.contains("agentvm daemon stop"))

        let mismatchZh = await cli.execute(
            arguments: ["--lang", "zh", "--workspace", wsURL.path, "daemon", "status"],
            environment: env
        )
        #expect(mismatchZh.exitCode == 1)
        #expect(mismatchZh.stderr.contains("ERR_DAEMON_VERSION_MISMATCH"))
        #expect(mismatchZh.stderr.contains("agentvm daemon stop"))

        // Deliver SIGTERM handler -> executes same graceful stop as `daemon stop`.
        await oldVerServer.handleTerminationSignal(SIGTERM)
        await oldVerServer.waitUntilStopped()
        #expect(sigtermHookBox.isSet() == true)
        #expect(!FileManager.default.fileExists(atPath: paths.directSocketPath))
    }
}

private final class Stage2AtomicFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var flag = false
    func set() { lock.withLock { flag = true } }
    func isSet() -> Bool { lock.withLock { flag } }
}

private final class Stage2ResultBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: T?
    func store(_ newValue: T) {
        lock.withLock { value = newValue }
    }
    func load() -> T? {
        lock.withLock { value }
    }
}
