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

    // MARK: - Item 2: Detached `posix_spawn` Launcher, `daemon start`, Contender Exit 0, Crash Tail & `up` Preflight

    @Test("Item 2a: DaemonProcessLauncher & 'daemon start' spawn detached session leader (SETSID, CLOEXEC, fd 0/1/2), handle exit-0 contender race, report 20-line daemon.log tail on non-zero exit, and stop cleanly")
    func daemonStartDetachedPosixSpawnContenderRaceFailureLogTailAndTeardown() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-d2a")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = ["HOME": isolatedHome, "CFFIXED_USER_HOME": isolatedHome]
        let cli = AgentVMCLIRunner()

        // 1. Offline Python helper speaking the exact single-line DaemonRPC hello + status + stop protocol
        //    so `swift test` exercises real `posix_spawn` (`SETSID | CLOEXEC_DEFAULT`, fd 0/1/2) without needing
        //    a pre-built `.build/debug/AgentVM` binary.
        let helperScriptPath = "\(realBase)/mock_daemon_rpc.py"
        let pidFilePath = "\(realBase)/mock.pid"
        let verMajor = SemanticVersion.current.major
        let verMinor = SemanticVersion.current.minor
        let verPatch = SemanticVersion.current.patch
        let currentProto = DaemonRPCHello.currentProtocolVersion
        let pySource = """
        import fcntl, json, os, signal, socket, sys, time

        ws = sys.argv[1]
        pid_file = sys.argv[2]
        run_dir = os.path.join(ws, "run")
        os.makedirs(run_dir, mode=0o700, exist_ok=True)
        os.chmod(run_dir, 0o700)
        lock_path = os.path.join(run_dir, "daemon.lock")
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            sys.stdout.write("contender lost lock\\n")
            sys.stdout.flush()
            os._exit(0)

        pid = os.getpid()
        with open(pid_file, "w", encoding="utf-8") as pf:
            pf.write(str(pid))
        started_at = "2026-11-17T00:00:00Z"
        exe_path = os.path.realpath(sys.executable)
        ver_obj = {"major": \(verMajor), "minor": \(verMinor), "patch": \(verPatch)}
        holder = {
            "executablePath": exe_path,
            "pid": pid,
            "startedAt": started_at,
            "version": ver_obj
        }
        os.ftruncate(lock_fd, 0)
        os.write(lock_fd, (json.dumps(holder) + "\\n").encode("utf-8"))

        sock_path = os.path.join(run_dir, "daemon.sock")
        try:
            os.unlink(sock_path)
        except FileNotFoundError:
            pass

        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.settimeout(10.0)
        srv.bind(sock_path)
        os.chmod(sock_path, 0o600)
        srv.listen(16)

        # Record open fds so test can verify POSIX_SPAWN_CLOEXEC_DEFAULT closed leaked parent descriptors
        open_fds = []
        for candidate in range(0, 64):
            try:
                os.fstat(candidate)
                open_fds.append(candidate)
            except OSError:
                pass
        sys.stdout.write(f"ready pid={pid} open_fds={open_fds}\\n")
        sys.stdout.flush()

        stopping = False
        def _on_term(signum, frame):
            global stopping
            stopping = True
            try:
                srv.close()
            except OSError:
                pass
        signal.signal(signal.SIGTERM, _on_term)
        signal.signal(signal.SIGINT, _on_term)
        signal.signal(signal.SIGHUP, signal.SIG_IGN)

        hello_line = (json.dumps({
            "jsonrpc": "2.0",
            "method": "hello",
            "params": {
                "executablePath": exe_path,
                "protocolVersion": \(currentProto),
                "semanticVersion": ver_obj
            }
        }) + "\\n").encode("utf-8")

        deadline = time.monotonic() + 10.0
        while not stopping and time.monotonic() < deadline:
            try:
                conn, _ = srv.accept()
            except OSError:
                break
            with conn:
                conn.sendall(hello_line)
                buf = b""
                lines = []
                while len(lines) < 2:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                    while b"\\n" in buf:
                        line, buf = buf.split(b"\\n", 1)
                        lines.append(line)
                if len(lines) < 2:
                    continue
                req = json.loads(lines[1].decode("utf-8"))
                req_id = req.get("id", 1)
                method = req.get("method", "")
                if method == "status":
                    resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "executablePath": exe_path,
                            "pid": pid,
                            "protocolVersion": \(currentProto),
                            "semanticVersion": ver_obj,
                            "socketPath": sock_path,
                            "startedAt": started_at,
                            "vms": [],
                            "workspacePath": ws
                        }
                    }
                    conn.sendall((json.dumps(resp) + "\\n").encode("utf-8"))
                elif method == "stop":
                    stopping = True
                    try:
                        srv.close()
                    except OSError:
                        pass
                    try:
                        os.unlink(sock_path)
                    except FileNotFoundError:
                        pass
                    resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"stoppedVMIDs": []}
                    }
                    conn.sendall((json.dumps(resp) + "\\n").encode("utf-8"))
                    break

        try:
            os.unlink(sock_path)
        except FileNotFoundError:
            pass
        os.ftruncate(lock_fd, 0)
        os.close(lock_fd)
        """
        try Data(pySource.utf8).write(to: URL(fileURLWithPath: helperScriptPath))

        // Open an extra pipe in the parent WITHOUT O_CLOEXEC to prove POSIX_SPAWN_CLOEXEC_DEFAULT prevents inheritance!
        var extraPipe: [Int32] = [-1, -1]
        #expect(Darwin.pipe(&extraPipe) == 0)
        defer {
            if extraPipe[0] >= 0 { _ = Darwin.close(extraPipe[0]) }
            if extraPipe[1] >= 0 { _ = Darwin.close(extraPipe[1]) }
        }

        let ws1 = URL(fileURLWithPath: "\(realBase)/Spawn1.agentvm", isDirectory: true)
        let ws1Paths = DaemonWorkspacePaths(workspaceURL: ws1)
        let pySpawnOverride = DaemonSpawnCommandOverride(
            executablePath: "/usr/bin/python3",
            arguments: ["-I", helperScriptPath, ws1Paths.canonicalWorkspacePath, pidFilePath],
            environment: env
        )

        var spawnedPIDToCleanup: pid_t = 0
        defer {
            var pids: Set<pid_t> = []
            if spawnedPIDToCleanup > 0 {
                pids.insert(spawnedPIDToCleanup)
            }
            if let raw = try? String(contentsOfFile: pidFilePath, encoding: .utf8),
               let parsed = Int32(raw.trimmingCharacters(in: .whitespacesAndNewlines)),
               parsed > 0 {
                pids.insert(parsed)
            }
            for p in pids {
                _ = Darwin.kill(p, SIGTERM)
                let deadline = DispatchTime.now().uptimeNanoseconds &+ 3_000_000_000
                while DispatchTime.now().uptimeNanoseconds < deadline {
                    var reapSt: Int32 = 0
                    _ = Darwin.waitpid(p, &reapSt, WNOHANG)
                    if Darwin.kill(p, 0) != 0 && Darwin.errno == ESRCH {
                        break
                    }
                    Darwin.usleep(20_000)
                }
                if Darwin.kill(p, 0) == 0 {
                    _ = Darwin.kill(p, SIGKILL)
                    var reapSt: Int32 = 0
                    _ = Darwin.waitpid(p, &reapSt, 0)
                }
            }
        }

        let start1 = await cli.execute(
            arguments: ["--lang", "en", "--workspace", ws1.path, "daemon", "start", "--json"],
            environment: env,
            daemonSpawnOverride: pySpawnOverride
        )
        #expect(start1.exitCode == 0, "daemon start failed: \(start1.stderr)")
        let start1Obj = try #require(
            try JSONSerialization.jsonObject(with: Data(start1.stdout.utf8)) as? [String: Any]
        )
        let childPID = pid_t(try #require(start1Obj["pid"] as? Int))
        spawnedPIDToCleanup = childPID
        #expect(childPID > 0 && childPID != Darwin.getpid())

        // Verify SETSID made the child its own process group / session leader (`pgid == pid`).
        #expect(Darwin.getpgid(childPID) == childPID)

        // Close parent's write end of `extraPipe` while child is still alive: immediate EOF (0 bytes) on
        // `extraPipe[0]` proves `POSIX_SPAWN_CLOEXEC_DEFAULT` prevented the child from inheriting `extraPipe[1]`.
        _ = Darwin.close(extraPipe[1])
        extraPipe[1] = -1
        var eofByte: UInt8 = 0
        let pipeReadRC = Darwin.read(extraPipe[0], &eofByte, 1)
        #expect(pipeReadRC == 0)

        // Verify daemon.log received child stdout.
        let ws1Log = try String(contentsOf: ws1Paths.daemonLogFileURL, encoding: .utf8)
        #expect(ws1Log.contains("ready pid=\(childPID)"))

        // Second `daemon start` returns 0 and reports the exact same PID without spawning another daemon.
        let start2 = await cli.execute(
            arguments: ["--lang", "zh", "--workspace", ws1.path, "daemon", "start"],
            environment: env,
            daemonSpawnOverride: pySpawnOverride
        )
        #expect(start2.exitCode == 0)
        #expect(start2.stdout.contains("\(childPID)"))

        // Stop the spawned daemon cleanly and verify process + socket are gone.
        let stop1 = await cli.execute(
            arguments: ["--lang", "en", "--workspace", ws1.path, "daemon", "stop"],
            environment: env
        )
        #expect(stop1.exitCode == 0)
        #expect(Darwin.kill(childPID, 0) != 0 && Darwin.errno == ESRCH)
        spawnedPIDToCleanup = 0

        // 2. Contender exiting 0 (`waitpid(WNOHANG)` exit 0 keeps polling until winner binds).
        let wsRace = URL(fileURLWithPath: "\(realBase)/Race.agentvm", isDirectory: true)
        let winnerTask = Task<WorkspaceDaemonServer?, Error> {
            try await Task.sleep(nanoseconds: 250_000_000)
            let out = try await WorkspaceDaemonServer.start(workspaceURL: wsRace)
            if case let .started(srv) = out {
                return srv
            }
            return nil
        }
        let contenderOverride = DaemonSpawnCommandOverride(
            executablePath: "/usr/bin/true",
            arguments: [],
            environment: env
        )
        let raceStart = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsRace.path, "daemon", "start", "--json"],
            environment: env,
            daemonSpawnOverride: contenderOverride
        )
        let winnerServer = try await winnerTask.value
        if let winnerServer {
            await winnerServer.stopAndCleanup()
        }
        #expect(raceStart.exitCode == 0, "Expected contender exit-0 to keep polling winner: \(raceStart.stderr)")

        // 3. Non-zero child exit writes trailing 20 lines of `daemon.log` to stderr and exits 1.
        let wsCrash = URL(fileURLWithPath: "\(realBase)/Crash.agentvm", isDirectory: true)
        let crashOverride = DaemonSpawnCommandOverride(
            executablePath: "/bin/sh",
            arguments: ["-c", "i=1; while [ $i -le 25 ]; do echo \"crash-line-$i\"; i=$((i+1)); done; exit 17"],
            environment: env
        )
        let crashOut = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsCrash.path, "daemon", "start"],
            environment: env,
            daemonSpawnOverride: crashOverride
        )
        #expect(crashOut.exitCode == 1)
        #expect(!crashOut.stderr.contains("crash-line-5\n"))
        for lineNo in 6...25 {
            #expect(crashOut.stderr.contains("crash-line-\(lineNo)"))
        }
    }

    @Test("Item 2b: 'up' runs local bootable-system (clearing simulated state) and virtualization-entitlement preflight before touching daemon, and returns ERR_DAEMON_REQUIRED in Stage 2 without spawning")
    func upPreflightChecksBootableSystemClearsSimStateChecksEntitlementAndNeverLaunchesDaemonInStage2() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-d2b")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        let wsURL = URL(fileURLWithPath: "\(realBase)/UpPreflight.agentvm", isDirectory: true)
        let cacheDir = URL(fileURLWithPath: "\(realBase)/cache", isDirectory: true)
        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()
        let paths = DaemonWorkspacePaths(workspaceURL: wsURL)

        // Stage a minimal 4 MiB GPT+ext4 bootable cached image offline.
        let imageBytes = 4 * 1024 * 1024
        let stagingURL = URL(fileURLWithPath: "\(realBase)/bootable.raw")
        try APFSCoWDiskEngine().createSparseRawDisk(at: stagingURL, virtualSizeBytes: UInt64(imageBytes), overwrite: true)
        let parts = try PartitionAndContainerInspector().writeProtectiveMBRAndGPT(
            to: stagingURL,
            partitions: [(name: "RootExt4", typeGUID: GPTWellKnownTypeGUID.linuxRootARM64.rawValue, sizeBytes: 2 * 1024 * 1024)]
        )
        var ext4Super = [UInt8](repeating: 0, count: 256)
        ext4Super[0x38] = 0x53
        ext4Super[0x39] = 0xEF
        ext4Super[0x5C] = 0x04
        ext4Super[0x60] = 0xC0
        let fh = try FileHandle(forUpdating: stagingURL)
        try fh.seek(toOffset: parts[0].firstLBA * 512 + 1024)
        try fh.write(contentsOf: Data(ext4Super))
        try fh.close()

        let sha512 = try BinaryChecksums.sha512HexFile(at: stagingURL)
        let imageID = "debian-12-bookworm-arm64"
        let entry = BaseImageCatalogEntry(
            id: imageID,
            displayName: "Debian 12 Test Image",
            distribution: "debian",
            version: "20261112-2660",
            guestOS: .linuxARM64,
            isSupported: true,
            downloadURL: "https://offline.agentvm.invalid/debian.raw",
            expectedSHA512: sha512,
            expectedSizeBytes: UInt64(imageBytes),
            defaultVirtualSizeBytes: UInt64(imageBytes)
        )
        let seeder = try BaseImageRegistryCatalog(cacheDirectoryURL: cacheDir, curatedEntries: [entry], createIfMissing: true)
        let staged = try await seeder.stageCachedCuratedImage(id: imageID, from: stagingURL, verifyChecksum: true)
        try? FileManager.default.removeItem(at: stagingURL)
        let cachedURL = URL(fileURLWithPath: try #require(staged.cachedLocalPath)).standardizedFileURL
        #expect(Darwin.chmod(cachedURL.path, 0o444) == 0)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        // Create empty-disk `a` and bootable-disk `t1`.
        #expect(await cli.execute(arguments: ["--workspace", wsURL.path, "create", "a"], curatedEntriesOverride: [entry], environment: env).exitCode == 0)
        #expect(await cli.execute(arguments: ["--workspace", wsURL.path, "create", "t1", "--image", imageID], curatedEntriesOverride: [entry], environment: env).exitCode == 0)

        // Put `a` into simulated running state first.
        #expect(await cli.execute(arguments: ["--backend", "simulation", "--workspace", wsURL.path, "up", "a"], curatedEntriesOverride: [entry], environment: env).exitCode == 0)

        let forbiddenSpawn = DaemonSpawnCommandOverride(
            executablePath: "/bin/sh",
            arguments: ["-c", "exit 91"],
            environment: env
        )

        // 1. Hardware `up a` clears simulated state, fails ERR_NO_BOOTABLE_SYSTEM (exit 1), and never spawns daemon.
        let upEmpty = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "a"],
            curatedEntriesOverride: [entry],
            environment: env,
            hasEntitlementOverride: true,
            daemonSpawnOverride: forbiddenSpawn
        )
        #expect(upEmpty.exitCode == 1)
        #expect(upEmpty.stderr.contains("ERR_NO_BOOTABLE_SYSTEM"))
        #expect(!FileManager.default.fileExists(atPath: paths.lockFileURL.path))
        #expect(!FileManager.default.fileExists(atPath: paths.directSocketPath))

        let verifyStore = try AgentVMProjectStore(bundleURL: wsURL, createIfMissing: false)
        let vmsAfterEmptyUp = try await verifyStore.listVMs()
        let recA = try #require(vmsAfterEmptyUp.first(where: { $0.spec.name == "a" }))
        #expect(recA.telemetry.state == .stopped && recA.telemetry.simulated == false)

        // 2. Hardware `up t1` without virtualization entitlement fails ERR_VZ_ENTITLEMENT_MISSING (exit 1), never spawns daemon.
        let upNoEnt = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t1"],
            curatedEntriesOverride: [entry],
            environment: env,
            hasEntitlementOverride: false,
            daemonSpawnOverride: forbiddenSpawn
        )
        #expect(upNoEnt.exitCode == 1)
        #expect(upNoEnt.stderr.contains("ERR_VZ_ENTITLEMENT_MISSING"))
        #expect(!FileManager.default.fileExists(atPath: paths.lockFileURL.path))
        #expect(!FileManager.default.fileExists(atPath: paths.directSocketPath))

        // 3. Hardware `up t1` when both checks pass still returns ERR_DAEMON_REQUIRED in Stage 2 and never spawns daemon.
        let upEntitled = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t1"],
            curatedEntriesOverride: [entry],
            environment: env,
            hasEntitlementOverride: true,
            daemonSpawnOverride: forbiddenSpawn
        )
        #expect(upEntitled.exitCode == 1)
        #expect(upEntitled.stderr.contains("ERR_DAEMON_REQUIRED"))
        #expect(!FileManager.default.fileExists(atPath: paths.lockFileURL.path))
        #expect(!FileManager.default.fileExists(atPath: paths.directSocketPath))
    }

    // MARK: - Items 3, 4 & 5: Connect-Only Commands, A52, `ps` `list`/Fallback, `events`, and A53 Whitelists

    @Test("Items 3 & 4: connect-only commands never spawn daemon, match Row 2 exit codes (exec 125 + A52 simulated reset, halt 0, pause 1, resume 1, stop 0), route ps via daemon list or DB reconciliation, and serve bilingual 'events'")
    func connectOnlyCommandsDisconnectedExitCodesA52AndLiveDaemonListAndEvents() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-d34")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        let wsURL = URL(fileURLWithPath: "\(realBase)/Client34.agentvm", isDirectory: true)
        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = ["HOME": isolatedHome, "CFFIXED_USER_HOME": isolatedHome]
        let cli = AgentVMCLIRunner()
        let paths = DaemonWorkspacePaths(workspaceURL: wsURL)

        let forbiddenSpawn = DaemonSpawnCommandOverride(
            executablePath: "/bin/sh",
            arguments: ["-c", "exit 92"],
            environment: env
        )

        #expect(await cli.execute(arguments: ["--workspace", wsURL.path, "init"], environment: env).exitCode == 0)
        #expect(await cli.execute(arguments: ["--workspace", wsURL.path, "create", "a"], environment: env).exitCode == 0)
        #expect(await cli.execute(arguments: ["--workspace", wsURL.path, "create", "b"], environment: env).exitCode == 0)

        // 1. Row 2 sequence with no daemon running:
        //    ps (0), ps --json (0), events --json (0), exec a -- true (125 ERR_LIFECYCLE_STATE + up hint),
        //    halt a (0), pause a (1), resume a (1), daemon stop (0) — zero daemon spawned, no daemon.sock!
        let rPs = await cli.execute(arguments: ["--lang", "en", "--workspace", wsURL.path, "ps"], environment: env, daemonSpawnOverride: forbiddenSpawn)
        #expect(rPs.exitCode == 0)

        let rPsJSON = await cli.execute(arguments: ["--lang", "en", "--workspace", wsURL.path, "ps", "--json"], environment: env, daemonSpawnOverride: forbiddenSpawn)
        #expect(rPsJSON.exitCode == 0)

        let rEventsJSON = await cli.execute(arguments: ["--lang", "en", "--workspace", wsURL.path, "events", "--json"], environment: env, daemonSpawnOverride: forbiddenSpawn)
        #expect(rEventsJSON.exitCode == 0)

        let rExecEn = await cli.execute(arguments: ["--lang", "en", "--workspace", wsURL.path, "exec", "a", "--", "true"], environment: env, daemonSpawnOverride: forbiddenSpawn)
        #expect(rExecEn.exitCode == 125)
        #expect(rExecEn.stdout.isEmpty)
        #expect(rExecEn.stderr.contains("ERR_LIFECYCLE_STATE"))
        #expect(rExecEn.stderr.contains("agentvm up a"))

        let rExecZh = await cli.execute(arguments: ["--lang", "zh", "--workspace", wsURL.path, "exec", "a", "--", "true"], environment: env, daemonSpawnOverride: forbiddenSpawn)
        #expect(rExecZh.exitCode == 125)
        #expect(rExecZh.stderr.contains("ERR_LIFECYCLE_STATE"))
        #expect(rExecZh.stderr.contains("agentvm up a"))

        let rHalt = await cli.execute(arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "a"], environment: env, daemonSpawnOverride: forbiddenSpawn)
        #expect(rHalt.exitCode == 0)

        let rPause = await cli.execute(arguments: ["--lang", "en", "--workspace", wsURL.path, "pause", "a"], environment: env, daemonSpawnOverride: forbiddenSpawn)
        #expect(rPause.exitCode == 1)

        let rResume = await cli.execute(arguments: ["--lang", "en", "--workspace", wsURL.path, "resume", "a"], environment: env, daemonSpawnOverride: forbiddenSpawn)
        #expect(rResume.exitCode == 1)

        let rStop = await cli.execute(arguments: ["--lang", "en", "--workspace", wsURL.path, "daemon", "stop"], environment: env, daemonSpawnOverride: forbiddenSpawn)
        #expect(rStop.exitCode == 0)

        #expect(!FileManager.default.fileExists(atPath: paths.directSocketPath))
        #expect(!FileManager.default.fileExists(atPath: paths.lockFileURL.path))

        // 2. A52: Put `a` into simulated running, then run hardware `exec a -- true`:
        //    must strip simulated running state FIRST and report state 'stopped' (never fake 'running'), exiting 125.
        #expect(await cli.execute(arguments: ["--backend", "simulation", "--workspace", wsURL.path, "up", "a"], environment: env).exitCode == 0)
        let execAfterSim = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "exec", "a", "--", "true"],
            environment: env,
            daemonSpawnOverride: forbiddenSpawn
        )
        #expect(execAfterSim.exitCode == 125)
        #expect(execAfterSim.stderr.contains("ERR_LIFECYCLE_STATE"))
        #expect(execAfterSim.stderr.contains("stopped"))
        #expect(!execAfterSim.stderr.contains("state 'running'"))
        #expect(execAfterSim.stderr.contains("agentvm up a"))

        // Simulation mode stays in-process and works unchanged.
        #expect(await cli.execute(arguments: ["--backend", "simulation", "--workspace", wsURL.path, "up", "a"], environment: env).exitCode == 0)
        let simExec = await cli.execute(arguments: ["--backend", "simulation", "--workspace", wsURL.path, "exec", "a", "--", "uname", "-a"], environment: env)
        #expect(simExec.exitCode == 0)
        #expect(simExec.stdout.hasPrefix("SIMULATED:"))

        // 3. Crashed hardware VM `b`: `ps` reconciles to `stopped` + writes `VM_RUNTIME_LOST`, and `events` reads it in EN & ZH.
        let store = try AgentVMProjectStore(bundleURL: wsURL, createIfMissing: false)
        var crashedB = try #require(try await store.listVMs().first(where: { $0.spec.name == "b" }))
        crashedB.telemetry.state = .running
        crashedB.telemetry.simulated = false
        try await store.upsertVM(crashedB)

        let psReconcile = await cli.execute(arguments: ["--lang", "zh", "--workspace", wsURL.path, "ps", "--json"], environment: env)
        #expect(psReconcile.exitCode == 0)
        #expect(!FileManager.default.fileExists(atPath: paths.directSocketPath))

        let evZhJSON = await cli.execute(arguments: ["--lang", "zh", "--workspace", wsURL.path, "events", "--vm", "b", "--limit", "5", "--json"], environment: env)
        #expect(evZhJSON.exitCode == 0)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decodedZhEvents = try decoder.decode([DiagnosticEvent].self, from: Data(evZhJSON.stdout.utf8))
        let lostZh = try #require(decodedZhEvents.first(where: { $0.code == "VM_RUNTIME_LOST" }))
        #expect(lostZh.message.contains("上次运行异常中断：持有这台机器的进程没有正常退出"))

        let evEnJSON = await cli.execute(arguments: ["--lang", "en", "--workspace", wsURL.path, "events", "--vm", "b", "--limit", "5", "--json"], environment: env)
        #expect(evEnJSON.exitCode == 0)
        let decodedEnEvents = try decoder.decode([DiagnosticEvent].self, from: Data(evEnJSON.stdout.utf8))
        let lostEn = try #require(decodedEnEvents.first(where: { $0.code == "VM_RUNTIME_LOST" }))
        #expect(lostEn.message.contains("Previous run terminated unexpectedly"))

        let evTextZh = await cli.execute(arguments: ["--lang", "zh", "--workspace", wsURL.path, "events", "--vm", "b", "--limit", "1"], environment: env)
        #expect(evTextZh.exitCode == 0)
        #expect(evTextZh.stdout.contains("VM_RUNTIME_LOST"))
        #expect(evTextZh.stdout.contains("上次运行异常中断：持有这台机器的进程没有正常退出"))

        let badLimit = await cli.execute(arguments: ["--lang", "en", "--workspace", wsURL.path, "events", "--limit", "0"], environment: env)
        #expect(badLimit.exitCode == AgentVMCLIRunner.usageErrorExitCode)

        // 4. With live WorkspaceDaemonServer running, `ps`, `exec`, `halt`, `pause` route over RPC cleanly.
        guard case let .started(server) = try await WorkspaceDaemonServer.start(workspaceURL: wsURL) else {
            Issue.record("Expected WorkspaceDaemonServer to start")
            return
        }
        defer {
            Task { await server.stopAndCleanup() }
        }

        let livePs = await cli.execute(arguments: ["--lang", "en", "--workspace", wsURL.path, "ps", "--json"], environment: env)
        #expect(livePs.exitCode == 0)
        let liveFleet = try decoder.decode([VMInstanceRecord].self, from: Data(livePs.stdout.utf8))
        #expect(liveFleet.count == 2)

        let liveExec = await cli.execute(arguments: ["--lang", "en", "--workspace", wsURL.path, "exec", "b", "--", "true"], environment: env)
        #expect(liveExec.exitCode == 125)
        #expect(liveExec.stderr.contains("ERR_LIFECYCLE_STATE"))
        #expect(liveExec.stderr.contains("agentvm up b"))

        let liveHalt = await cli.execute(arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "b"], environment: env)
        #expect(liveHalt.exitCode == 0)

        let livePause = await cli.execute(arguments: ["--lang", "en", "--workspace", wsURL.path, "pause", "b"], environment: env)
        #expect(livePause.exitCode == 1)

        await server.stopAndCleanup()
    }

    @Test("Item 5 (A53): cliSubcommands, bilingual helpBanner, and all 3 acceptance script whitelists include daemon and events (plus image & run in readme-commands.sh)")
    func subcommandRegistrationHelpBannerAndAcceptanceScriptWhitelistsA53() throws {
        #expect(AgentVMCLIRunner.cliSubcommands.contains("daemon"))
        #expect(AgentVMCLIRunner.cliSubcommands.contains("events"))

        let helpEn = AgentVMCLIRunner.helpBanner(language: .en)
        let helpZh = AgentVMCLIRunner.helpBanner(language: .zhHans)
        #expect(helpEn.contains("daemon"))
        #expect(helpEn.contains("events"))
        #expect(helpZh.contains("daemon"))
        #expect(helpZh.contains("events"))

        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()

        let readmeScript = try String(
            contentsOf: repoRoot.appendingPathComponent("Scripts/acceptance/readme-commands.sh"),
            encoding: .utf8
        )
        for token in ["\"image\"", "\"run\"", "\"daemon\"", "\"events\""] {
            #expect(readmeScript.contains(token), "readme-commands.sh missing \(token)")
        }

        let m0Script = try String(
            contentsOf: repoRoot.appendingPathComponent("Scripts/acceptance/m0-acceptance.sh"),
            encoding: .utf8
        )
        #expect(m0Script.contains("|daemon|") || m0Script.contains("daemon|"))
        #expect(m0Script.contains("|events|") || m0Script.contains("|events)"))

        let m1Script = try String(
            contentsOf: repoRoot.appendingPathComponent("Scripts/acceptance/m1-real-boot.sh"),
            encoding: .utf8
        )
        #expect(m1Script.contains("|daemon|") || m1Script.contains("daemon|"))
        #expect(m1Script.contains("|events|") || m1Script.contains("|events)"))
    }

    // MARK: - Item 6: `Scripts/acceptance/m2-daemon.sh` Structure, Guards & Strict Daemon Discovery

    @Test("Item 6: Scripts/acceptance/m2-daemon.sh exists, is executable, enforces strict 'daemon run --workspace' + comm==AGENTVM_BIN matching without fuzzy pgrep/pkill, and covers Rows 1-9")
    func m2DaemonAcceptanceScriptStructureGuardsAndStrictDaemonMatching() throws {
        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let scriptURL = repoRoot.appendingPathComponent("Scripts/acceptance/m2-daemon.sh")

        #expect(FileManager.default.isExecutableFile(atPath: scriptURL.path))
        let content = try String(contentsOf: scriptURL, encoding: .utf8)

        #expect(content.contains("ISOLATED_HOME"))
        #expect(content.contains("CFFIXED_USER_HOME"))
        #expect(content.contains("AGENTVM_BIN"))
        #expect(content.contains("daemon run --workspace"))
        #expect(content.contains("comm="))
        #expect(content.contains("DARWIN_USER_TEMP_DIR"))
        #expect(content.contains("没跑"))

        // Check executable code lines (non-comment lines) never use fuzzy `pgrep -f 'daemon run'` or `pkill -f`.
        let codeLines = content
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.hasPrefix("#") }
            .joined(separator: "\n")
        #expect(!codeLines.contains("pkill -f"))
        #expect(!codeLines.contains("pgrep -f 'daemon run'"))
        #expect(!codeLines.contains("pgrep -f \"daemon run\""))
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
