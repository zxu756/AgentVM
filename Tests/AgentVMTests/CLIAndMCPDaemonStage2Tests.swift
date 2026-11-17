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
