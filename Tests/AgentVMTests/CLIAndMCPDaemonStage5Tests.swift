import AgentVMCLIAndMCP
import AgentVMHypervisor
import AgentVMModels
import AgentVMStorageCoW
import AgentVMStore
import AgentVMVsockRPC
import Darwin
import Foundation
import Testing

@Suite("M2 Stage 5: Guest Agent v2 Process-Group RST/Timeout/Disconnect, Fake /proc CPU & Memory, and Pong v2 Handshake", .timeLimit(.minutes(2)))
struct CLIAndMCPDaemonStage5Tests {

    private func makeTemporaryDirectory(prefix: String = "avm-s5") throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func makeShortUnixListenerSocket(tag: String) throws -> (serverFD: Int32, sockPath: String) {
        let sockPath = "/tmp/avm-\(tag)-\(UUID().uuidString.prefix(8)).sock"
        _ = Darwin.unlink(sockPath)

        let serverFD = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        #expect(serverFD >= 0)

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(sockPath.utf8CString)
        #expect(pathBytes.count <= MemoryLayout.size(ofValue: addr.sun_path))
        withUnsafeMutableBytes(of: &addr.sun_path) { rawBuf in
            for (idx, b) in pathBytes.enumerated() {
                rawBuf[idx] = UInt8(bitPattern: b)
            }
        }
        let bindRC = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.bind(serverFD, saPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        #expect(bindRC == 0)
        #expect(Darwin.listen(serverFD, 4) == 0)
        return (serverFD, sockPath)
    }

    private func readPIDFile(_ url: URL, timeoutSeconds: TimeInterval = 3.0) async -> pid_t? {
        let deadline = DispatchTime.now().uptimeNanoseconds &+ UInt64(max(0.05, timeoutSeconds) * 1_000_000_000)
        while DispatchTime.now().uptimeNanoseconds < deadline {
            if let text = try? String(contentsOf: url, encoding: .utf8) {
                let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
                if let val = Int32(trimmed), val > 0 {
                    return pid_t(val)
                }
            }
            try? await Task.sleep(nanoseconds: 15_000_000)
        }
        return nil
    }

    private func isProcessDead(_ pid: pid_t) -> Bool {
        guard pid > 0 else { return true }
        if Darwin.kill(pid, 0) != 0 && Darwin.errno == ESRCH {
            return true
        }
        return false
    }

    private func waitForProcessExit(_ pid: pid_t, timeoutSeconds: TimeInterval = 2.0) async -> Bool {
        guard pid > 0 else { return true }
        let deadline = DispatchTime.now().uptimeNanoseconds &+ UInt64(max(0.05, timeoutSeconds) * 1_000_000_000)
        while DispatchTime.now().uptimeNanoseconds < deadline {
            if isProcessDead(pid) {
                return true
            }
            try? await Task.sleep(nanoseconds: 15_000_000)
        }
        return isProcessDead(pid)
    }

    private static func forceKillCleanupPIDFile(_ url: URL) {
        guard let text = try? String(contentsOf: url, encoding: .utf8),
              let raw = Int32(text.trimmingCharacters(in: .whitespacesAndNewlines)),
              raw > 1 else {
            return
        }
        let pid = pid_t(raw)
        let myPGID = Darwin.getpgrp()
        let childPGID = Darwin.getpgid(pid)
        if childPGID > 1 && childPGID != myPGID {
            _ = Darwin.killpg(childPGID, SIGKILL)
        }
        _ = Darwin.kill(pid, SIGKILL)
    }

    // MARK: - Item 1 & Item 4a: `--proc-root` CLI Flag + Stream `RST` Kills Entire Process Group (Including Grandchildren)

    @Test("Items 1 & 4: generated guest daemon accepts --proc-root, runs exec in start_new_session, and stream RST kills entire process group (including SIGTERM-ignoring grandchild) while keeping sibling stream alive")
    func guestDaemonAcceptsProcRootAndRSTKillsEntireProcessGroupKeepingSiblingAlive() async throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-py-rst")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let daemonScriptURL = tempDir.appendingPathComponent("agentvm_guestd.py")
        try GuestAgentBootstrapGenerator().pythonDaemonScript().write(
            to: daemonScriptURL,
            atomically: true,
            encoding: .utf8
        )

        // 1. Verify CLI `--help` advertises `--proc-root` (default `/proc`).
        let helpPipe = Pipe()
        let helpErrPipe = Pipe()
        let helpProc = Process()
        helpProc.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        helpProc.arguments = ["-I", daemonScriptURL.path, "--help"]
        helpProc.standardOutput = helpPipe
        helpProc.standardError = helpErrPipe
        try helpProc.run()
        #expect(helpProc.waitForExit(), "helpProc did not exit within 60 seconds")
        let helpOut = String(decoding: helpPipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        #expect(helpProc.terminationStatus == 0)
        #expect(helpOut.contains("--proc-root"), "agentvm-guestd.py --help must support --proc-root")

        // 2. Run GuestVsockConnectionSession over AF_UNIX (Fact 33 style) on macOS /usr/bin/python3.
        let (serverFD, sockPath) = try makeShortUnixListenerSocket(tag: "s5rst")
        defer {
            if serverFD >= 0 { _ = Darwin.close(serverFD) }
            _ = Darwin.unlink(sockPath)
        }

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        proc.arguments = [
            "-u",
            "-c",
            """
            import socket, sys
            sys.path.insert(0, sys.argv[1])
            import agentvm_guestd
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(sys.argv[2])
            session = agentvm_guestd.GuestVsockConnectionSession(
                conn=sock,
                heartbeat_interval=60,
                default_workspace=sys.argv[1],
            )
            session.run()
            """,
            tempDir.path,
            sockPath
        ]
        try proc.run()
        defer {
            if proc.isRunning {
                proc.terminate()
                proc.waitForExit()
            }
        }

        let clientFD = Darwin.accept(serverFD, nil, nil)
        #expect(clientFD >= 0)

        let session = VsockMultiplexSession(vmID: VMID("py-s5-rst-test"))
        try await session.attachPOSIXFileDescriptor(clientFD, closeWhenDone: true)
        defer {
            Task { await session.shutdown() }
        }

        let shellPIDFile = tempDir.appendingPathComponent("rst-shell.pid")
        let sleepPIDFile = tempDir.appendingPathComponent("rst-sleep.pid")
        let sigignPIDFile = tempDir.appendingPathComponent("rst-sigign.pid")
        defer {
            Self.forceKillCleanupPIDFile(sigignPIDFile)
            Self.forceKillCleanupPIDFile(sleepPIDFile)
            Self.forceKillCleanupPIDFile(shellPIDFile)
        }

        let sigignHelperURL = tempDir.appendingPathComponent("ignore_term_child.py")
        try """
        import os, signal, sys, time
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        with open(sys.argv[1], "w", encoding="utf-8") as fh:
            fh.write(f"{os.getpid()}\\n")
            fh.flush()
        time.sleep(60)
        """.write(to: sigignHelperURL, atomically: true, encoding: .utf8)

        let streamTracker = Stage5ExecStreamTracker()

        // Sibling stream B runs concurrently on the same multiplexed connection and must NOT be killed by stream A's RST.
        async let siblingTask = session.executeCommand(
            GuestExecRequest(
                executable: "/bin/sh",
                arguments: ["-c", "sleep 0.65; echo sibling-survived"],
                workingDirectory: tempDir.path,
                runAsUser: "root"
            )
        )

        let cmdScript = """
        echo $$ > "\(shellPIDFile.path)"
        /bin/sleep 60 &
        echo $! > "\(sleepPIDFile.path)"
        /usr/bin/python3 "\(sigignHelperURL.path)" "\(sigignPIDFile.path)" &
        while [ ! -s "\(sigignPIDFile.path)" ]; do /bin/sleep 0.02; done
        echo READY_FOR_RST
        wait
        """

        let cancelledTask = Task<Result<GuestExecResult, Error>, Never> {
            do {
                let res = try await session.executeCommandStreaming(
                    GuestExecRequest(
                        executable: "/bin/sh",
                        arguments: ["-c", cmdScript],
                        workingDirectory: tempDir.path,
                        runAsUser: "root",
                        timeoutSeconds: 30
                    ),
                    onStreamOpened: { sid in
                        streamTracker.recordStreamID(sid)
                    },
                    onChunk: { chunk in
                        if chunk.stream == .stdout {
                            streamTracker.appendStdout(chunk.data)
                        }
                    }
                )
                return .success(res)
            } catch {
                return .failure(error)
            }
        }

        let sawReady = await streamTracker.waitForSubstring("READY_FOR_RST", timeoutSeconds: 4.0)
        #expect(sawReady == true, "Expected READY_FOR_RST output before sending stream RST")

        let streamID = try #require(streamTracker.streamID)
        let shellPID = try #require(await readPIDFile(shellPIDFile))
        let sleepPID = try #require(await readPIDFile(sleepPIDFile))
        let sigignPID = try #require(await readPIDFile(sigignPIDFile))

        // Verify start_new_session=True placed child and grandchildren in a new process group == shellPID.
        let pythonDaemonPGID = Darwin.getpgid(proc.processIdentifier)
        let shellPGID = Darwin.getpgid(shellPID)
        let sleepPGID = Darwin.getpgid(sleepPID)
        let sigignPGID = Darwin.getpgid(sigignPID)
        #expect(shellPGID == shellPID, "exec child must lead its own session/process group (start_new_session=True)")
        #expect(shellPGID != pythonDaemonPGID)
        #expect(sleepPGID == shellPID)
        #expect(sigignPGID == shellPID)
        #expect(!isProcessDead(sleepPID))
        #expect(!isProcessDead(sigignPID))

        // Send AVM1 RST on stream A only.
        await session.cancelExecStream(streamID: streamID)
        _ = await cancelledTask.value

        let sleepKilled = await waitForProcessExit(sleepPID, timeoutSeconds: 2.0)
        let sigignKilled = await waitForProcessExit(sigignPID, timeoutSeconds: 2.0)
        let shellKilled = await waitForProcessExit(shellPID, timeoutSeconds: 2.0)
        #expect(sleepKilled == true, "Grandchild sleep (\(sleepPID)) must be killed on stream RST")
        #expect(sigignKilled == true, "SIGTERM-ignoring grandchild (\(sigignPID)) must be escalated to SIGKILL on stream RST")
        #expect(shellKilled == true, "Direct shell child (\(shellPID)) must be killed on stream RST")

        let siblingRes = try await siblingTask
        #expect(siblingRes.exitCode == 0)
        #expect(siblingRes.stdoutUTF8 == "sibling-survived\n")

        await session.shutdown()
        #expect(proc.waitForExit(), "proc did not exit within 60 seconds")
    }

    // MARK: - Item 1 & Item 4b: Exec Timeout Kills Entire Process Group (Including Grandchildren Holding Pipes)

    @Test("Items 1 & 4: generated guest daemon kills entire process group (including grandchildren) on command timeout without hanging on open stdout pipe")
    func guestDaemonTimeoutKillsEntireProcessGroupIncludingGrandchildren() async throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-py-tmo")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let daemonScriptURL = tempDir.appendingPathComponent("agentvm_guestd.py")
        try GuestAgentBootstrapGenerator().pythonDaemonScript().write(
            to: daemonScriptURL,
            atomically: true,
            encoding: .utf8
        )

        let (serverFD, sockPath) = try makeShortUnixListenerSocket(tag: "s5tmo")
        defer {
            if serverFD >= 0 { _ = Darwin.close(serverFD) }
            _ = Darwin.unlink(sockPath)
        }

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        proc.arguments = [
            "-u",
            "-c",
            """
            import socket, sys
            sys.path.insert(0, sys.argv[1])
            import agentvm_guestd
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(sys.argv[2])
            session = agentvm_guestd.GuestVsockConnectionSession(
                conn=sock,
                heartbeat_interval=60,
                default_workspace=sys.argv[1],
            )
            session.run()
            """,
            tempDir.path,
            sockPath
        ]
        try proc.run()
        defer {
            if proc.isRunning {
                proc.terminate()
                proc.waitForExit()
            }
        }

        let clientFD = Darwin.accept(serverFD, nil, nil)
        #expect(clientFD >= 0)

        let session = VsockMultiplexSession(vmID: VMID("py-s5-tmo-test"))
        try await session.attachPOSIXFileDescriptor(clientFD, closeWhenDone: true)
        defer {
            Task { await session.shutdown() }
        }

        let grandchildPIDFile = tempDir.appendingPathComponent("tmo-grandchild.pid")
        let shellPIDFile = tempDir.appendingPathComponent("tmo-shell.pid")
        defer {
            Self.forceKillCleanupPIDFile(grandchildPIDFile)
            Self.forceKillCleanupPIDFile(shellPIDFile)
        }

        let script = """
        echo $$ > "\(shellPIDFile.path)"
        /bin/sleep 60 &
        echo $! > "\(grandchildPIDFile.path)"
        echo started
        wait
        """

        let t0Ns = DispatchTime.now().uptimeNanoseconds
        let res = try await session.executeCommand(
            GuestExecRequest(
                executable: "/bin/sh",
                arguments: ["-c", script],
                workingDirectory: tempDir.path,
                runAsUser: "root",
                timeoutSeconds: 0.45
            )
        )
        let elapsedSec = Double(DispatchTime.now().uptimeNanoseconds - t0Ns) / 1_000_000_000.0
        #expect(res.timedOut == true)
        #expect(res.exitCode == 124)
        #expect(elapsedSec < 3.0, "Timed-out exec should return promptly, took \(elapsedSec)s")

        let grandchildPID = try #require(await readPIDFile(grandchildPIDFile))
        let grandchildDead = await waitForProcessExit(grandchildPID, timeoutSeconds: 2.0)
        #expect(grandchildDead == true, "Grandchild sleep (\(grandchildPID)) must be killed when exec times out")

        // Verify the guest daemon thread did not get stuck on open grandchild stdout pipe and serves subsequent execs.
        let afterRes = try await session.executeCommand(
            GuestExecRequest(
                executable: "/bin/sh",
                arguments: ["-c", "echo still-healthy"],
                workingDirectory: tempDir.path,
                runAsUser: "root",
                timeoutSeconds: 3.0
            )
        )
        #expect(afterRes.exitCode == 0)
        #expect(afterRes.stdoutUTF8 == "still-healthy\n")

        await session.shutdown()
        #expect(proc.waitForExit(), "proc did not exit within 60 seconds")
    }

    // MARK: - Item 1 & Item 4c: Connection Disconnect Kills Entire Process Group (Including Grandchildren)

    @Test("Items 1 & 4: generated guest daemon kills entire process group (including grandchildren) when vsock connection disconnects")
    func guestDaemonDisconnectKillsEntireProcessGroupIncludingGrandchildren() async throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-py-eof")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let daemonScriptURL = tempDir.appendingPathComponent("agentvm_guestd.py")
        try GuestAgentBootstrapGenerator().pythonDaemonScript().write(
            to: daemonScriptURL,
            atomically: true,
            encoding: .utf8
        )

        let (serverFD, sockPath) = try makeShortUnixListenerSocket(tag: "s5eof")
        defer {
            if serverFD >= 0 { _ = Darwin.close(serverFD) }
            _ = Darwin.unlink(sockPath)
        }

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        proc.arguments = [
            "-u",
            "-c",
            """
            import socket, sys
            sys.path.insert(0, sys.argv[1])
            import agentvm_guestd
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(sys.argv[2])
            session = agentvm_guestd.GuestVsockConnectionSession(
                conn=sock,
                heartbeat_interval=60,
                default_workspace=sys.argv[1],
            )
            session.run()
            """,
            tempDir.path,
            sockPath
        ]
        try proc.run()
        defer {
            if proc.isRunning {
                proc.terminate()
                proc.waitForExit()
            }
        }

        let clientFD = Darwin.accept(serverFD, nil, nil)
        #expect(clientFD >= 0)

        let session = VsockMultiplexSession(vmID: VMID("py-s5-eof-test"))
        try await session.attachPOSIXFileDescriptor(clientFD, closeWhenDone: true)
        defer {
            Task { await session.shutdown() }
        }

        let grandchildPIDFile = tempDir.appendingPathComponent("eof-grandchild.pid")
        let shellPIDFile = tempDir.appendingPathComponent("eof-shell.pid")
        defer {
            Self.forceKillCleanupPIDFile(grandchildPIDFile)
            Self.forceKillCleanupPIDFile(shellPIDFile)
        }

        let tracker = Stage5ExecStreamTracker()
        let script = """
        echo $$ > "\(shellPIDFile.path)"
        /bin/sleep 60 &
        echo $! > "\(grandchildPIDFile.path)"
        echo READY_FOR_DISCONNECT
        wait
        """

        let execTask = Task<Void, Never> {
            _ = try? await session.executeCommandStreaming(
                GuestExecRequest(
                    executable: "/bin/sh",
                    arguments: ["-c", script],
                    workingDirectory: tempDir.path,
                    runAsUser: "root",
                    timeoutSeconds: 30
                ),
                onChunk: { chunk in
                    if chunk.stream == .stdout {
                        tracker.appendStdout(chunk.data)
                    }
                }
            )
        }

        #expect(await tracker.waitForSubstring("READY_FOR_DISCONNECT", timeoutSeconds: 4.0) == true)
        let shellPID = try #require(await readPIDFile(shellPIDFile))
        let grandchildPID = try #require(await readPIDFile(grandchildPIDFile))
        #expect(!isProcessDead(grandchildPID))

        // Close host transport FD (session.shutdown() closes clientFD -> guest sees EOF).
        await session.shutdown()
        await execTask.value

        let grandchildDead = await waitForProcessExit(grandchildPID, timeoutSeconds: 2.0)
        let shellDead = await waitForProcessExit(shellPID, timeoutSeconds: 2.0)
        #expect(grandchildDead == true, "Grandchild sleep (\(grandchildPID)) must be killed when vsock disconnects")
        #expect(shellDead == true, "Shell child (\(shellPID)) must be killed when vsock disconnects")

        #expect(proc.waitForExit(), "proc did not exit within 60 seconds")
    }

    // MARK: - Item 2: Fake `--proc-root` CPU (`cpuUsagePercent`) & Memory (`memTotalBytes`, `memAvailableBytes`)

    @Test("Item 2: generated guest daemon with --proc-root omits cpuUsagePercent on first heartbeat and when Δtotal == 0, computes aggregate multi-vCPU (Δtotal - Δidle)/Δtotal*100 across subsequent intervals, and reports MemTotal/MemAvailable")
    func guestDaemonFakeProcRootComputesAggregateCPUUsageAndMemoryAndOmitsFirstAndZeroDelta() async throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-py-cpu")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let fakeProcURL = tempDir.appendingPathComponent("proc", isDirectory: true)
        try FileManager.default.createDirectory(at: fakeProcURL, withIntermediateDirectories: true)

        let statURL = fakeProcURL.appendingPathComponent("stat")
        let meminfoURL = fakeProcURL.appendingPathComponent("meminfo")
        let uptimeURL = fakeProcURL.appendingPathComponent("uptime")

        // Baseline /proc snapshot (2 vCPUs; aggregate first line total = 10000, idle+iowait = 8400+200 = 8600).
        try """
        cpu  1000 100 300 8400 200 0 0 0 0 0
        cpu0 500 50 150 4200 100 0 0 0 0 0
        cpu1 500 50 150 4200 100 0 0 0 0 0
        """.write(to: statURL, atomically: true, encoding: .utf8)

        try """
        MemTotal:        2097152 kB
        MemFree:          524288 kB
        MemAvailable:    1572864 kB
        Buffers:           65536 kB
        Cached:           983040 kB
        """.write(to: meminfoURL, atomically: true, encoding: .utf8)

        try "120.50 240.00\n".write(to: uptimeURL, atomically: true, encoding: .utf8)

        let daemonScriptURL = tempDir.appendingPathComponent("agentvm_guestd.py")
        try GuestAgentBootstrapGenerator().pythonDaemonScript().write(
            to: daemonScriptURL,
            atomically: true,
            encoding: .utf8
        )

        let (serverFD, sockPath) = try makeShortUnixListenerSocket(tag: "s5cpu")
        defer {
            if serverFD >= 0 { _ = Darwin.close(serverFD) }
            _ = Darwin.unlink(sockPath)
        }

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        proc.arguments = [
            "-u",
            "-c",
            """
            import socket, sys
            sys.path.insert(0, sys.argv[1])
            import agentvm_guestd
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(sys.argv[2])
            session = agentvm_guestd.GuestVsockConnectionSession(
                conn=sock,
                heartbeat_interval=3600,
                default_workspace=sys.argv[1],
                proc_root=sys.argv[3],
            )
            session.run()
            """,
            tempDir.path,
            sockPath,
            fakeProcURL.path
        ]
        try proc.run()
        defer {
            if proc.isRunning {
                proc.terminate()
                proc.waitForExit()
            }
        }

        var clientFD = Darwin.accept(serverFD, nil, nil)
        #expect(clientFD >= 0)
        defer {
            if clientFD >= 0 { _ = Darwin.close(clientFD) }
        }

        let wirePeer = Stage5RawWireClient(fd: clientFD)

        // 1. First heartbeat (emitted on connect): must NOT carry `cpuUsagePercent`, and must report MemTotal & MemAvailable.
        let hb1 = try wirePeer.readNextHeartbeatJSON(timeoutMilliseconds: 3_000)
        #expect(hb1["cpuUsagePercent"] == nil, "First heartbeat must omit cpuUsagePercent (no previous sample)")
        #expect((hb1["memTotalBytes"] as? NSNumber)?.uint64Value == 2_097_152 * 1024)
        #expect((hb1["memAvailableBytes"] as? NSNumber)?.uint64Value == 1_572_864 * 1024)
        let uptime1 = (hb1["uptimeSeconds"] as? NSNumber)?.doubleValue ?? 0
        #expect(abs(uptime1 - 120.5) < 0.01)

        // 2. Second heartbeat with identical /proc/stat (Δtotal == 0): must ALSO omit `cpuUsagePercent`.
        try wirePeer.solicitHeartbeat()
        let hb2 = try wirePeer.readNextHeartbeatJSON(timeoutMilliseconds: 3_000)
        #expect(hb2["cpuUsagePercent"] == nil, "Heartbeat with Δtotal == 0 must omit cpuUsagePercent")

        // 3. Third heartbeat: advance aggregate /proc/stat by Δtotal = 400, Δidle = 250 -> (400 - 250)/400 * 100 = 37.5%,
        //    and lower MemAvailable to 1048576 kB (1 GiB).
        try """
        cpu  1100 110 340 8630 220 0 0 0 0 0
        cpu0 550 55 170 4315 110 0 0 0 0 0
        cpu1 550 55 170 4315 110 0 0 0 0 0
        """.write(to: statURL, atomically: true, encoding: .utf8)

        try """
        MemTotal:        2097152 kB
        MemFree:          262144 kB
        MemAvailable:    1048576 kB
        """.write(to: meminfoURL, atomically: true, encoding: .utf8)

        try wirePeer.solicitHeartbeat()
        let hb3 = try wirePeer.readNextHeartbeatJSON(timeoutMilliseconds: 3_000)
        let cpu3 = (hb3["cpuUsagePercent"] as? NSNumber)?.doubleValue
        #expect(cpu3 != nil, "Heartbeat with Δtotal > 0 must include cpuUsagePercent")
        if let cpu3 {
            #expect(abs(cpu3 - 37.5) < 0.01, "Expected aggregate cpuUsagePercent == 37.5, got \(cpu3)")
        }
        #expect((hb3["memTotalBytes"] as? NSNumber)?.uint64Value == 2_097_152 * 1024)
        #expect((hb3["memAvailableBytes"] as? NSNumber)?.uint64Value == 1_048_576 * 1024)

        // 4. Fourth heartbeat: advance from sample 3 by Δtotal = 200, Δidle = 50 -> (200 - 50)/200 * 100 = 75.0%
        //    (proves delta is computed against previous sample, not cumulative boot jiffies which would give 50.0%).
        try """
        cpu  1250 110 340 8680 220 0 0 0 0 0
        cpu0 625 55 170 4340 110 0 0 0 0 0
        cpu1 625 55 170 4340 110 0 0 0 0 0
        """.write(to: statURL, atomically: true, encoding: .utf8)

        try wirePeer.solicitHeartbeat()
        let hb4 = try wirePeer.readNextHeartbeatJSON(timeoutMilliseconds: 3_000)
        let cpu4 = (hb4["cpuUsagePercent"] as? NSNumber)?.doubleValue
        #expect(cpu4 != nil)
        if let cpu4 {
            #expect(abs(cpu4 - 75.0) < 0.01, "Expected interval delta cpuUsagePercent == 75.0, got \(cpu4)")
        }

        _ = Darwin.close(clientFD)
        clientFD = -1
        #expect(proc.waitForExit(), "proc did not exit within 60 seconds")
    }

    // MARK: - Item 3: `pong` Version `"2"`, Host `ping` on Every Vsock Connect & Reconnect, `daemon status --json` `guestAgentVersion`, and Legacy `"1.0.0"` Compatibility

    @Test("Item 3 (A46, A50): generated guest daemon replies pong version 2; host pings on initial vsock connect and Stage 3b reconnect, records guestAgentVersion in daemon status --json, and keeps working with 1.0.0 guest")
    func guestDaemonPongVersion2AndHostHandshakeOnConnectAndReconnectWithLegacyAndV2Guests() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-s5-hs")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let daemonScriptURL = URL(fileURLWithPath: "\(realBase)/agentvm_guestd.py")
        try GuestAgentBootstrapGenerator().pythonDaemonScript().write(
            to: daemonScriptURL,
            atomically: true,
            encoding: .utf8
        )

        // Part A: Direct Fact-33 check that generated `agentvm_guestd.py` replies `pong` with `agentVersion == "2"`.
        do {
            let (serverFD, sockPath) = try makeShortUnixListenerSocket(tag: "s5p2")
            defer {
                if serverFD >= 0 { _ = Darwin.close(serverFD) }
                _ = Darwin.unlink(sockPath)
            }
            let pyProc = Process()
            pyProc.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
            pyProc.arguments = [
                "-u",
                "-c",
                """
                import socket, sys
                sys.path.insert(0, sys.argv[1])
                import agentvm_guestd
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.connect(sys.argv[2])
                session = agentvm_guestd.GuestVsockConnectionSession(
                    conn=sock,
                    heartbeat_interval=3600,
                    default_workspace=sys.argv[1],
                )
                session.run()
                """,
                realBase,
                sockPath
            ]
            try pyProc.run()
            defer {
                if pyProc.isRunning {
                    pyProc.terminate()
                    pyProc.waitForExit()
                }
            }

            var cfd = Darwin.accept(serverFD, nil, nil)
            #expect(cfd >= 0)
            defer {
                if cfd >= 0 { _ = Darwin.close(cfd) }
            }
            let rawClient = Stage5RawWireClient(fd: cfd)
            try rawClient.sendControlPing()
            let pong = try rawClient.readNextControlEnvelope(timeoutMilliseconds: 3_000)
            #expect(pong.kind == .pong)
            #expect(pong.agentVersion == "2", "Generated guest daemon pong must advertise agentVersion == \"2\"")
            _ = Darwin.close(cfd)
            cfd = -1
            #expect(pyProc.waitForExit(), "pyProc did not exit within 60 seconds")
        }

        // Part B: End-to-end daemon vsock handshake over AF_UNIX against:
        //   1st connect (`up t1`): simulated legacy `1.0.0` guest over AF_UNIX -> host pings first,
        //                          `daemon status --json` lists `guestAgentVersion == "1.0.0"`, and `exec` works.
        //   2nd connect (after vsock EOF -> Stage 3b reconnect): real generated `agentvm_guestd.py` over AF_UNIX ->
        //                          host pings again on reconnect, `daemon status --json` updates `guestAgentVersion == "2"`,
        //                          and `exec` works.
        let legacyUnixGuest = try Stage5LegacyUnixGuestServer(tag: "s5v1", advertisedVersion: "1.0.0")
        defer { legacyUnixGuest.shutdown() }

        let v2SockPath = "/tmp/avm-s5v2-\(UUID().uuidString.prefix(8)).sock"
        _ = Darwin.unlink(v2SockPath)
        defer { _ = Darwin.unlink(v2SockPath) }

        let readyPipe = Pipe()
        let v2PyProc = Process()
        v2PyProc.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        v2PyProc.arguments = [
            "-u",
            "-c",
            """
            import os, socket, sys
            sys.path.insert(0, sys.argv[1])
            import agentvm_guestd
            sock_path = sys.argv[2]
            try:
                os.unlink(sock_path)
            except FileNotFoundError:
                pass
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(sock_path)
            srv.listen(4)
            sys.stdout.write("LISTENING\\n")
            sys.stdout.flush()
            conn, _ = srv.accept()
            srv.close()
            session = agentvm_guestd.GuestVsockConnectionSession(
                conn=conn,
                heartbeat_interval=3600,
                default_workspace=sys.argv[1],
            )
            session.run()
            """,
            realBase,
            v2SockPath
        ]
        v2PyProc.standardOutput = readyPipe
        try v2PyProc.run()
        defer {
            if v2PyProc.isRunning {
                v2PyProc.terminate()
                v2PyProc.waitForExit()
            }
        }
        #expect(Self.waitForPipeLine(readyPipe.fileHandleForReading, containing: "LISTENING", timeoutSeconds: 3.0) == true)

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/HandshakeS5.agentvm", isDirectory: true)
        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()
        let forbiddenSpawn = DaemonSpawnCommandOverride(
            executablePath: "/bin/sh",
            arguments: ["-c", "exit 96"],
            environment: env
        )

        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "create", "t1", "--image", entry.id],
            curatedEntriesOverride: [entry],
            environment: env
        ).exitCode == 0)

        let switchingBackend = Stage5UnixSocketSwitchingHardwareBackend(
            socketPathsByConnectOrder: [legacyUnixGuest.sockPath, v2SockPath]
        )

        let startOutcome = try await WorkspaceDaemonServer.start(
            workspaceURL: wsURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: switchingBackend,
            vsockConnectTimeoutNanoseconds: 5_000_000_000,
            vsockRetryIntervalNanoseconds: 100_000_000,
            gracefulStopTimeoutNanoseconds: 120_000_000
        )
        guard case let .started(server) = startOutcome else {
            Issue.record("Expected WorkspaceDaemonServer.start to succeed")
            return
        }
        defer {
            server.listener.close(unlinkSocket: true, removeSymlink: true)
            server.singletonLock.release(clearFile: true)
            server.logManager.close()
        }

        do {
            // 1. `up t1` connects to legacy 1.0.0 AF_UNIX guest.
            let upRes = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(upRes.exitCode == 0, "up t1 failed against 1.0.0 guest: \(upRes.stderr)")

            #expect(legacyUnixGuest.pingCount == 1, "Host must ping guest immediately upon initial vsock connect")
            #expect(legacyUnixGuest.inboundChannels.first == .control, "First frame sent by host on vsock connect must be control ping")

            // 2. `daemon status --json` lists `t1` with `guestAgentVersion == "1.0.0"`.
            let status1 = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "daemon", "status", "--json"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(status1.exitCode == 0)
            let status1JSON = try #require(
                try JSONSerialization.jsonObject(with: Data(status1.stdout.utf8)) as? [String: Any]
            )
            let vms1 = try #require(status1JSON["vms"] as? [[String: Any]])
            let t1Entry1 = try #require(vms1.first(where: { ($0["spec"] as? [String: Any])?["name"] as? String == "t1" }))
            #expect(t1Entry1["guestAgentVersion"] as? String == "1.0.0", "daemon status --json must report guestAgentVersion == \"1.0.0\" for legacy guest")

            // 3. `exec` against legacy `1.0.0` guest continues to work normally.
            let exec1 = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "exec", "t1", "--", "/bin/echo", "legacy-still-works"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(exec1.exitCode == 0, "exec must keep working when guestAgentVersion is 1.0.0: \(exec1.stderr)")
            #expect(exec1.stdout == "legacy-1.0.0: /bin/echo legacy-still-works\n")

            // 4. Close legacy `1.0.0` guest connection -> triggers Stage 3b vsock EOF & reconnect onto generated v2 Python daemon.
            legacyUnixGuest.closeActiveConnection()

            var reconnectedToV2 = false
            let deadlineNs = DispatchTime.now().uptimeNanoseconds &+ 4_000_000_000
            while DispatchTime.now().uptimeNanoseconds < deadlineNs {
                if switchingBackend.connectCount >= 2 {
                    let psCheck = await cli.execute(
                        arguments: ["--lang", "en", "--workspace", wsURL.path, "ps", "--json"],
                        curatedEntriesOverride: [entry],
                        environment: env,
                        daemonSpawnOverride: forbiddenSpawn
                    )
                    if let psArr = (try? JSONSerialization.jsonObject(with: Data(psCheck.stdout.utf8))) as? [[String: Any]],
                       let rec = psArr.first(where: { ($0["spec"] as? [String: Any])?["name"] as? String == "t1" }),
                       let tel = rec["telemetry"] as? [String: Any],
                       tel["guestAgentConnected"] as? Bool == true {
                        reconnectedToV2 = true
                        break
                    }
                }
                try? await Task.sleep(nanoseconds: 40_000_000)
            }
            #expect(reconnectedToV2 == true, "Daemon must reconnect vsock to second AF_UNIX endpoint after EOF")

            // 5. `daemon status --json` now reports `guestAgentVersion == "2"` from the reconnected v2 Python guest!
            let status2 = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "daemon", "status", "--json"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(status2.exitCode == 0)
            let status2JSON = try #require(
                try JSONSerialization.jsonObject(with: Data(status2.stdout.utf8)) as? [String: Any]
            )
            let vms2 = try #require(status2JSON["vms"] as? [[String: Any]])
            let t1Entry2 = try #require(vms2.first(where: { ($0["spec"] as? [String: Any])?["name"] as? String == "t1" }))
            #expect(t1Entry2["guestAgentVersion"] as? String == "2", "daemon status --json must update guestAgentVersion to \"2\" after reconnecting to v2 guest")

            // 6. `exec` over the reconnected v2 Python guest succeeds.
            let exec2 = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "exec", "t1", "--", "/bin/echo", "hello-from-v2"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(exec2.exitCode == 0, "exec against v2 guest failed: \(exec2.stderr)")
            #expect(exec2.stdout == "hello-from-v2\n")

            await server.stopAndCleanup()
        } catch {
            await server.stopAndCleanup()
            throw error
        }
    }

    // MARK: - Private Workspace & Image Helpers for Stage 5 Handshake Tests

    private func makePrivateTmpDirectory(prefix: String = "avm-s5") throws -> String {
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

    private static func sweepDarwinUserTempSymlinks(pointingUnder basePath: String) {
        guard let darwinTempDir = try? DaemonSocketAddressResolver.darwinUserTempDirectoryURL() else {
            return
        }
        let canonicalBase = DaemonSocketAddressResolver.canonicalRealPath(
            of: URL(fileURLWithPath: basePath, isDirectory: true)
        )
        var prefixes = [canonicalBase]
        if canonicalBase.hasPrefix("/private/tmp/") {
            prefixes.append(String(canonicalBase.dropFirst("/private".count)))
        } else if canonicalBase.hasPrefix("/tmp/") {
            prefixes.append("/private" + canonicalBase)
        }
        let uniquePrefixes = Array(Set(prefixes))

        guard let names = try? FileManager.default.contentsOfDirectory(atPath: darwinTempDir.path) else {
            return
        }
        for name in names where name.hasPrefix("avm-") {
            let linkPath = darwinTempDir.appendingPathComponent(name, isDirectory: false).path
            var st = Darwin.stat()
            guard Darwin.lstat(linkPath, &st) == 0, (st.st_mode & S_IFMT) == S_IFLNK else {
                continue
            }
            var buf = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
            let len = Darwin.readlink(linkPath, &buf, Int(PATH_MAX))
            guard len > 0 else { continue }
            let rawTarget = String(decoding: buf.prefix(len).map { UInt8(bitPattern: $0) }, as: UTF8.self)
            let resolvedTarget: String
            if rawTarget.hasPrefix("/") {
                resolvedTarget = DaemonSocketAddressResolver.canonicalRealPath(
                    of: URL(fileURLWithPath: rawTarget, isDirectory: true)
                )
            } else {
                resolvedTarget = DaemonSocketAddressResolver.canonicalRealPath(
                    of: darwinTempDir.appendingPathComponent(rawTarget, isDirectory: true)
                )
            }
            let matches = uniquePrefixes.contains { prefix in
                rawTarget == prefix
                    || rawTarget.hasPrefix(prefix + "/")
                    || resolvedTarget == prefix
                    || resolvedTarget.hasPrefix(prefix + "/")
            }
            if matches {
                _ = Darwin.unlink(linkPath)
            }
        }
    }

    private func stageBootableCachedImage(
        in baseDir: String,
        imageID: String = "debian-12-bookworm-arm64"
    ) async throws -> (cacheDir: URL, cachedFileURL: URL, entry: BaseImageCatalogEntry) {
        let cacheDir = URL(fileURLWithPath: "\(baseDir)/cache", isDirectory: true)
        let imageBytes = 4 * 1024 * 1024
        let stagingURL = URL(fileURLWithPath: "\(baseDir)/staging-\(UUID().uuidString).raw")
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
        return (cacheDir, cachedURL, entry)
    }

    private static func waitForPipeLine(_ handle: FileHandle, containing needle: String, timeoutSeconds: TimeInterval) -> Bool {
        let fd = handle.fileDescriptor
        let deadline = DispatchTime.now().uptimeNanoseconds &+ UInt64(max(0.05, timeoutSeconds) * 1_000_000_000)
        var collected = Data()
        var scratch = [UInt8](repeating: 0, count: 512)
        while DispatchTime.now().uptimeNanoseconds < deadline {
            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            if Darwin.poll(&pfd, 1, 25) > 0 {
                let n = Darwin.read(fd, &scratch, scratch.count)
                if n > 0 {
                    collected.append(contentsOf: scratch.prefix(n))
                    if String(decoding: collected, as: UTF8.self).contains(needle) {
                        return true
                    }
                } else if n == 0 {
                    break
                }
            }
        }
        return String(decoding: collected, as: UTF8.self).contains(needle)
    }
}

// MARK: - Stage 5 Raw AVM1 Wire & Unix Socket Helpers

private final class Stage5RawWireClient: @unchecked Sendable {
    private let fd: Int32
    private let codec = VsockWireCodec()
    private let accumulator = VsockStreamAccumulator()
    private var outSeq: UInt32 = 0

    init(fd: Int32) {
        self.fd = fd
        var one: Int32 = 1
        _ = Darwin.setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
    }

    func solicitHeartbeat() throws {
        outSeq &+= 1
        let frame = try codec.encodeFrame(
            channel: .telemetryHeartbeat,
            flags: [.syn, .endOfMessage],
            streamID: 0,
            sequence: outSeq,
            payload: Data(),
            compressIfBeneficial: false
        )
        try writeAll(frame)
    }

    func sendControlPing() throws {
        outSeq &+= 1
        let ping = VsockControlEnvelope(kind: .ping)
        let payload = try VsockWireJSON.encode(ping)
        let frame = try codec.encodeFrame(
            channel: .control,
            flags: [.syn, .endOfMessage],
            streamID: 0,
            sequence: outSeq,
            payload: payload,
            compressIfBeneficial: false
        )
        try writeAll(frame)
    }

    func readNextHeartbeatJSON(timeoutMilliseconds: Int32) throws -> [String: Any] {
        while true {
            let (header, payload) = try readNextFrame(timeoutMilliseconds: timeoutMilliseconds)
            if header.channel == .telemetryHeartbeat {
                guard let obj = try JSONSerialization.jsonObject(with: payload) as? [String: Any] else {
                    throw AgentVMError.vsockProtocolViolation(detail: "Heartbeat payload is not a JSON object.")
                }
                return obj
            }
        }
    }

    func readNextControlEnvelope(timeoutMilliseconds: Int32) throws -> VsockControlEnvelope {
        while true {
            let (header, payload) = try readNextFrame(timeoutMilliseconds: timeoutMilliseconds)
            if header.channel == .control {
                return try VsockWireJSON.decode(VsockControlEnvelope.self, from: payload)
            }
        }
    }

    private func readNextFrame(timeoutMilliseconds: Int32) throws -> (header: VsockFrameHeader, payload: Data) {
        let deadlineNs = DispatchTime.now().uptimeNanoseconds &+ UInt64(max(1, timeoutMilliseconds)) * 1_000_000
        var scratch = [UInt8](repeating: 0, count: 65_536)
        while true {
            if let existing = try accumulator.nextFrame() {
                return existing
            }
            let nowNs = DispatchTime.now().uptimeNanoseconds
            if nowNs >= deadlineNs {
                throw AgentVMError.vsockProtocolViolation(detail: "Timed out waiting for AVM1 frame on Stage5RawWireClient.")
            }
            let remainingMs = Int32(min(250, max(1, (deadlineNs - nowNs) / 1_000_000)))
            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let prc = Darwin.poll(&pfd, 1, remainingMs)
            if prc == 0 {
                continue
            }
            if prc < 0 {
                if Darwin.errno == EINTR { continue }
                throw AgentVMError.vsockProtocolViolation(detail: "poll failed (errno=\(Darwin.errno))")
            }
            let n = Darwin.read(fd, &scratch, scratch.count)
            if n > 0 {
                try accumulator.appendBytes(Data(scratch.prefix(n)))
            } else if n == 0 {
                throw AgentVMError.vsockProtocolViolation(detail: "Peer closed AF_UNIX socket before expected frame arrived.")
            } else if Darwin.errno != EINTR && Darwin.errno != EAGAIN {
                throw AgentVMError.vsockProtocolViolation(detail: "read failed (errno=\(Darwin.errno))")
            }
        }
    }

    private func writeAll(_ data: Data) throws {
        try data.withUnsafeBytes { rawBuf in
            guard let base = rawBuf.baseAddress else { return }
            var written = 0
            while written < rawBuf.count {
                let n = Darwin.write(fd, base.advanced(by: written), rawBuf.count - written)
                if n > 0 {
                    written += n
                } else if n < 0 && Darwin.errno == EINTR {
                    continue
                } else {
                    throw AgentVMError.vsockProtocolViolation(detail: "write failed (errno=\(Darwin.errno))")
                }
            }
        }
    }
}

private final class Stage5LegacyUnixGuestServer: @unchecked Sendable {
    let sockPath: String
    private let advertisedVersion: String
    private let lock = NSLock()
    private var listenFD: Int32 = -1
    private var activeConnFD: Int32 = -1
    private var acceptThreadTask: Task<Void, Never>?
    private var recordedChannels: [VsockChannelKind] = []
    private var recordedPings = 0

    var pingCount: Int {
        lock.withLock { recordedPings }
    }

    var inboundChannels: [VsockChannelKind] {
        lock.withLock { recordedChannels }
    }

    init(tag: String, advertisedVersion: String) throws {
        self.advertisedVersion = advertisedVersion
        self.sockPath = "/tmp/avm-\(tag)-\(UUID().uuidString.prefix(8)).sock"
        _ = Darwin.unlink(sockPath)

        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(Darwin.errno))
        }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(sockPath.utf8CString)
        withUnsafeMutableBytes(of: &addr.sun_path) { rawBuf in
            for (idx, b) in pathBytes.enumerated() {
                rawBuf[idx] = UInt8(bitPattern: b)
            }
        }
        let bindRC = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.bind(fd, saPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bindRC == 0, Darwin.listen(fd, 4) == 0 else {
            let err = Darwin.errno
            _ = Darwin.close(fd)
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(err))
        }
        self.listenFD = fd
        let versionStr = advertisedVersion

        self.acceptThreadTask = Task.detached { [weak self] in
            let cfd = Darwin.accept(fd, nil, nil)
            guard cfd >= 0 else { return }
            var one: Int32 = 1
            _ = Darwin.setsockopt(cfd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            self?.setActiveConn(cfd)

            let codec = VsockWireCodec()
            let acc = VsockStreamAccumulator(codec: codec)
            var outSeq: UInt32 = 0
            var execBufs: [UInt32: Data] = [:]
            var scratch = [UInt8](repeating: 0, count: 65_536)

            func writeWire(_ data: Data) -> Bool {
                data.withUnsafeBytes { rawBuf -> Bool in
                    guard let base = rawBuf.baseAddress else { return true }
                    var offset = 0
                    while offset < rawBuf.count {
                        let n = Darwin.write(cfd, base.advanced(by: offset), rawBuf.count - offset)
                        if n > 0 {
                            offset += n
                        } else if n < 0 && Darwin.errno == EINTR {
                            continue
                        } else {
                            return false
                        }
                    }
                    return true
                }
            }

            while !Task.isCancelled {
                let n = Darwin.read(cfd, &scratch, scratch.count)
                if n <= 0 { break }
                guard let frames = try? acc.ingest(Data(scratch.prefix(n))) else { break }
                for (header, payload) in frames {
                    self?.recordInbound(channel: header.channel)
                    switch header.channel {
                    case .control:
                        self?.recordPing()
                        outSeq &+= 1
                        let pong = VsockControlEnvelope(kind: .pong, agentVersion: versionStr)
                        if let encoded = try? VsockWireJSON.encode(pong),
                           let wire = try? codec.encodeFrame(
                               channel: .control,
                               flags: [.ack, .endOfMessage],
                               streamID: 0,
                               sequence: outSeq,
                               payload: encoded,
                               compressIfBeneficial: false
                           ) {
                            if !writeWire(wire) { return }
                        }
                    case .execProcess:
                        if header.flags.contains(.rst) {
                            execBufs.removeValue(forKey: header.streamID)
                            continue
                        }
                        if !payload.isEmpty {
                            execBufs[header.streamID, default: Data()].append(payload)
                        }
                        if header.flags.contains(.endOfMessage),
                           let rawReq = execBufs.removeValue(forKey: header.streamID),
                           let req = try? VsockWireJSON.decode(GuestExecRequest.self, from: rawReq) {
                            let line = "legacy-\(versionStr): \(req.commandLineSummary)\n"
                            let chunk = GuestExecOutputChunk(
                                requestID: req.id,
                                stream: .stdout,
                                sequence: 1,
                                data: Data(line.utf8)
                            )
                            let done = VsockExecCompletionEnvelope(
                                requestID: req.id,
                                exitCode: 0,
                                durationMilliseconds: 2,
                                timedOut: false
                            )
                            if let chunkBytes = try? VsockWireJSON.encode(chunk),
                               let chunkWire = try? codec.encodeFrame(
                                   channel: .execProcess,
                                   flags: [.ack],
                                   streamID: header.streamID,
                                   sequence: 1,
                                   payload: chunkBytes,
                                   compressIfBeneficial: false
                               ),
                               let doneBytes = try? VsockWireJSON.encode(done),
                               let doneWire = try? codec.encodeFrame(
                                   channel: .execProcess,
                                   flags: [.fin, .endOfMessage],
                                   streamID: header.streamID,
                                   sequence: 2,
                                   payload: doneBytes,
                                   compressIfBeneficial: false
                               ) {
                                _ = writeWire(chunkWire)
                                _ = writeWire(doneWire)
                            }
                        }
                    default:
                        break
                    }
                }
            }
        }
    }

    private func setActiveConn(_ fd: Int32) {
        lock.withLock { activeConnFD = fd }
    }

    private func recordInbound(channel: VsockChannelKind) {
        lock.withLock { recordedChannels.append(channel) }
    }

    private func recordPing() {
        lock.withLock { recordedPings += 1 }
    }

    func closeActiveConnection() {
        let cfd = lock.withLock { () -> Int32 in
            let cur = activeConnFD
            activeConnFD = -1
            return cur
        }
        if cfd >= 0 {
            _ = Darwin.shutdown(cfd, SHUT_RDWR)
            _ = Darwin.close(cfd)
        }
    }

    func shutdown() {
        acceptThreadTask?.cancel()
        closeActiveConnection()
        let lfd = lock.withLock { () -> Int32 in
            let cur = listenFD
            listenFD = -1
            return cur
        }
        if lfd >= 0 {
            _ = Darwin.close(lfd)
        }
        _ = Darwin.unlink(sockPath)
    }
}

private final class Stage5UnixSocketSwitchingHardwareBackend: HardwareVMLowLevelBackend, HardwareVMInstanceHandle, @unchecked Sendable {
    private let lock = NSLock()
    private let socketPaths: [String]
    private var connectIndex = 0
    private var openClientFDs: [Int32] = []

    var connectCount: Int {
        lock.withLock { connectIndex }
    }

    init(socketPathsByConnectOrder: [String]) {
        self.socketPaths = socketPathsByConnectOrder
    }

    func startMachine(
        spec: VMSpec,
        networkSocketFD: Int32?,
        consoleLogURL: URL,
        translator: VZConfigurationTranslator
    ) async throws -> any HardwareVMInstanceHandle {
        _ = try translator.buildVZConfiguration(
            from: spec,
            networkSocketFD: networkSocketFD,
            serialLogFileURL: consoleLogURL,
            validateConfiguration: false
        )
        return self
    }

    func prematureStopReason() -> String? { nil }

    func connectVsock(port: UInt32) async throws -> HardwareVsockFDDescriptor {
        let path: String = lock.withLock {
            let idx = min(connectIndex, max(0, socketPaths.count - 1))
            connectIndex += 1
            return socketPaths[idx]
        }

        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(Darwin.errno))
        }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8CString)
        withUnsafeMutableBytes(of: &addr.sun_path) { rawBuf in
            for (idx, b) in pathBytes.enumerated() {
                rawBuf[idx] = UInt8(bitPattern: b)
            }
        }
        let rc = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.connect(fd, saPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard rc == 0 else {
            let err = Darwin.errno
            _ = Darwin.close(fd)
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(err))
        }
        lock.withLock { openClientFDs.append(fd) }
        return HardwareVsockFDDescriptor(fileDescriptor: fd, closeWhenSessionEnds: true)
    }

    func closeVsockConnection() async {
        lock.withLock { openClientFDs.removeAll() }
    }

    func pause() async throws {}
    func resume() async throws {}
    func saveMachineState(to url: URL) async throws {}
    func shutdown(gracefulTimeoutNanoseconds: UInt64) async {
        await closeVsockConnection()
    }
}

private final class Stage5ExecStreamTracker: @unchecked Sendable {
    private let lock = NSLock()
    private var recordedStreamID: UInt32?
    private var stdoutBuffer = Data()

    var streamID: UInt32? {
        lock.withLock { recordedStreamID }
    }

    func recordStreamID(_ sid: UInt32) {
        lock.withLock { recordedStreamID = sid }
    }

    func appendStdout(_ chunk: Data) {
        lock.withLock { stdoutBuffer.append(chunk) }
    }

    func waitForSubstring(_ needle: String, timeoutSeconds: TimeInterval) async -> Bool {
        let deadline = DispatchTime.now().uptimeNanoseconds &+ UInt64(max(0.05, timeoutSeconds) * 1_000_000_000)
        while DispatchTime.now().uptimeNanoseconds < deadline {
            let hasMatch = lock.withLock {
                String(decoding: stdoutBuffer, as: UTF8.self).contains(needle)
            }
            if hasMatch {
                return true
            }
            try? await Task.sleep(nanoseconds: 15_000_000)
        }
        return lock.withLock {
            String(decoding: stdoutBuffer, as: UTF8.self).contains(needle)
        }
    }
}
