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
        helpProc.waitUntilExit()
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
                proc.waitUntilExit()
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
        proc.waitUntilExit()
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
                proc.waitUntilExit()
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
        proc.waitUntilExit()
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
                proc.waitUntilExit()
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

        proc.waitUntilExit()
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
