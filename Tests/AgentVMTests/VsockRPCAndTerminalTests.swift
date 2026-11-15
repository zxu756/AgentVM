import AgentVMModels
import AgentVMVsockRPC
import Darwin
import Foundation
import Testing

@Suite("M05 AVM1 Vsock Wire Framing, Multiplexed RPC, Port Forwarding & VT100 Terminal", .timeLimit(.minutes(1)))
struct VsockRPCAndTerminalTests {

    // MARK: - Helpers

    private func makeTemporaryDirectory(prefix: String = "avm-vsock") throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    // MARK: - 1. VsockWireCodec 24-Byte AVM1 Framing, CRC32 & Zlib

    @Test("VsockWireCodec encodes 24-byte Big-Endian AVM1 header + payload + 4-byte IEEE CRC32 trailer")
    func vsockWireCodec24ByteAVM1FramingRoundTrip() throws {
        let codec = VsockWireCodec()
        let payload = Data("{\"hello\":\"agentvm-vsock\"}".utf8)

        let wire = try codec.encodeFrame(
            channel: .control,
            flags: [.syn, .endOfMessage],
            streamID: 7,
            sequence: 42,
            windowCredit: 131_072,
            payload: payload,
            compressIfBeneficial: false
        )

        #expect(wire.count == 24 + payload.count + 4)
        // Verify Big-Endian magic "AVM1" (0x41564D31) at bytes [0..3]
        #expect(Array(wire.prefix(4)) == [0x41, 0x56, 0x4D, 0x31])
        #expect(wire[4] == VsockFrameHeader.currentProtocolVersion)
        #expect(wire[5] == VsockChannelKind.control.rawValue)

        let decoded = try #require(try codec.decodeFrame(from: wire))
        #expect(decoded.bytesConsumed == wire.count)
        #expect(decoded.header.magic == VsockFrameHeader.wireMagic)
        #expect(decoded.header.channel == .control)
        #expect(decoded.header.flags == [.syn, .endOfMessage])
        #expect(decoded.header.streamID == 7)
        #expect(decoded.header.sequenceNumber == 42)
        #expect(decoded.header.windowCredit == 131_072)
        #expect(decoded.payload == payload)
    }

    @Test("VsockWireCodec detects single-bit payload corruption via ERR_VSOCK_CRC_MISMATCH and rejects bad magic")
    func vsockWireCodecDetectsCRC32MismatchAndBadMagic() throws {
        let codec = VsockWireCodec()
        let payload = Data("critical-rpc-frame-payload".utf8)
        var wire = try codec.encodeFrame(
            channel: .execProcess,
            flags: [.ack],
            streamID: 3,
            sequence: 1,
            payload: payload
        )

        // Flip 1 bit inside payload byte (offset 25) -> must throw vsockCRCMismatch
        wire[25] ^= 0x01
        do {
            _ = try codec.decodeFrame(from: wire)
            Issue.record("Expected vsockCRCMismatch on corrupted wire payload")
        } catch let err as AgentVMError {
            #expect(err.errorCode == "ERR_VSOCK_CRC")
        }

        // Corrupt 4-byte magic prefix -> must throw vsockProtocolViolation immediately
        var badMagic = wire
        badMagic[0] = 0xDE
        badMagic[1] = 0xAD
        do {
            _ = try codec.decodeFrame(from: badMagic)
            Issue.record("Expected vsockProtocolViolation on invalid AVM1 magic")
        } catch let err as AgentVMError {
            #expect(err.errorCode == "ERR_VSOCK_PROTOCOL")
        }
    }

    @Test("VsockWireCodec compresses repetitive payloads via RFC 1950 zlib and restores exact bytes")
    func vsockWireCodecZlibCompressionRoundTrip() throws {
        let codec = VsockWireCodec()
        let repetitive = Data(String(repeating: "drwxr-xr-x 12 agent staff 4096 Nov 13 /workspace/src\n", count: 80).utf8)

        let compressedWire = try codec.encodeFrame(
            channel: .execProcess,
            flags: [.ack, .endOfMessage],
            streamID: 9,
            sequence: 5,
            payload: repetitive,
            compressIfBeneficial: true
        )
        #expect(compressedWire.count < repetitive.count)

        let decoded = try #require(try codec.decodeFrame(from: compressedWire))
        #expect(decoded.header.flags.contains(.compressed))
        #expect(decoded.payload == repetitive)

        // Direct static length-prefixed zlib helpers including empty payload edge case
        let emptyCompressed = try VsockWireCodec.zlibCompressWithLengthHeader(Data())
        let emptyRestored = try VsockWireCodec.zlibDecompressWithLengthHeader(emptyCompressed, maxOutputBytes: 1024)
        #expect(emptyRestored.isEmpty)

        // Decompression bomb guard when declared uncompressed size > maxOutputBytes
        let mediumCompressed = try VsockWireCodec.zlibCompressWithLengthHeader(Data(repeating: 0x41, count: 4096))
        #expect(throws: AgentVMError.self) {
            _ = try VsockWireCodec.zlibDecompressWithLengthHeader(mediumCompressed, maxOutputBytes: 512)
        }
    }

    @Test("VsockStreamAccumulator reassembles multiple frames fed 1 byte at a time and coalesced back-to-back")
    func vsockStreamAccumulatorByteByByteFragmentedReassembly() throws {
        let codec = VsockWireCodec()
        let accumulator = VsockStreamAccumulator(codec: codec)

        let p1 = Data("frame-one-alpha".utf8)
        let p2 = Data(String(repeating: "compressible-beta-payload-", count: 16).utf8)
        let p3 = Data() // Zero-byte control ping

        let f1 = try codec.encodeFrame(channel: .control, flags: [.syn], streamID: 0, sequence: 1, payload: p1)
        let f2 = try codec.encodeFrame(
            channel: .fileTransfer,
            flags: [.ack],
            streamID: 5,
            sequence: 2,
            payload: p2,
            compressIfBeneficial: true
        )
        let f3 = try codec.encodeFrame(channel: .telemetryHeartbeat, flags: [.fin], streamID: 0, sequence: 3, payload: p3)

        var combined = Data()
        combined.append(f1)
        combined.append(f2)
        combined.append(f3)

        // Feed strictly 1 byte per call across the entire multi-frame stream
        var reassembled: [(header: VsockFrameHeader, payload: Data)] = []
        for singleByte in combined {
            let drained = try accumulator.ingest(Data([singleByte]))
            reassembled.append(contentsOf: drained)
        }

        #expect(reassembled.count == 3)
        #expect(accumulator.bufferedByteCount == 0)
        #expect(accumulator.totalFramesDecoded == 3)
        #expect(accumulator.totalBytesIngested == UInt64(combined.count))
        #expect(reassembled[0].payload == p1)
        #expect(reassembled[1].payload == p2)
        #expect(reassembled[2].payload == p3)

        // Also verify coalesced single-shot ingestion after reset()
        accumulator.reset()
        #expect(accumulator.totalFramesDecoded == 0)
        let coalesced = try accumulator.ingest(combined)
        #expect(coalesced.count == 3)
        #expect(coalesced[1].header.streamID == 5)
    }

    // MARK: - 2. VsockMultiplexSession Loopback Exec, Multi-Chunk SHA-256 File Transfer & Heartbeat

    @Test("VsockMultiplexSession simulated loopback pair executes commands with exit codes, env vars, and streaming chunks")
    func vsockLoopbackSessionExecuteCommandAndStreaming() async throws {
        let vmID = VMID("vm-vsock-exec")
        let (host, guest) = await VsockMultiplexSession.createLoopbackPair(vmID: vmID)

        let unameRes = try await host.executeCommand(
            GuestExecRequest(executable: "/usr/bin/uname", arguments: ["-a"], workingDirectory: "/workspace")
        )
        #expect(unameRes.exitCode == 0)
        #expect(unameRes.stdoutUTF8.contains("Linux"))
        #expect(unameRes.stdoutUTF8.contains("aarch64"))

        // Streaming chunk callback + environment expansion via sh -c
        actor ChunkCollector {
            var chunks: [GuestExecOutputChunk] = []
            func append(_ c: GuestExecOutputChunk) { chunks.append(c) }
            func all() -> [GuestExecOutputChunk] { chunks }
        }
        let collector = ChunkCollector()
        let envRes = try await host.executeCommandStreaming(
            GuestExecRequest(
                executable: "/bin/sh",
                arguments: ["-c", "echo token=${AGENT_TOKEN}"],
                environment: ["AGENT_TOKEN": "avm-ok-42"]
            )
        ) { chunk in
            await collector.append(chunk)
        }
        #expect(envRes.exitCode == 0)
        #expect(envRes.stdoutUTF8.trimmingCharacters(in: .whitespacesAndNewlines) == "token=avm-ok-42")
        #expect(!(await collector.all()).isEmpty)

        // Non-zero exit codes (false -> 1, nonexistent binary -> 127)
        let falseRes = try await host.executeCommand(GuestExecRequest(executable: "/bin/false"))
        #expect(falseRes.exitCode == 1)

        let missingRes = try await host.executeCommand(GuestExecRequest(executable: "/usr/bin/nonexistent-tool"))
        #expect(missingRes.exitCode == 127)
        #expect(missingRes.stderrUTF8.contains("not found"))

        await host.shutdown()
        await guest.shutdown()
    }

    @Test("VsockMultiplexSession simulated loopback enforces command watchdog timeout returning exitCode 124 and timedOut == true")
    func vsockLoopbackSessionCommandWatchdogTimeout() async throws {
        let (host, guest) = await VsockMultiplexSession.createLoopbackPair(vmID: VMID("vm-timeout"))

        let slowReq = GuestExecRequest(
            executable: "/bin/sleep",
            arguments: ["2.0"],
            timeoutSeconds: 0.08
        )
        let res = try await host.executeCommand(slowReq)
        #expect(res.timedOut == true)
        #expect(res.exitCode == 124)

        await host.shutdown()
        await guest.shutdown()
    }

    @Test("VsockMultiplexSession simulated loopback streams multi-chunk 384 KiB pushFile and pullFile exercising window-credit replenishment and SHA-256")
    func vsockMultiChunkFileTransferWindowCreditsAndSHA256RoundTrip() async throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-vsock-xfer")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let (host, guest) = await VsockMultiplexSession.createLoopbackPair(vmID: VMID("vm-xfer"))

        // 384 KiB payload exceeds the 256 KiB (262,144 B) default stream window credit AND splits across twelve 32 KiB frames!
        let payloadByteCount = 384 * 1024
        var pseudoRandom = [UInt8](repeating: 0, count: payloadByteCount)
        var s: UInt64 = 0xCAFE_BABE_1234_5678
        for idx in 0..<payloadByteCount {
            s ^= s << 13
            s ^= s >> 7
            s ^= s << 17
            pseudoRandom[idx] = UInt8(truncatingIfNeeded: s)
        }
        let originalData = Data(pseudoRandom)
        let expectedSHA256 = BinaryChecksums.sha256Hex(originalData)

        let sourceURL = tempDir.appendingPathComponent("artifact-upload.bin")
        let pulledURL = tempDir.appendingPathComponent("artifact-downloaded.bin")
        try originalData.write(to: sourceURL)

        let pushManifest = try await host.pushFile(
            localURL: sourceURL,
            guestDestinationPath: "/workspace/artifact-upload.bin",
            permissions: 0o755
        )
        #expect(pushManifest.totalBytes == UInt64(payloadByteCount))
        #expect(pushManifest.sha256Hex == expectedSHA256)
        #expect(pushManifest.posixPermissions == 0o755)

        let pullManifest = try await host.pullFile(
            guestSourcePath: "/workspace/artifact-upload.bin",
            localDestinationURL: pulledURL
        )
        #expect(pullManifest.totalBytes == UInt64(payloadByteCount))
        #expect(pullManifest.sha256Hex == expectedSHA256)

        let downloadedData = try Data(contentsOf: pulledURL)
        #expect(downloadedData == originalData)
        #expect(BinaryChecksums.sha256Hex(downloadedData) == expectedSHA256)

        let telemetry = await host.sessionTelemetry()
        #expect(telemetry.windowUpdatesReceived >= 1)
        #expect(telemetry.windowUpdatesSent >= 1)
        #expect(telemetry.framesSent >= 12)

        await host.shutdown()
        await guest.shutdown()
    }

    @Test("VsockMultiplexSession simulated loopback exchanges telemetry heartbeats and interactive PTY stream frames")
    func vsockHeartbeatAndInteractivePTYStreaming() async throws {
        let vmID = VMID("vm-pty-hb")
        let (host, guest) = await VsockMultiplexSession.createLoopbackPair(vmID: vmID)

        let heartbeat = try await host.requestHeartbeat()
        #expect(heartbeat.hostname == vmID.rawValue)
        #expect(heartbeat.kernelRelease.contains("6.8.0"))
        #expect(heartbeat.memTotalBytes > 0)
        #expect(!heartbeat.topProcesses.isEmpty)
        #expect(await host.latestHeartbeat()?.hostname == vmID.rawValue)

        let tty = VT100ScreenBuffer(columns: 80, rows: 24)
        await host.attachTerminalScreenBuffer(tty)
        try await host.resizePTY(columns: 100, rows: 30)
        #expect(tty.columns == 100)
        #expect(tty.rows == 30)

        try await host.sendPTYInput(Data("whoami\r".utf8))
        // Allow async loopback stream delivery to settle into VT100ScreenBuffer
        for _ in 0..<20 {
            if tty.renderPlainText().contains("whoami: executed") { break }
            try await Task.sleep(nanoseconds: 15_000_000)
        }
        #expect(tty.renderPlainText().contains("whoami: executed"))

        await host.shutdown()
        await guest.shutdown()
    }

    @Test("VsockMultiplexSession operates over real POSIX AF_UNIX SOCK_STREAM file descriptors")
    func vsockPOSIXSocketPairLiveTransportRoundTrip() async throws {
        var fds: [Int32] = [-1, -1]
        #expect(Darwin.socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)

        let vmID = VMID("vm-posix-vsock")
        let host = VsockMultiplexSession(vmID: vmID)
        let codec = VsockWireCodec()
        defer {
            _ = Darwin.close(fds[1])
        }

        try await host.attachPOSIXFileDescriptor(fds[0], closeWhenDone: true)

        // Feed a real AVM1 guest heartbeat frame from peer socket fd[1] into host fd[0]
        let hb = GuestHeartbeatPayload(
            hostname: "posix-guest",
            kernelRelease: "6.8.0-virt",
            uptimeSeconds: 99.0,
            loadAvg1: 0.1,
            loadAvg5: 0.1,
            loadAvg15: 0.1,
            memTotalBytes: 1_073_741_824,
            memAvailableBytes: 536_870_912,
            rootFilesystemUsedBytes: 1_000_000,
            rootFilesystemTotalBytes: 10_000_000
        )
        let hbWire = try codec.encodeFrame(
            channel: .telemetryHeartbeat,
            flags: [.ack, .endOfMessage],
            streamID: 0,
            sequence: 1,
            payload: try VsockWireJSON.encode(hb),
            compressIfBeneficial: true
        )
        let written = hbWire.withUnsafeBytes { ptr -> Int in
            guard let base = ptr.baseAddress else { return -1 }
            return Darwin.write(fds[1], base, ptr.count)
        }
        #expect(written == hbWire.count)

        for _ in 0..<30 {
            if await host.latestHeartbeat()?.hostname == "posix-guest" { break }
            try await Task.sleep(nanoseconds: 15_000_000)
        }
        #expect(await host.latestHeartbeat()?.hostname == "posix-guest")

        await host.shutdown()
    }

    // MARK: - 3. HostPortForwardManager Ephemeral 127.0.0.1:0 Bind & Live TCP Payload Relay

    @Test("HostPortForwardManager simulated guest responder binds ephemeral 127.0.0.1:0 listener and relays TCP HTTP over Vsock")
    func hostPortForwardEphemeralBindAndLiveTCPRelay() async throws {
        let vmID = VMID("vm-portfwd")
        let vsock = VsockMultiplexSession(vmID: vmID)
        await vsock.attachSimulatedGuestResponder()
        let manager = HostPortForwardManager()

        let rule = PortForwardRuleSpec(
            id: PortForwardID("fwd-ephemeral"),
            label: "ephemeral-http",
            protocolType: .vsockStream,
            hostBindAddress: "127.0.0.1",
            hostPort: 0,
            guestPort: 8080
        )
        let binding = try await manager.startForwardRule(rule, vmID: vmID, vsockSession: vsock)
        #expect(binding.actualBoundPort > 0)
        #expect((await manager.listActiveBindings(for: vmID)).count == 1)

        // Open a real BSD IPv4 TCP client socket to 127.0.0.1:<actualBoundPort>
        let clientFD = Darwin.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        #expect(clientFD >= 0)
        defer { _ = Darwin.close(clientFD) }

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = binding.actualBoundPort.bigEndian
        _ = "127.0.0.1".withCString { Darwin.inet_pton(AF_INET, $0, &addr.sin_addr) }

        let connectRC = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.connect(clientFD, saPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        #expect(connectRC == 0)

        let httpReq = Data("GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".utf8)
        let sent = httpReq.withUnsafeBytes { ptr -> Int in
            guard let base = ptr.baseAddress else { return -1 }
            return Darwin.send(clientFD, base, ptr.count, 0)
        }
        #expect(sent == httpReq.count)

        var pfd = Darwin.pollfd(fd: clientFD, events: Int16(POLLIN), revents: 0)
        let ready = Darwin.poll(&pfd, 1, 2000)
        #expect(ready == 1)

        var replyBuf = [UInt8](repeating: 0, count: 1024)
        let n = replyBuf.withUnsafeMutableBytes { ptr -> Int in
            guard let base = ptr.baseAddress else { return -1 }
            return Darwin.recv(clientFD, base, ptr.count, 0)
        }
        #expect(n > 0)
        let replyText = String(decoding: replyBuf[0..<max(0, n)], as: UTF8.self)
        #expect(replyText.contains("HTTP/1.1 200 OK"))
        #expect(replyText.contains("agentvm-guest-vsock"))

        await manager.stopForwardRule(rule.id)
        #expect((await manager.listActiveBindings(for: vmID)).isEmpty)
        await manager.stopAllRules()
        await vsock.shutdown()
    }

    @Test("HostPortForwardManager simulated guest responder rejects duplicate non-ephemeral port collisions with ERR_PORT_FORWARD_BIND")
    func hostPortForwardDetectsDuplicatePortBindCollision() async throws {
        let vmID = VMID("vm-port-collide")
        let vsock = VsockMultiplexSession(vmID: vmID)
        await vsock.attachSimulatedGuestResponder()
        let manager = HostPortForwardManager()

        let first = try await manager.startForwardRule(
            PortForwardRuleSpec(id: PortForwardID("fwd-1"), label: "first", hostPort: 0, guestPort: 8000),
            vmID: vmID,
            vsockSession: vsock
        )

        do {
            _ = try await manager.startForwardRule(
                PortForwardRuleSpec(id: PortForwardID("fwd-2"), label: "duplicate", hostPort: first.actualBoundPort, guestPort: 8001),
                vmID: vmID,
                vsockSession: vsock
            )
            Issue.record("Expected portForwardBindFailed when binding an already-bound TCP port")
        } catch let err as AgentVMError {
            #expect(err.errorCode == "ERR_PORT_FORWARD_BIND")
        }

        await manager.stopAllRules()
        await vsock.shutdown()
    }

    // MARK: - 4. VT100ScreenBuffer State Machine, SGR, Wrap, Scrollback & Alternate Screen

    @Test("VT100ScreenBuffer executes CUP/CUU/CUD/CHA cursor addressing and ED/EL selective screen erasure")
    func vt100CursorAddressingAndScreenErase() {
        let tty = VT100ScreenBuffer(columns: 20, rows: 6)
        tty.feed("Hello World")
        #expect(tty.cursorRow == 0)
        #expect(tty.cursorColumn == 11)

        // Move to 1-based row 3, col 5 (`ESC[3;5H`) and print " blade" -> row 2, col 4..9
        tty.feed("\u{1B}[3;5Hblade")
        #expect(tty.cursorRow == 2)
        #expect(tty.cursorColumn == 9)

        // CHA (`ESC[1G`) moves to col 0 on current row and overwrites "VM:"
        tty.feed("\u{1B}[1GVM:")
        let lines = tty.renderPlainTextLines()
        #expect(lines[0] == "Hello World")
        #expect(lines[2] == "VM: blade")

        // Erase to end of line (`ESC[0K`) at row 0 col 5 leaves only "Hello"
        tty.feed("\u{1B}[1;6H\u{1B}[0K")
        #expect(tty.renderPlainTextLines()[0] == "Hello")
    }

    @Test("VT100ScreenBuffer tracks SGR 16-color, 256-color, 24-bit TrueColor, bold, underline, and inverse attributes")
    func vt100SGRColorAndAttributeRendition() {
        let tty = VT100ScreenBuffer(columns: 16, rows: 4)
        // Bold + Underline + Red FG (31) + Blue BG (44) on 'A', 256-color FG 208 on 'B', TrueColor RGB(0,255,0) on 'C', Reset on 'D'
        tty.feed("\u{1B}[1;4;31;44mA\u{1B}[38;5;208mB\u{1B}[38;2;0;255;0;7mC\u{1B}[0mD")

        let grid = tty.snapshotVisibleGrid()
        let cellA = grid[0][0]
        #expect(cellA.scalar == "A")
        #expect(cellA.isBold == true)
        #expect(cellA.isUnderline == true)
        #expect(cellA.fgANSI == 1)
        #expect(cellA.bgANSI == 4)

        let cellB = grid[0][1]
        #expect(cellB.scalar == "B")
        #expect(cellB.fgANSI == 208)

        let cellC = grid[0][2]
        #expect(cellC.scalar == "C")
        #expect(cellC.isInverse == true)
        #expect(cellC.fgANSI != TerminalCell.defaultForegroundANSI)

        let cellD = grid[0][3]
        #expect(cellD.scalar == "D")
        #expect(cellD.isBold == false)
        #expect(cellD.isUnderline == false)
        #expect(cellD.isInverse == false)
        #expect(cellD.fgANSI == TerminalCell.defaultForegroundANSI)
    }

    @Test("VT100ScreenBuffer implements DECAWM delayed right-margin line wrap and O(1) scrollback ring eviction")
    func vt100DelayedLineWrapAndScrollbackRingBufferEviction() {
        let tty = VT100ScreenBuffer(columns: 8, rows: 3, maxScrollbackLines: 4)

        // Writing exactly 8 chars fills row 0 with pending wrap (still on row 0 until 9th char arrives!)
        tty.feed("12345678")
        #expect(tty.cursorRow == 0)
        tty.feed("9")
        #expect(tty.cursorRow == 1)
        #expect(tty.cursorColumn == 1)
        #expect(tty.renderPlainTextLines()[0] == "12345678")
        #expect(tty.renderPlainTextLines()[1] == "9")

        // Reset and push 9 numbered lines through a 3-row screen with maxScrollbackLines == 4
        tty.reset()
        for i in 1...9 {
            tty.feed("Line-0\(i)" + (i < 9 ? "\r\n" : ""))
        }
        // Visible rows should be Line-07, Line-08, Line-09; scrollback retains 4 lines: Line-03..Line-06 (evicting 01 & 02)
        #expect(tty.scrollbackCount == 4)
        let fullHistory = tty.renderPlainTextLines(includeScrollback: true)
        #expect(fullHistory == ["Line-03", "Line-04", "Line-05", "Line-06", "Line-07", "Line-08", "Line-09"])
    }

    @Test("VT100ScreenBuffer switches cleanly into and out of ?1049h alternate screen preserving primary grid and cursor")
    func vt100AlternateScreenBufferSaveAndRestore() {
        let tty = VT100ScreenBuffer(columns: 24, rows: 5)
        tty.feed("shell$ ls -la\r\ntotal 42")
        let savedRow = tty.cursorRow
        let savedCol = tty.cursorColumn
        #expect(tty.isAlternateScreen == false)

        // Enter full-screen TUI alternate screen (`ESC[?1049h`)
        tty.feed("\u{1B}[?1049h")
        #expect(tty.isAlternateScreen == true)
        #expect(tty.renderPlainText().isEmpty)

        tty.feed("\u{1B}[1;1H--- HTOP ALTERNATE VIEW ---")
        #expect(tty.renderPlainText().contains("HTOP ALTERNATE VIEW"))
        #expect(tty.scrollbackCount == 0)

        // Exit alternate screen (`ESC[?1049l`) -> primary buffer and cursor coordinates restored intact
        tty.feed("\u{1B}[?1049l")
        #expect(tty.isAlternateScreen == false)
        #expect(tty.cursorRow == savedRow)
        #expect(tty.cursorColumn == savedCol)
        #expect(tty.renderPlainText() == "shell$ ls -la\ntotal 42")
    }

    @Test("VT100ScreenBuffer reassembles split multi-byte UTF-8 sequences across chunks and parses OSC window titles & BEL")
    func vt100SplitUTF8ReassemblyAndOSCTitleAndBell() {
        let tty = VT100ScreenBuffer(columns: 40, rows: 4)

        // OSC 0 window title terminated by BEL (0x07), plus standalone BEL
        tty.feed("\u{1B}]0;claude-worker@ubuntu:/workspace\u{07}\u{07}")
        #expect(tty.windowTitle == "claude-worker@ubuntu:/workspace")
        #expect(tty.bellCount == 1) // OSC terminator BEL is consumed by OSC; second BEL increments bellCount!

        // Feed multi-byte UTF-8 ("λ🚀Ω") 1 byte at a time across arbitrary packet boundaries
        let utf8Bytes = Array("λ🚀Ω".utf8)
        for byte in utf8Bytes {
            tty.feed(Data([byte]))
        }
        #expect(tty.renderPlainTextLines()[0].contains("λ"))
        #expect(tty.renderPlainTextLines()[0].contains("Ω"))
    }

    // MARK: - 5. GuestAgentBootstrapGenerator Python Daemon & Systemd Service

    @Test("GuestAgentBootstrapGenerator emits Python 3 AVM1 vsock daemon, systemd service unit, and kernel module config")
    func guestAgentBootstrapPythonDaemonAndSystemdTemplates() {
        let generator = GuestAgentBootstrapGenerator(
            vsockPort: 2049,
            heartbeatIntervalSeconds: 3,
            defaultWorkspacePath: "/workspace"
        )

        let py = generator.pythonDaemonScript()
        #expect(py.hasPrefix("#!/usr/bin/env python3"))
        #expect(py.contains("AVM1_MAGIC = 0x41564D31"))
        #expect(py.contains("AF_VSOCK"))
        #expect(py.contains("zlib.crc32"))

        let unit = generator.systemdServiceUnit()
        #expect(unit.contains("[Unit]"))
        #expect(unit.contains("--port 2049"))
        #expect(unit.contains("--heartbeat-interval 3"))
        #expect(unit.contains("WantedBy=multi-user.target"))

        let modules = generator.kernelModulesConfig()
        #expect(modules.contains("vmw_vsock_virtio_transport"))
    }

    @Test("GuestAgentBootstrapGenerator.applying(to:) injects files and runcmd idempotently without duplicates")
    func guestAgentBootstrapCloudInitIdempotentApplication() {
        let generator = GuestAgentBootstrapGenerator()
        let baseSpec = CloudInitSpec(
            hostname: "vsock-node",
            aptPackages: ["git"],
            injectGuestVsockAgent: true
        )

        let once = generator.applying(to: baseSpec)
        let twice = generator.applying(to: once)

        #expect(once.writeFiles.count == 3)
        #expect(twice.writeFiles.count == 3)
        #expect(once.runCommands == twice.runCommands)
        #expect(once.runCommands.contains { $0.contains("serial-getty@hvc0.service") })
        #expect(!once.aptPackages.contains("python3"))
        #expect(!twice.aptPackages.contains("python3"))

        // When injectGuestVsockAgent == false, applying(to:) leaves CloudInitSpec untouched
        let optOut = CloudInitSpec(hostname: "minimal", aptPackages: ["curl"], injectGuestVsockAgent: false)
        let untouched = generator.applying(to: optOut)
        #expect(untouched.writeFiles.isEmpty)
        #expect(untouched.runCommands.isEmpty)
    }

    @Test("Generated Python guest daemon converts signal-killed child exit codes (-N) to 128 + N")
    func guestDaemonScriptConvertsSignalExitCodeTo128PlusSignalNumber() async throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-py-daemon")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let daemonModuleURL = tempDir.appendingPathComponent("agentvm_guestd.py")
        try GuestAgentBootstrapGenerator().pythonDaemonScript().write(
            to: daemonModuleURL,
            atomically: true,
            encoding: .utf8
        )

        let sockPath = "/tmp/avm-py-\(UUID().uuidString.prefix(8)).sock"
        _ = Darwin.unlink(sockPath)
        defer { _ = Darwin.unlink(sockPath) }

        let serverFD = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        #expect(serverFD >= 0)
        defer {
            if serverFD >= 0 {
                _ = Darwin.close(serverFD)
            }
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathUTF8 = Array(sockPath.utf8CString)
        #expect(pathUTF8.count <= MemoryLayout.size(ofValue: addr.sun_path))
        withUnsafeMutableBytes(of: &addr.sun_path) { rawBuf in
            for (idx, ch) in pathUTF8.enumerated() {
                rawBuf[idx] = UInt8(bitPattern: ch)
            }
        }
        let bindRes = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.bind(serverFD, saPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        #expect(bindRes == 0)
        #expect(Darwin.listen(serverFD, 2) == 0)

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

        let session = VsockMultiplexSession(vmID: VMID("py-daemon-signal-test"))
        try await session.attachPOSIXFileDescriptor(clientFD, closeWhenDone: true)
        defer {
            Task { await session.shutdown() }
        }

        let normalRes = try await session.executeCommand(GuestExecRequest(
            executable: "/bin/sh",
            arguments: ["-c", "exit 7"],
            workingDirectory: tempDir.path,
            runAsUser: "root"
        ))
        #expect(normalRes.exitCode == 7)

        let sigkillRes = try await session.executeCommand(GuestExecRequest(
            executable: "/bin/sh",
            arguments: ["-c", "kill -9 $$"],
            workingDirectory: tempDir.path,
            runAsUser: "root"
        ))
        #expect(sigkillRes.exitCode == 137)

        let sigtermRes = try await session.executeCommand(GuestExecRequest(
            executable: "/bin/sh",
            arguments: ["-c", "kill -15 $$"],
            workingDirectory: tempDir.path,
            runAsUser: "root"
        ))
        #expect(sigtermRes.exitCode == 143)

        let ptySigkillRes = try await session.executeCommand(GuestExecRequest(
            executable: "/bin/sh",
            arguments: ["-c", "kill -9 $$"],
            workingDirectory: tempDir.path,
            allocatePTY: true,
            runAsUser: "root"
        ))
        #expect(ptySigkillRes.exitCode == 137)

        await session.shutdown()
        proc.waitUntilExit()
    }

    @Test("Generated Python guest daemon streams stdout chunks live before long-running child exits")
    func guestDaemonScriptStreamsStdoutLiveBeforeSleepCompletes() async throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-py-stream")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let daemonModuleURL = tempDir.appendingPathComponent("agentvm_guestd.py")
        try GuestAgentBootstrapGenerator().pythonDaemonScript().write(
            to: daemonModuleURL,
            atomically: true,
            encoding: .utf8
        )

        var fds: [Int32] = [-1, -1]
        #expect(Darwin.socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        let guestHandle = FileHandle(fileDescriptor: fds[1], closeOnDealloc: false)
        proc.standardInput = guestHandle
        proc.arguments = [
            "-u",
            "-c",
            """
            import os, socket, sys
            sys.path.insert(0, sys.argv[1])
            import agentvm_guestd
            sock = socket.fromfd(0, socket.AF_UNIX, socket.SOCK_STREAM)
            session = agentvm_guestd.GuestVsockConnectionSession(
                conn=sock,
                heartbeat_interval=60,
                default_workspace=sys.argv[1],
            )
            session.run()
            """,
            tempDir.path
        ]
        try proc.run()
        _ = Darwin.close(fds[1])
        defer {
            if proc.isRunning {
                proc.terminate()
                proc.waitUntilExit()
            }
        }

        let session = VsockMultiplexSession(vmID: VMID("py-daemon-stream-test"))
        try await session.attachPOSIXFileDescriptor(fds[0], closeWhenDone: true)
        defer {
            Task { await session.shutdown() }
        }

        final class ChunkTimingRecorder: @unchecked Sendable {
            private let lock = NSLock()
            var firstStdoutElapsedMs: Double?
            var streamedStdout = Data()

            func record(data: Data, elapsedMs: Double) {
                lock.withLock {
                    streamedStdout.append(data)
                    if firstStdoutElapsedMs == nil,
                       String(decoding: streamedStdout, as: UTF8.self).contains("started") {
                        firstStdoutElapsedMs = elapsedMs
                    }
                }
            }
        }

        let startNs = DispatchTime.now().uptimeNanoseconds
        let recorder = ChunkTimingRecorder()

        let result = try await session.executeCommandStreaming(
            GuestExecRequest(
                executable: "/bin/sh",
                arguments: ["-c", "echo started; sleep 3"],
                workingDirectory: tempDir.path,
                runAsUser: "root"
            ),
            onChunk: { chunk in
                guard chunk.stream == .stdout else { return }
                let nowNs = DispatchTime.now().uptimeNanoseconds
                recorder.record(data: chunk.data, elapsedMs: Double(nowNs - startNs) / 1_000_000.0)
            }
        )

        #expect(result.exitCode == 0)
        #expect(result.stdoutData == Data("started\n".utf8))
        let firstMs = try #require(recorder.firstStdoutElapsedMs)
        // Must arrive well before the 3000 ms sleep finishes!
        #expect(firstMs < 1_500.0, "Expected 'started' chunk before sleep 3 ended, but arrived at \(firstMs) ms")

        await session.shutdown()
        proc.waitUntilExit()
    }
}
