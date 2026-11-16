import AgentVMCLIAndMCP
import AgentVMModels
import Darwin
import Foundation
import Testing

@Suite("M2 Stage 1: Daemon JSON-RPC 2.0 Codec, Line Framing, Socket Address & Singleton Lock", .timeLimit(.minutes(1)))
struct CLIAndMCPDaemonRPCTests {

    // MARK: - Item 1: DaemonRPC Codable JSON-RPC 2.0 Protocol & Version Handshake

    @Test("Item 1: DaemonRPCMethod set, hello handshake compatibility, localized errors independent of shared localizer, exec.output base64, and exec final response")
    func daemonRPCProtocolCodecAndHandshakeVersionCheck() async throws {
        // 1. Method set matches 01-agentvm.md item 2 exactly.
        #expect(
            DaemonRPCMethod.allCases.map(\.rawValue) == [
                "status", "stop", "list", "up", "halt", "pause", "resume", "exec"
            ]
        )

        // 2. Hello handshake wire format & compatibility comparison.
        let clientHello = DaemonRPCHello(
            protocolVersion: DaemonRPCHello.currentProtocolVersion,
            semanticVersion: SemanticVersion(major: 1, minor: 3, patch: 0),
            executablePath: "/opt/agentvm/bin/AgentVM"
        )
        let helloLine = try DaemonRPCCodec.encodeHelloLine(clientHello)
        #expect(!helloLine.contains(0x0A))
        let helloJSON = try #require(
            try JSONSerialization.jsonObject(with: helloLine) as? [String: Any]
        )
        #expect(helloJSON["jsonrpc"] as? String == "2.0")
        #expect(helloJSON["method"] as? String == "hello")
        let decodedHello = try DaemonRPCCodec.decodeHelloLine(helloLine)
        #expect(decodedHello == clientHello)

        // Compatible even if test runner and signed binary paths differ, as long as versions match.
        let compatibleDaemonHello = DaemonRPCHello(
            protocolVersion: DaemonRPCHello.currentProtocolVersion,
            semanticVersion: SemanticVersion(major: 1, minor: 3, patch: 0),
            executablePath: "/Applications/AgentVM.app/Contents/MacOS/AgentVM"
        )
        try clientHello.verifyCompatibility(withDaemon: compatibleDaemonHello, language: .en)

        // SemanticVersion mismatch -> instructs user to run `agentvm daemon stop` in both en and zh.
        let olderDaemonHello = DaemonRPCHello(
            protocolVersion: DaemonRPCHello.currentProtocolVersion,
            semanticVersion: SemanticVersion(major: 1, minor: 2, patch: 0),
            executablePath: "/usr/local/bin/agentvm-old"
        )
        do {
            try clientHello.verifyCompatibility(withDaemon: olderDaemonHello, language: .en)
            Issue.record("Expected version mismatch error for 1.3.0 client vs 1.2.0 daemon")
        } catch let err as DaemonRPCProtocolError {
            #expect(err.errorCode == "ERR_DAEMON_VERSION_MISMATCH")
            let msg = err.localizedMessage(in: .en)
            #expect(msg.contains("agentvm daemon stop"))
            #expect(msg.contains("1.3.0"))
            #expect(msg.contains("1.2.0"))
            #expect(msg.contains("/usr/local/bin/agentvm-old"))
        }

        // ProtocolVersion mismatch -> localized in Chinese when requested.
        let newerProtoDaemonHello = DaemonRPCHello(
            protocolVersion: DaemonRPCHello.currentProtocolVersion + 1,
            semanticVersion: SemanticVersion(major: 1, minor: 3, patch: 0),
            executablePath: "/usr/local/bin/agentvm-next"
        )
        do {
            try clientHello.verifyCompatibility(withDaemon: newerProtoDaemonHello, language: .zhHans)
            Issue.record("Expected protocol mismatch error")
        } catch let err as DaemonRPCProtocolError {
            #expect(err.errorCode == "ERR_DAEMON_VERSION_MISMATCH")
            let zhMsg = err.localizedMessage(in: .zhHans)
            #expect(zhMsg.contains("agentvm daemon stop"))
            #expect(zhMsg.contains("/usr/local/bin/agentvm-next"))
        }

        // 3. Requests for all 8 methods round-trip without JSONSerialization / [String: Any] in codec.
        let calls: [(DaemonRPCID, DaemonRPCCall)] = [
            (.int(1), .status(DaemonRPCStatusParams(lang: .en))),
            (.int(2), .stop(DaemonRPCStopParams(lang: .zhHans))),
            (.int(3), .list(DaemonRPCListParams(lang: .en))),
            (.int(4), .up(DaemonRPCVMLifecycleParams(vm: "t1", lang: .en))),
            (.int(5), .halt(DaemonRPCVMLifecycleParams(vm: "t1", lang: .zhHans))),
            (.int(6), .pause(DaemonRPCVMLifecycleParams(vm: "t1", lang: .en))),
            (.int(7), .resume(DaemonRPCVMLifecycleParams(vm: "t1", lang: .zhHans))),
            (.string("req-exec-8"), .exec(DaemonRPCExecParams(
                vm: "t1",
                executable: "/bin/sh",
                arguments: ["-c", "echo hi"],
                workingDirectory: "/",
                runAsUser: "root",
                environment: ["FOO": "BAR"],
                timeoutSeconds: 3600,
                lang: .zhHans
            )))
        ]
        for (id, call) in calls {
            let env = DaemonRPCRequestEnvelope(id: id, call: call)
            let line = try DaemonRPCCodec.encodeRequestLine(env)
            #expect(!line.contains(0x0A))
            let decoded = try DaemonRPCCodec.decodeRequestLine(line)
            #expect(decoded == env)
            #expect(decoded.method == call.method)
            #expect(decoded.language == call.language)
        }

        // Unknown method produces JSON-RPC -32601 preserving request id.
        let badMethodLine = Data(#"{"jsonrpc":"2.0","id":77,"method":"reboot_host","params":{}}"#.utf8)
        do {
            _ = try DaemonRPCCodec.decodeRequestLine(badMethodLine)
            Issue.record("Expected unknown method error")
        } catch let reqErr as DaemonRPCRequestDecodeError {
            #expect(reqErr.requestID == .int(77))
            #expect(reqErr.rpcError.code == DaemonRPCError.methodNotFoundCode)
        }

        // 4. exec.output notification encodes stream + base64 data, preserves all 256 byte values,
        // and interleaves cleanly before final exec response (exitCode, timedOut).
        let binaryChunk = Data((0...255).map(UInt8.init))
        let notifLine = try DaemonRPCCodec.encodeExecOutputLine(
            DaemonRPCExecOutputParams(stream: .stdout, data: binaryChunk)
        )
        #expect(!notifLine.contains(0x0A))
        let rawNotifObj = try #require(
            try JSONSerialization.jsonObject(with: notifLine) as? [String: Any]
        )
        #expect(rawNotifObj["jsonrpc"] as? String == "2.0")
        #expect(rawNotifObj["method"] as? String == "exec.output")
        #expect(rawNotifObj["id"] == nil)
        let notifParams = try #require(rawNotifObj["params"] as? [String: Any])
        #expect(notifParams["stream"] as? String == "stdout")
        #expect(notifParams["data"] as? String == binaryChunk.base64EncodedString())

        let frame1 = try DaemonRPCCodec.decodeServerFrame(DaemonRPCExecResult.self, from: notifLine)
        switch frame1 {
        case let .execOutput(out):
            #expect(out.stream == .stdout)
            #expect(out.data == binaryChunk)
        case .response:
            Issue.record("Expected execOutput notification frame")
        }

        // Invalid base64 in exec.output is rejected.
        let invalidB64Line = Data(#"{"jsonrpc":"2.0","method":"exec.output","params":{"stream":"stderr","data":"***not-base64***"}}"#.utf8)
        #expect(throws: Error.self) {
            _ = try DaemonRPCCodec.decodeServerFrame(DaemonRPCExecResult.self, from: invalidB64Line)
        }

        // Final exec response carries exitCode and timedOut.
        let execResp = DaemonRPCResponse<DaemonRPCExecResult>.success(
            id: .string("req-exec-8"),
            result: DaemonRPCExecResult(exitCode: 124, timedOut: true)
        )
        let execRespLine = try DaemonRPCCodec.encodeResponseLine(execResp)
        let frame2 = try DaemonRPCCodec.decodeServerFrame(DaemonRPCExecResult.self, from: execRespLine)
        switch frame2 {
        case .execOutput:
            Issue.record("Expected final response frame")
        case let .response(decodedResp):
            #expect(decodedResp.id == .string("req-exec-8"))
            #expect(try decodedResp.resultOrThrow() == DaemonRPCExecResult(exitCode: 124, timedOut: true))
        }

        // 5. Error response carries AgentVMError.errorCode and localizes strictly per request `lang`,
        // never reading AgentVMLocalizer.shared.
        let previousSharedLang = await MainActor.run { AgentVMLocalizer.shared.language }
        defer {
            Task { @MainActor in
                AgentVMLocalizer.shared.setLanguage(previousSharedLang, persist: false)
            }
        }

        await MainActor.run {
            AgentVMLocalizer.shared.setLanguage(.en, persist: false)
        }
        let domainError = AgentVMError.vmBusy(vmName: "blade-1", holderPID: 4321)
        let zhErrorResp = DaemonRPCResponse<DaemonRPCExecResult>.failure(
            id: .int(9),
            agentVMError: domainError,
            language: .zhHans
        )
        let zhErrorLine = try DaemonRPCCodec.encodeResponseLine(zhErrorResp)
        let decodedZhErr = try DaemonRPCCodec.decodeResponseLine(DaemonRPCExecResult.self, from: zhErrorLine)
        guard case let .failure(zhErrPayload) = decodedZhErr.outcome else {
            Issue.record("Expected failure outcome")
            return
        }
        #expect(zhErrPayload.errorCode == "ERR_VM_LOCKED")
        #expect(zhErrPayload.message.contains("blade-1"))
        #expect(zhErrPayload.message.contains("4321"))
        #expect(zhErrPayload.message.contains("占用"))

        await MainActor.run {
            AgentVMLocalizer.shared.setLanguage(.zhHans, persist: false)
        }
        let enErrorResp = DaemonRPCResponse<DaemonRPCExecResult>.failure(
            id: .int(10),
            agentVMError: domainError,
            language: .en
        )
        let enErrorLine = try DaemonRPCCodec.encodeResponseLine(enErrorResp)
        let decodedEnErr = try DaemonRPCCodec.decodeResponseLine(DaemonRPCExecResult.self, from: enErrorLine)
        guard case let .failure(enErrPayload) = decodedEnErr.outcome else {
            Issue.record("Expected failure outcome")
            return
        }
        #expect(enErrPayload.errorCode == "ERR_VM_LOCKED")
        #expect(enErrPayload.message.contains("currently in use by process 4321"))
    }

    // MARK: - Item 2: Chunked 64 KiB Line Reader/Writer & Bounded Line Length

    @Test("Item 2: DaemonRPCLineReader reads in 64 KiB chunks (never byte-by-byte), handles coalesced/fragmented lines, and rejects oversized or unterminated lines")
    func daemonRPCLineReaderChunkedIOAndMaxLineLimit() throws {
        #expect(DaemonRPCLineFraming.defaultReadChunkBytes == 64 * 1024)
        #expect(DaemonRPCLineFraming.maxLineBytes == 8 * 1024 * 1024)

        // 1. Live socketpair: 200 KiB line + 2 coalesced follow-up lines -> read syscall count << byte count
        // and every read requests 64 KiB.
        var pair: [Int32] = [-1, -1]
        #expect(Darwin.socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0)
        defer {
            if pair[0] >= 0 { _ = Darwin.close(pair[0]) }
            if pair[1] >= 0 { _ = Darwin.close(pair[1]) }
        }

        final class SyscallCounter: @unchecked Sendable {
            let lock = NSLock()
            var callCount = 0
            var requestedSizes: [Int] = []
            func record(requested: Int) {
                lock.withLock {
                    callCount += 1
                    requestedSizes.append(requested)
                }
            }
        }
        let counter = SyscallCounter()

        let bigPayload = Data(repeating: UInt8(ascii: "x"), count: 200_000)
        let line2 = Data(#"{"jsonrpc":"2.0","id":2,"result":{"ok":true}}"#.utf8)
        let line3 = Data(#"{"jsonrpc":"2.0","id":3,"result":{"ok":false}}"#.utf8)

        let writeFD = pair[1]
        let writerThreadFinished = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            try? DaemonRPCLineWriter.writeLineData(bigPayload, toFD: writeFD)
            var coalesced = Data()
            coalesced.append(line2)
            coalesced.append(0x0A)
            coalesced.append(line3)
            coalesced.append(0x0A)
            coalesced.withUnsafeBytes { raw in
                if let base = raw.baseAddress {
                    _ = Darwin.write(writeFD, base, raw.count)
                }
            }
            _ = Darwin.shutdown(writeFD, SHUT_WR)
            writerThreadFinished.signal()
        }

        let reader = DaemonRPCLineReader(
            fd: pair[0],
            readFunction: { fd, buf, count in
                counter.record(requested: count)
                return Darwin.read(fd, buf, count)
            }
        )

        let got1 = try #require(try reader.readLineData())
        let got2 = try #require(try reader.readLineData())
        let got3 = try #require(try reader.readLineData())
        let gotEOF = try reader.readLineData()
        writerThreadFinished.wait()

        #expect(got1 == bigPayload)
        #expect(got2 == line2)
        #expect(got3 == line3)
        #expect(gotEOF == nil)
        #expect(counter.callCount > 0 && counter.callCount < 50, "Expected chunked reads, got \(counter.callCount) syscalls")
        #expect(counter.requestedSizes.allSatisfy { $0 == 64 * 1024 })

        // 2. Exact maxLineBytes boundary passes; maxLineBytes + 1 fails immediately without unbounded buffering.
        let exact4K = Data(repeating: UInt8(ascii: "a"), count: 4096)
        let over4K = Data(repeating: UInt8(ascii: "b"), count: 4097)
        var wireBytes = Data()
        wireBytes.append(exact4K)
        wireBytes.append(0x0A)
        wireBytes.append(over4K)
        wireBytes.append(0x0A)

        var cursor = 0
        let boundedReader = DaemonRPCLineReader(
            fd: -1,
            readChunkBytes: 1024,
            maxLineBytes: 4096,
            readFunction: { _, buf, count in
                let remaining = wireBytes.count - cursor
                guard remaining > 0 else { return 0 }
                let n = min(count, remaining)
                wireBytes.withUnsafeBytes { src in
                    buf.copyMemory(from: src.baseAddress!.advanced(by: cursor), byteCount: n)
                }
                cursor += n
                return n
            }
        )
        #expect(try boundedReader.readLineData() == exact4K)
        #expect(throws: DaemonRPCLineFramingError.lineTooLong(limitBytes: 4096)) {
            _ = try boundedReader.readLineData()
        }

        // 3. Default 8 MiB limit stops reading an endless newline-free stream right past 8 MiB (does not consume 64 MiB).
        var fedBytes = 0
        let defaultLimitReader = DaemonRPCLineReader(
            fd: -1,
            readFunction: { _, buf, count in
                if fedBytes >= 64 * 1024 * 1024 { return 0 }
                memset(buf, Int32(UInt8(ascii: "z")), count)
                fedBytes += count
                return count
            }
        )
        #expect(throws: DaemonRPCLineFramingError.lineTooLong(limitBytes: DaemonRPCLineFraming.maxLineBytes)) {
            _ = try defaultLimitReader.readLineData()
        }
        #expect(
            fedBytes == DaemonRPCLineFraming.maxLineBytes + DaemonRPCLineFraming.defaultReadChunkBytes,
            "Reader must abort immediately once unread bytes exceed maxLineBytes (fed \(fedBytes) bytes)"
        )

        // 4. Unterminated trailing bytes at EOF & writer newline/size guards.
        var didSendPartial = false
        let truncatedReader = DaemonRPCLineReader(
            fd: -1,
            readFunction: { _, buf, _ in
                guard !didSendPartial else { return 0 }
                didSendPartial = true
                let partial = Array(#"{"jsonrpc":"2.0""#.utf8)
                buf.copyMemory(from: partial, byteCount: partial.count)
                return partial.count
            }
        )
        #expect(throws: DaemonRPCLineFramingError.unterminatedLineAtEOF(byteCount: 16)) {
            _ = try truncatedReader.readLineData()
        }

        #expect(throws: DaemonRPCLineFramingError.embeddedNewlineInOutgoingLine) {
            try DaemonRPCLineWriter.writeLineData(Data("bad\nline".utf8), toFD: pair[1])
        }
    }

    // MARK: - Item 3: Socket Address Rule, SHA-256 Symlink & sockaddr_un Bounds Check (A43)

    private func makeMkdtempDirectory(prefix: String = "avm-m2-s1") throws -> URL {
        let baseTemp = try DaemonSocketAddressResolver.darwinUserTempDirectoryURL()
        let pattern = baseTemp.appendingPathComponent("\(prefix).XXXXXX", isDirectory: true).path
        var cTemplate = Array(pattern.utf8CString)
        let createdPtr = cTemplate.withUnsafeMutableBufferPointer { buf in
            Darwin.mkdtemp(buf.baseAddress)
        }
        guard let createdPtr else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(Darwin.errno))
        }
        return URL(fileURLWithPath: String(cString: createdPtr), isDirectory: true).standardizedFileURL
    }

    @Test("Item 3 (A43): makeSockAddrUn enforces 103-byte UTF-8 ceiling before copying, and DaemonSocketAddressResolver computes direct vs DARWIN_USER_TEMP_DIR symlink with conflict protection")
    func socketAddressResolverAndSockAddrUnLengthGuard() throws {
        #expect(DaemonUnixSocketAddress.maxPathUTF8Bytes == 103)

        // 1. A43: 103 UTF-8 bytes succeeds; 104 UTF-8 bytes, empty path, and interior NUL fail before copying.
        let path103 = "/" + String(repeating: "a", count: 102)
        #expect(path103.utf8.count == 103)
        let addr103 = try DaemonUnixSocketAddress.makeSockAddrUn(socketPath: path103)
        #expect(addr103.sun_family == sa_family_t(AF_UNIX))

        let path104 = "/" + String(repeating: "a", count: 103)
        #expect(path104.utf8.count == 104)
        #expect(throws: DaemonSocketError.socketPathTooLong(path: path104, utf8ByteCount: 104, maxBytes: 103)) {
            _ = try DaemonUnixSocketAddress.makeSockAddrUn(socketPath: path104)
        }
        #expect(throws: DaemonSocketError.emptySocketPath) {
            _ = try DaemonUnixSocketAddress.makeSockAddrUn(socketPath: "")
        }
        #expect(throws: DaemonSocketError.interiorNullByte(path: "/tmp/a\0b.sock")) {
            _ = try DaemonUnixSocketAddress.makeSockAddrUn(socketPath: "/tmp/a\0b.sock")
        }

        // 2. Short path (standardizedFileURL collapses '//' per Fact 26) uses direct mode without creating symlink.
        let tempRoot = try makeMkdtempDirectory(prefix: "avm-addr")
        defer { try? FileManager.default.removeItem(at: tempRoot) }

        let shortWS = URL(fileURLWithPath: "/tmp//avm-short-\(UUID().uuidString.prefix(8)).agentvm", isDirectory: true)
        let shortPlan = try DaemonSocketAddressResolver.computePlan(for: shortWS)
        #expect(shortPlan.mode == .direct)
        #expect(shortPlan.symlinkURL == nil)
        #expect(!shortPlan.connectSocketPath.contains("//"))

        // 3. Long path (> 103 UTF-8 bytes, including multi-byte UTF-8) uses DARWIN_USER_TEMP_DIR/avm-<sha256-16> -> <ws>/run.
        let isolatedTempDir = tempRoot.appendingPathComponent("t", isDirectory: true)
        try FileManager.default.createDirectory(at: isolatedTempDir, withIntermediateDirectories: true)

        let longWS = tempRoot
            .appendingPathComponent(String(repeating: "long-seg-", count: 8) + "工作区", isDirectory: true)
            .appendingPathComponent("ws.agentvm", isDirectory: true)
        try FileManager.default.createDirectory(at: longWS, withIntermediateDirectories: true)

        let realWSPath = DaemonSocketAddressResolver.canonicalRealPath(of: longWS)
        let expectedHash16 = String(BinaryChecksums.sha256Hex(Data(realWSPath.utf8)).prefix(16))

        let (boundPlan, _) = try DaemonSocketAddressResolver.prepareForBind(
            workspaceURL: longWS,
            userTempDirectoryOverride: isolatedTempDir
        )
        defer { DaemonSocketAddressResolver.removeSymlinkIfPresent(for: boundPlan) }

        #expect(boundPlan.mode == .tempDirectorySymlink)
        let symlinkURL = try #require(boundPlan.symlinkURL)
        #expect(symlinkURL.lastPathComponent == "avm-\(expectedHash16)")
        #expect(boundPlan.connectSocketPath == symlinkURL.appendingPathComponent("daemon.sock").path)
        #expect(boundPlan.connectSocketPath.utf8.count <= 103)

        // Client resolves identical address and does not fail when symlink points to <longWS>/run.
        let (clientPlan, _) = try DaemonSocketAddressResolver.resolveForConnect(
            workspaceURL: longWS,
            userTempDirectoryOverride: isolatedTempDir
        )
        #expect(clientPlan == boundPlan)

        // Cleanup removes owned symlink; subsequent resolveForConnect does NOT recreate dangling symlink.
        DaemonSocketAddressResolver.removeSymlinkIfPresent(for: boundPlan)
        var st = Darwin.stat()
        #expect(Darwin.lstat(symlinkURL.path, &st) != 0 && Darwin.errno == ENOENT)
        _ = try DaemonSocketAddressResolver.resolveForConnect(
            workspaceURL: longWS,
            userTempDirectoryOverride: isolatedTempDir
        )
        #expect(Darwin.lstat(symlinkURL.path, &st) != 0 && Darwin.errno == ENOENT)

        // 4. Existing symlink pointing elsewhere throws error on both bind and connect and is NEVER overwritten.
        let foreignTarget = tempRoot.appendingPathComponent("foreign-dir/run", isDirectory: true).path
        #expect(Darwin.symlink(foreignTarget, symlinkURL.path) == 0)
        defer { _ = Darwin.unlink(symlinkURL.path) }

        do {
            _ = try DaemonSocketAddressResolver.prepareForBind(
                workspaceURL: longWS,
                userTempDirectoryOverride: isolatedTempDir
            )
            Issue.record("Expected symlinkTargetMismatch on prepareForBind")
        } catch let err as DaemonSocketError {
            guard case .symlinkTargetMismatch = err else {
                Issue.record("Unexpected DaemonSocketError: \(err)")
                return
            }
        }

        do {
            _ = try DaemonSocketAddressResolver.resolveForConnect(
                workspaceURL: longWS,
                userTempDirectoryOverride: isolatedTempDir
            )
            Issue.record("Expected symlinkTargetMismatch on resolveForConnect")
        } catch let err as DaemonSocketError {
            guard case .symlinkTargetMismatch = err else {
                Issue.record("Unexpected DaemonSocketError: \(err)")
                return
            }
        }

        // Verify foreign symlink is untouched even if removeSymlinkIfPresent is called!
        DaemonSocketAddressResolver.removeSymlinkIfPresent(for: boundPlan)
        var readBuf = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
        let linkLen = Darwin.readlink(symlinkURL.path, &readBuf, Int(PATH_MAX))
        #expect(linkLen > 0)
        let preservedTarget = String(decoding: readBuf.prefix(linkLen).map { UInt8(bitPattern: $0) }, as: UTF8.self)
        #expect(preservedTarget == foreignTarget)
    }
}
