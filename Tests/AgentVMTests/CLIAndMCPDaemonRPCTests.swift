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

    // MARK: - Item 4: Listen & Connect Primitives (0700 run/, 0600 socket, SO_NOSIGPIPE, getpeereid)

    @Test("Item 4: DaemonSocketListener enforces 0700 run/ and 0600 socket, sets SO_NOSIGPIPE (returning EPIPE instead of SIGPIPE), and verifies peer UID via getpeereid")
    func socketListenerAndClientPermissionsNoSigPipeAndPeerUID() throws {
        let tempRoot = try makeMkdtempDirectory(prefix: "avm-sock")
        defer { try? FileManager.default.removeItem(at: tempRoot) }

        let wsURL = tempRoot.appendingPathComponent("s.agentvm", isDirectory: true)
        let paths = DaemonWorkspacePaths(workspaceURL: wsURL)

        // Pre-create run/ with 0755 to prove listener tightens it to 0700.
        try FileManager.default.createDirectory(
            at: paths.runDirectoryURL,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o755]
        )
        _ = Darwin.chmod(paths.runDirectoryURL.path, mode_t(0o755))

        let listener = try DaemonSocketListener.bindDirect(paths: paths)
        defer { listener.close(unlinkSocket: true) }

        // 1. Verify 0700 on run/ and 0600 S_IFSOCK on daemon.sock.
        var runStat = Darwin.stat()
        #expect(stat(paths.runDirectoryURL.path, &runStat) == 0)
        #expect((runStat.st_mode & 0o777) == 0o700)

        var sockStat = Darwin.stat()
        #expect(stat(paths.directSocketPath, &sockStat) == 0)
        #expect((sockStat.st_mode & S_IFMT) == S_IFSOCK)
        #expect((sockStat.st_mode & 0o777) == 0o600)
        #expect(try DaemonSocketPrimitives.isNoSigPipeEnabled(listener.listenFD) == true)

        // 2. Connect + accept with matching UID, verify SO_NOSIGPIPE on both ends, and verify writing after peer close returns EPIPE without SIGPIPE.
        let acceptedBox = LockedResultBox<Result<DaemonSocketConnection, Error>>()
        let acceptDone = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            let res = Result { try listener.acceptConnection() }
            acceptedBox.store(res)
            acceptDone.signal()
        }

        let clientConn = try DaemonSocketClient.connectDirect(socketPath: paths.directSocketPath)
        acceptDone.wait()
        let serverConn = try #require(acceptedBox.load()).get()
        defer {
            clientConn.close()
            serverConn.close()
        }

        #expect(serverConn.peerUID == Darwin.getuid())
        #expect(clientConn.peerUID == Darwin.getuid())
        #expect(try DaemonSocketPrimitives.isNoSigPipeEnabled(clientConn.fd) == true)
        #expect(try DaemonSocketPrimitives.isNoSigPipeEnabled(serverConn.fd) == true)

        try clientConn.writeLineData(Data(#"{"ping":1}"#.utf8))
        #expect(try serverConn.makeLineReader().readLineData() == Data(#"{"ping":1}"#.utf8))

        // Close client and write from server -> SO_NOSIGPIPE converts broken pipe into EPIPE error instead of killing test process.
        clientConn.close()
        do {
            try serverConn.writeLineData(Data(repeating: UInt8(ascii: "p"), count: 1024))
            Issue.record("Expected EPIPE error writing to closed peer socket")
        } catch let err as DaemonRPCLineFramingError {
            guard case let .ioError(errnoCode, _) = err else {
                Issue.record("Expected ioError, got \(err)")
                return
            }
            #expect(errnoCode == EPIPE || errnoCode == ECONNRESET)
        }

        // 3. Peer UID mismatch in getpeereid rejects and immediately closes the accepted connection.
        let wrongUID = Darwin.getuid() &+ 1
        let rejectedBox = LockedResultBox<Result<DaemonSocketConnection, Error>>()
        let rejectDone = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            let res = Result { try listener.acceptConnection(expectedUID: wrongUID) }
            rejectedBox.store(res)
            rejectDone.signal()
        }

        let rejectedClient = try DaemonSocketClient.connectDirect(socketPath: paths.directSocketPath)
        defer { rejectedClient.close() }
        rejectDone.wait()

        do {
            _ = try #require(rejectedBox.load()).get()
            Issue.record("Expected unauthorizedPeerUID when expectedUID != getuid()")
        } catch let err as DaemonSocketError {
            #expect(err == .unauthorizedPeerUID(expected: wrongUID, actual: Darwin.getuid()))
        }

        // Server closed the rejected fd immediately, so client reads EOF (or ECONNRESET).
        do {
            let eof = try rejectedClient.makeLineReader().readLineData()
            #expect(eof == nil)
        } catch let err as DaemonRPCLineFramingError {
            if case let .ioError(code, _) = err {
                #expect(code == ECONNRESET)
            } else {
                Issue.record("Unexpected framing error on rejected peer: \(err)")
            }
        }
    }

    // MARK: - Item 5: Singleton Lock (`daemon.lock`) & Ordered `lock -> unlink -> bind` Startup

    @Test("Item 5: DaemonSingletonLock writes/reads holder metadata under non-blocking flock, and acquireLockAndBind enforces lock -> unlink stale sock -> bind so contenders never delete the winner's socket")
    func singletonLockMetadataAndLockBeforeUnlinkBindOrder() throws {
        let tempRoot = try makeMkdtempDirectory(prefix: "avm-lock")
        defer { try? FileManager.default.removeItem(at: tempRoot) }

        let wsURL = tempRoot.appendingPathComponent("lockws.agentvm", isDirectory: true)
        let paths = DaemonWorkspacePaths(workspaceURL: wsURL)
        try DaemonSocketPrimitives.ensureRunDirectory0700(at: paths.runDirectoryURL)

        // Plant a stale socket from a previously crashed process (bind and close FD without unlinking).
        do {
            let stale = try DaemonSocketListener.bindDirect(paths: paths)
            stale.close(unlinkSocket: false)
        }
        var staleStat = Darwin.stat()
        #expect(stat(paths.directSocketPath, &staleStat) == 0)

        let start1 = Date(timeIntervalSince1970: 1_763_330_000.125)
        let ver1 = SemanticVersion(major: 1, minor: 3, patch: 0)
        let exe1 = "/opt/agentvm/bin/AgentVM-winner"

        let firstOutcome = try DaemonWorkspaceServerBootstrap.acquireLockAndBind(
            workspaceURL: wsURL,
            pid: Darwin.getpid(),
            version: ver1,
            executablePath: exe1,
            startedAt: start1
        )
        let server1: DaemonBoundWorkspaceServer
        switch firstOutcome {
        case let .bound(srv):
            server1 = srv
        case .alreadyRunning:
            Issue.record("Expected first acquireLockAndBind to win singleton lock")
            return
        }
        defer { server1.shutdownAndCleanup() }

        // Contender #2 fails non-blocking flock, reads winner's exact metadata, and MUST NOT unlink winner's daemon.sock.
        let secondOutcome = try DaemonWorkspaceServerBootstrap.acquireLockAndBind(
            workspaceURL: wsURL,
            pid: 99_999,
            version: SemanticVersion(major: 9, minor: 9, patch: 9),
            executablePath: "/opt/agentvm/bin/AgentVM-loser",
            startedAt: Date(timeIntervalSince1970: 1_763_339_999)
        )
        switch secondOutcome {
        case .bound:
            Issue.record("Second contender must not acquire daemon.lock while server1 holds it")
            return
        case let .alreadyRunning(holder):
            let info = try #require(holder)
            #expect(info.pid == Darwin.getpid())
            #expect(info.version == ver1)
            #expect(info.executablePath == exe1)
            #expect(abs(info.startedAt.timeIntervalSince(start1)) < 0.001)
        }

        // Winner's socket must still be present on disk and accept a live client connection!
        var liveSockStat = Darwin.stat()
        #expect(stat(paths.directSocketPath, &liveSockStat) == 0)

        let acceptedBox = LockedResultBox<Result<DaemonSocketConnection, Error>>()
        let acceptSem = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            acceptedBox.store(Result { try server1.listener.acceptConnection() })
            acceptSem.signal()
        }
        let client = try DaemonSocketClient.connectDirect(socketPath: paths.directSocketPath)
        acceptSem.wait()
        let accepted = try #require(acceptedBox.load()).get()
        try client.writeLineData(Data(#"{"still":"alive"}"#.utf8))
        #expect(try accepted.makeLineReader().readLineData() == Data(#"{"still":"alive"}"#.utf8))
        client.close()
        accepted.close()

        // Clean shutdown removes socket, clears lock file, and releases flock so a new server can bind.
        server1.shutdownAndCleanup()
        #expect(stat(paths.directSocketPath, &liveSockStat) != 0 && Darwin.errno == ENOENT)
        #expect(DaemonSingletonLock.readHolderInfo(at: paths.lockFileURL) == nil)

        let thirdOutcome = try DaemonWorkspaceServerBootstrap.acquireLockAndBind(
            workspaceURL: wsURL,
            pid: Darwin.getpid(),
            version: ver1,
            executablePath: "/opt/agentvm/bin/AgentVM-restarted",
            startedAt: Date(timeIntervalSince1970: 1_763_340_000)
        )
        guard case let .bound(server3) = thirdOutcome else {
            Issue.record("Expected acquireLockAndBind to succeed after server1 shutdownAndCleanup")
            return
        }
        #expect(server3.holderInfo.executablePath == "/opt/agentvm/bin/AgentVM-restarted")
        server3.shutdownAndCleanup()
    }

    // MARK: - Item 6: Hypothesis 11 End-to-End Verification (>=120B Workspace, 103B & 104B Boundaries, Symlink Conflict)

    private func makeShortTmpMkdtemp(prefix: String = "avm-h11") throws -> URL {
        var cTemplate = Array("/tmp/\(prefix).XXXXXX".utf8CString)
        let createdPtr = cTemplate.withUnsafeMutableBufferPointer { buf in
            Darwin.mkdtemp(buf.baseAddress)
        }
        guard let createdPtr else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(Darwin.errno))
        }
        return URL(fileURLWithPath: String(cString: createdPtr), isDirectory: true).standardizedFileURL
    }

    private func assertLiveRPCLineRoundTrip(
        server: DaemonBoundWorkspaceServer,
        workspaceURL: URL
    ) throws {
        let acceptBox = LockedResultBox<Result<DaemonSocketConnection, Error>>()
        let acceptSem = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            acceptBox.store(Result { try server.listener.acceptConnection() })
            acceptSem.signal()
        }

        let clientConn = try DaemonSocketClient.connectWorkspace(workspaceURL: workspaceURL)
        acceptSem.wait()
        let serverConn = try #require(acceptBox.load()).get()
        defer {
            clientConn.close()
            serverConn.close()
        }

        let clientHello = DaemonRPCHello(executablePath: "/opt/agentvm/client")
        let daemonHello = DaemonRPCHello(executablePath: "/opt/agentvm/daemon")
        try clientConn.writeLineData(try DaemonRPCCodec.encodeHelloLine(clientHello))
        try serverConn.writeLineData(try DaemonRPCCodec.encodeHelloLine(daemonHello))

        let serverReadHello = try DaemonRPCCodec.decodeHelloLine(
            try #require(try serverConn.makeLineReader().readLineData())
        )
        let clientReadHello = try DaemonRPCCodec.decodeHelloLine(
            try #require(try clientConn.makeLineReader().readLineData())
        )
        #expect(serverReadHello == clientHello)
        try clientHello.verifyCompatibility(withDaemon: clientReadHello, language: .en)

        let req = DaemonRPCRequestEnvelope(
            id: .int(42),
            call: .exec(DaemonRPCExecParams(vm: "t1", executable: "/usr/bin/uname", arguments: ["-r"]))
        )
        try clientConn.writeLineData(try DaemonRPCCodec.encodeRequestLine(req))
        let receivedReq = try DaemonRPCCodec.decodeRequestLine(
            try #require(try serverConn.makeLineReader().readLineData())
        )
        #expect(receivedReq == req)

        let chunk = DaemonRPCExecOutputParams(stream: .stdout, data: Data("6.1.0-54-cloud-arm64\n".utf8))
        try serverConn.writeLineData(try DaemonRPCCodec.encodeExecOutputLine(chunk))
        let resp = DaemonRPCResponse<DaemonRPCExecResult>.success(
            id: .int(42),
            result: DaemonRPCExecResult(exitCode: 0, timedOut: false)
        )
        try serverConn.writeLineData(try DaemonRPCCodec.encodeResponseLine(resp))

        let clientReader = clientConn.makeLineReader()
        let f1 = try DaemonRPCCodec.decodeServerFrame(
            DaemonRPCExecResult.self,
            from: try #require(try clientReader.readLineData())
        )
        let f2 = try DaemonRPCCodec.decodeServerFrame(
            DaemonRPCExecResult.self,
            from: try #require(try clientReader.readLineData())
        )
        #expect(f1 == .execOutput(chunk))
        #expect(f2 == .response(resp))
    }

    @Test("Item 6 (Hypothesis 11): >=120-byte workspace, exact 103-byte direct boundary, exact 104-byte symlink boundary, and existing-symlink conflict over real DARWIN_USER_TEMP_DIR")
    func hypothesis11LongPathSymlinkAndExact103Vs104Boundaries() throws {
        let tempRoot = try makeShortTmpMkdtemp(prefix: "avm-h11")
        defer { try? FileManager.default.removeItem(at: tempRoot) }

        let darwinTempDir = try DaemonSocketAddressResolver.darwinUserTempDirectoryURL()
        let canonicalTempRoot = DaemonSocketAddressResolver.canonicalRealPath(of: tempRoot)
        let fixedOverhead = canonicalTempRoot.utf8.count + 1 + "/ws.agentvm/run/daemon.sock".utf8.count
        #expect(fixedOverhead < 90)

        // 1. Exact 103-byte socket path boundary: direct bind/connect, zero symlink in DARWIN_USER_TEMP_DIR.
        let pad103 = String(repeating: "a", count: 103 - fixedOverhead)
        let ws103 = tempRoot.appendingPathComponent(pad103, isDirectory: true)
            .appendingPathComponent("ws.agentvm", isDirectory: true)
        let paths103 = DaemonWorkspacePaths(workspaceURL: ws103)
        #expect(paths103.directSocketPathUTF8ByteCount == 103)

        guard case let .bound(srv103) = try DaemonWorkspaceServerBootstrap.acquireLockAndBind(workspaceURL: ws103) else {
            Issue.record("Expected 103-byte socket path to bind")
            return
        }
        defer { srv103.shutdownAndCleanup() }
        #expect(srv103.address.mode == .direct)
        #expect(srv103.address.symlinkURL == nil)
        try assertLiveRPCLineRoundTrip(server: srv103, workspaceURL: ws103)
        srv103.shutdownAndCleanup()

        // 2. Exact 104-byte socket path boundary: uses DARWIN_USER_TEMP_DIR/avm-<sha256-16> symlink.
        let pad104 = String(repeating: "b", count: 104 - fixedOverhead)
        let ws104 = tempRoot.appendingPathComponent(pad104, isDirectory: true)
            .appendingPathComponent("ws.agentvm", isDirectory: true)
        let paths104 = DaemonWorkspacePaths(workspaceURL: ws104)
        #expect(paths104.directSocketPathUTF8ByteCount == 104)

        guard case let .bound(srv104) = try DaemonWorkspaceServerBootstrap.acquireLockAndBind(workspaceURL: ws104) else {
            Issue.record("Expected 104-byte socket path to bind via symlink")
            return
        }
        defer { srv104.shutdownAndCleanup() }
        #expect(srv104.address.mode == .tempDirectorySymlink)
        let sym104 = try #require(srv104.address.symlinkURL)
        #expect(sym104.deletingLastPathComponent().standardizedFileURL == darwinTempDir)
        var symStat = Darwin.stat()
        #expect(Darwin.lstat(sym104.path, &symStat) == 0 && (symStat.st_mode & S_IFMT) == S_IFLNK)
        try assertLiveRPCLineRoundTrip(server: srv104, workspaceURL: ws104)
        srv104.shutdownAndCleanup()
        #expect(Darwin.lstat(sym104.path, &symStat) != 0 && Darwin.errno == ENOENT)

        // 3. >= 120-byte workspace path: bind, connect, exchange RPC lines via DARWIN_USER_TEMP_DIR symlink.
        let wsLong = tempRoot
            .appendingPathComponent(String(repeating: "deep-workspace-segment-", count: 6), isDirectory: true)
            .appendingPathComponent("ws.agentvm", isDirectory: true)
        #expect(wsLong.standardizedFileURL.path.utf8.count >= 120)

        guard case let .bound(srvLong) = try DaemonWorkspaceServerBootstrap.acquireLockAndBind(workspaceURL: wsLong) else {
            Issue.record("Expected >=120-byte workspace to bind via symlink")
            return
        }
        defer { srvLong.shutdownAndCleanup() }
        #expect(srvLong.address.mode == .tempDirectorySymlink)
        let symLong = try #require(srvLong.address.symlinkURL)
        #expect(srvLong.address.connectSocketPath.utf8.count <= 103)

        var physStat = Darwin.stat()
        #expect(stat(DaemonWorkspacePaths(workspaceURL: wsLong).directSocketPath, &physStat) == 0)
        #expect((physStat.st_mode & S_IFMT) == S_IFSOCK)
        #expect((physStat.st_mode & 0o777) == 0o600)

        try assertLiveRPCLineRoundTrip(server: srvLong, workspaceURL: wsLong)
        srvLong.shutdownAndCleanup()
        #expect(Darwin.lstat(symLong.path, &symStat) != 0 && Darwin.errno == ENOENT)
        #expect(stat(DaemonWorkspacePaths(workspaceURL: wsLong).directSocketPath, &physStat) != 0 && Darwin.errno == ENOENT)

        // 4. Existing symlink in DARWIN_USER_TEMP_DIR pointing elsewhere fails without overwriting and releases lock.
        let wsConflict = tempRoot
            .appendingPathComponent(String(repeating: "conflict-workspace-seg-", count: 6), isDirectory: true)
            .appendingPathComponent("ws.agentvm", isDirectory: true)
        #expect(wsConflict.standardizedFileURL.path.utf8.count >= 120)
        let conflictPlan = try DaemonSocketAddressResolver.computePlan(for: wsConflict)
        let conflictSymURL = try #require(conflictPlan.symlinkURL)
        let wrongTarget = tempRoot.appendingPathComponent("wrong-place/run", isDirectory: true).path
        _ = Darwin.unlink(conflictSymURL.path)
        #expect(Darwin.symlink(wrongTarget, conflictSymURL.path) == 0)
        defer { _ = Darwin.unlink(conflictSymURL.path) }

        do {
            _ = try DaemonWorkspaceServerBootstrap.acquireLockAndBind(workspaceURL: wsConflict)
            Issue.record("Expected symlinkTargetMismatch when DARWIN_USER_TEMP_DIR symlink points elsewhere")
        } catch let err as DaemonSocketError {
            guard case .symlinkTargetMismatch = err else {
                Issue.record("Unexpected error: \(err)")
                return
            }
        }

        do {
            _ = try DaemonSocketClient.connectWorkspace(workspaceURL: wsConflict)
            Issue.record("Expected client connectWorkspace to fail on mismatched symlink")
        } catch let err as DaemonSocketError {
            guard case .symlinkTargetMismatch = err else {
                Issue.record("Unexpected client error: \(err)")
                return
            }
        }

        // Verify foreign symlink target is untouched AND daemon.lock was released on failure!
        var linkBuf = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
        let n = Darwin.readlink(conflictSymURL.path, &linkBuf, Int(PATH_MAX))
        #expect(n > 0)
        let remainingTarget = String(decoding: linkBuf.prefix(n).map { UInt8(bitPattern: $0) }, as: UTF8.self)
        #expect(remainingTarget == wrongTarget)

        let lockProbe = try DaemonSingletonLock.tryAcquire(workspaceURL: wsConflict)
        switch lockProbe {
        case let .acquired(lock):
            lock.release(clearFile: true)
        case .alreadyHeld:
            Issue.record("Failed acquireLockAndBind must release daemon.lock before rethrowing")
        }
    }
}

private final class LockedResultBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: T?
    func store(_ newValue: T) {
        lock.withLock { value = newValue }
    }
    func load() -> T? {
        lock.withLock { value }
    }
}
