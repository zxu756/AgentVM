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
}
