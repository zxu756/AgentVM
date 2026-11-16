import AgentVMModels
import Foundation

// MARK: - Line-Delimited JSON-RPC 2.0 Wire Protocol for AgentVM Workspace Daemon (M2)

public enum DaemonRPCConstants {
    public static let jsonRPCVersion = "2.0"
    public static let helloMethod = "hello"
    public static let execOutputMethod = "exec.output"
}

public enum DaemonRPCMethod: String, Codable, Hashable, CaseIterable, Sendable {
    case status
    case stop
    case list
    case up
    case halt
    case pause
    case resume
    case exec
}

public enum DaemonRPCID: Codable, Hashable, Sendable, ExpressibleByIntegerLiteral, ExpressibleByStringLiteral {
    case int(Int64)
    case string(String)
    case null

    public init(integerLiteral value: Int64) {
        self = .int(value)
    }

    public init(stringLiteral value: String) {
        self = .string(value)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let intVal = try? container.decode(Int64.self) {
            self = .int(intVal)
        } else if let strVal = try? container.decode(String.self) {
            self = .string(strVal)
        } else {
            throw DecodingError.typeMismatch(
                DaemonRPCID.self,
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "JSON-RPC id must be an integer, string, or null."
                )
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case let .int(val):
            try container.encode(val)
        case let .string(val):
            try container.encode(val)
        case .null:
            try container.encodeNil()
        }
    }
}

// MARK: - Hello Handshake & Version Compatibility

public struct DaemonRPCHello: Codable, Hashable, Sendable {
    public static let currentProtocolVersion: Int = 1

    public var protocolVersion: Int
    public var semanticVersion: SemanticVersion
    public var executablePath: String

    public init(
        protocolVersion: Int = Self.currentProtocolVersion,
        semanticVersion: SemanticVersion = .current,
        executablePath: String
    ) {
        self.protocolVersion = protocolVersion
        self.semanticVersion = semanticVersion
        self.executablePath = executablePath
    }

    public func isCompatible(withDaemon daemon: DaemonRPCHello) -> Bool {
        protocolVersion == daemon.protocolVersion && semanticVersion == daemon.semanticVersion
    }

    public func verifyCompatibility(
        withDaemon daemon: DaemonRPCHello,
        language: AppLanguage = .en
    ) throws {
        guard isCompatible(withDaemon: daemon) else {
            throw DaemonRPCProtocolError.versionMismatch(client: self, daemon: daemon)
        }
        _ = language
    }
}

public struct DaemonRPCHelloMessage: Codable, Hashable, Sendable {
    public var jsonrpc: String
    public var method: String
    public var params: DaemonRPCHello

    public init(
        jsonrpc: String = DaemonRPCConstants.jsonRPCVersion,
        method: String = DaemonRPCConstants.helloMethod,
        params: DaemonRPCHello
    ) {
        self.jsonrpc = jsonrpc
        self.method = method
        self.params = params
    }
}

public enum DaemonRPCProtocolError: Error, LocalizedError, Hashable, Sendable {
    case versionMismatch(client: DaemonRPCHello, daemon: DaemonRPCHello)
    case invalidJSONRPCVersion(String?)
    case unexpectedMethod(expected: String, actual: String)
    case malformedEnvelope(detail: String)
    case encodedLineContainsNewline

    public var errorCode: String {
        switch self {
        case .versionMismatch:
            return "ERR_DAEMON_VERSION_MISMATCH"
        case .invalidJSONRPCVersion, .unexpectedMethod, .malformedEnvelope, .encodedLineContainsNewline:
            return "ERR_DAEMON_PROTOCOL"
        }
    }

    public var errorDescription: String? {
        localizedMessage(in: .en)
    }

    public func localizedMessage(in language: AppLanguage) -> String {
        let isZh = (language == .zhHans)
        switch self {
        case let .versionMismatch(client, daemon):
            if isZh {
                return "守护进程版本与当前命令行不一致（命令行：v\(client.semanticVersion) 协议 \(client.protocolVersion)，运行中的守护进程：v\(daemon.semanticVersion) 协议 \(daemon.protocolVersion)，路径「\(daemon.executablePath)」）。请先运行 'agentvm daemon stop' 停止旧守护进程后再试。"
            }
            return "Running daemon version does not match this CLI (client: v\(client.semanticVersion) protocol \(client.protocolVersion), daemon: v\(daemon.semanticVersion) protocol \(daemon.protocolVersion) at '\(daemon.executablePath)'). Run 'agentvm daemon stop' first to stop the old daemon."
        case let .invalidJSONRPCVersion(found):
            let desc = found ?? "nil"
            return isZh
                ? "守护进程 JSON-RPC 版本无效（期望 2.0，收到 \(desc)）。"
                : "Invalid daemon JSON-RPC version (expected 2.0, got \(desc))."
        case let .unexpectedMethod(expected, actual):
            return isZh
                ? "守护进程握手或帧方法不匹配（期望「\(expected)」，收到「\(actual)」）。"
                : "Unexpected daemon RPC method (expected '\(expected)', got '\(actual)')."
        case let .malformedEnvelope(detail):
            return isZh
                ? "守护进程协议消息格式错误：\(detail)"
                : "Malformed daemon RPC message: \(detail)"
        case .encodedLineContainsNewline:
            return isZh
                ? "编码后的单行 JSON-RPC 消息包含非法换行符。"
                : "Encoded single-line JSON-RPC payload unexpectedly contained a newline byte."
        }
    }
}

// MARK: - Method Parameters & Result Payloads

public struct DaemonRPCStatusParams: Codable, Hashable, Sendable {
    public var lang: AppLanguage

    public init(lang: AppLanguage = .en) {
        self.lang = lang
    }

    private enum CodingKeys: String, CodingKey {
        case lang
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.lang = try container.decodeIfPresent(AppLanguage.self, forKey: .lang) ?? .en
    }
}

public struct DaemonRPCStatusResult: Codable, Hashable, Sendable {
    public var pid: Int32
    public var startedAt: Date
    public var socketPath: String
    public var workspacePath: String
    public var executablePath: String
    public var protocolVersion: Int
    public var semanticVersion: SemanticVersion
    public var vms: [VMInstanceRecord]

    public init(
        pid: Int32,
        startedAt: Date,
        socketPath: String,
        workspacePath: String,
        executablePath: String,
        protocolVersion: Int = DaemonRPCHello.currentProtocolVersion,
        semanticVersion: SemanticVersion = .current,
        vms: [VMInstanceRecord] = []
    ) {
        self.pid = pid
        self.startedAt = startedAt
        self.socketPath = socketPath
        self.workspacePath = workspacePath
        self.executablePath = executablePath
        self.protocolVersion = protocolVersion
        self.semanticVersion = semanticVersion
        self.vms = vms
    }
}

public struct DaemonRPCStopParams: Codable, Hashable, Sendable {
    public var lang: AppLanguage

    public init(lang: AppLanguage = .en) {
        self.lang = lang
    }

    private enum CodingKeys: String, CodingKey {
        case lang
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.lang = try container.decodeIfPresent(AppLanguage.self, forKey: .lang) ?? .en
    }
}

public struct DaemonRPCStopResult: Codable, Hashable, Sendable {
    public var stoppedVMIDs: [VMID]

    public init(stoppedVMIDs: [VMID] = []) {
        self.stoppedVMIDs = stoppedVMIDs
    }
}

public struct DaemonRPCListParams: Codable, Hashable, Sendable {
    public var lang: AppLanguage

    public init(lang: AppLanguage = .en) {
        self.lang = lang
    }

    private enum CodingKeys: String, CodingKey {
        case lang
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.lang = try container.decodeIfPresent(AppLanguage.self, forKey: .lang) ?? .en
    }
}

public struct DaemonRPCListResult: Codable, Hashable, Sendable {
    public var vms: [VMInstanceRecord]

    public init(vms: [VMInstanceRecord]) {
        self.vms = vms
    }
}

public struct DaemonRPCVMLifecycleParams: Codable, Hashable, Sendable {
    public var vm: String
    public var lang: AppLanguage

    public init(vm: String, lang: AppLanguage = .en) {
        self.vm = vm
        self.lang = lang
    }

    private enum CodingKeys: String, CodingKey {
        case vm
        case lang
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.vm = try container.decode(String.self, forKey: .vm)
        self.lang = try container.decodeIfPresent(AppLanguage.self, forKey: .lang) ?? .en
    }
}

public struct DaemonRPCVMLifecycleResult: Codable, Hashable, Sendable {
    public var vm: VMInstanceRecord

    public init(vm: VMInstanceRecord) {
        self.vm = vm
    }
}

public struct DaemonRPCExecParams: Codable, Hashable, Sendable {
    public static let defaultWorkingDirectory = "/"
    public static let defaultRunAsUser = "root"
    public static let defaultTimeoutSeconds: TimeInterval = 3600

    public var vm: String
    public var executable: String
    public var arguments: [String]
    public var workingDirectory: String
    public var runAsUser: String
    public var environment: [String: String]
    public var timeoutSeconds: TimeInterval
    public var lang: AppLanguage

    public init(
        vm: String,
        executable: String,
        arguments: [String] = [],
        workingDirectory: String = Self.defaultWorkingDirectory,
        runAsUser: String = Self.defaultRunAsUser,
        environment: [String: String] = [:],
        timeoutSeconds: TimeInterval = Self.defaultTimeoutSeconds,
        lang: AppLanguage = .en
    ) {
        self.vm = vm
        self.executable = executable
        self.arguments = arguments
        self.workingDirectory = workingDirectory
        self.runAsUser = runAsUser
        self.environment = environment
        self.timeoutSeconds = timeoutSeconds
        self.lang = lang
    }

    private enum CodingKeys: String, CodingKey {
        case vm
        case executable
        case arguments
        case workingDirectory
        case runAsUser
        case environment
        case timeoutSeconds
        case lang
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.vm = try container.decode(String.self, forKey: .vm)
        self.executable = try container.decode(String.self, forKey: .executable)
        self.arguments = try container.decodeIfPresent([String].self, forKey: .arguments) ?? []
        self.workingDirectory = try container.decodeIfPresent(String.self, forKey: .workingDirectory) ?? Self.defaultWorkingDirectory
        self.runAsUser = try container.decodeIfPresent(String.self, forKey: .runAsUser) ?? Self.defaultRunAsUser
        self.environment = try container.decodeIfPresent([String: String].self, forKey: .environment) ?? [:]
        self.timeoutSeconds = try container.decodeIfPresent(TimeInterval.self, forKey: .timeoutSeconds) ?? Self.defaultTimeoutSeconds
        self.lang = try container.decodeIfPresent(AppLanguage.self, forKey: .lang) ?? .en
    }
}

public enum DaemonRPCExecStream: String, Codable, Hashable, Sendable {
    case stdout
    case stderr
}

public struct DaemonRPCExecOutputParams: Codable, Hashable, Sendable {
    public var stream: DaemonRPCExecStream
    /// Raw chunk bytes; encoded on the JSON-RPC wire as a Base64 string (`JSONEncoder.DataEncodingStrategy.base64`).
    public var data: Data

    public init(stream: DaemonRPCExecStream, data: Data) {
        self.stream = stream
        self.data = data
    }
}

public struct DaemonRPCExecOutputNotification: Codable, Hashable, Sendable {
    public var jsonrpc: String
    public var method: String
    public var params: DaemonRPCExecOutputParams

    public init(
        jsonrpc: String = DaemonRPCConstants.jsonRPCVersion,
        method: String = DaemonRPCConstants.execOutputMethod,
        params: DaemonRPCExecOutputParams
    ) {
        self.jsonrpc = jsonrpc
        self.method = method
        self.params = params
    }
}

public struct DaemonRPCExecResult: Codable, Hashable, Sendable {
    public var exitCode: Int32
    public var timedOut: Bool

    public init(exitCode: Int32, timedOut: Bool = false) {
        self.exitCode = exitCode
        self.timedOut = timedOut
    }
}

// MARK: - Strongly-Typed Request Envelopes

public struct DaemonRPCRequest<Params: Codable & Sendable>: Codable, Sendable {
    public var jsonrpc: String
    public var id: DaemonRPCID
    public var method: DaemonRPCMethod
    public var params: Params

    public init(
        jsonrpc: String = DaemonRPCConstants.jsonRPCVersion,
        id: DaemonRPCID,
        method: DaemonRPCMethod,
        params: Params
    ) {
        self.jsonrpc = jsonrpc
        self.id = id
        self.method = method
        self.params = params
    }
}

public enum DaemonRPCCall: Hashable, Sendable {
    case status(DaemonRPCStatusParams)
    case stop(DaemonRPCStopParams)
    case list(DaemonRPCListParams)
    case up(DaemonRPCVMLifecycleParams)
    case halt(DaemonRPCVMLifecycleParams)
    case pause(DaemonRPCVMLifecycleParams)
    case resume(DaemonRPCVMLifecycleParams)
    case exec(DaemonRPCExecParams)

    public var method: DaemonRPCMethod {
        switch self {
        case .status: return .status
        case .stop: return .stop
        case .list: return .list
        case .up: return .up
        case .halt: return .halt
        case .pause: return .pause
        case .resume: return .resume
        case .exec: return .exec
        }
    }

    public var language: AppLanguage {
        switch self {
        case let .status(p): return p.lang
        case let .stop(p): return p.lang
        case let .list(p): return p.lang
        case let .up(p): return p.lang
        case let .halt(p): return p.lang
        case let .pause(p): return p.lang
        case let .resume(p): return p.lang
        case let .exec(p): return p.lang
        }
    }
}

public struct DaemonRPCRequestEnvelope: Codable, Hashable, Sendable {
    public var jsonrpc: String
    public var id: DaemonRPCID
    public var call: DaemonRPCCall

    public var method: DaemonRPCMethod { call.method }
    public var language: AppLanguage { call.language }

    public init(
        jsonrpc: String = DaemonRPCConstants.jsonRPCVersion,
        id: DaemonRPCID,
        call: DaemonRPCCall
    ) {
        self.jsonrpc = jsonrpc
        self.id = id
        self.call = call
    }

    private enum CodingKeys: String, CodingKey {
        case jsonrpc
        case id
        case method
        case params
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let ver = try container.decode(String.self, forKey: .jsonrpc)
        guard ver == DaemonRPCConstants.jsonRPCVersion else {
            throw DaemonRPCProtocolError.invalidJSONRPCVersion(ver)
        }
        self.jsonrpc = ver
        self.id = try container.decode(DaemonRPCID.self, forKey: .id)
        let method = try container.decode(DaemonRPCMethod.self, forKey: .method)
        switch method {
        case .status:
            let p = try container.decodeIfPresent(DaemonRPCStatusParams.self, forKey: .params) ?? DaemonRPCStatusParams()
            self.call = .status(p)
        case .stop:
            let p = try container.decodeIfPresent(DaemonRPCStopParams.self, forKey: .params) ?? DaemonRPCStopParams()
            self.call = .stop(p)
        case .list:
            let p = try container.decodeIfPresent(DaemonRPCListParams.self, forKey: .params) ?? DaemonRPCListParams()
            self.call = .list(p)
        case .up:
            self.call = .up(try container.decode(DaemonRPCVMLifecycleParams.self, forKey: .params))
        case .halt:
            self.call = .halt(try container.decode(DaemonRPCVMLifecycleParams.self, forKey: .params))
        case .pause:
            self.call = .pause(try container.decode(DaemonRPCVMLifecycleParams.self, forKey: .params))
        case .resume:
            self.call = .resume(try container.decode(DaemonRPCVMLifecycleParams.self, forKey: .params))
        case .exec:
            self.call = .exec(try container.decode(DaemonRPCExecParams.self, forKey: .params))
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(jsonrpc, forKey: .jsonrpc)
        try container.encode(id, forKey: .id)
        try container.encode(call.method, forKey: .method)
        switch call {
        case let .status(p): try container.encode(p, forKey: .params)
        case let .stop(p): try container.encode(p, forKey: .params)
        case let .list(p): try container.encode(p, forKey: .params)
        case let .up(p): try container.encode(p, forKey: .params)
        case let .halt(p): try container.encode(p, forKey: .params)
        case let .pause(p): try container.encode(p, forKey: .params)
        case let .resume(p): try container.encode(p, forKey: .params)
        case let .exec(p): try container.encode(p, forKey: .params)
        }
    }
}

// MARK: - JSON-RPC 2.0 Error & Response Envelopes

public struct DaemonRPCError: Codable, Hashable, Sendable, Error, LocalizedError {
    public static let parseErrorCode = -32700
    public static let invalidRequestCode = -32600
    public static let methodNotFoundCode = -32601
    public static let invalidParamsCode = -32602
    public static let internalErrorCode = -32603
    public static let applicationErrorCode = -32000

    public var code: Int
    public var errorCode: String
    public var message: String

    public init(code: Int = Self.applicationErrorCode, errorCode: String, message: String) {
        self.code = code
        self.errorCode = errorCode
        self.message = message
    }

    public var errorDescription: String? { message }

    /// Converts an `AgentVMError` into a wire `DaemonRPCError` localized strictly for `language`
    /// without reading or mutating `AgentVMLocalizer.shared`.
    public static func from(_ error: AgentVMError, language: AppLanguage) -> DaemonRPCError {
        let rpcCode: Int
        switch error {
        case .cliUsageError:
            rpcCode = Self.invalidParamsCode
        default:
            rpcCode = Self.applicationErrorCode
        }
        return DaemonRPCError(
            code: rpcCode,
            errorCode: error.errorCode,
            message: error.localizedMessage(in: language)
        )
    }
}

public struct DaemonRPCRequestDecodeError: Error, Hashable, Sendable {
    public var requestID: DaemonRPCID
    public var rpcError: DaemonRPCError

    public init(requestID: DaemonRPCID, rpcError: DaemonRPCError) {
        self.requestID = requestID
        self.rpcError = rpcError
    }
}

public struct DaemonRPCResponse<ResultPayload: Codable & Sendable>: Codable, Sendable {
    public enum Outcome: Sendable {
        case success(ResultPayload)
        case failure(DaemonRPCError)
    }

    public var jsonrpc: String
    public var id: DaemonRPCID
    public var outcome: Outcome

    public init(
        jsonrpc: String = DaemonRPCConstants.jsonRPCVersion,
        id: DaemonRPCID,
        outcome: Outcome
    ) {
        self.jsonrpc = jsonrpc
        self.id = id
        self.outcome = outcome
    }

    public static func success(id: DaemonRPCID, result: ResultPayload) -> Self {
        Self(id: id, outcome: .success(result))
    }

    public static func failure(id: DaemonRPCID, error: DaemonRPCError) -> Self {
        Self(id: id, outcome: .failure(error))
    }

    public static func failure(
        id: DaemonRPCID,
        agentVMError: AgentVMError,
        language: AppLanguage
    ) -> Self {
        Self(id: id, outcome: .failure(.from(agentVMError, language: language)))
    }

    public func resultOrThrow() throws -> ResultPayload {
        switch outcome {
        case let .success(res):
            return res
        case let .failure(err):
            throw err
        }
    }

    private enum CodingKeys: String, CodingKey {
        case jsonrpc
        case id
        case result
        case error
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let ver = try container.decode(String.self, forKey: .jsonrpc)
        guard ver == DaemonRPCConstants.jsonRPCVersion else {
            throw DaemonRPCProtocolError.invalidJSONRPCVersion(ver)
        }
        self.jsonrpc = ver
        self.id = try container.decode(DaemonRPCID.self, forKey: .id)
        let hasError = container.contains(.error)
        let hasResult = container.contains(.result)
        if hasError && !hasResult {
            self.outcome = .failure(try container.decode(DaemonRPCError.self, forKey: .error))
        } else if hasResult && !hasError {
            self.outcome = .success(try container.decode(ResultPayload.self, forKey: .result))
        } else {
            throw DaemonRPCProtocolError.malformedEnvelope(
                detail: "JSON-RPC 2.0 response must contain exactly one of 'result' or 'error'."
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(jsonrpc, forKey: .jsonrpc)
        try container.encode(id, forKey: .id)
        switch outcome {
        case let .success(payload):
            try container.encode(payload, forKey: .result)
        case let .failure(err):
            try container.encode(err, forKey: .error)
        }
    }
}

extension DaemonRPCResponse.Outcome: Equatable where ResultPayload: Equatable {}
extension DaemonRPCResponse.Outcome: Hashable where ResultPayload: Hashable {}
extension DaemonRPCResponse: Equatable where ResultPayload: Equatable {}
extension DaemonRPCResponse: Hashable where ResultPayload: Hashable {}

public enum DaemonRPCServerFrame<ResultPayload: Codable & Sendable>: Sendable {
    case execOutput(DaemonRPCExecOutputParams)
    case response(DaemonRPCResponse<ResultPayload>)
}

extension DaemonRPCServerFrame: Equatable where ResultPayload: Equatable {}
extension DaemonRPCServerFrame: Hashable where ResultPayload: Hashable {}

// MARK: - Single-Line Codable Wire Codec

public enum DaemonRPCCodec {
    private struct RawLanguageProbe: Decodable {
        var lang: AppLanguage?
    }

    private struct RawEnvelopeProbe: Decodable {
        var jsonrpc: String?
        var id: DaemonRPCID?
        var method: String?
        var params: RawLanguageProbe?
    }

    private struct ServerFrameProbe: Decodable {
        var jsonrpc: String?
        var method: String?
        var hasID: Bool

        private enum CodingKeys: String, CodingKey {
            case jsonrpc
            case id
            case method
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self.jsonrpc = try container.decodeIfPresent(String.self, forKey: .jsonrpc)
            self.method = try container.decodeIfPresent(String.self, forKey: .method)
            self.hasID = container.contains(.id)
        }
    }

    public static func makeEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dataEncodingStrategy = .base64
        encoder.dateEncodingStrategy = .custom { date, enc in
            var container = enc.singleValueContainer()
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            try container.encode(formatter.string(from: date))
        }
        return encoder
    }

    public static func makeDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dataDecodingStrategy = .base64
        decoder.dateDecodingStrategy = .custom { dec in
            let container = try dec.singleValueContainer()
            let raw = try container.decode(String.self)
            let fractional = ISO8601DateFormatter()
            fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let parsed = fractional.date(from: raw) {
                return parsed
            }
            let basic = ISO8601DateFormatter()
            basic.formatOptions = [.withInternetDateTime]
            if let parsed = basic.date(from: raw) {
                return parsed
            }
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Invalid ISO-8601 timestamp '\(raw)'."
            )
        }
        return decoder
    }

    public static func encodePayloadLine<T: Encodable>(_ value: T) throws -> Data {
        let data = try makeEncoder().encode(value)
        guard !data.contains(0x0A) else {
            throw DaemonRPCProtocolError.encodedLineContainsNewline
        }
        return data
    }

    public static func decodePayloadLine<T: Decodable>(_ type: T.Type, from lineData: Data) throws -> T {
        try makeDecoder().decode(T.self, from: lineData)
    }

    public static func encodeHelloLine(_ hello: DaemonRPCHello) throws -> Data {
        try encodePayloadLine(DaemonRPCHelloMessage(params: hello))
    }

    public static func decodeHelloLine(_ lineData: Data) throws -> DaemonRPCHello {
        let msg = try decodePayloadLine(DaemonRPCHelloMessage.self, from: lineData)
        guard msg.jsonrpc == DaemonRPCConstants.jsonRPCVersion else {
            throw DaemonRPCProtocolError.invalidJSONRPCVersion(msg.jsonrpc)
        }
        guard msg.method == DaemonRPCConstants.helloMethod else {
            throw DaemonRPCProtocolError.unexpectedMethod(
                expected: DaemonRPCConstants.helloMethod,
                actual: msg.method
            )
        }
        return msg.params
    }

    public static func encodeRequestLine(_ envelope: DaemonRPCRequestEnvelope) throws -> Data {
        try encodePayloadLine(envelope)
    }

    public static func encodeRequestLine<Params: Codable & Sendable>(
        _ request: DaemonRPCRequest<Params>
    ) throws -> Data {
        try encodePayloadLine(request)
    }

    public static func decodeRequestLine(_ lineData: Data) throws -> DaemonRPCRequestEnvelope {
        let decoder = makeDecoder()
        let probe: RawEnvelopeProbe
        do {
            probe = try decoder.decode(RawEnvelopeProbe.self, from: lineData)
        } catch {
            throw DaemonRPCRequestDecodeError(
                requestID: .null,
                rpcError: DaemonRPCError(
                    code: DaemonRPCError.parseErrorCode,
                    errorCode: "ERR_DAEMON_PROTOCOL",
                    message: "Malformed JSON-RPC request line: \(error.localizedDescription)"
                )
            )
        }

        let reqID = probe.id ?? .null
        let lang = probe.params?.lang ?? .en
        let isZh = (lang == .zhHans)

        guard probe.jsonrpc == DaemonRPCConstants.jsonRPCVersion else {
            throw DaemonRPCRequestDecodeError(
                requestID: reqID,
                rpcError: DaemonRPCError(
                    code: DaemonRPCError.invalidRequestCode,
                    errorCode: "ERR_DAEMON_PROTOCOL",
                    message: DaemonRPCProtocolError.invalidJSONRPCVersion(probe.jsonrpc).localizedMessage(in: lang)
                )
            )
        }

        guard let rawMethod = probe.method, !rawMethod.isEmpty, probe.id != nil else {
            throw DaemonRPCRequestDecodeError(
                requestID: reqID,
                rpcError: DaemonRPCError(
                    code: DaemonRPCError.invalidRequestCode,
                    errorCode: "ERR_DAEMON_PROTOCOL",
                    message: isZh
                        ? "JSON-RPC 请求缺少 id 或 method 字段。"
                        : "JSON-RPC request is missing required 'id' or 'method' field."
                )
            )
        }

        guard DaemonRPCMethod(rawValue: rawMethod) != nil else {
            throw DaemonRPCRequestDecodeError(
                requestID: reqID,
                rpcError: DaemonRPCError(
                    code: DaemonRPCError.methodNotFoundCode,
                    errorCode: "ERR_DAEMON_METHOD_NOT_FOUND",
                    message: isZh
                        ? "未知的守护进程方法「\(rawMethod)」。"
                        : "Unknown daemon RPC method '\(rawMethod)'."
                )
            )
        }

        do {
            return try decoder.decode(DaemonRPCRequestEnvelope.self, from: lineData)
        } catch {
            throw DaemonRPCRequestDecodeError(
                requestID: reqID,
                rpcError: DaemonRPCError(
                    code: DaemonRPCError.invalidParamsCode,
                    errorCode: "ERR_CLI_USAGE",
                    message: isZh
                        ? "方法「\(rawMethod)」的参数格式无效：\(error.localizedDescription)"
                        : "Invalid parameters for method '\(rawMethod)': \(error.localizedDescription)"
                )
            )
        }
    }

    public static func encodeExecOutputLine(_ output: DaemonRPCExecOutputParams) throws -> Data {
        try encodePayloadLine(DaemonRPCExecOutputNotification(params: output))
    }

    public static func encodeResponseLine<ResultPayload: Codable & Sendable>(
        _ response: DaemonRPCResponse<ResultPayload>
    ) throws -> Data {
        try encodePayloadLine(response)
    }

    public static func decodeResponseLine<ResultPayload: Codable & Sendable>(
        _ resultType: ResultPayload.Type = ResultPayload.self,
        from lineData: Data
    ) throws -> DaemonRPCResponse<ResultPayload> {
        _ = resultType
        return try decodePayloadLine(DaemonRPCResponse<ResultPayload>.self, from: lineData)
    }

    public static func decodeServerFrame<ResultPayload: Codable & Sendable>(
        _ resultType: ResultPayload.Type = ResultPayload.self,
        from lineData: Data
    ) throws -> DaemonRPCServerFrame<ResultPayload> {
        _ = resultType
        let decoder = makeDecoder()
        let probe = try decoder.decode(ServerFrameProbe.self, from: lineData)
        guard probe.jsonrpc == DaemonRPCConstants.jsonRPCVersion else {
            throw DaemonRPCProtocolError.invalidJSONRPCVersion(probe.jsonrpc)
        }
        if !probe.hasID, let method = probe.method {
            guard method == DaemonRPCConstants.execOutputMethod else {
                throw DaemonRPCProtocolError.unexpectedMethod(
                    expected: DaemonRPCConstants.execOutputMethod,
                    actual: method
                )
            }
            let notif = try decoder.decode(DaemonRPCExecOutputNotification.self, from: lineData)
            return .execOutput(notif.params)
        }
        let resp = try decoder.decode(DaemonRPCResponse<ResultPayload>.self, from: lineData)
        return .response(resp)
    }
}
