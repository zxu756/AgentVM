import AgentVMModels
import Foundation

// MARK: - Wiretap Boolean Filter AST & Field Definitions

public enum WiretapFilterField: String, Codable, Hashable, Sendable, CaseIterable {
    case proto
    case verdict
    case direction
    case vm
    case ip
    case srcIP = "ip.src"
    case dstIP = "ip.dst"
    case mac
    case srcMAC = "eth.src"
    case dstMAC = "eth.dst"
    case port
    case srcPort = "sport"
    case dstPort = "dport"
    case sni
    case alpn
    case dns
    case httpHost = "http.host"
    case http
    case domain
    case flags
    case rule
    case vlan
    case length = "len"
    case info

    public init?(alias raw: String) {
        switch raw.lowercased() {
        case "proto", "protocol":
            self = .proto
        case "verdict", "action":
            self = .verdict
        case "dir", "direction":
            self = .direction
        case "vm", "vmid", "vm_id":
            self = .vm
        case "ip", "addr", "ip.addr":
            self = .ip
        case "src", "srcip", "ip.src":
            self = .srcIP
        case "dst", "dstip", "ip.dst":
            self = .dstIP
        case "mac", "eth.addr":
            self = .mac
        case "srcmac", "eth.src":
            self = .srcMAC
        case "dstmac", "eth.dst":
            self = .dstMAC
        case "port", "tcp.port", "udp.port":
            self = .port
        case "sport", "srcport", "tcp.srcport", "udp.srcport":
            self = .srcPort
        case "dport", "dstport", "tcp.dstport", "udp.dstport":
            self = .dstPort
        case "sni", "tls.sni":
            self = .sni
        case "alpn", "tls.alpn":
            self = .alpn
        case "dns", "qname", "dns.qname":
            self = .dns
        case "host", "http.host":
            self = .httpHost
        case "http", "uri", "http.req", "http.uri":
            self = .http
        case "domain":
            self = .domain
        case "flags", "tcp.flags":
            self = .flags
        case "rule", "ruleid", "rule_id":
            self = .rule
        case "vlan", "vlan.id":
            self = .vlan
        case "len", "length", "size", "frame.len":
            self = .length
        case "info", "summary", "reason":
            self = .info
        default:
            return nil
        }
    }
}

public enum WiretapComparisonOperator: String, Codable, Hashable, Sendable, CaseIterable {
    case equal = "=="
    case notEqual = "!="
    case contains = "contains"
    case startsWith = "startsWith"
    case endsWith = "endsWith"
    case globMatch = "~="
    case greaterThan = ">"
    case greaterOrEqual = ">="
    case lessThan = "<"
    case lessOrEqual = "<="
}

public indirect enum WiretapFilterExpression: Hashable, Sendable, CustomStringConvertible {
    case matchAll
    case substring(String)
    case comparison(field: WiretapFilterField, op: WiretapComparisonOperator, value: String)
    case not(WiretapFilterExpression)
    case and(WiretapFilterExpression, WiretapFilterExpression)
    case or(WiretapFilterExpression, WiretapFilterExpression)

    public var description: String {
        switch self {
        case .matchAll:
            return "*"
        case let .substring(term):
            return "contains(\"\(term)\")"
        case let .comparison(field, op, value):
            return "\(field.rawValue) \(op.rawValue) \"\(value)\""
        case let .not(inner):
            return "!(\(inner.description))"
        case let .and(lhs, rhs):
            return "(\(lhs.description) && \(rhs.description))"
        case let .or(lhs, rhs):
            return "(\(lhs.description) || \(rhs.description))"
        }
    }
}

// MARK: - Recursive-Descent Wiretap Filter Query Parser & Evaluator

public struct WiretapFilterQuery: Hashable, Sendable, CustomStringConvertible {
    public static let matchAll = WiretapFilterQuery("")

    public let rawQuery: String
    public let expression: WiretapFilterExpression
    public let usedSubstringFallback: Bool
    public let parseWarning: String?

    /// Resilient initializer intended for interactive UI filter bars:
    /// parses full boolean expressions (`&&`, `||`, `!`, `(...)`, field comparisons),
    /// and gracefully falls back to case-insensitive substring matching on arbitrary text.
    public init(_ rawQuery: String) {
        self.rawQuery = rawQuery
        let trimmed = rawQuery.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            self.expression = .matchAll
            self.usedSubstringFallback = false
            self.parseWarning = nil
            return
        }

        do {
            let parsedExpr = try Self.parseExpressionStrict(trimmed)
            self.expression = parsedExpr
            self.usedSubstringFallback = false
            self.parseWarning = nil
        } catch {
            self.expression = .substring(trimmed)
            self.usedSubstringFallback = true
            self.parseWarning = error.localizedDescription
        }
    }

    /// Strict initializer that throws `AgentVMError.cliUsageError` if boolean/operator syntax is malformed.
    public init(parsing rawQuery: String) throws {
        self.rawQuery = rawQuery
        let trimmed = rawQuery.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            self.expression = .matchAll
        } else {
            self.expression = try Self.parseExpressionStrict(trimmed)
        }
        self.usedSubstringFallback = false
        self.parseWarning = nil
    }

    public static func parse(_ rawQuery: String) throws -> WiretapFilterQuery {
        try WiretapFilterQuery(parsing: rawQuery)
    }

    public var description: String {
        expression.description
    }

    public func matches(_ packet: CapturedPacket) -> Bool {
        Self.evaluate(expression, against: packet)
    }

    public func evaluate(_ packet: CapturedPacket) -> Bool {
        matches(packet)
    }

    public func filter(_ packets: [CapturedPacket]) -> [CapturedPacket] {
        if case .matchAll = expression {
            return packets
        }
        return packets.filter { matches($0) }
    }

    public static func completionSuggestions(forPrefix prefix: String) -> [String] {
        let catalog: [String] = [
            "proto == TLS",
            "proto == DNS",
            "proto == HTTP",
            "proto == DHCP",
            "proto == ARP",
            "proto == TCP",
            "verdict == ALLOW",
            "verdict == DROP",
            "verdict == DNS_SINKHOLE",
            "verdict == REJECT_RST",
            "verdict == RATE_LIMITED",
            "port == 443",
            "port == 53",
            "port == 80",
            "sni contains github",
            "dns contains anthropic",
            "ip == 10.211.55.10",
            "dst == 169.254.169.254",
            "vm == "
        ]
        let clean = prefix.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !clean.isEmpty else { return Array(catalog.prefix(8)) }
        return catalog.filter { $0.lowercased().contains(clean) }
    }

    // MARK: - Lexer

    private enum Token: Equatable {
        case leftParen
        case rightParen
        case logicalAnd
        case logicalOr
        case logicalNot
        case symbolicOp(WiretapComparisonOperator)
        case word(String, quoted: Bool)
    }

    private static func tokenize(_ input: String) throws -> [Token] {
        let chars = Array(input.unicodeScalars)
        var tokens: [Token] = []
        var i = 0

        while i < chars.count {
            let c = chars[i]
            if CharacterSet.whitespacesAndNewlines.contains(c) {
                i += 1
                continue
            }

            switch c {
            case "(":
                tokens.append(.leftParen)
                i += 1
            case ")":
                tokens.append(.rightParen)
                i += 1
            case "&":
                if i + 1 < chars.count && chars[i + 1] == "&" {
                    tokens.append(.logicalAnd)
                    i += 2
                } else {
                    throw AgentVMError.cliUsageError(detail: "Expected '&&' at index \(i) in wiretap filter.")
                }
            case "|":
                if i + 1 < chars.count && chars[i + 1] == "|" {
                    tokens.append(.logicalOr)
                    i += 2
                } else {
                    throw AgentVMError.cliUsageError(detail: "Expected '||' at index \(i) in wiretap filter.")
                }
            case "!":
                if i + 1 < chars.count && chars[i + 1] == "=" {
                    tokens.append(.symbolicOp(.notEqual))
                    i += 2
                } else {
                    tokens.append(.logicalNot)
                    i += 1
                }
            case "=":
                if i + 1 < chars.count && chars[i + 1] == "=" {
                    tokens.append(.symbolicOp(.equal))
                    i += 2
                } else {
                    tokens.append(.symbolicOp(.equal))
                    i += 1
                }
            case "~":
                if i + 1 < chars.count && chars[i + 1] == "=" {
                    tokens.append(.symbolicOp(.globMatch))
                    i += 2
                } else {
                    throw AgentVMError.cliUsageError(detail: "Expected '~=' at index \(i) in wiretap filter.")
                }
            case "^":
                if i + 1 < chars.count && chars[i + 1] == "=" {
                    tokens.append(.symbolicOp(.startsWith))
                    i += 2
                } else {
                    throw AgentVMError.cliUsageError(detail: "Expected '^=' at index \(i) in wiretap filter.")
                }
            case "$":
                if i + 1 < chars.count && chars[i + 1] == "=" {
                    tokens.append(.symbolicOp(.endsWith))
                    i += 2
                } else {
                    throw AgentVMError.cliUsageError(detail: "Expected '$=' at index \(i) in wiretap filter.")
                }
            case ">":
                if i + 1 < chars.count && chars[i + 1] == "=" {
                    tokens.append(.symbolicOp(.greaterOrEqual))
                    i += 2
                } else {
                    tokens.append(.symbolicOp(.greaterThan))
                    i += 1
                }
            case "<":
                if i + 1 < chars.count && chars[i + 1] == "=" {
                    tokens.append(.symbolicOp(.lessOrEqual))
                    i += 2
                } else if i + 1 < chars.count && chars[i + 1] == ">" {
                    tokens.append(.symbolicOp(.notEqual))
                    i += 2
                } else {
                    tokens.append(.symbolicOp(.lessThan))
                    i += 1
                }
            case "\"", "'":
                let quote = c
                i += 1
                var buf = String.UnicodeScalarView()
                var closed = false
                while i < chars.count {
                    let cur = chars[i]
                    if cur == "\\" && i + 1 < chars.count {
                        buf.append(chars[i + 1])
                        i += 2
                    } else if cur == quote {
                        closed = true
                        i += 1
                        break
                    } else {
                        buf.append(cur)
                        i += 1
                    }
                }
                guard closed else {
                    throw AgentVMError.cliUsageError(detail: "Unterminated quoted string in wiretap filter.")
                }
                tokens.append(.word(String(buf), quoted: true))

            default:
                var buf = String.UnicodeScalarView()
                while i < chars.count && !isDelimiter(chars[i]) {
                    buf.append(chars[i])
                    i += 1
                }
                let word = String(buf)
                let lower = word.lowercased()
                if lower == "and" {
                    tokens.append(.logicalAnd)
                } else if lower == "or" {
                    tokens.append(.logicalOr)
                } else if lower == "not" {
                    tokens.append(.logicalNot)
                } else {
                    tokens.append(.word(word, quoted: false))
                }
            }
        }
        return tokens
    }

    private static func isDelimiter(_ scalar: UnicodeScalar) -> Bool {
        if CharacterSet.whitespacesAndNewlines.contains(scalar) {
            return true
        }
        switch scalar {
        case "(", ")", "&", "|", "!", "=", "~", "^", "$", "<", ">", "\"", "'":
            return true
        default:
            return false
        }
    }

    // MARK: - Recursive-Descent Grammar: OrExpr -> AndExpr -> UnaryExpr -> Primary

    private struct ParserState {
        let tokens: [Token]
        var index: Int = 0

        var isAtEnd: Bool { index >= tokens.count }

        func peek(ahead: Int = 0) -> Token? {
            let target = index + ahead
            guard target >= 0 && target < tokens.count else { return nil }
            return tokens[target]
        }

        mutating func advance() -> Token? {
            guard index < tokens.count else { return nil }
            defer { index += 1 }
            return tokens[index]
        }
    }

    private static func parseExpressionStrict(_ input: String) throws -> WiretapFilterExpression {
        let tokens = try tokenize(input)
        guard !tokens.isEmpty else { return .matchAll }
        var state = ParserState(tokens: tokens)
        let root = try parseOr(&state)
        if !state.isAtEnd {
            throw AgentVMError.cliUsageError(
                detail: "Unexpected trailing token #\(state.index + 1) in wiretap filter '\(input)'."
            )
        }
        return root
    }

    private static func parseOr(_ state: inout ParserState) throws -> WiretapFilterExpression {
        var left = try parseAnd(&state)
        while state.peek() == .logicalOr {
            _ = state.advance()
            let right = try parseAnd(&state)
            left = .or(left, right)
        }
        return left
    }

    private static func parseAnd(_ state: inout ParserState) throws -> WiretapFilterExpression {
        var left = try parseUnary(&state)
        while state.peek() == .logicalAnd {
            _ = state.advance()
            let right = try parseUnary(&state)
            left = .and(left, right)
        }
        return left
    }

    private static func parseUnary(_ state: inout ParserState) throws -> WiretapFilterExpression {
        if state.peek() == .logicalNot {
            _ = state.advance()
            let inner = try parseUnary(&state)
            return .not(inner)
        }
        return try parsePrimary(&state)
    }

    private static func parsePrimary(_ state: inout ParserState) throws -> WiretapFilterExpression {
        guard let token = state.advance() else {
            throw AgentVMError.cliUsageError(detail: "Unexpected end of wiretap filter expression.")
        }

        switch token {
        case .leftParen:
            let nested = try parseOr(&state)
            guard state.advance() == .rightParen else {
                throw AgentVMError.cliUsageError(detail: "Missing closing ')' in wiretap filter expression.")
            }
            return nested

        case let .word(lhsText, lhsQuoted):
            if !lhsQuoted {
                // Case 1: Symbolic comparison operator (`field == value`, `port >= 1024`, etc.)
                if case let .symbolicOp(op)? = state.peek() {
                    _ = state.advance()
                    guard let field = WiretapFilterField(alias: lhsText) else {
                        throw AgentVMError.cliUsageError(
                            detail: "Unknown wiretap filter field '\(lhsText)'."
                        )
                    }
                    let rhsValue = try consumeComparisonValue(&state, fieldName: lhsText, op: op)
                    return .comparison(field: field, op: op, value: rhsValue)
                }

                // Case 2: Word comparison operator (`sni contains github`, `dns endsWith .io`, etc.)
                if case let .word(opWord, false)? = state.peek(),
                   let wordOp = parseKeywordOperator(opWord) {
                    guard let field = WiretapFilterField(alias: lhsText) else {
                        throw AgentVMError.cliUsageError(
                            detail: "Unknown wiretap filter field '\(lhsText)' before '\(opWord)'."
                        )
                    }
                    _ = state.advance()
                    let rhsValue = try consumeComparisonValue(&state, fieldName: lhsText, op: wordOp)
                    return .comparison(field: field, op: wordOp, value: rhsValue)
                }
            }

            // Case 3: Bare protocol name or plain substring fallback term
            if !lhsQuoted && lhsText == "*" {
                return .matchAll
            }
            return .substring(lhsText)

        default:
            throw AgentVMError.cliUsageError(
                detail: "Unexpected operator or parenthesis in wiretap filter expression."
            )
        }
    }

    private static func parseKeywordOperator(_ raw: String) -> WiretapComparisonOperator? {
        switch raw.lowercased() {
        case "contains", "has":
            return .contains
        case "startswith", "prefix":
            return .startsWith
        case "endswith", "suffix":
            return .endsWith
        case "matches", "glob", "like":
            return .globMatch
        default:
            return nil
        }
    }

    private static func consumeComparisonValue(
        _ state: inout ParserState,
        fieldName: String,
        op: WiretapComparisonOperator
    ) throws -> String {
        guard case let .word(val, _)? = state.advance() else {
            throw AgentVMError.cliUsageError(
                detail: "Expected comparison value after '\(fieldName) \(op.rawValue)'."
            )
        }
        return val
    }

    // MARK: - AST Packet Evaluation

    private static func evaluate(
        _ expr: WiretapFilterExpression,
        against packet: CapturedPacket
    ) -> Bool {
        switch expr {
        case .matchAll:
            return true
        case let .substring(term):
            return matchesPlainSubstring(term: term, packet: packet)
        case let .comparison(field, op, value):
            return evaluateComparison(field: field, op: op, value: value, packet: packet)
        case let .not(inner):
            return !evaluate(inner, against: packet)
        case let .and(lhs, rhs):
            return evaluate(lhs, against: packet) && evaluate(rhs, against: packet)
        case let .or(lhs, rhs):
            return evaluate(lhs, against: packet) || evaluate(rhs, against: packet)
        }
    }

    private static func evaluateComparison(
        field: WiretapFilterField,
        op: WiretapComparisonOperator,
        value: String,
        packet: CapturedPacket
    ) -> Bool {
        switch field {
        case .proto:
            var protos = [packet.highestProtocol.rawValue]
            for layer in packet.dissectedLayers {
                protos.append(layer.protocolKind.rawValue)
            }
            return evaluateStringCandidates(protos, op: op, target: value)

        case .verdict:
            var candidates = [packet.verdict.rawValue]
            switch packet.verdict {
            case .dnsSinkhole: candidates.append("SINKHOLE")
            case .rejectRST: candidates.append(contentsOf: ["REJECT", "RST"])
            case .rateLimited: candidates.append(contentsOf: ["RATELIMIT", "RATELIMITED"])
            case .pluginBlocked: candidates.append(contentsOf: ["PLUGIN", "BLOCKED"])
            case .allow, .drop: break
            }
            return evaluateStringCandidates(candidates, op: op, target: value)

        case .direction:
            return evaluateStringCandidates([packet.direction.rawValue], op: op, target: value)

        case .vm:
            return evaluateStringCandidates([packet.vmID.rawValue], op: op, target: value)

        case .ip:
            let candidates = [packet.sourceIP, packet.destinationIP].compactMap { $0 }
            return evaluateIPCandidates(candidates, op: op, target: value)

        case .srcIP:
            let candidates = [packet.sourceIP].compactMap { $0 }
            return evaluateIPCandidates(candidates, op: op, target: value)

        case .dstIP:
            let candidates = [packet.destinationIP].compactMap { $0 }
            return evaluateIPCandidates(candidates, op: op, target: value)

        case .mac:
            return evaluateStringCandidates([packet.sourceMAC, packet.destinationMAC], op: op, target: value)

        case .srcMAC:
            return evaluateStringCandidates([packet.sourceMAC], op: op, target: value)

        case .dstMAC:
            return evaluateStringCandidates([packet.destinationMAC], op: op, target: value)

        case .port:
            let ports = [packet.sourcePort, packet.destinationPort].compactMap { $0 }.map(Int.init)
            return evaluateNumericCandidates(ports, op: op, target: value)

        case .srcPort:
            let ports = [packet.sourcePort].compactMap { $0 }.map(Int.init)
            return evaluateNumericCandidates(ports, op: op, target: value)

        case .dstPort:
            let ports = [packet.destinationPort].compactMap { $0 }.map(Int.init)
            return evaluateNumericCandidates(ports, op: op, target: value)

        case .sni:
            let candidates = [packet.tlsSNI].compactMap { $0 }
            return evaluateStringCandidates(candidates, op: op, target: value)

        case .alpn:
            return evaluateStringCandidates(packet.tlsALPN, op: op, target: value)

        case .dns:
            let candidates = [packet.dnsQueryName].compactMap { $0 }
            return evaluateStringCandidates(candidates, op: op, target: value)

        case .httpHost:
            let candidates = [packet.httpHost].compactMap { $0 }
            return evaluateStringCandidates(candidates, op: op, target: value)

        case .http:
            let candidates = [packet.httpRequestLine, packet.httpHost].compactMap { $0 }
            return evaluateStringCandidates(candidates, op: op, target: value)

        case .domain:
            let candidates = [packet.tlsSNI, packet.dnsQueryName, packet.httpHost].compactMap { $0 }
            return evaluateStringCandidates(candidates, op: op, target: value)

        case .flags:
            guard let flags = packet.tcpFlags else {
                return op == .notEqual
            }
            let tokens = flags.description.split(separator: ",").map(String.init) + [flags.description]
            return evaluateStringCandidates(tokens, op: op, target: value)

        case .rule:
            let candidates = [packet.matchedRuleID?.rawValue].compactMap { $0 }
            return evaluateStringCandidates(candidates, op: op, target: value)

        case .vlan:
            let vlans = [packet.vlanID].compactMap { $0 }.map(Int.init)
            return evaluateNumericCandidates(vlans, op: op, target: value)

        case .length:
            return evaluateNumericCandidates([packet.frameLength], op: op, target: value)

        case .info:
            return evaluateStringCandidates([packet.infoSummary, packet.verdictReason], op: op, target: value)
        }
    }

    private static func evaluateIPCandidates(
        _ candidates: [String],
        op: WiretapComparisonOperator,
        target: String
    ) -> Bool {
        if target.contains("/"), let cidr = IPv4CIDR(parsing: target) {
            let anyInCIDR = candidates.contains { raw in
                guard let ip = IPv4Address(parsing: raw) else { return false }
                return cidr.contains(ip)
            }
            switch op {
            case .equal, .contains, .globMatch:
                return anyInCIDR
            case .notEqual:
                return !anyInCIDR
            default:
                break
            }
        }
        return evaluateStringCandidates(candidates, op: op, target: target)
    }

    private static func evaluateNumericCandidates(
        _ candidates: [Int],
        op: WiretapComparisonOperator,
        target: String
    ) -> Bool {
        guard let rhs = Int(target) else {
            let asStrings = candidates.map(String.init)
            return evaluateStringCandidates(asStrings, op: op, target: target)
        }
        if candidates.isEmpty {
            return op == .notEqual
        }
        switch op {
        case .equal:
            return candidates.contains(rhs)
        case .notEqual:
            return !candidates.contains(rhs)
        case .greaterThan:
            return candidates.contains { $0 > rhs }
        case .greaterOrEqual:
            return candidates.contains { $0 >= rhs }
        case .lessThan:
            return candidates.contains { $0 < rhs }
        case .lessOrEqual:
            return candidates.contains { $0 <= rhs }
        case .contains, .startsWith, .endsWith, .globMatch:
            return evaluateStringCandidates(candidates.map(String.init), op: op, target: target)
        }
    }

    private static func evaluateStringCandidates(
        _ candidates: [String],
        op: WiretapComparisonOperator,
        target: String
    ) -> Bool {
        if candidates.isEmpty {
            return op == .notEqual
        }
        let needle = target.lowercased()
        let hasWildcard = needle.contains("*") || needle.contains("?")

        switch op {
        case .equal:
            return candidates.contains { cand in
                if hasWildcard {
                    return GlobPatternMatcher.matches(pattern: needle, candidate: cand)
                }
                return cand.lowercased() == needle
            }
        case .notEqual:
            return !candidates.contains { cand in
                if hasWildcard {
                    return GlobPatternMatcher.matches(pattern: needle, candidate: cand)
                }
                return cand.lowercased() == needle
            }
        case .contains:
            return candidates.contains { cand in
                if hasWildcard {
                    return GlobPatternMatcher.matches(pattern: needle, candidate: cand)
                }
                return cand.lowercased().contains(needle)
            }
        case .startsWith:
            return candidates.contains { $0.lowercased().hasPrefix(needle) }
        case .endsWith:
            return candidates.contains { $0.lowercased().hasSuffix(needle) }
        case .globMatch:
            let glob = hasWildcard ? needle : "*\(needle)*"
            return candidates.contains { GlobPatternMatcher.matches(pattern: glob, candidate: $0) }
        case .greaterThan:
            return candidates.contains { $0.lowercased() > needle }
        case .greaterOrEqual:
            return candidates.contains { $0.lowercased() >= needle }
        case .lessThan:
            return candidates.contains { $0.lowercased() < needle }
        case .lessOrEqual:
            return candidates.contains { $0.lowercased() <= needle }
        }
    }

    private static func matchesPlainSubstring(term: String, packet: CapturedPacket) -> Bool {
        let needle = term.lowercased()
        guard !needle.isEmpty else { return true }

        if packet.highestProtocol.rawValue.lowercased().contains(needle) { return true }
        if packet.verdict.rawValue.lowercased().contains(needle) { return true }
        if packet.vmID.rawValue.lowercased().contains(needle) { return true }
        if packet.direction.rawValue.lowercased().contains(needle) { return true }
        if packet.infoSummary.lowercased().contains(needle) { return true }
        if packet.verdictReason.lowercased().contains(needle) { return true }
        if packet.sourceMAC.lowercased().contains(needle) { return true }
        if packet.destinationMAC.lowercased().contains(needle) { return true }
        if let sip = packet.sourceIP, sip.lowercased().contains(needle) { return true }
        if let dip = packet.destinationIP, dip.lowercased().contains(needle) { return true }
        if let sp = packet.sourcePort, String(sp).contains(needle) { return true }
        if let dp = packet.destinationPort, String(dp).contains(needle) { return true }
        if let sni = packet.tlsSNI, sni.lowercased().contains(needle) { return true }
        if packet.tlsALPN.contains(where: { $0.lowercased().contains(needle) }) { return true }
        if let qname = packet.dnsQueryName, qname.lowercased().contains(needle) { return true }
        if let host = packet.httpHost, host.lowercased().contains(needle) { return true }
        if let req = packet.httpRequestLine, req.lowercased().contains(needle) { return true }
        if let rule = packet.matchedRuleID?.rawValue, rule.lowercased().contains(needle) { return true }
        if let flags = packet.tcpFlags?.description, flags.lowercased().contains(needle) { return true }
        if packet.dissectedLayers.contains(where: { $0.protocolKind.rawValue.lowercased() == needle }) { return true }

        return false
    }
}
