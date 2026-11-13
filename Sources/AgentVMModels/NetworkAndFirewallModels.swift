import Foundation

// MARK: - Layer 2 MAC & Layer 3 IPv4 / CIDR Value Types

public struct MACAddress: Codable, Hashable, Sendable, CustomStringConvertible {
    public let octets: [UInt8] // Guaranteed count == 6

    public init(octets: [UInt8]) {
        precondition(octets.count == 6, "MACAddress requires 6 octets")
        self.octets = octets
    }

    public init?(parsing string: String) {
        let parts = string.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "-", with: ":")
            .split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 6 else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(6)
        for part in parts {
            guard part.count == 1 || part.count == 2,
                  let val = UInt8(part, radix: 16) else {
                return nil
            }
            bytes.append(val)
        }
        self.octets = bytes
    }

    public static let broadcast = MACAddress(octets: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    public static let defaultGateway = MACAddress(octets: [0x52, 0x54, 0x00, 0xA6, 0xE1, 0x01])

    public static func deterministicGuestMAC(seed: String) -> MACAddress {
        var hash: UInt64 = 1469598103934665603
        for b in seed.utf8 {
            hash ^= UInt64(b)
            hash &*= 1099511628211
        }
        return MACAddress(octets: [
            0x52, 0x54, 0x00,
            UInt8((hash >> 16) & 0xFF),
            UInt8((hash >> 8) & 0xFF),
            UInt8(hash & 0xFE)
        ])
    }

    public var isBroadcast: Bool {
        octets == [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
    }

    public var isMulticast: Bool {
        (octets[0] & 0x01) != 0
    }

    public var isLocallyAdministered: Bool {
        (octets[0] & 0x02) != 0
    }

    public var description: String {
        octets.map { String(format: "%02x", $0) }.joined(separator: ":")
    }
}

public struct IPv4Address: Codable, Hashable, Sendable, Comparable, CustomStringConvertible {
    public let rawHostOrder: UInt32

    public init(rawHostOrder: UInt32) {
        self.rawHostOrder = rawHostOrder
    }

    public init(a: UInt8, b: UInt8, c: UInt8, d: UInt8) {
        self.rawHostOrder = (UInt32(a) << 24) | (UInt32(b) << 16) | (UInt32(c) << 8) | UInt32(d)
    }

    public init?(parsing string: String) {
        let parts = string.trimmingCharacters(in: .whitespacesAndNewlines)
            .split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4,
              let a = UInt8(parts[0]),
              let b = UInt8(parts[1]),
              let c = UInt8(parts[2]),
              let d = UInt8(parts[3]) else {
            return nil
        }
        self.init(a: a, b: b, c: c, d: d)
    }

    public static let zero = IPv4Address(rawHostOrder: 0)
    public static let broadcast = IPv4Address(rawHostOrder: 0xFFFF_FFFF)
    public static let loopback = IPv4Address(a: 127, b: 0, c: 0, d: 1)
    public static let switchGateway = IPv4Address(a: 10, b: 211, c: 55, d: 1)

    public var octets: (UInt8, UInt8, UInt8, UInt8) {
        (
            UInt8((rawHostOrder >> 24) & 0xFF),
            UInt8((rawHostOrder >> 16) & 0xFF),
            UInt8((rawHostOrder >> 8) & 0xFF),
            UInt8(rawHostOrder & 0xFF)
        )
    }

    public var octetsArray: [UInt8] {
        let o = octets
        return [o.0, o.1, o.2, o.3]
    }

    public var isPrivateRFC1918: Bool {
        let (a, b, _, _) = octets
        if a == 10 { return true }
        if a == 172 && (16...31).contains(b) { return true }
        if a == 192 && b == 168 { return true }
        return false
    }

    public var isLoopback: Bool {
        octets.0 == 127
    }

    public var isLinkLocal: Bool {
        let (a, b, _, _) = octets
        return a == 169 && b == 254
    }

    public var isMulticast: Bool {
        (224...239).contains(octets.0)
    }

    public var description: String {
        let (a, b, c, d) = octets
        return "\(a).\(b).\(c).\(d)"
    }

    public static func < (lhs: IPv4Address, rhs: IPv4Address) -> Bool {
        lhs.rawHostOrder < rhs.rawHostOrder
    }
}

public struct IPv4CIDR: Codable, Hashable, Sendable, CustomStringConvertible {
    public let networkAddress: IPv4Address
    public let prefixLength: UInt8

    public init?(network: IPv4Address, prefixLength: UInt8) {
        guard prefixLength <= 32 else { return nil }
        let mask: UInt32 = prefixLength == 0 ? 0 : (~UInt32(0) << (32 - UInt32(prefixLength)))
        self.networkAddress = IPv4Address(rawHostOrder: network.rawHostOrder & mask)
        self.prefixLength = prefixLength
    }

    public init?(parsing string: String) {
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = trimmed.split(separator: "/", omittingEmptySubsequences: false)
        if parts.count == 1, let ip = IPv4Address(parsing: String(parts[0])) {
            self.init(network: ip, prefixLength: 32)
            return
        }
        guard parts.count == 2,
              let ip = IPv4Address(parsing: String(parts[0])),
              let plen = UInt8(parts[1]) else {
            return nil
        }
        self.init(network: ip, prefixLength: plen)
    }

    public var netmask: IPv4Address {
        let mask: UInt32 = prefixLength == 0 ? 0 : (~UInt32(0) << (32 - UInt32(prefixLength)))
        return IPv4Address(rawHostOrder: mask)
    }

    public var broadcastAddress: IPv4Address {
        let hostMask = ~netmask.rawHostOrder
        return IPv4Address(rawHostOrder: networkAddress.rawHostOrder | hostMask)
    }

    public func contains(_ address: IPv4Address) -> Bool {
        if prefixLength == 0 { return true }
        return (address.rawHostOrder & netmask.rawHostOrder) == networkAddress.rawHostOrder
    }

    public var description: String {
        "\(networkAddress.description)/\(prefixLength)"
    }
}

// MARK: - Protocol Classification & TCP State

public enum NetworkDirection: String, Codable, Hashable, Sendable, CaseIterable {
    case egress
    case ingress
    case lateralVMToVM = "lateral"
}

public enum DissectedProtocolKind: String, Codable, Hashable, Sendable, CaseIterable {
    case ethernet = "ETH"
    case arp = "ARP"
    case ipv4 = "IPv4"
    case icmp = "ICMP"
    case udp = "UDP"
    case tcp = "TCP"
    case dhcp = "DHCP"
    case dns = "DNS"
    case tls = "TLS"
    case http = "HTTP"
    case ssh = "SSH"
    case unknown = "RAW"
}

public struct TCPFlags: OptionSet, Codable, Hashable, Sendable, CustomStringConvertible {
    public let rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    public static let fin = TCPFlags(rawValue: 1 << 0)
    public static let syn = TCPFlags(rawValue: 1 << 1)
    public static let rst = TCPFlags(rawValue: 1 << 2)
    public static let psh = TCPFlags(rawValue: 1 << 3)
    public static let ack = TCPFlags(rawValue: 1 << 4)
    public static let urg = TCPFlags(rawValue: 1 << 5)
    public static let ece = TCPFlags(rawValue: 1 << 6)
    public static let cwr = TCPFlags(rawValue: 1 << 7)

    public var description: String {
        var tags: [String] = []
        if contains(.syn) { tags.append("SYN") }
        if contains(.ack) { tags.append("ACK") }
        if contains(.psh) { tags.append("PSH") }
        if contains(.fin) { tags.append("FIN") }
        if contains(.rst) { tags.append("RST") }
        if contains(.urg) { tags.append("URG") }
        return tags.isEmpty ? "NONE" : tags.joined(separator: ",")
    }
}

public enum TCPFlowLifecycleState: String, Codable, Hashable, Sendable, CaseIterable {
    case synSent = "SYN_SENT"
    case synReceived = "SYN_RCVD"
    case established = "ESTABLISHED"
    case closing = "FIN_WAIT"
    case closed = "CLOSED"
    case reset = "RESET"
}

// MARK: - Wireshark-Grade Protocol Dissection Tree Models

public struct DissectedField: Codable, Hashable, Sendable, Identifiable {
    public var id: String
    public var label: String
    public var valueSummary: String
    public var byteOffset: Int
    public var byteLength: Int
    public var children: [DissectedField]

    public init(
        id: String = UUID().uuidString,
        label: String,
        valueSummary: String,
        byteOffset: Int,
        byteLength: Int,
        children: [DissectedField] = []
    ) {
        self.id = id
        self.label = label
        self.valueSummary = valueSummary
        self.byteOffset = max(0, byteOffset)
        self.byteLength = max(0, byteLength)
        self.children = children
    }

    public var byteRange: Range<Int> {
        byteOffset..<(byteOffset + byteLength)
    }
}

public struct DissectedLayer: Codable, Hashable, Sendable, Identifiable {
    public var id: String
    public var protocolKind: DissectedProtocolKind
    public var title: String
    public var summary: String
    public var byteOffset: Int
    public var byteLength: Int
    public var fields: [DissectedField]

    public init(
        id: String = UUID().uuidString,
        protocolKind: DissectedProtocolKind,
        title: String,
        summary: String,
        byteOffset: Int,
        byteLength: Int,
        fields: [DissectedField]
    ) {
        self.id = id
        self.protocolKind = protocolKind
        self.title = title
        self.summary = summary
        self.byteOffset = max(0, byteOffset)
        self.byteLength = max(0, byteLength)
        self.fields = fields
    }

    public var byteRange: Range<Int> {
        byteOffset..<(byteOffset + byteLength)
    }
}

// MARK: - Firewall Verdict, Rules & Captured Packet

public enum FirewallVerdict: String, Codable, Hashable, Sendable, CaseIterable {
    case allow = "ALLOW"
    case drop = "DROP"
    case rejectRST = "REJECT_RST"
    case dnsSinkhole = "DNS_SINKHOLE"
    case rateLimited = "RATE_LIMITED"
    case pluginBlocked = "PLUGIN_DROP"

    public var isPermitted: Bool {
        self == .allow
    }
}

public enum FirewallCondition: Codable, Hashable, Sendable {
    case any
    case destinationCIDR(String)
    case sourceCIDR(String)
    case destinationPortRange(lower: UInt16, upper: UInt16)
    case transportProtocol(DissectedProtocolKind)
    case tlsSNIGlob(String)
    case dnsDomainSuffix(String)
    case httpHostGlob(String)

    public var humanReadableSummary: String {
        switch self {
        case .any:
            return "*"
        case let .destinationCIDR(cidr):
            return "dst in \(cidr)"
        case let .sourceCIDR(cidr):
            return "src in \(cidr)"
        case let .destinationPortRange(lower, upper):
            return lower == upper ? "dport == \(lower)" : "dport in \(lower)...\(upper)"
        case let .transportProtocol(proto):
            return "proto == \(proto.rawValue)"
        case let .tlsSNIGlob(glob):
            return "tls.sni ~= \(glob)"
        case let .dnsDomainSuffix(suffix):
            return "dns.qname endsWith \(suffix)"
        case let .httpHostGlob(glob):
            return "http.host ~= \(glob)"
        }
    }
}

public struct FirewallRule: Codable, Hashable, Sendable, Identifiable {
    public var id: RuleID
    public var priority: Int
    public var name: String
    public var enabled: Bool
    public var direction: NetworkDirection
    public var conditions: [FirewallCondition]
    public var verdict: FirewallVerdict
    public var rateLimitKbps: Int?
    public var rateLimitPacketsPerSec: Int?
    public var emitAuditAlert: Bool
    public var rationale: String

    public init(
        id: RuleID = .generate(prefix: "rule"),
        priority: Int,
        name: String,
        enabled: Bool = true,
        direction: NetworkDirection = .egress,
        conditions: [FirewallCondition],
        verdict: FirewallVerdict,
        rateLimitKbps: Int? = nil,
        rateLimitPacketsPerSec: Int? = nil,
        emitAuditAlert: Bool = false,
        rationale: String = ""
    ) {
        self.id = id
        self.priority = priority
        self.name = name
        self.enabled = enabled
        self.direction = direction
        self.conditions = conditions
        self.verdict = verdict
        self.rateLimitKbps = rateLimitKbps
        self.rateLimitPacketsPerSec = rateLimitPacketsPerSec
        self.emitAuditAlert = emitAuditAlert
        self.rationale = rationale
    }
}

public struct FirewallPolicySet: Codable, Hashable, Sendable, Identifiable {
    public var id: PolicySetID
    public var name: String
    public var summary: String
    public var defaultEgressVerdict: FirewallVerdict
    public var defaultIngressVerdict: FirewallVerdict
    public var blockPrivateMetadataIPs: Bool
    public var rules: [FirewallRule]
    public var updatedAt: Date

    public init(
        id: PolicySetID = .generate(prefix: "pol"),
        name: String,
        summary: String,
        defaultEgressVerdict: FirewallVerdict = .drop,
        defaultIngressVerdict: FirewallVerdict = .allow,
        blockPrivateMetadataIPs: Bool = true,
        rules: [FirewallRule],
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.name = name
        self.summary = summary
        self.defaultEgressVerdict = defaultEgressVerdict
        self.defaultIngressVerdict = defaultIngressVerdict
        self.blockPrivateMetadataIPs = blockPrivateMetadataIPs
        self.rules = rules
        self.updatedAt = updatedAt
    }

    public static func strictAgentAllowlistPreset() -> FirewallPolicySet {
        FirewallPolicySet(
            id: PolicySetID("pol-strict-agent-allowlist"),
            name: "Strict Coding-Agent Allowlist",
            summary: "Permits GitHub, PyPI, Crates.io, npm, Anthropic/OpenAI APIs & DNS; drops unknown exfiltration endpoints.",
            defaultEgressVerdict: .drop,
            defaultIngressVerdict: .allow,
            blockPrivateMetadataIPs: true,
            rules: [
                FirewallRule(
                    id: RuleID("rule-allow-switch-dhcp"),
                    priority: 10,
                    name: "Allow Virtual Switch ARP & DHCP",
                    conditions: [.destinationPortRange(lower: 67, upper: 68), .transportProtocol(.udp)],
                    verdict: .allow,
                    rationale: "Required for guest lease bootstrap."
                ),
                FirewallRule(
                    id: RuleID("rule-allow-dns"),
                    priority: 20,
                    name: "Allow Switch DNS Resolver",
                    conditions: [.destinationPortRange(lower: 53, upper: 53)],
                    verdict: .allow,
                    rationale: "Permits audited DNS resolution."
                ),
                FirewallRule(
                    id: RuleID("rule-block-cloud-metadata"),
                    priority: 30,
                    name: "Block Cloud Instance Metadata (169.254.169.254)",
                    conditions: [.destinationCIDR("169.254.169.254/32")],
                    verdict: .drop,
                    emitAuditAlert: true,
                    rationale: "Prevents SSRF metadata credential harvesting."
                ),
                FirewallRule(
                    id: RuleID("rule-allow-github"),
                    priority: 40,
                    name: "Allow GitHub TLS (*.github.com, *.githubusercontent.com)",
                    conditions: [.destinationPortRange(lower: 443, upper: 443), .tlsSNIGlob("*github*")],
                    verdict: .allow,
                    rationale: "Git clone and release artifact pulls."
                ),
                FirewallRule(
                    id: RuleID("rule-allow-registries"),
                    priority: 50,
                    name: "Allow Package Registries (PyPI, npm, crates.io)",
                    conditions: [.destinationPortRange(lower: 443, upper: 443), .tlsSNIGlob("*.pypi.org")],
                    verdict: .allow,
                    rateLimitKbps: 50_000,
                    rationale: "Dependency installation with 50 Mbps burst cap."
                ),
                FirewallRule(
                    id: RuleID("rule-allow-llm-apis"),
                    priority: 60,
                    name: "Allow Frontier Model APIs (Anthropic & OpenAI)",
                    conditions: [.destinationPortRange(lower: 443, upper: 443), .tlsSNIGlob("api.anthropic.com")],
                    verdict: .allow,
                    rationale: "Nested model inference."
                ),
                FirewallRule(
                    id: RuleID("rule-sinkhole-pastebin"),
                    priority: 70,
                    name: "Sinkhole Exfiltration Pastebins & Webhook Sinks",
                    conditions: [.dnsDomainSuffix("webhook.site")],
                    verdict: .dnsSinkhole,
                    emitAuditAlert: true,
                    rationale: "Blocks covert prompt-injection secret exfiltration."
                )
            ]
        )
    }

    public static func airgappedPreset() -> FirewallPolicySet {
        FirewallPolicySet(
            id: PolicySetID("pol-airgap"),
            name: "Total Air-Gap Sandbox",
            summary: "Drops all external L3/L4 egress; permits only VirtioFS and Vsock host channels.",
            defaultEgressVerdict: .drop,
            defaultIngressVerdict: .drop,
            blockPrivateMetadataIPs: true,
            rules: []
        )
    }
}

public struct CapturedPacket: Codable, Hashable, Sendable, Identifiable {
    public var id: PacketID
    public var sequenceNumber: UInt64
    public var timestampMicros: UInt64
    public var vmID: VMID
    public var direction: NetworkDirection
    public var rawFrame: Data
    public var sourceMAC: String
    public var destinationMAC: String
    public var etherType: UInt16
    public var vlanID: UInt16?
    public var sourceIP: String?
    public var destinationIP: String?
    public var sourcePort: UInt16?
    public var destinationPort: UInt16?
    public var highestProtocol: DissectedProtocolKind
    public var tcpFlags: TCPFlags?
    public var dnsQueryName: String?
    public var tlsSNI: String?
    public var tlsALPN: [String]
    public var httpHost: String?
    public var httpRequestLine: String?
    public var infoSummary: String
    public var verdict: FirewallVerdict
    public var matchedRuleID: RuleID?
    public var verdictReason: String
    public var dissectedLayers: [DissectedLayer]

    public init(
        id: PacketID = .generate(prefix: "pkt"),
        sequenceNumber: UInt64,
        timestampMicros: UInt64,
        vmID: VMID,
        direction: NetworkDirection,
        rawFrame: Data,
        sourceMAC: String,
        destinationMAC: String,
        etherType: UInt16,
        vlanID: UInt16? = nil,
        sourceIP: String? = nil,
        destinationIP: String? = nil,
        sourcePort: UInt16? = nil,
        destinationPort: UInt16? = nil,
        highestProtocol: DissectedProtocolKind,
        tcpFlags: TCPFlags? = nil,
        dnsQueryName: String? = nil,
        tlsSNI: String? = nil,
        tlsALPN: [String] = [],
        httpHost: String? = nil,
        httpRequestLine: String? = nil,
        infoSummary: String,
        verdict: FirewallVerdict = .allow,
        matchedRuleID: RuleID? = nil,
        verdictReason: String = "Default policy",
        dissectedLayers: [DissectedLayer] = []
    ) {
        self.id = id
        self.sequenceNumber = sequenceNumber
        self.timestampMicros = timestampMicros
        self.vmID = vmID
        self.direction = direction
        self.rawFrame = rawFrame
        self.sourceMAC = sourceMAC
        self.destinationMAC = destinationMAC
        self.etherType = etherType
        self.vlanID = vlanID
        self.sourceIP = sourceIP
        self.destinationIP = destinationIP
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort
        self.highestProtocol = highestProtocol
        self.tcpFlags = tcpFlags
        self.dnsQueryName = dnsQueryName
        self.tlsSNI = tlsSNI
        self.tlsALPN = tlsALPN
        self.httpHost = httpHost
        self.httpRequestLine = httpRequestLine
        self.infoSummary = infoSummary
        self.verdict = verdict
        self.matchedRuleID = matchedRuleID
        self.verdictReason = verdictReason
        self.dissectedLayers = dissectedLayers
    }

    public var frameLength: Int { rawFrame.count }
}

public struct NetworkFlow5Tuple: Codable, Hashable, Sendable {
    public var vmID: VMID
    public var transport: DissectedProtocolKind
    public var sourceIP: String
    public var sourcePort: UInt16
    public var destinationIP: String
    public var destinationPort: UInt16

    public init(
        vmID: VMID,
        transport: DissectedProtocolKind,
        sourceIP: String,
        sourcePort: UInt16,
        destinationIP: String,
        destinationPort: UInt16
    ) {
        self.vmID = vmID
        self.transport = transport
        self.sourceIP = sourceIP
        self.sourcePort = sourcePort
        self.destinationIP = destinationIP
        self.destinationPort = destinationPort
    }
}

public struct NetworkFlowRecord: Codable, Hashable, Sendable, Identifiable {
    public var id: FlowID
    public var tuple: NetworkFlow5Tuple
    public var resolvedDomainOrSNI: String?
    public var tcpState: TCPFlowLifecycleState?
    public var packetsSent: UInt64
    public var packetsReceived: UInt64
    public var bytesSent: UInt64
    public var bytesReceived: UInt64
    public var verdict: FirewallVerdict
    public var matchedRuleID: RuleID?
    public var firstSeenAt: Date
    public var lastSeenAt: Date

    public init(
        id: FlowID = .generate(prefix: "flow"),
        tuple: NetworkFlow5Tuple,
        resolvedDomainOrSNI: String? = nil,
        tcpState: TCPFlowLifecycleState? = nil,
        packetsSent: UInt64 = 0,
        packetsReceived: UInt64 = 0,
        bytesSent: UInt64 = 0,
        bytesReceived: UInt64 = 0,
        verdict: FirewallVerdict = .allow,
        matchedRuleID: RuleID? = nil,
        firstSeenAt: Date = Date(),
        lastSeenAt: Date = Date()
    ) {
        self.id = id
        self.tuple = tuple
        self.resolvedDomainOrSNI = resolvedDomainOrSNI
        self.tcpState = tcpState
        self.packetsSent = packetsSent
        self.packetsReceived = packetsReceived
        self.bytesSent = bytesSent
        self.bytesReceived = bytesReceived
        self.verdict = verdict
        self.matchedRuleID = matchedRuleID
        self.firstSeenAt = firstSeenAt
        self.lastSeenAt = lastSeenAt
    }
}

public struct FirewallRuleStepEvaluation: Codable, Hashable, Sendable, Identifiable {
    public var id: String { ruleID.rawValue }
    public var ruleID: RuleID
    public var ruleName: String
    public var priority: Int
    public var matched: Bool
    public var detail: String

    public init(ruleID: RuleID, ruleName: String, priority: Int, matched: Bool, detail: String) {
        self.ruleID = ruleID
        self.ruleName = ruleName
        self.priority = priority
        self.matched = matched
        self.detail = detail
    }
}

public struct FirewallSimulationTrace: Codable, Hashable, Sendable {
    public var policyID: PolicySetID
    public var finalVerdict: FirewallVerdict
    public var winningRuleID: RuleID?
    public var reason: String
    public var evaluatedSteps: [FirewallRuleStepEvaluation]

    public init(
        policyID: PolicySetID,
        finalVerdict: FirewallVerdict,
        winningRuleID: RuleID?,
        reason: String,
        evaluatedSteps: [FirewallRuleStepEvaluation]
    ) {
        self.policyID = policyID
        self.finalVerdict = finalVerdict
        self.winningRuleID = winningRuleID
        self.reason = reason
        self.evaluatedSteps = evaluatedSteps
    }
}
