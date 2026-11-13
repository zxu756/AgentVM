import AgentVMModels
import Foundation

// MARK: - Auxiliary Firewall Inspection & Policy Analysis Models

public struct FirewallDNSCorrelationRecord: Codable, Hashable, Sendable, Identifiable {
    public var id: String { ipv4.description }
    public var ipv4: IPv4Address
    public var domain: String
    public var recordedAt: Date
    public var expiresAt: Date

    public init(ipv4: IPv4Address, domain: String, recordedAt: Date, expiresAt: Date) {
        self.ipv4 = ipv4
        self.domain = domain
        self.recordedAt = recordedAt
        self.expiresAt = expiresAt
    }

    public func isExpired(at referenceDate: Date = Date()) -> Bool {
        referenceDate >= expiresAt
    }
}

public struct FirewallEngineMetrics: Codable, Hashable, Sendable {
    public var evaluatedPacketsTotal: UInt64
    public var allowedPacketsTotal: UInt64
    public var droppedPacketsTotal: UInt64
    public var rejectedRSTPacketsTotal: UInt64
    public var sinkholedDNSPacketsTotal: UInt64
    public var rateLimitedPacketsTotal: UInt64
    public var metadataBlockedPacketsTotal: UInt64
    public var activeFlowCount: Int
    public var cachedDNSMappingsCount: Int

    public init(
        evaluatedPacketsTotal: UInt64 = 0,
        allowedPacketsTotal: UInt64 = 0,
        droppedPacketsTotal: UInt64 = 0,
        rejectedRSTPacketsTotal: UInt64 = 0,
        sinkholedDNSPacketsTotal: UInt64 = 0,
        rateLimitedPacketsTotal: UInt64 = 0,
        metadataBlockedPacketsTotal: UInt64 = 0,
        activeFlowCount: Int = 0,
        cachedDNSMappingsCount: Int = 0
    ) {
        self.evaluatedPacketsTotal = evaluatedPacketsTotal
        self.allowedPacketsTotal = allowedPacketsTotal
        self.droppedPacketsTotal = droppedPacketsTotal
        self.rejectedRSTPacketsTotal = rejectedRSTPacketsTotal
        self.sinkholedDNSPacketsTotal = sinkholedDNSPacketsTotal
        self.rateLimitedPacketsTotal = rateLimitedPacketsTotal
        self.metadataBlockedPacketsTotal = metadataBlockedPacketsTotal
        self.activeFlowCount = activeFlowCount
        self.cachedDNSMappingsCount = cachedDNSMappingsCount
    }
}

public struct FirewallRuleConflictFinding: Codable, Hashable, Sendable, Identifiable {
    public var id: String { "\(shadowedRuleID.rawValue)-by-\(precedingRuleID.rawValue)" }
    public var precedingRuleID: RuleID
    public var shadowedRuleID: RuleID
    public var severity: DiagnosticSeverity
    public var explanation: String

    public init(
        precedingRuleID: RuleID,
        shadowedRuleID: RuleID,
        severity: DiagnosticSeverity = .warning,
        explanation: String
    ) {
        self.precedingRuleID = precedingRuleID
        self.shadowedRuleID = shadowedRuleID
        self.severity = severity
        self.explanation = explanation
    }
}

// MARK: - Stateful L3 / L4 / L7 Deep Packet Inspection Egress Firewall Actor

public actor EgressFirewallEngine {
    private static let cloudMetadataIPv4 = IPv4Address(a: 169, b: 254, c: 169, d: 254)

    private struct TokenBucketState: Sendable {
        var byteTokens: Double
        var maxByteTokens: Double
        var byteRefillPerSec: Double

        var packetTokens: Double
        var maxPacketTokens: Double
        var packetRefillPerSec: Double

        var lastRefillUptimeSeconds: Double

        mutating func refill(nowUptime: Double) {
            let elapsed = max(0.0, nowUptime - lastRefillUptimeSeconds)
            lastRefillUptimeSeconds = nowUptime
            if elapsed > 0 {
                if byteRefillPerSec > 0 {
                    byteTokens = min(maxByteTokens, byteTokens + elapsed * byteRefillPerSec)
                }
                if packetRefillPerSec > 0 {
                    packetTokens = min(maxPacketTokens, packetTokens + elapsed * packetRefillPerSec)
                }
            }
        }

        mutating func tryConsume(frameBytes: Int, nowUptime: Double) -> Bool {
            refill(nowUptime: nowUptime)
            let neededBytes = Double(max(1, frameBytes))
            if byteRefillPerSec > 0 && byteTokens < neededBytes {
                return false
            }
            if packetRefillPerSec > 0 && packetTokens < 1.0 {
                return false
            }
            if byteRefillPerSec > 0 {
                byteTokens -= neededBytes
            }
            if packetRefillPerSec > 0 {
                packetTokens -= 1.0
            }
            return true
        }

        func wouldAllow(frameBytes: Int, nowUptime: Double) -> Bool {
            var copy = self
            return copy.tryConsume(frameBytes: frameBytes, nowUptime: nowUptime)
        }
    }

    private struct RateBucketKey: Hashable, Sendable {
        let vmID: VMID
        let ruleID: RuleID
    }

    private struct CanonicalFlowKey: Hashable, Sendable {
        let vmID: VMID
        let transport: DissectedProtocolKind
        let endpointAIP: String
        let endpointAPort: UInt16
        let endpointBIP: String
        let endpointBPort: UInt16

        init(tuple: NetworkFlow5Tuple) {
            self.vmID = tuple.vmID
            self.transport = tuple.transport
            let left = "\(tuple.sourceIP):\(tuple.sourcePort)"
            let right = "\(tuple.destinationIP):\(tuple.destinationPort)"
            if left <= right {
                self.endpointAIP = tuple.sourceIP
                self.endpointAPort = tuple.sourcePort
                self.endpointBIP = tuple.destinationIP
                self.endpointBPort = tuple.destinationPort
            } else {
                self.endpointAIP = tuple.destinationIP
                self.endpointAPort = tuple.destinationPort
                self.endpointBIP = tuple.sourceIP
                self.endpointBPort = tuple.sourcePort
            }
        }
    }

    private struct ManagedFlowState: Sendable {
        var record: NetworkFlowRecord
        var initiatorSourceIP: String
        var initiatorSourcePort: UInt16
        var finFromInitiator: Bool
        var finFromResponder: Bool
    }

    private var policy: FirewallPolicySet
    private var dnsCorrelationByIP: [IPv4Address: FirewallDNSCorrelationRecord] = [:]
    private var flows: [CanonicalFlowKey: ManagedFlowState] = [:]
    private var rateBuckets: [RateBucketKey: TokenBucketState] = [:]

    private var evaluatedPacketsCount: UInt64 = 0
    private var allowedPacketsCount: UInt64 = 0
    private var droppedPacketsCount: UInt64 = 0
    private var rejectedRSTPacketsCount: UInt64 = 0
    private var sinkholedDNSPacketsCount: UInt64 = 0
    private var rateLimitedPacketsCount: UInt64 = 0
    private var metadataBlockedPacketsCount: UInt64 = 0

    public init(policy: FirewallPolicySet = .strictAgentAllowlistPreset()) {
        self.policy = policy
    }

    // MARK: - Policy & DNS Correlation Management

    public func updatePolicy(_ policy: FirewallPolicySet) {
        self.policy = policy
        // Reset token buckets so modified rate limits take effect immediately
        self.rateBuckets.removeAll()
    }

    public func currentPolicy() -> FirewallPolicySet {
        policy
    }

    public func recordDNSResolution(
        domain: String,
        ipv4: IPv4Address,
        ttlSeconds: UInt32 = 300
    ) {
        let normalized = Self.normalizeDomain(domain)
        guard !normalized.isEmpty, ipv4 != .zero, ipv4 != .broadcast else {
            return
        }
        let now = Date()
        let clampedTTL = TimeInterval(max(1, ttlSeconds))
        dnsCorrelationByIP[ipv4] = FirewallDNSCorrelationRecord(
            ipv4: ipv4,
            domain: normalized,
            recordedAt: now,
            expiresAt: now.addingTimeInterval(clampedTTL)
        )
    }

    public func lookupDomain(for ipv4: IPv4Address) -> String? {
        let now = Date()
        guard let entry = dnsCorrelationByIP[ipv4] else { return nil }
        if entry.isExpired(at: now) {
            dnsCorrelationByIP.removeValue(forKey: ipv4)
            return nil
        }
        return entry.domain
    }

    public func dnsCorrelationTable() -> [FirewallDNSCorrelationRecord] {
        let now = Date()
        dnsCorrelationByIP = dnsCorrelationByIP.filter { !$0.value.isExpired(at: now) }
        return dnsCorrelationByIP.values.sorted { $0.ipv4 < $1.ipv4 }
    }

    public func clearDNSCache() {
        dnsCorrelationByIP.removeAll()
    }

    // MARK: - Live Packet Evaluation & Dry-Run Policy Simulation

    public func evaluate(
        _ packet: CapturedPacket
    ) -> (verdict: FirewallVerdict, ruleID: RuleID?, reason: String) {
        // Opportunistically harvest DNS A-record answers from DNS responses
        ingestDNSAnswersIfPresent(from: packet)

        let now = Date()
        let uptimeNow = ProcessInfo.processInfo.systemUptime
        let outcome = runPolicyPipeline(
            on: packet,
            now: now,
            uptimeNow: uptimeNow,
            consumeRateTokens: true
        )

        evaluatedPacketsCount &+= 1
        switch outcome.finalVerdict {
        case .allow:
            allowedPacketsCount &+= 1
        case .drop, .pluginBlocked:
            droppedPacketsCount &+= 1
        case .rejectRST:
            rejectedRSTPacketsCount &+= 1
        case .dnsSinkhole:
            sinkholedDNSPacketsCount &+= 1
        case .rateLimited:
            rateLimitedPacketsCount &+= 1
        }
        if outcome.triggeredMetadataGuard {
            metadataBlockedPacketsCount &+= 1
        }

        updateFlowState(
            for: packet,
            verdict: outcome.finalVerdict,
            matchedRuleID: outcome.winningRuleID,
            effectiveDomain: outcome.effectiveDomain,
            now: now
        )

        return (outcome.finalVerdict, outcome.winningRuleID, outcome.reason)
    }

    public func simulate(_ packet: CapturedPacket) -> FirewallSimulationTrace {
        let now = Date()
        let uptimeNow = ProcessInfo.processInfo.systemUptime
        let outcome = runPolicyPipeline(
            on: packet,
            now: now,
            uptimeNow: uptimeNow,
            consumeRateTokens: false
        )
        return FirewallSimulationTrace(
            policyID: policy.id,
            finalVerdict: outcome.finalVerdict,
            winningRuleID: outcome.winningRuleID,
            reason: outcome.reason,
            evaluatedSteps: outcome.steps
        )
    }

    // MARK: - Stateful Flow Table Inspection

    public func activeFlows() -> [NetworkFlowRecord] {
        flows.values
            .map(\.record)
            .sorted { lhs, rhs in
                if lhs.lastSeenAt != rhs.lastSeenAt {
                    return lhs.lastSeenAt > rhs.lastSeenAt
                }
                return lhs.id < rhs.id
            }
    }

    public func resetFlows() {
        flows.removeAll()
        rateBuckets.removeAll()
    }

    public func metrics() -> FirewallEngineMetrics {
        let now = Date()
        let liveDNSMappings = dnsCorrelationByIP.values.filter { !$0.isExpired(at: now) }.count
        return FirewallEngineMetrics(
            evaluatedPacketsTotal: evaluatedPacketsCount,
            allowedPacketsTotal: allowedPacketsCount,
            droppedPacketsTotal: droppedPacketsCount,
            rejectedRSTPacketsTotal: rejectedRSTPacketsCount,
            sinkholedDNSPacketsTotal: sinkholedDNSPacketsCount,
            rateLimitedPacketsTotal: rateLimitedPacketsCount,
            metadataBlockedPacketsTotal: metadataBlockedPacketsCount,
            activeFlowCount: flows.count,
            cachedDNSMappingsCount: liveDNSMappings
        )
    }

    /// Detects unreachable or shadowed rules inside the active `FirewallPolicySet`.
    public func analyzePolicyConflicts() -> [FirewallRuleConflictFinding] {
        let sorted = sortedRules()
        var findings: [FirewallRuleConflictFinding] = []

        for i in 0..<sorted.count where sorted[i].enabled {
            let earlier = sorted[i]
            let isUnconditionalCatchAll = earlier.conditions.isEmpty
                || earlier.conditions.allSatisfy { $0 == .any }
            guard isUnconditionalCatchAll else { continue }

            for j in (i + 1)..<sorted.count where sorted[j].enabled {
                let later = sorted[j]
                guard later.direction == earlier.direction else { continue }
                findings.append(
                    FirewallRuleConflictFinding(
                        precedingRuleID: earlier.id,
                        shadowedRuleID: later.id,
                        severity: .warning,
                        explanation: "Rule '\(later.name)' (priority \(later.priority)) is shadowed by unconditional rule '\(earlier.name)' (priority \(earlier.priority))."
                    )
                )
            }
        }
        return findings
    }

    // MARK: - Core Policy Evaluation Pipeline

    private struct PipelineOutcome {
        var finalVerdict: FirewallVerdict
        var winningRuleID: RuleID?
        var reason: String
        var steps: [FirewallRuleStepEvaluation]
        var effectiveDomain: String?
        var triggeredMetadataGuard: Bool
    }

    private func runPolicyPipeline(
        on packet: CapturedPacket,
        now: Date,
        uptimeNow: Double,
        consumeRateTokens: Bool
    ) -> PipelineOutcome {
        let parsedSrcIP = packet.sourceIP.flatMap(IPv4Address.init(parsing:))
        let parsedDstIP = packet.destinationIP.flatMap(IPv4Address.init(parsing:))
        let correlatedDomain = resolveInheritedDomain(for: packet, dstIP: parsedDstIP, now: now)

        let isMetadataTarget = policy.blockPrivateMetadataIPs && (
            parsedDstIP == Self.cloudMetadataIPv4 || parsedSrcIP == Self.cloudMetadataIPv4
        )

        let orderedRules = sortedRules()
        var steps: [FirewallRuleStepEvaluation] = []
        steps.reserveCapacity(orderedRules.count)

        var tentativePortOnlyAllow: (rule: FirewallRule, detail: String)? = nil
        var winningRule: FirewallRule? = nil
        var winningDetail: String = ""

        for rule in orderedRules {
            if !rule.enabled {
                steps.append(
                    FirewallRuleStepEvaluation(
                        ruleID: rule.id,
                        ruleName: rule.name,
                        priority: rule.priority,
                        matched: false,
                        detail: "Skipped (rule disabled)"
                    )
                )
                continue
            }

            if !Self.directionMatches(ruleDirection: rule.direction, packetDirection: packet.direction) {
                steps.append(
                    FirewallRuleStepEvaluation(
                        ruleID: rule.id,
                        ruleName: rule.name,
                        priority: rule.priority,
                        matched: false,
                        detail: "Direction mismatch (rule=\(rule.direction.rawValue), packet=\(packet.direction.rawValue))"
                    )
                )
                continue
            }

            let matchEval = evaluateConditions(
                rule.conditions,
                packet: packet,
                srcIP: parsedSrcIP,
                dstIP: parsedDstIP,
                correlatedDomain: correlatedDomain
            )

            steps.append(
                FirewallRuleStepEvaluation(
                    ruleID: rule.id,
                    ruleName: rule.name,
                    priority: rule.priority,
                    matched: matchEval.matched,
                    detail: matchEval.detail
                )
            )

            guard matchEval.matched else { continue }

            // If we previously matched a purely transport/port-only bootstrap allow rule (e.g. dport==53),
            // allow a more specific L3 host CIDR or L7 DPI restrictive rule (e.g. DNS sinkhole or 169.254.169.254)
            // to veto the generic port opener.
            if let existingAllow = tentativePortOnlyAllow {
                if !rule.verdict.isPermitted && Self.hasSpecificL3OrL7Guard(rule.conditions) {
                    winningRule = rule
                    winningDetail = "\(matchEval.detail) [Overrides generic port rule '\(existingAllow.rule.name)']"
                    tentativePortOnlyAllow = nil
                    break
                } else {
                    continue
                }
            }

            if rule.verdict == .allow && Self.isPurePortOrTransportOpener(rule.conditions) {
                tentativePortOnlyAllow = (rule, matchEval.detail)
                continue
            }

            winningRule = rule
            winningDetail = matchEval.detail
            break
        }

        if winningRule == nil, let fallbackAllow = tentativePortOnlyAllow {
            winningRule = fallbackAllow.rule
            winningDetail = fallbackAllow.detail
        }

        // Enforce mandatory RFC 3927 / Cloud Metadata 169.254.169.254 protection if blockPrivateMetadataIPs is active
        if isMetadataTarget {
            if let winner = winningRule, !winner.verdict.isPermitted {
                return PipelineOutcome(
                    finalVerdict: winner.verdict,
                    winningRuleID: winner.id,
                    reason: "Matched rule '\(winner.name)': \(winningDetail)",
                    steps: steps,
                    effectiveDomain: correlatedDomain,
                    triggeredMetadataGuard: true
                )
            }
            return PipelineOutcome(
                finalVerdict: .drop,
                winningRuleID: winningRule?.id,
                reason: "Blocked cloud instance metadata IP 169.254.169.254 (policy.blockPrivateMetadataIPs=true)",
                steps: steps,
                effectiveDomain: correlatedDomain,
                triggeredMetadataGuard: true
            )
        }

        if let winner = winningRule {
            // Check per-rule Token-Bucket Rate Limiters when verdict permits traffic
            if winner.verdict == .allow && (winner.rateLimitKbps != nil || winner.rateLimitPacketsPerSec != nil) {
                let withinLimit = checkRateLimit(
                    for: packet,
                    rule: winner,
                    uptimeNow: uptimeNow,
                    consume: consumeRateTokens
                )
                if !withinLimit {
                    var limitParts: [String] = []
                    if let kbps = winner.rateLimitKbps, kbps > 0 { limitParts.append("\(kbps) kbps") }
                    if let pps = winner.rateLimitPacketsPerSec, pps > 0 { limitParts.append("\(pps) pkt/s") }
                    let capText = limitParts.joined(separator: ", ")
                    return PipelineOutcome(
                        finalVerdict: .rateLimited,
                        winningRuleID: winner.id,
                        reason: "Rate limit exceeded on rule '\(winner.name)' (\(capText))",
                        steps: steps,
                        effectiveDomain: correlatedDomain,
                        triggeredMetadataGuard: false
                    )
                }
            }

            return PipelineOutcome(
                finalVerdict: winner.verdict,
                winningRuleID: winner.id,
                reason: "Matched rule '\(winner.name)': \(winningDetail)",
                steps: steps,
                effectiveDomain: correlatedDomain,
                triggeredMetadataGuard: false
            )
        }

        // Link-local switch control plane (ARP neighbor discovery & gateway ICMP ping) when switch isn't fully air-gapped
        let isTotalAirgap = policy.rules.isEmpty
            && policy.defaultEgressVerdict == .drop
            && policy.defaultIngressVerdict == .drop
        if !isTotalAirgap {
            if packet.highestProtocol == .arp || packet.etherType == 0x0806 {
                return PipelineOutcome(
                    finalVerdict: .allow,
                    winningRuleID: nil,
                    reason: "Permitted link-local L2 ARP neighbor resolution",
                    steps: steps,
                    effectiveDomain: nil,
                    triggeredMetadataGuard: false
                )
            }
            if packet.highestProtocol == .icmp && parsedDstIP == .switchGateway {
                return PipelineOutcome(
                    finalVerdict: .allow,
                    winningRuleID: nil,
                    reason: "Permitted local virtual switch gateway ICMP diagnostic",
                    steps: steps,
                    effectiveDomain: nil,
                    triggeredMetadataGuard: false
                )
            }
        }

        let defaultVerdict: FirewallVerdict
        switch packet.direction {
        case .ingress:
            defaultVerdict = policy.defaultIngressVerdict
        case .egress, .lateralVMToVM:
            defaultVerdict = policy.defaultEgressVerdict
        }

        return PipelineOutcome(
            finalVerdict: defaultVerdict,
            winningRuleID: nil,
            reason: "No rule matched; applied policy default \(packet.direction.rawValue) verdict (\(defaultVerdict.rawValue))",
            steps: steps,
            effectiveDomain: correlatedDomain,
            triggeredMetadataGuard: false
        )
    }

    // MARK: - Condition Matching & DNS Context Inheritance

    private func evaluateConditions(
        _ conditions: [FirewallCondition],
        packet: CapturedPacket,
        srcIP: IPv4Address?,
        dstIP: IPv4Address?,
        correlatedDomain: String?
    ) -> (matched: Bool, detail: String) {
        if conditions.isEmpty {
            return (true, "Unconditional rule matched")
        }

        var matchedClauses: [String] = []
        matchedClauses.reserveCapacity(conditions.count)

        for condition in conditions {
            switch condition {
            case .any:
                matchedClauses.append("*")

            case let .destinationCIDR(cidrString):
                guard let cidr = IPv4CIDR(parsing: cidrString) else {
                    return (false, "Invalid destination CIDR '\(cidrString)'")
                }
                guard let dstIP, cidr.contains(dstIP) else {
                    return (false, "dstIP \(packet.destinationIP ?? "none") not in \(cidrString)")
                }
                matchedClauses.append("dst \(dstIP) in \(cidrString)")

            case let .sourceCIDR(cidrString):
                guard let cidr = IPv4CIDR(parsing: cidrString) else {
                    return (false, "Invalid source CIDR '\(cidrString)'")
                }
                guard let srcIP, cidr.contains(srcIP) else {
                    return (false, "srcIP \(packet.sourceIP ?? "none") not in \(cidrString)")
                }
                matchedClauses.append("src \(srcIP) in \(cidrString)")

            case let .destinationPortRange(lower, upper):
                let lo = min(lower, upper)
                let hi = max(lower, upper)
                guard let dport = packet.destinationPort, (lo...hi).contains(dport) else {
                    return (false, "dport \(packet.destinationPort.map(String.init) ?? "none") outside \(lo)...\(hi)")
                }
                matchedClauses.append("dport == \(dport)")

            case let .transportProtocol(expectedProto):
                guard Self.packetMatchesProtocol(packet, expected: expectedProto) else {
                    return (false, "protocol \(packet.highestProtocol.rawValue) != \(expectedProto.rawValue)")
                }
                matchedClauses.append("proto == \(expectedProto.rawValue)")

            case let .tlsSNIGlob(globPattern):
                // Explicit SNI always takes precedence (prevents domain-fronting spoofing);
                // when SNI is absent (e.g. TCP SYN handshake or post-ClientHello encrypted frames),
                // inherit correlated DNS/flow domain if transport is TCP/TLS.
                let candidateSNI: String?
                let sourceTag: String
                if let explicitSNI = packet.tlsSNI, !explicitSNI.isEmpty {
                    candidateSNI = Self.normalizeDomain(explicitSNI)
                    sourceTag = "tls.sni"
                } else if Self.packetMatchesProtocol(packet, expected: .tcp), let inherited = correlatedDomain {
                    candidateSNI = inherited
                    sourceTag = "dns-correlated"
                } else {
                    candidateSNI = nil
                    sourceTag = "tls.sni"
                }

                guard let sni = candidateSNI,
                      Self.matchesDomainGlob(pattern: globPattern, domain: sni) else {
                    return (false, "\(sourceTag) '\(candidateSNI ?? "none")' !~= \(globPattern)")
                }
                matchedClauses.append("\(sourceTag) '\(sni)' ~= \(globPattern)")

            case let .dnsDomainSuffix(rawSuffix):
                let suffix = Self.normalizeDomain(rawSuffix)
                let candidateDomain: String?
                if let qname = packet.dnsQueryName, !qname.isEmpty {
                    candidateDomain = Self.normalizeDomain(qname)
                } else if let sni = packet.tlsSNI, !sni.isEmpty {
                    candidateDomain = Self.normalizeDomain(sni)
                } else if let host = packet.httpHost, !host.isEmpty {
                    candidateDomain = Self.normalizeDomain(host)
                } else {
                    candidateDomain = correlatedDomain
                }

                guard let domain = candidateDomain,
                      Self.domainMatchesSuffix(domain: domain, suffix: suffix) else {
                    return (false, "domain '\(candidateDomain ?? "none")' does not end with '\(suffix)'")
                }
                matchedClauses.append("domain '\(domain)' endsWith '\(suffix)'")

            case let .httpHostGlob(globPattern):
                let candidateHost: String?
                if let explicitHost = packet.httpHost, !explicitHost.isEmpty {
                    candidateHost = Self.normalizeDomain(explicitHost)
                } else if Self.packetMatchesProtocol(packet, expected: .tcp),
                          packet.tlsSNI == nil,
                          let inherited = correlatedDomain {
                    candidateHost = inherited
                } else {
                    candidateHost = nil
                }

                guard let host = candidateHost,
                      Self.matchesDomainGlob(pattern: globPattern, domain: host) else {
                    return (false, "http.host '\(candidateHost ?? "none")' !~= \(globPattern)")
                }
                matchedClauses.append("http.host '\(host)' ~= \(globPattern)")
            }
        }

        return (true, matchedClauses.joined(separator: " && "))
    }

    private func resolveInheritedDomain(
        for packet: CapturedPacket,
        dstIP: IPv4Address?,
        now: Date
    ) -> String? {
        if let explicitSNI = packet.tlsSNI, !explicitSNI.isEmpty {
            return Self.normalizeDomain(explicitSNI)
        }
        if let explicitHost = packet.httpHost, !explicitHost.isEmpty {
            return Self.normalizeDomain(explicitHost)
        }
        if let explicitQName = packet.dnsQueryName, !explicitQName.isEmpty {
            return Self.normalizeDomain(explicitQName)
        }
        if let tuple = extractFlow5Tuple(from: packet) {
            let key = CanonicalFlowKey(tuple: tuple)
            if let existingDomain = flows[key]?.record.resolvedDomainOrSNI, !existingDomain.isEmpty {
                return existingDomain
            }
        }
        if let dstIP, let entry = dnsCorrelationByIP[dstIP], !entry.isExpired(at: now) {
            return entry.domain
        }
        return nil
    }

    // MARK: - Token-Bucket Rate Limiting

    private func checkRateLimit(
        for packet: CapturedPacket,
        rule: FirewallRule,
        uptimeNow: Double,
        consume: Bool
    ) -> Bool {
        let kbps = max(0, rule.rateLimitKbps ?? 0)
        let pps = max(0, rule.rateLimitPacketsPerSec ?? 0)
        guard kbps > 0 || pps > 0 else { return true }

        let key = RateBucketKey(vmID: packet.vmID, ruleID: rule.id)
        let bytesPerSec = Double(kbps) * 125.0 // 1 kbps = 1000 bits/s = 125 bytes/s
        let pktsPerSec = Double(pps)

        var bucket = rateBuckets[key] ?? TokenBucketState(
            byteTokens: bytesPerSec,
            maxByteTokens: bytesPerSec,
            byteRefillPerSec: bytesPerSec,
            packetTokens: pktsPerSec,
            maxPacketTokens: pktsPerSec,
            packetRefillPerSec: pktsPerSec,
            lastRefillUptimeSeconds: uptimeNow
        )

        if consume {
            let allowed = bucket.tryConsume(frameBytes: packet.rawFrame.count, nowUptime: uptimeNow)
            rateBuckets[key] = bucket
            return allowed
        } else {
            return bucket.wouldAllow(frameBytes: packet.rawFrame.count, nowUptime: uptimeNow)
        }
    }

    // MARK: - 5-Tuple Stateful TCP / UDP Flow Tracking

    private func extractFlow5Tuple(from packet: CapturedPacket) -> NetworkFlow5Tuple? {
        guard let srcIP = packet.sourceIP,
              let dstIP = packet.destinationIP,
              let srcPort = packet.sourcePort,
              let dstPort = packet.destinationPort else {
            return nil
        }

        let transport: DissectedProtocolKind
        if Self.packetMatchesProtocol(packet, expected: .tcp) {
            transport = .tcp
        } else if Self.packetMatchesProtocol(packet, expected: .udp) {
            transport = .udp
        } else {
            return nil
        }

        return NetworkFlow5Tuple(
            vmID: packet.vmID,
            transport: transport,
            sourceIP: srcIP,
            sourcePort: srcPort,
            destinationIP: dstIP,
            destinationPort: dstPort
        )
    }

    private func updateFlowState(
        for packet: CapturedPacket,
        verdict: FirewallVerdict,
        matchedRuleID: RuleID?,
        effectiveDomain: String?,
        now: Date
    ) {
        guard let packetTuple = extractFlow5Tuple(from: packet) else {
            return
        }

        let key = CanonicalFlowKey(tuple: packetTuple)
        let frameLen = UInt64(packet.rawFrame.count)

        if var existing = flows[key] {
            let fromInitiator = (packetTuple.sourceIP == existing.initiatorSourceIP
                && packetTuple.sourcePort == existing.initiatorSourcePort)

            if fromInitiator {
                existing.record.packetsSent &+= 1
                existing.record.bytesSent &+= frameLen
            } else {
                existing.record.packetsReceived &+= 1
                existing.record.bytesReceived &+= frameLen
            }

            if let domain = effectiveDomain, !domain.isEmpty {
                existing.record.resolvedDomainOrSNI = domain
            }
            existing.record.verdict = verdict
            if let matchedRuleID {
                existing.record.matchedRuleID = matchedRuleID
            }
            existing.record.lastSeenAt = now

            if packetTuple.transport == .tcp {
                existing.record.tcpState = advanceTCPState(
                    current: existing.record.tcpState,
                    flags: packet.tcpFlags,
                    verdict: verdict,
                    fromInitiator: fromInitiator,
                    finFromInitiator: &existing.finFromInitiator,
                    finFromResponder: &existing.finFromResponder
                )
            }

            flows[key] = existing
        } else {
            var finInit = false
            var finResp = false
            let initialTCPState: TCPFlowLifecycleState?
            if packetTuple.transport == .tcp {
                initialTCPState = advanceTCPState(
                    current: nil,
                    flags: packet.tcpFlags,
                    verdict: verdict,
                    fromInitiator: true,
                    finFromInitiator: &finInit,
                    finFromResponder: &finResp
                )
            } else {
                initialTCPState = nil
            }

            let isEgressLike = (packet.direction != .ingress)
            let record = NetworkFlowRecord(
                tuple: packetTuple,
                resolvedDomainOrSNI: effectiveDomain,
                tcpState: initialTCPState,
                packetsSent: isEgressLike ? 1 : 0,
                packetsReceived: isEgressLike ? 0 : 1,
                bytesSent: isEgressLike ? frameLen : 0,
                bytesReceived: isEgressLike ? 0 : frameLen,
                verdict: verdict,
                matchedRuleID: matchedRuleID,
                firstSeenAt: now,
                lastSeenAt: now
            )

            flows[key] = ManagedFlowState(
                record: record,
                initiatorSourceIP: packetTuple.sourceIP,
                initiatorSourcePort: packetTuple.sourcePort,
                finFromInitiator: finInit,
                finFromResponder: finResp
            )
        }
    }

    private func advanceTCPState(
        current: TCPFlowLifecycleState?,
        flags: TCPFlags?,
        verdict: FirewallVerdict,
        fromInitiator: Bool,
        finFromInitiator: inout Bool,
        finFromResponder: inout Bool
    ) -> TCPFlowLifecycleState {
        if verdict == .rejectRST {
            return .reset
        }
        guard let flags else {
            return current ?? .synSent
        }
        if flags.contains(.rst) {
            finFromInitiator = false
            finFromResponder = false
            return .reset
        }
        if flags.contains(.fin) {
            if fromInitiator {
                finFromInitiator = true
            } else {
                finFromResponder = true
            }
            if finFromInitiator && finFromResponder {
                return .closed
            }
            return .closing
        }
        if flags.contains(.syn) {
            finFromInitiator = false
            finFromResponder = false
            if flags.contains(.ack) {
                return .synReceived
            }
            return .synSent
        }
        if flags.contains(.ack) {
            switch current {
            case .synSent, .synReceived, .none:
                return .established
            case .closing:
                return (finFromInitiator && finFromResponder) ? .closed : .closing
            case let .some(other):
                return other
            }
        }
        return current ?? .synSent
    }

    private func ingestDNSAnswersIfPresent(from packet: CapturedPacket) {
        guard packet.highestProtocol == .dns, packet.rawFrame.count >= 42 else {
            return
        }
        let bytes = [UInt8](packet.rawFrame)
        var etherType = (UInt16(bytes[12]) << 8) | UInt16(bytes[13])
        var l3Offset = 14
        if etherType == 0x8100 || etherType == 0x88A8 {
            guard bytes.count >= 46 else { return }
            etherType = (UInt16(bytes[16]) << 8) | UInt16(bytes[17])
            l3Offset = 18
        }
        guard etherType == 0x0800, bytes.count >= l3Offset + 28, bytes[l3Offset + 9] == 17 else {
            return
        }
        let ihl = Int(bytes[l3Offset] & 0x0F) * 4
        let udpOffset = l3Offset + ihl
        guard udpOffset + 20 <= bytes.count else { return }
        let udpLen = Int((UInt16(bytes[udpOffset + 4]) << 8) | UInt16(bytes[udpOffset + 5]))
        let dnsOffset = udpOffset + 8
        let dnsEnd = min(bytes.count, udpOffset + udpLen)
        guard dnsEnd - dnsOffset >= 12 else { return }

        let dnsBytes = Array(bytes[dnsOffset..<dnsEnd])
        let flags = (UInt16(dnsBytes[2]) << 8) | UInt16(dnsBytes[3])
        let isResp = (flags & 0x8000) != 0
        let rcode = flags & 0x000F
        let qdCount = Int((UInt16(dnsBytes[4]) << 8) | UInt16(dnsBytes[5]))
        let anCount = Int((UInt16(dnsBytes[6]) << 8) | UInt16(dnsBytes[7]))
        guard isResp, rcode == 0, qdCount >= 1, anCount >= 1 else { return }

        var cursor = 12
        var primaryQuestionDomain: String? = nil
        for q in 0..<qdCount {
            guard let (qname, consumed) = try? PacketDissector.decodeDNSName(in: dnsBytes, at: cursor),
                  cursor + consumed + 4 <= dnsBytes.count else {
                return
            }
            if q == 0 { primaryQuestionDomain = qname }
            cursor += consumed + 4
        }

        for _ in 0..<anCount {
            guard cursor < dnsBytes.count,
                  let (rname, consumed) = try? PacketDissector.decodeDNSName(in: dnsBytes, at: cursor),
                  cursor + consumed + 10 <= dnsBytes.count else {
                return
            }
            let metaOffset = cursor + consumed
            let rtype = (UInt16(dnsBytes[metaOffset]) << 8) | UInt16(dnsBytes[metaOffset + 1])
            let ttl = (UInt32(dnsBytes[metaOffset + 4]) << 24)
                | (UInt32(dnsBytes[metaOffset + 5]) << 16)
                | (UInt32(dnsBytes[metaOffset + 6]) << 8)
                | UInt32(dnsBytes[metaOffset + 7])
            let rdLen = Int((UInt16(dnsBytes[metaOffset + 8]) << 8) | UInt16(dnsBytes[metaOffset + 9]))
            let rdataOffset = metaOffset + 10
            guard rdataOffset + rdLen <= dnsBytes.count else { return }

            if rtype == 1 && rdLen == 4 {
                let ip = IPv4Address(
                    a: dnsBytes[rdataOffset],
                    b: dnsBytes[rdataOffset + 1],
                    c: dnsBytes[rdataOffset + 2],
                    d: dnsBytes[rdataOffset + 3]
                )
                let domainToRecord = primaryQuestionDomain ?? rname
                recordDNSResolution(domain: domainToRecord, ipv4: ip, ttlSeconds: max(30, ttl))
            }
            cursor = rdataOffset + rdLen
        }
    }

    // MARK: - Pure Static Rule Predicates

    private func sortedRules() -> [FirewallRule] {
        policy.rules.sorted { lhs, rhs in
            if lhs.priority != rhs.priority {
                return lhs.priority < rhs.priority
            }
            return lhs.id < rhs.id
        }
    }

    private static func directionMatches(
        ruleDirection: NetworkDirection,
        packetDirection: NetworkDirection
    ) -> Bool {
        if ruleDirection == packetDirection {
            return true
        }
        // Lateral guest-to-guest traffic still honors egress security rules unless a dedicated lateral rule matched
        if packetDirection == .lateralVMToVM && ruleDirection == .egress {
            return true
        }
        return false
    }

    private static func packetMatchesProtocol(
        _ packet: CapturedPacket,
        expected: DissectedProtocolKind
    ) -> Bool {
        if packet.highestProtocol == expected {
            return true
        }
        if packet.dissectedLayers.contains(where: { $0.protocolKind == expected }) {
            return true
        }
        // Fallback inference when unit tests construct lightweight CapturedPacket instances without dissectedLayers
        switch expected {
        case .tcp:
            return packet.tcpFlags != nil
                || packet.highestProtocol == .tls
                || packet.highestProtocol == .http
                || packet.highestProtocol == .ssh
        case .udp:
            return packet.tcpFlags == nil
                && (packet.highestProtocol == .dhcp || packet.highestProtocol == .dns)
        case .ipv4:
            return packet.etherType == 0x0800
        case .ethernet:
            return true
        default:
            return false
        }
    }

    private static func isPurePortOrTransportOpener(_ conditions: [FirewallCondition]) -> Bool {
        guard !conditions.isEmpty else { return false }
        var hasPortOrTransport = false
        for cond in conditions {
            switch cond {
            case .destinationPortRange, .transportProtocol:
                hasPortOrTransport = true
            case .any:
                continue
            case .destinationCIDR, .sourceCIDR, .tlsSNIGlob, .dnsDomainSuffix, .httpHostGlob:
                return false
            }
        }
        return hasPortOrTransport
    }

    private static func hasSpecificL3OrL7Guard(_ conditions: [FirewallCondition]) -> Bool {
        conditions.contains { cond in
            switch cond {
            case .tlsSNIGlob, .dnsDomainSuffix, .httpHostGlob, .destinationCIDR, .sourceCIDR:
                return true
            case .any, .destinationPortRange, .transportProtocol:
                return false
            }
        }
    }

    private static func normalizeDomain(_ raw: String) -> String {
        raw.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
            .lowercased()
    }

    private static func domainMatchesSuffix(domain: String, suffix: String) -> Bool {
        let cleanSuffix = suffix.hasPrefix(".") ? String(suffix.dropFirst()) : suffix
        guard !cleanSuffix.isEmpty else { return false }
        if domain == cleanSuffix {
            return true
        }
        return domain.hasSuffix("." + cleanSuffix)
    }

    private static func matchesDomainGlob(pattern: String, domain: String) -> Bool {
        let cleanPattern = normalizeDomain(pattern)
        if GlobPatternMatcher.matches(pattern: cleanPattern, candidate: domain) {
            return true
        }
        // Also permit "*.example.com" to match apex "example.com" when wildcard subdomain rule is used
        if cleanPattern.hasPrefix("*.") {
            let apex = String(cleanPattern.dropFirst(2))
            if domain == apex {
                return true
            }
        }
        return false
    }
}
