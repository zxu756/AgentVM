import AgentVMModels
import AgentVMNetSwitch
import Darwin
import Foundation
import Testing

@Suite("M04 NetSwitch L2/L3/L4/L7 Dissector, Egress Firewall, PCAPNG & Wiretap", .timeLimit(.minutes(1)))
struct NetSwitchDissectorAndPCAPTests {

    private let guestMAC = MACAddress(octets: [0x52, 0x54, 0x00, 0x10, 0x20, 0x30])
    private let gatewayMAC = MACAddress.defaultGateway
    private let guestIP = IPv4Address(a: 10, b: 211, c: 55, d: 42)
    private let gatewayIP = IPv4Address.switchGateway

    private func makeTemporaryDirectory(prefix: String) throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString.lowercased())", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    // MARK: - 1. PacketFrameCrafter + PacketDissector Byte-Level Round-Trips

    @Test("Ethernet II and IEEE 802.1Q VLAN tagged frames round-trip with exact byte offsets and TCI metadata")
    func ethernetAnd8021QVLANDissectionRoundTrip() throws {
        let crafter = PacketFrameCrafter()
        let dissector = PacketDissector(verifyChecksums: true)

        let rawEth = crafter.buildEthernetFrame(
            srcMAC: guestMAC,
            dstMAC: gatewayMAC,
            etherType: 0x88B5,
            payload: [0xDE, 0xAD, 0xBE, 0xEF]
        )
        let pktEth = try dissector.dissectEthernetFrame(rawEth, sequenceNumber: 1, vmID: VMID("vm-eth"))
        #expect(pktEth.sourceMAC == guestMAC.description)
        #expect(pktEth.destinationMAC == gatewayMAC.description)
        #expect(pktEth.etherType == 0x88B5)
        #expect(pktEth.vlanID == nil)

        let vlanUDP = crafter.buildUDPFrame(
            srcMAC: guestMAC,
            dstMAC: gatewayMAC,
            srcIP: guestIP,
            dstIP: IPv4Address(a: 1, b: 1, c: 1, d: 1),
            srcPort: 50001,
            dstPort: 9999,
            vlanID: 409,
            payload: Data("vlan-tagged-udp".utf8)
        )
        let pktVLAN = try dissector.dissectEthernetFrame(vlanUDP, sequenceNumber: 2, vmID: VMID("vm-vlan"))
        #expect(pktVLAN.vlanID == 409)
        #expect(pktVLAN.etherType == 0x0800)
        #expect(pktVLAN.sourcePort == 50001)
        #expect(pktVLAN.destinationPort == 9999)

        // Frame shorter than 14-byte Ethernet II header must throw ERR_NET_FRAME_MALFORMED
        #expect(throws: AgentVMError.self) {
            _ = try dissector.dissectEthernetFrame(Data([0x01, 0x02, 0x03]), vmID: VMID("vm-short"))
        }
    }

    @Test("ARP Request, ARP Reply, and Gratuitous ARP frames round-trip with accurate RFC 826 fields")
    func arpRequestReplyAndGratuitousRoundTrip() throws {
        let crafter = PacketFrameCrafter()
        let dissector = PacketDissector()

        let arpReq = crafter.buildARPPacket(
            isReply: false,
            senderMAC: guestMAC,
            senderIP: guestIP,
            targetMAC: .broadcast,
            targetIP: gatewayIP
        )
        let dissectedReq = try dissector.dissectEthernetFrame(arpReq, vmID: VMID("vm-arp"))
        #expect(dissectedReq.highestProtocol == .arp)
        #expect(dissectedReq.sourceIP == guestIP.description)
        #expect(dissectedReq.destinationIP == gatewayIP.description)
        #expect(dissectedReq.infoSummary.contains("Who has \(gatewayIP)"))

        let arpReply = crafter.buildARPPacket(
            isReply: true,
            senderMAC: gatewayMAC,
            senderIP: gatewayIP,
            targetMAC: guestMAC,
            targetIP: guestIP
        )
        let hdrReply = try dissector.parseARPHeader(bytes: [UInt8](arpReply), offset: 14)
        #expect(hdrReply.opcode == 2)
        #expect(hdrReply.senderMAC == gatewayMAC)
        #expect(hdrReply.isGratuitous == false)

        let gratuitous = crafter.buildARPPacket(
            isReply: false,
            senderMAC: guestMAC,
            senderIP: guestIP,
            targetMAC: .broadcast,
            targetIP: guestIP
        )
        let hdrGrat = try dissector.parseARPHeader(bytes: [UInt8](gratuitous), offset: 14)
        #expect(hdrGrat.isGratuitous == true)
    }

    @Test("IPv4 RFC 1071 header checksum verification and ICMPv4 Echo / Destination Unreachable dissection")
    func ipv4ChecksumAndICMPv4RoundTrip() throws {
        let crafter = PacketFrameCrafter()
        let dissector = PacketDissector(verifyChecksums: true)

        let echoReq = crafter.buildICMPv4Echo(
            isReply: false,
            srcMAC: guestMAC,
            dstMAC: gatewayMAC,
            srcIP: guestIP,
            dstIP: gatewayIP,
            identifier: 0x4156,
            sequence: 7,
            payload: Data("ping-payload-64".utf8)
        )
        // Verify raw IPv4 header RFC 1071 ones'-complement residual over [14..<34] equals 0x0000
        let rawBytes = [UInt8](echoReq)
        #expect(BinaryChecksums.rfc1071Checksum(Array(rawBytes[14..<34])) == 0x0000)

        let dissectedEcho = try dissector.dissectEthernetFrame(echoReq, vmID: VMID("vm-icmp"))
        #expect(dissectedEcho.highestProtocol == .icmp)
        #expect(dissectedEcho.sourceIP == guestIP.description)
        #expect(dissectedEcho.destinationIP == gatewayIP.description)

        let unreachable = crafter.buildICMPv4DestinationUnreachable(
            code: 3,
            srcMAC: gatewayMAC,
            dstMAC: guestMAC,
            srcIP: gatewayIP,
            dstIP: guestIP,
            quotedIPv4HeaderAndL4Prefix: Data(rawBytes[14..<min(rawBytes.count, 42)])
        )
        let dissectedUnreach = try dissector.dissectEthernetFrame(unreachable, vmID: VMID("vm-icmp"))
        #expect(dissectedUnreach.highestProtocol == .icmp)
        #expect(dissectedUnreach.infoSummary.contains("Unreachable"))
    }

    @Test("DHCPv4 Discover, Offer, Request, and Ack options round-trip through PacketDissector")
    func dhcpv4FullDORAMessageRoundTrip() throws {
        let crafter = PacketFrameCrafter()
        let dissector = PacketDissector(verifyChecksums: true)
        let subnetMask = IPv4Address(a: 255, b: 255, c: 255, d: 0)
        let txID: UInt32 = 0xCAFE_2026

        let messageTypes: [(UInt8, IPv4Address)] = [
            (1, .zero),      // DISCOVER
            (2, guestIP),    // OFFER
            (3, guestIP),    // REQUEST
            (5, guestIP)     // ACK
        ]

        for (msgType, yiaddr) in messageTypes {
            let frame = crafter.buildDHCPv4Packet(
                messageType: msgType,
                transactionID: txID,
                clientMAC: guestMAC,
                yourIP: yiaddr,
                serverIP: gatewayIP,
                subnetMask: subnetMask,
                routerIP: gatewayIP,
                dnsServers: [gatewayIP, IPv4Address(a: 1, b: 1, c: 1, d: 1)],
                leaseSeconds: 43_200,
                hostname: "agent-blade-01"
            )
            let pkt = try dissector.dissectEthernetFrame(frame, vmID: VMID("vm-dhcp"))
            #expect(pkt.highestProtocol == .dhcp)
            #expect(pkt.infoSummary.contains("DHCP"))
        }
    }

    @Test("DNS Query and Response round-trip with RFC 1035 0xC00C label compression")
    func dnsQueryAndCompressedResponseRoundTrip() throws {
        let crafter = PacketFrameCrafter()
        let dissector = PacketDissector(verifyChecksums: true)
        let resolvedAnthropic = IPv4Address(a: 160, b: 79, c: 104, d: 10)

        let queryFrame = crafter.buildDNSQuery(
            srcMAC: guestMAC,
            dstMAC: gatewayMAC,
            srcIP: guestIP,
            dstIP: gatewayIP,
            srcPort: 54321,
            transactionID: 0x7788,
            qname: "api.anthropic.com",
            qtype: 1
        )
        let dissectedQuery = try dissector.dissectEthernetFrame(queryFrame, vmID: VMID("vm-dns"))
        #expect(dissectedQuery.highestProtocol == .dns)
        #expect(dissectedQuery.dnsQueryName == "api.anthropic.com")

        let responseFrame = try crafter.buildDNSResponse(
            forRequest: queryFrame,
            resolvedIPv4: resolvedAnthropic,
            rcode: 0,
            ttl: 300
        )
        // Confirm answer section uses 2-byte RFC 1035 compression pointer 0xC0 0x0C
        #expect(responseFrame.contains(0xC0))
        let dissectedResp = try dissector.dissectEthernetFrame(responseFrame, vmID: VMID("vm-dns"), direction: .ingress)
        #expect(dissectedResp.highestProtocol == .dns)
        #expect(dissectedResp.dnsQueryName == "api.anthropic.com")
        #expect(dissectedResp.infoSummary.contains("160.79.104.10"))
    }

    @Test("PacketDissector.decodeDNSName rejects self-referential and mutual RFC 1035 compression pointer loops")
    func dnsMaliciousPointerLoopRejection() {
        // Self-loop at offset 12: [0xC0, 0x0C] jumps back to offset 12 infinitely unless guarded
        var selfLoopDNS = [UInt8](repeating: 0, count: 16)
        selfLoopDNS[12] = 0xC0
        selfLoopDNS[13] = 0x0C

        do {
            _ = try PacketDissector.decodeDNSName(in: selfLoopDNS, at: 12)
            Issue.record("Expected decodeDNSName to reject self-referential pointer loop")
        } catch let error as AgentVMError {
            #expect(error.errorCode == "ERR_NET_FRAME_MALFORMED")
        } catch {
            Issue.record("Unexpected error: \(error)")
        }

        // Mutual 2-hop cycle: offset 12 -> 14 -> 12
        var mutualLoopDNS = [UInt8](repeating: 0, count: 20)
        mutualLoopDNS[12] = 0xC0
        mutualLoopDNS[13] = 0x0E
        mutualLoopDNS[14] = 0xC0
        mutualLoopDNS[15] = 0x0C

        #expect(throws: AgentVMError.self) {
            _ = try PacketDissector.decodeDNSName(in: mutualLoopDNS, at: 12)
        }
    }

    @Test("TCP SYN/ACK segments and RFC 793 buildTCPRSTReply round-trip with verified transport checksums")
    func tcpFlagsAndRSTReplyRoundTrip() throws {
        let crafter = PacketFrameCrafter()
        let dissector = PacketDissector(verifyChecksums: true)
        let remoteIP = IPv4Address(a: 140, b: 82, c: 112, d: 4)

        let synFrame = crafter.buildTCPFrame(
            srcMAC: guestMAC,
            dstMAC: gatewayMAC,
            srcIP: guestIP,
            dstIP: remoteIP,
            srcPort: 51234,
            dstPort: 443,
            seq: 10_000,
            ack: 0,
            flags: [.syn],
            window: 65535
        )
        let synPkt = try dissector.dissectEthernetFrame(synFrame, vmID: VMID("vm-tcp"))
        #expect(synPkt.highestProtocol == .tcp)
        #expect(synPkt.tcpFlags == [.syn])
        #expect(synPkt.sourcePort == 51234)
        #expect(synPkt.destinationPort == 443)

        let rstReply = try crafter.buildTCPRSTReply(forIncomingFrame: synFrame)
        let rstPkt = try dissector.dissectEthernetFrame(rstReply, vmID: VMID("vm-tcp"), direction: .ingress)
        #expect(rstPkt.tcpFlags?.contains(.rst) == true)
        #expect(rstPkt.tcpFlags?.contains(.ack) == true)
        #expect(rstPkt.sourceIP == remoteIP.description)
        #expect(rstPkt.destinationIP == guestIP.description)
    }

    @Test("TLS 1.3 ClientHello extracts SNI ('api.anthropic.com') and ALPN ('h2', 'http/1.1') without decryption")
    func tls13ClientHelloSNIAndALPNDissection() throws {
        let crafter = PacketFrameCrafter()
        let dissector = PacketDissector(verifyChecksums: true)
        let anthropicIP = IPv4Address(a: 160, b: 79, c: 104, d: 10)

        let clientHelloPayload = crafter.buildTLSClientHelloPayload(
            serverName: "api.anthropic.com",
            alpnProtocols: ["h2", "http/1.1"]
        )
        let tlsFrame = crafter.buildTCPFrame(
            srcMAC: guestMAC,
            dstMAC: gatewayMAC,
            srcIP: guestIP,
            dstIP: anthropicIP,
            srcPort: 52100,
            dstPort: 443,
            seq: 1001,
            ack: 2001,
            flags: [.psh, .ack],
            payload: clientHelloPayload
        )

        let pkt = try dissector.dissectEthernetFrame(tlsFrame, vmID: VMID("vm-tls"))
        #expect(pkt.highestProtocol == .tls)
        #expect(pkt.tlsSNI == "api.anthropic.com")
        #expect(pkt.tlsALPN == ["h2", "http/1.1"])
        #expect(pkt.infoSummary.contains("api.anthropic.com"))
    }

    @Test("HTTP/1.1 request dissection extracts Host header and method/target request line")
    func http11RequestLineAndHostExtraction() throws {
        let crafter = PacketFrameCrafter()
        let dissector = PacketDissector(verifyChecksums: true)

        let httpPayload = crafter.buildHTTPRequestPayload(
            method: "POST",
            path: "/v1/messages",
            host: "proxy.internal.local:8080",
            extraHeaders: [("Content-Type", "application/json")],
            body: Data("{\"ping\":true}".utf8)
        )
        let httpFrame = crafter.buildTCPFrame(
            srcMAC: guestMAC,
            dstMAC: gatewayMAC,
            srcIP: guestIP,
            dstIP: IPv4Address(a: 10, b: 0, c: 0, d: 99),
            srcPort: 53000,
            dstPort: 8080,
            seq: 500,
            ack: 600,
            flags: [.psh, .ack],
            payload: httpPayload
        )

        let pkt = try dissector.dissectEthernetFrame(httpFrame, vmID: VMID("vm-http"))
        #expect(pkt.highestProtocol == .http)
        #expect(pkt.httpHost == "proxy.internal.local")
        #expect(pkt.httpRequestLine == "POST /v1/messages HTTP/1.1")
    }

    // MARK: - 2. EgressFirewallEngine DPI Allowlist, SSRF Block, DNS Correlation, Sinkhole, Rate Limit & Flows

    @Test("EgressFirewallEngine strict allowlist permits api.anthropic.com TLS SNI and drops unlisted domains")
    func firewallStrictAllowlistSNIEvaluation() async throws {
        let crafter = PacketFrameCrafter()
        let dissector = PacketDissector()
        let firewall = EgressFirewallEngine(policy: .strictAgentAllowlistPreset())

        let allowedFrame = crafter.buildTCPFrame(
            srcMAC: guestMAC, dstMAC: gatewayMAC,
            srcIP: guestIP, dstIP: IPv4Address(a: 160, b: 79, c: 104, d: 10),
            srcPort: 50100, dstPort: 443, seq: 1, ack: 1, flags: [.psh, .ack],
            payload: crafter.buildTLSClientHelloPayload(serverName: "api.anthropic.com")
        )
        let allowedPkt = try dissector.dissectEthernetFrame(allowedFrame, vmID: VMID("vm-fw"))
        let allowVerdict = await firewall.evaluate(allowedPkt)
        #expect(allowVerdict.verdict == .allow)

        let unlistedFrame = crafter.buildTCPFrame(
            srcMAC: guestMAC, dstMAC: gatewayMAC,
            srcIP: guestIP, dstIP: IPv4Address(a: 203, b: 0, c: 113, d: 77),
            srcPort: 50101, dstPort: 443, seq: 1, ack: 1, flags: [.psh, .ack],
            payload: crafter.buildTLSClientHelloPayload(serverName: "evil-c2.example.org")
        )
        let unlistedPkt = try dissector.dissectEthernetFrame(unlistedFrame, vmID: VMID("vm-fw"))
        let dropVerdict = await firewall.evaluate(unlistedPkt)
        #expect(dropVerdict.verdict == .drop)
    }

    @Test("EgressFirewallEngine blocks 169.254.169.254 cloud metadata SSRF probes and increments metadata counter")
    func firewallCloudMetadataSSRFBlock() async throws {
        let crafter = PacketFrameCrafter()
        let dissector = PacketDissector()
        let firewall = EgressFirewallEngine(policy: .strictAgentAllowlistPreset())

        let metadataIP = IPv4Address(a: 169, b: 254, c: 169, d: 254)
        let ssrfFrame = crafter.buildTCPFrame(
            srcMAC: guestMAC, dstMAC: gatewayMAC,
            srcIP: guestIP, dstIP: metadataIP,
            srcPort: 54000, dstPort: 80, seq: 100, ack: 0, flags: [.syn]
        )
        let ssrfPkt = try dissector.dissectEthernetFrame(ssrfFrame, vmID: VMID("vm-ssrf"))
        let eval = await firewall.evaluate(ssrfPkt)
        #expect(eval.verdict.isPermitted == false)

        let metrics = await firewall.metrics()
        #expect(metrics.metadataBlockedPacketsTotal == 1)
    }

    @Test("EgressFirewallEngine correlates DNS A-record resolutions so bare TCP SYN/ACK packets inherit domain policy")
    func firewallDNSToIPCorrelationInheritance() async throws {
        let crafter = PacketFrameCrafter()
        let dissector = PacketDissector()
        let firewall = EgressFirewallEngine(policy: .strictAgentAllowlistPreset())
        let resolvedIP = IPv4Address(a: 140, b: 82, c: 114, d: 3)

        // Before DNS resolution, a bare TCP ACK carrying no TLS SNI to 140.82.114.3:443 cannot match *.github.com
        let bareACKFrame = crafter.buildTCPFrame(
            srcMAC: guestMAC, dstMAC: gatewayMAC,
            srcIP: guestIP, dstIP: resolvedIP,
            srcPort: 51900, dstPort: 443, seq: 2, ack: 2, flags: [.ack]
        )
        let barePkt = try dissector.dissectEthernetFrame(bareACKFrame, vmID: VMID("vm-dns-corr"))
        let preDNS = await firewall.simulate(barePkt)
        #expect(preDNS.finalVerdict == .drop)

        // Feed DNS response mapping api.github.com -> 140.82.114.3
        let dnsReq = crafter.buildDNSQuery(
            srcMAC: guestMAC, dstMAC: gatewayMAC, srcIP: guestIP, dstIP: gatewayIP,
            transactionID: 0x1020, qname: "api.github.com"
        )
        let dnsResp = try crafter.buildDNSResponse(forRequest: dnsReq, resolvedIPv4: resolvedIP, ttl: 300)
        let dnsRespPkt = try dissector.dissectEthernetFrame(dnsResp, vmID: VMID("vm-dns-corr"), direction: .ingress)
        _ = await firewall.evaluate(dnsRespPkt)

        #expect(await firewall.lookupDomain(for: resolvedIP) == "api.github.com")
        let postDNS = await firewall.evaluate(barePkt)
        #expect(postDNS.verdict == .allow)
    }

    @Test("EgressFirewallEngine sinkholes exfiltration DNS queries to webhook.site")
    func firewallWebhookSiteDNSSinkhole() async throws {
        let crafter = PacketFrameCrafter()
        let dissector = PacketDissector()
        let firewall = EgressFirewallEngine(policy: .strictAgentAllowlistPreset())

        let exfilDNS = crafter.buildDNSQuery(
            srcMAC: guestMAC, dstMAC: gatewayMAC,
            srcIP: guestIP, dstIP: gatewayIP,
            transactionID: 0xDEAD,
            qname: "dropzone.webhook.site"
        )
        let pkt = try dissector.dissectEthernetFrame(exfilDNS, vmID: VMID("vm-sinkhole"))
        let verdict = await firewall.evaluate(pkt)
        #expect(verdict.verdict == .dnsSinkhole)
        #expect(await firewall.metrics().sinkholedDNSPacketsTotal == 1)
    }

    @Test("EgressFirewallEngine enforces per-rule token-bucket packet rate limits and side-effect-free simulate()")
    func firewallTokenBucketRateLimitAndSideEffectFreeSimulate() async throws {
        let crafter = PacketFrameCrafter()
        let dissector = PacketDissector()

        let rateRule = FirewallRule(
            id: RuleID("rule-tight-pps"),
            priority: 10,
            name: "Allow 1 pkt/sec burst",
            direction: .egress,
            conditions: [.destinationPortRange(lower: 8443, upper: 8443)],
            verdict: .allow,
            rateLimitPacketsPerSec: 1
        )
        let policy = FirewallPolicySet(
            id: PolicySetID("pol-rate"),
            name: "Rate Test",
            summary: "Token bucket 1 pkt/sec rate limiting test policy",
            defaultEgressVerdict: .drop,
            rules: [rateRule]
        )
        let firewall = EgressFirewallEngine(policy: policy)

        let frame = crafter.buildTCPFrame(
            srcMAC: guestMAC, dstMAC: gatewayMAC,
            srcIP: guestIP, dstIP: IPv4Address(a: 93, b: 184, c: 216, d: 34),
            srcPort: 55000, dstPort: 8443, seq: 1, ack: 0, flags: [.syn]
        )
        let pkt = try dissector.dissectEthernetFrame(frame, vmID: VMID("vm-rate"))

        // Calling simulate() 5 times must NOT consume any tokens, create flows, or increment counters
        for _ in 0..<5 {
            let sim = await firewall.simulate(pkt)
            #expect(sim.finalVerdict == .allow)
        }
        #expect(await firewall.metrics().evaluatedPacketsTotal == 0)
        #expect(await firewall.activeFlows().isEmpty)

        // Note: TokenBucket initializes burst capacity to max(2.0, rate * 2.0) -> burst of 2 packets, then .rateLimited!
        var verdicts: [FirewallVerdict] = []
        for _ in 0..<5 {
            verdicts.append(await firewall.evaluate(pkt).verdict)
        }
        #expect(verdicts.first == .allow)
        #expect(verdicts.contains(.rateLimited))
        #expect(await firewall.metrics().rateLimitedPacketsTotal >= 1)
    }

    @Test("EgressFirewallEngine tracks TCP 5-tuple flow state transitions from synSent -> established -> reset/closed")
    func firewallTCPFlowStateMachineTransitions() async throws {
        let crafter = PacketFrameCrafter()
        let dissector = PacketDissector()
        let allowAll = FirewallPolicySet(
            id: PolicySetID("pol-flow"),
            name: "Flow Tracker",
            summary: "Permits all TCP flows to exercise 5-tuple state transitions",
            defaultEgressVerdict: .allow,
            blockPrivateMetadataIPs: false,
            rules: [FirewallRule(priority: 1, name: "Allow All", conditions: [.any], verdict: .allow)]
        )
        let firewall = EgressFirewallEngine(policy: allowAll)
        let serverIP = IPv4Address(a: 1, b: 1, c: 1, d: 1)

        // 1. SYN -> .synSent
        let syn = try dissector.dissectEthernetFrame(
            crafter.buildTCPFrame(srcMAC: guestMAC, dstMAC: gatewayMAC, srcIP: guestIP, dstIP: serverIP, srcPort: 60000, dstPort: 443, seq: 100, ack: 0, flags: [.syn]),
            vmID: VMID("vm-tcp-sm")
        )
        _ = await firewall.evaluate(syn)
        #expect(await firewall.activeFlows().first?.tcpState == .synSent)

        // 2. SYN,ACK from responder -> .synReceived / .established on subsequent ACK
        let synAck = try dissector.dissectEthernetFrame(
            crafter.buildTCPFrame(srcMAC: gatewayMAC, dstMAC: guestMAC, srcIP: serverIP, dstIP: guestIP, srcPort: 443, dstPort: 60000, seq: 500, ack: 101, flags: [.syn, .ack]),
            vmID: VMID("vm-tcp-sm"),
            direction: .ingress
        )
        _ = await firewall.evaluate(synAck)

        let ack = try dissector.dissectEthernetFrame(
            crafter.buildTCPFrame(srcMAC: guestMAC, dstMAC: gatewayMAC, srcIP: guestIP, dstIP: serverIP, srcPort: 60000, dstPort: 443, seq: 101, ack: 501, flags: [.ack]),
            vmID: VMID("vm-tcp-sm")
        )
        _ = await firewall.evaluate(ack)
        #expect(await firewall.activeFlows().first?.tcpState == .established)

        // 3. RST -> .reset
        let rst = try dissector.dissectEthernetFrame(
            crafter.buildTCPFrame(srcMAC: guestMAC, dstMAC: gatewayMAC, srcIP: guestIP, dstIP: serverIP, srcPort: 60000, dstPort: 443, seq: 102, ack: 501, flags: [.rst]),
            vmID: VMID("vm-tcp-sm")
        )
        _ = await firewall.evaluate(rst)
        #expect(await firewall.activeFlows().first?.tcpState == .reset)
    }

    @Test("EgressFirewallEngine.analyzePolicyConflicts detects specific rules shadowed by earlier unconditional rules")
    func firewallPolicyConflictShadowDetection() async {
        let catchAllDrop = FirewallRule(
            id: RuleID("rule-catchall"),
            priority: 10,
            name: "Premature Drop All",
            direction: .egress,
            conditions: [.any],
            verdict: .drop
        )
        let unreachableAllow = FirewallRule(
            id: RuleID("rule-shadowed-github"),
            priority: 50,
            name: "Allow GitHub TLS",
            direction: .egress,
            conditions: [.tlsSNIGlob("*.github.com")],
            verdict: .allow
        )
        let policy = FirewallPolicySet(
            id: PolicySetID("pol-conflict"),
            name: "Conflicted Policy",
            summary: "Contains unconditional rule shadowing later specific SNI rule",
            rules: [catchAllDrop, unreachableAllow]
        )
        let firewall = EgressFirewallEngine(policy: policy)
        let conflicts = await firewall.analyzePolicyConflicts()
        #expect(conflicts.count == 1)
        #expect(conflicts.first?.precedingRuleID == catchAllDrop.id)
        #expect(conflicts.first?.shadowedRuleID == unreachableAllow.id)
    }

    // MARK: - 3. PCAPNGCodec, WiretapFilterQuery Boolean AST & UserSpaceL2Switch

    @Test("PCAPNGCodec encodes, inspects, and decodes packets losslessly while preserving verdicts, rules, and special characters")
    func pcapngLosslessEncodeInspectDecodeRoundTrip() throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-pcapng")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let crafter = PacketFrameCrafter()
        let dissector = PacketDissector()
        let codec = PCAPNGCodec()

        var pkt1 = try dissector.dissectEthernetFrame(
            crafter.buildDNSQuery(
                srcMAC: guestMAC, dstMAC: gatewayMAC, srcIP: guestIP, dstIP: gatewayIP,
                transactionID: 0x1111, qname: "api.anthropic.com"
            ),
            sequenceNumber: 10,
            timestampMicros: 1_730_000_000_123_456,
            vmID: VMID("vm-alpha"),
            direction: .egress
        )
        pkt1.verdict = .allow
        pkt1.matchedRuleID = RuleID("rule-dns-allow")
        pkt1.verdictReason = "Matched key=val;pct=100%"

        var pkt2 = try dissector.dissectEthernetFrame(
            crafter.buildTCPFrame(
                srcMAC: gatewayMAC, dstMAC: guestMAC,
                srcIP: IPv4Address(a: 169, b: 254, c: 169, d: 254), dstIP: guestIP,
                srcPort: 80, dstPort: 50500, seq: 0, ack: 1, flags: [.rst, .ack]
            ),
            sequenceNumber: 11,
            timestampMicros: 1_730_000_000_654_321,
            vmID: VMID("vm-beta"),
            direction: .ingress
        )
        pkt2.verdict = .rejectRST
        pkt2.matchedRuleID = RuleID("rule-ssrf-rst")
        pkt2.verdictReason = "Blocked SSRF metadata; injected RST"

        let pcapURL = tempDir.appendingPathComponent("capture.pcapng")
        try codec.writeCaptureFile(packets: [pkt1, pkt2], to: pcapURL, hardwareDescription: "Apple M4 Max Test")

        let rawData = try Data(contentsOf: pcapURL)
        let inspection = try codec.inspectCapture(data: rawData)
        #expect(inspection.sections.count == 1)
        #expect(inspection.sections.first?.hardware == "Apple M4 Max Test")
        #expect(inspection.interfaces.first?.linkType == PCAPNGCodec.linkTypeEthernet)
        #expect(inspection.enhancedPacketBlockCount == 2)
        #expect(inspection.firstTimestampMicros == pkt1.timestampMicros)
        #expect(inspection.lastTimestampMicros == pkt2.timestampMicros)

        let decoded = try codec.readCaptureFile(at: pcapURL)
        #expect(decoded.count == 2)
        #expect(decoded[0].rawFrame == pkt1.rawFrame)
        #expect(decoded[0].vmID == VMID("vm-alpha"))
        #expect(decoded[0].verdict == .allow)
        #expect(decoded[0].matchedRuleID == RuleID("rule-dns-allow"))
        #expect(decoded[0].verdictReason == "Matched key=val;pct=100%")
        #expect(decoded[0].direction == .egress)

        #expect(decoded[1].rawFrame == pkt2.rawFrame)
        #expect(decoded[1].vmID == VMID("vm-beta"))
        #expect(decoded[1].verdict == .rejectRST)
        #expect(decoded[1].direction == .ingress)
    }

    @Test("PCAPNGCodec rejects truncated streams and corrupted block length trailers with ERR_PCAPNG_CORRUPTED")
    func pcapngCorruptedStreamRejection() {
        let codec = PCAPNGCodec()

        #expect(throws: AgentVMError.self) {
            _ = try codec.decodeCapture(data: Data([0x0A, 0x0D, 0x0D, 0x0A]))
        }

        var validEmpty = codec.encodeCapture(packets: [])
        // Corrupt trailing block total length of SHB
        validEmpty[validEmpty.count - 1] ^= 0xFF
        #expect(throws: AgentVMError.self) {
            _ = try codec.inspectCapture(data: validEmpty)
        }
    }

    @Test("WiretapFilterQuery evaluates boolean AST precedence (&&, ||, !, parentheses), CIDR containment, and sni contains")
    func wiretapFilterBooleanASTAndCIDREvaluation() throws {
        let crafter = PacketFrameCrafter()
        let dissector = PacketDissector()

        var tlsAnthropic = try dissector.dissectEthernetFrame(
            crafter.buildTCPFrame(
                srcMAC: guestMAC, dstMAC: gatewayMAC,
                srcIP: guestIP, dstIP: IPv4Address(a: 160, b: 79, c: 104, d: 10),
                srcPort: 50001, dstPort: 443, seq: 1, ack: 1, flags: [.psh, .ack],
                payload: crafter.buildTLSClientHelloPayload(serverName: "api.anthropic.com")
            ),
            vmID: VMID("vm-claude")
        )
        tlsAnthropic.verdict = .allow

        var dnsWebhook = try dissector.dissectEthernetFrame(
            crafter.buildDNSQuery(
                srcMAC: guestMAC, dstMAC: gatewayMAC,
                srcIP: guestIP, dstIP: gatewayIP,
                transactionID: 0x9999, qname: "exfil.webhook.site"
            ),
            vmID: VMID("vm-rogue")
        )
        dnsWebhook.verdict = .dnsSinkhole

        var ssrfDrop = try dissector.dissectEthernetFrame(
            crafter.buildTCPFrame(
                srcMAC: guestMAC, dstMAC: gatewayMAC,
                srcIP: guestIP, dstIP: IPv4Address(a: 169, b: 254, c: 169, d: 254),
                srcPort: 50002, dstPort: 80, seq: 1, ack: 0, flags: [.syn]
            ),
            vmID: VMID("vm-rogue")
        )
        ssrfDrop.verdict = .drop

        let corpus = [tlsAnthropic, dnsWebhook, ssrfDrop]

        let q1 = try WiretapFilterQuery(
            parsing: "(proto == tls && sni contains \"anthropic\") || (ip.dst == 169.254.0.0/16 && !verdict == allow)"
        )
        let matched1 = q1.filter(corpus)
        #expect(matched1.count == 2)
        #expect(matched1.contains { $0.tlsSNI == "api.anthropic.com" })
        #expect(matched1.contains { $0.destinationIP == "169.254.169.254" })

        let q2 = try WiretapFilterQuery(parsing: "vm == \"vm-rogue\" && !(port == 80)")
        let matched2 = q2.filter(corpus)
        #expect(matched2.count == 1)
        #expect(matched2.first?.dnsQueryName == "exfil.webhook.site")

        let suggestions = WiretapFilterQuery.completionSuggestions(forPrefix: "sn")
        #expect(!suggestions.isEmpty)
    }

    @Test("UserSpaceL2Switch answers Gateway ARP, DHCPv4 DORA leases, ICMPv4 Echo, and static/sinkholed DNS")
    func userSpaceL2SwitchARPDHCPICMPAndDNSResponders() async throws {
        let l2Switch = UserSpaceL2Switch(subnetCIDR: "10.211.55.0/24", gatewayIP: "10.211.55.1")
        let crafter = PacketFrameCrafter()
        let dissector = PacketDissector()
        let vmID = VMID("vm-switch-01")

        // 1. DHCPv4 DISCOVER -> OFFER, then REQUEST -> ACK committing lease
        let discover = crafter.buildDHCPv4Packet(
            messageType: 1, transactionID: 0xABCD_0001, clientMAC: guestMAC,
            yourIP: .zero, serverIP: .zero,
            subnetMask: IPv4Address(a: 255, b: 255, c: 255, d: 0),
            routerIP: gatewayIP, dnsServers: [gatewayIP], hostname: "vm-switch-01"
        )
        let offerRes = try await l2Switch.injectFrameFromGuest(vmID: vmID, rawFrame: discover)
        #expect(offerRes.switchGeneratedReplies.count == 1)

        let leasesAfterOffer = await l2Switch.dhcpLeases()
        let offeredIP = try #require(leasesAfterOffer.first?.ipv4Address)

        let request = crafter.buildDHCPv4Packet(
            messageType: 3, transactionID: 0xABCD_0001, clientMAC: guestMAC,
            yourIP: offeredIP, serverIP: gatewayIP,
            subnetMask: IPv4Address(a: 255, b: 255, c: 255, d: 0),
            routerIP: gatewayIP, dnsServers: [gatewayIP], hostname: "vm-switch-01"
        )
        let ackRes = try await l2Switch.injectFrameFromGuest(vmID: vmID, rawFrame: request)
        #expect(ackRes.switchGeneratedReplies.count == 1)
        #expect(await l2Switch.dhcpLeases().first?.isCommittedACK == true)

        // 2. Gateway ARP Request -> ARP Reply
        let arpReq = crafter.buildARPPacket(
            isReply: false, senderMAC: guestMAC, senderIP: offeredIP, targetMAC: .broadcast, targetIP: gatewayIP
        )
        let arpRes = try await l2Switch.injectFrameFromGuest(vmID: vmID, rawFrame: arpReq)
        #expect(arpRes.switchGeneratedReplies.count == 1)
        let arpReplyDissected = try dissector.dissectEthernetFrame(arpRes.switchGeneratedReplies[0], vmID: vmID, direction: .ingress)
        #expect(arpReplyDissected.highestProtocol == .arp)

        // 3. Gateway ICMPv4 Ping -> Echo Reply
        let pingReq = crafter.buildICMPv4Echo(
            isReply: false, srcMAC: guestMAC, dstMAC: gatewayMAC, srcIP: offeredIP, dstIP: gatewayIP,
            identifier: 0x1234, sequence: 1, payload: Data("hello-gw".utf8)
        )
        let pingRes = try await l2Switch.injectFrameFromGuest(vmID: vmID, rawFrame: pingReq)
        #expect(pingRes.switchGeneratedReplies.count == 1)

        // 4. DNS Query for allowed domain -> A record reply; DNS Query for webhook.site -> 0.0.0.0 sinkhole reply
        let dnsAllow = crafter.buildDNSQuery(
            srcMAC: guestMAC, dstMAC: gatewayMAC, srcIP: offeredIP, dstIP: gatewayIP,
            transactionID: 0x2222, qname: "api.anthropic.com"
        )
        let dnsAllowRes = try await l2Switch.injectFrameFromGuest(vmID: vmID, rawFrame: dnsAllow)
        #expect(dnsAllowRes.captured.verdict == .allow)
        #expect(dnsAllowRes.switchGeneratedReplies.count == 1)

        let dnsSink = crafter.buildDNSQuery(
            srcMAC: guestMAC, dstMAC: gatewayMAC, srcIP: offeredIP, dstIP: gatewayIP,
            transactionID: 0x3333, qname: "leak.webhook.site"
        )
        let dnsSinkRes = try await l2Switch.injectFrameFromGuest(vmID: vmID, rawFrame: dnsSink)
        #expect(dnsSinkRes.captured.verdict == .dnsSinkhole)
        #expect(dnsSinkRes.switchGeneratedReplies.count == 1)
        let sinkReplyPkt = try dissector.dissectEthernetFrame(dnsSinkRes.switchGeneratedReplies[0], vmID: vmID, direction: .ingress)
        #expect(sinkReplyPkt.infoSummary.contains("0.0.0.0"))
    }

    @Test("UserSpaceL2Switch creates AF_UNIX SOCK_DGRAM socketpairs and relays live datagrams end-to-end")
    func userSpaceL2SwitchSocketPairCreationAndLiveDatagramRelay() async throws {
        let l2Switch = UserSpaceL2Switch()
        let crafter = PacketFrameCrafter()
        let vmID = VMID("vm-sockpair")

        let (vmSideFD, switchPortID) = try await l2Switch.createPortSocketPair(for: vmID, macAddress: guestMAC)
        defer {
            _ = Darwin.close(vmSideFD)
        }

        #expect(vmSideFD >= 0)
        #expect(await l2Switch.attachedPorts().first?.switchPortID == switchPortID)

        // Send a real Ethernet ARP frame from vmSideFD into the switch and read back the switch's ARP Reply datagram
        let arpFrame = crafter.buildARPPacket(
            isReply: false,
            senderMAC: guestMAC,
            senderIP: guestIP,
            targetMAC: .broadcast,
            targetIP: gatewayIP
        )
        let sent = arpFrame.withUnsafeBytes { rawPtr -> Int in
            guard let base = rawPtr.baseAddress else { return -1 }
            return Darwin.send(vmSideFD, base, rawPtr.count, 0)
        }
        #expect(sent == arpFrame.count)

        // Poll briefly for async DispatchSource switch reply without blocking forever
        var pfd = Darwin.pollfd(fd: vmSideFD, events: Int16(POLLIN), revents: 0)
        let ready = Darwin.poll(&pfd, 1, 1500)
        #expect(ready == 1)

        var recvBuf = [UInt8](repeating: 0, count: 256)
        let received = recvBuf.withUnsafeMutableBytes { rawPtr -> Int in
            guard let base = rawPtr.baseAddress else { return -1 }
            return Darwin.recv(vmSideFD, base, rawPtr.count, 0)
        }
        #expect(received >= 42)

        await l2Switch.detachPort(for: vmID)
        #expect(await l2Switch.attachedPorts().isEmpty)
    }

    @Test("UserSpaceL2Switch.seedDemonstrationTraffic populates multi-protocol wiretap ring and exports filtered PCAPNG")
    func userSpaceL2SwitchSeedDemoTrafficAndFilteredPCAPNGExport() async throws {
        let l2Switch = UserSpaceL2Switch()
        let seeded = try await l2Switch.seedDemonstrationTraffic(for: VMID("vm-demo-net"))
        #expect(seeded.count >= 10)

        let stats = await l2Switch.statistics()
        #expect(stats.capturedRingCount >= seeded.count)
        #expect(stats.totalDroppedFrames >= 1)

        let tlsOnly = await l2Switch.recentPackets(limit: 50, filterQuery: "proto == tls")
        #expect(!tlsOnly.isEmpty)
        #expect(tlsOnly.allSatisfy { $0.highestProtocol == .tls })

        let pcapData = await l2Switch.exportPCAPNGData(filterQuery: "proto == tls")
        let decoded = try PCAPNGCodec().decodeCapture(data: pcapData)
        #expect(decoded.count == tlsOnly.count)
    }

    @Test("UserSpaceL2Switch performs lateral VM-to-VM unicast MAC learning and forwards peer frames over socketpairs")
    func userSpaceL2SwitchLateralVMToVMForwarding() async throws {
        var lateralRule = FirewallPolicySet.strictAgentAllowlistPreset()
        lateralRule.rules.append(
            FirewallRule(
                id: RuleID("rule-allow-subnet-lateral"),
                priority: 5,
                name: "Allow Lateral Sandbox Subnet",
                conditions: [.destinationCIDR("10.211.55.0/24")],
                verdict: .allow
            )
        )
        let firewall = EgressFirewallEngine(policy: lateralRule)
        let l2Switch = UserSpaceL2Switch(firewall: firewall)
        let crafter = PacketFrameCrafter()

        let vmA = VMID("vm-peer-a")
        let vmB = VMID("vm-peer-b")
        let macA = MACAddress(octets: [0x52, 0x54, 0x00, 0xAA, 0x00, 0x01])
        let macB = MACAddress(octets: [0x52, 0x54, 0x00, 0xAA, 0x00, 0x02])
        let ipA = IPv4Address(a: 10, b: 211, c: 55, d: 21)
        let ipB = IPv4Address(a: 10, b: 211, c: 55, d: 22)

        let (fdA, _) = try await l2Switch.createPortSocketPair(for: vmA, macAddress: macA)
        let (fdB, _) = try await l2Switch.createPortSocketPair(for: vmB, macAddress: macB)
        defer {
            _ = Darwin.close(fdA)
            _ = Darwin.close(fdB)
        }

        let icmpLateral = crafter.buildICMPv4Echo(
            isReply: false,
            srcMAC: macA,
            dstMAC: macB,
            srcIP: ipA,
            dstIP: ipB,
            identifier: 0x7777,
            sequence: 1,
            payload: Data("lateral-ping".utf8)
        )
        let result = try await l2Switch.injectFrameFromGuest(vmID: vmA, rawFrame: icmpLateral)
        #expect(result.captured.direction == .lateralVMToVM)
        #expect(result.captured.verdict == .allow)

        var pfd = Darwin.pollfd(fd: fdB, events: Int16(POLLIN), revents: 0)
        let ready = Darwin.poll(&pfd, 1, 1500)
        #expect(ready == 1)

        var recvBuf = [UInt8](repeating: 0, count: 256)
        let received = recvBuf.withUnsafeMutableBytes { rawPtr -> Int in
            guard let base = rawPtr.baseAddress else { return -1 }
            return Darwin.recv(fdB, base, rawPtr.count, 0)
        }
        #expect(received == icmpLateral.count)
        #expect(Data(recvBuf[0..<received]) == icmpLateral)

        await l2Switch.detachPort(for: vmA)
        await l2Switch.detachPort(for: vmB)
    }

    @Test("WiretapFilterQuery rejects malformed filter syntax and evaluates HTTP host and port range predicates")
    func wiretapFilterSyntaxErrorsAndHTTPPortPredicates() throws {
        #expect(throws: AgentVMError.self) {
            _ = try WiretapFilterQuery(parsing: "proto == ")
        }
        #expect(throws: AgentVMError.self) {
            _ = try WiretapFilterQuery(parsing: "(proto == tcp && port == 443")
        }

        let crafter = PacketFrameCrafter()
        let dissector = PacketDissector()
        let httpFrame = crafter.buildTCPFrame(
            srcMAC: guestMAC,
            dstMAC: gatewayMAC,
            srcIP: guestIP,
            dstIP: IPv4Address(a: 93, b: 184, c: 216, d: 34),
            srcPort: 54321,
            dstPort: 8080,
            seq: 10,
            ack: 1,
            flags: [.psh, .ack],
            payload: crafter.buildHTTPRequestPayload(method: "POST", path: "/v1/telemetry", host: "metrics.example.org")
        )
        let pkt = try dissector.dissectEthernetFrame(httpFrame, vmID: VMID("vm-http"))
        let query = try WiretapFilterQuery(parsing: "proto == http && port == 8080")
        #expect(query.matches(pkt) == true)
    }
}
