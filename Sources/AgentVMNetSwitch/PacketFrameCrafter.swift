import AgentVMModels
import Foundation

// MARK: - Deterministic L2 / L3 / L4 / L7 Network Packet Crafter

public struct PacketFrameCrafter: Sendable {
    public init() {}

    // MARK: - Layer 2 Ethernet II & IEEE 802.1Q Builders

    public func buildEthernetFrame(
        srcMAC: MACAddress,
        dstMAC: MACAddress,
        etherType: UInt16,
        payload: [UInt8]
    ) -> Data {
        var writer = BinaryBufferWriter(capacity: 14 + payload.count)
        writer.appendBytes(dstMAC.octets)
        writer.appendBytes(srcMAC.octets)
        writer.appendUInt16BE(etherType)
        writer.appendBytes(payload)
        return writer.data
    }

    public func buildVLANFrame(
        srcMAC: MACAddress,
        dstMAC: MACAddress,
        vlanID: UInt16,
        priorityCodePoint: UInt8 = 0,
        dropEligible: Bool = false,
        etherType: UInt16,
        payload: [UInt8]
    ) -> Data {
        var writer = BinaryBufferWriter(capacity: 18 + payload.count)
        writer.appendBytes(dstMAC.octets)
        writer.appendBytes(srcMAC.octets)
        writer.appendUInt16BE(0x8100)
        let tci = (UInt16(priorityCodePoint & 0x07) << 13)
            | (dropEligible ? (1 << 12) : 0)
            | (vlanID & 0x0FFF)
        writer.appendUInt16BE(tci)
        writer.appendUInt16BE(etherType)
        writer.appendBytes(payload)
        return writer.data
    }

    // MARK: - ARP Request / Reply Builder (RFC 826)

    public func buildARPPacket(
        isReply: Bool,
        senderMAC: MACAddress,
        senderIP: IPv4Address,
        targetMAC: MACAddress,
        targetIP: IPv4Address
    ) -> Data {
        var arpWriter = BinaryBufferWriter(capacity: 28)
        arpWriter.appendUInt16BE(0x0001) // HTYPE: Ethernet (1)
        arpWriter.appendUInt16BE(0x0800) // PTYPE: IPv4 (0x0800)
        arpWriter.appendUInt8(6)         // HLEN: 6 octets
        arpWriter.appendUInt8(4)         // PLEN: 4 octets
        arpWriter.appendUInt16BE(isReply ? 2 : 1)
        arpWriter.appendBytes(senderMAC.octets)
        arpWriter.appendUInt32BE(senderIP.rawHostOrder)
        let arpTargetMAC = isReply ? targetMAC : (targetMAC == .broadcast ? MACAddress(octets: [0, 0, 0, 0, 0, 0]) : targetMAC)
        arpWriter.appendBytes(arpTargetMAC.octets)
        arpWriter.appendUInt32BE(targetIP.rawHostOrder)

        let ethernetDst = isReply ? targetMAC : .broadcast
        return buildEthernetFrame(
            srcMAC: senderMAC,
            dstMAC: ethernetDst,
            etherType: 0x0806,
            payload: arpWriter.bytes
        )
    }

    // MARK: - IPv4 Envelope Helper (RFC 791 + RFC 1071 Header Checksum)

    public func buildIPv4PacketBytes(
        srcIP: IPv4Address,
        dstIP: IPv4Address,
        protocolNumber: UInt8,
        identification: UInt16 = 0x4156,
        dscpECN: UInt8 = 0x00,
        ttl: UInt8 = 64,
        dontFragment: Bool = true,
        payload: [UInt8]
    ) -> [UInt8] {
        let totalLen = UInt16(clamping: 20 + payload.count)
        var hdr = BinaryBufferWriter(capacity: 20 + payload.count)
        hdr.appendUInt8(0x45) // Version 4, IHL 5 (20 bytes)
        hdr.appendUInt8(dscpECN)
        hdr.appendUInt16BE(totalLen)
        hdr.appendUInt16BE(identification)
        hdr.appendUInt16BE(dontFragment ? 0x4000 : 0x0000)
        hdr.appendUInt8(ttl)
        hdr.appendUInt8(protocolNumber)
        hdr.appendUInt16BE(0x0000) // Checksum placeholder at index 10..11
        hdr.appendUInt32BE(srcIP.rawHostOrder)
        hdr.appendUInt32BE(dstIP.rawHostOrder)

        let headerChecksum = BinaryChecksums.rfc1071Checksum(hdr.bytes)
        hdr.patchUInt16BE(headerChecksum, at: 10)
        hdr.appendBytes(payload)
        return hdr.bytes
    }

    // MARK: - ICMPv4 Echo & Unreachable Builders (RFC 792)

    public func buildICMPv4Echo(
        isReply: Bool,
        srcMAC: MACAddress,
        dstMAC: MACAddress,
        srcIP: IPv4Address,
        dstIP: IPv4Address,
        identifier: UInt16,
        sequence: UInt16,
        payload: Data
    ) -> Data {
        var icmp = BinaryBufferWriter(capacity: 8 + payload.count)
        icmp.appendUInt8(isReply ? 0 : 8)
        icmp.appendUInt8(0)
        icmp.appendUInt16BE(0x0000) // Checksum placeholder at index 2..3
        icmp.appendUInt16BE(identifier)
        icmp.appendUInt16BE(sequence)
        icmp.appendData(payload)

        let csum = BinaryChecksums.rfc1071Checksum(icmp.bytes)
        icmp.patchUInt16BE(csum, at: 2)

        let ipv4Bytes = buildIPv4PacketBytes(
            srcIP: srcIP,
            dstIP: dstIP,
            protocolNumber: 1,
            identification: sequence &+ 0x1000,
            payload: icmp.bytes
        )
        return buildEthernetFrame(
            srcMAC: srcMAC,
            dstMAC: dstMAC,
            etherType: 0x0800,
            payload: ipv4Bytes
        )
    }

    public func buildICMPv4DestinationUnreachable(
        code: UInt8 = 3,
        srcMAC: MACAddress,
        dstMAC: MACAddress,
        srcIP: IPv4Address,
        dstIP: IPv4Address,
        quotedIPv4HeaderAndL4Prefix: Data
    ) -> Data {
        let quotedSlice = Data(quotedIPv4HeaderAndL4Prefix.prefix(28))
        var icmp = BinaryBufferWriter(capacity: 8 + quotedSlice.count)
        icmp.appendUInt8(3) // Destination Unreachable
        icmp.appendUInt8(code)
        icmp.appendUInt16BE(0x0000)
        icmp.appendUInt32BE(0x0000_0000)
        icmp.appendData(quotedSlice)

        let csum = BinaryChecksums.rfc1071Checksum(icmp.bytes)
        icmp.patchUInt16BE(csum, at: 2)

        let ipv4Bytes = buildIPv4PacketBytes(
            srcIP: srcIP,
            dstIP: dstIP,
            protocolNumber: 1,
            payload: icmp.bytes
        )
        return buildEthernetFrame(
            srcMAC: srcMAC,
            dstMAC: dstMAC,
            etherType: 0x0800,
            payload: ipv4Bytes
        )
    }

    // MARK: - UDP Frame Builder (RFC 768)

    public func buildUDPFrame(
        srcMAC: MACAddress,
        dstMAC: MACAddress,
        srcIP: IPv4Address,
        dstIP: IPv4Address,
        srcPort: UInt16,
        dstPort: UInt16,
        vlanID: UInt16? = nil,
        payload: Data
    ) -> Data {
        let udpSegment = buildUDPSegmentBytes(
            srcIP: srcIP,
            dstIP: dstIP,
            srcPort: srcPort,
            dstPort: dstPort,
            payload: [UInt8](payload)
        )
        let ipv4Bytes = buildIPv4PacketBytes(
            srcIP: srcIP,
            dstIP: dstIP,
            protocolNumber: 17,
            payload: udpSegment
        )
        if let vlanID {
            return buildVLANFrame(
                srcMAC: srcMAC,
                dstMAC: dstMAC,
                vlanID: vlanID,
                etherType: 0x0800,
                payload: ipv4Bytes
            )
        }
        return buildEthernetFrame(
            srcMAC: srcMAC,
            dstMAC: dstMAC,
            etherType: 0x0800,
            payload: ipv4Bytes
        )
    }

    private func buildUDPSegmentBytes(
        srcIP: IPv4Address,
        dstIP: IPv4Address,
        srcPort: UInt16,
        dstPort: UInt16,
        payload: [UInt8]
    ) -> [UInt8] {
        let udpLen = UInt16(clamping: 8 + payload.count)
        var udp = BinaryBufferWriter(capacity: 8 + payload.count)
        udp.appendUInt16BE(srcPort)
        udp.appendUInt16BE(dstPort)
        udp.appendUInt16BE(udpLen)
        udp.appendUInt16BE(0x0000) // Checksum placeholder at index 6..7
        udp.appendBytes(payload)

        var csum = BinaryChecksums.ipv4TransportChecksum(
            srcIP: srcIP,
            dstIP: dstIP,
            protocolNumber: 17,
            segmentBytes: udp.bytes
        )
        if csum == 0 {
            csum = 0xFFFF
        }
        udp.patchUInt16BE(csum, at: 6)
        return udp.bytes
    }

    // MARK: - DHCPv4 Packet Builder (RFC 2131 & RFC 2132)

    public func buildDHCPv4Packet(
        messageType: UInt8,
        transactionID: UInt32,
        clientMAC: MACAddress,
        yourIP: IPv4Address,
        serverIP: IPv4Address,
        subnetMask: IPv4Address,
        routerIP: IPv4Address,
        dnsServers: [IPv4Address],
        leaseSeconds: UInt32 = 86_400,
        hostname: String? = nil
    ) -> Data {
        let isServerReply = (messageType == 2 || messageType == 5 || messageType == 6)

        var bootp = BinaryBufferWriter(capacity: 320)
        bootp.appendUInt8(isServerReply ? 2 : 1) // op: 1=BOOTREQUEST, 2=BOOTREPLY
        bootp.appendUInt8(1)                     // htype: Ethernet (1)
        bootp.appendUInt8(6)                     // hlen: 6
        bootp.appendUInt8(0)                     // hops: 0
        bootp.appendUInt32BE(transactionID)
        bootp.appendUInt16BE(0)                  // secs
        bootp.appendUInt16BE(isServerReply ? 0x0000 : 0x8000) // Broadcast flag on client discovery

        let ciaddr: IPv4Address = (messageType == 7 || messageType == 8) ? yourIP : .zero
        let yiaddr: IPv4Address = (isServerReply && messageType != 6) ? yourIP : .zero
        let siaddr: IPv4Address = isServerReply ? serverIP : .zero

        bootp.appendUInt32BE(ciaddr.rawHostOrder) // ciaddr (12..15)
        bootp.appendUInt32BE(yiaddr.rawHostOrder) // yiaddr (16..19)
        bootp.appendUInt32BE(siaddr.rawHostOrder) // siaddr (20..23)
        bootp.appendUInt32BE(0)                   // giaddr (24..27)

        // chaddr (16 bytes: 6-byte MAC + 10 zero padding bytes)
        bootp.appendBytes(clientMAC.octets)
        bootp.appendBytes([UInt8](repeating: 0, count: 10))

        // sname (64 bytes) + file (128 bytes)
        bootp.appendFixedASCII(isServerReply ? "agentvm-switch" : "", length: 64, padByte: 0x00)
        bootp.appendBytes([UInt8](repeating: 0, count: 128))

        // RFC 2132 DHCP Magic Cookie (offset 236..239)
        bootp.appendUInt32BE(0x6382_5363)

        // Option 53: DHCP Message Type
        bootp.appendUInt8(53)
        bootp.appendUInt8(1)
        bootp.appendUInt8(messageType)

        if isServerReply {
            // Option 54: DHCP Server Identifier
            let effectiveServer = serverIP == .zero ? .switchGateway : serverIP
            bootp.appendUInt8(54)
            bootp.appendUInt8(4)
            bootp.appendUInt32BE(effectiveServer.rawHostOrder)

            if messageType != 6 {
                // Option 51: IP Address Lease Time
                bootp.appendUInt8(51)
                bootp.appendUInt8(4)
                bootp.appendUInt32BE(leaseSeconds)

                // Option 1: Subnet Mask
                bootp.appendUInt8(1)
                bootp.appendUInt8(4)
                bootp.appendUInt32BE(subnetMask.rawHostOrder)

                // Option 3: Router / Default Gateway
                bootp.appendUInt8(3)
                bootp.appendUInt8(4)
                bootp.appendUInt32BE(routerIP.rawHostOrder)

                // Option 6: DNS Servers
                if !dnsServers.isEmpty {
                    let cappedDNS = Array(dnsServers.prefix(8))
                    bootp.appendUInt8(6)
                    bootp.appendUInt8(UInt8(cappedDNS.count * 4))
                    for dns in cappedDNS {
                        bootp.appendUInt32BE(dns.rawHostOrder)
                    }
                }
            }
        } else {
            // Client Request options (Option 50 Requested IP + Option 54 Server ID + Option 55 Param List)
            if messageType == 3 && yourIP != .zero {
                bootp.appendUInt8(50)
                bootp.appendUInt8(4)
                bootp.appendUInt32BE(yourIP.rawHostOrder)
            }
            if messageType == 3 && serverIP != .zero {
                bootp.appendUInt8(54)
                bootp.appendUInt8(4)
                bootp.appendUInt32BE(serverIP.rawHostOrder)
            }
            // Option 55: Parameter Request List (Subnet, Router, DNS, Domain, Lease Time)
            let requestedParams: [UInt8] = [1, 3, 6, 15, 51]
            bootp.appendUInt8(55)
            bootp.appendUInt8(UInt8(requestedParams.count))
            bootp.appendBytes(requestedParams)
        }

        if let hostname, !hostname.isEmpty {
            let hostUTF8 = Array(hostname.utf8.prefix(63))
            bootp.appendUInt8(12)
            bootp.appendUInt8(UInt8(hostUTF8.count))
            bootp.appendBytes(hostUTF8)
        }

        // Option 255: End
        bootp.appendUInt8(255)

        // Pad BOOTP payload to 300-byte minimum for strict RFC 1542 / udhcpc guest compatibility
        if bootp.count < 300 {
            bootp.appendBytes([UInt8](repeating: 0x00, count: 300 - bootp.count))
        } else {
            bootp.padToAlignment(4, fillByte: 0x00)
        }

        let ethSrc: MACAddress = isServerReply ? .defaultGateway : clientMAC
        let ethDst: MACAddress = isServerReply ? clientMAC : .broadcast
        let ipSrc: IPv4Address = isServerReply ? (serverIP == .zero ? .switchGateway : serverIP) : ciaddr
        let ipDst: IPv4Address = isServerReply ? (yourIP == .zero ? .broadcast : yourIP) : .broadcast
        let udpSrcPort: UInt16 = isServerReply ? 67 : 68
        let udpDstPort: UInt16 = isServerReply ? 68 : 67

        return buildUDPFrame(
            srcMAC: ethSrc,
            dstMAC: ethDst,
            srcIP: ipSrc,
            dstIP: ipDst,
            srcPort: udpSrcPort,
            dstPort: udpDstPort,
            payload: bootp.data
        )
    }

    // MARK: - DNS Query & Response Builders (RFC 1035)

    public static func encodeDNSName(_ domain: String) -> [UInt8] {
        let trimmed = domain
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard !trimmed.isEmpty else {
            return [0x00]
        }
        var out: [UInt8] = []
        let labels = trimmed.split(separator: ".", omittingEmptySubsequences: true)
        for label in labels {
            let utf8 = Array(label.utf8.prefix(63))
            out.append(UInt8(utf8.count))
            out.append(contentsOf: utf8)
        }
        out.append(0x00)
        return out
    }

    public func buildDNSQuery(
        srcMAC: MACAddress,
        dstMAC: MACAddress,
        srcIP: IPv4Address,
        dstIP: IPv4Address,
        srcPort: UInt16 = 53210,
        transactionID: UInt16,
        qname: String,
        qtype: UInt16 = 1
    ) -> Data {
        var dns = BinaryBufferWriter(capacity: 64)
        dns.appendUInt16BE(transactionID)
        dns.appendUInt16BE(0x0100) // Standard Query, RD = 1
        dns.appendUInt16BE(1)      // QDCOUNT = 1
        dns.appendUInt16BE(0)      // ANCOUNT = 0
        dns.appendUInt16BE(0)      // NSCOUNT = 0
        dns.appendUInt16BE(0)      // ARCOUNT = 0
        dns.appendBytes(Self.encodeDNSName(qname))
        dns.appendUInt16BE(qtype)
        dns.appendUInt16BE(0x0001) // QCLASS = IN

        return buildUDPFrame(
            srcMAC: srcMAC,
            dstMAC: dstMAC,
            srcIP: srcIP,
            dstIP: dstIP,
            srcPort: srcPort,
            dstPort: 53,
            payload: dns.data
        )
    }

    public func buildDNSResponse(
        forRequest requestFrame: Data,
        resolvedIPv4: IPv4Address?,
        rcode: UInt8 = 0,
        ttl: UInt32 = 120
    ) throws -> Data {
        let bytes = [UInt8](requestFrame)
        guard bytes.count >= 42 else {
            throw AgentVMError.networkFrameMalformed(
                layer: "DNS",
                detail: "DNS request frame too short (\(bytes.count) bytes)."
            )
        }

        let reqDstMAC = MACAddress(octets: Array(bytes[0..<6]))
        let reqSrcMAC = MACAddress(octets: Array(bytes[6..<12]))
        var etherType = Self.readUInt16BE(bytes, at: 12)
        var l3Offset = 14
        var vlanID: UInt16? = nil

        if etherType == 0x8100 || etherType == 0x88A8 {
            guard bytes.count >= 46 else {
                throw AgentVMError.networkFrameMalformed(
                    layer: "802.1Q VLAN",
                    detail: "Truncated VLAN tag in DNS request."
                )
            }
            vlanID = Self.readUInt16BE(bytes, at: 14) & 0x0FFF
            etherType = Self.readUInt16BE(bytes, at: 16)
            l3Offset = 18
        }

        guard etherType == 0x0800 else {
            throw AgentVMError.networkFrameMalformed(
                layer: "DNS",
                detail: String(format: "Expected IPv4 EtherType 0x0800, got 0x%04X.", etherType)
            )
        }

        let ihl = Int(bytes[l3Offset] & 0x0F) * 4
        let ipTotalLen = Int(Self.readUInt16BE(bytes, at: l3Offset + 2))
        let ipProto = bytes[l3Offset + 9]
        guard ihl >= 20, ipProto == 17, l3Offset + ipTotalLen <= bytes.count else {
            throw AgentVMError.networkFrameMalformed(
                layer: "DNS",
                detail: "Expected valid IPv4 + UDP DNS datagram."
            )
        }

        let reqSrcIP = IPv4Address(rawHostOrder: Self.readUInt32BE(bytes, at: l3Offset + 12))
        let reqDstIP = IPv4Address(rawHostOrder: Self.readUInt32BE(bytes, at: l3Offset + 16))
        let udpOffset = l3Offset + ihl
        guard udpOffset + 8 <= bytes.count else {
            throw AgentVMError.networkFrameMalformed(layer: "UDP", detail: "Truncated UDP header in DNS request.")
        }

        let reqSrcPort = Self.readUInt16BE(bytes, at: udpOffset)
        let reqDstPort = Self.readUInt16BE(bytes, at: udpOffset + 2)
        let udpLen = Int(Self.readUInt16BE(bytes, at: udpOffset + 4))
        let dnsOffset = udpOffset + 8
        let dnsEnd = min(bytes.count, udpOffset + udpLen)
        guard dnsEnd - dnsOffset >= 12 else {
            throw AgentVMError.networkFrameMalformed(layer: "DNS", detail: "Truncated 12-byte DNS header.")
        }

        let dnsReqBytes = Array(bytes[dnsOffset..<dnsEnd])
        let txID = Self.readUInt16BE(dnsReqBytes, at: 0)
        let reqFlags = Self.readUInt16BE(dnsReqBytes, at: 2)
        let qdCount = Int(Self.readUInt16BE(dnsReqBytes, at: 4))
        guard qdCount >= 1 else {
            throw AgentVMError.networkFrameMalformed(layer: "DNS", detail: "DNS request contains 0 questions.")
        }

        let (_, nameBytesConsumed) = try PacketDissector.decodeDNSName(in: dnsReqBytes, at: 12)
        let questionEnd = 12 + nameBytesConsumed + 4
        guard questionEnd <= dnsReqBytes.count else {
            throw AgentVMError.networkFrameMalformed(layer: "DNS", detail: "Truncated DNS question section.")
        }
        let qtype = Self.readUInt16BE(dnsReqBytes, at: 12 + nameBytesConsumed)
        let rawQuestionSection = Array(dnsReqBytes[12..<questionEnd])

        let rdBit = reqFlags & 0x0100
        let opcodeBits = reqFlags & 0x7800
        let respFlags: UInt16 = 0x8000 | opcodeBits | rdBit | 0x0080 | UInt16(rcode & 0x0F)
        let includeAnswer = (rcode == 0 && resolvedIPv4 != nil && (qtype == 1 || qtype == 255))

        var dnsResp = BinaryBufferWriter(capacity: questionEnd + 16)
        dnsResp.appendUInt16BE(txID)
        dnsResp.appendUInt16BE(respFlags)
        dnsResp.appendUInt16BE(1) // QDCOUNT
        dnsResp.appendUInt16BE(includeAnswer ? 1 : 0) // ANCOUNT
        dnsResp.appendUInt16BE(0) // NSCOUNT
        dnsResp.appendUInt16BE(0) // ARCOUNT
        dnsResp.appendBytes(rawQuestionSection)

        if includeAnswer, let ip = resolvedIPv4 {
            dnsResp.appendUInt16BE(0xC00C) // Compression pointer to offset 12 (QNAME)
            dnsResp.appendUInt16BE(0x0001) // TYPE A
            dnsResp.appendUInt16BE(0x0001) // CLASS IN
            dnsResp.appendUInt32BE(ttl)
            dnsResp.appendUInt16BE(4)      // RDLENGTH = 4
            dnsResp.appendUInt32BE(ip.rawHostOrder)
        }

        let replySrcMAC = reqDstMAC.isBroadcast ? MACAddress.defaultGateway : reqDstMAC
        return buildUDPFrame(
            srcMAC: replySrcMAC,
            dstMAC: reqSrcMAC,
            srcIP: reqDstIP,
            dstIP: reqSrcIP,
            srcPort: reqDstPort,
            dstPort: reqSrcPort,
            vlanID: vlanID,
            payload: dnsResp.data
        )
    }

    // MARK: - TCP Segment & RST Builders (RFC 793)

    public func buildTCPFrame(
        srcMAC: MACAddress,
        dstMAC: MACAddress,
        srcIP: IPv4Address,
        dstIP: IPv4Address,
        srcPort: UInt16,
        dstPort: UInt16,
        seq: UInt32,
        ack: UInt32,
        flags: TCPFlags,
        window: UInt16 = 65535,
        payload: Data = Data()
    ) -> Data {
        let payloadBytes = [UInt8](payload)
        var tcp = BinaryBufferWriter(capacity: 20 + payloadBytes.count)
        tcp.appendUInt16BE(srcPort)
        tcp.appendUInt16BE(dstPort)
        tcp.appendUInt32BE(seq)
        tcp.appendUInt32BE(ack)
        tcp.appendUInt8(0x50) // Data Offset = 5 words (20 bytes)
        tcp.appendUInt8(flags.rawValue)
        tcp.appendUInt16BE(window)
        tcp.appendUInt16BE(0x0000) // Checksum placeholder at index 16..17
        tcp.appendUInt16BE(0x0000) // Urgent Pointer
        tcp.appendBytes(payloadBytes)

        let tcpChecksum = BinaryChecksums.ipv4TransportChecksum(
            srcIP: srcIP,
            dstIP: dstIP,
            protocolNumber: 6,
            segmentBytes: tcp.bytes
        )
        tcp.patchUInt16BE(tcpChecksum, at: 16)

        let ipv4Bytes = buildIPv4PacketBytes(
            srcIP: srcIP,
            dstIP: dstIP,
            protocolNumber: 6,
            identification: UInt16(truncatingIfNeeded: (seq >> 4) &+ 1),
            payload: tcp.bytes
        )
        return buildEthernetFrame(
            srcMAC: srcMAC,
            dstMAC: dstMAC,
            etherType: 0x0800,
            payload: ipv4Bytes
        )
    }

    /// Synthesizes an RFC 793-compliant TCP Reset (`RST` / `RST,ACK`) response to tear down a rejected guest flow.
    public func buildTCPRSTReply(forIncomingFrame incomingFrame: Data) throws -> Data {
        let bytes = [UInt8](incomingFrame)
        guard bytes.count >= 54 else {
            throw AgentVMError.networkFrameMalformed(
                layer: "TCP",
                detail: "Incoming frame (\(bytes.count) bytes) too short to craft TCP RST."
            )
        }

        let inDstMAC = MACAddress(octets: Array(bytes[0..<6]))
        let inSrcMAC = MACAddress(octets: Array(bytes[6..<12]))
        var etherType = Self.readUInt16BE(bytes, at: 12)
        var l3Offset = 14
        if etherType == 0x8100 || etherType == 0x88A8 {
            guard bytes.count >= 58 else {
                throw AgentVMError.networkFrameMalformed(layer: "802.1Q", detail: "Truncated VLAN TCP frame.")
            }
            etherType = Self.readUInt16BE(bytes, at: 16)
            l3Offset = 18
        }

        guard etherType == 0x0800, bytes[l3Offset + 9] == 6 else {
            throw AgentVMError.networkFrameMalformed(layer: "TCP", detail: "Frame is not IPv4/TCP.")
        }

        let ihl = Int(bytes[l3Offset] & 0x0F) * 4
        let ipTotalLen = Int(Self.readUInt16BE(bytes, at: l3Offset + 2))
        let inSrcIP = IPv4Address(rawHostOrder: Self.readUInt32BE(bytes, at: l3Offset + 12))
        let inDstIP = IPv4Address(rawHostOrder: Self.readUInt32BE(bytes, at: l3Offset + 16))

        let tcpOffset = l3Offset + ihl
        guard tcpOffset + 20 <= bytes.count else {
            throw AgentVMError.networkFrameMalformed(layer: "TCP", detail: "Truncated TCP header.")
        }

        let inSrcPort = Self.readUInt16BE(bytes, at: tcpOffset)
        let inDstPort = Self.readUInt16BE(bytes, at: tcpOffset + 2)
        let inSeq = Self.readUInt32BE(bytes, at: tcpOffset + 4)
        let inAck = Self.readUInt32BE(bytes, at: tcpOffset + 8)
        let tcpHdrLen = Int(bytes[tcpOffset + 12] >> 4) * 4
        let inFlags = TCPFlags(rawValue: bytes[tcpOffset + 13])
        let tcpPayloadLen = max(0, ipTotalLen - ihl - tcpHdrLen)

        let outSeq: UInt32
        let outAck: UInt32
        let outFlags: TCPFlags

        if inFlags.contains(.ack) {
            outSeq = inAck
            outAck = 0
            outFlags = [.rst]
        } else {
            outSeq = 0
            var segAdvance = UInt32(tcpPayloadLen)
            if inFlags.contains(.syn) { segAdvance &+= 1 }
            if inFlags.contains(.fin) { segAdvance &+= 1 }
            outAck = inSeq &+ max(1, segAdvance)
            outFlags = [.rst, .ack]
        }

        let replySrcMAC = inDstMAC.isBroadcast ? MACAddress.defaultGateway : inDstMAC
        return buildTCPFrame(
            srcMAC: replySrcMAC,
            dstMAC: inSrcMAC,
            srcIP: inDstIP,
            dstIP: inSrcIP,
            srcPort: inDstPort,
            dstPort: inSrcPort,
            seq: outSeq,
            ack: outAck,
            flags: outFlags,
            window: 0
        )
    }

    // MARK: - TLS 1.3 / 1.2 ClientHello & HTTP/1.1 Payload Builders (RFC 8446 / RFC 9112)

    public func buildTLSClientHelloPayload(
        serverName: String,
        alpnProtocols: [String] = ["h2", "http/1.1"]
    ) -> Data {
        var extensions = BinaryBufferWriter(capacity: 192)

        // Extension 0x0000: server_name (SNI, RFC 6066)
        let sniBytes = Array(serverName.utf8)
        if !sniBytes.isEmpty {
            let entryLen = UInt16(3 + sniBytes.count)
            let extLen = UInt16(2 + Int(entryLen))
            extensions.appendUInt16BE(0x0000)
            extensions.appendUInt16BE(extLen)
            extensions.appendUInt16BE(entryLen)
            extensions.appendUInt8(0x00) // host_name
            extensions.appendUInt16BE(UInt16(sniBytes.count))
            extensions.appendBytes(sniBytes)
        }

        // Extension 0x0010: application_layer_protocol_negotiation (ALPN, RFC 7301)
        let validALPNs = alpnProtocols
            .map { Array($0.utf8) }
            .filter { !$0.isEmpty && $0.count <= 255 }
        if !validALPNs.isEmpty {
            var alpnList = BinaryBufferWriter(capacity: 32)
            for proto in validALPNs {
                alpnList.appendUInt8(UInt8(proto.count))
                alpnList.appendBytes(proto)
            }
            extensions.appendUInt16BE(0x0010)
            extensions.appendUInt16BE(UInt16(2 + alpnList.count))
            extensions.appendUInt16BE(UInt16(alpnList.count))
            extensions.appendBytes(alpnList.bytes)
        }

        // Extension 0x002B: supported_versions (TLS 1.3 = 0x0304, TLS 1.2 = 0x0303)
        extensions.appendUInt16BE(0x002B)
        extensions.appendUInt16BE(5)
        extensions.appendUInt8(4)
        extensions.appendUInt16BE(0x0304)
        extensions.appendUInt16BE(0x0303)

        // Extension 0x000A: supported_groups (x25519 = 0x001D, secp256r1 = 0x0017)
        extensions.appendUInt16BE(0x000A)
        extensions.appendUInt16BE(6)
        extensions.appendUInt16BE(4)
        extensions.appendUInt16BE(0x001D)
        extensions.appendUInt16BE(0x0017)

        // Extension 0x000D: signature_algorithms
        extensions.appendUInt16BE(0x000D)
        extensions.appendUInt16BE(6)
        extensions.appendUInt16BE(4)
        extensions.appendUInt16BE(0x0403) // ecdsa_secp256r1_sha256
        extensions.appendUInt16BE(0x0804) // rsa_pss_rsae_sha256

        // Extension 0x002D: psk_key_exchange_modes (psk_dhe_ke = 1)
        extensions.appendUInt16BE(0x002D)
        extensions.appendUInt16BE(2)
        extensions.appendUInt8(1)
        extensions.appendUInt8(1)

        // Extension 0x0033: key_share (x25519 32-byte deterministic ephemeral public key)
        var x25519Pub = [UInt8](repeating: 0, count: 32)
        for idx in 0..<32 {
            x25519Pub[idx] = UInt8((idx &* 17 &+ sniBytes.count) & 0xFF)
        }
        x25519Pub[0] &= 0xF8
        x25519Pub[31] = (x25519Pub[31] & 0x7F) | 0x40
        extensions.appendUInt16BE(0x0033)
        extensions.appendUInt16BE(38)
        extensions.appendUInt16BE(36)
        extensions.appendUInt16BE(0x001D) // x25519
        extensions.appendUInt16BE(32)
        extensions.appendBytes(x25519Pub)

        // Assemble ClientHello Body
        var chBody = BinaryBufferWriter(capacity: 128 + extensions.count)
        chBody.appendUInt16BE(0x0303) // legacy_version TLS 1.2

        // 32-byte Client Random seeded from serverName
        var randomBytes = [UInt8](repeating: 0, count: 32)
        var seed: UInt64 = 0xCBF2_9CE4_8422_2325
        for b in sniBytes {
            seed ^= UInt64(b)
            seed &*= 0x0000_0100_0000_01B3
        }
        for i in 0..<32 {
            seed ^= seed >> 12
            seed ^= seed << 25
            seed ^= seed >> 27
            randomBytes[i] = UInt8(truncatingIfNeeded: seed &* 0x2545_F491)
        }
        chBody.appendBytes(randomBytes)

        // 32-byte legacy_session_id (TLS 1.3 middlebox compatibility mode)
        chBody.appendUInt8(32)
        chBody.appendBytes(randomBytes.reversed())

        // Cipher Suites (5 standard TLS 1.3 / ECDHE suites = 10 bytes)
        let suites: [UInt16] = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F]
        chBody.appendUInt16BE(UInt16(suites.count * 2))
        for suite in suites {
            chBody.appendUInt16BE(suite)
        }

        // Compression Methods (1 byte: null = 0x00)
        chBody.appendUInt8(1)
        chBody.appendUInt8(0x00)

        // Extensions Vector
        chBody.appendUInt16BE(UInt16(extensions.count))
        chBody.appendBytes(extensions.bytes)

        // Wrap in Handshake Header (type 0x01 + u24 length) + TLS Record Header (type 0x16 + legacy 0x0301 + u16 length)
        let handshakeLen = chBody.count
        let recordLen = 4 + handshakeLen
        var record = BinaryBufferWriter(capacity: 5 + recordLen)
        record.appendUInt8(0x16) // ContentType: Handshake
        record.appendUInt16BE(0x0301) // Legacy Record Version TLS 1.0 per RFC 8446
        record.appendUInt16BE(UInt16(recordLen))
        record.appendUInt8(0x01) // HandshakeType: ClientHello
        record.appendUInt8(UInt8((handshakeLen >> 16) & 0xFF))
        record.appendUInt8(UInt8((handshakeLen >> 8) & 0xFF))
        record.appendUInt8(UInt8(handshakeLen & 0xFF))
        record.appendBytes(chBody.bytes)
        return record.data
    }

    public func buildHTTPRequestPayload(
        method: String = "GET",
        path: String = "/",
        host: String,
        userAgent: String = "AgentVM-Sandbox/1.0",
        extraHeaders: [(String, String)] = [],
        body: Data = Data()
    ) -> Data {
        var lines: [String] = [
            "\(method) \(path) HTTP/1.1",
            "Host: \(host)",
            "User-Agent: \(userAgent)",
            "Accept: */*"
        ]
        if !body.isEmpty {
            lines.append("Content-Length: \(body.count)")
        }
        for (k, v) in extraHeaders {
            lines.append("\(k): \(v)")
        }
        let headerString = lines.joined(separator: "\r\n") + "\r\n\r\n"
        var data = Data(headerString.utf8)
        data.append(body)
        return data
    }

    private static func readUInt16BE(_ bytes: [UInt8], at index: Int) -> UInt16 {
        (UInt16(bytes[index]) << 8) | UInt16(bytes[index + 1])
    }

    private static func readUInt32BE(_ bytes: [UInt8], at index: Int) -> UInt32 {
        (UInt32(bytes[index]) << 24)
            | (UInt32(bytes[index + 1]) << 16)
            | (UInt32(bytes[index + 2]) << 8)
            | UInt32(bytes[index + 3])
    }
}
