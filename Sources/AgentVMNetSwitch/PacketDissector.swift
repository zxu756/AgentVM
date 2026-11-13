import AgentVMModels
import Foundation

// MARK: - Structured Dissection Metadata Snapshots

public struct DissectedARPHeader: Codable, Hashable, Sendable {
    public var hardwareType: UInt16
    public var protocolType: UInt16
    public var hardwareSize: UInt8
    public var protocolSize: UInt8
    public var opcode: UInt16
    public var senderMAC: MACAddress
    public var senderIP: IPv4Address
    public var targetMAC: MACAddress
    public var targetIP: IPv4Address

    public init(
        hardwareType: UInt16,
        protocolType: UInt16,
        hardwareSize: UInt8,
        protocolSize: UInt8,
        opcode: UInt16,
        senderMAC: MACAddress,
        senderIP: IPv4Address,
        targetMAC: MACAddress,
        targetIP: IPv4Address
    ) {
        self.hardwareType = hardwareType
        self.protocolType = protocolType
        self.hardwareSize = hardwareSize
        self.protocolSize = protocolSize
        self.opcode = opcode
        self.senderMAC = senderMAC
        self.senderIP = senderIP
        self.targetMAC = targetMAC
        self.targetIP = targetIP
    }

    public var isGratuitous: Bool {
        senderIP == targetIP && senderIP != .zero
    }
}

public struct DissectedDHCPMessage: Codable, Hashable, Sendable {
    public var op: UInt8
    public var transactionID: UInt32
    public var flags: UInt16
    public var clientIP: IPv4Address
    public var yourIP: IPv4Address
    public var serverIP: IPv4Address
    public var relayAgentIP: IPv4Address
    public var clientMAC: MACAddress
    public var messageType: UInt8?
    public var requestedIP: IPv4Address?
    public var serverIdentifier: IPv4Address?
    public var subnetMask: IPv4Address?
    public var routerIP: IPv4Address?
    public var dnsServers: [IPv4Address]
    public var leaseTimeSeconds: UInt32?
    public var hostname: String?
    public var domainName: String?

    public init(
        op: UInt8,
        transactionID: UInt32,
        flags: UInt16,
        clientIP: IPv4Address,
        yourIP: IPv4Address,
        serverIP: IPv4Address,
        relayAgentIP: IPv4Address,
        clientMAC: MACAddress,
        messageType: UInt8? = nil,
        requestedIP: IPv4Address? = nil,
        serverIdentifier: IPv4Address? = nil,
        subnetMask: IPv4Address? = nil,
        routerIP: IPv4Address? = nil,
        dnsServers: [IPv4Address] = [],
        leaseTimeSeconds: UInt32? = nil,
        hostname: String? = nil,
        domainName: String? = nil
    ) {
        self.op = op
        self.transactionID = transactionID
        self.flags = flags
        self.clientIP = clientIP
        self.yourIP = yourIP
        self.serverIP = serverIP
        self.relayAgentIP = relayAgentIP
        self.clientMAC = clientMAC
        self.messageType = messageType
        self.requestedIP = requestedIP
        self.serverIdentifier = serverIdentifier
        self.subnetMask = subnetMask
        self.routerIP = routerIP
        self.dnsServers = dnsServers
        self.leaseTimeSeconds = leaseTimeSeconds
        self.hostname = hostname
        self.domainName = domainName
    }
}

public struct DissectedDNSQuestion: Codable, Hashable, Sendable {
    public var name: String
    public var qtype: UInt16
    public var qclass: UInt16

    public init(name: String, qtype: UInt16, qclass: UInt16) {
        self.name = name
        self.qtype = qtype
        self.qclass = qclass
    }
}

public struct DissectedDNSAnswer: Codable, Hashable, Sendable {
    public var name: String
    public var rtype: UInt16
    public var rclass: UInt16
    public var ttl: UInt32
    public var valueSummary: String
    public var ipv4Address: IPv4Address?

    public init(
        name: String,
        rtype: UInt16,
        rclass: UInt16,
        ttl: UInt32,
        valueSummary: String,
        ipv4Address: IPv4Address? = nil
    ) {
        self.name = name
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        self.valueSummary = valueSummary
        self.ipv4Address = ipv4Address
    }
}

public struct DissectedDNSMessage: Codable, Hashable, Sendable {
    public var transactionID: UInt16
    public var isResponse: Bool
    public var opcode: UInt8
    public var authoritative: Bool
    public var truncated: Bool
    public var recursionDesired: Bool
    public var recursionAvailable: Bool
    public var rcode: UInt8
    public var questions: [DissectedDNSQuestion]
    public var answers: [DissectedDNSAnswer]

    public init(
        transactionID: UInt16,
        isResponse: Bool,
        opcode: UInt8,
        authoritative: Bool,
        truncated: Bool,
        recursionDesired: Bool,
        recursionAvailable: Bool,
        rcode: UInt8,
        questions: [DissectedDNSQuestion],
        answers: [DissectedDNSAnswer]
    ) {
        self.transactionID = transactionID
        self.isResponse = isResponse
        self.opcode = opcode
        self.authoritative = authoritative
        self.truncated = truncated
        self.recursionDesired = recursionDesired
        self.recursionAvailable = recursionAvailable
        self.rcode = rcode
        self.questions = questions
        self.answers = answers
    }
}

public struct DissectedTLSClientHello: Codable, Hashable, Sendable {
    public var recordVersion: UInt16
    public var clientVersion: UInt16
    public var negotiatedSupportedVersions: [UInt16]
    public var cipherSuites: [UInt16]
    public var serverName: String?
    public var alpnProtocols: [String]
    public var extensionTypes: [UInt16]

    public init(
        recordVersion: UInt16,
        clientVersion: UInt16,
        negotiatedSupportedVersions: [UInt16],
        cipherSuites: [UInt16],
        serverName: String?,
        alpnProtocols: [String],
        extensionTypes: [UInt16]
    ) {
        self.recordVersion = recordVersion
        self.clientVersion = clientVersion
        self.negotiatedSupportedVersions = negotiatedSupportedVersions
        self.cipherSuites = cipherSuites
        self.serverName = serverName
        self.alpnProtocols = alpnProtocols
        self.extensionTypes = extensionTypes
    }
}

// MARK: - Deep Packet Dissector (L2 Ethernet -> L3 ARP/IPv4 -> L4 ICMP/UDP/TCP -> L7 DHCP/DNS/TLS/HTTP/SSH)

public struct PacketDissector: Sendable {
    public var verifyChecksums: Bool

    public init(verifyChecksums: Bool = true) {
        self.verifyChecksums = verifyChecksums
    }

    public func dissectEthernetFrame(
        _ frame: Data,
        sequenceNumber: UInt64 = 1,
        timestampMicros: UInt64? = nil,
        vmID: VMID,
        direction: NetworkDirection = .egress
    ) throws -> CapturedPacket {
        try dissectEthernetBytes(
            [UInt8](frame),
            rawData: frame,
            sequenceNumber: sequenceNumber,
            timestampMicros: timestampMicros,
            vmID: vmID,
            direction: direction
        )
    }

    public func dissectEthernetBytes(
        _ bytes: [UInt8],
        rawData: Data? = nil,
        sequenceNumber: UInt64 = 1,
        timestampMicros: UInt64? = nil,
        vmID: VMID,
        direction: NetworkDirection = .egress
    ) throws -> CapturedPacket {
        guard bytes.count >= 14 else {
            throw AgentVMError.networkFrameMalformed(
                layer: "Ethernet",
                detail: "Frame length \(bytes.count) bytes is shorter than minimum 14-byte Ethernet II header."
            )
        }

        let resolvedTimestamp = timestampMicros ?? Self.currentTimestampMicros()
        let prefix = "pkt\(sequenceNumber)"

        let dstMAC = MACAddress(octets: Array(bytes[0..<6]))
        let srcMAC = MACAddress(octets: Array(bytes[6..<12]))
        var rawEtherType = Self.readUInt16BE(bytes, at: 12)
        var l3Offset = 14
        var vlanID: UInt16? = nil

        var ethFields: [DissectedField] = [
            DissectedField(
                id: "\(prefix).eth.dst",
                label: "Destination MAC",
                valueSummary: Self.describeMAC(dstMAC),
                byteOffset: 0,
                byteLength: 6,
                children: [
                    DissectedField(
                        id: "\(prefix).eth.dst.ig",
                        label: "IG Bit (Individual/Group)",
                        valueSummary: dstMAC.isMulticast ? "1 (Multicast / Broadcast)" : "0 (Unicast)",
                        byteOffset: 0,
                        byteLength: 1
                    ),
                    DissectedField(
                        id: "\(prefix).eth.dst.lg",
                        label: "LG Bit (Local/Global)",
                        valueSummary: dstMAC.isLocallyAdministered ? "1 (Locally Administered)" : "0 (Globally Unique OUI)",
                        byteOffset: 0,
                        byteLength: 1
                    )
                ]
            ),
            DissectedField(
                id: "\(prefix).eth.src",
                label: "Source MAC",
                valueSummary: Self.describeMAC(srcMAC),
                byteOffset: 6,
                byteLength: 6
            )
        ]

        // Optional IEEE 802.1Q (0x8100) or 802.1ad QinQ (0x88A8) VLAN Tagging
        while rawEtherType == 0x8100 || rawEtherType == 0x88A8 {
            guard bytes.count >= l3Offset + 4 else {
                throw AgentVMError.networkFrameMalformed(
                    layer: "802.1Q VLAN",
                    detail: "Truncated 802.1Q VLAN tag at offset \(l3Offset) (frame size \(bytes.count))."
                )
            }
            let tpidOffset = l3Offset - 2
            let tci = Self.readUInt16BE(bytes, at: l3Offset)
            let pcp = (tci >> 13) & 0x07
            let dei = (tci >> 12) & 0x01
            let vid = tci & 0x0FFF
            vlanID = vid
            let innerEtherType = Self.readUInt16BE(bytes, at: l3Offset + 2)

            ethFields.append(
                DissectedField(
                    id: "\(prefix).eth.vlan.\(tpidOffset)",
                    label: "IEEE 802.1Q VLAN Tag",
                    valueSummary: "VID \(vid), PCP \(pcp), DEI \(dei)",
                    byteOffset: tpidOffset,
                    byteLength: 4,
                    children: [
                        DissectedField(
                            id: "\(prefix).eth.vlan.\(tpidOffset).tpid",
                            label: "Tag Protocol Identifier (TPID)",
                            valueSummary: String(format: "0x%04X", rawEtherType),
                            byteOffset: tpidOffset,
                            byteLength: 2
                        ),
                        DissectedField(
                            id: "\(prefix).eth.vlan.\(tpidOffset).tci",
                            label: "Tag Control Information (TCI)",
                            valueSummary: "Priority=\(pcp), DEI=\(dei), VLAN ID=\(vid)",
                            byteOffset: l3Offset,
                            byteLength: 2
                        )
                    ]
                )
            )
            rawEtherType = innerEtherType
            l3Offset += 4
        }

        let etherTypeOffset = l3Offset - 2
        ethFields.append(
            DissectedField(
                id: "\(prefix).eth.type",
                label: "EtherType",
                valueSummary: Self.describeEtherType(rawEtherType),
                byteOffset: etherTypeOffset,
                byteLength: 2
            )
        )

        let ethSummary: String
        if let vlanID {
            ethSummary = "Src: \(srcMAC), Dst: \(dstMAC), VLAN: \(vlanID), Type: \(Self.describeEtherType(rawEtherType))"
        } else {
            ethSummary = "Src: \(srcMAC), Dst: \(dstMAC), Type: \(Self.describeEtherType(rawEtherType))"
        }

        var layers: [DissectedLayer] = [
            DissectedLayer(
                id: "\(prefix).layer.eth",
                protocolKind: .ethernet,
                title: "Ethernet II",
                summary: ethSummary,
                byteOffset: 0,
                byteLength: l3Offset,
                fields: ethFields
            )
        ]

        var highestProtocol: DissectedProtocolKind = .ethernet
        var sourceIP: String? = nil
        var destinationIP: String? = nil
        var sourcePort: UInt16? = nil
        var destinationPort: UInt16? = nil
        var tcpFlags: TCPFlags? = nil
        var dnsQueryName: String? = nil
        var tlsSNI: String? = nil
        var tlsALPN: [String] = []
        var httpHost: String? = nil
        var httpRequestLine: String? = nil
        var infoSummary = "\(srcMAC) -> \(dstMAC) EtherType=\(String(format: "0x%04X", rawEtherType)) Len=\(bytes.count)"

        switch rawEtherType {
        case 0x0806:
            let arpOutcome = try dissectARP(bytes: bytes, offset: l3Offset, prefix: prefix)
            layers.append(arpOutcome.layer)
            highestProtocol = .arp
            sourceIP = arpOutcome.header.senderIP.description
            destinationIP = arpOutcome.header.targetIP.description
            infoSummary = arpOutcome.infoSummary

        case 0x0800:
            let ipv4Outcome = try dissectIPv4(bytes: bytes, offset: l3Offset, prefix: prefix)
            layers.append(contentsOf: ipv4Outcome.layers)
            highestProtocol = ipv4Outcome.highestProtocol
            sourceIP = ipv4Outcome.sourceIP.description
            destinationIP = ipv4Outcome.destinationIP.description
            sourcePort = ipv4Outcome.sourcePort
            destinationPort = ipv4Outcome.destinationPort
            tcpFlags = ipv4Outcome.tcpFlags
            dnsQueryName = ipv4Outcome.dnsQueryName
            tlsSNI = ipv4Outcome.tlsSNI
            tlsALPN = ipv4Outcome.tlsALPN
            httpHost = ipv4Outcome.httpHost
            httpRequestLine = ipv4Outcome.httpRequestLine
            infoSummary = ipv4Outcome.infoSummary

        case 0x86DD:
            // Lightweight IPv6 envelope dissection for neighbor discovery / dual-stack visibility
            if bytes.count >= l3Offset + 40 {
                let payloadLen = Self.readUInt16BE(bytes, at: l3Offset + 4)
                let nextHeader = bytes[l3Offset + 6]
                let hopLimit = bytes[l3Offset + 7]
                let srcIPv6 = Self.formatIPv6(Array(bytes[(l3Offset + 8)..<(l3Offset + 24)]))
                let dstIPv6 = Self.formatIPv6(Array(bytes[(l3Offset + 24)..<(l3Offset + 40)]))
                sourceIP = srcIPv6
                destinationIP = dstIPv6
                layers.append(
                    DissectedLayer(
                        id: "\(prefix).layer.ipv6",
                        protocolKind: .unknown,
                        title: "Internet Protocol Version 6",
                        summary: "Src: \(srcIPv6), Dst: \(dstIPv6), NextHdr: \(nextHeader), HopLimit: \(hopLimit)",
                        byteOffset: l3Offset,
                        byteLength: 40,
                        fields: [
                            DissectedField(
                                id: "\(prefix).ipv6.plen",
                                label: "Payload Length",
                                valueSummary: "\(payloadLen) bytes",
                                byteOffset: l3Offset + 4,
                                byteLength: 2
                            ),
                            DissectedField(
                                id: "\(prefix).ipv6.nxt",
                                label: "Next Header",
                                valueSummary: "\(nextHeader)",
                                byteOffset: l3Offset + 6,
                                byteLength: 1
                            ),
                            DissectedField(
                                id: "\(prefix).ipv6.hlim",
                                label: "Hop Limit",
                                valueSummary: "\(hopLimit)",
                                byteOffset: l3Offset + 7,
                                byteLength: 1
                            ),
                            DissectedField(
                                id: "\(prefix).ipv6.src",
                                label: "Source IPv6",
                                valueSummary: srcIPv6,
                                byteOffset: l3Offset + 8,
                                byteLength: 16
                            ),
                            DissectedField(
                                id: "\(prefix).ipv6.dst",
                                label: "Destination IPv6",
                                valueSummary: dstIPv6,
                                byteOffset: l3Offset + 24,
                                byteLength: 16
                            )
                        ]
                    )
                )
                highestProtocol = .unknown
                infoSummary = "IPv6 \(srcIPv6) -> \(dstIPv6) NextHdr=\(nextHeader) Len=\(payloadLen)"
            } else {
                throw AgentVMError.networkFrameMalformed(
                    layer: "IPv6",
                    detail: "IPv6 header requires 40 bytes, only \(bytes.count - l3Offset) available."
                )
            }

        default:
            let payloadLen = max(0, bytes.count - l3Offset)
            if payloadLen > 0 {
                layers.append(
                    DissectedLayer(
                        id: "\(prefix).layer.raw",
                        protocolKind: .unknown,
                        title: "Raw L2 Payload",
                        summary: "\(payloadLen) bytes (EtherType \(String(format: "0x%04X", rawEtherType)))",
                        byteOffset: l3Offset,
                        byteLength: payloadLen,
                        fields: [
                            DissectedField(
                                id: "\(prefix).raw.bytes",
                                label: "Payload Preview",
                                valueSummary: Self.hexPreview(bytes, offset: l3Offset, length: min(payloadLen, 24)),
                                byteOffset: l3Offset,
                                byteLength: payloadLen
                            )
                        ]
                    )
                )
                highestProtocol = .unknown
            }
        }

        return CapturedPacket(
            sequenceNumber: sequenceNumber,
            timestampMicros: resolvedTimestamp,
            vmID: vmID,
            direction: direction,
            rawFrame: rawData ?? Data(bytes),
            sourceMAC: srcMAC.description,
            destinationMAC: dstMAC.description,
            etherType: rawEtherType,
            vlanID: vlanID,
            sourceIP: sourceIP,
            destinationIP: destinationIP,
            sourcePort: sourcePort,
            destinationPort: destinationPort,
            highestProtocol: highestProtocol,
            tcpFlags: tcpFlags,
            dnsQueryName: dnsQueryName,
            tlsSNI: tlsSNI,
            tlsALPN: tlsALPN,
            httpHost: httpHost,
            httpRequestLine: httpRequestLine,
            infoSummary: infoSummary,
            dissectedLayers: layers
        )
    }

    // MARK: - ARP Dissection (EtherType 0x0806)

    public func parseARPHeader(bytes: [UInt8], offset: Int) throws -> DissectedARPHeader {
        guard bytes.count >= offset + 28 else {
            throw AgentVMError.networkFrameMalformed(
                layer: "ARP",
                detail: "ARP payload requires 28 bytes at offset \(offset), frame has \(bytes.count) bytes."
            )
        }
        let htype = Self.readUInt16BE(bytes, at: offset)
        let ptype = Self.readUInt16BE(bytes, at: offset + 2)
        let hlen = bytes[offset + 4]
        let plen = bytes[offset + 5]
        let oper = Self.readUInt16BE(bytes, at: offset + 6)
        let sha = MACAddress(octets: Array(bytes[(offset + 8)..<(offset + 14)]))
        let spa = IPv4Address(rawHostOrder: Self.readUInt32BE(bytes, at: offset + 14))
        let tha = MACAddress(octets: Array(bytes[(offset + 18)..<(offset + 24)]))
        let tpa = IPv4Address(rawHostOrder: Self.readUInt32BE(bytes, at: offset + 24))

        return DissectedARPHeader(
            hardwareType: htype,
            protocolType: ptype,
            hardwareSize: hlen,
            protocolSize: plen,
            opcode: oper,
            senderMAC: sha,
            senderIP: spa,
            targetMAC: tha,
            targetIP: tpa
        )
    }

    private func dissectARP(
        bytes: [UInt8],
        offset: Int,
        prefix: String
    ) throws -> (layer: DissectedLayer, header: DissectedARPHeader, infoSummary: String) {
        let hdr = try parseARPHeader(bytes: bytes, offset: offset)
        let operText: String
        let info: String

        switch hdr.opcode {
        case 1:
            operText = "1 (ARP Request)"
            if hdr.isGratuitous {
                info = "Gratuitous ARP for \(hdr.senderIP) (\(hdr.senderMAC))"
            } else {
                info = "Who has \(hdr.targetIP)? Tell \(hdr.senderIP)"
            }
        case 2:
            operText = "2 (ARP Reply)"
            info = "\(hdr.senderIP) is at \(hdr.senderMAC)"
        case 3:
            operText = "3 (RARP Request)"
            info = "RARP Who is \(hdr.targetMAC)? Tell \(hdr.senderMAC)"
        case 4:
            operText = "4 (RARP Reply)"
            info = "RARP \(hdr.targetMAC) is \(hdr.targetIP)"
        default:
            operText = "\(hdr.opcode) (Unknown)"
            info = "ARP Opcode \(hdr.opcode) \(hdr.senderIP) -> \(hdr.targetIP)"
        }

        let fields: [DissectedField] = [
            DissectedField(
                id: "\(prefix).arp.htype",
                label: "Hardware Type (HTYPE)",
                valueSummary: hdr.hardwareType == 1 ? "1 (Ethernet)" : "\(hdr.hardwareType)",
                byteOffset: offset,
                byteLength: 2
            ),
            DissectedField(
                id: "\(prefix).arp.ptype",
                label: "Protocol Type (PTYPE)",
                valueSummary: String(format: "0x%04X%@", hdr.protocolType, hdr.protocolType == 0x0800 ? " (IPv4)" : ""),
                byteOffset: offset + 2,
                byteLength: 2
            ),
            DissectedField(
                id: "\(prefix).arp.hlen",
                label: "Hardware Size (HLEN)",
                valueSummary: "\(hdr.hardwareSize)",
                byteOffset: offset + 4,
                byteLength: 1
            ),
            DissectedField(
                id: "\(prefix).arp.plen",
                label: "Protocol Size (PLEN)",
                valueSummary: "\(hdr.protocolSize)",
                byteOffset: offset + 5,
                byteLength: 1
            ),
            DissectedField(
                id: "\(prefix).arp.oper",
                label: "Opcode (OPER)",
                valueSummary: operText,
                byteOffset: offset + 6,
                byteLength: 2
            ),
            DissectedField(
                id: "\(prefix).arp.sha",
                label: "Sender MAC Address",
                valueSummary: hdr.senderMAC.description,
                byteOffset: offset + 8,
                byteLength: 6
            ),
            DissectedField(
                id: "\(prefix).arp.spa",
                label: "Sender IPv4 Address",
                valueSummary: hdr.senderIP.description,
                byteOffset: offset + 14,
                byteLength: 4
            ),
            DissectedField(
                id: "\(prefix).arp.tha",
                label: "Target MAC Address",
                valueSummary: hdr.targetMAC.description,
                byteOffset: offset + 18,
                byteLength: 6
            ),
            DissectedField(
                id: "\(prefix).arp.tpa",
                label: "Target IPv4 Address",
                valueSummary: hdr.targetIP.description,
                byteOffset: offset + 24,
                byteLength: 4
            )
        ]

        let layer = DissectedLayer(
            id: "\(prefix).layer.arp",
            protocolKind: .arp,
            title: "Address Resolution Protocol (\(hdr.opcode == 2 ? "reply" : "request"))",
            summary: info,
            byteOffset: offset,
            byteLength: 28,
            fields: fields
        )
        return (layer, hdr, info)
    }

    // MARK: - IPv4 Dissection (EtherType 0x0800)

    private struct IPv4DissectionOutcome {
        var layers: [DissectedLayer]
        var highestProtocol: DissectedProtocolKind
        var sourceIP: IPv4Address
        var destinationIP: IPv4Address
        var sourcePort: UInt16?
        var destinationPort: UInt16?
        var tcpFlags: TCPFlags?
        var dnsQueryName: String?
        var tlsSNI: String?
        var tlsALPN: [String]
        var httpHost: String?
        var httpRequestLine: String?
        var infoSummary: String
    }

    private func dissectIPv4(
        bytes: [UInt8],
        offset: Int,
        prefix: String
    ) throws -> IPv4DissectionOutcome {
        guard bytes.count >= offset + 20 else {
            throw AgentVMError.networkFrameMalformed(
                layer: "IPv4",
                detail: "IPv4 header requires at least 20 bytes at offset \(offset), got \(bytes.count - offset)."
            )
        }

        let verIHL = bytes[offset]
        let version = verIHL >> 4
        let ihlWords = Int(verIHL & 0x0F)
        let headerLength = ihlWords * 4

        guard version == 4 else {
            throw AgentVMError.networkFrameMalformed(
                layer: "IPv4",
                detail: "Expected IPv4 version 4 at offset \(offset), got \(version)."
            )
        }
        guard headerLength >= 20 && offset + headerLength <= bytes.count else {
            throw AgentVMError.networkFrameMalformed(
                layer: "IPv4",
                detail: "Invalid IPv4 IHL (\(headerLength) bytes) at offset \(offset) for frame size \(bytes.count)."
            )
        }

        let tosByte = bytes[offset + 1]
        let dscp = tosByte >> 2
        let ecn = tosByte & 0x03
        let totalLength = Int(Self.readUInt16BE(bytes, at: offset + 2))

        guard totalLength >= headerLength else {
            throw AgentVMError.networkFrameMalformed(
                layer: "IPv4",
                detail: "IPv4 Total Length (\(totalLength)) is smaller than header length (\(headerLength))."
            )
        }
        guard offset + totalLength <= bytes.count else {
            throw AgentVMError.networkFrameMalformed(
                layer: "IPv4",
                detail: "IPv4 Total Length (\(totalLength)) exceeds remaining frame bytes (\(bytes.count - offset))."
            )
        }

        let ipEnd = offset + totalLength
        let identification = Self.readUInt16BE(bytes, at: offset + 4)
        let flagsAndFrag = Self.readUInt16BE(bytes, at: offset + 6)
        let reservedBit = (flagsAndFrag >> 15) & 0x01
        let dontFragment = ((flagsAndFrag >> 14) & 0x01) != 0
        let moreFragments = ((flagsAndFrag >> 13) & 0x01) != 0
        let fragmentOffsetBytes = Int(flagsAndFrag & 0x1FFF) * 8

        let ttl = bytes[offset + 8]
        let proto = bytes[offset + 9]
        let headerChecksum = Self.readUInt16BE(bytes, at: offset + 10)
        let srcIP = IPv4Address(rawHostOrder: Self.readUInt32BE(bytes, at: offset + 12))
        let dstIP = IPv4Address(rawHostOrder: Self.readUInt32BE(bytes, at: offset + 16))

        let checksumSummary: String
        if verifyChecksums {
            var zeroedHeader = Array(bytes[offset..<(offset + headerLength)])
            zeroedHeader[10] = 0
            zeroedHeader[11] = 0
            let expectedChecksum = BinaryChecksums.rfc1071Checksum(zeroedHeader)
            let residual = BinaryChecksums.rfc1071Checksum(Array(bytes[offset..<(offset + headerLength)]))
            if residual == 0 || headerChecksum == expectedChecksum {
                checksumSummary = String(format: "0x%04X [Verified]", headerChecksum)
            } else {
                checksumSummary = String(
                    format: "0x%04X [Invalid, expected 0x%04X]",
                    headerChecksum,
                    expectedChecksum
                )
            }
        } else {
            checksumSummary = String(format: "0x%04X [Unchecked]", headerChecksum)
        }

        var flagTags: [String] = []
        if dontFragment { flagTags.append("DF") }
        if moreFragments { flagTags.append("MF") }
        let flagLabel = flagTags.isEmpty ? "0x00 (None)" : flagTags.joined(separator: ", ")

        var ipv4Fields: [DissectedField] = [
            DissectedField(
                id: "\(prefix).ipv4.ver_ihl",
                label: "Version & Header Length",
                valueSummary: "IPv\(version), IHL=\(ihlWords) (\(headerLength) bytes)",
                byteOffset: offset,
                byteLength: 1,
                children: [
                    DissectedField(
                        id: "\(prefix).ipv4.version",
                        label: "Version",
                        valueSummary: "4",
                        byteOffset: offset,
                        byteLength: 1
                    ),
                    DissectedField(
                        id: "\(prefix).ipv4.ihl",
                        label: "Internet Header Length",
                        valueSummary: "\(headerLength) bytes (\(ihlWords) words)",
                        byteOffset: offset,
                        byteLength: 1
                    )
                ]
            ),
            DissectedField(
                id: "\(prefix).ipv4.dscp_ecn",
                label: "Differentiated Services",
                valueSummary: "DSCP=\(Self.describeDSCP(dscp)) (\(dscp)), ECN=\(Self.describeECN(ecn)) (\(ecn))",
                byteOffset: offset + 1,
                byteLength: 1
            ),
            DissectedField(
                id: "\(prefix).ipv4.totlen",
                label: "Total Length",
                valueSummary: "\(totalLength) bytes",
                byteOffset: offset + 2,
                byteLength: 2
            ),
            DissectedField(
                id: "\(prefix).ipv4.id",
                label: "Identification",
                valueSummary: String(format: "0x%04X (%u)", identification, identification),
                byteOffset: offset + 4,
                byteLength: 2
            ),
            DissectedField(
                id: "\(prefix).ipv4.flags_frag",
                label: "Flags & Fragment Offset",
                valueSummary: "Flags=[\(flagLabel)], FragOffset=\(fragmentOffsetBytes)",
                byteOffset: offset + 6,
                byteLength: 2,
                children: [
                    DissectedField(
                        id: "\(prefix).ipv4.flags.rb",
                        label: "Reserved Bit",
                        valueSummary: "\(reservedBit)",
                        byteOffset: offset + 6,
                        byteLength: 1
                    ),
                    DissectedField(
                        id: "\(prefix).ipv4.flags.df",
                        label: "Don't Fragment (DF)",
                        valueSummary: dontFragment ? "1 (Set)" : "0 (Not Set)",
                        byteOffset: offset + 6,
                        byteLength: 1
                    ),
                    DissectedField(
                        id: "\(prefix).ipv4.flags.mf",
                        label: "More Fragments (MF)",
                        valueSummary: moreFragments ? "1 (Set)" : "0 (Not Set)",
                        byteOffset: offset + 6,
                        byteLength: 1
                    ),
                    DissectedField(
                        id: "\(prefix).ipv4.frag_offset",
                        label: "Fragment Offset",
                        valueSummary: "\(fragmentOffsetBytes) bytes",
                        byteOffset: offset + 6,
                        byteLength: 2
                    )
                ]
            ),
            DissectedField(
                id: "\(prefix).ipv4.ttl",
                label: "Time To Live (TTL)",
                valueSummary: "\(ttl)",
                byteOffset: offset + 8,
                byteLength: 1
            ),
            DissectedField(
                id: "\(prefix).ipv4.proto",
                label: "Protocol",
                valueSummary: Self.describeIPv4Protocol(proto),
                byteOffset: offset + 9,
                byteLength: 1
            ),
            DissectedField(
                id: "\(prefix).ipv4.checksum",
                label: "Header Checksum",
                valueSummary: checksumSummary,
                byteOffset: offset + 10,
                byteLength: 2
            ),
            DissectedField(
                id: "\(prefix).ipv4.src",
                label: "Source IPv4 Address",
                valueSummary: srcIP.description,
                byteOffset: offset + 12,
                byteLength: 4
            ),
            DissectedField(
                id: "\(prefix).ipv4.dst",
                label: "Destination IPv4 Address",
                valueSummary: dstIP.description,
                byteOffset: offset + 16,
                byteLength: 4
            )
        ]

        if headerLength > 20 {
            let optFields = dissectIPv4Options(
                bytes: bytes,
                start: offset + 20,
                end: offset + headerLength,
                prefix: prefix
            )
            ipv4Fields.append(
                DissectedField(
                    id: "\(prefix).ipv4.options",
                    label: "IPv4 Options",
                    valueSummary: "\(headerLength - 20) bytes (\(optFields.count) option(s))",
                    byteOffset: offset + 20,
                    byteLength: headerLength - 20,
                    children: optFields
                )
            )
        }

        let ipv4Layer = DissectedLayer(
            id: "\(prefix).layer.ipv4",
            protocolKind: .ipv4,
            title: "Internet Protocol Version 4",
            summary: "Src: \(srcIP), Dst: \(dstIP), Proto: \(Self.describeIPv4Protocol(proto)), TTL: \(ttl), Len: \(totalLength)",
            byteOffset: offset,
            byteLength: headerLength,
            fields: ipv4Fields
        )

        var outcome = IPv4DissectionOutcome(
            layers: [ipv4Layer],
            highestProtocol: .ipv4,
            sourceIP: srcIP,
            destinationIP: dstIP,
            sourcePort: nil,
            destinationPort: nil,
            tcpFlags: nil,
            dnsQueryName: nil,
            tlsSNI: nil,
            tlsALPN: [],
            httpHost: nil,
            httpRequestLine: nil,
            infoSummary: "\(srcIP) -> \(dstIP) IPv4 Proto=\(proto) Len=\(totalLength)"
        )

        let l4Offset = offset + headerLength

        // Non-initial IPv4 fragments carry raw fragment payload rather than L4 header
        if fragmentOffsetBytes > 0 {
            let fragPayloadLen = max(0, ipEnd - l4Offset)
            outcome.layers.append(
                DissectedLayer(
                    id: "\(prefix).layer.ipv4_frag",
                    protocolKind: .ipv4,
                    title: "IPv4 Fragment Payload",
                    summary: "Fragment offset \(fragmentOffsetBytes), \(fragPayloadLen) bytes",
                    byteOffset: l4Offset,
                    byteLength: fragPayloadLen,
                    fields: [
                        DissectedField(
                            id: "\(prefix).ipv4_frag.data",
                            label: "Fragment Data",
                            valueSummary: "\(fragPayloadLen) bytes",
                            byteOffset: l4Offset,
                            byteLength: fragPayloadLen
                        )
                    ]
                )
            )
            outcome.infoSummary = "\(srcIP) -> \(dstIP) IPv4 Fragment (offset=\(fragmentOffsetBytes), len=\(fragPayloadLen))"
            return outcome
        }

        switch proto {
        case 1:
            let icmpResult = try dissectICMPv4(
                bytes: bytes,
                offset: l4Offset,
                end: ipEnd,
                srcIP: srcIP,
                dstIP: dstIP,
                prefix: prefix
            )
            outcome.layers.append(icmpResult.layer)
            outcome.highestProtocol = .icmp
            outcome.infoSummary = icmpResult.infoSummary

        case 6:
            let tcpResult = try dissectTCP(
                bytes: bytes,
                offset: l4Offset,
                end: ipEnd,
                srcIP: srcIP,
                dstIP: dstIP,
                prefix: prefix
            )
            outcome.layers.append(contentsOf: tcpResult.layers)
            outcome.highestProtocol = tcpResult.highestProtocol
            outcome.sourcePort = tcpResult.srcPort
            outcome.destinationPort = tcpResult.dstPort
            outcome.tcpFlags = tcpResult.flags
            outcome.dnsQueryName = tcpResult.dnsQueryName
            outcome.tlsSNI = tcpResult.tlsSNI
            outcome.tlsALPN = tcpResult.tlsALPN
            outcome.httpHost = tcpResult.httpHost
            outcome.httpRequestLine = tcpResult.httpRequestLine
            outcome.infoSummary = tcpResult.infoSummary

        case 17:
            let udpResult = try dissectUDP(
                bytes: bytes,
                offset: l4Offset,
                end: ipEnd,
                srcIP: srcIP,
                dstIP: dstIP,
                prefix: prefix
            )
            outcome.layers.append(contentsOf: udpResult.layers)
            outcome.highestProtocol = udpResult.highestProtocol
            outcome.sourcePort = udpResult.srcPort
            outcome.destinationPort = udpResult.dstPort
            outcome.dnsQueryName = udpResult.dnsQueryName
            outcome.infoSummary = udpResult.infoSummary

        default:
            let rawLen = max(0, ipEnd - l4Offset)
            if rawLen > 0 {
                outcome.layers.append(
                    DissectedLayer(
                        id: "\(prefix).layer.l4_raw",
                        protocolKind: .unknown,
                        title: "IPv4 Payload (Protocol \(proto))",
                        summary: "\(rawLen) bytes",
                        byteOffset: l4Offset,
                        byteLength: rawLen,
                        fields: [
                            DissectedField(
                                id: "\(prefix).l4_raw.preview",
                                label: "Data",
                                valueSummary: Self.hexPreview(bytes, offset: l4Offset, length: min(rawLen, 24)),
                                byteOffset: l4Offset,
                                byteLength: rawLen
                            )
                        ]
                    )
                )
            }
        }

        return outcome
    }

    private func dissectIPv4Options(
        bytes: [UInt8],
        start: Int,
        end: Int,
        prefix: String
    ) -> [DissectedField] {
        var result: [DissectedField] = []
        var idx = start
        while idx < end {
            let optType = bytes[idx]
            if optType == 0 {
                result.append(
                    DissectedField(
                        id: "\(prefix).ipv4.opt.\(idx)",
                        label: "End of Options List (EOOL)",
                        valueSummary: "Type 0",
                        byteOffset: idx,
                        byteLength: end - idx
                    )
                )
                break
            } else if optType == 1 {
                result.append(
                    DissectedField(
                        id: "\(prefix).ipv4.opt.\(idx)",
                        label: "No-Operation (NOP)",
                        valueSummary: "Type 1",
                        byteOffset: idx,
                        byteLength: 1
                    )
                )
                idx += 1
            } else {
                guard idx + 1 < end else { break }
                let optLen = Int(bytes[idx + 1])
                guard optLen >= 2 && idx + optLen <= end else {
                    result.append(
                        DissectedField(
                            id: "\(prefix).ipv4.opt.\(idx)",
                            label: "Malformed IPv4 Option",
                            valueSummary: "Type \(optType), Length \(optLen)",
                            byteOffset: idx,
                            byteLength: end - idx
                        )
                    )
                    break
                }
                let optName: String
                switch optType {
                case 7: optName = "Record Route (RR)"
                case 68: optName = "Internet Timestamp"
                case 130: optName = "Security"
                case 131: optName = "Loose Source Route (LSRR)"
                case 137: optName = "Strict Source Route (SSRR)"
                case 148: optName = "Router Alert"
                default: optName = "Option \(optType)"
                }
                result.append(
                    DissectedField(
                        id: "\(prefix).ipv4.opt.\(idx)",
                        label: optName,
                        valueSummary: "Length \(optLen) bytes",
                        byteOffset: idx,
                        byteLength: optLen
                    )
                )
                idx += optLen
            }
        }
        return result
    }

    // MARK: - ICMPv4 Dissection (Protocol 1)

    private func dissectICMPv4(
        bytes: [UInt8],
        offset: Int,
        end: Int,
        srcIP: IPv4Address,
        dstIP: IPv4Address,
        prefix: String
    ) throws -> (layer: DissectedLayer, infoSummary: String) {
        let length = end - offset
        guard length >= 4 else {
            throw AgentVMError.networkFrameMalformed(
                layer: "ICMPv4",
                detail: "ICMPv4 packet requires at least 4 bytes at offset \(offset), got \(length)."
            )
        }

        let icmpType = bytes[offset]
        let icmpCode = bytes[offset + 1]
        let checksum = Self.readUInt16BE(bytes, at: offset + 2)

        let checksumStatus: String
        if verifyChecksums {
            var copy = Array(bytes[offset..<end])
            copy[2] = 0
            copy[3] = 0
            let expected = BinaryChecksums.rfc1071Checksum(copy)
            let residual = BinaryChecksums.rfc1071Checksum(Array(bytes[offset..<end]))
            checksumStatus = (residual == 0 || checksum == expected)
                ? String(format: "0x%04X [Verified]", checksum)
                : String(format: "0x%04X [Invalid, expected 0x%04X]", checksum, expected)
        } else {
            checksumStatus = String(format: "0x%04X", checksum)
        }

        let (typeDesc, codeDesc) = Self.describeICMPTypeAndCode(type: icmpType, code: icmpCode)

        var fields: [DissectedField] = [
            DissectedField(
                id: "\(prefix).icmp.type",
                label: "Type",
                valueSummary: "\(icmpType) (\(typeDesc))",
                byteOffset: offset,
                byteLength: 1
            ),
            DissectedField(
                id: "\(prefix).icmp.code",
                label: "Code",
                valueSummary: "\(icmpCode) (\(codeDesc))",
                byteOffset: offset + 1,
                byteLength: 1
            ),
            DissectedField(
                id: "\(prefix).icmp.checksum",
                label: "Checksum",
                valueSummary: checksumStatus,
                byteOffset: offset + 2,
                byteLength: 2
            )
        ]

        var infoSummary = "ICMP \(typeDesc) (\(codeDesc)) \(srcIP) -> \(dstIP)"

        if (icmpType == 0 || icmpType == 8) && length >= 8 {
            let ident = Self.readUInt16BE(bytes, at: offset + 4)
            let seq = Self.readUInt16BE(bytes, at: offset + 6)
            fields.append(
                DissectedField(
                    id: "\(prefix).icmp.id",
                    label: "Identifier",
                    valueSummary: String(format: "0x%04X (%u)", ident, ident),
                    byteOffset: offset + 4,
                    byteLength: 2
                )
            )
            fields.append(
                DissectedField(
                    id: "\(prefix).icmp.seq",
                    label: "Sequence Number",
                    valueSummary: "\(seq) (0x\(String(format: "%04X", seq)))",
                    byteOffset: offset + 6,
                    byteLength: 2
                )
            )
            let dataLen = end - (offset + 8)
            if dataLen > 0 {
                fields.append(
                    DissectedField(
                        id: "\(prefix).icmp.data",
                        label: "Echo Payload",
                        valueSummary: "\(dataLen) bytes (\(Self.hexPreview(bytes, offset: offset + 8, length: min(dataLen, 16))))",
                        byteOffset: offset + 8,
                        byteLength: dataLen
                    )
                )
            }
            infoSummary = "ICMP \(typeDesc) id=\(String(format: "0x%04X", ident)) seq=\(seq) ttl-path \(srcIP) -> \(dstIP)"
        } else if (icmpType == 3 || icmpType == 11) && length >= 8 {
            let nextHopMTU = Self.readUInt16BE(bytes, at: offset + 6)
            fields.append(
                DissectedField(
                    id: "\(prefix).icmp.unused",
                    label: icmpType == 3 && icmpCode == 4 ? "Next-Hop MTU" : "Unused Header Word",
                    valueSummary: icmpType == 3 && icmpCode == 4 ? "\(nextHopMTU)" : "0x00000000",
                    byteOffset: offset + 4,
                    byteLength: 4
                )
            )
            let quotedLen = end - (offset + 8)
            if quotedLen >= 20 {
                let quotedDst = IPv4Address(rawHostOrder: Self.readUInt32BE(bytes, at: offset + 8 + 16))
                fields.append(
                    DissectedField(
                        id: "\(prefix).icmp.quoted_ip",
                        label: "Quoted Original IPv4 Header",
                        valueSummary: "Original Dst: \(quotedDst) (\(quotedLen) bytes)",
                        byteOffset: offset + 8,
                        byteLength: quotedLen
                    )
                )
            }
        } else if length > 4 {
            fields.append(
                DissectedField(
                    id: "\(prefix).icmp.rest",
                    label: "ICMP Body",
                    valueSummary: "\(length - 4) bytes",
                    byteOffset: offset + 4,
                    byteLength: length - 4
                )
            )
        }

        let layer = DissectedLayer(
            id: "\(prefix).layer.icmp",
            protocolKind: .icmp,
            title: "Internet Control Message Protocol",
            summary: "\(typeDesc) (Type \(icmpType), Code \(icmpCode))",
            byteOffset: offset,
            byteLength: length,
            fields: fields
        )
        return (layer, infoSummary)
    }

    // MARK: - UDP + DHCPv4 + DNS Dissection (Protocol 17)

    private struct UDPDissectionOutcome {
        var layers: [DissectedLayer]
        var highestProtocol: DissectedProtocolKind
        var srcPort: UInt16
        var dstPort: UInt16
        var dnsQueryName: String?
        var infoSummary: String
    }

    private func dissectUDP(
        bytes: [UInt8],
        offset: Int,
        end: Int,
        srcIP: IPv4Address,
        dstIP: IPv4Address,
        prefix: String
    ) throws -> UDPDissectionOutcome {
        let available = end - offset
        guard available >= 8 else {
            throw AgentVMError.networkFrameMalformed(
                layer: "UDP",
                detail: "UDP header requires 8 bytes at offset \(offset), only \(available) left."
            )
        }

        let srcPort = Self.readUInt16BE(bytes, at: offset)
        let dstPort = Self.readUInt16BE(bytes, at: offset + 2)
        let udpLength = Int(Self.readUInt16BE(bytes, at: offset + 4))
        let checksum = Self.readUInt16BE(bytes, at: offset + 6)

        guard udpLength >= 8 && offset + udpLength <= end else {
            throw AgentVMError.networkFrameMalformed(
                layer: "UDP",
                detail: "Invalid UDP length \(udpLength) at offset \(offset) (IP payload \(available) bytes)."
            )
        }

        let udpEnd = offset + udpLength
        let checksumText: String
        if checksum == 0 {
            checksumText = "0x0000 [None / Optional in IPv4]"
        } else if verifyChecksums {
            var seg = Array(bytes[offset..<udpEnd])
            seg[6] = 0
            seg[7] = 0
            var expected = BinaryChecksums.ipv4TransportChecksum(
                srcIP: srcIP,
                dstIP: dstIP,
                protocolNumber: 17,
                segmentBytes: seg
            )
            if expected == 0 { expected = 0xFFFF }
            let residual = BinaryChecksums.ipv4TransportChecksum(
                srcIP: srcIP,
                dstIP: dstIP,
                protocolNumber: 17,
                segmentBytes: Array(bytes[offset..<udpEnd])
            )
            checksumText = (residual == 0 || checksum == expected)
                ? String(format: "0x%04X [Verified]", checksum)
                : String(format: "0x%04X [Invalid, expected 0x%04X]", checksum, expected)
        } else {
            checksumText = String(format: "0x%04X", checksum)
        }

        let payloadOffset = offset + 8
        let payloadLength = udpEnd - payloadOffset

        let udpFields: [DissectedField] = [
            DissectedField(
                id: "\(prefix).udp.srcport",
                label: "Source Port",
                valueSummary: "\(srcPort)",
                byteOffset: offset,
                byteLength: 2
            ),
            DissectedField(
                id: "\(prefix).udp.dstport",
                label: "Destination Port",
                valueSummary: "\(dstPort)",
                byteOffset: offset + 2,
                byteLength: 2
            ),
            DissectedField(
                id: "\(prefix).udp.length",
                label: "Length",
                valueSummary: "\(udpLength) bytes (payload \(payloadLength) bytes)",
                byteOffset: offset + 4,
                byteLength: 2
            ),
            DissectedField(
                id: "\(prefix).udp.checksum",
                label: "Checksum",
                valueSummary: checksumText,
                byteOffset: offset + 6,
                byteLength: 2
            )
        ]

        let udpLayer = DissectedLayer(
            id: "\(prefix).layer.udp",
            protocolKind: .udp,
            title: "User Datagram Protocol",
            summary: "Src Port: \(srcPort), Dst Port: \(dstPort), Len: \(payloadLength)",
            byteOffset: offset,
            byteLength: 8,
            fields: udpFields
        )

        var layers: [DissectedLayer] = [udpLayer]
        var highest: DissectedProtocolKind = .udp
        var dnsName: String? = nil
        var info = "UDP \(srcIP):\(srcPort) -> \(dstIP):\(dstPort) Len=\(payloadLength)"

        if (srcPort == 67 || srcPort == 68 || dstPort == 67 || dstPort == 68) && payloadLength >= 240 {
            if let dhcpResult = try dissectDHCPv4(
                bytes: bytes,
                offset: payloadOffset,
                end: udpEnd,
                prefix: prefix
            ) {
                layers.append(dhcpResult.layer)
                highest = .dhcp
                info = dhcpResult.infoSummary
            }
        } else if (srcPort == 53 || dstPort == 53) && payloadLength > 0 {
            let dnsResult = try dissectDNS(
                bytes: bytes,
                offset: payloadOffset,
                end: udpEnd,
                prefix: prefix
            )
            layers.append(dnsResult.layer)
            highest = .dns
            dnsName = dnsResult.message.questions.first?.name
            info = dnsResult.infoSummary
        } else if payloadLength > 0 {
            layers.append(
                DissectedLayer(
                    id: "\(prefix).layer.udp_payload",
                    protocolKind: .udp,
                    title: "UDP Payload",
                    summary: "\(payloadLength) bytes",
                    byteOffset: payloadOffset,
                    byteLength: payloadLength,
                    fields: [
                        DissectedField(
                            id: "\(prefix).udp.payload",
                            label: "Datagram Data",
                            valueSummary: Self.hexPreview(bytes, offset: payloadOffset, length: min(payloadLength, 24)),
                            byteOffset: payloadOffset,
                            byteLength: payloadLength
                        )
                    ]
                )
            )
        }

        return UDPDissectionOutcome(
            layers: layers,
            highestProtocol: highest,
            srcPort: srcPort,
            dstPort: dstPort,
            dnsQueryName: dnsName,
            infoSummary: info
        )
    }

    // MARK: - DHCPv4 Dissection (UDP Ports 67 / 68, RFC 2131 & RFC 2132)

    public func parseDHCPv4Message(bytes: [UInt8], offset: Int, end: Int) throws -> DissectedDHCPMessage? {
        guard end - offset >= 240 else { return nil }
        let magic = Self.readUInt32BE(bytes, at: offset + 236)
        guard magic == 0x6382_5363 else { return nil }

        let op = bytes[offset]
        let xid = Self.readUInt32BE(bytes, at: offset + 4)
        let flags = Self.readUInt16BE(bytes, at: offset + 10)
        let ciaddr = IPv4Address(rawHostOrder: Self.readUInt32BE(bytes, at: offset + 12))
        let yiaddr = IPv4Address(rawHostOrder: Self.readUInt32BE(bytes, at: offset + 16))
        let siaddr = IPv4Address(rawHostOrder: Self.readUInt32BE(bytes, at: offset + 20))
        let giaddr = IPv4Address(rawHostOrder: Self.readUInt32BE(bytes, at: offset + 24))
        let chaddr = MACAddress(octets: Array(bytes[(offset + 28)..<(offset + 34)]))

        var msg = DissectedDHCPMessage(
            op: op,
            transactionID: xid,
            flags: flags,
            clientIP: ciaddr,
            yourIP: yiaddr,
            serverIP: siaddr,
            relayAgentIP: giaddr,
            clientMAC: chaddr
        )

        var idx = offset + 240
        while idx < end {
            let code = bytes[idx]
            if code == 255 { break }
            if code == 0 {
                idx += 1
                continue
            }
            guard idx + 1 < end else { break }
            let optLen = Int(bytes[idx + 1])
            let valStart = idx + 2
            guard valStart + optLen <= end else { break }

            switch code {
            case 1 where optLen == 4:
                msg.subnetMask = IPv4Address(rawHostOrder: Self.readUInt32BE(bytes, at: valStart))
            case 3 where optLen >= 4:
                msg.routerIP = IPv4Address(rawHostOrder: Self.readUInt32BE(bytes, at: valStart))
            case 6 where optLen >= 4 && optLen % 4 == 0:
                var servers: [IPv4Address] = []
                for pos in stride(from: valStart, to: valStart + optLen, by: 4) {
                    servers.append(IPv4Address(rawHostOrder: Self.readUInt32BE(bytes, at: pos)))
                }
                msg.dnsServers = servers
            case 12 where optLen > 0:
                msg.hostname = String(decoding: bytes[valStart..<(valStart + optLen)], as: UTF8.self)
            case 15 where optLen > 0:
                msg.domainName = String(decoding: bytes[valStart..<(valStart + optLen)], as: UTF8.self)
            case 50 where optLen == 4:
                msg.requestedIP = IPv4Address(rawHostOrder: Self.readUInt32BE(bytes, at: valStart))
            case 51 where optLen == 4:
                msg.leaseTimeSeconds = Self.readUInt32BE(bytes, at: valStart)
            case 53 where optLen == 1:
                msg.messageType = bytes[valStart]
            case 54 where optLen == 4:
                msg.serverIdentifier = IPv4Address(rawHostOrder: Self.readUInt32BE(bytes, at: valStart))
            default:
                break
            }
            idx = valStart + optLen
        }

        return msg
    }

    private func dissectDHCPv4(
        bytes: [UInt8],
        offset: Int,
        end: Int,
        prefix: String
    ) throws -> (layer: DissectedLayer, message: DissectedDHCPMessage, infoSummary: String)? {
        guard let msg = try parseDHCPv4Message(bytes: bytes, offset: offset, end: end) else {
            return nil
        }

        var fields: [DissectedField] = [
            DissectedField(
                id: "\(prefix).dhcp.op",
                label: "Message Boot Opcode",
                valueSummary: msg.op == 1 ? "1 (Boot Request)" : (msg.op == 2 ? "2 (Boot Reply)" : "\(msg.op)"),
                byteOffset: offset,
                byteLength: 1
            ),
            DissectedField(
                id: "\(prefix).dhcp.htype",
                label: "Hardware Type",
                valueSummary: "\(bytes[offset + 1]) (Ethernet)",
                byteOffset: offset + 1,
                byteLength: 2
            ),
            DissectedField(
                id: "\(prefix).dhcp.xid",
                label: "Transaction ID",
                valueSummary: String(format: "0x%08X", msg.transactionID),
                byteOffset: offset + 4,
                byteLength: 4
            ),
            DissectedField(
                id: "\(prefix).dhcp.flags",
                label: "Bootp Flags",
                valueSummary: (msg.flags & 0x8000) != 0 ? "0x8000 (Broadcast)" : String(format: "0x%04X (Unicast)", msg.flags),
                byteOffset: offset + 10,
                byteLength: 2
            ),
            DissectedField(
                id: "\(prefix).dhcp.ciaddr",
                label: "Client IP Address (ciaddr)",
                valueSummary: msg.clientIP.description,
                byteOffset: offset + 12,
                byteLength: 4
            ),
            DissectedField(
                id: "\(prefix).dhcp.yiaddr",
                label: "Your Client IP Address (yiaddr)",
                valueSummary: msg.yourIP.description,
                byteOffset: offset + 16,
                byteLength: 4
            ),
            DissectedField(
                id: "\(prefix).dhcp.siaddr",
                label: "Next Server IP Address (siaddr)",
                valueSummary: msg.serverIP.description,
                byteOffset: offset + 20,
                byteLength: 4
            ),
            DissectedField(
                id: "\(prefix).dhcp.chaddr",
                label: "Client Hardware Address (chaddr)",
                valueSummary: msg.clientMAC.description,
                byteOffset: offset + 28,
                byteLength: 16
            ),
            DissectedField(
                id: "\(prefix).dhcp.cookie",
                label: "DHCP Magic Cookie",
                valueSummary: "0x63825363",
                byteOffset: offset + 236,
                byteLength: 4
            )
        ]

        var optionChildren: [DissectedField] = []
        var idx = offset + 240
        while idx < end {
            let code = bytes[idx]
            if code == 255 {
                optionChildren.append(
                    DissectedField(
                        id: "\(prefix).dhcp.opt.end.\(idx)",
                        label: "Option (255) End",
                        valueSummary: "0xFF",
                        byteOffset: idx,
                        byteLength: 1
                    )
                )
                idx += 1
                break
            }
            if code == 0 {
                idx += 1
                continue
            }
            guard idx + 1 < end else { break }
            let optLen = Int(bytes[idx + 1])
            let valStart = idx + 2
            guard valStart + optLen <= end else { break }

            let (optTitle, optSummary) = Self.describeDHCPOption(
                code: code,
                bytes: Array(bytes[valStart..<(valStart + optLen)])
            )
            optionChildren.append(
                DissectedField(
                    id: "\(prefix).dhcp.opt.\(code).\(idx)",
                    label: optTitle,
                    valueSummary: optSummary,
                    byteOffset: idx,
                    byteLength: 2 + optLen
                )
            )
            idx = valStart + optLen
        }

        if !optionChildren.isEmpty {
            fields.append(
                DissectedField(
                    id: "\(prefix).dhcp.options",
                    label: "DHCP Options",
                    valueSummary: "\(optionChildren.count) option(s)",
                    byteOffset: offset + 240,
                    byteLength: end - (offset + 240),
                    children: optionChildren
                )
            )
        }

        let typeLabel = Self.describeDHCPMessageType(msg.messageType)
        let xidHex = String(format: "0x%08X", msg.transactionID)
        let info: String
        switch msg.messageType {
        case 1:
            info = "DHCP Discover - Transaction ID \(xidHex) (\(msg.clientMAC))"
        case 2:
            info = "DHCP Offer    - \(msg.yourIP) from \(msg.serverIdentifier ?? msg.serverIP) (\(xidHex))"
        case 3:
            let req = msg.requestedIP ?? msg.yourIP
            info = "DHCP Request  - Requested \(req) (\(xidHex))"
        case 5:
            info = "DHCP ACK      - Assigned \(msg.yourIP) lease=\(msg.leaseTimeSeconds ?? 0)s (\(xidHex))"
        case 6:
            info = "DHCP NAK      - Transaction ID \(xidHex)"
        default:
            info = "DHCP \(typeLabel) - Transaction ID \(xidHex)"
        }

        let layer = DissectedLayer(
            id: "\(prefix).layer.dhcp",
            protocolKind: .dhcp,
            title: "Dynamic Host Configuration Protocol (\(typeLabel))",
            summary: info,
            byteOffset: offset,
            byteLength: end - offset,
            fields: fields
        )
        return (layer, msg, info)
    }

    // MARK: - DNS Dissection with Safe RFC 1035 Pointer Loop Guard

    /// Safely decodes an RFC 1035 domain name inside `dnsMessage` starting at `relativeOffset`.
    /// Enforces strict loop detection and maximum pointer jumps to prevent infinite decompression attacks.
    public static func decodeDNSName(
        in dnsMessage: [UInt8],
        at relativeOffset: Int,
        maxPointerJumps: Int = 32
    ) throws -> (name: String, bytesConsumedAtStart: Int) {
        guard relativeOffset >= 0 && relativeOffset < dnsMessage.count else {
            throw AgentVMError.networkFrameMalformed(
                layer: "DNS",
                detail: "DNS label start offset \(relativeOffset) out of bounds (\(dnsMessage.count) bytes)."
            )
        }

        var labels: [String] = []
        var cursor = relativeOffset
        var consumedAtOrigin = 0
        var jumpedViaPointer = false
        var pointerJumps = 0
        var visitedOffsets: Set<Int> = []
        var totalDecodedChars = 0

        while true {
            guard cursor >= 0 && cursor < dnsMessage.count else {
                throw AgentVMError.networkFrameMalformed(
                    layer: "DNS",
                    detail: "Truncated DNS label at offset \(cursor)."
                )
            }

            let tag = dnsMessage[cursor]

            if tag == 0x00 {
                if !jumpedViaPointer {
                    consumedAtOrigin += 1
                }
                break
            } else if (tag & 0xC0) == 0xC0 {
                // RFC 1035 Section 4.1.4 14-bit Compression Pointer
                guard cursor + 1 < dnsMessage.count else {
                    throw AgentVMError.networkFrameMalformed(
                        layer: "DNS",
                        detail: "Truncated 2-byte DNS compression pointer at offset \(cursor)."
                    )
                }
                if !jumpedViaPointer {
                    consumedAtOrigin += 2
                    jumpedViaPointer = true
                }
                pointerJumps += 1
                if pointerJumps > maxPointerJumps {
                    throw AgentVMError.networkFrameMalformed(
                        layer: "DNS",
                        detail: "DNS compression pointer exceeded maximum jump limit (\(maxPointerJumps))."
                    )
                }

                let targetOffset = (Int(tag & 0x3F) << 8) | Int(dnsMessage[cursor + 1])
                guard targetOffset >= 0 && targetOffset < dnsMessage.count else {
                    throw AgentVMError.networkFrameMalformed(
                        layer: "DNS",
                        detail: "DNS compression pointer target \(targetOffset) outside message (\(dnsMessage.count) bytes)."
                    )
                }
                if !visitedOffsets.insert(cursor).inserted || visitedOffsets.contains(targetOffset) {
                    throw AgentVMError.networkFrameMalformed(
                        layer: "DNS",
                        detail: "RFC 1035 DNS compression pointer loop detected (\(cursor) -> \(targetOffset))."
                    )
                }
                cursor = targetOffset
            } else if (tag & 0xC0) == 0x00 {
                let labelLen = Int(tag)
                let labelStart = cursor + 1
                let labelEnd = labelStart + labelLen
                guard labelEnd <= dnsMessage.count else {
                    throw AgentVMError.networkFrameMalformed(
                        layer: "DNS",
                        detail: "DNS label length \(labelLen) at offset \(cursor) exceeds DNS payload."
                    )
                }
                visitedOffsets.insert(cursor)
                let labelText = String(decoding: dnsMessage[labelStart..<labelEnd], as: UTF8.self)
                labels.append(labelText)
                totalDecodedChars += labelLen + 1
                if totalDecodedChars > 255 {
                    throw AgentVMError.networkFrameMalformed(
                        layer: "DNS",
                        detail: "Decoded DNS domain name exceeds RFC 1035 255-octet maximum."
                    )
                }
                if !jumpedViaPointer {
                    consumedAtOrigin += 1 + labelLen
                }
                cursor = labelEnd
            } else {
                throw AgentVMError.networkFrameMalformed(
                    layer: "DNS",
                    detail: String(format: "Unsupported DNS extended label bits 0x%02X at offset %d.", tag, cursor)
                )
            }
        }

        let joined = labels.isEmpty ? "." : labels.joined(separator: ".")
        return (joined, consumedAtOrigin)
    }

    private func dissectDNS(
        bytes: [UInt8],
        offset: Int,
        end: Int,
        prefix: String
    ) throws -> (layer: DissectedLayer, message: DissectedDNSMessage, infoSummary: String) {
        let dnsLen = end - offset
        guard dnsLen >= 12 else {
            throw AgentVMError.networkFrameMalformed(
                layer: "DNS",
                detail: "DNS header requires 12 bytes at offset \(offset), got \(dnsLen)."
            )
        }

        let dnsBytes = Array(bytes[offset..<end])
        let txID = Self.readUInt16BE(dnsBytes, at: 0)
        let flags = Self.readUInt16BE(dnsBytes, at: 2)
        let isResponse = ((flags >> 15) & 0x01) != 0
        let opcode = UInt8((flags >> 11) & 0x0F)
        let authoritative = ((flags >> 10) & 0x01) != 0
        let truncated = ((flags >> 9) & 0x01) != 0
        let recursionDesired = ((flags >> 8) & 0x01) != 0
        let recursionAvailable = ((flags >> 7) & 0x01) != 0
        let rcode = UInt8(flags & 0x0F)

        let qdCount = Int(Self.readUInt16BE(dnsBytes, at: 4))
        let anCount = Int(Self.readUInt16BE(dnsBytes, at: 6))
        let nsCount = Int(Self.readUInt16BE(dnsBytes, at: 8))
        let arCount = Int(Self.readUInt16BE(dnsBytes, at: 10))

        var fields: [DissectedField] = [
            DissectedField(
                id: "\(prefix).dns.id",
                label: "Transaction ID",
                valueSummary: String(format: "0x%04X", txID),
                byteOffset: offset,
                byteLength: 2
            ),
            DissectedField(
                id: "\(prefix).dns.flags",
                label: "Flags",
                valueSummary: String(
                    format: "0x%04X (%@, Opcode=%u, RCODE=%@)",
                    flags,
                    isResponse ? "Response" : "Standard Query",
                    opcode,
                    Self.describeDNSRCode(rcode)
                ),
                byteOffset: offset + 2,
                byteLength: 2,
                children: [
                    DissectedField(
                        id: "\(prefix).dns.flags.qr",
                        label: "QR",
                        valueSummary: isResponse ? "1 (Response)" : "0 (Query)",
                        byteOffset: offset + 2,
                        byteLength: 1
                    ),
                    DissectedField(
                        id: "\(prefix).dns.flags.rd",
                        label: "Recursion Desired (RD)",
                        valueSummary: recursionDesired ? "1" : "0",
                        byteOffset: offset + 2,
                        byteLength: 1
                    ),
                    DissectedField(
                        id: "\(prefix).dns.flags.ra",
                        label: "Recursion Available (RA)",
                        valueSummary: recursionAvailable ? "1" : "0",
                        byteOffset: offset + 3,
                        byteLength: 1
                    ),
                    DissectedField(
                        id: "\(prefix).dns.flags.rcode",
                        label: "Reply Code (RCODE)",
                        valueSummary: "\(rcode) (\(Self.describeDNSRCode(rcode)))",
                        byteOffset: offset + 3,
                        byteLength: 1
                    )
                ]
            ),
            DissectedField(
                id: "\(prefix).dns.qdcount",
                label: "Questions (QDCOUNT)",
                valueSummary: "\(qdCount)",
                byteOffset: offset + 4,
                byteLength: 2
            ),
            DissectedField(
                id: "\(prefix).dns.ancount",
                label: "Answer RRs (ANCOUNT)",
                valueSummary: "\(anCount)",
                byteOffset: offset + 6,
                byteLength: 2
            ),
            DissectedField(
                id: "\(prefix).dns.nscount",
                label: "Authority RRs (NSCOUNT)",
                valueSummary: "\(nsCount)",
                byteOffset: offset + 8,
                byteLength: 2
            ),
            DissectedField(
                id: "\(prefix).dns.arcount",
                label: "Additional RRs (ARCOUNT)",
                valueSummary: "\(arCount)",
                byteOffset: offset + 10,
                byteLength: 2
            )
        ]

        var cursor = 12
        var questions: [DissectedDNSQuestion] = []
        var questionFields: [DissectedField] = []

        for qIdx in 0..<qdCount {
            let qStart = cursor
            let (qname, nameBytes) = try Self.decodeDNSName(in: dnsBytes, at: cursor)
            cursor += nameBytes
            guard cursor + 4 <= dnsBytes.count else {
                throw AgentVMError.networkFrameMalformed(
                    layer: "DNS",
                    detail: "Truncated DNS question #\(qIdx) QTYPE/QCLASS at relative offset \(cursor)."
                )
            }
            let qtype = Self.readUInt16BE(dnsBytes, at: cursor)
            let qclass = Self.readUInt16BE(dnsBytes, at: cursor + 2)
            cursor += 4

            questions.append(DissectedDNSQuestion(name: qname, qtype: qtype, qclass: qclass))
            questionFields.append(
                DissectedField(
                    id: "\(prefix).dns.q.\(qIdx)",
                    label: "\(qname): type \(Self.describeDNSRecordType(qtype)), class IN",
                    valueSummary: "QTYPE=\(Self.describeDNSRecordType(qtype)) (\(qtype))",
                    byteOffset: offset + qStart,
                    byteLength: cursor - qStart,
                    children: [
                        DissectedField(
                            id: "\(prefix).dns.q.\(qIdx).name",
                            label: "QNAME",
                            valueSummary: qname,
                            byteOffset: offset + qStart,
                            byteLength: nameBytes
                        ),
                        DissectedField(
                            id: "\(prefix).dns.q.\(qIdx).type",
                            label: "QTYPE",
                            valueSummary: "\(Self.describeDNSRecordType(qtype)) (\(qtype))",
                            byteOffset: offset + qStart + nameBytes,
                            byteLength: 2
                        ),
                        DissectedField(
                            id: "\(prefix).dns.q.\(qIdx).class",
                            label: "QCLASS",
                            valueSummary: qclass == 1 ? "IN (0x0001)" : String(format: "0x%04X", qclass),
                            byteOffset: offset + qStart + nameBytes + 2,
                            byteLength: 2
                        )
                    ]
                )
            )
        }

        if !questionFields.isEmpty {
            let firstByte = questionFields.first!.byteOffset
            let lastField = questionFields.last!
            fields.append(
                DissectedField(
                    id: "\(prefix).dns.questions",
                    label: "Queries",
                    valueSummary: "\(questionFields.count) question(s)",
                    byteOffset: firstByte,
                    byteLength: (lastField.byteOffset + lastField.byteLength) - firstByte,
                    children: questionFields
                )
            )
        }

        var answers: [DissectedDNSAnswer] = []
        var answerFields: [DissectedField] = []

        for aIdx in 0..<anCount {
            guard cursor < dnsBytes.count else { break }
            let rrStart = cursor
            let (rname, nameBytes) = try Self.decodeDNSName(in: dnsBytes, at: cursor)
            cursor += nameBytes
            guard cursor + 10 <= dnsBytes.count else {
                throw AgentVMError.networkFrameMalformed(
                    layer: "DNS",
                    detail: "Truncated DNS Answer RR #\(aIdx) fixed fields at offset \(cursor)."
                )
            }
            let rtype = Self.readUInt16BE(dnsBytes, at: cursor)
            let rclass = Self.readUInt16BE(dnsBytes, at: cursor + 2)
            let ttl = Self.readUInt32BE(dnsBytes, at: cursor + 4)
            let rdLength = Int(Self.readUInt16BE(dnsBytes, at: cursor + 8))
            let rdataOffset = cursor + 10
            guard rdataOffset + rdLength <= dnsBytes.count else {
                throw AgentVMError.networkFrameMalformed(
                    layer: "DNS",
                    detail: "DNS Answer RR #\(aIdx) RDLENGTH \(rdLength) exceeds DNS payload."
                )
            }

            let (rdataSummary, resolvedIPv4) = try Self.decodeDNSRData(
                rtype: rtype,
                dnsBytes: dnsBytes,
                rdataOffset: rdataOffset,
                rdLength: rdLength
            )
            cursor = rdataOffset + rdLength

            answers.append(
                DissectedDNSAnswer(
                    name: rname,
                    rtype: rtype,
                    rclass: rclass,
                    ttl: ttl,
                    valueSummary: rdataSummary,
                    ipv4Address: resolvedIPv4
                )
            )
            answerFields.append(
                DissectedField(
                    id: "\(prefix).dns.an.\(aIdx)",
                    label: "\(rname): type \(Self.describeDNSRecordType(rtype)), ttl \(ttl)s",
                    valueSummary: rdataSummary,
                    byteOffset: offset + rrStart,
                    byteLength: cursor - rrStart,
                    children: [
                        DissectedField(
                            id: "\(prefix).dns.an.\(aIdx).name",
                            label: "NAME",
                            valueSummary: rname,
                            byteOffset: offset + rrStart,
                            byteLength: nameBytes
                        ),
                        DissectedField(
                            id: "\(prefix).dns.an.\(aIdx).type",
                            label: "TYPE",
                            valueSummary: "\(Self.describeDNSRecordType(rtype)) (\(rtype))",
                            byteOffset: offset + rrStart + nameBytes,
                            byteLength: 2
                        ),
                        DissectedField(
                            id: "\(prefix).dns.an.\(aIdx).ttl",
                            label: "TTL",
                            valueSummary: "\(ttl) seconds",
                            byteOffset: offset + rrStart + nameBytes + 4,
                            byteLength: 4
                        ),
                        DissectedField(
                            id: "\(prefix).dns.an.\(aIdx).rdata",
                            label: "RDATA",
                            valueSummary: rdataSummary,
                            byteOffset: offset + rdataOffset,
                            byteLength: rdLength
                        )
                    ]
                )
            )
        }

        if !answerFields.isEmpty {
            let firstByte = answerFields.first!.byteOffset
            let lastField = answerFields.last!
            fields.append(
                DissectedField(
                    id: "\(prefix).dns.answers",
                    label: "Answers",
                    valueSummary: "\(answerFields.count) answer(s)",
                    byteOffset: firstByte,
                    byteLength: (lastField.byteOffset + lastField.byteLength) - firstByte,
                    children: answerFields
                )
            )
        }

        let primaryQ = questions.first
        let qSummary = primaryQ.map { "\(Self.describeDNSRecordType($0.qtype)) \($0.name)" } ?? "(no question)"
        let txHex = String(format: "0x%04X", txID)
        let info: String
        if isResponse {
            if rcode != 0 {
                info = "DNS Response \(txHex) \(Self.describeDNSRCode(rcode)) \(qSummary)"
            } else if !answers.isEmpty {
                let ansJoined = answers.map(\.valueSummary).joined(separator: ", ")
                info = "DNS Response \(txHex) \(qSummary) -> \(ansJoined)"
            } else {
                info = "DNS Response \(txHex) \(qSummary) (0 answers)"
            }
        } else {
            info = "DNS Standard query \(txHex) \(qSummary)"
        }

        let message = DissectedDNSMessage(
            transactionID: txID,
            isResponse: isResponse,
            opcode: opcode,
            authoritative: authoritative,
            truncated: truncated,
            recursionDesired: recursionDesired,
            recursionAvailable: recursionAvailable,
            rcode: rcode,
            questions: questions,
            answers: answers
        )

        let layer = DissectedLayer(
            id: "\(prefix).layer.dns",
            protocolKind: .dns,
            title: "Domain Name System (\(isResponse ? "response" : "query"))",
            summary: info,
            byteOffset: offset,
            byteLength: dnsLen,
            fields: fields
        )
        return (layer, message, info)
    }

    private static func decodeDNSRData(
        rtype: UInt16,
        dnsBytes: [UInt8],
        rdataOffset: Int,
        rdLength: Int
    ) throws -> (String, IPv4Address?) {
        switch rtype {
        case 1 where rdLength == 4:
            let ip = IPv4Address(rawHostOrder: readUInt32BE(dnsBytes, at: rdataOffset))
            return (ip.description, ip)
        case 2, 5, 12:
            let (domain, _) = try decodeDNSName(in: dnsBytes, at: rdataOffset)
            return (domain, nil)
        case 15 where rdLength >= 3:
            let pref = readUInt16BE(dnsBytes, at: rdataOffset)
            let (exchange, _) = try decodeDNSName(in: dnsBytes, at: rdataOffset + 2)
            return ("\(pref) \(exchange)", nil)
        case 16:
            var parts: [String] = []
            var pos = rdataOffset
            let end = rdataOffset + rdLength
            while pos < end {
                let slen = Int(dnsBytes[pos])
                pos += 1
                guard pos + slen <= end else { break }
                parts.append(String(decoding: dnsBytes[pos..<(pos + slen)], as: UTF8.self))
                pos += slen
            }
            return ("\"\(parts.joined(separator: " "))\"", nil)
        case 28 where rdLength == 16:
            let ipv6 = formatIPv6(Array(dnsBytes[rdataOffset..<(rdataOffset + 16)]))
            return (ipv6, nil)
        default:
            return (hexPreview(dnsBytes, offset: rdataOffset, length: min(rdLength, 16)), nil)
        }
    }

    // MARK: - TCP + TLS 1.2/1.3 ClientHello DPI + HTTP/1.x + SSH Dissection (Protocol 6)

    private struct TCPDissectionOutcome {
        var layers: [DissectedLayer]
        var highestProtocol: DissectedProtocolKind
        var srcPort: UInt16
        var dstPort: UInt16
        var flags: TCPFlags
        var dnsQueryName: String?
        var tlsSNI: String?
        var tlsALPN: [String]
        var httpHost: String?
        var httpRequestLine: String?
        var infoSummary: String
    }

    private func dissectTCP(
        bytes: [UInt8],
        offset: Int,
        end: Int,
        srcIP: IPv4Address,
        dstIP: IPv4Address,
        prefix: String
    ) throws -> TCPDissectionOutcome {
        let available = end - offset
        guard available >= 20 else {
            throw AgentVMError.networkFrameMalformed(
                layer: "TCP",
                detail: "TCP header requires at least 20 bytes at offset \(offset), got \(available)."
            )
        }

        let srcPort = Self.readUInt16BE(bytes, at: offset)
        let dstPort = Self.readUInt16BE(bytes, at: offset + 2)
        let seq = Self.readUInt32BE(bytes, at: offset + 4)
        let ack = Self.readUInt32BE(bytes, at: offset + 8)
        let dataOffsetWords = Int(bytes[offset + 12] >> 4)
        let tcpHeaderLen = dataOffsetWords * 4

        guard tcpHeaderLen >= 20 && offset + tcpHeaderLen <= end else {
            throw AgentVMError.networkFrameMalformed(
                layer: "TCP",
                detail: "Invalid TCP Data Offset (\(tcpHeaderLen) bytes) at offset \(offset) for segment of \(available) bytes."
            )
        }

        let flagsByte = bytes[offset + 13]
        let flags = TCPFlags(rawValue: flagsByte)
        let window = Self.readUInt16BE(bytes, at: offset + 14)
        let checksum = Self.readUInt16BE(bytes, at: offset + 16)
        let urgentPointer = Self.readUInt16BE(bytes, at: offset + 18)

        let checksumText: String
        if verifyChecksums {
            var seg = Array(bytes[offset..<end])
            seg[16] = 0
            seg[17] = 0
            let expected = BinaryChecksums.ipv4TransportChecksum(
                srcIP: srcIP,
                dstIP: dstIP,
                protocolNumber: 6,
                segmentBytes: seg
            )
            let residual = BinaryChecksums.ipv4TransportChecksum(
                srcIP: srcIP,
                dstIP: dstIP,
                protocolNumber: 6,
                segmentBytes: Array(bytes[offset..<end])
            )
            checksumText = (residual == 0 || checksum == expected)
                ? String(format: "0x%04X [Verified]", checksum)
                : String(format: "0x%04X [Invalid, expected 0x%04X]", checksum, expected)
        } else {
            checksumText = String(format: "0x%04X", checksum)
        }

        let payloadOffset = offset + tcpHeaderLen
        let payloadLen = end - payloadOffset

        var tcpFields: [DissectedField] = [
            DissectedField(
                id: "\(prefix).tcp.srcport",
                label: "Source Port",
                valueSummary: "\(srcPort)",
                byteOffset: offset,
                byteLength: 2
            ),
            DissectedField(
                id: "\(prefix).tcp.dstport",
                label: "Destination Port",
                valueSummary: "\(dstPort)",
                byteOffset: offset + 2,
                byteLength: 2
            ),
            DissectedField(
                id: "\(prefix).tcp.seq",
                label: "Sequence Number",
                valueSummary: "\(seq)",
                byteOffset: offset + 4,
                byteLength: 4
            ),
            DissectedField(
                id: "\(prefix).tcp.ack",
                label: "Acknowledgment Number",
                valueSummary: "\(ack)",
                byteOffset: offset + 8,
                byteLength: 4
            ),
            DissectedField(
                id: "\(prefix).tcp.hdrlen",
                label: "Data Offset (Header Length)",
                valueSummary: "\(tcpHeaderLen) bytes (\(dataOffsetWords) words)",
                byteOffset: offset + 12,
                byteLength: 1
            ),
            DissectedField(
                id: "\(prefix).tcp.flags",
                label: "Flags",
                valueSummary: String(format: "0x%02X [%@]", flagsByte, flags.description),
                byteOffset: offset + 13,
                byteLength: 1,
                children: Self.buildTCPFlagChildren(flags: flags, offset: offset + 13, prefix: prefix)
            ),
            DissectedField(
                id: "\(prefix).tcp.win",
                label: "Window Size",
                valueSummary: "\(window)",
                byteOffset: offset + 14,
                byteLength: 2
            ),
            DissectedField(
                id: "\(prefix).tcp.checksum",
                label: "Checksum",
                valueSummary: checksumText,
                byteOffset: offset + 16,
                byteLength: 2
            ),
            DissectedField(
                id: "\(prefix).tcp.urgent",
                label: "Urgent Pointer",
                valueSummary: "\(urgentPointer)",
                byteOffset: offset + 18,
                byteLength: 2
            )
        ]

        if tcpHeaderLen > 20 {
            let optChildren = dissectTCPOptions(
                bytes: bytes,
                start: offset + 20,
                end: offset + tcpHeaderLen,
                prefix: prefix
            )
            tcpFields.append(
                DissectedField(
                    id: "\(prefix).tcp.options",
                    label: "TCP Options",
                    valueSummary: "\(tcpHeaderLen - 20) bytes (\(optChildren.count) item(s))",
                    byteOffset: offset + 20,
                    byteLength: tcpHeaderLen - 20,
                    children: optChildren
                )
            )
        }

        let tcpLayer = DissectedLayer(
            id: "\(prefix).layer.tcp",
            protocolKind: .tcp,
            title: "Transmission Control Protocol",
            summary: "\(srcPort) -> \(dstPort) [\(flags.description)] Seq=\(seq) Ack=\(ack) Win=\(window) Len=\(payloadLen)",
            byteOffset: offset,
            byteLength: tcpHeaderLen,
            fields: tcpFields
        )

        var outcome = TCPDissectionOutcome(
            layers: [tcpLayer],
            highestProtocol: .tcp,
            srcPort: srcPort,
            dstPort: dstPort,
            flags: flags,
            dnsQueryName: nil,
            tlsSNI: nil,
            tlsALPN: [],
            httpHost: nil,
            httpRequestLine: nil,
            infoSummary: "TCP \(srcIP):\(srcPort) -> \(dstIP):\(dstPort) [\(flags.description)] Seq=\(seq) Len=\(payloadLen)"
        )

        guard payloadLen > 0 else {
            return outcome
        }

        // 1) Inspect TLS Record Layer & ClientHello SNI / ALPN DPI
        if let tlsInspection = dissectTLSRecordIfPresent(
            bytes: bytes,
            offset: payloadOffset,
            end: end,
            prefix: prefix
        ) {
            outcome.layers.append(tlsInspection.layer)
            outcome.highestProtocol = .tls
            outcome.tlsSNI = tlsInspection.sni
            outcome.tlsALPN = tlsInspection.alpn
            outcome.infoSummary = tlsInspection.infoSummary
            return outcome
        }

        // 2) Inspect HTTP/1.x Cleartext Request / Response
        if let httpInspection = dissectHTTPMessageIfPresent(
            bytes: bytes,
            offset: payloadOffset,
            end: end,
            prefix: prefix
        ) {
            outcome.layers.append(httpInspection.layer)
            outcome.highestProtocol = .http
            outcome.httpHost = httpInspection.host
            outcome.httpRequestLine = httpInspection.requestLine
            outcome.infoSummary = httpInspection.infoSummary
            return outcome
        }

        // 3) Inspect SSH-2.0 Banner
        if let sshInspection = dissectSSHBannerIfPresent(
            bytes: bytes,
            offset: payloadOffset,
            end: end,
            prefix: prefix
        ) {
            outcome.layers.append(sshInspection.layer)
            outcome.highestProtocol = .ssh
            outcome.infoSummary = sshInspection.infoSummary
            return outcome
        }

        // 4) DNS over TCP (2-byte length prefix on port 53)
        if (srcPort == 53 || dstPort == 53) && payloadLen >= 14 {
            let tcpDNSLen = Int(Self.readUInt16BE(bytes, at: payloadOffset))
            if payloadOffset + 2 + tcpDNSLen <= end && tcpDNSLen >= 12 {
                if let dnsResult = try? dissectDNS(
                    bytes: bytes,
                    offset: payloadOffset + 2,
                    end: payloadOffset + 2 + tcpDNSLen,
                    prefix: prefix
                ) {
                    outcome.layers.append(dnsResult.layer)
                    outcome.highestProtocol = .dns
                    outcome.dnsQueryName = dnsResult.message.questions.first?.name
                    outcome.infoSummary = dnsResult.infoSummary + " [TCP]"
                    return outcome
                }
            }
        }

        outcome.layers.append(
            DissectedLayer(
                id: "\(prefix).layer.tcp_payload",
                protocolKind: .tcp,
                title: "TCP Segment Payload",
                summary: "\(payloadLen) bytes",
                byteOffset: payloadOffset,
                byteLength: payloadLen,
                fields: [
                    DissectedField(
                        id: "\(prefix).tcp.payload",
                        label: "Segment Data",
                        valueSummary: Self.hexPreview(bytes, offset: payloadOffset, length: min(payloadLen, 24)),
                        byteOffset: payloadOffset,
                        byteLength: payloadLen
                    )
                ]
            )
        )
        return outcome
    }

    private func dissectTCPOptions(
        bytes: [UInt8],
        start: Int,
        end: Int,
        prefix: String
    ) -> [DissectedField] {
        var opts: [DissectedField] = []
        var idx = start
        while idx < end {
            let kind = bytes[idx]
            if kind == 0 {
                opts.append(
                    DissectedField(
                        id: "\(prefix).tcp.opt.\(idx)",
                        label: "End of Option List (EOOL)",
                        valueSummary: "Kind 0",
                        byteOffset: idx,
                        byteLength: end - idx
                    )
                )
                break
            } else if kind == 1 {
                opts.append(
                    DissectedField(
                        id: "\(prefix).tcp.opt.\(idx)",
                        label: "No-Operation (NOP)",
                        valueSummary: "Kind 1",
                        byteOffset: idx,
                        byteLength: 1
                    )
                )
                idx += 1
            } else {
                guard idx + 1 < end else { break }
                let len = Int(bytes[idx + 1])
                guard len >= 2 && idx + len <= end else {
                    opts.append(
                        DissectedField(
                            id: "\(prefix).tcp.opt.\(idx)",
                            label: "Malformed TCP Option (Kind \(kind))",
                            valueSummary: "Length \(len)",
                            byteOffset: idx,
                            byteLength: end - idx
                        )
                    )
                    break
                }

                switch (kind, len) {
                case (2, 4):
                    let mss = Self.readUInt16BE(bytes, at: idx + 2)
                    opts.append(
                        DissectedField(
                            id: "\(prefix).tcp.opt.\(idx)",
                            label: "Maximum Segment Size (MSS)",
                            valueSummary: "\(mss) bytes",
                            byteOffset: idx,
                            byteLength: 4
                        )
                    )
                case (3, 3):
                    let shift = bytes[idx + 2]
                    opts.append(
                        DissectedField(
                            id: "\(prefix).tcp.opt.\(idx)",
                            label: "Window Scale (WSOPT)",
                            valueSummary: "Shift count \(shift) (multiplier \(1 << min(Int(shift), 14)))",
                            byteOffset: idx,
                            byteLength: 3
                        )
                    )
                case (4, 2):
                    opts.append(
                        DissectedField(
                            id: "\(prefix).tcp.opt.\(idx)",
                            label: "SACK Permitted",
                            valueSummary: "True",
                            byteOffset: idx,
                            byteLength: 2
                        )
                    )
                case (5, _) where len >= 10 && (len - 2) % 8 == 0:
                    var blocks: [String] = []
                    for pos in stride(from: idx + 2, to: idx + len, by: 8) {
                        let left = Self.readUInt32BE(bytes, at: pos)
                        let right = Self.readUInt32BE(bytes, at: pos + 4)
                        blocks.append("\(left)...\(right)")
                    }
                    opts.append(
                        DissectedField(
                            id: "\(prefix).tcp.opt.\(idx)",
                            label: "Selective ACK (SACK)",
                            valueSummary: blocks.joined(separator: ", "),
                            byteOffset: idx,
                            byteLength: len
                        )
                    )
                case (8, 10):
                    let tsVal = Self.readUInt32BE(bytes, at: idx + 2)
                    let tsEcr = Self.readUInt32BE(bytes, at: idx + 6)
                    opts.append(
                        DissectedField(
                            id: "\(prefix).tcp.opt.\(idx)",
                            label: "Timestamps (TSOPT)",
                            valueSummary: "TSval=\(tsVal), TSecr=\(tsEcr)",
                            byteOffset: idx,
                            byteLength: 10
                        )
                    )
                default:
                    opts.append(
                        DissectedField(
                            id: "\(prefix).tcp.opt.\(idx)",
                            label: "TCP Option Kind \(kind)",
                            valueSummary: "\(len) bytes",
                            byteOffset: idx,
                            byteLength: len
                        )
                    )
                }
                idx += len
            }
        }
        return opts
    }

    // MARK: - TLS 1.2 / 1.3 ClientHello DPI (RFC 5246 / RFC 8446 / RFC 6066 / RFC 7301)

    public func parseTLSClientHello(bytes: [UInt8], offset: Int, end: Int) -> DissectedTLSClientHello? {
        guard end - offset >= 43 else { return nil }
        guard bytes[offset] == 0x16, bytes[offset + 1] == 0x03, bytes[offset + 2] <= 0x04 else {
            return nil
        }
        let recordVersion = Self.readUInt16BE(bytes, at: offset + 1)
        let recordLen = Int(Self.readUInt16BE(bytes, at: offset + 3))
        let recordEnd = min(end, offset + 5 + recordLen)

        let hsOffset = offset + 5
        guard hsOffset + 38 <= recordEnd, bytes[hsOffset] == 0x01 else {
            return nil
        }

        let hsLen = Self.readUInt24BE(bytes, at: hsOffset + 1)
        let hsEnd = min(recordEnd, hsOffset + 4 + hsLen)
        let clientVersion = Self.readUInt16BE(bytes, at: hsOffset + 4)

        var cursor = hsOffset + 6 + 32 // version(2) + random(32)
        guard cursor < hsEnd else { return nil }

        let sessionIDLen = Int(bytes[cursor])
        cursor += 1 + sessionIDLen
        guard cursor + 2 <= hsEnd else { return nil }

        let cipherSuitesByteLen = Int(Self.readUInt16BE(bytes, at: cursor))
        cursor += 2
        guard cursor + cipherSuitesByteLen <= hsEnd, cipherSuitesByteLen % 2 == 0 else { return nil }

        var cipherSuites: [UInt16] = []
        for pos in stride(from: cursor, to: cursor + cipherSuitesByteLen, by: 2) {
            cipherSuites.append(Self.readUInt16BE(bytes, at: pos))
        }
        cursor += cipherSuitesByteLen

        guard cursor < hsEnd else { return nil }
        let compMethodsLen = Int(bytes[cursor])
        cursor += 1 + compMethodsLen

        var serverName: String? = nil
        var alpn: [String] = []
        var supportedVersions: [UInt16] = []
        var extensionTypes: [UInt16] = []

        if cursor + 2 <= hsEnd {
            let extTotalLen = Int(Self.readUInt16BE(bytes, at: cursor))
            cursor += 2
            let extEnd = min(hsEnd, cursor + extTotalLen)

            while cursor + 4 <= extEnd {
                let extType = Self.readUInt16BE(bytes, at: cursor)
                let extLen = Int(Self.readUInt16BE(bytes, at: cursor + 2))
                let extDataStart = cursor + 4
                guard extDataStart + extLen <= extEnd else { break }
                extensionTypes.append(extType)

                switch extType {
                case 0x0000 where extLen >= 5:
                    let listLen = Int(Self.readUInt16BE(bytes, at: extDataStart))
                    var pos = extDataStart + 2
                    let listEnd = min(extDataStart + extLen, pos + listLen)
                    while pos + 3 <= listEnd {
                        let nameType = bytes[pos]
                        let nameLen = Int(Self.readUInt16BE(bytes, at: pos + 1))
                        pos += 3
                        guard pos + nameLen <= listEnd else { break }
                        if nameType == 0x00 {
                            serverName = String(decoding: bytes[pos..<(pos + nameLen)], as: UTF8.self)
                            break
                        }
                        pos += nameLen
                    }

                case 0x0010 where extLen >= 3:
                    let listLen = Int(Self.readUInt16BE(bytes, at: extDataStart))
                    var pos = extDataStart + 2
                    let listEnd = min(extDataStart + extLen, pos + listLen)
                    while pos < listEnd {
                        let protoLen = Int(bytes[pos])
                        pos += 1
                        guard protoLen > 0, pos + protoLen <= listEnd else { break }
                        alpn.append(String(decoding: bytes[pos..<(pos + protoLen)], as: UTF8.self))
                        pos += protoLen
                    }

                case 0x002B where extLen >= 3:
                    let vListLen = Int(bytes[extDataStart])
                    var pos = extDataStart + 1
                    let vEnd = min(extDataStart + extLen, pos + vListLen)
                    while pos + 2 <= vEnd {
                        supportedVersions.append(Self.readUInt16BE(bytes, at: pos))
                        pos += 2
                    }

                default:
                    break
                }
                cursor = extDataStart + extLen
            }
        }

        return DissectedTLSClientHello(
            recordVersion: recordVersion,
            clientVersion: clientVersion,
            negotiatedSupportedVersions: supportedVersions,
            cipherSuites: cipherSuites,
            serverName: serverName,
            alpnProtocols: alpn,
            extensionTypes: extensionTypes
        )
    }

    private func dissectTLSRecordIfPresent(
        bytes: [UInt8],
        offset: Int,
        end: Int,
        prefix: String
    ) -> (layer: DissectedLayer, sni: String?, alpn: [String], infoSummary: String)? {
        let length = end - offset
        guard length >= 5 else { return nil }
        let contentType = bytes[offset]
        let verMajor = bytes[offset + 1]
        let verMinor = bytes[offset + 2]

        guard (0x14...0x17).contains(contentType), verMajor == 0x03, verMinor <= 0x04 else {
            return nil
        }

        let recordVersion = Self.readUInt16BE(bytes, at: offset + 1)
        let recordLength = Int(Self.readUInt16BE(bytes, at: offset + 3))
        guard recordLength > 0 && recordLength <= 18_432 else {
            return nil
        }
        let recordEnd = min(end, offset + 5 + recordLength)

        var recordFields: [DissectedField] = [
            DissectedField(
                id: "\(prefix).tls.content_type",
                label: "Content Type",
                valueSummary: Self.describeTLSContentType(contentType),
                byteOffset: offset,
                byteLength: 1
            ),
            DissectedField(
                id: "\(prefix).tls.record_ver",
                label: "Record Layer Version",
                valueSummary: Self.describeTLSVersion(recordVersion),
                byteOffset: offset + 1,
                byteLength: 2
            ),
            DissectedField(
                id: "\(prefix).tls.record_len",
                label: "Record Length",
                valueSummary: "\(recordLength) bytes",
                byteOffset: offset + 3,
                byteLength: 2
            )
        ]

        // Detailed ClientHello Handshake inspection
        if contentType == 0x16, offset + 9 <= recordEnd {
            let hsOffset = offset + 5
            let hsType = bytes[hsOffset]
            let hsLen = Self.readUInt24BE(bytes, at: hsOffset + 1)
            let hsEnd = min(recordEnd, hsOffset + 4 + hsLen)

            if hsType == 0x01, hsOffset + 38 <= hsEnd {
                let clientVer = Self.readUInt16BE(bytes, at: hsOffset + 4)
                var hsChildren: [DissectedField] = [
                    DissectedField(
                        id: "\(prefix).tls.ch.type",
                        label: "Handshake Type",
                        valueSummary: "ClientHello (1)",
                        byteOffset: hsOffset,
                        byteLength: 1
                    ),
                    DissectedField(
                        id: "\(prefix).tls.ch.len",
                        label: "Handshake Length",
                        valueSummary: "\(hsLen) bytes",
                        byteOffset: hsOffset + 1,
                        byteLength: 3
                    ),
                    DissectedField(
                        id: "\(prefix).tls.ch.ver",
                        label: "Client Version",
                        valueSummary: Self.describeTLSVersion(clientVer),
                        byteOffset: hsOffset + 4,
                        byteLength: 2
                    ),
                    DissectedField(
                        id: "\(prefix).tls.ch.random",
                        label: "Client Random",
                        valueSummary: Self.hexPreview(bytes, offset: hsOffset + 6, length: 16) + "...",
                        byteOffset: hsOffset + 6,
                        byteLength: 32
                    )
                ]

                var cursor = hsOffset + 38
                var extractedSNI: String? = nil
                var extractedALPN: [String] = []
                var supportsTLS13 = false

                if cursor < hsEnd {
                    let sidLen = Int(bytes[cursor])
                    if cursor + 1 + sidLen <= hsEnd {
                        hsChildren.append(
                            DissectedField(
                                id: "\(prefix).tls.ch.sid",
                                label: "Session ID",
                                valueSummary: sidLen == 0
                                    ? "Empty (0 bytes)"
                                    : "\(sidLen) bytes (\(Self.hexPreview(bytes, offset: cursor + 1, length: min(sidLen, 12))))",
                                byteOffset: cursor,
                                byteLength: 1 + sidLen
                            )
                        )
                        cursor += 1 + sidLen

                        if cursor + 2 <= hsEnd {
                            let csByteLen = Int(Self.readUInt16BE(bytes, at: cursor))
                            if cursor + 2 + csByteLen <= hsEnd && csByteLen % 2 == 0 {
                                var suiteFields: [DissectedField] = []
                                for pos in stride(from: cursor + 2, to: cursor + 2 + csByteLen, by: 2) {
                                    let suite = Self.readUInt16BE(bytes, at: pos)
                                    suiteFields.append(
                                        DissectedField(
                                            id: "\(prefix).tls.ch.cs.\(pos)",
                                            label: String(format: "0x%04X", suite),
                                            valueSummary: Self.describeTLSCipherSuite(suite),
                                            byteOffset: pos,
                                            byteLength: 2
                                        )
                                    )
                                }
                                hsChildren.append(
                                    DissectedField(
                                        id: "\(prefix).tls.ch.ciphers",
                                        label: "Cipher Suites",
                                        valueSummary: "\(suiteFields.count) suite(s)",
                                        byteOffset: cursor,
                                        byteLength: 2 + csByteLen,
                                        children: suiteFields
                                    )
                                )
                                cursor += 2 + csByteLen

                                if cursor < hsEnd {
                                    let compLen = Int(bytes[cursor])
                                    if cursor + 1 + compLen <= hsEnd {
                                        hsChildren.append(
                                            DissectedField(
                                                id: "\(prefix).tls.ch.comp",
                                                label: "Compression Methods",
                                                valueSummary: "\(compLen) method(s)",
                                                byteOffset: cursor,
                                                byteLength: 1 + compLen
                                            )
                                        )
                                        cursor += 1 + compLen

                                        if cursor + 2 <= hsEnd {
                                            let extTotalOffset = cursor
                                            let extTotalLen = Int(Self.readUInt16BE(bytes, at: cursor))
                                            cursor += 2
                                            let extEnd = min(hsEnd, cursor + extTotalLen)
                                            var extChildren: [DissectedField] = []

                                            while cursor + 4 <= extEnd {
                                                let extStart = cursor
                                                let extType = Self.readUInt16BE(bytes, at: cursor)
                                                let extLen = Int(Self.readUInt16BE(bytes, at: cursor + 2))
                                                let dataStart = cursor + 4
                                                guard dataStart + extLen <= extEnd else { break }

                                                switch extType {
                                                case 0x0000 where extLen >= 5:
                                                    let sniResult = Self.dissectSNIExtension(
                                                        bytes: bytes,
                                                        extStart: extStart,
                                                        dataStart: dataStart,
                                                        extLen: extLen,
                                                        prefix: prefix
                                                    )
                                                    if let host = sniResult.hostname {
                                                        extractedSNI = host
                                                    }
                                                    extChildren.append(sniResult.field)

                                                case 0x0010 where extLen >= 3:
                                                    let alpnResult = Self.dissectALPNExtension(
                                                        bytes: bytes,
                                                        extStart: extStart,
                                                        dataStart: dataStart,
                                                        extLen: extLen,
                                                        prefix: prefix
                                                    )
                                                    extractedALPN = alpnResult.protocols
                                                    extChildren.append(alpnResult.field)

                                                case 0x002B where extLen >= 3:
                                                    let vLen = Int(bytes[dataStart])
                                                    var vNames: [String] = []
                                                    var vp = dataStart + 1
                                                    let vEnd = min(dataStart + extLen, vp + vLen)
                                                    while vp + 2 <= vEnd {
                                                        let v = Self.readUInt16BE(bytes, at: vp)
                                                        if v == 0x0304 { supportsTLS13 = true }
                                                        vNames.append(Self.describeTLSVersion(v))
                                                        vp += 2
                                                    }
                                                    extChildren.append(
                                                        DissectedField(
                                                            id: "\(prefix).tls.ext.sup_ver.\(extStart)",
                                                            label: "Extension: supported_versions (0x002B)",
                                                            valueSummary: vNames.joined(separator: ", "),
                                                            byteOffset: extStart,
                                                            byteLength: 4 + extLen
                                                        )
                                                    )

                                                default:
                                                    extChildren.append(
                                                        DissectedField(
                                                            id: "\(prefix).tls.ext.\(extType).\(extStart)",
                                                            label: "Extension: \(Self.describeTLSExtension(extType))",
                                                            valueSummary: "\(extLen) bytes",
                                                            byteOffset: extStart,
                                                            byteLength: 4 + extLen
                                                        )
                                                    )
                                                }
                                                cursor = dataStart + extLen
                                            }

                                            hsChildren.append(
                                                DissectedField(
                                                    id: "\(prefix).tls.ch.extensions",
                                                    label: "Extensions",
                                                    valueSummary: "\(extChildren.count) extension(s) (\(extTotalLen) bytes)",
                                                    byteOffset: extTotalOffset,
                                                    byteLength: extEnd - extTotalOffset,
                                                    children: extChildren
                                                )
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                recordFields.append(
                    DissectedField(
                        id: "\(prefix).tls.handshake.ch",
                        label: "Handshake Protocol: ClientHello",
                        valueSummary: extractedSNI.map { "SNI=\($0)" } ?? "No SNI",
                        byteOffset: hsOffset,
                        byteLength: hsEnd - hsOffset,
                        children: hsChildren
                    )
                )

                let protoLabel = supportsTLS13 ? "TLSv1.3" : Self.describeTLSVersion(clientVer)
                var summaryParts = ["\(protoLabel) ClientHello"]
                if let sni = extractedSNI {
                    summaryParts.append("SNI=\(sni)")
                }
                if !extractedALPN.isEmpty {
                    summaryParts.append("ALPN=[\(extractedALPN.joined(separator: ","))]")
                }
                let info = summaryParts.joined(separator: " ")

                let layer = DissectedLayer(
                    id: "\(prefix).layer.tls",
                    protocolKind: .tls,
                    title: "Transport Layer Security (\(protoLabel))",
                    summary: info,
                    byteOffset: offset,
                    byteLength: length,
                    fields: recordFields
                )
                return (layer, extractedSNI, extractedALPN, info)
            } else {
                let hsName = Self.describeTLSHandshakeType(hsType)
                recordFields.append(
                    DissectedField(
                        id: "\(prefix).tls.handshake.\(hsType)",
                        label: "Handshake Protocol: \(hsName)",
                        valueSummary: "Length \(hsLen) bytes",
                        byteOffset: hsOffset,
                        byteLength: hsEnd - hsOffset
                    )
                )
                let info = "\(Self.describeTLSVersion(recordVersion)) Handshake (\(hsName))"
                let layer = DissectedLayer(
                    id: "\(prefix).layer.tls",
                    protocolKind: .tls,
                    title: "Transport Layer Security",
                    summary: info,
                    byteOffset: offset,
                    byteLength: length,
                    fields: recordFields
                )
                return (layer, nil, [], info)
            }
        }

        let contentDesc = Self.describeTLSContentType(contentType)
        let info = "\(Self.describeTLSVersion(recordVersion)) \(contentDesc) (\(recordLength) bytes)"
        let layer = DissectedLayer(
            id: "\(prefix).layer.tls",
            protocolKind: .tls,
            title: "Transport Layer Security",
            summary: info,
            byteOffset: offset,
            byteLength: length,
            fields: recordFields
        )
        return (layer, nil, [], info)
    }

    private static func dissectSNIExtension(
        bytes: [UInt8],
        extStart: Int,
        dataStart: Int,
        extLen: Int,
        prefix: String
    ) -> (hostname: String?, field: DissectedField) {
        let listLen = Int(readUInt16BE(bytes, at: dataStart))
        var pos = dataStart + 2
        let listEnd = min(dataStart + extLen, pos + listLen)
        var foundHost: String? = nil
        var children: [DissectedField] = [
            DissectedField(
                id: "\(prefix).tls.sni.list_len.\(extStart)",
                label: "Server Name List Length",
                valueSummary: "\(listLen) bytes",
                byteOffset: dataStart,
                byteLength: 2
            )
        ]

        while pos + 3 <= listEnd {
            let entryStart = pos
            let nameType = bytes[pos]
            let nameLen = Int(readUInt16BE(bytes, at: pos + 1))
            let nameOffset = pos + 3
            guard nameOffset + nameLen <= listEnd else { break }

            let host = String(decoding: bytes[nameOffset..<(nameOffset + nameLen)], as: UTF8.self)
            if nameType == 0x00 && foundHost == nil {
                foundHost = host
            }
            children.append(
                DissectedField(
                    id: "\(prefix).tls.sni.host.\(entryStart)",
                    label: "Server Name (host_name)",
                    valueSummary: host,
                    byteOffset: nameOffset,
                    byteLength: nameLen
                )
            )
            pos = nameOffset + nameLen
        }

        let field = DissectedField(
            id: "\(prefix).tls.ext.sni.\(extStart)",
            label: "Extension: server_name (SNI 0x0000)",
            valueSummary: foundHost ?? "(empty)",
            byteOffset: extStart,
            byteLength: 4 + extLen,
            children: children
        )
        return (foundHost, field)
    }

    private static func dissectALPNExtension(
        bytes: [UInt8],
        extStart: Int,
        dataStart: Int,
        extLen: Int,
        prefix: String
    ) -> (protocols: [String], field: DissectedField) {
        let listLen = Int(readUInt16BE(bytes, at: dataStart))
        var pos = dataStart + 2
        let listEnd = min(dataStart + extLen, pos + listLen)
        var protocols: [String] = []
        var children: [DissectedField] = []

        while pos < listEnd {
            let entryOffset = pos
            let pLen = Int(bytes[pos])
            pos += 1
            guard pLen > 0, pos + pLen <= listEnd else { break }
            let proto = String(decoding: bytes[pos..<(pos + pLen)], as: UTF8.self)
            protocols.append(proto)
            children.append(
                DissectedField(
                    id: "\(prefix).tls.alpn.p.\(entryOffset)",
                    label: "ALPN Next Protocol",
                    valueSummary: proto,
                    byteOffset: pos,
                    byteLength: pLen
                )
            )
            pos += pLen
        }

        let field = DissectedField(
            id: "\(prefix).tls.ext.alpn.\(extStart)",
            label: "Extension: ALPN (0x0010)",
            valueSummary: protocols.joined(separator: ", "),
            byteOffset: extStart,
            byteLength: 4 + extLen,
            children: children
        )
        return (protocols, field)
    }

    // MARK: - HTTP/1.x Cleartext Inspector & SSH-2.0 Banner Inspector

    private func dissectHTTPMessageIfPresent(
        bytes: [UInt8],
        offset: Int,
        end: Int,
        prefix: String
    ) -> (layer: DissectedLayer, host: String?, requestLine: String?, infoSummary: String)? {
        let length = end - offset
        guard length >= 12 else { return nil }

        let headLimit = min(end, offset + 4096)
        let headSlice = Array(bytes[offset..<headLimit])

        guard let firstNewlineRel = headSlice.firstIndex(of: 0x0A) else {
            return nil
        }
        let firstLineEndRel = (firstNewlineRel > 0 && headSlice[firstNewlineRel - 1] == 0x0D)
            ? firstNewlineRel - 1
            : firstNewlineRel
        guard firstLineEndRel > 0 else { return nil }

        let firstLine = String(decoding: headSlice[0..<firstLineEndRel], as: UTF8.self)
        let httpMethods = ["GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "]
        let isRequest = httpMethods.contains { firstLine.hasPrefix($0) }
        let isResponse = firstLine.hasPrefix("HTTP/1.0 ") || firstLine.hasPrefix("HTTP/1.1 ")

        guard isRequest || isResponse else { return nil }

        var fields: [DissectedField] = []
        var requestLine: String? = nil

        if isRequest {
            requestLine = firstLine
            let parts = firstLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
            let method = parts.count > 0 ? String(parts[0]) : ""
            let uri = parts.count > 1 ? String(parts[1]) : ""
            let version = parts.count > 2 ? String(parts[2]) : "HTTP/1.1"
            fields.append(
                DissectedField(
                    id: "\(prefix).http.reqline",
                    label: "Request Line",
                    valueSummary: firstLine,
                    byteOffset: offset,
                    byteLength: firstNewlineRel + 1,
                    children: [
                        DissectedField(
                            id: "\(prefix).http.method",
                            label: "Request Method",
                            valueSummary: method,
                            byteOffset: offset,
                            byteLength: method.utf8.count
                        ),
                        DissectedField(
                            id: "\(prefix).http.uri",
                            label: "Request URI",
                            valueSummary: uri,
                            byteOffset: offset + min(firstNewlineRel, method.utf8.count + 1),
                            byteLength: uri.utf8.count
                        ),
                        DissectedField(
                            id: "\(prefix).http.version",
                            label: "HTTP Version",
                            valueSummary: version,
                            byteOffset: offset + max(0, firstLineEndRel - version.utf8.count),
                            byteLength: version.utf8.count
                        )
                    ]
                )
            )
        } else {
            fields.append(
                DissectedField(
                    id: "\(prefix).http.statusline",
                    label: "Status Line",
                    valueSummary: firstLine,
                    byteOffset: offset,
                    byteLength: firstNewlineRel + 1
                )
            )
        }

        var extractedHost: String? = nil
        var lineStartRel = firstNewlineRel + 1

        while lineStartRel < headSlice.count {
            guard let nlRel = headSlice[lineStartRel...].firstIndex(of: 0x0A) else { break }
            let cleanEnd = (nlRel > lineStartRel && headSlice[nlRel - 1] == 0x0D) ? nlRel - 1 : nlRel
            if cleanEnd == lineStartRel {
                // End of HTTP headers (\r\n\r\n)
                let bodyOffset = offset + nlRel + 1
                if bodyOffset < end {
                    fields.append(
                        DissectedField(
                            id: "\(prefix).http.body",
                            label: "HTTP Message Body",
                            valueSummary: "\(end - bodyOffset) bytes",
                            byteOffset: bodyOffset,
                            byteLength: end - bodyOffset
                        )
                    )
                }
                break
            }

            let headerLine = String(decoding: headSlice[lineStartRel..<cleanEnd], as: UTF8.self)
            if let colon = headerLine.firstIndex(of: ":") {
                let name = String(headerLine[..<colon]).trimmingCharacters(in: .whitespaces)
                let rawValue = String(headerLine[headerLine.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
                if name.caseInsensitiveCompare("Host") == .orderedSame {
                    // Strip optional :port suffix for clean host rule matching if needed, keeping host header
                    let hostOnly = rawValue.split(separator: ":", maxSplits: 1).first.map(String.init) ?? rawValue
                    extractedHost = hostOnly.isEmpty ? rawValue : hostOnly
                }
                let displayValue = name.caseInsensitiveCompare("Authorization") == .orderedSame
                    ? "[Credentials Present, \(rawValue.count) chars]"
                    : rawValue

                fields.append(
                    DissectedField(
                        id: "\(prefix).http.hdr.\(lineStartRel)",
                        label: "\(name)",
                        valueSummary: displayValue,
                        byteOffset: offset + lineStartRel,
                        byteLength: (nlRel - lineStartRel) + 1
                    )
                )
            }
            lineStartRel = nlRel + 1
        }

        let info: String
        if let req = requestLine {
            if let host = extractedHost {
                info = "HTTP \(req) (Host: \(host))"
            } else {
                info = "HTTP \(req)"
            }
        } else {
            info = "HTTP \(firstLine)"
        }

        let layer = DissectedLayer(
            id: "\(prefix).layer.http",
            protocolKind: .http,
            title: "Hypertext Transfer Protocol",
            summary: info,
            byteOffset: offset,
            byteLength: length,
            fields: fields
        )
        return (layer, extractedHost, requestLine, info)
    }

    private func dissectSSHBannerIfPresent(
        bytes: [UInt8],
        offset: Int,
        end: Int,
        prefix: String
    ) -> (layer: DissectedLayer, infoSummary: String)? {
        let len = end - offset
        guard len >= 8 else { return nil }
        let prefixText = String(decoding: bytes[offset..<min(end, offset + 128)], as: UTF8.self)
        guard prefixText.hasPrefix("SSH-2.0-") || prefixText.hasPrefix("SSH-1.99-") else {
            return nil
        }
        let banner = prefixText.split(whereSeparator: \.isNewline).first.map(String.init) ?? prefixText
        let layer = DissectedLayer(
            id: "\(prefix).layer.ssh",
            protocolKind: .ssh,
            title: "Secure Shell Protocol",
            summary: "Protocol Banner: \(banner)",
            byteOffset: offset,
            byteLength: len,
            fields: [
                DissectedField(
                    id: "\(prefix).ssh.banner",
                    label: "SSH Identification Banner",
                    valueSummary: banner,
                    byteOffset: offset,
                    byteLength: min(len, banner.utf8.count)
                )
            ]
        )
        return (layer, "SSH Protocol: \(banner)")
    }

    // MARK: - Deterministic Byte & Description Helpers

    private static func currentTimestampMicros() -> UInt64 {
        UInt64(max(0, Date().timeIntervalSince1970 * 1_000_000.0))
    }

    private static func readUInt16BE(_ bytes: [UInt8], at index: Int) -> UInt16 {
        (UInt16(bytes[index]) << 8) | UInt16(bytes[index + 1])
    }

    private static func readUInt24BE(_ bytes: [UInt8], at index: Int) -> Int {
        (Int(bytes[index]) << 16) | (Int(bytes[index + 1]) << 8) | Int(bytes[index + 2])
    }

    private static func readUInt32BE(_ bytes: [UInt8], at index: Int) -> UInt32 {
        (UInt32(bytes[index]) << 24)
            | (UInt32(bytes[index + 1]) << 16)
            | (UInt32(bytes[index + 2]) << 8)
            | UInt32(bytes[index + 3])
    }

    private static func hexPreview(_ bytes: [UInt8], offset: Int, length: Int) -> String {
        guard length > 0, offset < bytes.count else { return "" }
        let end = min(bytes.count, offset + length)
        return bytes[offset..<end].map { String(format: "%02x", $0) }.joined(separator: " ")
    }

    private static func formatIPv6(_ octets: [UInt8]) -> String {
        guard octets.count == 16 else { return "::" }
        var groups: [String] = []
        groups.reserveCapacity(8)
        for i in stride(from: 0, to: 16, by: 2) {
            let word = (UInt16(octets[i]) << 8) | UInt16(octets[i + 1])
            groups.append(String(format: "%x", word))
        }
        return groups.joined(separator: ":")
    }

    private static func describeMAC(_ mac: MACAddress) -> String {
        if mac.isBroadcast {
            return "\(mac) (Broadcast)"
        }
        if mac == .defaultGateway {
            return "\(mac) (AgentVM Gateway)"
        }
        if mac.isMulticast {
            return "\(mac) (Multicast)"
        }
        return mac.description
    }

    private static func describeEtherType(_ type: UInt16) -> String {
        switch type {
        case 0x0800: return "0x0800 (IPv4)"
        case 0x0806: return "0x0806 (ARP)"
        case 0x8100: return "0x8100 (IEEE 802.1Q VLAN)"
        case 0x86DD: return "0x86DD (IPv6)"
        case 0x88CC: return "0x88CC (LLDP)"
        default: return String(format: "0x%04X", type)
        }
    }

    private static func describeIPv4Protocol(_ proto: UInt8) -> String {
        switch proto {
        case 1: return "1 (ICMP)"
        case 2: return "2 (IGMP)"
        case 6: return "6 (TCP)"
        case 17: return "17 (UDP)"
        case 47: return "47 (GRE)"
        case 50: return "50 (ESP)"
        case 58: return "58 (ICMPv6)"
        default: return "\(proto)"
        }
    }

    private static func describeDSCP(_ dscp: UInt8) -> String {
        switch dscp {
        case 0: return "CS0/BestEffort"
        case 8: return "CS1"
        case 16: return "CS2"
        case 24: return "CS3"
        case 32: return "CS4"
        case 40: return "CS5"
        case 46: return "EF"
        case 48: return "CS6"
        case 56: return "CS7"
        default: return "DSCP\(dscp)"
        }
    }

    private static func describeECN(_ ecn: UInt8) -> String {
        switch ecn {
        case 0: return "Not-ECT"
        case 1: return "ECT(1)"
        case 2: return "ECT(0)"
        case 3: return "CE"
        default: return "\(ecn)"
        }
    }

    private static func describeICMPTypeAndCode(type: UInt8, code: UInt8) -> (String, String) {
        switch type {
        case 0:
            return ("Echo Reply", "0")
        case 3:
            let c: String
            switch code {
            case 0: c = "Net Unreachable"
            case 1: c = "Host Unreachable"
            case 2: c = "Protocol Unreachable"
            case 3: c = "Port Unreachable"
            case 4: c = "Fragmentation Needed and DF Set"
            case 9: c = "Network Administratively Prohibited"
            case 10: c = "Host Administratively Prohibited"
            case 13: c = "Communication Administratively Prohibited"
            default: c = "Code \(code)"
            }
            return ("Destination Unreachable", c)
        case 5:
            return ("Redirect", "Code \(code)")
        case 8:
            return ("Echo Request", "0")
        case 11:
            return ("Time Exceeded", code == 0 ? "TTL Exceeded in Transit" : "Fragment Reassembly Time Exceeded")
        default:
            return ("Type \(type)", "Code \(code)")
        }
    }

    private static func describeDHCPMessageType(_ type: UInt8?) -> String {
        switch type {
        case 1: return "Discover"
        case 2: return "Offer"
        case 3: return "Request"
        case 4: return "Decline"
        case 5: return "ACK"
        case 6: return "NAK"
        case 7: return "Release"
        case 8: return "Inform"
        case let .some(v): return "Type \(v)"
        case .none: return "BOOTP"
        }
    }

    private static func describeDHCPOption(code: UInt8, bytes: [UInt8]) -> (String, String) {
        switch code {
        case 1 where bytes.count == 4:
            let ip = IPv4Address(a: bytes[0], b: bytes[1], c: bytes[2], d: bytes[3])
            return ("Option (1) Subnet Mask", ip.description)
        case 3 where bytes.count >= 4:
            let ip = IPv4Address(a: bytes[0], b: bytes[1], c: bytes[2], d: bytes[3])
            return ("Option (3) Router", ip.description)
        case 6 where bytes.count >= 4 && bytes.count % 4 == 0:
            var ips: [String] = []
            for i in stride(from: 0, to: bytes.count, by: 4) {
                ips.append(IPv4Address(a: bytes[i], b: bytes[i + 1], c: bytes[i + 2], d: bytes[i + 3]).description)
            }
            return ("Option (6) Domain Name Server", ips.joined(separator: ", "))
        case 12:
            return ("Option (12) Host Name", String(decoding: bytes, as: UTF8.self))
        case 15:
            return ("Option (15) Domain Name", String(decoding: bytes, as: UTF8.self))
        case 50 where bytes.count == 4:
            let ip = IPv4Address(a: bytes[0], b: bytes[1], c: bytes[2], d: bytes[3])
            return ("Option (50) Requested IP Address", ip.description)
        case 51 where bytes.count == 4:
            let secs = readUInt32BE(bytes, at: 0)
            return ("Option (51) IP Address Lease Time", "\(secs) seconds")
        case 53 where bytes.count == 1:
            return ("Option (53) DHCP Message Type", "\(bytes[0]) (\(describeDHCPMessageType(bytes[0])))")
        case 54 where bytes.count == 4:
            let ip = IPv4Address(a: bytes[0], b: bytes[1], c: bytes[2], d: bytes[3])
            return ("Option (54) DHCP Server Identifier", ip.description)
        case 55:
            let req = bytes.map(String.init).joined(separator: ", ")
            return ("Option (55) Parameter Request List", "[\(req)]")
        default:
            return ("Option (\(code))", "\(bytes.count) byte(s)")
        }
    }

    private static func describeDNSRecordType(_ qtype: UInt16) -> String {
        switch qtype {
        case 1: return "A"
        case 2: return "NS"
        case 5: return "CNAME"
        case 6: return "SOA"
        case 12: return "PTR"
        case 15: return "MX"
        case 16: return "TXT"
        case 28: return "AAAA"
        case 33: return "SRV"
        case 41: return "OPT"
        case 65: return "HTTPS"
        case 255: return "ANY"
        default: return "TYPE\(qtype)"
        }
    }

    private static func describeDNSRCode(_ rcode: UInt8) -> String {
        switch rcode {
        case 0: return "NOERROR"
        case 1: return "FORMERR"
        case 2: return "SERVFAIL"
        case 3: return "NXDOMAIN"
        case 4: return "NOTIMP"
        case 5: return "REFUSED"
        default: return "RCODE\(rcode)"
        }
    }

    private static func buildTCPFlagChildren(flags: TCPFlags, offset: Int, prefix: String) -> [DissectedField] {
        let specs: [(String, String, TCPFlags)] = [
            ("cwr", "Congestion Window Reduced (CWR)", .cwr),
            ("ece", "ECN-Echo (ECE)", .ece),
            ("urg", "Urgent (URG)", .urg),
            ("ack", "Acknowledgment (ACK)", .ack),
            ("psh", "Push (PSH)", .psh),
            ("rst", "Reset (RST)", .rst),
            ("syn", "Syn (SYN)", .syn),
            ("fin", "Fin (FIN)", .fin)
        ]
        return specs.map { key, label, bit in
            DissectedField(
                id: "\(prefix).tcp.flags.\(key)",
                label: label,
                valueSummary: flags.contains(bit) ? "1 (Set)" : "0 (Not Set)",
                byteOffset: offset,
                byteLength: 1
            )
        }
    }

    private static func describeTLSContentType(_ type: UInt8) -> String {
        switch type {
        case 0x14: return "ChangeCipherSpec (20)"
        case 0x15: return "Alert (21)"
        case 0x16: return "Handshake (22)"
        case 0x17: return "Application Data (23)"
        default: return "Type \(type)"
        }
    }

    private static func describeTLSHandshakeType(_ type: UInt8) -> String {
        switch type {
        case 0x01: return "ClientHello"
        case 0x02: return "ServerHello"
        case 0x04: return "NewSessionTicket"
        case 0x08: return "EncryptedExtensions"
        case 0x0B: return "Certificate"
        case 0x0C: return "ServerKeyExchange"
        case 0x0D: return "CertificateRequest"
        case 0x0E: return "ServerHelloDone"
        case 0x0F: return "CertificateVerify"
        case 0x10: return "ClientKeyExchange"
        case 0x14: return "Finished"
        default: return "HandshakeType(\(type))"
        }
    }

    private static func describeTLSVersion(_ version: UInt16) -> String {
        switch version {
        case 0x0300: return "SSLv3.0 (0x0300)"
        case 0x0301: return "TLSv1.0 (0x0301)"
        case 0x0302: return "TLSv1.1 (0x0302)"
        case 0x0303: return "TLSv1.2 (0x0303)"
        case 0x0304: return "TLSv1.3 (0x0304)"
        default: return String(format: "0x%04X", version)
        }
    }

    private static func describeTLSCipherSuite(_ suite: UInt16) -> String {
        switch suite {
        case 0x1301: return "TLS_AES_128_GCM_SHA256"
        case 0x1302: return "TLS_AES_256_GCM_SHA384"
        case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256"
        case 0xC02B: return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        case 0xC02C: return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
        case 0xC02F: return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        case 0xC030: return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        case 0xCCA8: return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        case 0xCCA9: return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
        case 0x009C: return "TLS_RSA_WITH_AES_128_GCM_SHA256"
        case 0x009D: return "TLS_RSA_WITH_AES_256_GCM_SHA384"
        case 0x00FF: return "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
        default: return String(format: "CipherSuite(0x%04X)", suite)
        }
    }

    private static func describeTLSExtension(_ extType: UInt16) -> String {
        switch extType {
        case 0x0000: return "server_name (0x0000)"
        case 0x0005: return "status_request / OCSP (0x0005)"
        case 0x000A: return "supported_groups (0x000A)"
        case 0x000B: return "ec_point_formats (0x000B)"
        case 0x000D: return "signature_algorithms (0x000D)"
        case 0x0010: return "application_layer_protocol_negotiation (0x0010)"
        case 0x0012: return "signed_certificate_timestamp (0x0012)"
        case 0x0017: return "extended_master_secret (0x0017)"
        case 0x0023: return "session_ticket (0x0023)"
        case 0x002B: return "supported_versions (0x002B)"
        case 0x002D: return "psk_key_exchange_modes (0x002D)"
        case 0x0033: return "key_share (0x0033)"
        case 0xFF01: return "renegotiation_info (0xFF01)"
        default: return String(format: "ext_0x%04X", extType)
        }
    }
}
