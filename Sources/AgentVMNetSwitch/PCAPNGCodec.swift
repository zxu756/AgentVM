import AgentVMModels
import Foundation

// MARK: - PCAPNG Metadata & Inspection Models

public struct PCAPNGSectionMetadata: Codable, Hashable, Sendable {
    public var isBigEndian: Bool
    public var majorVersion: UInt16
    public var minorVersion: UInt16
    public var hardware: String?
    public var operatingSystem: String?
    public var userApplication: String?
    public var comment: String?

    public init(
        isBigEndian: Bool,
        majorVersion: UInt16,
        minorVersion: UInt16,
        hardware: String? = nil,
        operatingSystem: String? = nil,
        userApplication: String? = nil,
        comment: String? = nil
    ) {
        self.isBigEndian = isBigEndian
        self.majorVersion = majorVersion
        self.minorVersion = minorVersion
        self.hardware = hardware
        self.operatingSystem = operatingSystem
        self.userApplication = userApplication
        self.comment = comment
    }
}

public struct PCAPNGInterfaceMetadata: Codable, Hashable, Sendable {
    public var interfaceIndex: Int
    public var linkType: UInt16
    public var snapLength: UInt32
    public var name: String?
    public var interfaceDescription: String?
    public var timestampResolutionRaw: UInt8

    public init(
        interfaceIndex: Int,
        linkType: UInt16,
        snapLength: UInt32,
        name: String? = nil,
        interfaceDescription: String? = nil,
        timestampResolutionRaw: UInt8 = 6
    ) {
        self.interfaceIndex = interfaceIndex
        self.linkType = linkType
        self.snapLength = snapLength
        self.name = name
        self.interfaceDescription = interfaceDescription
        self.timestampResolutionRaw = timestampResolutionRaw
    }
}

public struct PCAPNGInspectionReport: Codable, Hashable, Sendable {
    public var fileSizeBytes: Int
    public var sections: [PCAPNGSectionMetadata]
    public var interfaces: [PCAPNGInterfaceMetadata]
    public var enhancedPacketBlockCount: Int
    public var firstTimestampMicros: UInt64?
    public var lastTimestampMicros: UInt64?

    public init(
        fileSizeBytes: Int,
        sections: [PCAPNGSectionMetadata],
        interfaces: [PCAPNGInterfaceMetadata],
        enhancedPacketBlockCount: Int,
        firstTimestampMicros: UInt64?,
        lastTimestampMicros: UInt64?
    ) {
        self.fileSizeBytes = fileSizeBytes
        self.sections = sections
        self.interfaces = interfaces
        self.enhancedPacketBlockCount = enhancedPacketBlockCount
        self.firstTimestampMicros = firstTimestampMicros
        self.lastTimestampMicros = lastTimestampMicros
    }
}

// MARK: - Wireshark-Compatible PCAP Next Generation (.pcapng) Codec

public struct PCAPNGCodec: Sendable {
    public static let sectionHeaderBlockType: UInt32       = 0x0A0D_0D0A
    public static let interfaceDescriptionBlockType: UInt32 = 0x0000_0001
    public static let simplePacketBlockType: UInt32        = 0x0000_0003
    public static let nameResolutionBlockType: UInt32      = 0x0000_0004
    public static let interfaceStatisticsBlockType: UInt32 = 0x0000_0005
    public static let enhancedPacketBlockType: UInt32      = 0x0000_0006

    public static let byteOrderMagic: UInt32               = 0x1A2B_3C4D
    public static let byteOrderMagicSwapped: UInt32        = 0x4D3C_2B1A
    public static let linkTypeEthernet: UInt16             = 1
    public static let defaultSnapLength: UInt32            = 65_535

    private enum OptionCode {
        static let endOfOpt: UInt16      = 0
        static let comment: UInt16       = 1

        // Section Header Block Options
        static let shbHardware: UInt16   = 2
        static let shbOS: UInt16         = 3
        static let shbUserAppl: UInt16   = 4

        // Interface Description Block Options
        static let ifName: UInt16        = 2
        static let ifDescription: UInt16 = 3
        static let ifTsResol: UInt16     = 9

        // Enhanced Packet Block Options
        static let epbFlags: UInt16      = 2
    }

    public init() {}

    // MARK: - Encoding (.pcapng Binary Stream)

    public func encodeCapture(
        packets: [CapturedPacket],
        hardwareDescription: String = "AgentVM UserSpace L2 Switch"
    ) -> Data {
        var stream = BinaryBufferWriter(capacity: 256 + packets.count * 160)

        // 1. Section Header Block (SHB - 0x0A0D0D0A)
        appendSectionHeaderBlock(to: &stream, hardwareDescription: hardwareDescription)

        // 2. Interface Description Block (IDB - 0x00000001, LinkType=1 Ethernet, if_tsresol=6 us)
        appendInterfaceDescriptionBlock(to: &stream)

        // 3. Enhanced Packet Blocks (EPB - 0x00000006)
        for packet in packets {
            appendEnhancedPacketBlock(to: &stream, packet: packet)
        }

        return stream.data
    }

    public func writeCaptureFile(
        packets: [CapturedPacket],
        to url: URL,
        hardwareDescription: String = "AgentVM UserSpace L2 Switch"
    ) throws {
        let encoded = encodeCapture(packets: packets, hardwareDescription: hardwareDescription)
        let directory = url.deletingLastPathComponent()
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            try encoded.write(to: url, options: .atomic)
        } catch let error as NSError {
            throw AgentVMError.diskImageOperationFailed(
                path: url.path,
                errnoCode: Int32(error.code),
                detail: "Failed to write PCAPNG file: \(error.localizedDescription)"
            )
        }
    }

    private func appendSectionHeaderBlock(
        to stream: inout BinaryBufferWriter,
        hardwareDescription: String
    ) {
        var body = BinaryBufferWriter(capacity: 128)
        body.appendUInt32LE(Self.byteOrderMagic)
        body.appendUInt16LE(1) // Major Version 1
        body.appendUInt16LE(0) // Minor Version 0
        body.appendUInt64LE(0xFFFF_FFFF_FFFF_FFFF) // Unspecified Section Length (-1)

        Self.appendUTF8Option(to: &body, code: OptionCode.shbHardware, text: hardwareDescription)
        Self.appendUTF8Option(to: &body, code: OptionCode.shbOS, text: "macOS arm64 (Apple Silicon)")
        Self.appendUTF8Option(to: &body, code: OptionCode.shbUserAppl, text: "AgentVM NetSwitch 1.0")
        Self.appendEndOfOptions(to: &body)

        Self.appendFramedBlock(
            to: &stream,
            blockType: Self.sectionHeaderBlockType,
            alignedBody: body.bytes
        )
    }

    private func appendInterfaceDescriptionBlock(to stream: inout BinaryBufferWriter) {
        var body = BinaryBufferWriter(capacity: 96)
        body.appendUInt16LE(Self.linkTypeEthernet) // LinkType = 1 (LINKTYPE_ETHERNET)
        body.appendUInt16LE(0)                     // Reserved = 0
        body.appendUInt32LE(Self.defaultSnapLength)

        Self.appendUTF8Option(to: &body, code: OptionCode.ifName, text: "avm-br0")
        Self.appendUTF8Option(
            to: &body,
            code: OptionCode.ifDescription,
            text: "AgentVM User-Space L2 Switch + DPI Firewall"
        )
        // if_tsresol = 6 (10^-6 seconds = microseconds)
        Self.appendRawOption(to: &body, code: OptionCode.ifTsResol, valueBytes: [0x06])
        Self.appendEndOfOptions(to: &body)

        Self.appendFramedBlock(
            to: &stream,
            blockType: Self.interfaceDescriptionBlockType,
            alignedBody: body.bytes
        )
    }

    private func appendEnhancedPacketBlock(
        to stream: inout BinaryBufferWriter,
        packet: CapturedPacket
    ) {
        let snapLimit = Int(Self.defaultSnapLength)
        let capturedSlice = packet.rawFrame.prefix(snapLimit)
        let capturedLen = UInt32(capturedSlice.count)
        let originalLen = UInt32(clamping: packet.rawFrame.count)

        let tsHigh = UInt32((packet.timestampMicros >> 32) & 0xFFFF_FFFF)
        let tsLow = UInt32(packet.timestampMicros & 0xFFFF_FFFF)

        var body = BinaryBufferWriter(capacity: 64 + capturedSlice.count)
        body.appendUInt32LE(0) // Interface ID = 0
        body.appendUInt32LE(tsHigh)
        body.appendUInt32LE(tsLow)
        body.appendUInt32LE(capturedLen)
        body.appendUInt32LE(originalLen)
        body.appendData(Data(capturedSlice))
        body.padToAlignment(4, fillByte: 0x00)

        let commentText = Self.encodePacketComment(packet)
        Self.appendUTF8Option(to: &body, code: OptionCode.comment, text: commentText)

        // epb_flags direction bits (0..1: 1 = inbound/ingress, 2 = outbound/egress)
        let dirFlagWord: UInt32
        switch packet.direction {
        case .ingress:
            dirFlagWord = 0x0000_0001
        case .egress, .lateralVMToVM:
            dirFlagWord = 0x0000_0002
        }
        var flagWriter = BinaryBufferWriter(capacity: 4)
        flagWriter.appendUInt32LE(dirFlagWord)
        Self.appendRawOption(to: &body, code: OptionCode.epbFlags, valueBytes: flagWriter.bytes)
        Self.appendEndOfOptions(to: &body)

        Self.appendFramedBlock(
            to: &stream,
            blockType: Self.enhancedPacketBlockType,
            alignedBody: body.bytes
        )
    }

    private static func appendFramedBlock(
        to stream: inout BinaryBufferWriter,
        blockType: UInt32,
        alignedBody: [UInt8]
    ) {
        precondition(alignedBody.count % 4 == 0, "PCAPNG block body must be 32-bit aligned")
        let totalLength = UInt32(12 + alignedBody.count)
        stream.appendUInt32LE(blockType)
        stream.appendUInt32LE(totalLength)
        stream.appendBytes(alignedBody)
        stream.appendUInt32LE(totalLength)
    }

    private static func appendUTF8Option(
        to writer: inout BinaryBufferWriter,
        code: UInt16,
        text: String
    ) {
        guard !text.isEmpty else { return }
        let utf8 = Array(text.utf8.prefix(Int(UInt16.max)))
        appendRawOption(to: &writer, code: code, valueBytes: utf8)
    }

    private static func appendRawOption(
        to writer: inout BinaryBufferWriter,
        code: UInt16,
        valueBytes: [UInt8]
    ) {
        writer.appendUInt16LE(code)
        writer.appendUInt16LE(UInt16(clamping: valueBytes.count))
        writer.appendBytes(valueBytes)
        writer.padToAlignment(4, fillByte: 0x00)
    }

    private static func appendEndOfOptions(to writer: inout BinaryBufferWriter) {
        writer.appendUInt16LE(OptionCode.endOfOpt)
        writer.appendUInt16LE(0)
    }

    // MARK: - Decoding (.pcapng -> [CapturedPacket])

    public func decodeCapture(
        data: Data,
        defaultVMID: VMID = VMID("vm-pcap")
    ) throws -> [CapturedPacket] {
        let parsed = try parseStream(data: data, defaultVMID: defaultVMID, dissectFrames: true)
        return parsed.packets
    }

    public func readCaptureFile(
        at url: URL,
        defaultVMID: VMID = VMID("vm-pcap")
    ) throws -> [CapturedPacket] {
        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch let error as NSError {
            throw AgentVMError.diskImageOperationFailed(
                path: url.path,
                errnoCode: Int32(error.code),
                detail: "Unable to read PCAPNG file: \(error.localizedDescription)"
            )
        }
        return try decodeCapture(data: data, defaultVMID: defaultVMID)
    }

    public func inspectCapture(data: Data) throws -> PCAPNGInspectionReport {
        let parsed = try parseStream(
            data: data,
            defaultVMID: VMID("vm-inspect"),
            dissectFrames: false
        )
        return parsed.report
    }

    private func parseStream(
        data: Data,
        defaultVMID: VMID,
        dissectFrames: Bool
    ) throws -> (packets: [CapturedPacket], report: PCAPNGInspectionReport) {
        let bytes = [UInt8](data)
        guard bytes.count >= 28 else {
            throw AgentVMError.pcapCorrupted(
                detail: "PCAPNG stream is truncated (\(bytes.count) bytes, minimum SHB is 28 bytes)."
            )
        }

        let dissector = PacketDissector(verifyChecksums: true)
        var cursor = 0
        var currentBigEndian: Bool? = nil
        var sections: [PCAPNGSectionMetadata] = []
        var currentSectionInterfaces: [PCAPNGInterfaceMetadata] = []
        var allInterfaces: [PCAPNGInterfaceMetadata] = []
        var packets: [CapturedPacket] = []
        var epbCount = 0
        var firstTS: UInt64? = nil
        var lastTS: UInt64? = nil
        var nextSequence: UInt64 = 1

        while cursor < bytes.count {
            guard cursor + 12 <= bytes.count else {
                throw AgentVMError.pcapCorrupted(
                    detail: "Truncated PCAPNG block header at byte offset \(cursor)."
                )
            }

            // Section Header Block type 0x0A0D0D0A is endian-symmetric
            let rawTypeLE = Self.readUInt32(bytes, at: cursor, bigEndian: false)

            if rawTypeLE == Self.sectionHeaderBlockType {
                guard cursor + 28 <= bytes.count else {
                    throw AgentVMError.pcapCorrupted(
                        detail: "Truncated Section Header Block at offset \(cursor)."
                    )
                }
                let bomLE = Self.readUInt32(bytes, at: cursor + 8, bigEndian: false)
                let isBE: Bool
                if bomLE == Self.byteOrderMagic {
                    isBE = false
                } else if bomLE == Self.byteOrderMagicSwapped {
                    isBE = true
                } else {
                    throw AgentVMError.pcapCorrupted(
                        detail: String(format: "Invalid PCAPNG Byte-Order Magic 0x%08X at offset %d.", bomLE, cursor + 8)
                    )
                }

                let totalLen = Int(Self.readUInt32(bytes, at: cursor + 4, bigEndian: isBE))
                try Self.validateBlockBounds(
                    bytes: bytes,
                    blockStart: cursor,
                    totalLength: totalLen,
                    minLength: 28,
                    bigEndian: isBE,
                    blockLabel: "Section Header Block"
                )

                let major = Self.readUInt16(bytes, at: cursor + 12, bigEndian: isBE)
                let minor = Self.readUInt16(bytes, at: cursor + 14, bigEndian: isBE)
                guard major == 1 else {
                    throw AgentVMError.pcapCorrupted(
                        detail: "Unsupported PCAPNG version \(major).\(minor) (expected 1.x)."
                    )
                }

                let options = try Self.parseOptions(
                    bytes: bytes,
                    start: cursor + 24,
                    end: cursor + totalLen - 4,
                    bigEndian: isBE
                )
                var sectionMeta = PCAPNGSectionMetadata(
                    isBigEndian: isBE,
                    majorVersion: major,
                    minorVersion: minor
                )
                for (code, val) in options {
                    switch code {
                    case OptionCode.comment:
                        sectionMeta.comment = String(decoding: val, as: UTF8.self)
                    case OptionCode.shbHardware:
                        sectionMeta.hardware = String(decoding: val, as: UTF8.self)
                    case OptionCode.shbOS:
                        sectionMeta.operatingSystem = String(decoding: val, as: UTF8.self)
                    case OptionCode.shbUserAppl:
                        sectionMeta.userApplication = String(decoding: val, as: UTF8.self)
                    default:
                        break
                    }
                }

                currentBigEndian = isBE
                currentSectionInterfaces.removeAll()
                sections.append(sectionMeta)
                cursor += totalLen
                continue
            }

            guard let isBE = currentBigEndian else {
                throw AgentVMError.pcapCorrupted(
                    detail: "PCAPNG file must begin with a Section Header Block (0x0A0D0D0A)."
                )
            }

            let blockType = Self.readUInt32(bytes, at: cursor, bigEndian: isBE)
            let totalLen = Int(Self.readUInt32(bytes, at: cursor + 4, bigEndian: isBE))
            try Self.validateBlockBounds(
                bytes: bytes,
                blockStart: cursor,
                totalLength: totalLen,
                minLength: 12,
                bigEndian: isBE,
                blockLabel: String(format: "Block 0x%08X", blockType)
            )

            switch blockType {
            case Self.interfaceDescriptionBlockType:
                guard totalLen >= 20 else {
                    throw AgentVMError.pcapCorrupted(
                        detail: "Interface Description Block too short (\(totalLen) bytes) at offset \(cursor)."
                    )
                }
                let linkType = Self.readUInt16(bytes, at: cursor + 8, bigEndian: isBE)
                let snapLen = Self.readUInt32(bytes, at: cursor + 12, bigEndian: isBE)
                let options = try Self.parseOptions(
                    bytes: bytes,
                    start: cursor + 16,
                    end: cursor + totalLen - 4,
                    bigEndian: isBE
                )

                var iface = PCAPNGInterfaceMetadata(
                    interfaceIndex: currentSectionInterfaces.count,
                    linkType: linkType,
                    snapLength: snapLen,
                    timestampResolutionRaw: 6
                )
                for (code, val) in options {
                    switch code {
                    case OptionCode.ifName:
                        iface.name = String(decoding: val, as: UTF8.self)
                    case OptionCode.ifDescription:
                        iface.interfaceDescription = String(decoding: val, as: UTF8.self)
                    case OptionCode.ifTsResol where !val.isEmpty:
                        iface.timestampResolutionRaw = val[0]
                    default:
                        break
                    }
                }
                currentSectionInterfaces.append(iface)
                allInterfaces.append(iface)

            case Self.enhancedPacketBlockType:
                guard totalLen >= 32 else {
                    throw AgentVMError.pcapCorrupted(
                        detail: "Enhanced Packet Block too short (\(totalLen) bytes) at offset \(cursor)."
                    )
                }
                let interfaceID = Int(Self.readUInt32(bytes, at: cursor + 8, bigEndian: isBE))
                guard interfaceID >= 0 && interfaceID < currentSectionInterfaces.count else {
                    throw AgentVMError.pcapCorrupted(
                        detail: "Enhanced Packet Block references undeclared Interface ID \(interfaceID)."
                    )
                }
                let iface = currentSectionInterfaces[interfaceID]
                guard iface.linkType == Self.linkTypeEthernet else {
                    throw AgentVMError.pcapCorrupted(
                        detail: "Unsupported PCAPNG LinkType \(iface.linkType) (expected Ethernet LinkType 1)."
                    )
                }

                let tsHigh = UInt64(Self.readUInt32(bytes, at: cursor + 12, bigEndian: isBE))
                let tsLow = UInt64(Self.readUInt32(bytes, at: cursor + 16, bigEndian: isBE))
                let rawTicks = (tsHigh << 32) | tsLow
                let timestampMicros = Self.convertTicksToMicroseconds(
                    ticks: rawTicks,
                    tsResolByte: iface.timestampResolutionRaw
                )

                let capturedLen = Int(Self.readUInt32(bytes, at: cursor + 20, bigEndian: isBE))
                let paddedDataLen = Self.align4(capturedLen)
                let optionsOffset = cursor + 28 + paddedDataLen
                let blockFooterOffset = cursor + totalLen - 4

                guard capturedLen >= 0 && optionsOffset <= blockFooterOffset else {
                    throw AgentVMError.pcapCorrupted(
                        detail: "EPB captured length (\(capturedLen)) overflows block length (\(totalLen)) at offset \(cursor)."
                    )
                }

                epbCount += 1
                if firstTS == nil || timestampMicros < firstTS! { firstTS = timestampMicros }
                if lastTS == nil || timestampMicros > lastTS! { lastTS = timestampMicros }

                if dissectFrames {
                    let frameData = Data(bytes[(cursor + 28)..<(cursor + 28 + capturedLen)])
                    let options = try Self.parseOptions(
                        bytes: bytes,
                        start: optionsOffset,
                        end: blockFooterOffset,
                        bigEndian: isBE
                    )

                    var decodedMeta = DecodedCommentMetadata(
                        vmID: defaultVMID,
                        verdict: .allow,
                        direction: .egress,
                        sequenceNumber: nextSequence,
                        packetID: nil,
                        ruleID: nil,
                        reason: "Imported from PCAPNG"
                    )

                    for (code, val) in options {
                        switch code {
                        case OptionCode.epbFlags where val.count >= 4:
                            let flagWord = Self.readUInt32(val, at: 0, bigEndian: isBE)
                            let dirBits = flagWord & 0x03
                            if dirBits == 1 {
                                decodedMeta.direction = .ingress
                            } else if dirBits == 2 {
                                decodedMeta.direction = .egress
                            }
                        case OptionCode.comment:
                            let commentStr = String(decoding: val, as: UTF8.self)
                            Self.applyPacketComment(commentStr, into: &decodedMeta)
                        default:
                            break
                        }
                    }

                    var packet = try dissector.dissectEthernetFrame(
                        frameData,
                        sequenceNumber: decodedMeta.sequenceNumber,
                        timestampMicros: timestampMicros,
                        vmID: decodedMeta.vmID,
                        direction: decodedMeta.direction
                    )
                    if let packetID = decodedMeta.packetID {
                        packet.id = packetID
                    }
                    packet.verdict = decodedMeta.verdict
                    packet.matchedRuleID = decodedMeta.ruleID
                    packet.verdictReason = decodedMeta.reason
                    packets.append(packet)
                    nextSequence = max(nextSequence + 1, decodedMeta.sequenceNumber + 1)
                }

            case Self.simplePacketBlockType:
                guard totalLen >= 16, !currentSectionInterfaces.isEmpty else {
                    throw AgentVMError.pcapCorrupted(
                        detail: "Invalid Simple Packet Block at offset \(cursor)."
                    )
                }
                let origLen = Int(Self.readUInt32(bytes, at: cursor + 8, bigEndian: isBE))
                let snap = Int(currentSectionInterfaces[0].snapLength)
                let capLen = min(origLen, snap > 0 ? snap : origLen, totalLen - 16)
                guard capLen >= 14, cursor + 12 + capLen <= cursor + totalLen - 4 else {
                    throw AgentVMError.pcapCorrupted(
                        detail: "Truncated Simple Packet Block payload at offset \(cursor)."
                    )
                }
                epbCount += 1
                if dissectFrames {
                    let frameData = Data(bytes[(cursor + 12)..<(cursor + 12 + capLen)])
                    let packet = try dissector.dissectEthernetFrame(
                        frameData,
                        sequenceNumber: nextSequence,
                        timestampMicros: 0,
                        vmID: defaultVMID,
                        direction: .egress
                    )
                    packets.append(packet)
                    nextSequence += 1
                }

            default:
                // Skip optional PCAPNG blocks (NRB 0x04, ISB 0x05, DSB 0x0A, Custom blocks) cleanly
                break
            }

            cursor += totalLen
        }

        let report = PCAPNGInspectionReport(
            fileSizeBytes: bytes.count,
            sections: sections,
            interfaces: allInterfaces,
            enhancedPacketBlockCount: epbCount,
            firstTimestampMicros: firstTS,
            lastTimestampMicros: lastTS
        )
        return (packets, report)
    }

    // MARK: - Structured Comment Metadata Serialization (`opt_comment`)

    private struct DecodedCommentMetadata {
        var vmID: VMID
        var verdict: FirewallVerdict
        var direction: NetworkDirection
        var sequenceNumber: UInt64
        var packetID: PacketID?
        var ruleID: RuleID?
        var reason: String
    }

    private static func encodePacketComment(_ packet: CapturedPacket) -> String {
        let safeReason = packet.verdictReason
            .replacingOccurrences(of: "%", with: "%25")
            .replacingOccurrences(of: ";", with: "%3B")
            .replacingOccurrences(of: "=", with: "%3D")
        let ruleStr = packet.matchedRuleID?.rawValue ?? ""
        return "agentvm:vm=\(packet.vmID.rawValue);verdict=\(packet.verdict.rawValue);dir=\(packet.direction.rawValue);seq=\(packet.sequenceNumber);id=\(packet.id.rawValue);rule=\(ruleStr);reason=\(safeReason)"
    }

    private static func applyPacketComment(
        _ comment: String,
        into meta: inout DecodedCommentMetadata
    ) {
        let trimmed = comment.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix("agentvm:") else {
            if !trimmed.isEmpty {
                meta.reason = trimmed
            }
            return
        }

        let kvSection = trimmed.dropFirst("agentvm:".count)
        for pair in kvSection.split(separator: ";", omittingEmptySubsequences: true) {
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { continue }
            let key = String(parts[0])
            let val = String(parts[1])

            switch key {
            case "vm" where !val.isEmpty:
                meta.vmID = VMID(val)
            case "verdict":
                if let parsedVerdict = FirewallVerdict(rawValue: val) {
                    meta.verdict = parsedVerdict
                }
            case "dir":
                if let parsedDir = NetworkDirection(rawValue: val) {
                    meta.direction = parsedDir
                }
            case "seq":
                if let seq = UInt64(val) {
                    meta.sequenceNumber = seq
                }
            case "id" where !val.isEmpty:
                meta.packetID = PacketID(val)
            case "rule" where !val.isEmpty:
                meta.ruleID = RuleID(val)
            case "reason":
                meta.reason = val
                    .replacingOccurrences(of: "%3D", with: "=")
                    .replacingOccurrences(of: "%3B", with: ";")
                    .replacingOccurrences(of: "%25", with: "%")
            default:
                break
            }
        }
    }

    // MARK: - Block Validation, Option Parsing & Timestamp Resolution Math

    private static func validateBlockBounds(
        bytes: [UInt8],
        blockStart: Int,
        totalLength: Int,
        minLength: Int,
        bigEndian: Bool,
        blockLabel: String
    ) throws {
        guard totalLength >= minLength else {
            throw AgentVMError.pcapCorrupted(
                detail: "\(blockLabel) at offset \(blockStart) has invalid length \(totalLength) (< \(minLength))."
            )
        }
        guard totalLength % 4 == 0 else {
            throw AgentVMError.pcapCorrupted(
                detail: "\(blockLabel) length \(totalLength) at offset \(blockStart) is not 32-bit aligned."
            )
        }
        guard blockStart + totalLength <= bytes.count else {
            throw AgentVMError.pcapCorrupted(
                detail: "\(blockLabel) at offset \(blockStart) (length \(totalLength)) exceeds stream size (\(bytes.count))."
            )
        }
        let trailingLength = Int(readUInt32(bytes, at: blockStart + totalLength - 4, bigEndian: bigEndian))
        guard trailingLength == totalLength else {
            throw AgentVMError.pcapCorrupted(
                detail: "\(blockLabel) trailing length (\(trailingLength)) does not match header length (\(totalLength)) at offset \(blockStart)."
            )
        }
    }

    private static func parseOptions(
        bytes: [UInt8],
        start: Int,
        end: Int,
        bigEndian: Bool
    ) throws -> [(UInt16, [UInt8])] {
        guard start <= end else {
            throw AgentVMError.pcapCorrupted(detail: "Invalid option region \(start)...\(end).")
        }
        if start == end { return [] }

        var options: [(UInt16, [UInt8])] = []
        var pos = start
        while pos + 4 <= end {
            let optCode = readUInt16(bytes, at: pos, bigEndian: bigEndian)
            let optLen = Int(readUInt16(bytes, at: pos + 2, bigEndian: bigEndian))
            pos += 4
            if optCode == OptionCode.endOfOpt {
                break
            }
            let paddedLen = align4(optLen)
            guard pos + paddedLen <= end else {
                throw AgentVMError.pcapCorrupted(
                    detail: "PCAPNG option code \(optCode) length \(optLen) overflows block option area."
                )
            }
            let value = Array(bytes[pos..<(pos + optLen)])
            options.append((optCode, value))
            pos += paddedLen
        }
        return options
    }

    private static func convertTicksToMicroseconds(ticks: UInt64, tsResolByte: UInt8) -> UInt64 {
        if tsResolByte == 6 {
            return ticks
        }
        let isBinaryPower = (tsResolByte & 0x80) != 0
        let exponent = Int(tsResolByte & 0x7F)

        if !isBinaryPower {
            if exponent > 6 {
                var divisor: UInt64 = 1
                for _ in 0..<min(exponent - 6, 12) { divisor *= 10 }
                return ticks / divisor
            } else {
                var multiplier: UInt64 = 1
                for _ in 0..<(6 - exponent) { multiplier *= 10 }
                return ticks &* multiplier
            }
        } else {
            let clampedShift = min(exponent, 60)
            let highPrecision = Double(ticks) * 1_000_000.0 / Double(UInt64(1) << clampedShift)
            return UInt64(max(0.0, highPrecision))
        }
    }

    private static func align4(_ length: Int) -> Int {
        let rem = length % 4
        return rem == 0 ? length : (length + (4 - rem))
    }

    private static func readUInt16(_ bytes: [UInt8], at index: Int, bigEndian: Bool) -> UInt16 {
        if bigEndian {
            return (UInt16(bytes[index]) << 8) | UInt16(bytes[index + 1])
        }
        return UInt16(bytes[index]) | (UInt16(bytes[index + 1]) << 8)
    }

    private static func readUInt32(_ bytes: [UInt8], at index: Int, bigEndian: Bool) -> UInt32 {
        if bigEndian {
            return (UInt32(bytes[index]) << 24)
                | (UInt32(bytes[index + 1]) << 16)
                | (UInt32(bytes[index + 2]) << 8)
                | UInt32(bytes[index + 3])
        }
        return UInt32(bytes[index])
            | (UInt32(bytes[index + 1]) << 8)
            | (UInt32(bytes[index + 2]) << 16)
            | (UInt32(bytes[index + 3]) << 24)
    }
}
