import AgentVMModels
import Foundation
import zlib

// MARK: - Vsock Wire Protocol Constants & Envelopes

/// Canonical framing limits and protocol constants for the `AVM1` multiplexed VirtioSocket wire format.
public enum VsockWireConstants: Sendable {
    /// Fixed 24-byte Big-Endian frame header size (`magic` through `payloadLength`).
    public static let headerByteSize: Int = VsockFrameHeader.encodedByteSize // 24

    /// Fixed 4-byte Big-Endian IEEE 802.3 CRC-32 trailer size appended after the wire payload.
    public static let crcTrailerByteSize: Int = 4

    /// Total framing overhead per `AVM1` packet (`24` header + `4` CRC-32 trailer = `28` bytes).
    public static let minimumFrameByteSize: Int = headerByteSize + crcTrailerByteSize

    /// Fixed 4-byte Big-Endian uncompressed byte length prefix prepended inside `.compressed` payloads.
    public static let compressedSizePrefixBytes: Int = 4

    /// Default per-stream sliding window credit advertised on new streams (256 KiB).
    public static let defaultWindowCredit: UInt32 = 262_144

    /// Maximum payload chunk size emitted per multiplexed data frame (32 KiB).
    public static let defaultMaxChunkBytes: Int = 32_768

    /// Hard upper bound on a single frame's wire or decompressed payload (32 MiB) to prevent memory exhaustion.
    public static let maxAllowedPayloadBytes: Int = 32 * 1024 * 1024

    /// Minimum payload byte count before opportunistic zlib compression is attempted.
    public static let minCompressionCandidateBytes: Int = 64

    /// Default VirtioSocket guest daemon port inside Linux sandboxes.
    public static let defaultGuestVsockPort: UInt32 = 1025
}

/// Canonical JSON coder pair configured for cross-language (`Swift` <-> `Python 3`) `AVM1` control envelopes.
public enum VsockWireJSON: Sendable {
    public static func makeEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        encoder.dataEncodingStrategy = .base64
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }

    public static func makeDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        decoder.dataDecodingStrategy = .base64
        return decoder
    }

    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        do {
            return try makeEncoder().encode(value)
        } catch {
            throw AgentVMError.vsockProtocolViolation(
                detail: "Failed to JSON-encode \(T.self) envelope: \(error.localizedDescription)"
            )
        }
    }

    public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do {
            return try makeDecoder().decode(type, from: data)
        } catch {
            throw AgentVMError.vsockProtocolViolation(
                detail: "Failed to JSON-decode \(T.self) envelope (\(data.count) bytes): \(error.localizedDescription)"
            )
        }
    }
}

/// Codec telemetry snapshot capturing cumulative framing and compression efficiency metrics.
public struct VsockCodecMetrics: Codable, Hashable, Sendable {
    public var framesEncoded: UInt64
    public var framesDecoded: UInt64
    public var compressedFramesEncoded: UInt64
    public var compressedFramesDecoded: UInt64
    public var logicalBytesEncoded: UInt64
    public var wireBytesEncoded: UInt64
    public var wireBytesDecoded: UInt64
    public var crcMismatchCount: UInt64

    public init(
        framesEncoded: UInt64 = 0,
        framesDecoded: UInt64 = 0,
        compressedFramesEncoded: UInt64 = 0,
        compressedFramesDecoded: UInt64 = 0,
        logicalBytesEncoded: UInt64 = 0,
        wireBytesEncoded: UInt64 = 0,
        wireBytesDecoded: UInt64 = 0,
        crcMismatchCount: UInt64 = 0
    ) {
        self.framesEncoded = framesEncoded
        self.framesDecoded = framesDecoded
        self.compressedFramesEncoded = compressedFramesEncoded
        self.compressedFramesDecoded = compressedFramesDecoded
        self.logicalBytesEncoded = logicalBytesEncoded
        self.wireBytesEncoded = wireBytesEncoded
        self.wireBytesDecoded = wireBytesDecoded
        self.crcMismatchCount = crcMismatchCount
    }

    public var compressionRatio: Double {
        guard logicalBytesEncoded > 0 else { return 1.0 }
        return Double(wireBytesEncoded) / Double(logicalBytesEncoded)
    }
}

// MARK: - VsockWireCodec (24-Byte Big-Endian "AVM1" Framing + IEEE CRC32 + Zlib)

/// Stateless, thread-safe binary wire encoder and decoder for the `AVM1` (`0x41564D31`) VirtioSocket RPC protocol.
///
/// ### Wire Layout (Big-Endian Network Byte Order)
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Magic ("AVM1")                         |  0..3
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Version    |    Channel    |             Flags             |  4..7
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Stream ID                           |  8..11
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Sequence Number                        | 12..15
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Window Credit                         | 16..19
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Wire Payload Length                      | 20..23
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// ~                 Wire Payload (0..N octets)                    ~ 24..(24+N-1)
/// |     (if .compressed: 4B BE uncompressedLen + zlib stream)     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                  IEEE 802.3 Payload CRC-32                    | (24+N)..(28+N-1)
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
public struct VsockWireCodec: Sendable {
    public let maxPayloadBytes: Int
    public let zlibCompressionLevel: Int32

    public init(
        maxPayloadBytes: Int = VsockWireConstants.maxAllowedPayloadBytes,
        zlibCompressionLevel: Int32 = Z_DEFAULT_COMPRESSION
    ) {
        self.maxPayloadBytes = max(1024, maxPayloadBytes)
        self.zlibCompressionLevel = zlibCompressionLevel
    }

    // MARK: Frame Encoding

    /// Encodes a typed `AVM1` frame into its Big-Endian binary wire representation with IEEE CRC-32 protection.
    ///
    /// - Parameters:
    ///   - channel: Logical subsystem channel (`control`, `execProcess`, `fileTransfer`, `tcpPortForward`, `telemetryHeartbeat`, `interactivePTY`).
    ///   - flags: Frame control bitmask (`syn`, `ack`, `fin`, `rst`, `windowUpdate`, `compressed`, `endOfMessage`, `errorFrame`).
    ///   - streamID: Multiplexed stream identifier (`0` for session-global control/heartbeat, odd for host-initiated, even for guest-initiated).
    ///   - sequence: Per-stream monotonically increasing frame sequence number.
    ///   - windowCredit: Remaining receive window credit advertised to peer (default `262_144` bytes).
    ///   - payload: Uncompressed logical payload bytes.
    ///   - compressIfBeneficial: When `true`, runs RFC 1950 `zlib` `compress2` and sets `.compressed` if wire size decreases.
    /// - Returns: Serialized `AVM1` wire bytes ready for socket transmission.
    public func encodeFrame(
        channel: VsockChannelKind,
        flags: VsockFrameFlags,
        streamID: UInt32,
        sequence: UInt32,
        windowCredit: UInt32 = VsockWireConstants.defaultWindowCredit,
        payload: Data,
        compressIfBeneficial: Bool = false
    ) throws -> Data {
        guard payload.count <= maxPayloadBytes else {
            throw AgentVMError.vsockProtocolViolation(
                detail: "Outbound payload (\(payload.count) bytes) exceeds maximum frame limit (\(maxPayloadBytes) bytes)."
            )
        }

        var effectiveFlags = flags
        let wirePayload: Data

        if flags.contains(.compressed) {
            // Caller explicitly requested compression regardless of size savings.
            wirePayload = try Self.zlibCompressWithLengthHeader(payload, level: zlibCompressionLevel)
            effectiveFlags.insert(.compressed)
        } else if compressIfBeneficial && payload.count >= VsockWireConstants.minCompressionCandidateBytes {
            let candidate = try Self.zlibCompressWithLengthHeader(payload, level: zlibCompressionLevel)
            if candidate.count < payload.count {
                wirePayload = candidate
                effectiveFlags.insert(.compressed)
            } else {
                wirePayload = payload
                effectiveFlags.remove(.compressed)
            }
        } else {
            wirePayload = payload
            effectiveFlags.remove(.compressed)
        }

        guard wirePayload.count <= maxPayloadBytes,
              let wirePayloadLength = UInt32(exactly: wirePayload.count) else {
            throw AgentVMError.vsockProtocolViolation(
                detail: "Encoded wire payload (\(wirePayload.count) bytes) exceeds protocol limit."
            )
        }

        let crc = BinaryChecksums.crc32(wirePayload)

        let header = VsockFrameHeader(
            magic: VsockFrameHeader.wireMagic,
            version: VsockFrameHeader.currentProtocolVersion,
            channel: channel,
            flags: effectiveFlags,
            streamID: streamID,
            sequenceNumber: sequence,
            windowCredit: windowCredit,
            payloadLength: wirePayloadLength,
            payloadCRC32: crc
        )

        return serializeWireFrame(header: header, wirePayload: wirePayload)
    }

    /// Serializes a pre-constructed `VsockFrameHeader` and raw wire payload into Big-Endian wire bytes.
    public func serializeWireFrame(header: VsockFrameHeader, wirePayload: Data) -> Data {
        var writer = BinaryBufferWriter(
            capacity: VsockWireConstants.headerByteSize + wirePayload.count + VsockWireConstants.crcTrailerByteSize
        )
        // 24-byte Big-Endian AVM1 Header
        writer.appendUInt32BE(header.magic)
        writer.appendUInt8(header.version)
        writer.appendUInt8(header.channel.rawValue)
        writer.appendUInt16BE(header.flags.rawValue)
        writer.appendUInt32BE(header.streamID)
        writer.appendUInt32BE(header.sequenceNumber)
        writer.appendUInt32BE(header.windowCredit)
        writer.appendUInt32BE(UInt32(wirePayload.count))
        assert(writer.count == VsockFrameHeader.encodedByteSize)

        // Variable-length Wire Payload
        writer.appendData(wirePayload)

        // 4-byte Big-Endian IEEE 802.3 CRC-32 Trailer
        writer.appendUInt32BE(header.payloadCRC32)
        return writer.data
    }

    // MARK: Frame Decoding

    /// Attempts to decode a single `AVM1` frame from the beginning of `buffer`.
    ///
    /// - Parameter buffer: Contiguous stream buffer that may hold a partial frame, one complete frame, or multiple coalesced frames.
    /// - Returns: `nil` when `buffer` contains fewer bytes than needed for a complete frame; otherwise the decoded `(header, payload, bytesConsumed)` tuple.
    /// - Throws: `AgentVMError.vsockProtocolViolation` on invalid magic/version/channel/size or corrupt zlib stream,
    ///           or `AgentVMError.vsockCRCMismatch` when the IEEE CRC-32 check fails.
    public func decodeFrame(
        from buffer: Data
    ) throws -> (header: VsockFrameHeader, payload: Data, bytesConsumed: Int)? {
        // Fast-fail on corrupt stream synchronization as soon as the 4-byte magic prefix is present.
        if buffer.count >= 4 {
            let magic = Self.readUInt32BE(buffer, offset: 0)
            guard magic == VsockFrameHeader.wireMagic else {
                throw AgentVMError.vsockProtocolViolation(
                    detail: String(
                        format: "Invalid AVM1 frame magic 0x%08X (expected 0x%08X).",
                        magic,
                        VsockFrameHeader.wireMagic
                    )
                )
            }
        }

        guard buffer.count >= VsockWireConstants.headerByteSize else {
            return nil
        }

        var cursor = BinaryCursor(data: buffer.prefix(VsockWireConstants.headerByteSize))
        let magic = try cursor.readUInt32BE()
        let version = try cursor.readUInt8()
        let channelRaw = try cursor.readUInt8()
        let flagsRaw = try cursor.readUInt16BE()
        let streamID = try cursor.readUInt32BE()
        let sequenceNumber = try cursor.readUInt32BE()
        let windowCredit = try cursor.readUInt32BE()
        let wirePayloadLength = try cursor.readUInt32BE()

        guard version == VsockFrameHeader.currentProtocolVersion else {
            throw AgentVMError.vsockProtocolViolation(
                detail: "Unsupported AVM1 protocol version \(version) (expected \(VsockFrameHeader.currentProtocolVersion))."
            )
        }

        guard let channel = VsockChannelKind(rawValue: channelRaw) else {
            throw AgentVMError.vsockProtocolViolation(
                detail: "Unknown VsockChannelKind raw value \(channelRaw) on stream \(streamID)."
            )
        }

        let payloadByteCount = Int(wirePayloadLength)
        let maxWirePayload = maxPayloadBytes + VsockWireConstants.compressedSizePrefixBytes + 1024
        guard payloadByteCount >= 0 && payloadByteCount <= maxWirePayload else {
            throw AgentVMError.vsockProtocolViolation(
                detail: "Declared wire payload length \(wirePayloadLength) exceeds limit \(maxWirePayload)."
            )
        }

        let totalFrameBytes = VsockWireConstants.headerByteSize + payloadByteCount + VsockWireConstants.crcTrailerByteSize
        guard buffer.count >= totalFrameBytes else {
            return nil
        }

        let payloadStart = buffer.startIndex + VsockWireConstants.headerByteSize
        let payloadEnd = payloadStart + payloadByteCount
        let wirePayload = Data(buffer[payloadStart..<payloadEnd])

        let expectedCRC = Self.readUInt32BE(buffer, offset: VsockWireConstants.headerByteSize + payloadByteCount)
        let actualCRC = BinaryChecksums.crc32(wirePayload)
        guard actualCRC == expectedCRC else {
            throw AgentVMError.vsockCRCMismatch(expected: expectedCRC, actual: actualCRC)
        }

        let flags = VsockFrameFlags(rawValue: flagsRaw)
        let logicalPayload: Data
        if flags.contains(.compressed) {
            logicalPayload = try Self.zlibDecompressWithLengthHeader(
                wirePayload,
                maxOutputBytes: maxPayloadBytes
            )
        } else {
            guard wirePayload.count <= maxPayloadBytes else {
                throw AgentVMError.vsockProtocolViolation(
                    detail: "Uncompressed payload (\(wirePayload.count) bytes) exceeds limit (\(maxPayloadBytes) bytes)."
                )
            }
            logicalPayload = wirePayload
        }

        let header = VsockFrameHeader(
            magic: magic,
            version: version,
            channel: channel,
            flags: flags,
            streamID: streamID,
            sequenceNumber: sequenceNumber,
            windowCredit: windowCredit,
            payloadLength: wirePayloadLength,
            payloadCRC32: expectedCRC
        )

        return (header: header, payload: logicalPayload, bytesConsumed: totalFrameBytes)
    }

    // MARK: Zlib RFC 1950 Compression Primitives

    /// Compresses `input` with C `libz` (`compress2`) prefixed by its 4-byte Big-Endian uncompressed byte length.
    public static func zlibCompressWithLengthHeader(_ input: Data, level: Int32 = Z_DEFAULT_COMPRESSION) throws -> Data {
        guard let originalLength = UInt32(exactly: input.count) else {
            throw AgentVMError.vsockProtocolViolation(
                detail: "Payload too large (\(input.count) bytes) for 32-bit length header."
            )
        }

        let sourceLen = uLong(input.count)
        let bound = Int(compressBound(sourceLen))
        var compressedBuffer = [UInt8](repeating: 0, count: max(16, bound))
        var destLen = uLongf(compressedBuffer.count)

        let rc: Int32 = input.withUnsafeBytes { rawSrc in
            compressedBuffer.withUnsafeMutableBufferPointer { dstPtr in
                let srcBytePtr = rawSrc.bindMemory(to: Bytef.self).baseAddress
                return compress2(dstPtr.baseAddress, &destLen, srcBytePtr, sourceLen, level)
            }
        }

        guard rc == Z_OK else {
            throw AgentVMError.vsockProtocolViolation(
                detail: "zlib compress2 failed with return code \(rc)."
            )
        }

        var writer = BinaryBufferWriter(capacity: VsockWireConstants.compressedSizePrefixBytes + Int(destLen))
        writer.appendUInt32BE(originalLength)
        writer.appendBytes(Array(compressedBuffer.prefix(Int(destLen))))
        return writer.data
    }

    /// Decompresses a `.compressed` wire payload produced by `zlibCompressWithLengthHeader` using C `libz` (`uncompress`).
    public static func zlibDecompressWithLengthHeader(_ wirePayload: Data, maxOutputBytes: Int) throws -> Data {
        guard wirePayload.count >= VsockWireConstants.compressedSizePrefixBytes else {
            throw AgentVMError.vsockProtocolViolation(
                detail: "Compressed AVM1 payload (\(wirePayload.count) bytes) missing 4-byte length prefix."
            )
        }

        let expectedUncompressedLength = Int(readUInt32BE(wirePayload, offset: 0))
        guard expectedUncompressedLength >= 0 && expectedUncompressedLength <= maxOutputBytes else {
            throw AgentVMError.vsockProtocolViolation(
                detail: "Decompressed length \(expectedUncompressedLength) exceeds limit \(maxOutputBytes)."
            )
        }

        let compressedSlice = Data(wirePayload.dropFirst(VsockWireConstants.compressedSizePrefixBytes))
        if expectedUncompressedLength == 0 {
            // Verify empty zlib stream still decompresses cleanly rather than accepting arbitrary trailing garbage.
            var dummy = [UInt8](repeating: 0, count: 1)
            var outLen = uLongf(0)
            let rc: Int32 = compressedSlice.withUnsafeBytes { rawSrc in
                dummy.withUnsafeMutableBufferPointer { dstPtr in
                    let srcPtr = rawSrc.bindMemory(to: Bytef.self).baseAddress
                    return uncompress(dstPtr.baseAddress, &outLen, srcPtr, uLong(compressedSlice.count))
                }
            }
            guard rc == Z_OK && outLen == 0 else {
                throw AgentVMError.vsockProtocolViolation(
                    detail: "zlib uncompress failed on zero-length stream (rc=\(rc))."
                )
            }
            return Data()
        }

        var outputBuffer = [UInt8](repeating: 0, count: expectedUncompressedLength)
        var destLen = uLongf(expectedUncompressedLength)

        let rc: Int32 = compressedSlice.withUnsafeBytes { rawSrc in
            outputBuffer.withUnsafeMutableBufferPointer { dstPtr in
                let srcPtr = rawSrc.bindMemory(to: Bytef.self).baseAddress
                return uncompress(dstPtr.baseAddress, &destLen, srcPtr, uLong(compressedSlice.count))
            }
        }

        guard rc == Z_OK else {
            throw AgentVMError.vsockProtocolViolation(
                detail: "zlib uncompress failed with return code \(rc)."
            )
        }

        guard Int(destLen) == expectedUncompressedLength else {
            throw AgentVMError.vsockProtocolViolation(
                detail: "zlib decompressed byte count \(destLen) did not match declared \(expectedUncompressedLength)."
            )
        }

        return Data(outputBuffer)
    }

    // MARK: Byte Helpers

    @inline(__always)
    private static func readUInt32BE(_ data: Data, offset: Int) -> UInt32 {
        let base = data.startIndex + offset
        return (UInt32(data[base]) << 24)
            | (UInt32(data[base + 1]) << 16)
            | (UInt32(data[base + 2]) << 8)
            | UInt32(data[base + 3])
    }
}

// MARK: - Incremental Stream Reassembler (VsockStreamAccumulator)

/// Thread-safe incremental byte stream reassembler that extracts arbitrarily fragmented or coalesced
/// back-to-back `AVM1` frames from a `SOCK_STREAM` / `VZVirtioSocketConnection` byte pipe.
public final class VsockStreamAccumulator: @unchecked Sendable {
    private let lock = NSLock()
    private let codec: VsockWireCodec
    private let maxBufferCapacity: Int

    private var storage: Data
    private var readCursor: Int = 0
    private var decodedFrameCounter: UInt64 = 0
    private var ingestedByteCounter: UInt64 = 0

    private static let compactionThresholdBytes: Int = 16_384

    public init(
        codec: VsockWireCodec = VsockWireCodec(),
        maxBufferCapacity: Int = 64 * 1024 * 1024
    ) {
        self.codec = codec
        self.maxBufferCapacity = max(65_536, maxBufferCapacity)
        self.storage = Data()
        self.storage.reserveCapacity(65_536)
    }

    /// Number of unconsumed wire bytes currently buffered awaiting frame completion.
    public var bufferedByteCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return max(0, storage.count - readCursor)
    }

    /// Cumulative count of valid `AVM1` frames extracted since initialization or last `reset()`.
    public var totalFramesDecoded: UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return decodedFrameCounter
    }

    /// Cumulative raw socket bytes fed into the accumulator.
    public var totalBytesIngested: UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return ingestedByteCounter
    }

    /// Appends raw stream bytes and drains all complete `AVM1` frames available in FIFO order.
    @discardableResult
    public func append(_ chunk: Data) throws -> [(header: VsockFrameHeader, payload: Data)] {
        try ingest(chunk)
    }

    /// Ingests raw stream bytes and decodes zero or more complete `AVM1` frames.
    public func ingest(_ chunk: Data) throws -> [(header: VsockFrameHeader, payload: Data)] {
        lock.lock()
        defer { lock.unlock() }

        try appendLocked(chunk)
        var extracted: [(header: VsockFrameHeader, payload: Data)] = []

        while let frame = try nextFrameLocked() {
            extracted.append(frame)
        }

        compactIfNeededLocked()
        return extracted
    }

    /// Appends raw bytes without immediately draining frames (pair with `nextFrame()`).
    public func appendBytes(_ chunk: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        try appendLocked(chunk)
    }

    /// Pops the next complete frame from the internal stream buffer, or returns `nil` if more bytes are needed.
    public func nextFrame() throws -> (header: VsockFrameHeader, payload: Data)? {
        lock.lock()
        defer { lock.unlock() }
        let result = try nextFrameLocked()
        compactIfNeededLocked()
        return result
    }

    /// Clears all buffered unread bytes and resets counters (used after fatal framing errors or reconnects).
    public func reset() {
        lock.lock()
        defer { lock.unlock() }
        storage.removeAll(keepingCapacity: true)
        readCursor = 0
        decodedFrameCounter = 0
        ingestedByteCounter = 0
    }

    // MARK: Internal Locked Operations

    private func appendLocked(_ chunk: Data) throws {
        guard !chunk.isEmpty else { return }
        let unread = storage.count - readCursor
        guard unread + chunk.count <= maxBufferCapacity else {
            throw AgentVMError.vsockProtocolViolation(
                detail: "VsockStreamAccumulator buffer overflow (\(unread + chunk.count) > \(maxBufferCapacity) bytes)."
            )
        }
        storage.append(chunk)
        ingestedByteCounter &+= UInt64(chunk.count)
    }

    private func nextFrameLocked() throws -> (header: VsockFrameHeader, payload: Data)? {
        let unread = storage.count - readCursor
        guard unread >= 4 else { return nil }

        let activeSlice = Data(storage[(storage.startIndex + readCursor)..<storage.endIndex])
        do {
            guard let decoded = try codec.decodeFrame(from: activeSlice) else {
                return nil
            }
            readCursor += decoded.bytesConsumed
            decodedFrameCounter &+= 1
            return (header: decoded.header, payload: decoded.payload)
        } catch {
            // Advance past bad magic byte if resynchronization is ever attempted, or reset on fatal error.
            throw error
        }
    }

    private func compactIfNeededLocked() {
        if readCursor == storage.count {
            storage.removeAll(keepingCapacity: true)
            readCursor = 0
        } else if readCursor >= Self.compactionThresholdBytes && readCursor * 2 >= storage.count {
            storage = Data(storage[(storage.startIndex + readCursor)..<storage.endIndex])
            readCursor = 0
        }
    }
}

// MARK: - Typed Multiplexed Control & Channel Envelopes

/// Control message exchanged on `.control` (`streamID == 0`).
public struct VsockControlEnvelope: Codable, Hashable, Sendable {
    public enum Kind: String, Codable, Hashable, Sendable {
        case hello
        case helloAck
        case ping
        case pong
        case shutdown
    }

    public var kind: Kind
    public var agentVersion: String
    public var maxWindowBytes: UInt32
    public var timestampUnix: Double
    public var capabilities: [String]

    public init(
        kind: Kind,
        agentVersion: String = "1.0.0",
        maxWindowBytes: UInt32 = VsockWireConstants.defaultWindowCredit,
        timestampUnix: Double = Date().timeIntervalSince1970,
        capabilities: [String] = ["exec", "pty", "file-sha256", "tcp-forward", "heartbeat", "zlib"]
    ) {
        self.kind = kind
        self.agentVersion = agentVersion
        self.maxWindowBytes = maxWindowBytes
        self.timestampUnix = timestampUnix
        self.capabilities = capabilities
    }
}

/// Final completion frame payload emitted by the guest at the end of a `.execProcess` stream.
public struct VsockExecCompletionEnvelope: Codable, Hashable, Sendable {
    public var requestID: UUID
    public var exitCode: Int32
    public var durationMilliseconds: Int
    public var timedOut: Bool
    public var errorDetail: String?

    public init(
        requestID: UUID,
        exitCode: Int32,
        durationMilliseconds: Int,
        timedOut: Bool = false,
        errorDetail: String? = nil
    ) {
        self.requestID = requestID
        self.exitCode = exitCode
        self.durationMilliseconds = durationMilliseconds
        self.timedOut = timedOut
        self.errorDetail = errorDetail
    }
}

/// Structured header / acknowledgement frame payload exchanged on `.fileTransfer` streams.
public struct VsockFileTransferControlEnvelope: Codable, Hashable, Sendable {
    public enum Phase: String, Codable, Hashable, Sendable {
        case pushBegin
        case pullRequest
        case pullManifest
        case transferVerified
        case transferError
    }

    public var phase: Phase
    public var manifest: GuestFileTransferManifest?
    public var requestedPath: String?
    public var errorMessage: String?

    public init(
        phase: Phase,
        manifest: GuestFileTransferManifest? = nil,
        requestedPath: String? = nil,
        errorMessage: String? = nil
    ) {
        self.phase = phase
        self.manifest = manifest
        self.requestedPath = requestedPath
        self.errorMessage = errorMessage
    }
}

/// Handshake envelope exchanged at the start of a `.tcpPortForward` stream (`channel == 3`).
public struct VsockPortForwardEnvelope: Codable, Hashable, Sendable {
    public enum Action: String, Codable, Hashable, Sendable {
        case connect
        case connectAck
        case connectFailed
    }

    public var action: Action
    public var guestPort: UInt16
    public var sourceAddress: String
    public var sourcePort: UInt16
    public var errorDetail: String?

    public init(
        action: Action,
        guestPort: UInt16,
        sourceAddress: String = "127.0.0.1",
        sourcePort: UInt16 = 0,
        errorDetail: String? = nil
    ) {
        self.action = action
        self.guestPort = guestPort
        self.sourceAddress = sourceAddress
        self.sourcePort = sourcePort
        self.errorDetail = errorDetail
    }
}

/// Binary sub-opcodes used inside `.interactivePTY` (`channel == 5`) stream payloads.
public enum VsockPTYSubframeOpcode: UInt8, Sendable {
    case stdinBytes = 0x01
    case windowResize = 0x02
    case stdoutBytes = 0x03
    case openSession = 0x04
}
