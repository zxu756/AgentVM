import CryptoKit
import Darwin
import Foundation

// MARK: - Canonical Checksum & Hashing Primitives (CRC32, RFC 1071, SHA-256)

public enum BinaryChecksums: Sendable {
    private static let ieeeTable: [UInt32] = {
        var table = [UInt32](repeating: 0, count: 256)
        for i in 0..<256 {
            var c = UInt32(i)
            for _ in 0..<8 {
                if (c & 1) != 0 {
                    c = 0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >>= 1
                }
            }
            table[i] = c
        }
        return table
    }()

    /// Standard IEEE 802.3 CRC-32 (used by GPT headers, Vsock AVM1 frames, Ethernet FCS, and ZIP/Gzip).
    public static func crc32(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in data {
            let idx = Int((crc ^ UInt32(byte)) & 0xFF)
            crc = ieeeTable[idx] ^ (crc >> 8)
        }
        return crc ^ 0xFFFF_FFFF
    }

    public static func crc32(_ slice: ArraySlice<UInt8>) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in slice {
            let idx = Int((crc ^ UInt32(byte)) & 0xFF)
            crc = ieeeTable[idx] ^ (crc >> 8)
        }
        return crc ^ 0xFFFF_FFFF
    }

    /// RFC 1071 Ones'-Complement 16-bit Checksum (IPv4 header, ICMP, UDP, TCP).
    public static func rfc1071Checksum(_ bytes: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        var idx = 0
        let count = bytes.count
        while idx + 1 < count {
            let word = (UInt32(bytes[idx]) << 8) | UInt32(bytes[idx + 1])
            sum &+= word
            idx += 2
        }
        if idx < count {
            sum &+= UInt32(bytes[idx]) << 8
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) &+ (sum >> 16)
        }
        return ~UInt16(sum & 0xFFFF)
    }

    /// Transport-layer pseudo-header RFC 1071 checksum for TCP (proto=6) and UDP (proto=17).
    public static func ipv4TransportChecksum(
        srcIP: IPv4Address,
        dstIP: IPv4Address,
        protocolNumber: UInt8,
        segmentBytes: [UInt8]
    ) -> UInt16 {
        var pseudo: [UInt8] = []
        pseudo.reserveCapacity(12 + segmentBytes.count)
        pseudo.append(contentsOf: srcIP.octetsArray)
        pseudo.append(contentsOf: dstIP.octetsArray)
        pseudo.append(0)
        pseudo.append(protocolNumber)
        let len = UInt16(clamping: segmentBytes.count)
        pseudo.append(UInt8((len >> 8) & 0xFF))
        pseudo.append(UInt8(len & 0xFF))
        pseudo.append(contentsOf: segmentBytes)
        return rfc1071Checksum(pseudo)
    }

    public static func sha256Hex(_ data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    public static func sha256HexFile(at url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            let chunk = try handle.read(upToCount: 1_048_576) ?? Data()
            if chunk.isEmpty { break }
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    public static func sha512Hex(_ data: Data) -> String {
        let digest = SHA512.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    public static func sha512HexFile(at url: URL) throws -> String {
        let path = url.path
        let fd = Darwin.open(path, O_RDONLY)
        guard fd >= 0 else {
            let code = errno
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: code,
                detail: String(cString: strerror(code))
            )
        }
        defer { _ = Darwin.close(fd) }

        var hasher = SHA512()
        let chunkSize = 4 * 1024 * 1024
        var buffer = [UInt8](repeating: 0, count: chunkSize)
        try buffer.withUnsafeMutableBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return }
            while true {
                let bytesRead = Darwin.read(fd, baseAddress, chunkSize)
                if bytesRead > 0 {
                    hasher.update(bufferPointer: UnsafeRawBufferPointer(start: baseAddress, count: bytesRead))
                } else if bytesRead == 0 {
                    break
                } else {
                    let code = errno
                    if code == EINTR { continue }
                    throw AgentVMError.diskImageOperationFailed(
                        path: path,
                        errnoCode: code,
                        detail: String(cString: strerror(code))
                    )
                }
            }
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Deterministic Binary Cursor (Bounds-Checked Little & Big Endian I/O)

public struct BinaryCursor: Sendable {
    public let bytes: [UInt8]
    public private(set) var offset: Int

    public init(data: Data, offset: Int = 0) {
        self.bytes = [UInt8](data)
        self.offset = max(0, min(offset, data.count))
    }

    public init(bytes: [UInt8], offset: Int = 0) {
        self.bytes = bytes
        self.offset = max(0, min(offset, bytes.count))
    }

    public var remaining: Int {
        max(0, bytes.count - offset)
    }

    public var isAtEnd: Bool {
        offset >= bytes.count
    }

    public mutating func seek(to newOffset: Int) throws {
        guard newOffset >= 0 && newOffset <= bytes.count else {
            throw AgentVMError.networkFrameMalformed(
                layer: "BinaryCursor",
                detail: "Seek offset \(newOffset) outside 0...\(bytes.count)"
            )
        }
        offset = newOffset
    }

    public mutating func skip(_ count: Int) throws {
        try seek(to: offset + count)
    }

    public mutating func readUInt8() throws -> UInt8 {
        guard remaining >= 1 else {
            throw AgentVMError.networkFrameMalformed(layer: "BinaryCursor", detail: "Truncated UInt8 at \(offset)")
        }
        defer { offset += 1 }
        return bytes[offset]
    }

    public mutating func readUInt16BE() throws -> UInt16 {
        guard remaining >= 2 else {
            throw AgentVMError.networkFrameMalformed(layer: "BinaryCursor", detail: "Truncated UInt16BE at \(offset)")
        }
        defer { offset += 2 }
        return (UInt16(bytes[offset]) << 8) | UInt16(bytes[offset + 1])
    }

    public mutating func readUInt16LE() throws -> UInt16 {
        guard remaining >= 2 else {
            throw AgentVMError.networkFrameMalformed(layer: "BinaryCursor", detail: "Truncated UInt16LE at \(offset)")
        }
        defer { offset += 2 }
        return UInt16(bytes[offset]) | (UInt16(bytes[offset + 1]) << 8)
    }

    public mutating func readUInt32BE() throws -> UInt32 {
        guard remaining >= 4 else {
            throw AgentVMError.networkFrameMalformed(layer: "BinaryCursor", detail: "Truncated UInt32BE at \(offset)")
        }
        defer { offset += 4 }
        return (UInt32(bytes[offset]) << 24)
            | (UInt32(bytes[offset + 1]) << 16)
            | (UInt32(bytes[offset + 2]) << 8)
            | UInt32(bytes[offset + 3])
    }

    public mutating func readUInt32LE() throws -> UInt32 {
        guard remaining >= 4 else {
            throw AgentVMError.networkFrameMalformed(layer: "BinaryCursor", detail: "Truncated UInt32LE at \(offset)")
        }
        defer { offset += 4 }
        return UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
    }

    public mutating func readUInt64BE() throws -> UInt64 {
        let hi = UInt64(try readUInt32BE())
        let lo = UInt64(try readUInt32BE())
        return (hi << 32) | lo
    }

    public mutating func readUInt64LE() throws -> UInt64 {
        let lo = UInt64(try readUInt32LE())
        let hi = UInt64(try readUInt32LE())
        return (hi << 32) | lo
    }

    public mutating func readBytes(_ count: Int) throws -> [UInt8] {
        guard count >= 0, remaining >= count else {
            throw AgentVMError.networkFrameMalformed(
                layer: "BinaryCursor",
                detail: "Requested \(count) bytes at \(offset), only \(remaining) left"
            )
        }
        let slice = Array(bytes[offset..<(offset + count)])
        offset += count
        return slice
    }

    public mutating func readData(_ count: Int) throws -> Data {
        Data(try readBytes(count))
    }

    public mutating func readASCII(_ count: Int, trimTrailingSpaces: Bool = true) throws -> String {
        let raw = try readBytes(count)
        let trimmed: [UInt8]
        if trimTrailingSpaces {
            var end = raw.count
            while end > 0 && (raw[end - 1] == 0x20 || raw[end - 1] == 0x00) {
                end -= 1
            }
            trimmed = Array(raw.prefix(end))
        } else {
            trimmed = raw
        }
        return String(decoding: trimmed, as: UTF8.self)
    }
}

public struct BinaryBufferWriter: Sendable {
    public private(set) var bytes: [UInt8]

    public init(capacity: Int = 256) {
        self.bytes = []
        self.bytes.reserveCapacity(capacity)
    }

    public var count: Int { bytes.count }
    public var data: Data { Data(bytes) }

    public mutating func appendUInt8(_ value: UInt8) {
        bytes.append(value)
    }

    public mutating func appendUInt16BE(_ value: UInt16) {
        bytes.append(UInt8((value >> 8) & 0xFF))
        bytes.append(UInt8(value & 0xFF))
    }

    public mutating func appendUInt16LE(_ value: UInt16) {
        bytes.append(UInt8(value & 0xFF))
        bytes.append(UInt8((value >> 8) & 0xFF))
    }

    public mutating func appendUInt16BothEndian(_ value: UInt16) {
        appendUInt16LE(value)
        appendUInt16BE(value)
    }

    public mutating func appendUInt32BE(_ value: UInt32) {
        bytes.append(UInt8((value >> 24) & 0xFF))
        bytes.append(UInt8((value >> 16) & 0xFF))
        bytes.append(UInt8((value >> 8) & 0xFF))
        bytes.append(UInt8(value & 0xFF))
    }

    public mutating func appendUInt32LE(_ value: UInt32) {
        bytes.append(UInt8(value & 0xFF))
        bytes.append(UInt8((value >> 8) & 0xFF))
        bytes.append(UInt8((value >> 16) & 0xFF))
        bytes.append(UInt8((value >> 24) & 0xFF))
    }

    public mutating func appendUInt32BothEndian(_ value: UInt32) {
        appendUInt32LE(value)
        appendUInt32BE(value)
    }

    public mutating func appendUInt64BE(_ value: UInt64) {
        appendUInt32BE(UInt32((value >> 32) & 0xFFFF_FFFF))
        appendUInt32BE(UInt32(value & 0xFFFF_FFFF))
    }

    public mutating func appendUInt64LE(_ value: UInt64) {
        appendUInt32LE(UInt32(value & 0xFFFF_FFFF))
        appendUInt32LE(UInt32((value >> 32) & 0xFFFF_FFFF))
    }

    public mutating func appendBytes(_ slice: [UInt8]) {
        bytes.append(contentsOf: slice)
    }

    public mutating func appendData(_ data: Data) {
        bytes.append(contentsOf: data)
    }

    public mutating func appendFixedASCII(_ text: String, length: Int, padByte: UInt8 = 0x20) {
        let utf8 = Array(text.utf8.prefix(length))
        bytes.append(contentsOf: utf8)
        if utf8.count < length {
            bytes.append(contentsOf: repeatElement(padByte, count: length - utf8.count))
        }
    }

    public mutating func padToAlignment(_ alignment: Int, fillByte: UInt8 = 0x00) {
        guard alignment > 1 else { return }
        let rem = bytes.count % alignment
        if rem != 0 {
            bytes.append(contentsOf: repeatElement(fillByte, count: alignment - rem))
        }
    }

    public mutating func patchUInt16BE(_ value: UInt16, at index: Int) {
        precondition(index >= 0 && index + 1 < bytes.count)
        bytes[index] = UInt8((value >> 8) & 0xFF)
        bytes[index + 1] = UInt8(value & 0xFF)
    }

    public mutating func patchUInt32LE(_ value: UInt32, at index: Int) {
        precondition(index >= 0 && index + 3 < bytes.count)
        bytes[index] = UInt8(value & 0xFF)
        bytes[index + 1] = UInt8((value >> 8) & 0xFF)
        bytes[index + 2] = UInt8((value >> 16) & 0xFF)
        bytes[index + 3] = UInt8((value >> 24) & 0xFF)
    }

    public mutating func patchUInt32BE(_ value: UInt32, at index: Int) {
        precondition(index >= 0 && index + 3 < bytes.count)
        bytes[index] = UInt8((value >> 24) & 0xFF)
        bytes[index + 1] = UInt8((value >> 16) & 0xFF)
        bytes[index + 2] = UInt8((value >> 8) & 0xFF)
        bytes[index + 3] = UInt8(value & 0xFF)
    }
}

// MARK: - Wildcard / Glob Matcher Shared by Firewall & Command Palette

public enum GlobPatternMatcher: Sendable {
    /// Case-insensitive `*` and `?` glob pattern matching.
    public static func matches(pattern: String, candidate: String) -> Bool {
        let p = Array(pattern.lowercased().utf8)
        let s = Array(candidate.lowercased().utf8)
        var pi = 0
        var si = 0
        var starIdx = -1
        var matchIdx = 0

        while si < s.count {
            if pi < p.count && (p[pi] == UInt8(ascii: "?") || p[pi] == s[si]) {
                pi += 1
                si += 1
            } else if pi < p.count && p[pi] == UInt8(ascii: "*") {
                starIdx = pi
                matchIdx = si
                pi += 1
            } else if starIdx != -1 {
                pi = starIdx + 1
                matchIdx += 1
                si = matchIdx
            } else {
                return false
            }
        }
        while pi < p.count && p[pi] == UInt8(ascii: "*") {
            pi += 1
        }
        return pi == p.count
    }
}
