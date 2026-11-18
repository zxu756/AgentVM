import AgentVMModels
import Darwin
import Foundation
import zlib

// MARK: - Darwin clonefile(2) & APFS Low-Level Bindings

@_silgen_name("clonefile")
private func avm_darwin_clonefile(
    _ src: UnsafePointer<CChar>,
    _ dst: UnsafePointer<CChar>,
    _ flags: UInt32
) -> Int32

// MARK: - APFS Volume Capability & Patch Metadata Models

/// Hardware and filesystem capability telemetry for a storage pool directory on macOS.
public struct APFSVolumeCapabilities: Codable, Hashable, Sendable {
    public var directoryPath: String
    public var filesystemTypeName: String
    public var mountPointPath: String
    public var blockSizeBytes: UInt32
    public var optimalIOSizeBytes: UInt32
    public var totalCapacityBytes: UInt64
    public var availableCapacityBytes: UInt64
    public var supportsClonefileCoW: Bool
    public var supportsSparseSeekHole: Bool
    public var supportsPunchHole: Bool
    public var probedAt: Date

    public init(
        directoryPath: String,
        filesystemTypeName: String,
        mountPointPath: String,
        blockSizeBytes: UInt32,
        optimalIOSizeBytes: UInt32,
        totalCapacityBytes: UInt64,
        availableCapacityBytes: UInt64,
        supportsClonefileCoW: Bool,
        supportsSparseSeekHole: Bool,
        supportsPunchHole: Bool,
        probedAt: Date = Date()
    ) {
        self.directoryPath = directoryPath
        self.filesystemTypeName = filesystemTypeName
        self.mountPointPath = mountPointPath
        self.blockSizeBytes = blockSizeBytes
        self.optimalIOSizeBytes = optimalIOSizeBytes
        self.totalCapacityBytes = totalCapacityBytes
        self.availableCapacityBytes = availableCapacityBytes
        self.supportsClonefileCoW = supportsClonefileCoW
        self.supportsSparseSeekHole = supportsSparseSeekHole
        self.supportsPunchHole = supportsPunchHole
        self.probedAt = probedAt
    }

    public var isAPFS: Bool {
        filesystemTypeName.lowercased() == "apfs"
    }
}

/// Decoded header summary for an `"AVMPATCH"` sparse binary delta patch archive.
public struct SparseBinaryPatchHeader: Codable, Hashable, Sendable {
    public static let wireMagicASCII = "AVMPATCH"
    public static let currentVersion: UInt16 = 1

    public var version: UInt16
    public var flags: UInt16
    public var baseVirtualSizeBytes: UInt64
    public var targetVirtualSizeBytes: UInt64
    public var scanChunkSizeBytes: UInt32
    public var dirtyBlockCount: UInt32
    public var totalUncompressedDirtyBytes: UInt64
    public var totalCompressedPayloadBytes: UInt64
    public var archiveCRC32: UInt32

    public init(
        version: UInt16 = Self.currentVersion,
        flags: UInt16 = 0x0001,
        baseVirtualSizeBytes: UInt64,
        targetVirtualSizeBytes: UInt64,
        scanChunkSizeBytes: UInt32,
        dirtyBlockCount: UInt32,
        totalUncompressedDirtyBytes: UInt64,
        totalCompressedPayloadBytes: UInt64,
        archiveCRC32: UInt32
    ) {
        self.version = version
        self.flags = flags
        self.baseVirtualSizeBytes = baseVirtualSizeBytes
        self.targetVirtualSizeBytes = targetVirtualSizeBytes
        self.scanChunkSizeBytes = scanChunkSizeBytes
        self.dirtyBlockCount = dirtyBlockCount
        self.totalUncompressedDirtyBytes = totalUncompressedDirtyBytes
        self.totalCompressedPayloadBytes = totalCompressedPayloadBytes
        self.archiveCRC32 = archiveCRC32
    }

    public var compressionRatio: Double {
        guard totalUncompressedDirtyBytes > 0 else { return 0.0 }
        return Double(totalCompressedPayloadBytes) / Double(totalUncompressedDirtyBytes)
    }
}

// MARK: - Incremental IEEE 802.3 CRC-32 Engine (Matches BinaryChecksums.crc32)

internal struct IncrementalCRC32: Sendable {
    private static let table: [UInt32] = {
        var tbl = [UInt32](repeating: 0, count: 256)
        for i in 0..<256 {
            var c = UInt32(i)
            for _ in 0..<8 {
                if (c & 1) != 0 {
                    c = 0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >>= 1
                }
            }
            tbl[i] = c
        }
        return tbl
    }()

    private var rawState: UInt32 = 0xFFFF_FFFF

    internal init() {}

    internal mutating func update(_ buffer: UnsafeRawBufferPointer) {
        guard let base = buffer.baseAddress else { return }
        let bytes = base.assumingMemoryBound(to: UInt8.self)
        var crc = rawState
        for idx in 0..<buffer.count {
            let tableIdx = Int((crc ^ UInt32(bytes[idx])) & 0xFF)
            crc = Self.table[tableIdx] ^ (crc >> 8)
        }
        rawState = crc
    }

    internal mutating func update(_ bytes: [UInt8]) {
        bytes.withUnsafeBytes { update($0) }
    }

    internal mutating func update(_ data: Data) {
        data.withUnsafeBytes { update($0) }
    }

    internal mutating func updateZeroBytes(count: UInt64) {
        guard count > 0 else { return }
        var remaining = count
        var crc = rawState
        // Advance in 4 KiB batches to keep large sparse hole checksums responsive.
        while remaining >= 4096 {
            for _ in 0..<4096 {
                let tableIdx = Int(crc & 0xFF)
                crc = Self.table[tableIdx] ^ (crc >> 8)
            }
            remaining -= 4096
        }
        while remaining > 0 {
            let tableIdx = Int(crc & 0xFF)
            crc = Self.table[tableIdx] ^ (crc >> 8)
            remaining -= 1
        }
        rawState = crc
    }

    internal var finalized: UInt32 {
        rawState ^ 0xFFFF_FFFF
    }
}

// MARK: - APFS Copy-on-Write Disk Engine

public enum DiskCloneStrategyUsed: String, Codable, Hashable, Sendable {
    case apfsClonefile
    case fullCopyFallback
}

/// Production-grade APFS Copy-on-Write (`clonefile`), sparse extent scanner (`SEEK_DATA`/`SEEK_HOLE`),
/// hole-punching compactor (`F_PUNCHHOLE`), and zlib-compressed binary delta patch engine (`AVMPATCH`).
public struct APFSCoWDiskEngine: Sendable {
    /// Darwin `<sys/_types/_seek_set.h>` `SEEK_DATA` selector (`4` on XNU/macOS).
    private static let darwinSeekData: Int32 = Darwin.SEEK_DATA
    /// Darwin `<sys/_types/_seek_set.h>` `SEEK_HOLE` selector (`3` on XNU/macOS).
    private static let darwinSeekHole: Int32 = Darwin.SEEK_HOLE
    /// Default 64 KiB comparison window matching APFS / Virtio-Blk optimal cluster granularity.
    public static let defaultComparisonChunkBytes: Int = 65_536
    /// Maximum uncompressed bytes per `"AVMPATCH"` block record (1 MiB).
    private static let maxPatchBlockBytes: Int = 1_048_576
    /// `"AVMPATCH"` 8-byte ASCII signature.
    private static let patchMagicBytes: [UInt8] = Array("AVMPATCH".utf8)
    /// Fixed byte size of the `"AVMPATCH"` file header.
    private static let patchHeaderByteLength: Int = 36

    public let comparisonChunkBytes: Int
    public let zlibCompressionLevel: Int32
    public let forceCopyFallbackErrnoForTesting: Int32?
    public let onExtentScanForTesting: (@Sendable (URL, URL?) -> Void)?
    public let onDiskContentReadForTesting: (@Sendable (String) -> Void)?

    public init() {
        self.comparisonChunkBytes = Self.defaultComparisonChunkBytes
        self.zlibCompressionLevel = Z_DEFAULT_COMPRESSION
        self.forceCopyFallbackErrnoForTesting = nil
        self.onExtentScanForTesting = nil
        self.onDiskContentReadForTesting = nil
    }

    public init(
        forceCopyFallbackErrnoForTesting: Int32?,
        onExtentScanForTesting: (@Sendable (URL, URL?) -> Void)? = nil,
        onDiskContentReadForTesting: (@Sendable (String) -> Void)? = nil
    ) {
        self.comparisonChunkBytes = Self.defaultComparisonChunkBytes
        self.zlibCompressionLevel = Z_DEFAULT_COMPRESSION
        self.forceCopyFallbackErrnoForTesting = forceCopyFallbackErrnoForTesting
        self.onExtentScanForTesting = onExtentScanForTesting
        self.onDiskContentReadForTesting = onDiskContentReadForTesting
    }

    public init(comparisonChunkBytes: Int, zlibCompressionLevel: Int32 = Z_DEFAULT_COMPRESSION) {
        let clampedChunk = max(4096, min(comparisonChunkBytes, 1_048_576))
        self.comparisonChunkBytes = clampedChunk
        self.zlibCompressionLevel = min(max(zlibCompressionLevel, Z_NO_COMPRESSION), Z_BEST_COMPRESSION)
        self.forceCopyFallbackErrnoForTesting = nil
        self.onExtentScanForTesting = nil
        self.onDiskContentReadForTesting = nil
    }

    // MARK: - APFS Private Bytes & Allocated Space Metadata (`getattrlist` + `stat`)

    public func readFileSpaceMetrics(at url: URL) throws -> DiskFileSpaceMetrics {
        let summary = try scanSparseExtents(at: url)
        return DiskFileSpaceMetrics(
            imagePath: summary.imagePath,
            virtualSizeBytes: summary.virtualSizeBytes,
            allocatedDiskBytes: summary.physicalAllocatedBytes,
            privateBytes: summary.uniqueDirtyBytes,
            filesystemBlockSize: summary.filesystemBlockSize,
            sampledAt: summary.scannedAt
        )
    }

    // MARK: - Sparse Raw Disk Lifecycle

    /// Creates a POSIX sparse raw disk image of `virtualSizeBytes` using `open`, `ftruncate`, and `fsync`
    /// without materializing zero blocks on APFS.
    public func createSparseRawDisk(
        at url: URL,
        virtualSizeBytes: UInt64,
        overwrite: Bool = false
    ) throws {
        let path = url.path
        guard virtualSizeBytes > 0 else {
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: EINVAL,
                detail: "Virtual disk size must be greater than zero bytes."
            )
        }
        guard virtualSizeBytes <= UInt64(Int64.max) else {
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: EOVERFLOW,
                detail: "Virtual disk size \(virtualSizeBytes) exceeds POSIX off_t limit."
            )
        }

        try Self.ensureParentDirectoryExists(for: url)

        if overwrite {
            // Unlink any pre-existing file or CoW clone so we never mutate shared hardlinks or fail on read-only modes.
            if Darwin.unlink(path) != 0 && Darwin.errno != ENOENT {
                let err = Darwin.errno
                throw AgentVMError.diskImageOperationFailed(
                    path: path,
                    errnoCode: err,
                    detail: "Failed to unlink existing image before overwrite (\(Self.posixErrorString(err)))."
                )
            }
        }

        let openFlags: Int32 = O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC
        let fd = Darwin.open(path, openFlags, mode_t(0o644))
        guard fd >= 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: err,
                detail: "POSIX open(O_CREAT|O_EXCL) failed (\(Self.posixErrorString(err)))."
            )
        }
        defer { _ = Darwin.close(fd) }

        if Darwin.ftruncate(fd, off_t(virtualSizeBytes)) != 0 {
            let err = Darwin.errno
            _ = Darwin.unlink(path)
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: err,
                detail: "POSIX ftruncate(\(virtualSizeBytes)) failed (\(Self.posixErrorString(err)))."
            )
        }

        if Darwin.fsync(fd) != 0 {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: err,
                detail: "POSIX fsync failed after creating sparse disk (\(Self.posixErrorString(err)))."
            )
        }
    }

    /// Resizes an existing sparse raw disk image in place via `ftruncate` and `fsync`, preserving existing extents.
    public func resizeSparseRawDisk(at url: URL, newSizeBytes: UInt64) throws {
        try resizeSparseRawDisk(at: url, newSizeBytes: newSizeBytes, allowShrink: true)
    }

    /// Resizes an existing sparse raw disk image with an optional guard against shrinking below its current size.
    public func resizeSparseRawDisk(
        at url: URL,
        newSizeBytes: UInt64,
        allowShrink: Bool
    ) throws {
        let path = url.path
        guard newSizeBytes > 0 else {
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: EINVAL,
                detail: "Resized virtual disk size must be greater than zero bytes."
            )
        }
        guard newSizeBytes <= UInt64(Int64.max) else {
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: EOVERFLOW,
                detail: "Requested virtual size \(newSizeBytes) exceeds POSIX off_t maximum."
            )
        }

        let fd = Darwin.open(path, O_RDWR | O_CLOEXEC)
        guard fd >= 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: err,
                detail: "Cannot open disk image for resize (\(Self.posixErrorString(err)))."
            )
        }
        defer { _ = Darwin.close(fd) }

        var st = Darwin.stat()
        guard Darwin.fstat(fd, &st) == 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: err,
                detail: "fstat failed during disk resize (\(Self.posixErrorString(err)))."
            )
        }

        let currentSize = UInt64(max(0, st.st_size))
        if !allowShrink && newSizeBytes < currentSize {
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: EINVAL,
                detail: "Refusing to shrink disk from \(currentSize) to \(newSizeBytes) bytes while allowShrink=false."
            )
        }

        if newSizeBytes == currentSize {
            return
        }

        if Darwin.ftruncate(fd, off_t(newSizeBytes)) != 0 {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: err,
                detail: "ftruncate(\(newSizeBytes)) failed during resize (\(Self.posixErrorString(err)))."
            )
        }

        if Darwin.fsync(fd) != 0 {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: err,
                detail: "fsync failed after resizing disk (\(Self.posixErrorString(err)))."
            )
        }
    }

    // MARK: - APFS Instant Copy-on-Write Clone + Sparse Cross-Volume Fallback

    /// Clones a disk image instantaneously using Darwin `clonefile(2)` on APFS.
    /// If `sourceURL` and `destinationURL` reside on different volumes (`EXDEV`) or a filesystem without
    /// `clonefile` support (`ENOTSUP` / `EOPNOTSUPP`), falls back to a sparse hole-preserving chunk copy.
    public func cloneDiskCoW(
        from sourceURL: URL,
        to destinationURL: URL,
        overwrite: Bool = false
    ) throws {
        _ = try cloneDiskCoWReportingStrategy(
            from: sourceURL,
            to: destinationURL,
            overwrite: overwrite
        )
    }

    /// Clones a disk image using Darwin `clonefile(2)` on APFS and reports whether zero-copy `clonefile`
    /// succeeded or fell back to a full sparse copy across volumes (`EXDEV` / `ENOTSUP` / `EOPNOTSUPP`).
    @discardableResult
    public func cloneDiskCoWReportingStrategy(
        from sourceURL: URL,
        to destinationURL: URL,
        overwrite: Bool = false
    ) throws -> DiskCloneStrategyUsed {
        let srcPath = sourceURL.path
        let dstPath = destinationURL.path

        var srcStat = Darwin.stat()
        guard stat(srcPath, &srcStat) == 0 else {
            let err = Darwin.errno
            throw AgentVMError.cowCloneFailed(source: srcPath, destination: dstPath, errnoCode: err)
        }
        guard (srcStat.st_mode & S_IFMT) == S_IFREG else {
            throw AgentVMError.cowCloneFailed(source: srcPath, destination: dstPath, errnoCode: EINVAL)
        }

        try Self.ensureParentDirectoryExists(for: destinationURL)

        var dstStat = Darwin.stat()
        if Darwin.lstat(dstPath, &dstStat) == 0 {
            if srcStat.st_dev == dstStat.st_dev && srcStat.st_ino == dstStat.st_ino {
                throw AgentVMError.cowCloneFailed(source: srcPath, destination: dstPath, errnoCode: EINVAL)
            }
            guard overwrite else {
                throw AgentVMError.cowCloneFailed(source: srcPath, destination: dstPath, errnoCode: EEXIST)
            }
            if Darwin.unlink(dstPath) != 0 {
                let err = Darwin.errno
                throw AgentVMError.cowCloneFailed(source: srcPath, destination: dstPath, errnoCode: err)
            }
        }

        let cloneResult: Int32
        let cloneErr: Int32
        if let simulatedErrno = forceCopyFallbackErrnoForTesting {
            cloneResult = -1
            cloneErr = simulatedErrno
        } else {
            cloneResult = srcPath.withCString { srcCStr in
                dstPath.withCString { dstCStr in
                    avm_darwin_clonefile(srcCStr, dstCStr, 0)
                }
            }
            cloneErr = cloneResult == 0 ? 0 : Darwin.errno
        }

        if cloneResult == 0 {
            // Ensure directory entry durability by syncing destination file metadata.
            let dstFD = Darwin.open(dstPath, O_RDONLY | O_CLOEXEC)
            if dstFD >= 0 {
                _ = Darwin.fsync(dstFD)
                _ = Darwin.close(dstFD)
            }
            return .apfsClonefile
        }

        if cloneErr == EXDEV || cloneErr == ENOTSUP || cloneErr == EOPNOTSUPP {
            try Self.sparseHolePreservingCopy(
                sourcePath: srcPath,
                destinationPath: dstPath,
                chunkSize: comparisonChunkBytes
            )
            return .fullCopyFallback
        }

        throw AgentVMError.cowCloneFailed(source: srcPath, destination: dstPath, errnoCode: cloneErr)
    }

    // MARK: - Sparse Hole Punching & Compaction

    /// Punches an unallocated sparse hole into an existing raw disk image at `[offsetBytes, offsetBytes + lengthBytes)`.
    /// Uses Darwin `fcntl(F_PUNCHHOLE)` for filesystem-block-aligned interior spans and explicit zeroing on unaligned edges.
    public func punchSparseHole(
        at url: URL,
        offsetBytes: UInt64,
        lengthBytes: UInt64
    ) throws {
        guard lengthBytes > 0 else { return }
        let path = url.path

        let fd = Darwin.open(path, O_RDWR | O_CLOEXEC)
        guard fd >= 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: err,
                detail: "Cannot open disk image for hole punching (\(Self.posixErrorString(err)))."
            )
        }
        defer { _ = Darwin.close(fd) }

        var st = Darwin.stat()
        guard Darwin.fstat(fd, &st) == 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: err,
                detail: "fstat failed in punchSparseHole (\(Self.posixErrorString(err)))."
            )
        }

        let fileSize = UInt64(max(0, st.st_size))
        guard offsetBytes < fileSize else { return }
        let clampedLength = min(lengthBytes, fileSize - offsetBytes)
        let endOffset = offsetBytes + clampedLength

        let fsBlockSize = UInt64(Self.queryFilesystemBlockSize(fd: fd))
        let alignedStart = ((offsetBytes + fsBlockSize - 1) / fsBlockSize) * fsBlockSize
        let alignedEnd = (endOffset / fsBlockSize) * fsBlockSize

        if alignedStart < alignedEnd {
            if offsetBytes < alignedStart {
                try Self.writeZeros(fd: fd, path: path, offset: offsetBytes, length: alignedStart - offsetBytes)
            }
            var punch = fpunchhole_t(
                fp_flags: 0,
                reserved: 0,
                fp_offset: off_t(alignedStart),
                fp_length: off_t(alignedEnd - alignedStart)
            )
            if Darwin.fcntl(fd, F_PUNCHHOLE, &punch) != 0 {
                // Fallback to explicit zero-fill if the underlying filesystem rejects F_PUNCHHOLE.
                try Self.writeZeros(fd: fd, path: path, offset: alignedStart, length: alignedEnd - alignedStart)
            }
            if alignedEnd < endOffset {
                try Self.writeZeros(fd: fd, path: path, offset: alignedEnd, length: endOffset - alignedEnd)
            }
        } else {
            try Self.writeZeros(fd: fd, path: path, offset: offsetBytes, length: clampedLength)
        }

        _ = Darwin.fsync(fd)
    }

    /// Scans allocated regions of a raw disk image and converts filesystem-block-aligned runs of zero bytes
    /// into true APFS sparse holes using `F_PUNCHHOLE`, returning total bytes reclaimed.
    public func compactZeroBlocksToHoles(at url: URL) throws -> UInt64 {
        let path = url.path
        let fd = Darwin.open(path, O_RDWR | O_CLOEXEC)
        guard fd >= 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: err,
                detail: "Cannot open disk image for zero-block compaction (\(Self.posixErrorString(err)))."
            )
        }
        defer { _ = Darwin.close(fd) }

        var st = Darwin.stat()
        guard Darwin.fstat(fd, &st) == 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: err,
                detail: "fstat failed during compaction (\(Self.posixErrorString(err)))."
            )
        }

        let virtualSize = UInt64(max(0, st.st_size))
        guard virtualSize > 0 else { return 0 }

        let fsBlockSize = Int(Self.queryFilesystemBlockSize(fd: fd))
        let stepSize = max(fsBlockSize, (comparisonChunkBytes / fsBlockSize) * fsBlockSize)
        let rawBuffer = UnsafeMutableRawPointer.allocate(byteCount: stepSize, alignment: 8)
        defer { rawBuffer.deallocate() }

        var reclaimedBytes: UInt64 = 0
        var cursor: UInt64 = 0
        var pendingZeroStart: UInt64?
        var pendingZeroLength: UInt64 = 0

        func flushZeroRun() {
            guard let start = pendingZeroStart, pendingZeroLength >= UInt64(fsBlockSize) else {
                pendingZeroStart = nil
                pendingZeroLength = 0
                return
            }
            let alignedLen = (pendingZeroLength / UInt64(fsBlockSize)) * UInt64(fsBlockSize)
            if alignedLen > 0 {
                var punch = fpunchhole_t(
                    fp_flags: 0,
                    reserved: 0,
                    fp_offset: off_t(start),
                    fp_length: off_t(alignedLen)
                )
                if Darwin.fcntl(fd, F_PUNCHHOLE, &punch) == 0 {
                    reclaimedBytes += alignedLen
                }
            }
            pendingZeroStart = nil
            pendingZeroLength = 0
        }

        while cursor < virtualSize {
            guard let dataStart = Self.seekNextDataOffset(fd: fd, from: cursor, fileSize: virtualSize) else {
                break
            }
            let holeStart = Self.seekNextHoleOffset(fd: fd, from: dataStart, fileSize: virtualSize)
            var pos = dataStart
            while pos < holeStart {
                let toRead = Int(min(UInt64(stepSize), holeStart - pos))
                try Self.preadExact(fd: fd, path: path, into: rawBuffer, count: toRead, offset: pos)
                let slice = UnsafeRawBufferPointer(start: rawBuffer, count: toRead)
                if Self.isAllZero(slice) && (pos % UInt64(fsBlockSize) == 0) {
                    if pendingZeroStart == nil {
                        pendingZeroStart = pos
                        pendingZeroLength = UInt64(toRead)
                    } else {
                        pendingZeroLength += UInt64(toRead)
                    }
                } else {
                    flushZeroRun()
                }
                pos += UInt64(toRead)
            }
            flushZeroRun()
            cursor = holeStart
        }

        _ = Darwin.fsync(fd)
        return reclaimedBytes
    }

    // MARK: - APFS Extent & Parent CoW Comparison Scanner

    /// Scans a disk image using Darwin `lseek(SEEK_DATA / SEEK_HOLE)` combined with chunked 64 KiB zero
    /// and parent-block comparison, coalescing adjacent blocks into `SparseExtent` ranges.
    public func scanSparseExtents(
        at url: URL,
        compareAgainstParent parentURL: URL? = nil,
        computeChecksums: Bool = false
    ) throws -> DiskAllocationSummary {
        onExtentScanForTesting?(url, parentURL)
        let targetPath = url.path
        let targetFD = Darwin.open(targetPath, O_RDONLY | O_CLOEXEC)
        guard targetFD >= 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: targetPath,
                errnoCode: err,
                detail: "Cannot open disk image for sparse extent scan (\(Self.posixErrorString(err)))."
            )
        }
        defer { _ = Darwin.close(targetFD) }

        var targetStat = Darwin.stat()
        guard Darwin.fstat(targetFD, &targetStat) == 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: targetPath,
                errnoCode: err,
                detail: "fstat failed on target disk image (\(Self.posixErrorString(err)))."
            )
        }

        let virtualSize = UInt64(max(0, targetStat.st_size))
        let fsBlockSize = Self.queryFilesystemBlockSize(fd: targetFD)

        if virtualSize == 0 {
            return DiskAllocationSummary(
                imagePath: targetPath,
                virtualSizeBytes: 0,
                physicalAllocatedBytes: 0,
                sparseHoleBytes: 0,
                sharedWithParentBytes: 0,
                uniqueDirtyBytes: 0,
                filesystemBlockSize: fsBlockSize,
                extents: [],
                scannedAt: Date()
            )
        }

        var parentFD: Int32 = -1
        var parentSize: UInt64 = 0
        var parentPath: String = ""
        if let parentURL {
            parentPath = parentURL.path
            parentFD = Darwin.open(parentPath, O_RDONLY | O_CLOEXEC)
            guard parentFD >= 0 else {
                let err = Darwin.errno
                throw AgentVMError.diskImageOperationFailed(
                    path: parentPath,
                    errnoCode: err,
                    detail: "Cannot open parent CoW image for extent comparison (\(Self.posixErrorString(err)))."
                )
            }
            var pst = Darwin.stat()
            guard Darwin.fstat(parentFD, &pst) == 0 else {
                let err = Darwin.errno
                _ = Darwin.close(parentFD)
                throw AgentVMError.diskImageOperationFailed(
                    path: parentPath,
                    errnoCode: err,
                    detail: "fstat failed on parent CoW image (\(Self.posixErrorString(err)))."
                )
            }
            parentSize = UInt64(max(0, pst.st_size))
        }
        defer {
            if parentFD >= 0 {
                _ = Darwin.close(parentFD)
            }
        }

        let chunkCap = comparisonChunkBytes
        let targetBuf = UnsafeMutableRawPointer.allocate(byteCount: chunkCap, alignment: 8)
        defer { targetBuf.deallocate() }

        let parentBuf: UnsafeMutableRawPointer? = parentFD >= 0
            ? UnsafeMutableRawPointer.allocate(byteCount: chunkCap, alignment: 8)
            : nil
        defer { parentBuf?.deallocate() }

        var coalescer = ExtentCoalescer(computeChecksums: computeChecksums)
        var sparseHoleBytes: UInt64 = 0
        var sharedBytes: UInt64 = 0
        var dirtyBytes: UInt64 = 0

        var cursor: UInt64 = 0
        while cursor < virtualSize {
            guard let dataStart = Self.seekNextDataOffset(fd: targetFD, from: cursor, fileSize: virtualSize) else {
                // Kernel guarantees [cursor, virtualSize) is an unallocated sparse hole in target.
                let holeLen = virtualSize - cursor
                coalescer.appendHole(offset: cursor, length: holeLen)
                sparseHoleBytes += holeLen
                break
            }

            if dataStart > cursor {
                let holeLen = dataStart - cursor
                coalescer.appendHole(offset: cursor, length: holeLen)
                sparseHoleBytes += holeLen
            }

            let holeStart = Self.seekNextHoleOffset(fd: targetFD, from: dataStart, fileSize: virtualSize)
            var pos = dataStart
            while pos < holeStart {
                let chunkLen = Int(min(UInt64(chunkCap), holeStart - pos))
                onDiskContentReadForTesting?(targetPath)
                try Self.preadExact(fd: targetFD, path: targetPath, into: targetBuf, count: chunkLen, offset: pos)
                let targetSlice = UnsafeRawBufferPointer(start: targetBuf, count: chunkLen)
                let targetZero = Self.isAllZero(targetSlice)

                if parentFD < 0 {
                    if targetZero {
                        coalescer.appendHole(offset: pos, length: UInt64(chunkLen))
                        sparseHoleBytes += UInt64(chunkLen)
                    } else {
                        coalescer.appendData(offset: pos, kind: .allocatedDirty, bytes: targetSlice)
                        dirtyBytes += UInt64(chunkLen)
                    }
                } else if let pBuf = parentBuf {
                    let parentZeroOrOutOfBounds: Bool
                    if pos >= parentSize {
                        memset(pBuf, 0, chunkLen)
                        parentZeroOrOutOfBounds = true
                    } else {
                        let readableParent = Int(min(UInt64(chunkLen), parentSize - pos))
                        try Self.preadExact(fd: parentFD, path: parentPath, into: pBuf, count: readableParent, offset: pos)
                        if readableParent < chunkLen {
                            memset(pBuf.advanced(by: readableParent), 0, chunkLen - readableParent)
                        }
                        let pSlice = UnsafeRawBufferPointer(start: pBuf, count: chunkLen)
                        parentZeroOrOutOfBounds = Self.isAllZero(pSlice)
                    }

                    if targetZero {
                        if parentZeroOrOutOfBounds {
                            // Unflushed zero buffer or shared zero region -> sparse hole.
                            coalescer.appendHole(offset: pos, length: UInt64(chunkLen))
                            sparseHoleBytes += UInt64(chunkLen)
                        } else {
                            // Child explicitly zeroed out a block that contained non-zero data in parent.
                            coalescer.appendData(offset: pos, kind: .allocatedDirty, bytes: targetSlice)
                            dirtyBytes += UInt64(chunkLen)
                        }
                    } else if !parentZeroOrOutOfBounds && memcmp(targetBuf, pBuf, chunkLen) == 0 {
                        coalescer.appendData(offset: pos, kind: .allocatedClean, bytes: targetSlice)
                        sharedBytes += UInt64(chunkLen)
                    } else {
                        coalescer.appendData(offset: pos, kind: .allocatedDirty, bytes: targetSlice)
                        dirtyBytes += UInt64(chunkLen)
                    }
                }

                pos += UInt64(chunkLen)
            }

            cursor = holeStart
        }

        let extents = coalescer.finalize()
        let physicalAllocatedBytes = sharedBytes + dirtyBytes

        return DiskAllocationSummary(
            imagePath: targetPath,
            virtualSizeBytes: virtualSize,
            physicalAllocatedBytes: physicalAllocatedBytes,
            sparseHoleBytes: sparseHoleBytes,
            sharedWithParentBytes: sharedBytes,
            uniqueDirtyBytes: dirtyBytes,
            filesystemBlockSize: fsBlockSize,
            extents: extents,
            scannedAt: Date()
        )
    }

    // MARK: - Sparse Binary Delta Patch ("AVMPATCH" + zlib + CRC32 Trailer)

    /// Exports a compact `"AVMPATCH"` binary delta archive encoding every 64 KiB block where `targetURL`
    /// diverges from `baseURL`, compressed with zlib and sealed with a full-archive IEEE CRC-32 trailer.
    public func exportSparseBinaryPatch(baseURL: URL, targetURL: URL) throws -> Data {
        let basePath = baseURL.path
        let targetPath = targetURL.path

        let baseFD = Darwin.open(basePath, O_RDONLY | O_CLOEXEC)
        guard baseFD >= 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: basePath,
                errnoCode: err,
                detail: "Cannot open base disk image for AVMPATCH export (\(Self.posixErrorString(err)))."
            )
        }
        defer { _ = Darwin.close(baseFD) }

        let targetFD = Darwin.open(targetPath, O_RDONLY | O_CLOEXEC)
        guard targetFD >= 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: targetPath,
                errnoCode: err,
                detail: "Cannot open target disk image for AVMPATCH export (\(Self.posixErrorString(err)))."
            )
        }
        defer { _ = Darwin.close(targetFD) }

        var baseStat = Darwin.stat()
        var targetStat = Darwin.stat()
        guard Darwin.fstat(baseFD, &baseStat) == 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: basePath,
                errnoCode: err,
                detail: "fstat failed on base disk (\(Self.posixErrorString(err)))."
            )
        }
        guard Darwin.fstat(targetFD, &targetStat) == 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: targetPath,
                errnoCode: err,
                detail: "fstat failed on target disk (\(Self.posixErrorString(err)))."
            )
        }

        let baseSize = UInt64(max(0, baseStat.st_size))
        let targetSize = UInt64(max(0, targetStat.st_size))

        let chunkCap = comparisonChunkBytes
        let baseBuf = UnsafeMutableRawPointer.allocate(byteCount: chunkCap, alignment: 8)
        let targetBuf = UnsafeMutableRawPointer.allocate(byteCount: chunkCap, alignment: 8)
        defer {
            baseBuf.deallocate()
            targetBuf.deallocate()
        }

        struct RawDirtyRun {
            var offset: UInt64
            var data: Data
        }

        var dirtyRuns: [RawDirtyRun] = []
        var activeRun: RawDirtyRun?

        func flushActiveRun() {
            if let run = activeRun, !run.data.isEmpty {
                dirtyRuns.append(run)
            }
            activeRun = nil
        }

        var cursor: UInt64 = 0
        while cursor < targetSize {
            // Fast-skip intervals where BOTH base and target are inside kernel sparse holes.
            let nextTargetData = Self.seekNextDataOffset(fd: targetFD, from: cursor, fileSize: targetSize)
            let nextBaseData: UInt64? = cursor < baseSize
                ? Self.seekNextDataOffset(fd: baseFD, from: cursor, fileSize: min(baseSize, targetSize))
                : nil

            let earliestData: UInt64?
            switch (nextTargetData, nextBaseData) {
            case (nil, nil):
                earliestData = nil
            case let (.some(t), nil):
                earliestData = t
            case let (nil, .some(b)):
                earliestData = b
            case let (.some(t), .some(b)):
                earliestData = min(t, b)
            }

            guard let start = earliestData, start < targetSize else {
                flushActiveRun()
                break
            }

            if start > cursor {
                flushActiveRun()
                cursor = start
            }

            let targetHole = Self.seekNextHoleOffset(fd: targetFD, from: cursor, fileSize: targetSize)
            let baseHole: UInt64 = cursor < baseSize
                ? Self.seekNextHoleOffset(fd: baseFD, from: cursor, fileSize: min(baseSize, targetSize))
                : cursor
            let spanEnd = min(targetSize, max(targetHole, baseHole))

            var pos = cursor
            while pos < spanEnd {
                let chunkLen = Int(min(UInt64(chunkCap), spanEnd - pos))

                try Self.preadExact(fd: targetFD, path: targetPath, into: targetBuf, count: chunkLen, offset: pos)

                if pos >= baseSize {
                    memset(baseBuf, 0, chunkCap)
                } else {
                    let baseReadable = Int(min(UInt64(chunkLen), baseSize - pos))
                    try Self.preadExact(fd: baseFD, path: basePath, into: baseBuf, count: baseReadable, offset: pos)
                    if baseReadable < chunkLen {
                        memset(baseBuf.advanced(by: baseReadable), 0, chunkLen - baseReadable)
                    }
                }

                if memcmp(baseBuf, targetBuf, chunkLen) != 0 {
                    let sliceData = Data(bytes: targetBuf, count: chunkLen)
                    if var existing = activeRun,
                       existing.offset + UInt64(existing.data.count) == pos,
                       existing.data.count + chunkLen <= Self.maxPatchBlockBytes {
                        existing.data.append(sliceData)
                        activeRun = existing
                    } else {
                        flushActiveRun()
                        activeRun = RawDirtyRun(offset: pos, data: sliceData)
                    }
                } else {
                    flushActiveRun()
                }

                pos += UInt64(chunkLen)
            }

            flushActiveRun()
            cursor = spanEnd
        }

        // Encode AVMPATCH binary container:
        // Header (36 bytes):
        //   0..<8   : ASCII "AVMPATCH"
        //   8..<10  : UInt16LE version = 1
        //   10..<12 : UInt16LE flags = 0x0001 (zlib compressed payloads)
        //   12..<20 : UInt64LE baseVirtualSizeBytes
        //   20..<28 : UInt64LE targetVirtualSizeBytes
        //   28..<32 : UInt32LE comparisonChunkBytes
        //   32..<36 : UInt32LE dirtyBlockCount
        var writer = BinaryBufferWriter(capacity: Self.patchHeaderByteLength + dirtyRuns.count * 256 + 4)
        writer.appendBytes(Self.patchMagicBytes)
        writer.appendUInt16LE(SparseBinaryPatchHeader.currentVersion)
        writer.appendUInt16LE(0x0001)
        writer.appendUInt64LE(baseSize)
        writer.appendUInt64LE(targetSize)
        writer.appendUInt32LE(UInt32(clamping: chunkCap))
        writer.appendUInt32LE(UInt32(clamping: dirtyRuns.count))

        for run in dirtyRuns {
            let uncompressedCRC = BinaryChecksums.crc32(run.data)
            let compressed = try Self.zlibCompress(run.data, level: zlibCompressionLevel, contextPath: targetPath)
            writer.appendUInt64LE(run.offset)
            writer.appendUInt32LE(UInt32(run.data.count))
            writer.appendUInt32LE(UInt32(compressed.count))
            writer.appendUInt32LE(uncompressedCRC)
            writer.appendData(compressed)
        }

        let trailerCRC = BinaryChecksums.crc32(writer.bytes[0..<writer.count])
        writer.appendUInt32LE(trailerCRC)
        return writer.data
    }

    /// Inspects and validates the header and CRC-32 trailer of an `"AVMPATCH"` archive without modifying any disk.
    public func inspectSparseBinaryPatch(_ patchData: Data) throws -> SparseBinaryPatchHeader {
        guard patchData.count >= Self.patchHeaderByteLength + 4 else {
            throw AgentVMError.diskImageOperationFailed(
                path: "<avmpatch>",
                errnoCode: EFTYPE,
                detail: "AVMPATCH buffer too short (\(patchData.count) bytes; minimum 40 bytes)."
            )
        }

        var cursor = BinaryCursor(data: patchData)
        let magic = try cursor.readBytes(8)
        guard magic == Self.patchMagicBytes else {
            throw AgentVMError.diskImageOperationFailed(
                path: "<avmpatch>",
                errnoCode: EFTYPE,
                detail: "Invalid patch magic header (expected 'AVMPATCH')."
            )
        }

        let bodySlice = cursor.bytes[0..<(cursor.bytes.count - 4)]
        let expectedTrailerOffset = cursor.bytes.count - 4
        var trailerCursor = BinaryCursor(bytes: cursor.bytes, offset: expectedTrailerOffset)
        let recordedTrailerCRC = try trailerCursor.readUInt32LE()
        let computedTrailerCRC = BinaryChecksums.crc32(bodySlice)
        guard recordedTrailerCRC == computedTrailerCRC else {
            throw AgentVMError.diskImageOperationFailed(
                path: "<avmpatch>",
                errnoCode: EFTYPE,
                detail: String(
                    format: "AVMPATCH CRC32 trailer mismatch (expected 0x%08X, computed 0x%08X).",
                    recordedTrailerCRC,
                    computedTrailerCRC
                )
            )
        }

        let version = try cursor.readUInt16LE()
        guard version == SparseBinaryPatchHeader.currentVersion else {
            throw AgentVMError.diskImageOperationFailed(
                path: "<avmpatch>",
                errnoCode: EFTYPE,
                detail: "Unsupported AVMPATCH format version \(version)."
            )
        }

        let flags = try cursor.readUInt16LE()
        let baseSize = try cursor.readUInt64LE()
        let targetSize = try cursor.readUInt64LE()
        let chunkSize = try cursor.readUInt32LE()
        let blockCount = try cursor.readUInt32LE()

        var totalUncompressed: UInt64 = 0
        var totalCompressed: UInt64 = 0

        for blockIndex in 0..<blockCount {
            guard cursor.offset + 20 <= expectedTrailerOffset else {
                throw AgentVMError.diskImageOperationFailed(
                    path: "<avmpatch>",
                    errnoCode: EFTYPE,
                    detail: "Truncated AVMPATCH block header at index \(blockIndex)."
                )
            }
            let offset = try cursor.readUInt64LE()
            let uncompressedLen = try cursor.readUInt32LE()
            let compressedLen = try cursor.readUInt32LE()
            _ = try cursor.readUInt32LE()

            guard offset + UInt64(uncompressedLen) <= targetSize else {
                throw AgentVMError.diskImageOperationFailed(
                    path: "<avmpatch>",
                    errnoCode: EINVAL,
                    detail: "AVMPATCH block \(blockIndex) overflows target virtual size \(targetSize)."
                )
            }
            guard cursor.offset + Int(compressedLen) <= expectedTrailerOffset else {
                throw AgentVMError.diskImageOperationFailed(
                    path: "<avmpatch>",
                    errnoCode: EFTYPE,
                    detail: "Truncated AVMPATCH compressed payload at block \(blockIndex)."
                )
            }
            try cursor.skip(Int(compressedLen))
            totalUncompressed += UInt64(uncompressedLen)
            totalCompressed += UInt64(compressedLen)
        }

        guard cursor.offset == expectedTrailerOffset else {
            throw AgentVMError.diskImageOperationFailed(
                path: "<avmpatch>",
                errnoCode: EFTYPE,
                detail: "Trailing unparsed bytes before AVMPATCH CRC32 trailer."
            )
        }

        return SparseBinaryPatchHeader(
            version: version,
            flags: flags,
            baseVirtualSizeBytes: baseSize,
            targetVirtualSizeBytes: targetSize,
            scanChunkSizeBytes: chunkSize,
            dirtyBlockCount: blockCount,
            totalUncompressedDirtyBytes: totalUncompressed,
            totalCompressedPayloadBytes: totalCompressed,
            archiveCRC32: recordedTrailerCRC
        )
    }

    /// Reconstructs `outputURL` by CoW-cloning `baseURL`, verifying the `"AVMPATCH"` CRC-32 trailer,
    /// resizing to the target virtual capacity, and applying each zlib-decompressed dirty extent block.
    public func applySparseBinaryPatch(
        _ patchData: Data,
        to baseURL: URL,
        outputURL: URL
    ) throws {
        let header = try inspectSparseBinaryPatch(patchData)
        let basePath = baseURL.path
        let outPath = outputURL.path

        var baseStat = Darwin.stat()
        guard stat(basePath, &baseStat) == 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: basePath,
                errnoCode: err,
                detail: "Cannot stat base disk image for AVMPATCH apply (\(Self.posixErrorString(err)))."
            )
        }

        let actualBaseSize = UInt64(max(0, baseStat.st_size))
        guard actualBaseSize == header.baseVirtualSizeBytes else {
            throw AgentVMError.diskImageOperationFailed(
                path: basePath,
                errnoCode: EINVAL,
                detail: "Base disk size mismatch (patch expects \(header.baseVirtualSizeBytes) B, found \(actualBaseSize) B)."
            )
        }

        // Step 1: CoW clone base -> output so unchanged regions remain shared APFS extents.
        try cloneDiskCoW(from: baseURL, to: outputURL, overwrite: true)

        // Step 2: Adjust virtual disk size if target grew or shrunk relative to base.
        if header.targetVirtualSizeBytes != header.baseVirtualSizeBytes {
            if header.targetVirtualSizeBytes == 0 {
                let fd = Darwin.open(outPath, O_RDWR | O_CLOEXEC)
                if fd >= 0 {
                    _ = Darwin.ftruncate(fd, 0)
                    _ = Darwin.fsync(fd)
                    _ = Darwin.close(fd)
                }
                return
            }
            try resizeSparseRawDisk(at: outputURL, newSizeBytes: header.targetVirtualSizeBytes, allowShrink: true)
        }

        guard header.dirtyBlockCount > 0 else { return }

        let outFD = Darwin.open(outPath, O_RDWR | O_CLOEXEC)
        guard outFD >= 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: outPath,
                errnoCode: err,
                detail: "Cannot open cloned output disk to apply AVMPATCH blocks (\(Self.posixErrorString(err)))."
            )
        }
        defer { _ = Darwin.close(outFD) }

        let fsBlockSize = UInt64(Self.queryFilesystemBlockSize(fd: outFD))
        var cursor = BinaryCursor(data: patchData, offset: Self.patchHeaderByteLength)
        let isZlibCompressed = (header.flags & 0x0001) != 0

        for blockIndex in 0..<header.dirtyBlockCount {
            let blockOffset = try cursor.readUInt64LE()
            let uncompressedLen = Int(try cursor.readUInt32LE())
            let compressedLen = Int(try cursor.readUInt32LE())
            let expectedBlockCRC = try cursor.readUInt32LE()
            let payload = try cursor.readData(compressedLen)

            let rawBlock: Data
            if isZlibCompressed {
                rawBlock = try Self.zlibDecompress(
                    payload,
                    expectedLength: uncompressedLen,
                    contextPath: outPath
                )
            } else {
                guard payload.count == uncompressedLen else {
                    throw AgentVMError.diskImageOperationFailed(
                        path: outPath,
                        errnoCode: EFTYPE,
                        detail: "Uncompressed AVMPATCH block \(blockIndex) length mismatch."
                    )
                }
                rawBlock = payload
            }

            let actualBlockCRC = BinaryChecksums.crc32(rawBlock)
            guard actualBlockCRC == expectedBlockCRC else {
                throw AgentVMError.diskImageOperationFailed(
                    path: outPath,
                    errnoCode: EFTYPE,
                    detail: String(
                        format: "AVMPATCH block %d CRC32 mismatch (expected 0x%08X, got 0x%08X).",
                        blockIndex,
                        expectedBlockCRC,
                        actualBlockCRC
                    )
                )
            }

            let isZeroBlock = rawBlock.withUnsafeBytes { Self.isAllZero($0) }
            if isZeroBlock && (blockOffset % fsBlockSize == 0) && (UInt64(uncompressedLen) % fsBlockSize == 0) {
                var punch = fpunchhole_t(
                    fp_flags: 0,
                    reserved: 0,
                    fp_offset: off_t(blockOffset),
                    fp_length: off_t(uncompressedLen)
                )
                if Darwin.fcntl(outFD, F_PUNCHHOLE, &punch) != 0 {
                    try rawBlock.withUnsafeBytes { rawPtr in
                        if let baseAddress = rawPtr.baseAddress {
                            try Self.pwriteExact(
                                fd: outFD,
                                path: outPath,
                                from: baseAddress,
                                count: rawBlock.count,
                                offset: blockOffset
                            )
                        }
                    }
                }
            } else {
                try rawBlock.withUnsafeBytes { rawPtr in
                    if let baseAddress = rawPtr.baseAddress {
                        try Self.pwriteExact(
                            fd: outFD,
                            path: outPath,
                            from: baseAddress,
                            count: rawBlock.count,
                            offset: blockOffset
                        )
                    }
                }
            }
        }

        if Darwin.fsync(outFD) != 0 {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: outPath,
                errnoCode: err,
                detail: "fsync failed after applying AVMPATCH (\(Self.posixErrorString(err)))."
            )
        }
    }

    // MARK: - APFS Storage Pool Capability Probe

    /// Probes `statfs` metadata and empirically verifies `clonefile(2)`, `SEEK_HOLE`, and `F_PUNCHHOLE`
    /// support in `directoryURL`.
    public func probeAPFSCapabilities(at directoryURL: URL) throws -> APFSVolumeCapabilities {
        let dirPath = directoryURL.path
        try FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: true)

        var stfs = Darwin.statfs()
        guard statfs(dirPath, &stfs) == 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: dirPath,
                errnoCode: err,
                detail: "statfs failed on storage pool directory (\(Self.posixErrorString(err)))."
            )
        }

        let fsType = withUnsafeBytes(of: stfs.f_fstypename) { buf in
            String(decoding: buf.prefix { $0 != 0 }, as: UTF8.self)
        }
        let mountOn = withUnsafeBytes(of: stfs.f_mntonname) { buf in
            String(decoding: buf.prefix { $0 != 0 }, as: UTF8.self)
        }

        let blockSize = UInt32(stfs.f_bsize > 0 ? stfs.f_bsize : 4096)
        let ioSize = UInt32(stfs.f_iosize > 0 ? stfs.f_iosize : Int32(blockSize))
        let totalBytes = UInt64(stfs.f_blocks) * UInt64(blockSize)
        let availBytes = UInt64(stfs.f_bavail) * UInt64(blockSize)

        let nonce = UUID().uuidString.lowercased()
        let probeSrc = directoryURL.appendingPathComponent(".avm-probe-\(nonce).src").path
        let probeDst = directoryURL.appendingPathComponent(".avm-probe-\(nonce).dst").path
        defer {
            _ = Darwin.unlink(probeSrc)
            _ = Darwin.unlink(probeDst)
        }

        var supportsClone = false
        var supportsSeekHole = false
        var supportsPunch = false

        let fd = Darwin.open(probeSrc, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, mode_t(0o600))
        if fd >= 0 {
            if Darwin.ftruncate(fd, off_t(blockSize * 4)) == 0 {
                let seekRes = Darwin.lseek(fd, 0, Self.darwinSeekHole)
                supportsSeekHole = (seekRes >= 0)

                var punch = fpunchhole_t(
                    fp_flags: 0,
                    reserved: 0,
                    fp_offset: 0,
                    fp_length: off_t(blockSize)
                )
                supportsPunch = (Darwin.fcntl(fd, F_PUNCHHOLE, &punch) == 0)
            }
            _ = Darwin.close(fd)

            let rc = probeSrc.withCString { sPtr in
                probeDst.withCString { dPtr in
                    avm_darwin_clonefile(sPtr, dPtr, 0)
                }
            }
            supportsClone = (rc == 0)
        }

        return APFSVolumeCapabilities(
            directoryPath: dirPath,
            filesystemTypeName: fsType,
            mountPointPath: mountOn,
            blockSizeBytes: blockSize,
            optimalIOSizeBytes: ioSize,
            totalCapacityBytes: totalBytes,
            availableCapacityBytes: availBytes,
            supportsClonefileCoW: supportsClone,
            supportsSparseSeekHole: supportsSeekHole,
            supportsPunchHole: supportsPunch,
            probedAt: Date()
        )
    }

    // MARK: - Internal Extent Coalescer

    private struct ExtentCoalescer {
        let computeChecksums: Bool
        private(set) var completedExtents: [SparseExtent] = []
        private var activeOffset: UInt64 = 0
        private var activeLength: UInt64 = 0
        private var activeKind: SparseExtentKind?
        private var activeCRC = IncrementalCRC32()

        init(computeChecksums: Bool) {
            self.computeChecksums = computeChecksums
        }

        mutating func appendHole(offset: UInt64, length: UInt64) {
            guard length > 0 else { return }
            if activeKind == .sparseHole && (activeOffset + activeLength == offset) {
                activeLength += length
                if computeChecksums {
                    activeCRC.updateZeroBytes(count: length)
                }
            } else {
                flushActive()
                activeOffset = offset
                activeLength = length
                activeKind = .sparseHole
                if computeChecksums {
                    activeCRC = IncrementalCRC32()
                    activeCRC.updateZeroBytes(count: length)
                }
            }
        }

        mutating func appendData(offset: UInt64, kind: SparseExtentKind, bytes: UnsafeRawBufferPointer) {
            let length = UInt64(bytes.count)
            guard length > 0 else { return }
            if activeKind == kind && (activeOffset + activeLength == offset) {
                activeLength += length
                if computeChecksums {
                    activeCRC.update(bytes)
                }
            } else {
                flushActive()
                activeOffset = offset
                activeLength = length
                activeKind = kind
                if computeChecksums {
                    activeCRC = IncrementalCRC32()
                    activeCRC.update(bytes)
                }
            }
        }

        private mutating func flushActive() {
            guard let kind = activeKind, activeLength > 0 else { return }
            let crc: UInt32? = computeChecksums ? activeCRC.finalized : nil
            completedExtents.append(SparseExtent(
                offsetBytes: activeOffset,
                lengthBytes: activeLength,
                kind: kind,
                checksumCRC32: crc
            ))
            activeKind = nil
            activeLength = 0
        }

        mutating func finalize() -> [SparseExtent] {
            flushActive()
            return completedExtents
        }
    }

    // MARK: - Internal Low-Level POSIX & zlib Helpers

    internal static func ensureParentDirectoryExists(for fileURL: URL) throws {
        let parentDir = fileURL.deletingLastPathComponent()
        do {
            try FileManager.default.createDirectory(at: parentDir, withIntermediateDirectories: true)
        } catch {
            throw AgentVMError.diskImageOperationFailed(
                path: parentDir.path,
                errnoCode: EIO,
                detail: "Failed to create parent directory: \(error.localizedDescription)"
            )
        }
    }

    internal static func posixErrorString(_ code: Int32) -> String {
        guard let cStr = Darwin.strerror(code) else {
            return "errno \(code)"
        }
        return String(cString: cStr)
    }

    internal static func queryFilesystemBlockSize(fd: Int32) -> UInt32 {
        var stfs = Darwin.statfs()
        if Darwin.fstatfs(fd, &stfs) == 0 && stfs.f_bsize > 0 {
            return UInt32(stfs.f_bsize)
        }
        return 4096
    }

    /// Returns the offset `>= from` of the next allocated data span, or `nil` if `[from, fileSize)` is a hole.
    internal static func seekNextDataOffset(fd: Int32, from offset: UInt64, fileSize: UInt64) -> UInt64? {
        guard offset < fileSize else { return nil }
        let res = Darwin.lseek(fd, off_t(offset), darwinSeekData)
        if res < 0 {
            let err = Darwin.errno
            if err == ENXIO {
                return nil
            }
            // Filesystem does not implement SEEK_DATA; treat starting at `offset` as candidate data.
            return offset
        }
        let uRes = UInt64(res)
        return uRes < fileSize ? max(offset, uRes) : nil
    }

    /// Returns the offset `> from` of the next sparse hole, or `fileSize` if data continues to EOF.
    internal static func seekNextHoleOffset(fd: Int32, from dataOffset: UInt64, fileSize: UInt64) -> UInt64 {
        guard dataOffset < fileSize else { return fileSize }
        let res = Darwin.lseek(fd, off_t(dataOffset), darwinSeekHole)
        if res < 0 {
            return fileSize
        }
        let uRes = UInt64(res)
        if uRes <= dataOffset || uRes > fileSize {
            return fileSize
        }
        return uRes
    }

    @inline(__always)
    internal static func isAllZero(_ buffer: UnsafeRawBufferPointer) -> Bool {
        let count = buffer.count
        if count == 0 { return true }
        guard let base = buffer.baseAddress else { return true }
        let alignedCount = count & ~7
        var byteIdx = 0
        while byteIdx < alignedCount {
            if base.loadUnaligned(fromByteOffset: byteIdx, as: UInt64.self) != 0 {
                return false
            }
            byteIdx += 8
        }
        let bytes = base.assumingMemoryBound(to: UInt8.self)
        while byteIdx < count {
            if bytes[byteIdx] != 0 {
                return false
            }
            byteIdx += 1
        }
        return true
    }

    internal static func preadExact(
        fd: Int32,
        path: String,
        into buffer: UnsafeMutableRawPointer,
        count: Int,
        offset: UInt64
    ) throws {
        var totalRead = 0
        while totalRead < count {
            let dst = buffer.advanced(by: totalRead)
            let n = Darwin.pread(fd, dst, count - totalRead, off_t(offset + UInt64(totalRead)))
            if n > 0 {
                totalRead += n
            } else if n == 0 {
                // Beyond physical EOF inside a sparse tail: fill remaining bytes with 0x00.
                memset(dst, 0, count - totalRead)
                return
            } else {
                let err = Darwin.errno
                if err == EINTR { continue }
                throw AgentVMError.diskImageOperationFailed(
                    path: path,
                    errnoCode: err,
                    detail: "pread failed at offset \(offset + UInt64(totalRead)) (\(posixErrorString(err)))."
                )
            }
        }
    }

    internal static func pwriteExact(
        fd: Int32,
        path: String,
        from buffer: UnsafeRawPointer,
        count: Int,
        offset: UInt64
    ) throws {
        var totalWritten = 0
        while totalWritten < count {
            let src = buffer.advanced(by: totalWritten)
            let n = Darwin.pwrite(fd, src, count - totalWritten, off_t(offset + UInt64(totalWritten)))
            if n > 0 {
                totalWritten += n
            } else {
                let err = Darwin.errno
                if err == EINTR { continue }
                throw AgentVMError.diskImageOperationFailed(
                    path: path,
                    errnoCode: err,
                    detail: "pwrite failed at offset \(offset + UInt64(totalWritten)) (\(posixErrorString(err)))."
                )
            }
        }
    }

    private static func writeZeros(fd: Int32, path: String, offset: UInt64, length: UInt64) throws {
        guard length > 0 else { return }
        let bufLen = Int(min(length, 65_536))
        let zeroBuf = UnsafeMutableRawPointer.allocate(byteCount: bufLen, alignment: 8)
        memset(zeroBuf, 0, bufLen)
        defer { zeroBuf.deallocate() }

        var remaining = length
        var curOffset = offset
        while remaining > 0 {
            let step = Int(min(UInt64(bufLen), remaining))
            try pwriteExact(fd: fd, path: path, from: UnsafeRawPointer(zeroBuf), count: step, offset: curOffset)
            curOffset += UInt64(step)
            remaining -= UInt64(step)
        }
    }

    /// Cross-volume (`EXDEV`) fallback copy that preserves sparse holes via `SEEK_DATA`/`SEEK_HOLE` + zero detection.
    private static func sparseHolePreservingCopy(
        sourcePath: String,
        destinationPath: String,
        chunkSize: Int
    ) throws {
        let srcFD = Darwin.open(sourcePath, O_RDONLY | O_CLOEXEC)
        guard srcFD >= 0 else {
            throw AgentVMError.cowCloneFailed(source: sourcePath, destination: destinationPath, errnoCode: Darwin.errno)
        }
        defer { _ = Darwin.close(srcFD) }

        var srcStat = Darwin.stat()
        guard Darwin.fstat(srcFD, &srcStat) == 0 else {
            throw AgentVMError.cowCloneFailed(source: sourcePath, destination: destinationPath, errnoCode: Darwin.errno)
        }

        let virtualSize = UInt64(max(0, srcStat.st_size))

        let dstFD = Darwin.open(destinationPath, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, mode_t(0o644))
        guard dstFD >= 0 else {
            throw AgentVMError.cowCloneFailed(source: sourcePath, destination: destinationPath, errnoCode: Darwin.errno)
        }
        defer { _ = Darwin.close(dstFD) }

        if Darwin.ftruncate(dstFD, off_t(virtualSize)) != 0 {
            let err = Darwin.errno
            _ = Darwin.unlink(destinationPath)
            throw AgentVMError.cowCloneFailed(source: sourcePath, destination: destinationPath, errnoCode: err)
        }

        if virtualSize == 0 {
            _ = Darwin.fsync(dstFD)
            return
        }

        let buf = UnsafeMutableRawPointer.allocate(byteCount: chunkSize, alignment: 8)
        defer { buf.deallocate() }

        var cursor: UInt64 = 0
        while cursor < virtualSize {
            guard let dataStart = seekNextDataOffset(fd: srcFD, from: cursor, fileSize: virtualSize) else {
                break
            }
            let holeStart = seekNextHoleOffset(fd: srcFD, from: dataStart, fileSize: virtualSize)
            var pos = dataStart
            while pos < holeStart {
                let step = Int(min(UInt64(chunkSize), holeStart - pos))
                try preadExact(fd: srcFD, path: sourcePath, into: buf, count: step, offset: pos)
                let slice = UnsafeRawBufferPointer(start: buf, count: step)
                if !isAllZero(slice) {
                    try pwriteExact(fd: dstFD, path: destinationPath, from: UnsafeRawPointer(buf), count: step, offset: pos)
                }
                pos += UInt64(step)
            }
            cursor = holeStart
        }

        if Darwin.fsync(dstFD) != 0 {
            let err = Darwin.errno
            throw AgentVMError.cowCloneFailed(source: sourcePath, destination: destinationPath, errnoCode: err)
        }
    }

    private static func zlibCompress(_ input: Data, level: Int32, contextPath: String) throws -> Data {
        if input.isEmpty {
            return Data()
        }
        let maxBound = Int(zlib.compressBound(uLong(input.count)))
        var outBytes = [UInt8](repeating: 0, count: max(16, maxBound))
        var destLen = uLongf(outBytes.count)

        let rc: Int32 = input.withUnsafeBytes { rawSrc in
            outBytes.withUnsafeMutableBufferPointer { dstBuf in
                let srcPtr = rawSrc.bindMemory(to: Bytef.self).baseAddress!
                return zlib.compress2(dstBuf.baseAddress!, &destLen, srcPtr, uLong(input.count), level)
            }
        }

        guard rc == Z_OK else {
            throw AgentVMError.diskImageOperationFailed(
                path: contextPath,
                errnoCode: EIO,
                detail: "zlib compress2 failed with code \(rc) while encoding AVMPATCH."
            )
        }

        return Data(outBytes.prefix(Int(destLen)))
    }

    private static func zlibDecompress(_ compressed: Data, expectedLength: Int, contextPath: String) throws -> Data {
        if expectedLength == 0 {
            return Data()
        }
        guard !compressed.isEmpty else {
            throw AgentVMError.diskImageOperationFailed(
                path: contextPath,
                errnoCode: EFTYPE,
                detail: "Empty compressed payload for non-empty AVMPATCH block (\(expectedLength) bytes)."
            )
        }

        var outBytes = [UInt8](repeating: 0, count: expectedLength)
        var destLen = uLongf(expectedLength)

        let rc: Int32 = compressed.withUnsafeBytes { rawSrc in
            outBytes.withUnsafeMutableBufferPointer { dstBuf in
                let srcPtr = rawSrc.bindMemory(to: Bytef.self).baseAddress!
                return zlib.uncompress(dstBuf.baseAddress!, &destLen, srcPtr, uLong(compressed.count))
            }
        }

        guard rc == Z_OK, Int(destLen) == expectedLength else {
            throw AgentVMError.diskImageOperationFailed(
                path: contextPath,
                errnoCode: EFTYPE,
                detail: "zlib uncompress failed (rc=\(rc), decoded=\(destLen), expected=\(expectedLength))."
            )
        }

        return Data(outBytes)
    }
}
