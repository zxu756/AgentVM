import AgentVMModels
import Darwin
import Foundation

// MARK: - Filesystem Magic & Superblock Telemetry Models

public enum DetectedFilesystemKind: String, Codable, Hashable, Sendable, CaseIterable {
    case ext4 = "ext4"
    case ext3 = "ext3"
    case ext2 = "ext2"
    case fat32EFI = "fat32-efi"
    case fat16 = "fat16"
    case xfs = "xfs"
    case btrfs = "btrfs"
    case linuxSwap = "linux-swap"
    case apfsContainer = "apfs"
    case luksEncrypted = "luks"
    case iso9660 = "iso9660"
    case qcow2 = "qcow2"
    case unknown = "unknown"

    public var displayName: String {
        switch self {
        case .ext4: return "Linux ext4 Filesystem"
        case .ext3: return "Linux ext3 Journaling FS"
        case .ext2: return "Linux ext2 Filesystem"
        case .fat32EFI: return "FAT32 / UEFI System Partition"
        case .fat16: return "FAT16 / VFAT Volume"
        case .xfs: return "SGI / Linux XFS"
        case .btrfs: return "Btrfs Copy-on-Write FS"
        case .linuxSwap: return "Linux Swap Space (v2)"
        case .apfsContainer: return "Apple APFS Container (NXSB)"
        case .luksEncrypted: return "LUKS Encrypted Volume"
        case .iso9660: return "ISO-9660 Optical / Cloud-Init"
        case .qcow2: return "QEMU QCOW2 Container"
        case .unknown: return "Unformatted / Raw Blocks"
        }
    }

    @MainActor
    public var localizedDisplayName: String {
        switch self {
        case .ext4: return L("Linux ext4 Filesystem", "Linux ext4 文件系统")
        case .ext3: return L("Linux ext3 Journaling FS", "Linux ext3 日志文件系统")
        case .ext2: return L("Linux ext2 Filesystem", "Linux ext2 文件系统")
        case .fat32EFI: return L("FAT32 / UEFI System Partition", "FAT32 / UEFI 系统分区")
        case .fat16: return L("FAT16 / VFAT Volume", "FAT16 / VFAT 卷")
        case .xfs: return L("SGI / Linux XFS", "SGI / Linux XFS 文件系统")
        case .btrfs: return L("Btrfs Copy-on-Write FS", "Btrfs 写时复制文件系统")
        case .linuxSwap: return L("Linux Swap Space (v2)", "Linux 交换分区 (v2)")
        case .apfsContainer: return L("Apple APFS Container (NXSB)", "Apple APFS 容器 (NXSB)")
        case .luksEncrypted: return L("LUKS Encrypted Volume", "LUKS 加密卷")
        case .iso9660: return L("ISO-9660 Optical / Cloud-Init", "ISO-9660 光盘 / Cloud-Init")
        case .qcow2: return L("QEMU QCOW2 Container", "QEMU QCOW2 镜像容器")
        case .unknown: return L("Unformatted / Raw Blocks", "未格式化 / 原始数据块")
        }
    }

    public var sfSymbolName: String {
        switch self {
        case .ext4, .ext3, .ext2, .xfs, .btrfs:
            return "internaldrive"
        case .fat32EFI, .fat16:
            return "memorychip"
        case .linuxSwap:
            return "arrow.left.arrow.right.square"
        case .apfsContainer:
            return "externaldrive.badge.checkmark"
        case .luksEncrypted:
            return "lock.shield"
        case .iso9660:
            return "opticaldisc"
        case .qcow2:
            return "square.stack.3d.up"
        case .unknown:
            return "questionmark.square.dashed"
        }
    }
}

public struct FilesystemSuperblockSignature: Codable, Hashable, Sendable, Identifiable {
    public var id: String { "\(byteOffsetOnDisk)-\(kind.rawValue)" }
    public var kind: DetectedFilesystemKind
    public var partitionIndex: Int?
    public var partitionName: String?
    public var byteOffsetOnDisk: UInt64
    public var magicHexSummary: String
    public var volumeLabel: String?
    public var filesystemUUID: String?
    public var blockOrSectorSizeBytes: UInt32?
    public var totalFilesystemBytes: UInt64?
    public var featureFlagsSummary: [String]

    public init(
        kind: DetectedFilesystemKind,
        partitionIndex: Int? = nil,
        partitionName: String? = nil,
        byteOffsetOnDisk: UInt64,
        magicHexSummary: String,
        volumeLabel: String? = nil,
        filesystemUUID: String? = nil,
        blockOrSectorSizeBytes: UInt32? = nil,
        totalFilesystemBytes: UInt64? = nil,
        featureFlagsSummary: [String] = []
    ) {
        self.kind = kind
        self.partitionIndex = partitionIndex
        self.partitionName = partitionName
        self.byteOffsetOnDisk = byteOffsetOnDisk
        self.magicHexSummary = magicHexSummary
        self.volumeLabel = volumeLabel
        self.filesystemUUID = filesystemUUID
        self.blockOrSectorSizeBytes = blockOrSectorSizeBytes
        self.totalFilesystemBytes = totalFilesystemBytes
        self.featureFlagsSummary = featureFlagsSummary
    }
}

// MARK: - Block-Level Shannon Entropy Telemetry Models

public enum EntropyRegime: String, Codable, Hashable, Sendable, CaseIterable {
    case sparseOrZero = "zero"
    case constantFill = "constant"
    case lowEntropyMetadata = "metadata-text"
    case moderateStructuredBinary = "executable-data"
    case highEntropyCompressedOrEncrypted = "compressed-encrypted"

    public var displayName: String {
        switch self {
        case .sparseOrZero: return "Zero / Sparse Hole (0.0 b/B)"
        case .constantFill: return "Constant Byte Pattern (0.0 b/B)"
        case .lowEntropyMetadata: return "Structured Metadata / UTF-8 (< 4.5 b/B)"
        case .moderateStructuredBinary: return "Machine Code / Dense Data (4.5–7.2 b/B)"
        case .highEntropyCompressedOrEncrypted: return "Compressed / Encrypted (>= 7.2 b/B)"
        }
    }
}

public struct DiskEntropyBlockSample: Codable, Hashable, Sendable, Identifiable {
    public var id: UInt64 { offsetBytes }
    public var offsetBytes: UInt64
    public var lengthBytes: UInt32
    public var shannonBitsPerByte: Double
    public var uniqueByteSymbolCount: Int
    public var zeroByteFraction: Double
    public var asciiPrintableFraction: Double
    public var chiSquareUniformity: Double
    public var regime: EntropyRegime
    public var isSparseKernelHole: Bool

    public init(
        offsetBytes: UInt64,
        lengthBytes: UInt32,
        shannonBitsPerByte: Double,
        uniqueByteSymbolCount: Int,
        zeroByteFraction: Double,
        asciiPrintableFraction: Double,
        chiSquareUniformity: Double,
        regime: EntropyRegime,
        isSparseKernelHole: Bool
    ) {
        self.offsetBytes = offsetBytes
        self.lengthBytes = lengthBytes
        self.shannonBitsPerByte = shannonBitsPerByte
        self.uniqueByteSymbolCount = uniqueByteSymbolCount
        self.zeroByteFraction = zeroByteFraction
        self.asciiPrintableFraction = asciiPrintableFraction
        self.chiSquareUniformity = chiSquareUniformity
        self.regime = regime
        self.isSparseKernelHole = isSparseKernelHole
    }
}

public struct DiskForensicsReport: Codable, Hashable, Sendable {
    public var imagePath: String
    public var virtualSizeBytes: UInt64
    public var containerSummary: DiskContainerHeaderSummary
    public var detectedFilesystems: [FilesystemSuperblockSignature]
    public var overallAllocatedEntropyBits: Double
    public var peakBlockEntropyBits: Double
    public var highEntropySuspiciousBytes: UInt64
    public var entropyHeatmapSamples: [DiskEntropyBlockSample]
    public var analyzedAt: Date

    public init(
        imagePath: String,
        virtualSizeBytes: UInt64,
        containerSummary: DiskContainerHeaderSummary,
        detectedFilesystems: [FilesystemSuperblockSignature],
        overallAllocatedEntropyBits: Double,
        peakBlockEntropyBits: Double,
        highEntropySuspiciousBytes: UInt64,
        entropyHeatmapSamples: [DiskEntropyBlockSample],
        analyzedAt: Date = Date()
    ) {
        self.imagePath = imagePath
        self.virtualSizeBytes = virtualSizeBytes
        self.containerSummary = containerSummary
        self.detectedFilesystems = detectedFilesystems
        self.overallAllocatedEntropyBits = overallAllocatedEntropyBits
        self.peakBlockEntropyBits = peakBlockEntropyBits
        self.highEntropySuspiciousBytes = highEntropySuspiciousBytes
        self.entropyHeatmapSamples = entropyHeatmapSamples
        self.analyzedAt = analyzedAt
    }
}

// MARK: - Disk Shannon Entropy & Filesystem Superblock Forensics Analyzer

/// Block-level information-theoretic Shannon entropy profiler and OS filesystem superblock recognizer
/// supporting ext4/ext3/ext2 (`0xEF53` at `1024+0x38`), FAT32/EFI System Partition, XFS (`"XFSB"`),
/// Btrfs (`"_BHRfS_M"`), Linux swap (`"SWAPSPACE2"`), APFS (`"NXSB"`), LUKS, ISO-9660, and QCOW2.
public struct DiskEntropyAndForensicsAnalyzer: Sendable {
    /// Bytes read from the start of a disk or GPT partition to cover offset `0`, `1024` (ext4),
    /// `32768` (ISO-9660), and `65536` (Btrfs primary superblock / 64K ARM64 swap header).
    public static let superblockProbeByteWindow: Int = 69_632

    public init() {}

    // MARK: - Shannon Entropy & Byte-Distribution Profiling

    /// Computes exact Shannon entropy $H(X) = -\sum p_i \log_2(p_i)$ in `[0.0, 8.0]` bits per byte.
    public func computeShannonEntropy(_ data: Data) -> Double {
        guard !data.isEmpty else { return 0.0 }
        var histogram = [Int](repeating: 0, count: 256)
        data.withUnsafeBytes { rawBuf in
            guard let base = rawBuf.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
            for i in 0..<rawBuf.count {
                histogram[Int(base[i])] &+= 1
            }
        }
        return Self.entropyFromHistogram(histogram, totalCount: data.count)
    }

    /// Profiles a single block buffer into a `DiskEntropyBlockSample` including Shannon entropy,
    /// symbol cardinality, printable ASCII ratio, Pearson $\chi^2$ uniformity, and `EntropyRegime`.
    public func analyzeBlockSample(
        data: Data,
        offsetBytes: UInt64 = 0,
        isSparseKernelHole: Bool = false
    ) -> DiskEntropyBlockSample {
        if isSparseKernelHole || data.isEmpty {
            return DiskEntropyBlockSample(
                offsetBytes: offsetBytes,
                lengthBytes: UInt32(clamping: data.count),
                shannonBitsPerByte: 0.0,
                uniqueByteSymbolCount: data.isEmpty ? 0 : 1,
                zeroByteFraction: 1.0,
                asciiPrintableFraction: 0.0,
                chiSquareUniformity: 0.0,
                regime: .sparseOrZero,
                isSparseKernelHole: isSparseKernelHole
            )
        }

        var histogram = [Int](repeating: 0, count: 256)
        var printableCount = 0

        data.withUnsafeBytes { rawBuf in
            guard let base = rawBuf.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
            for i in 0..<rawBuf.count {
                let b = base[i]
                histogram[Int(b)] &+= 1
                if (b >= 0x20 && b <= 0x7E) || b == 0x09 || b == 0x0A || b == 0x0D {
                    printableCount &+= 1
                }
            }
        }

        let total = data.count
        let zeroCount = histogram[0]
        if zeroCount == total {
            return DiskEntropyBlockSample(
                offsetBytes: offsetBytes,
                lengthBytes: UInt32(clamping: total),
                shannonBitsPerByte: 0.0,
                uniqueByteSymbolCount: 1,
                zeroByteFraction: 1.0,
                asciiPrintableFraction: 0.0,
                chiSquareUniformity: 0.0,
                regime: .sparseOrZero,
                isSparseKernelHole: false
            )
        }

        var uniqueSymbols = 0
        let expectedPerBucket = Double(total) / 256.0
        var chiSquare = 0.0
        for count in histogram {
            if count > 0 { uniqueSymbols += 1 }
            let diff = Double(count) - expectedPerBucket
            chiSquare += (diff * diff) / expectedPerBucket
        }

        let entropy = Self.entropyFromHistogram(histogram, totalCount: total)
        let zeroFrac = Double(zeroCount) / Double(total)
        let printableFrac = Double(printableCount) / Double(total)

        let regime: EntropyRegime
        if uniqueSymbols <= 1 {
            regime = .constantFill
        } else if entropy < 4.5 {
            regime = .lowEntropyMetadata
        } else if entropy < 7.2 {
            regime = .moderateStructuredBinary
        } else {
            regime = .highEntropyCompressedOrEncrypted
        }

        return DiskEntropyBlockSample(
            offsetBytes: offsetBytes,
            lengthBytes: UInt32(clamping: total),
            shannonBitsPerByte: entropy,
            uniqueByteSymbolCount: uniqueSymbols,
            zeroByteFraction: zeroFrac,
            asciiPrintableFraction: printableFrac,
            chiSquareUniformity: chiSquare,
            regime: regime,
            isSparseKernelHole: false
        )
    }

    // MARK: - Filesystem Superblock & Container Magic Recognizer

    /// Detects OS filesystem or encrypted volume signatures inside `regionData` (probed from `baseOffsetOnDisk`).
    public func detectFilesystemSignature(
        in regionData: Data,
        baseOffsetOnDisk: UInt64 = 0,
        partitionIndex: Int? = nil,
        partitionName: String? = nil
    ) -> FilesystemSuperblockSignature? {
        let bytes = [UInt8](regionData)
        guard bytes.count >= 64 else { return nil }

        // 1. QEMU QCOW2 Container (`0x514649FB` at +0)
        if bytes.count >= 32,
           bytes[0] == 0x51, bytes[1] == 0x46, bytes[2] == 0x49, bytes[3] == 0xFB {
            var c = BinaryCursor(bytes: bytes, offset: 4)
            let version = (try? c.readUInt32BE()) ?? 3
            try? c.skip(12)
            let clusterBits = (try? c.readUInt32BE()) ?? 16
            let vSize = (try? c.readUInt64BE()) ?? 0
            return FilesystemSuperblockSignature(
                kind: .qcow2,
                partitionIndex: partitionIndex,
                partitionName: partitionName,
                byteOffsetOnDisk: baseOffsetOnDisk,
                magicHexSummary: "0x514649FB ('QFI\\xfb') @ +0x0",
                volumeLabel: nil,
                filesystemUUID: nil,
                blockOrSectorSizeBytes: (9...21).contains(clusterBits) ? (1 << clusterBits) : nil,
                totalFilesystemBytes: vSize,
                featureFlagsSummary: ["v\(version)", "cluster_bits=\(clusterBits)"]
            )
        }

        // 2. LUKS v1/v2 Encrypted Volume (`"LUKS\xba\xbe"` at +0)
        if bytes.count >= 208,
           bytes[0] == 0x4C, bytes[1] == 0x55, bytes[2] == 0x4B, bytes[3] == 0x53,
           bytes[4] == 0xBA, bytes[5] == 0xBE {
            let version = (UInt16(bytes[6]) << 8) | UInt16(bytes[7])
            let uuidRaw = String(decoding: bytes[168..<208].prefix { $0 != 0 }, as: UTF8.self)
            return FilesystemSuperblockSignature(
                kind: .luksEncrypted,
                partitionIndex: partitionIndex,
                partitionName: partitionName,
                byteOffsetOnDisk: baseOffsetOnDisk,
                magicHexSummary: "LUKS\\xba\\xbe @ +0x0",
                volumeLabel: nil,
                filesystemUUID: uuidRaw.isEmpty ? nil : uuidRaw,
                blockOrSectorSizeBytes: 4096,
                totalFilesystemBytes: nil,
                featureFlagsSummary: ["LUKSv\(version)"]
            )
        }

        // 3. SGI / Linux XFS (`"XFSB"` at +0)
        if bytes.count >= 128,
           bytes[0] == 0x58, bytes[1] == 0x46, bytes[2] == 0x53, bytes[3] == 0x42 {
            var c = BinaryCursor(bytes: bytes, offset: 4)
            let blockSize = (try? c.readUInt32BE()) ?? 4096
            let dblocks = (try? c.readUInt64BE()) ?? 0
            let uuidStr = Self.formatStandardUUID(Array(bytes[32..<48]))
            let label = Self.readNullTerminatedASCII(bytes, range: 108..<120)
            return FilesystemSuperblockSignature(
                kind: .xfs,
                partitionIndex: partitionIndex,
                partitionName: partitionName,
                byteOffsetOnDisk: baseOffsetOnDisk,
                magicHexSummary: "\"XFSB\" (0x58465342) @ +0x0",
                volumeLabel: label.isEmpty ? nil : label,
                filesystemUUID: uuidStr,
                blockOrSectorSizeBytes: blockSize,
                totalFilesystemBytes: dblocks > 0 ? dblocks * UInt64(blockSize) : nil,
                featureFlagsSummary: ["xfs-v5"]
            )
        }

        // 4. Apple APFS Container Superblock (`nx_magic == "NXSB"` at +32 of `nx_superblock_t`, or +0 synthetic)
        if let apfsSig = Self.detectAPFSSuperblock(
            bytes: bytes,
            baseOffsetOnDisk: baseOffsetOnDisk,
            partitionIndex: partitionIndex,
            partitionName: partitionName
        ) {
            return apfsSig
        }

        // 5. Btrfs Copy-on-Write Filesystem (`"_BHRfS_M"` at `0x10000 + 0x40` = `65,600`, or `+0x40` superblock slice)
        if let btrfsSig = Self.detectBtrfsSuperblock(
            bytes: bytes,
            baseOffsetOnDisk: baseOffsetOnDisk,
            partitionIndex: partitionIndex,
            partitionName: partitionName
        ) {
            return btrfsSig
        }

        // 6. Linux ext2 / ext3 / ext4 (`s_magic == 0xEF53` LE at `1024 + 0x38` = `1080`)
        if let extSig = Self.detectExtSuperblock(
            bytes: bytes,
            baseOffsetOnDisk: baseOffsetOnDisk,
            partitionIndex: partitionIndex,
            partitionName: partitionName
        ) {
            return extSig
        }

        // 7. Linux Swap Space (`"SWAPSPACE2"` or `"SWAP-SPACE"` at pageSize - 10 for 4K, 16K, or 64K pages)
        if let swapSig = Self.detectLinuxSwap(
            bytes: bytes,
            baseOffsetOnDisk: baseOffsetOnDisk,
            partitionIndex: partitionIndex,
            partitionName: partitionName
        ) {
            return swapSig
        }

        // 8. ISO-9660 Primary Volume Descriptor (`"CD001"` at `32768 + 1`)
        if bytes.count >= 32768 + 136 {
            let pvd = 32768
            if bytes[pvd + 1] == 0x43, bytes[pvd + 2] == 0x44,
               bytes[pvd + 3] == 0x30, bytes[pvd + 4] == 0x30, bytes[pvd + 5] == 0x31 {
                var c = BinaryCursor(bytes: bytes, offset: pvd + 40)
                let volID = (try? c.readASCII(32, trimTrailingSpaces: true)) ?? ""
                var szCur = BinaryCursor(bytes: bytes, offset: pvd + 80)
                let blocks = UInt64((try? szCur.readUInt32LE()) ?? 0)
                var bsCur = BinaryCursor(bytes: bytes, offset: pvd + 128)
                let lbSize = UInt32((try? bsCur.readUInt16LE()) ?? 2048)
                return FilesystemSuperblockSignature(
                    kind: .iso9660,
                    partitionIndex: partitionIndex,
                    partitionName: partitionName,
                    byteOffsetOnDisk: baseOffsetOnDisk + 32768,
                    magicHexSummary: "\"CD001\" @ +0x8001",
                    volumeLabel: volID.isEmpty ? nil : volID,
                    filesystemUUID: nil,
                    blockOrSectorSizeBytes: lbSize,
                    totalFilesystemBytes: blocks > 0 ? blocks * UInt64(lbSize) : nil,
                    featureFlagsSummary: ["ECMA-119"]
                )
            }
        }

        // 9. FAT32 / FAT16 / UEFI System Partition (VFAT BPB at +0, excluding GPT Protective MBR 0xEE)
        if let fatSig = Self.detectFATBootSector(
            bytes: bytes,
            baseOffsetOnDisk: baseOffsetOnDisk,
            partitionIndex: partitionIndex,
            partitionName: partitionName
        ) {
            return fatSig
        }

        return nil
    }

    // MARK: - End-to-End Disk Image Forensics & Entropy Heatmap Profiler

    /// Profiles a disk image at `url`: inspects container headers & GPT partitions, probes every partition
    /// and whole-disk offset for OS filesystem superblocks, and samples sparse-hole-aware Shannon entropy blocks.
    public func analyzeDiskImage(
        at url: URL,
        sampleWindowBytes: Int = 65_536,
        maxHeatmapSamples: Int = 256
    ) throws -> DiskForensicsReport {
        let inspector = PartitionAndContainerInspector()
        let container = try inspector.inspectContainer(at: url)
        let path = url.path

        let fd = Darwin.open(path, O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: err,
                detail: "Cannot open disk image for forensics analysis (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }
        defer { _ = Darwin.close(fd) }

        var st = Darwin.stat()
        guard Darwin.fstat(fd, &st) == 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: err,
                detail: "fstat failed during forensics analysis (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }

        let physicalFileSize = UInt64(max(0, st.st_size))
        var detectedFS: [FilesystemSuperblockSignature] = []

        // Probe whole-disk offset 0 first.
        if physicalFileSize >= 64 {
            let leadLen = Int(min(physicalFileSize, UInt64(Self.superblockProbeByteWindow)))
            var leadBuf = [UInt8](repeating: 0, count: leadLen)
            try leadBuf.withUnsafeMutableBytes { buf in
                try APFSCoWDiskEngine.preadExact(fd: fd, path: path, into: buf.baseAddress!, count: leadLen, offset: 0)
            }
            if let wholeSig = detectFilesystemSignature(in: Data(leadBuf), baseOffsetOnDisk: 0) {
                detectedFS.append(wholeSig)
            }
        }

        // Probe every active GPT partition on raw disks.
        if container.format == .rawSparse && !container.partitions.isEmpty {
            let sectorSize = UInt64(container.clusterOrSectorSize > 0 ? container.clusterOrSectorSize : 512)
            for part in container.partitions {
                let partByteStart = part.firstLBA * sectorSize
                let partSizeBytes = part.sizeBytes(sectorSize: sectorSize)
                guard partByteStart < physicalFileSize && partSizeBytes >= 512 else { continue }
                let readable = Int(min(
                    UInt64(Self.superblockProbeByteWindow),
                    min(partSizeBytes, physicalFileSize - partByteStart)
                ))
                var partBuf = [UInt8](repeating: 0, count: readable)
                try partBuf.withUnsafeMutableBytes { buf in
                    try APFSCoWDiskEngine.preadExact(
                        fd: fd,
                        path: path,
                        into: buf.baseAddress!,
                        count: readable,
                        offset: partByteStart
                    )
                }
                if let sig = detectFilesystemSignature(
                    in: Data(partBuf),
                    baseOffsetOnDisk: partByteStart,
                    partitionIndex: part.index,
                    partitionName: part.name
                ) {
                    detectedFS.append(sig)
                }
            }
        }

        // Compute block-window Shannon entropy heatmap across physicalFileSize.
        let clampedWindow = max(4096, min(sampleWindowBytes, 1_048_576))
        let clampedMaxSamples = max(1, maxHeatmapSamples)
        var samples: [DiskEntropyBlockSample] = []
        var weightedAllocatedEntropySum = 0.0
        var totalAllocatedSampledBytes: UInt64 = 0
        var peakEntropy = 0.0
        var highEntropyBytes: UInt64 = 0

        if physicalFileSize > 0 {
            let rawWindowCount = Int((physicalFileSize + UInt64(clampedWindow) - 1) / UInt64(clampedWindow))
            let strideWindows = max(1, (rawWindowCount + clampedMaxSamples - 1) / clampedMaxSamples)
            let scratch = UnsafeMutableRawPointer.allocate(byteCount: clampedWindow, alignment: 8)
            defer { scratch.deallocate() }

            var windowIdx = 0
            while windowIdx < rawWindowCount && samples.count < clampedMaxSamples {
                let offset = UInt64(windowIdx) * UInt64(clampedWindow)
                let len = Int(min(UInt64(clampedWindow), physicalFileSize - offset))

                // Check if kernel reports [offset, offset + len) as a sparse hole without reading zeros.
                let nextData = APFSCoWDiskEngine.seekNextDataOffset(fd: fd, from: offset, fileSize: physicalFileSize)
                if nextData == nil || nextData! >= offset + UInt64(len) {
                    samples.append(analyzeBlockSample(
                        data: Data(count: 0),
                        offsetBytes: offset,
                        isSparseKernelHole: true
                    ))
                } else {
                    try APFSCoWDiskEngine.preadExact(fd: fd, path: path, into: scratch, count: len, offset: offset)
                    let blockData = Data(bytes: scratch, count: len)
                    let sample = analyzeBlockSample(data: blockData, offsetBytes: offset, isSparseKernelHole: false)
                    var adjustedSample = sample
                    adjustedSample.lengthBytes = UInt32(len)
                    samples.append(adjustedSample)

                    if sample.regime != .sparseOrZero {
                        weightedAllocatedEntropySum += sample.shannonBitsPerByte * Double(len)
                        totalAllocatedSampledBytes += UInt64(len)
                        if sample.shannonBitsPerByte > peakEntropy {
                            peakEntropy = sample.shannonBitsPerByte
                        }
                        if sample.regime == .highEntropyCompressedOrEncrypted {
                            highEntropyBytes += UInt64(len) * UInt64(strideWindows)
                        }
                    }
                }

                windowIdx += strideWindows
            }
        }

        let overallEntropy = totalAllocatedSampledBytes > 0
            ? (weightedAllocatedEntropySum / Double(totalAllocatedSampledBytes))
            : 0.0

        return DiskForensicsReport(
            imagePath: path,
            virtualSizeBytes: container.virtualSizeBytes,
            containerSummary: container,
            detectedFilesystems: detectedFS,
            overallAllocatedEntropyBits: overallEntropy,
            peakBlockEntropyBits: peakEntropy,
            highEntropySuspiciousBytes: min(physicalFileSize, highEntropyBytes),
            entropyHeatmapSamples: samples,
            analyzedAt: Date()
        )
    }

    // MARK: - Internal Superblock Parsers

    private static func entropyFromHistogram(_ histogram: [Int], totalCount: Int) -> Double {
        guard totalCount > 0 else { return 0.0 }
        let invTotal = 1.0 / Double(totalCount)
        var h = 0.0
        for count in histogram where count > 0 {
            let p = Double(count) * invTotal
            h -= p * Foundation.log2(p)
        }
        return max(0.0, min(8.0, h))
    }

    private static func detectAPFSSuperblock(
        bytes: [UInt8],
        baseOffsetOnDisk: UInt64,
        partitionIndex: Int?,
        partitionName: String?
    ) -> FilesystemSuperblockSignature? {
        // Real Apple APFS `nx_superblock_t` places `nx_magic` ("NXSB") at offset +32 after `obj_phys_t`.
        // Also support +0 in case a caller passes the sliced payload starting directly at `nx_magic`.
        for magicOffset in [32, 0] {
            guard bytes.count >= magicOffset + 56 else { continue }
            if bytes[magicOffset] == 0x4E,
               bytes[magicOffset + 1] == 0x58,
               bytes[magicOffset + 2] == 0x53,
               bytes[magicOffset + 3] == 0x42 {
                var c = BinaryCursor(bytes: bytes, offset: magicOffset + 4)
                let blockSize = (try? c.readUInt32LE()) ?? 4096
                let blockCount = (try? c.readUInt64LE()) ?? 0
                let uuidOffset = magicOffset + 40
                let uuidStr: String? = bytes.count >= uuidOffset + 16
                    ? formatStandardUUID(Array(bytes[uuidOffset..<(uuidOffset + 16)]))
                    : nil
                let effectiveBlockSize = (blockSize >= 4096 && blockSize <= 65_536) ? blockSize : 4096
                return FilesystemSuperblockSignature(
                    kind: .apfsContainer,
                    partitionIndex: partitionIndex,
                    partitionName: partitionName,
                    byteOffsetOnDisk: baseOffsetOnDisk,
                    magicHexSummary: String(format: "\"NXSB\" (0x4253584E) @ +0x%X", magicOffset),
                    volumeLabel: nil,
                    filesystemUUID: uuidStr,
                    blockOrSectorSizeBytes: effectiveBlockSize,
                    totalFilesystemBytes: blockCount > 0 ? blockCount * UInt64(effectiveBlockSize) : nil,
                    featureFlagsSummary: ["apfs-container"]
                )
            }
        }
        return nil
    }

    private static func detectBtrfsSuperblock(
        bytes: [UInt8],
        baseOffsetOnDisk: UInt64,
        partitionIndex: Int?,
        partitionName: String?
    ) -> FilesystemSuperblockSignature? {
        let btrfsMagic: [UInt8] = [0x5F, 0x42, 0x48, 0x52, 0x66, 0x53, 0x5F, 0x4D] // "_BHRfS_M"
        for sbStart in [65_536, 0] {
            let magicPos = sbStart + 0x40
            guard bytes.count >= magicPos + 8 else { continue }
            if Array(bytes[magicPos..<(magicPos + 8)]) == btrfsMagic {
                let uuidStr: String? = bytes.count >= sbStart + 0x30
                    ? formatStandardUUID(Array(bytes[(sbStart + 0x20)..<(sbStart + 0x30)]))
                    : nil
                var totalBytes: UInt64?
                var sectorSize: UInt32?
                if bytes.count >= sbStart + 0x98 {
                    var c = BinaryCursor(bytes: bytes, offset: sbStart + 0x70)
                    totalBytes = try? c.readUInt64LE()
                    var sc = BinaryCursor(bytes: bytes, offset: sbStart + 0x90)
                    sectorSize = try? sc.readUInt32LE()
                }
                var label: String?
                if bytes.count >= sbStart + 0x12B + 64 {
                    let rawLabel = readNullTerminatedASCII(bytes, range: (sbStart + 0x12B)..<min(bytes.count, sbStart + 0x22B))
                    if !rawLabel.isEmpty { label = rawLabel }
                }
                return FilesystemSuperblockSignature(
                    kind: .btrfs,
                    partitionIndex: partitionIndex,
                    partitionName: partitionName,
                    byteOffsetOnDisk: baseOffsetOnDisk + UInt64(sbStart),
                    magicHexSummary: String(format: "\"_BHRfS_M\" @ +0x%X", magicPos),
                    volumeLabel: label,
                    filesystemUUID: uuidStr,
                    blockOrSectorSizeBytes: sectorSize ?? 4096,
                    totalFilesystemBytes: totalBytes,
                    featureFlagsSummary: ["cow-btree"]
                )
            }
        }
        return nil
    }

    private static func detectExtSuperblock(
        bytes: [UInt8],
        baseOffsetOnDisk: UInt64,
        partitionIndex: Int?,
        partitionName: String?
    ) -> FilesystemSuperblockSignature? {
        let sbOffset = 1024
        let magicOffset = sbOffset + 0x38 // 1080 (0x438)
        guard bytes.count >= magicOffset + 2 else { return nil }
        let magic = UInt16(bytes[magicOffset]) | (UInt16(bytes[magicOffset + 1]) << 8)
        guard magic == 0xEF53 else { return nil }

        var blockSize: UInt32 = 4096
        var blocksLo: UInt64 = 0
        var blocksHi: UInt64 = 0
        var compat: UInt32 = 0
        var incompat: UInt32 = 0
        var roCompat: UInt32 = 0
        var uuidStr: String?
        var volumeName: String?

        if bytes.count >= sbOffset + 0x68 {
            var c = BinaryCursor(bytes: bytes, offset: sbOffset + 0x04)
            blocksLo = UInt64((try? c.readUInt32LE()) ?? 0)
            var lc = BinaryCursor(bytes: bytes, offset: sbOffset + 0x18)
            let logBlockSize = (try? lc.readUInt32LE()) ?? 2
            if logBlockSize <= 6 {
                blockSize = 1024 << logBlockSize
            }
            var fc = BinaryCursor(bytes: bytes, offset: sbOffset + 0x5C)
            compat = (try? fc.readUInt32LE()) ?? 0
            incompat = (try? fc.readUInt32LE()) ?? 0
            roCompat = (try? fc.readUInt32LE()) ?? 0
        }

        if bytes.count >= sbOffset + 0x88 {
            let uuidSlice = Array(bytes[(sbOffset + 0x68)..<(sbOffset + 0x78)])
            if !uuidSlice.allSatisfy({ $0 == 0 }) {
                uuidStr = formatStandardUUID(uuidSlice)
            }
            let rawVol = readNullTerminatedASCII(bytes, range: (sbOffset + 0x78)..<(sbOffset + 0x88))
            if !rawVol.isEmpty {
                volumeName = rawVol
            }
        }

        if (incompat & 0x0080) != 0 && bytes.count >= sbOffset + 0x154 {
            var hc = BinaryCursor(bytes: bytes, offset: sbOffset + 0x150)
            blocksHi = UInt64((try? hc.readUInt32LE()) ?? 0)
        }

        let totalBlocks = (blocksHi << 32) | blocksLo
        var features: [String] = []
        if (compat & 0x0004) != 0 { features.append("has_journal") }
        if (incompat & 0x0040) != 0 { features.append("extents") }
        if (incompat & 0x0080) != 0 { features.append("64bit") }
        if (incompat & 0x0200) != 0 { features.append("flex_bg") }
        if (roCompat & 0x0400) != 0 { features.append("metadata_csum") }

        let kind: DetectedFilesystemKind
        if (incompat & (0x0040 | 0x0080 | 0x0200)) != 0 || (roCompat & (0x0008 | 0x0400)) != 0 {
            kind = .ext4
        } else if (compat & 0x0004) != 0 {
            kind = .ext3
        } else if compat != 0 || incompat != 0 || roCompat != 0 {
            kind = .ext2
        } else {
            // Default canonical classification for bare 0xEF53 superblocks in modern Linux VM tooling.
            kind = .ext4
        }

        return FilesystemSuperblockSignature(
            kind: kind,
            partitionIndex: partitionIndex,
            partitionName: partitionName,
            byteOffsetOnDisk: baseOffsetOnDisk + UInt64(sbOffset),
            magicHexSummary: "0xEF53 @ +0x438 (1024+0x38)",
            volumeLabel: volumeName,
            filesystemUUID: uuidStr,
            blockOrSectorSizeBytes: blockSize,
            totalFilesystemBytes: totalBlocks > 0 ? totalBlocks * UInt64(blockSize) : nil,
            featureFlagsSummary: features
        )
    }

    private static func detectLinuxSwap(
        bytes: [UInt8],
        baseOffsetOnDisk: UInt64,
        partitionIndex: Int?,
        partitionName: String?
    ) -> FilesystemSuperblockSignature? {
        let sigV2 = Array("SWAPSPACE2".utf8)
        let sigV1 = Array("SWAP-SPACE".utf8)

        for pageSize in [4096, 16_384, 65_536] {
            let sigOffset = pageSize - 10
            guard bytes.count >= pageSize else { continue }
            let slice = Array(bytes[sigOffset..<pageSize])
            guard slice == sigV2 || slice == sigV1 else { continue }

            var uuidStr: String?
            var label: String?
            var totalSwapBytes: UInt64?

            if bytes.count >= 1068 {
                var c = BinaryCursor(bytes: bytes, offset: 1028)
                let lastPage = UInt64((try? c.readUInt32LE()) ?? 0)
                if lastPage > 0 {
                    totalSwapBytes = (lastPage + 1) * UInt64(pageSize)
                }
                let uuidSlice = Array(bytes[1036..<1052])
                if !uuidSlice.allSatisfy({ $0 == 0 }) {
                    uuidStr = formatStandardUUID(uuidSlice)
                }
                let rawLabel = readNullTerminatedASCII(bytes, range: 1052..<1068)
                if !rawLabel.isEmpty { label = rawLabel }
            }

            let tag = slice == sigV2 ? "SWAPSPACE2" : "SWAP-SPACE"
            return FilesystemSuperblockSignature(
                kind: .linuxSwap,
                partitionIndex: partitionIndex,
                partitionName: partitionName,
                byteOffsetOnDisk: baseOffsetOnDisk,
                magicHexSummary: String(format: "\"%@\" @ +0x%X (page=%d)", tag, sigOffset, pageSize),
                volumeLabel: label,
                filesystemUUID: uuidStr,
                blockOrSectorSizeBytes: UInt32(pageSize),
                totalFilesystemBytes: totalSwapBytes,
                featureFlagsSummary: ["page_size=\(pageSize)"]
            )
        }
        return nil
    }

    private static func detectFATBootSector(
        bytes: [UInt8],
        baseOffsetOnDisk: UInt64,
        partitionIndex: Int?,
        partitionName: String?
    ) -> FilesystemSuperblockSignature? {
        guard bytes.count >= 512 else { return nil }
        guard bytes[510] == 0x55 && bytes[511] == 0xAA else { return nil }

        // Exclude GPT Protective MBR (`0xEE` partition entry at LBA 0).
        for slot in 0..<4 {
            let entryPos = 446 + slot * 16
            if bytes[entryPos + 4] == 0xEE {
                return nil
            }
        }

        let fsType32 = String(decoding: bytes[82..<90], as: UTF8.self)
        let fsType16 = String(decoding: bytes[54..<62], as: UTF8.self)
        let bytesPerSector = UInt16(bytes[11]) | (UInt16(bytes[12]) << 8)
        let sectorsPerCluster = bytes[13]
        let numFATs = bytes[16]
        let validSectorSize = [512, 1024, 2048, 4096].contains(Int(bytesPerSector))
        let validSPC = sectorsPerCluster > 0 && (sectorsPerCluster & (sectorsPerCluster - 1)) == 0

        if fsType32.hasPrefix("FAT32") || (validSectorSize && validSPC && (1...4).contains(numFATs) && bytes[17] == 0 && bytes[18] == 0) {
            let effSector = validSectorSize ? UInt32(bytesPerSector) : 512
            let effCluster = validSPC ? effSector * UInt32(sectorsPerCluster) : effSector
            var sc = BinaryCursor(bytes: bytes, offset: 32)
            let totalSectors32 = UInt64((try? sc.readUInt32LE()) ?? 0)
            let rawLabel = String(decoding: bytes[71..<82], as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            let cleanLabel = (rawLabel.isEmpty || rawLabel == "NO NAME") ? nil : rawLabel
            var vc = BinaryCursor(bytes: bytes, offset: 67)
            let serial = (try? vc.readUInt32LE()) ?? 0
            let uuidHex = serial != 0 ? String(format: "%04X-%04X", (serial >> 16) & 0xFFFF, serial & 0xFFFF) : nil

            return FilesystemSuperblockSignature(
                kind: .fat32EFI,
                partitionIndex: partitionIndex,
                partitionName: partitionName,
                byteOffsetOnDisk: baseOffsetOnDisk,
                magicHexSummary: "\"FAT32\" @ +0x52 & 0x55AA @ +0x1FE",
                volumeLabel: cleanLabel,
                filesystemUUID: uuidHex,
                blockOrSectorSizeBytes: effCluster,
                totalFilesystemBytes: totalSectors32 > 0 ? totalSectors32 * UInt64(effSector) : nil,
                featureFlagsSummary: ["vfat", "uefi-esp"]
            )
        }

        if fsType16.hasPrefix("FAT16") || fsType16.hasPrefix("FAT12") {
            let effSector = validSectorSize ? UInt32(bytesPerSector) : 512
            let rawLabel = String(decoding: bytes[43..<54], as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            let cleanLabel = (rawLabel.isEmpty || rawLabel == "NO NAME") ? nil : rawLabel
            return FilesystemSuperblockSignature(
                kind: .fat16,
                partitionIndex: partitionIndex,
                partitionName: partitionName,
                byteOffsetOnDisk: baseOffsetOnDisk,
                magicHexSummary: "\"FAT16\" @ +0x36 & 0x55AA @ +0x1FE",
                volumeLabel: cleanLabel,
                filesystemUUID: nil,
                blockOrSectorSizeBytes: effSector,
                totalFilesystemBytes: nil,
                featureFlagsSummary: ["vfat"]
            )
        }

        return nil
    }

    private static func formatStandardUUID(_ bytes: [UInt8]) -> String {
        precondition(bytes.count == 16)
        return String(
            format: "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5],
            bytes[6], bytes[7],
            bytes[8], bytes[9],
            bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
        )
    }

    private static func readNullTerminatedASCII(_ bytes: [UInt8], range: Range<Int>) -> String {
        let clampedUpper = min(bytes.count, range.upperBound)
        guard range.lowerBound < clampedUpper else { return "" }
        let slice = bytes[range.lowerBound..<clampedUpper].prefix { $0 != 0 }
        return String(decoding: slice, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
