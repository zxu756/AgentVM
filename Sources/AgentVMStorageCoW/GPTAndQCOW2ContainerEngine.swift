import AgentVMModels
import Darwin
import Foundation

// MARK: - Well-Known UEFI / GPT Partition Type GUID Catalog

public enum GPTWellKnownTypeGUID: String, Codable, Hashable, Sendable, CaseIterable {
    case efiSystemPartition = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
    case biosBootPartition = "21686148-6449-6E6F-744E-656564454649"
    case linuxFilesystem = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
    case linuxRootARM64 = "B921B045-1DF0-41C3-AF44-4C6F280D3FAE"
    case linuxRootX86_64 = "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709"
    case linuxSwap = "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F"
    case linuxLVM = "E6D6D379-F507-44C2-A23C-238F2A3DF928"
    case appleAPFS = "7C3457EF-0000-11AA-AA11-00306543ECAC"
    case freebsdBoot = "83BD6B9D-7F41-11DC-BE0B-001560B84F0F"
    case freebsdUFS = "516E7CB6-6ECF-11D6-8FF8-00022D09712B"
    case microsoftBasicData = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"

    public var displayName: String {
        switch self {
        case .efiSystemPartition: return "EFI System Partition (ESP)"
        case .biosBootPartition: return "BIOS Boot Partition"
        case .linuxFilesystem: return "Linux Filesystem Data"
        case .linuxRootARM64: return "Linux Root (ARM64)"
        case .linuxRootX86_64: return "Linux Root (x86-64)"
        case .linuxSwap: return "Linux Swap"
        case .linuxLVM: return "Linux LVM Physical Volume"
        case .appleAPFS: return "Apple APFS Container"
        case .freebsdBoot: return "FreeBSD Boot"
        case .freebsdUFS: return "FreeBSD UFS"
        case .microsoftBasicData: return "Microsoft Basic Data"
        }
    }
}

// MARK: - GPT & QCOW2 Detailed Diagnostic Reports

public struct GPTVerificationReport: Codable, Hashable, Sendable {
    public var diskGUID: String
    public var totalLBAs: UInt64
    public var firstUsableLBA: UInt64
    public var lastUsableLBA: UInt64
    public var primaryHeaderCRC32: UInt32
    public var backupHeaderCRC32: UInt32
    public var partitionArrayCRC32: UInt32
    public var hasValidProtectiveMBR: Bool
    public var hasMatchingBackupGPT: Bool
    public var partitions: [GPTPartitionEntrySummary]

    public init(
        diskGUID: String,
        totalLBAs: UInt64,
        firstUsableLBA: UInt64,
        lastUsableLBA: UInt64,
        primaryHeaderCRC32: UInt32,
        backupHeaderCRC32: UInt32,
        partitionArrayCRC32: UInt32,
        hasValidProtectiveMBR: Bool,
        hasMatchingBackupGPT: Bool,
        partitions: [GPTPartitionEntrySummary]
    ) {
        self.diskGUID = diskGUID
        self.totalLBAs = totalLBAs
        self.firstUsableLBA = firstUsableLBA
        self.lastUsableLBA = lastUsableLBA
        self.primaryHeaderCRC32 = primaryHeaderCRC32
        self.backupHeaderCRC32 = backupHeaderCRC32
        self.partitionArrayCRC32 = partitionArrayCRC32
        self.hasValidProtectiveMBR = hasValidProtectiveMBR
        self.hasMatchingBackupGPT = hasMatchingBackupGPT
        self.partitions = partitions
    }
}

public struct QCOW2HeaderInfo: Codable, Hashable, Sendable {
    public static let wireMagic: UInt32 = 0x5146_49FB // "QFI\xfb"

    public var version: UInt32
    public var clusterBits: UInt32
    public var clusterSizeBytes: UInt32
    public var virtualSizeBytes: UInt64
    public var backingFileOffset: UInt64
    public var backingFilePath: String?
    public var l1Size: UInt32
    public var l1TableOffset: UInt64
    public var refcountTableOffset: UInt64
    public var refcountTableClusters: UInt32
    public var refcountOrder: UInt32
    public var headerLength: UInt32
    public var incompatibleFeatures: UInt64
    public var compatibleFeatures: UInt64
    public var autoclearFeatures: UInt64
    public var allocatedDataClusters: UInt64
    public var explicitZeroClusters: UInt64

    public init(
        version: UInt32,
        clusterBits: UInt32,
        clusterSizeBytes: UInt32,
        virtualSizeBytes: UInt64,
        backingFileOffset: UInt64,
        backingFilePath: String?,
        l1Size: UInt32,
        l1TableOffset: UInt64,
        refcountTableOffset: UInt64,
        refcountTableClusters: UInt32,
        refcountOrder: UInt32,
        headerLength: UInt32,
        incompatibleFeatures: UInt64,
        compatibleFeatures: UInt64,
        autoclearFeatures: UInt64,
        allocatedDataClusters: UInt64,
        explicitZeroClusters: UInt64
    ) {
        self.version = version
        self.clusterBits = clusterBits
        self.clusterSizeBytes = clusterSizeBytes
        self.virtualSizeBytes = virtualSizeBytes
        self.backingFileOffset = backingFileOffset
        self.backingFilePath = backingFilePath
        self.l1Size = l1Size
        self.l1TableOffset = l1TableOffset
        self.refcountTableOffset = refcountTableOffset
        self.refcountTableClusters = refcountTableClusters
        self.refcountOrder = refcountOrder
        self.headerLength = headerLength
        self.incompatibleFeatures = incompatibleFeatures
        self.compatibleFeatures = compatibleFeatures
        self.autoclearFeatures = autoclearFeatures
        self.allocatedDataClusters = allocatedDataClusters
        self.explicitZeroClusters = explicitZeroClusters
    }
}

// MARK: - Partition Table (MBR / GPT) & QCOW2 Container Engine

/// Pure-Swift Protective MBR + UEFI GUID Partition Table (GPT) writer/verifier and QEMU QCOW2 v2/v3
/// sparse cluster reader/writer/converter.
public struct PartitionAndContainerInspector: Sendable {
    public static let gptSectorSize: Int = 512
    public static let gptHeaderSignatureASCII = "EFI PART"
    public static let gptRevisionV1: UInt32 = 0x0001_0000
    public static let gptHeaderByteSize: Int = 92
    public static let gptEntryCount: Int = 128
    public static let gptEntryByteSize: Int = 128
    public static let gptEntryArrayByteSize: Int = 128 * 128 // 16,384 bytes (32 512-byte sectors)

    private static let qcow2CopiedFlag: UInt64 = 1 << 63
    private static let qcow2CompressedFlag: UInt64 = 1 << 62
    private static let qcow2ZeroClusterFlag: UInt64 = 1 << 0
    private static let qcow2StandardOffsetMask: UInt64 = 0x00FF_FFFF_FFFF_FE00
    private static let zeroGUIDString = "00000000-0000-0000-0000-000000000000"

    public init() {}

    // MARK: - Protective MBR + Primary & Backup UEFI GPT Writer

    /// Writes a Protective MBR (LBA 0, `0x55AA`, `0xEE`) along with both Primary GPT (LBA 1..33)
    /// and Backup GPT (`totalLBAs - 33 .. totalLBAs - 1`) to an existing raw disk image at `diskURL`.
    public func writeProtectiveMBRAndGPT(
        to diskURL: URL,
        partitions: [(name: String, typeGUID: String, sizeBytes: UInt64)]
    ) throws -> [GPTPartitionEntrySummary] {
        guard partitions.count <= Self.gptEntryCount else {
            throw AgentVMError.partitionTableInvalid(
                detail: "GPT supports at most \(Self.gptEntryCount) partitions (requested \(partitions.count))."
            )
        }

        let path = diskURL.path
        let fd = Darwin.open(path, O_RDWR | O_CLOEXEC)
        guard fd >= 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: err,
                detail: "Cannot open disk image to write Protective MBR and GPT (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }
        defer { _ = Darwin.close(fd) }

        var st = Darwin.stat()
        guard Darwin.fstat(fd, &st) == 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: err,
                detail: "fstat failed on target GPT disk (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }

        let diskSizeBytes = UInt64(max(0, st.st_size))
        let sectorSize = UInt64(Self.gptSectorSize)
        guard diskSizeBytes >= 68 * sectorSize else {
            throw AgentVMError.partitionTableInvalid(
                detail: "Disk size (\(diskSizeBytes) B) is smaller than the minimum 68-sector (34,816 B) UEFI GPT envelope."
            )
        }

        let totalLBAs = diskSizeBytes / sectorSize
        let firstUsableLBA: UInt64 = 34
        let lastUsableLBA: UInt64 = totalLBAs - 34

        // Validate partition specs upfront.
        var parsedTypeGUIDs: [[UInt8]] = []
        var canonicalTypeStrings: [String] = []
        for (idx, part) in partitions.enumerated() {
            guard part.sizeBytes >= sectorSize else {
                throw AgentVMError.partitionTableInvalid(
                    detail: "Partition \(idx) ('\(part.name)') size (\(part.sizeBytes) B) must be at least \(sectorSize) bytes."
                )
            }
            let encodedType = try Self.encodeMixedEndianGUID(part.typeGUID)
            let canonical = Self.decodeMixedEndianGUID(encodedType)
            guard canonical != Self.zeroGUIDString else {
                throw AgentVMError.partitionTableInvalid(
                    detail: "Partition \(idx) ('\(part.name)') cannot use all-zero unused Type GUID."
                )
            }
            parsedTypeGUIDs.append(encodedType)
            canonicalTypeStrings.append(canonical)
        }

        // Choose optimal partition alignment:
        // Prefer standard 1 MiB (2048-sector) alignment when disk capacity allows; fall back to 4 KiB (8-sector)
        // or 1-sector alignment on compact test images.
        let layout = try Self.layoutPartitions(
            partitions: partitions,
            firstUsableLBA: firstUsableLBA,
            lastUsableLBA: lastUsableLBA,
            sectorSize: sectorSize
        )

        let diskGUIDString = UUID().uuidString.uppercased()
        let diskGUIDBytes = try Self.encodeMixedEndianGUID(diskGUIDString)

        // Build 128 * 128 = 16,384-byte Partition Entry Array.
        var entryArrayWriter = BinaryBufferWriter(capacity: Self.gptEntryArrayByteSize)
        var summaries: [GPTPartitionEntrySummary] = []
        summaries.reserveCapacity(partitions.count)

        for idx in 0..<Self.gptEntryCount {
            if idx < partitions.count {
                let uniqueGUIDStr = UUID().uuidString.uppercased()
                let uniqueGUIDBytes = try Self.encodeMixedEndianGUID(uniqueGUIDStr)
                let range = layout[idx]
                let partName = partitions[idx].name
                let nameUTF16LE = Self.encodeUTF16LEPartitionName(partName)

                entryArrayWriter.appendBytes(parsedTypeGUIDs[idx]) // 0..<16
                entryArrayWriter.appendBytes(uniqueGUIDBytes)    // 16..<32
                entryArrayWriter.appendUInt64LE(range.firstLBA)  // 32..<40
                entryArrayWriter.appendUInt64LE(range.lastLBA)   // 40..<48
                entryArrayWriter.appendUInt64LE(0)               // 48..<56 attributesFlags
                entryArrayWriter.appendBytes(nameUTF16LE)        // 56..<128 (72 bytes)

                summaries.append(GPTPartitionEntrySummary(
                    index: idx,
                    typeGUID: canonicalTypeStrings[idx],
                    uniquePartitionGUID: uniqueGUIDStr,
                    firstLBA: range.firstLBA,
                    lastLBA: range.lastLBA,
                    attributesFlags: 0,
                    name: Self.decodeUTF16LEPartitionName(nameUTF16LE)
                ))
            } else {
                entryArrayWriter.appendBytes([UInt8](repeating: 0, count: Self.gptEntryByteSize))
            }
        }

        precondition(entryArrayWriter.count == Self.gptEntryArrayByteSize)
        let entryArrayBytes = entryArrayWriter.bytes
        let entryArrayCRC32 = BinaryChecksums.crc32(entryArrayBytes[0..<entryArrayBytes.count])

        // 1. Protective MBR at LBA 0.
        let protectiveMBR = Self.encodeProtectiveMBR(totalLBAs: totalLBAs)
        precondition(protectiveMBR.count == Self.gptSectorSize)

        // 2. Primary GPT Header at LBA 1 (Entries at LBA 2..33).
        let primaryHeaderSector = Self.encodeGPTHeaderSector(
            myLBA: 1,
            alternateLBA: totalLBAs - 1,
            firstUsableLBA: firstUsableLBA,
            lastUsableLBA: lastUsableLBA,
            diskGUIDBytes: diskGUIDBytes,
            partitionEntryLBA: 2,
            entryCount: UInt32(Self.gptEntryCount),
            entrySize: UInt32(Self.gptEntryByteSize),
            entryArrayCRC32: entryArrayCRC32
        )

        // 3. Backup GPT Header at `totalLBAs - 1` (Entries at `totalLBAs - 33 .. totalLBAs - 2`).
        let backupEntryLBA = totalLBAs - 33
        let backupHeaderSector = Self.encodeGPTHeaderSector(
            myLBA: totalLBAs - 1,
            alternateLBA: 1,
            firstUsableLBA: firstUsableLBA,
            lastUsableLBA: lastUsableLBA,
            diskGUIDBytes: diskGUIDBytes,
            partitionEntryLBA: backupEntryLBA,
            entryCount: UInt32(Self.gptEntryCount),
            entrySize: UInt32(Self.gptEntryByteSize),
            entryArrayCRC32: entryArrayCRC32
        )

        // Write Protective MBR + Primary GPT Header + Primary Entry Array atomically at offset 0.
        var primaryEnvelope = [UInt8]()
        primaryEnvelope.reserveCapacity(2 * Self.gptSectorSize + Self.gptEntryArrayByteSize)
        primaryEnvelope.append(contentsOf: protectiveMBR)
        primaryEnvelope.append(contentsOf: primaryHeaderSector)
        primaryEnvelope.append(contentsOf: entryArrayBytes)

        try primaryEnvelope.withUnsafeBytes { rawPtr in
            try APFSCoWDiskEngine.pwriteExact(
                fd: fd,
                path: path,
                from: rawPtr.baseAddress!,
                count: primaryEnvelope.count,
                offset: 0
            )
        }

        // Write Backup Entry Array + Backup GPT Header at the end of the disk.
        var backupEnvelope = [UInt8]()
        backupEnvelope.reserveCapacity(Self.gptEntryArrayByteSize + Self.gptSectorSize)
        backupEnvelope.append(contentsOf: entryArrayBytes)
        backupEnvelope.append(contentsOf: backupHeaderSector)

        try backupEnvelope.withUnsafeBytes { rawPtr in
            try APFSCoWDiskEngine.pwriteExact(
                fd: fd,
                path: path,
                from: rawPtr.baseAddress!,
                count: backupEnvelope.count,
                offset: backupEntryLBA * sectorSize
            )
        }

        if Darwin.fsync(fd) != 0 {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: err,
                detail: "fsync failed after writing GPT (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }

        return summaries
    }

    /// Performs full cryptographic CRC-32 and geometric verification of Protective MBR, Primary GPT,
    /// Backup GPT, and all active partition entries on `diskURL`.
    public func verifyGPTIntegrity(at diskURL: URL) throws -> GPTVerificationReport {
        let path = diskURL.path
        let fd = Darwin.open(path, O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: err,
                detail: "Cannot open disk image for GPT verification (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }
        defer { _ = Darwin.close(fd) }

        var st = Darwin.stat()
        guard Darwin.fstat(fd, &st) == 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: err,
                detail: "fstat failed during GPT verification (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }

        let fileSize = UInt64(max(0, st.st_size))
        let sectorSize = UInt64(Self.gptSectorSize)
        guard fileSize >= 68 * sectorSize else {
            throw AgentVMError.partitionTableInvalid(
                detail: "Disk image (\(fileSize) B) is too small to hold Primary and Backup UEFI GPT structures."
            )
        }
        let totalLBAs = fileSize / sectorSize

        // Read LBA 0 (Protective MBR) + LBA 1 (Primary GPT Header).
        var headBytes = [UInt8](repeating: 0, count: 2 * Self.gptSectorSize)
        try headBytes.withUnsafeMutableBytes { buf in
            try APFSCoWDiskEngine.preadExact(fd: fd, path: path, into: buf.baseAddress!, count: buf.count, offset: 0)
        }

        let hasValidPMBR = Self.validateProtectiveMBR(Array(headBytes[0..<Self.gptSectorSize]))
        guard hasValidPMBR else {
            throw AgentVMError.partitionTableInvalid(
                detail: "Missing Protective MBR signature (0x55AA) or 0xEE partition entry at LBA 0."
            )
        }

        let primaryHeader = try Self.parseAndValidateGPTHeader(
            sectorBytes: Array(headBytes[Self.gptSectorSize..<(2 * Self.gptSectorSize)]),
            expectedMyLBA: 1
        )

        let entryArrayBytesCount = Int(primaryHeader.numEntries) * Int(primaryHeader.entrySize)
        guard entryArrayBytesCount > 0 && entryArrayBytesCount <= 1_048_576 else {
            throw AgentVMError.partitionTableInvalid(
                detail: "Unreasonable GPT partition entry array byte size (\(entryArrayBytesCount))."
            )
        }
        let primaryEntriesOffset = primaryHeader.partitionEntryLBA * sectorSize
        guard primaryEntriesOffset + UInt64(entryArrayBytesCount) <= fileSize else {
            throw AgentVMError.partitionTableInvalid(detail: "Primary GPT entry array overflows disk image.")
        }

        var primaryEntryArray = [UInt8](repeating: 0, count: entryArrayBytesCount)
        try primaryEntryArray.withUnsafeMutableBytes { buf in
            try APFSCoWDiskEngine.preadExact(
                fd: fd,
                path: path,
                into: buf.baseAddress!,
                count: entryArrayBytesCount,
                offset: primaryEntriesOffset
            )
        }

        let computedPrimaryArrayCRC = BinaryChecksums.crc32(primaryEntryArray[0..<primaryEntryArray.count])
        guard computedPrimaryArrayCRC == primaryHeader.entryArrayCRC32 else {
            throw AgentVMError.partitionTableInvalid(
                detail: String(
                    format: "Primary GPT Partition Entry Array CRC32 mismatch (expected 0x%08X, got 0x%08X).",
                    primaryHeader.entryArrayCRC32,
                    computedPrimaryArrayCRC
                )
            )
        }

        let partitions = try Self.parseGPTEntries(
            entryArrayBytes: primaryEntryArray,
            numEntries: Int(primaryHeader.numEntries),
            entrySize: Int(primaryHeader.entrySize),
            firstUsableLBA: primaryHeader.firstUsableLBA,
            lastUsableLBA: primaryHeader.lastUsableLBA
        )

        // Verify Backup GPT Header & Backup Partition Entry Array at `primaryHeader.alternateLBA`.
        var backupHeaderBytes = [UInt8](repeating: 0, count: Self.gptSectorSize)
        var backupMatches = false
        var backupHeaderCRC: UInt32 = 0

        if primaryHeader.alternateLBA < totalLBAs {
            try backupHeaderBytes.withUnsafeMutableBytes { buf in
                try APFSCoWDiskEngine.preadExact(
                    fd: fd,
                    path: path,
                    into: buf.baseAddress!,
                    count: Self.gptSectorSize,
                    offset: primaryHeader.alternateLBA * sectorSize
                )
            }
            if let backupHeader = try? Self.parseAndValidateGPTHeader(
                sectorBytes: backupHeaderBytes,
                expectedMyLBA: primaryHeader.alternateLBA
            ) {
                backupHeaderCRC = backupHeader.headerCRC32
                let backupEntriesOffset = backupHeader.partitionEntryLBA * sectorSize
                if backupHeader.diskGUID == primaryHeader.diskGUID,
                   backupHeader.entryArrayCRC32 == primaryHeader.entryArrayCRC32,
                   backupEntriesOffset + UInt64(entryArrayBytesCount) <= fileSize {
                    var backupEntryArray = [UInt8](repeating: 0, count: entryArrayBytesCount)
                    try backupEntryArray.withUnsafeMutableBytes { buf in
                        try APFSCoWDiskEngine.preadExact(
                            fd: fd,
                            path: path,
                            into: buf.baseAddress!,
                            count: entryArrayBytesCount,
                            offset: backupEntriesOffset
                        )
                    }
                    let backupArrayCRC = BinaryChecksums.crc32(backupEntryArray[0..<backupEntryArray.count])
                    backupMatches = (backupArrayCRC == backupHeader.entryArrayCRC32) && (backupEntryArray == primaryEntryArray)
                }
            }
        }

        return GPTVerificationReport(
            diskGUID: primaryHeader.diskGUID,
            totalLBAs: totalLBAs,
            firstUsableLBA: primaryHeader.firstUsableLBA,
            lastUsableLBA: primaryHeader.lastUsableLBA,
            primaryHeaderCRC32: primaryHeader.headerCRC32,
            backupHeaderCRC32: backupHeaderCRC,
            partitionArrayCRC32: primaryHeader.entryArrayCRC32,
            hasValidProtectiveMBR: hasValidPMBR,
            hasMatchingBackupGPT: backupMatches,
            partitions: partitions
        )
    }

    // MARK: - Unified Disk Container Header Inspector (QCOW2 / ISO-9660 / Raw + GPT)

    /// Inspects any disk container at `url` and classifies it as `.qcow2`, `.iso9660`, or `.rawSparse`,
    /// extracting virtual capacity, cluster/sector geometry, backing path, ISO volume ID, and GPT partitions.
    public func inspectContainer(at url: URL) throws -> DiskContainerHeaderSummary {
        let path = url.path
        let fd = Darwin.open(path, O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: err,
                detail: "Cannot open container image for inspection (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }
        defer { _ = Darwin.close(fd) }

        var st = Darwin.stat()
        guard Darwin.fstat(fd, &st) == 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: err,
                detail: "fstat failed on container image (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }

        let fileSize = UInt64(max(0, st.st_size))

        // 1. Probe QCOW2 magic (`0x514649FB`) at byte offset 0.
        if fileSize >= 4 {
            var magicBytes = [UInt8](repeating: 0, count: 4)
            try magicBytes.withUnsafeMutableBytes { buf in
                try APFSCoWDiskEngine.preadExact(fd: fd, path: path, into: buf.baseAddress!, count: 4, offset: 0)
            }
            var mc = BinaryCursor(bytes: magicBytes)
            let magic = try mc.readUInt32BE()
            if magic == QCOW2HeaderInfo.wireMagic {
                let qcowInfo = try parseQCOW2Header(fd: fd, path: path, fileSize: fileSize)
                // Also inspect guest virtual LBA 0..33 inside the QCOW2 container if present!
                var guestDiskGUID: String?
                var guestPartitions: [GPTPartitionEntrySummary] = []
                if qcowInfo.virtualSizeBytes >= UInt64(34 * Self.gptSectorSize),
                   let guestLead = try? readQCOW2GuestPrefix(
                       fd: fd,
                       path: path,
                       fileSize: fileSize,
                       header: qcowInfo,
                       byteLength: 34 * Self.gptSectorSize
                   ) {
                    if let gpt = try? Self.inspectGPTFromPrefixBuffer(guestLead, validateStrictly: false) {
                        guestDiskGUID = gpt.diskGUID
                        guestPartitions = gpt.partitions
                    }
                }
                return DiskContainerHeaderSummary(
                    format: .qcow2,
                    virtualSizeBytes: qcowInfo.virtualSizeBytes,
                    clusterOrSectorSize: qcowInfo.clusterSizeBytes,
                    backingFilePath: qcowInfo.backingFilePath,
                    gptDiskGUID: guestDiskGUID,
                    partitions: guestPartitions,
                    isoVolumeIdentifier: nil
                )
            }
        }

        // 2. Probe ISO-9660 Primary Volume Descriptor at Sector 16 (offset 32,768).
        if fileSize >= UInt64(17 * ISO9660CloudInitBuilder.sectorSize) {
            var vdSector = [UInt8](repeating: 0, count: ISO9660CloudInitBuilder.sectorSize)
            try vdSector.withUnsafeMutableBytes { buf in
                try APFSCoWDiskEngine.preadExact(
                    fd: fd,
                    path: path,
                    into: buf.baseAddress!,
                    count: buf.count,
                    offset: UInt64(16 * ISO9660CloudInitBuilder.sectorSize)
                )
            }
            let ident = String(decoding: vdSector[1..<6], as: UTF8.self)
            if ident == "CD001" {
                var isoCursor = BinaryCursor(bytes: vdSector, offset: 0)
                let vdType = try isoCursor.readUInt8()
                try isoCursor.skip(7)
                _ = try isoCursor.readASCII(32, trimTrailingSpaces: true)
                let volumeID = vdType == 0x01 ? (try isoCursor.readASCII(32, trimTrailingSpaces: true)) : nil
                try isoCursor.skip(8)
                let volumeBlocks = try isoCursor.readUInt32LE()
                try isoCursor.skip(4 + 32 + 4 + 4)
                let blockSize = UInt32(try isoCursor.readUInt16LE())
                let effectiveBlockSize = blockSize >= 512 ? blockSize : 2048
                let computedVirtual = max(fileSize, UInt64(volumeBlocks) * UInt64(effectiveBlockSize))
                return DiskContainerHeaderSummary(
                    format: .iso9660,
                    virtualSizeBytes: fileSize > 0 ? fileSize : computedVirtual,
                    clusterOrSectorSize: effectiveBlockSize,
                    backingFilePath: nil,
                    gptDiskGUID: nil,
                    partitions: [],
                    isoVolumeIdentifier: volumeID
                )
            }
        }

        // 3. Raw / Sparse Disk Image — check Protective MBR + UEFI GPT if large enough.
        var gptDiskGUID: String?
        var gptPartitions: [GPTPartitionEntrySummary] = []

        if fileSize >= UInt64(2 * Self.gptSectorSize) {
            let prefixLen = Int(min(fileSize, UInt64(34 * Self.gptSectorSize)))
            var prefixBytes = [UInt8](repeating: 0, count: prefixLen)
            try prefixBytes.withUnsafeMutableBytes { buf in
                try APFSCoWDiskEngine.preadExact(fd: fd, path: path, into: buf.baseAddress!, count: prefixLen, offset: 0)
            }

            let hasPMBR = Self.validateProtectiveMBR(Array(prefixBytes[0..<Self.gptSectorSize]))
            let lba1Sig = String(decoding: prefixBytes[Self.gptSectorSize..<(Self.gptSectorSize + 8)], as: UTF8.self)

            if hasPMBR || lba1Sig == Self.gptHeaderSignatureASCII {
                let parsedGPT = try Self.inspectGPTFromFileDescriptor(
                    fd: fd,
                    path: path,
                    fileSize: fileSize,
                    lba1Sector: Array(prefixBytes[Self.gptSectorSize..<(2 * Self.gptSectorSize)])
                )
                gptDiskGUID = parsedGPT.diskGUID
                gptPartitions = parsedGPT.partitions
            }
        }

        return DiskContainerHeaderSummary(
            format: .rawSparse,
            virtualSizeBytes: fileSize,
            clusterOrSectorSize: UInt32(Self.gptSectorSize),
            backingFilePath: nil,
            gptDiskGUID: gptDiskGUID,
            partitions: gptPartitions,
            isoVolumeIdentifier: nil
        )
    }

    // MARK: - Pure-Swift QCOW2 v2/v3 Parser, Writer & Sparse Converter

    /// Inspects a QCOW2 v2 or v3 container file and returns its decoded cluster and table geometry.
    public func inspectQCOW2Header(at url: URL) throws -> QCOW2HeaderInfo {
        let path = url.path
        let fd = Darwin.open(path, O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: err,
                detail: "Cannot open QCOW2 file (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }
        defer { _ = Darwin.close(fd) }

        var st = Darwin.stat()
        guard Darwin.fstat(fd, &st) == 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: err,
                detail: "fstat failed on QCOW2 file (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }

        return try parseQCOW2Header(fd: fd, path: path, fileSize: UInt64(max(0, st.st_size)))
    }

    /// Converts a raw/sparse disk image into a standards-compliant uncompressed QEMU QCOW2 v3 container
    /// (`magic = 0x514649FB`), omitting sparse/zero clusters so only non-zero guest clusters are allocated.
    public func writeUncompressedQCOW2(
        fromRawURL rawURL: URL,
        toQCOW2URL qcow2URL: URL,
        clusterBits: UInt32 = 16
    ) throws {
        let rawPath = rawURL.path
        let qcowPath = qcow2URL.path

        guard (9...21).contains(clusterBits) else {
            throw AgentVMError.diskImageOperationFailed(
                path: qcowPath,
                errnoCode: EINVAL,
                detail: "QCOW2 cluster_bits \(clusterBits) must be within 9...21 (512 B ... 2 MiB)."
            )
        }

        let rawFD = Darwin.open(rawPath, O_RDONLY | O_CLOEXEC)
        guard rawFD >= 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: rawPath,
                errnoCode: err,
                detail: "Cannot open source raw disk for QCOW2 export (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }
        defer { _ = Darwin.close(rawFD) }

        var rawStat = Darwin.stat()
        guard Darwin.fstat(rawFD, &rawStat) == 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: rawPath,
                errnoCode: err,
                detail: "fstat failed on source raw disk (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }

        let virtualSize = UInt64(max(0, rawStat.st_size))
        let clusterSize = Int(1 << clusterBits)
        let clusterSizeU64 = UInt64(clusterSize)
        let l2EntriesPerCluster = clusterSize / 8 // 8-byte BE entries
        let totalGuestClusters = Int((virtualSize + clusterSizeU64 - 1) / clusterSizeU64)
        let l1Size = max(1, (totalGuestClusters + l2EntriesPerCluster - 1) / l2EntriesPerCluster)

        // Pass 1: Identify all non-zero guest cluster indices using SEEK_DATA / SEEK_HOLE + 64-bit zero check.
        let scratch = UnsafeMutableRawPointer.allocate(byteCount: clusterSize, alignment: 8)
        defer { scratch.deallocate() }

        var allocatedGuestClusters: [Int] = []
        var activeL1Slots = Set<Int>()

        var byteCursor: UInt64 = 0
        while byteCursor < virtualSize {
            guard let nextData = APFSCoWDiskEngine.seekNextDataOffset(fd: rawFD, from: byteCursor, fileSize: virtualSize) else {
                break
            }
            let nextHole = APFSCoWDiskEngine.seekNextHoleOffset(fd: rawFD, from: nextData, fileSize: virtualSize)
            let startCluster = Int(nextData / clusterSizeU64)
            let endClusterExclusive = Int((nextHole + clusterSizeU64 - 1) / clusterSizeU64)

            for guestClusterIdx in startCluster..<min(totalGuestClusters, endClusterExclusive) {
                let guestOffset = UInt64(guestClusterIdx) * clusterSizeU64
                let readable = Int(min(clusterSizeU64, virtualSize - guestOffset))
                try APFSCoWDiskEngine.preadExact(fd: rawFD, path: rawPath, into: scratch, count: readable, offset: guestOffset)
                if readable < clusterSize {
                    memset(scratch.advanced(by: readable), 0, clusterSize - readable)
                }
                let slice = UnsafeRawBufferPointer(start: scratch, count: clusterSize)
                if !APFSCoWDiskEngine.isAllZero(slice) {
                    allocatedGuestClusters.append(guestClusterIdx)
                    activeL1Slots.insert(guestClusterIdx / l2EntriesPerCluster)
                }
            }

            byteCursor = UInt64(endClusterExclusive) * clusterSizeU64
        }

        let sortedL1Slots = activeL1Slots.sorted()
        let l1Clusters = max(1, (l1Size * 8 + clusterSize - 1) / clusterSize)
        let l2TableClusters = sortedL1Slots.count
        let dataClustersCount = allocatedGuestClusters.count

        // Refcount geometry (refcount_order = 4 -> 16-bit refcounts -> clusterSize / 2 entries per refcount block).
        let refcountsPerBlock = clusterSize / 2
        let blocksPerRefcountTableCluster = clusterSize / 8
        let fixedNonRefcountClusters = 1 + l1Clusters + l2TableClusters + dataClustersCount

        var refcountBlockClusters = 1
        var refcountTableClusters = 1
        while true {
            let totalClusters = fixedNonRefcountClusters + refcountTableClusters + refcountBlockClusters
            let neededBlocks = max(1, (totalClusters + refcountsPerBlock - 1) / refcountsPerBlock)
            let neededTable = max(1, (neededBlocks + blocksPerRefcountTableCluster - 1) / blocksPerRefcountTableCluster)
            if neededBlocks == refcountBlockClusters && neededTable == refcountTableClusters {
                break
            }
            refcountBlockClusters = neededBlocks
            refcountTableClusters = neededTable
        }

        // Deterministic Host Cluster Map:
        //   [0]                                 : QCOW2 v3 Header
        //   [1 ..< 1 + rcTable]                 : Refcount Table
        //   [rcBlockStart ..< rcBlockEnd]       : Refcount Blocks (16-bit BE = 1 for all used clusters)
        //   [l1Start ..< l1End]                 : L1 Table
        //   [l2Start ..< l2End]                 : Allocated L2 Tables
        //   [dataStart ..< totalHostClusters]   : Allocated Guest Data Clusters
        let refcountTableClusterStart = 1
        let refcountBlockClusterStart = refcountTableClusterStart + refcountTableClusters
        let l1ClusterStart = refcountBlockClusterStart + refcountBlockClusters
        let l2ClusterStart = l1ClusterStart + l1Clusters
        let dataClusterStart = l2ClusterStart + l2TableClusters
        let totalHostClusters = dataClusterStart + dataClustersCount

        let refcountTableOffset = UInt64(refcountTableClusterStart) * clusterSizeU64
        let l1TableOffset = UInt64(l1ClusterStart) * clusterSizeU64

        try APFSCoWDiskEngine.ensureParentDirectoryExists(for: qcow2URL)
        if Darwin.unlink(qcowPath) != 0 && Darwin.errno != ENOENT {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: qcowPath,
                errnoCode: err,
                detail: "Cannot remove pre-existing QCOW2 target (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }

        let outFD = Darwin.open(qcowPath, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, mode_t(0o644))
        guard outFD >= 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: qcowPath,
                errnoCode: err,
                detail: "Cannot create QCOW2 image file (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }
        defer { _ = Darwin.close(outFD) }

        let finalQCOW2Bytes = UInt64(totalHostClusters) * clusterSizeU64
        if Darwin.ftruncate(outFD, off_t(finalQCOW2Bytes)) != 0 {
            let err = Darwin.errno
            _ = Darwin.unlink(qcowPath)
            throw AgentVMError.diskImageOperationFailed(
                path: qcowPath,
                errnoCode: err,
                detail: "ftruncate failed on QCOW2 output (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }

        // 1. Write Cluster 0: QCOW2 v3 Header (104 bytes, zero-padded to clusterSize).
        var headerWriter = BinaryBufferWriter(capacity: clusterSize)
        headerWriter.appendUInt32BE(QCOW2HeaderInfo.wireMagic) // 0..<4: "QFI\xfb"
        headerWriter.appendUInt32BE(3)                         // 4..<8: version = 3
        headerWriter.appendUInt64BE(0)                         // 8..<16: backing_file_offset = 0
        headerWriter.appendUInt32BE(0)                         // 16..<20: backing_file_size = 0
        headerWriter.appendUInt32BE(clusterBits)               // 20..<24: cluster_bits
        headerWriter.appendUInt64BE(virtualSize)               // 24..<32: size
        headerWriter.appendUInt32BE(0)                         // 32..<36: crypt_method = 0
        headerWriter.appendUInt32BE(UInt32(l1Size))            // 36..<40: l1_size
        headerWriter.appendUInt64BE(l1TableOffset)             // 40..<48: l1_table_offset
        headerWriter.appendUInt64BE(refcountTableOffset)       // 48..<56: refcount_table_offset
        headerWriter.appendUInt32BE(UInt32(refcountTableClusters)) // 56..<60: refcount_table_clusters
        headerWriter.appendUInt32BE(0)                         // 60..<64: nb_snapshots
        headerWriter.appendUInt64BE(0)                         // 64..<72: snapshots_offset
        headerWriter.appendUInt64BE(0)                         // 72..<80: incompatible_features
        headerWriter.appendUInt64BE(0)                         // 80..<88: compatible_features
        headerWriter.appendUInt64BE(0)                         // 88..<96: autoclear_features
        headerWriter.appendUInt32BE(4)                         // 96..<100: refcount_order = 4 (16-bit)
        headerWriter.appendUInt32BE(104)                       // 100..<104: header_length = 104
        headerWriter.padToAlignment(clusterSize, fillByte: 0x00)

        try headerWriter.bytes.withUnsafeBytes { buf in
            try APFSCoWDiskEngine.pwriteExact(fd: outFD, path: qcowPath, from: buf.baseAddress!, count: clusterSize, offset: 0)
        }

        // 2. Write Refcount Table Clusters.
        var rcTableWriter = BinaryBufferWriter(capacity: refcountTableClusters * clusterSize)
        for blockIdx in 0..<refcountBlockClusters {
            let blockHostOffset = UInt64(refcountBlockClusterStart + blockIdx) * clusterSizeU64
            rcTableWriter.appendUInt64BE(blockHostOffset)
        }
        rcTableWriter.padToAlignment(refcountTableClusters * clusterSize, fillByte: 0x00)
        try rcTableWriter.bytes.withUnsafeBytes { buf in
            try APFSCoWDiskEngine.pwriteExact(
                fd: outFD,
                path: qcowPath,
                from: buf.baseAddress!,
                count: rcTableWriter.count,
                offset: refcountTableOffset
            )
        }

        // 3. Write Refcount Block Clusters (every allocated cluster 0..<totalHostClusters has refcount = 1).
        var rcBlocksWriter = BinaryBufferWriter(capacity: refcountBlockClusters * clusterSize)
        for _ in 0..<totalHostClusters {
            rcBlocksWriter.appendUInt16BE(1)
        }
        rcBlocksWriter.padToAlignment(refcountBlockClusters * clusterSize, fillByte: 0x00)
        try rcBlocksWriter.bytes.withUnsafeBytes { buf in
            try APFSCoWDiskEngine.pwriteExact(
                fd: outFD,
                path: qcowPath,
                from: buf.baseAddress!,
                count: rcBlocksWriter.count,
                offset: UInt64(refcountBlockClusterStart) * clusterSizeU64
            )
        }

        // 4. Build L1 & L2 mappings.
        var l1SlotToHostL2Cluster: [Int: Int] = [:]
        for (slotPos, l1Slot) in sortedL1Slots.enumerated() {
            l1SlotToHostL2Cluster[l1Slot] = l2ClusterStart + slotPos
        }

        var l1Writer = BinaryBufferWriter(capacity: l1Clusters * clusterSize)
        for l1Idx in 0..<l1Size {
            if let hostL2Cluster = l1SlotToHostL2Cluster[l1Idx] {
                let l2HostOffset = UInt64(hostL2Cluster) * clusterSizeU64
                l1Writer.appendUInt64BE(Self.qcow2CopiedFlag | l2HostOffset)
            } else {
                l1Writer.appendUInt64BE(0)
            }
        }
        l1Writer.padToAlignment(l1Clusters * clusterSize, fillByte: 0x00)
        try l1Writer.bytes.withUnsafeBytes { buf in
            try APFSCoWDiskEngine.pwriteExact(
                fd: outFD,
                path: qcowPath,
                from: buf.baseAddress!,
                count: l1Writer.count,
                offset: l1TableOffset
            )
        }

        // Map guestClusterIdx -> hostDataCluster.
        var guestToHostDataCluster: [Int: Int] = [:]
        guestToHostDataCluster.reserveCapacity(allocatedGuestClusters.count)
        for (dataOrdinal, guestClusterIdx) in allocatedGuestClusters.enumerated() {
            guestToHostDataCluster[guestClusterIdx] = dataClusterStart + dataOrdinal
        }

        // 5. Write each allocated L2 Table Cluster.
        for (slotPos, l1Slot) in sortedL1Slots.enumerated() {
            var l2Writer = BinaryBufferWriter(capacity: clusterSize)
            let baseGuestCluster = l1Slot * l2EntriesPerCluster
            for subIdx in 0..<l2EntriesPerCluster {
                let guestClusterIdx = baseGuestCluster + subIdx
                if let hostDataCluster = guestToHostDataCluster[guestClusterIdx] {
                    let hostDataOffset = UInt64(hostDataCluster) * clusterSizeU64
                    l2Writer.appendUInt64BE(Self.qcow2CopiedFlag | hostDataOffset)
                } else {
                    l2Writer.appendUInt64BE(0)
                }
            }
            let l2WriteOffset = UInt64(l2ClusterStart + slotPos) * clusterSizeU64
            try l2Writer.bytes.withUnsafeBytes { buf in
                try APFSCoWDiskEngine.pwriteExact(
                    fd: outFD,
                    path: qcowPath,
                    from: buf.baseAddress!,
                    count: clusterSize,
                    offset: l2WriteOffset
                )
            }
        }

        // 6. Stream non-zero guest data clusters into `[dataClusterStart ..< totalHostClusters)`.
        for (dataOrdinal, guestClusterIdx) in allocatedGuestClusters.enumerated() {
            let srcOffset = UInt64(guestClusterIdx) * clusterSizeU64
            let readable = Int(min(clusterSizeU64, virtualSize - srcOffset))
            try APFSCoWDiskEngine.preadExact(fd: rawFD, path: rawPath, into: scratch, count: readable, offset: srcOffset)
            if readable < clusterSize {
                memset(scratch.advanced(by: readable), 0, clusterSize - readable)
            }
            let dstOffset = UInt64(dataClusterStart + dataOrdinal) * clusterSizeU64
            try APFSCoWDiskEngine.pwriteExact(
                fd: outFD,
                path: qcowPath,
                from: UnsafeRawPointer(scratch),
                count: clusterSize,
                offset: dstOffset
            )
        }

        if Darwin.fsync(outFD) != 0 {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: qcowPath,
                errnoCode: err,
                detail: "fsync failed while finalizing QCOW2 container (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }
    }

    /// Converts an uncompressed QEMU QCOW2 v2/v3 image into an APFS sparse raw disk image at `destinationURL`,
    /// skipping unallocated and zero-flagged clusters so sparse holes are preserved, and returns its `DiskAllocationSummary`.
    public func convertUncompressedQCOW2ToRawSparse(
        sourceURL: URL,
        destinationURL: URL
    ) throws -> DiskAllocationSummary {
        let srcPath = sourceURL.path
        let dstPath = destinationURL.path

        let srcFD = Darwin.open(srcPath, O_RDONLY | O_CLOEXEC)
        guard srcFD >= 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: srcPath,
                errnoCode: err,
                detail: "Cannot open source QCOW2 image (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }
        defer { _ = Darwin.close(srcFD) }

        var srcStat = Darwin.stat()
        guard Darwin.fstat(srcFD, &srcStat) == 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: srcPath,
                errnoCode: err,
                detail: "fstat failed on source QCOW2 image (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }

        let srcFileSize = UInt64(max(0, srcStat.st_size))
        let header = try parseQCOW2Header(fd: srcFD, path: srcPath, fileSize: srcFileSize)
        let virtualSize = header.virtualSizeBytes
        let clusterSize = Int(header.clusterSizeBytes)
        let clusterSizeU64 = UInt64(clusterSize)
        let l2EntriesPerCluster = clusterSize / 8

        let engine = APFSCoWDiskEngine()
        if virtualSize == 0 {
            try APFSCoWDiskEngine.ensureParentDirectoryExists(for: destinationURL)
            _ = Darwin.unlink(dstPath)
            let emptyFD = Darwin.open(dstPath, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, mode_t(0o644))
            if emptyFD >= 0 {
                _ = Darwin.fsync(emptyFD)
                _ = Darwin.close(emptyFD)
            }
            return try engine.scanSparseExtents(at: destinationURL)
        }

        try engine.createSparseRawDisk(at: destinationURL, virtualSizeBytes: virtualSize, overwrite: true)

        let dstFD = Darwin.open(dstPath, O_RDWR | O_CLOEXEC)
        guard dstFD >= 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: dstPath,
                errnoCode: err,
                detail: "Cannot open destination raw disk for QCOW2 conversion (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }
        defer { _ = Darwin.close(dstFD) }

        // Read L1 table.
        let l1ByteLen = Int(header.l1Size) * 8
        if l1ByteLen > 0 {
            guard header.l1TableOffset + UInt64(l1ByteLen) <= srcFileSize else {
                throw AgentVMError.diskImageOperationFailed(
                    path: srcPath,
                    errnoCode: EFTYPE,
                    detail: "QCOW2 L1 table at offset \(header.l1TableOffset) overflows container size \(srcFileSize)."
                )
            }

            var l1Bytes = [UInt8](repeating: 0, count: l1ByteLen)
            try l1Bytes.withUnsafeMutableBytes { buf in
                try APFSCoWDiskEngine.preadExact(
                    fd: srcFD,
                    path: srcPath,
                    into: buf.baseAddress!,
                    count: l1ByteLen,
                    offset: header.l1TableOffset
                )
            }

            let clusterBuf = UnsafeMutableRawPointer.allocate(byteCount: clusterSize, alignment: 8)
            let l2BytesBuf = UnsafeMutableRawPointer.allocate(byteCount: clusterSize, alignment: 8)
            defer {
                clusterBuf.deallocate()
                l2BytesBuf.deallocate()
            }

            var l1Cursor = BinaryCursor(bytes: l1Bytes)
            for l1Idx in 0..<Int(header.l1Size) {
                let l1Entry = try l1Cursor.readUInt64BE()
                let l2Offset = l1Entry & Self.qcow2StandardOffsetMask
                if l2Offset == 0 { continue }

                guard l2Offset + clusterSizeU64 <= srcFileSize else {
                    throw AgentVMError.diskImageOperationFailed(
                        path: srcPath,
                        errnoCode: EFTYPE,
                        detail: "QCOW2 L2 table offset \(l2Offset) (L1[\(l1Idx)]) exceeds file size \(srcFileSize)."
                    )
                }

                try APFSCoWDiskEngine.preadExact(fd: srcFD, path: srcPath, into: l2BytesBuf, count: clusterSize, offset: l2Offset)
                let l2Array = Array(UnsafeRawBufferPointer(start: l2BytesBuf, count: clusterSize))
                var l2Cursor = BinaryCursor(bytes: l2Array)

                for l2Idx in 0..<l2EntriesPerCluster {
                    let guestClusterIdx = UInt64(l1Idx * l2EntriesPerCluster + l2Idx)
                    let guestOffset = guestClusterIdx * clusterSizeU64
                    if guestOffset >= virtualSize { break }

                    let l2Entry = try l2Cursor.readUInt64BE()
                    if (l2Entry & Self.qcow2CompressedFlag) != 0 {
                        throw AgentVMError.diskImageOperationFailed(
                            path: srcPath,
                            errnoCode: ENOTSUP,
                            detail: "Compressed QCOW2 cluster encountered at guest offset \(guestOffset) in uncompressed converter."
                        )
                    }
                    if (l2Entry & Self.qcow2ZeroClusterFlag) != 0 {
                        // Explicit zero cluster -> leave as sparse hole in raw output.
                        continue
                    }

                    let hostClusterOffset = l2Entry & Self.qcow2StandardOffsetMask
                    if hostClusterOffset == 0 {
                        // Unallocated cluster -> leave as sparse hole.
                        continue
                    }

                    let writeLen = Int(min(clusterSizeU64, virtualSize - guestOffset))
                    guard hostClusterOffset + UInt64(writeLen) <= srcFileSize else {
                        throw AgentVMError.diskImageOperationFailed(
                            path: srcPath,
                            errnoCode: EFTYPE,
                            detail: "QCOW2 data cluster at \(hostClusterOffset) overflows container bounds (\(srcFileSize))."
                        )
                    }

                    try APFSCoWDiskEngine.preadExact(
                        fd: srcFD,
                        path: srcPath,
                        into: clusterBuf,
                        count: writeLen,
                        offset: hostClusterOffset
                    )
                    let slice = UnsafeRawBufferPointer(start: clusterBuf, count: writeLen)
                    if !APFSCoWDiskEngine.isAllZero(slice) {
                        try APFSCoWDiskEngine.pwriteExact(
                            fd: dstFD,
                            path: dstPath,
                            from: UnsafeRawPointer(clusterBuf),
                            count: writeLen,
                            offset: guestOffset
                        )
                    }
                }
            }
        }

        if Darwin.fsync(dstFD) != 0 {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: dstPath,
                errnoCode: err,
                detail: "fsync failed on converted sparse raw disk (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }

        return try engine.scanSparseExtents(at: destinationURL)
    }

    // MARK: - Mixed-Endian UEFI GUID & UTF-16LE Partition Name Codecs

    /// Encodes a canonical UUID string (`XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`) into 16-byte UEFI mixed-endian layout.
    public static func encodeMixedEndianGUID(_ guidString: String) throws -> [UInt8] {
        let trimmed = guidString.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = trimmed.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count == 5,
              parts[0].count == 8,
              parts[1].count == 4,
              parts[2].count == 4,
              parts[3].count == 4,
              parts[4].count == 12,
              let d1 = UInt32(parts[0], radix: 16),
              let d2 = UInt16(parts[1], radix: 16),
              let d3 = UInt16(parts[2], radix: 16),
              let d4Hi = UInt16(parts[3], radix: 16),
              let d4Lo = UInt64(parts[4], radix: 16) else {
            throw AgentVMError.partitionTableInvalid(
                detail: "Malformed UEFI GUID string '\(guidString)' (expected XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX)."
            )
        }

        var w = BinaryBufferWriter(capacity: 16)
        w.appendUInt32LE(d1)
        w.appendUInt16LE(d2)
        w.appendUInt16LE(d3)
        w.appendUInt16BE(d4Hi)
        w.appendUInt16BE(UInt16((d4Lo >> 32) & 0xFFFF))
        w.appendUInt32BE(UInt32(d4Lo & 0xFFFF_FFFF))
        return w.bytes
    }

    /// Decodes a 16-byte UEFI mixed-endian GUID slice into canonical uppercase UUID string format.
    public static func decodeMixedEndianGUID(_ bytes: [UInt8]) -> String {
        precondition(bytes.count == 16)
        var c = BinaryCursor(bytes: bytes)
        let d1 = (try? c.readUInt32LE()) ?? 0
        let d2 = (try? c.readUInt16LE()) ?? 0
        let d3 = (try? c.readUInt16LE()) ?? 0
        let d4a = (try? c.readUInt16BE()) ?? 0
        let d4bHi = UInt64((try? c.readUInt16BE()) ?? 0)
        let d4bLo = UInt64((try? c.readUInt32BE()) ?? 0)
        let d4b = (d4bHi << 32) | d4bLo
        return String(format: "%08X-%04X-%04X-%04X-%012llX", d1, d2, d3, d4a, d4b)
    }

    /// Encodes a partition name into a NUL-padded 72-byte (36-code-unit) UTF-16LE field.
    public static func encodeUTF16LEPartitionName(_ name: String) -> [UInt8] {
        var w = BinaryBufferWriter(capacity: 72)
        let units = Array(name.utf16.prefix(36))
        for unit in units {
            w.appendUInt16LE(unit)
        }
        while w.count < 72 {
            w.appendUInt8(0x00)
        }
        return w.bytes
    }

    /// Decodes a 72-byte UTF-16LE GPT partition name up to the first NUL code unit.
    public static func decodeUTF16LEPartitionName(_ bytes: [UInt8]) -> String {
        var units: [UInt16] = []
        units.reserveCapacity(36)
        var idx = 0
        while idx + 1 < min(72, bytes.count) {
            let unit = UInt16(bytes[idx]) | (UInt16(bytes[idx + 1]) << 8)
            if unit == 0 { break }
            units.append(unit)
            idx += 2
        }
        return String(utf16CodeUnits: units, count: units.count)
    }

    // MARK: - Internal GPT & Protective MBR Helpers

    private static func layoutPartitions(
        partitions: [(name: String, typeGUID: String, sizeBytes: UInt64)],
        firstUsableLBA: UInt64,
        lastUsableLBA: UInt64,
        sectorSize: UInt64
    ) throws -> [(firstLBA: UInt64, lastLBA: UInt64)] {
        if partitions.isEmpty { return [] }

        for alignmentSectors: UInt64 in [2048, 8, 1] {
            var cursor = max(firstUsableLBA, alignmentSectors)
            if alignmentSectors > 1 {
                cursor = ((cursor + alignmentSectors - 1) / alignmentSectors) * alignmentSectors
            }
            var candidate: [(firstLBA: UInt64, lastLBA: UInt64)] = []
            var fits = true

            for part in partitions {
                if alignmentSectors > 1 {
                    cursor = ((cursor + alignmentSectors - 1) / alignmentSectors) * alignmentSectors
                }
                let sectorCount = (part.sizeBytes + sectorSize - 1) / sectorSize
                guard sectorCount >= 1 else {
                    fits = false
                    break
                }
                let endLBA = cursor + sectorCount - 1
                if endLBA > lastUsableLBA || endLBA < cursor {
                    fits = false
                    break
                }
                candidate.append((firstLBA: cursor, lastLBA: endLBA))
                cursor = endLBA + 1
            }

            if fits {
                return candidate
            }
        }

        let totalRequestedBytes = partitions.reduce(UInt64(0)) { $0 + $1.sizeBytes }
        let usableBytes = (lastUsableLBA >= firstUsableLBA ? (lastUsableLBA - firstUsableLBA + 1) : 0) * sectorSize
        throw AgentVMError.partitionTableInvalid(
            detail: "Requested partitions (\(totalRequestedBytes) B) exceed GPT usable capacity (\(usableBytes) B)."
        )
    }

    private static func encodeProtectiveMBR(totalLBAs: UInt64) -> [UInt8] {
        var mbr = [UInt8](repeating: 0, count: gptSectorSize)
        // Partition Entry #1 at offset 446..<462
        mbr[446] = 0x00 // Non-bootable protective entry
        mbr[447] = 0x00 // Starting CHS head = 0
        mbr[448] = 0x02 // Starting CHS sector = 2 (LBA 1)
        mbr[449] = 0x00 // Starting CHS cylinder = 0
        mbr[450] = 0xEE // GPT Protective OS Type
        mbr[451] = 0xFF // Ending CHS
        mbr[452] = 0xFF
        mbr[453] = 0xFF

        let startLBA: UInt32 = 1
        let spannedSectors = UInt32(min(totalLBAs - 1, UInt64(UInt32.max)))
        mbr[454] = UInt8(startLBA & 0xFF)
        mbr[455] = UInt8((startLBA >> 8) & 0xFF)
        mbr[456] = UInt8((startLBA >> 16) & 0xFF)
        mbr[457] = UInt8((startLBA >> 24) & 0xFF)

        mbr[458] = UInt8(spannedSectors & 0xFF)
        mbr[459] = UInt8((spannedSectors >> 8) & 0xFF)
        mbr[460] = UInt8((spannedSectors >> 16) & 0xFF)
        mbr[461] = UInt8((spannedSectors >> 24) & 0xFF)

        // MBR Signature 0x55, 0xAA (little-endian 0xAA55 / wire signature 0x55AA)
        mbr[510] = 0x55
        mbr[511] = 0xAA
        return mbr
    }

    private static func validateProtectiveMBR(_ sector: [UInt8]) -> Bool {
        guard sector.count >= gptSectorSize else { return false }
        guard sector[510] == 0x55 && sector[511] == 0xAA else { return false }
        for slot in 0..<4 {
            let base = 446 + slot * 16
            if sector[base + 4] == 0xEE {
                return true
            }
        }
        return false
    }

    private static func encodeGPTHeaderSector(
        myLBA: UInt64,
        alternateLBA: UInt64,
        firstUsableLBA: UInt64,
        lastUsableLBA: UInt64,
        diskGUIDBytes: [UInt8],
        partitionEntryLBA: UInt64,
        entryCount: UInt32,
        entrySize: UInt32,
        entryArrayCRC32: UInt32
    ) -> [UInt8] {
        var w = BinaryBufferWriter(capacity: gptSectorSize)
        w.appendFixedASCII(gptHeaderSignatureASCII, length: 8, padByte: 0x20) // 0..<8: "EFI PART"
        w.appendUInt32LE(gptRevisionV1)          // 8..<12: 0x00010000
        w.appendUInt32LE(UInt32(gptHeaderByteSize)) // 12..<16: 92
        w.appendUInt32LE(0)                      // 16..<20: HeaderCRC32 zeroed during calculation
        w.appendUInt32LE(0)                      // 20..<24: Reserved
        w.appendUInt64LE(myLBA)                  // 24..<32: MyLBA
        w.appendUInt64LE(alternateLBA)           // 32..<40: AlternateLBA
        w.appendUInt64LE(firstUsableLBA)         // 40..<48: FirstUsableLBA
        w.appendUInt64LE(lastUsableLBA)          // 48..<56: LastUsableLBA
        w.appendBytes(diskGUIDBytes)             // 56..<72: DiskGUID (16 B)
        w.appendUInt64LE(partitionEntryLBA)      // 72..<80: PartitionEntryLBA
        w.appendUInt32LE(entryCount)             // 80..<84: NumberOfPartitionEntries
        w.appendUInt32LE(entrySize)              // 84..<88: SizeOfPartitionEntry
        w.appendUInt32LE(entryArrayCRC32)        // 88..<92: PartitionEntryArrayCRC32

        let headerCRC = BinaryChecksums.crc32(w.bytes[0..<gptHeaderByteSize])
        w.patchUInt32LE(headerCRC, at: 16)
        w.padToAlignment(gptSectorSize, fillByte: 0x00)
        return w.bytes
    }

    private struct ParsedGPTHeader {
        var headerSize: UInt32
        var headerCRC32: UInt32
        var myLBA: UInt64
        var alternateLBA: UInt64
        var firstUsableLBA: UInt64
        var lastUsableLBA: UInt64
        var diskGUID: String
        var partitionEntryLBA: UInt64
        var numEntries: UInt32
        var entrySize: UInt32
        var entryArrayCRC32: UInt32
    }

    private static func parseAndValidateGPTHeader(
        sectorBytes: [UInt8],
        expectedMyLBA: UInt64?
    ) throws -> ParsedGPTHeader {
        guard sectorBytes.count >= gptSectorSize else {
            throw AgentVMError.partitionTableInvalid(detail: "Truncated GPT header sector.")
        }
        var c = BinaryCursor(bytes: sectorBytes)
        let sig = try c.readASCII(8, trimTrailingSpaces: false)
        guard sig == gptHeaderSignatureASCII else {
            throw AgentVMError.partitionTableInvalid(
                detail: "Missing 'EFI PART' GPT signature at LBA \(expectedMyLBA ?? 1) (found '\(sig)')."
            )
        }

        let revision = try c.readUInt32LE()
        guard revision == gptRevisionV1 else {
            throw AgentVMError.partitionTableInvalid(
                detail: String(format: "Unsupported GPT header revision 0x%08X.", revision)
            )
        }

        let headerSize = try c.readUInt32LE()
        guard headerSize >= UInt32(gptHeaderByteSize) && headerSize <= UInt32(gptSectorSize) else {
            throw AgentVMError.partitionTableInvalid(
                detail: "Invalid GPT header size \(headerSize) bytes (expected 92...512)."
            )
        }

        let storedHeaderCRC = try c.readUInt32LE()
        _ = try c.readUInt32LE() // Reserved
        let myLBA = try c.readUInt64LE()
        let alternateLBA = try c.readUInt64LE()
        let firstUsable = try c.readUInt64LE()
        let lastUsable = try c.readUInt64LE()
        let guidBytes = try c.readBytes(16)
        let entryLBA = try c.readUInt64LE()
        let numEntries = try c.readUInt32LE()
        let entrySize = try c.readUInt32LE()
        let entryArrayCRC = try c.readUInt32LE()

        if let expectedMyLBA, myLBA != expectedMyLBA {
            throw AgentVMError.partitionTableInvalid(
                detail: "GPT Header MyLBA mismatch (expected \(expectedMyLBA), found \(myLBA))."
            )
        }

        var zeroedCopy = Array(sectorBytes[0..<Int(headerSize)])
        zeroedCopy[16] = 0
        zeroedCopy[17] = 0
        zeroedCopy[18] = 0
        zeroedCopy[19] = 0
        let computedCRC = BinaryChecksums.crc32(zeroedCopy[0..<zeroedCopy.count])
        guard computedCRC == storedHeaderCRC else {
            throw AgentVMError.partitionTableInvalid(
                detail: String(
                    format: "GPT Header CRC32 mismatch (expected 0x%08X, computed 0x%08X).",
                    storedHeaderCRC,
                    computedCRC
                )
            )
        }

        guard entrySize >= 128 && (entrySize & (entrySize - 1)) == 0 else {
            throw AgentVMError.partitionTableInvalid(
                detail: "Invalid GPT partition entry size \(entrySize) (must be >= 128 and power of two)."
            )
        }

        return ParsedGPTHeader(
            headerSize: headerSize,
            headerCRC32: storedHeaderCRC,
            myLBA: myLBA,
            alternateLBA: alternateLBA,
            firstUsableLBA: firstUsable,
            lastUsableLBA: lastUsable,
            diskGUID: decodeMixedEndianGUID(guidBytes),
            partitionEntryLBA: entryLBA,
            numEntries: numEntries,
            entrySize: entrySize,
            entryArrayCRC32: entryArrayCRC
        )
    }

    private static func parseGPTEntries(
        entryArrayBytes: [UInt8],
        numEntries: Int,
        entrySize: Int,
        firstUsableLBA: UInt64,
        lastUsableLBA: UInt64
    ) throws -> [GPTPartitionEntrySummary] {
        var results: [GPTPartitionEntrySummary] = []
        var occupiedRanges: [(index: Int, first: UInt64, last: UInt64)] = []

        for idx in 0..<numEntries {
            let base = idx * entrySize
            guard base + 128 <= entryArrayBytes.count else { break }
            let typeBytes = Array(entryArrayBytes[base..<(base + 16)])
            if typeBytes.allSatisfy({ $0 == 0 }) {
                continue
            }
            let typeGUID = decodeMixedEndianGUID(typeBytes)
            let uniqueGUID = decodeMixedEndianGUID(Array(entryArrayBytes[(base + 16)..<(base + 32)]))

            var ec = BinaryCursor(bytes: entryArrayBytes, offset: base + 32)
            let firstLBA = try ec.readUInt64LE()
            let lastLBA = try ec.readUInt64LE()
            let attrFlags = try ec.readUInt64LE()
            let nameBytes = try ec.readBytes(72)
            let name = decodeUTF16LEPartitionName(nameBytes)

            guard firstLBA >= firstUsableLBA, lastLBA <= lastUsableLBA, firstLBA <= lastLBA else {
                throw AgentVMError.partitionTableInvalid(
                    detail: "GPT partition \(idx) ('\(name)') LBA range \(firstLBA)...\(lastLBA) outside usable \(firstUsableLBA)...\(lastUsableLBA)."
                )
            }

            for prev in occupiedRanges {
                if firstLBA <= prev.last && lastLBA >= prev.first {
                    throw AgentVMError.partitionTableInvalid(
                        detail: "GPT partition \(idx) (\(firstLBA)...\(lastLBA)) overlaps partition \(prev.index) (\(prev.first)...\(prev.last))."
                    )
                }
            }
            occupiedRanges.append((index: idx, first: firstLBA, last: lastLBA))

            results.append(GPTPartitionEntrySummary(
                index: idx,
                typeGUID: typeGUID,
                uniquePartitionGUID: uniqueGUID,
                firstLBA: firstLBA,
                lastLBA: lastLBA,
                attributesFlags: attrFlags,
                name: name
            ))
        }

        return results
    }

    private static func inspectGPTFromFileDescriptor(
        fd: Int32,
        path: String,
        fileSize: UInt64,
        lba1Sector: [UInt8]
    ) throws -> (diskGUID: String, partitions: [GPTPartitionEntrySummary]) {
        let header = try parseAndValidateGPTHeader(sectorBytes: lba1Sector, expectedMyLBA: 1)
        let arrayByteCount = Int(header.numEntries) * Int(header.entrySize)
        let arrayOffset = header.partitionEntryLBA * UInt64(gptSectorSize)
        guard arrayByteCount > 0, arrayOffset + UInt64(arrayByteCount) <= fileSize else {
            throw AgentVMError.partitionTableInvalid(
                detail: "GPT partition entry array (offset=\(arrayOffset), bytes=\(arrayByteCount)) exceeds disk size (\(fileSize))."
            )
        }

        var entryBytes = [UInt8](repeating: 0, count: arrayByteCount)
        try entryBytes.withUnsafeMutableBytes { buf in
            try APFSCoWDiskEngine.preadExact(fd: fd, path: path, into: buf.baseAddress!, count: arrayByteCount, offset: arrayOffset)
        }

        let computedArrayCRC = BinaryChecksums.crc32(entryBytes[0..<entryBytes.count])
        guard computedArrayCRC == header.entryArrayCRC32 else {
            throw AgentVMError.partitionTableInvalid(
                detail: String(
                    format: "GPT Partition Entry Array CRC32 mismatch (expected 0x%08X, computed 0x%08X).",
                    header.entryArrayCRC32,
                    computedArrayCRC
                )
            )
        }

        let partitions = try parseGPTEntries(
            entryArrayBytes: entryBytes,
            numEntries: Int(header.numEntries),
            entrySize: Int(header.entrySize),
            firstUsableLBA: header.firstUsableLBA,
            lastUsableLBA: header.lastUsableLBA
        )
        return (diskGUID: header.diskGUID, partitions: partitions)
    }

    private static func inspectGPTFromPrefixBuffer(
        _ prefixBytes: [UInt8],
        validateStrictly: Bool
    ) throws -> (diskGUID: String, partitions: [GPTPartitionEntrySummary])? {
        guard prefixBytes.count >= 34 * gptSectorSize else { return nil }
        let lba1 = Array(prefixBytes[gptSectorSize..<(2 * gptSectorSize)])
        let sig = String(decoding: lba1[0..<8], as: UTF8.self)
        guard sig == gptHeaderSignatureASCII else { return nil }

        let header = try parseAndValidateGPTHeader(sectorBytes: lba1, expectedMyLBA: 1)
        let arrayByteCount = Int(header.numEntries) * Int(header.entrySize)
        let arrayOffset = Int(header.partitionEntryLBA) * gptSectorSize
        guard arrayOffset + arrayByteCount <= prefixBytes.count else {
            if validateStrictly {
                throw AgentVMError.partitionTableInvalid(detail: "Truncated GPT entry array in prefix.")
            }
            return nil
        }
        let entrySlice = Array(prefixBytes[arrayOffset..<(arrayOffset + arrayByteCount)])
        let crc = BinaryChecksums.crc32(entrySlice[0..<entrySlice.count])
        guard crc == header.entryArrayCRC32 else {
            if validateStrictly {
                throw AgentVMError.partitionTableInvalid(detail: "GPT entry array CRC mismatch.")
            }
            return nil
        }
        let parts = try parseGPTEntries(
            entryArrayBytes: entrySlice,
            numEntries: Int(header.numEntries),
            entrySize: Int(header.entrySize),
            firstUsableLBA: header.firstUsableLBA,
            lastUsableLBA: header.lastUsableLBA
        )
        return (diskGUID: header.diskGUID, partitions: parts)
    }

    // MARK: - Internal QCOW2 Parsing Helpers

    private func parseQCOW2Header(fd: Int32, path: String, fileSize: UInt64) throws -> QCOW2HeaderInfo {
        guard fileSize >= 72 else {
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: EFTYPE,
                detail: "QCOW2 header truncated (\(fileSize) bytes; minimum 72 bytes)."
            )
        }

        let leadCount = Int(min(fileSize, 104))
        var hdrBytes = [UInt8](repeating: 0, count: leadCount)
        try hdrBytes.withUnsafeMutableBytes { buf in
            try APFSCoWDiskEngine.preadExact(fd: fd, path: path, into: buf.baseAddress!, count: leadCount, offset: 0)
        }

        var c = BinaryCursor(bytes: hdrBytes)
        let magic = try c.readUInt32BE()
        guard magic == QCOW2HeaderInfo.wireMagic else {
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: EFTYPE,
                detail: String(format: "Invalid QCOW2 magic 0x%08X (expected 0x514649FB).", magic)
            )
        }

        let version = try c.readUInt32BE()
        guard version == 2 || version == 3 else {
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: ENOTSUP,
                detail: "Unsupported QCOW2 version \(version) (supported: v2 and v3)."
            )
        }

        let backingOffset = try c.readUInt64BE()
        let backingSize = try c.readUInt32BE()
        let clusterBits = try c.readUInt32BE()
        guard (9...21).contains(clusterBits) else {
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: EFTYPE,
                detail: "Invalid QCOW2 cluster_bits \(clusterBits) (valid range 9...21)."
            )
        }

        let virtualSize = try c.readUInt64BE()
        let cryptMethod = try c.readUInt32BE()
        guard cryptMethod == 0 else {
            throw AgentVMError.diskImageOperationFailed(
                path: path,
                errnoCode: ENOTSUP,
                detail: "Encrypted QCOW2 containers (crypt_method=\(cryptMethod)) are not supported."
            )
        }

        let l1Size = try c.readUInt32BE()
        let l1TableOffset = try c.readUInt64BE()
        let refcountTableOffset = try c.readUInt64BE()
        let refcountTableClusters = try c.readUInt32BE()
        _ = try c.readUInt32BE() // nb_snapshots
        _ = try c.readUInt64BE() // snapshots_offset

        var incompatibleFeatures: UInt64 = 0
        var compatibleFeatures: UInt64 = 0
        var autoclearFeatures: UInt64 = 0
        var refcountOrder: UInt32 = 4
        var headerLength: UInt32 = 72

        if version == 3 {
            guard leadCount >= 104 else {
                throw AgentVMError.diskImageOperationFailed(
                    path: path,
                    errnoCode: EFTYPE,
                    detail: "QCOW2 v3 header shorter than required 104 bytes."
                )
            }
            incompatibleFeatures = try c.readUInt64BE()
            compatibleFeatures = try c.readUInt64BE()
            autoclearFeatures = try c.readUInt64BE()
            refcountOrder = try c.readUInt32BE()
            headerLength = try c.readUInt32BE()

            // Incompatible bit 1 = corrupt flag; bit 4 = extended L2 entries.
            if (incompatibleFeatures & (1 << 1)) != 0 {
                throw AgentVMError.diskImageOperationFailed(
                    path: path,
                    errnoCode: EFTYPE,
                    detail: "QCOW2 image has the incompatible CORRUPT bit set."
                )
            }
        }

        var backingPath: String?
        if backingOffset > 0 && backingSize > 0 {
            guard backingSize <= 4096 && backingOffset + UInt64(backingSize) <= fileSize else {
                throw AgentVMError.diskImageOperationFailed(
                    path: path,
                    errnoCode: EFTYPE,
                    detail: "Invalid QCOW2 backing file descriptor (offset=\(backingOffset), size=\(backingSize))."
                )
            }
            var backingBytes = [UInt8](repeating: 0, count: Int(backingSize))
            try backingBytes.withUnsafeMutableBytes { buf in
                try APFSCoWDiskEngine.preadExact(
                    fd: fd,
                    path: path,
                    into: buf.baseAddress!,
                    count: Int(backingSize),
                    offset: backingOffset
                )
            }
            backingPath = String(decoding: backingBytes, as: UTF8.self)
        }

        let clusterSize = UInt32(1 << clusterBits)
        var allocatedDataClusters: UInt64 = 0
        var explicitZeroClusters: UInt64 = 0

        let l1BytesLen = Int(l1Size) * 8
        if l1BytesLen > 0 && l1TableOffset + UInt64(l1BytesLen) <= fileSize {
            var l1Bytes = [UInt8](repeating: 0, count: l1BytesLen)
            try l1Bytes.withUnsafeMutableBytes { buf in
                try APFSCoWDiskEngine.preadExact(fd: fd, path: path, into: buf.baseAddress!, count: l1BytesLen, offset: l1TableOffset)
            }
            let l2Entries = Int(clusterSize) / 8
            var l2Raw = [UInt8](repeating: 0, count: Int(clusterSize))
            var l1Cur = BinaryCursor(bytes: l1Bytes)

            for _ in 0..<Int(l1Size) {
                let l1Entry = try l1Cur.readUInt64BE()
                let l2Off = l1Entry & Self.qcow2StandardOffsetMask
                if l2Off == 0 || l2Off + UInt64(clusterSize) > fileSize { continue }
                try l2Raw.withUnsafeMutableBytes { buf in
                    try APFSCoWDiskEngine.preadExact(fd: fd, path: path, into: buf.baseAddress!, count: Int(clusterSize), offset: l2Off)
                }
                var l2Cur = BinaryCursor(bytes: l2Raw)
                for _ in 0..<l2Entries {
                    let l2Entry = try l2Cur.readUInt64BE()
                    if (l2Entry & Self.qcow2ZeroClusterFlag) != 0 {
                        explicitZeroClusters += 1
                    } else if (l2Entry & Self.qcow2StandardOffsetMask) != 0 || (l2Entry & Self.qcow2CompressedFlag) != 0 {
                        allocatedDataClusters += 1
                    }
                }
            }
        }

        return QCOW2HeaderInfo(
            version: version,
            clusterBits: clusterBits,
            clusterSizeBytes: clusterSize,
            virtualSizeBytes: virtualSize,
            backingFileOffset: backingOffset,
            backingFilePath: backingPath,
            l1Size: l1Size,
            l1TableOffset: l1TableOffset,
            refcountTableOffset: refcountTableOffset,
            refcountTableClusters: refcountTableClusters,
            refcountOrder: refcountOrder,
            headerLength: headerLength,
            incompatibleFeatures: incompatibleFeatures,
            compatibleFeatures: compatibleFeatures,
            autoclearFeatures: autoclearFeatures,
            allocatedDataClusters: allocatedDataClusters,
            explicitZeroClusters: explicitZeroClusters
        )
    }

    /// Reads the leading `byteLength` guest virtual bytes from an uncompressed QCOW2 image so `inspectContainer`
    /// can surface embedded GPT partitions even before conversion.
    private func readQCOW2GuestPrefix(
        fd: Int32,
        path: String,
        fileSize: UInt64,
        header: QCOW2HeaderInfo,
        byteLength: Int
    ) throws -> [UInt8] {
        var result = [UInt8](repeating: 0, count: byteLength)
        guard header.l1Size > 0 else { return result }

        let clusterSize = Int(header.clusterSizeBytes)
        let l2Entries = clusterSize / 8
        let clustersNeeded = (byteLength + clusterSize - 1) / clusterSize

        var l1Bytes = [UInt8](repeating: 0, count: Int(header.l1Size) * 8)
        guard header.l1TableOffset + UInt64(l1Bytes.count) <= fileSize else { return result }
        try l1Bytes.withUnsafeMutableBytes { buf in
            try APFSCoWDiskEngine.preadExact(fd: fd, path: path, into: buf.baseAddress!, count: buf.count, offset: header.l1TableOffset)
        }

        for guestClusterIdx in 0..<clustersNeeded {
            let l1Idx = guestClusterIdx / l2Entries
            let l2Idx = guestClusterIdx % l2Entries
            if l1Idx >= Int(header.l1Size) { break }

            var l1c = BinaryCursor(bytes: l1Bytes, offset: l1Idx * 8)
            let l1Entry = try l1c.readUInt64BE()
            let l2Off = l1Entry & Self.qcow2StandardOffsetMask
            if l2Off == 0 || l2Off + UInt64(clusterSize) > fileSize { continue }

            var l2EntryBytes = [UInt8](repeating: 0, count: 8)
            try l2EntryBytes.withUnsafeMutableBytes { buf in
                try APFSCoWDiskEngine.preadExact(
                    fd: fd,
                    path: path,
                    into: buf.baseAddress!,
                    count: 8,
                    offset: l2Off + UInt64(l2Idx * 8)
                )
            }
            var l2c = BinaryCursor(bytes: l2EntryBytes)
            let l2Entry = try l2c.readUInt64BE()
            if (l2Entry & Self.qcow2CompressedFlag) != 0 || (l2Entry & Self.qcow2ZeroClusterFlag) != 0 {
                continue
            }
            let hostDataOff = l2Entry & Self.qcow2StandardOffsetMask
            if hostDataOff == 0 { continue }

            let dstStart = guestClusterIdx * clusterSize
            let toCopy = min(clusterSize, byteLength - dstStart)
            guard hostDataOff + UInt64(toCopy) <= fileSize else { continue }

            var chunk = [UInt8](repeating: 0, count: toCopy)
            try chunk.withUnsafeMutableBytes { buf in
                try APFSCoWDiskEngine.preadExact(fd: fd, path: path, into: buf.baseAddress!, count: toCopy, offset: hostDataOff)
            }
            result.replaceSubrange(dstStart..<(dstStart + toCopy), with: chunk)
        }

        return result
    }
}
