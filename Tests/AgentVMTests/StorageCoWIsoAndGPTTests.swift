import AgentVMModels
import AgentVMStorageCoW
import AgentVMVsockRPC
import Darwin
import Foundation
import Testing

@Suite("M03 Storage CoW, AVMPATCH, ISO-9660 Rock Ridge, GPT/QCOW2 & Forensics", .timeLimit(.minutes(1)))
struct StorageCoWIsoAndGPTTests {

    private func makeTemporaryDirectory(prefix: String) throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString.lowercased())", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func writeBytes(_ data: Data, to url: URL, at offset: UInt64) throws {
        let fd = Darwin.open(url.path, O_RDWR | O_CLOEXEC)
        #expect(fd >= 0)
        defer { _ = Darwin.close(fd) }
        let written = data.withUnsafeBytes { rawBuf -> Int in
            guard let base = rawBuf.baseAddress else { return 0 }
            return Darwin.pwrite(fd, base, rawBuf.count, off_t(offset))
        }
        #expect(written == data.count)
        _ = Darwin.fsync(fd)
    }

    private func readBytes(from url: URL, at offset: UInt64, count: Int) throws -> Data {
        let fd = Darwin.open(url.path, O_RDONLY | O_CLOEXEC)
        #expect(fd >= 0)
        defer { _ = Darwin.close(fd) }
        var buf = [UInt8](repeating: 0, count: count)
        let readCount = buf.withUnsafeMutableBytes { rawBuf -> Int in
            guard let base = rawBuf.baseAddress else { return -1 }
            return Darwin.pread(fd, base, rawBuf.count, off_t(offset))
        }
        #expect(readCount == count)
        return Data(buf)
    }

    // MARK: - 1. APFS Volume Capabilities, Sparse Disks, clonefile CoW & AVMPATCH

    @Test("APFSCoWDiskEngine probes macOS APFS volume capabilities cleanly without leaving probe files")
    func apfsCapabilityProbeTelemetry() throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-apfs-probe")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let engine = APFSCoWDiskEngine()
        let caps = try engine.probeAPFSCapabilities(at: tempDir)
        #expect(caps.blockSizeBytes >= 4096)
        #expect(caps.totalCapacityBytes > 0)
        #expect(caps.supportsSparseSeekHole == true)
        if caps.isAPFS {
            #expect(caps.supportsClonefileCoW == true)
        }

        let leftoverFiles = try FileManager.default.contentsOfDirectory(atPath: tempDir.path)
        #expect(leftoverFiles.isEmpty)
    }

    @Test("APFSCoWDiskEngine creates purely sparse raw disks with zero physical blocks and guards exclusive creation")
    func sparseDiskCreationAndExclusiveGuard() throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-sparse-create")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let engine = APFSCoWDiskEngine()
        let diskURL = tempDir.appendingPathComponent("sparse-4mb.raw")
        let virtualBytes: UInt64 = 4 * 1024 * 1024

        #expect(throws: AgentVMError.self) {
            try engine.createSparseRawDisk(at: diskURL, virtualSizeBytes: 0)
        }

        try engine.createSparseRawDisk(at: diskURL, virtualSizeBytes: virtualBytes, overwrite: false)

        let summary = try engine.scanSparseExtents(at: diskURL, computeChecksums: true)
        #expect(summary.virtualSizeBytes == virtualBytes)
        #expect(summary.physicalAllocatedBytes == 0)
        #expect(summary.sparseHoleBytes == virtualBytes)
        #expect(summary.extents.count == 1)
        #expect(summary.extents.first?.kind == .sparseHole)

        // Exclusive create without overwrite must fail on existing image
        #expect(throws: AgentVMError.self) {
            try engine.createSparseRawDisk(at: diskURL, virtualSizeBytes: virtualBytes, overwrite: false)
        }

        // Overwrite unlinks and recreates cleanly
        try engine.createSparseRawDisk(at: diskURL, virtualSizeBytes: 2 * 1024 * 1024, overwrite: true)
        let overwrittenSummary = try engine.scanSparseExtents(at: diskURL)
        #expect(overwrittenSummary.virtualSizeBytes == 2 * 1024 * 1024)
    }

    @Test("APFSCoWDiskEngine resizes sparse disks while preserving allocated extents and enforcing allowShrink guard")
    func sparseDiskResizeGrowAndShrinkGuard() throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-sparse-resize")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let engine = APFSCoWDiskEngine()
        let diskURL = tempDir.appendingPathComponent("resizable.raw")
        try engine.createSparseRawDisk(at: diskURL, virtualSizeBytes: 1024 * 1024)

        let marker = Data((0..<4096).map { UInt8(($0 * 37 + 11) & 0xFF) })
        try writeBytes(marker, to: diskURL, at: 65_536)

        try engine.resizeSparseRawDisk(at: diskURL, newSizeBytes: 2 * 1024 * 1024, allowShrink: false)
        let grown = try engine.scanSparseExtents(at: diskURL)
        #expect(grown.virtualSizeBytes == 2 * 1024 * 1024)
        #expect(try readBytes(from: diskURL, at: 65_536, count: 4096) == marker)

        #expect(throws: AgentVMError.self) {
            try engine.resizeSparseRawDisk(at: diskURL, newSizeBytes: 512 * 1024, allowShrink: false)
        }

        try engine.resizeSparseRawDisk(at: diskURL, newSizeBytes: 512 * 1024, allowShrink: true)
        let shrunk = try engine.scanSparseExtents(at: diskURL)
        #expect(shrunk.virtualSizeBytes == 512 * 1024)
        #expect(try readBytes(from: diskURL, at: 65_536, count: 4096) == marker)
    }

    @Test("APFSCoWDiskEngine cloneDiskCoW and scanSparseExtents distinguish sparse holes, shared parent blocks, and dirty child blocks")
    func apfsClonefileCoWAndParentDirtyExtentClassification() throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-cow-extents")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let engine = APFSCoWDiskEngine(comparisonChunkBytes: 65_536, zlibCompressionLevel: 6)
        let parentURL = tempDir.appendingPathComponent("parent-base.raw")
        let childURL = tempDir.appendingPathComponent("child-branch.raw")
        let virtualSize: UInt64 = 1024 * 1024 // 16 x 64 KiB chunks

        try engine.createSparseRawDisk(at: parentURL, virtualSizeBytes: virtualSize)
        let sharedChunkA = Data((0..<65_536).map { UInt8(($0 &* 7 &+ 3) & 0xFF) })
        let parentChunkB = Data((0..<65_536).map { UInt8(($0 &* 13 &+ 9) & 0xFF) })
        try writeBytes(sharedChunkA, to: parentURL, at: 0)           // [0 ..< 64K]: stays untouched in child -> .allocatedClean
        try writeBytes(parentChunkB, to: parentURL, at: 262_144)     // [256K ..< 320K]: mutated in child -> .allocatedDirty
        let parentOriginalSHA = try BinaryChecksums.sha256HexFile(at: parentURL)

        try engine.cloneDiskCoW(from: parentURL, to: childURL, overwrite: false)
        #expect(throws: AgentVMError.self) {
            try engine.cloneDiskCoW(from: parentURL, to: childURL, overwrite: false)
        }

        // Mutate [256K ..< 320K] and allocate fresh dirty block at [512K ..< 576K] in child
        let mutatedChunkB = Data((0..<65_536).map { UInt8(($0 &* 29 &+ 0x55) & 0xFF) })
        let childNewChunkC = Data((0..<65_536).map { UInt8(($0 &* 41 &+ 0xAA) & 0xFF) })
        try writeBytes(mutatedChunkB, to: childURL, at: 262_144)
        try writeBytes(childNewChunkC, to: childURL, at: 524_288)

        // Parent image must remain 100% unmodified (true Copy-on-Write isolation)
        #expect(try BinaryChecksums.sha256HexFile(at: parentURL) == parentOriginalSHA)

        let childScan = try engine.scanSparseExtents(
            at: childURL,
            compareAgainstParent: parentURL,
            computeChecksums: true
        )
        #expect(childScan.virtualSizeBytes == virtualSize)
        #expect(childScan.sharedWithParentBytes == 65_536)
        #expect(childScan.uniqueDirtyBytes == 131_072)
        #expect(childScan.sparseHoleBytes == virtualSize - 196_608)

        let kindsPresent = Set(childScan.extents.map(\.kind))
        #expect(kindsPresent.contains(.allocatedClean))
        #expect(kindsPresent.contains(.allocatedDirty))
        #expect(kindsPresent.contains(.sparseHole))

        let cleanExtent = try #require(childScan.extents.first { $0.kind == .allocatedClean })
        #expect(cleanExtent.offsetBytes == 0)
        #expect(cleanExtent.lengthBytes == 65_536)
        #expect(cleanExtent.checksumCRC32 == BinaryChecksums.crc32(sharedChunkA))
    }

    @Test("APFSCoWDiskEngine punches sparse holes and compacts allocated zero runs back into kernel sparse holes")
    func sparseHolePunchingAndZeroBlockCompaction() throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-punch")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let engine = APFSCoWDiskEngine(comparisonChunkBytes: 65_536, zlibCompressionLevel: 6)
        let diskURL = tempDir.appendingPathComponent("compaction.raw")
        try engine.createSparseRawDisk(at: diskURL, virtualSizeBytes: 512 * 1024)

        // Write 256 KiB of non-zero data followed by 128 KiB of explicit zeros
        let nonZero = Data(repeating: 0x5A, count: 262_144)
        let explicitZeros = Data(repeating: 0x00, count: 131_072)
        try writeBytes(nonZero, to: diskURL, at: 0)
        try writeBytes(explicitZeros, to: diskURL, at: 262_144)

        // Punch a 64 KiB hole in the middle of the non-zero region [64K ..< 128K]
        try engine.punchSparseHole(at: diskURL, offsetBytes: 65_536, lengthBytes: 65_536)
        let punchedSlice = try readBytes(from: diskURL, at: 65_536, count: 65_536)
        #expect(punchedSlice == Data(repeating: 0x00, count: 65_536))
        #expect(try readBytes(from: diskURL, at: 0, count: 4096) == Data(repeating: 0x5A, count: 4096))

        // Compact remaining explicit zero blocks
        _ = try engine.compactZeroBlocksToHoles(at: diskURL)
        let postScan = try engine.scanSparseExtents(at: diskURL)
        #expect(postScan.uniqueDirtyBytes == 196_608) // 256K - 64K punched = 192K non-zero remaining
        #expect(postScan.sparseHoleBytes == 512 * 1024 - 196_608)
    }

    @Test("AVMPATCH binary delta export, inspect, and apply reconstructs target disk with byte-identical SHA-256")
    func avmPatchBinaryDeltaExportInspectAndByteIdenticalApply() throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-patch-ok")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let engine = APFSCoWDiskEngine(comparisonChunkBytes: 65_536, zlibCompressionLevel: 6)
        let baseURL = tempDir.appendingPathComponent("base.raw")
        let targetURL = tempDir.appendingPathComponent("target.raw")
        let appliedURL = tempDir.appendingPathComponent("reconstructed.raw")

        try engine.createSparseRawDisk(at: baseURL, virtualSizeBytes: 1024 * 1024)
        try writeBytes(Data((0..<65_536).map { UInt8(($0 &+ 1) & 0xFF) }), to: baseURL, at: 0)
        try writeBytes(Data(repeating: 0xCC, count: 65_536), to: baseURL, at: 131_072)
        try writeBytes(Data(repeating: 0xDD, count: 65_536), to: baseURL, at: 393_216)

        // Clone base -> target, grow target to 1.5 MiB, overwrite 131_072, zero out 393_216, and append at 1.25 MiB
        try engine.cloneDiskCoW(from: baseURL, to: targetURL)
        try engine.resizeSparseRawDisk(at: targetURL, newSizeBytes: 1536 * 1024)
        try writeBytes(Data((0..<65_536).map { UInt8(($0 &* 19 &+ 7) & 0xFF) }), to: targetURL, at: 131_072)
        try writeBytes(Data(repeating: 0x00, count: 65_536), to: targetURL, at: 393_216)
        try writeBytes(Data("AVMPATCH-TAIL-EXTENT-PAYLOAD".utf8), to: targetURL, at: 1280 * 1024)

        let patchArchive = try engine.exportSparseBinaryPatch(baseURL: baseURL, targetURL: targetURL)
        #expect(String(decoding: patchArchive.prefix(8), as: UTF8.self) == SparseBinaryPatchHeader.wireMagicASCII)

        let header = try engine.inspectSparseBinaryPatch(patchArchive)
        #expect(header.version == SparseBinaryPatchHeader.currentVersion)
        #expect(header.baseVirtualSizeBytes == 1024 * 1024)
        #expect(header.targetVirtualSizeBytes == 1536 * 1024)
        #expect(header.dirtyBlockCount == 3)
        #expect(header.totalCompressedPayloadBytes < header.totalUncompressedDirtyBytes)

        try engine.applySparseBinaryPatch(patchArchive, to: baseURL, outputURL: appliedURL)

        let expectedSHA = try BinaryChecksums.sha256HexFile(at: targetURL)
        let reconstructedSHA = try BinaryChecksums.sha256HexFile(at: appliedURL)
        #expect(reconstructedSHA == expectedSHA)
    }

    @Test("AVMPATCH rejects corrupted CRC32 trailers, truncated buffers, and mismatched base disk sizes")
    func avmPatchRejectsCorruptedTrailerAndTruncatedArchive() throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-patch-bad")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let engine = APFSCoWDiskEngine(comparisonChunkBytes: 65_536, zlibCompressionLevel: 6)
        let baseURL = tempDir.appendingPathComponent("base.raw")
        let targetURL = tempDir.appendingPathComponent("target.raw")
        let wrongBaseURL = tempDir.appendingPathComponent("wrong-base.raw")
        let outURL = tempDir.appendingPathComponent("out.raw")

        try engine.createSparseRawDisk(at: baseURL, virtualSizeBytes: 256 * 1024)
        try engine.cloneDiskCoW(from: baseURL, to: targetURL)
        try writeBytes(Data("delta-block".utf8), to: targetURL, at: 65_536)
        try engine.createSparseRawDisk(at: wrongBaseURL, virtualSizeBytes: 512 * 1024)

        let validPatch = try engine.exportSparseBinaryPatch(baseURL: baseURL, targetURL: targetURL)

        // 1. Truncated archive (< 40 bytes)
        #expect(throws: AgentVMError.self) {
            _ = try engine.inspectSparseBinaryPatch(Data("AVMPATCH".utf8))
        }

        // 2. Flip 1 bit inside compressed payload -> archive CRC32 trailer mismatch
        var corruptedPatch = validPatch
        let midIdx = corruptedPatch.count / 2
        corruptedPatch[midIdx] ^= 0x01
        #expect(throws: AgentVMError.self) {
            _ = try engine.inspectSparseBinaryPatch(corruptedPatch)
        }

        // 3. Applying against wrong-size base image must fail before mutating base
        #expect(throws: AgentVMError.self) {
            try engine.applySparseBinaryPatch(validPatch, to: wrongBaseURL, outputURL: outURL)
        }
    }

    // MARK: - 2. ISO-9660 + Rock Ridge (`cidata`) Cloud-Init Builder & Reader

    @Test("ISO9660CloudInitBuilder synthesizes NoCloud meta-data, user-data, network-config, and vendor-data")
    func iso9660NoCloudFilesSynthesisAndGuestAgentInjection() throws {
        let builder = ISO9660CloudInitBuilder()
        let spec = CloudInitSpec(
            instanceID: "iid-agentvm-iso-01",
            hostname: "sandbox-noble-01",
            defaultUser: "agent",
            sshAuthorizedKeys: ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey agent@host"],
            aptPackages: ["git", "curl", "python3"],
            writeFiles: [
                CloudInitWriteFile(guestPath: "/etc/environment", content: "LANG=C.UTF-8\n")
            ],
            runCommands: ["echo ready > /var/run/agentvm.ready"],
            injectGuestVsockAgent: true
        )

        let entries = builder.renderNoCloudFiles(from: spec, guestAgentScript: "#!/usr/bin/env python3\nprint('ok')\n")
        let paths = entries.map(\.path)
        #expect(paths == ["meta-data", "user-data", "network-config", "vendor-data"])

        let metaText = try #require(entries.first { $0.path == "meta-data" }?.utf8String)
        #expect(metaText.contains("instance-id:"))
        #expect(metaText.contains("iid-agentvm-iso-01"))
        #expect(metaText.contains("sandbox-noble-01"))

        let userText = try #require(entries.first { $0.path == "user-data" }?.utf8String)
        #expect(userText.hasPrefix("#cloud-config"))
        #expect(userText.contains("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey"))
        #expect(userText.contains("/usr/local/bin/agentvm-guest-agent"))

        let netText = try #require(entries.first { $0.path == "network-config" }?.utf8String)
        #expect(netText.contains("version: 2"))
    }

    @Test("ISO9660CloudInitBuilder writes Sector 16 CD001 PVD and round-trips lowercase Rock Ridge filenames deterministically")
    func iso9660Sector16PVDRockRidgeAndLosslessExtraction() throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-iso9660")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let builder = ISO9660CloudInitBuilder()
        let spec = CloudInitSpec(
            instanceID: "iid-rockridge-verify",
            hostname: "rockridge-vm",
            defaultUser: "ubuntu",
            aptPackages: ["jq"]
        )
        var baseFiles = builder.renderNoCloudFiles(from: spec)
        let nestedScript = Data("#!/bin/sh\nexec /usr/local/bin/agentvm-guest-agent --vsock 5050\n".utf8)
        baseFiles.append(ISOFileEntry(
            path: "etc/agentvm/start-agent.sh",
            data: nestedScript,
            posixMode: 0o755
        ))

        let isoDataA = try builder.buildISOImageData(volumeIdentifier: "cidata", files: baseFiles)
        let isoDataB = try builder.buildISOImageData(volumeIdentifier: "cidata", files: baseFiles.reversed())

        // Identical files in reversed caller order must produce bit-for-bit identical SHA-256 ISO images
        #expect(BinaryChecksums.sha256Hex(isoDataA) == BinaryChecksums.sha256Hex(isoDataB))
        #expect(isoDataA.count % ISO9660CloudInitBuilder.sectorSize == 0)

        // Verify Sector 16 (byte offset 32,768) Primary Volume Descriptor: [0x01, 'C', 'D', '0', '0', '1', 0x01]
        let pvdOffset = 16 * ISO9660CloudInitBuilder.sectorSize
        #expect(isoDataA[pvdOffset] == 0x01)
        #expect(String(decoding: isoDataA[(pvdOffset + 1)..<(pvdOffset + 6)], as: UTF8.self) == "CD001")
        #expect(isoDataA[pvdOffset + 6] == 0x01)

        // Verify Sector 17 (byte offset 34,816) Volume Descriptor Set Terminator: [0xFF, 'C', 'D', '0', '0', '1', 0x01]
        let vdstOffset = 17 * ISO9660CloudInitBuilder.sectorSize
        #expect(isoDataA[vdstOffset] == 0xFF)
        #expect(String(decoding: isoDataA[(vdstOffset + 1)..<(vdstOffset + 6)], as: UTF8.self) == "CD001")

        // Inspect & extract lossless Rock Ridge lowercase files
        let inspected = try builder.inspectISOImage(data: isoDataA)
        #expect(inspected.volumeID == "cidata")
        for original in baseFiles {
            #expect(inspected.files[original.path] == original.data)
        }

        // Verify disk write + ISOInspectionReport via buildCloudInitISO & inspectISOImageFile
        let isoFileURL = tempDir.appendingPathComponent("seed-cidata.iso")
        let containerSummary = try builder.buildCloudInitISO(from: spec, outputURL: isoFileURL)
        #expect(containerSummary.format == .iso9660)
        #expect(containerSummary.isoVolumeIdentifier == "cidata")

        let fileReport = try builder.inspectISOImageFile(at: isoFileURL)
        #expect(fileReport.logicalBlockSize == 2048)
        #expect(fileReport.hasRockRidgeSUSP == true)
        #expect(Set(fileReport.entries.map(\.path)) == Set(["meta-data", "user-data", "network-config", "vendor-data"]))
    }

    @Test("ISO9660CloudInitBuilder rejects duplicate paths, parent traversal, and invalid volume identifiers")
    func iso9660ValidationRejectsDuplicatePathsAndOversizedVolumeID() {
        let builder = ISO9660CloudInitBuilder()

        #expect(throws: AgentVMError.self) {
            _ = try builder.buildISOImageData(
                volumeIdentifier: "",
                files: [ISOFileEntry(path: "meta-data", utf8Content: "id: 1\n")]
            )
        }

        #expect(throws: AgentVMError.self) {
            _ = try builder.buildISOImageData(
                volumeIdentifier: String(repeating: "V", count: 40),
                files: [ISOFileEntry(path: "meta-data", utf8Content: "id: 1\n")]
            )
        }

        #expect(throws: AgentVMError.self) {
            _ = try builder.buildISOImageData(
                volumeIdentifier: "cidata",
                files: [
                    ISOFileEntry(path: "meta-data", utf8Content: "a"),
                    ISOFileEntry(path: "/meta-data", utf8Content: "b")
                ]
            )
        }

        #expect(throws: AgentVMError.self) {
            _ = try builder.buildISOImageData(
                volumeIdentifier: "cidata",
                files: [ISOFileEntry(path: "../escape", utf8Content: "nope")]
            )
        }
    }

    // MARK: - 3. Protective MBR, Primary/Backup UEFI GPT & Uncompressed QCOW2 v3

    @Test("PartitionAndContainerInspector round-trips mixed-endian UEFI GUIDs and 36-unit UTF-16LE partition names")
    func uefiMixedEndianGUIDAndUTF16LEPartitionNameRoundTrip() throws {
        let espGUID = GPTWellKnownTypeGUID.efiSystemPartition.rawValue // C12A7328-F81F-11D2-BA4B-00A0C93EC93B
        let encoded = try PartitionAndContainerInspector.encodeMixedEndianGUID(espGUID)
        #expect(encoded.count == 16)
        // First 3 components are little-endian per UEFI Spec Table 5-5, final 8 bytes are big-endian:
        #expect(Array(encoded[0..<4]) == [0x28, 0x73, 0x2A, 0xC1])
        #expect(Array(encoded[4..<6]) == [0x1F, 0xF8])
        #expect(Array(encoded[6..<8]) == [0xD2, 0x11])
        #expect(Array(encoded[8..<10]) == [0xBA, 0x4B])
        #expect(Array(encoded[10..<16]) == [0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B])

        let decoded = PartitionAndContainerInspector.decodeMixedEndianGUID(encoded)
        #expect(decoded == espGUID)

        #expect(throws: AgentVMError.self) {
            _ = try PartitionAndContainerInspector.encodeMixedEndianGUID("not-a-valid-guid")
        }

        let nameUTF16 = PartitionAndContainerInspector.encodeUTF16LEPartitionName("AgentVM-ARM64-Root")
        #expect(nameUTF16.count == 72)
        #expect(PartitionAndContainerInspector.decodeUTF16LEPartitionName(nameUTF16) == "AgentVM-ARM64-Root")
    }

    @Test("PartitionAndContainerInspector writes Protective MBR + Primary & Backup GPT with matching IEEE CRC-32")
    func protectiveMBRAndPrimaryBackupGPTVerification() throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-gpt-valid")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let diskEngine = APFSCoWDiskEngine()
        let inspector = PartitionAndContainerInspector()
        let diskURL = tempDir.appendingPathComponent("gpt-disk.raw")
        try diskEngine.createSparseRawDisk(at: diskURL, virtualSizeBytes: 4 * 1024 * 1024)

        let writtenPartitions = try inspector.writeProtectiveMBRAndGPT(
            to: diskURL,
            partitions: [
                (name: "EFI-System", typeGUID: GPTWellKnownTypeGUID.efiSystemPartition.rawValue, sizeBytes: 256 * 1024),
                (name: "Linux-Swap", typeGUID: GPTWellKnownTypeGUID.linuxSwap.rawValue, sizeBytes: 256 * 1024),
                (name: "AgentVM-Root", typeGUID: GPTWellKnownTypeGUID.linuxRootARM64.rawValue, sizeBytes: 2 * 1024 * 1024)
            ]
        )
        #expect(writtenPartitions.count == 3)

        // Check LBA 0 boot signature (0x55, 0xAA at bytes 510..511) and LBA 1 "EFI PART" signature
        let lba0And1 = try readBytes(from: diskURL, at: 0, count: 1024)
        #expect(lba0And1[510] == 0x55)
        #expect(lba0And1[511] == 0xAA)
        #expect(lba0And1[446 + 4] == 0xEE) // Protective MBR partition type 0xEE
        #expect(String(decoding: lba0And1[512..<520], as: UTF8.self) == "EFI PART")

        let report = try inspector.verifyGPTIntegrity(at: diskURL)
        #expect(report.hasValidProtectiveMBR == true)
        #expect(report.hasMatchingBackupGPT == true)
        #expect(report.primaryHeaderCRC32 != 0)
        #expect(report.backupHeaderCRC32 != 0)
        #expect(report.partitionArrayCRC32 != 0)
        #expect(report.partitions.map(\.name) == ["EFI-System", "Linux-Swap", "AgentVM-Root"])

        let container = try inspector.inspectContainer(at: diskURL)
        #expect(container.format == .rawSparse)
        #expect(container.gptDiskGUID == report.diskGUID)
        #expect(container.partitions.count == 3)
    }

    @Test("PartitionAndContainerInspector.verifyGPTIntegrity rejects corrupted Protective MBR and tampered GPT entries")
    func gptIntegrityDetectsCorruptedPrimaryHeaderAndEntryArray() throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-gpt-tamper")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let diskEngine = APFSCoWDiskEngine()
        let inspector = PartitionAndContainerInspector()
        let goodURL = tempDir.appendingPathComponent("good-gpt.raw")
        let badArrayURL = tempDir.appendingPathComponent("bad-array.raw")
        let badMBRURL = tempDir.appendingPathComponent("bad-mbr.raw")

        try diskEngine.createSparseRawDisk(at: goodURL, virtualSizeBytes: 2 * 1024 * 1024)
        _ = try inspector.writeProtectiveMBRAndGPT(
            to: goodURL,
            partitions: [(name: "RootFS", typeGUID: GPTWellKnownTypeGUID.linuxFilesystem.rawValue, sizeBytes: 1024 * 1024)]
        )

        try diskEngine.cloneDiskCoW(from: goodURL, to: badArrayURL)
        try writeBytes(Data([0xFF]), to: badArrayURL, at: 1024 + 64) // Flip byte in LBA 2 Partition Entry 0
        #expect(throws: AgentVMError.self) {
            _ = try inspector.verifyGPTIntegrity(at: badArrayURL)
        }

        try diskEngine.cloneDiskCoW(from: goodURL, to: badMBRURL)
        try writeBytes(Data([0x00, 0x00]), to: badMBRURL, at: 510) // Erase 0x55AA signature at LBA 0
        #expect(throws: AgentVMError.self) {
            _ = try inspector.verifyGPTIntegrity(at: badMBRURL)
        }
    }

    @Test("PartitionAndContainerInspector writes, inspects, and converts uncompressed QCOW2 v3 with byte-exact SHA-256")
    func uncompressedQCOW2v3WriteInspectAndSparseConvertRoundTrip() throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-qcow2")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let diskEngine = APFSCoWDiskEngine()
        let inspector = PartitionAndContainerInspector()
        let rawSourceURL = tempDir.appendingPathComponent("source.raw")
        let qcow2URL = tempDir.appendingPathComponent("exported.qcow2")
        let rawConvertedURL = tempDir.appendingPathComponent("converted.raw")

        let virtualBytes: UInt64 = 2 * 1024 * 1024 // 32 x 64 KiB clusters
        try diskEngine.createSparseRawDisk(at: rawSourceURL, virtualSizeBytes: virtualBytes)
        _ = try inspector.writeProtectiveMBRAndGPT(
            to: rawSourceURL,
            partitions: [(name: "QCOW2-Root", typeGUID: GPTWellKnownTypeGUID.linuxRootARM64.rawValue, sizeBytes: 1536 * 1024)]
        )
        // Write deterministic payload in middle cluster (offset 640 KiB) leaving other interior clusters sparse
        let clusterPayload = Data((0..<65_536).map { UInt8(($0 &* 31 &+ 17) & 0xFF) })
        try writeBytes(clusterPayload, to: rawSourceURL, at: 10 * 65_536)
        let originalSHA = try BinaryChecksums.sha256HexFile(at: rawSourceURL)

        try inspector.writeUncompressedQCOW2(fromRawURL: rawSourceURL, toQCOW2URL: qcow2URL, clusterBits: 16)

        let qcowHeader = try inspector.inspectQCOW2Header(at: qcow2URL)
        #expect(qcowHeader.version == 3)
        #expect(qcowHeader.clusterBits == 16)
        #expect(qcowHeader.clusterSizeBytes == 65_536)
        #expect(qcowHeader.virtualSizeBytes == virtualBytes)
        // Only Cluster 0 (Primary GPT), Cluster 10 (payload), and Cluster 31 (Backup GPT) should be allocated = 3 data clusters!
        #expect(qcowHeader.allocatedDataClusters == 3)

        // Unified container inspector parses guest GPT partitions directly through QCOW2 L1/L2 translation
        let containerInfo = try inspector.inspectContainer(at: qcow2URL)
        #expect(containerInfo.format == .qcow2)
        #expect(containerInfo.partitions.map(\.name) == ["QCOW2-Root"])

        let convertedAlloc = try inspector.convertUncompressedQCOW2ToRawSparse(
            sourceURL: qcow2URL,
            destinationURL: rawConvertedURL
        )
        #expect(convertedAlloc.virtualSizeBytes == virtualBytes)
        #expect(convertedAlloc.sparseHoleBytes > 1500 * 1024)
        #expect(try BinaryChecksums.sha256HexFile(at: rawConvertedURL) == originalSHA)
    }

    // MARK: - 4. DiskEntropyAndForensicsAnalyzer & SnapshotLineageAndDiffEngine

    @Test("DiskEntropyAndForensicsAnalyzer computes exact Shannon entropy across zero, constant, ASCII, and uniform blocks")
    func entropyProfilerClassifiesZeroConstantTextAndHighEntropyRegimes() {
        let analyzer = DiskEntropyAndForensicsAnalyzer()

        #expect(analyzer.computeShannonEntropy(Data()) == 0.0)
        let zeroSample = analyzer.analyzeBlockSample(data: Data(repeating: 0x00, count: 4096))
        #expect(zeroSample.regime == .sparseOrZero)
        #expect(zeroSample.shannonBitsPerByte == 0.0)

        let constSample = analyzer.analyzeBlockSample(data: Data(repeating: 0xEE, count: 4096))
        #expect(constSample.regime == .constantFill)
        #expect(constSample.shannonBitsPerByte == 0.0)
        #expect(constSample.uniqueByteSymbolCount == 1)

        let lowMetaSample = analyzer.analyzeBlockSample(
            data: Data(String(repeating: "0000 0001 0002 0003\n", count: 200).utf8)
        )
        #expect(lowMetaSample.regime == .lowEntropyMetadata)
        #expect(lowMetaSample.shannonBitsPerByte > 1.0 && lowMetaSample.shannonBitsPerByte < 4.5)
        #expect(lowMetaSample.asciiPrintableFraction > 0.99)

        let yamlSample = analyzer.analyzeBlockSample(
            data: Data(String(repeating: "hostname: agent-vm-01\npackages: [git, curl]\n", count: 120).utf8)
        )
        #expect(yamlSample.regime == .moderateStructuredBinary)
        #expect(yamlSample.shannonBitsPerByte >= 4.5 && yamlSample.shannonBitsPerByte < 7.2)
        #expect(yamlSample.asciiPrintableFraction > 0.99)

        // Perfectly uniform 256-symbol histogram (each byte 0..255 appears 32 times = 8192 bytes) -> H(X) == 8.0 bits/byte
        var uniformBytes = [UInt8]()
        uniformBytes.reserveCapacity(8192)
        for _ in 0..<32 {
            for sym in 0...255 {
                uniformBytes.append(UInt8(sym))
            }
        }
        let highSample = analyzer.analyzeBlockSample(data: Data(uniformBytes))
        #expect(highSample.regime == .highEntropyCompressedOrEncrypted)
        #expect(abs(highSample.shannonBitsPerByte - 8.0) < 0.0001)
        #expect(highSample.uniqueByteSymbolCount == 256)
    }

    @Test("DiskEntropyAndForensicsAnalyzer recognizes ext4 (0xEF53), Linux swap (SWAPSPACE2), XFS, and LUKS signatures")
    func filesystemSuperblockDetectionExt4SwapXFSLUKSAndISO() {
        let analyzer = DiskEntropyAndForensicsAnalyzer()

        // 1. Linux ext4 superblock: s_magic = 0xEF53 LE at 1024 + 0x38, INCOMPAT_EXTENTS (0x40) | INCOMPAT_64BIT (0x80) at 1024 + 0x60, RO_COMPAT_METADATA_CSUM (0x400) at 1024 + 0x64
        var ext4Buf = [UInt8](repeating: 0, count: 4096)
        ext4Buf[1024 + 0x38] = 0x53
        ext4Buf[1024 + 0x39] = 0xEF
        ext4Buf[1024 + 0x5C] = 0x04 // COMPAT_HAS_JOURNAL
        ext4Buf[1024 + 0x60] = 0xC0 // INCOMPAT_EXTENTS | INCOMPAT_64BIT
        let labelBytes = Array("agentvm-root".utf8)
        for (i, b) in labelBytes.enumerated() { ext4Buf[1024 + 0x78 + i] = b }
        let ext4Sig = analyzer.detectFilesystemSignature(in: Data(ext4Buf))
        #expect(ext4Sig?.kind == .ext4)
        #expect(ext4Sig?.volumeLabel == "agentvm-root")

        // 2. Linux Swap v2: "SWAPSPACE2" at 4096 - 10 = 4086
        var swapBuf = [UInt8](repeating: 0, count: 4096)
        swapBuf[1024] = 1 // version 1 header
        for (i, b) in Array("SWAPSPACE2".utf8).enumerated() {
            swapBuf[4086 + i] = b
        }
        let swapSig = analyzer.detectFilesystemSignature(in: Data(swapBuf))
        #expect(swapSig?.kind == .linuxSwap)

        // 3. XFS: "XFSB" at offset 0
        var xfsBuf = [UInt8](repeating: 0, count: 512)
        for (i, b) in Array("XFSB".utf8).enumerated() { xfsBuf[i] = b }
        xfsBuf[4] = 0x00; xfsBuf[5] = 0x00; xfsBuf[6] = 0x10; xfsBuf[7] = 0x00 // 4096 blocksize BE
        #expect(analyzer.detectFilesystemSignature(in: Data(xfsBuf))?.kind == .xfs)

        // 4. LUKS: "LUKS\xba\xbe" at offset 0
        var luksBuf = [UInt8](repeating: 0, count: 256)
        let luksMagic: [UInt8] = [0x4C, 0x55, 0x4B, 0x53, 0xBA, 0xBE, 0x00, 0x02]
        for (i, b) in luksMagic.enumerated() { luksBuf[i] = b }
        #expect(analyzer.detectFilesystemSignature(in: Data(luksBuf))?.kind == .luksEncrypted)
    }

    @Test("DiskEntropyAndForensicsAnalyzer.analyzeDiskImage profiles GPT partitions, superblocks, and entropy heatmaps")
    func endToEndDiskForensicsReportAcrossGPTPartitions() throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-forensics")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let diskEngine = APFSCoWDiskEngine()
        let inspector = PartitionAndContainerInspector()
        let analyzer = DiskEntropyAndForensicsAnalyzer()
        let diskURL = tempDir.appendingPathComponent("forensic-target.raw")

        try diskEngine.createSparseRawDisk(at: diskURL, virtualSizeBytes: 4 * 1024 * 1024)
        let parts = try inspector.writeProtectiveMBRAndGPT(
            to: diskURL,
            partitions: [
                (name: "RootExt4", typeGUID: GPTWellKnownTypeGUID.linuxRootARM64.rawValue, sizeBytes: 1024 * 1024),
                (name: "SwapArea", typeGUID: GPTWellKnownTypeGUID.linuxSwap.rawValue, sizeBytes: 512 * 1024)
            ]
        )

        // Write ext4 superblock into Partition 0 and SWAPSPACE2 into Partition 1 + 64 KiB high-entropy block
        let p0Start = parts[0].firstLBA * 512
        var ext4Super = [UInt8](repeating: 0, count: 256)
        ext4Super[0x38] = 0x53
        ext4Super[0x39] = 0xEF
        ext4Super[0x5C] = 0x04
        ext4Super[0x60] = 0xC0
        try writeBytes(Data(ext4Super), to: diskURL, at: p0Start + 1024)

        let p1Start = parts[1].firstLBA * 512
        try writeBytes(Data("SWAPSPACE2".utf8), to: diskURL, at: p1Start + 4086)

        var encryptedLike = [UInt8](repeating: 0, count: 65_536)
        var x: UInt64 = 0x9E37_79B9_7F4A_7C15
        for i in 0..<encryptedLike.count {
            x ^= x >> 12
            x ^= x << 25
            x ^= x >> 27
            encryptedLike[i] = UInt8(truncatingIfNeeded: x &* 0x2545_F491_4F6C_DD1D)
        }
        try writeBytes(Data(encryptedLike), to: diskURL, at: 3 * 1024 * 1024)

        let report = try analyzer.analyzeDiskImage(at: diskURL, sampleWindowBytes: 65_536, maxHeatmapSamples: 128)
        #expect(report.containerSummary.format == .rawSparse)
        #expect(report.detectedFilesystems.contains { $0.kind == .ext4 && $0.partitionName == "RootExt4" })
        #expect(report.detectedFilesystems.contains { $0.kind == .linuxSwap && $0.partitionName == "SwapArea" })
        #expect(report.highEntropySuspiciousBytes >= 65_536)
        #expect(report.peakBlockEntropyBits > 7.5)
    }

    @Test("SnapshotLineageAndDiffEngine computes binary APFS CoW disk diffs and LCA across live disk clones")
    func storageSnapshotLineageValidationAndRealDiskDiff() throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-storage-dag")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let diskEngine = APFSCoWDiskEngine(comparisonChunkBytes: 65_536)
        let diffEngine = SnapshotLineageAndDiffEngine(diskEngine: diskEngine)

        let rootDisk = tempDir.appendingPathComponent("s0.raw")
        let leftDisk = tempDir.appendingPathComponent("s1-left.raw")
        let rightDisk = tempDir.appendingPathComponent("s2-right.raw")

        try diskEngine.createSparseRawDisk(at: rootDisk, virtualSizeBytes: 512 * 1024)
        try writeBytes(Data(repeating: 0x11, count: 65_536), to: rootDisk, at: 0)
        try diskEngine.cloneDiskCoW(from: rootDisk, to: leftDisk)
        try diskEngine.cloneDiskCoW(from: rootDisk, to: rightDisk)

        // Diverge rightDisk on 2 chunks (128 KiB)
        try writeBytes(Data(repeating: 0x22, count: 65_536), to: rightDisk, at: 65_536)
        try writeBytes(Data(repeating: 0x33, count: 65_536), to: rightDisk, at: 131_072)

        let specLeft = VMSpec(id: VMID("vm-s"), name: "branch-left", compute: CPUAndMemorySpec(vcpuCount: 2, memoryMB: 2048, minBalloonMemoryMB: 512))
        let specRight = VMSpec(id: VMID("vm-s"), name: "branch-right", compute: CPUAndMemorySpec(vcpuCount: 4, memoryMB: 4096, minBalloonMemoryMB: 1024))

        let s0 = SnapshotNode(
            id: SnapshotID("s0"), vmID: VMID("vm-s"), parentSnapshotID: nil, branchName: "main",
            title: "Golden", kind: .baseGoldenImage, diskClonePath: rootDisk.path,
            virtualDiskBytes: 512 * 1024, allocatedDiskBytes: 65_536, dirtyDeltaBytes: 0, specSnapshot: specLeft, isPinned: true
        )
        let sLeft = SnapshotNode(
            id: SnapshotID("s-left"), vmID: VMID("vm-s"), parentSnapshotID: s0.id, branchName: "main",
            title: "Left", kind: .coldDiskOnly, diskClonePath: leftDisk.path,
            virtualDiskBytes: 512 * 1024, allocatedDiskBytes: 65_536, dirtyDeltaBytes: 0, specSnapshot: specLeft
        )
        let sRight = SnapshotNode(
            id: SnapshotID("s-right"), vmID: VMID("vm-s"), parentSnapshotID: s0.id, branchName: "exp",
            title: "Right", kind: .coldDiskOnly, diskClonePath: rightDisk.path,
            virtualDiskBytes: 512 * 1024, allocatedDiskBytes: 196_608, dirtyDeltaBytes: 131_072, specSnapshot: specRight
        )

        let dag = try diffEngine.validateLineageDAG(snapshots: [s0, sLeft, sRight])
        #expect(dag.rootSnapshotIDs == [s0.id])
        #expect(dag.forkPointSnapshotIDs == [s0.id])
        #expect(dag.maxLineageDepth == 2)

        let diff = try diffEngine.diffSnapshots(leftID: sLeft.id, rightID: sRight.id, in: [s0, sLeft, sRight])
        #expect(diff.lowestCommonAncestorID == s0.id)
        #expect(diff.divergentBytes == 131_072)
        #expect(diff.divergentExtents.count == 1) // coalesced [64K ..< 192K]
        #expect(diff.configDiffs.contains { $0.fieldName == "compute.vcpuCount" })
    }

    @Test("SnapshotLineageAndDiffEngine.executeGarbageCollection unlinks pruned disk clones and reparents surviving nodes")
    func storageSnapshotGarbageCollectionUnlinksPrunedClonesAndReparents() throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-storage-gc")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let diskEngine = APFSCoWDiskEngine()
        let diffEngine = SnapshotLineageAndDiffEngine(diskEngine: diskEngine)
        let d0 = tempDir.appendingPathComponent("gc-0.raw")
        let d1 = tempDir.appendingPathComponent("gc-1.raw")
        let d2 = tempDir.appendingPathComponent("gc-2.raw")
        for url in [d0, d1, d2] {
            try diskEngine.createSparseRawDisk(at: url, virtualSizeBytes: 65_536)
        }

        let spec = VMSpec(id: VMID("vm-gc"), name: "gc-vm")
        let baseTime = Date(timeIntervalSince1970: 1_730_000_000)
        let n0 = SnapshotNode(
            id: SnapshotID("gc-0"), vmID: VMID("vm-gc"), parentSnapshotID: nil, branchName: "main",
            title: "Root", kind: .baseGoldenImage, createdAt: baseTime, diskClonePath: d0.path,
            virtualDiskBytes: 65_536, allocatedDiskBytes: 0, dirtyDeltaBytes: 0, specSnapshot: spec,
            isPinned: true
        )
        let n1 = SnapshotNode(
            id: SnapshotID("gc-1"), vmID: VMID("vm-gc"), parentSnapshotID: n0.id, branchName: "main",
            title: "Old Checkpoint", kind: .autoPreCommandCheckpoint, createdAt: baseTime.addingTimeInterval(60), diskClonePath: d1.path,
            virtualDiskBytes: 65_536, allocatedDiskBytes: 65_536, dirtyDeltaBytes: 65_536, specSnapshot: spec,
            isPinned: false
        )
        let n2 = SnapshotNode(
            id: SnapshotID("gc-2"), vmID: VMID("vm-gc"), parentSnapshotID: n1.id, branchName: "main",
            title: "Head", kind: .coldDiskOnly, createdAt: baseTime.addingTimeInterval(120), diskClonePath: d2.path,
            virtualDiskBytes: 65_536, allocatedDiskBytes: 65_536, dirtyDeltaBytes: 65_536, specSnapshot: spec,
            isPinned: false
        )

        let policy = GarbageCollectionPolicy(
            keepMinimumPerBranch: 1,
            maxUnpinnedAgeHours: 1,
            preserveBranchForkPoints: true
        )
        let plan = try diffEngine.planGarbageCollection(
            snapshots: [n0, n1, n2],
            activeHeadIDs: [n2.id],
            policy: policy,
            referenceDate: baseTime.addingTimeInterval(86_400 * 7)
        )
        #expect(plan.candidateSnapshotIDs == [n1.id])
        #expect(plan.reparentings[n2.id] == n0.id)

        let survivors = try diffEngine.executeGarbageCollection(plan: plan, snapshots: [n0, n1, n2])
        #expect(FileManager.default.fileExists(atPath: d1.path) == false)
        #expect(FileManager.default.fileExists(atPath: d0.path) == true)
        #expect(FileManager.default.fileExists(atPath: d2.path) == true)
        #expect(survivors.first { $0.id == n2.id }?.parentSnapshotID == n0.id)
    }

    @Test("Default CloudInitSpec and ISO9660CloudInitBuilder enforce lock_passwd: true, no passwd/SSH keys, DHCPv4 without 10.211.55, and single port-1025 daemon")
    func cloudInitDefaultsDHCPNoPasswordAndSinglePort1025Daemon() throws {
        let builder = ISO9660CloudInitBuilder()
        let bootstrap = GuestAgentBootstrapGenerator()
        let defaultSpec = CloudInitSpec(instanceID: "iid-m1-defaults", hostname: "m1-node")
        let enriched = bootstrap.applying(to: defaultSpec)
        let entries = builder.renderNoCloudFiles(from: enriched)

        let userText = try #require(entries.first { $0.path == "user-data" }?.utf8String)
        let trimmedUserLines = userText
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespaces) }
        #expect(trimmedUserLines.contains("lock_passwd: true"))
        #expect(!trimmedUserLines.contains { $0.hasPrefix("passwd:") })
        #expect(!userText.contains("ssh_authorized_keys"))
        #expect(userText.contains("/usr/local/sbin/agentvm-guestd.py"))
        #expect(userText.contains("agentvm-guestd.service"))
        #expect(userText.contains("--port 1025"))
        #expect(!userText.contains("/usr/local/bin/agentvm-guest-agent"))
        #expect(!userText.contains("agentvm-guest-agent.service"))
        #expect(!userText.contains("7100"))

        let netText = try #require(entries.first { $0.path == "network-config" }?.utf8String)
        #expect(netText.contains("dhcp4: true"))
        #expect(!netText.contains("10.211.55"))
    }

    @Test("Repository Sources contain only a single guest vsock daemon script and its port is 1025")
    func repositoryHasOnlyOneGuestDaemonScriptOnPort1025() throws {
        let testFileURL = URL(fileURLWithPath: #filePath)
        let repoRootURL = testFileURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourcesURL = repoRootURL.appendingPathComponent("Sources", isDirectory: true)

        let enumerator = try #require(FileManager.default.enumerator(
            at: sourcesURL,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        ))

        var filesWithGuestVsockDaemon: [String] = []
        var filesWithPort7100: [String] = []

        for case let fileURL as URL in enumerator where fileURL.pathExtension == "swift" {
            let content = try String(contentsOf: fileURL, encoding: .utf8)
            let relPath = fileURL.path.replacingOccurrences(of: repoRootURL.path + "/", with: "")
            if content.contains("AF_VSOCK") && content.contains("#!/usr/bin/env python3") {
                filesWithGuestVsockDaemon.append(relPath)
            }
            if content.contains("7100") || content.contains("defaultGuestVsockAgentPythonScript") {
                filesWithPort7100.append(relPath)
            }
        }

        #expect(filesWithGuestVsockDaemon == ["Sources/AgentVMVsockRPC/GuestAgentBootstrapGenerator.swift"])
        #expect(filesWithPort7100.isEmpty)
        #expect(GuestAgentBootstrapGenerator.defaultVsockPort == 1025)
    }

    @Test("APFSCoWDiskEngine.cloneDiskCoWReportingStrategy reports apfsClonefile vs EXDEV fullCopyFallback without mutating read-only source")
    func cloneDiskCoWReportingStrategyAndReadOnlySourceImmutability() throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-clone-strategy")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let srcURL = tempDir.appendingPathComponent("cached-readonly.raw")
        let sizeBytes = 4 * 1024 * 1024
        var srcBytes = Data(repeating: 0, count: sizeBytes)
        srcBytes.replaceSubrange(0..<4096, with: Data((0..<4096).map { UInt8(($0 * 13 + 5) & 0xFF) }))
        srcBytes.replaceSubrange((sizeBytes - 4096)..<sizeBytes, with: Data((0..<4096).map { UInt8(($0 * 29 + 11) & 0xFF) }))
        try srcBytes.write(to: srcURL)
        #expect(Darwin.chmod(srcURL.path, 0o444) == 0)

        var srcStatBefore = Darwin.stat()
        #expect(stat(srcURL.path, &srcStatBefore) == 0)
        let shaBefore = BinaryChecksums.sha256Hex(srcBytes)

        // 1. Same-volume APFS clone
        let cowDstURL = tempDir.appendingPathComponent("vm-cow.raw")
        let defaultEngine = APFSCoWDiskEngine()
        let cowStrategy = try defaultEngine.cloneDiskCoWReportingStrategy(from: srcURL, to: cowDstURL, overwrite: true)
        #expect(cowStrategy == .apfsClonefile)
        #expect(try Data(contentsOf: cowDstURL) == srcBytes)

        // 2. Cross-volume EXDEV fallback to full copy
        let copyDstURL = tempDir.appendingPathComponent("vm-copy-fallback.raw")
        let fallbackEngine = APFSCoWDiskEngine(forceCopyFallbackErrnoForTesting: EXDEV)
        let copyStrategy = try fallbackEngine.cloneDiskCoWReportingStrategy(from: srcURL, to: copyDstURL, overwrite: true)
        #expect(copyStrategy == .fullCopyFallback)
        #expect(try Data(contentsOf: copyDstURL) == srcBytes)

        // Mutating destination must never mutate read-only source
        #expect(Darwin.chmod(cowDstURL.path, 0o644) == 0)
        try writeBytes(Data(repeating: 0xEE, count: 4096), to: cowDstURL, at: 0)
        try writeBytes(Data(repeating: 0xDD, count: 4096), to: copyDstURL, at: 0)

        var srcStatAfter = Darwin.stat()
        #expect(stat(srcURL.path, &srcStatAfter) == 0)
        #expect((srcStatAfter.st_mode & 0o777) == 0o444)
        #expect(srcStatAfter.st_size == srcStatBefore.st_size)
        #expect(srcStatAfter.st_mtimespec.tv_sec == srcStatBefore.st_mtimespec.tv_sec)
        #expect(srcStatAfter.st_mtimespec.tv_nsec == srcStatBefore.st_mtimespec.tv_nsec)
        #expect(BinaryChecksums.sha256Hex(try Data(contentsOf: srcURL)) == shaBefore)

        _ = Darwin.chmod(srcURL.path, 0o644)
    }

    @Test("Generated cloud-init excludes package_update, packages, and wheel, and configures user-space /dev/hvc0 output without touching GRUB")
    func cloudInitGeneratedConfigExcludesPackagesAndWheelAndConfiguresHvc0WithoutGrub() throws {
        let builder = ISO9660CloudInitBuilder()
        let bootstrap = GuestAgentBootstrapGenerator()
        let spec = CloudInitSpec(
            instanceID: "iid-m1-hvc0",
            hostname: "t1",
            defaultUser: "agent",
            aptPackages: ["python3", "curl"],
            injectGuestVsockAgent: true
        )
        let enriched = bootstrap.applying(to: spec)
        let entries = builder.renderNoCloudFiles(from: enriched)

        let userText = try #require(entries.first { $0.path == "user-data" }?.utf8String)
        let vendorText = try #require(entries.first { $0.path == "vendor-data" }?.utf8String)

        // Must never emit package installation directives or Debian-nonexistent 'wheel' group
        #expect(!userText.contains("package_update"))
        #expect(!userText.contains("package_upgrade"))
        #expect(!userText.contains("\npackages:"))
        #expect(!userText.contains("wheel"))
        #expect(userText.contains("groups: [sudo, adm, systemd-journal]"))

        // Must configure user-space /dev/hvc0 output (kernel module, dmesg pre-start, serial-getty)
        #expect(userText.contains("virtio_console"))
        #expect(userText.contains("/dev/hvc0"))
        #expect(userText.contains("dmesg > /dev/hvc0"))
        #expect(userText.contains("serial-getty@hvc0.service"))

        // Must never modify GRUB console parameters (which hangs next boot when virtio_console=m)
        #expect(!userText.contains("GRUB_CMDLINE"))
        #expect(!userText.contains("update-grub"))
        #expect(!userText.contains("console=hvc0"))
        #expect(!vendorText.contains("console=hvc0"))
    }
}
