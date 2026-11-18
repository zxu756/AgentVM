import AgentVMCLIAndMCP
import AgentVMHypervisor
import AgentVMModels
import AgentVMStorageCoW
import AgentVMStore
import Darwin
import Foundation
import Testing

@_silgen_name("clonefile")
private func m3_test_clonefile(
    _ src: UnsafePointer<CChar>,
    _ dst: UnsafePointer<CChar>,
    _ flags: UInt32
) -> Int32

private final class M3ScanHookTracker: @unchecked Sendable {
    private let lock = NSLock()
    private var extentScanCalls: [(target: String, parent: String?)] = []
    private var contentReadPaths: [String] = []

    func recordExtentScan(target: URL, parent: URL?) {
        lock.lock()
        extentScanCalls.append((target.path, parent?.path))
        lock.unlock()
    }

    func recordContentRead(path: String) {
        lock.lock()
        contentReadPaths.append(path)
        lock.unlock()
    }

    func reset() {
        lock.lock()
        extentScanCalls.removeAll()
        contentReadPaths.removeAll()
        lock.unlock()
    }

    func snapshot() -> (extentScanCount: Int, contentReadCount: Int) {
        lock.lock()
        defer { lock.unlock() }
        return (extentScanCalls.count, contentReadPaths.count)
    }
}

@Suite("M3 Stage 1: APFS Private Bytes, Extent-Scan Removal & Legacy Compatibility", .timeLimit(.minutes(2)))
struct M3Stage1PrivateBytesTests {

    private func makeTempDirectory(prefix: String = "avm-m3-stage1") throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func darwinGetattrlistPrivateBytes(at url: URL) throws -> UInt64 {
        var alist = attrlist()
        alist.bitmapcount = UInt16(ATTR_BIT_MAP_COUNT)
        alist.forkattr = attrgroup_t(ATTR_CMNEXT_PRIVATESIZE)

        var rawBuf = [UInt8](repeating: 0, count: 16)
        let rc = url.path.withCString { cPath in
            rawBuf.withUnsafeMutableBytes { ptr -> Int32 in
                guard let base = ptr.baseAddress else { return -1 }
                return Darwin.getattrlist(
                    cPath,
                    &alist,
                    base,
                    12,
                    UInt32(FSOPT_ATTR_CMN_EXTENDED)
                )
            }
        }
        guard rc == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(Darwin.errno))
        }
        let returnedLength = rawBuf.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 0, as: UInt32.self) }
        #expect(returnedLength >= 12)
        let privSigned = rawBuf.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 4, as: Int64.self) }
        return UInt64(max(0, privSigned))
    }

    private func darwinStatAllocatedBytes(at url: URL) throws -> UInt64 {
        var st = Darwin.stat()
        guard stat(url.path, &st) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(Darwin.errno))
        }
        return UInt64(max(0, st.st_blocks)) * 512
    }

    private func makePatternData(count: Int, mul: Int, add: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        for i in 0..<count {
            bytes[i] = UInt8((i * mul + add) & 0xFF)
        }
        return Data(bytes)
    }

    @Test("APFS private bytes read via product matches Darwin getattrlist(ATTR_CMNEXT_PRIVATESIZE): 0 after clonefile, block size after write")
    func apfsPrivateBytesMatchesDarwinGetattrlistOnCloneAndWrite() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-m3-privbytes")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let engine = APFSCoWDiskEngine()
        let caps = try engine.probeAPFSCapabilities(at: tempDir)
        #expect(caps.supportsClonefileCoW == true)

        // 1. Direct file + clonefile + write 1 block test
        let srcURL = tempDir.appendingPathComponent("origin.raw")
        let cloneURL = tempDir.appendingPathComponent("clone.raw")
        let initialSize = 256 * 1024
        let nonZeroPattern = makePatternData(count: initialSize, mul: 31, add: 7)
        try nonZeroPattern.write(to: srcURL)

        let srcPrivInitial = try darwinGetattrlistPrivateBytes(at: srcURL)
        #expect(srcPrivInitial == UInt64(initialSize))
        let srcMetricsInitial = try engine.readFileSpaceMetrics(at: srcURL)
        #expect(srcMetricsInitial.privateBytes == srcPrivInitial)
        #expect(srcMetricsInitial.allocatedDiskBytes == (try darwinStatAllocatedBytes(at: srcURL)))

        let cloneRC = srcURL.path.withCString { sPtr in
            cloneURL.path.withCString { dPtr in
                m3_test_clonefile(sPtr, dPtr, 0)
            }
        }
        #expect(cloneRC == 0)

        // Immediately after clonefile(2), all extents are shared: private bytes MUST be 0 on both files.
        let expectedClonePrivZero = try darwinGetattrlistPrivateBytes(at: cloneURL)
        let expectedSrcPrivZero = try darwinGetattrlistPrivateBytes(at: srcURL)
        #expect(expectedClonePrivZero == 0)
        #expect(expectedSrcPrivZero == 0)

        let cloneMetricsBeforeWrite = try engine.readFileSpaceMetrics(at: cloneURL)
        let srcMetricsBeforeWrite = try engine.readFileSpaceMetrics(at: srcURL)
        #expect(cloneMetricsBeforeWrite.privateBytes == 0)
        #expect(cloneMetricsBeforeWrite.privateBytes == expectedClonePrivZero)
        #expect(srcMetricsBeforeWrite.privateBytes == expectedSrcPrivZero)
        #expect(cloneMetricsBeforeWrite.allocatedDiskBytes == (try darwinStatAllocatedBytes(at: cloneURL)))

        // Overwrite one 64 KiB block in cloneURL at offset 64 KiB
        let dirtyBlock = Data(repeating: 0xA5, count: 65_536)
        let fd = Darwin.open(cloneURL.path, O_RDWR | O_CLOEXEC)
        #expect(fd >= 0)
        dirtyBlock.withUnsafeBytes { rawPtr in
            if let base = rawPtr.baseAddress {
                let written = Darwin.pwrite(fd, base, dirtyBlock.count, off_t(65_536))
                #expect(written == dirtyBlock.count)
            }
        }
        _ = Darwin.fsync(fd)
        _ = Darwin.close(fd)

        let expectedClonePrivAfterWrite = try darwinGetattrlistPrivateBytes(at: cloneURL)
        let expectedAllocAfterWrite = try darwinStatAllocatedBytes(at: cloneURL)
        #expect(expectedClonePrivAfterWrite > 0)

        let cloneMetricsAfterWrite = try engine.readFileSpaceMetrics(at: cloneURL)
        #expect(cloneMetricsAfterWrite.privateBytes == expectedClonePrivAfterWrite)
        #expect(cloneMetricsAfterWrite.allocatedDiskBytes == expectedAllocAfterWrite)

        // 2. End-to-end CLI ps --json refreshes live APFS private bytes from root disk without snapshot
        let mockHome = tempDir.appendingPathComponent("home", isDirectory: true)
        let cacheDir = tempDir.appendingPathComponent("cache", isDirectory: true)
        let bundleURL = tempDir.appendingPathComponent("PrivFleet.agentvm", isDirectory: true)
        let env = ["HOME": mockHome.path, "AGENTVM_IMAGE_CACHE": cacheDir.path]

        let imageID = "debian-12-bookworm-arm64"
        let imgPayload = makePatternData(count: 1024 * 1024, mul: 13, add: 3)
        let entry = BaseImageCatalogEntry(
            id: imageID,
            displayName: "Debian 12 Test",
            distribution: "debian",
            version: "12",
            guestOS: .linuxARM64,
            isSupported: true,
            downloadURL: "https://offline.agentvm.invalid/deb.raw",
            expectedSHA512: BinaryChecksums.sha512Hex(imgPayload),
            expectedSizeBytes: UInt64(imgPayload.count),
            defaultVirtualSizeBytes: UInt64(imgPayload.count)
        )
        let stageURL = tempDir.appendingPathComponent("stage.raw")
        try imgPayload.write(to: stageURL)
        let catalog = try BaseImageRegistryCatalog(cacheDirectoryURL: cacheDir, curatedEntries: [entry], createIfMissing: true)
        let staged = try await catalog.stageCachedCuratedImage(id: imageID, from: stageURL, verifyChecksum: true)
        try? FileManager.default.removeItem(at: stageURL)
        if let p = staged.cachedLocalPath { _ = Darwin.chmod(p, 0o444) }

        let cli = AgentVMCLIRunner()
        let createOut = await cli.execute(
            arguments: ["--lang", "en", "create", "p", "--image", imageID],
            bundleURLOverride: bundleURL,
            curatedEntriesOverride: [entry],
            environment: env
        )
        #expect(createOut.exitCode == 0, "stderr: \(createOut.stderr)")

        let psZero = await cli.execute(
            arguments: ["--lang", "en", "ps", "--json"],
            bundleURLOverride: bundleURL,
            curatedEntriesOverride: [entry],
            environment: env
        )
        #expect(psZero.exitCode == 0)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let vmsBefore = try decoder.decode([VMInstanceRecord].self, from: Data(psZero.stdout.utf8))
        let pBefore = try #require(vmsBefore.first(where: { $0.spec.name == "p" }))
        let pDiskURL = URL(fileURLWithPath: try #require(pBefore.spec.blockDevices.first?.imagePath))
        #expect(pBefore.telemetry.apfsPrivateBytes == 0)
        #expect(pBefore.telemetry.apfsPrivateBytes == (try darwinGetattrlistPrivateBytes(at: pDiskURL)))

        // Mutate 64 KiB on p's root disk and verify `ps --json` reports the live private bytes immediately
        let pFD = Darwin.open(pDiskURL.path, O_RDWR | O_CLOEXEC)
        #expect(pFD >= 0)
        dirtyBlock.withUnsafeBytes { rawPtr in
            if let base = rawPtr.baseAddress {
                _ = Darwin.pwrite(pFD, base, dirtyBlock.count, 0)
            }
        }
        _ = Darwin.fsync(pFD)
        _ = Darwin.close(pFD)

        let psAfter = await cli.execute(
            arguments: ["--lang", "en", "ps", "--json"],
            bundleURLOverride: bundleURL,
            curatedEntriesOverride: [entry],
            environment: env
        )
        #expect(psAfter.exitCode == 0)
        let vmsAfter = try decoder.decode([VMInstanceRecord].self, from: Data(psAfter.stdout.utf8))
        let pAfter = try #require(vmsAfter.first(where: { $0.spec.name == "p" }))
        let expectedLivePriv = try darwinGetattrlistPrivateBytes(at: pDiskURL)
        #expect(expectedLivePriv > 0)
        #expect(pAfter.telemetry.apfsPrivateBytes == expectedLivePriv)
    }

    @Test("create, create --image, snapshot, and branch never invoke scanSparseExtents or read disk contents")
    func createSnapshotAndBranchNeverInvokeExtentScanOrReadDiskContents() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-m3-noscan")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let tracker = M3ScanHookTracker()
        let hookedEngine = APFSCoWDiskEngine(
            forceCopyFallbackErrnoForTesting: nil,
            onExtentScanForTesting: { target, parent in
                tracker.recordExtentScan(target: target, parent: parent)
            },
            onDiskContentReadForTesting: { path in
                tracker.recordContentRead(path: path)
            }
        )

        // Positive control: scanSparseExtents remains functional for tests / diff and triggers both hooks
        let controlURL = tempDir.appendingPathComponent("control.raw")
        try Data(repeating: 0x42, count: 131_072).write(to: controlURL)
        let controlSummary = try hookedEngine.scanSparseExtents(at: controlURL)
        #expect(controlSummary.uniqueDirtyBytes == 131_072)
        let controlCounts = tracker.snapshot()
        #expect(controlCounts.extentScanCount == 1)
        #expect(controlCounts.contentReadCount >= 1)
        tracker.reset()

        // Stage a 4 MiB non-zero base image in local cache
        let cacheDir = tempDir.appendingPathComponent("cache", isDirectory: true)
        let imageID = "debian-12-bookworm-arm64"
        let imageBytes = makePatternData(count: 4 * 1024 * 1024, mul: 19, add: 11)
        let entry = BaseImageCatalogEntry(
            id: imageID,
            displayName: "Debian 12 NoScan Test",
            distribution: "debian",
            version: "12",
            guestOS: .linuxARM64,
            isSupported: true,
            downloadURL: "https://offline.agentvm.invalid/noscan.raw",
            expectedSHA512: BinaryChecksums.sha512Hex(imageBytes),
            expectedSizeBytes: UInt64(imageBytes.count),
            defaultVirtualSizeBytes: UInt64(imageBytes.count)
        )
        let stagingURL = tempDir.appendingPathComponent("staging.raw")
        try imageBytes.write(to: stagingURL)
        let catalog = try BaseImageRegistryCatalog(cacheDirectoryURL: cacheDir, curatedEntries: [entry], createIfMissing: true)
        let staged = try await catalog.stageCachedCuratedImage(id: imageID, from: stagingURL, verifyChecksum: true)
        try? FileManager.default.removeItem(at: stagingURL)
        if let p = staged.cachedLocalPath { _ = Darwin.chmod(p, 0o444) }

        let bundleURL = tempDir.appendingPathComponent("NoScan.agentvm", isDirectory: true)
        let coordinator = try AgentVMFleetCoordinator(
            bundleURL: bundleURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            diskEngine: hookedEngine
        )

        // 1. Plain createSandboxVM
        let plainCreated = try await coordinator.createSandboxVM(
            name: "plain-box",
            diskVirtualBytes: 16 * 1024 * 1024
        )
        #expect(tracker.snapshot().extentScanCount == 0)
        #expect(tracker.snapshot().contentReadCount == 0)

        // 2. createVMFromImage
        let imageCreated = try await coordinator.createVMFromImage(
            name: "image-box",
            imageID: imageID
        )
        #expect(tracker.snapshot().extentScanCount == 0)
        #expect(tracker.snapshot().contentReadCount == 0)

        // Mutate 64 KiB on image-box's disk so it has real dirty blocks before snapshot & branch
        let diskPath = try #require(imageCreated.vmRecord.spec.blockDevices.first?.imagePath)
        let fd = Darwin.open(diskPath, O_RDWR | O_CLOEXEC)
        #expect(fd >= 0)
        let block = Data(repeating: 0xCC, count: 65_536)
        block.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress {
                _ = Darwin.pwrite(fd, base, block.count, off_t(131_072))
            }
        }
        _ = Darwin.fsync(fd)
        _ = Darwin.close(fd)

        // 3. captureSnapshot
        _ = try await coordinator.captureSnapshot(
            vmID: imageCreated.vmRecord.id,
            title: "Checkpoint Without Scan"
        )
        #expect(tracker.snapshot().extentScanCount == 0)
        #expect(tracker.snapshot().contentReadCount == 0)

        // 4. forkCoWBranch (both image-backed and empty-disk)
        _ = try await coordinator.forkCoWBranch(
            fromVMID: imageCreated.vmRecord.id,
            branchName: "image-child",
            agentOwnerTag: "worker-1",
            bootImmediately: false
        )
        _ = try await coordinator.forkCoWBranch(
            fromVMID: plainCreated.vmRecord.id,
            branchName: "plain-child",
            agentOwnerTag: "worker-2",
            bootImmediately: false
        )
        #expect(tracker.snapshot().extentScanCount == 0)
        #expect(tracker.snapshot().contentReadCount == 0)
    }

    @Test("Legacy JSON payloads and pre-M3 SQLite workspaces lacking apfsPrivateBytes / allocatedDiskBytes decode cleanly")
    func legacyWorkspaceAndJSONWithoutNewFieldsDecodeCleanly() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-m3-legacy")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        // 1. Legacy VMLiveTelemetry JSON (has cowDirtyBytes, lacks apfsPrivateBytes and allocatedDiskBytes)
        let legacyTelemetryJSON = """
        {
          "activeTCPFlows": 0,
          "balloonReclaimedMB": 0,
          "cowDirtyBytes": 131072,
          "diskReadBytesTotal": 0,
          "diskWriteBytesTotal": 0,
          "firewallDroppedPackets": 0,
          "guestAgentConnected": false,
          "memoryResidentMB": 0,
          "netRxBytesTotal": 0,
          "netRxPackets": 0,
          "netTxBytesTotal": 0,
          "netTxPackets": 0,
          "sampledAt": "2026-11-18T00:00:00Z",
          "state": "stopped",
          "uptimeSeconds": 0,
          "vmID": "vm-legacy-01",
          "vsockStreamsOpen": 0
        }
        """
        let decodedTelemetry = try decoder.decode(VMLiveTelemetry.self, from: Data(legacyTelemetryJSON.utf8))
        #expect(decodedTelemetry.vmID == VMID("vm-legacy-01"))
        #expect(decodedTelemetry.apfsPrivateBytes == 131_072)
        #expect(decodedTelemetry.cowDirtyBytes == 131_072)
        #expect(decodedTelemetry.allocatedDiskBytes == 0)

        // 2. Legacy SnapshotNode JSON (has dirtyDeltaBytes, lacks apfsPrivateBytes)
        let dummySpec = VMSpec(
            id: VMID("vm-legacy-01"),
            name: "legacy-vm",
            bootLoader: .efiBoot(variableStorePath: "/tmp/legacy.nvram", createVariableStoreIfMissing: true)
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let specJSONString = String(decoding: try encoder.encode(dummySpec), as: UTF8.self)
        let legacySnapshotJSON = """
        {
          "agentActor": "coordinator",
          "allocatedDiskBytes": 524288,
          "branchName": "main",
          "createdAt": "2026-11-18T00:00:00Z",
          "dirtyDeltaBytes": 65536,
          "diskClonePath": "/tmp/nonexistent-legacy-snap.raw",
          "id": "snap-legacy-01",
          "isPinned": true,
          "kind": "cold-disk",
          "memoryStateBytes": 0,
          "notes": "legacy",
          "specSnapshot": \(specJSONString),
          "tags": ["legacy"],
          "title": "Legacy Checkpoint",
          "virtualDiskBytes": 16777216,
          "vmID": "vm-legacy-01"
        }
        """
        let decodedSnap = try decoder.decode(SnapshotNode.self, from: Data(legacySnapshotJSON.utf8))
        #expect(decodedSnap.id == SnapshotID("snap-legacy-01"))
        #expect(decodedSnap.apfsPrivateBytes == 65_536)
        #expect(decodedSnap.dirtyDeltaBytes == 65_536)
        #expect(decodedSnap.allocatedDiskBytes == 524_288)

        // 3. Legacy .agentvm SQLite bundle whose telemetry_json & snapshots row contain only pre-M3 fields
        let bundleURL = tempDir.appendingPathComponent("LegacyFleet.agentvm", isDirectory: true)
        do {
            let store = try AgentVMProjectStore(bundleURL: bundleURL, createIfMissing: true)
            let syntheticDiskPath = bundleURL.appendingPathComponent("disks/missing-legacy.raw").path
            var spec = dummySpec
            spec.blockDevices = [
                BlockDeviceSpec(label: "root", imagePath: syntheticDiskPath, virtualSizeBytes: 16_777_216)
            ]
            let record = VMInstanceRecord(
                spec: spec,
                currentHeadSnapshotID: SnapshotID("snap-legacy-01"),
                telemetry: VMLiveTelemetry(vmID: spec.id, state: .stopped, cowDirtyBytes: 262_144)
            )
            try await store.upsertVM(record)
            try await store.upsertSnapshot(decodedSnap)
        }

        // Overwrite telemetry_json in SQLite with strict pre-M3 SQLite JSON (numeric Date, cowDirtyBytes only,
        // no apfsPrivateBytes / allocatedDiskBytes) and set apfs_private_bytes to NULL so decoding falls back to dirty_delta_bytes.
        do {
            let rawDB = try SQLiteWALDatabase(
                fileURL: bundleURL.appendingPathComponent("state.sqlite"),
                runMigrations: false
            )
            let existingRow = try #require(try rawDB.queryOne(
                "SELECT telemetry_json FROM vms WHERE id = ?;",
                bindings: ["vm-legacy-01".sqliteValue]
            ))
            let currentJSON = try existingRow.string("telemetry_json")
            var obj = try #require(try JSONSerialization.jsonObject(with: Data(currentJSON.utf8)) as? [String: Any])
            obj.removeValue(forKey: "apfsPrivateBytes")
            obj.removeValue(forKey: "allocatedDiskBytes")
            obj["cowDirtyBytes"] = 131_072
            let strippedData = try JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])
            let strippedJSON = String(decoding: strippedData, as: UTF8.self)
            #expect(!strippedJSON.contains("apfsPrivateBytes"))
            #expect(!strippedJSON.contains("allocatedDiskBytes"))

            try rawDB.execute(
                "UPDATE vms SET telemetry_json = ? WHERE id = ?;",
                bindings: [strippedJSON.sqliteValue, "vm-legacy-01".sqliteValue]
            )
            let cols = try rawDB.query("PRAGMA table_info(snapshots);")
            let colNames = Set(try cols.map { try $0.string("name").lowercased() })
            if colNames.contains("apfs_private_bytes") {
                try rawDB.execute("UPDATE snapshots SET apfs_private_bytes = NULL WHERE id = 'snap-legacy-01';")
            }
        }

        let reopenedStore = try AgentVMProjectStore(bundleURL: bundleURL, createIfMissing: false)
        let fetchedVM = try #require(try await reopenedStore.fetchVM(VMID("vm-legacy-01")))
        #expect(fetchedVM.telemetry.apfsPrivateBytes == 131_072)
        let fetchedSnap = try #require(try await reopenedStore.fetchSnapshot(SnapshotID("snap-legacy-01")))
        #expect(fetchedSnap.apfsPrivateBytes == 65_536)

        let cli = AgentVMCLIRunner()
        let env = ["HOME": tempDir.appendingPathComponent("home").path]
        let psOut = await cli.execute(arguments: ["--lang", "en", "ps", "--json"], bundleURLOverride: bundleURL, environment: env)
        #expect(psOut.exitCode == 0, "stderr: \(psOut.stderr)")
        let snapListOut = await cli.execute(arguments: ["--lang", "en", "snapshot", "list"], bundleURLOverride: bundleURL, environment: env)
        #expect(snapListOut.exitCode == 0, "stderr: \(snapListOut.stderr)")
        #expect(snapListOut.stdout.contains("snap-legacy-01"))
    }

    @Test("CLI ps / snapshot list columns clarify non-shared bytes, diagnostics avoid hardcoded 0 B, and ENOTSUP/EXDEV explain on stderr")
    func cliColumnsDiagnosticsMillisecondsAndNonAPFSFallbackStderr() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-m3-cli")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let env = ["HOME": tempDir.appendingPathComponent("home").path]
        let bundleURL = tempDir.appendingPathComponent("CLIFleet.agentvm", isDirectory: true)
        let cli = AgentVMCLIRunner()

        let c1 = await cli.execute(arguments: ["--lang", "en", "create", "a"], bundleURLOverride: bundleURL, environment: env)
        #expect(c1.exitCode == 0)

        // 1. ps & snapshot list column headers in English and Chinese clearly state non-shared private bytes
        let psEn = await cli.execute(arguments: ["--lang", "en", "ps"], bundleURLOverride: bundleURL, environment: env)
        #expect(psEn.exitCode == 0)
        #expect(psEn.stdout.contains("APFS_PRIVATE"))
        #expect(psEn.stdout.contains("not shared with other clones"))
        #expect(!psEn.stdout.contains("COW_DIRTY"))

        let psZh = await cli.execute(arguments: ["--lang", "zh", "ps"], bundleURLOverride: bundleURL, environment: env)
        #expect(psZh.exitCode == 0)
        #expect(psZh.stdout.contains("私有字节"))
        #expect(psZh.stdout.contains("不与其他克隆共享"))
        #expect(!psZh.stdout.contains("CoW 脏块"))

        let psJSON = await cli.execute(arguments: ["--lang", "en", "ps", "--json"], bundleURLOverride: bundleURL, environment: env)
        #expect(psJSON.exitCode == 0)
        #expect(psJSON.stdout.contains("\"apfsPrivateBytes\""))
        #expect(psJSON.stdout.contains("\"allocatedDiskBytes\""))

        let snapEn = await cli.execute(arguments: ["--lang", "en", "snapshot", "list"], bundleURLOverride: bundleURL, environment: env)
        #expect(snapEn.exitCode == 0)
        #expect(snapEn.stdout.contains("APFS_PRIVATE"))
        #expect(snapEn.stdout.contains("not shared with other clones"))
        #expect(snapEn.stdout.contains("ALLOCATED"))

        let snapZh = await cli.execute(arguments: ["--lang", "zh", "snapshot", "list"], bundleURLOverride: bundleURL, environment: env)
        #expect(snapZh.exitCode == 0)
        #expect(snapZh.stdout.contains("私有字节"))
        #expect(snapZh.stdout.contains("不与其他克隆共享"))
        #expect(snapZh.stdout.contains("分配字节"))

        // 2. Non-APFS (ENOTSUP) and cross-volume (EXDEV) fallback explain on stderr across create, snapshot, branch
        //    and COW_BRANCH_FORKED diagnostic formats actual measured private bytes (never hardcoded "0 B unique dirty pages").
        for simulatedErrno in [ENOTSUP, EXDEV] {
            let fbBundle = tempDir.appendingPathComponent("Fallback-\(simulatedErrno).agentvm", isDirectory: true)
            let fbEngine = APFSCoWDiskEngine(forceCopyFallbackErrnoForTesting: simulatedErrno)

            let fbCreateEn = await cli.execute(
                arguments: ["--lang", "en", "create", "fb-parent"],
                bundleURLOverride: fbBundle,
                environment: env,
                diskEngineOverride: fbEngine
            )
            #expect(fbCreateEn.exitCode == 0)
            #expect(fbCreateEn.stderr.lowercased().contains("copy"))

            let fbSnapZh = await cli.execute(
                arguments: ["--lang", "zh", "snapshot", "fb-parent", "检查点"],
                bundleURLOverride: fbBundle,
                environment: env,
                diskEngineOverride: fbEngine
            )
            #expect(fbSnapZh.exitCode == 0)
            #expect(fbSnapZh.stderr.contains("完整复制"))

            let fbBranchEn = await cli.execute(
                arguments: ["--lang", "en", "branch", "fb-parent", "fb-child", "--no-boot"],
                bundleURLOverride: fbBundle,
                environment: env,
                diskEngineOverride: fbEngine
            )
            #expect(fbBranchEn.exitCode == 0)
            #expect(fbBranchEn.stdout.contains(" in ") && fbBranchEn.stdout.contains(" ms"))
            #expect(fbBranchEn.stderr.lowercased().contains("copy"))

            let eventsOut = await cli.execute(
                arguments: ["--lang", "en", "events", "--vm", "fb-child", "--json"],
                bundleURLOverride: fbBundle,
                environment: env
            )
            #expect(eventsOut.exitCode == 0)
            #expect(eventsOut.stdout.contains("COW_BRANCH_FORKED"))
            #expect(!eventsOut.stdout.contains("unique dirty pages"))
            // Because fbEngine performed a full copy (not APFS clonefile), the child disk's GPT headers are private (> 0 B),
            // proving the diagnostic message formatted real measured bytes rather than a hardcoded "0 B".
            #expect(!eventsOut.stdout.contains("(0 B"))
        }
    }
}
