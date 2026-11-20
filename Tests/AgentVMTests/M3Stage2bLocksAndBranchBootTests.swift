import AgentVMCLIAndMCP
import AgentVMHypervisor
import AgentVMModels
import AgentVMStorageCoW
import AgentVMStore
import AgentVMVsockRPC
import Darwin
import Foundation
import Testing

private actor M3LineageClonePauseGate {
    private let targetOperation: String
    private var reached = false
    private var released = false
    private var reachedWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

    init(targetOperation: String) {
        self.targetOperation = targetOperation
    }

    func onAfterClone(operation: String) async {
        guard operation == targetOperation else { return }
        if !reached {
            reached = true
            let waiters = reachedWaiters
            reachedWaiters.removeAll()
            for w in waiters {
                w.resume()
            }
        }
        if !released {
            await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                if released {
                    cont.resume()
                } else {
                    releaseWaiters.append(cont)
                }
            }
        }
    }

    func waitUntilReached() async {
        if reached { return }
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            if reached {
                cont.resume()
            } else {
                reachedWaiters.append(cont)
            }
        }
    }

    func release() {
        guard !released else { return }
        released = true
        let waiters = releaseWaiters
        releaseWaiters.removeAll()
        for w in waiters {
            w.resume()
        }
    }
}

private final class M3Stage2bMockHardwareBackend: HardwareVMLowLevelBackend, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var startCount = 0
    private var openFDs: [Int32] = []

    func closeAllDescriptors() {
        let fds = lock.withLock { () -> [Int32] in
            let copy = openFDs
            openFDs.removeAll()
            return copy
        }
        for fd in fds where fd >= 0 {
            _ = Darwin.close(fd)
        }
    }

    func startMachine(
        spec: VMSpec,
        networkSocketFD: Int32?,
        consoleLogURL: URL,
        translator: VZConfigurationTranslator
    ) async throws -> any HardwareVMInstanceHandle {
        _ = try translator.buildVZConfiguration(
            from: spec,
            networkSocketFD: networkSocketFD,
            serialLogFileURL: consoleLogURL,
            validateConfiguration: false
        )
        lock.withLock { startCount += 1 }
        return M3Stage2bMockVMHandle()
    }
}

private final class M3Stage2bMockVMHandle: HardwareVMInstanceHandle, @unchecked Sendable {
    private let stateLock = NSLock()
    private var hostFD: Int32 = -1
    private var peerFD: Int32 = -1

    func prematureStopReason() -> String? { nil }

    func connectVsock(port: UInt32) async throws -> HardwareVsockFDDescriptor {
        var fds: [Int32] = [-1, -1]
        guard Darwin.socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(Darwin.errno))
        }
        stateLock.withLock {
            if hostFD >= 0 { _ = Darwin.close(hostFD) }
            if peerFD >= 0 { _ = Darwin.close(peerFD) }
            hostFD = fds[0]
            peerFD = fds[1]
        }
        return HardwareVsockFDDescriptor(fileDescriptor: fds[0], closeWhenSessionEnds: false)
    }

    func closeVsockConnection() async {
        let (h, p) = stateLock.withLock { () -> (Int32, Int32) in
            let curH = hostFD
            let curP = peerFD
            hostFD = -1
            peerFD = -1
            return (curH, curP)
        }
        if h >= 0 { _ = Darwin.close(h) }
        if p >= 0 { _ = Darwin.close(p) }
    }

    func pause() async throws {}
    func resume() async throws {}
    func saveMachineState(to url: URL) async throws {}

    func shutdown(gracefulTimeoutNanoseconds: UInt64) async {
        await closeVsockConnection()
    }
}

@Suite("M3 Stage 2b: Lineage VMExecutionLock, Outdated Text Cleanup & branch --boot", .timeLimit(.minutes(2)))
struct M3Stage2bLocksAndBranchBootTests {

    private func makePrivateTmpDirectory(prefix: String = "avm-m3-s2b") throws -> String {
        var cTemplate = Array("/private/tmp/\(prefix).XXXXXX".utf8CString)
        let createdPtr = cTemplate.withUnsafeMutableBufferPointer { buf in
            Darwin.mkdtemp(buf.baseAddress)
        }
        guard let createdPtr else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(Darwin.errno))
        }
        let raw = String(cString: createdPtr)
        return DaemonSocketAddressResolver.canonicalRealPath(of: URL(fileURLWithPath: raw, isDirectory: true))
    }

    private static func sweepDarwinUserTempSymlinks(pointingUnder basePath: String) {
        guard let darwinTempDir = try? DaemonSocketAddressResolver.darwinUserTempDirectoryURL() else {
            return
        }
        let canonicalBase = DaemonSocketAddressResolver.canonicalRealPath(
            of: URL(fileURLWithPath: basePath, isDirectory: true)
        )
        var prefixes = [canonicalBase]
        if canonicalBase.hasPrefix("/private/tmp/") {
            prefixes.append(String(canonicalBase.dropFirst("/private".count)))
        } else if canonicalBase.hasPrefix("/tmp/") {
            prefixes.append("/private" + canonicalBase)
        }
        let uniquePrefixes = Array(Set(prefixes))

        guard let names = try? FileManager.default.contentsOfDirectory(atPath: darwinTempDir.path) else {
            return
        }
        for name in names where name.hasPrefix("avm-") {
            let linkPath = darwinTempDir.appendingPathComponent(name, isDirectory: false).path
            var st = Darwin.stat()
            guard Darwin.lstat(linkPath, &st) == 0, (st.st_mode & S_IFMT) == S_IFLNK else {
                continue
            }
            var buf = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
            let len = Darwin.readlink(linkPath, &buf, Int(PATH_MAX))
            guard len > 0 else { continue }
            let rawTarget = String(decoding: buf.prefix(len).map { UInt8(bitPattern: $0) }, as: UTF8.self)
            let resolvedTarget: String
            if rawTarget.hasPrefix("/") {
                resolvedTarget = DaemonSocketAddressResolver.canonicalRealPath(
                    of: URL(fileURLWithPath: rawTarget, isDirectory: true)
                )
            } else {
                resolvedTarget = DaemonSocketAddressResolver.canonicalRealPath(
                    of: darwinTempDir.appendingPathComponent(rawTarget, isDirectory: true)
                )
            }
            let matches = uniquePrefixes.contains { prefix in
                rawTarget == prefix
                    || rawTarget.hasPrefix(prefix + "/")
                    || resolvedTarget == prefix
                    || resolvedTarget.hasPrefix(prefix + "/")
            }
            if matches {
                _ = Darwin.unlink(linkPath)
            }
        }
    }

    private func stageBootableCachedImage(
        in baseDir: String,
        imageID: String = "debian-12-bookworm-arm64"
    ) async throws -> (cacheDir: URL, cachedFileURL: URL, entry: BaseImageCatalogEntry) {
        let cacheDir = URL(fileURLWithPath: "\(baseDir)/cache", isDirectory: true)
        let imageBytes = 4 * 1024 * 1024
        let stagingURL = URL(fileURLWithPath: "\(baseDir)/staging-\(UUID().uuidString).raw")
        try APFSCoWDiskEngine().createSparseRawDisk(at: stagingURL, virtualSizeBytes: UInt64(imageBytes), overwrite: true)
        let parts = try PartitionAndContainerInspector().writeProtectiveMBRAndGPT(
            to: stagingURL,
            partitions: [(name: "RootExt4", typeGUID: GPTWellKnownTypeGUID.linuxRootARM64.rawValue, sizeBytes: 2 * 1024 * 1024)]
        )
        var ext4Super = [UInt8](repeating: 0, count: 256)
        ext4Super[0x38] = 0x53
        ext4Super[0x39] = 0xEF
        ext4Super[0x5C] = 0x04
        ext4Super[0x60] = 0xC0
        let fh = try FileHandle(forUpdating: stagingURL)
        try fh.seek(toOffset: parts[0].firstLBA * 512 + 1024)
        try fh.write(contentsOf: Data(ext4Super))
        try fh.close()

        let sha512 = try BinaryChecksums.sha512HexFile(at: stagingURL)
        let entry = BaseImageCatalogEntry(
            id: imageID,
            displayName: "Debian 12 Test Image",
            distribution: "debian",
            version: "20261112-2660",
            guestOS: .linuxARM64,
            isSupported: true,
            downloadURL: "https://offline.agentvm.invalid/debian.raw",
            expectedSHA512: sha512,
            expectedSizeBytes: UInt64(imageBytes),
            defaultVirtualSizeBytes: UInt64(imageBytes)
        )
        let seeder = try BaseImageRegistryCatalog(cacheDirectoryURL: cacheDir, curatedEntries: [entry], createIfMissing: true)
        let staged = try await seeder.stageCachedCuratedImage(id: imageID, from: stagingURL, verifyChecksum: true)
        try? FileManager.default.removeItem(at: stagingURL)
        let cachedURL = URL(fileURLWithPath: try #require(staged.cachedLocalPath)).standardizedFileURL
        #expect(Darwin.chmod(cachedURL.path, 0o444) == 0)
        return (cacheDir, cachedURL, entry)
    }

    private func withStartedDaemonServer<T>(
        workspaceURL: URL,
        imageCacheDirectoryURL: URL? = nil,
        curatedImageEntries: [BaseImageCatalogEntry]? = nil,
        hardwareBackendOverride: (any HardwareVMLowLevelBackend)? = nil,
        _ body: (WorkspaceDaemonServer) async throws -> T
    ) async throws -> T {
        let outcome = try await WorkspaceDaemonServer.start(
            workspaceURL: workspaceURL,
            imageCacheDirectoryURL: imageCacheDirectoryURL,
            curatedImageEntries: curatedImageEntries,
            hardwareBackendOverride: hardwareBackendOverride,
            vsockConnectTimeoutNanoseconds: 5_000_000_000,
            vsockRetryIntervalNanoseconds: 10_000_000,
            gracefulStopTimeoutNanoseconds: 100_000_000
        )
        guard case let .started(server) = outcome else {
            Issue.record("Expected WorkspaceDaemonServer.start to acquire singleton lock for \(workspaceURL.path)")
            throw NSError(domain: "M3Stage2bLocksAndBranchBootTests", code: 1)
        }
        defer {
            server.listener.close(unlinkSocket: true, removeSymlink: true)
            server.singletonLock.release(clearFile: true)
            server.logManager.close()
        }
        do {
            let result = try await body(server)
            await server.stopAndCleanup()
            return result
        } catch {
            await server.stopAndCleanup()
            throw error
        }
    }

    private func decodeVMsJSON(_ rawJSON: String) throws -> [VMInstanceRecord] {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode([VMInstanceRecord].self, from: Data(rawJSON.utf8))
    }

    // MARK: - 1. Row 4: In-Progress `restore`, `branch`, and `snapshot` Hold `VMExecutionLock` Across Disk Clone

    @Test("Row 4 (A58): while one coordinator is paused after clone in restore, branch, or snapshot, another coordinator's up and restore fail ERR_VM_LOCKED and lock releases on completion")
    func row4CoordinatorLockMutualExclusionDuringRestoreBranchAndSnapshot() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-m3-r4")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/Row4Locks.agentvm", isDirectory: true)
        let mockBackend = M3Stage2bMockHardwareBackend()
        defer { mockBackend.closeAllDescriptors() }

        let coord1 = try AgentVMFleetCoordinator(
            bundleURL: wsURL,
            executionBackend: .strictHardwareVZ,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mockBackend
        )
        let coord2Daemon = try AgentVMFleetCoordinator(
            bundleURL: wsURL,
            executionBackend: .strictHardwareVZ,
            isWorkspaceDaemon: true,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mockBackend
        )
        let coord3Client = try AgentVMFleetCoordinator(
            bundleURL: wsURL,
            executionBackend: .strictHardwareVZ,
            isWorkspaceDaemon: false,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mockBackend
        )

        let created = try await coord1.createVMFromImage(name: "t1", imageID: entry.id)
        let vmID = created.vmRecord.id
        let baseSnapID = created.rootSnapshot.id
        let lockURL = coord1.lockFileURL(for: vmID)
        #expect(VMExecutionLock.isLocked(at: lockURL) == false)

        // Helper verifying that while `coord1` is paused after disk clone, `coord2Daemon` `up`, `coord3Client` `up` & `restore` all fail ERR_VM_LOCKED.
        func assertContendersBlockedByLock(contextLabel: String) async {
            #expect(VMExecutionLock.isLocked(at: lockURL) == true, "[\(contextLabel)] expected VMExecutionLock to be held")

            var daemonUpErr: AgentVMError?
            do {
                _ = try await coord2Daemon.bootPersistentVM(vmID)
            } catch let err as AgentVMError {
                daemonUpErr = err
            } catch {
                Issue.record("[\(contextLabel)] unexpected error from daemon bootPersistentVM: \(error)")
            }
            if daemonUpErr == nil {
                // Clean up if RED phase let daemon boot through!
                _ = try? await coord2Daemon.haltVM(vmID)
            }
            #expect(daemonUpErr?.errorCode == "ERR_VM_LOCKED", "[\(contextLabel)] expected daemon up to fail ERR_VM_LOCKED, got \(String(describing: daemonUpErr))")

            var clientUpErr: AgentVMError?
            do {
                _ = try await coord3Client.bootPersistentVM(vmID)
            } catch let err as AgentVMError {
                clientUpErr = err
            } catch {
                Issue.record("[\(contextLabel)] unexpected error from client bootPersistentVM: \(error)")
            }
            #expect(clientUpErr?.errorCode == "ERR_VM_LOCKED", "[\(contextLabel)] expected client up to fail ERR_VM_LOCKED, got \(String(describing: clientUpErr))")

            var secondRestoreErr: AgentVMError?
            do {
                _ = try await coord3Client.restoreToSnapshot(baseSnapID)
            } catch let err as AgentVMError {
                secondRestoreErr = err
            } catch {
                Issue.record("[\(contextLabel)] unexpected error from second restoreToSnapshot: \(error)")
            }
            #expect(secondRestoreErr?.errorCode == "ERR_VM_LOCKED", "[\(contextLabel)] expected second restore to fail ERR_VM_LOCKED, got \(String(describing: secondRestoreErr))")
        }

        // Case A: `restore` in progress on `coord1` (paused right after disk clone)
        do {
            let gate = M3LineageClonePauseGate(targetOperation: "restore")
            await coord1.setAfterLineageCloneHookForTesting { op, id in
                if id == vmID {
                    await gate.onAfterClone(operation: op)
                }
            }
            let task = Task {
                try await coord1.restoreToSnapshot(baseSnapID)
            }
            await gate.waitUntilReached()
            await assertContendersBlockedByLock(contextLabel: "in-flight restore")
            await gate.release()
            let restored = try await task.value
            #expect(restored.id == vmID)
            await coord1.setAfterLineageCloneHookForTesting(nil)
            #expect(VMExecutionLock.isLocked(at: lockURL) == false, "Lock must be released after restore completes")
        }

        // Case B: `branch` in progress on `coord1` (paused right after disk clone)
        do {
            let gate = M3LineageClonePauseGate(targetOperation: "branch")
            await coord1.setAfterLineageCloneHookForTesting { op, id in
                if id == vmID {
                    await gate.onAfterClone(operation: op)
                }
            }
            let task = Task {
                try await coord1.forkCoWBranch(
                    fromVMID: vmID,
                    branchName: "t1-branch-lock",
                    agentOwnerTag: "m3-test",
                    bootImmediately: false
                )
            }
            await gate.waitUntilReached()
            await assertContendersBlockedByLock(contextLabel: "in-flight branch")
            await gate.release()
            let forked = try await task.value
            #expect(forked.childVM.spec.name == "t1-branch-lock")
            await coord1.setAfterLineageCloneHookForTesting(nil)
            #expect(VMExecutionLock.isLocked(at: lockURL) == false, "Lock must be released after branch completes")
        }

        // Case C: `snapshot` in progress on `coord1` (paused right after disk clone)
        do {
            let gate = M3LineageClonePauseGate(targetOperation: "snapshot")
            await coord1.setAfterLineageCloneHookForTesting { op, id in
                if id == vmID {
                    await gate.onAfterClone(operation: op)
                }
            }
            let task = Task {
                try await coord1.captureSnapshot(vmID: vmID, title: "s-lock-test")
            }
            await gate.waitUntilReached()
            await assertContendersBlockedByLock(contextLabel: "in-flight snapshot")
            await gate.release()
            let snap = try await task.value
            #expect(snap.vmID == vmID)
            await coord1.setAfterLineageCloneHookForTesting(nil)
            #expect(VMExecutionLock.isLocked(at: lockURL) == false, "Lock must be released after snapshot completes")
        }

        #expect(mockBackend.startCount == 0, "Contending up must be blocked by VMExecutionLock before startMachine")
    }

    // MARK: - 2. Outdated "in M3" / "requires M2 daemon ... not available yet" Wording Removed

    @Test("A57 & A58 wording: ERR_VM_LOCKED on daemon-held VM no longer says 'in M3', and persistentBootRequiresDaemon no longer says 'M2 ... not available yet'")
    func outdatedM2AndM3LockAndDaemonErrorTextRemoved() async throws {
        // 1. Direct inspection of `persistentBootRequiresDaemon`
        let daemonReqErr = AgentVMError.persistentBootRequiresDaemon(vmName: "t1")
        #expect(daemonReqErr.errorCode == "ERR_DAEMON_REQUIRED")
        let enDaemonMsg = daemonReqErr.localizedMessage(in: .en)
        let zhDaemonMsg = daemonReqErr.localizedMessage(in: .zhHans)
        let enDaemonHint = daemonReqErr.remediationHint
        #expect(!enDaemonMsg.contains("M2"), "Outdated M2 mention in EN persistentBootRequiresDaemon: \(enDaemonMsg)")
        #expect(!enDaemonMsg.lowercased().contains("not available yet"), "Outdated 'not available yet' in EN persistentBootRequiresDaemon: \(enDaemonMsg)")
        #expect(!zhDaemonMsg.contains("M2"), "Outdated M2 mention in ZH persistentBootRequiresDaemon: \(zhDaemonMsg)")
        #expect(!zhDaemonMsg.contains("尚未实现"), "Outdated '尚未实现' in ZH persistentBootRequiresDaemon: \(zhDaemonMsg)")
        #expect(!enDaemonHint.contains("M2"))

        // 2. When a non-daemon lock holder holds `<t1>.lock` (no daemon running), CLI `snapshot`/`branch`/`restore`
        //    exit 1 with ERR_VM_LOCKED without saying 'M3' (in Stage 3a, daemon-held VMs route via DaemonRPC instead).
        let realBase = try makePrivateTmpDirectory(prefix: "avm-m3-text")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/NoM3Text.agentvm", isDirectory: true)
        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()

        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "create", "t1", "--image", entry.id],
            curatedEntriesOverride: [entry],
            environment: env
        ).exitCode == 0)

        let inspectStore = try AgentVMProjectStore(bundleURL: wsURL, createIfMissing: false)
        let t1 = try #require(try await inspectStore.listVMs().first(where: { $0.spec.name == "t1" }))
        let baseSnapID = try #require(t1.currentHeadSnapshotID)
        let lockURL = wsURL.appendingPathComponent("locks/\(t1.id.rawValue).lock")

        let externalLock = try VMExecutionLock.acquire(at: lockURL, vmName: "t1")
        defer { externalLock.release() }

        for lang in ["en", "zh"] {
            let snapRes = await cli.execute(
                arguments: ["--lang", lang, "--workspace", wsURL.path, "snapshot", "t1", "s1"],
                curatedEntriesOverride: [entry],
                environment: env
            )
            #expect(snapRes.exitCode == 1)
            #expect(snapRes.stderr.contains("ERR_VM_LOCKED"))
            #expect(!snapRes.stderr.contains("M3"), "Outdated M3 text in snapshot (\(lang)): \(snapRes.stderr)")

            let branchRes = await cli.execute(
                arguments: ["--lang", lang, "--workspace", wsURL.path, "branch", "t1", "t1-c"],
                curatedEntriesOverride: [entry],
                environment: env
            )
            #expect(branchRes.exitCode == 1)
            #expect(branchRes.stderr.contains("ERR_VM_LOCKED"))
            #expect(!branchRes.stderr.contains("M3"), "Outdated M3 text in branch (\(lang)): \(branchRes.stderr)")

            let restoreRes = await cli.execute(
                arguments: ["--lang", lang, "--workspace", wsURL.path, "restore", baseSnapID.rawValue],
                curatedEntriesOverride: [entry],
                environment: env
            )
            #expect(restoreRes.exitCode == 1)
            #expect(restoreRes.stderr.contains("ERR_VM_LOCKED"))
            #expect(!restoreRes.stderr.contains("M3"), "Outdated M3 text in restore (\(lang)): \(restoreRes.stderr)")
        }
    }

    // MARK: - 3. Row 3: `branch --boot` Runs `up` Preflight Before Creating Child VM

    @Test("Row 3 (A57): 'branch a a2 --boot' on empty disk exits 1 with ERR_NO_BOOTABLE_SYSTEM and leaves no a2 in ps --json; missing entitlement also leaves no child")
    func row3BranchBootPreflightRejectsEmptyDiskAndMissingEntitlementBeforeCreatingChild() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-m3-r3")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/Row3Preflight.agentvm", isDirectory: true)
        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()
        let paths = DaemonWorkspacePaths(workspaceURL: wsURL)
        let forbiddenSpawn = DaemonSpawnCommandOverride(executablePath: "/bin/sh", arguments: ["-c", "exit 98"], environment: env)

        #expect(await cli.execute(arguments: ["--workspace", wsURL.path, "create", "a"], curatedEntriesOverride: [entry], environment: env).exitCode == 0)
        #expect(await cli.execute(arguments: ["--workspace", wsURL.path, "create", "t1", "--image", entry.id], curatedEntriesOverride: [entry], environment: env).exitCode == 0)

        // Put `a` into simulated running first to ensure `branch a a2 --boot` strips simulated state in preflight too.
        #expect(await cli.execute(arguments: ["--backend", "simulation", "--workspace", wsURL.path, "up", "a"], curatedEntriesOverride: [entry], environment: env).exitCode == 0)

        // 1. Row 3: `branch a a2 --boot` on empty disk -> exit 1, ERR_NO_BOOTABLE_SYSTEM, `a2` NOT in `ps --json`, daemon never touched.
        let r3Out = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "branch", "a", "a2", "--boot"],
            curatedEntriesOverride: [entry],
            environment: env,
            hasEntitlementOverride: true,
            daemonSpawnOverride: forbiddenSpawn
        )
        #expect(r3Out.exitCode == 1)
        #expect(r3Out.stdout.isEmpty)
        #expect(r3Out.stderr.contains("ERR_NO_BOOTABLE_SYSTEM"), "Expected ERR_NO_BOOTABLE_SYSTEM, got: \(r3Out.stderr)")
        #expect(!FileManager.default.fileExists(atPath: paths.directSocketPath))

        let psAfterEmpty = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "ps", "--json"],
            curatedEntriesOverride: [entry],
            environment: env,
            daemonSpawnOverride: forbiddenSpawn
        )
        #expect(psAfterEmpty.exitCode == 0)
        let vmsAfterEmpty = try decodeVMsJSON(psAfterEmpty.stdout)
        #expect(!vmsAfterEmpty.contains(where: { $0.spec.name == "a2" }), "a2 must NOT be created when preflight fails")

        // 2. Bootable `t1` without virtualization entitlement -> exit 1, ERR_VZ_ENTITLEMENT_MISSING, `t1_noent` NOT created, daemon never touched.
        let noEntOut = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "branch", "t1", "t1_noent", "--boot"],
            curatedEntriesOverride: [entry],
            environment: env,
            hasEntitlementOverride: false,
            daemonSpawnOverride: forbiddenSpawn
        )
        #expect(noEntOut.exitCode == 1)
        #expect(noEntOut.stdout.isEmpty)
        #expect(noEntOut.stderr.contains("ERR_VZ_ENTITLEMENT_MISSING"), "Expected ERR_VZ_ENTITLEMENT_MISSING, got: \(noEntOut.stderr)")
        #expect(!FileManager.default.fileExists(atPath: paths.directSocketPath))

        let psAfterNoEnt = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "ps", "--json"],
            curatedEntriesOverride: [entry],
            environment: env,
            daemonSpawnOverride: forbiddenSpawn
        )
        #expect(psAfterNoEnt.exitCode == 0)
        let vmsAfterNoEnt = try decodeVMsJSON(psAfterNoEnt.stdout)
        #expect(!vmsAfterNoEnt.contains(where: { $0.spec.name == "t1_noent" }), "t1_noent must NOT be created when entitlement preflight fails")
    }

    // MARK: - 4. Without `--boot`, Child Never Boots Even If Parent Is Running; `--no-boot` Preserved as Default

    @Test("Decided Item 4: without --boot, branch never boots child even when parent is running; --no-boot equals default")
    func branchWithoutBootNeverBootsChildEvenWhenParentIsRunning() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-m3-noboot")
        defer { try? FileManager.default.removeItem(atPath: realBase) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/DefaultNoBoot.agentvm", isDirectory: true)
        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = ["HOME": isolatedHome, "CFFIXED_USER_HOME": isolatedHome]
        let cli = AgentVMCLIRunner()

        #expect(await cli.execute(arguments: ["--backend", "simulation", "--workspace", wsURL.path, "create", "p"], environment: env).exitCode == 0)
        #expect(await cli.execute(arguments: ["--backend", "simulation", "--workspace", wsURL.path, "up", "p"], environment: env).exitCode == 0)

        // 1. Default `branch p c_default` (no flags) while `p` is running -> child is `stopped`!
        let defaultOut = await cli.execute(
            arguments: ["--backend", "simulation", "--lang", "en", "--workspace", wsURL.path, "branch", "p", "c_default"],
            environment: env
        )
        #expect(defaultOut.exitCode == 0)

        // 2. Explicit `branch p c_noboot --no-boot` -> child is `stopped`!
        let noBootOut = await cli.execute(
            arguments: ["--backend", "simulation", "--lang", "en", "--workspace", wsURL.path, "branch", "p", "c_noboot", "--no-boot"],
            environment: env
        )
        #expect(noBootOut.exitCode == 0)

        // 3. Explicit `branch p c_boot --boot` -> child IS `running`!
        let bootOut = await cli.execute(
            arguments: ["--backend", "simulation", "--lang", "en", "--workspace", wsURL.path, "branch", "p", "c_boot", "--boot"],
            environment: env
        )
        #expect(bootOut.exitCode == 0)

        let inspectStore = try AgentVMProjectStore(bundleURL: wsURL, createIfMissing: false)
        let vms = try await inspectStore.listVMs()
        let pRec = try #require(vms.first(where: { $0.spec.name == "p" }))
        let cDefault = try #require(vms.first(where: { $0.spec.name == "c_default" }))
        let cNoBoot = try #require(vms.first(where: { $0.spec.name == "c_noboot" }))
        let cBoot = try #require(vms.first(where: { $0.spec.name == "c_boot" }))

        #expect(pRec.telemetry.state == .running)
        #expect(cDefault.telemetry.state == .stopped, "Child without --boot must stay stopped even when parent is running")
        #expect(cNoBoot.telemetry.state == .stopped, "Child with --no-boot must stay stopped")
        #expect(cBoot.telemetry.state == .running, "Child with --boot must boot")

        // 4. MCP `agentvm_fork_cow_branch` omitting `bootImmediately` while parent is running -> child stays `stopped`!
        let simCoord = try AgentVMFleetCoordinator(bundleURL: wsURL, executionBackend: .deterministicSimulation)
        _ = try await simCoord.bootVM(pRec.id)
        let mcp = AgentVMMCPServer(coordinator: simCoord)
        let reqObj: [String: Any] = [
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": [
                "name": "agentvm_fork_cow_branch",
                "arguments": [
                    "parentVMID": pRec.id.rawValue,
                    "branchName": "c_mcp_default"
                ]
            ]
        ]
        let reqLine = String(decoding: try JSONSerialization.data(withJSONObject: reqObj), as: UTF8.self)
        let respLine = try #require(await mcp.handleJSONRPCLine(reqLine))
        #expect(respLine.contains("c_mcp_default"))
        let cMCP = try #require(try await inspectStore.listVMs().first(where: { $0.spec.name == "c_mcp_default" }))
        #expect(cMCP.telemetry.state == .stopped, "MCP branch omitting bootImmediately must default to stopped")
    }

    // MARK: - 5. `branch --boot` Boots Child via Workspace Daemon, and Preserves Stopped Child When Boot Fails

    @Test("A57: 'branch --boot' boots child via workspace daemon (running + guestAgentConnected), and on boot failure keeps stopped child with clear EN/ZH message")
    func branchBootBootsViaWorkspaceDaemonAndPreservesStoppedChildWithExplanationWhenBootFails() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-m3-bboot")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/BranchBootDaemon.agentvm", isDirectory: true)
        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()
        let failingSpawn = DaemonSpawnCommandOverride(executablePath: "/bin/sh", arguments: ["-c", "exit 99"], environment: env)

        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "create", "p", "--image", entry.id],
            curatedEntriesOverride: [entry],
            environment: env
        ).exitCode == 0)

        // Part A: No daemon running yet, preflight passes (`hasEntitlementOverride: true`), child `c_spawn_fail` is created,
        // then spawning daemon fails (exit 99) -> exits 1, `c_spawn_fail` is preserved as `stopped`, stderr explains created & not booted!
        let failEn = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "branch", "p", "c_spawn_fail_en", "--boot"],
            curatedEntriesOverride: [entry],
            environment: env,
            hasEntitlementOverride: true,
            daemonSpawnOverride: failingSpawn
        )
        #expect(failEn.exitCode == 1)
        #expect(failEn.stderr.contains("ERR_DAEMON_IPC"))
        #expect(failEn.stderr.contains("c_spawn_fail_en"))
        #expect(failEn.stderr.lowercased().contains("created") && failEn.stderr.lowercased().contains("stopped"))

        let failZh = await cli.execute(
            arguments: ["--lang", "zh", "--workspace", wsURL.path, "branch", "p", "c_spawn_fail_zh", "--boot"],
            curatedEntriesOverride: [entry],
            environment: env,
            hasEntitlementOverride: true,
            daemonSpawnOverride: failingSpawn
        )
        #expect(failZh.exitCode == 1)
        #expect(failZh.stderr.contains("ERR_DAEMON_IPC"))
        #expect(failZh.stderr.contains("c_spawn_fail_zh"))
        #expect(failZh.stderr.contains("已建好") && failZh.stderr.contains("没有开机"))

        let psAfterSpawnFail = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "ps", "--json"],
            curatedEntriesOverride: [entry],
            environment: env,
            daemonSpawnOverride: failingSpawn
        )
        #expect(psAfterSpawnFail.exitCode == 0)
        let vmsAfterSpawnFail = try decodeVMsJSON(psAfterSpawnFail.stdout)
        let recFailEn = try #require(vmsAfterSpawnFail.first(where: { $0.spec.name == "c_spawn_fail_en" }))
        let recFailZh = try #require(vmsAfterSpawnFail.first(where: { $0.spec.name == "c_spawn_fail_zh" }))
        #expect(recFailEn.telemetry.state == .stopped && recFailEn.telemetry.guestAgentConnected == false)
        #expect(recFailZh.telemetry.state == .stopped && recFailZh.telemetry.guestAgentConnected == false)

        // Part B: With workspace daemon running:
        //  1) `branch p c_ok --boot` succeeds (exit 0), `c_ok` is `running` with `guestAgentConnected == true`, `p` remains `stopped`.
        //  2) Under `policy airgap`, `branch p c_airgap --boot` creates `c_airgap`, then daemon `.up` fails `ERR_AIRGAP_UNSUPPORTED` ->
        //     exits 1, `c_airgap` preserved in `stopped` state, stderr explains child was created and not booted.
        let mockBackend = M3Stage2bMockHardwareBackend()
        defer { mockBackend.closeAllDescriptors() }

        try await withStartedDaemonServer(
            workspaceURL: wsURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mockBackend
        ) { _ in
            let bootOK = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "branch", "p", "c_ok", "--boot"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: failingSpawn
            )
            #expect(bootOK.exitCode == 0, "Expected branch --boot via daemon to succeed, got stderr: \(bootOK.stderr)")
            #expect(bootOK.stdout.contains("Forked CoW branch 'c_ok'"))

            let psRunning = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "ps", "--json"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: failingSpawn
            )
            #expect(psRunning.exitCode == 0)
            let vmsRunning = try decodeVMsJSON(psRunning.stdout)
            let pRec = try #require(vmsRunning.first(where: { $0.spec.name == "p" }))
            let cOKRec = try #require(vmsRunning.first(where: { $0.spec.name == "c_ok" }))
            #expect(pRec.telemetry.state == .stopped)
            #expect(cOKRec.telemetry.state == .running)
            #expect(cOKRec.telemetry.guestAgentConnected == true)

            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "c_ok"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: failingSpawn
            ).exitCode == 0)

            // Switch policy to `airgap` so daemon `.up` fails after child creation
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "policy", "airgap"],
                curatedEntriesOverride: [entry],
                environment: env
            ).exitCode == 0)

            let airgapBootFail = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "branch", "p", "c_airgap", "--boot"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: failingSpawn
            )
            #expect(airgapBootFail.exitCode == 1)
            #expect(airgapBootFail.stderr.contains("ERR_AIRGAP_UNSUPPORTED"))
            #expect(airgapBootFail.stderr.contains("c_airgap"))
            #expect(airgapBootFail.stderr.lowercased().contains("created") && airgapBootFail.stderr.lowercased().contains("stopped"))

            let psAfterAirgap = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "ps", "--json"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: failingSpawn
            )
            let vmsAfterAirgap = try decodeVMsJSON(psAfterAirgap.stdout)
            let cAirgapRec = try #require(vmsAfterAirgap.first(where: { $0.spec.name == "c_airgap" }))
            #expect(cAirgapRec.telemetry.state == .stopped && cAirgapRec.telemetry.guestAgentConnected == false)
        }
    }
}
