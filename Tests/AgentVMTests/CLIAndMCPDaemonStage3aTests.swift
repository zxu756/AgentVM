import AgentVMCLIAndMCP
import AgentVMHypervisor
import AgentVMModels
import AgentVMStorageCoW
import AgentVMStore
import AgentVMVsockRPC
import Darwin
import Foundation
import Testing

@Suite("M2 Stage 3a: Daemon Lifecycle, Per-VM Serialization, Lock Order, A51, A40 & A39", .timeLimit(.minutes(2)))
struct CLIAndMCPDaemonStage3aTests {

    private func makePrivateTmpDirectory(prefix: String = "avm-s3a") throws -> String {
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
        vsockConnectTimeoutNanoseconds: UInt64 = 5_000_000_000,
        vsockRetryIntervalNanoseconds: UInt64 = 10_000_000,
        gracefulStopTimeoutNanoseconds: UInt64 = 100_000_000,
        _ body: (WorkspaceDaemonServer) async throws -> T
    ) async throws -> T {
        let outcome = try await WorkspaceDaemonServer.start(
            workspaceURL: workspaceURL,
            imageCacheDirectoryURL: imageCacheDirectoryURL,
            curatedImageEntries: curatedImageEntries,
            hardwareBackendOverride: hardwareBackendOverride,
            vsockConnectTimeoutNanoseconds: vsockConnectTimeoutNanoseconds,
            vsockRetryIntervalNanoseconds: vsockRetryIntervalNanoseconds,
            gracefulStopTimeoutNanoseconds: gracefulStopTimeoutNanoseconds
        )
        guard case let .started(server) = outcome else {
            Issue.record("Expected WorkspaceDaemonServer.start to acquire singleton lock for \(workspaceURL.path)")
            throw NSError(domain: "CLIAndMCPDaemonStage3aTests", code: 1)
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

    // MARK: - Items 1, 2 & 3: Daemon Lifecycle (`up`/`halt`/`pause`/`resume`), Per-VM Queue (A38), Lock Order & A51

    @Test("Item 1: 'up', 'pause', 'resume', and 'halt' route through daemon, serialize per-VM operations (A38), and preserve idempotent 'up'")
    func daemonLifecycleUpPauseResumeHaltAndPerVMSerializationA38() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-s3a-i1")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/Lifecycle.agentvm", isDirectory: true)
        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()
        let forbiddenSpawn = DaemonSpawnCommandOverride(
            executablePath: "/bin/sh",
            arguments: ["-c", "exit 93"],
            environment: env
        )

        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "create", "t1", "--image", entry.id],
            curatedEntriesOverride: [entry],
            environment: env
        ).exitCode == 0)

        let mockBackend = Stage3aMockHardwareBackend(startDelayNanoseconds: 120_000_000, shutdownDelayNanoseconds: 80_000_000)
        defer { mockBackend.closeAllDescriptors() }

        try await withStartedDaemonServer(
            workspaceURL: wsURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mockBackend
        ) { _ in
            // 1. Two concurrent `up t1` calls queue on t1 (A38): both exit 0, and `startMachine` runs exactly ONCE.
            async let up1 = cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            )
            async let up2 = cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            )
            let (rUp1, rUp2) = await (up1, up2)
            #expect(rUp1.exitCode == 0, "up1 stderr: \(rUp1.stderr)")
            #expect(rUp2.exitCode == 0, "up2 stderr: \(rUp2.stderr)")
            #expect(mockBackend.startCount == 1)
            #expect(mockBackend.maxConcurrentLifecycleOps == 1)

            // 2. Subsequent `up t1` while running is idempotent (exit 0, startCount still 1).
            let rUp3 = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(rUp3.exitCode == 0)
            #expect(mockBackend.startCount == 1)

            // 3. `pause t1` -> invokes VZ pause, state becomes paused; `resume t1` -> invokes VZ resume, state becomes running.
            let rPause = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "pause", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(rPause.exitCode == 0)
            #expect(mockBackend.pauseCount == 1)

            let psPaused = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "ps", "--json"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(psPaused.exitCode == 0)
            #expect(psPaused.stdout.contains("\"state\" : \"paused\""))

            let rResume = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "resume", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(rResume.exitCode == 0)
            #expect(mockBackend.resumeCount == 1)

            // 4. `halt t1` -> graceful shutdown, state becomes stopped; second `halt t1` also exits 0.
            let rHalt = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(rHalt.exitCode == 0)
            #expect(mockBackend.shutdownCount == 1)

            let rHaltAgain = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(rHaltAgain.exitCode == 0)

            // 5. Concurrent `up t1` and `halt t1` serialize strictly (maxConcurrentLifecycleOps == 1).
            async let raceUp = cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            )
            async let raceHalt = cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            let (rRaceUp, rRaceHalt) = await (raceUp, raceHalt)
            #expect(rRaceUp.exitCode == 0)
            #expect(rRaceHalt.exitCode == 0)
            #expect(mockBackend.maxConcurrentLifecycleOps == 1)

            // Ensure stopped before exiting scope.
            _ = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
        }
    }

    @Test("Item 2: daemon acquires VMExecutionLock before startMachine, releases only after stopped is written to SQLite, and contends mutually with 'run' (125 ERR_VM_LOCKED)")
    func daemonVMExecutionLockHoldingOrderAndMutualExclusionWithRun() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-s3a-i2")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/LockOrder.agentvm", isDirectory: true)
        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()
        let forbiddenSpawn = DaemonSpawnCommandOverride(
            executablePath: "/bin/sh",
            arguments: ["-c", "exit 94"],
            environment: env
        )

        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "create", "t1", "--image", entry.id],
            curatedEntriesOverride: [entry],
            environment: env
        ).exitCode == 0)

        let inspectStore = try AgentVMProjectStore(bundleURL: wsURL, createIfMissing: false)
        let vmRecord = try #require(try await inspectStore.listVMs().first(where: { $0.spec.name == "t1" }))
        let lockURL = inspectStore.locksDirectoryURL.appendingPathComponent("\(vmRecord.id.rawValue).lock", isDirectory: false)

        let mockBackend = Stage3aMockHardwareBackend(lockURLToInspect: lockURL, storeToInspect: inspectStore)
        defer { mockBackend.closeAllDescriptors() }

        try await withStartedDaemonServer(
            workspaceURL: wsURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mockBackend
        ) { _ in
            #expect(VMExecutionLock.isLocked(at: lockURL) == false)

            // 1. `up t1` acquires lock BEFORE `startMachine` and keeps holding it after `up` returns.
            let upOut = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(upOut.exitCode == 0, "up failed: \(upOut.stderr)")
            #expect(mockBackend.wasLockedDuringStartMachine == true)
            #expect(VMExecutionLock.isLocked(at: lockURL) == true)

            // 2. While daemon holds `t1`, `agentvm run t1 -- true` fails with 125 and ERR_VM_LOCKED before touching hardwareBackend.
            let shouldNeverStartBackend = Stage3aMockHardwareBackend(failStartImmediately: true)
            let runContend = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "run", "t1", "--", "true"],
                curatedEntriesOverride: [entry],
                environment: env,
                hardwareBackendOverride: shouldNeverStartBackend
            )
            #expect(runContend.exitCode == 125)
            #expect(runContend.stdout.isEmpty)
            #expect(runContend.stderr.contains("ERR_VM_LOCKED"))
            #expect(shouldNeverStartBackend.startCount == 0)

            // 3. `pause` and `resume` keep the lock held throughout.
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "pause", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
            #expect(VMExecutionLock.isLocked(at: lockURL) == true)

            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "resume", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
            #expect(VMExecutionLock.isLocked(at: lockURL) == true)

            // 4. Observe exact moment lock is released during `halt t1`: SQLite state MUST already be `stopped`.
            let lockInitiallyHeld = VMExecutionLock.isLocked(at: lockURL)
            let stateAtUnlockTask = Task<VMLifecycleState?, Error> {
                let deadline = DispatchTime.now().uptimeNanoseconds &+ 5_000_000_000
                while VMExecutionLock.isLocked(at: lockURL) && DispatchTime.now().uptimeNanoseconds < deadline {
                    Darwin.usleep(500)
                }
                return try await inspectStore.fetchVM(vmRecord.id)?.telemetry.state
            }
            _ = lockInitiallyHeld

            let haltOut = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(haltOut.exitCode == 0)
            #expect(mockBackend.wasLockedDuringShutdown == true)
            #expect(mockBackend.dbStateDuringShutdown != .stopped)
            #expect(VMExecutionLock.isLocked(at: lockURL) == false)

            let observedStateUponUnlock = try await stateAtUnlockTask.value
            #expect(observedStateUponUnlock == .stopped)

            // 5. Conversely, when external `run` (simulated by holding VMExecutionLock) holds `t1`, daemon `up t1` exits 1 with ERR_VM_LOCKED.
            let externalRunLock = try VMExecutionLock.acquire(at: lockURL, vmName: "t1")
            defer { externalRunLock.release() }

            let upWhileRunHoldsLock = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(upWhileRunHoldsLock.exitCode == 1)
            #expect(upWhileRunHoldsLock.stderr.contains("ERR_VM_LOCKED"))
            #expect(mockBackend.startCount == 1)
        }
    }

    @Test("Item 3 (A51): hardware bootVM never treats SQLite 'running' state as idempotent unless this coordinator holds the live VM instance in memory")
    func hardwareBootRequiresInMemoryInstanceForIdempotentRunningCheckA51() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-s3a-i3")
        defer { try? FileManager.default.removeItem(atPath: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/A51.agentvm", isDirectory: true)
        let mockBackend = Stage3aMockHardwareBackend()
        defer { mockBackend.closeAllDescriptors() }

        let coordinator = try AgentVMFleetCoordinator(
            bundleURL: wsURL,
            executionBackend: .strictHardwareVZ,
            isWorkspaceDaemon: true,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mockBackend,
            vsockConnectTimeoutNanoseconds: 5_000_000_000,
            vsockRetryIntervalNanoseconds: 10_000_000,
            gracefulStopTimeoutNanoseconds: 50_000_000
        )

        let created = try await coordinator.createVMFromImage(name: "t1", imageID: entry.id)
        let vmID = created.vmRecord.id

        // Manually stamp non-simulated `running` into SQLite while `hardwareBoxes[vmID]` is nil in `coordinator`.
        var staleRunning = created.vmRecord
        staleRunning.telemetry.state = .running
        staleRunning.telemetry.simulated = false
        staleRunning.telemetry.guestAgentConnected = true
        try await coordinator.store.upsertVM(staleRunning)

        // Case A: Another process holds the lock -> must NOT return fake idempotent success; must fail ERR_VM_LOCKED.
        let lockURL = coordinator.lockFileURL(for: vmID)
        do {
            let foreignLock = try VMExecutionLock.acquire(at: lockURL, vmName: "t1")
            defer { foreignLock.release() }
            do {
                _ = try await coordinator.bootVM(vmID)
                Issue.record("Expected bootVM to fail with ERR_VM_LOCKED when SQLite says running, hardwareBoxes is nil, and foreign lock is held")
            } catch let err as AgentVMError {
                #expect(err.errorCode == "ERR_VM_LOCKED")
            }
            #expect(mockBackend.startCount == 0)
        }

        // Case B: No process holds the lock, SQLite still says `running`, `hardwareBoxes[vmID]` is nil ->
        // must NOT return without starting; must actually call `startMachine` and hold the live instance!
        let booted = try await coordinator.bootVM(vmID)
        #expect(booted.telemetry.state == .running)
        #expect(mockBackend.startCount == 1)
        #expect(try await coordinator.daemonHeldVMs().map(\.id) == [vmID])

        // Case C: Now both SQLite is `running` AND `hardwareBoxes[vmID] != nil` -> idempotent return, startCount stays 1.
        let bootedAgain = try await coordinator.bootVM(vmID)
        #expect(bootedAgain.telemetry.state == .running)
        #expect(mockBackend.startCount == 1)

        _ = try await coordinator.haltVM(vmID)
        #expect(VMExecutionLock.isLocked(at: lockURL) == false)
    }

    // MARK: - Item 4 (A40): Re-Read Manifest Policy Before Every `up` (`airgap` -> Exit 1 `ERR_AIRGAP_UNSUPPORTED`)

    @Test("Item 4a (A40): mutating manifest.json via a second AgentVMProjectStore causes subsequent boot on the same coordinator to be rejected")
    func secondStoreManifestMutationBlocksSubsequentBootOnSameCoordinatorA40() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-s3a-i4a")
        defer { try? FileManager.default.removeItem(atPath: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/A40Store.agentvm", isDirectory: true)
        let mockBackend = Stage3aMockHardwareBackend()
        defer { mockBackend.closeAllDescriptors() }

        let coordinator = try AgentVMFleetCoordinator(
            bundleURL: wsURL,
            executionBackend: .strictHardwareVZ,
            isWorkspaceDaemon: true,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mockBackend,
            vsockConnectTimeoutNanoseconds: 5_000_000_000,
            vsockRetryIntervalNanoseconds: 10_000_000,
            gracefulStopTimeoutNanoseconds: 50_000_000
        )

        let created = try await coordinator.createVMFromImage(name: "t1", imageID: entry.id)
        let vmID = created.vmRecord.id
        let lockURL = coordinator.lockFileURL(for: vmID)

        // Mutate manifest.json through a completely separate AgentVMProjectStore instance (simulating another CLI process).
        let secondStore = try AgentVMProjectStore(bundleURL: wsURL, createIfMissing: false)
        var manifest = try await secondStore.loadManifest()
        manifest.activeFirewallPolicyID = PolicySetID("pol-airgap")
        manifest.updatedAt = Date()
        try await secondStore.saveManifest(manifest)

        var caughtError: AgentVMError?
        do {
            _ = try await coordinator.bootVM(vmID)
        } catch let err as AgentVMError {
            caughtError = err
        }
        let err = try #require(caughtError, "Expected coordinator.bootVM to reject boot after secondStore set airgap in manifest.json")
        #expect(err == .airgapPolicyUnsupportedBeforeM5(vmName: "t1"))
        #expect(err.errorCode == "ERR_AIRGAP_UNSUPPORTED")
        #expect(mockBackend.startCount == 0)
        #expect(VMExecutionLock.isLocked(at: lockURL) == false)

        // Flip manifest back to strict via secondStore -> same coordinator now allows booting t1.
        var strictManifest = try await secondStore.loadManifest()
        strictManifest.activeFirewallPolicyID = PolicySetID("pol-strict-agent-allowlist")
        strictManifest.updatedAt = Date()
        try await secondStore.saveManifest(strictManifest)

        let booted = try await coordinator.bootVM(vmID)
        #expect(booted.telemetry.state == .running)
        #expect(mockBackend.startCount == 1)
        _ = try await coordinator.haltVM(vmID)
    }

    @Test("Item 4b (A40): live daemon re-reads manifest policy before 'up', returning exit 1 ERR_AIRGAP_UNSUPPORTED on airgap and 0 after switching to strict")
    func daemonUpReReadsManifestAirgapPolicyExiting1AndRecoversOnStrictA40() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-s3a-i4b")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/A40Daemon.agentvm", isDirectory: true)
        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()
        let forbiddenSpawn = DaemonSpawnCommandOverride(
            executablePath: "/bin/sh",
            arguments: ["-c", "exit 95"],
            environment: env
        )

        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "create", "t1", "--image", entry.id],
            curatedEntriesOverride: [entry],
            environment: env
        ).exitCode == 0)
        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "create", "t2", "--image", entry.id],
            curatedEntriesOverride: [entry],
            environment: env
        ).exitCode == 0)

        let mockBackend = Stage3aMockHardwareBackend()
        defer { mockBackend.closeAllDescriptors() }

        try await withStartedDaemonServer(
            workspaceURL: wsURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mockBackend
        ) { _ in
            // Boot t1 while policy is default (strict).
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
            #expect(mockBackend.startCount == 1)

            // Another CLI invocation sets `policy airgap` in manifest.json while daemon stays running.
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "policy", "airgap"],
                curatedEntriesOverride: [entry],
                environment: env
            ).exitCode == 0)

            // Daemon `up t2` must re-read manifest, reject with exit 1 & ERR_AIRGAP_UNSUPPORTED (EN & ZH), and start nothing.
            let upAirgapEn = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t2"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(upAirgapEn.exitCode == 1)
            #expect(upAirgapEn.stderr.contains("ERR_AIRGAP_UNSUPPORTED"))
            #expect(upAirgapEn.stderr.contains("M5"))
            #expect(mockBackend.startCount == 1)

            let upAirgapZh = await cli.execute(
                arguments: ["--lang", "zh", "--workspace", wsURL.path, "up", "t2"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(upAirgapZh.exitCode == 1)
            #expect(upAirgapZh.stderr.contains("ERR_AIRGAP_UNSUPPORTED"))
            #expect(upAirgapZh.stderr.contains("M5"))
            #expect(mockBackend.startCount == 1)

            // Switch back to `policy strict`, then `up t2` succeeds -> exit 0.
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "policy", "strict"],
                curatedEntriesOverride: [entry],
                environment: env
            ).exitCode == 0)

            let upStrict = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t2"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(upStrict.exitCode == 0)
            #expect(mockBackend.startCount == 2)

            _ = await cli.execute(arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "t2"], curatedEntriesOverride: [entry], environment: env, daemonSpawnOverride: forbiddenSpawn)
            _ = await cli.execute(arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "t1"], curatedEntriesOverride: [entry], environment: env, daemonSpawnOverride: forbiddenSpawn)
        }
    }

    // MARK: - Item 5 (A39): Cross-Process Lock Protection (`snapshot`/`branch`/`restore` -> M3, MCP & UI Coordinator `up`/`halt`/`pause`/`resume`/`exec` -> M4)

    @Test("Item 5 (A39): when VM lock is held by daemon, CLI/MCP snapshot/branch/restore fail exit 1 ERR_VM_LOCKED (M3, disk inode untouched), and non-daemon coordinator & MCP up/halt/pause/resume/exec fail ERR_VM_LOCKED (M4)")
    func crossProcessLockProtectsSnapshotBranchRestoreM3AndMCPAndCoordinatorLifecycleExecM4_A39() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-s3a-i5")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/A39Protect.agentvm", isDirectory: true)
        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()
        let forbiddenSpawn = DaemonSpawnCommandOverride(
            executablePath: "/bin/sh",
            arguments: ["-c", "exit 96"],
            environment: env
        )

        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "create", "t1", "--image", entry.id],
            curatedEntriesOverride: [entry],
            environment: env
        ).exitCode == 0)

        let inspectStore = try AgentVMProjectStore(bundleURL: wsURL, createIfMissing: false)
        let createdRecord = try #require(try await inspectStore.listVMs().first(where: { $0.spec.name == "t1" }))
        let vmID = createdRecord.id
        let baseSnapID = try #require(createdRecord.currentHeadSnapshotID)
        let rootDiskPath = try #require(createdRecord.spec.blockDevices.first?.imagePath)
        var diskStatBefore = Darwin.stat()
        #expect(stat(rootDiskPath, &diskStatBefore) == 0)

        let mockBackend = Stage3aMockHardwareBackend()
        defer { mockBackend.closeAllDescriptors() }

        try await withStartedDaemonServer(
            workspaceURL: wsURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mockBackend
        ) { _ in
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)

            // 1. M3 Stage 3a/3b (A59/A60/A61): while daemon holds `t1`, CLI `snapshot`, `branch`, and `restore` all route through daemon RPC and exit 0:
            //    `snapshot` and `branch` keep parent root disk inode untouched; `restore` halts, saves pre-restore snapshot, swaps disk, and boots `t1` back to `running`.
            for lang in ["en", "zh"] {
                let snapRes = await cli.execute(
                    arguments: ["--lang", lang, "--workspace", wsURL.path, "snapshot", "t1", "live-attempt-\(lang)"],
                    curatedEntriesOverride: [entry],
                    environment: env,
                    daemonSpawnOverride: forbiddenSpawn
                )
                #expect(snapRes.exitCode == 0, "snapshot (\(lang)) exited \(snapRes.exitCode): \(snapRes.stderr)")

                let branchRes = await cli.execute(
                    arguments: ["--lang", lang, "--workspace", wsURL.path, "branch", "t1", "t1-child-\(lang)", "--no-boot"],
                    curatedEntriesOverride: [entry],
                    environment: env,
                    daemonSpawnOverride: forbiddenSpawn
                )
                #expect(branchRes.exitCode == 0, "branch (\(lang)) exited \(branchRes.exitCode): \(branchRes.stderr)")
            }

            // Root disk inode must remain untouched across live `snapshot` and `branch`!
            var diskStatAfterSnapBranch = Darwin.stat()
            #expect(stat(rootDiskPath, &diskStatAfterSnapBranch) == 0)
            #expect(diskStatAfterSnapBranch.st_ino == diskStatBefore.st_ino)

            for lang in ["en", "zh"] {
                let restoreRes = await cli.execute(
                    arguments: ["--lang", lang, "--workspace", wsURL.path, "restore", baseSnapID.rawValue],
                    curatedEntriesOverride: [entry],
                    environment: env,
                    daemonSpawnOverride: forbiddenSpawn
                )
                #expect(restoreRes.exitCode == 0, "restore (\(lang)) exited \(restoreRes.exitCode): \(restoreRes.stderr)")
                #expect(restoreRes.stdout.contains("snap-"))
                #expect(!restoreRes.stderr.contains("M3"))
            }

            // Root disk inode was swapped by live `restore`, and `t1` is booted back to `running`!
            var diskStatAfter = Darwin.stat()
            #expect(stat(rootDiskPath, &diskStatAfter) == 0)
            #expect(diskStatAfter.st_ino != diskStatBefore.st_ino)
            let dbRecAfterCLI = try #require(try await inspectStore.fetchVM(vmID))
            #expect(dbRecAfterCLI.telemetry.state == .running)
            #expect(dbRecAfterCLI.telemetry.guestAgentConnected == true)

            // 2. Separate non-daemon AgentVMFleetCoordinator (used by Studio UI & MCP, no GUI started):
            //    `bootPersistentVM` (up), `haltVM` (halt), `pauseVM` (pause), `resumeVM` (resume), `executeInGuest` (exec)
            //    must ALL fail with ERR_VM_LOCKED and explain M4 in both EN and ZH without altering SQLite state!
            let externalCoordinator = try AgentVMFleetCoordinator(
                bundleURL: wsURL,
                executionBackend: .strictHardwareVZ,
                imageCacheDirectoryURL: cacheDir,
                curatedImageEntries: [entry]
            )

            let uiLifecycleChecks: [(String, () async throws -> Void)] = [
                ("up", { _ = try await externalCoordinator.bootPersistentVM(vmID) }),
                ("halt", { _ = try await externalCoordinator.haltVM(vmID) }),
                ("pause", { _ = try await externalCoordinator.pauseVM(vmID) }),
                ("resume", { _ = try await externalCoordinator.resumeVM(vmID) }),
                ("exec", { _ = try await externalCoordinator.executeInGuest(vmID: vmID, request: GuestExecRequest(executable: "true")) })
            ]
            for (opName, call) in uiLifecycleChecks {
                var caught: AgentVMError?
                do {
                    try await call()
                } catch let err as AgentVMError {
                    caught = err
                }
                let err = try #require(caught, "Expected non-daemon coordinator '\(opName)' to throw ERR_VM_LOCKED")
                #expect(err.errorCode == "ERR_VM_LOCKED")
                #expect(err.localizedMessage(in: .en).contains("M4"))
                #expect(err.localizedMessage(in: .zhHans).contains("M4"))
            }

            // Verify external coordinator did NOT overwrite daemon's `running` state in SQLite!
            let dbRecAfterCoord = try #require(try await inspectStore.fetchVM(vmID))
            #expect(dbRecAfterCoord.telemetry.state == .running)

            // 3. MCP JSON-RPC server (`AgentVMMCPServer`): in M4 Stage 3, `snapshot`, `branch`, `restore`, and `exec` all route through daemon RPC and succeed
            //    (while direct non-daemon coordinator calls above continue to reject with ERR_VM_LOCKED).
            let mcp = AgentVMMCPServer(coordinator: externalCoordinator)
            let mcpSuccessCalls: [(String, [String: Any])] = [
                ("agentvm_capture_snapshot", ["vmID": vmID.rawValue, "title": "mcp-snap"]),
                ("agentvm_fork_cow_branch", ["parentVMID": vmID.rawValue, "branchName": "mcp-child", "bootImmediately": false]),
                ("agentvm_restore_snapshot", ["snapshotID": baseSnapID.rawValue]),
                ("agentvm_exec_command", ["vmID": vmID.rawValue, "executable": "uname", "arguments": ["-r"]])
            ]
            for (idx, item) in mcpSuccessCalls.enumerated() {
                let reqObj: [String: Any] = [
                    "jsonrpc": "2.0",
                    "id": idx + 1,
                    "method": "tools/call",
                    "params": [
                        "name": item.0,
                        "arguments": item.1
                    ]
                ]
                let reqLine = String(decoding: try JSONSerialization.data(withJSONObject: reqObj), as: UTF8.self)
                let respLine = try #require(await mcp.handleJSONRPCLine(reqLine))
                let respObj = try #require(try JSONSerialization.jsonObject(with: Data(respLine.utf8)) as? [String: Any])
                let resultObj = try #require(respObj["result"] as? [String: Any])
                #expect((resultObj["isError"] as? Bool) == false, "Expected MCP \(item.0) to route via daemon and succeed: \(respLine)")
            }

            // Daemon still holds `t1` in `running` state and halts it cleanly.
            let psCheck = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "ps", "--json"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(psCheck.exitCode == 0)
            #expect(psCheck.stdout.contains("\"state\" : \"running\""))

            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
        }
    }

    // MARK: - Item 7 (Hypothesis 12): Two OS Processes, Separate AgentVMProjectStore Instances, 5s Telemetry Writes vs 20 `ps` Reads Over 30s

    @Test("Item 7 (Hypothesis 12): two separate OS processes each open AgentVMProjectStore — one writes telemetry every 5s and the other runs 20 'ps' read paths over 30s with zero SQLITE_BUSY")
    func hypothesis12TwoProcessesConcurrentTelemetryWritesAndPsReadsNoSQLiteBusy() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-s3a-h12")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/H12Concurrent.agentvm", isDirectory: true)
        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)

        let setupCoordinator = try AgentVMFleetCoordinator(
            bundleURL: wsURL,
            executionBackend: .strictHardwareVZ
        )
        let t1Created = try await setupCoordinator.createSandboxVM(name: "t1", diskVirtualBytes: 16 * 1024 * 1024)
        _ = try await setupCoordinator.createSandboxVM(name: "t2", diskVirtualBytes: 16 * 1024 * 1024)
        let t1ID = t1Created.vmRecord.id

        // Process 1 (`getpid()`) opens its own dedicated AgentVMProjectStore and holds t1's execution lock
        // so Process 2's `ps` read path (`listVMsForReporting`) observes a live running hardware VM.
        let writerStore = try AgentVMProjectStore(bundleURL: wsURL, createIfMissing: false)
        let dbConfig = try await writerStore.databaseJournalAndBusyTimeout()
        #expect(dbConfig.journalMode.lowercased() == "wal")
        #expect(dbConfig.busyTimeoutMilliseconds >= 5_000)

        let lockURL = wsURL.appendingPathComponent("locks/\(t1ID.rawValue).lock", isDirectory: false)
        let t1Lock = try VMExecutionLock.acquire(at: lockURL, vmName: "t1")
        defer { t1Lock.release() }

        var seedRecord = try #require(try await writerStore.fetchVM(t1ID))
        seedRecord.telemetry.state = .running
        seedRecord.telemetry.simulated = false
        seedRecord.telemetry.guestAgentConnected = true
        seedRecord.telemetry.hasLiveGuestTelemetry = true
        seedRecord.telemetry.uptimeSeconds = 0
        seedRecord.telemetry.sampledAt = Date()
        try await writerStore.upsertVM(seedRecord)

        // Process 2 (`childProc.processIdentifier != getpid()`) runs `AgentVM --lang en --workspace <ws> mcp`
        // (headless stdio, zero GUI, zero network), opening its own single AgentVMProjectStore for the entire 30s window.
        let agentVMBinaryURL = try Self.locateBuiltAgentVMExecutable()
        let stdinPipe = Pipe()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()

        let childProc = Process()
        childProc.executableURL = agentVMBinaryURL
        childProc.arguments = ["--lang", "en", "--workspace", wsURL.path, "mcp"]
        childProc.environment = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"
        ]
        childProc.standardInput = stdinPipe
        childProc.standardOutput = stdoutPipe
        childProc.standardError = stderrPipe
        try childProc.run()
        let childPID = childProc.processIdentifier
        #expect(childPID > 0 && childPID != Darwin.getpid())

        defer {
            try? stdinPipe.fileHandleForWriting.close()
            if childProc.isRunning {
                childProc.terminate()
                childProc.waitForExit()
            }
            try? stdoutPipe.fileHandleForReading.close()
            try? stderrPipe.fileHandleForReading.close()
        }

        let startNs = DispatchTime.now().uptimeNanoseconds

        // Task A (Process 1): write telemetry every 5 seconds across 30 seconds (t = 0, 5, 10, 15, 20, 25, 30s -> 7 writes).
        let writerTask = Task<Stage3aH12WriterSummary, Never> {
            var completedWrites = 0
            var sqliteBusyCount = 0
            var failureMessages: [String] = []

            for tick in 0...6 {
                let targetOffsetNs = UInt64(tick) * 5_000_000_000
                let nowNs = DispatchTime.now().uptimeNanoseconds
                let targetNs = startNs &+ targetOffsetNs
                if targetNs > nowNs {
                    try? await Task.sleep(nanoseconds: targetNs - nowNs)
                }

                do {
                    if var rec = try await writerStore.fetchVM(t1ID) {
                        rec.telemetry.state = .running
                        rec.telemetry.simulated = false
                        rec.telemetry.guestAgentConnected = true
                        rec.telemetry.hasLiveGuestTelemetry = true
                        rec.telemetry.uptimeSeconds = Double((tick + 1) * 5)
                        rec.telemetry.cpuUsagePercent = Double(12 + tick * 6)
                        rec.telemetry.memoryResidentMB = UInt64(512 + tick * 32)
                        rec.telemetry.sampledAt = Date()
                        try await writerStore.upsertVM(rec)
                        completedWrites += 1
                    } else {
                        failureMessages.append("tick \(tick): fetchVM returned nil")
                    }
                } catch let err as AgentVMError {
                    if case let .storageDatabaseError(code, _, detail) = err, code == 5 {
                        sqliteBusyCount += 1
                        failureMessages.append("tick \(tick): SQLITE_BUSY (\(detail))")
                    } else {
                        failureMessages.append("tick \(tick): \(err.errorCode) \(err.localizedDescription)")
                    }
                } catch {
                    failureMessages.append("tick \(tick): \(error.localizedDescription)")
                }
            }

            return Stage3aH12WriterSummary(
                completedWrites: completedWrites,
                sqliteBusyCount: sqliteBusyCount,
                failureMessages: failureMessages
            )
        }

        // Task B (Process 2): execute 20 `ps` read-path calls (`agentvm_list_fleet` -> `listVMsForReporting`)
        // across the 30-second window, deliberately aligning bursts on the 5s write ticks!
        let readScheduleSeconds: [Double] = [
            0.0, 1.5, 3.0,
            5.0, 5.01, 7.5,
            10.0, 10.01, 12.5,
            15.0, 15.01, 17.5,
            20.0, 20.01, 22.5,
            25.0, 25.01, 27.5,
            29.99, 30.0
        ]
        #expect(readScheduleSeconds.count == 20)

        let stdinFD = stdinPipe.fileHandleForWriting.fileDescriptor
        let stdoutFD = stdoutPipe.fileHandleForReading.fileDescriptor

        let readerTask = Task.detached(priority: .userInitiated) { () -> Stage3aH12ReaderSummary in
            let lineReader = Stage3aFDLineReader(fd: stdoutFD)
            let fleetDecoder = JSONDecoder()
            fleetDecoder.dateDecodingStrategy = .iso8601

            var completedReads = 0
            var sqliteBusyCount = 0
            var distinctUptimes = Set<Int>()
            var failureMessages: [String] = []

            for (idx, scheduledSec) in readScheduleSeconds.enumerated() {
                let targetOffsetNs = UInt64(scheduledSec * 1_000_000_000.0)
                let nowNs = DispatchTime.now().uptimeNanoseconds
                let targetNs = startNs &+ targetOffsetNs
                if targetNs > nowNs {
                    try? await Task.sleep(nanoseconds: targetNs - nowNs)
                }

                let reqID = idx + 1
                let reqLine = "{\"jsonrpc\":\"2.0\",\"id\":\(reqID),\"method\":\"tools/call\",\"params\":{\"name\":\"agentvm_list_fleet\",\"arguments\":{}}}\n"
                guard Stage3aFDLineReader.writeAll(fd: stdinFD, data: Data(reqLine.utf8)) else {
                    failureMessages.append("read #\(reqID): failed writing MCP request to Process 2 stdin")
                    break
                }

                guard let respLine = lineReader.readLine() else {
                    failureMessages.append("read #\(reqID): unexpected EOF from Process 2 stdout")
                    break
                }

                guard let respObj = (try? JSONSerialization.jsonObject(with: Data(respLine.utf8))) as? [String: Any],
                      let resultObj = respObj["result"] as? [String: Any],
                      let contentArr = resultObj["content"] as? [[String: Any]] else {
                    failureMessages.append("read #\(reqID): malformed JSON-RPC response: \(respLine)")
                    continue
                }

                let isError = (resultObj["isError"] as? Bool) ?? false
                let combinedText = contentArr.compactMap { $0["text"] as? String }.joined(separator: "\n")
                if isError {
                    if combinedText.contains("SQLite error (5)")
                        || combinedText.localizedCaseInsensitiveContains("database is locked")
                        || combinedText.localizedCaseInsensitiveContains("SQLITE_BUSY") {
                        sqliteBusyCount += 1
                    }
                    failureMessages.append("read #\(reqID): \(combinedText)")
                    continue
                }

                do {
                    let decodedVMs = try fleetDecoder.decode([VMInstanceRecord].self, from: Data(combinedText.utf8))
                    if let t1 = decodedVMs.first(where: { $0.id == t1ID }),
                       decodedVMs.count == 2,
                       t1.telemetry.state == .running {
                        completedReads += 1
                        distinctUptimes.insert(Int(t1.telemetry.uptimeSeconds.rounded()))
                    } else {
                        failureMessages.append("read #\(reqID): unexpected fleet snapshot count=\(decodedVMs.count)")
                    }
                } catch {
                    failureMessages.append("read #\(reqID): fleet JSON decode failed: \(error.localizedDescription)")
                }
            }

            return Stage3aH12ReaderSummary(
                completedReads: completedReads,
                sqliteBusyCount: sqliteBusyCount,
                distinctObservedUptimeCount: distinctUptimes.count,
                failureMessages: failureMessages
            )
        }

        let writerSummary = await writerTask.value
        let readerSummary = await readerTask.value
        let elapsedSeconds = Double(DispatchTime.now().uptimeNanoseconds - startNs) / 1_000_000_000.0

        try? stdinPipe.fileHandleForWriting.close()
        #expect(childProc.waitForExit(), "childProc did not exit within 60 seconds")
        #expect(childProc.terminationStatus == 0)

        #expect(elapsedSeconds >= 29.9, "Expected 30s Hypothesis 12 window, elapsed=\(elapsedSeconds)s")
        #expect(writerSummary.sqliteBusyCount == 0, "Writer SQLITE_BUSY errors: \(writerSummary.failureMessages)")
        #expect(readerSummary.sqliteBusyCount == 0, "Reader SQLITE_BUSY errors: \(readerSummary.failureMessages)")
        #expect(writerSummary.failureMessages.isEmpty, "Writer failures: \(writerSummary.failureMessages)")
        #expect(readerSummary.failureMessages.isEmpty, "Reader failures: \(readerSummary.failureMessages)")
        #expect(writerSummary.completedWrites == 7)
        #expect(readerSummary.completedReads == 20)
        #expect(readerSummary.distinctObservedUptimeCount >= 5, "Reader observed \(readerSummary.distinctObservedUptimeCount) distinct telemetry commits across processes")
    }

    private static func locateBuiltAgentVMExecutable() throws -> URL {
        let bundleDir = Bundle(for: Stage3aBundleLocatorToken.self).bundleURL.deletingLastPathComponent()
        let sibling = bundleDir.appendingPathComponent("AgentVM", isDirectory: false)
        if FileManager.default.isExecutableFile(atPath: sibling.path) {
            return sibling
        }
        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let fallbacks = [
            repoRoot.appendingPathComponent(".build/out/Products/Debug/AgentVM"),
            repoRoot.appendingPathComponent(".build/arm64-apple-macosx/debug/AgentVM"),
            repoRoot.appendingPathComponent(".build/debug/AgentVM")
        ]
        for candidate in fallbacks where FileManager.default.isExecutableFile(atPath: candidate.path) {
            return candidate
        }
        throw NSError(
            domain: "CLIAndMCPDaemonStage3aTests",
            code: 404,
            userInfo: [NSLocalizedDescriptionKey: "Unable to locate built AgentVM binary next to test bundle at \(bundleDir.path)."]
        )
    }
}

private final class Stage3aBundleLocatorToken {}

private struct Stage3aH12WriterSummary: Sendable {
    var completedWrites: Int
    var sqliteBusyCount: Int
    var failureMessages: [String]
}

private struct Stage3aH12ReaderSummary: Sendable {
    var completedReads: Int
    var sqliteBusyCount: Int
    var distinctObservedUptimeCount: Int
    var failureMessages: [String]
}

private final class Stage3aFDLineReader {
    private let fd: Int32
    private var buffer = Data()

    init(fd: Int32) {
        self.fd = fd
    }

    func readLine() -> String? {
        let newline = UInt8(ascii: "\n")
        var chunk = [UInt8](repeating: 0, count: 65_536)
        while true {
            if let nlIndex = buffer.firstIndex(of: newline) {
                let lineData = buffer.subdata(in: buffer.startIndex..<nlIndex)
                buffer.removeSubrange(buffer.startIndex...nlIndex)
                return String(decoding: lineData, as: UTF8.self)
            }
            let n = Darwin.read(fd, &chunk, chunk.count)
            if n > 0 {
                buffer.append(contentsOf: chunk.prefix(n))
            } else if n < 0 && Darwin.errno == EINTR {
                continue
            } else {
                if buffer.isEmpty {
                    return nil
                }
                let remaining = buffer
                buffer.removeAll()
                return String(decoding: remaining, as: UTF8.self)
            }
        }
    }

    static func writeAll(fd: Int32, data: Data) -> Bool {
        data.withUnsafeBytes { rawBuf in
            guard let base = rawBuf.baseAddress else { return true }
            var offset = 0
            while offset < rawBuf.count {
                let n = Darwin.write(fd, base.advanced(by: offset), rawBuf.count - offset)
                if n > 0 {
                    offset += n
                } else if n < 0 && Darwin.errno == EINTR {
                    continue
                } else {
                    return false
                }
            }
            return true
        }
    }
}

// MARK: - Deterministic Mock Hardware Backend for Stage 3a Tests

private final class Stage3aMockHardwareBackend: HardwareVMLowLevelBackend, @unchecked Sendable {
    private let lock = NSLock()
    private let startDelayNanoseconds: UInt64
    private let shutdownDelayNanoseconds: UInt64
    private let failStartImmediately: Bool
    private let lockURLToInspect: URL?
    private let storeToInspect: AgentVMProjectStore?

    private var activeOps = 0
    private(set) var maxConcurrentLifecycleOps = 0
    private(set) var startCount = 0
    private(set) var pauseCount = 0
    private(set) var resumeCount = 0
    private(set) var shutdownCount = 0
    private(set) var wasLockedDuringStartMachine = false
    private(set) var wasLockedDuringShutdown = false
    private(set) var dbStateDuringShutdown: VMLifecycleState?
    private var openFDs: [Int32] = []

    init(
        startDelayNanoseconds: UInt64 = 0,
        shutdownDelayNanoseconds: UInt64 = 0,
        failStartImmediately: Bool = false,
        lockURLToInspect: URL? = nil,
        storeToInspect: AgentVMProjectStore? = nil
    ) {
        self.startDelayNanoseconds = startDelayNanoseconds
        self.shutdownDelayNanoseconds = shutdownDelayNanoseconds
        self.failStartImmediately = failStartImmediately
        self.lockURLToInspect = lockURLToInspect
        self.storeToInspect = storeToInspect
    }

    fileprivate func enterOp() {
        lock.withLock {
            activeOps += 1
            if activeOps > maxConcurrentLifecycleOps {
                maxConcurrentLifecycleOps = activeOps
            }
        }
    }

    fileprivate func leaveOp() {
        lock.withLock {
            activeOps = max(0, activeOps - 1)
        }
    }

    fileprivate func recordPause() {
        lock.withLock { pauseCount += 1 }
    }

    fileprivate func recordResume() {
        lock.withLock { resumeCount += 1 }
    }

    fileprivate func recordShutdown(locked: Bool, dbState: VMLifecycleState?) {
        lock.withLock {
            shutdownCount += 1
            wasLockedDuringShutdown = locked
            dbStateDuringShutdown = dbState
        }
    }

    fileprivate func registerFD(_ fd: Int32) {
        lock.withLock { openFDs.append(fd) }
    }

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
        enterOp()
        defer { leaveOp() }

        _ = try translator.buildVZConfiguration(
            from: spec,
            networkSocketFD: networkSocketFD,
            serialLogFileURL: consoleLogURL,
            validateConfiguration: false
        )
        let lockedNow = lockURLToInspect.map { VMExecutionLock.isLocked(at: $0) } ?? false
        lock.withLock {
            startCount += 1
            wasLockedDuringStartMachine = lockedNow
        }
        if failStartImmediately {
            throw AgentVMError.virtualizationUnsupported(reason: "Unexpected startMachine call when lock should have blocked execution.")
        }
        if startDelayNanoseconds > 0 {
            try? await Task.sleep(nanoseconds: startDelayNanoseconds)
        }
        return Stage3aMockVMHandle(
            owner: self,
            vmID: spec.id,
            shutdownDelayNanoseconds: shutdownDelayNanoseconds,
            lockURLToInspect: lockURLToInspect,
            storeToInspect: storeToInspect
        )
    }
}

private final class Stage3aMockVMHandle: HardwareVMInstanceHandle, @unchecked Sendable {
    private unowned let owner: Stage3aMockHardwareBackend
    private let vmID: VMID
    private let shutdownDelayNanoseconds: UInt64
    private let lockURLToInspect: URL?
    private let storeToInspect: AgentVMProjectStore?
    private let stateLock = NSLock()
    private var hostFD: Int32 = -1
    private var peerFD: Int32 = -1
    private var responderTask: Task<Void, Never>?

    init(
        owner: Stage3aMockHardwareBackend,
        vmID: VMID,
        shutdownDelayNanoseconds: UInt64,
        lockURLToInspect: URL?,
        storeToInspect: AgentVMProjectStore?
    ) {
        self.owner = owner
        self.vmID = vmID
        self.shutdownDelayNanoseconds = shutdownDelayNanoseconds
        self.lockURLToInspect = lockURLToInspect
        self.storeToInspect = storeToInspect
    }

    func prematureStopReason() -> String? { nil }

    func connectVsock(port: UInt32) async throws -> HardwareVsockFDDescriptor {
        await closeVsockConnection()
        var fds: [Int32] = [-1, -1]
        guard Darwin.socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(Darwin.errno))
        }
        var one: Int32 = 1
        _ = Darwin.setsockopt(fds[0], SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        _ = Darwin.setsockopt(fds[1], SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        let hFD = fds[0]
        let pFD = fds[1]

        let task = Task.detached {
            let codec = VsockWireCodec()
            let acc = VsockStreamAccumulator(codec: codec)
            var buf = [UInt8](repeating: 0, count: 65_536)
            var execBuffers: [UInt32: Data] = [:]
            var seq: UInt32 = 0

            func writeFrame(channel: VsockChannelKind, flags: VsockFrameFlags, streamID: UInt32, payload: Data) {
                seq &+= 1
                guard let wire = try? codec.encodeFrame(
                    channel: channel,
                    flags: flags,
                    streamID: streamID,
                    sequence: seq,
                    windowCredit: VsockWireConstants.defaultWindowCredit,
                    payload: payload,
                    compressIfBeneficial: false
                ) else { return }
                wire.withUnsafeBytes { rawBuf in
                    guard let base = rawBuf.baseAddress else { return }
                    var written = 0
                    while written < rawBuf.count {
                        let n = Darwin.write(pFD, base.advanced(by: written), rawBuf.count - written)
                        if n > 0 {
                            written += n
                        } else if n < 0 && Darwin.errno == EINTR {
                            continue
                        } else {
                            break
                        }
                    }
                }
            }

            while !Task.isCancelled {
                let n = Darwin.read(pFD, &buf, buf.count)
                if n == 0 { break }
                if n < 0 {
                    if Darwin.errno == EINTR { continue }
                    break
                }
                guard let frames = try? acc.ingest(Data(buf[0..<n])) else { break }
                for (header, payload) in frames {
                    switch header.channel {
                    case .control:
                        if let pongData = try? VsockWireJSON.encode(VsockControlEnvelope(kind: .pong, agentVersion: "2")) {
                            writeFrame(channel: .control, flags: [.ack, .endOfMessage], streamID: 0, payload: pongData)
                        }
                    case .execProcess:
                        if header.flags.contains(.rst) {
                            execBuffers.removeValue(forKey: header.streamID)
                            continue
                        }
                        if !payload.isEmpty {
                            execBuffers[header.streamID, default: Data()].append(payload)
                        }
                        if header.flags.contains(.endOfMessage),
                           let reqBytes = execBuffers.removeValue(forKey: header.streamID),
                           let req = try? VsockWireJSON.decode(GuestExecRequest.self, from: reqBytes),
                           let doneData = try? VsockWireJSON.encode(
                               VsockExecCompletionEnvelope(requestID: req.id, exitCode: 0, durationMilliseconds: 1, timedOut: false)
                           ) {
                            writeFrame(channel: .execProcess, flags: [.fin, .endOfMessage], streamID: header.streamID, payload: doneData)
                        }
                    default:
                        break
                    }
                }
            }
        }

        stateLock.withLock {
            hostFD = hFD
            peerFD = pFD
            responderTask = task
        }
        return HardwareVsockFDDescriptor(fileDescriptor: hFD, closeWhenSessionEnds: false)
    }

    func closeVsockConnection() async {
        let (h, p, t) = stateLock.withLock { () -> (Int32, Int32, Task<Void, Never>?) in
            let curH = hostFD
            let curP = peerFD
            let curT = responderTask
            hostFD = -1
            peerFD = -1
            responderTask = nil
            return (curH, curP, curT)
        }
        t?.cancel()
        if p >= 0 {
            _ = Darwin.shutdown(p, SHUT_RDWR)
            _ = Darwin.close(p)
        }
        if h >= 0 {
            _ = Darwin.shutdown(h, SHUT_RDWR)
            _ = Darwin.close(h)
        }
    }

    func pause() async throws {
        owner.enterOp()
        defer { owner.leaveOp() }
        owner.recordPause()
    }

    func resume() async throws {
        owner.enterOp()
        defer { owner.leaveOp() }
        owner.recordResume()
    }

    func saveMachineState(to url: URL) async throws {}

    func shutdown(gracefulTimeoutNanoseconds: UInt64) async {
        owner.enterOp()
        defer { owner.leaveOp() }
        let lockedNow = lockURLToInspect.map { VMExecutionLock.isLocked(at: $0) } ?? false
        let dbState = try? await storeToInspect?.fetchVM(vmID)?.telemetry.state
        owner.recordShutdown(locked: lockedNow, dbState: dbState)
        if shutdownDelayNanoseconds > 0 {
            try? await Task.sleep(nanoseconds: shutdownDelayNanoseconds)
        }
        await closeVsockConnection()
    }
}
