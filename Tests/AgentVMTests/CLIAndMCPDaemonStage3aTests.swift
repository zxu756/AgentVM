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
