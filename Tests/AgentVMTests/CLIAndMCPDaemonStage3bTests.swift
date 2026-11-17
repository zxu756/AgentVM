import AgentVMCLIAndMCP
import AgentVMHypervisor
import AgentVMModels
import AgentVMStorageCoW
import AgentVMStore
import AgentVMVsockRPC
import Darwin
import Foundation
import Testing

@Suite("M2 Stage 3b: Stop Observation (A33), Daemon Stop VM_STOPPED & Vsock EOF Reconnect (A34)", .timeLimit(.minutes(2)))
struct CLIAndMCPDaemonStage3bTests {

    private func makePrivateTmpDirectory(prefix: String = "avm-s3b") throws -> String {
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
        vsockRetryIntervalNanoseconds: UInt64 = 50_000_000,
        gracefulStopTimeoutNanoseconds: UInt64 = 120_000_000,
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
            throw NSError(domain: "CLIAndMCPDaemonStage3bTests", code: 1)
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

    private func decodeJSON<T: Decodable>(_ type: T.Type, from text: String) throws -> T {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(T.self, from: Data(text.utf8))
    }

    // MARK: - Item 1: Spontaneous Stop Observation (`guestDidStop`, `didStopWithError`) & `halt` `VM_STOPPED` (A33)

    @Test("Item 1 (A33): spontaneous guestDidStop and didStopWithError mark VM stopped within 5s, record diagnostics, release lock, and fail in-flight exec with 125; halt records VM_STOPPED with guest-shutdown or hard-stop")
    func stopObservationGuestDidStopDidStopWithErrorAndHaltVMStoppedReasonsA33() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-s3b-i1")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/StopObsA33.agentvm", isDirectory: true)
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
        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "create", "t2", "--image", entry.id],
            curatedEntriesOverride: [entry],
            environment: env
        ).exitCode == 0)

        let inspectStore = try AgentVMProjectStore(bundleURL: wsURL, createIfMissing: false)
        let allCreated = try await inspectStore.listVMs()
        let t1ID = try #require(allCreated.first(where: { $0.spec.name == "t1" })?.id)
        let t2ID = try #require(allCreated.first(where: { $0.spec.name == "t2" })?.id)
        let t1LockURL = inspectStore.locksDirectoryURL.appendingPathComponent("\(t1ID.rawValue).lock", isDirectory: false)
        let t2LockURL = inspectStore.locksDirectoryURL.appendingPathComponent("\(t2ID.rawValue).lock", isDirectory: false)

        let stepSignal = Stage3bStepSignal()
        let gate1 = Stage3bBlockingGate(maxBlockMilliseconds: 1_500)
        let gate2 = Stage3bBlockingGate(maxBlockMilliseconds: 1_500)

        let mockBackend = Stage3bControllableHardwareBackend { _, streamID, req, writer in
            switch req.executable {
            case "hang-on-t1":
                stepSignal.signal(1)
                gate1.wait(timeoutMilliseconds: 1_500)
                // Fallback completion with exitCode 99 only if host failed to abort exec on VM stop!
                _ = writer.sendCompletion(streamID: streamID, requestID: req.id, exitCode: 99)
            case "hang-on-t2":
                stepSignal.signal(2)
                gate2.wait(timeoutMilliseconds: 1_500)
                _ = writer.sendCompletion(streamID: streamID, requestID: req.id, exitCode: 98)
            default:
                _ = writer.sendOutputChunk(streamID: streamID, requestID: req.id, stream: .stdout, seq: 1, data: Data("ok\n".utf8))
                _ = writer.sendCompletion(streamID: streamID, requestID: req.id, exitCode: 0)
            }
        }
        defer {
            gate1.open()
            gate2.open()
            mockBackend.shutdownAll()
        }

        try await withStartedDaemonServer(
            workspaceURL: wsURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mockBackend,
            gracefulStopTimeoutNanoseconds: 120_000_000
        ) { _ in
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t2"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
            #expect(VMExecutionLock.isLocked(at: t1LockURL) == true)
            #expect(VMExecutionLock.isLocked(at: t2LockURL) == true)

            // 1a. Spontaneous `guestDidStop` on `t1` while `exec` is in flight:
            //     in-flight exec exits 125 promptly, DB becomes `stopped`, `VM_STOPPED_BY_GUEST` is recorded, and lock is released.
            let t1Handle1 = try #require(mockBackend.latestHandle(for: t1ID))
            async let inflightExec1 = cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "exec", "t1", "--", "hang-on-t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(await stepSignal.wait(for: 1, timeoutSeconds: 2.0) == true)

            let stopT0 = DispatchTime.now().uptimeNanoseconds
            t1Handle1.simulateSpontaneousGuestDidStop(closeVsockFirst: false)

            let exec1Res = await inflightExec1
            gate1.open()
            #expect(exec1Res.exitCode == 125, "In-flight exec on t1 should fail with 125 when guestDidStop fires, got \(exec1Res.exitCode)")

            var t1StoppedObserved = false
            while DispatchTime.now().uptimeNanoseconds - stopT0 < 5_000_000_000 {
                let psRes = await cli.execute(
                    arguments: ["--lang", "en", "--workspace", wsURL.path, "ps", "--json"],
                    curatedEntriesOverride: [entry],
                    environment: env,
                    daemonSpawnOverride: forbiddenSpawn
                )
                if psRes.exitCode == 0,
                   let vms = try? decodeJSON([VMInstanceRecord].self, from: psRes.stdout),
                   let t1Rec = vms.first(where: { $0.id == t1ID }),
                   t1Rec.telemetry.state == .stopped,
                   t1Rec.telemetry.guestAgentConnected == false,
                   !VMExecutionLock.isLocked(at: t1LockURL) {
                    t1StoppedObserved = true
                    break
                }
                try? await Task.sleep(nanoseconds: 20_000_000)
            }
            #expect(t1StoppedObserved == true, "t1 must transition to stopped with lock released within 5s of guestDidStop")

            let evT1En = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "events", "--vm", "t1", "--json"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(evT1En.exitCode == 0)
            let t1Events = try decodeJSON([DiagnosticEvent].self, from: evT1En.stdout)
            #expect(t1Events.contains(where: { $0.code == "VM_STOPPED_BY_GUEST" && $0.vmID == t1ID }))

            // 1b. Spontaneous `didStopWithError` on `t2` while `exec` is in flight:
            //     in-flight exec exits 125, DB becomes `stopped`, `VM_STOPPED_WITH_ERROR` carries VZ's reason, and lock is released.
            let t2Handle1 = try #require(mockBackend.latestHandle(for: t2ID))
            async let inflightExec2 = cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "exec", "t2", "--", "hang-on-t2"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(await stepSignal.wait(for: 2, timeoutSeconds: 2.0) == true)

            let vzErrorReason = "VZErrorDomain code=2: Virtual machine kernel panicked (simulated)"
            let errT0 = DispatchTime.now().uptimeNanoseconds
            t2Handle1.simulateSpontaneousStopWithError(vzErrorReason)

            let exec2Res = await inflightExec2
            gate2.open()
            #expect(exec2Res.exitCode == 125, "In-flight exec on t2 should fail with 125 when didStopWithError fires, got \(exec2Res.exitCode)")

            var t2StoppedObserved = false
            while DispatchTime.now().uptimeNanoseconds - errT0 < 5_000_000_000 {
                let psRes = await cli.execute(
                    arguments: ["--lang", "en", "--workspace", wsURL.path, "ps", "--json"],
                    curatedEntriesOverride: [entry],
                    environment: env,
                    daemonSpawnOverride: forbiddenSpawn
                )
                if psRes.exitCode == 0,
                   let vms = try? decodeJSON([VMInstanceRecord].self, from: psRes.stdout),
                   let t2Rec = vms.first(where: { $0.id == t2ID }),
                   t2Rec.telemetry.state == .stopped,
                   t2Rec.telemetry.guestAgentConnected == false,
                   !VMExecutionLock.isLocked(at: t2LockURL) {
                    t2StoppedObserved = true
                    break
                }
                try? await Task.sleep(nanoseconds: 20_000_000)
            }
            #expect(t2StoppedObserved == true, "t2 must transition to stopped with lock released within 5s of didStopWithError")

            let evT2En = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "events", "--vm", "t2", "--json"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(evT2En.exitCode == 0)
            let t2EventsEn = try decodeJSON([DiagnosticEvent].self, from: evT2En.stdout)
            let errDiagEn = t2EventsEn.first(where: { $0.code == "VM_STOPPED_WITH_ERROR" && $0.vmID == t2ID })
            #expect(errDiagEn != nil)
            if let errDiagEn {
                #expect(errDiagEn.message.contains("Virtual machine kernel panicked (simulated)"))
            }

            let evT2Zh = await cli.execute(
                arguments: ["--lang", "zh", "--workspace", wsURL.path, "events", "--vm", "t2", "--json"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            let t2EventsZh = try decodeJSON([DiagnosticEvent].self, from: evT2Zh.stdout)
            let errDiagZh = t2EventsZh.first(where: { $0.code == "VM_STOPPED_WITH_ERROR" && $0.vmID == t2ID })
            #expect(errDiagZh != nil)
            if let errDiagZh {
                #expect(errDiagZh.message.contains("Virtual machine kernel panicked (simulated)"))
            }

            // 1c. Re-boot `t1` and `t2` (proving locks were released!), then `halt t1` (graceful -> `guest-shutdown`)
            //     and `halt t2` (graceful timeout -> `hard-stop`).
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t2"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)

            let t1Handle2 = try #require(mockBackend.latestHandle(for: t1ID))
            t1Handle2.setShutdownBehavior(.gracefulGuestShutdown(delayNanoseconds: 15_000_000))
            let t2Handle2 = try #require(mockBackend.latestHandle(for: t2ID))
            t2Handle2.setShutdownBehavior(.timeoutThenHardStop)

            let haltT1 = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(haltT1.exitCode == 0)

            let haltT2 = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "t2"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(haltT2.exitCode == 0)

            let postHaltT1 = try decodeJSON(
                [DiagnosticEvent].self,
                from: await cli.execute(
                    arguments: ["--lang", "en", "--workspace", wsURL.path, "events", "--vm", "t1", "--json"],
                    curatedEntriesOverride: [entry],
                    environment: env,
                    daemonSpawnOverride: forbiddenSpawn
                ).stdout
            )
            let t1StoppedDiag = postHaltT1.first(where: { $0.code == "VM_STOPPED" && $0.vmID == t1ID })
            #expect(t1StoppedDiag != nil)
            #expect(t1StoppedDiag?.metadata["reason"] == "guest-shutdown")
            #expect(t1StoppedDiag?.message.contains("guest-shutdown") == true)

            let postHaltT2 = try decodeJSON(
                [DiagnosticEvent].self,
                from: await cli.execute(
                    arguments: ["--lang", "en", "--workspace", wsURL.path, "events", "--vm", "t2", "--json"],
                    curatedEntriesOverride: [entry],
                    environment: env,
                    daemonSpawnOverride: forbiddenSpawn
                ).stdout
            )
            let t2StoppedDiag = postHaltT2.first(where: { $0.code == "VM_STOPPED" && $0.vmID == t2ID })
            #expect(t2StoppedDiag != nil)
            #expect(t2StoppedDiag?.metadata["reason"] == "hard-stop")
            #expect(t2StoppedDiag?.message.contains("hard-stop") == true)
        }
    }

    // MARK: - Item 3: `daemon stop` Halts All Running VMs & Writes `VM_STOPPED` Before Deleting Socket/Symlink & Unlocking `daemon.lock`

    @Test("Item 3: 'daemon stop' shuts down all running VMs via halt flow and records VM_STOPPED before removing daemon.sock, avm-* symlink, and daemon.lock")
    func daemonStopHaltsAllVMsWritesVMStoppedBeforeRemovingSocketSymlinkAndLock() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-s3b-i3")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        // Use >= 120-byte workspace path so both direct daemon.sock and DARWIN_USER_TEMP_DIR avm-* symlink exist.
        let longWSPath = "\(realBase)/long-segment-alpha-0123456789abcdef/long-segment-beta-0123456789abcdef/long-segment-gamma-0123456789abcdef/StopAll.agentvm"
        #expect(longWSPath.utf8.count >= 120)
        let wsURL = URL(fileURLWithPath: longWSPath, isDirectory: true)
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
            arguments: ["-c", "exit 97"],
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

        let inspectStore = try AgentVMProjectStore(bundleURL: wsURL, createIfMissing: false)
        let createdVMs = try await inspectStore.listVMs()
        let t1ID = try #require(createdVMs.first(where: { $0.spec.name == "t1" })?.id)
        let t2ID = try #require(createdVMs.first(where: { $0.spec.name == "t2" })?.id)

        let paths = DaemonWorkspacePaths(workspaceURL: wsURL)
        let plan = try DaemonSocketAddressResolver.computePlan(for: wsURL)
        let symlinkURL = try #require(plan.symlinkURL)

        let shutdownProbe = Stage3bDaemonStopOrderProbe(
            directSocketPath: paths.directSocketPath,
            symlinkPath: symlinkURL.path,
            daemonLockPath: paths.lockFileURL.path
        )
        let mockBackend = Stage3bControllableHardwareBackend(
            onShutdownHook: { _ in
                shutdownProbe.sampleDuringVMShutdown()
            },
            execHandler: { _, streamID, req, writer in
                _ = writer.sendCompletion(streamID: streamID, requestID: req.id, exitCode: 0)
            }
        )
        defer { mockBackend.shutdownAll() }

        try await withStartedDaemonServer(
            workspaceURL: wsURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mockBackend,
            gracefulStopTimeoutNanoseconds: 120_000_000
        ) { _ in
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t2"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)

            let h1 = try #require(mockBackend.latestHandle(for: t1ID))
            h1.setShutdownBehavior(.gracefulGuestShutdown(delayNanoseconds: 25_000_000))
            let h2 = try #require(mockBackend.latestHandle(for: t2ID))
            h2.setShutdownBehavior(.gracefulGuestShutdown(delayNanoseconds: 25_000_000))

            let stopRes = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "daemon", "stop"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(stopRes.exitCode == 0, "daemon stop stderr: \(stopRes.stderr)")

            // During VM shutdown, socket, symlink, and non-empty daemon.lock MUST still have been present.
            let snap = shutdownProbe.snapshot()
            #expect(snap.sampleCount == 2)
            #expect(snap.allSawSocketPresent == true)
            #expect(snap.allSawSymlinkPresent == true)
            #expect(snap.allSawDaemonLockNonEmpty == true)

            // After `daemon stop` returns, socket & symlink are deleted, `daemon.lock` is cleared & unlocked,
            // and both `t1` and `t2` are `stopped` with `VM_STOPPED` (`guest-shutdown`).
            var st = Darwin.stat()
            #expect(Darwin.lstat(paths.directSocketPath, &st) != 0 && Darwin.errno == ENOENT)
            #expect(Darwin.lstat(symlinkURL.path, &st) != 0 && Darwin.errno == ENOENT)

            let lockAttrSize = (try? FileManager.default.attributesOfItem(atPath: paths.lockFileURL.path)[.size] as? UInt64) ?? 999
            #expect(lockAttrSize == 0, "daemon.lock must be truncated to 0 bytes after daemon stop")

            let eventsOut = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "events", "--json"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(eventsOut.exitCode == 0)
            let events = try decodeJSON([DiagnosticEvent].self, from: eventsOut.stdout)
            let t1Stop = events.first(where: { $0.code == "VM_STOPPED" && $0.vmID == t1ID })
            let t2Stop = events.first(where: { $0.code == "VM_STOPPED" && $0.vmID == t2ID })
            #expect(t1Stop?.metadata["reason"] == "guest-shutdown")
            #expect(t2Stop?.metadata["reason"] == "guest-shutdown")
        }
    }
}

// MARK: - Stage 3b Test Helpers (Simulated VZ Callbacks & AF_UNIX Vsock Guest Peer)

private final class Stage3bDaemonStopOrderProbe: @unchecked Sendable {
    private let lock = NSLock()
    private let directSocketPath: String
    private let symlinkPath: String
    private let daemonLockPath: String
    private var samples = 0
    private var sawSocketEveryTime = true
    private var sawSymlinkEveryTime = true
    private var sawLockNonEmptyEveryTime = true

    init(directSocketPath: String, symlinkPath: String, daemonLockPath: String) {
        self.directSocketPath = directSocketPath
        self.symlinkPath = symlinkPath
        self.daemonLockPath = daemonLockPath
    }

    func sampleDuringVMShutdown() {
        var st1 = Darwin.stat()
        let hasSock = (Darwin.lstat(directSocketPath, &st1) == 0)
        var st2 = Darwin.stat()
        let hasSym = (Darwin.lstat(symlinkPath, &st2) == 0 && (st2.st_mode & S_IFMT) == S_IFLNK)
        var st3 = Darwin.stat()
        let hasLockContent = (stat(daemonLockPath, &st3) == 0 && st3.st_size > 0)

        lock.withLock {
            samples += 1
            if !hasSock { sawSocketEveryTime = false }
            if !hasSym { sawSymlinkEveryTime = false }
            if !hasLockContent { sawLockNonEmptyEveryTime = false }
        }
    }

    func snapshot() -> (sampleCount: Int, allSawSocketPresent: Bool, allSawSymlinkPresent: Bool, allSawDaemonLockNonEmpty: Bool) {
        lock.withLock {
            (samples, sawSocketEveryTime, sawSymlinkEveryTime, sawLockNonEmptyEveryTime)
        }
    }
}

private final class Stage3bStepSignal: @unchecked Sendable {
    private let lock = NSLock()
    private var step: Int = 0

    func signal(_ value: Int) {
        lock.withLock {
            if value > step { step = value }
        }
    }

    func wait(for target: Int, timeoutSeconds: TimeInterval) async -> Bool {
        let deadline = DispatchTime.now().uptimeNanoseconds &+ UInt64(max(0.05, timeoutSeconds) * 1_000_000_000)
        while DispatchTime.now().uptimeNanoseconds < deadline {
            if lock.withLock({ step >= target }) {
                return true
            }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        return lock.withLock { step >= target }
    }
}

private final class Stage3bBlockingGate: @unchecked Sendable {
    private let lock = NSLock()
    private var readFD: Int32 = -1
    private var writeFD: Int32 = -1
    private var opened = false
    private let deadlineNs: UInt64

    init(maxBlockMilliseconds: UInt64 = 1_500) {
        self.deadlineNs = DispatchTime.now().uptimeNanoseconds &+ (maxBlockMilliseconds * 1_000_000)
        var fds: [Int32] = [-1, -1]
        if Darwin.pipe(&fds) == 0 {
            readFD = fds[0]
            writeFD = fds[1]
        } else {
            opened = true
        }
    }

    deinit {
        closeAll()
    }

    func wait(timeoutMilliseconds: Int32) {
        let nowNs = DispatchTime.now().uptimeNanoseconds
        if nowNs >= deadlineNs {
            open()
            return
        }
        let remMs = Int32(min(UInt64(timeoutMilliseconds), (deadlineNs - nowNs) / 1_000_000))
        guard remMs > 0 else {
            open()
            return
        }
        let rfd = lock.withLock { opened ? -1 : readFD }
        guard rfd >= 0 else { return }
        var pfd = Darwin.pollfd(fd: rfd, events: Int16(POLLIN | POLLHUP), revents: 0)
        _ = Darwin.poll(&pfd, 1, remMs)
    }

    func open() {
        let wfd = lock.withLock { () -> Int32 in
            if opened { return -1 }
            opened = true
            let cur = writeFD
            writeFD = -1
            return cur
        }
        if wfd >= 0 {
            var b: UInt8 = 1
            _ = Darwin.write(wfd, &b, 1)
            _ = Darwin.close(wfd)
        }
    }

    private func closeAll() {
        let (r, w) = lock.withLock { () -> (Int32, Int32) in
            opened = true
            let cr = readFD
            let cw = writeFD
            readFD = -1
            writeFD = -1
            return (cr, cw)
        }
        if w >= 0 { _ = Darwin.close(w) }
        if r >= 0 { _ = Darwin.close(r) }
    }
}

private final class Stage3bGuestWireWriter: @unchecked Sendable {
    private let lock = NSLock()
    private let codec = VsockWireCodec()
    private var fd: Int32
    private var closed = false
    private var seqByStream: [UInt32: UInt32] = [:]

    init(fd: Int32) {
        self.fd = fd
    }

    func markClosed() {
        lock.withLock {
            closed = true
            fd = -1
        }
    }

    @discardableResult
    func writeRawWireBytes(_ wire: Data) -> Bool {
        lock.lock()
        if closed || fd < 0 {
            lock.unlock()
            return false
        }
        let targetFD = fd
        let ok = wire.withUnsafeBytes { rawBuf -> Bool in
            guard let base = rawBuf.baseAddress else { return true }
            var offset = 0
            while offset < rawBuf.count {
                let n = Darwin.write(targetFD, base.advanced(by: offset), rawBuf.count - offset)
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
        lock.unlock()
        return ok
    }

    @discardableResult
    func sendRawFrame(
        channel: VsockChannelKind,
        flags: VsockFrameFlags,
        streamID: UInt32,
        windowCredit: UInt32 = VsockWireConstants.defaultWindowCredit,
        payload: Data,
        compress: Bool = false
    ) -> Bool {
        let seq = lock.withLock { () -> UInt32 in
            let next = (seqByStream[streamID] ?? 0) &+ 1
            seqByStream[streamID] = next
            return next
        }
        guard let wire = try? codec.encodeFrame(
            channel: channel,
            flags: flags,
            streamID: streamID,
            sequence: seq,
            windowCredit: windowCredit,
            payload: payload,
            compressIfBeneficial: compress
        ) else {
            return false
        }
        return writeRawWireBytes(wire)
    }

    @discardableResult
    func sendOutputChunk(
        streamID: UInt32,
        requestID: UUID,
        stream: GuestExecStreamKind,
        seq: UInt32,
        data: Data
    ) -> Bool {
        let chunk = GuestExecOutputChunk(requestID: requestID, stream: stream, sequence: seq, data: data)
        guard let payload = try? VsockWireJSON.encode(chunk) else { return false }
        return sendRawFrame(
            channel: .execProcess,
            flags: [.ack],
            streamID: streamID,
            payload: payload
        )
    }

    @discardableResult
    func sendCompletion(
        streamID: UInt32,
        requestID: UUID,
        exitCode: Int32,
        durationMs: Int = 2,
        timedOut: Bool = false
    ) -> Bool {
        let done = VsockExecCompletionEnvelope(
            requestID: requestID,
            exitCode: exitCode,
            durationMilliseconds: durationMs,
            timedOut: timedOut
        )
        guard let payload = try? VsockWireJSON.encode(done) else { return false }
        return sendRawFrame(
            channel: .execProcess,
            flags: [.fin, .endOfMessage],
            streamID: streamID,
            payload: payload
        )
    }

    @discardableResult
    func sendHeartbeat(hostname: String = "s3b-guest", uptimeSeconds: Double = 10.0) -> Bool {
        let hb = GuestHeartbeatPayload(
            hostname: hostname,
            kernelRelease: "6.1.0-54-cloud-arm64",
            uptimeSeconds: uptimeSeconds,
            loadAvg1: 0.1,
            loadAvg5: 0.1,
            loadAvg15: 0.1,
            memTotalBytes: 2_081_640_448,
            memAvailableBytes: 1_900_000_000,
            rootFilesystemUsedBytes: 1_000_000_000,
            rootFilesystemTotalBytes: 3_221_225_472
        )
        guard let payload = try? VsockWireJSON.encode(hb) else { return false }
        return sendRawFrame(
            channel: .telemetryHeartbeat,
            flags: [.ack, .endOfMessage],
            streamID: 0,
            payload: payload,
            compress: true
        )
    }
}

private enum Stage3bMockShutdownBehavior: Sendable {
    case gracefulGuestShutdown(delayNanoseconds: UInt64)
    case timeoutThenHardStop
}

private final class Stage3bControllableHardwareBackend: HardwareVMLowLevelBackend, @unchecked Sendable {
    typealias ExecHandler = @Sendable (VMID, UInt32, GuestExecRequest, Stage3bGuestWireWriter) async -> Void

    private let lock = NSLock()
    private let onShutdownHook: (@Sendable (VMID) -> Void)?
    private let execHandler: ExecHandler
    private var handlesByVM: [VMID: [Stage3bControllableVMHandle]] = [:]

    init(
        onShutdownHook: (@Sendable (VMID) -> Void)? = nil,
        execHandler: @escaping ExecHandler
    ) {
        self.onShutdownHook = onShutdownHook
        self.execHandler = execHandler
    }

    func latestHandle(for vmID: VMID) -> Stage3bControllableVMHandle? {
        lock.withLock { handlesByVM[vmID]?.last }
    }

    func shutdownAll() {
        let all = lock.withLock { () -> [Stage3bControllableVMHandle] in
            let flat = handlesByVM.values.flatMap { $0 }
            handlesByVM.removeAll()
            return flat
        }
        for h in all {
            h.forceCloseSockets()
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
        let handle = Stage3bControllableVMHandle(
            vmID: spec.id,
            onShutdownHook: onShutdownHook,
            execHandler: execHandler
        )
        lock.withLock {
            handlesByVM[spec.id, default: []].append(handle)
        }
        return handle
    }
}

private final class Stage3bControllableVMHandle: HardwareVMInstanceHandle, @unchecked Sendable {
    let vmID: VMID
    private let onShutdownHook: (@Sendable (VMID) -> Void)?
    private let execHandler: Stage3bControllableHardwareBackend.ExecHandler
    private let lock = NSLock()
    private var hostFD: Int32 = -1
    private var peerFD: Int32 = -1
    private var activeWriter: Stage3bGuestWireWriter?
    private var readLoopTask: Task<Void, Never>?
    private var stopReasonText: String?
    private var stopEventRecorded: HardwareVMStopEvent?
    private var stopObserver: (@Sendable (HardwareVMStopEvent) -> Void)?
    private var hostShutdownInitiated = false
    private var shutdownBehavior: Stage3bMockShutdownBehavior = .gracefulGuestShutdown(delayNanoseconds: 5_000_000)

    init(
        vmID: VMID,
        onShutdownHook: (@Sendable (VMID) -> Void)?,
        execHandler: @escaping Stage3bControllableHardwareBackend.ExecHandler
    ) {
        self.vmID = vmID
        self.onShutdownHook = onShutdownHook
        self.execHandler = execHandler
    }

    func setShutdownBehavior(_ behavior: Stage3bMockShutdownBehavior) {
        lock.withLock { shutdownBehavior = behavior }
    }

    func prematureStopReason() -> String? {
        lock.withLock { stopReasonText }
    }

    func setStopObserver(_ observer: (@Sendable (HardwareVMStopEvent) -> Void)?) {
        let immediate: HardwareVMStopEvent? = lock.withLock {
            if hostShutdownInitiated {
                stopObserver = nil
                return nil
            }
            if let existing = stopEventRecorded {
                stopObserver = nil
                return existing
            }
            stopObserver = observer
            return nil
        }
        if let immediate, let observer {
            observer(immediate)
        }
    }

    func simulateSpontaneousGuestDidStop(closeVsockFirst: Bool) {
        if closeVsockFirst {
            closeGuestPeerSocketOnly()
        }
        let obs = lock.withLock { () -> (@Sendable (HardwareVMStopEvent) -> Void)? in
            if stopReasonText == nil {
                stopReasonText = "guestDidStop"
            }
            if stopEventRecorded == nil {
                stopEventRecorded = .guestDidStop
            }
            guard !hostShutdownInitiated else { return nil }
            let cur = stopObserver
            stopObserver = nil
            return cur
        }
        obs?(.guestDidStop)
    }

    func simulateSpontaneousStopWithError(_ errorDescription: String) {
        let obs = lock.withLock { () -> (@Sendable (HardwareVMStopEvent) -> Void)? in
            if stopReasonText == nil {
                stopReasonText = "didStopWithError: \(errorDescription)"
            }
            if stopEventRecorded == nil {
                stopEventRecorded = .didStopWithError(errorDescription)
            }
            guard !hostShutdownInitiated else { return nil }
            let cur = stopObserver
            stopObserver = nil
            return cur
        }
        obs?(.didStopWithError(errorDescription))
    }

    func closeGuestPeerSocketOnly() {
        let (p, w, t) = lock.withLock { () -> (Int32, Stage3bGuestWireWriter?, Task<Void, Never>?) in
            let curP = peerFD
            let curW = activeWriter
            let curT = readLoopTask
            peerFD = -1
            activeWriter = nil
            readLoopTask = nil
            return (curP, curW, curT)
        }
        w?.markClosed()
        t?.cancel()
        if p >= 0 {
            _ = Darwin.shutdown(p, SHUT_RDWR)
            _ = Darwin.close(p)
        }
    }

    func connectVsock(port: UInt32) async throws -> HardwareVsockFDDescriptor {
        forceCloseSockets()
        var fds: [Int32] = [-1, -1]
        guard Darwin.socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(Darwin.errno))
        }
        var one: Int32 = 1
        _ = Darwin.setsockopt(fds[0], SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        _ = Darwin.setsockopt(fds[1], SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))

        let hFD = fds[0]
        let pFD = fds[1]
        let writer = Stage3bGuestWireWriter(fd: pFD)
        let handler = execHandler
        let myVMID = vmID

        let task = Task.detached {
            let codec = VsockWireCodec()
            let acc = VsockStreamAccumulator(codec: codec)
            var buf = [UInt8](repeating: 0, count: 65_536)
            var execBuffers: [UInt32: Data] = [:]

            _ = writer.sendHeartbeat()

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
                    case .telemetryHeartbeat:
                        _ = writer.sendHeartbeat()
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
                           let req = try? VsockWireJSON.decode(GuestExecRequest.self, from: reqBytes) {
                            let sid = header.streamID
                            Task.detached {
                                await handler(myVMID, sid, req, writer)
                            }
                        }
                    default:
                        break
                    }
                }
            }
        }

        lock.withLock {
            hostFD = hFD
            peerFD = pFD
            activeWriter = writer
            readLoopTask = task
        }
        return HardwareVsockFDDescriptor(fileDescriptor: hFD, closeWhenSessionEnds: true)
    }

    func forceCloseSockets() {
        let (h, p, w, t) = lock.withLock { () -> (Int32, Int32, Stage3bGuestWireWriter?, Task<Void, Never>?) in
            let curH = hostFD
            let curP = peerFD
            let curW = activeWriter
            let curT = readLoopTask
            hostFD = -1
            peerFD = -1
            activeWriter = nil
            readLoopTask = nil
            return (curH, curP, curW, curT)
        }
        w?.markClosed()
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

    func closeVsockConnection() async {
        closeGuestPeerSocketOnly()
    }

    func pause() async throws {}
    func resume() async throws {}
    func saveMachineState(to url: URL) async throws {}

    func shutdown(gracefulTimeoutNanoseconds: UInt64) async {
        _ = await shutdownReportingDisposition(gracefulTimeoutNanoseconds: gracefulTimeoutNanoseconds)
    }

    func shutdownReportingDisposition(gracefulTimeoutNanoseconds: UInt64) async -> HardwareVMShutdownDisposition {
        lock.withLock {
            hostShutdownInitiated = true
            stopObserver = nil
        }
        onShutdownHook?(vmID)
        let behavior = lock.withLock { shutdownBehavior }
        let disposition: HardwareVMShutdownDisposition
        switch behavior {
        case let .gracefulGuestShutdown(delayNs):
            if delayNs > 0 {
                try? await Task.sleep(nanoseconds: min(delayNs, gracefulTimeoutNanoseconds))
            }
            disposition = .guestShutdown
        case .timeoutThenHardStop:
            if gracefulTimeoutNanoseconds > 0 {
                try? await Task.sleep(nanoseconds: gracefulTimeoutNanoseconds)
            }
            disposition = .hardStop
        }
        forceCloseSockets()
        return disposition
    }
}
