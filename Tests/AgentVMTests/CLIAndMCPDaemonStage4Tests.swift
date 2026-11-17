import AgentVMCLIAndMCP
import AgentVMHypervisor
import AgentVMModels
import AgentVMPluginHost
import AgentVMStorageCoW
import AgentVMStore
import AgentVMVsockRPC
import Darwin
import Foundation
import Testing

@Suite("M2 Stage 4: Daemon Exec Streaming, Defaults, Cancellation RST, Bounded Ledger/Queue & Plugins", .timeLimit(.minutes(2)))
struct CLIAndMCPDaemonStage4Tests {

    private func makePrivateTmpDirectory(prefix: String = "avm-s4") throws -> String {
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
            throw NSError(domain: "CLIAndMCPDaemonStage4Tests", code: 1)
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

    // MARK: - Item 1: `exec` via Daemon (Lifecycle State Guard, Defaults A42, Live Byte Streaming & Exit Codes)

    @Test("Item 1: 'exec' via daemon rejects stopped/paused VMs with 125 ERR_LIFECYCLE_STATE without auto-booting, uses root/'/'/3600s defaults (A42), streams raw bytes live, and preserves exit codes")
    func daemonExecLifecycleStateDefaultsLiveByteStreamingAndExitCodes() async throws {
        // 0. GuestExecRequest defaults must match `run` (A42: root, /, 3600s).
        let defaultReq = GuestExecRequest(executable: "uname", arguments: ["-r"])
        #expect(defaultReq.runAsUser == "root")
        #expect(defaultReq.workingDirectory == "/")
        #expect(defaultReq.timeoutSeconds == 3600)

        let realBase = try makePrivateTmpDirectory(prefix: "avm-s4-i1")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/ExecStage4.agentvm", isDirectory: true)
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

        var stdoutBytesArr: [UInt8] = [0x00, 0xFF, 0xFE, 0x80, 0x41, 0x56, 0x4D, 0x0A]
        stdoutBytesArr.reserveCapacity(8 + 128 * 1024)
        for idx in 0..<(128 * 1024) {
            stdoutBytesArr.append(UInt8((idx * 73 + 19) & 0xFF))
        }
        let binaryStdout = Data(stdoutBytesArr)
        let binaryStderr = Data([0x00, 0x81, 0xFE, 0xFF, 0x45, 0x52, 0x52, 0x0A])

        let mockBackend = Stage4ScriptableGuestBackend { streamID, req, writer in
            switch req.executable {
            case "check-defaults":
                let info = "\(req.runAsUser)|\(req.workingDirectory)|\(Int(req.timeoutSeconds))\n"
                writer.sendOutputChunk(streamID: streamID, requestID: req.id, stream: .stdout, seq: 1, data: Data(info.utf8))
                writer.sendCompletion(streamID: streamID, requestID: req.id, exitCode: 0)
            case "stream-binary":
                writer.sendOutputChunk(streamID: streamID, requestID: req.id, stream: .stdout, seq: 1, data: Data(binaryStdout.prefix(4096)))
                writer.sendOutputChunk(streamID: streamID, requestID: req.id, stream: .stderr, seq: 2, data: binaryStderr)
                try? await Task.sleep(nanoseconds: 250_000_000)
                writer.sendOutputChunk(streamID: streamID, requestID: req.id, stream: .stdout, seq: 3, data: Data(binaryStdout.dropFirst(4096)))
                writer.sendCompletion(streamID: streamID, requestID: req.id, exitCode: 0)
            case "exit-7":
                writer.sendOutputChunk(streamID: streamID, requestID: req.id, stream: .stdout, seq: 1, data: Data("out\n".utf8))
                writer.sendOutputChunk(streamID: streamID, requestID: req.id, stream: .stderr, seq: 2, data: Data("err\n".utf8))
                writer.sendCompletion(streamID: streamID, requestID: req.id, exitCode: 7)
            case "sigkill-self":
                writer.sendCompletion(streamID: streamID, requestID: req.id, exitCode: 137)
            default:
                writer.sendCompletion(streamID: streamID, requestID: req.id, exitCode: 0)
            }
        }
        defer { mockBackend.shutdownAll() }

        try await withStartedDaemonServer(
            workspaceURL: wsURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mockBackend
        ) { _ in
            // 1. Stopped VM with live daemon: `exec` returns 125 ERR_LIFECYCLE_STATE, states 'stopped', hints 'up', does NOT auto-boot.
            let execStoppedEn = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "exec", "t1", "--", "check-defaults"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(execStoppedEn.exitCode == 125)
            #expect(execStoppedEn.stdoutData.isEmpty)
            #expect(execStoppedEn.stderr.contains("ERR_LIFECYCLE_STATE"))
            #expect(execStoppedEn.stderr.contains("stopped"))
            #expect(execStoppedEn.stderr.contains("agentvm up t1"))
            #expect(mockBackend.startCount == 0)

            // 2. Boot `t1`, pause `t1`, then `exec`: returns 125 ERR_LIFECYCLE_STATE, states 'paused', hints 'resume'.
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
            #expect(mockBackend.startCount == 1)

            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "pause", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)

            let execPausedEn = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "exec", "t1", "--", "check-defaults"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(execPausedEn.exitCode == 125)
            #expect(execPausedEn.stdoutData.isEmpty)
            #expect(execPausedEn.stderr.contains("ERR_LIFECYCLE_STATE"))
            #expect(execPausedEn.stderr.contains("paused"))
            #expect(execPausedEn.stderr.contains("agentvm resume t1"))

            let execPausedZh = await cli.execute(
                arguments: ["--lang", "zh", "--workspace", wsURL.path, "exec", "t1", "--", "check-defaults"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(execPausedZh.exitCode == 125)
            #expect(execPausedZh.stderr.contains("ERR_LIFECYCLE_STATE"))
            #expect(execPausedZh.stderr.contains("paused"))
            #expect(execPausedZh.stderr.contains("agentvm resume t1"))

            // 3. Resume `t1` and verify `exec` uses root, /, 3600s defaults (A42).
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "resume", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)

            let defaultsRes = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "exec", "t1", "--", "check-defaults"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(defaultsRes.exitCode == 0, "defaultsRes stderr: \(defaultsRes.stderr)")
            #expect(defaultsRes.stdout == "root|/|3600\n")
            #expect(defaultsRes.stderrData.isEmpty)

            // 4. Verify live byte-by-byte binary streaming on stdout and stderr (first chunk arrives well before 250ms delay completes).
            let streamTracker = Stage4LiveChunkTracker()
            let t0Ns = DispatchTime.now().uptimeNanoseconds
            let streamRes = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "exec", "t1", "--", "stream-binary"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn,
                liveStdoutDataHandler: { chunk in
                    let elapsedMs = Double(DispatchTime.now().uptimeNanoseconds - t0Ns) / 1_000_000.0
                    streamTracker.recordStdout(chunk, elapsedMs: elapsedMs)
                },
                liveStderrDataHandler: { chunk in
                    streamTracker.recordStderr(chunk)
                }
            )
            let totalElapsedMs = Double(DispatchTime.now().uptimeNanoseconds - t0Ns) / 1_000_000.0
            #expect(streamRes.exitCode == 0)
            let snap = streamTracker.snapshot()
            #expect(snap.stdout == binaryStdout)
            #expect(snap.stderr == binaryStderr)
            let firstChunkMs = try #require(snap.firstStdoutChunkMs)
            #expect(firstChunkMs < 200.0 && firstChunkMs < totalElapsedMs, "First stdout chunk (\(firstChunkMs) ms) must arrive live before command completion (\(totalElapsedMs) ms)")

            // 5. Exit codes: guest exit 7, signal 128+9 = 137, and AgentVM failure (missing VM) = 125.
            let exit7Res = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "exec", "t1", "--", "exit-7"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(exit7Res.exitCode == 7)
            #expect(exit7Res.stdoutData == Data("out\n".utf8))
            #expect(exit7Res.stderrData == Data("err\n".utf8))

            let sigkillRes = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "exec", "t1", "--", "sigkill-self"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(sigkillRes.exitCode == 137)
            #expect(sigkillRes.stdoutData.isEmpty)
            #expect(sigkillRes.stderrData.isEmpty)

            let missingVMRes = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "exec", "no-such-vm", "--", "true"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(missingVMRes.exitCode == 125)
            #expect(missingVMRes.stdoutData.isEmpty)
            #expect(missingVMRes.stderr.contains("ERR_VM_NOT_FOUND"))

            _ = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
        }
    }

    // MARK: - Item 2: `exec` Cancellation (`SIGINT` -> 130, `SIGTERM` -> 143, Daemon Emits Vsock `RST`, VM Keeps Running)

    @Test("Item 2: 'exec' client receiving SIGINT or SIGTERM closes socket, daemon emits AVM1 RST on that stream, client exits 130 or 143, and VM stays running")
    func daemonExecCancellationClosesSocketEmitsVsockRSTExits130Or143AndLeavesVMRunning() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-s4-i2")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/ExecCancelStage4.agentvm", isDirectory: true)
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

        let rstRecorder = Stage4InboundFrameRecorder()
        let mockBackend = Stage4ScriptableGuestBackend(
            frameObserver: { header, _, _ in
                rstRecorder.record(header)
            },
            execHandler: { streamID, req, writer in
                rstRecorder.recordExecStarted(executable: req.executable, streamID: streamID)
                if req.executable.hasPrefix("hang-until-rst") {
                    writer.sendOutputChunk(streamID: streamID, requestID: req.id, stream: .stdout, seq: 1, data: Data("started\n".utf8))
                    let deadline = DispatchTime.now().uptimeNanoseconds &+ 1_500_000_000
                    while DispatchTime.now().uptimeNanoseconds < deadline {
                        if rstRecorder.hasRST(forStreamID: streamID) {
                            return
                        }
                        try? await Task.sleep(nanoseconds: 10_000_000)
                    }
                    // Fallback completion if host never sent RST so unimplemented test fails fast instead of hanging.
                    writer.sendCompletion(streamID: streamID, requestID: req.id, exitCode: 99)
                } else if req.executable == "after-cancel-echo" {
                    writer.sendOutputChunk(streamID: streamID, requestID: req.id, stream: .stdout, seq: 1, data: Data("alive\n".utf8))
                    writer.sendCompletion(streamID: streamID, requestID: req.id, exitCode: 0)
                } else {
                    writer.sendCompletion(streamID: streamID, requestID: req.id, exitCode: 0)
                }
            }
        )
        defer { mockBackend.shutdownAll() }

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

            // 1. SIGINT via OneShotRunSignalController -> client closes socket, returns 130 promptly, daemon emits RST on streamID1.
            let sigIntController = OneShotRunSignalController()
            let t0Int = DispatchTime.now().uptimeNanoseconds
            let intTask = Task<CLIExecutionOutcome, Never> {
                await cli.execute(
                    arguments: ["--lang", "en", "--workspace", wsURL.path, "exec", "t1", "--", "hang-until-rst-int"],
                    curatedEntriesOverride: [entry],
                    environment: env,
                    daemonSpawnOverride: forbiddenSpawn,
                    signalController: sigIntController
                )
            }
            let streamID1 = try await rstRecorder.waitForExecStreamID(executable: "hang-until-rst-int", timeoutSeconds: 2.0)
            try await Task.sleep(nanoseconds: 40_000_000)
            sigIntController.deliver(signal: SIGINT)

            let intOutcome = await intTask.value
            let intElapsedMs = Double(DispatchTime.now().uptimeNanoseconds - t0Int) / 1_000_000.0
            #expect(intOutcome.exitCode == 130, "Expected SIGINT exit 130, got \(intOutcome.exitCode) (stderr: \(intOutcome.stderr))")
            #expect(intOutcome.stderrData.isEmpty)
            #expect(intElapsedMs < 1_000.0, "SIGINT cancellation took \(intElapsedMs) ms (expected < 1000 ms)")
            let rst1Observed = await rstRecorder.waitForRST(streamID: streamID1, timeoutSeconds: 1.0)
            #expect(rst1Observed == true, "Daemon must emit AVM1 .rst frame on cancelled exec stream \(streamID1)")

            // 2. Real child `AgentVM ... exec` CLI process receiving OS SIGTERM -> exits 143 (not uncaught signal), daemon emits RST on streamID2.
            let agentVMBinaryURL = try Self.locateBuiltAgentVMExecutable()
            let stdoutPipe = Pipe()
            let stderrPipe = Pipe()
            let childProc = Process()
            childProc.executableURL = agentVMBinaryURL
            childProc.arguments = ["--lang", "en", "--workspace", wsURL.path, "exec", "t1", "--", "hang-until-rst-term"]
            childProc.environment = [
                "HOME": isolatedHome,
                "CFFIXED_USER_HOME": isolatedHome,
                "AGENTVM_IMAGE_CACHE": cacheDir.path,
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"
            ]
            childProc.standardInput = FileHandle.nullDevice
            childProc.standardOutput = stdoutPipe
            childProc.standardError = stderrPipe
            try childProc.run()
            defer {
                if childProc.isRunning {
                    childProc.terminate()
                }
            }

            let streamID2 = try await rstRecorder.waitForExecStreamID(executable: "hang-until-rst-term", timeoutSeconds: 2.0)
            try await Task.sleep(nanoseconds: 40_000_000)
            #expect(Darwin.kill(childProc.processIdentifier, SIGTERM) == 0)
            childProc.waitUntilExit()

            #expect(childProc.terminationReason == .exit, "Expected graceful exit(143), got terminationReason=\(childProc.terminationReason.rawValue)")
            #expect(childProc.terminationStatus == 143, "Expected SIGTERM exit 143, got \(childProc.terminationStatus)")
            let childStderr = (try? stderrPipe.fileHandleForReading.readToEnd()) ?? Data()
            #expect(childStderr.isEmpty)
            let rst2Observed = await rstRecorder.waitForRST(streamID: streamID2, timeoutSeconds: 1.0)
            #expect(rst2Observed == true, "Daemon must emit AVM1 .rst frame on SIGTERM-cancelled exec stream \(streamID2)")

            // 3. VM `t1` keeps running on the same instance and serves subsequent `exec` cleanly.
            #expect(mockBackend.startCount == 1)
            let psRes = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "ps", "--json"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(psRes.exitCode == 0)
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            let fleet = try decoder.decode([VMInstanceRecord].self, from: Data(psRes.stdout.utf8))
            #expect(fleet.first?.telemetry.state == .running)

            let afterRes = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "exec", "t1", "--", "after-cancel-echo"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(afterRes.exitCode == 0)
            #expect(afterRes.stdout == "alive\n")

            _ = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
        }
    }

    // MARK: - Item 3 (A36): Bounded `exec_history` (64 KiB Prefix Per Stream + Total Byte Counts)

    @Test("Item 3 (A36): streaming 'exec' delivers full >64 KiB stdout/stderr to client while exec_history stores only first 64 KiB per stream plus exact total byte counts")
    func daemonExecBoundedHistoryStores64KiBPrefixAndTotalByteCountsA36() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-s4-i3")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/ExecHistoryA36.agentvm", isDirectory: true)
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

        let stdoutTotal = 200 * 1024 // 204,800 B (> 64 KiB)
        let stderrTotal = 150 * 1024 // 153,600 B (> 64 KiB)
        var outArr = [UInt8](repeating: 0, count: stdoutTotal)
        for i in 0..<stdoutTotal { outArr[i] = UInt8((i * 31 + 7) & 0xFF) }
        var errArr = [UInt8](repeating: 0, count: stderrTotal)
        for i in 0..<stderrTotal { errArr[i] = UInt8((i * 53 + 11) & 0xFF) }
        let fullStdout = Data(outArr)
        let fullStderr = Data(errArr)

        let mockBackend = Stage4ScriptableGuestBackend { streamID, req, writer in
            var seq: UInt32 = 0
            let step = 32 * 1024
            var off = 0
            while off < fullStdout.count {
                let end = min(fullStdout.count, off + step)
                seq &+= 1
                writer.sendOutputChunk(streamID: streamID, requestID: req.id, stream: .stdout, seq: seq, data: Data(fullStdout[off..<end]))
                off = end
            }
            off = 0
            while off < fullStderr.count {
                let end = min(fullStderr.count, off + step)
                seq &+= 1
                writer.sendOutputChunk(streamID: streamID, requestID: req.id, stream: .stderr, seq: seq, data: Data(fullStderr[off..<end]))
                off = end
            }
            writer.sendCompletion(streamID: streamID, requestID: req.id, exitCode: 0)
        }
        defer { mockBackend.shutdownAll() }

        try await withStartedDaemonServer(
            workspaceURL: wsURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mockBackend
        ) { server in
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)

            let tracker = Stage4LiveChunkTracker()
            let res = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "exec", "t1", "--", "emit-large-streams"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn,
                liveStdoutDataHandler: { tracker.recordStdout($0, elapsedMs: 0) },
                liveStderrDataHandler: { tracker.recordStderr($0) }
            )
            #expect(res.exitCode == 0)
            // Unbuffered streaming outcome itself retains 0 bytes in CLIExecutionOutcome while live handlers get 100%.
            #expect(res.stdoutData.isEmpty)
            #expect(res.stderrData.isEmpty)
            let snap = tracker.snapshot()
            #expect(snap.stdout == fullStdout)
            #expect(snap.stderr == fullStderr)

            // Verify persisted SQLite `exec_history` row via a fresh store instance:
            // stdout_data and stderr_data are capped at 65,536 bytes each, while total byte counts are exact.
            let readerStore = try AgentVMProjectStore(bundleURL: wsURL, createIfMissing: false)
            let history = try await readerStore.listExecResults(limit: 10)
            let entryRow = try #require(history.first(where: { $0.commandLine == "emit-large-streams" }))
            #expect(entryRow.stdoutData.count == 65_536)
            #expect(entryRow.stderrData.count == 65_536)
            #expect(entryRow.stdoutData == Data(fullStdout.prefix(65_536)))
            #expect(entryRow.stderrData == Data(fullStderr.prefix(65_536)))
            #expect(entryRow.stdoutTotalBytes == UInt64(stdoutTotal))
            #expect(entryRow.stderrTotalBytes == UInt64(stderrTotal))
            _ = server

            _ = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
        }
    }

    private static func locateBuiltAgentVMExecutable() throws -> URL {
        let bundleDir = Bundle(for: Stage4BundleLocatorToken.self).bundleURL.deletingLastPathComponent()
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
            domain: "CLIAndMCPDaemonStage4Tests",
            code: 404,
            userInfo: [NSLocalizedDescriptionKey: "Unable to locate built AgentVM binary next to test bundle at \(bundleDir.path)."]
        )
    }
}

private final class Stage4BundleLocatorToken {}

final class Stage4InboundFrameRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var rstStreamIDs: Set<UInt32> = []
    private var windowUpdatesByStream: [UInt32: [UInt32]] = [:]
    private var execStreamByExecutable: [String: UInt32] = [:]

    func record(_ header: VsockFrameHeader) {
        lock.withLock {
            if header.channel == .execProcess && header.flags.contains(.rst) {
                rstStreamIDs.insert(header.streamID)
            }
            if header.flags.contains(.windowUpdate) {
                windowUpdatesByStream[header.streamID, default: []].append(header.windowCredit)
            }
        }
    }

    func recordExecStarted(executable: String, streamID: UInt32) {
        lock.withLock {
            execStreamByExecutable[executable] = streamID
        }
    }

    func hasRST(forStreamID streamID: UInt32) -> Bool {
        lock.withLock { rstStreamIDs.contains(streamID) }
    }

    func windowUpdates(forStreamID streamID: UInt32) -> [UInt32] {
        lock.withLock { windowUpdatesByStream[streamID] ?? [] }
    }

    func waitForExecStreamID(executable: String, timeoutSeconds: TimeInterval) async throws -> UInt32 {
        let deadline = DispatchTime.now().uptimeNanoseconds &+ UInt64(max(0.05, timeoutSeconds) * 1_000_000_000)
        while DispatchTime.now().uptimeNanoseconds < deadline {
            if let sid = lock.withLock({ execStreamByExecutable[executable] }) {
                return sid
            }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        throw NSError(
            domain: "Stage4InboundFrameRecorder",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: "Timed out waiting for exec '\(executable)' to reach guest."]
        )
    }

    func waitForRST(streamID: UInt32, timeoutSeconds: TimeInterval) async -> Bool {
        let deadline = DispatchTime.now().uptimeNanoseconds &+ UInt64(max(0.05, timeoutSeconds) * 1_000_000_000)
        while DispatchTime.now().uptimeNanoseconds < deadline {
            if hasRST(forStreamID: streamID) {
                return true
            }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        return hasRST(forStreamID: streamID)
    }
}

// MARK: - Stage 4 Test Support: Scriptable AVM1 Guest Peer & Live Stream Tracker

final class Stage4LiveChunkTracker: @unchecked Sendable {
    private let lock = NSLock()
    private var stdoutBytes = Data()
    private var stderrBytes = Data()
    private var firstStdoutMs: Double?

    func recordStdout(_ chunk: Data, elapsedMs: Double) {
        guard !chunk.isEmpty else { return }
        lock.withLock {
            if firstStdoutMs == nil {
                firstStdoutMs = elapsedMs
            }
            stdoutBytes.append(chunk)
        }
    }

    func recordStderr(_ chunk: Data) {
        guard !chunk.isEmpty else { return }
        lock.withLock {
            stderrBytes.append(chunk)
        }
    }

    func snapshot() -> (stdout: Data, stderr: Data, firstStdoutChunkMs: Double?) {
        lock.withLock {
            (stdoutBytes, stderrBytes, firstStdoutMs)
        }
    }
}

final class Stage4GuestWireWriter: @unchecked Sendable {
    private let lock = NSLock()
    private let fd: Int32
    private let codec = VsockWireCodec()
    private var seqByStream: [UInt32: UInt32] = [:]
    private var closed = false

    init(fd: Int32) {
        self.fd = fd
    }

    func markClosed() {
        lock.withLock { closed = true }
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
        lock.lock()
        if closed || fd < 0 {
            lock.unlock()
            return false
        }
        let seq = (seqByStream[streamID] ?? 0) &+ 1
        seqByStream[streamID] = seq
        let targetFD = fd
        guard let wire = try? codec.encodeFrame(
            channel: channel,
            flags: flags,
            streamID: streamID,
            sequence: seq,
            windowCredit: windowCredit,
            payload: payload,
            compressIfBeneficial: compress
        ) else {
            lock.unlock()
            return false
        }
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
    func sendOutputChunk(
        streamID: UInt32,
        requestID: UUID,
        stream: GuestExecStreamKind,
        seq: UInt32,
        data: Data,
        compress: Bool = false
    ) -> Bool {
        let chunk = GuestExecOutputChunk(requestID: requestID, stream: stream, sequence: seq, data: data)
        guard let payload = try? VsockWireJSON.encode(chunk) else { return false }
        return sendRawFrame(
            channel: .execProcess,
            flags: [.ack],
            streamID: streamID,
            payload: payload,
            compress: compress
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
            payload: payload,
            compress: false
        )
    }

    @discardableResult
    func sendHeartbeat(hostname: String = "s4-guest", uptimeSeconds: Double = 42.0) -> Bool {
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

final class Stage4ScriptableGuestBackend: HardwareVMLowLevelBackend, @unchecked Sendable {
    typealias ExecHandler = @Sendable (UInt32, GuestExecRequest, Stage4GuestWireWriter) async -> Void
    typealias InboundFrameObserver = @Sendable (VsockFrameHeader, Data, Stage4GuestWireWriter) -> Void

    private let lock = NSLock()
    private let execHandler: ExecHandler
    private let frameObserver: InboundFrameObserver?
    private(set) var startCount = 0
    private(set) var execCount = 0
    private var handles: [Stage4ScriptableVMHandle] = []

    init(
        frameObserver: InboundFrameObserver? = nil,
        execHandler: @escaping ExecHandler
    ) {
        self.frameObserver = frameObserver
        self.execHandler = execHandler
    }

    fileprivate func recordExec() {
        lock.withLock { execCount += 1 }
    }

    func shutdownAll() {
        let all = lock.withLock { () -> [Stage4ScriptableVMHandle] in
            let copy = handles
            handles.removeAll()
            return copy
        }
        for h in all {
            h.forceClose()
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
        let handle = Stage4ScriptableVMHandle(owner: self, execHandler: execHandler, frameObserver: frameObserver)
        lock.withLock {
            startCount += 1
            handles.append(handle)
        }
        return handle
    }
}

final class Stage4ScriptableVMHandle: HardwareVMInstanceHandle, @unchecked Sendable {
    private unowned let owner: Stage4ScriptableGuestBackend
    private let execHandler: Stage4ScriptableGuestBackend.ExecHandler
    private let frameObserver: Stage4ScriptableGuestBackend.InboundFrameObserver?
    private let lock = NSLock()
    private var hostFD: Int32 = -1
    private var peerFD: Int32 = -1
    private var activeWriter: Stage4GuestWireWriter?
    private var readLoopTask: Task<Void, Never>?

    init(
        owner: Stage4ScriptableGuestBackend,
        execHandler: @escaping Stage4ScriptableGuestBackend.ExecHandler,
        frameObserver: Stage4ScriptableGuestBackend.InboundFrameObserver?
    ) {
        self.owner = owner
        self.execHandler = execHandler
        self.frameObserver = frameObserver
    }

    func prematureStopReason() -> String? { nil }

    func connectVsock(port: UInt32) async throws -> HardwareVsockFDDescriptor {
        forceClose()
        var fds: [Int32] = [-1, -1]
        guard Darwin.socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(Darwin.errno))
        }
        var one: Int32 = 1
        _ = Darwin.setsockopt(fds[0], SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        _ = Darwin.setsockopt(fds[1], SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))

        let hFD = fds[0]
        let pFD = fds[1]
        let writer = Stage4GuestWireWriter(fd: pFD)
        let handler = execHandler
        let observer = frameObserver

        let task = Task.detached { [weak self] in
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
                    observer?(header, payload, writer)
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
                            self?.owner.recordExec()
                            let sid = header.streamID
                            Task.detached {
                                await handler(sid, req, writer)
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
        return HardwareVsockFDDescriptor(fileDescriptor: hFD, closeWhenSessionEnds: false)
    }

    func forceClose() {
        let (h, p, w, t) = lock.withLock { () -> (Int32, Int32, Stage4GuestWireWriter?, Task<Void, Never>?) in
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
        forceClose()
    }

    func pause() async throws {}
    func resume() async throws {}
    func saveMachineState(to url: URL) async throws {}

    func shutdown(gracefulTimeoutNanoseconds: UInt64) async {
        forceClose()
    }
}
