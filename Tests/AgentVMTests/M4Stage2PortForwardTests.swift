import AgentVMCLIAndMCP
import AgentVMHypervisor
import AgentVMModels
import AgentVMStorageCoW
import AgentVMStore
import AgentVMVsockRPC
import Darwin
import Foundation
import Testing

@Suite("M4 Stage 2: Daemon-Managed Port Forwarding, Half-Close Relay & Bind Error Honesty", .serialized, .timeLimit(.minutes(2)))
struct M4Stage2PortForwardTests {

    // MARK: - Helpers

    private func makePrivateTmpDirectory(prefix: String = "avm-m4-s2") throws -> String {
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
        vsockRetryIntervalNanoseconds: UInt64 = 30_000_000,
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
            throw NSError(domain: "M4Stage2PortForwardTests", code: 1)
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

    private func bindLoopbackOccupationSocket() throws -> (fd: Int32, port: UInt16) {
        let fd = Darwin.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(Darwin.errno))
        }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        _ = "127.0.0.1".withCString { Darwin.inet_pton(AF_INET, $0, &addr.sin_addr) }
        let brc = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.bind(fd, saPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard brc == 0, Darwin.listen(fd, 8) == 0 else {
            let err = Darwin.errno
            _ = Darwin.close(fd)
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(err))
        }
        var queried = sockaddr_in()
        var qLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &queried) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.getsockname(fd, saPtr, &qLen)
            }
        }
        return (fd, UInt16(bigEndian: queried.sin_port))
    }

    private func reserveFreeLoopbackPort() throws -> UInt16 {
        let (fd, port) = try bindLoopbackOccupationSocket()
        _ = Darwin.close(fd)
        return port
    }

    private func canConnectLoopback(port: UInt16) -> Bool {
        let fd = Darwin.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else { return false }
        defer { _ = Darwin.close(fd) }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        _ = "127.0.0.1".withCString { Darwin.inet_pton(AF_INET, $0, &addr.sin_addr) }
        let rc = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.connect(fd, saPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return rc == 0
    }

    private func sendHalfCloseAndReadAllLoopback(port: UInt16, payload: Data, timeoutMs: Int32 = 3_000) throws -> Data {
        let fd = Darwin.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(Darwin.errno))
        }
        defer { _ = Darwin.close(fd) }
        var yes: Int32 = 1
        _ = Darwin.setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        _ = "127.0.0.1".withCString { Darwin.inet_pton(AF_INET, $0, &addr.sin_addr) }

        let rc = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.connect(fd, saPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard rc == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(Darwin.errno))
        }

        if !payload.isEmpty {
            let written = payload.withUnsafeBytes { rawBuf -> Int in
                guard let base = rawBuf.baseAddress else { return 0 }
                return Darwin.send(fd, base, rawBuf.count, 0)
            }
            #expect(written == payload.count)
        }
        #expect(Darwin.shutdown(fd, SHUT_WR) == 0)

        var collected = Data()
        var buf = [UInt8](repeating: 0, count: 8192)
        while true {
            var pfd = Darwin.pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let prc = Darwin.poll(&pfd, 1, timeoutMs)
            if prc <= 0 {
                break
            }
            let n = Darwin.recv(fd, &buf, buf.count, 0)
            if n > 0 {
                collected.append(contentsOf: buf[0..<n])
            } else if n == 0 {
                break
            } else if Darwin.errno != EINTR {
                break
            }
        }
        return collected
    }

    // MARK: - 1. Half-Close + 100 ms Delayed Response Over Real Vsock + Python guestd

    @Test("HostPortForwardManager + VsockMultiplexSession + agentvm-guestd.py preserve full 100 ms delayed response after client SHUT_WR half-close")
    func halfCloseDelayed100msResponseOverVsockAndGuestd() async throws {
        let baseDir = try makePrivateTmpDirectory(prefix: "avm-m4-s2-halfclose")
        defer { try? FileManager.default.removeItem(atPath: baseDir) }

        let tempURL = URL(fileURLWithPath: baseDir, isDirectory: true)
        let daemonModuleURL = tempURL.appendingPathComponent("agentvm_guestd.py")
        try GuestAgentBootstrapGenerator().pythonDaemonScript().write(
            to: daemonModuleURL,
            atomically: true,
            encoding: .utf8
        )

        // Start a local TCP server representing the guest service on 127.0.0.1:0:
        // reads until client EOF, sleeps 100 ms (0.10 s), and replies "DELAYED_REPLY_OK:<request>".
        let backendOut = Pipe()
        let backendProc = Process()
        backendProc.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        backendProc.arguments = [
            "-u", "-c",
            """
            import socket, sys, time
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 0))
            srv.listen(4)
            print(srv.getsockname()[1], flush=True)
            conn, _ = srv.accept()
            chunks = []
            while True:
                b = conn.recv(4096)
                if not b:
                    break
                chunks.append(b)
            req = b"".join(chunks)
            time.sleep(0.10)
            conn.sendall(b"DELAYED_REPLY_OK:" + req)
            conn.close()
            srv.close()
            """
        ]
        backendProc.standardOutput = backendOut
        try backendProc.run()
        defer {
            if backendProc.isRunning {
                backendProc.terminate()
                backendProc.waitUntilExit()
            }
        }

        var portLineBytes = Data()
        while true {
            let byte = backendOut.fileHandleForReading.readData(ofLength: 1)
            if byte.isEmpty || byte.first == 0x0A { break }
            portLineBytes.append(byte)
        }
        let guestBackendPort = try #require(UInt16(String(decoding: portLineBytes, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)))
        #expect(guestBackendPort > 0)

        let sockPath = "\(baseDir)/guestd.sock"
        _ = Darwin.unlink(sockPath)
        defer { _ = Darwin.unlink(sockPath) }

        let unixListenFD = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        #expect(unixListenFD >= 0)
        defer { _ = Darwin.close(unixListenFD) }

        var unAddr = sockaddr_un()
        unAddr.sun_family = sa_family_t(AF_UNIX)
        let pathCString = Array(sockPath.utf8CString)
        #expect(pathCString.count <= MemoryLayout.size(ofValue: unAddr.sun_path))
        withUnsafeMutableBytes(of: &unAddr.sun_path) { rawBuf in
            for (idx, ch) in pathCString.enumerated() {
                rawBuf[idx] = UInt8(bitPattern: ch)
            }
        }
        let bindRes = withUnsafePointer(to: &unAddr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.bind(unixListenFD, saPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        #expect(bindRes == 0)
        #expect(Darwin.listen(unixListenFD, 2) == 0)

        let guestdProc = Process()
        guestdProc.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        guestdProc.arguments = [
            "-u", "-c",
            """
            import socket, sys
            sys.path.insert(0, sys.argv[1])
            import agentvm_guestd
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(sys.argv[2])
            session = agentvm_guestd.GuestVsockConnectionSession(
                conn=sock,
                heartbeat_interval=60,
                default_workspace=sys.argv[1],
            )
            session.run()
            """,
            baseDir,
            sockPath
        ]
        try guestdProc.run()
        defer {
            if guestdProc.isRunning {
                guestdProc.terminate()
                guestdProc.waitUntilExit()
            }
        }

        let peerFD = Darwin.accept(unixListenFD, nil, nil)
        #expect(peerFD >= 0)

        let vmID = VMID("vm-halfclose")
        let session = VsockMultiplexSession(vmID: vmID)
        try await session.attachPOSIXFileDescriptor(peerFD, closeWhenDone: true)
        let manager = HostPortForwardManager()

        let binding = try await manager.startForwardRule(
            PortForwardRuleSpec(label: "delayed-echo", hostPort: 0, guestPort: guestBackendPort),
            vmID: vmID,
            vsockSession: session
        )

        let replyData = try sendHalfCloseAndReadAllLoopback(
            port: binding.actualBoundPort,
            payload: Data("PING".utf8)
        )
        let replyString = String(decoding: replyData, as: UTF8.self)
        #expect(replyString == "DELAYED_REPLY_OK:PING")

        await manager.stopAllRules()
        await session.shutdown()
        backendProc.waitUntilExit()
        guestdProc.terminate()
        guestdProc.waitUntilExit()
    }

    // MARK: - 2. Port Bind Failures Never Swallowed & Localized Port + Reason

    @Test("AgentVMFleetCoordinator and forward CLI surface port bind conflicts and permission errors without swallowing via try?")
    func portBindConflictNotSwallowedAndLocalizedStderr() async throws {
        let baseDir = try makePrivateTmpDirectory(prefix: "avm-m4-s2-binderr")
        defer { try? FileManager.default.removeItem(atPath: baseDir) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: baseDir) }

        let (occFD, occupiedPort) = try bindLoopbackOccupationSocket()
        defer { _ = Darwin.close(occFD) }

        // 2a. Simulation coordinator bootVM must NOT swallow portForwardManager.startForwardRule failure!
        let simWS = URL(fileURLWithPath: "\(baseDir)/SimBindErr.agentvm", isDirectory: true)
        let simCoord = try AgentVMFleetCoordinator(bundleURL: simWS, executionBackend: .deterministicSimulation)
        let simCreated = try await simCoord.createSandboxVM(
            name: "sim-collide",
            diskVirtualBytes: 8 * 1024 * 1024,
            portForwards: [PortForwardRuleSpec(label: "conflict", hostPort: occupiedPort, guestPort: 8000)]
        )
        do {
            _ = try await simCoord.bootVM(simCreated.vmRecord.id)
            Issue.record("Expected simulation bootVM to fail with ERR_PORT_FORWARD_BIND when hostPort \(occupiedPort) is already bound")
        } catch let err as AgentVMError {
            #expect(err.errorCode == "ERR_PORT_FORWARD_BIND")
            let enMsg = err.localizedMessage(in: .en)
            let zhMsg = err.localizedMessage(in: .zhHans)
            #expect(enMsg.contains("\(occupiedPort)"))
            #expect(enMsg.lowercased().contains("in use") || enMsg.lowercased().contains("address already in use"))
            #expect(zhMsg.contains("\(occupiedPort)"))
            #expect(zhMsg.contains("占用"))
        }

        // 2b. Hardware attachManagedVsockSession must NOT swallow bind failure, and CLI `forward` reports port + reason in en & zh!
        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: baseDir)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let hwWS = URL(fileURLWithPath: "\(baseDir)/HwBindErr.agentvm", isDirectory: true)
        let isolatedHome = "\(baseDir)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let forbiddenSpawn = DaemonSpawnCommandOverride(executablePath: "/bin/sh", arguments: ["-c", "exit 96"], environment: env)
        let mockBackend = M4S2MockHardwareBackend()
        defer { mockBackend.shutdownAll() }

        let cli = AgentVMCLIRunner()
        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", hwWS.path, "create", "t1", "--image", entry.id],
            curatedEntriesOverride: [entry],
            environment: env
        ).exitCode == 0)

        try await withStartedDaemonServer(
            workspaceURL: hwWS,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mockBackend
        ) { server in
            // Pre-populate a conflicting rule on t-pre and verify hardware `up` surfaces ERR_PORT_FORWARD_BIND
            let preCreated = try await server.coordinator.createVMFromImage(
                name: "t-pre",
                imageID: entry.id,
                portForwards: [PortForwardRuleSpec(label: "pre-conflict", hostPort: occupiedPort, guestPort: 8000)]
            )
            let upConflict = await cli.execute(
                arguments: ["--lang", "en", "--workspace", hwWS.path, "up", preCreated.vmRecord.spec.name],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(upConflict.exitCode == 1)
            #expect(upConflict.stderr.contains("ERR_PORT_FORWARD_BIND"))
            #expect(upConflict.stderr.contains("\(occupiedPort)"))

            // Boot t1 cleanly, then attempt `forward t1 <occupiedPort>:8000` in en & zh
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", hwWS.path, "up", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)

            let fwdEn = await cli.execute(
                arguments: ["--lang", "en", "--workspace", hwWS.path, "forward", "t1", "\(occupiedPort):8000"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(fwdEn.exitCode == 1)
            #expect(fwdEn.stderr.contains("ERR_PORT_FORWARD_BIND"))
            #expect(fwdEn.stderr.contains("\(occupiedPort)"))
            #expect(fwdEn.stderr.lowercased().contains("in use"))

            let fwdZh = await cli.execute(
                arguments: ["--lang", "zh", "--workspace", hwWS.path, "forward", "t1", "\(occupiedPort):8000"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(fwdZh.exitCode == 1)
            #expect(fwdZh.stderr.contains("ERR_PORT_FORWARD_BIND"))
            #expect(fwdZh.stderr.contains("\(occupiedPort)"))
            #expect(fwdZh.stderr.contains("占用"))

            if Darwin.geteuid() != 0 {
                let privEn = await cli.execute(
                    arguments: ["--lang", "en", "--workspace", hwWS.path, "forward", "t1", "1:8000"],
                    curatedEntriesOverride: [entry],
                    environment: env,
                    daemonSpawnOverride: forbiddenSpawn
                )
                #expect(privEn.exitCode == 1)
                #expect(privEn.stderr.contains("ERR_PORT_FORWARD_BIND"))
                #expect(privEn.stderr.contains("1"))
                #expect(privEn.stderr.lowercased().contains("permission"))

                let privZh = await cli.execute(
                    arguments: ["--lang", "zh", "--workspace", hwWS.path, "forward", "t1", "1:8000"],
                    curatedEntriesOverride: [entry],
                    environment: env,
                    daemonSpawnOverride: forbiddenSpawn
                )
                #expect(privZh.exitCode == 1)
                #expect(privZh.stderr.contains("ERR_PORT_FORWARD_BIND"))
                #expect(privZh.stderr.contains("权限"))
            }
        }
    }

    // MARK: - 3. CLI Grammar, Usage Exit Codes, Stopped-VM Rejection & Bilingual Help

    @Test("forward CLI validates add/list/stop/--foreground arguments (exit 2), rejects non-running or missing VMs (exit 1), and documents bilingual --help")
    func forwardCLIArgumentParsingStoppedVMAndHelpBanner() async throws {
        let baseDir = try makePrivateTmpDirectory(prefix: "avm-m4-s2-cli")
        defer { try? FileManager.default.removeItem(atPath: baseDir) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: baseDir) }

        #expect(AgentVMCLIRunner.cliSubcommands.contains("forward"))
        let helpEn = AgentVMCLIRunner.helpBanner(language: .en)
        let helpZh = AgentVMCLIRunner.helpBanner(language: .zhHans)
        #expect(helpEn.contains("forward"))
        #expect(helpEn.contains("--foreground"))
        #expect(helpEn.contains("forward list"))
        #expect(helpEn.contains("forward stop"))
        #expect(helpZh.contains("forward"))
        #expect(helpZh.contains("--foreground"))
        #expect(helpZh.contains("forward list"))
        #expect(helpZh.contains("forward stop"))

        let cli = AgentVMCLIRunner()
        let uncreatedWS = URL(fileURLWithPath: "\(baseDir)/NeverCreated.agentvm", isDirectory: true)
        let badInvocations: [[String]] = [
            ["forward"],
            ["forward", "t1"],
            ["forward", "t1", "8000"],
            ["forward", "t1", "0:8000"],
            ["forward", "t1", "8080:0"],
            ["forward", "t1", "70000:8000"],
            ["forward", "t1", "abc:8000"],
            ["forward", "t1", ":8000"],
            ["forward", "t1", "8080:"],
            ["forward", "t1", "0.0.0.0:8080:8000"],
            ["forward", "t1", "8080:8000", "extra"],
            ["forward", "t1", "8080:8000", "--json"],
            ["forward", "t1", "8080:8000", "--vm", "t1"],
            ["forward", "list", "extra"],
            ["forward", "list", "--foreground"],
            ["forward", "list", "--vm", ""],
            ["forward", "stop"],
            ["forward", "stop", "t1"],
            ["forward", "stop", "t1", "0"],
            ["forward", "stop", "t1", "70000"],
            ["forward", "stop", "t1", "abc"],
            ["forward", "stop", "t1", "8080", "extra"],
            ["forward", "stop", "t1", "8080", "--json"],
            ["forward", "stop", "t1", "8080", "--foreground"],
            ["forward", "--unknown-flag"]
        ]

        for inv in badInvocations {
            for lang in ["en", "zh"] {
                let res = await cli.execute(arguments: ["--lang", lang, "--workspace", uncreatedWS.path] + inv)
                #expect(res.exitCode == 2, "Expected exit 2 for \(inv) (\(lang)), got \(res.exitCode): \(res.stderr)")
                #expect(!res.stderr.isEmpty)
            }
        }
        #expect(FileManager.default.fileExists(atPath: uncreatedWS.path) == false)

        // Stopped VM and missing VM must exit 1 with descriptive stderr (both without daemon and with daemon)
        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: baseDir)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }
        let wsURL = URL(fileURLWithPath: "\(baseDir)/StoppedCheck.agentvm", isDirectory: true)
        let isolatedHome = "\(baseDir)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let forbiddenSpawn = DaemonSpawnCommandOverride(executablePath: "/bin/sh", arguments: ["-c", "exit 96"], environment: env)

        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "create", "stopped-vm", "--image", entry.id],
            curatedEntriesOverride: [entry],
            environment: env
        ).exitCode == 0)

        let freePort = try reserveFreeLoopbackPort()

        let missingRes = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "forward", "no-such-vm", "\(freePort):8000"],
            curatedEntriesOverride: [entry],
            environment: env,
            daemonSpawnOverride: forbiddenSpawn
        )
        #expect(missingRes.exitCode == 1)
        #expect(missingRes.stderr.contains("ERR_VM_NOT_FOUND"))

        // Without daemon running: `forward stopped-vm` must NOT spawn daemon and must exit 1 explaining VM is not running
        let stoppedNoDaemonEn = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "forward", "stopped-vm", "\(freePort):8000"],
            curatedEntriesOverride: [entry],
            environment: env,
            daemonSpawnOverride: forbiddenSpawn
        )
        #expect(stoppedNoDaemonEn.exitCode == 1)
        #expect(stoppedNoDaemonEn.stderr.contains("ERR_LIFECYCLE_STATE"))
        #expect(stoppedNoDaemonEn.stderr.contains("stopped-vm"))

        let stoppedNoDaemonZh = await cli.execute(
            arguments: ["--lang", "zh", "--workspace", wsURL.path, "forward", "stopped-vm", "\(freePort):8000"],
            curatedEntriesOverride: [entry],
            environment: env,
            daemonSpawnOverride: forbiddenSpawn
        )
        #expect(stoppedNoDaemonZh.exitCode == 1)
        #expect(stoppedNoDaemonZh.stderr.contains("ERR_LIFECYCLE_STATE"))
        #expect(stoppedNoDaemonZh.stderr.contains("stopped-vm"))

        // `forward list` when daemon is not running returns 0 with empty list without spawning daemon
        let listNoDaemonJSON = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "forward", "list", "--json"],
            curatedEntriesOverride: [entry],
            environment: env,
            daemonSpawnOverride: forbiddenSpawn
        )
        #expect(listNoDaemonJSON.exitCode == 0)
        let parsedEmpty = try JSONSerialization.jsonObject(with: Data(listNoDaemonJSON.stdout.utf8)) as? [[String: Any]]
        #expect(parsedEmpty?.isEmpty == true)

        // With daemon running while `stopped-vm` is still stopped: also exits 1 with ERR_LIFECYCLE_STATE
        let mockBackend = M4S2MockHardwareBackend()
        defer { mockBackend.shutdownAll() }
        try await withStartedDaemonServer(
            workspaceURL: wsURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mockBackend
        ) { _ in
            let stoppedWithDaemon = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "forward", "stopped-vm", "\(freePort):8000"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(stoppedWithDaemon.exitCode == 1)
            #expect(stoppedWithDaemon.stderr.contains("ERR_LIFECYCLE_STATE"))
        }
    }

    // MARK: - 4. DaemonRPC Codec Round-Trip for Forward Methods

    @Test("DaemonRPCCodec encodes and decodes forward.add, forward.list, and forward.stop JSON-RPC 2.0 envelopes")
    func daemonRPCForwardMethodsCodecRoundTrip() throws {
        let rawMethods = DaemonRPCMethod.allCases.map(\.rawValue)
        #expect(rawMethods.contains("forward.add"))
        #expect(rawMethods.contains("forward.list"))
        #expect(rawMethods.contains("forward.stop"))

        let addJSON = #"{"id":41,"jsonrpc":"2.0","method":"forward.add","params":{"foreground":true,"guestPort":8000,"hostPort":18080,"lang":"en","vm":"t1"}}"#
        let decodedAdd = try DaemonRPCCodec.decodeRequestLine(Data(addJSON.utf8))
        #expect(decodedAdd.id == .int(41))
        #expect(decodedAdd.method.rawValue == "forward.add")
        let reencodedAdd = try DaemonRPCCodec.encodeRequestLine(decodedAdd)
        #expect(!reencodedAdd.contains(0x0A))
        #expect(try DaemonRPCCodec.decodeRequestLine(reencodedAdd) == decodedAdd)

        let listJSON = #"{"id":42,"jsonrpc":"2.0","method":"forward.list","params":{"lang":"zh-Hans","vm":"t1"}}"#
        let decodedList = try DaemonRPCCodec.decodeRequestLine(Data(listJSON.utf8))
        #expect(decodedList.id == .int(42))
        #expect(decodedList.method.rawValue == "forward.list")
        #expect(decodedList.language == .zhHans)
        let reencodedList = try DaemonRPCCodec.encodeRequestLine(decodedList)
        #expect(try DaemonRPCCodec.decodeRequestLine(reencodedList) == decodedList)

        let stopJSON = #"{"id":"req-fwd-stop","jsonrpc":"2.0","method":"forward.stop","params":{"hostPort":18080,"lang":"en","vm":"t1"}}"#
        let decodedStop = try DaemonRPCCodec.decodeRequestLine(Data(stopJSON.utf8))
        #expect(decodedStop.id == .string("req-fwd-stop"))
        #expect(decodedStop.method.rawValue == "forward.stop")
        let reencodedStop = try DaemonRPCCodec.encodeRequestLine(decodedStop)
        #expect(try DaemonRPCCodec.decodeRequestLine(reencodedStop) == decodedStop)
    }

    // MARK: - 5. End-to-End Daemon-Managed Forward, List, Stop, --foreground (SIGINT/SIGTERM), Reconnect & Halt Release

    @Test("Daemon-managed forward binds 127.0.0.1, persists across guest vsock reconnect, supports list/stop/--foreground signals, and releases port on halt")
    func daemonManagedForwardLifecycleListStopForegroundReconnectAndHaltRelease() async throws {
        let baseDir = try makePrivateTmpDirectory(prefix: "avm-m4-s2-e2e")
        defer { try? FileManager.default.removeItem(atPath: baseDir) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: baseDir) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: baseDir)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(baseDir)/FwdLifecycle.agentvm", isDirectory: true)
        let isolatedHome = "\(baseDir)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let forbiddenSpawn = DaemonSpawnCommandOverride(executablePath: "/bin/sh", arguments: ["-c", "exit 96"], environment: env)
        let mockBackend = M4S2MockHardwareBackend()
        defer { mockBackend.shutdownAll() }

        let cli = AgentVMCLIRunner()
        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "create", "t1", "--image", entry.id],
            curatedEntriesOverride: [entry],
            environment: env
        ).exitCode == 0)

        let inspectStore = try AgentVMProjectStore(bundleURL: wsURL, createIfMissing: false)
        let t1ID = try #require((try await inspectStore.listVMs()).first(where: { $0.spec.name == "t1" })?.id)

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

            // 5a. Add daemon-managed forward p1:8000 -> exits 0, relays TCP traffic, persists in portForwards
            let p1 = try reserveFreeLoopbackPort()
            let addOut = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "forward", "t1", "\(p1):8000"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(addOut.exitCode == 0, "forward add failed: \(addOut.stderr)")
            #expect(addOut.stdout.contains("127.0.0.1:\(p1)"))
            #expect(addOut.stdout.contains("8000"))

            let echoed1 = try sendHalfCloseAndReadAllLoopback(port: p1, payload: Data("hello".utf8))
            #expect(String(decoding: echoed1, as: UTF8.self) == "GUEST:8000:hello")

            // Duplicate forward on p1 fails non-zero while keeping original forward alive
            let dupOut = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "forward", "t1", "\(p1):8001"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(dupOut.exitCode == 1)
            #expect(dupOut.stderr.contains("ERR_PORT_FORWARD_BIND"))
            let echoedAfterDup = try sendHalfCloseAndReadAllLoopback(port: p1, payload: Data("still-up".utf8))
            #expect(String(decoding: echoedAfterDup, as: UTF8.self) == "GUEST:8000:still-up")

            // 5b. `forward list` (text + --json + --vm t1)
            let listText = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "forward", "list"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(listText.exitCode == 0)
            #expect(listText.stdout.contains("\(p1)"))
            #expect(listText.stdout.contains("8000"))
            #expect(listText.stdout.contains("t1"))

            let listJSON = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "forward", "list", "--vm", "t1", "--json"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(listJSON.exitCode == 0)
            let listArr = try #require(try JSONSerialization.jsonObject(with: Data(listJSON.stdout.utf8)) as? [[String: Any]])
            #expect(listArr.count == 1)
            #expect(listArr[0]["vmName"] as? String == "t1")
            #expect(listArr[0]["hostBindAddress"] as? String == "127.0.0.1")
            #expect(listArr[0]["hostPort"] as? Int == Int(p1))
            #expect(listArr[0]["guestPort"] as? Int == 8000)

            // Confirm persisted in VM spec (`portForwards`)
            let storedT1 = try #require(try await inspectStore.fetchVM(t1ID))
            #expect(storedT1.spec.portForwards.contains(where: { $0.hostPort == p1 && $0.guestPort == 8000 }))

            // 5c. Simulate guest reboot (vsock EOF -> reconnect) and verify p1:8000 automatically rebinds!
            let handle = try #require(mockBackend.latestHandle(for: t1ID))
            let prevGen = handle.connectCount
            handle.closeGuestPeerSocketOnly()

            var reconnected = false
            for _ in 0..<100 {
                if handle.connectCount > prevGen, canConnectLoopback(port: p1) {
                    if let testReply = try? sendHalfCloseAndReadAllLoopback(port: p1, payload: Data("post-reboot".utf8)),
                       String(decoding: testReply, as: UTF8.self) == "GUEST:8000:post-reboot" {
                        reconnected = true
                        break
                    }
                }
                try await Task.sleep(nanoseconds: 25_000_000)
            }
            #expect(reconnected == true, "Expected dynamically added port forward \(p1):8000 to automatically rebind on vsock reconnect")

            // 5d. `--foreground` with SIGINT and SIGTERM: blocks while forwarding, unbinds cleanly on signal
            for sig in [SIGINT, SIGTERM] {
                let fgPort = try reserveFreeLoopbackPort()
                let sigCtrl = OneShotRunSignalController()
                let fgTask = Task<CLIExecutionOutcome, Never> {
                    await cli.execute(
                        arguments: ["--lang", "en", "--workspace", wsURL.path, "forward", "t1", "\(fgPort):8001", "--foreground"],
                        curatedEntriesOverride: [entry],
                        environment: env,
                        daemonSpawnOverride: forbiddenSpawn,
                        signalController: sigCtrl
                    )
                }

                var fgReady = false
                for _ in 0..<80 {
                    if canConnectLoopback(port: fgPort),
                       let r = try? sendHalfCloseAndReadAllLoopback(port: fgPort, payload: Data("fg".utf8)),
                       String(decoding: r, as: UTF8.self) == "GUEST:8001:fg" {
                        fgReady = true
                        break
                    }
                    try await Task.sleep(nanoseconds: 20_000_000)
                }
                #expect(fgReady == true, "--foreground port \(fgPort) did not become ready")

                sigCtrl.deliver(signal: sig)
                let fgOutcome = await fgTask.value
                #expect(fgOutcome.exitCode == 0, "--foreground expected exit 0 on signal \(sig), got \(fgOutcome.exitCode): \(fgOutcome.stderr)")
                #expect(canConnectLoopback(port: fgPort) == false, "--foreground port \(fgPort) should be unbound upon exit")
            }

            // 5e. `forward stop t1 <p1>` unbinds port and removes rule; second stop returns non-zero
            let stopOut = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "forward", "stop", "t1", "\(p1)"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(stopOut.exitCode == 0)
            #expect(canConnectLoopback(port: p1) == false)

            let stopAgain = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "forward", "stop", "t1", "\(p1)"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(stopAgain.exitCode == 1)

            // 5f. `halt t1` releases active port-forward listener immediately
            let pHalt = try reserveFreeLoopbackPort()
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "forward", "t1", "\(pHalt):8002"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
            #expect(canConnectLoopback(port: pHalt) == true)

            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
            #expect(canConnectLoopback(port: pHalt) == false, "Expected halt to release forwarded host port \(pHalt)")

            let listAfterHalt = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "forward", "list", "--json"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(listAfterHalt.exitCode == 0)
            let emptyAfterHalt = try #require(try JSONSerialization.jsonObject(with: Data(listAfterHalt.stdout.utf8)) as? [[String: Any]])
            #expect(emptyAfterHalt.isEmpty)
        }
    }
}

// MARK: - Minimal AVM1 Mock Hardware Backend Supporting Port-Forward Streams & Reconnect

private final class M4S2MockHardwareBackend: HardwareVMLowLevelBackend, @unchecked Sendable {
    private let lock = NSLock()
    private var handlesByVM: [VMID: [M4S2MockVMHandle]] = [:]

    func latestHandle(for vmID: VMID) -> M4S2MockVMHandle? {
        lock.withLock { handlesByVM[vmID]?.last }
    }

    func shutdownAll() {
        let all = lock.withLock { () -> [M4S2MockVMHandle] in
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
        let handle = M4S2MockVMHandle(vmID: spec.id)
        lock.withLock {
            handlesByVM[spec.id, default: []].append(handle)
        }
        return handle
    }
}

private final class M4S2GuestWireSender: @unchecked Sendable {
    private let lock = NSLock()
    private let fd: Int32
    private var closed = false
    private var seqByStream: [UInt32: UInt32] = [:]
    private let codec = VsockWireCodec()

    init(fd: Int32) {
        self.fd = fd
    }

    func markClosed() {
        lock.withLock { closed = true }
    }

    @discardableResult
    func sendFrame(channel: VsockChannelKind, flags: VsockFrameFlags, streamID: UInt32, payload: Data) -> Bool {
        lock.withLock {
            guard !closed, fd >= 0 else { return false }
            let seq = (seqByStream[streamID] ?? 0) &+ 1
            seqByStream[streamID] = seq
            guard let wire = try? codec.encodeFrame(
                channel: channel,
                flags: flags,
                streamID: streamID,
                sequence: seq,
                payload: payload,
                compressIfBeneficial: false
            ) else {
                return false
            }
            return wire.withUnsafeBytes { rawBuf -> Bool in
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

    func sendHeartbeat() {
        let hb = GuestHeartbeatPayload(
            hostname: "mock-guest",
            kernelRelease: "6.1.0-mock",
            uptimeSeconds: 10.0,
            loadAvg1: 0.1,
            loadAvg5: 0.1,
            loadAvg15: 0.1,
            memTotalBytes: 1_073_741_824,
            memAvailableBytes: 536_870_912,
            rootFilesystemUsedBytes: 1_000_000,
            rootFilesystemTotalBytes: 8_000_000
        )
        if let encoded = try? VsockWireJSON.encode(hb) {
            _ = sendFrame(channel: .telemetryHeartbeat, flags: [.ack, .endOfMessage], streamID: 0, payload: encoded)
        }
    }
}

private final class M4S2MockVMHandle: HardwareVMInstanceHandle, @unchecked Sendable {
    let vmID: VMID
    private let lock = NSLock()
    private var hostFD: Int32 = -1
    private var peerFD: Int32 = -1
    private var sender: M4S2GuestWireSender?
    private var readTask: Task<Void, Never>?
    private var stopObserver: (@Sendable (HardwareVMStopEvent) -> Void)?
    private(set) var connectCount: Int = 0

    init(vmID: VMID) {
        self.vmID = vmID
    }

    func prematureStopReason() -> String? { nil }

    func setStopObserver(_ observer: (@Sendable (HardwareVMStopEvent) -> Void)?) {
        lock.withLock { stopObserver = observer }
    }

    func closeGuestPeerSocketOnly() {
        let (p, s, t) = lock.withLock { () -> (Int32, M4S2GuestWireSender?, Task<Void, Never>?) in
            let curP = peerFD
            let curS = sender
            let curT = readTask
            peerFD = -1
            sender = nil
            readTask = nil
            return (curP, curS, curT)
        }
        s?.markClosed()
        t?.cancel()
        if p >= 0 {
            _ = Darwin.close(p)
        }
    }

    func connectVsock(port: UInt32) async throws -> HardwareVsockFDDescriptor {
        _ = port
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
        let wireSender = M4S2GuestWireSender(fd: pFD)

        let task = Task.detached {
            let codec = VsockWireCodec()
            let acc = VsockStreamAccumulator(codec: codec)
            var buf = [UInt8](repeating: 0, count: 65_536)
            var pfPorts: [UInt32: UInt16] = [:]
            var pfBuffers: [UInt32: Data] = [:]

            wireSender.sendHeartbeat()

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
                        if let ctrl = try? VsockWireJSON.decode(VsockControlEnvelope.self, from: payload), ctrl.kind == .ping {
                            let pong = VsockControlEnvelope(kind: .pong, agentVersion: "2")
                            if let data = try? VsockWireJSON.encode(pong) {
                                _ = wireSender.sendFrame(channel: .control, flags: [.ack, .endOfMessage], streamID: 0, payload: data)
                            }
                        }
                    case .telemetryHeartbeat:
                        wireSender.sendHeartbeat()
                    case .tcpPortForward:
                        let sid = header.streamID
                        if header.flags.contains(.syn),
                           let req = try? VsockWireJSON.decode(VsockPortForwardEnvelope.self, from: payload) {
                            pfPorts[sid] = req.guestPort
                            pfBuffers[sid] = Data()
                            let ack = VsockPortForwardEnvelope(action: .connectAck, guestPort: req.guestPort)
                            if let ackBytes = try? VsockWireJSON.encode(ack) {
                                _ = wireSender.sendFrame(channel: .tcpPortForward, flags: [.syn, .ack], streamID: sid, payload: ackBytes)
                            }
                            continue
                        }
                        if !payload.isEmpty {
                            pfBuffers[sid, default: Data()].append(payload)
                        }
                        if header.flags.contains(.rst) {
                            pfPorts.removeValue(forKey: sid)
                            pfBuffers.removeValue(forKey: sid)
                            continue
                        }
                        if header.flags.contains(.fin) {
                            let gPort = pfPorts.removeValue(forKey: sid) ?? 0
                            let body = pfBuffers.removeValue(forKey: sid) ?? Data()
                            var reply = Data("GUEST:\(gPort):".utf8)
                            reply.append(body)
                            _ = wireSender.sendFrame(channel: .tcpPortForward, flags: [.ack], streamID: sid, payload: reply)
                            _ = wireSender.sendFrame(channel: .tcpPortForward, flags: [.fin, .endOfMessage], streamID: sid, payload: Data())
                        }
                    default:
                        break
                    }
                }
            }
        }

        lock.withLock {
            connectCount += 1
            hostFD = hFD
            peerFD = pFD
            sender = wireSender
            readTask = task
        }
        return HardwareVsockFDDescriptor(fileDescriptor: hFD, closeWhenSessionEnds: false)
    }

    func forceCloseSockets() {
        let (h, p, s, t) = lock.withLock { () -> (Int32, Int32, M4S2GuestWireSender?, Task<Void, Never>?) in
            let curH = hostFD
            let curP = peerFD
            let curS = sender
            let curT = readTask
            hostFD = -1
            peerFD = -1
            sender = nil
            readTask = nil
            return (curH, curP, curS, curT)
        }
        s?.markClosed()
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
        _ = gracefulTimeoutNanoseconds
        lock.withLock { stopObserver = nil }
        forceCloseSockets()
        return .guestShutdown
    }
}
