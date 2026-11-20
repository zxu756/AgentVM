import AgentVMCLIAndMCP
import AgentVMHypervisor
import AgentVMModels
import AgentVMStorageCoW
import AgentVMStore
import AgentVMVsockRPC
import Darwin
import Foundation
import Testing

// MARK: - Scriptable Mock Hardware Backend & Guest Vsock Responder for M3 Stage 3b

private final class M3Stage3bGuestWireWriter: @unchecked Sendable {
    private let lock = NSLock()
    private var fd: Int32
    private var closed = false
    private var seqByStream: [UInt32: UInt32] = [:]
    private let codec = VsockWireCodec()

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
    func sendRawFrame(
        channel: VsockChannelKind,
        flags: VsockFrameFlags,
        streamID: UInt32,
        windowCredit: UInt32 = VsockWireConstants.defaultWindowCredit,
        payload: Data,
        compress: Bool = false
    ) -> Bool {
        return lock.withLock {
            guard !closed, fd >= 0 else { return false }
            let seq = (seqByStream[streamID] ?? 0) &+ 1
            seqByStream[streamID] = seq
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
            return wire.withUnsafeBytes { rawBuf in
                guard let base = rawBuf.baseAddress else { return true }
                var written = 0
                while written < rawBuf.count {
                    let n = Darwin.write(fd, base.advanced(by: written), rawBuf.count - written)
                    if n > 0 {
                        written += n
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

    @discardableResult
    func sendPong(agentVersion: String = "2") -> Bool {
        let pong = VsockControlEnvelope(
            kind: .pong,
            agentVersion: agentVersion
        )
        guard let payload = try? VsockWireJSON.encode(pong) else { return false }
        return sendRawFrame(
            channel: .control,
            flags: [.ack, .endOfMessage],
            streamID: 0,
            payload: payload,
            compress: false
        )
    }

    @discardableResult
    func sendHeartbeat(hostname: String = "m3-s3b-guest", uptimeSeconds: Double = 12.0) -> Bool {
        let hb = GuestHeartbeatPayload(
            hostname: hostname,
            kernelRelease: "6.1.0-54-cloud-arm64",
            uptimeSeconds: uptimeSeconds,
            loadAvg1: 0.05,
            loadAvg5: 0.05,
            loadAvg15: 0.05,
            memTotalBytes: 2_147_483_648,
            memAvailableBytes: 1_900_000_000,
            rootFilesystemUsedBytes: 900_000_000,
            rootFilesystemTotalBytes: 4_194_304
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

    @discardableResult
    func sendOutputChunk(streamID: UInt32, requestID: UUID, stream: GuestExecStreamKind, text: String) -> Bool {
        let chunk = GuestExecOutputChunk(requestID: requestID, stream: stream, sequence: 1, data: Data(text.utf8))
        guard let payload = try? VsockWireJSON.encode(chunk) else { return false }
        return sendRawFrame(
            channel: .execProcess,
            flags: [.ack],
            streamID: streamID,
            payload: payload,
            compress: false
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
}

private struct M3Stage3bBackendObservation: Sendable {
    var event: String
    var uptimeNanoseconds: UInt64
    var gracefulTimeoutNanoseconds: UInt64?
    var observedDiskIno: UInt64?
    var observedDiskSHA256: String?
    var snapshotFileNames: [String]
    var snapshotSHA256ByFile: [String: String]
    var spec: VMSpec?
}

private final class M3Stage3bMockBackend: HardwareVMLowLevelBackend, @unchecked Sendable {
    private let lock = NSLock()
    private let workspaceURL: URL
    private var pongDelayNanoseconds: UInt64 = 0
    private var nextStartError: Error?
    private(set) var observations: [M3Stage3bBackendObservation] = []
    private var handles: [M3Stage3bMockVMHandle] = []

    init(workspaceURL: URL, pongDelayNanoseconds: UInt64 = 0) {
        self.workspaceURL = workspaceURL
        self.pongDelayNanoseconds = pongDelayNanoseconds
    }

    func setPongDelayNanoseconds(_ ns: UInt64) {
        lock.withLock { pongDelayNanoseconds = ns }
    }

    func currentPongDelayNanoseconds() -> UInt64 {
        lock.withLock { pongDelayNanoseconds }
    }

    func setFailNextStartMachine(_ error: Error?) {
        lock.withLock { nextStartError = error }
    }

    func clearObservations() {
        lock.withLock { observations.removeAll() }
    }

    func snapshotObservations() -> [M3Stage3bBackendObservation] {
        lock.withLock { observations }
    }

    fileprivate func recordObservation(
        event: String,
        spec: VMSpec?,
        gracefulTimeoutNanoseconds: UInt64? = nil
    ) {
        var ino: UInt64?
        var diskSHA: String?
        if let diskPath = spec?.blockDevices.first?.imagePath {
            var st = Darwin.stat()
            if stat(diskPath, &st) == 0 {
                ino = st.st_ino
            }
            diskSHA = try? BinaryChecksums.sha256HexFile(at: URL(fileURLWithPath: diskPath))
        }
        let snapsDir = workspaceURL.appendingPathComponent("snapshots", isDirectory: true)
        let names = ((try? FileManager.default.contentsOfDirectory(atPath: snapsDir.path)) ?? []).sorted()
        var snapSHAs: [String: String] = [:]
        for n in names where n.hasSuffix(".raw") {
            let p = snapsDir.appendingPathComponent(n)
            if let d = try? BinaryChecksums.sha256HexFile(at: p) {
                snapSHAs[n] = d
            }
        }
        let obs = M3Stage3bBackendObservation(
            event: event,
            uptimeNanoseconds: DispatchTime.now().uptimeNanoseconds,
            gracefulTimeoutNanoseconds: gracefulTimeoutNanoseconds,
            observedDiskIno: ino,
            observedDiskSHA256: diskSHA,
            snapshotFileNames: names,
            snapshotSHA256ByFile: snapSHAs,
            spec: spec
        )
        lock.withLock {
            observations.append(obs)
        }
    }

    func shutdownAll() {
        let copy = lock.withLock { () -> [M3Stage3bMockVMHandle] in
            let all = handles
            handles.removeAll()
            return all
        }
        for h in copy {
            h.forceClose()
        }
    }

    func startMachine(
        spec: VMSpec,
        networkSocketFD: Int32?,
        consoleLogURL: URL,
        translator: VZConfigurationTranslator
    ) async throws -> any HardwareVMInstanceHandle {
        recordObservation(event: "startMachine", spec: spec)
        if let injected = lock.withLock({ () -> Error? in
            let e = nextStartError
            nextStartError = nil
            return e
        }) {
            throw injected
        }
        _ = try translator.buildVZConfiguration(
            from: spec,
            networkSocketFD: networkSocketFD,
            serialLogFileURL: consoleLogURL,
            validateConfiguration: false
        )
        let handle = M3Stage3bMockVMHandle(owner: self, spec: spec)
        lock.withLock {
            handles.append(handle)
        }
        return handle
    }
}

private final class M3Stage3bMockVMHandle: HardwareVMInstanceHandle, @unchecked Sendable {
    private unowned let owner: M3Stage3bMockBackend
    private let spec: VMSpec
    private let lock = NSLock()
    private var hostFD: Int32 = -1
    private var peerFD: Int32 = -1
    private var writer: M3Stage3bGuestWireWriter?
    private var readTask: Task<Void, Never>?

    init(owner: M3Stage3bMockBackend, spec: VMSpec) {
        self.owner = owner
        self.spec = spec
    }

    func prematureStopReason() -> String? { nil }

    func connectVsock(port: UInt32) async throws -> HardwareVsockFDDescriptor {
        forceClose()
        owner.recordObservation(event: "connectVsock", spec: spec)
        var fds: [Int32] = [-1, -1]
        guard Darwin.socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(Darwin.errno))
        }
        var one: Int32 = 1
        _ = Darwin.setsockopt(fds[0], SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        _ = Darwin.setsockopt(fds[1], SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))

        let hFD = fds[0]
        let pFD = fds[1]
        let wireWriter = M3Stage3bGuestWireWriter(fd: pFD)
        let backendOwner = owner
        let handleSpec = spec

        let task = Task.detached {
            let codec = VsockWireCodec()
            let acc = VsockStreamAccumulator(codec: codec)
            var buf = [UInt8](repeating: 0, count: 65_536)
            var execBuffers: [UInt32: Data] = [:]

            _ = wireWriter.sendHeartbeat(hostname: handleSpec.name)

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
                        let delayNs = backendOwner.currentPongDelayNanoseconds()
                        if delayNs > 0 {
                            try? await Task.sleep(nanoseconds: delayNs)
                        }
                        backendOwner.recordObservation(event: "guestdPong", spec: handleSpec)
                        _ = wireWriter.sendPong(agentVersion: "2")
                    case .telemetryHeartbeat:
                        _ = wireWriter.sendHeartbeat(hostname: handleSpec.name)
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
                            if req.executable == "/bin/sync" || req.executable == "sync" {
                                backendOwner.recordObservation(event: "guestSync", spec: handleSpec)
                            }
                            _ = wireWriter.sendOutputChunk(
                                streamID: sid,
                                requestID: req.id,
                                stream: .stdout,
                                text: "ok\n"
                            )
                            _ = wireWriter.sendCompletion(
                                streamID: sid,
                                requestID: req.id,
                                exitCode: 0
                            )
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
            writer = wireWriter
            readTask = task
        }
        return HardwareVsockFDDescriptor(fileDescriptor: hFD, closeWhenSessionEnds: false)
    }

    func forceClose() {
        let (h, p, w, t) = lock.withLock { () -> (Int32, Int32, M3Stage3bGuestWireWriter?, Task<Void, Never>?) in
            let ch = hostFD
            let cp = peerFD
            let cw = writer
            let ct = readTask
            hostFD = -1
            peerFD = -1
            writer = nil
            readTask = nil
            return (ch, cp, cw, ct)
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

    func pause() async throws {
        owner.recordObservation(event: "pause", spec: spec)
    }

    func resume() async throws {
        owner.recordObservation(event: "resume", spec: spec)
    }

    func saveMachineState(to url: URL) async throws {
        Issue.record("saveMachineState must never be called during M3 disk-only restore")
    }

    func shutdown(gracefulTimeoutNanoseconds: UInt64) async {
        _ = await shutdownReportingDisposition(gracefulTimeoutNanoseconds: gracefulTimeoutNanoseconds)
    }

    func shutdownReportingDisposition(gracefulTimeoutNanoseconds: UInt64) async -> HardwareVMShutdownDisposition {
        owner.recordObservation(
            event: "halt",
            spec: spec,
            gracefulTimeoutNanoseconds: gracefulTimeoutNanoseconds
        )
        forceClose()
        return .guestShutdown
    }
}

@Suite("M3 Stage 3b: Pre-Restore Auto Snapshot, Live Daemon Restore (halt -> snapshot -> swap -> up) & Identity Invariance", .timeLimit(.minutes(2)))
struct M3Stage3bRestoreTests {

    private func makePrivateTmpDirectory(prefix: String = "avm-m3-s3b") throws -> String {
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
        gracefulStopTimeoutNanoseconds: UInt64 = 30_000_000_000,
        _ body: (WorkspaceDaemonServer) async throws -> T
    ) async throws -> T {
        let outcome = try await WorkspaceDaemonServer.start(
            workspaceURL: workspaceURL,
            imageCacheDirectoryURL: imageCacheDirectoryURL,
            curatedImageEntries: curatedImageEntries,
            hardwareBackendOverride: hardwareBackendOverride,
            vsockConnectTimeoutNanoseconds: 5_000_000_000,
            vsockRetryIntervalNanoseconds: 10_000_000,
            gracefulStopTimeoutNanoseconds: gracefulStopTimeoutNanoseconds
        )
        guard case let .started(server) = outcome else {
            Issue.record("Expected WorkspaceDaemonServer.start to acquire singleton lock for \(workspaceURL.path)")
            throw NSError(domain: "M3Stage3bRestoreTests", code: 1)
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

    private func decodeJSON<T: Decodable>(_ type: T.Type, from rawJSON: String) throws -> T {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(T.self, from: Data(rawJSON.utf8))
    }

    private func invokeMCPTool(
        _ mcp: AgentVMMCPServer,
        id: Int,
        name: String,
        arguments: [String: Any]
    ) async throws -> (isError: Bool, text: String) {
        let reqObj: [String: Any] = [
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": [
                "name": name,
                "arguments": arguments
            ]
        ]
        let reqLine = String(decoding: try JSONSerialization.data(withJSONObject: reqObj), as: UTF8.self)
        let respLine = try #require(await mcp.handleJSONRPCLine(reqLine))
        let respObj = try #require(try JSONSerialization.jsonObject(with: Data(respLine.utf8)) as? [String: Any])
        let resultObj = try #require(respObj["result"] as? [String: Any], "Expected MCP result envelope, got: \(respLine)")
        let isError = (resultObj["isError"] as? Bool) ?? true
        let contentArr = (resultObj["content"] as? [[String: Any]]) ?? []
        let text = contentArr.compactMap { $0["text"] as? String }.joined(separator: "\n")
        return (isError, text)
    }

    private func writeDiskMarker(at diskURL: URL, offset: UInt64 = 1_572_864, marker: String) throws -> String {
        let fh = try FileHandle(forUpdating: diskURL)
        try fh.seek(toOffset: offset)
        try fh.write(contentsOf: Data(marker.utf8))
        try fh.synchronize()
        try fh.close()
        return try BinaryChecksums.sha256HexFile(at: diskURL)
    }

    private func extractPrintedSnapshotIDs(from text: String) -> [String] {
        guard let regex = try? NSRegularExpression(pattern: #"snap-[0-9a-f]+"#) else {
            return []
        }
        let nsRange = NSRange(text.startIndex..<text.endIndex, in: text)
        return regex.matches(in: text, range: nsRange).compactMap { match in
            guard let r = Range(match.range, in: text) else { return nil }
            return String(text[r])
        }
    }

    // MARK: - 1. Stopped Restore Captures Auto Pre-Restore Snapshot, Prints ID (EN/ZH/MCP/Sim), & Row 16 Undo

    @Test("A60 (Row 16 & 17): stopped restore captures 'auto: before restore <id>' cold-disk snapshot first, prints its ID in EN/ZH/MCP/simulation, and restoring that auto-snapshot recovers pre-restore disk")
    func stoppedRestoreCapturesAutoPreRestoreSnapshotPrintsIDBilinguallyAndRestoresAutoSnapshot() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-m3-s3b-stopped")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/StoppedRestore.agentvm", isDirectory: true)
        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()
        let forbiddenSpawn = DaemonSpawnCommandOverride(executablePath: "/bin/sh", arguments: ["-c", "exit 94"], environment: env)

        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "create", "p", "--image", entry.id],
            curatedEntriesOverride: [entry],
            environment: env
        ).exitCode == 0)

        let inspectStore = try AgentVMProjectStore(bundleURL: wsURL, createIfMissing: false)
        let pRec = try #require(try await inspectStore.listVMs().first(where: { $0.spec.name == "p" }))
        let pID = pRec.id
        let diskURL = URL(fileURLWithPath: try #require(pRec.spec.blockDevices.first?.imagePath))

        let s1MarkerSHA = try writeDiskMarker(at: diskURL, marker: "S1_SAVED_MARKER_PAYLOAD_0001")
        let s1Out = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "snapshot", "p", "s1"],
            curatedEntriesOverride: [entry],
            environment: env,
            daemonSpawnOverride: forbiddenSpawn
        )
        #expect(s1Out.exitCode == 0)
        let snapsAfterS1 = try await inspectStore.listSnapshots(forVM: pID)
        let s1Node = try #require(snapsAfterS1.first(where: { $0.title == "s1" }))

        // Mutate disk (simulating deleting /root/a before restore)
        let mutatedENSHA = try writeDiskMarker(at: diskURL, marker: "DELETED_ROOT_A_BEFORE_EN_RESTORE")
        #expect(mutatedENSHA != s1MarkerSHA)
        let snapIDsBeforeEN = Set((try await inspectStore.listSnapshots(forVM: pID)).map(\.id.rawValue))

        // EN stopped restore
        let restoreEN = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "restore", s1Node.id.rawValue],
            curatedEntriesOverride: [entry],
            environment: env,
            daemonSpawnOverride: forbiddenSpawn
        )
        #expect(restoreEN.exitCode == 0, "restore EN failed: \(restoreEN.stderr)")
        let snapsAfterEN = try await inspectStore.listSnapshots(forVM: pID)
        let newENNodes = snapsAfterEN.filter { !snapIDsBeforeEN.contains($0.id.rawValue) }
        #expect(newENNodes.count == 1, "Expected exactly 1 pre-restore auto snapshot on EN stopped restore, got \(newENNodes.count)")
        if let autoEN = newENNodes.first {
            #expect(autoEN.title == "auto: before restore \(s1Node.id.rawValue)")
            #expect(autoEN.kind == .coldDiskOnly)
            #expect(autoEN.parentSnapshotID == s1Node.id)
            #expect(restoreEN.stdout.contains(autoEN.id.rawValue), "EN restore stdout must print auto-snapshot ID \(autoEN.id.rawValue), got: \(restoreEN.stdout)")
            let autoENCloneSHA = try BinaryChecksums.sha256HexFile(at: URL(fileURLWithPath: autoEN.diskClonePath))
            #expect(autoENCloneSHA == mutatedENSHA, "Pre-restore auto snapshot must preserve pre-restore disk bytes")
        }
        #expect((try BinaryChecksums.sha256HexFile(at: diskURL)) == s1MarkerSHA)
        let pAfterEN = try #require(try await inspectStore.fetchVM(pID))
        #expect(pAfterEN.currentHeadSnapshotID == s1Node.id)
        #expect(pAfterEN.telemetry.state == .stopped)

        // ZH stopped restore
        let mutatedZHSHA = try writeDiskMarker(at: diskURL, marker: "DELETED_ROOT_A_BEFORE_ZH_RESTORE")
        let snapIDsBeforeZH = Set((try await inspectStore.listSnapshots(forVM: pID)).map(\.id.rawValue))
        let restoreZH = await cli.execute(
            arguments: ["--lang", "zh", "--workspace", wsURL.path, "restore", s1Node.id.rawValue],
            curatedEntriesOverride: [entry],
            environment: env,
            daemonSpawnOverride: forbiddenSpawn
        )
        #expect(restoreZH.exitCode == 0, "restore ZH failed: \(restoreZH.stderr)")
        let newZHNodes = (try await inspectStore.listSnapshots(forVM: pID)).filter { !snapIDsBeforeZH.contains($0.id.rawValue) }
        #expect(newZHNodes.count == 1, "Expected 1 pre-restore auto snapshot on ZH stopped restore, got \(newZHNodes.count)")
        if let autoZH = newZHNodes.first {
            #expect(autoZH.title == "auto: before restore \(s1Node.id.rawValue)")
            #expect(autoZH.kind == .coldDiskOnly)
            #expect(restoreZH.stdout.contains(autoZH.id.rawValue), "ZH restore stdout must print auto-snapshot ID \(autoZH.id.rawValue), got: \(restoreZH.stdout)")
            let autoZHCloneSHA = try BinaryChecksums.sha256HexFile(at: URL(fileURLWithPath: autoZH.diskClonePath))
            #expect(autoZHCloneSHA == mutatedZHSHA)

            // Row 16 check: restore the auto-created snapshot -> recovers mutatedZHSHA!
            let undoRes = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "restore", autoZH.id.rawValue],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(undoRes.exitCode == 0)
            #expect((try BinaryChecksums.sha256HexFile(at: diskURL)) == mutatedZHSHA, "Restoring auto pre-restore snapshot must bring back pre-restore disk contents")
        }

        // MCP stopped restore also creates auto pre-restore snapshot and returns its ID
        let mcpCoord = try AgentVMFleetCoordinator(
            bundleURL: wsURL,
            executionBackend: .strictHardwareVZ,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry]
        )
        let mcp = AgentVMMCPServer(coordinator: mcpCoord)
        let snapIDsBeforeMCP = Set((try await inspectStore.listSnapshots(forVM: pID)).map(\.id.rawValue))
        let mcpRes = try await invokeMCPTool(mcp, id: 1, name: "agentvm_restore_snapshot", arguments: [
            "snapshotID": s1Node.id.rawValue
        ])
        #expect(mcpRes.isError == false, "MCP stopped restore failed: \(mcpRes.text)")
        let newMCPNodes = (try await inspectStore.listSnapshots(forVM: pID)).filter { !snapIDsBeforeMCP.contains($0.id.rawValue) }
        #expect(newMCPNodes.count == 1, "Expected MCP stopped restore to save auto pre-restore snapshot")
        if let autoMCP = newMCPNodes.first {
            #expect(autoMCP.title == "auto: before restore \(s1Node.id.rawValue)")
            #expect(mcpRes.text.contains(autoMCP.id.rawValue), "MCP restore response must include auto-snapshot ID: \(mcpRes.text)")
        }

        // Simulation backend restore also captures auto pre-restore snapshot and prints SIMULATED-marked ID
        let simWS = URL(fileURLWithPath: "\(realBase)/SimRestore.agentvm", isDirectory: true)
        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", simWS.path, "--backend", "simulation", "create", "simvm"],
            environment: env
        ).exitCode == 0)
        let simSnap = await cli.execute(
            arguments: ["--lang", "en", "--workspace", simWS.path, "--backend", "simulation", "snapshot", "simvm", "sim-s1"],
            environment: env
        )
        #expect(simSnap.exitCode == 0)
        let simS1ID = try #require(extractPrintedSnapshotIDs(from: simSnap.stdout).first)
        let simRestore = await cli.execute(
            arguments: ["--lang", "en", "--workspace", simWS.path, "--backend", "simulation", "restore", simS1ID],
            environment: env
        )
        #expect(simRestore.exitCode == 0)
        let printedSimIDs = extractPrintedSnapshotIDs(from: simRestore.stdout).filter { $0 != simS1ID }
        #expect(!printedSimIDs.isEmpty, "Simulation restore stdout must print auto pre-restore snapshot ID, got: \(simRestore.stdout)")
    }

    // MARK: - 2. Pre-Restore Snapshot Failure Does Not Swap Disk (Exits 1 & Explains, Stopped + Live)

    @Test("A60: if capturing the pre-restore snapshot fails, restore does not swap the root disk, exits 1, and explains (stopped and live)")
    func preRestoreSnapshotFailureAbortsWithoutSwappingDiskAndReturnsExit1WithExplanation() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-m3-s3b-presnapfail")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/PreSnapFail.agentvm", isDirectory: true)
        let snapshotsDir = wsURL.appendingPathComponent("snapshots", isDirectory: true)
        defer { _ = Darwin.chmod(snapshotsDir.path, 0o755) }

        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()
        let forbiddenSpawn = DaemonSpawnCommandOverride(executablePath: "/bin/sh", arguments: ["-c", "exit 94"], environment: env)

        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "create", "p", "--image", entry.id],
            curatedEntriesOverride: [entry],
            environment: env
        ).exitCode == 0)

        let inspectStore = try AgentVMProjectStore(bundleURL: wsURL, createIfMissing: false)
        let pRec = try #require(try await inspectStore.listVMs().first(where: { $0.spec.name == "p" }))
        let pID = pRec.id
        let diskURL = URL(fileURLWithPath: try #require(pRec.spec.blockDevices.first?.imagePath))
        let lockURL = wsURL.appendingPathComponent("locks/\(pID.rawValue).lock")

        _ = try writeDiskMarker(at: diskURL, marker: "CLEAN_S1_MARKER_BYTES")
        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "snapshot", "p", "s1"],
            curatedEntriesOverride: [entry],
            environment: env,
            daemonSpawnOverride: forbiddenSpawn
        ).exitCode == 0)
        let s1Node = try #require((try await inspectStore.listSnapshots(forVM: pID)).first(where: { $0.title == "s1" }))

        let keptMutatedSHA = try writeDiskMarker(at: diskURL, marker: "MUST_SURVIVE_FAILED_PRE_RESTORE_SNAP")
        var statBefore = Darwin.stat()
        #expect(stat(diskURL.path, &statBefore) == 0)

        // Part A: Stopped local VM with read-only snapshots/ directory -> pre-restore clonefile fails, disk untouched!
        #expect(Darwin.chmod(snapshotsDir.path, 0o555) == 0)
        for lang in ["en", "zh"] {
            let res = await cli.execute(
                arguments: ["--lang", lang, "--workspace", wsURL.path, "restore", s1Node.id.rawValue],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(res.exitCode == 1, "Stopped restore (\(lang)) must exit 1 when pre-restore snapshot fails, got \(res.exitCode)")
            #expect(!res.stderr.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, "Stopped restore (\(lang)) must explain failure on stderr")
            var statAfter = Darwin.stat()
            #expect(stat(diskURL.path, &statAfter) == 0)
            #expect(statAfter.st_ino == statBefore.st_ino, "Stopped restore (\(lang)) must NOT swap root disk inode when pre-restore snapshot fails")
            #expect((try BinaryChecksums.sha256HexFile(at: diskURL)) == keptMutatedSHA, "Stopped restore (\(lang)) must NOT overwrite root disk bytes when pre-restore snapshot fails")
        }
        #expect(VMExecutionLock.isLocked(at: lockURL) == false)
        #expect(Darwin.chmod(snapshotsDir.path, 0o755) == 0)

        // Part B: Running daemon-held VM with read-only snapshots/ directory -> halts, pre-restore snapshot fails,
        // does NOT swap disk, reboots original disk, exits 1 and explains!
        let mockBackend = M3Stage3bMockBackend(workspaceURL: wsURL)
        defer { mockBackend.shutdownAll() }

        try await withStartedDaemonServer(
            workspaceURL: wsURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mockBackend
        ) { _ in
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "p"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)

            var liveStatBefore = Darwin.stat()
            #expect(stat(diskURL.path, &liveStatBefore) == 0)
            #expect(Darwin.chmod(snapshotsDir.path, 0o555) == 0)
            defer { _ = Darwin.chmod(snapshotsDir.path, 0o755) }

            for lang in ["en", "zh"] {
                let liveRes = await cli.execute(
                    arguments: ["--lang", lang, "--workspace", wsURL.path, "restore", s1Node.id.rawValue],
                    curatedEntriesOverride: [entry],
                    environment: env,
                    daemonSpawnOverride: forbiddenSpawn
                )
                #expect(liveRes.exitCode == 1, "Live restore (\(lang)) must exit 1 when pre-restore snapshot fails")
                #expect(!liveRes.stderr.contains("ERR_LIVE_RESTORE_UNIMPLEMENTED"), "ERR_LIVE_RESTORE_UNIMPLEMENTED must not appear: \(liveRes.stderr)")
                var liveStatAfter = Darwin.stat()
                #expect(stat(diskURL.path, &liveStatAfter) == 0)
                #expect(liveStatAfter.st_ino == liveStatBefore.st_ino, "Live restore (\(lang)) must NOT swap disk when pre-restore snapshot fails")
                #expect((try BinaryChecksums.sha256HexFile(at: diskURL)) == keptMutatedSHA)

                let psOut = await cli.execute(
                    arguments: ["--lang", "en", "--workspace", wsURL.path, "ps", "--json"],
                    curatedEntriesOverride: [entry],
                    environment: env,
                    daemonSpawnOverride: forbiddenSpawn
                )
                let vms = try decodeJSON([VMInstanceRecord].self, from: psOut.stdout)
                let pNow = try #require(vms.first(where: { $0.id == pID }))
                #expect(pNow.telemetry.state == .running, "Daemon must leave VM running on original disk when pre-restore snapshot fails")
                #expect(pNow.telemetry.guestAgentConnected == true)
            }
        }
    }

    // MARK: - 3. Live Restore Routes via RPC in Strict Order: halt -> pre-snapshot -> swap-disk -> up (Waits for guestd)

    @Test("A60 (Row 15): live restore on daemon-held VM routes via RPC (CLI EN/ZH & MCP), executes halt -> pre-snapshot -> swap-disk -> up (30s graceful timeout), and waits for guestd")
    func liveRestoreRoutesViaDaemonRPCInStrictOrderHaltSnapshotSwapUpAndWaitsForGuestd() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-m3-s3b-liveorder")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/LiveOrder.agentvm", isDirectory: true)
        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()
        let forbiddenSpawn = DaemonSpawnCommandOverride(executablePath: "/bin/sh", arguments: ["-c", "exit 94"], environment: env)

        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "create", "p", "--image", entry.id],
            curatedEntriesOverride: [entry],
            environment: env
        ).exitCode == 0)

        let inspectStore = try AgentVMProjectStore(bundleURL: wsURL, createIfMissing: false)
        let pRec = try #require(try await inspectStore.listVMs().first(where: { $0.spec.name == "p" }))
        let pID = pRec.id
        let diskURL = URL(fileURLWithPath: try #require(pRec.spec.blockDevices.first?.imagePath))

        let mockBackend = M3Stage3bMockBackend(workspaceURL: wsURL)
        defer { mockBackend.shutdownAll() }

        try await withStartedDaemonServer(
            workspaceURL: wsURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mockBackend,
            gracefulStopTimeoutNanoseconds: 30_000_000_000
        ) { _ in
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "p"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)

            let s1DiskSHA = try writeDiskMarker(at: diskURL, marker: "LIVE_S1_ROOT_A_PRESENT")
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "snapshot", "p", "s1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
            let s1Node = try #require((try await inspectStore.listSnapshots(forVM: pID)).first(where: { $0.title == "s1" }))
            #expect(s1Node.kind == .liveDisk)

            // Mutate live disk (simulating deleting /root/a inside running p)
            let mutatedLiveSHA = try writeDiskMarker(at: diskURL, marker: "LIVE_ROOT_A_DELETED_NOW")
            #expect(mutatedLiveSHA != s1DiskSHA)
            var inoBeforeRestore = Darwin.stat()
            #expect(stat(diskURL.path, &inoBeforeRestore) == 0)

            let snapIDsBeforeRestore = Set((try await inspectStore.listSnapshots(forVM: pID)).map(\.id.rawValue))
            mockBackend.clearObservations()
            mockBackend.setPongDelayNanoseconds(60_000_000)

            let restoreRes = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "restore", s1Node.id.rawValue],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            let restoreFinishedNs = DispatchTime.now().uptimeNanoseconds

            #expect(restoreRes.exitCode == 0, "Expected live restore to exit 0, got \(restoreRes.exitCode): \(restoreRes.stderr)")
            #expect(!restoreRes.stderr.contains("ERR_LIVE_RESTORE_UNIMPLEMENTED"))

            let snapsAfterRestore = try await inspectStore.listSnapshots(forVM: pID)
            let newAutoNodes = snapsAfterRestore.filter { !snapIDsBeforeRestore.contains($0.id.rawValue) }
            #expect(newAutoNodes.count == 1, "Expected 1 auto pre-restore snapshot during live restore, got \(newAutoNodes.count)")
            let autoNode = newAutoNodes.first
            if let autoNode {
                #expect(autoNode.title == "auto: before restore \(s1Node.id.rawValue)")
                #expect(autoNode.kind == .coldDiskOnly)
                #expect(restoreRes.stdout.contains(autoNode.id.rawValue), "Live restore stdout must print auto-snapshot ID \(autoNode.id.rawValue), got: \(restoreRes.stdout)")
            }

            // Verify strict execution order in daemon:
            //   1) halt (graceful 30s timeout; auto-snapshot NOT created yet; disk still has mutatedLiveSHA)
            //   2) pre-restore snapshot (cloned AFTER halt and BEFORE swap-disk -> contains mutatedLiveSHA)
            //   3) swap-disk (completed BEFORE up -> startMachine sees new inode and s1DiskSHA)
            //   4) up + guestd pong (completed BEFORE restore RPC returned)
            let obs = mockBackend.snapshotObservations()
            let eventNames = obs.map(\.event)
            #expect(eventNames == ["halt", "startMachine", "connectVsock", "guestdPong"], "Expected daemon lifecycle sequence [halt, startMachine, connectVsock, guestdPong], got \(eventNames)")
            if let haltObs = obs.first(where: { $0.event == "halt" }),
               let startObs = obs.first(where: { $0.event == "startMachine" }),
               let pongObs = obs.first(where: { $0.event == "guestdPong" }),
               let autoNode {
                let autoFileName = URL(fileURLWithPath: autoNode.diskClonePath).lastPathComponent
                #expect(haltObs.gracefulTimeoutNanoseconds == 30_000_000_000)
                #expect(!haltObs.snapshotFileNames.contains(autoFileName), "Auto pre-restore snapshot must be captured AFTER halt, not while VM is still running")
                #expect(haltObs.observedDiskSHA256 == mutatedLiveSHA)

                #expect(startObs.snapshotFileNames.contains(autoFileName), "Auto pre-restore snapshot must exist BEFORE up (startMachine)")
                #expect(startObs.snapshotSHA256ByFile[autoFileName] == mutatedLiveSHA, "Auto pre-restore snapshot must capture pre-restore disk BEFORE swap-disk")
                #expect(startObs.observedDiskSHA256 == s1DiskSHA, "Root disk must already be swapped to target snapshot BEFORE up (startMachine)")
                #expect(startObs.observedDiskIno != inoBeforeRestore.st_ino, "Root disk inode must be replaced before startMachine")
                #expect(haltObs.uptimeNanoseconds <= startObs.uptimeNanoseconds)
                #expect(pongObs.uptimeNanoseconds <= restoreFinishedNs, "Live restore must wait for guestd handshake before returning")
            }

            // Verify VM is running with guestAgentConnected == true after restore
            let psAfter = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "ps", "--json"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            let vmsAfter = try decodeJSON([VMInstanceRecord].self, from: psAfter.stdout)
            let pAfter = try #require(vmsAfter.first(where: { $0.id == pID }))
            #expect(pAfter.telemetry.state == .running)
            #expect(pAfter.telemetry.guestAgentConnected == true)
            #expect(pAfter.currentHeadSnapshotID == s1Node.id)

            // ZH live restore back to autoNode (Row 16 live!) + MCP live restore
            mockBackend.setPongDelayNanoseconds(0)
            if let autoNode {
                let zhLiveRestore = await cli.execute(
                    arguments: ["--lang", "zh", "--workspace", wsURL.path, "restore", autoNode.id.rawValue],
                    curatedEntriesOverride: [entry],
                    environment: env,
                    daemonSpawnOverride: forbiddenSpawn
                )
                #expect(zhLiveRestore.exitCode == 0, "ZH live restore failed: \(zhLiveRestore.stderr)")
                let printedZH = extractPrintedSnapshotIDs(from: zhLiveRestore.stdout).filter { $0 != autoNode.id.rawValue }
                #expect(!printedZH.isEmpty, "ZH live restore stdout must print new auto-snapshot ID: \(zhLiveRestore.stdout)")
                #expect((try BinaryChecksums.sha256HexFile(at: diskURL)) == mutatedLiveSHA)
            }

            let externalCoord = try AgentVMFleetCoordinator(
                bundleURL: wsURL,
                executionBackend: .strictHardwareVZ,
                imageCacheDirectoryURL: cacheDir,
                curatedImageEntries: [entry]
            )
            let mcp = AgentVMMCPServer(coordinator: externalCoord)
            let mcpLiveRes = try await invokeMCPTool(mcp, id: 2, name: "agentvm_restore_snapshot", arguments: [
                "snapshotID": s1Node.id.rawValue
            ])
            #expect(mcpLiveRes.isError == false, "MCP live restore must succeed via daemon RPC, got: \(mcpLiveRes.text)")
            let mcpPrinted = extractPrintedSnapshotIDs(from: mcpLiveRes.text).filter { $0 != s1Node.id.rawValue }
            #expect(!mcpPrinted.isEmpty, "MCP live restore text must include pre-restore snapshot ID: \(mcpLiveRes.text)")
            #expect((try BinaryChecksums.sha256HexFile(at: diskURL)) == s1DiskSHA)
        }
    }

    // MARK: - 4. Disk Swap Failure During Live Restore Reboots Original Disk & Returns Exit 1

    @Test("A60: when disk swap fails during live restore, daemon reboots VM on its intact original disk, waits for guestd, and returns exit 1 with explanation")
    func liveRestoreDiskSwapFailureRebootsOriginalDiskAndReturnsExit1() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-m3-s3b-swapfail")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/SwapFail.agentvm", isDirectory: true)
        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()
        let forbiddenSpawn = DaemonSpawnCommandOverride(executablePath: "/bin/sh", arguments: ["-c", "exit 94"], environment: env)

        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "create", "p", "--image", entry.id],
            curatedEntriesOverride: [entry],
            environment: env
        ).exitCode == 0)

        let inspectStore = try AgentVMProjectStore(bundleURL: wsURL, createIfMissing: false)
        let pRec = try #require(try await inspectStore.listVMs().first(where: { $0.spec.name == "p" }))
        let pID = pRec.id
        let diskURL = URL(fileURLWithPath: try #require(pRec.spec.blockDevices.first?.imagePath))

        let mockBackend = M3Stage3bMockBackend(workspaceURL: wsURL)
        defer { mockBackend.shutdownAll() }

        try await withStartedDaemonServer(
            workspaceURL: wsURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mockBackend
        ) { _ in
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "p"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)

            _ = try writeDiskMarker(at: diskURL, marker: "TARGET_SNAP_S1_BYTES")
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "snapshot", "p", "s1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
            let s1Node = try #require((try await inspectStore.listSnapshots(forVM: pID)).first(where: { $0.title == "s1" }))

            let origDiskSHA = try writeDiskMarker(at: diskURL, marker: "ORIGINAL_DISK_MUST_BOOT_ON_SWAP_ERR")
            var origStat = Darwin.stat()
            #expect(stat(diskURL.path, &origStat) == 0)

            // Remove s1's backing clone file so halt + pre-restore snapshot succeed, then disk swap fails!
            try FileManager.default.removeItem(atPath: s1Node.diskClonePath)

            for lang in ["en", "zh"] {
                mockBackend.clearObservations()
                let res = await cli.execute(
                    arguments: ["--lang", lang, "--workspace", wsURL.path, "restore", s1Node.id.rawValue],
                    curatedEntriesOverride: [entry],
                    environment: env,
                    daemonSpawnOverride: forbiddenSpawn
                )
                #expect(res.exitCode == 1, "Expected live restore (\(lang)) to exit 1 on disk swap failure")
                #expect(!res.stderr.contains("ERR_LIVE_RESTORE_UNIMPLEMENTED"), "Must not return ERR_LIVE_RESTORE_UNIMPLEMENTED: \(res.stderr)")
                #expect(!res.stderr.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

                let obs = mockBackend.snapshotObservations()
                let events = obs.map(\.event)
                #expect(events == ["halt", "startMachine", "connectVsock", "guestdPong"], "Swap failure (\(lang)) must halt and then reboot original disk, got \(events)")
                if let recoveryStart = obs.first(where: { $0.event == "startMachine" }) {
                    #expect(recoveryStart.observedDiskIno == origStat.st_ino, "Recovery boot must use untouched original disk inode")
                    #expect(recoveryStart.observedDiskSHA256 == origDiskSHA, "Recovery boot must use untouched original disk contents")
                }

                let psOut = await cli.execute(
                    arguments: ["--lang", "en", "--workspace", wsURL.path, "ps", "--json"],
                    curatedEntriesOverride: [entry],
                    environment: env,
                    daemonSpawnOverride: forbiddenSpawn
                )
                let vms = try decodeJSON([VMInstanceRecord].self, from: psOut.stdout)
                let pNow = try #require(vms.first(where: { $0.id == pID }))
                #expect(pNow.telemetry.state == .running)
                #expect(pNow.telemetry.guestAgentConnected == true)
            }

            let externalCoord = try AgentVMFleetCoordinator(
                bundleURL: wsURL,
                executionBackend: .strictHardwareVZ,
                imageCacheDirectoryURL: cacheDir,
                curatedImageEntries: [entry]
            )
            let mcp = AgentVMMCPServer(coordinator: externalCoord)
            let mcpFail = try await invokeMCPTool(mcp, id: 10, name: "agentvm_restore_snapshot", arguments: [
                "snapshotID": s1Node.id.rawValue
            ])
            #expect(mcpFail.isError == true)
            #expect(!mcpFail.text.contains("ERR_LIVE_RESTORE_UNIMPLEMENTED"))
        }
    }

    // MARK: - 5. Boot Failure During Live Restore Leaves VM Cleanly Stopped & Releases Execution Lock

    @Test("A60: when rebooting after disk swap fails during live restore, VM is left cleanly stopped with execution lock released and exit 1")
    func liveRestoreBootFailureLeavesVMStoppedCleanlyAndReleasesLock() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-m3-s3b-upfail")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/UpFail.agentvm", isDirectory: true)
        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()
        let forbiddenSpawn = DaemonSpawnCommandOverride(executablePath: "/bin/sh", arguments: ["-c", "exit 94"], environment: env)

        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "create", "p", "--image", entry.id],
            curatedEntriesOverride: [entry],
            environment: env
        ).exitCode == 0)

        let inspectStore = try AgentVMProjectStore(bundleURL: wsURL, createIfMissing: false)
        let pRec = try #require(try await inspectStore.listVMs().first(where: { $0.spec.name == "p" }))
        let pID = pRec.id
        let diskURL = URL(fileURLWithPath: try #require(pRec.spec.blockDevices.first?.imagePath))
        let lockURL = wsURL.appendingPathComponent("locks/\(pID.rawValue).lock")

        let mockBackend = M3Stage3bMockBackend(workspaceURL: wsURL)
        defer { mockBackend.shutdownAll() }

        try await withStartedDaemonServer(
            workspaceURL: wsURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mockBackend
        ) { _ in
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "p"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)

            let s1SHA = try writeDiskMarker(at: diskURL, marker: "S1_RESTORE_TARGET_FOR_UP_FAIL")
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "snapshot", "p", "s1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
            let s1Node = try #require((try await inspectStore.listSnapshots(forVM: pID)).first(where: { $0.title == "s1" }))
            _ = try writeDiskMarker(at: diskURL, marker: "MUTATED_BEFORE_UP_FAIL")

            mockBackend.setFailNextStartMachine(
                AgentVMError.virtualizationUnsupported(reason: "injected mock startMachine failure")
            )
            let res = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "restore", s1Node.id.rawValue],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(res.exitCode == 1, "Expected live restore to exit 1 when post-swap up fails")
            #expect(!res.stderr.contains("ERR_LIVE_RESTORE_UNIMPLEMENTED"))

            let psOut = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "ps", "--json"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            let vms = try decodeJSON([VMInstanceRecord].self, from: psOut.stdout)
            let pNow = try #require(vms.first(where: { $0.id == pID }))
            #expect(pNow.telemetry.state == .stopped, "Failed post-swap boot must leave VM cleanly stopped")
            #expect(pNow.telemetry.guestAgentConnected == false)
            #expect((try BinaryChecksums.sha256HexFile(at: diskURL)) == s1SHA)
            #expect(VMExecutionLock.isLocked(at: lockURL) == false, "Execution lock must be released when post-swap boot leaves VM stopped")

            // Subsequent `up p` works cleanly because lock was not leaked
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "p"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
        }
    }

    // MARK: - 6. Identity Fields & cidata ISO Stay Unchanged Across Stopped & Live Restore

    @Test("A60 (Row 18): restore preserves all VM identity fields (hostname, machine-id/cloud-init, instance-id, MAC, IPv4 config, cidata ISO) across both live and stopped restore")
    func restorePreservesAllVMIdentityFieldsAndCidataISOAcrossStoppedAndLiveRestore() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-m3-s3b-identity")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/IdentityRestore.agentvm", isDirectory: true)
        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()
        let forbiddenSpawn = DaemonSpawnCommandOverride(executablePath: "/bin/sh", arguments: ["-c", "exit 94"], environment: env)

        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "create", "p", "--image", entry.id],
            curatedEntriesOverride: [entry],
            environment: env
        ).exitCode == 0)
        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "branch", "p", "c1", "--no-boot"],
            curatedEntriesOverride: [entry],
            environment: env,
            daemonSpawnOverride: forbiddenSpawn
        ).exitCode == 0)

        let inspectStore = try AgentVMProjectStore(bundleURL: wsURL, createIfMissing: false)
        let c1Initial = try #require(try await inspectStore.listVMs().first(where: { $0.spec.name == "c1" }))
        let c1ID = c1Initial.id
        let isoPath = try #require(c1Initial.spec.cloudInitISOPath)
        var isoStatBefore = Darwin.stat()
        #expect(stat(isoPath, &isoStatBefore) == 0)
        let isoSHABefore = try BinaryChecksums.sha256HexFile(at: URL(fileURLWithPath: isoPath))

        let mockBackend = M3Stage3bMockBackend(workspaceURL: wsURL)
        defer { mockBackend.shutdownAll() }

        try await withStartedDaemonServer(
            workspaceURL: wsURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mockBackend
        ) { _ in
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "c1"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)

            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "snapshot", "c1", "s1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
            let s1Node = try #require((try await inspectStore.listSnapshots(forVM: c1ID)).first(where: { $0.title == "s1" }))

            mockBackend.clearObservations()
            let liveRestoreRes = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "restore", s1Node.id.rawValue],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(liveRestoreRes.exitCode == 0, "Live restore on c1 failed: \(liveRestoreRes.stderr)")

            let c1AfterLive = try #require(try await inspectStore.fetchVM(c1ID))
            #expect(c1AfterLive.spec == c1Initial.spec, "Live restore must preserve entire VMSpec (hostname, instance-id, cloudInit, ISO path, MAC, IPv4 config, machineIdentifier)")
            if let bootedSpec = mockBackend.snapshotObservations().first(where: { $0.event == "startMachine" })?.spec {
                #expect(bootedSpec == c1Initial.spec, "Rebooted VM in live restore must receive identical VMSpec")
            }

            var isoStatAfterLive = Darwin.stat()
            #expect(stat(isoPath, &isoStatAfterLive) == 0)
            #expect(isoStatAfterLive.st_ino == isoStatBefore.st_ino, "Live restore must not regenerate or replace cidata ISO")
            #expect((try BinaryChecksums.sha256HexFile(at: URL(fileURLWithPath: isoPath))) == isoSHABefore)

            // Now halt c1, take s2, stopped restore -> verify identity still identical
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "c1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)

            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "snapshot", "c1", "s2"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
            let s2Node = try #require((try await inspectStore.listSnapshots(forVM: c1ID)).first(where: { $0.title == "s2" }))

            let stoppedRestoreRes = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "restore", s2Node.id.rawValue],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(stoppedRestoreRes.exitCode == 0)
            let c1AfterStopped = try #require(try await inspectStore.fetchVM(c1ID))
            #expect(c1AfterStopped.spec == c1Initial.spec, "Stopped restore must preserve entire VMSpec")
            var isoStatAfterStopped = Darwin.stat()
            #expect(stat(isoPath, &isoStatAfterStopped) == 0)
            #expect(isoStatAfterStopped.st_ino == isoStatBefore.st_ino, "Stopped restore must not regenerate or replace cidata ISO")
            #expect((try BinaryChecksums.sha256HexFile(at: URL(fileURLWithPath: isoPath))) == isoSHABefore)
        }
    }
}
