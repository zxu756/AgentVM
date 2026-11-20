import AgentVMCLIAndMCP
import AgentVMHypervisor
import AgentVMModels
import AgentVMStorageCoW
import AgentVMStore
import AgentVMVsockRPC
import Darwin
import Foundation
import Testing

// MARK: - Scriptable Mock Hardware Backend & Guest Vsock Responder for M3 Stage 3a

private final class M3Stage3aGuestWireWriter: @unchecked Sendable {
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
    func sendHeartbeat(hostname: String = "m3-s3a-guest", uptimeSeconds: Double = 12.0) -> Bool {
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

private final class M3Stage3aMockBackend: HardwareVMLowLevelBackend, @unchecked Sendable {
    struct SyncReplyConfig: Sendable {
        var exitCode: Int32 = 0
        var stderrText: String = ""
        var timedOut: Bool = false
    }

    private let lock = NSLock()
    private var syncConfig = SyncReplyConfig()
    private var pauseDelayNanoseconds: UInt64 = 0
    private(set) var startCount = 0
    private(set) var pauseCount = 0
    private(set) var resumeCount = 0
    private(set) var isCurrentlyPaused = false
    private(set) var eventTimeline: [String] = []
    private(set) var receivedSyncRequests: [GuestExecRequest] = []
    private var handles: [M3Stage3aMockVMHandle] = []

    init(
        syncConfig: SyncReplyConfig = SyncReplyConfig(),
        pauseDelayNanoseconds: UInt64 = 0
    ) {
        self.syncConfig = syncConfig
        self.pauseDelayNanoseconds = pauseDelayNanoseconds
    }

    func updateSyncConfig(_ config: SyncReplyConfig) {
        lock.withLock { syncConfig = config }
    }

    func currentSyncConfig() -> SyncReplyConfig {
        lock.withLock { syncConfig }
    }

    func clearTimelineAndCounts() {
        lock.withLock {
            pauseCount = 0
            resumeCount = 0
            eventTimeline.removeAll()
            receivedSyncRequests.removeAll()
        }
    }

    fileprivate func recordSyncRequest(_ req: GuestExecRequest) {
        lock.withLock {
            receivedSyncRequests.append(req)
            eventTimeline.append("sync")
        }
    }

    fileprivate func recordPause() -> UInt64 {
        lock.withLock {
            pauseCount += 1
            isCurrentlyPaused = true
            eventTimeline.append("pause")
            return pauseDelayNanoseconds
        }
    }

    fileprivate func recordResume() {
        lock.withLock {
            resumeCount += 1
            isCurrentlyPaused = false
            eventTimeline.append("resume")
        }
    }

    func disconnectAllVsockPeers() {
        let copy = lock.withLock { handles }
        for h in copy {
            h.dropPeerVsockOnly()
        }
    }

    func shutdownAll() {
        let copy = lock.withLock { () -> [M3Stage3aMockVMHandle] in
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
        _ = try translator.buildVZConfiguration(
            from: spec,
            networkSocketFD: networkSocketFD,
            serialLogFileURL: consoleLogURL,
            validateConfiguration: false
        )
        let handle = M3Stage3aMockVMHandle(owner: self)
        lock.withLock {
            startCount += 1
            handles.append(handle)
        }
        return handle
    }
}

private final class M3Stage3aMockVMHandle: HardwareVMInstanceHandle, @unchecked Sendable {
    private unowned let owner: M3Stage3aMockBackend
    private let lock = NSLock()
    private var hostFD: Int32 = -1
    private var peerFD: Int32 = -1
    private var writer: M3Stage3aGuestWireWriter?
    private var readTask: Task<Void, Never>?

    init(owner: M3Stage3aMockBackend) {
        self.owner = owner
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
        let wireWriter = M3Stage3aGuestWireWriter(fd: pFD)
        let backendOwner = owner

        let task = Task.detached {
            let codec = VsockWireCodec()
            let acc = VsockStreamAccumulator(codec: codec)
            var buf = [UInt8](repeating: 0, count: 65_536)
            var execBuffers: [UInt32: Data] = [:]

            _ = wireWriter.sendHeartbeat()

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
                        _ = wireWriter.sendPong(agentVersion: "2")
                    case .telemetryHeartbeat:
                        _ = wireWriter.sendHeartbeat()
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
                                backendOwner.recordSyncRequest(req)
                                let cfg = backendOwner.currentSyncConfig()
                                if !cfg.stderrText.isEmpty {
                                    _ = wireWriter.sendOutputChunk(
                                        streamID: sid,
                                        requestID: req.id,
                                        stream: .stderr,
                                        text: cfg.stderrText
                                    )
                                }
                                _ = wireWriter.sendCompletion(
                                    streamID: sid,
                                    requestID: req.id,
                                    exitCode: cfg.exitCode,
                                    timedOut: cfg.timedOut
                                )
                            } else {
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

    func dropPeerVsockOnly() {
        let (p, w, t) = lock.withLock { () -> (Int32, M3Stage3aGuestWireWriter?, Task<Void, Never>?) in
            let cp = peerFD
            let cw = writer
            let ct = readTask
            peerFD = -1
            writer = nil
            readTask = nil
            return (cp, cw, ct)
        }
        w?.markClosed()
        t?.cancel()
        if p >= 0 {
            _ = Darwin.shutdown(p, SHUT_RDWR)
            _ = Darwin.close(p)
        }
    }

    func forceClose() {
        let (h, p, w, t) = lock.withLock { () -> (Int32, Int32, M3Stage3aGuestWireWriter?, Task<Void, Never>?) in
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
        let delayNs = owner.recordPause()
        if delayNs > 0 {
            try? await Task.sleep(nanoseconds: delayNs)
        }
    }

    func resume() async throws {
        owner.recordResume()
    }

    func saveMachineState(to url: URL) async throws {
        Issue.record("saveMachineState must never be called during M3 disk-only snapshot/branch")
    }

    func shutdown(gracefulTimeoutNanoseconds: UInt64) async {
        forceClose()
    }
}

@Suite("M3 Stage 3a: Daemon RPC snapshot/branch/restore, Routing & Live Guest-Synced Fork/Snapshot", .timeLimit(.minutes(2)))
struct M3Stage3aDaemonLiveForkSnapshotTests {

    private func makePrivateTmpDirectory(prefix: String = "avm-m3-s3a") throws -> String {
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
        vsockReconnectInitialDelayNanoseconds: UInt64 = 10_000_000_000,
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
            throw NSError(domain: "M3Stage3aDaemonLiveForkSnapshotTests", code: 1)
        }
        _ = vsockReconnectInitialDelayNanoseconds
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

    // MARK: - 1. DaemonRPC Methods (`snapshot`, `branch`, `restore`) & `live-disk` SnapshotKind Compatibility

    @Test("A61 & A59: DaemonRPC adds snapshot/branch/restore methods, and SnapshotKind 'live-disk' encodes/decodes while preserving legacy 'cold-disk' compatibility")
    func daemonRPCMethodsAndSnapshotKindLiveDiskCompatibility() async throws {
        // 1. DaemonRPCMethod includes snapshot, branch, restore
        let methodRawValues = DaemonRPCMethod.allCases.map(\.rawValue)
        #expect(methodRawValues.contains("snapshot"))
        #expect(methodRawValues.contains("branch"))
        #expect(methodRawValues.contains("restore"))

        // 2. Wire JSON-RPC request lines for snapshot, branch, and restore decode and re-encode cleanly
        let snapshotWire = Data(#"{"jsonrpc":"2.0","id":11,"method":"snapshot","params":{"vm":"p","title":"s1","lang":"zh-Hans"}}"#.utf8)
        let decodedSnapReq = try DaemonRPCCodec.decodeRequestLine(snapshotWire)
        #expect(decodedSnapReq.id == .int(11))
        #expect(decodedSnapReq.method.rawValue == "snapshot")
        #expect(decodedSnapReq.language == .zhHans)
        let reencodedSnap = try DaemonRPCCodec.encodeRequestLine(decodedSnapReq)
        let roundTripSnap = try DaemonRPCCodec.decodeRequestLine(reencodedSnap)
        #expect(roundTripSnap == decodedSnapReq)

        let branchWire = Data(#"{"jsonrpc":"2.0","id":12,"method":"branch","params":{"vm":"p","branchName":"c2","owner":"tester","lang":"en"}}"#.utf8)
        let decodedBranchReq = try DaemonRPCCodec.decodeRequestLine(branchWire)
        #expect(decodedBranchReq.id == .int(12))
        #expect(decodedBranchReq.method.rawValue == "branch")
        #expect(decodedBranchReq.language == .en)
        let reencodedBranch = try DaemonRPCCodec.encodeRequestLine(decodedBranchReq)
        let roundTripBranch = try DaemonRPCCodec.decodeRequestLine(reencodedBranch)
        #expect(roundTripBranch == decodedBranchReq)

        let restoreWire = Data(#"{"jsonrpc":"2.0","id":13,"method":"restore","params":{"snapshotID":"snap-123","lang":"zh-Hans"}}"#.utf8)
        let decodedRestoreReq = try DaemonRPCCodec.decodeRequestLine(restoreWire)
        #expect(decodedRestoreReq.id == .int(13))
        #expect(decodedRestoreReq.method.rawValue == "restore")
        #expect(decodedRestoreReq.language == .zhHans)
        let reencodedRestore = try DaemonRPCCodec.encodeRequestLine(decodedRestoreReq)
        let roundTripRestore = try DaemonRPCCodec.decodeRequestLine(reencodedRestore)
        #expect(roundTripRestore == decodedRestoreReq)

        // 3. SnapshotKind `live-disk` round-trips in JSON & SQLite while `cold-disk` and unknown legacy strings decode compatibly
        let liveDiskKind = SnapshotKind(rawValue: "live-disk")
        #expect(liveDiskKind != nil, "SnapshotKind must define rawValue 'live-disk'")
        #expect(SnapshotKind.allCases.map(\.rawValue).contains("live-disk"))

        let realBase = try makePrivateTmpDirectory(prefix: "avm-m3-kind")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        let wsURL = URL(fileURLWithPath: "\(realBase)/KindCompat.agentvm", isDirectory: true)
        let store = try AgentVMProjectStore(bundleURL: wsURL, createIfMissing: true)

        let dummySpec = VMSpec(
            id: VMID("vm-kindtest"),
            name: "kindtest",
            agentOwnerTag: "unit",
            guestOS: .linuxARM64,
            bootLoader: .efiBoot(variableStorePath: "\(realBase)/v.nvram", createVariableStoreIfMissing: true),
            blockDevices: [
                BlockDeviceSpec(label: "root", imagePath: "\(realBase)/v.raw", virtualSizeBytes: 4096, format: .rawSparse, readOnly: false, isBootVolume: true)
            ]
        )

        if let resolvedLiveKind = liveDiskKind {
            let liveNode = SnapshotNode(
                id: SnapshotID("snap-live-01"),
                vmID: dummySpec.id,
                title: "Live S1",
                kind: resolvedLiveKind,
                diskClonePath: "\(realBase)/snap-live.raw",
                virtualDiskBytes: 4096,
                allocatedDiskBytes: 0,
                apfsPrivateBytes: 0,
                specSnapshot: dummySpec
            )
            let coldNode = SnapshotNode(
                id: SnapshotID("snap-cold-01"),
                vmID: dummySpec.id,
                title: "Cold S0",
                kind: .coldDiskOnly,
                diskClonePath: "\(realBase)/snap-cold.raw",
                virtualDiskBytes: 4096,
                allocatedDiskBytes: 0,
                apfsPrivateBytes: 0,
                specSnapshot: dummySpec
            )

            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601

            let liveData = try encoder.encode(liveNode)
            let liveJSONStr = String(decoding: liveData, as: UTF8.self)
            #expect(liveJSONStr.contains("\"live-disk\""))
            let decodedLive = try decoder.decode(SnapshotNode.self, from: liveData)
            #expect(decodedLive.kind.rawValue == "live-disk")

            let coldData = try encoder.encode(coldNode)
            let decodedCold = try decoder.decode(SnapshotNode.self, from: coldData)
            #expect(decodedCold.kind == SnapshotKind.coldDiskOnly)

            // Unknown legacy kind string in JSON falls back compatibly to `.coldDiskOnly`
            let legacyUnknownJSON = liveJSONStr.replacingOccurrences(of: "\"live-disk\"", with: "\"legacy-disk-v0\"")
            let decodedLegacy = try decoder.decode(SnapshotNode.self, from: Data(legacyUnknownJSON.utf8))
            #expect(decodedLegacy.kind == SnapshotKind.coldDiskOnly)

            // SQLite round-trip for both `live-disk` and `cold-disk`
            try await store.upsertVM(VMInstanceRecord(spec: dummySpec, currentHeadSnapshotID: coldNode.id))
            try await store.upsertSnapshot(coldNode)
            try await store.upsertSnapshot(liveNode)

            let fetchedCold = try #require(try await store.fetchSnapshot(coldNode.id))
            let fetchedLive = try #require(try await store.fetchSnapshot(liveNode.id))
            #expect(fetchedCold.kind == SnapshotKind.coldDiskOnly)
            #expect(fetchedLive.kind.rawValue == "live-disk")
        }
    }

    // MARK: - 2. Daemon-Held VM Routes `snapshot` / `branch` / `restore` Through RPC Without Local Lock

    @Test("A61 & A59: when daemon holds running VM, CLI and MCP snapshot/branch route via RPC without local lock, record live-disk, keep parent running, and restore exits 1 explaining live restore is unimplemented")
    func routingWhenDaemonHoldsVMUsesRPCWithoutLocalLockAndKeepsParentRunning() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-m3-rpc")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/DaemonHeldRoute.agentvm", isDirectory: true)
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
        let pCreated = try #require(try await inspectStore.listVMs().first(where: { $0.spec.name == "p" }))
        let pID = pCreated.id
        let lockURL = wsURL.appendingPathComponent("locks/\(pID.rawValue).lock")

        let mockBackend = M3Stage3aMockBackend()
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
            #expect(VMExecutionLock.isLocked(at: lockURL) == true, "Daemon must hold p.lock while running")

            // Client coordinator for MCP (must NOT run local lineage clone when daemon holds p)
            let clientCoordinator = try AgentVMFleetCoordinator(
                bundleURL: wsURL,
                executionBackend: .strictHardwareVZ,
                imageCacheDirectoryURL: cacheDir,
                curatedImageEntries: [entry]
            )
            await clientCoordinator.setAfterLineageCloneHookForTesting { op, _ in
                Issue.record("Local client coordinator must not run local lineage clone (\(op)) when daemon holds VM")
            }
            let mcp = AgentVMMCPServer(coordinator: clientCoordinator)

            // 1. CLI `snapshot p s1` while daemon holds `p` -> exit 0, routed via daemon RPC (sync timeout=30 -> pause -> clone -> resume)
            mockBackend.clearTimelineAndCounts()
            let snapOut = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "snapshot", "p", "s1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(snapOut.exitCode == 0, "Expected live CLI snapshot to exit 0, stderr: \(snapOut.stderr)")
            #expect(mockBackend.receivedSyncRequests.count == 1)
            #expect(mockBackend.receivedSyncRequests.first?.timeoutSeconds == 30)
            #expect(mockBackend.eventTimeline == ["sync", "pause", "resume"])
            #expect(mockBackend.isCurrentlyPaused == false)

            // Verify `snapshot list --json` and `snapshot list` show `s1` with kind `live-disk` and no memory state file
            let snapListJSON = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "snapshot", "list", "--json"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(snapListJSON.exitCode == 0)
            let allSnaps = try decodeJSON([SnapshotNode].self, from: snapListJSON.stdout)
            let s1Node = try #require(allSnaps.first(where: { $0.title == "s1" }))
            #expect(s1Node.kind.rawValue == "live-disk")
            #expect(s1Node.memoryStatePath == nil)
            #expect(s1Node.memoryStateBytes == 0)

            let snapListTable = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "snapshot", "list"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(snapListTable.stdout.contains("live-disk"))

            // 2. CLI `branch p c2` while daemon holds `p` -> exit 0, `p` still running, `c2` is stopped with distinct ISO
            mockBackend.clearTimelineAndCounts()
            let branchOut = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "branch", "p", "c2"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(branchOut.exitCode == 0, "Expected live CLI branch to exit 0, stderr: \(branchOut.stderr)")
            #expect(mockBackend.eventTimeline == ["sync", "pause", "resume"])

            let psJSON = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "ps", "--json"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            let vmsAfterBranch = try decodeJSON([VMInstanceRecord].self, from: psJSON.stdout)
            let pAfter = try #require(vmsAfterBranch.first(where: { $0.spec.name == "p" }))
            let c2After = try #require(vmsAfterBranch.first(where: { $0.spec.name == "c2" }))
            #expect(pAfter.telemetry.state == .running, "Parent VM must remain running after live branch")
            #expect(pAfter.telemetry.guestAgentConnected == true)
            #expect(c2After.telemetry.state == .stopped, "Child VM must default to stopped")
            #expect(c2After.spec.cloudInitISOPath != pAfter.spec.cloudInitISOPath)

            // 3. MCP `agentvm_capture_snapshot` and `agentvm_fork_cow_branch` follow the exact same daemon routing
            mockBackend.clearTimelineAndCounts()
            let mcpSnap = try await invokeMCPTool(mcp, id: 1, name: "agentvm_capture_snapshot", arguments: [
                "vmID": pID.rawValue,
                "title": "s2-mcp"
            ])
            #expect(mcpSnap.isError == false, "Expected MCP live snapshot to succeed, got: \(mcpSnap.text)")
            #expect(mockBackend.eventTimeline == ["sync", "pause", "resume"])
            let s2Node = try #require(try await inspectStore.listSnapshots(forVM: pID).first(where: { $0.title == "s2-mcp" }))
            #expect(s2Node.kind.rawValue == "live-disk")

            mockBackend.clearTimelineAndCounts()
            let mcpBranch = try await invokeMCPTool(mcp, id: 2, name: "agentvm_fork_cow_branch", arguments: [
                "parentVMID": pID.rawValue,
                "branchName": "c3-mcp"
            ])
            #expect(mcpBranch.isError == false, "Expected MCP live branch to succeed, got: \(mcpBranch.text)")
            #expect(mockBackend.eventTimeline == ["sync", "pause", "resume"])
            let c3Rec = try #require(try await inspectStore.listVMs().first(where: { $0.spec.name == "c3-mcp" }))
            #expect(c3Rec.telemetry.state == .stopped)

            // 4. CLI & MCP `restore` on running `p` -> exit 1 / isError=true, explains live restore is not implemented yet (EN & ZH, no milestone or version strings)
            for lang in ["en", "zh"] {
                let restoreRes = await cli.execute(
                    arguments: ["--lang", lang, "--workspace", wsURL.path, "restore", s1Node.id.rawValue],
                    curatedEntriesOverride: [entry],
                    environment: env,
                    daemonSpawnOverride: forbiddenSpawn
                )
                #expect(restoreRes.exitCode == 1, "Expected live restore (\(lang)) to exit 1")
                #expect(!restoreRes.stderr.contains("ERR_VM_LOCKED"), "Live restore must route to daemon rather than failing local lock: \(restoreRes.stderr)")
                #expect(!restoreRes.stderr.contains("M3") && !restoreRes.stderr.contains("M4") && !restoreRes.stderr.contains("3b") && !restoreRes.stderr.contains("1.4"))
                if lang == "en" {
                    #expect(restoreRes.stderr.lowercased().contains("not implemented"))
                } else {
                    #expect(restoreRes.stderr.contains("尚未实现") || restoreRes.stderr.contains("还没实现") || restoreRes.stderr.contains("未实现"))
                }
            }
            let mcpRestore = try await invokeMCPTool(mcp, id: 3, name: "agentvm_restore_snapshot", arguments: [
                "snapshotID": s1Node.id.rawValue
            ])
            #expect(mcpRestore.isError == true)
            #expect(mcpRestore.text.lowercased().contains("not implemented"))
            #expect(!mcpRestore.text.contains("ERR_VM_LOCKED"))
            #expect(!mcpRestore.text.contains("M3") && !mcpRestore.text.contains("3b"))

            // Parent `p` is still running!
            let pFinal = try #require(try await inspectStore.fetchVM(pID))
            #expect(pFinal.telemetry.state == .running)

            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "p"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
        }
    }

    // MARK: - 3. Stopped VM or No Daemon Routes Locally (Takes Lock) & Never Spawns Daemon

    @Test("A61: snapshot, branch, and restore run locally with VMExecutionLock when no daemon is running or target VM is stopped, and never spawn a daemon")
    func routingWhenNoDaemonOrVMStoppedRunsLocallyWithLockAndNeverSpawnsDaemon() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-m3-local")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/LocalRoute.agentvm", isDirectory: true)
        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let spawnMarker = "\(realBase)/daemon-was-spawned"
        let forbiddenSpawn = DaemonSpawnCommandOverride(
            executablePath: "/bin/sh",
            arguments: ["-c", "touch '\(spawnMarker)' && exit 93"],
            environment: env
        )
        let cli = AgentVMCLIRunner()
        let paths = DaemonWorkspacePaths(workspaceURL: wsURL)

        #expect(await cli.execute(arguments: ["--workspace", wsURL.path, "create", "running-vm", "--image", entry.id], curatedEntriesOverride: [entry], environment: env).exitCode == 0)
        #expect(await cli.execute(arguments: ["--workspace", wsURL.path, "create", "stopped-vm", "--image", entry.id], curatedEntriesOverride: [entry], environment: env).exitCode == 0)

        let inspectStore = try AgentVMProjectStore(bundleURL: wsURL, createIfMissing: false)
        let stoppedRec = try #require(try await inspectStore.listVMs().first(where: { $0.spec.name == "stopped-vm" }))
        let stoppedLockURL = wsURL.appendingPathComponent("locks/\(stoppedRec.id.rawValue).lock")

        // Part A: No daemon running -> `snapshot`, `branch`, `restore` run locally, record `cold-disk`, and NEVER spawn daemon
        let localSnap = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "snapshot", "stopped-vm", "cold-s1"],
            curatedEntriesOverride: [entry],
            environment: env,
            daemonSpawnOverride: forbiddenSpawn
        )
        #expect(localSnap.exitCode == 0)

        let coldS1 = try #require(try await inspectStore.listSnapshots(forVM: stoppedRec.id).first(where: { $0.title == "cold-s1" }))
        #expect(coldS1.kind == SnapshotKind.coldDiskOnly)

        let localBranch = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "branch", "stopped-vm", "cold-c1"],
            curatedEntriesOverride: [entry],
            environment: env,
            daemonSpawnOverride: forbiddenSpawn
        )
        #expect(localBranch.exitCode == 0)

        let localRestore = await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "restore", coldS1.id.rawValue],
            curatedEntriesOverride: [entry],
            environment: env,
            daemonSpawnOverride: forbiddenSpawn
        )
        #expect(localRestore.exitCode == 0)
        #expect(!FileManager.default.fileExists(atPath: paths.directSocketPath), "None of snapshot/branch/restore may start a daemon")
        #expect(!FileManager.default.fileExists(atPath: spawnMarker), "daemonSpawnOverride must never be invoked")

        // Part B: Daemon IS running and holding `running-vm`, while `stopped-vm` is stopped ->
        // operations on `stopped-vm` STILL run locally in this process (taking `stopped-vm`'s lock, zero daemon guest sync/pause)!
        let mockBackend = M3Stage3aMockBackend()
        defer { mockBackend.shutdownAll() }

        try await withStartedDaemonServer(
            workspaceURL: wsURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mockBackend
        ) { _ in
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "running-vm"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
            mockBackend.clearTimelineAndCounts()

            // Side-by-side proof in the same workspace: `running-vm` routes to daemon RPC, while `stopped-vm` stays local!
            let liveCheckOnRunning = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "snapshot", "running-vm", "live-s-side"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(liveCheckOnRunning.exitCode == 0)
            #expect(mockBackend.eventTimeline == ["sync", "pause", "resume"])
            mockBackend.clearTimelineAndCounts()

            let stoppedSnapWhileDaemonUp = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "snapshot", "stopped-vm", "cold-s2"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(stoppedSnapWhileDaemonUp.exitCode == 0)
            let coldS2 = try #require(try await inspectStore.listSnapshots(forVM: stoppedRec.id).first(where: { $0.title == "cold-s2" }))
            #expect(coldS2.kind == SnapshotKind.coldDiskOnly, "Stopped VM snapshot must remain cold-disk even when daemon runs another VM")

            let stoppedBranchWhileDaemonUp = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "branch", "stopped-vm", "cold-c2"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(stoppedBranchWhileDaemonUp.exitCode == 0)

            let stoppedRestoreWhileDaemonUp = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "restore", coldS2.id.rawValue],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(stoppedRestoreWhileDaemonUp.exitCode == 0)
            #expect(mockBackend.eventTimeline.isEmpty, "Stopped VM operations must execute locally without touching daemon VM handle")

            // Prove local execution acquires `stopped-vm`'s VMExecutionLock: hold `stopped-vm.lock` externally -> ERR_VM_LOCKED!
            let heldLock = try VMExecutionLock.acquire(at: stoppedLockURL, vmName: "stopped-vm")
            defer { heldLock.release() }

            let lockedSnap = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "snapshot", "stopped-vm", "blocked"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(lockedSnap.exitCode == 1)
            #expect(lockedSnap.stderr.contains("ERR_VM_LOCKED"))

            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "running-vm"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
        }
    }

    // MARK: - 4. Guest `sync` Failure Does NOT Call `pause` and Exits 1 With Explanation

    @Test("A59: when guestd sync fails or times out on running VM, daemon never calls pause, exits 1 explaining failure, and leaves VM running")
    func guestSyncFailureAbortsBeforePauseAndReturnsExit1WithExplanation() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-m3-syncfail")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/SyncFail.agentvm", isDirectory: true)
        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()
        let forbiddenSpawn = DaemonSpawnCommandOverride(executablePath: "/bin/sh", arguments: ["-c", "exit 92"], environment: env)

        #expect(await cli.execute(arguments: ["--workspace", wsURL.path, "create", "p", "--image", entry.id], curatedEntriesOverride: [entry], environment: env).exitCode == 0)

        let inspectStore = try AgentVMProjectStore(bundleURL: wsURL, createIfMissing: false)
        let pRec = try #require(try await inspectStore.listVMs().first(where: { $0.spec.name == "p" }))

        let mockBackend = M3Stage3aMockBackend(
            syncConfig: .init(exitCode: 5, stderrText: "sync: I/O error on /dev/vda1", timedOut: false)
        )
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

            // 1. Non-zero exit code from `sync` -> EN & ZH both exit 1, explain sync failure, pauseCount == 0!
            for lang in ["en", "zh"] {
                mockBackend.clearTimelineAndCounts()
                let snapFail = await cli.execute(
                    arguments: ["--lang", lang, "--workspace", wsURL.path, "snapshot", "p", "bad-snap"],
                    curatedEntriesOverride: [entry],
                    environment: env,
                    daemonSpawnOverride: forbiddenSpawn
                )
                #expect(snapFail.exitCode == 1)
                #expect(snapFail.stdout.isEmpty)
                #expect(!snapFail.stderr.contains("ERR_VM_LOCKED"))
                #expect(snapFail.stderr.lowercased().contains("sync"), "Stderr (\(lang)) must explain sync failure: \(snapFail.stderr)")
                #expect(mockBackend.receivedSyncRequests.count == 1)
                #expect(mockBackend.pauseCount == 0, "pause() must NEVER be called when guest sync fails")
                #expect(mockBackend.resumeCount == 0)

                mockBackend.clearTimelineAndCounts()
                let branchFail = await cli.execute(
                    arguments: ["--lang", lang, "--workspace", wsURL.path, "branch", "p", "bad-child"],
                    curatedEntriesOverride: [entry],
                    environment: env,
                    daemonSpawnOverride: forbiddenSpawn
                )
                #expect(branchFail.exitCode == 1)
                #expect(branchFail.stdout.isEmpty)
                #expect(!branchFail.stderr.contains("ERR_VM_LOCKED"))
                #expect(branchFail.stderr.lowercased().contains("sync"), "Stderr (\(lang)) must explain sync failure: \(branchFail.stderr)")
                #expect(mockBackend.receivedSyncRequests.count == 1)
                #expect(mockBackend.pauseCount == 0, "pause() must NEVER be called when guest sync fails")
                #expect(mockBackend.resumeCount == 0)
            }

            // 2. Timed-out `sync` -> also exits 1 without calling `pause()`
            mockBackend.updateSyncConfig(.init(exitCode: 124, stderrText: "", timedOut: true))
            mockBackend.clearTimelineAndCounts()
            let timeoutFail = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "branch", "p", "timeout-child"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(timeoutFail.exitCode == 1)
            #expect(timeoutFail.stderr.lowercased().contains("sync"))
            #expect(mockBackend.pauseCount == 0)

            // Verify no `VM_PAUSED_FOR_SNAPSHOT` diagnostic, no child VM created, and `p` remains `running`
            let diags = try await inspectStore.listDiagnostics(vmID: pRec.id, limit: 100)
            #expect(!diags.contains(where: { $0.code == "VM_PAUSED_FOR_SNAPSHOT" }))
            let vms = try await inspectStore.listVMs()
            #expect(vms.count == 1)
            #expect(vms.first?.telemetry.state == .running)

            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "p"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
        }
    }

    // MARK: - 5. `clonefile` Error Calls `resume()` Strictly Before Returning Error

    @Test("A59: when root-disk or NVRAM clonefile fails while paused, daemon calls resume() strictly before returning error and leaves parent running")
    func clonefileFailureCallsResumeStrictlyBeforeReturningError() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-m3-cloneerr")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/CloneErrResume.agentvm", isDirectory: true)
        let snapshotsDir = wsURL.appendingPathComponent("snapshots", isDirectory: true)
        let disksDir = wsURL.appendingPathComponent("disks", isDirectory: true)
        defer {
            _ = Darwin.chmod(snapshotsDir.path, 0o755)
            _ = Darwin.chmod(disksDir.path, 0o755)
        }

        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()
        let forbiddenSpawn = DaemonSpawnCommandOverride(executablePath: "/bin/sh", arguments: ["-c", "exit 91"], environment: env)

        #expect(await cli.execute(arguments: ["--workspace", wsURL.path, "create", "p", "--image", entry.id], curatedEntriesOverride: [entry], environment: env).exitCode == 0)

        let inspectStore = try AgentVMProjectStore(bundleURL: wsURL, createIfMissing: false)
        let pRec = try #require(try await inspectStore.listVMs().first(where: { $0.spec.name == "p" }))
        let snapsBefore = try await inspectStore.listSnapshots(forVM: pRec.id).count

        let mockBackend = M3Stage3aMockBackend()
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

            // Case A: Make `snapshots/` read-only (0555) so root disk `clonefile` fails with EACCES while paused
            #expect(Darwin.chmod(snapshotsDir.path, 0o555) == 0)

            mockBackend.clearTimelineAndCounts()
            let snapErr = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "snapshot", "p", "fail-root-snap"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            // Immediately on return: resume MUST have already been called!
            #expect(snapErr.exitCode == 1)
            #expect(snapErr.stderr.contains("ERR_APFS_COW_CLONE"))
            #expect(mockBackend.isCurrentlyPaused == false, "VM must already be resumed before snapshot error returns")
            #expect(mockBackend.eventTimeline == ["sync", "pause", "resume"])

            mockBackend.clearTimelineAndCounts()
            let branchRootErr = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "branch", "p", "fail-root-branch"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(branchRootErr.exitCode == 1)
            #expect(branchRootErr.stderr.contains("ERR_APFS_COW_CLONE"))
            #expect(mockBackend.isCurrentlyPaused == false, "VM must already be resumed before branch error returns")
            #expect(mockBackend.eventTimeline == ["sync", "pause", "resume"])

            #expect(Darwin.chmod(snapshotsDir.path, 0o755) == 0)

            // Case B: Make `disks/` read-only (0555) while `snapshots/` is writable (0755), so root disk clone succeeds and NVRAM clone fails!
            let snapFilesBeforeNvramFail = (try? FileManager.default.contentsOfDirectory(atPath: snapshotsDir.path))?.count ?? 0
            #expect(Darwin.chmod(disksDir.path, 0o555) == 0)

            mockBackend.clearTimelineAndCounts()
            let branchNvramErr = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "branch", "p", "fail-nvram-branch"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(branchNvramErr.exitCode == 1)
            #expect(branchNvramErr.stderr.contains("ERR_APFS_COW_CLONE"))
            #expect(mockBackend.isCurrentlyPaused == false, "VM must already be resumed when NVRAM clone fails")
            #expect(mockBackend.eventTimeline == ["sync", "pause", "resume"])

            #expect(Darwin.chmod(disksDir.path, 0o755) == 0)
            let snapFilesAfterNvramFail = (try? FileManager.default.contentsOfDirectory(atPath: snapshotsDir.path))?.count ?? 0
            #expect(snapFilesAfterNvramFail == snapFilesBeforeNvramFail, "Partial fork snapshot must be cleaned up when NVRAM clone fails")

            // Verify no partial DB entries were committed and `p` is still `running` and responsive to `exec`
            let snapsAfterErr = try await inspectStore.listSnapshots(forVM: pRec.id).count
            let vmsAfterErr = try await inspectStore.listVMs().count
            #expect(snapsAfterErr == snapsBefore)
            #expect(vmsAfterErr == 1)
            let execCheck = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "exec", "p", "--", "true"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(execCheck.exitCode == 0)

            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "p"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
        }
    }

    // MARK: - 6. `VM_PAUSED_FOR_SNAPSHOT` Diagnostic Event Carries Pause Milliseconds

    @Test("A59: live snapshot and live branch emit VM_PAUSED_FOR_SNAPSHOT on parent VM with measured pause milliseconds in events --vm")
    func diagnosticsRecordVMPausedForSnapshotWithMillisecondsInEventsCLI() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-m3-diag")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        defer { Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase) }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/PauseDiag.agentvm", isDirectory: true)
        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()
        let forbiddenSpawn = DaemonSpawnCommandOverride(executablePath: "/bin/sh", arguments: ["-c", "exit 90"], environment: env)

        #expect(await cli.execute(arguments: ["--workspace", wsURL.path, "create", "p", "--image", entry.id], curatedEntriesOverride: [entry], environment: env).exitCode == 0)

        let mockBackend = M3Stage3aMockBackend(pauseDelayNanoseconds: 15_000_000)
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

            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "snapshot", "p", "s-diag"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)

            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "branch", "p", "c-diag"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)

            let eventsJSONOut = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "events", "--vm", "p", "--json"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(eventsJSONOut.exitCode == 0)
            let events = try decodeJSON([DiagnosticEvent].self, from: eventsJSONOut.stdout)
            let pausedEvents = events.filter { $0.code == "VM_PAUSED_FOR_SNAPSHOT" }
            #expect(pausedEvents.count == 2, "Expected 2 VM_PAUSED_FOR_SNAPSHOT events (snapshot + branch), got \(pausedEvents.count)")

            for ev in pausedEvents {
                let rawMs = try #require(ev.metadata["pauseMs"], "VM_PAUSED_FOR_SNAPSHOT metadata must include pauseMs")
                let parsedMs = try #require(Double(rawMs))
                #expect(parsedMs >= 10.0, "Measured pauseMs (\(parsedMs)) must reflect pause->resume duration (>= 10 ms)")
                #expect(ev.message.contains("ms"))
            }

            // Human-readable `events --vm p` in both EN & ZH includes `VM_PAUSED_FOR_SNAPSHOT` and `ms`
            for lang in ["en", "zh"] {
                let textOut = await cli.execute(
                    arguments: ["--lang", lang, "--workspace", wsURL.path, "events", "--vm", "p"],
                    curatedEntriesOverride: [entry],
                    environment: env,
                    daemonSpawnOverride: forbiddenSpawn
                )
                #expect(textOut.exitCode == 0)
                #expect(textOut.stdout.contains("VM_PAUSED_FOR_SNAPSHOT"))
                #expect(textOut.stdout.contains("ms"))
            }

            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "p"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
        }
    }
}
