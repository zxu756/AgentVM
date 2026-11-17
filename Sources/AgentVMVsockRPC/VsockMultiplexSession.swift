import AgentVMModels
import Darwin
import Dispatch
import Foundation

// MARK: - Session Telemetry & Internal Promise Primitives

/// Live transport and flow-control counters reported by `VsockMultiplexSession`.
public struct VsockSessionTelemetry: Codable, Hashable, Sendable {
    public var vmID: VMID
    public var framesSent: UInt64
    public var framesReceived: UInt64
    public var compressedFramesSent: UInt64
    public var compressedFramesReceived: UInt64
    public var windowUpdatesSent: UInt64
    public var windowUpdatesReceived: UInt64
    public var wireBytesSent: UInt64
    public var wireBytesReceived: UInt64
    public var openStreams: Int
    public var isGuestResponderAttached: Bool

    public init(
        vmID: VMID,
        framesSent: UInt64 = 0,
        framesReceived: UInt64 = 0,
        compressedFramesSent: UInt64 = 0,
        compressedFramesReceived: UInt64 = 0,
        windowUpdatesSent: UInt64 = 0,
        windowUpdatesReceived: UInt64 = 0,
        wireBytesSent: UInt64 = 0,
        wireBytesReceived: UInt64 = 0,
        openStreams: Int = 0,
        isGuestResponderAttached: Bool = false
    ) {
        self.vmID = vmID
        self.framesSent = framesSent
        self.framesReceived = framesReceived
        self.compressedFramesSent = compressedFramesSent
        self.compressedFramesReceived = compressedFramesReceived
        self.windowUpdatesSent = windowUpdatesSent
        self.windowUpdatesReceived = windowUpdatesReceived
        self.wireBytesSent = wireBytesSent
        self.wireBytesReceived = wireBytesReceived
        self.openStreams = openStreams
        self.isGuestResponderAttached = isGuestResponderAttached
    }
}

/// Reentrancy-safe one-shot promise used inside `VsockMultiplexSession` so replies arriving before or after
/// `wait()` suspension always resolve deterministically without continuation races.
private final class VsockRPCPromise<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var settledResult: Result<Value, Error>?
    private var continuation: CheckedContinuation<Value, Error>?

    func resolve(_ value: Value) {
        complete(.success(value))
    }

    func reject(_ error: Error) {
        complete(.failure(error))
    }

    func complete(_ result: Result<Value, Error>) {
        lock.lock()
        if settledResult != nil {
            lock.unlock()
            return
        }
        if let cont = continuation {
            continuation = nil
            settledResult = result
            lock.unlock()
            cont.resume(with: result)
        } else {
            settledResult = result
            lock.unlock()
        }
    }

    func wait() async throws -> Value {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Value, Error>) in
            lock.lock()
            if let existing = settledResult {
                lock.unlock()
                cont.resume(with: existing)
            } else {
                continuation = cont
                lock.unlock()
            }
        }
    }
}

// MARK: - VsockMultiplexSession Actor

/// Multiplexed VirtioSocket (`AVM1`) session manager implementing logical stream framing, credit-based
/// sliding-window flow control, POSIX `VZVirtioSocketConnection` file-descriptor I/O, and a byte-accurate
/// in-process simulated Linux guest responder.
public actor VsockMultiplexSession {
    // MARK: Internal Stream Tracking Models

    private struct StreamFlowState {
        let streamID: UInt32
        let channel: VsockChannelKind
        var outboundSequence: UInt32 = 0
        var inboundSequence: UInt32 = 0
        var peerSendWindowCredit: UInt32 = VsockWireConstants.defaultWindowCredit
        var localReceiveWindowCredit: UInt32 = VsockWireConstants.defaultWindowCredit
        var uncreditedConsumedBytes: UInt32 = 0
        var isHalfClosedLocal: Bool = false
        var isHalfClosedRemote: Bool = false
        var creditWaiters: [UUID: CheckedContinuation<Void, Error>] = [:]
    }

    private struct PendingExecContext {
        let request: GuestExecRequest
        let startedAt: Date
        let maxRetainedBytesPerStream: Int?
        var stdoutBuffer: Data = Data()
        var stderrBuffer: Data = Data()
        var stdoutTotalBytes: UInt64 = 0
        var stderrTotalBytes: UInt64 = 0
        let onChunk: (@Sendable (GuestExecOutputChunk) async -> Void)?
        let promise: VsockRPCPromise<GuestExecResult>
    }

    private struct PendingPushContext {
        let manifest: GuestFileTransferManifest
        let promise: VsockRPCPromise<GuestFileTransferManifest>
    }

    private struct PendingPullContext {
        let guestSourcePath: String
        let localDestinationURL: URL
        var declaredManifest: GuestFileTransferManifest?
        var receivedBytes: Data = Data()
        let promise: VsockRPCPromise<GuestFileTransferManifest>
    }

    private struct ActivePortForwardStream {
        let streamID: UInt32
        let guestPort: UInt16
        var handshakePromise: VsockRPCPromise<Void>?
        let inboundContinuation: AsyncStream<Data>.Continuation
    }

    private struct GuestInboundPushAssembly {
        let manifest: GuestFileTransferManifest
        var data: Data = Data()
    }

    // MARK: Stored Properties

    public let vmID: VMID
    private let codec = VsockWireCodec()
    private let accumulator = VsockStreamAccumulator()

    private var transportWrite: (@Sendable (Data) async throws -> Void)?
    private var inboundTransportPumpTask: Task<Void, Never>?
    private var inboundTransportContinuation: AsyncStream<Data>.Continuation?
    private var attachedReadSource: DispatchSourceRead?
    private var attachedFD: Int32 = -1
    private var closeAttachedFDOnShutdown: Bool = false
    private var isShutDown: Bool = false

    // Stream allocation & flow control
    private var isGuestServerRole: Bool = false
    private var nextHostStreamID: UInt32 = 1   // Odd stream IDs for host-initiated streams
    private var nextGuestStreamID: UInt32 = 2  // Even stream IDs for guest-initiated streams
    private var controlSequence: UInt32 = 0
    private var openStreams: [UInt32: StreamFlowState] = [:]

    // Pending RPC state tables
    private var pendingExecs: [UInt32: PendingExecContext] = [:]
    private var pendingFilePushes: [UInt32: PendingPushContext] = [:]
    private var pendingFilePulls: [UInt32: PendingPullContext] = [:]
    private var pendingHeartbeatWaiters: [VsockRPCPromise<GuestHeartbeatPayload>] = []
    private var portForwardStreams: [UInt32: ActivePortForwardStream] = [:]

    // Interactive PTY state
    private var defaultPTYStreamID: UInt32?
    private var ptyColumns: UInt16 = 120
    private var ptyRows: UInt16 = 36
    private var attachedScreenBuffer: VT100ScreenBuffer?
    private var ptyOutputSubscribers: [UUID: AsyncStream<Data>.Continuation] = [:]

    // Telemetry & Heartbeat state
    private var cachedHeartbeat: GuestHeartbeatPayload?
    private var framesSentCount: UInt64 = 0
    private var framesReceivedCount: UInt64 = 0
    private var compressedFramesSentCount: UInt64 = 0
    private var compressedFramesReceivedCount: UInt64 = 0
    private var windowUpdatesSentCount: UInt64 = 0
    private var windowUpdatesReceivedCount: UInt64 = 0
    private var wireBytesSentCount: UInt64 = 0
    private var wireBytesReceivedCount: UInt64 = 0

    // Simulated Guest State (used when `isGuestServerRole == true` or via `attachSimulatedGuestResponder()`)
    private var pairedLoopbackPeer: VsockMultiplexSession?
    private var simulatedPeerEndpoint: SimulatedGuestWirePeer?
    private var guestVirtualFiles: [String: VirtualGuestFile] = [:]
    private var guestInboundPushes: [UInt32: GuestInboundPushAssembly] = [:]

    private static let windowReplenishThreshold: UInt32 = 65_536

    // MARK: Initialization & Loopback Pairing

    public init(
        vmID: VMID,
        transportWrite: (@Sendable (Data) async throws -> Void)? = nil
    ) {
        self.vmID = vmID
        self.transportWrite = transportWrite
    }

    /// Creates a cross-wired in-process `(host, guest)` `VsockMultiplexSession` pair communicating
    /// strictly via `AVM1` Big-Endian binary frames with IEEE CRC-32 and zlib compression.
    public static func createLoopbackPair(
        vmID: VMID
    ) async -> (host: VsockMultiplexSession, guest: VsockMultiplexSession) {
        let pipe = LoopbackSessionBridge()
        let host = VsockMultiplexSession(vmID: vmID) { outboundBytes in
            try await pipe.sendFromHostToGuest(outboundBytes)
        }
        let guest = VsockMultiplexSession(vmID: vmID) { outboundBytes in
            try await pipe.sendFromGuestToHost(outboundBytes)
        }
        pipe.bind(host: host, guest: guest)
        await host.retainPairedLoopbackPeer(guest)
        await guest.activateAsGuestServerRole()
        if let initialHeartbeatWire = try? await guest.makeGuestHeartbeatWireFrame() {
            try? await host.receiveRawTransportBytes(initialHeartbeatWire)
        }
        return (host: host, guest: guest)
    }

    private func retainPairedLoopbackPeer(_ peer: VsockMultiplexSession) {
        self.pairedLoopbackPeer = peer
    }

    /// Attaches an in-process simulated Linux guest responder that decodes and encodes real `AVM1` wire frames
    /// byte-for-byte over `receiveRawTransportBytes(_:)`.
    public func attachSimulatedGuestResponder() async {
        detachFDSourceIfPresent()
        let inboundPipe = makeSerialInboundTransportPipe()
        let peer = SimulatedGuestWirePeer(vmID: vmID) { guestReplyWireBytes in
            inboundPipe.yield(guestReplyWireBytes)
        }
        self.simulatedPeerEndpoint = peer
        self.transportWrite = { outboundWireBytes in
            try await peer.receiveHostWireBytes(outboundWireBytes)
        }

        // Seed an initial guest telemetry heartbeat frame immediately over the AVM1 wire codec.
        if let initialHeartbeatWire = try? await peer.makeHeartbeatWireFrame() {
            try? await receiveRawTransportBytes(initialHeartbeatWire)
        }
    }

    // MARK: Live POSIX File Descriptor / FileHandle Transport

    /// Attaches a live POSIX stream socket descriptor (e.g. `VZVirtioSocketConnection.fileDescriptor`)
    /// using non-blocking GCD `DispatchSourceRead` event notifications and a strict-FIFO `AsyncStream` pump.
    public func attachPOSIXFileDescriptor(_ fileDescriptor: Int32, closeWhenDone: Bool = false) throws {
        guard fileDescriptor >= 0 else {
            throw AgentVMError.vsockProtocolViolation(detail: "Invalid POSIX file descriptor \(fileDescriptor).")
        }
        detachFDSourceIfPresent()

        var noSigPipe: Int32 = 1
        _ = Darwin.setsockopt(
            fileDescriptor,
            SOL_SOCKET,
            SO_NOSIGPIPE,
            &noSigPipe,
            socklen_t(MemoryLayout<Int32>.size)
        )

        let existingFlags = Darwin.fcntl(fileDescriptor, F_GETFL, 0)
        if existingFlags >= 0 {
            _ = Darwin.fcntl(fileDescriptor, F_SETFL, existingFlags | O_NONBLOCK)
        }

        self.attachedFD = fileDescriptor
        self.closeAttachedFDOnShutdown = closeWhenDone
        self.transportWrite = { data in
            try Self.writeAllToPOSIXDescriptor(fd: fileDescriptor, data: data)
        }

        let inboundPipe = makeSerialInboundTransportPipe()
        let readQueue = DispatchQueue(label: "com.agentvm.vsock.read.\(vmID.rawValue)", qos: .userInitiated)
        let source = DispatchSource.makeReadSource(fileDescriptor: fileDescriptor, queue: readQueue)
        let shouldClose = closeWhenDone

        source.setEventHandler {
            var scratch = [UInt8](repeating: 0, count: 65_536)
            var coalesced = Data()
            while true {
                let n = Darwin.read(fileDescriptor, &scratch, scratch.count)
                if n > 0 {
                    coalesced.append(contentsOf: scratch.prefix(n))
                } else if n == 0 {
                    if !coalesced.isEmpty {
                        inboundPipe.yield(coalesced)
                        coalesced.removeAll(keepingCapacity: false)
                    }
                    inboundPipe.finish()
                    source.cancel()
                    break
                } else {
                    if errno == EAGAIN || errno == EWOULDBLOCK {
                        break
                    }
                    if errno == EINTR {
                        continue
                    }
                    if !coalesced.isEmpty {
                        inboundPipe.yield(coalesced)
                        coalesced.removeAll(keepingCapacity: false)
                    }
                    inboundPipe.finish()
                    source.cancel()
                    break
                }
            }
            if !coalesced.isEmpty {
                inboundPipe.yield(coalesced)
            }
        }

        source.setCancelHandler {
            inboundPipe.finish()
            if shouldClose {
                _ = Darwin.close(fileDescriptor)
            }
        }

        self.attachedReadSource = source
        source.resume()
    }

    /// Attaches a `Foundation.FileHandle` backed by a VirtioSocket or UNIX domain stream connection.
    public func attachFileHandle(_ fileHandle: FileHandle, closeWhenDone: Bool = false) throws {
        try attachPOSIXFileDescriptor(fileHandle.fileDescriptor, closeWhenDone: closeWhenDone)
    }

    /// Gracefully tears down transport sources and fails any in-flight stream continuations.
    public func shutdown() {
        guard !isShutDown else { return }
        isShutDown = true
        detachFDSourceIfPresent()
        pairedLoopbackPeer = nil
        simulatedPeerEndpoint = nil

        let closedError = AgentVMError.vsockProtocolViolation(
            detail: "VsockMultiplexSession for VM '\(vmID.rawValue)' was shut down."
        )

        for (_, stream) in openStreams {
            for (_, waiter) in stream.creditWaiters {
                waiter.resume(throwing: closedError)
            }
        }
        openStreams.removeAll()

        for (_, execCtx) in pendingExecs {
            execCtx.promise.reject(closedError)
        }
        pendingExecs.removeAll()

        for (_, pushCtx) in pendingFilePushes {
            pushCtx.promise.reject(closedError)
        }
        pendingFilePushes.removeAll()

        for (_, pullCtx) in pendingFilePulls {
            pullCtx.promise.reject(closedError)
        }
        pendingFilePulls.removeAll()

        for waiter in pendingHeartbeatWaiters {
            waiter.reject(closedError)
        }
        pendingHeartbeatWaiters.removeAll()

        for (_, pf) in portForwardStreams {
            pf.handshakePromise?.reject(closedError)
            pf.inboundContinuation.finish()
        }
        portForwardStreams.removeAll()

        for (_, sub) in ptyOutputSubscribers {
            sub.finish()
        }
        ptyOutputSubscribers.removeAll()
    }

    // MARK: Inbound Raw Wire Byte Processing

    /// Feeds raw transport socket bytes into the `VsockStreamAccumulator`, validates `AVM1` framing & CRC-32,
    /// updates stream sliding-window credits, and dispatches channel handlers.
    public func receiveRawTransportBytes(_ data: Data) async throws {
        guard !data.isEmpty else { return }
        wireBytesReceivedCount &+= UInt64(data.count)

        let frames = try accumulator.ingest(data)
        for (header, payload) in frames {
            framesReceivedCount &+= 1
            if header.flags.contains(.compressed) {
                compressedFramesReceivedCount &+= 1
            }
            if header.flags.contains(.windowUpdate) {
                windowUpdatesReceivedCount &+= 1
            }
            try await handleDecodedFrame(header: header, payload: payload)
        }
    }

    // MARK: Guest Command Execution (Channel .execProcess)

    /// Executes a command inside the guest sandbox over a multiplexed `.execProcess` `AVM1` stream.
    public func executeCommand(_ request: GuestExecRequest) async throws -> GuestExecResult {
        try await executeCommandStreaming(request, onChunk: nil)
    }

    /// Executes a command inside the guest sandbox while streaming live `stdout`/`stderr` chunks as they arrive.
    public func executeCommandStreaming(
        _ request: GuestExecRequest,
        onChunk: (@Sendable (GuestExecOutputChunk) async -> Void)? = nil
    ) async throws -> GuestExecResult {
        try await executeCommandStreaming(
            request,
            onStreamOpened: nil,
            onChunk: onChunk
        )
    }

    /// Executes a command inside the guest sandbox while exposing the allocated `AVM1` `streamID` and streaming chunks.
    public func executeCommandStreaming(
        _ request: GuestExecRequest,
        maxRetainedBytesPerStream: Int? = nil,
        onStreamOpened: (@Sendable (UInt32) -> Void)?,
        onChunk: (@Sendable (GuestExecOutputChunk) async -> Void)?
    ) async throws -> GuestExecResult {
        try ensureActiveTransport()

        let streamID = allocateStreamID(channel: .execProcess)
        let promise = VsockRPCPromise<GuestExecResult>()
        let startedAt = Date()

        pendingExecs[streamID] = PendingExecContext(
            request: request,
            startedAt: startedAt,
            maxRetainedBytesPerStream: maxRetainedBytesPerStream,
            onChunk: onChunk,
            promise: promise
        )
        onStreamOpened?(streamID)

        let encodedRequest = try VsockWireJSON.encode(request)

        // Enforce command execution watchdog timeout.
        let timeoutSeconds = max(0.05, request.timeoutSeconds)
        let watchdogTask = Task { [weak self] in
            let nanos = UInt64(min(timeoutSeconds, 86_400.0) * 1_000_000_000.0)
            try? await Task.sleep(nanoseconds: nanos)
            guard !Task.isCancelled, let self else { return }
            await self.handleExecWatchdogTimeout(streamID: streamID)
        }
        defer { watchdogTask.cancel() }

        do {
            try await sendStreamPayloadChunked(
                streamID: streamID,
                channel: .execProcess,
                initialFlags: [.syn],
                finalFlags: [.endOfMessage],
                payload: encodedRequest,
                compressIfBeneficial: true
            )
            return try await promise.wait()
        } catch {
            pendingExecs.removeValue(forKey: streamID)
            closeStreamState(streamID: streamID)
            throw error
        }
    }

    private func handleExecWatchdogTimeout(streamID: UInt32) async {
        guard let ctx = pendingExecs.removeValue(forKey: streamID) else { return }
        try? await sendRawControlFrame(
            channel: .execProcess,
            flags: [.rst, .endOfMessage],
            streamID: streamID,
            payload: Data()
        )
        closeStreamState(streamID: streamID)
        let elapsedMs = max(1, Int(Date().timeIntervalSince(ctx.startedAt) * 1000.0))
        let timedOutResult = GuestExecResult(
            requestID: ctx.request.id,
            vmID: vmID,
            commandLine: ctx.request.commandLineSummary,
            exitCode: 124,
            stdoutData: ctx.stdoutBuffer,
            stderrData: ctx.stderrBuffer,
            stdoutTotalBytes: ctx.stdoutTotalBytes,
            stderrTotalBytes: ctx.stderrTotalBytes,
            durationMilliseconds: elapsedMs,
            timedOut: true,
            completedAt: Date()
        )
        ctx.promise.resolve(timedOutResult)
    }

    /// Aborts a single in-flight `.execProcess` stream by sending an `AVM1` `RST` frame on `streamID`
    /// without tearing down the multiplexed vsock session or affecting sibling streams.
    public func cancelExecStream(
        streamID: UInt32,
        reason: String = "Exec cancelled by client disconnect."
    ) async {
        guard let ctx = pendingExecs.removeValue(forKey: streamID) else { return }
        try? await sendRawControlFrame(
            channel: .execProcess,
            flags: [.rst, .endOfMessage],
            streamID: streamID,
            payload: Data()
        )
        closeStreamState(streamID: streamID)
        ctx.promise.reject(AgentVMError.vsockProtocolViolation(detail: reason))
    }

    // MARK: File Transfer with SHA-256 Integrity & Flow Control (Channel .fileTransfer)

    /// Streams a host file to `guestDestinationPath` inside the VM over `.fileTransfer` with sliding-window
    /// backpressure and guest-side SHA-256 verification.
    public func pushFile(
        localURL: URL,
        guestDestinationPath: String,
        permissions: UInt16 = 0o644
    ) async throws -> GuestFileTransferManifest {
        try ensureActiveTransport()

        let normalizedGuestPath = guestDestinationPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalizedGuestPath.isEmpty else {
            throw AgentVMError.vsockProtocolViolation(detail: "Guest destination path must not be empty.")
        }

        let fileData: Data
        let modTime: Int64
        do {
            fileData = try Data(contentsOf: localURL)
            let attrs = try FileManager.default.attributesOfItem(atPath: localURL.path)
            let mdate = (attrs[.modificationDate] as? Date) ?? Date()
            modTime = Int64(mdate.timeIntervalSince1970)
        } catch {
            throw AgentVMError.diskImageOperationFailed(
                path: localURL.path,
                errnoCode: errno,
                detail: "Unable to read local source file for vsock push: \(error.localizedDescription)"
            )
        }

        let sha256 = BinaryChecksums.sha256Hex(fileData)
        let manifest = GuestFileTransferManifest(
            direction: .hostToGuest,
            sourcePath: localURL.path,
            destinationPath: normalizedGuestPath,
            totalBytes: UInt64(fileData.count),
            sha256Hex: sha256,
            posixPermissions: permissions,
            modifiedTimestamp: modTime
        )

        let streamID = allocateStreamID(channel: .fileTransfer)
        let promise = VsockRPCPromise<GuestFileTransferManifest>()
        pendingFilePushes[streamID] = PendingPushContext(manifest: manifest, promise: promise)

        do {
            // 1. Send SYN control header carrying the transfer manifest.
            let beginEnvelope = VsockFileTransferControlEnvelope(phase: .pushBegin, manifest: manifest)
            let beginBytes = try VsockWireJSON.encode(beginEnvelope)
            try await sendSingleStreamFrame(
                streamID: streamID,
                channel: .fileTransfer,
                flags: [.syn],
                payload: beginBytes,
                compressIfBeneficial: true,
                consumesWindow: false
            )

            // 2. Stream raw binary file chunks subject to credit-based sliding-window flow control.
            if fileData.isEmpty {
                try await sendSingleStreamFrame(
                    streamID: streamID,
                    channel: .fileTransfer,
                    flags: [.ack, .endOfMessage],
                    payload: Data(),
                    compressIfBeneficial: false,
                    consumesWindow: false
                )
            } else {
                try await sendStreamPayloadChunked(
                    streamID: streamID,
                    channel: .fileTransfer,
                    initialFlags: [.ack],
                    finalFlags: [.ack, .endOfMessage],
                    payload: fileData,
                    compressIfBeneficial: true
                )
            }

            return try await promise.wait()
        } catch {
            pendingFilePushes.removeValue(forKey: streamID)
            closeStreamState(streamID: streamID)
            throw error
        }
    }

    /// Pulls `guestSourcePath` from the VM to `localDestinationURL` on the host, verifying the SHA-256
    /// digest before atomically committing the downloaded file.
    public func pullFile(
        guestSourcePath: String,
        localDestinationURL: URL
    ) async throws -> GuestFileTransferManifest {
        try ensureActiveTransport()

        let normalizedSource = guestSourcePath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalizedSource.isEmpty else {
            throw AgentVMError.vsockProtocolViolation(detail: "Guest source path must not be empty.")
        }

        let streamID = allocateStreamID(channel: .fileTransfer)
        let promise = VsockRPCPromise<GuestFileTransferManifest>()
        pendingFilePulls[streamID] = PendingPullContext(
            guestSourcePath: normalizedSource,
            localDestinationURL: localDestinationURL,
            promise: promise
        )

        do {
            let pullEnvelope = VsockFileTransferControlEnvelope(
                phase: .pullRequest,
                requestedPath: normalizedSource
            )
            let pullBytes = try VsockWireJSON.encode(pullEnvelope)
            try await sendSingleStreamFrame(
                streamID: streamID,
                channel: .fileTransfer,
                flags: [.syn, .endOfMessage],
                payload: pullBytes,
                compressIfBeneficial: false,
                consumesWindow: false
            )
            return try await promise.wait()
        } catch {
            pendingFilePulls.removeValue(forKey: streamID)
            closeStreamState(streamID: streamID)
            throw error
        }
    }

    // MARK: Interactive PTY Console (Channel .interactivePTY)

    /// Attaches a `VT100ScreenBuffer` so incoming `.interactivePTY` output frames automatically render into it.
    public func attachTerminalScreenBuffer(_ screenBuffer: VT100ScreenBuffer) {
        self.attachedScreenBuffer = screenBuffer
    }

    /// Subscribes to decoded `.interactivePTY` guest terminal output chunks.
    public func ptyOutputStream() -> AsyncStream<Data> {
        let subscriberID = UUID()
        return AsyncStream { continuation in
            self.ptyOutputSubscribers[subscriberID] = continuation
            continuation.onTermination = { [weak self] _ in
                guard let self else { return }
                Task {
                    await self.removePTYSubscriber(subscriberID)
                }
            }
        }
    }

    private func removePTYSubscriber(_ id: UUID) {
        ptyOutputSubscribers.removeValue(forKey: id)
    }

    /// Sends raw terminal keystrokes/stdin bytes to an open `.interactivePTY` stream (lazily opening one if `streamID == nil`).
    public func sendPTYInput(_ bytes: Data, streamID: UInt32? = nil) async throws {
        try ensureActiveTransport()
        let activeStreamID = try await resolveOrOpenPTYStream(requestedStreamID: streamID)
        guard !bytes.isEmpty else { return }

        var writer = BinaryBufferWriter(capacity: 1 + bytes.count)
        writer.appendUInt8(VsockPTYSubframeOpcode.stdinBytes.rawValue)
        writer.appendData(bytes)

        try await sendStreamPayloadChunked(
            streamID: activeStreamID,
            channel: .interactivePTY,
            initialFlags: [.ack],
            finalFlags: [.ack],
            payload: writer.data,
            compressIfBeneficial: false
        )
    }

    /// Sends a `TIOCSWINSZ` terminal resize frame (`columns` x `rows`) over `.interactivePTY`.
    public func resizePTY(columns: UInt16, rows: UInt16, streamID: UInt32? = nil) async throws {
        try ensureActiveTransport()
        let clampedCols = max(4, columns)
        let clampedRows = max(2, rows)
        self.ptyColumns = clampedCols
        self.ptyRows = clampedRows
        attachedScreenBuffer?.resize(columns: Int(clampedCols), rows: Int(clampedRows))

        let activeStreamID = try await resolveOrOpenPTYStream(requestedStreamID: streamID)
        var writer = BinaryBufferWriter(capacity: 5)
        writer.appendUInt8(VsockPTYSubframeOpcode.windowResize.rawValue)
        writer.appendUInt16BE(clampedCols)
        writer.appendUInt16BE(clampedRows)

        try await sendSingleStreamFrame(
            streamID: activeStreamID,
            channel: .interactivePTY,
            flags: [.ack],
            payload: writer.data,
            compressIfBeneficial: false,
            consumesWindow: false
        )
    }

    private func resolveOrOpenPTYStream(requestedStreamID: UInt32?) async throws -> UInt32 {
        if let explicit = requestedStreamID {
            if openStreams[explicit] == nil {
                openStreams[explicit] = StreamFlowState(streamID: explicit, channel: .interactivePTY)
                try await sendPTYOpenFrame(streamID: explicit)
            }
            return explicit
        }
        if let existing = defaultPTYStreamID, openStreams[existing] != nil {
            return existing
        }
        let allocated = allocateStreamID(channel: .interactivePTY)
        defaultPTYStreamID = allocated
        try await sendPTYOpenFrame(streamID: allocated)
        return allocated
    }

    private func sendPTYOpenFrame(streamID: UInt32) async throws {
        var writer = BinaryBufferWriter(capacity: 5)
        writer.appendUInt8(VsockPTYSubframeOpcode.openSession.rawValue)
        writer.appendUInt16BE(ptyColumns)
        writer.appendUInt16BE(ptyRows)
        try await sendSingleStreamFrame(
            streamID: streamID,
            channel: .interactivePTY,
            flags: [.syn],
            payload: writer.data,
            compressIfBeneficial: false,
            consumesWindow: false
        )
    }

    // MARK: TCP Port-Forward Stream Multiplexing (Channel .tcpPortForward)

    /// Opens a multiplexed `.tcpPortForward` stream targeting `127.0.0.1:<guestPort>` inside the guest.
    public func openPortForwardStream(
        guestPort: UInt16,
        sourceAddress: String = "127.0.0.1",
        sourcePort: UInt16 = 0
    ) async throws -> (streamID: UInt32, inboundData: AsyncStream<Data>) {
        try ensureActiveTransport()
        guard guestPort > 0 else {
            throw AgentVMError.vsockProtocolViolation(detail: "Cannot forward to guest TCP port 0.")
        }

        let streamID = allocateStreamID(channel: .tcpPortForward)
        let handshakePromise = VsockRPCPromise<Void>()

        var capturedContinuation: AsyncStream<Data>.Continuation!
        let inboundStream = AsyncStream<Data> { continuation in
            capturedContinuation = continuation
        }

        portForwardStreams[streamID] = ActivePortForwardStream(
            streamID: streamID,
            guestPort: guestPort,
            handshakePromise: handshakePromise,
            inboundContinuation: capturedContinuation
        )

        let connectEnv = VsockPortForwardEnvelope(
            action: .connect,
            guestPort: guestPort,
            sourceAddress: sourceAddress,
            sourcePort: sourcePort
        )
        let connectPayload = try VsockWireJSON.encode(connectEnv)

        do {
            try await sendSingleStreamFrame(
                streamID: streamID,
                channel: .tcpPortForward,
                flags: [.syn],
                payload: connectPayload,
                compressIfBeneficial: false,
                consumesWindow: false
            )
            try await handshakePromise.wait()
            return (streamID: streamID, inboundData: inboundStream)
        } catch {
            if let removed = portForwardStreams.removeValue(forKey: streamID) {
                removed.inboundContinuation.finish()
            }
            closeStreamState(streamID: streamID)
            throw error
        }
    }

    /// Sends raw TCP socket payload bytes across an established `.tcpPortForward` stream.
    public func sendPortForwardData(streamID: UInt32, payload: Data) async throws {
        guard !payload.isEmpty else { return }
        guard portForwardStreams[streamID] != nil, openStreams[streamID] != nil else {
            throw AgentVMError.vsockProtocolViolation(
                detail: "Port-forward stream \(streamID) is no longer open."
            )
        }
        try await sendStreamPayloadChunked(
            streamID: streamID,
            channel: .tcpPortForward,
            initialFlags: [.ack],
            finalFlags: [.ack],
            payload: payload,
            compressIfBeneficial: false
        )
    }

    /// Half-closes / terminates a `.tcpPortForward` stream and notifies the guest bridge.
    public func closePortForwardStream(streamID: UInt32) async throws {
        if let pf = portForwardStreams.removeValue(forKey: streamID) {
            pf.inboundContinuation.finish()
        }
        guard openStreams[streamID] != nil else { return }
        try? await sendSingleStreamFrame(
            streamID: streamID,
            channel: .tcpPortForward,
            flags: [.fin, .endOfMessage],
            payload: Data(),
            compressIfBeneficial: false,
            consumesWindow: false
        )
        closeStreamState(streamID: streamID)
    }

    // MARK: Telemetry & Stream Inspection

    /// Returns the most recently received `GuestHeartbeatPayload` from the guest daemon, if any.
    public func latestHeartbeat() -> GuestHeartbeatPayload? {
        cachedHeartbeat
    }

    /// Actively solicits a fresh `GuestHeartbeatPayload` over `.telemetryHeartbeat`.
    public func requestHeartbeat() async throws -> GuestHeartbeatPayload {
        try ensureActiveTransport()
        let promise = VsockRPCPromise<GuestHeartbeatPayload>()
        pendingHeartbeatWaiters.append(promise)

        controlSequence &+= 1
        let frame = try codec.encodeFrame(
            channel: .telemetryHeartbeat,
            flags: [.syn, .endOfMessage],
            streamID: 0,
            sequence: controlSequence,
            windowCredit: VsockWireConstants.defaultWindowCredit,
            payload: Data(),
            compressIfBeneficial: false
        )
        try await transmitEncodedFrame(frame, wasCompressed: false)
        return try await promise.wait()
    }

    /// Number of currently open logical multiplexed streams (`streamID != 0`).
    public func openStreamCount() -> Int {
        openStreams.count
    }

    /// Snapshot of cumulative framing, compression, and sliding-window statistics.
    public func sessionTelemetry() -> VsockSessionTelemetry {
        VsockSessionTelemetry(
            vmID: vmID,
            framesSent: framesSentCount,
            framesReceived: framesReceivedCount,
            compressedFramesSent: compressedFramesSentCount,
            compressedFramesReceived: compressedFramesReceivedCount,
            windowUpdatesSent: windowUpdatesSentCount,
            windowUpdatesReceived: windowUpdatesReceivedCount,
            wireBytesSent: wireBytesSentCount,
            wireBytesReceived: wireBytesReceivedCount,
            openStreams: openStreams.count,
            isGuestResponderAttached: simulatedPeerEndpoint != nil
        )
    }

    // MARK: Internal Multiplexing, Credit Sliding Window & Channel Dispatch

    private func ensureActiveTransport() throws {
        if isShutDown {
            throw AgentVMError.vsockProtocolViolation(
                detail: "VsockMultiplexSession for VM '\(vmID.rawValue)' has been shut down."
            )
        }
        guard transportWrite != nil else {
            throw AgentVMError.vsockProtocolViolation(
                detail: "No Vsock transport or simulated responder attached for VM '\(vmID.rawValue)'."
            )
        }
    }

    private func allocateStreamID(channel: VsockChannelKind) -> UInt32 {
        let allocated: UInt32
        if isGuestServerRole {
            allocated = nextGuestStreamID
            nextGuestStreamID &+= 2
        } else {
            allocated = nextHostStreamID
            nextHostStreamID &+= 2
        }
        openStreams[allocated] = StreamFlowState(streamID: allocated, channel: channel)
        return allocated
    }

    private func closeStreamState(streamID: UInt32) {
        guard let removed = openStreams.removeValue(forKey: streamID) else { return }
        let cancelErr = AgentVMError.vsockProtocolViolation(detail: "Stream \(streamID) closed.")
        for (_, waiter) in removed.creditWaiters {
            waiter.resume(throwing: cancelErr)
        }
        if defaultPTYStreamID == streamID {
            defaultPTYStreamID = nil
        }
    }

    private func sendStreamPayloadChunked(
        streamID: UInt32,
        channel: VsockChannelKind,
        initialFlags: VsockFrameFlags,
        finalFlags: VsockFrameFlags,
        payload: Data,
        compressIfBeneficial: Bool
    ) async throws {
        if payload.isEmpty {
            let combined = initialFlags.union(finalFlags)
            try await sendSingleStreamFrame(
                streamID: streamID,
                channel: channel,
                flags: combined,
                payload: Data(),
                compressIfBeneficial: false,
                consumesWindow: false
            )
            return
        }

        var cursor = 0
        var isFirstFrame = true
        let total = payload.count

        while cursor < total {
            try await waitForPeerWindowCreditIfNeeded(streamID: streamID)
            guard let stream = openStreams[streamID] else {
                throw AgentVMError.vsockProtocolViolation(
                    detail: "Stream \(streamID) closed while transmitting chunked payload."
                )
            }

            let availableWindow = Int(stream.peerSendWindowCredit)
            let chunkLength = min(
                total - cursor,
                min(VsockWireConstants.defaultMaxChunkBytes, max(1, availableWindow))
            )
            let isLastFrame = (cursor + chunkLength >= total)

            var frameFlags: VsockFrameFlags = []
            if isFirstFrame {
                frameFlags.formUnion(initialFlags)
            } else {
                frameFlags.insert(.ack)
            }
            if isLastFrame {
                frameFlags.formUnion(finalFlags)
            }

            let slice = Data(payload[(payload.startIndex + cursor)..<(payload.startIndex + cursor + chunkLength)])
            try await sendSingleStreamFrame(
                streamID: streamID,
                channel: channel,
                flags: frameFlags,
                payload: slice,
                compressIfBeneficial: compressIfBeneficial,
                consumesWindow: true
            )

            cursor += chunkLength
            isFirstFrame = false
        }
    }

    private func waitForPeerWindowCreditIfNeeded(streamID: UInt32) async throws {
        while true {
            guard var stream = openStreams[streamID] else {
                throw AgentVMError.vsockProtocolViolation(detail: "Stream \(streamID) closed awaiting window credit.")
            }
            if stream.peerSendWindowCredit > 0 {
                return
            }
            let waiterID = UUID()
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                stream.creditWaiters[waiterID] = cont
                openStreams[streamID] = stream
            }
        }
    }

    private func replenishPeerWindowCredit(streamID: UInt32, creditIncrement: UInt32) {
        guard var stream = openStreams[streamID], creditIncrement > 0 else { return }
        let sum = UInt64(stream.peerSendWindowCredit) + UInt64(creditIncrement)
        stream.peerSendWindowCredit = UInt32(min(UInt64(UInt32.max), sum))
        let waiters = Array(stream.creditWaiters.values)
        stream.creditWaiters.removeAll()
        openStreams[streamID] = stream
        for waiter in waiters {
            waiter.resume()
        }
    }

    private func accountInboundPayloadWindow(streamID: UInt32, channel: VsockChannelKind, byteCount: Int) async throws {
        guard streamID != 0, byteCount > 0, var stream = openStreams[streamID] else { return }
        let consumed = UInt32(clamping: byteCount)
        if stream.localReceiveWindowCredit >= consumed {
            stream.localReceiveWindowCredit -= consumed
        } else {
            stream.localReceiveWindowCredit = 0
        }
        stream.uncreditedConsumedBytes &+= consumed

        if stream.uncreditedConsumedBytes >= Self.windowReplenishThreshold {
            let replenish = stream.uncreditedConsumedBytes
            stream.uncreditedConsumedBytes = 0
            stream.localReceiveWindowCredit = min(
                VsockWireConstants.defaultWindowCredit,
                stream.localReceiveWindowCredit &+ replenish
            )
            stream.outboundSequence &+= 1
            let seq = stream.outboundSequence
            openStreams[streamID] = stream

            let winFrame = try codec.encodeFrame(
                channel: channel,
                flags: [.windowUpdate, .ack],
                streamID: streamID,
                sequence: seq,
                windowCredit: replenish,
                payload: Data(),
                compressIfBeneficial: false
            )
            windowUpdatesSentCount &+= 1
            try await transmitEncodedFrame(winFrame, wasCompressed: false)
        } else {
            openStreams[streamID] = stream
        }
    }

    private func sendSingleStreamFrame(
        streamID: UInt32,
        channel: VsockChannelKind,
        flags: VsockFrameFlags,
        payload: Data,
        compressIfBeneficial: Bool,
        consumesWindow: Bool
    ) async throws {
        var stream = openStreams[streamID] ?? StreamFlowState(streamID: streamID, channel: channel)
        stream.outboundSequence &+= 1
        if consumesWindow && !payload.isEmpty {
            let cost = UInt32(clamping: payload.count)
            stream.peerSendWindowCredit = stream.peerSendWindowCredit >= cost ? (stream.peerSendWindowCredit - cost) : 0
        }
        let seq = stream.outboundSequence
        let credit = stream.localReceiveWindowCredit
        openStreams[streamID] = stream

        let wireData = try codec.encodeFrame(
            channel: channel,
            flags: flags,
            streamID: streamID,
            sequence: seq,
            windowCredit: credit,
            payload: payload,
            compressIfBeneficial: compressIfBeneficial
        )
        let compressedApplied = wireData.count >= 8 && ((UInt16(wireData[6]) << 8 | UInt16(wireData[7])) & VsockFrameFlags.compressed.rawValue) != 0
        try await transmitEncodedFrame(wireData, wasCompressed: compressedApplied)
    }

    private func sendRawControlFrame(
        channel: VsockChannelKind,
        flags: VsockFrameFlags,
        streamID: UInt32,
        payload: Data
    ) async throws {
        controlSequence &+= 1
        let wireData = try codec.encodeFrame(
            channel: channel,
            flags: flags,
            streamID: streamID,
            sequence: controlSequence,
            windowCredit: VsockWireConstants.defaultWindowCredit,
            payload: payload,
            compressIfBeneficial: false
        )
        try await transmitEncodedFrame(wireData, wasCompressed: false)
    }

    private func transmitEncodedFrame(_ wireBytes: Data, wasCompressed: Bool) async throws {
        guard let writer = transportWrite else {
            throw AgentVMError.vsockProtocolViolation(detail: "Vsock transport writer is disconnected.")
        }
        framesSentCount &+= 1
        if wasCompressed {
            compressedFramesSentCount &+= 1
        }
        wireBytesSentCount &+= UInt64(wireBytes.count)
        try await writer(wireBytes)
    }

    // MARK: Frame Router

    private func handleDecodedFrame(header: VsockFrameHeader, payload: Data) async throws {
        let streamID = header.streamID

        if header.flags.contains(.windowUpdate) {
            replenishPeerWindowCredit(streamID: streamID, creditIncrement: header.windowCredit)
            if payload.isEmpty && !header.flags.contains(.fin) && !header.flags.contains(.rst) {
                return
            }
        }

        if streamID != 0 {
            if openStreams[streamID] == nil && header.flags.contains(.syn) {
                openStreams[streamID] = StreamFlowState(
                    streamID: streamID,
                    channel: header.channel,
                    peerSendWindowCredit: max(4096, header.windowCredit)
                )
            }
            if var stream = openStreams[streamID] {
                stream.inboundSequence = header.sequenceNumber
                openStreams[streamID] = stream
            }
            try await accountInboundPayloadWindow(
                streamID: streamID,
                channel: header.channel,
                byteCount: payload.count
            )
        }

        if isGuestServerRole {
            try await handleGuestServerInboundFrame(header: header, payload: payload)
            return
        }

        switch header.channel {
        case .control:
            try await handleHostControlFrame(header: header, payload: payload)
        case .execProcess:
            await handleHostExecFrame(header: header, payload: payload)
        case .fileTransfer:
            await handleHostFileTransferFrame(header: header, payload: payload)
        case .tcpPortForward:
            await handleHostPortForwardFrame(header: header, payload: payload)
        case .telemetryHeartbeat:
            handleHostHeartbeatFrame(header: header, payload: payload)
        case .interactivePTY:
            handleHostPTYFrame(header: header, payload: payload)
        }
    }

    private func handleHostControlFrame(header: VsockFrameHeader, payload: Data) async throws {
        guard !payload.isEmpty else { return }
        if let ctrl = try? VsockWireJSON.decode(VsockControlEnvelope.self, from: payload),
           ctrl.kind == .ping {
            let pong = VsockControlEnvelope(kind: .pong)
            let encoded = try VsockWireJSON.encode(pong)
            try await sendRawControlFrame(
                channel: .control,
                flags: [.ack, .endOfMessage],
                streamID: 0,
                payload: encoded
            )
        }
    }

    private func handleHostExecFrame(header: VsockFrameHeader, payload: Data) async {
        let streamID = header.streamID
        guard var ctx = pendingExecs[streamID] else { return }

        if header.flags.contains(.errorFrame) || header.flags.contains(.rst) {
            pendingExecs.removeValue(forKey: streamID)
            closeStreamState(streamID: streamID)
            let detail = String(decoding: payload, as: UTF8.self)
            ctx.promise.reject(
                AgentVMError.vsockProtocolViolation(
                    detail: detail.isEmpty ? "Guest reset exec stream \(streamID)." : detail
                )
            )
            return
        }

        if header.flags.contains(.fin) {
            pendingExecs.removeValue(forKey: streamID)
            closeStreamState(streamID: streamID)
            do {
                let completion = try VsockWireJSON.decode(VsockExecCompletionEnvelope.self, from: payload)
                if let errDetail = completion.errorDetail, !errDetail.isEmpty, completion.exitCode == -1 {
                    ctx.promise.reject(AgentVMError.vsockProtocolViolation(detail: errDetail))
                    return
                }
                let result = GuestExecResult(
                    requestID: ctx.request.id,
                    vmID: vmID,
                    commandLine: ctx.request.commandLineSummary,
                    exitCode: completion.exitCode,
                    stdoutData: ctx.stdoutBuffer,
                    stderrData: ctx.stderrBuffer,
                    stdoutTotalBytes: ctx.stdoutTotalBytes,
                    stderrTotalBytes: ctx.stderrTotalBytes,
                    durationMilliseconds: max(1, completion.durationMilliseconds),
                    timedOut: completion.timedOut,
                    completedAt: Date()
                )
                ctx.promise.resolve(result)
            } catch {
                ctx.promise.reject(error)
            }
            return
        }

        if !payload.isEmpty,
           let chunk = try? VsockWireJSON.decode(GuestExecOutputChunk.self, from: payload) {
            switch chunk.stream {
            case .stdout:
                ctx.stdoutTotalBytes &+= UInt64(chunk.data.count)
                if let limit = ctx.maxRetainedBytesPerStream {
                    let remaining = limit - ctx.stdoutBuffer.count
                    if remaining > 0 {
                        ctx.stdoutBuffer.append(chunk.data.prefix(remaining))
                    }
                } else {
                    ctx.stdoutBuffer.append(chunk.data)
                }
            case .stderr, .systemNotice:
                ctx.stderrTotalBytes &+= UInt64(chunk.data.count)
                if let limit = ctx.maxRetainedBytesPerStream {
                    let remaining = limit - ctx.stderrBuffer.count
                    if remaining > 0 {
                        ctx.stderrBuffer.append(chunk.data.prefix(remaining))
                    }
                } else {
                    ctx.stderrBuffer.append(chunk.data)
                }
            }
            pendingExecs[streamID] = ctx
            if let callback = ctx.onChunk {
                await callback(chunk)
            }
        }
    }

    private func handleHostFileTransferFrame(header: VsockFrameHeader, payload: Data) async {
        let streamID = header.streamID

        // Case 1: Response to `pushFile`
        if let pushCtx = pendingFilePushes[streamID] {
            if header.flags.contains(.errorFrame) || header.flags.contains(.rst) {
                pendingFilePushes.removeValue(forKey: streamID)
                closeStreamState(streamID: streamID)
                let msg = (try? VsockWireJSON.decode(VsockFileTransferControlEnvelope.self, from: payload))?.errorMessage
                    ?? String(decoding: payload, as: UTF8.self)
                pushCtx.promise.reject(
                    AgentVMError.vsockProtocolViolation(detail: "Guest file push failed: \(msg)")
                )
                return
            }

            if header.flags.contains(.fin) || header.flags.contains(.endOfMessage) {
                pendingFilePushes.removeValue(forKey: streamID)
                closeStreamState(streamID: streamID)
                do {
                    let ctrl = try VsockWireJSON.decode(VsockFileTransferControlEnvelope.self, from: payload)
                    guard ctrl.phase == .transferVerified, let verifiedManifest = ctrl.manifest else {
                        throw AgentVMError.vsockProtocolViolation(
                            detail: ctrl.errorMessage ?? "Guest did not confirm file SHA-256 verification."
                        )
                    }
                    guard verifiedManifest.sha256Hex.lowercased() == pushCtx.manifest.sha256Hex.lowercased() else {
                        throw AgentVMError.vsockProtocolViolation(
                            detail: "Guest reported mismatched SHA-256 (\(verifiedManifest.sha256Hex) != \(pushCtx.manifest.sha256Hex))."
                        )
                    }
                    pushCtx.promise.resolve(verifiedManifest)
                } catch {
                    pushCtx.promise.reject(error)
                }
            }
            return
        }

        // Case 2: Response stream for `pullFile`
        guard var pullCtx = pendingFilePulls[streamID] else { return }

        if header.flags.contains(.errorFrame) || header.flags.contains(.rst) {
            pendingFilePulls.removeValue(forKey: streamID)
            closeStreamState(streamID: streamID)
            let msg = (try? VsockWireJSON.decode(VsockFileTransferControlEnvelope.self, from: payload))?.errorMessage
                ?? String(decoding: payload, as: UTF8.self)
            pullCtx.promise.reject(
                AgentVMError.vsockProtocolViolation(detail: "Guest file pull failed for '\(pullCtx.guestSourcePath)': \(msg)")
            )
            return
        }

        if pullCtx.declaredManifest == nil && header.flags.contains(.syn) {
            do {
                let ctrl = try VsockWireJSON.decode(VsockFileTransferControlEnvelope.self, from: payload)
                guard ctrl.phase == .pullManifest, let manifest = ctrl.manifest else {
                    throw AgentVMError.vsockProtocolViolation(detail: "Expected pullManifest header on stream \(streamID).")
                }
                pullCtx.declaredManifest = manifest
                pullCtx.receivedBytes.reserveCapacity(Int(min(manifest.totalBytes, 16_777_216)))
                pendingFilePulls[streamID] = pullCtx
            } catch {
                pendingFilePulls.removeValue(forKey: streamID)
                closeStreamState(streamID: streamID)
                pullCtx.promise.reject(error)
            }
            return
        }

        if !payload.isEmpty {
            pullCtx.receivedBytes.append(payload)
            pendingFilePulls[streamID] = pullCtx
        }

        if header.flags.contains(.fin) || header.flags.contains(.endOfMessage) {
            pendingFilePulls.removeValue(forKey: streamID)
            closeStreamState(streamID: streamID)

            guard var manifest = pullCtx.declaredManifest else {
                pullCtx.promise.reject(
                    AgentVMError.vsockProtocolViolation(detail: "File pull completed before manifest arrived.")
                )
                return
            }

            let actualSHA256 = BinaryChecksums.sha256Hex(pullCtx.receivedBytes)
            guard actualSHA256.lowercased() == manifest.sha256Hex.lowercased() else {
                pullCtx.promise.reject(
                    AgentVMError.vsockProtocolViolation(
                        detail: "Pulled file SHA-256 mismatch (expected \(manifest.sha256Hex), got \(actualSHA256))."
                    )
                )
                return
            }

            do {
                let parentDir = pullCtx.localDestinationURL.deletingLastPathComponent()
                try FileManager.default.createDirectory(at: parentDir, withIntermediateDirectories: true)
                try pullCtx.receivedBytes.write(to: pullCtx.localDestinationURL, options: .atomic)
                _ = Darwin.chmod(pullCtx.localDestinationURL.path, mode_t(manifest.posixPermissions))
                manifest.destinationPath = pullCtx.localDestinationURL.path
                pullCtx.promise.resolve(manifest)
            } catch {
                pullCtx.promise.reject(
                    AgentVMError.diskImageOperationFailed(
                        path: pullCtx.localDestinationURL.path,
                        errnoCode: errno,
                        detail: "Failed writing pulled guest file: \(error.localizedDescription)"
                    )
                )
            }
        }
    }

    private func handleHostPortForwardFrame(header: VsockFrameHeader, payload: Data) async {
        let streamID = header.streamID
        guard var pf = portForwardStreams[streamID] else { return }

        if header.flags.contains(.errorFrame) || header.flags.contains(.rst) {
            portForwardStreams.removeValue(forKey: streamID)
            closeStreamState(streamID: streamID)
            let errDetail = (try? VsockWireJSON.decode(VsockPortForwardEnvelope.self, from: payload))?.errorDetail
                ?? "Guest port-forward connection refused."
            pf.handshakePromise?.reject(AgentVMError.vsockProtocolViolation(detail: errDetail))
            pf.inboundContinuation.finish()
            return
        }

        if let handshake = pf.handshakePromise, header.flags.contains(.syn) && header.flags.contains(.ack) {
            if let env = try? VsockWireJSON.decode(VsockPortForwardEnvelope.self, from: payload),
               env.action == .connectFailed {
                portForwardStreams.removeValue(forKey: streamID)
                closeStreamState(streamID: streamID)
                handshake.reject(
                    AgentVMError.vsockProtocolViolation(detail: env.errorDetail ?? "Guest port connect failed.")
                )
                pf.inboundContinuation.finish()
                return
            }
            pf.handshakePromise = nil
            portForwardStreams[streamID] = pf
            handshake.resolve(())
            return
        }

        if !payload.isEmpty {
            pf.inboundContinuation.yield(payload)
        }

        if header.flags.contains(.fin) {
            portForwardStreams.removeValue(forKey: streamID)
            closeStreamState(streamID: streamID)
            pf.inboundContinuation.finish()
        }
    }

    private func handleHostHeartbeatFrame(header: VsockFrameHeader, payload: Data) {
        guard !payload.isEmpty,
              let heartbeat = try? VsockWireJSON.decode(GuestHeartbeatPayload.self, from: payload) else {
            return
        }
        cachedHeartbeat = heartbeat
        let waiters = pendingHeartbeatWaiters
        pendingHeartbeatWaiters.removeAll()
        for waiter in waiters {
            waiter.resolve(heartbeat)
        }
    }

    private func handleHostPTYFrame(header: VsockFrameHeader, payload: Data) {
        if header.flags.contains(.fin) || header.flags.contains(.rst) {
            closeStreamState(streamID: header.streamID)
            return
        }
        guard !payload.isEmpty else { return }

        let terminalBytes: Data
        if let first = payload.first, first == VsockPTYSubframeOpcode.stdoutBytes.rawValue {
            terminalBytes = Data(payload.dropFirst())
        } else {
            terminalBytes = payload
        }
        guard !terminalBytes.isEmpty else { return }

        attachedScreenBuffer?.feed(terminalBytes)
        for (_, subscriber) in ptyOutputSubscribers {
            subscriber.yield(terminalBytes)
        }
    }

    // MARK: Guest Server Role Support (for `createLoopbackPair(vmID:)`)

    private func activateAsGuestServerRole() {
        isGuestServerRole = true
        guestVirtualFiles = SimulatedGuestEngine.defaultVirtualFiles(vmID: vmID)
    }

    private func makeGuestHeartbeatWireFrame() throws -> Data {
        let hb = SimulatedGuestEngine.makeHeartbeat(vmID: vmID)
        cachedHeartbeat = hb
        let encoded = try VsockWireJSON.encode(hb)
        controlSequence &+= 1
        return try codec.encodeFrame(
            channel: .telemetryHeartbeat,
            flags: [.ack, .endOfMessage],
            streamID: 0,
            sequence: controlSequence,
            windowCredit: VsockWireConstants.defaultWindowCredit,
            payload: encoded,
            compressIfBeneficial: true
        )
    }

    private func emitGuestTelemetryHeartbeat() async throws {
        let frame = try makeGuestHeartbeatWireFrame()
        try await transmitEncodedFrame(frame, wasCompressed: false)
    }

    private func handleGuestServerInboundFrame(header: VsockFrameHeader, payload: Data) async throws {
        let streamID = header.streamID
        switch header.channel {
        case .control:
            let ack = VsockControlEnvelope(kind: .pong)
            try await sendRawControlFrame(
                channel: .control,
                flags: [.ack, .endOfMessage],
                streamID: 0,
                payload: try VsockWireJSON.encode(ack)
            )

        case .telemetryHeartbeat:
            try await emitGuestTelemetryHeartbeat()

        case .execProcess:
            guard !payload.isEmpty else { return }
            let req = try VsockWireJSON.decode(GuestExecRequest.self, from: payload)
            let outcome = SimulatedGuestEngine.execute(
                request: req,
                virtualFiles: &guestVirtualFiles
            )
            if outcome.simulatedDelayMs > 0 {
                try? await Task.sleep(nanoseconds: UInt64(outcome.simulatedDelayMs) * 1_000_000)
            }
            if openStreams[streamID] == nil { return }
            var chunkSeq: UInt32 = 0
            if !outcome.stdout.isEmpty {
                chunkSeq &+= 1
                let chunk = GuestExecOutputChunk(requestID: req.id, stream: .stdout, sequence: chunkSeq, data: outcome.stdout)
                try await sendSingleStreamFrame(
                    streamID: streamID,
                    channel: .execProcess,
                    flags: [.ack],
                    payload: try VsockWireJSON.encode(chunk),
                    compressIfBeneficial: true,
                    consumesWindow: true
                )
            }
            if !outcome.stderr.isEmpty {
                chunkSeq &+= 1
                let chunk = GuestExecOutputChunk(requestID: req.id, stream: .stderr, sequence: chunkSeq, data: outcome.stderr)
                try await sendSingleStreamFrame(
                    streamID: streamID,
                    channel: .execProcess,
                    flags: [.ack],
                    payload: try VsockWireJSON.encode(chunk),
                    compressIfBeneficial: true,
                    consumesWindow: true
                )
            }
            let done = VsockExecCompletionEnvelope(
                requestID: req.id,
                exitCode: outcome.exitCode,
                durationMilliseconds: max(1, outcome.durationMs),
                timedOut: false
            )
            try await sendSingleStreamFrame(
                streamID: streamID,
                channel: .execProcess,
                flags: [.fin, .endOfMessage],
                payload: try VsockWireJSON.encode(done),
                compressIfBeneficial: false,
                consumesWindow: false
            )
            closeStreamState(streamID: streamID)

        case .fileTransfer:
            try await handleGuestServerFileTransfer(header: header, payload: payload)

        case .tcpPortForward:
            try await handleGuestServerPortForward(header: header, payload: payload)

        case .interactivePTY:
            try await handleGuestServerPTY(header: header, payload: payload)
        }
    }

    private func handleGuestServerFileTransfer(header: VsockFrameHeader, payload: Data) async throws {
        let streamID = header.streamID
        if header.flags.contains(.syn) {
            let ctrl = try VsockWireJSON.decode(VsockFileTransferControlEnvelope.self, from: payload)
            switch ctrl.phase {
            case .pushBegin:
                guard let manifest = ctrl.manifest else { return }
                var asm = GuestInboundPushAssembly(manifest: manifest)
                asm.data.reserveCapacity(Int(min(manifest.totalBytes, 16_777_216)))
                guestInboundPushes[streamID] = asm
                return
            case .pullRequest:
                let reqPath = ctrl.requestedPath ?? ""
                guard let file = guestVirtualFiles[reqPath] else {
                    let errEnv = VsockFileTransferControlEnvelope(
                        phase: .transferError,
                        requestedPath: reqPath,
                        errorMessage: "ENOENT: '\(reqPath)' not found in guest filesystem."
                    )
                    try await sendSingleStreamFrame(
                        streamID: streamID,
                        channel: .fileTransfer,
                        flags: [.errorFrame, .fin, .endOfMessage],
                        payload: try VsockWireJSON.encode(errEnv),
                        compressIfBeneficial: false,
                        consumesWindow: false
                    )
                    closeStreamState(streamID: streamID)
                    return
                }
                let sha = BinaryChecksums.sha256Hex(file.data)
                let manifest = GuestFileTransferManifest(
                    direction: .guestToHost,
                    sourcePath: reqPath,
                    destinationPath: reqPath,
                    totalBytes: UInt64(file.data.count),
                    sha256Hex: sha,
                    posixPermissions: file.permissions,
                    modifiedTimestamp: file.modifiedTimestamp
                )
                let manifestEnv = VsockFileTransferControlEnvelope(phase: .pullManifest, manifest: manifest)
                try await sendSingleStreamFrame(
                    streamID: streamID,
                    channel: .fileTransfer,
                    flags: [.syn, .ack],
                    payload: try VsockWireJSON.encode(manifestEnv),
                    compressIfBeneficial: true,
                    consumesWindow: false
                )
                let pullPayload = file.data
                Task { [weak self] in
                    guard let self else { return }
                    try? await self.streamGuestPullPayloadAndClose(streamID: streamID, payload: pullPayload)
                }
                return
        default:
            return
        }
        }

        guard var asm = guestInboundPushes[streamID] else { return }
        if !payload.isEmpty {
            asm.data.append(payload)
            guestInboundPushes[streamID] = asm
        }
        if header.flags.contains(.endOfMessage) || header.flags.contains(.fin) {
            guestInboundPushes.removeValue(forKey: streamID)
            let actualSHA = BinaryChecksums.sha256Hex(asm.data)
            guard actualSHA.lowercased() == asm.manifest.sha256Hex.lowercased() else {
                let errEnv = VsockFileTransferControlEnvelope(
                    phase: .transferError,
                    manifest: asm.manifest,
                    errorMessage: "SHA-256 mismatch on guest write (expected \(asm.manifest.sha256Hex), got \(actualSHA))."
                )
                try await sendSingleStreamFrame(
                    streamID: streamID,
                    channel: .fileTransfer,
                    flags: [.errorFrame, .fin, .endOfMessage],
                    payload: try VsockWireJSON.encode(errEnv),
                    compressIfBeneficial: false,
                    consumesWindow: false
                )
                closeStreamState(streamID: streamID)
                return
            }
            guestVirtualFiles[asm.manifest.destinationPath] = VirtualGuestFile(
                data: asm.data,
                permissions: asm.manifest.posixPermissions,
                modifiedTimestamp: asm.manifest.modifiedTimestamp
            )
            let okEnv = VsockFileTransferControlEnvelope(phase: .transferVerified, manifest: asm.manifest)
            try await sendSingleStreamFrame(
                streamID: streamID,
                channel: .fileTransfer,
                flags: [.fin, .endOfMessage],
                payload: try VsockWireJSON.encode(okEnv),
                compressIfBeneficial: false,
                consumesWindow: false
            )
            closeStreamState(streamID: streamID)
        }
    }

    private func streamGuestPullPayloadAndClose(streamID: UInt32, payload: Data) async throws {
        try await sendStreamPayloadChunked(
            streamID: streamID,
            channel: .fileTransfer,
            initialFlags: [.ack],
            finalFlags: [.fin, .endOfMessage],
            payload: payload,
            compressIfBeneficial: true
        )
        closeStreamState(streamID: streamID)
    }

    private func handleGuestServerPortForward(header: VsockFrameHeader, payload: Data) async throws {
        let streamID = header.streamID
        if header.flags.contains(.syn) {
            let env = try VsockWireJSON.decode(VsockPortForwardEnvelope.self, from: payload)
            let ack = VsockPortForwardEnvelope(action: .connectAck, guestPort: env.guestPort)
            try await sendSingleStreamFrame(
                streamID: streamID,
                channel: .tcpPortForward,
                flags: [.syn, .ack],
                payload: try VsockWireJSON.encode(ack),
                compressIfBeneficial: false,
                consumesWindow: false
            )
            return
        }
        if header.flags.contains(.fin) || header.flags.contains(.rst) {
            try await sendSingleStreamFrame(
                streamID: streamID,
                channel: .tcpPortForward,
                flags: [.fin, .endOfMessage],
                payload: Data(),
                compressIfBeneficial: false,
                consumesWindow: false
            )
            closeStreamState(streamID: streamID)
            return
        }
        if !payload.isEmpty {
            let reply = SimulatedGuestEngine.respondToPortForwardBytes(payload)
            try await sendStreamPayloadChunked(
                streamID: streamID,
                channel: .tcpPortForward,
                initialFlags: [.ack],
                finalFlags: [.ack],
                payload: reply,
                compressIfBeneficial: false
            )
        }
    }

    private func handleGuestServerPTY(header: VsockFrameHeader, payload: Data) async throws {
        let streamID = header.streamID
        guard let opByte = payload.first,
              let op = VsockPTYSubframeOpcode(rawValue: opByte) else {
            return
        }
        let body = Data(payload.dropFirst())
        switch op {
        case .openSession:
            let banner = "\u{1B}[1;32magent@\(vmID.rawValue)\u{1B}[0m:\u{1B}[1;34m/workspace\u{1B}[0m$ "
            var out = BinaryBufferWriter(capacity: 1 + banner.utf8.count)
            out.appendUInt8(VsockPTYSubframeOpcode.stdoutBytes.rawValue)
            out.appendData(Data(banner.utf8))
            try await sendSingleStreamFrame(
                streamID: streamID,
                channel: .interactivePTY,
                flags: [.syn, .ack],
                payload: out.data,
                compressIfBeneficial: false,
                consumesWindow: false
            )
        case .windowResize:
            break
        case .stdinBytes:
            let echoed = SimulatedGuestEngine.renderPTYResponse(forStdin: body, vmID: vmID)
            var out = BinaryBufferWriter(capacity: 1 + echoed.count)
            out.appendUInt8(VsockPTYSubframeOpcode.stdoutBytes.rawValue)
            out.appendData(echoed)
            try await sendSingleStreamFrame(
                streamID: streamID,
                channel: .interactivePTY,
                flags: [.ack],
                payload: out.data,
                compressIfBeneficial: false,
                consumesWindow: false
            )
        case .stdoutBytes:
            break
        }
    }

    // MARK: POSIX Helpers

    private func makeSerialInboundTransportPipe() -> AsyncStream<Data>.Continuation {
        let (stream, continuation) = AsyncStream<Data>.makeStream()
        self.inboundTransportContinuation = continuation
        self.inboundTransportPumpTask = Task { [weak self] in
            for await chunk in stream {
                if Task.isCancelled { break }
                guard let self else { break }
                try? await self.receiveRawTransportBytes(chunk)
            }
        }
        return continuation
    }

    private func detachFDSourceIfPresent() {
        inboundTransportContinuation?.finish()
        inboundTransportContinuation = nil
        inboundTransportPumpTask?.cancel()
        inboundTransportPumpTask = nil
        if let src = attachedReadSource {
            attachedReadSource = nil
            src.cancel()
        }
        attachedFD = -1
        closeAttachedFDOnShutdown = false
    }

    private static func writeAllToPOSIXDescriptor(fd: Int32, data: Data) throws {
        try data.withUnsafeBytes { rawBuf in
            guard let base = rawBuf.baseAddress else { return }
            var written = 0
            let total = rawBuf.count
            while written < total {
                let ptr = base.advanced(by: written)
                let rc = Darwin.write(fd, ptr, total - written)
                if rc > 0 {
                    written += rc
                } else if rc < 0 && errno == EINTR {
                    continue
                } else if rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
                    var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
                    _ = Darwin.poll(&pfd, 1, 50)
                    continue
                } else {
                    throw AgentVMError.vsockProtocolViolation(
                        detail: "POSIX vsock write failed on fd \(fd) (errno=\(errno))."
                    )
                }
            }
        }
    }
}

// MARK: - Loopback Session Cross-Wire Bridge & Simulated Guest Peer

private final class LoopbackSessionBridge: @unchecked Sendable {
    private let lock = NSLock()
    private weak var hostSession: VsockMultiplexSession?
    private weak var guestSession: VsockMultiplexSession?
    private var hostToGuestContinuation: AsyncStream<Data>.Continuation?
    private var guestToHostContinuation: AsyncStream<Data>.Continuation?
    private var pumpTasks: [Task<Void, Never>] = []

    deinit {
        hostToGuestContinuation?.finish()
        guestToHostContinuation?.finish()
        for task in pumpTasks {
            task.cancel()
        }
    }

    func bind(host: VsockMultiplexSession, guest: VsockMultiplexSession) {
        let (h2gStream, h2gCont) = AsyncStream<Data>.makeStream()
        let (g2hStream, g2hCont) = AsyncStream<Data>.makeStream()

        let h2gTask = Task { [weak guest] in
            for await wireBytes in h2gStream {
                guard let guest else { break }
                try? await guest.receiveRawTransportBytes(wireBytes)
            }
        }
        let g2hTask = Task { [weak host] in
            for await wireBytes in g2hStream {
                guard let host else { break }
                try? await host.receiveRawTransportBytes(wireBytes)
            }
        }

        lock.lock()
        self.hostSession = host
        self.guestSession = guest
        self.hostToGuestContinuation = h2gCont
        self.guestToHostContinuation = g2hCont
        self.pumpTasks = [h2gTask, g2hTask]
        lock.unlock()
    }

    func sendFromHostToGuest(_ wireBytes: Data) async throws {
        let cont: AsyncStream<Data>.Continuation? = {
            lock.lock()
            defer { lock.unlock() }
            return guestSession != nil ? hostToGuestContinuation : nil
        }()
        guard let cont else {
            throw AgentVMError.vsockProtocolViolation(detail: "Loopback guest session deallocated.")
        }
        cont.yield(wireBytes)
    }

    func sendFromGuestToHost(_ wireBytes: Data) async throws {
        let cont: AsyncStream<Data>.Continuation? = {
            lock.lock()
            defer { lock.unlock() }
            return hostSession != nil ? guestToHostContinuation : nil
        }()
        guard let cont else {
            throw AgentVMError.vsockProtocolViolation(detail: "Loopback host session deallocated.")
        }
        cont.yield(wireBytes)
    }
}

private struct VirtualGuestFile: Sendable {
    var data: Data
    var permissions: UInt16
    var modifiedTimestamp: Int64
}

/// Self-contained simulated Linux guest daemon peer attached by `attachSimulatedGuestResponder()`.
/// Decodes every incoming `AVM1` frame via `VsockStreamAccumulator` and emits real `AVM1` response frames.
private actor SimulatedGuestWirePeer {
    private let vmID: VMID
    private let codec = VsockWireCodec()
    private let accumulator = VsockStreamAccumulator()
    private let emitToHost: @Sendable (Data) -> Void

    private var sequenceByStream: [UInt32: UInt32] = [:]
    private var uncreditedByStream: [UInt32: UInt32] = [:]
    private var virtualFiles: [String: VirtualGuestFile]
    private var inboundPushes: [UInt32: (manifest: GuestFileTransferManifest, data: Data)] = [:]

    init(vmID: VMID, emitToHost: @escaping @Sendable (Data) -> Void) {
        self.vmID = vmID
        self.emitToHost = emitToHost
        self.virtualFiles = SimulatedGuestEngine.defaultVirtualFiles(vmID: vmID)
    }

    func makeHeartbeatWireFrame() throws -> Data {
        let hb = SimulatedGuestEngine.makeHeartbeat(vmID: vmID)
        let encoded = try VsockWireJSON.encode(hb)
        return try nextFrame(
            channel: .telemetryHeartbeat,
            flags: [.ack, .endOfMessage],
            streamID: 0,
            payload: encoded,
            compress: true
        )
    }

    func receiveHostWireBytes(_ data: Data) throws {
        let frames = try accumulator.ingest(data)
        for (header, payload) in frames {
            try processFrame(header: header, payload: payload)
        }
    }

    private func nextFrame(
        channel: VsockChannelKind,
        flags: VsockFrameFlags,
        streamID: UInt32,
        windowCredit: UInt32 = VsockWireConstants.defaultWindowCredit,
        payload: Data,
        compress: Bool
    ) throws -> Data {
        let seq = (sequenceByStream[streamID] ?? 0) &+ 1
        sequenceByStream[streamID] = seq
        return try codec.encodeFrame(
            channel: channel,
            flags: flags,
            streamID: streamID,
            sequence: seq,
            windowCredit: windowCredit,
            payload: payload,
            compressIfBeneficial: compress
        )
    }

    private func maybeEmitWindowUpdate(streamID: UInt32, channel: VsockChannelKind, receivedBytes: Int) throws {
        guard streamID != 0, receivedBytes > 0 else { return }
        let updated = (uncreditedByStream[streamID] ?? 0) &+ UInt32(clamping: receivedBytes)
        if updated >= 65_536 {
            uncreditedByStream[streamID] = 0
            let winFrame = try nextFrame(
                channel: channel,
                flags: [.windowUpdate, .ack],
                streamID: streamID,
                windowCredit: updated,
                payload: Data(),
                compress: false
            )
            emitToHost(winFrame)
        } else {
            uncreditedByStream[streamID] = updated
        }
    }

    private func processFrame(header: VsockFrameHeader, payload: Data) throws {
        let streamID = header.streamID
        if header.flags.contains(.windowUpdate) && payload.isEmpty && !header.flags.contains(.fin) {
            return
        }
        try maybeEmitWindowUpdate(streamID: streamID, channel: header.channel, receivedBytes: payload.count)

        switch header.channel {
        case .control:
            let pong = VsockControlEnvelope(kind: .pong)
            emitToHost(
                try nextFrame(
                    channel: .control,
                    flags: [.ack, .endOfMessage],
                    streamID: 0,
                    payload: try VsockWireJSON.encode(pong),
                    compress: false
                )
            )

        case .telemetryHeartbeat:
            emitToHost(try makeHeartbeatWireFrame())

        case .execProcess:
            if header.flags.contains(.rst) { return }
            guard !payload.isEmpty else { return }
            let request = try VsockWireJSON.decode(GuestExecRequest.self, from: payload)
            let outcome = SimulatedGuestEngine.execute(request: request, virtualFiles: &virtualFiles)
            if outcome.simulatedDelayMs > 0 {
                // Honour sleep requests asynchronously so host timeout watchdogs can trigger when exceeded.
                let delayMs = outcome.simulatedDelayMs
                Task {
                    try? await Task.sleep(nanoseconds: UInt64(delayMs) * 1_000_000)
                    self.emitExecOutcome(streamID: streamID, request: request, outcome: outcome)
                }
            } else {
                emitExecOutcome(streamID: streamID, request: request, outcome: outcome)
            }

        case .fileTransfer:
            try processFileTransfer(header: header, payload: payload)

        case .tcpPortForward:
            try processPortForward(header: header, payload: payload)

        case .interactivePTY:
            try processPTY(header: header, payload: payload)
        }
    }

    private func emitExecOutcome(
        streamID: UInt32,
        request: GuestExecRequest,
        outcome: SimulatedGuestEngine.ExecOutcome
    ) {
        do {
            var seq: UInt32 = 0
            if !outcome.stdout.isEmpty {
                seq &+= 1
                let chunk = GuestExecOutputChunk(
                    requestID: request.id,
                    stream: .stdout,
                    sequence: seq,
                    data: outcome.stdout
                )
                emitToHost(
                    try nextFrame(
                        channel: .execProcess,
                        flags: [.ack],
                        streamID: streamID,
                        payload: try VsockWireJSON.encode(chunk),
                        compress: true
                    )
                )
            }
            if !outcome.stderr.isEmpty {
                seq &+= 1
                let chunk = GuestExecOutputChunk(
                    requestID: request.id,
                    stream: .stderr,
                    sequence: seq,
                    data: outcome.stderr
                )
                emitToHost(
                    try nextFrame(
                        channel: .execProcess,
                        flags: [.ack],
                        streamID: streamID,
                        payload: try VsockWireJSON.encode(chunk),
                        compress: true
                    )
                )
            }
            let completion = VsockExecCompletionEnvelope(
                requestID: request.id,
                exitCode: outcome.exitCode,
                durationMilliseconds: max(1, outcome.durationMs),
                timedOut: false
            )
            emitToHost(
                try nextFrame(
                    channel: .execProcess,
                    flags: [.fin, .endOfMessage],
                    streamID: streamID,
                    payload: try VsockWireJSON.encode(completion),
                    compress: false
                )
            )
        } catch {
            // Ignore encoding failures on torn-down stream.
        }
    }

    private func processFileTransfer(header: VsockFrameHeader, payload: Data) throws {
        let streamID = header.streamID
        if header.flags.contains(.syn) {
            let ctrl = try VsockWireJSON.decode(VsockFileTransferControlEnvelope.self, from: payload)
            switch ctrl.phase {
            case .pushBegin:
                if let manifest = ctrl.manifest {
                    var buf = Data()
                    buf.reserveCapacity(Int(min(manifest.totalBytes, 16_777_216)))
                    inboundPushes[streamID] = (manifest: manifest, data: buf)
                }
                return

            case .pullRequest:
                let reqPath = ctrl.requestedPath ?? ""
                guard let stored = virtualFiles[reqPath] else {
                    let errEnv = VsockFileTransferControlEnvelope(
                        phase: .transferError,
                        requestedPath: reqPath,
                        errorMessage: "ENOENT: '\(reqPath)' does not exist in simulated guest."
                    )
                    emitToHost(
                        try nextFrame(
                            channel: .fileTransfer,
                            flags: [.errorFrame, .fin, .endOfMessage],
                            streamID: streamID,
                            payload: try VsockWireJSON.encode(errEnv),
                            compress: false
                        )
                    )
                    return
                }
                let sha = BinaryChecksums.sha256Hex(stored.data)
                let manifest = GuestFileTransferManifest(
                    direction: .guestToHost,
                    sourcePath: reqPath,
                    destinationPath: reqPath,
                    totalBytes: UInt64(stored.data.count),
                    sha256Hex: sha,
                    posixPermissions: stored.permissions,
                    modifiedTimestamp: stored.modifiedTimestamp
                )
                let manifestEnv = VsockFileTransferControlEnvelope(phase: .pullManifest, manifest: manifest)
                emitToHost(
                    try nextFrame(
                        channel: .fileTransfer,
                        flags: [.syn, .ack],
                        streamID: streamID,
                        payload: try VsockWireJSON.encode(manifestEnv),
                        compress: true
                    )
                )

                if stored.data.isEmpty {
                    emitToHost(
                        try nextFrame(
                            channel: .fileTransfer,
                            flags: [.fin, .endOfMessage],
                            streamID: streamID,
                            payload: Data(),
                            compress: false
                        )
                    )
                } else {
                    var offset = 0
                    while offset < stored.data.count {
                        let chunkLen = min(VsockWireConstants.defaultMaxChunkBytes, stored.data.count - offset)
                        let isLast = (offset + chunkLen >= stored.data.count)
                        let slice = Data(stored.data[(stored.data.startIndex + offset)..<(stored.data.startIndex + offset + chunkLen)])
                        let flags: VsockFrameFlags = isLast ? [.ack, .fin, .endOfMessage] : [.ack]
                        emitToHost(
                            try nextFrame(
                                channel: .fileTransfer,
                                flags: flags,
                                streamID: streamID,
                                payload: slice,
                                compress: true
                            )
                        )
                        offset += chunkLen
                    }
                }
                return

            default:
                return
            }
        }

        guard var active = inboundPushes[streamID] else { return }
        if !payload.isEmpty {
            active.data.append(payload)
            inboundPushes[streamID] = active
        }
        if header.flags.contains(.endOfMessage) || header.flags.contains(.fin) {
            inboundPushes.removeValue(forKey: streamID)
            let actualSHA = BinaryChecksums.sha256Hex(active.data)
            guard actualSHA.lowercased() == active.manifest.sha256Hex.lowercased() else {
                let errEnv = VsockFileTransferControlEnvelope(
                    phase: .transferError,
                    manifest: active.manifest,
                    errorMessage: "Guest SHA-256 verification failed (\(actualSHA) != \(active.manifest.sha256Hex))."
                )
                emitToHost(
                    try nextFrame(
                        channel: .fileTransfer,
                        flags: [.errorFrame, .fin, .endOfMessage],
                        streamID: streamID,
                        payload: try VsockWireJSON.encode(errEnv),
                        compress: false
                    )
                )
                return
            }
            virtualFiles[active.manifest.destinationPath] = VirtualGuestFile(
                data: active.data,
                permissions: active.manifest.posixPermissions,
                modifiedTimestamp: active.manifest.modifiedTimestamp
            )
            let verifiedEnv = VsockFileTransferControlEnvelope(
                phase: .transferVerified,
                manifest: active.manifest
            )
            emitToHost(
                try nextFrame(
                    channel: .fileTransfer,
                    flags: [.fin, .endOfMessage],
                    streamID: streamID,
                    payload: try VsockWireJSON.encode(verifiedEnv),
                    compress: false
                )
            )
        }
    }

    private func processPortForward(header: VsockFrameHeader, payload: Data) throws {
        let streamID = header.streamID
        if header.flags.contains(.syn) {
            let req = try VsockWireJSON.decode(VsockPortForwardEnvelope.self, from: payload)
            let ack = VsockPortForwardEnvelope(action: .connectAck, guestPort: req.guestPort)
            emitToHost(
                try nextFrame(
                    channel: .tcpPortForward,
                    flags: [.syn, .ack],
                    streamID: streamID,
                    payload: try VsockWireJSON.encode(ack),
                    compress: false
                )
            )
            return
        }
        if header.flags.contains(.fin) || header.flags.contains(.rst) {
            emitToHost(
                try nextFrame(
                    channel: .tcpPortForward,
                    flags: [.fin, .endOfMessage],
                    streamID: streamID,
                    payload: Data(),
                    compress: false
                )
            )
            return
        }
        if !payload.isEmpty {
            let reply = SimulatedGuestEngine.respondToPortForwardBytes(payload)
            emitToHost(
                try nextFrame(
                    channel: .tcpPortForward,
                    flags: [.ack],
                    streamID: streamID,
                    payload: reply,
                    compress: false
                )
            )
        }
    }

    private func processPTY(header: VsockFrameHeader, payload: Data) throws {
        let streamID = header.streamID
        guard let first = payload.first,
              let op = VsockPTYSubframeOpcode(rawValue: first) else {
            return
        }
        let body = Data(payload.dropFirst())
        switch op {
        case .openSession:
            let banner = "\u{1B}[1;32magent@\(vmID.rawValue)\u{1B}[0m:\u{1B}[1;34m/workspace\u{1B}[0m$ "
            var writer = BinaryBufferWriter(capacity: 1 + banner.utf8.count)
            writer.appendUInt8(VsockPTYSubframeOpcode.stdoutBytes.rawValue)
            writer.appendData(Data(banner.utf8))
            emitToHost(
                try nextFrame(
                    channel: .interactivePTY,
                    flags: [.syn, .ack],
                    streamID: streamID,
                    payload: writer.data,
                    compress: false
                )
            )
        case .windowResize:
            break
        case .stdinBytes:
            let reply = SimulatedGuestEngine.renderPTYResponse(forStdin: body, vmID: vmID)
            var writer = BinaryBufferWriter(capacity: 1 + reply.count)
            writer.appendUInt8(VsockPTYSubframeOpcode.stdoutBytes.rawValue)
            writer.appendData(reply)
            emitToHost(
                try nextFrame(
                    channel: .interactivePTY,
                    flags: [.ack],
                    streamID: streamID,
                    payload: writer.data,
                    compress: false
                )
            )
        case .stdoutBytes:
            break
        }
    }
}

// MARK: - Deterministic Simulated Guest Command & Telemetry Engine

private enum SimulatedGuestEngine {
    struct ExecOutcome: Sendable {
        var exitCode: Int32
        var stdout: Data
        var stderr: Data
        var durationMs: Int
        var simulatedDelayMs: Int = 0
    }

    static func defaultVirtualFiles(vmID: VMID) -> [String: VirtualGuestFile] {
        let now = Int64(Date().timeIntervalSince1970)
        let osRelease = """
        PRETTY_NAME="Ubuntu 24.04.1 LTS (AgentVM Sandbox)"
        NAME="Ubuntu"
        VERSION_ID="24.04"
        ID=ubuntu
        HOME_URL="https://www.ubuntu.com/"
        """
        return [
            "/etc/hostname": VirtualGuestFile(
                data: Data("\(vmID.rawValue)\n".utf8),
                permissions: 0o644,
                modifiedTimestamp: now
            ),
            "/etc/os-release": VirtualGuestFile(
                data: Data((osRelease + "\n").utf8),
                permissions: 0o644,
                modifiedTimestamp: now
            ),
            "/workspace/.agentvm-ready": VirtualGuestFile(
                data: Data("ready\n".utf8),
                permissions: 0o644,
                modifiedTimestamp: now
            )
        ]
    }

    static func makeHeartbeat(vmID: VMID) -> GuestHeartbeatPayload {
        GuestHeartbeatPayload(
            hostname: vmID.rawValue,
            kernelRelease: "6.8.0-agentvm-arm64",
            uptimeSeconds: 184.6,
            loadAvg1: 0.18,
            loadAvg5: 0.12,
            loadAvg15: 0.08,
            memTotalBytes: 2 * 1024 * 1024 * 1024,
            memAvailableBytes: 1_536 * 1024 * 1024,
            rootFilesystemUsedBytes: 2_415_919_104,
            rootFilesystemTotalBytes: 21_474_836_480,
            topProcesses: [
                GuestProcessSample(
                    pid: 1,
                    ppid: 0,
                    user: "root",
                    cpuPercent: 0.2,
                    rssBytes: 13_107_200,
                    command: "/sbin/init"
                ),
                GuestProcessSample(
                    pid: 142,
                    ppid: 1,
                    user: "root",
                    cpuPercent: 0.5,
                    rssBytes: 19_660_800,
                    command: "/usr/bin/python3 /usr/local/sbin/agentvm-guestd.py --port 1025"
                ),
                GuestProcessSample(
                    pid: 418,
                    ppid: 142,
                    user: "agent",
                    cpuPercent: 1.4,
                    rssBytes: 42_991_616,
                    command: "/bin/bash --login"
                )
            ],
            reportedAt: Date()
        )
    }

    static func execute(
        request: GuestExecRequest,
        virtualFiles: inout [String: VirtualGuestFile]
    ) -> ExecOutcome {
        let baseExec = URL(fileURLWithPath: request.executable).lastPathComponent
        let args = request.arguments

        switch baseExec {
        case "true":
            return ExecOutcome(exitCode: 0, stdout: Data(), stderr: Data(), durationMs: 2)

        case "false":
            return ExecOutcome(exitCode: 1, stdout: Data(), stderr: Data(), durationMs: 2)

        case "echo":
            var suppressNewline = false
            var words = args
            if words.first == "-n" {
                suppressNewline = true
                words.removeFirst()
            }
            let text = words.joined(separator: " ") + (suppressNewline ? "" : "\n")
            return ExecOutcome(exitCode: 0, stdout: Data(text.utf8), stderr: Data(), durationMs: 3)

        case "pwd":
            return ExecOutcome(
                exitCode: 0,
                stdout: Data("\(request.workingDirectory)\n".utf8),
                stderr: Data(),
                durationMs: 2
            )

        case "whoami":
            return ExecOutcome(
                exitCode: 0,
                stdout: Data("\(request.runAsUser)\n".utf8),
                stderr: Data(),
                durationMs: 2
            )

        case "id":
            let uid = request.runAsUser == "root" ? 0 : 1000
            let out = "uid=\(uid)(\(request.runAsUser)) gid=\(uid)(\(request.runAsUser)) groups=\(uid)(\(request.runAsUser))\n"
            return ExecOutcome(exitCode: 0, stdout: Data(out.utf8), stderr: Data(), durationMs: 3)

        case "uname":
            let out: String
            if args.contains("-a") {
                out = "Linux agent-sandbox 6.8.0-agentvm-arm64 #1 SMP PREEMPT_DYNAMIC aarch64 GNU/Linux\n"
            } else if args.contains("-r") {
                out = "6.8.0-agentvm-arm64\n"
            } else if args.contains("-m") {
                out = "aarch64\n"
            } else {
                out = "Linux\n"
            }
            return ExecOutcome(exitCode: 0, stdout: Data(out.utf8), stderr: Data(), durationMs: 2)

        case "env", "printenv":
            let lines = request.environment.keys.sorted().map { "\($0)=\(request.environment[$0] ?? "")" }
            let out = lines.isEmpty ? "" : (lines.joined(separator: "\n") + "\n")
            return ExecOutcome(exitCode: 0, stdout: Data(out.utf8), stderr: Data(), durationMs: 3)

        case "cat":
            if args.isEmpty {
                return ExecOutcome(
                    exitCode: 0,
                    stdout: request.stdinPayload ?? Data(),
                    stderr: Data(),
                    durationMs: 2
                )
            }
            var combined = Data()
            for pathArg in args {
                let resolved = resolvePath(pathArg, cwd: request.workingDirectory)
                if let file = virtualFiles[resolved] {
                    combined.append(file.data)
                } else {
                    let err = "cat: \(pathArg): No such file or directory\n"
                    return ExecOutcome(exitCode: 1, stdout: combined, stderr: Data(err.utf8), durationMs: 3)
                }
            }
            return ExecOutcome(exitCode: 0, stdout: combined, stderr: Data(), durationMs: 3)

        case "ls":
            let targetDir = args.last(where: { !$0.hasPrefix("-") }) ?? request.workingDirectory
            let prefix = targetDir.hasSuffix("/") ? targetDir : (targetDir + "/")
            let entries = virtualFiles.keys
                .filter { $0.hasPrefix(prefix) }
                .map { String($0.dropFirst(prefix.count)) }
                .sorted()
            let out = entries.isEmpty ? "" : (entries.joined(separator: "\n") + "\n")
            return ExecOutcome(exitCode: 0, stdout: Data(out.utf8), stderr: Data(), durationMs: 4)

        case "sleep":
            let seconds = Double(args.first ?? "0") ?? 0
            let delayMs = max(0, Int(seconds * 1000.0))
            return ExecOutcome(
                exitCode: 0,
                stdout: Data(),
                stderr: Data(),
                durationMs: max(1, delayMs),
                simulatedDelayMs: delayMs
            )

        case "sh", "bash", "zsh":
            if let cIdx = args.firstIndex(of: "-c"), cIdx + 1 < args.count {
                return evaluateSimpleShellScript(
                    script: args[cIdx + 1],
                    request: request,
                    virtualFiles: &virtualFiles
                )
            }
            if let stdin = request.stdinPayload, !stdin.isEmpty {
                return evaluateSimpleShellScript(
                    script: String(decoding: stdin, as: UTF8.self),
                    request: request,
                    virtualFiles: &virtualFiles
                )
            }
            return ExecOutcome(exitCode: 0, stdout: Data(), stderr: Data(), durationMs: 3)

        default:
            if request.executable.contains("nonexistent") || request.executable.contains("not-found") {
                let err = "\(request.executable): command not found\n"
                return ExecOutcome(exitCode: 127, stdout: Data(), stderr: Data(err.utf8), durationMs: 2)
            }
            let summary = "executed: \(request.commandLineSummary)\n"
            return ExecOutcome(exitCode: 0, stdout: Data(summary.utf8), stderr: Data(), durationMs: 4)
        }
    }

    private static func evaluateSimpleShellScript(
        script: String,
        request: GuestExecRequest,
        virtualFiles: inout [String: VirtualGuestFile]
    ) -> ExecOutcome {
        var expanded = script
        for (key, value) in request.environment {
            expanded = expanded.replacingOccurrences(of: "${\(key)}", with: value)
            expanded = expanded.replacingOccurrences(of: "$\(key)", with: value)
        }

        let trimmed = expanded.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("exit ") {
            let codeStr = trimmed.dropFirst(5).trimmingCharacters(in: .whitespaces)
            let code = Int32(codeStr) ?? 0
            return ExecOutcome(exitCode: code, stdout: Data(), stderr: Data(), durationMs: 2)
        }
        if trimmed.hasPrefix("sleep ") {
            let secStr = trimmed.dropFirst(6).trimmingCharacters(in: .whitespaces)
            let secs = Double(secStr) ?? 0
            let ms = max(0, Int(secs * 1000.0))
            return ExecOutcome(exitCode: 0, stdout: Data(), stderr: Data(), durationMs: max(1, ms), simulatedDelayMs: ms)
        }
        if trimmed.hasPrefix("cat ") {
            let path = String(trimmed.dropFirst(4)).trimmingCharacters(in: .whitespacesAndNewlines)
            var sub = request
            sub.executable = "/bin/cat"
            sub.arguments = [path]
            return execute(request: sub, virtualFiles: &virtualFiles)
        }
        if trimmed.hasPrefix("echo ") {
            var rest = String(trimmed.dropFirst(5))
            let toStderr = rest.hasSuffix(">&2") || rest.hasSuffix("1>&2")
            if rest.hasSuffix("1>&2") {
                rest = String(rest.dropLast(4)).trimmingCharacters(in: .whitespaces)
            } else if rest.hasSuffix(">&2") {
                rest = String(rest.dropLast(3)).trimmingCharacters(in: .whitespaces)
            }
            rest = rest.trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            let line = Data((rest + "\n").utf8)
            if toStderr {
                return ExecOutcome(exitCode: 0, stdout: Data(), stderr: line, durationMs: 3)
            }
            return ExecOutcome(exitCode: 0, stdout: line, stderr: Data(), durationMs: 3)
        }

        let out = Data((trimmed + "\n").utf8)
        return ExecOutcome(exitCode: 0, stdout: out, stderr: Data(), durationMs: 4)
    }

    private static func resolvePath(_ raw: String, cwd: String) -> String {
        if raw.hasPrefix("/") { return raw }
        if cwd.hasSuffix("/") { return cwd + raw }
        return cwd + "/" + raw
    }

    static func respondToPortForwardBytes(_ inbound: Data) -> Data {
        let text = String(decoding: inbound, as: UTF8.self)
        if text.hasPrefix("GET ") || text.hasPrefix("HEAD ") || text.hasPrefix("POST ") {
            let body = "{\"status\":\"ok\",\"service\":\"agentvm-guest-vsock\"}\n"
            let http = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
            return Data(http.utf8)
        }
        // Deterministic echo responder for raw TCP loopback verification.
        return inbound
    }

    static func renderPTYResponse(forStdin stdin: Data, vmID: VMID) -> Data {
        let text = String(decoding: stdin, as: UTF8.self)
        if text.contains("\r") || text.contains("\n") {
            let cmd = text.trimmingCharacters(in: .whitespacesAndNewlines)
            var out = text.replacingOccurrences(of: "\r", with: "\r\n")
            if !out.hasSuffix("\n") { out += "\r\n" }
            if !cmd.isEmpty {
                out += "\(cmd): executed\r\n"
            }
            out += "\u{1B}[1;32magent@\(vmID.rawValue)\u{1B}[0m:\u{1B}[1;34m/workspace\u{1B}[0m$ "
            return Data(out.utf8)
        }
        return stdin
    }
}
