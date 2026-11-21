import AgentVMModels
import Darwin
import Dispatch
import Foundation

// MARK: - Active Port-Forward Binding Snapshot

/// Live runtime binding descriptor and byte-counter snapshot for an active localhost port forward.
public struct ActivePortForwardBinding: Codable, Hashable, Sendable, Identifiable {
    public var id: PortForwardID
    public var vmID: VMID
    public var rule: PortForwardRuleSpec
    public var actualBoundPort: UInt16
    public var activeConnections: Int
    public var bytesHostToGuest: UInt64
    public var bytesGuestToHost: UInt64
    public var startedAt: Date

    public init(
        id: PortForwardID,
        vmID: VMID,
        rule: PortForwardRuleSpec,
        actualBoundPort: UInt16,
        activeConnections: Int = 0,
        bytesHostToGuest: UInt64 = 0,
        bytesGuestToHost: UInt64 = 0,
        startedAt: Date = Date()
    ) {
        self.id = id
        self.vmID = vmID
        self.rule = rule
        self.actualBoundPort = actualBoundPort
        self.activeConnections = activeConnections
        self.bytesHostToGuest = bytesHostToGuest
        self.bytesGuestToHost = bytesGuestToHost
        self.startedAt = startedAt
    }

    public var totalTransferredBytes: UInt64 {
        bytesHostToGuest &+ bytesGuestToHost
    }
}

// MARK: - HostPortForwardManager Actor (POSIX Loopback TCP <-> Guest Vsock / TCP Relay)

/// Manages host-side BSD loopback `SOCK_STREAM` listeners (`127.0.0.1:<hostPort>`) and asynchronously relays
/// accepted TCP connections either into a `VsockMultiplexSession` `.tcpPortForward` stream or a target loopback TCP port.
public actor HostPortForwardManager {
    private struct ManagedListenerEntry {
        let id: PortForwardID
        let vmID: VMID
        let rule: PortForwardRuleSpec
        let actualBoundPort: UInt16
        let startedAt: Date
        let listenerSocket: SafePOSIXSocket
        let acceptSource: DispatchSourceRead
        let relayCoordinator: BindingRelayCoordinator

        func snapshot() -> ActivePortForwardBinding {
            let counters = relayCoordinator.snapshotCounters()
            return ActivePortForwardBinding(
                id: id,
                vmID: vmID,
                rule: rule,
                actualBoundPort: actualBoundPort,
                activeConnections: counters.activeConnections,
                bytesHostToGuest: counters.bytesHostToGuest,
                bytesGuestToHost: counters.bytesGuestToHost,
                startedAt: startedAt
            )
        }

        func teardown() {
            relayCoordinator.stopAllConnections()
            acceptSource.cancel()
            listenerSocket.requestClose()
        }
    }

    private var activeListeners: [PortForwardID: ManagedListenerEntry] = [:]
    private let teardownRegistry = ListenerTeardownRegistry()

    public init() {}

    deinit {
        teardownRegistry.teardownAll()
    }

    // MARK: Lifecycle API

    /// Binds a POSIX IPv4 `SOCK_STREAM` listener for `rule` (supporting `hostPort == 0` ephemeral port assignment)
    /// and starts relaying inbound TCP connections to `targetLoopbackPortOverride` or `vsockSession`.
    @discardableResult
    public func startForwardRule(
        _ rule: PortForwardRuleSpec,
        vmID: VMID,
        targetLoopbackPortOverride: UInt16? = nil,
        vsockSession: VsockMultiplexSession? = nil
    ) async throws -> ActivePortForwardBinding {
        if rule.hostPort > 0,
           activeListeners.values.contains(where: { $0.id != rule.id && $0.actualBoundPort == rule.hostPort }) {
            throw AgentVMError.portForwardBindFailed(port: rule.hostPort, errnoCode: EADDRINUSE)
        }

        // Tear down any existing binding sharing the same PortForwardID before re-binding.
        if let existing = activeListeners.removeValue(forKey: rule.id) {
            teardownRegistry.unregister(id: rule.id)
            existing.teardown()
        }

        let rawListenFD = Darwin.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard rawListenFD >= 0 else {
            throw AgentVMError.portForwardBindFailed(port: rule.hostPort, errnoCode: errno)
        }

        let listenSocket = SafePOSIXSocket(fd: rawListenFD)
        Self.configureStandardStreamSocketOptions(fd: rawListenFD)
        Self.setNonBlocking(fd: rawListenFD)

        var bindAddr = sockaddr_in()
        bindAddr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        bindAddr.sin_family = sa_family_t(AF_INET)
        bindAddr.sin_port = rule.hostPort.bigEndian

        let normalizedHost = rule.hostBindAddress.trimmingCharacters(in: .whitespacesAndNewlines)
        let effectiveHost: String
        if normalizedHost.isEmpty || normalizedHost.lowercased() == "localhost" {
            effectiveHost = "127.0.0.1"
        } else if normalizedHost == "*" {
            effectiveHost = "0.0.0.0"
        } else {
            effectiveHost = normalizedHost
        }

        let ptonRC = effectiveHost.withCString { cStr in
            Darwin.inet_pton(AF_INET, cStr, &bindAddr.sin_addr)
        }
        guard ptonRC == 1 else {
            listenSocket.requestClose()
            throw AgentVMError.portForwardBindFailed(port: rule.hostPort, errnoCode: EINVAL)
        }

        if effectiveHost == "127.0.0.1" && rule.hostPort > 0 {
            if let wildcardConflictErrno = Self.probeWildcardListenerConflict(port: rule.hostPort) {
                listenSocket.requestClose()
                throw AgentVMError.portForwardBindFailed(port: rule.hostPort, errnoCode: wildcardConflictErrno)
            }
        }

        let bindRC: Int32 = withUnsafePointer(to: &bindAddr) { addrPtr in
            addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.bind(rawListenFD, saPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if bindRC != 0 {
            let err = errno
            listenSocket.requestClose()
            throw AgentVMError.portForwardBindFailed(port: rule.hostPort, errnoCode: err)
        }

        // Discover OS-assigned port via getsockname (essential when rule.hostPort == 0).
        var queriedAddr = sockaddr_in()
        var queriedLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        let nameRC: Int32 = withUnsafeMutablePointer(to: &queriedAddr) { addrPtr in
            addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.getsockname(rawListenFD, saPtr, &queriedLen)
            }
        }
        if nameRC != 0 {
            let err = errno
            listenSocket.requestClose()
            throw AgentVMError.portForwardBindFailed(port: rule.hostPort, errnoCode: err)
        }
        let actualBoundPort = UInt16(bigEndian: queriedAddr.sin_port)

        if Darwin.listen(rawListenFD, 128) != 0 {
            let err = errno
            listenSocket.requestClose()
            throw AgentVMError.portForwardBindFailed(port: actualBoundPort, errnoCode: err)
        }

        let startedAt = Date()
        let coordinator = BindingRelayCoordinator(
            rule: rule,
            targetLoopbackPortOverride: targetLoopbackPortOverride,
            vsockSession: vsockSession
        )

        let acceptQueue = DispatchQueue(
            label: "com.agentvm.portfwd.accept.\(rule.id.rawValue)",
            qos: .userInitiated
        )
        listenSocket.retainDispatchMonitor()
        let acceptSource = DispatchSource.makeReadSource(fileDescriptor: rawListenFD, queue: acceptQueue)

        acceptSource.setEventHandler {
            while !coordinator.isStopped {
                var peerAddr = sockaddr_in()
                var peerLen = socklen_t(MemoryLayout<sockaddr_in>.size)
                let clientFD: Int32 = withUnsafeMutablePointer(to: &peerAddr) { ptr in
                    ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                        Darwin.accept(rawListenFD, saPtr, &peerLen)
                    }
                }
                if clientFD >= 0 {
                    Self.configureClientStreamSocketOptions(fd: clientFD)
                    Self.setNonBlocking(fd: clientFD)
                    let peerPort = UInt16(bigEndian: peerAddr.sin_port)
                    let peerIP = Self.ipv4String(from: peerAddr.sin_addr)
                    coordinator.spawnConnectionRelay(
                        clientFD: clientFD,
                        peerAddress: peerIP,
                        peerPort: peerPort
                    )
                } else {
                    if errno == EINTR { continue }
                    break
                }
            }
        }

        acceptSource.setCancelHandler {
            listenSocket.releaseDispatchMonitor()
        }

        acceptSource.resume()

        let entry = ManagedListenerEntry(
            id: rule.id,
            vmID: vmID,
            rule: rule,
            actualBoundPort: actualBoundPort,
            startedAt: startedAt,
            listenerSocket: listenSocket,
            acceptSource: acceptSource,
            relayCoordinator: coordinator
        )
        activeListeners[rule.id] = entry
        teardownRegistry.register(id: rule.id) {
            entry.teardown()
        }
        return entry.snapshot()
    }

    /// Stops and unbinds a single port-forward rule, closing its listener and any in-flight TCP relays.
    public func stopForwardRule(_ id: PortForwardID) {
        guard let removed = activeListeners.removeValue(forKey: id) else { return }
        teardownRegistry.unregister(id: id)
        removed.teardown()
    }

    /// Stops and unbinds all active port-forward rules belonging to `vmID`.
    public func stopAllRules(for vmID: VMID) {
        let matchingIDs = activeListeners.values
            .filter { $0.vmID == vmID }
            .map(\.id)
        for id in matchingIDs {
            if let removed = activeListeners.removeValue(forKey: id) {
                teardownRegistry.unregister(id: id)
                removed.teardown()
            }
        }
    }

    /// Stops all active port-forward rules across every VM in the process.
    public func stopAllRules() {
        let allEntries = Array(activeListeners.values)
        activeListeners.removeAll()
        teardownRegistry.clearAll()
        for entry in allEntries {
            entry.teardown()
        }
    }

    /// Lists live binding snapshots (optionally filtered by `vmID`), sorted deterministically by `actualBoundPort`.
    public func listActiveBindings(for vmID: VMID? = nil) -> [ActivePortForwardBinding] {
        activeListeners.values
            .filter { entry in
                guard let vmID else { return true }
                return entry.vmID == vmID
            }
            .map { $0.snapshot() }
            .sorted { lhs, rhs in
                if lhs.actualBoundPort != rhs.actualBoundPort {
                    return lhs.actualBoundPort < rhs.actualBoundPort
                }
                return lhs.id < rhs.id
            }
    }

    /// Looks up a single live binding snapshot by its `PortForwardID`.
    public func binding(for id: PortForwardID) -> ActivePortForwardBinding? {
        activeListeners[id]?.snapshot()
    }

    // MARK: Static Socket Configuration Helpers

    fileprivate static func probeWildcardListenerConflict(port: UInt16) -> Int32? {
        let probeFD = Darwin.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard probeFD >= 0 else { return nil }
        defer { _ = Darwin.close(probeFD) }
        configureStandardStreamSocketOptions(fd: probeFD)
        var anyAddr = sockaddr_in()
        anyAddr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        anyAddr.sin_family = sa_family_t(AF_INET)
        anyAddr.sin_port = port.bigEndian
        anyAddr.sin_addr.s_addr = INADDR_ANY.bigEndian
        let rc = withUnsafePointer(to: &anyAddr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.bind(probeFD, saPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if rc != 0 && Darwin.errno == EADDRINUSE {
            return EADDRINUSE
        }
        return nil
    }

    fileprivate static func configureStandardStreamSocketOptions(fd: Int32) {
        var yes: Int32 = 1
        _ = Darwin.setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        _ = Darwin.setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, socklen_t(MemoryLayout<Int32>.size))
    }

    fileprivate static func configureClientStreamSocketOptions(fd: Int32) {
        var yes: Int32 = 1
        _ = Darwin.setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, socklen_t(MemoryLayout<Int32>.size))
        _ = Darwin.setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, socklen_t(MemoryLayout<Int32>.size))
    }

    fileprivate static func setNonBlocking(fd: Int32) {
        let flags = Darwin.fcntl(fd, F_GETFL, 0)
        if flags >= 0 {
            _ = Darwin.fcntl(fd, F_SETFL, flags | O_NONBLOCK)
        }
    }

    fileprivate static func ipv4String(from addr: in_addr) -> String {
        var copy = addr
        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        let ptr = Darwin.inet_ntop(AF_INET, &copy, &buf, socklen_t(buf.count))
        guard ptr != nil else { return "127.0.0.1" }
        let nulIndex = buf.firstIndex(of: 0) ?? buf.count
        let utf8 = buf.prefix(nulIndex).map { UInt8(bitPattern: $0) }
        return String(decoding: utf8, as: UTF8.self)
    }
}

// MARK: - Reference-Counted kqueue-Safe POSIX Socket Wrapper

/// Coordinates `Darwin.shutdown` and `Darwin.close` with active GCD `DispatchSource` monitors
/// so file descriptors are never closed while still registered in `kqueue` and never double-closed.
private final class SafePOSIXSocket: @unchecked Sendable {
    private let lock = NSLock()
    let fd: Int32
    private var activeMonitors: Int = 0
    private var closeRequested: Bool = false
    private var closedDescriptor: Bool = false

    init(fd: Int32) {
        self.fd = fd
    }

    var isUsable: Bool {
        lock.lock()
        defer { lock.unlock() }
        return !closeRequested && !closedDescriptor && fd >= 0
    }

    func retainDispatchMonitor() {
        lock.lock()
        activeMonitors += 1
        lock.unlock()
    }

    func releaseDispatchMonitor() {
        lock.lock()
        activeMonitors = max(0, activeMonitors - 1)
        let shouldCloseNow = (activeMonitors == 0 && closeRequested && !closedDescriptor)
        if shouldCloseNow {
            closedDescriptor = true
        }
        lock.unlock()

        if shouldCloseNow && fd >= 0 {
            _ = Darwin.close(fd)
        }
    }

    func shutdownWrite() {
        lock.lock()
        let valid = !closedDescriptor && fd >= 0
        lock.unlock()
        if valid {
            _ = Darwin.shutdown(fd, SHUT_WR)
        }
    }

    func requestClose() {
        lock.lock()
        if closedDescriptor {
            lock.unlock()
            return
        }
        let firstCloseRequest = !closeRequested
        closeRequested = true
        let shouldCloseImmediately = (activeMonitors == 0)
        if shouldCloseImmediately {
            closedDescriptor = true
        }
        lock.unlock()

        if firstCloseRequest && fd >= 0 {
            _ = Darwin.shutdown(fd, SHUT_RDWR)
        }
        if shouldCloseImmediately && fd >= 0 {
            _ = Darwin.close(fd)
        }
    }
}

// MARK: - Per-Binding Bidirectional Relay Coordinator

private final class BindingRelayCoordinator: @unchecked Sendable {
    struct Counters: Sendable {
        var activeConnections: Int
        var bytesHostToGuest: UInt64
        var bytesGuestToHost: UInt64
    }

    private let lock = NSLock()
    private let rule: PortForwardRuleSpec
    private let targetLoopbackPortOverride: UInt16?
    private let vsockSession: VsockMultiplexSession?
    private let ioQueue: DispatchQueue

    private var stopped: Bool = false
    private var activeConnectionsCount: Int = 0
    private var hostToGuestBytes: UInt64 = 0
    private var guestToHostBytes: UInt64 = 0
    private var trackedSockets: [UUID: SafePOSIXSocket] = [:]
    private var trackedTasks: [UUID: Task<Void, Never>] = [:]

    init(
        rule: PortForwardRuleSpec,
        targetLoopbackPortOverride: UInt16?,
        vsockSession: VsockMultiplexSession?
    ) {
        self.rule = rule
        self.targetLoopbackPortOverride = targetLoopbackPortOverride
        self.vsockSession = vsockSession
        self.ioQueue = DispatchQueue(
            label: "com.agentvm.portfwd.io.\(rule.id.rawValue)",
            qos: .userInitiated,
            attributes: .concurrent
        )
    }

    var isStopped: Bool {
        lock.lock()
        defer { lock.unlock() }
        return stopped
    }

    func snapshotCounters() -> Counters {
        lock.lock()
        defer { lock.unlock() }
        return Counters(
            activeConnections: activeConnectionsCount,
            bytesHostToGuest: hostToGuestBytes,
            bytesGuestToHost: guestToHostBytes
        )
    }

    func recordHostToGuest(_ byteCount: Int) {
        guard byteCount > 0 else { return }
        lock.lock()
        hostToGuestBytes &+= UInt64(byteCount)
        lock.unlock()
    }

    func recordGuestToHost(_ byteCount: Int) {
        guard byteCount > 0 else { return }
        lock.lock()
        guestToHostBytes &+= UInt64(byteCount)
        lock.unlock()
    }

    func stopAllConnections() {
        lock.lock()
        stopped = true
        let sockets = Array(trackedSockets.values)
        let tasks = Array(trackedTasks.values)
        trackedSockets.removeAll()
        trackedTasks.removeAll()
        lock.unlock()

        for task in tasks {
            task.cancel()
        }
        for sock in sockets {
            sock.requestClose()
        }
    }

    func spawnConnectionRelay(clientFD: Int32, peerAddress: String, peerPort: UInt16) {
        let clientSocket = SafePOSIXSocket(fd: clientFD)
        let connID = UUID()

        lock.lock()
        if stopped {
            lock.unlock()
            clientSocket.requestClose()
            return
        }
        activeConnectionsCount += 1
        trackedSockets[connID] = clientSocket
        lock.unlock()

        let task = Task { [weak self] in
            guard let self else {
                clientSocket.requestClose()
                return
            }
            defer {
                clientSocket.requestClose()
                self.finishConnection(connID: connID)
            }

            if let overridePort = self.targetLoopbackPortOverride {
                await self.relayViaTargetLoopbackTCP(
                    connID: connID,
                    clientSocket: clientSocket,
                    targetPort: overridePort
                )
            } else if let vsock = self.vsockSession {
                await self.relayViaVsockSession(
                    clientSocket: clientSocket,
                    vsockSession: vsock,
                    guestPort: self.rule.guestPort,
                    peerAddress: peerAddress,
                    peerPort: peerPort
                )
            } else {
                await self.relayViaTargetLoopbackTCP(
                    connID: connID,
                    clientSocket: clientSocket,
                    targetPort: self.rule.guestPort
                )
            }
        }

        lock.lock()
        if stopped {
            lock.unlock()
            task.cancel()
        } else {
            trackedTasks[connID] = task
            lock.unlock()
        }
    }

    private func finishConnection(connID: UUID) {
        lock.lock()
        activeConnectionsCount = max(0, activeConnectionsCount - 1)
        trackedSockets.removeValue(forKey: connID)
        trackedTasks.removeValue(forKey: connID)
        lock.unlock()
    }

    private func registerAuxiliarySocket(_ socket: SafePOSIXSocket) -> UUID {
        let auxID = UUID()
        lock.lock()
        if stopped {
            lock.unlock()
            socket.requestClose()
            return auxID
        }
        trackedSockets[auxID] = socket
        lock.unlock()
        return auxID
    }

    private func unregisterAuxiliarySocket(_ auxID: UUID) {
        lock.lock()
        trackedSockets.removeValue(forKey: auxID)
        lock.unlock()
    }

    // MARK: Relay Mode 1 - Loopback TCP Upstream Endpoint (127.0.0.1:<targetPort>)

    private func relayViaTargetLoopbackTCP(
        connID: UUID,
        clientSocket: SafePOSIXSocket,
        targetPort: UInt16
    ) async {
        guard let upstreamSocket = await connectLoopbackUpstream(port: targetPort) else {
            return
        }
        let auxID = registerAuxiliarySocket(upstreamSocket)
        defer {
            upstreamSocket.requestClose()
            unregisterAuxiliarySocket(auxID)
        }

        await withTaskGroup(of: Void.self) { group in
            // Host Client -> Target Guest/Loopback Socket
            group.addTask {
                let inbound = Self.makeAsyncReadStream(socket: clientSocket, queue: self.ioQueue)
                for await chunk in inbound {
                    if Task.isCancelled { break }
                    guard Self.writeAll(socket: upstreamSocket, data: chunk) else { break }
                    self.recordHostToGuest(chunk.count)
                }
                upstreamSocket.shutdownWrite()
            }

            // Target Guest/Loopback Socket -> Host Client
            group.addTask {
                let inbound = Self.makeAsyncReadStream(socket: upstreamSocket, queue: self.ioQueue)
                for await chunk in inbound {
                    if Task.isCancelled { break }
                    guard Self.writeAll(socket: clientSocket, data: chunk) else { break }
                    self.recordGuestToHost(chunk.count)
                }
                clientSocket.shutdownWrite()
            }

            await group.waitForAll()
        }
    }

    private func connectLoopbackUpstream(port: UInt16) async -> SafePOSIXSocket? {
        guard port > 0 else { return nil }
        let fd = Darwin.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else { return nil }

        HostPortForwardManager.configureClientStreamSocketOptions(fd: fd)
        HostPortForwardManager.setNonBlocking(fd: fd)
        let upstream = SafePOSIXSocket(fd: fd)

        var targetAddr = sockaddr_in()
        targetAddr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        targetAddr.sin_family = sa_family_t(AF_INET)
        targetAddr.sin_port = port.bigEndian
        _ = "127.0.0.1".withCString { Darwin.inet_pton(AF_INET, $0, &targetAddr.sin_addr) }

        let rc: Int32 = withUnsafePointer(to: &targetAddr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.connect(fd, saPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        if rc == 0 {
            return upstream
        }
        guard errno == EINPROGRESS else {
            upstream.requestClose()
            return nil
        }

        // Wait non-blockingly via DispatchSourceWrite for connect completion.
        let connected: Bool = await withCheckedContinuation { continuation in
            let stateBox = ConnectOnceBox()
            upstream.retainDispatchMonitor()
            let writeSource = DispatchSource.makeWriteSource(fileDescriptor: fd, queue: ioQueue)

            writeSource.setEventHandler {
                var soError: Int32 = 0
                var len = socklen_t(MemoryLayout<Int32>.size)
                let optRC = Darwin.getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &len)
                let ok = (optRC == 0 && soError == 0)
                if stateBox.tryResolve() {
                    writeSource.cancel()
                    continuation.resume(returning: ok)
                }
            }

            writeSource.setCancelHandler {
                upstream.releaseDispatchMonitor()
                if stateBox.tryResolve() {
                    continuation.resume(returning: false)
                }
            }

            writeSource.resume()

            ioQueue.asyncAfter(deadline: .now() + .seconds(5)) {
                if stateBox.tryResolve() {
                    writeSource.cancel()
                    continuation.resume(returning: false)
                }
            }
        }

        if !connected {
            upstream.requestClose()
            return nil
        }
        return upstream
    }

    // MARK: Relay Mode 2 - Multiplexed Vsock .tcpPortForward Stream

    private func relayViaVsockSession(
        clientSocket: SafePOSIXSocket,
        vsockSession: VsockMultiplexSession,
        guestPort: UInt16,
        peerAddress: String,
        peerPort: UInt16
    ) async {
        guard let opened = try? await vsockSession.openPortForwardStream(
            guestPort: guestPort,
            sourceAddress: peerAddress,
            sourcePort: peerPort
        ) else {
            return
        }

        let streamID = opened.streamID
        let inboundFromGuest = opened.inboundData

        await withTaskGroup(of: Void.self) { group in
            // Host TCP Client -> Vsock Stream
            group.addTask {
                let outcomeBox = SocketReadOutcomeBox()
                let hostReads = Self.makeAsyncReadStream(
                    socket: clientSocket,
                    queue: self.ioQueue,
                    outcomeBox: outcomeBox
                )
                var sendFailed = false
                for await chunk in hostReads {
                    if Task.isCancelled {
                        sendFailed = true
                        break
                    }
                    do {
                        try await vsockSession.sendPortForwardData(streamID: streamID, payload: chunk)
                        self.recordHostToGuest(chunk.count)
                    } catch {
                        sendFailed = true
                        break
                    }
                }
                if sendFailed || Task.isCancelled || outcomeBox.readErrorOccurred {
                    clientSocket.requestClose()
                    try? await vsockSession.closePortForwardStream(streamID: streamID)
                } else if outcomeBox.didSeeCleanEOF {
                    try? await vsockSession.halfClosePortForwardWrite(streamID: streamID)
                }
            }

            // Vsock Stream -> Host TCP Client
            group.addTask {
                var writeFailed = false
                for await chunk in inboundFromGuest {
                    if Task.isCancelled {
                        writeFailed = true
                        break
                    }
                    guard Self.writeAll(socket: clientSocket, data: chunk) else {
                        writeFailed = true
                        break
                    }
                    self.recordGuestToHost(chunk.count)
                }
                if writeFailed || Task.isCancelled {
                    clientSocket.requestClose()
                    try? await vsockSession.closePortForwardStream(streamID: streamID)
                } else {
                    clientSocket.shutdownWrite()
                }
            }

            await group.waitForAll()
        }

        try? await vsockSession.closePortForwardStream(streamID: streamID)
    }

    // MARK: Non-Blocking GCD Socket Read / Write Primitives

    private static func makeAsyncReadStream(
        socket: SafePOSIXSocket,
        queue: DispatchQueue,
        outcomeBox: SocketReadOutcomeBox? = nil
    ) -> AsyncStream<Data> {
        AsyncStream { continuation in
            guard socket.isUsable else {
                continuation.finish()
                return
            }

            socket.retainDispatchMonitor()
            let readSource = DispatchSource.makeReadSource(fileDescriptor: socket.fd, queue: queue)

            readSource.setEventHandler {
                var buffer = [UInt8](repeating: 0, count: 32_768)
                while socket.isUsable {
                    let n = Darwin.read(socket.fd, &buffer, buffer.count)
                    if n > 0 {
                        continuation.yield(Data(buffer.prefix(n)))
                    } else if n == 0 {
                        outcomeBox?.recordCleanEOF()
                        continuation.finish()
                        readSource.cancel()
                        break
                    } else {
                        if errno == EINTR { continue }
                        if errno == EAGAIN || errno == EWOULDBLOCK { break }
                        outcomeBox?.recordReadError(errno)
                        continuation.finish()
                        readSource.cancel()
                        break
                    }
                }
            }

            readSource.setCancelHandler {
                socket.releaseDispatchMonitor()
                continuation.finish()
            }

            continuation.onTermination = { _ in
                readSource.cancel()
            }

            readSource.resume()
        }
    }

    private static func writeAll(socket: SafePOSIXSocket, data: Data) -> Bool {
        guard !data.isEmpty else { return true }
        return data.withUnsafeBytes { rawBuf in
            guard let base = rawBuf.baseAddress else { return true }
            var offset = 0
            let total = rawBuf.count
            while offset < total && socket.isUsable {
                let n = Darwin.write(socket.fd, base.advanced(by: offset), total - offset)
                if n > 0 {
                    offset += n
                } else if n < 0 && errno == EINTR {
                    continue
                } else if n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
                    var pfd = pollfd(fd: socket.fd, events: Int16(POLLOUT), revents: 0)
                    let prc = Darwin.poll(&pfd, 1, 100)
                    if prc < 0 && errno != EINTR {
                        return false
                    }
                } else {
                    return false
                }
            }
            return offset == total
        }
    }
}

private final class ListenerTeardownRegistry: @unchecked Sendable {
    private let lock = NSLock()
    private var handlers: [PortForwardID: () -> Void] = [:]

    func register(id: PortForwardID, handler: @escaping () -> Void) {
        lock.lock()
        handlers[id] = handler
        lock.unlock()
    }

    func unregister(id: PortForwardID) {
        lock.lock()
        handlers.removeValue(forKey: id)
        lock.unlock()
    }

    func clearAll() {
        lock.lock()
        handlers.removeAll()
        lock.unlock()
    }

    func teardownAll() {
        lock.lock()
        let copy = Array(handlers.values)
        handlers.removeAll()
        lock.unlock()
        for fn in copy {
            fn()
        }
    }
}

private final class SocketReadOutcomeBox: @unchecked Sendable {
    private let lock = NSLock()
    private var sawEOF = false
    private var recordedErrno: Int32?

    var didSeeCleanEOF: Bool {
        lock.lock()
        defer { lock.unlock() }
        return sawEOF
    }

    var readErrorOccurred: Bool {
        lock.lock()
        defer { lock.unlock() }
        return recordedErrno != nil
    }

    func recordCleanEOF() {
        lock.lock()
        sawEOF = true
        lock.unlock()
    }

    func recordReadError(_ code: Int32) {
        lock.lock()
        recordedErrno = code
        lock.unlock()
    }
}

private final class ConnectOnceBox: @unchecked Sendable {
    private let lock = NSLock()
    private var resolved = false

    func tryResolve() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if resolved { return false }
        resolved = true
        return true
    }
}
