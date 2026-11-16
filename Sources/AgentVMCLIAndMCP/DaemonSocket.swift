import AgentVMModels
import Darwin
import Foundation

// MARK: - Workspace Daemon Paths, Unix Socket Address Rules & Bounds Guards (M2 Stage 1)

public struct DaemonWorkspacePaths: Hashable, Sendable {
    public let workspaceURL: URL
    public let runDirectoryURL: URL
    public let lockFileURL: URL
    public let directSocketFileURL: URL
    public let logsDirectoryURL: URL
    public let daemonLogFileURL: URL

    public init(workspaceURL: URL) {
        let stdWorkspace = workspaceURL.standardizedFileURL
        let stdRun = stdWorkspace.appendingPathComponent("run", isDirectory: true).standardizedFileURL
        let stdLogs = stdWorkspace.appendingPathComponent("logs", isDirectory: true).standardizedFileURL
        self.workspaceURL = stdWorkspace
        self.runDirectoryURL = stdRun
        self.lockFileURL = stdRun.appendingPathComponent("daemon.lock", isDirectory: false).standardizedFileURL
        self.directSocketFileURL = stdRun.appendingPathComponent("daemon.sock", isDirectory: false).standardizedFileURL
        self.logsDirectoryURL = stdLogs
        self.daemonLogFileURL = stdLogs.appendingPathComponent("daemon.log", isDirectory: false).standardizedFileURL
    }

    public var directSocketPath: String {
        directSocketFileURL.path
    }

    public var directSocketPathUTF8ByteCount: Int {
        directSocketPath.utf8.count
    }
}

public enum DaemonSocketError: Error, LocalizedError, Hashable, Sendable {
    case emptySocketPath
    case interiorNullByte(path: String)
    case socketPathTooLong(path: String, utf8ByteCount: Int, maxBytes: Int)
    case darwinTempDirectoryUnavailable(errnoCode: Int32)
    case symlinkTargetMismatch(symlinkPath: String, expectedTarget: String, actualTarget: String)
    case unauthorizedPeerUID(expected: uid_t, actual: uid_t)
    case syscallFailed(operation: String, path: String, errnoCode: Int32, detail: String)

    public var errorCode: String {
        "ERR_DAEMON_IPC"
    }

    public var errorDescription: String? {
        localizedMessage(in: .en)
    }

    public func localizedMessage(in language: AppLanguage) -> String {
        let isZh = (language == .zhHans)
        switch self {
        case .emptySocketPath:
            return isZh
                ? "守护进程 Unix 套接字路径为空。"
                : "Daemon Unix socket path must not be empty."
        case let .interiorNullByte(path):
            return isZh
                ? "守护进程套接字路径包含非法空字节：「\(path)」。"
                : "Daemon Unix socket path contains an interior NUL byte: '\(path)'."
        case let .socketPathTooLong(path, utf8ByteCount, maxBytes):
            return isZh
                ? "守护进程 Unix 套接字路径过长（\(utf8ByteCount) UTF-8 字节，上限 \(maxBytes) 字节）：「\(path)」。"
                : "Daemon Unix socket path exceeds sockaddr_un limit (\(utf8ByteCount) UTF-8 bytes, max \(maxBytes)): '\(path)'."
        case let .darwinTempDirectoryUnavailable(errnoCode):
            return isZh
                ? "无法获取系统用户临时目录 _CS_DARWIN_USER_TEMP_DIR（errno=\(errnoCode)）。"
                : "Unable to query _CS_DARWIN_USER_TEMP_DIR via confstr (errno=\(errnoCode))."
        case let .symlinkTargetMismatch(symlinkPath, expectedTarget, actualTarget):
            return isZh
                ? "临时目录中的守护进程符号链接「\(symlinkPath)」已存在但指向「\(actualTarget)」（期望指向「\(expectedTarget)」），已拒绝覆盖。"
                : "Daemon socket symlink '\(symlinkPath)' already exists and points to '\(actualTarget)' instead of '\(expectedTarget)'; refusing to overwrite."
        case let .unauthorizedPeerUID(expected, actual):
            return isZh
                ? "拒绝来自其他用户的守护进程套接字连接（期望 uid=\(expected)，实际 uid=\(actual)）。"
                : "Rejected daemon socket peer with mismatched UID (expected uid=\(expected), got uid=\(actual))."
        case let .syscallFailed(operation, path, errnoCode, detail):
            return isZh
                ? "守护进程套接字操作 \(operation) 失败「\(path)」（errno=\(errnoCode)）：\(detail)"
                : "Daemon socket \(operation) failed on '\(path)' (errno=\(errnoCode)): \(detail)"
        }
    }

    public func asAgentVMError(socketPath: String, language: AppLanguage = .en) -> AgentVMError {
        .ipcDaemonUnavailable(socketPath: socketPath, detail: localizedMessage(in: language))
    }
}

// MARK: - Bounds-Checked `sockaddr_un` Builder (Fixes A43)

public enum DaemonUnixSocketAddress {
    /// Darwin `sockaddr_un.sun_path` is 104 bytes including the trailing NUL terminator, leaving 103 UTF-8 path bytes.
    public static let maxPathUTF8Bytes: Int = {
        let sample = sockaddr_un()
        return MemoryLayout.size(ofValue: sample.sun_path) - 1
    }()

    /// Validates UTF-8 length and NUL safety BEFORE touching `sockaddr_un.sun_path` (A43).
    public static func makeSockAddrUn(socketPath: String) throws -> sockaddr_un {
        let utf8Bytes = Array(socketPath.utf8)
        guard !utf8Bytes.isEmpty else {
            throw DaemonSocketError.emptySocketPath
        }
        guard !utf8Bytes.contains(0) else {
            throw DaemonSocketError.interiorNullByte(path: socketPath)
        }
        guard utf8Bytes.count <= maxPathUTF8Bytes else {
            throw DaemonSocketError.socketPathTooLong(
                path: socketPath,
                utf8ByteCount: utf8Bytes.count,
                maxBytes: maxPathUTF8Bytes
            )
        }

        var addr = sockaddr_un()
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { rawBuf in
            precondition(utf8Bytes.count < rawBuf.count)
            rawBuf.copyBytes(from: utf8Bytes)
        }
        return addr
    }
}

// MARK: - Long-Path Symlink Socket Address Resolver

public struct DaemonResolvedSocketAddress: Hashable, Sendable {
    public enum Mode: String, Hashable, Sendable {
        case direct
        case tempDirectorySymlink
    }

    public let mode: Mode
    /// Path passed into `sockaddr_un` (`<= 103` UTF-8 bytes).
    public let connectSocketPath: String
    /// Physical socket path `<workspace>/run/daemon.sock` (standardized).
    public let physicalSocketFileURL: URL
    /// `<DARWIN_USER_TEMP_DIR>/avm-<16-hex>` when `mode == .tempDirectorySymlink`, otherwise `nil`.
    public let symlinkURL: URL?
    /// Canonical real path of `<workspace>/run` when `mode == .tempDirectorySymlink`, otherwise `nil`.
    public let expectedSymlinkTargetPath: String?

    public init(
        mode: Mode,
        connectSocketPath: String,
        physicalSocketFileURL: URL,
        symlinkURL: URL?,
        expectedSymlinkTargetPath: String?
    ) {
        self.mode = mode
        self.connectSocketPath = connectSocketPath
        self.physicalSocketFileURL = physicalSocketFileURL
        self.symlinkURL = symlinkURL
        self.expectedSymlinkTargetPath = expectedSymlinkTargetPath
    }
}

public enum DaemonSocketAddressResolver {
    public static let symlinkHashHexPrefixLength = 16

    public static func darwinUserTempDirectoryURL() throws -> URL {
        let requiredLen = Darwin.confstr(_CS_DARWIN_USER_TEMP_DIR, nil, 0)
        guard requiredLen > 0 else {
            throw DaemonSocketError.darwinTempDirectoryUnavailable(errnoCode: Darwin.errno)
        }
        var buf = [CChar](repeating: 0, count: requiredLen)
        let written = Darwin.confstr(_CS_DARWIN_USER_TEMP_DIR, &buf, buf.count)
        guard written > 0 else {
            throw DaemonSocketError.darwinTempDirectoryUnavailable(errnoCode: Darwin.errno)
        }
        let nullIndex = buf.firstIndex(of: 0) ?? buf.count
        let pathBytes = buf[0..<nullIndex].map { UInt8(bitPattern: $0) }
        let rawPath = String(decoding: pathBytes, as: UTF8.self)
        return URL(fileURLWithPath: rawPath, isDirectory: true).standardizedFileURL
    }

    /// Resolves symlinks on the deepest existing ancestor via POSIX `realpath(3)` and appends standardized
    /// remaining components, so pre-creation and post-creation callers compute the exact same real path.
    public static func canonicalRealPath(of url: URL) -> String {
        let standardized = url.standardizedFileURL
        var probeURL = standardized
        var trailingComponents: [String] = []

        while probeURL.path != "/" && !probeURL.path.isEmpty {
            if let resolvedC = Darwin.realpath(probeURL.path, nil) {
                defer { Darwin.free(resolvedC) }
                let baseBytes = UnsafeBufferPointer(start: resolvedC, count: Int(Darwin.strlen(resolvedC)))
                    .map { UInt8(bitPattern: $0) }
                var resolvedURL = URL(
                    fileURLWithPath: String(decoding: baseBytes, as: UTF8.self),
                    isDirectory: true
                )
                for component in trailingComponents.reversed() {
                    resolvedURL.appendPathComponent(component, isDirectory: false)
                }
                return resolvedURL.standardizedFileURL.path
            }
            let last = probeURL.lastPathComponent
            if last.isEmpty || last == "/" {
                break
            }
            trailingComponents.append(last)
            probeURL.deleteLastPathComponent()
        }

        return standardized.path
    }

    public static func computePlan(
        for workspaceURL: URL,
        userTempDirectoryOverride: URL? = nil
    ) throws -> DaemonResolvedSocketAddress {
        let paths = DaemonWorkspacePaths(workspaceURL: workspaceURL)
        if paths.directSocketPathUTF8ByteCount <= DaemonUnixSocketAddress.maxPathUTF8Bytes {
            _ = try DaemonUnixSocketAddress.makeSockAddrUn(socketPath: paths.directSocketPath)
            return DaemonResolvedSocketAddress(
                mode: .direct,
                connectSocketPath: paths.directSocketPath,
                physicalSocketFileURL: paths.directSocketFileURL,
                symlinkURL: nil,
                expectedSymlinkTargetPath: nil
            )
        }

        let realWorkspacePath = canonicalRealPath(of: paths.workspaceURL)
        let fullHash = BinaryChecksums.sha256Hex(Data(realWorkspacePath.utf8))
        let hashPrefix = String(fullHash.prefix(symlinkHashHexPrefixLength))
        let symlinkName = "avm-\(hashPrefix)"

        let tempDirURL = try (userTempDirectoryOverride?.standardizedFileURL ?? darwinUserTempDirectoryURL())
        let symlinkURL = tempDirURL
            .appendingPathComponent(symlinkName, isDirectory: false)
            .standardizedFileURL
        let shortSocketPath = symlinkURL
            .appendingPathComponent("daemon.sock", isDirectory: false)
            .standardizedFileURL
            .path

        // Validate that the short symlinked socket path itself fits in sockaddr_un (A43).
        _ = try DaemonUnixSocketAddress.makeSockAddrUn(socketPath: shortSocketPath)

        let expectedRunTarget = canonicalRealPath(of: paths.runDirectoryURL)
        return DaemonResolvedSocketAddress(
            mode: .tempDirectorySymlink,
            connectSocketPath: shortSocketPath,
            physicalSocketFileURL: paths.directSocketFileURL,
            symlinkURL: symlinkURL,
            expectedSymlinkTargetPath: expectedRunTarget
        )
    }

    public static func prepareForBind(
        workspaceURL: URL,
        userTempDirectoryOverride: URL? = nil
    ) throws -> (address: DaemonResolvedSocketAddress, sockAddr: sockaddr_un) {
        let plan = try computePlan(
            for: workspaceURL,
            userTempDirectoryOverride: userTempDirectoryOverride
        )
        if let symlinkURL = plan.symlinkURL,
           let expectedTarget = plan.expectedSymlinkTargetPath {
            let parentDir = symlinkURL.deletingLastPathComponent()
            do {
                try FileManager.default.createDirectory(at: parentDir, withIntermediateDirectories: true)
            } catch {
                let code = Darwin.errno
                throw DaemonSocketError.syscallFailed(
                    operation: "mkdir",
                    path: parentDir.path,
                    errnoCode: code,
                    detail: error.localizedDescription
                )
            }
            try ensureSymlinkMatchesTarget(
                symlinkURL: symlinkURL,
                expectedRunTargetPath: expectedTarget,
                createIfMissing: true
            )
        }
        let sockAddr = try DaemonUnixSocketAddress.makeSockAddrUn(socketPath: plan.connectSocketPath)
        return (plan, sockAddr)
    }

    public static func resolveForConnect(
        workspaceURL: URL,
        userTempDirectoryOverride: URL? = nil
    ) throws -> (address: DaemonResolvedSocketAddress, sockAddr: sockaddr_un) {
        let plan = try computePlan(
            for: workspaceURL,
            userTempDirectoryOverride: userTempDirectoryOverride
        )
        if let symlinkURL = plan.symlinkURL,
           let expectedTarget = plan.expectedSymlinkTargetPath {
            try ensureSymlinkMatchesTarget(
                symlinkURL: symlinkURL,
                expectedRunTargetPath: expectedTarget,
                createIfMissing: false
            )
        }
        let sockAddr = try DaemonUnixSocketAddress.makeSockAddrUn(socketPath: plan.connectSocketPath)
        return (plan, sockAddr)
    }

    public static func removeSymlinkIfPresent(for address: DaemonResolvedSocketAddress) {
        guard let symlinkURL = address.symlinkURL,
              let expectedTarget = address.expectedSymlinkTargetPath else {
            return
        }
        let symlinkPath = symlinkURL.path
        var st = Darwin.stat()
        guard Darwin.lstat(symlinkPath, &st) == 0 else { return }
        guard (st.st_mode & S_IFMT) == S_IFLNK else { return }
        guard let rawTarget = try? readSymlinkRawTarget(at: symlinkPath) else { return }
        let resolvedURL = resolveSymlinkDestinationURL(symlinkPath: symlinkPath, rawTarget: rawTarget)
        if canonicalRealPath(of: resolvedURL) == expectedTarget {
            _ = Darwin.unlink(symlinkPath)
        }
    }

    private static func ensureSymlinkMatchesTarget(
        symlinkURL: URL,
        expectedRunTargetPath: String,
        createIfMissing: Bool
    ) throws {
        let symlinkPath = symlinkURL.path
        var st = Darwin.stat()
        if Darwin.lstat(symlinkPath, &st) != 0 {
            let code = Darwin.errno
            if code == ENOENT {
                guard createIfMissing else {
                    return
                }
                if Darwin.symlink(expectedRunTargetPath, symlinkPath) == 0 {
                    return
                }
                let symErr = Darwin.errno
                if symErr != EEXIST {
                    throw DaemonSocketError.syscallFailed(
                        operation: "symlink",
                        path: symlinkPath,
                        errnoCode: symErr,
                        detail: String(cString: Darwin.strerror(symErr))
                    )
                }
                // Lost a concurrent creation race: re-stat and verify the winner's target below.
                guard Darwin.lstat(symlinkPath, &st) == 0 else {
                    let retryErr = Darwin.errno
                    throw DaemonSocketError.syscallFailed(
                        operation: "lstat",
                        path: symlinkPath,
                        errnoCode: retryErr,
                        detail: String(cString: Darwin.strerror(retryErr))
                    )
                }
            } else {
                throw DaemonSocketError.syscallFailed(
                    operation: "lstat",
                    path: symlinkPath,
                    errnoCode: code,
                    detail: String(cString: Darwin.strerror(code))
                )
            }
        }

        guard (st.st_mode & S_IFMT) == S_IFLNK else {
            throw DaemonSocketError.symlinkTargetMismatch(
                symlinkPath: symlinkPath,
                expectedTarget: expectedRunTargetPath,
                actualTarget: "<non-symlink>"
            )
        }

        let rawTarget = try readSymlinkRawTarget(at: symlinkPath)
        let resolvedURL = resolveSymlinkDestinationURL(symlinkPath: symlinkPath, rawTarget: rawTarget)
        let actualCanonical = canonicalRealPath(of: resolvedURL)
        guard actualCanonical == expectedRunTargetPath else {
            throw DaemonSocketError.symlinkTargetMismatch(
                symlinkPath: symlinkPath,
                expectedTarget: expectedRunTargetPath,
                actualTarget: rawTarget
            )
        }
    }

    private static func readSymlinkRawTarget(at path: String) throws -> String {
        var buf = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
        let len = Darwin.readlink(path, &buf, Int(PATH_MAX))
        guard len >= 0 else {
            let code = Darwin.errno
            throw DaemonSocketError.syscallFailed(
                operation: "readlink",
                path: path,
                errnoCode: code,
                detail: String(cString: Darwin.strerror(code))
            )
        }
        let bytes = buf.prefix(len).map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self)
    }

    private static func resolveSymlinkDestinationURL(symlinkPath: String, rawTarget: String) -> URL {
        if rawTarget.hasPrefix("/") {
            return URL(fileURLWithPath: rawTarget, isDirectory: true).standardizedFileURL
        }
        return URL(fileURLWithPath: symlinkPath, isDirectory: false)
            .deletingLastPathComponent()
            .appendingPathComponent(rawTarget, isDirectory: true)
            .standardizedFileURL
    }
}

// MARK: - Socket Primitives: 0700 `run/`, 0600 `daemon.sock`, `SO_NOSIGPIPE`, `getpeereid`

public enum DaemonSocketPrimitives {
    public static func ensureRunDirectory0700(at runDirectoryURL: URL) throws {
        let stdURL = runDirectoryURL.standardizedFileURL
        do {
            try FileManager.default.createDirectory(
                at: stdURL,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        } catch {
            let code = Darwin.errno
            throw DaemonSocketError.syscallFailed(
                operation: "mkdir",
                path: stdURL.path,
                errnoCode: code,
                detail: error.localizedDescription
            )
        }
        guard Darwin.chmod(stdURL.path, mode_t(0o700)) == 0 else {
            let code = Darwin.errno
            throw DaemonSocketError.syscallFailed(
                operation: "chmod(0700)",
                path: stdURL.path,
                errnoCode: code,
                detail: String(cString: Darwin.strerror(code))
            )
        }
    }

    public static func configureSocketDescriptor(_ fd: Int32, path: String) throws {
        let currentFlags = Darwin.fcntl(fd, F_GETFD)
        if currentFlags >= 0 {
            _ = Darwin.fcntl(fd, F_SETFD, currentFlags | FD_CLOEXEC)
        }
        var one: Int32 = 1
        let rc = Darwin.setsockopt(
            fd,
            SOL_SOCKET,
            SO_NOSIGPIPE,
            &one,
            socklen_t(MemoryLayout<Int32>.size)
        )
        guard rc == 0 else {
            let code = Darwin.errno
            throw DaemonSocketError.syscallFailed(
                operation: "setsockopt(SO_NOSIGPIPE)",
                path: path,
                errnoCode: code,
                detail: String(cString: Darwin.strerror(code))
            )
        }
    }

    public static func isNoSigPipeEnabled(_ fd: Int32) throws -> Bool {
        var val: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        guard Darwin.getsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &val, &len) == 0 else {
            let code = Darwin.errno
            throw DaemonSocketError.syscallFailed(
                operation: "getsockopt(SO_NOSIGPIPE)",
                path: "fd:\(fd)",
                errnoCode: code,
                detail: String(cString: Darwin.strerror(code))
            )
        }
        return val != 0
    }

    public static func verifyPeerUID(
        _ fd: Int32,
        expectedUID: uid_t = Darwin.getuid(),
        path: String
    ) throws -> (uid: uid_t, gid: gid_t) {
        var peerUID: uid_t = 0
        var peerGID: gid_t = 0
        guard Darwin.getpeereid(fd, &peerUID, &peerGID) == 0 else {
            let code = Darwin.errno
            throw DaemonSocketError.syscallFailed(
                operation: "getpeereid",
                path: path,
                errnoCode: code,
                detail: String(cString: Darwin.strerror(code))
            )
        }
        guard peerUID == expectedUID else {
            throw DaemonSocketError.unauthorizedPeerUID(expected: expectedUID, actual: peerUID)
        }
        return (peerUID, peerGID)
    }
}

public final class DaemonSocketConnection: @unchecked Sendable {
    private let lock = NSLock()
    private var rawFD: Int32
    public let peerUID: uid_t
    public let peerGID: gid_t

    public init(fd: Int32, peerUID: uid_t, peerGID: gid_t) {
        self.rawFD = fd
        self.peerUID = peerUID
        self.peerGID = peerGID
    }

    deinit {
        close()
    }

    public var fd: Int32 {
        lock.withLock { rawFD }
    }

    public func makeLineReader(
        readChunkBytes: Int = DaemonRPCLineFraming.defaultReadChunkBytes,
        maxLineBytes: Int = DaemonRPCLineFraming.maxLineBytes
    ) -> DaemonRPCLineReader {
        DaemonRPCLineReader(
            fd: fd,
            readChunkBytes: readChunkBytes,
            maxLineBytes: maxLineBytes
        )
    }

    public func writeLineData(
        _ lineData: Data,
        maxLineBytes: Int = DaemonRPCLineFraming.maxLineBytes
    ) throws {
        let current = fd
        guard current >= 0 else {
            throw DaemonRPCLineFramingError.ioError(
                errnoCode: EBADF,
                detail: "Daemon socket connection is already closed."
            )
        }
        try DaemonRPCLineWriter.writeLineData(lineData, toFD: current, maxLineBytes: maxLineBytes)
    }

    public func close() {
        let descriptor = lock.withLock { () -> Int32 in
            let current = rawFD
            rawFD = -1
            return current
        }
        if descriptor >= 0 {
            _ = Darwin.close(descriptor)
        }
    }
}

public final class DaemonSocketListener: @unchecked Sendable {
    private let lock = NSLock()
    private var rawListenFD: Int32
    public let address: DaemonResolvedSocketAddress
    public let runDirectoryURL: URL

    private init(
        listenFD: Int32,
        address: DaemonResolvedSocketAddress,
        runDirectoryURL: URL
    ) {
        self.rawListenFD = listenFD
        self.address = address
        self.runDirectoryURL = runDirectoryURL
    }

    deinit {
        close(unlinkSocket: false, removeSymlink: false)
    }

    public var listenFD: Int32 {
        lock.withLock { rawListenFD }
    }

    public static func bindDirect(
        paths: DaemonWorkspacePaths,
        backlog: Int32 = 32
    ) throws -> DaemonSocketListener {
        let sockAddr = try DaemonUnixSocketAddress.makeSockAddrUn(socketPath: paths.directSocketPath)
        let directAddress = DaemonResolvedSocketAddress(
            mode: .direct,
            connectSocketPath: paths.directSocketPath,
            physicalSocketFileURL: paths.directSocketFileURL,
            symlinkURL: nil,
            expectedSymlinkTargetPath: nil
        )
        return try bindResolved(
            address: directAddress,
            sockAddr: sockAddr,
            runDirectoryURL: paths.runDirectoryURL,
            backlog: backlog
        )
    }

    public static func bindResolved(
        address: DaemonResolvedSocketAddress,
        sockAddr: sockaddr_un,
        runDirectoryURL: URL,
        backlog: Int32 = 32
    ) throws -> DaemonSocketListener {
        try DaemonSocketPrimitives.ensureRunDirectory0700(at: runDirectoryURL)

        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            let code = Darwin.errno
            throw DaemonSocketError.syscallFailed(
                operation: "socket",
                path: address.connectSocketPath,
                errnoCode: code,
                detail: String(cString: Darwin.strerror(code))
            )
        }

        do {
            try DaemonSocketPrimitives.configureSocketDescriptor(fd, path: address.connectSocketPath)

            var mutableAddr = sockAddr
            let bindRC = withUnsafePointer(to: &mutableAddr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                    Darwin.bind(fd, saPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            guard bindRC == 0 else {
                let code = Darwin.errno
                throw DaemonSocketError.syscallFailed(
                    operation: "bind",
                    path: address.connectSocketPath,
                    errnoCode: code,
                    detail: String(cString: Darwin.strerror(code))
                )
            }

            // Tighten socket permissions to 0600 on the physical file BEFORE calling listen().
            guard Darwin.chmod(address.physicalSocketFileURL.path, mode_t(0o600)) == 0 else {
                let code = Darwin.errno
                _ = Darwin.unlink(address.physicalSocketFileURL.path)
                throw DaemonSocketError.syscallFailed(
                    operation: "chmod(0600)",
                    path: address.physicalSocketFileURL.path,
                    errnoCode: code,
                    detail: String(cString: Darwin.strerror(code))
                )
            }

            guard Darwin.listen(fd, backlog) == 0 else {
                let code = Darwin.errno
                _ = Darwin.unlink(address.physicalSocketFileURL.path)
                throw DaemonSocketError.syscallFailed(
                    operation: "listen",
                    path: address.connectSocketPath,
                    errnoCode: code,
                    detail: String(cString: Darwin.strerror(code))
                )
            }
        } catch {
            _ = Darwin.close(fd)
            throw error
        }

        return DaemonSocketListener(
            listenFD: fd,
            address: address,
            runDirectoryURL: runDirectoryURL
        )
    }

    public func acceptConnection(
        expectedUID: uid_t = Darwin.getuid()
    ) throws -> DaemonSocketConnection {
        let serverFD = listenFD
        guard serverFD >= 0 else {
            throw DaemonSocketError.syscallFailed(
                operation: "accept",
                path: address.connectSocketPath,
                errnoCode: EBADF,
                detail: "Listener socket is closed."
            )
        }

        var clientFD: Int32 = -1
        while true {
            clientFD = Darwin.accept(serverFD, nil, nil)
            if clientFD >= 0 {
                break
            }
            let code = Darwin.errno
            if code == EINTR {
                continue
            }
            throw DaemonSocketError.syscallFailed(
                operation: "accept",
                path: address.connectSocketPath,
                errnoCode: code,
                detail: String(cString: Darwin.strerror(code))
            )
        }

        do {
            try DaemonSocketPrimitives.configureSocketDescriptor(clientFD, path: address.connectSocketPath)
            let creds = try DaemonSocketPrimitives.verifyPeerUID(
                clientFD,
                expectedUID: expectedUID,
                path: address.connectSocketPath
            )
            return DaemonSocketConnection(fd: clientFD, peerUID: creds.uid, peerGID: creds.gid)
        } catch {
            _ = Darwin.close(clientFD)
            throw error
        }
    }

    public func close(unlinkSocket: Bool = true, removeSymlink: Bool = false) {
        let descriptor = lock.withLock { () -> Int32 in
            let current = rawListenFD
            rawListenFD = -1
            return current
        }
        guard descriptor >= 0 else { return }
        _ = Darwin.close(descriptor)
        if unlinkSocket {
            _ = Darwin.unlink(address.physicalSocketFileURL.path)
        }
        if removeSymlink {
            DaemonSocketAddressResolver.removeSymlinkIfPresent(for: address)
        }
    }
}

public enum DaemonSocketClient {
    public static func connectDirect(
        socketPath: String,
        expectedUID: uid_t = Darwin.getuid()
    ) throws -> DaemonSocketConnection {
        let sockAddr = try DaemonUnixSocketAddress.makeSockAddrUn(socketPath: socketPath)
        let directAddr = DaemonResolvedSocketAddress(
            mode: .direct,
            connectSocketPath: socketPath,
            physicalSocketFileURL: URL(fileURLWithPath: socketPath, isDirectory: false).standardizedFileURL,
            symlinkURL: nil,
            expectedSymlinkTargetPath: nil
        )
        return try connectResolved(
            address: directAddr,
            sockAddr: sockAddr,
            expectedUID: expectedUID
        )
    }

    public static func connectResolved(
        address: DaemonResolvedSocketAddress,
        sockAddr: sockaddr_un,
        expectedUID: uid_t = Darwin.getuid()
    ) throws -> DaemonSocketConnection {
        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            let code = Darwin.errno
            throw DaemonSocketError.syscallFailed(
                operation: "socket",
                path: address.connectSocketPath,
                errnoCode: code,
                detail: String(cString: Darwin.strerror(code))
            )
        }

        do {
            try DaemonSocketPrimitives.configureSocketDescriptor(fd, path: address.connectSocketPath)

            var mutableAddr = sockAddr
            while true {
                let rc = withUnsafePointer(to: &mutableAddr) { ptr in
                    ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                        Darwin.connect(fd, saPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
                    }
                }
                if rc == 0 {
                    break
                }
                let code = Darwin.errno
                if code == EINTR {
                    continue
                }
                throw DaemonSocketError.syscallFailed(
                    operation: "connect",
                    path: address.connectSocketPath,
                    errnoCode: code,
                    detail: String(cString: Darwin.strerror(code))
                )
            }

            let creds = try DaemonSocketPrimitives.verifyPeerUID(
                fd,
                expectedUID: expectedUID,
                path: address.connectSocketPath
            )
            return DaemonSocketConnection(fd: fd, peerUID: creds.uid, peerGID: creds.gid)
        } catch {
            _ = Darwin.close(fd)
            throw error
        }
    }
}
