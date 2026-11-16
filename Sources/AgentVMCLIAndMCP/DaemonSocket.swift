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
