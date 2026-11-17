import AgentVMCLIAndMCP
import AgentVMHypervisor
import AgentVMModels
import AgentVMStorageCoW
import AgentVMStore
import Darwin
import Foundation
import Testing

@Suite("M2 Stage 2: Daemon Skeleton, Spawner, Client Routing, Reconciliation & Events", .timeLimit(.minutes(1)))
struct CLIAndMCPDaemonStage2Tests {

    private func makePrivateTmpDirectory(prefix: String = "avm-s2") throws -> String {
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

    // MARK: - Item 0: Canonical Real Path Socket Length Check (`/private/tmp` Existence Independence)

    @Test("Item 0: /private/tmp workspace where stripped path <= 103B and canonical /private/tmp path > 103B resolves identical symlink address before and after daemon.sock exists")
    func privateTmpSocketLengthUsesCanonicalRealPathConsistentlyBeforeAndAfterBind() throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-p0")
        defer { try? FileManager.default.removeItem(atPath: realBase) }
        #expect(realBase.hasPrefix("/private/tmp/"))

        let suffix = "/ws.agentvm/run/daemon.sock"
        // Target canonical socket UTF-8 length = 107 (> 103); stripped `/tmp/...` length = 99 (<= 103).
        let targetCanonicalBytes = 107
        let padLen = targetCanonicalBytes - (realBase.utf8.count + 1 + suffix.utf8.count)
        #expect(padLen > 0)
        let pad = String(repeating: "p", count: padLen)

        let privateWSPath = "\(realBase)/\(pad)/ws.agentvm"
        let strippedTmpWSPath = String(privateWSPath.dropFirst("/private".count))
        #expect(strippedTmpWSPath.hasPrefix("/tmp/"))

        let canonicalSockLen = "\(privateWSPath)/run/daemon.sock".utf8.count
        let strippedSockLen = "\(strippedTmpWSPath)/run/daemon.sock".utf8.count
        #expect(canonicalSockLen == 107 && canonicalSockLen > DaemonUnixSocketAddress.maxPathUTF8Bytes)
        #expect(strippedSockLen == 99 && strippedSockLen <= DaemonUnixSocketAddress.maxPathUTF8Bytes)

        let privateWSURL = URL(fileURLWithPath: privateWSPath, isDirectory: true)
        let strippedWSURL = URL(fileURLWithPath: strippedTmpWSPath, isDirectory: true)

        // 1. Daemon computes socket address BEFORE workspace or daemon.sock exists on disk.
        let daemonAddressBeforeSocketExists = try DaemonSocketAddressResolver.computePlan(for: privateWSURL)
        #expect(daemonAddressBeforeSocketExists.mode == .tempDirectorySymlink)

        // 2. Also verify when <workspace>/run ALREADY exists on disk while daemon.sock does NOT exist yet.
        try FileManager.default.createDirectory(
            atPath: "\(privateWSPath)/run",
            withIntermediateDirectories: true
        )
        let daemonAddressWithRunDirNoSock = try DaemonSocketAddressResolver.computePlan(for: privateWSURL)
        #expect(daemonAddressWithRunDirNoSock == daemonAddressBeforeSocketExists)

        // 3. Bind server so daemon.sock NOW exists on disk.
        guard case let .bound(server) = try DaemonWorkspaceServerBootstrap.acquireLockAndBind(workspaceURL: privateWSURL) else {
            Issue.record("Expected acquireLockAndBind to succeed on /private/tmp workspace")
            return
        }
        defer { server.shutdownAndCleanup() }

        var sockStat = Darwin.stat()
        #expect(stat("\(privateWSPath)/run/daemon.sock", &sockStat) == 0)
        #expect(server.address == daemonAddressBeforeSocketExists)

        // 4. Client resolves socket address AFTER daemon.sock exists (both /private/tmp and /tmp spellings).
        let (clientAddressAfterSocketExists, _) = try DaemonSocketAddressResolver.resolveForConnect(workspaceURL: privateWSURL)
        let (clientStrippedAliasAddress, _) = try DaemonSocketAddressResolver.resolveForConnect(workspaceURL: strippedWSURL)
        #expect(clientAddressAfterSocketExists == daemonAddressBeforeSocketExists)
        #expect(clientStrippedAliasAddress == daemonAddressBeforeSocketExists)

        // 5. Verify live client connect succeeds over the resolved address.
        let acceptedSem = DispatchSemaphore(value: 0)
        let acceptedBox = Stage2ResultBox<Result<DaemonSocketConnection, Error>>()
        DispatchQueue.global().async {
            acceptedBox.store(Result { try server.listener.acceptConnection() })
            acceptedSem.signal()
        }
        let clientConn = try DaemonSocketClient.connectWorkspace(workspaceURL: privateWSURL)
        acceptedSem.wait()
        let serverConn = try #require(acceptedBox.load()).get()
        clientConn.close()
        serverConn.close()
        server.shutdownAndCleanup()
    }
}

private final class Stage2ResultBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: T?
    func store(_ newValue: T) {
        lock.withLock { value = newValue }
    }
    func load() -> T? {
        lock.withLock { value }
    }
}
