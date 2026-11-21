import AgentVMCLIAndMCP
import AgentVMHypervisor
import AgentVMModels
import AgentVMStorageCoW
import AgentVMStore
import AgentVMVsockRPC
import Darwin
import Foundation
import Testing

@Suite("M4 Stage 3: MCP Daemon Integration, Create/Fork Parameters & M5 Honesty Gate", .serialized, .timeLimit(.minutes(2)))
struct M4Stage3MCPDaemonTests {

    // MARK: - Helpers

    private func makePrivateTmpDirectory(prefix: String = "avm-m4-s3") throws -> String {
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
            throw NSError(domain: "M4Stage3MCPDaemonTests", code: 1)
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

    private struct MCPCallOutcome {
        var isError: Bool
        var texts: [String]
        var joinedText: String { texts.joined(separator: "\n") }
    }

    private func callMCPTool(
        _ mcp: AgentVMMCPServer,
        id: Int,
        name: String,
        arguments: [String: Any]
    ) async throws -> MCPCallOutcome {
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
        if let errObj = respObj["error"] as? [String: Any] {
            Issue.record("Expected MCP tool result envelope for \(name), got JSON-RPC error: \(errObj)")
            throw NSError(domain: "M4Stage3MCPDaemonTests", code: 2)
        }
        let resultObj = try #require(respObj["result"] as? [String: Any])
        let isError = try #require(resultObj["isError"] as? Bool)
        let contentArr = try #require(resultObj["content"] as? [[String: Any]])
        let texts = contentArr.compactMap { $0["text"] as? String }
        return MCPCallOutcome(isError: isError, texts: texts)
    }

    private func extractUserDataFromISO(at isoPath: String, scratchRoot: String) throws -> String {
        let outDir = "\(scratchRoot)/iso-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: outDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: outDir) }

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
        proc.arguments = ["-xf", isoPath, "-C", outDir]
        try proc.run()
        proc.waitUntilExit()
        #expect(proc.terminationStatus == 0)

        let candidates = ["\(outDir)/user-data", "\(outDir)/USER_DATA", "\(outDir)/USER-DATA"]
        for path in candidates where FileManager.default.fileExists(atPath: path) {
            return try String(contentsOfFile: path, encoding: .utf8)
        }
        let entries = (try? FileManager.default.contentsOfDirectory(atPath: outDir)) ?? []
        for entry in entries where entry.lowercased().hasPrefix("user") {
            return try String(contentsOfFile: "\(outDir)/\(entry)", encoding: .utf8)
        }
        Issue.record("Could not locate user-data inside extracted ISO at \(isoPath); entries=\(entries)")
        return ""
    }

    // MARK: - 1. tools/list Schema & M5 Unimplemented Gate (Default vs Simulation Backend)

    @Test("tools/list keeps exact 9 tool names with updated schemas, and M5 tools return isError=true on default backend while preserving SIMULATED demo on simulation backend")
    func toolsListExposesExactNineNamesAndM5ToolsFailOnDefaultBackendOnly() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-m4s3-m5")
        defer {
            Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase)
            try? FileManager.default.removeItem(atPath: realBase)
        }

        let defaultWS = URL(fileURLWithPath: "\(realBase)/default.agentvm", isDirectory: true)
        let defaultCoord = try AgentVMFleetCoordinator(bundleURL: defaultWS, executionBackend: .strictHardwareVZ)
        let defaultMCP = AgentVMMCPServer(coordinator: defaultCoord)

        // 1a. tools/list has exact 9 tool names and updated parameter schemas
        let listRaw = try #require(await defaultMCP.handleJSONRPCLine(#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#))
        let listObj = try #require(try JSONSerialization.jsonObject(with: Data(listRaw.utf8)) as? [String: Any])
        let tools = try #require((listObj["result"] as? [String: Any])?["tools"] as? [[String: Any]])
        let names = tools.compactMap { $0["name"] as? String }
        let expectedNames: Set<String> = [
            "agentvm_list_fleet",
            "agentvm_create_vm",
            "agentvm_fork_cow_branch",
            "agentvm_exec_command",
            "agentvm_capture_snapshot",
            "agentvm_restore_snapshot",
            "agentvm_query_wiretap",
            "agentvm_set_firewall_preset",
            "agentvm_doctor"
        ]
        #expect(names.count == 9)
        #expect(Set(names) == expectedNames)

        func schemaProps(for toolName: String) throws -> [String: Any] {
            let entry = try #require(tools.first(where: { ($0["name"] as? String) == toolName }))
            let schema = try #require(entry["inputSchema"] as? [String: Any])
            return try #require(schema["properties"] as? [String: Any])
        }

        let createProps = try schemaProps(for: "agentvm_create_vm")
        #expect(createProps["image"] != nil)
        #expect(createProps["diskSize"] != nil)
        #expect(createProps["mounts"] != nil)
        #expect(createProps["bootImmediately"] != nil)

        let forkProps = try schemaProps(for: "agentvm_fork_cow_branch")
        #expect(forkProps["bootImmediately"] != nil)
        #expect(forkProps["inheritMounts"] != nil)

        let execProps = try schemaProps(for: "agentvm_exec_command")
        #expect(execProps["workingDirectory"] != nil)
        #expect(execProps["runAsUser"] != nil)
        #expect(execProps["timeoutSeconds"] != nil)
        #expect(execProps["environment"] != nil)

        // 1b. Default backend: agentvm_query_wiretap and agentvm_set_firewall_preset return isError=true mentioning M5
        let wiretapDefault = try await callMCPTool(defaultMCP, id: 2, name: "agentvm_query_wiretap", arguments: [:])
        #expect(wiretapDefault.isError == true)
        #expect(wiretapDefault.joinedText.contains("M5"))
        #expect(!wiretapDefault.joinedText.contains("SIMULATED"))

        let firewallDefault = try await callMCPTool(
            defaultMCP,
            id: 3,
            name: "agentvm_set_firewall_preset",
            arguments: ["preset": "airgap"]
        )
        #expect(firewallDefault.isError == true)
        #expect(firewallDefault.joinedText.contains("M5"))
        #expect(!firewallDefault.joinedText.contains("SIMULATED"))

        // Persisted workspace policy must NOT have been mutated to airgap by the rejected MCP call
        let cli = AgentVMCLIRunner()
        let policyAfter = await cli.execute(
            arguments: ["--lang", "en", "--workspace", defaultWS.path, "policy"]
        )
        #expect(policyAfter.exitCode == 0)
        #expect(policyAfter.stdout.contains("Strict Coding-Agent Allowlist"))
        #expect(!policyAfter.stdout.contains("Total Air-Gap"))

        // 1c. Simulation backend: both M5 tools remain isError=false with SIMULATED: prefix on every line
        let simWS = URL(fileURLWithPath: "\(realBase)/sim.agentvm", isDirectory: true)
        let simCoord = try AgentVMFleetCoordinator(bundleURL: simWS, executionBackend: .deterministicSimulation)
        let simMCP = AgentVMMCPServer(coordinator: simCoord)

        let wiretapSim = try await callMCPTool(simMCP, id: 4, name: "agentvm_query_wiretap", arguments: [:])
        #expect(wiretapSim.isError == false)
        #expect(wiretapSim.joinedText.hasPrefix("SIMULATED:"))

        let firewallSim = try await callMCPTool(
            simMCP,
            id: 5,
            name: "agentvm_set_firewall_preset",
            arguments: ["preset": "airgap"]
        )
        #expect(firewallSim.isError == false)
        #expect(firewallSim.joinedText.hasPrefix("SIMULATED:"))
    }

    // MARK: - 2. agentvm_exec_command via Daemon (Name/ID Resolution, Defaults, Options, Stopped VM, Overflow & Disconnect)

    @Test("agentvm_exec_command resolves name and vm-ID, routes via DaemonClient.performExecCall with root/'/'/3600s defaults, collects stdout/stderr, and reports ERR_LIFECYCLE_STATE / overflow / disconnect")
    func mcpExecCommandRoutesViaDaemonResolvesNamesAndHandlesErrors() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-m4s3-exec")
        defer {
            Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase)
            try? FileManager.default.removeItem(atPath: realBase)
        }

        let (cacheDir, _, entry) = try await stageBootableCachedImage(in: realBase)
        let wsURL = URL(fileURLWithPath: "\(realBase)/ws.agentvm", isDirectory: true)
        let env = [
            "HOME": "\(realBase)/home",
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        try FileManager.default.createDirectory(atPath: "\(realBase)/home/Library/Preferences", withIntermediateDirectories: true)

        let cli = AgentVMCLIRunner()
        let forbiddenSpawn = DaemonSpawnCommandOverride(
            executablePath: "/usr/bin/false",
            arguments: [],
            environment: env
        )

        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "create", "t1", "--image", entry.id],
            curatedEntriesOverride: [entry],
            environment: env
        ).exitCode == 0)

        let daemonMock = M4S3MockHardwareBackend()
        defer { daemonMock.shutdownAll() }
        let mcpGuardBackend = M4S3MockHardwareBackend()
        defer { mcpGuardBackend.shutdownAll() }

        let mcpCoord = try AgentVMFleetCoordinator(
            bundleURL: wsURL,
            executionBackend: .strictHardwareVZ,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mcpGuardBackend
        )
        let mcp = AgentVMMCPServer(coordinator: mcpCoord)

        // 2a. Stopped VM when no daemon is running -> isError=true, ERR_LIFECYCLE_STATE (both by name and by vm-... ID)
        let vmsBefore = try await mcpCoord.store.listVMs()
        let t1Record = try #require(vmsBefore.first(where: { $0.spec.name == "t1" }))

        let stoppedByName = try await callMCPTool(
            mcp,
            id: 10,
            name: "agentvm_exec_command",
            arguments: ["vmID": "t1", "executable": "uname", "arguments": ["-r"]]
        )
        #expect(stoppedByName.isError == true)
        #expect(stoppedByName.joinedText.contains("ERR_LIFECYCLE_STATE"))
        #expect(!stoppedByName.joinedText.contains("SIMULATED"))

        let stoppedByID = try await callMCPTool(
            mcp,
            id: 11,
            name: "agentvm_exec_command",
            arguments: ["vmID": t1Record.id.rawValue, "executable": "uname", "arguments": ["-r"]]
        )
        #expect(stoppedByID.isError == true)
        #expect(stoppedByID.joinedText.contains("ERR_LIFECYCLE_STATE"))

        // 2b. Running VM held by daemon: exec by name uses defaults (root, '/', 3600s); exec by ID forwards custom options
        try await withStartedDaemonServer(
            workspaceURL: wsURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: daemonMock
        ) { _ in
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)

            let handle = try #require(daemonMock.latestHandle(for: t1Record.id))
            handle.setExecHandler { req in
                M4S3MockExecReply(
                    stdout: Data("6.1.0-54-cloud-arm64\n".utf8),
                    stderr: Data("warn:\(req.runAsUser)@\(req.workingDirectory)\n".utf8),
                    exitCode: 0,
                    delayNanoseconds: 40_000_000
                )
            }

            let execByName = try await callMCPTool(
                mcp,
                id: 12,
                name: "agentvm_exec_command",
                arguments: ["vmID": "t1", "executable": "uname", "arguments": ["-r"]]
            )
            #expect(execByName.isError == false, "Expected exec by name to succeed via daemon: \(execByName.joinedText)")
            #expect(execByName.joinedText.contains("exitCode=0"))
            #expect(execByName.joinedText.contains("6.1.0-54-cloud-arm64"))
            #expect(execByName.joinedText.contains("warn:root@/"))
            #expect(!execByName.joinedText.contains("SIMULATED"))

            let firstReq = try #require(handle.recordedExecRequests().last)
            #expect(firstReq.executable == "uname")
            #expect(firstReq.arguments == ["-r"])
            #expect(firstReq.runAsUser == "root")
            #expect(firstReq.workingDirectory == "/")
            #expect(firstReq.timeoutSeconds == 3600)
            #expect(firstReq.environment.isEmpty)

            // Custom workingDirectory, runAsUser, timeoutSeconds, environment + VMID
            let execByID = try await callMCPTool(
                mcp,
                id: 13,
                name: "agentvm_exec_command",
                arguments: [
                    "vmID": t1Record.id.rawValue,
                    "executable": "/usr/bin/env",
                    "arguments": ["sh", "-c", "pwd"],
                    "workingDirectory": "/workspace",
                    "runAsUser": "agent",
                    "timeoutSeconds": 90,
                    "environment": ["MY_TOKEN": "abc123", "LANG": "C.UTF-8"]
                ]
            )
            #expect(execByID.isError == false)
            let secondReq = try #require(handle.recordedExecRequests().last)
            #expect(secondReq.workingDirectory == "/workspace")
            #expect(secondReq.runAsUser == "agent")
            #expect(secondReq.timeoutSeconds == 90)
            #expect(secondReq.environment == ["MY_TOKEN": "abc123", "LANG": "C.UTF-8"])

            // MCP coordinator itself never booted any VM
            #expect(mcpGuardBackend.startCount == 0)

            // Halt `t1` while daemon stays up -> exec on stopped VM returns ERR_LIFECYCLE_STATE
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)

            let stoppedWhileDaemonUp = try await callMCPTool(
                mcp,
                id: 14,
                name: "agentvm_exec_command",
                arguments: ["vmID": "t1", "executable": "uname", "arguments": ["-r"]]
            )
            #expect(stoppedWhileDaemonUp.isError == true)
            #expect(stoppedWhileDaemonUp.joinedText.contains("ERR_LIFECYCLE_STATE"))
        }

        // 2c. Stub daemon socket testing mid-exec disconnect (ERR_DAEMON_IPC) and overflow (ERR_EXEC_OUTPUT_OVERFLOW)
        let disconnectWS = URL(fileURLWithPath: "\(realBase)/disc.agentvm", isDirectory: true)
        let discCoord = try AgentVMFleetCoordinator(bundleURL: disconnectWS, executionBackend: .strictHardwareVZ)
        let discVM = try await discCoord.createSandboxVM(name: "d1").vmRecord
        let discMCP = AgentVMMCPServer(coordinator: discCoord)

        try await Self.withStubDaemonSocket(workspaceURL: disconnectWS) { conn, call in
            guard case .exec = call.call else { return }
            let chunk = DaemonRPCExecOutputParams(stream: .stdout, data: Data("partial-line\n".utf8))
            try? conn.writeLineData(try DaemonRPCCodec.encodeExecOutputLine(chunk))
            // Abruptly close without sending final JSON-RPC response!
            conn.close()
        } body: {
            let dropped = try await callMCPTool(
                discMCP,
                id: 15,
                name: "agentvm_exec_command",
                arguments: ["vmID": "d1", "executable": "yes"]
            )
            #expect(dropped.isError == true)
            #expect(dropped.joinedText.contains("ERR_DAEMON_IPC"))
        }

        try await Self.withStubDaemonSocket(workspaceURL: disconnectWS) { conn, call in
            guard case .exec = call.call else { return }
            let overflowErr = AgentVMError.execOutputBufferOverflow(
                vmID: discVM.id,
                streamID: 1,
                queuedBytes: 2_097_153,
                hardLimitBytes: 2_097_152
            )
            let resp = DaemonRPCResponse<DaemonRPCExecResult>.failure(
                id: call.id,
                agentVMError: overflowErr,
                language: .en
            )
            try? conn.writeLineData(try DaemonRPCCodec.encodeResponseLine(resp))
            conn.close()
        } body: {
            let overflowed = try await callMCPTool(
                discMCP,
                id: 16,
                name: "agentvm_exec_command",
                arguments: ["vmID": "d1", "executable": "yes"]
            )
            #expect(overflowed.isError == true)
            #expect(overflowed.joinedText.contains("ERR_EXEC_OUTPUT_OVERFLOW"))
        }
    }

    // MARK: - 3. agentvm_list_fleet Queries Daemon .list First & Falls Back to Store

    @Test("agentvm_list_fleet queries running daemon (.list) first and falls back to SQLite when daemon is not running")
    func mcpListFleetQueriesDaemonFirstAndFallsBackToSQLite() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-m4s3-list")
        defer {
            Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase)
            try? FileManager.default.removeItem(atPath: realBase)
        }

        let wsURL = URL(fileURLWithPath: "\(realBase)/list.agentvm", isDirectory: true)
        let coord = try AgentVMFleetCoordinator(bundleURL: wsURL, executionBackend: .strictHardwareVZ)
        let created = try await coord.createSandboxVM(name: "fleet-vm").vmRecord
        let mcp = AgentVMMCPServer(coordinator: coord)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        // 3a. With live daemon socket listening: MCP list_fleet MUST return daemon's live .list payload
        var liveRecord = created
        liveRecord.telemetry.state = .running
        liveRecord.telemetry.hasLiveGuestTelemetry = true
        liveRecord.telemetry.uptimeSeconds = 7777.0
        liveRecord.telemetry.guestAgentVersion = "2"

        let snapshotLiveRecord = liveRecord
        try await Self.withStubDaemonSocket(workspaceURL: wsURL) { conn, envelope in
            guard case .list = envelope.call else { return }
            let resp = DaemonRPCResponse<DaemonRPCListResult>.success(
                id: envelope.id,
                result: DaemonRPCListResult(vms: [snapshotLiveRecord])
            )
            try? conn.writeLineData(try DaemonRPCCodec.encodeResponseLine(resp))
            conn.close()
        } body: {
            let listed = try await callMCPTool(mcp, id: 20, name: "agentvm_list_fleet", arguments: [:])
            #expect(listed.isError == false)
            #expect(listed.texts.count == 1)
            let records = try decoder.decode([VMInstanceRecord].self, from: Data(listed.texts[0].utf8))
            let first = try #require(records.first)
            #expect(first.telemetry.state == .running)
            #expect(first.telemetry.uptimeSeconds == 7777.0)
        }

        // 3b. Once daemon socket is gone: MCP list_fleet falls back to SQLite reporting (stopped, uptime 0)
        let fallback = try await callMCPTool(mcp, id: 21, name: "agentvm_list_fleet", arguments: [:])
        #expect(fallback.isError == false)
        let fallbackRecords = try decoder.decode([VMInstanceRecord].self, from: Data(fallback.texts[0].utf8))
        let fbFirst = try #require(fallbackRecords.first)
        #expect(fbFirst.telemetry.state == .stopped)
        #expect(fbFirst.telemetry.uptimeSeconds == 0)
    }

    // MARK: - 4. agentvm_fork_cow_branch bootImmediately via Daemon & inheritMounts

    @Test("agentvm_fork_cow_branch runs preflight before cloning, boots child in daemon when bootImmediately=true without ERR_DAEMON_REQUIRED, and honors inheritMounts")
    func mcpForkCowBranchBootImmediatelyViaDaemonAndInheritMounts() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-m4s3-fork")
        defer {
            Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase)
            try? FileManager.default.removeItem(atPath: realBase)
        }

        let (cacheDir, _, entry) = try await stageBootableCachedImage(in: realBase)
        let wsURL = URL(fileURLWithPath: "\(realBase)/fork.agentvm", isDirectory: true)
        let rwDir = "\(realBase)/share-rw"
        try FileManager.default.createDirectory(atPath: rwDir, withIntermediateDirectories: true)
        let env = [
            "HOME": "\(realBase)/home",
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        try FileManager.default.createDirectory(atPath: "\(realBase)/home/Library/Preferences", withIntermediateDirectories: true)

        let daemonMock = M4S3MockHardwareBackend()
        defer { daemonMock.shutdownAll() }
        let mcpGuardBackend = M4S3MockHardwareBackend()
        defer { mcpGuardBackend.shutdownAll() }

        let mcpCoord = try AgentVMFleetCoordinator(
            bundleURL: wsURL,
            executionBackend: .strictHardwareVZ,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mcpGuardBackend
        )
        let mcp = AgentVMMCPServer(coordinator: mcpCoord)

        // 4a. Empty-disk VM + bootImmediately=true fails preflight with ERR_NO_BOOTABLE_SYSTEM BEFORE cloning child
        _ = try await mcpCoord.createSandboxVM(name: "empty-parent")
        let badBoot = try await callMCPTool(
            mcp,
            id: 30,
            name: "agentvm_fork_cow_branch",
            arguments: ["parentVMID": "empty-parent", "branchName": "orphan-child", "bootImmediately": true]
        )
        #expect(badBoot.isError == true)
        #expect(badBoot.joinedText.contains("ERR_NO_BOOTABLE_SYSTEM"))
        let afterFailedPreflight = try await mcpCoord.store.listVMs()
        #expect(!afterFailedPreflight.contains(where: { $0.spec.name == "orphan-child" }))

        // 4b. Create bootable parent `p1` with `/workspace` VirtioFS mount and boot in daemon
        let cli = AgentVMCLIRunner()
        let forbiddenSpawn = DaemonSpawnCommandOverride(
            executablePath: "/usr/bin/false",
            arguments: [],
            environment: env
        )
        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "create", "p1", "--image", entry.id, "--mount", "\(rwDir):/workspace"],
            curatedEntriesOverride: [entry],
            environment: env
        ).exitCode == 0)

        try await withStartedDaemonServer(
            workspaceURL: wsURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: daemonMock
        ) { daemonServer in
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "p1"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)

            // Fork child `c-boot` with bootImmediately: true (default inheritMounts = true)
            let forkBoot = try await callMCPTool(
                mcp,
                id: 31,
                name: "agentvm_fork_cow_branch",
                arguments: [
                    "parentVMID": "p1",
                    "branchName": "c-boot",
                    "bootImmediately": true
                ]
            )
            #expect(forkBoot.isError == false, "Expected fork with bootImmediately=true to succeed via daemon: \(forkBoot.joinedText)")
            #expect(!forkBoot.joinedText.contains("ERR_DAEMON_REQUIRED"))
            #expect(mcpGuardBackend.startCount == 0)

            let heldVMs = try await daemonServer.coordinator.daemonHeldVMs()
            let childRunning = try #require(heldVMs.first(where: { $0.spec.name == "c-boot" }))
            #expect(childRunning.telemetry.state == .running)
            #expect(childRunning.spec.virtioFSMounts.count == 1)
            #expect(childRunning.spec.virtioFSMounts.first?.guestMountPoint == "/workspace")

            let childBootUserData = try extractUserDataFromISO(
                at: try #require(childRunning.spec.cloudInitISOPath),
                scratchRoot: realBase
            )
            #expect(childBootUserData.contains("mounts:"))
            #expect(childBootUserData.contains("virtiofs"))

            // Exec inside booted child via MCP works immediately
            let childExec = try await callMCPTool(
                mcp,
                id: 32,
                name: "agentvm_exec_command",
                arguments: ["vmID": "c-boot", "executable": "uname", "arguments": ["-r"]]
            )
            #expect(childExec.isError == false)

            // Fork child `c-nomount` with inheritMounts: false
            let forkNoMounts = try await callMCPTool(
                mcp,
                id: 33,
                name: "agentvm_fork_cow_branch",
                arguments: [
                    "parentVMID": "p1",
                    "branchName": "c-nomount",
                    "inheritMounts": false,
                    "bootImmediately": false
                ]
            )
            #expect(forkNoMounts.isError == false)
            let allVMs = try await mcpCoord.store.listVMs()
            let childNoMount = try #require(allVMs.first(where: { $0.spec.name == "c-nomount" }))
            #expect(childNoMount.spec.virtioFSMounts.isEmpty)
            let noMountUserData = try extractUserDataFromISO(
                at: try #require(childNoMount.spec.cloudInitISOPath),
                scratchRoot: realBase
            )
            #expect(!noMountUserData.contains("virtiofs"))
        }
    }

    // MARK: - 5. agentvm_create_vm Optional Parameters (image, diskSize, mounts, bootImmediately) & Error Semantics

    @Test("agentvm_create_vm validates image, diskSize, and mounts with CLI error semantics and provisions + boots mounted VM via daemon")
    func mcpCreateVMValidatesParametersAndBootsViaDaemon() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-m4s3-create")
        defer {
            Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase)
            try? FileManager.default.removeItem(atPath: realBase)
        }

        let (cacheDir, _, entry) = try await stageBootableCachedImage(in: realBase)
        let wsURL = URL(fileURLWithPath: "\(realBase)/create.agentvm", isDirectory: true)
        let rwDir = "\(realBase)/rw-share"
        let roDir = "\(realBase)/ro-share"
        let plainFile = "\(realBase)/not-a-dir.txt"
        try FileManager.default.createDirectory(atPath: rwDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: roDir, withIntermediateDirectories: true)
        try Data("hello\n".utf8).write(to: URL(fileURLWithPath: plainFile))

        let daemonMock = M4S3MockHardwareBackend()
        defer { daemonMock.shutdownAll() }
        let mcpGuardBackend = M4S3MockHardwareBackend()
        defer { mcpGuardBackend.shutdownAll() }

        let mcpCoord = try AgentVMFleetCoordinator(
            bundleURL: wsURL,
            executionBackend: .strictHardwareVZ,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mcpGuardBackend
        )
        let mcp = AgentVMMCPServer(coordinator: mcpCoord)

        // 5a. Validation errors must all return isError=true and leave zero VM records in workspace
        let invalidCalls: [(String, [String: Any], String)] = [
            (
                "diskSize without image",
                ["name": "bad-ds-no-img", "diskSize": "8G"],
                "ERR_CLI_USAGE"
            ),
            (
                "malformed diskSize",
                ["name": "bad-ds-fmt", "image": entry.id, "diskSize": "0G"],
                "ERR_CLI_USAGE"
            ),
            (
                "diskSize smaller than image",
                ["name": "bad-ds-small", "image": entry.id, "diskSize": "1M"],
                "ERR_DISK_SIZE_TOO_SMALL"
            ),
            (
                "unknown image",
                ["name": "bad-img", "image": "nonexistent-linux-arm64"],
                "ERR_IMAGE_NOT_FOUND"
            ),
            (
                "relative guestPath",
                ["name": "bad-rel-guest", "mounts": [["hostPath": rwDir, "guestPath": "workspace"]]],
                "ERR_CLI_USAGE"
            ),
            (
                "root guestPath",
                ["name": "bad-root-guest", "mounts": [["hostPath": rwDir, "guestPath": "/"]]],
                "ERR_CLI_USAGE"
            ),
            (
                "dotdot guestPath",
                ["name": "bad-dotdot-guest", "mounts": [["hostPath": rwDir, "guestPath": "/workspace/../etc"]]],
                "ERR_CLI_USAGE"
            ),
            (
                "duplicate guestPath",
                [
                    "name": "bad-dup-guest",
                    "mounts": [
                        ["hostPath": rwDir, "guestPath": "/workspace"],
                        ["hostPath": roDir, "guestPath": "/workspace/", "readOnly": true]
                    ]
                ],
                "ERR_CLI_USAGE"
            ),
            (
                "missing hostPath",
                ["name": "bad-missing-host", "mounts": [["hostPath": "\(realBase)/missing-dir", "guestPath": "/workspace"]]],
                "ERR_SHARED_DIR_INVALID"
            ),
            (
                "file hostPath",
                ["name": "bad-file-host", "mounts": [["hostPath": plainFile, "guestPath": "/workspace"]]],
                "ERR_SHARED_DIR_INVALID"
            )
        ]

        for (idx, tc) in invalidCalls.enumerated() {
            let res = try await callMCPTool(mcp, id: 40 + idx, name: "agentvm_create_vm", arguments: tc.1)
            #expect(res.isError == true, "[\(tc.0)] expected isError=true, got: \(res.joinedText)")
            #expect(res.joinedText.contains(tc.2), "[\(tc.0)] expected \(tc.2), got: \(res.joinedText)")
        }

        let vmsAfterBad = try await mcpCoord.store.listVMs()
        let badNames = vmsAfterBad.map(\.spec.name)
        #expect(badNames.isEmpty, "Invalid create_vm calls must not leave partial VMs: \(badNames)")

        // 5b. Pure MCP one-step create + mounts + bootImmediately=true via daemon
        try await withStartedDaemonServer(
            workspaceURL: wsURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: daemonMock
        ) { _ in
            let created = try await callMCPTool(
                mcp,
                id: 60,
                name: "agentvm_create_vm",
                arguments: [
                    "name": "mcp-live",
                    "image": entry.id,
                    "diskSize": "8M",
                    "mounts": [
                        ["hostPath": rwDir, "guestPath": "/workspace"],
                        ["hostPath": roDir, "guestPath": "/mnt/ro", "readOnly": true]
                    ],
                    "bootImmediately": true
                ]
            )
            #expect(created.isError == false, "Expected pure MCP create_vm + bootImmediately to succeed: \(created.joinedText)")
            #expect(mcpGuardBackend.startCount == 0, "MCP process must never start VZVirtualMachine in-process")
            #expect(daemonMock.startCount == 1, "Workspace daemon must start the VM")

            let listed = try await callMCPTool(mcp, id: 61, name: "agentvm_list_fleet", arguments: [:])
            #expect(listed.isError == false)
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            let fleet = try decoder.decode([VMInstanceRecord].self, from: Data(listed.texts[0].utf8))
            let vm = try #require(fleet.first(where: { $0.spec.name == "mcp-live" }))
            #expect(vm.telemetry.state == .running)
            #expect(vm.spec.blockDevices.first?.virtualSizeBytes == 8 * 1024 * 1024)
            #expect(vm.spec.virtioFSMounts.count == 2)
            if vm.spec.virtioFSMounts.count == 2 {
                #expect(vm.spec.virtioFSMounts[0].guestMountPoint == "/workspace")
                #expect(vm.spec.virtioFSMounts[0].readOnly == false)
                #expect(vm.spec.virtioFSMounts[1].guestMountPoint == "/mnt/ro")
                #expect(vm.spec.virtioFSMounts[1].readOnly == true)
            }

            let userData = try extractUserDataFromISO(at: try #require(vm.spec.cloudInitISOPath), scratchRoot: realBase)
            #expect(userData.contains("mounts:"))
            #expect(userData.contains("/workspace"))
            #expect(userData.contains("/mnt/ro"))

            let execOut = try await callMCPTool(
                mcp,
                id: 62,
                name: "agentvm_exec_command",
                arguments: ["vmID": "mcp-live", "executable": "uname", "arguments": ["-r"]]
            )
            #expect(execOut.isError == false)
        }
    }

    // MARK: - 6. Environment Passthrough on Spawn, Entitlement Preflight & Client-Side Output Cap

    @Test("AgentVMMCPServer forwards environment (HOME, AGENTVM_IMAGE_CACHE) when spawning daemon, enforces entitlement preflight before creating VM, and caps bounded exec output")
    func mcpEnvironmentPassthroughEntitlementPreflightAndClientOutputOverflow() async throws {
        let realBase = try makePrivateTmpDirectory(prefix: "avm-m4s3-env")
        defer {
            Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase)
            try? FileManager.default.removeItem(atPath: realBase)
        }

        let (cacheDir, _, entry) = try await stageBootableCachedImage(in: realBase)
        let wsURL = URL(fileURLWithPath: "\(realBase)/env.agentvm", isDirectory: true)
        let isoHome = "\(realBase)/isolated-home"
        try FileManager.default.createDirectory(atPath: "\(isoHome)/Library/Preferences", withIntermediateDirectories: true)

        let mcpGuardBackend = M4S3MockHardwareBackend()
        defer { mcpGuardBackend.shutdownAll() }

        let coord = try AgentVMFleetCoordinator(
            bundleURL: wsURL,
            executionBackend: .strictHardwareVZ,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: mcpGuardBackend
        )

        // 6a. Missing entitlement (`hasEntitlementOverride: false`) rejects `create_vm(..., bootImmediately: true)` BEFORE creating files
        let unentitledMCP = AgentVMMCPServer(
            coordinator: coord,
            hasEntitlementOverride: false
        )
        let noEntCreate = try await callMCPTool(
            unentitledMCP,
            id: 70,
            name: "agentvm_create_vm",
            arguments: [
                "name": "unentitled-vm",
                "image": entry.id,
                "bootImmediately": true
            ]
        )
        #expect(noEntCreate.isError == true)
        #expect(noEntCreate.joinedText.contains("ERR_VZ_ENTITLEMENT_MISSING"))
        let vmsAfterNoEnt = try await coord.store.listVMs()
        #expect(vmsAfterNoEnt.map(\.spec.name).isEmpty)

        // 6b. On-demand daemon spawn receives MCP server's `environment` (`HOME`, `AGENTVM_IMAGE_CACHE`)
        let envDumpFile = "\(realBase)/spawned-daemon-env.txt"
        let customEnv = [
            "HOME": isoHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path,
            "PATH": "/usr/bin:/bin"
        ]
        // Spawn a helper shell command that dumps its inherited HOME and AGENTVM_IMAGE_CACHE to `envDumpFile` and exits 42
        let dumpSpawn = DaemonSpawnCommandOverride(
            executablePath: "/bin/sh",
            arguments: ["-c", "printf 'HOME=%s\\nAGENTVM_IMAGE_CACHE=%s\\n' \"$HOME\" \"$AGENTVM_IMAGE_CACHE\" > '\(envDumpFile)'; exit 42"],
            environment: nil // nil ensures DaemonProcessLauncher uses `environment` passed by AgentVMMCPServer!
        )
        let spawnMCP = AgentVMMCPServer(
            coordinator: coord,
            environment: customEnv,
            daemonSpawnOverride: dumpSpawn,
            hasEntitlementOverride: true
        )
        let spawnAttempt = try await callMCPTool(
            spawnMCP,
            id: 71,
            name: "agentvm_create_vm",
            arguments: [
                "name": "env-check-vm",
                "image": entry.id,
                "bootImmediately": true
            ]
        )
        #expect(spawnAttempt.isError == true)
        #expect(spawnAttempt.joinedText.contains("ERR_DAEMON_IPC"))
        let dumpedEnv = try String(contentsOfFile: envDumpFile, encoding: .utf8)
        #expect(dumpedEnv.contains("HOME=\(isoHome)"))
        #expect(dumpedEnv.contains("AGENTVM_IMAGE_CACHE=\(cacheDir.path)"))

        // 6c. MCP client-side bounded output cap aborts stream and returns ERR_EXEC_OUTPUT_OVERFLOW
        let cappedMCP = AgentVMMCPServer(
            coordinator: coord,
            hasEntitlementOverride: true,
            maxExecOutputBytes: 4096
        )
        try await Self.withStubDaemonSocket(workspaceURL: wsURL) { conn, call in
            guard case .exec = call.call else { return }
            let bigChunk = DaemonRPCExecOutputParams(stream: .stdout, data: Data(repeating: 0x41, count: 6000))
            try? conn.writeLineData(try DaemonRPCCodec.encodeExecOutputLine(bigChunk))
            let resp = DaemonRPCResponse<DaemonRPCExecResult>.success(
                id: call.id,
                result: DaemonRPCExecResult(exitCode: 0, timedOut: false)
            )
            try? conn.writeLineData(try DaemonRPCCodec.encodeResponseLine(resp))
            conn.close()
        } body: {
            let cappedOut = try await callMCPTool(
                cappedMCP,
                id: 72,
                name: "agentvm_exec_command",
                arguments: ["vmID": "env-check-vm", "executable": "yes"]
            )
            #expect(cappedOut.isError == true)
            #expect(cappedOut.joinedText.contains("ERR_EXEC_OUTPUT_OVERFLOW"))
        }
    }

    // MARK: - Stub Daemon Unix Socket Helper

    private static func withStubDaemonSocket<T>(
        workspaceURL: URL,
        handler: @escaping @Sendable (DaemonSocketConnection, DaemonRPCRequestEnvelope) -> Void,
        body: () async throws -> T
    ) async throws -> T {
        let paths = DaemonWorkspacePaths(workspaceURL: workspaceURL)
        try FileManager.default.createDirectory(at: paths.runDirectoryURL, withIntermediateDirectories: true)
        let (address, sockAddr) = try DaemonSocketAddressResolver.prepareForBind(workspaceURL: paths.workspaceURL)
        let listener = try DaemonSocketListener.bindResolved(
            address: address,
            sockAddr: sockAddr,
            runDirectoryURL: paths.runDirectoryURL,
            backlog: 8
        )
        let serverHello = DaemonRPCHello(
            executablePath: DaemonExecutableLocator.resolveCurrentExecutablePath()
        )
        let q = DispatchQueue(label: "io.zxu756.agentvm.test.stub-daemon.\(UUID().uuidString)")
        q.async {
            while let conn = try? listener.acceptConnection() {
                let reader = conn.makeLineReader()
                guard let clientHelloLine = try? reader.readLineData(),
                      (try? DaemonRPCCodec.decodeHelloLine(clientHelloLine)) != nil,
                      let encodedHello = try? DaemonRPCCodec.encodeHelloLine(serverHello),
                      (try? conn.writeLineData(encodedHello)) != nil,
                      let reqLine = try? reader.readLineData(),
                      let reqEnv = try? DaemonRPCCodec.decodeRequestLine(reqLine) else {
                    conn.close()
                    continue
                }
                handler(conn, reqEnv)
            }
        }
        defer {
            listener.close(unlinkSocket: true, removeSymlink: true)
        }
        return try await body()
    }
}

// MARK: - Controllable AVM1 Mock Hardware Backend for M4 Stage 3 Tests

private struct M4S3MockExecReply: Sendable {
    var stdout: Data = Data("mock-ok\n".utf8)
    var stderr: Data = Data()
    var exitCode: Int32 = 0
    var timedOut: Bool = false
    var delayNanoseconds: UInt64 = 0
}

private final class M4S3MockHardwareBackend: HardwareVMLowLevelBackend, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var startCount = 0
    private var handlesByVM: [VMID: [M4S3MockVMHandle]] = [:]

    func latestHandle(for vmID: VMID) -> M4S3MockVMHandle? {
        lock.withLock { handlesByVM[vmID]?.last }
    }

    func shutdownAll() {
        let all = lock.withLock { () -> [M4S3MockVMHandle] in
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
        let handle = M4S3MockVMHandle(vmID: spec.id)
        lock.withLock {
            startCount += 1
            handlesByVM[spec.id, default: []].append(handle)
        }
        return handle
    }
}

private final class M4S3MockVMHandle: HardwareVMInstanceHandle, @unchecked Sendable {
    private let vmID: VMID
    private let lock = NSLock()
    private var hostFD: Int32 = -1
    private var peerFD: Int32 = -1
    private var pumpTask: Task<Void, Never>?
    private var execRequests: [GuestExecRequest] = []
    private var execHandler: (@Sendable (GuestExecRequest) -> M4S3MockExecReply)?

    init(vmID: VMID) {
        self.vmID = vmID
    }

    func setExecHandler(_ handler: (@escaping @Sendable (GuestExecRequest) -> M4S3MockExecReply)) {
        lock.withLock { execHandler = handler }
    }

    func recordedExecRequests() -> [GuestExecRequest] {
        lock.withLock { execRequests }
    }

    fileprivate func recordExecRequest(_ req: GuestExecRequest) -> (@Sendable (GuestExecRequest) -> M4S3MockExecReply)? {
        lock.withLock {
            execRequests.append(req)
            return execHandler
        }
    }

    func prematureStopReason() -> String? { nil }

    func connectVsock(port: UInt32) async throws -> HardwareVsockFDDescriptor {
        await closeVsockConnection()
        var fds: [Int32] = [-1, -1]
        guard Darwin.socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(Darwin.errno))
        }
        var one: Int32 = 1
        _ = Darwin.setsockopt(fds[0], SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        _ = Darwin.setsockopt(fds[1], SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        let hFD = fds[0]
        let pFD = fds[1]

        let sender = M4S3GuestWireSender(fd: pFD)
        let task = Task.detached { [weak self] in
            let codec = VsockWireCodec()
            let acc = VsockStreamAccumulator(codec: codec)
            var buf = [UInt8](repeating: 0, count: 65_536)
            var execBuffers: [UInt32: Data] = [:]

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
                        if let pong = try? VsockWireJSON.encode(VsockControlEnvelope(kind: .pong, agentVersion: "2")) {
                            sender.sendFrame(channel: .control, flags: [.ack, .endOfMessage], streamID: 0, payload: pong)
                        }
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
                            let customHandler = self?.recordExecRequest(req)
                            let streamID = header.streamID
                            Task.detached {
                                let reply = customHandler?(req) ?? M4S3MockExecReply()
                                if reply.delayNanoseconds > 0 {
                                    try? await Task.sleep(nanoseconds: reply.delayNanoseconds)
                                }
                                var chunkSeq: UInt32 = 0
                                if !reply.stdout.isEmpty {
                                    chunkSeq += 1
                                    let outChunk = GuestExecOutputChunk(
                                        requestID: req.id,
                                        stream: .stdout,
                                        sequence: chunkSeq,
                                        data: reply.stdout
                                    )
                                    if let p = try? VsockWireJSON.encode(outChunk) {
                                        sender.sendFrame(channel: .execProcess, flags: [.ack], streamID: streamID, payload: p)
                                    }
                                }
                                if !reply.stderr.isEmpty {
                                    chunkSeq += 1
                                    let errChunk = GuestExecOutputChunk(
                                        requestID: req.id,
                                        stream: .stderr,
                                        sequence: chunkSeq,
                                        data: reply.stderr
                                    )
                                    if let p = try? VsockWireJSON.encode(errChunk) {
                                        sender.sendFrame(channel: .execProcess, flags: [.ack], streamID: streamID, payload: p)
                                    }
                                }
                                let done = VsockExecCompletionEnvelope(
                                    requestID: req.id,
                                    exitCode: reply.exitCode,
                                    durationMilliseconds: 2,
                                    timedOut: reply.timedOut
                                )
                                if let p = try? VsockWireJSON.encode(done) {
                                    sender.sendFrame(channel: .execProcess, flags: [.fin, .endOfMessage], streamID: streamID, payload: p)
                                }
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
            pumpTask = task
        }
        return HardwareVsockFDDescriptor(fileDescriptor: hFD, closeWhenSessionEnds: false)
    }

    func forceCloseSockets() {
        let (h, p, t) = lock.withLock { () -> (Int32, Int32, Task<Void, Never>?) in
            let curH = hostFD
            let curP = peerFD
            let curT = pumpTask
            hostFD = -1
            peerFD = -1
            pumpTask = nil
            return (curH, curP, curT)
        }
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
        forceCloseSockets()
    }

    func pause() async throws {}
    func resume() async throws {}
    func saveMachineState(to url: URL) async throws {}

    func shutdown(gracefulTimeoutNanoseconds: UInt64) async {
        forceCloseSockets()
    }
}

private final class M4S3GuestWireSender: @unchecked Sendable {
    private let lock = NSLock()
    private let fd: Int32
    private var seq: UInt32 = 0
    private let codec = VsockWireCodec()

    init(fd: Int32) {
        self.fd = fd
    }

    func sendFrame(channel: VsockChannelKind, flags: VsockFrameFlags, streamID: UInt32, payload: Data) {
        lock.withLock {
            guard fd >= 0 else { return }
            seq &+= 1
            guard let wire = try? codec.encodeFrame(
                channel: channel,
                flags: flags,
                streamID: streamID,
                sequence: seq,
                windowCredit: VsockWireConstants.defaultWindowCredit,
                payload: payload,
                compressIfBeneficial: false
            ) else { return }
            wire.withUnsafeBytes { rawBuf in
                guard let base = rawBuf.baseAddress else { return }
                var written = 0
                while written < rawBuf.count {
                    let n = Darwin.write(fd, base.advanced(by: written), rawBuf.count - written)
                    if n > 0 {
                        written += n
                    } else if n < 0 && Darwin.errno == EINTR {
                        continue
                    } else {
                        break
                    }
                }
            }
        }
    }
}
