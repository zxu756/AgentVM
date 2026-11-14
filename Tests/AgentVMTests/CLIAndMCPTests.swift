import AgentVMCLIAndMCP
import AgentVMHypervisor
import AgentVMModels
import AgentVMNetSwitch
import AgentVMPluginHost
import AgentVMStorageCoW
import AgentVMStore
import Foundation
import Testing

@Suite("M11.7b Headless CLI Runner, MCP JSON-RPC Server & HTML Export", .timeLimit(.minutes(1)))
struct CLIAndMCPTests {

    private func makeTempDirectory(prefix: String = "avm-cli-mcp-tests") throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func haltAllRunningVMs(_ coordinator: AgentVMFleetCoordinator) async {
        guard let vms = try? await coordinator.store.listVMs() else { return }
        for vm in vms where vm.telemetry.state != .stopped {
            _ = try? await coordinator.haltVM(vm.id)
        }
    }

    // MARK: - 1. Headless CLI Runner (`agentvm <subcommand>`)

    @Test("AgentVMCLIRunner help, version, doctor readiness report, and unknown subcommand exit code 64")
    func cliRunnerDoctorHelpVersionAndExitCodes() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-cli-doctor")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let bundleURL = tempDir.appendingPathComponent("CLIDoctor.agentvm", isDirectory: true)
        let cli = AgentVMCLIRunner()

        let helpOut = await cli.execute(arguments: ["--lang", "en", "--help"], bundleURLOverride: bundleURL)
        #expect(helpOut.exitCode == 0)
        #expect(helpOut.stdout.contains("USAGE:"))
        #expect(!helpOut.stdout.contains("20ms"))
        #expect(!helpOut.stdout.contains("20 ms"))

        let helpZh = await cli.execute(arguments: ["--lang", "zh", "--help"], bundleURLOverride: bundleURL)
        #expect(helpZh.exitCode == 0)
        #expect(helpZh.stdout.contains("用法:"))
        #expect(!helpZh.stdout.contains("20ms"))
        #expect(!helpZh.stdout.contains("20 毫秒"))

        let verOut = await cli.execute(arguments: ["--version"], bundleURLOverride: bundleURL)
        #expect(verOut.exitCode == 0)
        #expect(verOut.stdout.contains("agentvm"))

        let doctorOut = await cli.execute(arguments: ["--lang", "en", "doctor"], bundleURLOverride: bundleURL)
        #expect(doctorOut.exitCode == 0)
        #expect(doctorOut.stdout.contains("AgentVM System Readiness Doctor"))
        #expect(doctorOut.stdout.contains("APFS clonefile(2)"))
        #expect(doctorOut.stdout.contains("PASS"))
        #expect(!doctorOut.stdout.contains("20ms"))
        #expect(!doctorOut.stdout.contains("20 ms"))
        #expect(!doctorOut.stdout.contains("SIMULATION FALLBACK"))
        #expect(doctorOut.stdout.contains("Integrity Issues  : 0"))

        let doctorZh = await cli.execute(arguments: ["--lang", "zh", "doctor"], bundleURLOverride: bundleURL)
        #expect(doctorZh.exitCode == 0)
        #expect(doctorZh.stdout.contains("系统就绪自检"))
        #expect(doctorZh.stdout.contains("APFS clonefile(2)"))
        #expect(!doctorZh.stdout.contains("20ms"))
        #expect(!doctorZh.stdout.contains("20 毫秒"))
        #expect(doctorZh.stdout.contains("完整性问题"))

        let unknownOut = await cli.execute(arguments: ["nonexistent-subcmd"], bundleURLOverride: bundleURL)
        #expect(unknownOut.exitCode == 64)
        #expect(unknownOut.stderr.contains("Unknown subcommand") || unknownOut.stderr.contains("未知子命令"))
    }

    @Test("AgentVMCLIRunner plain ps (without --json) does not segfault after create and formats bilingual headers + em-dash telemetry")
    func cliPlainPSDoesNotCrashAndFormatsUnmeasuredTelemetryAndBilingualHeaders() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-cli-ps-plain")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let bundleURL = tempDir.appendingPathComponent("PlainPS.agentvm", isDirectory: true)
        let cli = AgentVMCLIRunner()

        let createOut = await cli.execute(
            arguments: ["--lang", "en", "create", "a"],
            bundleURLOverride: bundleURL
        )
        #expect(createOut.exitCode == 0)

        let psEn = await cli.execute(
            arguments: ["--lang", "en", "ps"],
            bundleURLOverride: bundleURL
        )
        #expect(psEn.exitCode == 0)
        #expect(psEn.stdout.contains("VM_ID"))
        #expect(psEn.stdout.contains("NAME"))
        #expect(psEn.stdout.contains("a"))
        #expect(psEn.stdout.contains("—"))
        #expect(!psEn.stdout.contains("14.5"))
        #expect(!psEn.stdout.contains("640"))

        let psZh = await cli.execute(
            arguments: ["--lang", "zh", "ps"],
            bundleURLOverride: bundleURL
        )
        #expect(psZh.exitCode == 0)
        #expect(psZh.stdout.contains("虚拟机 ID"))
        #expect(psZh.stdout.contains("名称"))
        #expect(psZh.stdout.contains("状态"))
        #expect(psZh.stdout.contains("—"))
    }

    @Test("AgentVMCLIRunner simulated demo end-to-end init --seed-demo, ps --json, create, branch, snapshot, pcap, and policy commands")
    func cliRunnerEndToEndSubcommandWorkflow() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-cli-workflow")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let bundleURL = tempDir.appendingPathComponent("CLIWorkflow.agentvm", isDirectory: true)
        let cli = AgentVMCLIRunner()

        // Pre-seed and immediately halt active port-forward listeners so CLI `init --seed-demo` runs idempotently without orphaned NWListeners
        let seedCoord = try AgentVMFleetCoordinator(
            bundleURL: bundleURL,
            executionBackend: .deterministicSimulation
        )
        try await seedCoord.seedIndustrialDemonstrationFleetIfEmpty()
        await haltAllRunningVMs(seedCoord)

        // 1. `init --seed-demo` via `--workspace` flag (explicit `--lang en` for locale-deterministic English assertions, plus `[DEMO]` marker)
        let initOut = await cli.execute(arguments: ["--lang", "en", "--workspace", bundleURL.path, "init", "--seed-demo"])
        #expect(initOut.exitCode == 0)
        #expect(initOut.stdout.contains("[DEMO]"))
        #expect(initOut.stdout.contains("Initialized workspace"))

        let initZhOut = await cli.execute(arguments: ["--lang", "zh", "--workspace", bundleURL.path, "init", "--seed-demo"])
        #expect(initZhOut.exitCode == 0)
        #expect(initZhOut.stdout.contains("[演示数据]"))

        // 2. `create` an additional blade
        let createOut = await cli.execute(
            arguments: ["--lang", "en", "create", "cli-blade-01", "--owner", "cli-tester", "--cpus", "2", "--memory-mb", "1024"],
            bundleURLOverride: bundleURL
        )
        #expect(createOut.exitCode == 0)
        #expect(createOut.stdout.contains("Created VM 'cli-blade-01'"))

        // 3. `branch` with `--no-boot`
        let branchOut = await cli.execute(
            arguments: ["--lang", "en", "branch", "cli-blade-01", "cli-exp-branch", "--owner", "codex", "--no-boot"],
            bundleURLOverride: bundleURL
        )
        #expect(branchOut.exitCode == 0)
        #expect(branchOut.stdout.contains("Forked CoW branch 'cli-exp-branch'"))

        // 4. `ps --json` decodes cleanly to 5 VMInstanceRecords (3 seeded + 1 created + 1 forked)
        let psOut = await cli.execute(arguments: ["--lang", "en", "ps", "--json"], bundleURLOverride: bundleURL)
        #expect(psOut.exitCode == 0)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decodedVMs = try decoder.decode([VMInstanceRecord].self, from: Data(psOut.stdout.utf8))
        #expect(decodedVMs.count == 5)
        #expect(decodedVMs.contains(where: { $0.spec.name == "cli-exp-branch" }))

        // 5. `snapshot` capture + `snapshot list`
        let snapCaptureOut = await cli.execute(
            arguments: ["--lang", "en", "snapshot", "cli-blade-01", "Pre-Deploy-Milestone"],
            bundleURLOverride: bundleURL
        )
        #expect(snapCaptureOut.exitCode == 0)
        #expect(snapCaptureOut.stdout.contains("Pre-Deploy-Milestone"))

        let snapListOut = await cli.execute(arguments: ["--lang", "en", "snapshot", "list"], bundleURLOverride: bundleURL)
        #expect(snapListOut.exitCode == 0)
        #expect(snapListOut.stdout.contains("Pre-Deploy-Milestone"))

        // 6. `pcap` + `pcap --export` + `policy airgap` / `policy strict`
        let pcapPath = tempDir.appendingPathComponent("cli-export.pcapng")
        let pcapExportOut = await cli.execute(
            arguments: ["--lang", "en", "pcap", "--export", pcapPath.path],
            bundleURLOverride: bundleURL
        )
        #expect(pcapExportOut.exitCode == 0)
        let exportedPCAPData = try Data(contentsOf: pcapPath)
        #expect(exportedPCAPData.count >= 60) // Valid PCAPNG SHB + IDB header blocks

        let pcapTextOut = await cli.execute(arguments: ["--lang", "en", "pcap"], bundleURLOverride: bundleURL)
        #expect(pcapTextOut.exitCode == 0)

        let airgapOut = await cli.execute(arguments: ["--lang", "en", "policy", "airgap"], bundleURLOverride: bundleURL)
        #expect(airgapOut.exitCode == 0)
        #expect(airgapOut.stdout.contains("Total Air-Gap"))

        let strictOut = await cli.execute(arguments: ["--lang", "en", "policy", "strict"], bundleURLOverride: bundleURL)
        #expect(strictOut.exitCode == 0)
        #expect(strictOut.stdout.contains("Strict Coding-Agent Allowlist"))

        let policyListOut = await cli.execute(arguments: ["--lang", "en", "policy"], bundleURLOverride: bundleURL)
        #expect(policyListOut.exitCode == 0)
        #expect(policyListOut.stdout.contains("rules)"))
    }

    @Test("AgentVMCLIRunner simulated export-hcl & export-html verify Hallmark CSS header, Rack-Graphite variables, and zero home-path leak")
    func cliExportHCLAndHallmarkHTMLHomePathScrubbing() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-cli-html")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let bundleURL = tempDir.appendingPathComponent("AuditExport.agentvm", isDirectory: true)
        let coordinator = try AgentVMFleetCoordinator(
            bundleURL: bundleURL,
            executionBackend: .deterministicSimulation
        )

        let homePath = NSHomeDirectory()
        let summary = try await coordinator.createSandboxVM(
            name: "audit-blade-<xss>",
            agentOwnerTag: "security&ops",
            diskVirtualBytes: 16 * 1024 * 1024,
            sharedDirectories: [
                VirtioFSMountSpec(
                    mountTag: "workspace",
                    hostDirectoryPath: "\(homePath)/Projects/ConfidentialRepo",
                    guestMountPoint: "/workspace"
                )
            ]
        )

        // Inject an HTTP packet referencing the raw host home directory path to verify HTML scrubbing
        let crafter = PacketFrameCrafter()
        let srcMAC = MACAddress(parsing: summary.vmRecord.spec.networkInterfaces[0].macAddress) ?? .defaultGateway
        let srcIP = try #require(IPv4Address(parsing: summary.vmRecord.spec.networkInterfaces[0].ipv4Address))
        let homeLeakHTTP = crafter.buildTCPFrame(
            srcMAC: srcMAC,
            dstMAC: .defaultGateway,
            srcIP: srcIP,
            dstIP: IPv4Address(a: 198, b: 51, c: 100, d: 42),
            srcPort: 54100,
            dstPort: 80,
            seq: 500,
            ack: 1,
            flags: [.psh, .ack],
            payload: crafter.buildHTTPRequestPayload(
                method: "GET",
                path: "/v1/secrets/private-key.pem",
                host: "audit.example.com"
            )
        )
        _ = try await coordinator.processOutboundGuestFrame(vmID: summary.vmRecord.id, rawFrame: homeLeakHTTP)

        // 1. Verify live coordinator standalone HTML export (including live wiretap packet rows & VirtioFS home-path scrubbing)
        let directHTML = try await HtmlFleetReportExporter().renderStandaloneHTML(coordinator: coordinator)
        #expect(directHTML.lowercased().contains("hallmark · v2.0.0"))
        #expect(directHTML.contains("--bg-chassis: #141517"))
        #expect(directHTML.contains("audit-blade-&lt;xss&gt;"))
        #expect(directHTML.contains("@security&amp;ops"))
        #expect(directHTML.contains("~/Projects/ConfidentialRepo"))
        #expect(!directHTML.contains(homePath))

        // 2. Verify CLI `export-hcl` and `export-html <path>` subcommands
        let cli = AgentVMCLIRunner()
        let hclOut = await cli.execute(arguments: ["export-hcl"], bundleURLOverride: bundleURL)
        #expect(hclOut.exitCode == 0)
        #expect(hclOut.stdout.contains("firewall_policy"))
        #expect(hclOut.stdout.contains("sandbox_vm \"audit-blade--xss\""))
        #expect(!hclOut.stdout.contains(homePath))
        #expect(hclOut.stdout.contains("~/Projects/ConfidentialRepo"))

        let htmlOutURL = tempDir.appendingPathComponent("fleet-security-report.html")
        let htmlCLIOut = await cli.execute(
            arguments: ["export-html", htmlOutURL.path],
            bundleURLOverride: bundleURL
        )
        #expect(htmlCLIOut.exitCode == 0)
        let diskHTML = try String(contentsOf: htmlOutURL, encoding: .utf8)
        #expect(diskHTML.lowercased().contains("hallmark · v2.0.0"))
        #expect(!diskHTML.contains(homePath))
    }

    // MARK: - 2. JSON-RPC 2.0 Model Context Protocol (`AgentVMMCPServer`)

    @Test("AgentVMMCPServer simulated JSON-RPC initialize, notifications/initialized, tools/list, and -32601 error handling")
    func mcpServerProtocolHandshakeAndToolsCatalog() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-mcp-handshake")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let coordinator = try AgentVMFleetCoordinator(
            bundleURL: tempDir.appendingPathComponent("MCPHandshake.agentvm", isDirectory: true),
            executionBackend: .deterministicSimulation
        )
        let mcp = AgentVMMCPServer(coordinator: coordinator)

        // 1. `initialize`
        let initRaw = try #require(await mcp.handleJSONRPCLine(
            #"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#
        ))
        let initJSON = try #require(try JSONSerialization.jsonObject(with: Data(initRaw.utf8)) as? [String: Any])
        #expect(initJSON["id"] as? Int == 1)
        let initResult = try #require(initJSON["result"] as? [String: Any])
        #expect(initResult["protocolVersion"] as? String == "2024-11-05")
        let serverInfo = try #require(initResult["serverInfo"] as? [String: Any])
        #expect(serverInfo["name"] as? String == "agentvm-mcp")

        // 2. `notifications/initialized` returns nil (no JSON-RPC response emitted for notifications)
        let notifResp = await mcp.handleJSONRPCLine(#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
        #expect(notifResp == nil)

        // 3. `tools/list` exposes all 9 AgentVM MCP tools
        let listRaw = try #require(await mcp.handleJSONRPCLine(
            #"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#
        ))
        let listJSON = try #require(try JSONSerialization.jsonObject(with: Data(listRaw.utf8)) as? [String: Any])
        let listResult = try #require(listJSON["result"] as? [String: Any])
        let tools = try #require(listResult["tools"] as? [[String: Any]])
        #expect(tools.count == 9)
        let toolNames = Set(tools.compactMap { $0["name"] as? String })
        #expect(toolNames.contains("agentvm_list_fleet"))
        #expect(toolNames.contains("agentvm_create_vm"))
        #expect(toolNames.contains("agentvm_fork_cow_branch"))
        #expect(toolNames.contains("agentvm_query_wiretap"))
        #expect(toolNames.contains("agentvm_doctor"))

        // 4. Unknown JSON-RPC method returns standard -32601 error object
        let errRaw = try #require(await mcp.handleJSONRPCLine(
            #"{"jsonrpc":"2.0","id":99,"method":"resources/nonexistent"}"#
        ))
        let errJSON = try #require(try JSONSerialization.jsonObject(with: Data(errRaw.utf8)) as? [String: Any])
        let errorObj = try #require(errJSON["error"] as? [String: Any])
        #expect(errorObj["code"] as? Int == -32601)
    }

    @Test("AgentVMMCPServer simulated tools/call dispatches create_vm, list_fleet, fork_cow_branch, query_wiretap, and structured errors")
    func mcpServerToolsCallEndToEndDispatch() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-mcp-tools")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let coordinator = try AgentVMFleetCoordinator(
            bundleURL: tempDir.appendingPathComponent("MCPTools.agentvm", isDirectory: true),
            executionBackend: .deterministicSimulation
        )
        let mcp = AgentVMMCPServer(coordinator: coordinator)

        func callTool(id: Int, name: String, arguments: [String: Any]) async throws -> (isError: Bool, text: String) {
            let payload: [String: Any] = [
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": [
                    "name": name,
                    "arguments": arguments
                ]
            ]
            let line = String(decoding: try JSONSerialization.data(withJSONObject: payload), as: UTF8.self)
            let rawResp = try #require(await mcp.handleJSONRPCLine(line))
            let obj = try #require(try JSONSerialization.jsonObject(with: Data(rawResp.utf8)) as? [String: Any])
            let res = try #require(obj["result"] as? [String: Any])
            let isErr = (res["isError"] as? Bool) ?? false
            let content = try #require(res["content"] as? [[String: Any]])
            let text = (content.first?["text"] as? String) ?? ""
            return (isErr, text)
        }

        // 1. `agentvm_create_vm`
        let created = try await callTool(
            id: 10,
            name: "agentvm_create_vm",
            arguments: ["name": "mcp-primary", "owner": "claude-mcp", "vcpus": 2, "memoryMB": 1024]
        )
        #expect(created.isError == false)
        #expect(created.text.contains("mcp-primary"))

        // 2. `agentvm_list_fleet`
        let listed = try await callTool(id: 11, name: "agentvm_list_fleet", arguments: [:])
        #expect(listed.isError == false)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let fleet = try decoder.decode([VMInstanceRecord].self, from: Data(listed.text.utf8))
        let parentVM = try #require(fleet.first)
        #expect(parentVM.spec.name == "mcp-primary")

        // 3. `agentvm_fork_cow_branch` (with bootImmediately: false when testing pure CoW branch creation; here simulated backend boots simulated responder)
        let forked = try await callTool(
            id: 12,
            name: "agentvm_fork_cow_branch",
            arguments: [
                "parentVMID": parentVM.id.rawValue,
                "branchName": "mcp-child-branch",
                "owner": "codex-mcp"
            ]
        )
        #expect(forked.isError == false)
        #expect(forked.text.contains("mcp-child-branch"))

        // 4. Seed demo L2 packets and query with `agentvm_query_wiretap` boolean filter
        _ = try await coordinator.l2Switch.seedDemonstrationTraffic(for: parentVM.id)
        let wiretap = try await callTool(
            id: 13,
            name: "agentvm_query_wiretap",
            arguments: ["filter": "proto == DNS || proto == TLS", "limit": 20]
        )
        #expect(wiretap.isError == false)
        #expect(wiretap.text.contains("[DNS]") || wiretap.text.contains("[TLSv1.3]"))

        // 5. Missing VM error returns `isError: true` with `ERR_VM_NOT_FOUND`
        let missing = try await callTool(
            id: 14,
            name: "agentvm_fork_cow_branch",
            arguments: ["parentVMID": "vm-does-not-exist", "branchName": "orphan"]
        )
        #expect(missing.isError == true)
        #expect(missing.text.contains("ERR_VM_NOT_FOUND"))

        await haltAllRunningVMs(coordinator)
    }

    @Test("CLI up and exec fail honestly without --backend simulation, while explicit --backend simulation prefixes SIMULATED")
    func cliHonestUpAndExecFailWithoutSimulationAndExplicitSimulationAddsPrefix() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-cli-honest-exec")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let bundleURL = tempDir.appendingPathComponent("HonestCLI.agentvm", isDirectory: true)
        let cli = AgentVMCLIRunner()

        let createOut = await cli.execute(
            arguments: ["--lang", "en", "create", "a"],
            bundleURLOverride: bundleURL
        )
        #expect(createOut.exitCode == 0)

        // 1. `up a` without `--backend simulation` fails in English & Chinese and leaves state != running
        let upEn = await cli.execute(
            arguments: ["--lang", "en", "up", "a"],
            bundleURLOverride: bundleURL
        )
        #expect(upEn.exitCode != 0)
        #expect(upEn.stderr.lowercased().contains("bootable"))
        #expect(upEn.stdout.isEmpty)

        let upZh = await cli.execute(
            arguments: ["--lang", "zh", "up", "a"],
            bundleURLOverride: bundleURL
        )
        #expect(upZh.exitCode != 0)
        #expect(upZh.stderr.contains("可引导") || upZh.stderr.contains("引导"))

        let psJSON = await cli.execute(
            arguments: ["ps", "--json"],
            bundleURLOverride: bundleURL
        )
        #expect(psJSON.exitCode == 0)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let vms = try decoder.decode([VMInstanceRecord].self, from: Data(psJSON.stdout.utf8))
        let vmA = try #require(vms.first(where: { $0.spec.name == "a" }))
        #expect(vmA.telemetry.state != .running)
        #expect(vmA.telemetry.guestAgentConnected == false)

        // 2. `exec a -- uname -a` without `--backend simulation` fails with zero Linux kernel output
        let execEn = await cli.execute(
            arguments: ["--lang", "en", "exec", "a", "--", "uname", "-a"],
            bundleURLOverride: bundleURL
        )
        #expect(execEn.exitCode != 0)
        #expect(!execEn.stdout.contains("Linux"))
        #expect(!execEn.stderr.contains("Linux 6."))
        #expect(!execEn.stderr.isEmpty)

        let execZh = await cli.execute(
            arguments: ["--lang", "zh", "exec", "a", "--", "uname", "-a"],
            bundleURLOverride: bundleURL
        )
        #expect(execZh.exitCode != 0)
        #expect(!execZh.stdout.contains("Linux"))
        #expect(execZh.stderr.contains("可引导") || execZh.stderr.contains("客户机"))

        // 3. Explicit `--backend simulation exec a -- uname -a` exits 0 and prefixes every line with SIMULATED
        let simBundleURL = tempDir.appendingPathComponent("ExplicitSimCLI.agentvm", isDirectory: true)
        _ = await cli.execute(arguments: ["create", "a"], bundleURLOverride: simBundleURL)
        let simExec = await cli.execute(
            arguments: ["--backend", "simulation", "exec", "a", "--", "uname", "-a"],
            bundleURLOverride: simBundleURL
        )
        #expect(simExec.exitCode == 0)
        let nonEmptyLines = simExec.stdout
            .split(separator: "\n", omittingEmptySubsequences: true)
            .map(String.init)
        #expect(!nonEmptyLines.isEmpty)
        for line in nonEmptyLines {
            #expect(line.hasPrefix("SIMULATED:"))
        }

        // Second consecutive CLI invocation on the same workspace must re-attach simulated responder cleanly
        let simExecSecond = await cli.execute(
            arguments: ["--lang", "zh", "--backend", "simulation", "exec", "a", "--", "uname", "-a"],
            bundleURLOverride: simBundleURL
        )
        #expect(simExecSecond.exitCode == 0)
        #expect(simExecSecond.stdout.hasPrefix("SIMULATED:"))
    }

    @Test("MCP server with default backend rejects agentvm_exec_command on empty disk without falling back to simulator")
    func mcpDefaultBackendRejectsExecWithoutSimulation() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-mcp-honest")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let coordinator = try AgentVMFleetCoordinator(
            bundleURL: tempDir.appendingPathComponent("MCPDefault.agentvm", isDirectory: true)
        )
        let mcp = AgentVMMCPServer(coordinator: coordinator)
        let vm = try await coordinator.createSandboxVM(name: "mcp-empty", diskVirtualBytes: 16 * 1024 * 1024).vmRecord

        let payload: [String: Any] = [
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": [
                "name": "agentvm_exec_command",
                "arguments": [
                    "vmID": vm.id.rawValue,
                    "executable": "uname",
                    "arguments": ["-a"]
                ]
            ]
        ]
        let line = String(decoding: try JSONSerialization.data(withJSONObject: payload), as: UTF8.self)
        let rawResp = try #require(await mcp.handleJSONRPCLine(line))
        let obj = try #require(try JSONSerialization.jsonObject(with: Data(rawResp.utf8)) as? [String: Any])
        let res = try #require(obj["result"] as? [String: Any])
        #expect(res["isError"] as? Bool == true)
        let content = try #require(res["content"] as? [[String: Any]])
        let text = (content.first?["text"] as? String) ?? ""
        #expect(text.contains("ERR_NO_BOOTABLE_SYSTEM"))
        #expect(!text.contains("Linux 6."))
    }
}
