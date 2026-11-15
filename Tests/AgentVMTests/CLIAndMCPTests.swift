import AgentVMCLIAndMCP
import AgentVMHypervisor
import AgentVMModels
import AgentVMNetSwitch
import AgentVMPluginHost
import AgentVMStorageCoW
import AgentVMStore
import Darwin
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

    // MARK: - 5. M1 Image Catalog CLI (`agentvm image list`, `image pull`, `image verify`)

    private func cliPosixStat(_ url: URL) throws -> Darwin.stat {
        var st = Darwin.stat()
        guard stat(url.path, &st) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        return st
    }

    @Test("M1 CLI: 'agentvm image list' reports supported Debian vs unsupported entries, supports --json and --lang zh, validates usage, and creates zero workspace files")
    func cliImageListSupportedUnsupportedAndNoDefaultWorkspaceSideEffects() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-cli-img-list")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let mockHome = tempDir.appendingPathComponent("mock-home", isDirectory: true)
        let cacheDir = tempDir.appendingPathComponent("shared-cache", isDirectory: true)
        let env = [
            "HOME": mockHome.path,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()

        // 1. Help banner mentions `image`
        let helpEn = await cli.execute(arguments: ["--lang", "en", "help"], environment: env)
        #expect(helpEn.exitCode == 0)
        #expect(helpEn.stdout.contains("image"))

        let helpZh = await cli.execute(arguments: ["--lang", "zh", "help"], environment: env)
        #expect(helpZh.exitCode == 0)
        #expect(helpZh.stdout.contains("image"))

        // 2. English `image list` (without --workspace!) must NOT materialize DefaultFleet.agentvm or cacheDir
        let listEn = await cli.execute(arguments: ["--lang", "en", "image", "list"], environment: env)
        #expect(listEn.exitCode == 0)
        #expect(listEn.stderr.isEmpty)
        #expect(listEn.stdout.contains("debian-12-bookworm-arm64"))
        #expect(listEn.stdout.contains("SUPPORTED"))
        #expect(listEn.stdout.contains("NOT CACHED"))
        #expect(listEn.stdout.contains("ubuntu-24.04-noble-arm64"))
        #expect(listEn.stdout.contains("UNSUPPORTED"))
        #expect(!FileManager.default.fileExists(atPath: mockHome.path))
        #expect(!FileManager.default.fileExists(atPath: cacheDir.path))

        // 3. Chinese `image list`
        let listZh = await cli.execute(arguments: ["--lang", "zh", "image", "list"], environment: env)
        #expect(listZh.exitCode == 0)
        #expect(listZh.stdout.contains("debian-12-bookworm-arm64"))
        #expect(listZh.stdout.contains("可用") || listZh.stdout.contains("支持"))
        #expect(listZh.stdout.contains("未缓存"))
        #expect(listZh.stdout.contains("暂不支持"))

        // 4. `image list --json`
        let listJSON = await cli.execute(arguments: ["--lang", "en", "image", "list", "--json"], environment: env)
        #expect(listJSON.exitCode == 0)
        let jsonArray = try #require(
            try JSONSerialization.jsonObject(with: Data(listJSON.stdout.utf8)) as? [[String: Any]]
        )
        #expect(jsonArray.count == 6)
        let debianObj = try #require(jsonArray.first(where: { ($0["id"] as? String) == "debian-12-bookworm-arm64" }))
        #expect(debianObj["supported"] as? Bool == true)
        #expect(debianObj["cached"] as? Bool == false)
        #expect(debianObj["expectedSizeBytes"] as? UInt64 == 3_221_225_472 || (debianObj["expectedSizeBytes"] as? Int) == 3_221_225_472)

        for item in jsonArray where (item["id"] as? String) != "debian-12-bookworm-arm64" {
            #expect(item["supported"] as? Bool == false)
            #expect(item["cached"] as? Bool == false)
        }

        // 5. `--backend simulation image list --json` carries simulated markers
        let simJSON = await cli.execute(
            arguments: ["--backend", "simulation", "--lang", "en", "image", "list", "--json"],
            environment: env
        )
        #expect(simJSON.exitCode == 0)
        #expect(simJSON.stderr.hasPrefix("SIMULATED:"))
        let simArr = try #require(
            try JSONSerialization.jsonObject(with: Data(simJSON.stdout.utf8)) as? [[String: Any]]
        )
        for item in simArr {
            #expect(item["simulated"] as? Bool == true)
        }

        // 6. Strict grammar validation: missing/unknown sub-actions, extra args, or disallowed flags exit 2
        let badInvocations: [[String]] = [
            ["image"],
            ["image", "bogus"],
            ["image", "list", "extra"],
            ["image", "pull"],
            ["image", "pull", "debian-12-bookworm-arm64", "extra"],
            ["image", "pull", "debian-12-bookworm-arm64", "--json"],
            ["image", "verify"],
            ["image", "verify", "debian-12-bookworm-arm64", "extra"],
            ["image", "verify", "debian-12-bookworm-arm64", "--json"],
            ["image", "list", "--bogus"]
        ]
        for badArgs in badInvocations {
            let res = await cli.execute(arguments: badArgs, environment: env)
            #expect(
                res.exitCode == AgentVMCLIRunner.usageErrorExitCode,
                "Expected usage exit code 2 for \(badArgs), got \(res.exitCode)"
            )
        }
    }

    @Test("M1 CLI: 'agentvm image pull' offline URLProtocol scenarios (unsupported, Range 206 resume, 200 restart, checksum mismatch, http redirect rejected)")
    func cliImagePullOfflineStubScenarios() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-cli-img-pull")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let mockHome = tempDir.appendingPathComponent("mock-home", isDirectory: true)
        let cli = AgentVMCLIRunner()

        let payloadSize = 2 * 1024 * 1024 // 2 MiB
        var raw = [UInt8](repeating: 0, count: payloadSize)
        for i in 0..<payloadSize {
            raw[i] = UInt8((i &* 71 &+ 29) & 0xFF)
        }
        let payload = Data(raw)
        let expectedSHA512 = BinaryChecksums.sha512Hex(payload)

        // 1. Unsupported entry fails non-zero and makes zero network requests
        do {
            let sessionID = UUID().uuidString
            let config = CLIImageStubURLProtocol.makeSessionConfiguration(sessionID: sessionID) { req in
                Issue.record("Unsupported image pull must not contact network: \(req.url?.absoluteString ?? "")")
                throw URLError(.cannotConnectToHost)
            }
            defer { CLIImageStubURLProtocol.unregister(sessionID: sessionID) }

            let cacheDir = tempDir.appendingPathComponent("cache-unsupported", isDirectory: true)
            let pullEn = await cli.execute(
                arguments: ["--lang", "en", "image", "pull", "ubuntu-24.04-noble-arm64"],
                imageCacheURLOverride: cacheDir,
                urlSessionConfiguration: config,
                environment: ["HOME": mockHome.path]
            )
            #expect(pullEn.exitCode != 0)
            #expect(pullEn.stderr.contains("ERR_IMAGE_UNSUPPORTED"))
            #expect(pullEn.stderr.lowercased().contains("not yet supported") || pullEn.stderr.lowercased().contains("unsupported"))
            #expect(CLIImageStubURLProtocol.recordedRequests(sessionID: sessionID).isEmpty)

            let pullZh = await cli.execute(
                arguments: ["--lang", "zh", "image", "pull", "fedora-cloud-41-arm64"],
                imageCacheURLOverride: cacheDir,
                urlSessionConfiguration: config,
                environment: ["HOME": mockHome.path]
            )
            #expect(pullZh.exitCode != 0)
            #expect(pullZh.stderr.contains("暂不支持"))
            #expect(CLIImageStubURLProtocol.recordedRequests(sessionID: sessionID).isEmpty)
        }

        // 2. Resume partial download with HTTP 206 + progress written to stderr + 0444 final mode
        do {
            let sessionID = UUID().uuidString
            let splitOffset = 786_432 // 768 KiB already in .part
            let stubURL = "https://cdn.stub.agentvm.invalid/bookworm/debian-12.raw"
            let config = CLIImageStubURLProtocol.makeSessionConfiguration(sessionID: sessionID) { req in
                #expect(req.value(forHTTPHeaderField: "Range") == "bytes=\(splitOffset)-")
                let rest = payload.subdata(in: splitOffset..<payloadSize)
                let resp = HTTPURLResponse(
                    url: req.url!,
                    statusCode: 206,
                    httpVersion: "HTTP/1.1",
                    headerFields: [
                        "Content-Range": "bytes \(splitOffset)-\(payloadSize - 1)/\(payloadSize)",
                        "Content-Length": "\(rest.count)"
                    ]
                )!
                return .chunks(response: resp, chunks: [rest])
            }
            defer { CLIImageStubURLProtocol.unregister(sessionID: sessionID) }

            let cacheDir = tempDir.appendingPathComponent("cache-206", isDirectory: true)
            try FileManager.default.createDirectory(at: cacheDir, withIntermediateDirectories: true)
            let partURL = cacheDir.appendingPathComponent("debian-12-bookworm-arm64.raw.part")
            try payload.prefix(splitOffset).write(to: partURL)

            let entry = BaseImageCatalogEntry(
                id: "debian-12-bookworm-arm64",
                displayName: "Debian CLI 206",
                distribution: "debian",
                version: "20261112-2660",
                guestOS: .linuxARM64,
                isSupported: true,
                downloadURL: stubURL,
                expectedSHA512: expectedSHA512,
                expectedSizeBytes: UInt64(payloadSize),
                defaultVirtualSizeBytes: UInt64(payloadSize)
            )

            let streamed = CLILockedStringBox()
            let res = await cli.execute(
                arguments: ["--lang", "en", "image", "pull", "debian-12-bookworm-arm64"],
                imageCacheURLOverride: cacheDir,
                curatedEntriesOverride: [entry],
                urlSessionConfiguration: config,
                environment: ["HOME": mockHome.path],
                liveStderrHandler: { streamed.append($0) }
            )
            #expect(res.exitCode == 0)
            #expect(!res.stderr.isEmpty, "Progress must be written to stderr")
            #expect(streamed.value() == res.stderr)
            #expect(!FileManager.default.fileExists(atPath: partURL.path))

            let finalURL = cacheDir.appendingPathComponent("debian-12-bookworm-arm64.raw")
            #expect(try Data(contentsOf: finalURL) == payload)
            let st = try cliPosixStat(finalURL)
            #expect((st.st_mode & 0o777) == 0o444)
        }

        // 3. Server ignores Range and returns 200 -> truncates .part and succeeds
        do {
            let sessionID = UUID().uuidString
            let stubURL = "https://cdn200.stub.agentvm.invalid/bookworm/debian-12.raw"
            let config = CLIImageStubURLProtocol.makeSessionConfiguration(sessionID: sessionID) { req in
                #expect(req.value(forHTTPHeaderField: "Range") == "bytes=262144-")
                let resp = HTTPURLResponse(url: req.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
                return .chunks(response: resp, chunks: [payload])
            }
            defer { CLIImageStubURLProtocol.unregister(sessionID: sessionID) }

            let cacheDir = tempDir.appendingPathComponent("cache-200", isDirectory: true)
            try FileManager.default.createDirectory(at: cacheDir, withIntermediateDirectories: true)
            let partURL = cacheDir.appendingPathComponent("debian-12-bookworm-arm64.raw.part")
            try Data(repeating: 0xAA, count: 262_144).write(to: partURL)

            let entry = BaseImageCatalogEntry(
                id: "debian-12-bookworm-arm64",
                displayName: "Debian CLI 200",
                distribution: "debian",
                version: "20261112-2660",
                guestOS: .linuxARM64,
                isSupported: true,
                downloadURL: stubURL,
                expectedSHA512: expectedSHA512,
                expectedSizeBytes: UInt64(payloadSize),
                defaultVirtualSizeBytes: UInt64(payloadSize)
            )

            let res = await cli.execute(
                arguments: ["--lang", "en", "image", "pull", "debian-12-bookworm-arm64"],
                imageCacheURLOverride: cacheDir,
                curatedEntriesOverride: [entry],
                urlSessionConfiguration: config,
                environment: ["HOME": mockHome.path]
            )
            #expect(res.exitCode == 0)
            #expect(!FileManager.default.fileExists(atPath: partURL.path))
            #expect(try Data(contentsOf: cacheDir.appendingPathComponent("debian-12-bookworm-arm64.raw")) == payload)
        }

        // 4. Checksum mismatch deletes .part and exits non-zero; redirect to http:// rejected
        do {
            let sessionID = UUID().uuidString
            let mismatchURL = "https://badsum.stub.agentvm.invalid/debian.raw"
            let redirectStartURL = "https://redirect.stub.agentvm.invalid/debian.raw"
            let redirectPlainHTTP = "http://mirror.stub.agentvm.invalid/debian.raw"
            let config = CLIImageStubURLProtocol.makeSessionConfiguration(sessionID: sessionID) { req in
                let u = req.url?.absoluteString ?? ""
                if u == mismatchURL {
                    var bad = payload
                    bad[0] ^= 0xFF
                    let resp = HTTPURLResponse(url: req.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
                    return .chunks(response: resp, chunks: [bad])
                } else if u == redirectStartURL {
                    let resp = HTTPURLResponse(
                        url: req.url!,
                        statusCode: 302,
                        httpVersion: "HTTP/1.1",
                        headerFields: ["Location": redirectPlainHTTP]
                    )!
                    return .redirect(response: resp, newURL: URL(string: redirectPlainHTTP)!)
                }
                Issue.record("Must never follow plain http:// redirect: \(u)")
                throw URLError(.badURL)
            }
            defer { CLIImageStubURLProtocol.unregister(sessionID: sessionID) }

            let badSumCache = tempDir.appendingPathComponent("cache-badsum", isDirectory: true)
            let badSumRes = await cli.execute(
                arguments: ["--lang", "en", "image", "pull", "debian-12-bookworm-arm64"],
                imageCacheURLOverride: badSumCache,
                curatedEntriesOverride: [
                    BaseImageCatalogEntry(
                        id: "debian-12-bookworm-arm64",
                        displayName: "Debian Bad Sum",
                        distribution: "debian",
                        version: "20261112-2660",
                        guestOS: .linuxARM64,
                        isSupported: true,
                        downloadURL: mismatchURL,
                        expectedSHA512: expectedSHA512,
                        expectedSizeBytes: UInt64(payloadSize)
                    )
                ],
                urlSessionConfiguration: config,
                environment: ["HOME": mockHome.path]
            )
            #expect(badSumRes.exitCode != 0)
            #expect(badSumRes.stderr.contains("ERR_IMAGE_CHECKSUM_MISMATCH"))
            #expect(!FileManager.default.fileExists(atPath: badSumCache.appendingPathComponent("debian-12-bookworm-arm64.raw.part").path))

            let httpRedirectCache = tempDir.appendingPathComponent("cache-http-redir", isDirectory: true)
            let redirRes = await cli.execute(
                arguments: ["--lang", "en", "image", "pull", "debian-12-bookworm-arm64"],
                imageCacheURLOverride: httpRedirectCache,
                curatedEntriesOverride: [
                    BaseImageCatalogEntry(
                        id: "debian-12-bookworm-arm64",
                        displayName: "Debian HTTP Redirect",
                        distribution: "debian",
                        version: "20261112-2660",
                        guestOS: .linuxARM64,
                        isSupported: true,
                        downloadURL: redirectStartURL,
                        expectedSHA512: expectedSHA512,
                        expectedSizeBytes: UInt64(payloadSize)
                    )
                ],
                urlSessionConfiguration: config,
                environment: ["HOME": mockHome.path]
            )
            #expect(redirRes.exitCode != 0)
            #expect(redirRes.stderr.contains("ERR_IMAGE_INSECURE_URL"))
        }
    }

    @Test("M1 CLI: local 3 MiB file exercises 'agentvm image verify' (valid, missing, APFS clone 1-byte flip) and cache-hit 'agentvm image pull' without network")
    func cliImageVerifyAndCacheHitPullWithLocalMultiMBFile() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-cli-3mb-verify")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let mockHome = tempDir.appendingPathComponent("mock-home", isDirectory: true)
        let cacheDir = tempDir.appendingPathComponent("shared-images", isDirectory: true)
        let env = [
            "HOME": mockHome.path,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()

        let fileSize = 3 * 1024 * 1024 // 3 MiB local file
        var bytes = [UInt8](repeating: 0, count: fileSize)
        for i in 0..<fileSize {
            bytes[i] = UInt8((i &* 37 &+ 11) & 0xFF)
        }
        let localData = Data(bytes)
        let expectedSHA512 = BinaryChecksums.sha512Hex(localData)

        let entry = BaseImageCatalogEntry(
            id: "debian-12-bookworm-arm64",
            displayName: "Debian 12 Local 3 MiB Fixture",
            distribution: "debian",
            version: "20261112-2660",
            guestOS: .linuxARM64,
            isSupported: true,
            downloadURL: "https://offline-fixture.stub.agentvm.invalid/debian-3mb.raw",
            expectedSHA512: expectedSHA512,
            expectedSizeBytes: UInt64(fileSize),
            defaultVirtualSizeBytes: UInt64(fileSize)
        )
        let unsupportedEntry = BaseImageCatalogEntry(
            id: "ubuntu-24.04-noble-arm64",
            displayName: "Ubuntu Unsupported",
            distribution: "ubuntu",
            version: "24.04",
            guestOS: .linuxARM64,
            isSupported: false
        )
        let fixtures = [entry, unsupportedEntry]

        let noNetSession = UUID().uuidString
        let noNetConfig = CLIImageStubURLProtocol.makeSessionConfiguration(sessionID: noNetSession) { req in
            Issue.record("Must NOT make network requests during verify or cache-hit pull: \(req.url?.absoluteString ?? "")")
            throw URLError(.notConnectedToInternet)
        }
        defer { CLIImageStubURLProtocol.unregister(sessionID: noNetSession) }

        // 1. Before caching: `image verify` fails non-zero (missing file & unsupported entry) without touching network
        let missingVerify = await cli.execute(
            arguments: ["--lang", "en", "image", "verify", "debian-12-bookworm-arm64"],
            curatedEntriesOverride: fixtures,
            urlSessionConfiguration: noNetConfig,
            environment: env
        )
        #expect(missingVerify.exitCode != 0)
        #expect(missingVerify.stderr.contains("ERR_IMAGE_NOT_CACHED"))

        let unsupportedVerify = await cli.execute(
            arguments: ["--lang", "en", "image", "verify", "ubuntu-24.04-noble-arm64"],
            curatedEntriesOverride: fixtures,
            urlSessionConfiguration: noNetConfig,
            environment: env
        )
        #expect(unsupportedVerify.exitCode != 0)
        #expect(unsupportedVerify.stderr.contains("ERR_IMAGE_UNSUPPORTED"))

        // 2. Seed cache via initial offline pull
        do {
            let seedSession = UUID().uuidString
            let seedConfig = CLIImageStubURLProtocol.makeSessionConfiguration(sessionID: seedSession) { req in
                let resp = HTTPURLResponse(url: req.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
                return .chunks(response: resp, chunks: [localData])
            }
            defer { CLIImageStubURLProtocol.unregister(sessionID: seedSession) }

            let firstPull = await cli.execute(
                arguments: ["--lang", "en", "image", "pull", "debian-12-bookworm-arm64"],
                curatedEntriesOverride: fixtures,
                urlSessionConfiguration: seedConfig,
                environment: env
            )
            #expect(firstPull.exitCode == 0)
        }

        // `image list` now reports CACHED / 已缓存
        let listAfterEn = await cli.execute(
            arguments: ["--lang", "en", "image", "list"],
            curatedEntriesOverride: fixtures,
            urlSessionConfiguration: noNetConfig,
            environment: env
        )
        #expect(listAfterEn.exitCode == 0)
        #expect(listAfterEn.stdout.contains("CACHED"))
        #expect(!listAfterEn.stdout.contains("NOT CACHED"))

        let listAfterZh = await cli.execute(
            arguments: ["--lang", "zh", "image", "list"],
            curatedEntriesOverride: fixtures,
            urlSessionConfiguration: noNetConfig,
            environment: env
        )
        #expect(listAfterZh.exitCode == 0)
        #expect(listAfterZh.stdout.contains("已缓存"))

        let cachedRawURL = cacheDir.appendingPathComponent("debian-12-bookworm-arm64.raw")
        let indexURL = cacheDir.appendingPathComponent("catalog-index.json")
        let statBefore = try cliPosixStat(cachedRawURL)
        let indexStatBefore = try cliPosixStat(indexURL)

        // 3. `image verify` on valid 3 MiB cached file exits 0, makes 0 network calls, and leaves cache untouched
        let verifyOk = await cli.execute(
            arguments: ["--lang", "en", "image", "verify", "debian-12-bookworm-arm64"],
            curatedEntriesOverride: fixtures,
            urlSessionConfiguration: noNetConfig,
            environment: env
        )
        #expect(verifyOk.exitCode == 0)
        #expect(verifyOk.stdout.contains(expectedSHA512))
        #expect(CLIImageStubURLProtocol.recordedRequests(sessionID: noNetSession).isEmpty)

        // 4. Second `image pull` hits verified cache: exits 0 immediately, says already cached, 0 network calls, inode & mtime unchanged
        let secondPullEn = await cli.execute(
            arguments: ["--lang", "en", "image", "pull", "debian-12-bookworm-arm64"],
            curatedEntriesOverride: fixtures,
            urlSessionConfiguration: noNetConfig,
            environment: env
        )
        #expect(secondPullEn.exitCode == 0)
        #expect(
            secondPullEn.stdout.lowercased().contains("already")
                || secondPullEn.stderr.lowercased().contains("already")
        )
        #expect(CLIImageStubURLProtocol.recordedRequests(sessionID: noNetSession).isEmpty)

        let secondPullZh = await cli.execute(
            arguments: ["--lang", "zh", "image", "pull", "debian-12-bookworm-arm64"],
            curatedEntriesOverride: fixtures,
            urlSessionConfiguration: noNetConfig,
            environment: env
        )
        #expect(secondPullZh.exitCode == 0)
        #expect(secondPullZh.stdout.contains("已在") || secondPullZh.stdout.contains("已缓存"))

        let statAfter = try cliPosixStat(cachedRawURL)
        let indexStatAfter = try cliPosixStat(indexURL)
        #expect(statAfter.st_ino == statBefore.st_ino)
        #expect(statAfter.st_mtimespec.tv_sec == statBefore.st_mtimespec.tv_sec)
        #expect(statAfter.st_mtimespec.tv_nsec == statBefore.st_mtimespec.tv_nsec)
        #expect(indexStatAfter.st_mtimespec.tv_sec == indexStatBefore.st_mtimespec.tv_sec)
        #expect(indexStatAfter.st_mtimespec.tv_nsec == indexStatBefore.st_mtimespec.tv_nsec)

        // 5. Copy cached file via clonefile into a separate temp cache dir (without catalog-index.json), flip 1 byte -> `image verify` fails non-zero & writes mismatch to stderr
        let tamperedCacheDir = tempDir.appendingPathComponent("tampered-copy-cache", isDirectory: true)
        try FileManager.default.createDirectory(at: tamperedCacheDir, withIntermediateDirectories: true)
        let tamperedRawURL = tamperedCacheDir.appendingPathComponent("debian-12-bookworm-arm64.raw")
        #expect(Darwin.clonefile(cachedRawURL.path, tamperedRawURL.path, 0) == 0)
        #expect(Darwin.chmod(tamperedRawURL.path, 0o644) == 0)
        do {
            let fh = try FileHandle(forUpdating: tamperedRawURL)
            try fh.seek(toOffset: UInt64(fileSize - 4096))
            try fh.write(contentsOf: Data([localData[fileSize - 4096] ^ 0x80]))
            try fh.close()
        }
        #expect(Darwin.chmod(tamperedRawURL.path, 0o444) == 0)

        let badVerifyEn = await cli.execute(
            arguments: ["--lang", "en", "image", "verify", "debian-12-bookworm-arm64"],
            curatedEntriesOverride: fixtures,
            urlSessionConfiguration: noNetConfig,
            environment: ["HOME": mockHome.path, "AGENTVM_IMAGE_CACHE": tamperedCacheDir.path]
        )
        #expect(badVerifyEn.exitCode != 0)
        #expect(badVerifyEn.stderr.contains("ERR_IMAGE_CHECKSUM_MISMATCH"))
        #expect(badVerifyEn.stderr.lowercased().contains("mismatch"))

        let badVerifyZh = await cli.execute(
            arguments: ["--lang", "zh", "image", "verify", "debian-12-bookworm-arm64"],
            curatedEntriesOverride: fixtures,
            urlSessionConfiguration: noNetConfig,
            environment: ["HOME": mockHome.path, "AGENTVM_IMAGE_CACHE": tamperedCacheDir.path]
        )
        #expect(badVerifyZh.exitCode != 0)
        #expect(badVerifyZh.stderr.contains("校验") || badVerifyZh.stderr.contains("不符"))

        // Original cache still passes `image verify`
        let origStillValid = await cli.execute(
            arguments: ["--lang", "en", "image", "verify", "debian-12-bookworm-arm64"],
            curatedEntriesOverride: fixtures,
            urlSessionConfiguration: noNetConfig,
            environment: env
        )
        #expect(origStillValid.exitCode == 0)
        #expect(!FileManager.default.fileExists(atPath: mockHome.path))
    }

    @Test("M1 CLI & Catalog: 'image pull' removes corrupted cached image and clears its index record before starting re-download, while 'image verify' only reports without deleting")
    func cliImagePullDeletesCorruptedCachedFileAndIndexBeforeRedownload() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-cli-corrupt-repull")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let mockHome = tempDir.appendingPathComponent("mock-home", isDirectory: true)
        let cacheDir = tempDir.appendingPathComponent("shared-images", isDirectory: true)
        let env = [
            "HOME": mockHome.path,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()

        let fileSize = 1_048_576 // 1 MiB deterministic payload
        var bytes = [UInt8](repeating: 0, count: fileSize)
        for i in 0..<fileSize {
            bytes[i] = UInt8((i &* 61 &+ 19) & 0xFF)
        }
        let cleanData = Data(bytes)
        let expectedSHA512 = BinaryChecksums.sha512Hex(cleanData)
        let imageID = "debian-12-bookworm-arm64"
        let entry = BaseImageCatalogEntry(
            id: imageID,
            displayName: "Debian Corrupted Re-Pull Fixture",
            distribution: "debian",
            version: "20261112-2660",
            guestOS: .linuxARM64,
            isSupported: true,
            downloadURL: "https://repull.stub.agentvm.invalid/debian-1mb.raw",
            expectedSHA512: expectedSHA512,
            expectedSizeBytes: UInt64(fileSize),
            defaultVirtualSizeBytes: UInt64(fileSize)
        )

        @Sendable func manifestContainsImageID(_ targetID: String, at manifestURL: URL) -> Bool {
            guard let data = try? Data(contentsOf: manifestURL),
                  let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let records = root["records"] as? [[String: Any]] else {
                return false
            }
            return records.contains { rec in
                if let nestedEntry = rec["entry"] as? [String: Any],
                   (nestedEntry["id"] as? String) == targetID {
                    return true
                }
                return (rec["id"] as? String) == targetID
            }
        }

        // 1. Seed cache via initial offline pull
        do {
            let seedSession = UUID().uuidString
            let seedConfig = CLIImageStubURLProtocol.makeSessionConfiguration(sessionID: seedSession) { req in
                let resp = HTTPURLResponse(url: req.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
                return .chunks(response: resp, chunks: [cleanData])
            }
            defer { CLIImageStubURLProtocol.unregister(sessionID: seedSession) }

            let seeded = await cli.execute(
                arguments: ["--lang", "en", "image", "pull", imageID],
                curatedEntriesOverride: [entry],
                urlSessionConfiguration: seedConfig,
                environment: env
            )
            #expect(seeded.exitCode == 0)
        }

        let finalURL = cacheDir.appendingPathComponent("debian-12-bookworm-arm64.raw")
        let manifestURL = cacheDir.appendingPathComponent("catalog-index.json")
        #expect(FileManager.default.fileExists(atPath: finalURL.path))
        #expect(manifestContainsImageID(imageID, at: manifestURL))

        // 2. Corrupt 1 byte of the cached canonical file on disk
        #expect(Darwin.chmod(finalURL.path, 0o644) == 0)
        do {
            let fh = try FileHandle(forUpdating: finalURL)
            try fh.seek(toOffset: UInt64(fileSize / 2))
            try fh.write(contentsOf: Data([cleanData[fileSize / 2] ^ 0xFF]))
            try fh.close()
        }
        #expect(Darwin.chmod(finalURL.path, 0o444) == 0)

        // 3. `image verify` must report mismatch (non-zero) WITHOUT deleting the file or clearing its index record
        do {
            let noNetSession = UUID().uuidString
            let noNetConfig = CLIImageStubURLProtocol.makeSessionConfiguration(sessionID: noNetSession) { req in
                Issue.record("image verify must never touch network: \(req.url?.absoluteString ?? "")")
                throw URLError(.notConnectedToInternet)
            }
            defer { CLIImageStubURLProtocol.unregister(sessionID: noNetSession) }

            let verifyRes = await cli.execute(
                arguments: ["--lang", "en", "image", "verify", imageID],
                curatedEntriesOverride: [entry],
                urlSessionConfiguration: noNetConfig,
                environment: env
            )
            #expect(verifyRes.exitCode != 0)
            #expect(verifyRes.stderr.contains("ERR_IMAGE_CHECKSUM_MISMATCH"))
            #expect(FileManager.default.fileExists(atPath: finalURL.path), "image verify must not delete bad file")
            #expect(manifestContainsImageID(imageID, at: manifestURL), "image verify must not clear index record")
        }

        // 4. `image pull` on the corrupted file: BEFORE download begins (observed when HTTP request arrives),
        //    the bad canonical file must already be deleted and its index record cleared — even if download fails!
        final class InFlightSnapshotBox: @unchecked Sendable {
            private let lock = NSLock()
            var callCount = 0
            var finalFileExistedOnAttempt1: Bool?
            var indexRecordExistedOnAttempt1: Bool?

            func recordAttempt(finalFileExists: Bool, indexRecordExists: Bool) -> Int {
                lock.lock()
                defer { lock.unlock() }
                callCount += 1
                if callCount == 1 {
                    finalFileExistedOnAttempt1 = finalFileExists
                    indexRecordExistedOnAttempt1 = indexRecordExists
                }
                return callCount
            }
        }

        let probe = InFlightSnapshotBox()
        let repullSession = UUID().uuidString
        let repullConfig = CLIImageStubURLProtocol.makeSessionConfiguration(sessionID: repullSession) { req in
            let attempt = probe.recordAttempt(
                finalFileExists: FileManager.default.fileExists(atPath: finalURL.path),
                indexRecordExists: manifestContainsImageID(imageID, at: manifestURL)
            )
            if attempt == 1 {
                let failResp = HTTPURLResponse(url: req.url!, statusCode: 503, httpVersion: "HTTP/1.1", headerFields: nil)!
                return .chunks(response: failResp, chunks: [])
            }
            let okResp = HTTPURLResponse(url: req.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
            return .chunks(response: okResp, chunks: [cleanData])
        }
        defer { CLIImageStubURLProtocol.unregister(sessionID: repullSession) }

        // Attempt 1 fails HTTP 503 -> bad file and index record must ALREADY have been removed before download started
        let failedPull = await cli.execute(
            arguments: ["--lang", "en", "image", "pull", imageID],
            curatedEntriesOverride: [entry],
            urlSessionConfiguration: repullConfig,
            environment: env
        )
        #expect(failedPull.exitCode != 0)
        #expect(probe.callCount == 1)
        #expect(probe.finalFileExistedOnAttempt1 == false, "Corrupted canonical file must be deleted before download starts")
        #expect(probe.indexRecordExistedOnAttempt1 == false, "Stale index record must be cleared before download starts")
        #expect(!FileManager.default.fileExists(atPath: finalURL.path))
        #expect(!manifestContainsImageID(imageID, at: manifestURL))

        let reloadedAfterFail = try BaseImageRegistryCatalog(
            cacheDirectoryURL: cacheDir,
            curatedEntries: [entry]
        )
        #expect(await reloadedAfterFail.isImageCached(id: imageID) == false)
        await #expect(throws: AgentVMError.self) {
            _ = try await reloadedAfterFail.verifiedCachedImageURL(forID: imageID)
        }

        // Attempt 2 succeeds HTTP 200 -> clean file and verified index record are restored
        let recoveredPull = await cli.execute(
            arguments: ["--lang", "en", "image", "pull", imageID],
            curatedEntriesOverride: [entry],
            urlSessionConfiguration: repullConfig,
            environment: env
        )
        #expect(recoveredPull.exitCode == 0)
        #expect(probe.callCount == 2)
        #expect(try Data(contentsOf: finalURL) == cleanData)
        #expect(manifestContainsImageID(imageID, at: manifestURL))
        let st = try cliPosixStat(finalURL)
        #expect((st.st_mode & 0o777) == 0o444)
    }

    // MARK: - M1 Item 2: CLI `create <name> --image <id> [--disk-size <N>G]`

    @Test("M1 CLI 'create --image': rejects missing cache, unverified index, and mtime/size mismatch without network or creating workspace files")
    func cliCreateWithImageRejectsMissingAndMismatchedCacheWithoutCreatingFiles() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-cli-create-img-gate")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let mockHome = tempDir.appendingPathComponent("mock-home", isDirectory: true)
        let cacheDir = tempDir.appendingPathComponent("shared-images", isDirectory: true)
        let env = [
            "HOME": mockHome.path,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()

        let noNetSession = UUID().uuidString
        let noNetConfig = CLIImageStubURLProtocol.makeSessionConfiguration(sessionID: noNetSession) { req in
            Issue.record("create --image must never access the network: \(req.url?.absoluteString ?? "")")
            throw URLError(.notConnectedToInternet)
        }
        defer { CLIImageStubURLProtocol.unregister(sessionID: noNetSession) }

        let fileSize = 4 * 1024 * 1024 // 4 MiB fake image
        var payload = Data(repeating: 0, count: fileSize)
        let pattern = Data((0..<8192).map { UInt8(($0 * 41 + 13) & 0xFF) })
        payload.replaceSubrange(0..<pattern.count, with: pattern)
        payload.replaceSubrange((fileSize - pattern.count)..<fileSize, with: pattern)
        let expectedSHA512 = BinaryChecksums.sha512Hex(payload)
        let imageID = "debian-12-bookworm-arm64"
        let entry = BaseImageCatalogEntry(
            id: imageID,
            displayName: "Debian 12 Fake 4 MiB CLI Image",
            distribution: "debian",
            version: "20261112-2660",
            guestOS: .linuxARM64,
            isSupported: true,
            downloadURL: "https://create-never-downloads.agentvm.invalid/debian.raw",
            expectedSHA512: expectedSHA512,
            expectedSizeBytes: UInt64(fileSize),
            defaultVirtualSizeBytes: UInt64(fileSize)
        )

        // 1. Cache directory does not have the image -> non-zero, hints `image pull`, creates zero workspace files
        let wsMissingEn = tempDir.appendingPathComponent("MissingEn.agentvm", isDirectory: true)
        let missingEn = await cli.execute(
            arguments: ["--lang", "en", "create", "dev1", "--image", imageID],
            bundleURLOverride: wsMissingEn,
            curatedEntriesOverride: [entry],
            urlSessionConfiguration: noNetConfig,
            environment: env
        )
        #expect(missingEn.exitCode != 0)
        #expect(missingEn.stdout.isEmpty)
        #expect(missingEn.stderr.contains("image pull"))
        #expect(!FileManager.default.fileExists(atPath: wsMissingEn.path))

        let wsMissingZh = tempDir.appendingPathComponent("MissingZh.agentvm", isDirectory: true)
        let missingZh = await cli.execute(
            arguments: ["--lang", "zh", "create", "dev1", "--image", imageID],
            bundleURLOverride: wsMissingZh,
            curatedEntriesOverride: [entry],
            urlSessionConfiguration: noNetConfig,
            environment: env
        )
        #expect(missingZh.exitCode != 0)
        #expect(missingZh.stdout.isEmpty)
        #expect(missingZh.stderr.contains("image pull"))
        #expect(!FileManager.default.fileExists(atPath: wsMissingZh.path))

        // Seed valid 4 MiB cached image + catalog-index.json offline
        let stagingURL = tempDir.appendingPathComponent("staging.raw")
        try payload.write(to: stagingURL)
        let seeder = try BaseImageRegistryCatalog(
            cacheDirectoryURL: cacheDir,
            curatedEntries: [entry],
            createIfMissing: true
        )
        let staged = try await seeder.stageCachedCuratedImage(id: imageID, from: stagingURL, verifyChecksum: true)
        try? FileManager.default.removeItem(at: stagingURL)
        let cachedRawURL = URL(fileURLWithPath: try #require(staged.cachedLocalPath)).standardizedFileURL
        #expect(Darwin.chmod(cachedRawURL.path, 0o444) == 0)

        let manifestURL = cacheDir.appendingPathComponent("catalog-index.json")
        let cleanManifestData = try Data(contentsOf: manifestURL)
        let cleanStat = try cliPosixStat(cachedRawURL)

        // 2. Index has `verified: false` -> rejected, hints `image pull`, zero workspace files
        if var root = try JSONSerialization.jsonObject(with: cleanManifestData) as? [String: Any],
           var records = root["records"] as? [[String: Any]], !records.isEmpty {
            records[0]["verified"] = false
            root["records"] = records
            let unverifiedData = try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys])
            try unverifiedData.write(to: manifestURL, options: [.atomic])
        }
        let wsUnverified = tempDir.appendingPathComponent("Unverified.agentvm", isDirectory: true)
        let unverifiedOut = await cli.execute(
            arguments: ["--lang", "en", "create", "dev2", "--image", imageID],
            bundleURLOverride: wsUnverified,
            curatedEntriesOverride: [entry],
            urlSessionConfiguration: noNetConfig,
            environment: env
        )
        #expect(unverifiedOut.exitCode != 0)
        #expect(unverifiedOut.stderr.contains("image pull"))
        #expect(!FileManager.default.fileExists(atPath: wsUnverified.path))

        // Restore valid manifest, then alter file mtime so stat disagrees with index -> rejected
        try cleanManifestData.write(to: manifestURL, options: [.atomic])
        #expect(Darwin.chmod(cachedRawURL.path, 0o644) == 0)
        var bumpedTimes = [
            timeval(tv_sec: cleanStat.st_atimespec.tv_sec, tv_usec: Int32(cleanStat.st_atimespec.tv_nsec / 1000)),
            timeval(tv_sec: cleanStat.st_mtimespec.tv_sec + 30, tv_usec: Int32(cleanStat.st_mtimespec.tv_nsec / 1000))
        ]
        #expect(Darwin.utimes(cachedRawURL.path, &bumpedTimes) == 0)
        #expect(Darwin.chmod(cachedRawURL.path, 0o444) == 0)

        let wsBadMtime = tempDir.appendingPathComponent("BadMtime.agentvm", isDirectory: true)
        let badMtimeOut = await cli.execute(
            arguments: ["--lang", "en", "create", "dev3", "--image", imageID],
            bundleURLOverride: wsBadMtime,
            curatedEntriesOverride: [entry],
            urlSessionConfiguration: noNetConfig,
            environment: env
        )
        #expect(badMtimeOut.exitCode != 0)
        #expect(badMtimeOut.stderr.contains("image pull"))
        #expect(!FileManager.default.fileExists(atPath: wsBadMtime.path))

        // Alter index recorded logicalBytes while matching current mtime -> rejected
        let currentStat = try cliPosixStat(cachedRawURL)
        if var root = try JSONSerialization.jsonObject(with: cleanManifestData) as? [String: Any],
           var records = root["records"] as? [[String: Any]], !records.isEmpty {
            records[0]["mtimeSeconds"] = currentStat.st_mtimespec.tv_sec
            records[0]["mtimeNanoseconds"] = currentStat.st_mtimespec.tv_nsec
            records[0]["logicalBytes"] = fileSize + 8192
            root["records"] = records
            let badSizeData = try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys])
            try badSizeData.write(to: manifestURL, options: [.atomic])
        }
        let wsBadSize = tempDir.appendingPathComponent("BadSize.agentvm", isDirectory: true)
        let badSizeOut = await cli.execute(
            arguments: ["--lang", "zh", "create", "dev4", "--image", imageID],
            bundleURLOverride: wsBadSize,
            curatedEntriesOverride: [entry],
            urlSessionConfiguration: noNetConfig,
            environment: env
        )
        #expect(badSizeOut.exitCode != 0)
        #expect(badSizeOut.stderr.contains("image pull"))
        #expect(!FileManager.default.fileExists(atPath: wsBadSize.path))
        #expect(CLIImageStubURLProtocol.recordedRequests(sessionID: noNetSession).isEmpty)
        #expect(!FileManager.default.fileExists(atPath: mockHome.path))
    }

    @Test("M1 CLI 'create --image [--disk-size]': clones disk, resizes via ftruncate, rejects smaller disk size with zero leftovers, prints NAT/M5 notice, and keeps plain create unchanged")
    func cliCreateWithImageClonesResizesPrintsNATNoticeAndPreservesPlainCreate() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-cli-create-img-ok")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let mockHome = tempDir.appendingPathComponent("mock-home", isDirectory: true)
        let cacheDir = tempDir.appendingPathComponent("shared-images", isDirectory: true)
        let env = [
            "HOME": mockHome.path,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()

        let noNetSession = UUID().uuidString
        let noNetConfig = CLIImageStubURLProtocol.makeSessionConfiguration(sessionID: noNetSession) { req in
            Issue.record("create --image must never access the network: \(req.url?.absoluteString ?? "")")
            throw URLError(.notConnectedToInternet)
        }
        defer { CLIImageStubURLProtocol.unregister(sessionID: noNetSession) }

        // Seed 4 MiB fake image + valid index in temp cache
        let fileSize = 4 * 1024 * 1024
        var payload = Data(repeating: 0, count: fileSize)
        let headerBlock = Data((0..<8192).map { UInt8(($0 * 29 + 7) & 0xFF) })
        let footerBlock = Data((0..<8192).map { UInt8(($0 * 67 + 3) & 0xFF) })
        payload.replaceSubrange(0..<headerBlock.count, with: headerBlock)
        payload.replaceSubrange((fileSize - footerBlock.count)..<fileSize, with: footerBlock)
        let expectedSHA512 = BinaryChecksums.sha512Hex(payload)

        let imageID = "debian-12-bookworm-arm64"
        let entry4M = BaseImageCatalogEntry(
            id: imageID,
            displayName: "Debian 12 Fake 4 MiB CLI Image",
            distribution: "debian",
            version: "20261112-2660",
            guestOS: .linuxARM64,
            isSupported: true,
            downloadURL: "https://offline.agentvm.invalid/debian-4m.raw",
            expectedSHA512: expectedSHA512,
            expectedSizeBytes: UInt64(fileSize),
            defaultVirtualSizeBytes: UInt64(fileSize)
        )

        // Also prepare a 2 GiB sparse image entry (0 physical blocks) so `--disk-size 1G` (<N>G smaller than image) is tested too
        let sparse2GID = "debian-2g-sparse-test"
        let sparse2GBytes: UInt64 = 2 * 1024 * 1024 * 1024
        let entry2G = BaseImageCatalogEntry(
            id: sparse2GID,
            displayName: "Debian 2 GiB Sparse Test Image",
            distribution: "debian",
            version: "20261112-2660",
            guestOS: .linuxARM64,
            isSupported: true,
            downloadURL: "https://offline.agentvm.invalid/debian-2g.raw",
            expectedSHA512: String(repeating: "b", count: 128),
            expectedSizeBytes: sparse2GBytes,
            defaultVirtualSizeBytes: sparse2GBytes
        )

        let stagingURL = tempDir.appendingPathComponent("staging-4m.raw")
        try payload.write(to: stagingURL)
        let seeder = try BaseImageRegistryCatalog(
            cacheDirectoryURL: cacheDir,
            curatedEntries: [entry4M, entry2G],
            createIfMissing: true
        )
        let staged = try await seeder.stageCachedCuratedImage(id: imageID, from: stagingURL, verifyChecksum: true)
        try? FileManager.default.removeItem(at: stagingURL)
        let cached4MURL = URL(fileURLWithPath: try #require(staged.cachedLocalPath)).standardizedFileURL
        #expect(Darwin.chmod(cached4MURL.path, 0o444) == 0)

        // Add the 2 GiB sparse image file + verified index record into catalog-index.json (instant, 0 bytes allocated)
        let cached2GURL = cacheDir.appendingPathComponent(entry2G.cacheFileName).standardizedFileURL
        try APFSCoWDiskEngine().createSparseRawDisk(at: cached2GURL, virtualSizeBytes: sparse2GBytes, overwrite: true)
        #expect(Darwin.chmod(cached2GURL.path, 0o444) == 0)
        let stat2G = try cliPosixStat(cached2GURL)
        let manifestURL = cacheDir.appendingPathComponent("catalog-index.json")
        do {
            let existingManifestData = try Data(contentsOf: manifestURL)
            if var root = try JSONSerialization.jsonObject(with: existingManifestData) as? [String: Any],
               var records = root["records"] as? [[String: Any]],
               var templateRec = records.first {
                let encodedEntry2G = try JSONSerialization.jsonObject(with: JSONEncoder().encode(entry2G))
                templateRec["entry"] = encodedEntry2G
                templateRec["fileName"] = entry2G.cacheFileName
                templateRec["localPath"] = entry2G.cacheFileName
                templateRec["logicalBytes"] = sparse2GBytes
                templateRec["physicalBytes"] = 0
                templateRec["virtualBytes"] = sparse2GBytes
                templateRec["mtimeSeconds"] = stat2G.st_mtimespec.tv_sec
                templateRec["mtimeNanoseconds"] = stat2G.st_mtimespec.tv_nsec
                templateRec["verified"] = true
                templateRec["sha512Hex"] = entry2G.expectedSHA512
                records.append(templateRec)
                root["records"] = records
                let updatedData = try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys])
                try updatedData.write(to: manifestURL, options: [.atomic])
            }
        }

        let stat4MBefore = try cliPosixStat(cached4MURL)
        let cachedBytesBefore = try Data(contentsOf: cached4MURL)

        // 1. Smaller `--disk-size` on brand-new workspaces MUST fail non-zero and create ZERO files/directories
        let wsTooSmallM = tempDir.appendingPathComponent("TooSmall2M.agentvm", isDirectory: true)
        let smallMOut = await cli.execute(
            arguments: ["--lang", "en", "create", "tiny-m", "--image", imageID, "--disk-size", "2M"],
            bundleURLOverride: wsTooSmallM,
            curatedEntriesOverride: [entry4M, entry2G],
            urlSessionConfiguration: noNetConfig,
            environment: env
        )
        #expect(smallMOut.exitCode != 0)
        #expect(smallMOut.stdout.isEmpty)
        #expect(smallMOut.stderr.contains("ERR_DISK_SIZE_TOO_SMALL"))
        #expect(!FileManager.default.fileExists(atPath: wsTooSmallM.path), "Failed create --disk-size 2M must leave zero files")

        let wsTooSmallG = tempDir.appendingPathComponent("TooSmall1G.agentvm", isDirectory: true)
        let smallGOut = await cli.execute(
            arguments: ["--lang", "zh", "create", "tiny-g", "--image", sparse2GID, "--disk-size", "1G"],
            bundleURLOverride: wsTooSmallG,
            curatedEntriesOverride: [entry4M, entry2G],
            urlSessionConfiguration: noNetConfig,
            environment: env
        )
        #expect(smallGOut.exitCode != 0)
        #expect(smallGOut.stdout.isEmpty)
        #expect(smallGOut.stderr.contains("ERR_DISK_SIZE_TOO_SMALL"))
        #expect(!FileManager.default.fileExists(atPath: wsTooSmallG.path), "Failed create --disk-size 1G (< 2G image) must leave zero files")

        // Invalid usage options also exit 2 and create zero files
        for badArgs in [
            ["--lang", "en", "create", "noimg", "--disk-size", "8G"],
            ["--lang", "en", "create", "--image", imageID],
            ["--lang", "en", "create", "bad0", "--image", imageID, "--disk-size", "0G"],
            ["--lang", "en", "create", "badunit", "--image", imageID, "--disk-size", "8T"]
        ] {
            let badWS = tempDir.appendingPathComponent("BadUsage-\(UUID().uuidString).agentvm", isDirectory: true)
            let badRes = await cli.execute(
                arguments: badArgs,
                bundleURLOverride: badWS,
                curatedEntriesOverride: [entry4M, entry2G],
                urlSessionConfiguration: noNetConfig,
                environment: env
            )
            #expect(badRes.exitCode == 2, "Expected usage exit code 2 for \(badArgs), got \(badRes.exitCode)")
            #expect(!FileManager.default.fileExists(atPath: badWS.path))
        }

        // 2. Default `create <name> --image <id>` (no --disk-size): logical size == image size, NAT + M5 notice on stdout
        let bundleURL = tempDir.appendingPathComponent("FleetCreateImg.agentvm", isDirectory: true)
        let createDefaultEn = await cli.execute(
            arguments: ["--lang", "en", "create", "box-default", "--image", imageID],
            bundleURLOverride: bundleURL,
            curatedEntriesOverride: [entry4M, entry2G],
            urlSessionConfiguration: noNetConfig,
            environment: env
        )
        #expect(createDefaultEn.exitCode == 0, "stderr: \(createDefaultEn.stderr)")
        #expect(createDefaultEn.stdout.contains("system NAT"))
        #expect(createDefaultEn.stdout.contains("M5"))

        // 3. `create <name> --image <id> --disk-size 1G` (`--lang zh`): logical size == 1 GiB, Chinese NAT + M5 notice
        let createExpandedZh = await cli.execute(
            arguments: ["--lang", "zh", "create", "box-expanded", "--image", imageID, "--disk-size", "1G"],
            bundleURLOverride: bundleURL,
            curatedEntriesOverride: [entry4M, entry2G],
            urlSessionConfiguration: noNetConfig,
            environment: env
        )
        #expect(createExpandedZh.exitCode == 0, "stderr: \(createExpandedZh.stderr)")
        #expect(createExpandedZh.stdout.contains("网络是系统 NAT"))
        #expect(createExpandedZh.stdout.contains("出口策略在 M5 之前不生效"))

        // 4. Simulation mode marks every line with SIMULATED: including the NAT/M5 notice
        let createSim = await cli.execute(
            arguments: ["--lang", "en", "--backend", "simulation", "create", "box-sim", "--image", imageID],
            bundleURLOverride: bundleURL,
            curatedEntriesOverride: [entry4M, entry2G],
            urlSessionConfiguration: noNetConfig,
            environment: env
        )
        #expect(createSim.exitCode == 0)
        let simLines = createSim.stdout.split(separator: "\n", omittingEmptySubsequences: true)
        #expect(simLines.count >= 2)
        for line in simLines {
            #expect(line.hasPrefix("SIMULATED:"))
        }
        #expect(createSim.stdout.contains("system NAT"))
        #expect(createSim.stdout.contains("M5"))

        // Verify cloned disk logical sizes & contents in workspace
        let coordinator = try AgentVMFleetCoordinator(bundleURL: bundleURL, imageCacheDirectoryURL: cacheDir, curatedImageEntries: [entry4M, entry2G])
        let vms = try await coordinator.store.listVMs()
        let defaultVM = try #require(vms.first(where: { $0.spec.name == "box-default" }))
        let expandedVM = try #require(vms.first(where: { $0.spec.name == "box-expanded" }))

        let defaultDiskURL = URL(fileURLWithPath: try #require(defaultVM.spec.blockDevices.first?.imagePath)).standardizedFileURL
        let expandedDiskURL = URL(fileURLWithPath: try #require(expandedVM.spec.blockDevices.first?.imagePath)).standardizedFileURL
        #expect(defaultDiskURL != cached4MURL)
        #expect(expandedDiskURL != cached4MURL)

        let defaultDiskStat = try cliPosixStat(defaultDiskURL)
        let expandedDiskStat = try cliPosixStat(expandedDiskURL)
        #expect(UInt64(defaultDiskStat.st_size) == UInt64(fileSize))
        #expect(UInt64(expandedDiskStat.st_size) == 1 * 1024 * 1024 * 1024)
        #expect(defaultDiskStat.st_ino != stat4MBefore.st_ino)
        #expect(try Data(contentsOf: defaultDiskURL) == cachedBytesBefore)
        do {
            let fh = try FileHandle(forReadingFrom: expandedDiskURL)
            let head4M = try fh.read(upToCount: fileSize) ?? Data()
            try fh.close()
            #expect(head4M == cachedBytesBefore)
        }

        // 5. Smaller `--disk-size` inside an ALREADY initialized workspace also leaves zero new files or DB rows
        let disksDir = bundleURL.appendingPathComponent("disks", isDirectory: true)
        let isosDir = bundleURL.appendingPathComponent("isos", isDirectory: true)
        let snapsDir = bundleURL.appendingPathComponent("snapshots", isDirectory: true)
        let disksBefore = try FileManager.default.contentsOfDirectory(atPath: disksDir.path).sorted()
        let isosBefore = try FileManager.default.contentsOfDirectory(atPath: isosDir.path).sorted()
        let snapsBefore = try FileManager.default.contentsOfDirectory(atPath: snapsDir.path).sorted()
        let vmCountBefore = vms.count

        let failInExisting = await cli.execute(
            arguments: ["--lang", "en", "create", "should-not-exist", "--image", sparse2GID, "--disk-size", "1G"],
            bundleURLOverride: bundleURL,
            curatedEntriesOverride: [entry4M, entry2G],
            urlSessionConfiguration: noNetConfig,
            environment: env
        )
        #expect(failInExisting.exitCode != 0)
        #expect(failInExisting.stderr.contains("ERR_DISK_SIZE_TOO_SMALL"))
        #expect(try FileManager.default.contentsOfDirectory(atPath: disksDir.path).sorted() == disksBefore)
        #expect(try FileManager.default.contentsOfDirectory(atPath: isosDir.path).sorted() == isosBefore)
        #expect(try FileManager.default.contentsOfDirectory(atPath: snapsDir.path).sorted() == snapsBefore)
        #expect(try await coordinator.store.listVMs().count == vmCountBefore)

        // 6. Cached image file bytes, permissions (0444), and mtime are untouched
        let stat4MAfter = try cliPosixStat(cached4MURL)
        #expect(stat4MAfter.st_ino == stat4MBefore.st_ino)
        #expect((stat4MAfter.st_mode & 0o777) == 0o444)
        #expect(stat4MAfter.st_size == stat4MBefore.st_size)
        #expect(stat4MAfter.st_mtimespec.tv_sec == stat4MBefore.st_mtimespec.tv_sec)
        #expect(stat4MAfter.st_mtimespec.tv_nsec == stat4MBefore.st_mtimespec.tv_nsec)
        #expect(try Data(contentsOf: cached4MURL) == cachedBytesBefore)

        // 7. Plain `create` without `--image` preserves existing behavior (empty disk; `up` fails with ERR_NO_BOOTABLE_SYSTEM)
        let plainCreate = await cli.execute(
            arguments: ["--lang", "en", "create", "plain-empty"],
            bundleURLOverride: bundleURL,
            environment: env
        )
        #expect(plainCreate.exitCode == 0)
        #expect(plainCreate.stdout.contains("empty sparse GPT disk"))

        let plainUp = await cli.execute(
            arguments: ["--lang", "en", "up", "plain-empty"],
            bundleURLOverride: bundleURL,
            environment: env
        )
        #expect(plainUp.exitCode != 0)
        #expect(plainUp.stderr.contains("ERR_NO_BOOTABLE_SYSTEM"))
        #expect(CLIImageStubURLProtocol.recordedRequests(sessionID: noNetSession).isEmpty)
        #expect(!FileManager.default.fileExists(atPath: mockHome.path))
    }

    @Test("M1 CLI 'create --image': cross-volume clonefile EXDEV falls back to full copy and explains on stderr in en and zh without mutating cache")
    func cliCreateWithImageCrossVolumeCopyFallbackExplainsOnStderr() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-cli-create-exdev")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let mockHome = tempDir.appendingPathComponent("mock-home", isDirectory: true)
        let cacheDir = tempDir.appendingPathComponent("shared-images", isDirectory: true)
        let env = [
            "HOME": mockHome.path,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()

        let fileSize = 2 * 1024 * 1024
        let payload = Data((0..<fileSize).map { UInt8(($0 * 17 + 5) & 0xFF) })
        let expectedSHA512 = BinaryChecksums.sha512Hex(payload)
        let imageID = "debian-12-bookworm-arm64"
        let entry = BaseImageCatalogEntry(
            id: imageID,
            displayName: "Debian 12 Fake Cross-Volume Image",
            distribution: "debian",
            version: "20261112-2660",
            guestOS: .linuxARM64,
            isSupported: true,
            downloadURL: "https://offline.agentvm.invalid/debian-exdev.raw",
            expectedSHA512: expectedSHA512,
            expectedSizeBytes: UInt64(fileSize),
            defaultVirtualSizeBytes: UInt64(fileSize)
        )

        let stagingURL = tempDir.appendingPathComponent("staging-exdev.raw")
        try payload.write(to: stagingURL)
        let seeder = try BaseImageRegistryCatalog(
            cacheDirectoryURL: cacheDir,
            curatedEntries: [entry],
            createIfMissing: true
        )
        let staged = try await seeder.stageCachedCuratedImage(id: imageID, from: stagingURL, verifyChecksum: true)
        try? FileManager.default.removeItem(at: stagingURL)
        let cachedURL = URL(fileURLWithPath: try #require(staged.cachedLocalPath)).standardizedFileURL
        #expect(Darwin.chmod(cachedURL.path, 0o444) == 0)
        let statBefore = try cliPosixStat(cachedURL)

        let bundleURL = tempDir.appendingPathComponent("CrossVol.agentvm", isDirectory: true)
        let fallbackEngine = APFSCoWDiskEngine(forceCopyFallbackErrnoForTesting: EXDEV)

        let liveChunks = CLILockedStringBox()
        let outEn = await cli.execute(
            arguments: ["--lang", "en", "create", "xvol-en", "--image", imageID],
            bundleURLOverride: bundleURL,
            curatedEntriesOverride: [entry],
            environment: env,
            diskEngineOverride: fallbackEngine
        ) { chunk in
            liveChunks.append(chunk)
        }
        #expect(outEn.exitCode == 0, "stderr: \(outEn.stderr)")
        #expect(outEn.stdout.contains("system NAT"))
        #expect(outEn.stdout.contains("M5"))
        #expect(!outEn.stderr.isEmpty)
        #expect(outEn.stderr.lowercased().contains("copy") && outEn.stderr.lowercased().contains("volume"))
        #expect(liveChunks.value().lowercased().contains("copy"))

        let outZh = await cli.execute(
            arguments: ["--lang", "zh", "create", "xvol-zh", "--image", imageID],
            bundleURLOverride: bundleURL,
            curatedEntriesOverride: [entry],
            environment: env,
            diskEngineOverride: fallbackEngine
        )
        #expect(outZh.exitCode == 0, "stderr: \(outZh.stderr)")
        #expect(outZh.stdout.contains("网络是系统 NAT"))
        #expect(outZh.stderr.contains("完整复制") && outZh.stderr.contains("卷"))

        let coordinator = try AgentVMFleetCoordinator(bundleURL: bundleURL, imageCacheDirectoryURL: cacheDir, curatedImageEntries: [entry])
        let vms = try await coordinator.store.listVMs()
        let enVM = try #require(vms.first(where: { $0.spec.name == "xvol-en" }))
        let enDiskURL = URL(fileURLWithPath: try #require(enVM.spec.blockDevices.first?.imagePath))
        #expect(try Data(contentsOf: enDiskURL) == payload)

        let statAfter = try cliPosixStat(cachedURL)
        #expect(statAfter.st_ino == statBefore.st_ino)
        #expect((statAfter.st_mode & 0o777) == 0o444)
        #expect(statAfter.st_mtimespec.tv_sec == statBefore.st_mtimespec.tv_sec)
        #expect(try Data(contentsOf: cachedURL) == payload)
    }
}

// MARK: - CLI Offline URLProtocol Test Helpers

private final class CLILockedStringBox: @unchecked Sendable {
    private let lock = NSLock()
    private var buffer = ""

    func append(_ chunk: String) {
        lock.lock()
        defer { lock.unlock() }
        buffer += chunk
    }

    func value() -> String {
        lock.lock()
        defer { lock.unlock() }
        return buffer
    }
}

private final class CLIImageStubURLProtocol: URLProtocol, @unchecked Sendable {
    enum StubReply {
        case chunks(response: HTTPURLResponse, chunks: [Data])
        case redirect(response: HTTPURLResponse, newURL: URL)
    }

    typealias Handler = @Sendable (URLRequest) throws -> StubReply

    private static let sessionHeader = "X-AgentVM-CLI-Stub-Session"
    private static let lock = NSLock()
    private nonisolated(unsafe) static var handlers: [String: Handler] = [:]
    private nonisolated(unsafe) static var requestsBySession: [String: [URLRequest]] = [:]

    static func makeSessionConfiguration(sessionID: String, handler: @escaping Handler) -> URLSessionConfiguration {
        lock.lock()
        handlers[sessionID] = handler
        requestsBySession[sessionID] = []
        lock.unlock()

        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [CLIImageStubURLProtocol.self]
        config.httpAdditionalHeaders = [sessionHeader: sessionID]
        config.urlCache = nil
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        return config
    }

    static func unregister(sessionID: String) {
        lock.lock()
        handlers.removeValue(forKey: sessionID)
        requestsBySession.removeValue(forKey: sessionID)
        lock.unlock()
    }

    static func recordedRequests(sessionID: String) -> [URLRequest] {
        lock.lock()
        defer { lock.unlock() }
        return requestsBySession[sessionID] ?? []
    }

    override class func canInit(with request: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        let sessionID = request.value(forHTTPHeaderField: Self.sessionHeader) ?? ""
        Self.lock.lock()
        if !sessionID.isEmpty {
            Self.requestsBySession[sessionID, default: []].append(request)
        }
        let handler = Self.handlers[sessionID]
        Self.lock.unlock()

        guard let handler else {
            client?.urlProtocol(self, didFailWithError: URLError(.unsupportedURL))
            return
        }

        do {
            switch try handler(request) {
            case let .redirect(response, newURL):
                var redirected = request
                redirected.url = newURL
                client?.urlProtocol(self, wasRedirectedTo: redirected, redirectResponse: response)
                client?.urlProtocolDidFinishLoading(self)
            case let .chunks(response, chunks):
                client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
                for chunk in chunks where !chunk.isEmpty {
                    client?.urlProtocol(self, didLoad: chunk)
                }
                client?.urlProtocolDidFinishLoading(self)
            }
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}
