import AgentVMCLIAndMCP
import AgentVMHypervisor
import AgentVMModels
import AgentVMNetSwitch
import AgentVMPluginHost
import AgentVMStore
import Foundation
import Security
import Testing

/// M0 rework (A21–A24 and the smaller CLI items).
///
/// Every test here drives the product only through its public entry points (`AgentVMCLIRunner.execute`,
/// `AgentVMMCPServer.handleJSONRPCLine`) and inspects text / JSON output, the same way a user or an agent
/// would. Each `cli.execute` call builds a fresh coordinator on the workspace, which is what a separate
/// CLI process does.
@Suite("M0 rework: simulation never passes for real (CLI, JSON, MCP), doctor entitlement, policy persistence", .timeLimit(.minutes(1)))
struct CLIAndMCPSimulationHonestyTests {

    // MARK: - Helpers

    private func makeTempDirectory(prefix: String) throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func run(_ arguments: [String], in bundleURL: URL) async -> CLIExecutionOutcome {
        await AgentVMCLIRunner().execute(arguments: arguments, bundleURLOverride: bundleURL)
    }

    private func nonEmptyLines(_ text: String) -> [String] {
        text.split(separator: "\n", omittingEmptySubsequences: true).map(String.init)
    }

    /// Text output of a simulation-mode command: at least one line somewhere, and every line of stdout and
    /// stderr starts with `SIMULATED:`.
    private func expectEveryLineMarked(_ outcome: CLIExecutionOutcome, _ label: String) {
        let lines = nonEmptyLines(outcome.stdout) + nonEmptyLines(outcome.stderr)
        #expect(!lines.isEmpty, "\(label): produced no output at all, so nothing says it was simulated")
        for line in lines {
            #expect(line.hasPrefix("SIMULATED:"), "\(label): unmarked line: \(line)")
        }
    }

    private func decodeFleetJSON(_ text: String) throws -> [[String: Any]] {
        let object = try JSONSerialization.jsonObject(with: Data(text.utf8))
        return try #require(object as? [[String: Any]])
    }

    private func telemetry(named name: String, in fleet: [[String: Any]]) throws -> [String: Any] {
        let record = try #require(fleet.first(where: { (($0["spec"] as? [String: Any])?["name"] as? String) == name }))
        return try #require(record["telemetry"] as? [String: Any])
    }

    private func haltEverything(in bundleURL: URL) async {
        guard let coordinator = try? AgentVMFleetCoordinator(bundleURL: bundleURL, executionBackend: .deterministicSimulation),
              let vms = try? await coordinator.store.listVMs() else { return }
        for vm in vms where vm.telemetry.state != .stopped {
            _ = try? await coordinator.haltVM(vm.id)
        }
    }

    private func currentProcessHasVirtualizationEntitlement() -> Bool {
        guard let task = SecTaskCreateFromSelf(nil),
              let value = SecTaskCopyValueForEntitlement(task, "com.apple.security.virtualization" as CFString, nil) else {
            return false
        }
        return (value as? Bool) == true
    }

    private struct MCPCallResult {
        var isError: Bool
        var texts: [String]
        var joinedText: String { texts.joined(separator: "\n") }
    }

    private func callTool(
        _ mcp: AgentVMMCPServer,
        id: Int,
        name: String,
        arguments: [String: Any]
    ) async throws -> MCPCallResult {
        let payload: [String: Any] = [
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": ["name": name, "arguments": arguments]
        ]
        let line = String(decoding: try JSONSerialization.data(withJSONObject: payload), as: UTF8.self)
        let raw = try #require(await mcp.handleJSONRPCLine(line))
        let object = try #require(try JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any])
        let result = try #require(object["result"] as? [String: Any], "tool \(name) returned a JSON-RPC error instead of a tool result: \(raw)")
        let content = try #require(result["content"] as? [[String: Any]])
        return MCPCallResult(
            isError: (result["isError"] as? Bool) ?? false,
            texts: content.compactMap { $0["text"] as? String }
        )
    }

    // MARK: - A21: simulated state must not leak into the default path

    @Test("A21: after `--backend simulation up a`, default `ps` and `ps --json` mark the state as simulated (en and zh)")
    func simulatedBootStateIsMarkedOnDefaultBackendPSAndJSON() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-a21-ps")
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let bundleURL = tempDir.appendingPathComponent("A21.agentvm", isDirectory: true)

        #expect(await run(["--lang", "en", "init"], in: bundleURL).exitCode == 0)
        #expect(await run(["--lang", "en", "create", "a"], in: bundleURL).exitCode == 0)
        let simUp = await run(["--lang", "en", "--backend", "simulation", "up", "a"], in: bundleURL)
        #expect(simUp.exitCode == 0)
        expectEveryLineMarked(simUp, "simulation up")

        // Default backend, no flags: text output.
        let psEn = await run(["--lang", "en", "ps"], in: bundleURL)
        #expect(psEn.exitCode == 0)
        #expect(psEn.stdout.contains("SIMULATED"), "default ps shows no SIMULATED marker:\n\(psEn.stdout)")
        for line in nonEmptyLines(psEn.stdout) where line.contains("running") {
            #expect(line.contains("SIMULATED"), "default ps prints an unmarked running row: \(line)")
        }

        let psZh = await run(["--lang", "zh", "ps"], in: bundleURL)
        #expect(psZh.exitCode == 0)
        #expect(psZh.stdout.contains("SIMULATED"), "default ps (zh) shows no SIMULATED marker:\n\(psZh.stdout)")
        for line in nonEmptyLines(psZh.stdout) where line.contains("运行中") {
            #expect(line.contains("SIMULATED"), "default ps (zh) prints an unmarked 运行中 row: \(line)")
        }

        // Default backend, no flags: JSON output carries an explicit boolean next to the state.
        let psJSON = await run(["--lang", "en", "ps", "--json"], in: bundleURL)
        #expect(psJSON.exitCode == 0)
        let fleet = try decodeFleetJSON(psJSON.stdout)
        let telemetryA = try telemetry(named: "a", in: fleet)
        let state = try #require(telemetryA["state"] as? String)
        let simulatedField = telemetryA["simulated"] as? Bool
        #expect(simulatedField != nil, "ps --json has no telemetry.simulated field at all")
        if state == "running" {
            #expect(simulatedField == true, "ps --json reports running without \"simulated\": true")
        }
        if (telemetryA["guestAgentConnected"] as? Bool) == true {
            #expect(simulatedField == true, "ps --json reports guestAgentConnected without \"simulated\": true")
        }

        await haltEverything(in: bundleURL)
    }

    @Test("A21: the default backend never acts on a simulated `running` state (up, exec, pause all fail honestly)")
    func defaultBackendNeverActsOnSimulatedRunningState() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-a21-act")
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let bundleURL = tempDir.appendingPathComponent("A21Act.agentvm", isDirectory: true)

        #expect(await run(["--lang", "en", "create", "a"], in: bundleURL).exitCode == 0)

        // 1. default `up a` after a simulated boot must not report "-> running".
        #expect(await run(["--backend", "simulation", "up", "a"], in: bundleURL).exitCode == 0)
        let upDefault = await run(["--lang", "en", "up", "a"], in: bundleURL)
        #expect(upDefault.exitCode != 0, "default up exited 0 on a VM that only ran in the simulator: \(upDefault.stdout)")
        #expect(upDefault.stdout.isEmpty)
        #expect(upDefault.stderr.contains("ERR_NO_BOOTABLE_SYSTEM"))

        // The hardware backend discarded the simulated state: stopped, no agent, not simulated.
        let afterUp = try telemetry(named: "a", in: try decodeFleetJSON(await run(["ps", "--json"], in: bundleURL).stdout))
        #expect(afterUp["state"] as? String == "stopped")
        #expect(afterUp["guestAgentConnected"] as? Bool == false)
        #expect(afterUp["simulated"] as? Bool == false)

        // 2. default `exec` after a simulated boot: non-zero, no responder output on either stream.
        #expect(await run(["--backend", "simulation", "up", "a"], in: bundleURL).exitCode == 0)
        let execDefault = await run(["--lang", "en", "exec", "a", "--", "uname", "-a"], in: bundleURL)
        #expect(execDefault.exitCode != 0)
        #expect(!execDefault.stdout.contains("Linux"))
        #expect(!execDefault.stderr.contains("Linux"))
        #expect(!execDefault.stdout.contains("6.8.0"))

        // 3. default `pause` after a simulated boot: there is nothing real to pause.
        #expect(await run(["--backend", "simulation", "up", "a"], in: bundleURL).exitCode == 0)
        let pauseDefault = await run(["--lang", "en", "pause", "a"], in: bundleURL)
        #expect(pauseDefault.exitCode != 0, "default pause succeeded on a simulated VM: \(pauseDefault.stdout)")

        await haltEverything(in: bundleURL)
    }

    @Test("A21: MCP on the default backend marks simulated state in agentvm_list_fleet")
    func mcpDefaultBackendListFleetMarksSimulatedState() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-a21-mcp")
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let bundleURL = tempDir.appendingPathComponent("A21MCP.agentvm", isDirectory: true)

        #expect(await run(["create", "a"], in: bundleURL).exitCode == 0)
        #expect(await run(["--backend", "simulation", "up", "a"], in: bundleURL).exitCode == 0)

        let coordinator = try AgentVMFleetCoordinator(bundleURL: bundleURL)
        let mcp = AgentVMMCPServer(coordinator: coordinator)
        let listed = try await callTool(mcp, id: 1, name: "agentvm_list_fleet", arguments: [:])
        #expect(listed.isError == false)
        let fleet = try decodeFleetJSON(try #require(listed.texts.first))
        let telemetryA = try telemetry(named: "a", in: fleet)
        if telemetryA["state"] as? String == "running" {
            #expect(telemetryA["simulated"] as? Bool == true, "MCP list_fleet reports running without \"simulated\": true")
        }
        #expect(telemetryA["simulated"] as? Bool != nil)

        await haltEverything(in: bundleURL)
    }

    // MARK: - A22: every output of simulation mode carries the marker

    @Test("A22: every CLI subcommand output in simulation mode is marked (text lines, ps --json, export-hcl, pcap file, HTML page)")
    func everyCLISubcommandOutputIsMarkedInSimulationMode() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-a22-cli")
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let bundleURL = tempDir.appendingPathComponent("A22.agentvm", isDirectory: true)
        let sim = ["--lang", "en", "--backend", "simulation"]

        expectEveryLineMarked(await run(sim + ["doctor"], in: bundleURL), "doctor")
        expectEveryLineMarked(await run(sim + ["init"], in: bundleURL), "init")
        expectEveryLineMarked(await run(sim + ["create", "s1"], in: bundleURL), "create")
        expectEveryLineMarked(await run(sim + ["ps"], in: bundleURL), "ps (stopped)")
        expectEveryLineMarked(await run(sim + ["up", "s1"], in: bundleURL), "up")
        expectEveryLineMarked(await run(sim + ["ps"], in: bundleURL), "ps (running)")
        expectEveryLineMarked(await run(sim + ["pause", "s1"], in: bundleURL), "pause")
        expectEveryLineMarked(await run(sim + ["resume", "s1"], in: bundleURL), "resume")

        // exec: multi-line stdout, empty output with exit 0, empty output with exit 1, stderr-only output.
        let multiLine = await run(sim + ["exec", "s1", "--", "cat", "/etc/os-release"], in: bundleURL)
        #expect(nonEmptyLines(multiLine.stdout).count >= 3)
        expectEveryLineMarked(multiLine, "exec cat /etc/os-release")
        let silentOK = await run(sim + ["exec", "s1", "--", "env"], in: bundleURL)
        expectEveryLineMarked(silentOK, "exec env (no output)")
        let silentFail = await run(sim + ["exec", "s1", "--", "false"], in: bundleURL)
        #expect(silentFail.exitCode != 0)
        expectEveryLineMarked(silentFail, "exec false (no output, exit 1)")
        let stderrOnly = await run(sim + ["exec", "s1", "--", "nonexistent-cmd"], in: bundleURL)
        expectEveryLineMarked(stderrOnly, "exec nonexistent-cmd")

        let snapOut = await run(sim + ["snapshot", "s1", "checkpoint-one"], in: bundleURL)
        expectEveryLineMarked(snapOut, "snapshot capture")
        let snapList = await run(sim + ["snapshot", "list"], in: bundleURL)
        expectEveryLineMarked(snapList, "snapshot list")
        let snapID = try #require(
            nonEmptyLines(snapList.stdout)
                .first(where: { $0.contains("checkpoint-one") })?
                .split(whereSeparator: { $0 == " " || $0 == "\t" })
                .first(where: { $0.hasPrefix("snap-") })
                .map(String.init)
        )
        expectEveryLineMarked(await run(sim + ["branch", "s1", "s2", "--no-boot"], in: bundleURL), "branch")
        expectEveryLineMarked(await run(sim + ["restore", snapID], in: bundleURL), "restore")
        expectEveryLineMarked(await run(sim + ["pcap"], in: bundleURL), "pcap")
        expectEveryLineMarked(await run(sim + ["policy"], in: bundleURL), "policy")
        expectEveryLineMarked(await run(sim + ["policy", "airgap"], in: bundleURL), "policy airgap")
        expectEveryLineMarked(await run(sim + ["policy", "strict"], in: bundleURL), "policy strict")
        expectEveryLineMarked(await run(sim + ["plugin"], in: bundleURL), "plugin")
        expectEveryLineMarked(await run(sim + ["up", "does-not-exist"], in: bundleURL), "error path")

        // ps --json stays valid JSON; every record says it is reported by the simulator.
        let psJSON = await run(sim + ["ps", "--json"], in: bundleURL)
        #expect(psJSON.exitCode == 0)
        let fleet = try decodeFleetJSON(psJSON.stdout)
        #expect(fleet.count == 2)
        for record in fleet {
            let telemetry = try #require(record["telemetry"] as? [String: Any])
            #expect(telemetry["simulated"] as? Bool == true, "simulation-mode ps --json record without \"simulated\": true")
        }
        for line in nonEmptyLines(psJSON.stderr) {
            #expect(line.hasPrefix("SIMULATED:"))
        }

        // export-hcl stays valid HCL; the marker is an HCL comment line.
        let hcl = await run(sim + ["export-hcl"], in: bundleURL)
        #expect(hcl.exitCode == 0)
        #expect(nonEmptyLines(hcl.stdout).contains(where: { $0.hasPrefix("# SIMULATED:") }), "export-hcl has no '# SIMULATED:' comment line")
        // The marker is an ordinary HCL comment: the document still imports to the same two VM specs.
        let importedSpecs = try TopologyIACCodec().importHCL(hcl.stdout, defaultDiskDirectory: tempDir)
        #expect(importedSpecs.map(\.name).sorted() == ["s1", "s2"])

        // pcap --export: the command output is marked and so is the file itself (section comment).
        let pcapURL = tempDir.appendingPathComponent("sim.pcapng")
        let pcapExport = await run(sim + ["pcap", "--export", pcapURL.path], in: bundleURL)
        #expect(pcapExport.exitCode == 0)
        expectEveryLineMarked(pcapExport, "pcap --export")
        let pcapBytes = try Data(contentsOf: pcapURL)
        #expect(String(decoding: pcapBytes, as: UTF8.self).contains("SIMULATED"), "exported .pcapng carries no SIMULATED comment")
        // ...and it is still a well-formed capture.
        _ = try PCAPNGCodec().inspectCapture(data: pcapBytes)

        // export-html: the command output is marked and so is the page.
        let htmlURL = tempDir.appendingPathComponent("sim.html")
        let htmlExport = await run(sim + ["export-html", htmlURL.path], in: bundleURL)
        #expect(htmlExport.exitCode == 0)
        expectEveryLineMarked(htmlExport, "export-html")
        let html = try String(contentsOf: htmlURL, encoding: .utf8)
        #expect(html.contains("SIMULATED"), "exported HTML page carries no SIMULATED marker")

        expectEveryLineMarked(await run(sim + ["halt", "s1"], in: bundleURL), "halt")
    }

    @Test("A22: a default-backend HTML export of a workspace holding simulated state marks it and does not count it as active")
    func defaultBackendHTMLExportMarksSimulatedState() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-a22-html")
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let bundleURL = tempDir.appendingPathComponent("A22HTML.agentvm", isDirectory: true)

        #expect(await run(["create", "a"], in: bundleURL).exitCode == 0)
        #expect(await run(["--backend", "simulation", "up", "a"], in: bundleURL).exitCode == 0)

        let htmlURL = tempDir.appendingPathComponent("default.html")
        #expect(await run(["--lang", "en", "export-html", htmlURL.path], in: bundleURL).exitCode == 0)
        let html = try String(contentsOf: htmlURL, encoding: .utf8)
        #expect(html.contains("SIMULATED"), "default export-html shows a simulated VM with no marker")
        #expect(!html.contains("<div class=\"metric-value\">1 / 1</div>"), "default export-html counts a simulated VM as an active blade")

        await haltEverything(in: bundleURL)
    }

    @Test("A22: every MCP tool listed by tools/list returns a marked result in simulation mode")
    func everyMCPToolResultIsMarkedInSimulationMode() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-a22-mcp")
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let bundleURL = tempDir.appendingPathComponent("A22MCP.agentvm", isDirectory: true)

        let coordinator = try AgentVMFleetCoordinator(bundleURL: bundleURL, executionBackend: .deterministicSimulation)
        let mcp = AgentVMMCPServer(coordinator: coordinator)
        let seedVM = try await coordinator.createSandboxVM(name: "mcp-seed", diskVirtualBytes: 16 * 1024 * 1024).vmRecord
        let seedSnap = try await coordinator.captureSnapshot(vmID: seedVM.id, title: "mcp-seed-snap")

        let listRaw = try #require(await mcp.handleJSONRPCLine(#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#))
        let listObject = try #require(try JSONSerialization.jsonObject(with: Data(listRaw.utf8)) as? [String: Any])
        let tools = try #require((listObject["result"] as? [String: Any])?["tools"] as? [[String: Any]])
        let toolNames = tools.compactMap { $0["name"] as? String }
        #expect(!toolNames.isEmpty)

        // One realistic call per tool. A tool that appears in tools/list without an entry here fails the test,
        // so a newly added tool cannot ship without a marker check.
        let argumentsByTool: [String: [String: Any]] = [
            "agentvm_list_fleet": [:],
            "agentvm_create_vm": ["name": "mcp-second"],
            "agentvm_fork_cow_branch": ["parentVMID": seedVM.id.rawValue, "branchName": "mcp-fork", "bootImmediately": false],
            "agentvm_exec_command": ["vmID": seedVM.id.rawValue, "executable": "cat", "arguments": ["/etc/os-release"]],
            "agentvm_capture_snapshot": ["vmID": seedVM.id.rawValue, "title": "mcp-snap"],
            "agentvm_restore_snapshot": ["snapshotID": seedSnap.id.rawValue],
            "agentvm_query_wiretap": [:],
            "agentvm_set_firewall_preset": ["preset": "airgap"],
            "agentvm_doctor": [:]
        ]

        var callID = 100
        for name in toolNames {
            guard let arguments = argumentsByTool[name] else {
                Issue.record("tools/list exposes '\(name)' but this test has no simulation-marker check for it")
                continue
            }
            callID += 1
            let result = try await callTool(mcp, id: callID, name: name, arguments: arguments)
            #expect(result.isError == false, "\(name) failed in simulation mode: \(result.joinedText)")
            #expect(result.joinedText.contains("SIMULATED"), "\(name): result carries no SIMULATED marker: \(result.joinedText.prefix(200))")
            if name == "agentvm_list_fleet" {
                // The first content block stays machine-readable JSON; every record is flagged.
                let fleet = try decodeFleetJSON(try #require(result.texts.first))
                for record in fleet {
                    let telemetry = try #require(record["telemetry"] as? [String: Any])
                    #expect(telemetry["simulated"] as? Bool == true)
                }
            } else {
                for line in nonEmptyLines(result.joinedText) {
                    #expect(line.hasPrefix("SIMULATED:"), "\(name): unmarked line: \(line)")
                }
            }
        }

        // An error result in simulation mode is marked as well.
        let failing = try await callTool(mcp, id: 999, name: "agentvm_restore_snapshot", arguments: ["snapshotID": "snap-does-not-exist"])
        #expect(failing.isError == true)
        for line in nonEmptyLines(failing.joinedText) {
            #expect(line.hasPrefix("SIMULATED:"), "error result unmarked line: \(line)")
        }

        for vm in try await coordinator.store.listVMs() where vm.telemetry.state != .stopped {
            _ = try? await coordinator.haltVM(vm.id)
        }
    }

    // MARK: - A23: doctor reads the entitlement of the running executable

    @Test("A23: doctor's virtualization line follows the entitlement actually present on the running process (en, zh, MCP)")
    func doctorVirtualizationLineReflectsRealEntitlement() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-a23")
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let bundleURL = tempDir.appendingPathComponent("A23.agentvm", isDirectory: true)

        let entitled = currentProcessHasVirtualizationEntitlement()

        let doctorEn = await run(["--lang", "en", "doctor"], in: bundleURL)
        #expect(doctorEn.exitCode == 0)
        let lineEn = try #require(nonEmptyLines(doctorEn.stdout).first(where: { $0.hasPrefix("Apple VZ Support") }))
        let doctorZh = await run(["--lang", "zh", "doctor"], in: bundleURL)
        #expect(doctorZh.exitCode == 0)
        let lineZh = try #require(nonEmptyLines(doctorZh.stdout).first(where: { $0.hasPrefix("Apple VZ 虚拟化") }))

        if entitled {
            #expect(lineEn.contains("PASS"))
            #expect(lineZh.contains("通过"))
        } else {
            // The test runner is not signed with com.apple.security.virtualization: no "PASS" / "通过".
            #expect(!lineEn.contains("PASS"), "doctor claims PASS without the entitlement: \(lineEn)")
            #expect(!lineZh.contains("通过"), "doctor claims 通过 without the entitlement: \(lineZh)")
            #expect(!lineZh.contains("已具备"), "doctor claims the entitlement is present: \(lineZh)")
            #expect(lineZh.contains("系统支持虚拟化；当前可执行文件没有虚拟化权限，无法启动虚拟机"), "unexpected zh line: \(lineZh)")
            #expect(lineEn.contains("cannot start virtual machines"), "unexpected en line: \(lineEn)")
        }

        let coordinator = try AgentVMFleetCoordinator(bundleURL: bundleURL)
        let mcp = AgentVMMCPServer(coordinator: coordinator)
        let mcpDoctor = try await callTool(mcp, id: 5, name: "agentvm_doctor", arguments: [:])
        #expect(mcpDoctor.isError == false)
        #expect(mcpDoctor.joinedText.contains("VZEntitled=\(entitled)"), "MCP doctor does not report the entitlement: \(mcpDoctor.joinedText)")
        #expect(mcpDoctor.joinedText.contains("canStartVMs="), "MCP doctor does not say whether a VM can be started: \(mcpDoctor.joinedText)")
    }

    // MARK: - A24: `policy <preset>` survives the process

    @Test("A24: `policy airgap` is still in effect for the next process (CLI and MCP), and the message does not overclaim")
    func policySelectionPersistsAcrossProcesses() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-a24")
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let bundleURL = tempDir.appendingPathComponent("A24.agentvm", isDirectory: true)

        let before = await run(["--lang", "en", "policy"], in: bundleURL)
        #expect(before.exitCode == 0)
        #expect(before.stdout.contains("Strict Coding-Agent Allowlist"))

        let airgap = await run(["--lang", "en", "policy", "airgap"], in: bundleURL)
        #expect(airgap.exitCode == 0)
        #expect(airgap.stdout.contains("Total Air-Gap"))
        // No guest traffic reaches the firewall before M5; the confirmation must say so.
        #expect(airgap.stdout.contains("M5"), "policy airgap claims an air gap without the M5 caveat: \(airgap.stdout)")
        let airgapZh = await run(["--lang", "zh", "policy", "airgap"], in: bundleURL)
        #expect(airgapZh.exitCode == 0)
        #expect(airgapZh.stdout.contains("M5"))

        // A new process: the selection is still there.
        let after = await run(["--lang", "en", "policy"], in: bundleURL)
        #expect(after.exitCode == 0)
        #expect(after.stdout.contains("Total Air-Gap"), "policy reverted in the next process:\n\(after.stdout)")
        #expect(!after.stdout.contains("Strict Coding-Agent Allowlist"))
        let hcl = await run(["export-hcl"], in: bundleURL)
        #expect(hcl.stdout.contains("pol-airgap"))

        // And back.
        #expect(await run(["policy", "strict"], in: bundleURL).exitCode == 0)
        let restored = await run(["--lang", "en", "policy"], in: bundleURL)
        #expect(restored.stdout.contains("Strict Coding-Agent Allowlist"))

        // Same through MCP: set in one server, read in a new process.
        do {
            let coordinator = try AgentVMFleetCoordinator(bundleURL: bundleURL)
            let mcp = AgentVMMCPServer(coordinator: coordinator)
            let set = try await callTool(mcp, id: 7, name: "agentvm_set_firewall_preset", arguments: ["preset": "airgap"])
            #expect(set.isError == false)
        }
        let afterMCP = await run(["--lang", "en", "policy"], in: bundleURL)
        #expect(afterMCP.stdout.contains("Total Air-Gap"), "MCP preset did not persist:\n\(afterMCP.stdout)")
    }

    // MARK: - Smaller CLI items from the review

    @Test("Unknown options and arguments exit 2 instead of being ignored; documented options still work")
    func unknownOptionsExitWithCodeTwo() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-opts")
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let bundleURL = tempDir.appendingPathComponent("Opts.agentvm", isDirectory: true)
        #expect(await run(["--lang", "en", "create", "a", "--cpus", "2", "--memory-mb", "1024", "--owner", "me"], in: bundleURL).exitCode == 0)

        let rejected: [[String]] = [
            ["ps", "--bogus"],
            ["policy", "bogus"],
            ["policy", "--bogus"],
            ["doctor", "--bogus"],
            ["init", "--bogus"],
            ["create", "b", "--bogus"],
            ["up", "a", "--bogus"],
            ["snapshot", "list", "--bogus"],
            ["branch", "a", "c", "--bogus"],
            ["pcap", "--bogus"],
            ["plugin", "--bogus"],
            ["export-hcl", "--bogus"],
            ["export-html", "--bogus"]
        ]
        for arguments in rejected {
            let outcome = await run(["--lang", "en"] + arguments, in: bundleURL)
            #expect(outcome.exitCode == 2, "`\(arguments.joined(separator: " "))` exited \(outcome.exitCode), expected 2")
            #expect(outcome.stdout.isEmpty, "`\(arguments.joined(separator: " "))` still printed a result: \(outcome.stdout)")
            #expect(outcome.stderr.contains("bogus"), "`\(arguments.joined(separator: " "))` error does not name the offending token: \(outcome.stderr)")
        }
        let zhRejected = await run(["--lang", "zh", "ps", "--bogus"], in: bundleURL)
        #expect(zhRejected.exitCode == 2)
        #expect(zhRejected.stderr.contains("--bogus"))

        // Nothing was created by the rejected `create b --bogus` / `branch a c --bogus`.
        let fleet = try decodeFleetJSON(await run(["ps", "--json"], in: bundleURL).stdout)
        #expect(fleet.count == 1)

        // Documented options keep working.
        #expect(await run(["ps", "--json"], in: bundleURL).exitCode == 0)
        #expect(await run(["branch", "a", "b", "--no-boot", "--owner", "me"], in: bundleURL).exitCode == 0)
        #expect(await run(["snapshot", "a", "--title", "t1"], in: bundleURL).exitCode == 0)
        #expect(await run(["pcap", "--filter", "proto == DNS"], in: bundleURL).exitCode == 0)
        // Everything after the VM in `exec` belongs to the guest command and is never parsed as a host option.
        let exec = await run(["--backend", "simulation", "exec", "a", "--", "echo", "--bogus"], in: bundleURL)
        #expect(exec.exitCode == 0)
        #expect(exec.stdout.contains("--bogus"))
        await haltEverything(in: bundleURL)
    }

    @Test("`pcap --export` with no captured traffic says it wrote 0 packets (en and zh)")
    func pcapExportWithoutTrafficReportsZeroPackets() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-pcap0")
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let bundleURL = tempDir.appendingPathComponent("Pcap0.agentvm", isDirectory: true)
        #expect(await run(["create", "a"], in: bundleURL).exitCode == 0)

        let enURL = tempDir.appendingPathComponent("empty-en.pcapng")
        let en = await run(["--lang", "en", "pcap", "--export", enURL.path], in: bundleURL)
        #expect(en.exitCode == 0)
        #expect(en.stdout.contains("0 packets"), "empty export does not say 0 packets: \(en.stdout)")

        let zhURL = tempDir.appendingPathComponent("empty-zh.pcapng")
        let zh = await run(["--lang", "zh", "pcap", "--export", zhURL.path], in: bundleURL)
        #expect(zh.exitCode == 0)
        #expect(zh.stdout.contains("0 个数据包"), "empty export (zh) does not say 0 个数据包: \(zh.stdout)")

        let report = try PCAPNGCodec().inspectCapture(data: try Data(contentsOf: enURL))
        #expect(report.enhancedPacketBlockCount == 0)
    }

    @Test("`create` with a name that already exists fails and creates nothing; so does `branch` onto an existing name")
    func duplicateVMNameIsRejected() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-dup")
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let bundleURL = tempDir.appendingPathComponent("Dup.agentvm", isDirectory: true)

        #expect(await run(["--lang", "en", "create", "a"], in: bundleURL).exitCode == 0)
        let second = await run(["--lang", "en", "create", "a"], in: bundleURL)
        #expect(second.exitCode != 0, "second `create a` succeeded: \(second.stdout)")
        #expect(second.stderr.contains("ERR_VM_NAME_EXISTS"))
        let secondZh = await run(["--lang", "zh", "create", "A"], in: bundleURL)
        #expect(secondZh.exitCode != 0)
        #expect(secondZh.stderr.contains("ERR_VM_NAME_EXISTS"))

        let branchOntoExisting = await run(["--lang", "en", "branch", "a", "a", "--no-boot"], in: bundleURL)
        #expect(branchOntoExisting.exitCode != 0)

        let fleet = try decodeFleetJSON(await run(["ps", "--json"], in: bundleURL).stdout)
        #expect(fleet.count == 1)
        // The rejected attempts left no extra disk images behind.
        let disks = try FileManager.default.contentsOfDirectory(atPath: bundleURL.appendingPathComponent("disks").path)
        #expect(disks.filter { $0.hasSuffix(".raw") }.count == 1)
    }

    @Test("Chinese `up` error is Chinese end to end; English `create` carries the empty-disk note the Chinese one has")
    func bilingualParityOfUpErrorAndCreateNote() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-i18n")
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let bundleURL = tempDir.appendingPathComponent("I18N.agentvm", isDirectory: true)

        let createEn = await run(["--lang", "en", "create", "a"], in: bundleURL)
        #expect(createEn.exitCode == 0)
        #expect(createEn.stdout.contains("no guest OS installed"), "English create lacks the empty-disk note: \(createEn.stdout)")
        let createZh = await run(["--lang", "zh", "create", "b"], in: bundleURL)
        #expect(createZh.stdout.contains("未安装客户机系统"))

        let upZh = await run(["--lang", "zh", "up", "a"], in: bundleURL)
        #expect(upZh.exitCode != 0)
        #expect(upZh.stderr.contains("ERR_NO_BOOTABLE_SYSTEM"))
        #expect(upZh.stderr.contains("空的分区表"), "zh up error has no Chinese disk detail: \(upZh.stderr)")
        for englishFragment in ["Boot disk", "contains only", "partition table", "bootloader", "filesystem"] {
            #expect(!upZh.stderr.contains(englishFragment), "zh up error still contains English '\(englishFragment)': \(upZh.stderr)")
        }

        let upEn = await run(["--lang", "en", "up", "a"], in: bundleURL)
        #expect(upEn.stderr.contains("contains only an empty partition table"))
    }
}
