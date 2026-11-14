import AgentVMHypervisor
import AgentVMModels
import AgentVMNetSwitch
import AgentVMPluginHost
import AgentVMStore
import Foundation

// MARK: - JSON-RPC 2.0 Model Context Protocol (MCP) Server for Coding Agents

public actor AgentVMMCPServer {
    private let coordinator: AgentVMFleetCoordinator

    public init(coordinator: AgentVMFleetCoordinator) {
        self.coordinator = coordinator
    }

    public static var toolDefinitions: [[String: Any]] {
        [
            [
                "name": "agentvm_list_fleet",
                "description": "List all sandbox VMs, lifecycle states, IPv4 addresses, and APFS CoW dirty disk deltas.",
                "inputSchema": ["type": "object", "properties": [:]]
            ],
            [
                "name": "agentvm_create_vm",
                "description": "Provision a fresh Apple Silicon microVM with GPT root disk and NoCloud cidata ISO.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "name": ["type": "string"],
                        "owner": ["type": "string"],
                        "vcpus": ["type": "integer"],
                        "memoryMB": ["type": "integer"]
                    ],
                    "required": ["name"]
                ]
            ],
            [
                "name": "agentvm_fork_cow_branch",
                "description": "Fork an APFS clonefile(2) Copy-on-Write sandbox branch from an existing VM.",
                "inputSchema": {
                    [
                        "type": "object",
                        "properties": [
                            "parentVMID": ["type": "string"],
                            "branchName": ["type": "string"],
                            "owner": ["type": "string"],
                            "bootImmediately": ["type": "boolean"]
                        ],
                        "required": ["parentVMID", "branchName"]
                    ]
                }()
            ],
            [
                "name": "agentvm_exec_command",
                "description": "Execute a command inside a sandbox VM over multiplexed AVM1 VirtioSocket with pre-exec JS guardrails.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "vmID": ["type": "string"],
                        "executable": ["type": "string"],
                        "arguments": ["type": "array", "items": ["type": "string"]],
                        "workingDirectory": ["type": "string"]
                    ],
                    "required": ["vmID", "executable"]
                ]
            ],
            [
                "name": "agentvm_capture_snapshot",
                "description": "Capture a live RAM + CoW disk checkpoint of a sandbox VM.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "vmID": ["type": "string"],
                        "title": ["type": "string"]
                    ],
                    "required": ["vmID", "title"]
                ]
            ],
            [
                "name": "agentvm_restore_snapshot",
                "description": "Roll back a sandbox VM to an earlier snapshot node.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "snapshotID": ["type": "string"]
                    ],
                    "required": ["snapshotID"]
                ]
            ],
            [
                "name": "agentvm_query_wiretap",
                "description": "Query L2 switch packet wiretap using boolean filter expressions (e.g. 'proto == TLS && verdict == DROP').",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "filter": ["type": "string"],
                        "limit": ["type": "integer"]
                    ]
                ]
            ],
            [
                "name": "agentvm_set_firewall_preset",
                "description": "Switch the L2 egress firewall between 'strict' coding-agent allowlist and 'airgap' mode.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "preset": ["type": "string"]
                    ],
                    "required": ["preset"]
                ]
            ],
            [
                "name": "agentvm_doctor",
                "description": "Return Apple Virtualization, APFS clonefile, Rosetta, and SQLite WAL diagnostics.",
                "inputSchema": ["type": "object", "properties": [:]]
            ]
        ]
    }

    public func handleJSONRPCLine(_ line: String) async -> String? {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              let reqData = trimmed.data(using: .utf8),
              let json = (try? JSONSerialization.jsonObject(with: reqData)) as? [String: Any] else {
            return nil
        }

        let idValue = json["id"]
        let method = (json["method"] as? String) ?? ""
        let params = (json["params"] as? [String: Any]) ?? [:]

        if method == "notifications/initialized" {
            return nil
        }

        do {
            let resultObject: [String: Any]
            switch method {
            case "initialize":
                resultObject = [
                    "protocolVersion": "2024-11-05",
                    "capabilities": ["tools": ["listChanged": false]],
                    "serverInfo": [
                        "name": "agentvm-mcp",
                        "version": SemanticVersion.current.description
                    ]
                ]
            case "tools/list":
                resultObject = ["tools": Self.toolDefinitions]
            case "tools/call":
                let toolName = (params["name"] as? String) ?? ""
                let args = (params["arguments"] as? [String: Any]) ?? [:]
                let text = try await dispatchToolCall(name: toolName, arguments: args)
                resultObject = [
                    "content": [["type": "text", "text": text]],
                    "isError": false
                ]
            default:
                return encodeError(id: idValue, code: -32601, message: "Method not found: \(method)")
            }
            return encodeResult(id: idValue, result: resultObject)
        } catch let err as AgentVMError {
            return encodeResult(
                id: idValue,
                result: [
                    "content": [["type": "text", "text": "[\(err.errorCode)] \(err.localizedDescription)"]],
                    "isError": true
                ]
            )
        } catch {
            return encodeError(id: idValue, code: -32603, message: error.localizedDescription)
        }
    }

    public func runStdioLoop() async {
        while let line = readLine(strippingNewline: true) {
            if let resp = await handleJSONRPCLine(line) {
                print(resp)
                fflush(stdout)
            }
        }
    }

    private func dispatchToolCall(name: String, arguments: [String: Any]) async throws -> String {
        switch name {
        case "agentvm_list_fleet":
            let vms = try await coordinator.store.listVMs()
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            encoder.dateEncodingStrategy = .iso8601
            return String(decoding: try encoder.encode(vms), as: UTF8.self)

        case "agentvm_create_vm":
            let vmName = (arguments["name"] as? String) ?? "mcp-sandbox"
            let owner = (arguments["owner"] as? String) ?? "mcp-client"
            let cpus = (arguments["vcpus"] as? Int) ?? 2
            let mem = UInt64((arguments["memoryMB"] as? Int) ?? 2048)
            let created = try await coordinator.createSandboxVM(
                name: vmName,
                agentOwnerTag: owner,
                vcpus: cpus,
                memoryMB: mem
            )
            return "Created VM \(created.vmRecord.id.rawValue) ('\(created.vmRecord.spec.name)') with root snapshot \(created.rootSnapshot.id.rawValue)."

        case "agentvm_fork_cow_branch":
            guard let parentStr = arguments["parentVMID"] as? String,
                  let branchName = arguments["branchName"] as? String else {
                throw AgentVMError.cliUsageError(detail: "parentVMID and branchName are required.")
            }
            let owner = (arguments["owner"] as? String) ?? "mcp-branch"
            let parentID = VMID(parentStr)
            let parentRecord = try await coordinator.store.fetchVM(parentID)
            let bootNow = (arguments["bootImmediately"] as? Bool) ?? (parentRecord?.telemetry.state == .running)
            let forked = try await coordinator.forkCoWBranch(
                fromVMID: parentID,
                branchName: branchName,
                agentOwnerTag: owner,
                bootImmediately: bootNow
            )
            let isSim = await coordinator.currentExecutionBackend() == .deterministicSimulation
            let prefix = isSim ? "SIMULATED: " : ""
            return String(
                format: "%@Forked CoW branch %@ ('%@') in %.2f ms from snapshot %@.",
                prefix,
                forked.childVM.id.rawValue,
                forked.childVM.spec.name,
                forked.cloneDurationMilliseconds,
                forked.forkPointSnapshot.id.rawValue
            )

        case "agentvm_exec_command":
            guard let vmIDStr = arguments["vmID"] as? String,
                  let exe = arguments["executable"] as? String else {
                throw AgentVMError.cliUsageError(detail: "vmID and executable are required.")
            }
            let cmdArgs = (arguments["arguments"] as? [String]) ?? []
            let cwd = (arguments["workingDirectory"] as? String) ?? "/workspace"
            let res = try await coordinator.executeInGuest(
                vmID: VMID(vmIDStr),
                request: GuestExecRequest(executable: exe, arguments: cmdArgs, workingDirectory: cwd)
            )
            let isSim = await coordinator.currentExecutionBackend() == .deterministicSimulation
            let prefix = isSim ? "SIMULATED: " : ""
            return "\(prefix)exitCode=\(res.exitCode)\nstdout:\n\(res.stdoutUTF8)\nstderr:\n\(res.stderrUTF8)"

        case "agentvm_capture_snapshot":
            guard let vmIDStr = arguments["vmID"] as? String,
                  let title = arguments["title"] as? String else {
                throw AgentVMError.cliUsageError(detail: "vmID and title are required.")
            }
            let snap = try await coordinator.captureSnapshot(vmID: VMID(vmIDStr), title: title)
            return "Snapshot \(snap.id.rawValue) ('\(snap.title)') created."

        case "agentvm_restore_snapshot":
            guard let snapStr = arguments["snapshotID"] as? String else {
                throw AgentVMError.cliUsageError(detail: "snapshotID is required.")
            }
            let vm = try await coordinator.restoreToSnapshot(SnapshotID(snapStr))
            return "Restored VM \(vm.id.rawValue) to snapshot \(snapStr)."

        case "agentvm_query_wiretap":
            let filter = arguments["filter"] as? String
            let limit = (arguments["limit"] as? Int) ?? 40
            let pkts = await coordinator.l2Switch.recentPackets(limit: limit, filterQuery: filter)
            return pkts.map {
                "#\($0.sequenceNumber) [\($0.highestProtocol.rawValue)] \($0.sourceIP ?? $0.sourceMAC) -> \($0.destinationIP ?? $0.destinationMAC) [\($0.verdict.rawValue)] \($0.infoSummary)"
            }.joined(separator: "\n")

        case "agentvm_set_firewall_preset":
            let preset = (arguments["preset"] as? String)?.lowercased() ?? "strict"
            if preset == "airgap" {
                await coordinator.l2Switch.firewall.updatePolicy(.airgappedPreset())
                return "Applied Total Air-Gap firewall policy."
            } else {
                await coordinator.l2Switch.firewall.updatePolicy(.strictAgentAllowlistPreset())
                return "Applied Strict Coding-Agent Allowlist firewall policy."
            }

        case "agentvm_doctor":
            let caps = await coordinator.hostCapabilities()
            return "VZSupported=\(caps.isVirtualizationFrameworkSupported), arch=\(caps.architecture), cores=\(caps.physicalCores), memory=\(caps.hostMemoryGBFormatted)"

        default:
            throw AgentVMError.cliUsageError(detail: "Unknown MCP tool '\(name)'.")
        }
    }

    private func encodeResult(id: Any?, result: [String: Any]) -> String {
        let envelope: [String: Any] = [
            "jsonrpc": "2.0",
            "id": id ?? NSNull(),
            "result": result
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: envelope) else {
            return "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"encode failed\"}}"
        }
        return String(decoding: data, as: UTF8.self)
    }

    private func encodeError(id: Any?, code: Int, message: String) -> String {
        let envelope: [String: Any] = [
            "jsonrpc": "2.0",
            "id": id ?? NSNull(),
            "error": ["code": code, "message": message]
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: envelope) else {
            return "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"encode failed\"}}"
        }
        return String(decoding: data, as: UTF8.self)
    }
}
