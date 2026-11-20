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
                "description": "List all sandbox VM records as JSON: lifecycle state, IPv4 address, allocatedDiskBytes, and apfsPrivateBytes (bytes not shared with other APFS clones). telemetry.simulated is true when the state was written or is reported by the simulation backend (no real guest behind it).",
                "inputSchema": ["type": "object", "properties": [:]]
            ],
            [
                "name": "agentvm_create_vm",
                "description": "Create a sandbox VM record with an empty sparse GPT root disk and a NoCloud cidata ISO. No guest OS is installed; the name must be unique in the workspace.",
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
                "description": "Execute a command in a sandbox VM through the AVM1 session after pre-exec JS guardrails. In this build no real guest can be booted, so the call fails on the default backend; under --backend simulation the reply comes from the host-side simulator and every line is marked SIMULATED.",
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
                "description": "Capture an APFS CoW disk snapshot of a sandbox VM. Guest RAM state is saved only for a VM actually running on the hardware backend; the simulation backend records disk only.",
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
                "description": "Query the in-process L2 switch capture ring with boolean filter expressions (e.g. 'proto == TLS && verdict == DROP'). No guest traffic reaches the switch before M5, so the ring only holds frames injected in this process.",
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
                "description": "Select the workspace firewall preset ('strict' coding-agent allowlist or 'airgap') and save it to the workspace. Not enforced on guest traffic before M5.",
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
                "description": "Return host diagnostics: Virtualization.framework support, whether this executable has the virtualization entitlement, whether it can start VMs, architecture, cores, memory.",
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
                // Single exit point for tool results: under the simulation backend every result, success or
                // error, leaves through `markedContent`, so a tool cannot return unmarked simulated output.
                let isSimulation = await coordinator.currentExecutionBackend() == .deterministicSimulation
                do {
                    let text = try await dispatchToolCall(name: toolName, arguments: args)
                    resultObject = [
                        "content": Self.markedContent(
                            text: text,
                            isMachineReadableJSON: Self.jsonResultTools.contains(toolName),
                            isSimulation: isSimulation
                        ),
                        "isError": false
                    ]
                } catch let err as AgentVMError {
                    resultObject = [
                        "content": Self.markedContent(
                            text: "[\(err.errorCode)] \(err.localizedDescription)",
                            isMachineReadableJSON: false,
                            isSimulation: isSimulation
                        ),
                        "isError": true
                    ]
                } catch let rpcErr as DaemonRPCError {
                    resultObject = [
                        "content": Self.markedContent(
                            text: "[\(rpcErr.errorCode)] \(rpcErr.message)",
                            isMachineReadableJSON: false,
                            isSimulation: isSimulation
                        ),
                        "isError": true
                    ]
                } catch let protoErr as DaemonRPCProtocolError {
                    resultObject = [
                        "content": Self.markedContent(
                            text: "[\(protoErr.errorCode)] \(protoErr.localizedMessage(in: .en))",
                            isMachineReadableJSON: false,
                            isSimulation: isSimulation
                        ),
                        "isError": true
                    ]
                }
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

    /// Tools whose text result is JSON and must stay parseable.
    static let jsonResultTools: Set<String> = ["agentvm_list_fleet"]

    /// Builds the `content` array of a tool result.
    /// - Simulation backend, plain text: every line is prefixed with `SIMULATED: `.
    /// - Simulation backend, JSON: the JSON block is left intact (its records carry `"simulated": true`) and a
    ///   second, marked text block is appended, so even an empty list comes back with a marker.
    static func markedContent(text: String, isMachineReadableJSON: Bool, isSimulation: Bool) -> [[String: Any]] {
        guard isSimulation else {
            return [["type": "text", "text": text]]
        }
        if isMachineReadableJSON {
            return [
                ["type": "text", "text": text],
                ["type": "text", "text": "SIMULATED: the JSON above is reported by the simulation backend; every record has telemetry.simulated = true and its runtime state does not come from a real guest."]
            ]
        }
        let marked = text.isEmpty
            ? "SIMULATED: (no output)"
            : AgentVMCLIRunner.prefixSimulatedLines(text)
        return [["type": "text", "text": marked]]
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
            return try AgentVMCLIRunner.encodeFleetJSON(try await coordinator.listVMsForReporting())

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
            return "Created VM \(created.vmRecord.id.rawValue) ('\(created.vmRecord.spec.name)') with root snapshot \(created.rootSnapshot.id.rawValue) (empty sparse GPT disk, no guest OS installed)."

        case "agentvm_fork_cow_branch":
            guard let parentStr = arguments["parentVMID"] as? String,
                  let branchName = arguments["branchName"] as? String else {
                throw AgentVMError.cliUsageError(detail: "parentVMID and branchName are required.")
            }
            let owner = (arguments["owner"] as? String) ?? "mcp-branch"
            let parentID = try await resolveMCPVMID(parentStr)
            let bootNow = (arguments["bootImmediately"] as? Bool) ?? false
            let isSimulation = await coordinator.currentExecutionBackend() == .deterministicSimulation
            let forked: CoWBranchForkResult
            if !isSimulation,
               try DaemonClient.isVMHeldByRunningDaemon(
                   workspaceURL: coordinator.store.bundleURL,
                   vmID: parentID,
                   language: .en
               ) {
                let rpcOutcome = try DaemonClient.performUnaryCall(
                    workspaceURL: coordinator.store.bundleURL,
                    call: .branch(DaemonRPCBranchParams(vm: parentID.rawValue, branchName: branchName, owner: owner, lang: .en)),
                    resultType: DaemonRPCBranchResult.self
                )
                switch rpcOutcome {
                case let .connected((_, branchRes)):
                    var resolvedFork = branchRes.fork
                    if bootNow {
                        resolvedFork.childVM = try await coordinator.bootPersistentVM(resolvedFork.childVM.id)
                    }
                    forked = resolvedFork
                case .daemonNotRunning:
                    forked = try await coordinator.forkCoWBranch(
                        fromVMID: parentID,
                        branchName: branchName,
                        agentOwnerTag: owner,
                        bootImmediately: bootNow
                    )
                }
            } else {
                forked = try await coordinator.forkCoWBranch(
                    fromVMID: parentID,
                    branchName: branchName,
                    agentOwnerTag: owner,
                    bootImmediately: bootNow
                )
            }
            return String(
                format: "Forked CoW branch %@ ('%@') in %.2f ms from snapshot %@.",
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
            return "exitCode=\(res.exitCode)\nstdout:\n\(res.stdoutUTF8)\nstderr:\n\(res.stderrUTF8)"

        case "agentvm_capture_snapshot":
            guard let vmIDStr = arguments["vmID"] as? String,
                  let title = arguments["title"] as? String else {
                throw AgentVMError.cliUsageError(detail: "vmID and title are required.")
            }
            let targetVMID = try await resolveMCPVMID(vmIDStr)
            let isSimulation = await coordinator.currentExecutionBackend() == .deterministicSimulation
            let snap: SnapshotNode
            if !isSimulation,
               try DaemonClient.isVMHeldByRunningDaemon(
                   workspaceURL: coordinator.store.bundleURL,
                   vmID: targetVMID,
                   language: .en
               ) {
                let rpcOutcome = try DaemonClient.performUnaryCall(
                    workspaceURL: coordinator.store.bundleURL,
                    call: .snapshot(DaemonRPCSnapshotParams(vm: targetVMID.rawValue, title: title, lang: .en)),
                    resultType: DaemonRPCSnapshotResult.self
                )
                switch rpcOutcome {
                case let .connected((_, snapRes)):
                    snap = snapRes.snapshot
                case .daemonNotRunning:
                    snap = try await coordinator.captureSnapshot(vmID: targetVMID, title: title)
                }
            } else {
                snap = try await coordinator.captureSnapshot(vmID: targetVMID, title: title)
            }
            return "Snapshot \(snap.id.rawValue) ('\(snap.title)') created."

        case "agentvm_restore_snapshot":
            guard let snapStr = arguments["snapshotID"] as? String else {
                throw AgentVMError.cliUsageError(detail: "snapshotID is required.")
            }
            let snapID = SnapshotID(snapStr)
            guard let snapNode = try await coordinator.store.fetchSnapshot(snapID) else {
                throw AgentVMError.snapshotNotFound(snapID)
            }
            let isSimulation = await coordinator.currentExecutionBackend() == .deterministicSimulation
            let vm: VMInstanceRecord
            let preRestoreSnapshot: SnapshotNode
            if !isSimulation,
               try DaemonClient.isVMHeldByRunningDaemon(
                   workspaceURL: coordinator.store.bundleURL,
                   vmID: snapNode.vmID,
                   language: .en
               ) {
                let rpcOutcome = try DaemonClient.performUnaryCall(
                    workspaceURL: coordinator.store.bundleURL,
                    call: .restore(DaemonRPCRestoreParams(snapshotID: snapID.rawValue, lang: .en)),
                    resultType: DaemonRPCRestoreResult.self
                )
                switch rpcOutcome {
                case let .connected((_, restoreRes)):
                    vm = restoreRes.vm
                    guard let capturedPre = restoreRes.preRestoreSnapshot else {
                        throw DaemonRPCProtocolError.malformedEnvelope(
                            detail: "Daemon restore result omitted required preRestoreSnapshot."
                        )
                    }
                    preRestoreSnapshot = capturedPre
                case .daemonNotRunning:
                    (vm, preRestoreSnapshot, _) = try await coordinator.restoreToSnapshotReportingStrategy(
                        snapID,
                        language: .en
                    )
                }
            } else {
                (vm, preRestoreSnapshot, _) = try await coordinator.restoreToSnapshotReportingStrategy(
                    snapID,
                    language: .en
                )
            }
            return "Restored VM \(vm.id.rawValue) to snapshot \(snapStr) (pre-restore snapshot: \(preRestoreSnapshot.id.rawValue))."

        case "agentvm_query_wiretap":
            let filter = arguments["filter"] as? String
            let limit = (arguments["limit"] as? Int) ?? 40
            let pkts = await coordinator.l2Switch.recentPackets(limit: limit, filterQuery: filter)
            if pkts.isEmpty {
                return "0 packets. The capture ring is in-memory and per-process, and no guest traffic reaches the switch before M5."
            }
            return pkts.map {
                "#\($0.sequenceNumber) [\($0.highestProtocol.rawValue)] \($0.sourceIP ?? $0.sourceMAC) -> \($0.destinationIP ?? $0.destinationMAC) [\($0.verdict.rawValue)] \($0.infoSummary)"
            }.joined(separator: "\n")

        case "agentvm_set_firewall_preset":
            guard let preset = (arguments["preset"] as? String)?.lowercased() else {
                throw AgentVMError.cliUsageError(detail: "preset is required ('strict' or 'airgap').")
            }
            let caveat = "Saved to the workspace. No guest traffic passes through this policy before M5, so nothing is enforced on real traffic yet."
            switch preset {
            case "airgap":
                try await coordinator.activateFirewallPolicy(.airgappedPreset())
                return "Workspace firewall preset set to Total Air-Gap. \(caveat)"
            case "strict":
                try await coordinator.activateFirewallPolicy(.strictAgentAllowlistPreset())
                return "Workspace firewall preset set to Strict Coding-Agent Allowlist. \(caveat)"
            default:
                throw AgentVMError.cliUsageError(detail: "Unknown firewall preset '\(preset)' (expected 'strict' or 'airgap').")
            }

        case "agentvm_doctor":
            let caps = await coordinator.hostCapabilities()
            return "VZSupported=\(caps.isVirtualizationFrameworkSupported), VZEntitled=\(caps.hasVirtualizationEntitlement), canStartVMs=\(caps.canStartVirtualMachines), arch=\(caps.architecture), cores=\(caps.physicalCores), memory=\(caps.hostMemoryGBFormatted)"

        default:
            throw AgentVMError.cliUsageError(detail: "Unknown MCP tool '\(name)'.")
        }
    }

    private func resolveMCPVMID(_ token: String) async throws -> VMID {
        let vms = try await coordinator.store.listVMs()
        if let exact = vms.first(where: { $0.id.rawValue == token }) {
            return exact.id
        }
        if let byName = vms.first(where: { $0.spec.name.caseInsensitiveCompare(token) == .orderedSame }) {
            return byName.id
        }
        return VMID(token)
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
