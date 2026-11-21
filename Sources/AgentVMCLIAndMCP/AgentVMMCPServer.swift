import AgentVMHypervisor
import AgentVMModels
import AgentVMNetSwitch
import AgentVMPluginHost
import AgentVMStore
import CoreFoundation
import Foundation

// MARK: - JSON-RPC 2.0 Model Context Protocol (MCP) Server for Coding Agents

public actor AgentVMMCPServer {
    public static let defaultMaxExecOutputBytes = 16 * 1024 * 1024

    private let coordinator: AgentVMFleetCoordinator
    private let language: AppLanguage
    private let environment: [String: String]
    private let daemonSpawnOverride: DaemonSpawnCommandOverride?
    private let checkProcessEntitlement: Bool
    private let hasEntitlementOverride: Bool?
    private let maxExecOutputBytes: Int
    private let blockingIPCQueue = DispatchQueue(
        label: "io.zxu756.agentvm.mcp.daemon-ipc",
        qos: .userInitiated,
        attributes: .concurrent
    )

    public init(
        coordinator: AgentVMFleetCoordinator,
        language: AppLanguage = .en,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        daemonSpawnOverride: DaemonSpawnCommandOverride? = nil,
        checkProcessEntitlement: Bool = true,
        hasEntitlementOverride: Bool? = nil,
        maxExecOutputBytes: Int = AgentVMMCPServer.defaultMaxExecOutputBytes
    ) {
        self.coordinator = coordinator
        self.language = language
        self.environment = environment
        self.daemonSpawnOverride = daemonSpawnOverride
        self.checkProcessEntitlement = checkProcessEntitlement
        self.hasEntitlementOverride = hasEntitlementOverride
        self.maxExecOutputBytes = max(1024, maxExecOutputBytes)
    }

    public static var toolDefinitions: [[String: Any]] {
        [
            [
                "name": "agentvm_list_fleet",
                "description": "List all sandbox VM records as JSON (queries the live workspace daemon first on the default backend and falls back to SQLite when no daemon is running): lifecycle state, IPv4 address, allocatedDiskBytes, apfsPrivateBytes, and virtioFSMounts. telemetry.simulated is true when the state was written or is reported by the simulation backend.",
                "inputSchema": ["type": "object", "properties": [:]]
            ],
            [
                "name": "agentvm_create_vm",
                "description": "Create a sandbox VM in the workspace. When 'image' is provided (e.g. 'debian-12-bookworm-arm64'), clones the verified cached base image with optional 'diskSize' (e.g. '8G'), VirtioFS 'mounts' ([{hostPath, guestPath, readOnly?}]), and 'bootImmediately' (boots via the workspace daemon). When 'image' is omitted, creates an empty sparse GPT root disk with NoCloud cidata ISO.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "name": ["type": "string"],
                        "owner": ["type": "string"],
                        "vcpus": ["type": "integer"],
                        "memoryMB": ["type": "integer"],
                        "image": ["type": "string"],
                        "diskSize": ["type": "string"],
                        "mounts": [
                            "type": "array",
                            "items": [
                                "type": "object",
                                "properties": [
                                    "hostPath": ["type": "string"],
                                    "guestPath": ["type": "string"],
                                    "readOnly": ["type": "boolean"]
                                ],
                                "required": ["hostPath", "guestPath"]
                            ]
                        ],
                        "bootImmediately": ["type": "boolean"]
                    ],
                    "required": ["name"]
                ]
            ],
            [
                "name": "agentvm_fork_cow_branch",
                "description": "Fork an APFS clonefile(2) Copy-on-Write sandbox branch from an existing VM (accepts VM name or vm-... ID). Inherits parent VirtioFS mounts by default unless 'inheritMounts' is false; when 'bootImmediately' is true, runs pre-boot checks and starts the child VM via the workspace daemon.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "parentVMID": ["type": "string"],
                        "branchName": ["type": "string"],
                        "owner": ["type": "string"],
                        "bootImmediately": ["type": "boolean"],
                        "inheritMounts": ["type": "boolean"]
                    ],
                    "required": ["parentVMID", "branchName"]
                ]
            ],
            [
                "name": "agentvm_exec_command",
                "description": "Execute a command in a running sandbox VM via the workspace daemon's AVM1 session (accepts VM name or vm-... ID; defaults: runAsUser 'root', workingDirectory '/', timeoutSeconds 3600). Returns ERR_LIFECYCLE_STATE if the VM is not running. Under --backend simulation, replies come from the host-side simulator and every line is marked SIMULATED.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "vmID": ["type": "string"],
                        "executable": ["type": "string"],
                        "arguments": ["type": "array", "items": ["type": "string"]],
                        "workingDirectory": ["type": "string"],
                        "runAsUser": ["type": "string"],
                        "timeoutSeconds": ["type": "number"],
                        "environment": [
                            "type": "object",
                            "additionalProperties": ["type": "string"]
                        ]
                    ],
                    "required": ["vmID", "executable"]
                ]
            ],
            [
                "name": "agentvm_capture_snapshot",
                "description": "Capture an APFS CoW disk snapshot of a sandbox VM (routes via the workspace daemon when the VM is running).",
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
                "description": "Roll back a sandbox VM to an earlier snapshot node (routes via the workspace daemon when the VM is running).",
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
                "description": "Not implemented before M5 on the default backend (returns isError: true); under --backend simulation, queries the in-process simulated L2 switch demonstration ring.",
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
                "description": "Not implemented before M5 on the default backend (returns isError: true); under --backend simulation, selects the simulated workspace firewall preset ('strict' or 'airgap').",
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
                        text: "[\(err.errorCode)] \(err.localizedMessage(in: language))",
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
                        text: "[\(protoErr.errorCode)] \(protoErr.localizedMessage(in: language))",
                        isMachineReadableJSON: false,
                        isSimulation: isSimulation
                    ),
                    "isError": true
                ]
            } catch let launchErr as DaemonLaunchError {
                resultObject = [
                    "content": Self.markedContent(
                        text: "[\(launchErr.errorCode)] \(launchErr.localizedMessage(in: language))",
                        isMachineReadableJSON: false,
                        isSimulation: isSimulation
                    ),
                    "isError": true
                ]
            } catch let sockErr as DaemonSocketError {
                resultObject = [
                    "content": Self.markedContent(
                        text: "[\(sockErr.errorCode)] \(sockErr.localizedMessage(in: language))",
                        isMachineReadableJSON: false,
                        isSimulation: isSimulation
                    ),
                    "isError": true
                ]
            } catch let framingErr as DaemonRPCLineFramingError {
                resultObject = [
                    "content": Self.markedContent(
                        text: "[\(framingErr.errorCode)] \(framingErr.localizedMessage(in: language))",
                        isMachineReadableJSON: false,
                        isSimulation: isSimulation
                    ),
                    "isError": true
                ]
            } catch {
                resultObject = [
                    "content": Self.markedContent(
                        text: "[ERR_DAEMON_IPC] \(error.localizedDescription)",
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

    // MARK: - Blocking Daemon Socket Offload (Dedicated GCD Queue)

    private nonisolated func runBlockingIPC<T: Sendable>(
        _ operation: @escaping @Sendable () throws -> T
    ) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            blockingIPCQueue.async {
                do {
                    continuation.resume(returning: try operation())
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    private func effectiveEntitlementProvider() -> (@Sendable () -> Bool)? {
        if let explicitEnt = hasEntitlementOverride {
            return { explicitEnt }
        }
        if coordinator.hasHardwareBackendOverride {
            return { true }
        }
        return nil
    }

    private func bootVMViaWorkspaceDaemon(
        vmRecord: VMInstanceRecord,
        contextDescription: String
    ) async throws -> VMInstanceRecord {
        let wsURL = coordinator.store.bundleURL
        let lang = language
        _ = try await coordinator.preflightPersistentBoot(
            vmRecord.id,
            checkProcessEntitlement: checkProcessEntitlement,
            hasEntitlementOverride: effectiveEntitlementProvider()
        )
        do {
            _ = try await DaemonProcessLauncher.launchOrConnect(
                workspaceURL: wsURL,
                language: lang,
                environment: environment,
                spawnOverride: daemonSpawnOverride
            )
            let params = DaemonRPCVMLifecycleParams(vm: vmRecord.id.rawValue, lang: lang)
            let rpcOutcome = try await runBlockingIPC {
                try DaemonClient.performUnaryCall(
                    workspaceURL: wsURL,
                    call: .up(params),
                    resultType: DaemonRPCVMLifecycleResult.self
                )
            }
            switch rpcOutcome {
            case let .connected((_, lifeRes)):
                return lifeRes.vm
            case .daemonNotRunning:
                let paths = DaemonWorkspacePaths(workspaceURL: wsURL)
                throw AgentVMError.ipcDaemonUnavailable(
                    socketPath: paths.directSocketPath,
                    detail: "Workspace daemon closed connection before completing 'up'."
                )
            }
        } catch {
            let errCode: String
            let errDetail: String
            if let avmErr = error as? AgentVMError {
                errCode = avmErr.errorCode
                errDetail = avmErr.localizedMessage(in: lang)
            } else if let rpcErr = error as? DaemonRPCError {
                errCode = rpcErr.errorCode
                errDetail = rpcErr.message
            } else if let launchErr = error as? DaemonLaunchError {
                errCode = launchErr.errorCode
                errDetail = launchErr.localizedMessage(in: lang)
            } else if let protoErr = error as? DaemonRPCProtocolError {
                errCode = protoErr.errorCode
                errDetail = protoErr.localizedMessage(in: lang)
            } else if let sockErr = error as? DaemonSocketError {
                errCode = sockErr.errorCode
                errDetail = sockErr.localizedMessage(in: lang)
            } else {
                errCode = "ERR_DAEMON_IPC"
                errDetail = error.localizedDescription
            }
            let msg = "\(contextDescription) was created and kept in 'stopped' state without booting: \(errDetail)"
            throw DaemonRPCError(
                code: DaemonRPCError.internalErrorCode,
                errorCode: errCode,
                message: msg
            )
        }
    }

    // MARK: - Tool Dispatch

    private func dispatchToolCall(name: String, arguments: [String: Any]) async throws -> String {
        let wsURL = coordinator.store.bundleURL
        let lang = language
        let isSimulation = await coordinator.currentExecutionBackend() == .deterministicSimulation

        switch name {
        case "agentvm_list_fleet":
            let vms: [VMInstanceRecord]
            if !isSimulation {
                let rpcOutcome = try await runBlockingIPC {
                    try DaemonClient.performUnaryCall(
                        workspaceURL: wsURL,
                        call: .list(DaemonRPCListParams(lang: lang)),
                        resultType: DaemonRPCListResult.self
                    )
                }
                switch rpcOutcome {
                case let .connected((_, listResult)):
                    vms = listResult.vms
                case .daemonNotRunning:
                    vms = try await coordinator.listVMsForReporting(language: lang)
                }
            } else {
                vms = try await coordinator.listVMsForReporting(language: lang)
            }
            return try AgentVMCLIRunner.encodeFleetJSON(vms)

        case "agentvm_create_vm":
            let rawNameProvided = arguments["name"]
            let vmName: String
            if let rawName = rawNameProvided {
                guard let nameStr = rawName as? String else {
                    throw AgentVMError.cliUsageError(detail: "Parameter 'name' must be a non-empty string.")
                }
                let trimmed = nameStr.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !trimmed.isEmpty else {
                    throw AgentVMError.cliUsageError(detail: "Parameter 'name' must not be empty.")
                }
                vmName = trimmed
            } else {
                if arguments["image"] != nil {
                    throw AgentVMError.cliUsageError(detail: "Parameter 'name' is required when 'image' is specified.")
                }
                vmName = "mcp-sandbox"
            }

            let owner = try Self.extractOptionalString(from: arguments, key: "owner") ?? "mcp-client"
            let cpus: Int
            if let explicitCPUs = try Self.extractOptionalInt(from: arguments, key: "vcpus") {
                guard explicitCPUs >= 1 else {
                    throw AgentVMError.cliUsageError(
                        detail: "Invalid 'vcpus' value '\(explicitCPUs)' (expected integer >= 1)."
                    )
                }
                cpus = explicitCPUs
            } else {
                cpus = 2
            }

            let mem: UInt64
            if let explicitMem = try Self.extractOptionalInt(from: arguments, key: "memoryMB") {
                guard explicitMem >= 256 else {
                    throw AgentVMError.cliUsageError(
                        detail: "Invalid 'memoryMB' value '\(explicitMem)' (expected integer >= 256)."
                    )
                }
                mem = UInt64(explicitMem)
            } else {
                mem = 2048
            }

            let bootNow = try Self.extractOptionalBool(from: arguments, key: "bootImmediately") ?? false

            if arguments["diskSize"] != nil && arguments["image"] == nil {
                throw AgentVMError.cliUsageError(detail: "Option 'diskSize' requires 'image'.")
            }

            let resolvedImageID: String?
            if let rawImageObj = arguments["image"] {
                guard let rawImageStr = rawImageObj as? String else {
                    throw AgentVMError.cliUsageError(detail: "Option 'image' must be a non-empty string.")
                }
                let trimmed = rawImageStr.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !trimmed.isEmpty else {
                    throw AgentVMError.cliUsageError(detail: "Option 'image' requires a non-empty image ID.")
                }
                resolvedImageID = trimmed
            } else {
                resolvedImageID = nil
            }

            let requestedDiskBytes: UInt64?
            if let rawDiskObj = arguments["diskSize"] {
                guard let rawDiskStr = rawDiskObj as? String,
                      let parsedBytes = AgentVMCLIRunner.parseDiskSizeBytes(rawDiskStr) else {
                    throw AgentVMError.cliUsageError(
                        detail: "Invalid 'diskSize' value '\(rawDiskObj)' (expected <N>G, e.g. 8G)."
                    )
                }
                requestedDiskBytes = parsedBytes
            } else {
                requestedDiskBytes = nil
            }

            let parsedMounts = try Self.parseMCPMountsArgument(arguments["mounts"], language: lang)
            try AgentVMFleetCoordinator.verifySharedHostDirectories(parsedMounts)

            if bootNow && !isSimulation {
                guard resolvedImageID != nil else {
                    throw AgentVMError.noBootableSystem(
                        vmName: vmName,
                        reason: .emptyPartitionTable(fileName: "\(vmName).raw")
                    )
                }
                try coordinator.verifyHostCanStartHardwareVM(
                    checkProcessEntitlement: checkProcessEntitlement,
                    hasEntitlementOverride: effectiveEntitlementProvider()
                )
            }

            if let imageID = resolvedImageID {
                let created = try await coordinator.createVMFromImage(
                    name: vmName,
                    imageID: imageID,
                    requestedDiskBytes: requestedDiskBytes,
                    agentOwnerTag: owner,
                    vcpus: cpus,
                    memoryMB: mem,
                    sharedDirectories: parsedMounts
                )
                let diskBytes = created.vmRecord.spec.blockDevices.first?.virtualSizeBytes ?? created.rootSnapshot.virtualDiskBytes
                let sizeStr = ByteMetricsFormatter.formatBytes(diskBytes)
                if bootNow {
                    let booted: VMInstanceRecord
                    if isSimulation {
                        booted = try await coordinator.bootPersistentVM(created.vmRecord.id)
                    } else {
                        booted = try await bootVMViaWorkspaceDaemon(
                            vmRecord: created.vmRecord,
                            contextDescription: "Created VM '\(created.vmRecord.spec.name)' (\(created.vmRecord.id.rawValue))"
                        )
                    }
                    return "Created VM \(booted.id.rawValue) ('\(booted.spec.name)') from image '\(imageID)' (disk \(sizeStr)) with root snapshot \(created.rootSnapshot.id.rawValue) and booted to state '\(booted.telemetry.state.rawValue)'."
                }
                return "Created VM \(created.vmRecord.id.rawValue) ('\(created.vmRecord.spec.name)') from image '\(imageID)' (disk \(sizeStr)) with root snapshot \(created.rootSnapshot.id.rawValue)."
            }

            let created = try await coordinator.createSandboxVM(
                name: vmName,
                agentOwnerTag: owner,
                vcpus: cpus,
                memoryMB: mem,
                sharedDirectories: parsedMounts
            )
            if bootNow {
                let booted = try await coordinator.bootPersistentVM(created.vmRecord.id)
                return "Created VM \(booted.id.rawValue) ('\(booted.spec.name)') with root snapshot \(created.rootSnapshot.id.rawValue) and booted to state '\(booted.telemetry.state.rawValue)'."
            }
            return "Created VM \(created.vmRecord.id.rawValue) ('\(created.vmRecord.spec.name)') with root snapshot \(created.rootSnapshot.id.rawValue) (empty sparse GPT disk, no guest OS installed)."

        case "agentvm_fork_cow_branch":
            guard let rawParent = arguments["parentVMID"] as? String,
                  let rawBranch = arguments["branchName"] as? String else {
                throw AgentVMError.cliUsageError(detail: "parentVMID and branchName are required.")
            }
            let parentStr = rawParent.trimmingCharacters(in: .whitespacesAndNewlines)
            let branchName = rawBranch.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !parentStr.isEmpty, !branchName.isEmpty else {
                throw AgentVMError.cliUsageError(detail: "parentVMID and branchName must not be empty.")
            }
            let owner = try Self.extractOptionalString(from: arguments, key: "owner") ?? "mcp-branch"
            let bootNow = try Self.extractOptionalBool(from: arguments, key: "bootImmediately") ?? false
            let inheritMounts = try Self.extractOptionalBool(from: arguments, key: "inheritMounts") ?? true

            let parentID = try await resolveMCPVMID(parentStr)
            if bootNow && !isSimulation {
                _ = try await coordinator.preflightPersistentBoot(
                    parentID,
                    checkProcessEntitlement: checkProcessEntitlement,
                    hasEntitlementOverride: effectiveEntitlementProvider(),
                    verifySharedDirectories: inheritMounts
                )
            }

            let forked: CoWBranchForkResult
            if !isSimulation,
               try await runBlockingIPC({
                   try DaemonClient.isVMHeldByRunningDaemon(
                       workspaceURL: wsURL,
                       vmID: parentID,
                       language: lang
                   )
               }) {
                let branchParams = DaemonRPCBranchParams(
                    vm: parentID.rawValue,
                    branchName: branchName,
                    owner: owner,
                    inheritMounts: inheritMounts,
                    lang: lang
                )
                let rpcOutcome = try await runBlockingIPC {
                    try DaemonClient.performUnaryCall(
                        workspaceURL: wsURL,
                        call: .branch(branchParams),
                        resultType: DaemonRPCBranchResult.self
                    )
                }
                switch rpcOutcome {
                case let .connected((_, branchRes)):
                    forked = branchRes.fork
                case .daemonNotRunning:
                    forked = try await coordinator.forkCoWBranch(
                        fromVMID: parentID,
                        branchName: branchName,
                        agentOwnerTag: owner,
                        bootImmediately: false,
                        inheritMounts: inheritMounts
                    )
                }
            } else {
                forked = try await coordinator.forkCoWBranch(
                    fromVMID: parentID,
                    branchName: branchName,
                    agentOwnerTag: owner,
                    bootImmediately: false,
                    inheritMounts: inheritMounts
                )
            }

            if bootNow {
                let booted: VMInstanceRecord
                if isSimulation {
                    booted = try await coordinator.bootPersistentVM(forked.childVM.id)
                } else {
                    booted = try await bootVMViaWorkspaceDaemon(
                        vmRecord: forked.childVM,
                        contextDescription: "Child VM '\(forked.childVM.spec.name)' (\(forked.childVM.id.rawValue), forked from snapshot \(forked.forkPointSnapshot.id.rawValue))"
                    )
                }
                return String(
                    format: "Forked CoW branch %@ ('%@') in %.2f ms from snapshot %@ and booted to state '%@'.",
                    booted.id.rawValue,
                    booted.spec.name,
                    forked.cloneDurationMilliseconds,
                    forked.forkPointSnapshot.id.rawValue,
                    booted.telemetry.state.rawValue
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
            guard let rawVMID = arguments["vmID"] as? String,
                  let exe = arguments["executable"] as? String else {
                throw AgentVMError.cliUsageError(detail: "vmID and executable are required.")
            }
            let vmToken = rawVMID.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !vmToken.isEmpty, !exe.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw AgentVMError.cliUsageError(detail: "vmID and executable must not be empty.")
            }
            let cmdArgs = try Self.extractOptionalStringArray(from: arguments, key: "arguments") ?? []
            let cwd = try Self.extractOptionalString(from: arguments, key: "workingDirectory")
                ?? DaemonRPCExecParams.defaultWorkingDirectory
            let runAsUser: String
            if let explicitUser = try Self.extractOptionalString(from: arguments, key: "runAsUser") {
                let trimmedUser = explicitUser.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !trimmedUser.isEmpty else {
                    throw AgentVMError.cliUsageError(detail: "Option 'runAsUser' must not be empty.")
                }
                runAsUser = trimmedUser
            } else {
                runAsUser = DaemonRPCExecParams.defaultRunAsUser
            }
            let timeoutSeconds = try Self.extractOptionalPositiveSeconds(from: arguments, key: "timeoutSeconds")
                ?? DaemonRPCExecParams.defaultTimeoutSeconds
            let execEnv = try Self.extractOptionalStringMap(from: arguments, key: "environment") ?? [:]

            let resolvedVMID = try await resolveMCPVMID(vmToken)

            if isSimulation {
                let res = try await coordinator.executeInGuest(
                    vmID: resolvedVMID,
                    request: GuestExecRequest(
                        executable: exe,
                        arguments: cmdArgs,
                        workingDirectory: cwd,
                        environment: execEnv,
                        runAsUser: runAsUser,
                        timeoutSeconds: timeoutSeconds
                    )
                )
                return "exitCode=\(res.exitCode)\nstdout:\n\(res.stdoutUTF8)\nstderr:\n\(res.stderrUTF8)"
            }

            let execParams = DaemonRPCExecParams(
                vm: resolvedVMID.rawValue,
                executable: exe,
                arguments: cmdArgs,
                workingDirectory: cwd,
                runAsUser: runAsUser,
                environment: execEnv,
                timeoutSeconds: timeoutSeconds,
                lang: lang
            )
            let hardLimit = maxExecOutputBytes
            let collector = BoundedMCPExecOutputCollector(maxBytes: hardLimit)
            let rpcOutcome: DaemonClientConnectionResult<(daemonHello: DaemonRPCHello, result: DaemonRPCExecResult)>
            do {
                rpcOutcome = try await runBlockingIPC {
                    try DaemonClient.performExecCall(
                        workspaceURL: wsURL,
                        params: execParams,
                        onConnectionEstablished: { conn in
                            collector.bindConnection(conn)
                        },
                        onOutputChunk: { chunk in
                            collector.append(chunk)
                        }
                    )
                }
            } catch {
                if let attemptedBytes = collector.overflowAttemptedBytes {
                    throw AgentVMError.execOutputBufferOverflow(
                        vmID: resolvedVMID,
                        streamID: 0,
                        queuedBytes: attemptedBytes,
                        hardLimitBytes: hardLimit
                    )
                }
                throw error
            }
            if let attemptedBytes = collector.overflowAttemptedBytes {
                throw AgentVMError.execOutputBufferOverflow(
                    vmID: resolvedVMID,
                    streamID: 0,
                    queuedBytes: attemptedBytes,
                    hardLimitBytes: hardLimit
                )
            }

            switch rpcOutcome {
            case let .connected((_, execRes)):
                let collected = collector.snapshot()
                let stdoutUTF8 = String(decoding: collected.stdout, as: UTF8.self)
                let stderrUTF8 = String(decoding: collected.stderr, as: UTF8.self)
                return "exitCode=\(execRes.exitCode)\nstdout:\n\(stdoutUTF8)\nstderr:\n\(stderrUTF8)"
            case .daemonNotRunning:
                let rec = try await coordinator.prepareDisconnectedVMForClientOperation(resolvedVMID, language: lang)
                throw DaemonLifecycleErrorFormatter.execNotRunningRPCError(
                    vmName: rec.spec.name,
                    vmID: rec.id,
                    state: rec.telemetry.state,
                    language: lang
                )
            }

        case "agentvm_capture_snapshot":
            guard let vmIDStr = arguments["vmID"] as? String,
                  let title = arguments["title"] as? String else {
                throw AgentVMError.cliUsageError(detail: "vmID and title are required.")
            }
            let targetVMID = try await resolveMCPVMID(vmIDStr)
            let snap: SnapshotNode
            if !isSimulation,
               try await runBlockingIPC({
                   try DaemonClient.isVMHeldByRunningDaemon(
                       workspaceURL: wsURL,
                       vmID: targetVMID,
                       language: lang
                   )
               }) {
                let rpcOutcome = try await runBlockingIPC {
                    try DaemonClient.performUnaryCall(
                        workspaceURL: wsURL,
                        call: .snapshot(DaemonRPCSnapshotParams(vm: targetVMID.rawValue, title: title, lang: lang)),
                        resultType: DaemonRPCSnapshotResult.self
                    )
                }
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
            let targetVMID = snapNode.vmID
            let vm: VMInstanceRecord
            let preRestoreSnapshot: SnapshotNode
            if !isSimulation,
               try await runBlockingIPC({
                   try DaemonClient.isVMHeldByRunningDaemon(
                       workspaceURL: wsURL,
                       vmID: targetVMID,
                       language: lang
                   )
               }) {
                let rpcOutcome = try await runBlockingIPC {
                    try DaemonClient.performUnaryCall(
                        workspaceURL: wsURL,
                        call: .restore(DaemonRPCRestoreParams(snapshotID: snapID.rawValue, lang: lang)),
                        resultType: DaemonRPCRestoreResult.self
                    )
                }
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
                        language: lang
                    )
                }
            } else {
                (vm, preRestoreSnapshot, _) = try await coordinator.restoreToSnapshotReportingStrategy(
                    snapID,
                    language: lang
                )
            }
            return "Restored VM \(vm.id.rawValue) to snapshot \(snapStr) (pre-restore snapshot: \(preRestoreSnapshot.id.rawValue))."

        case "agentvm_query_wiretap":
            guard isSimulation else {
                throw AgentVMError.unimplementedBeforeM5(feature: "agentvm_query_wiretap")
            }
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
            guard isSimulation else {
                throw AgentVMError.unimplementedBeforeM5(feature: "agentvm_set_firewall_preset")
            }
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

    // MARK: - Strict JSON Argument Validation Helpers

    private static func isJSONBool(_ value: Any) -> Bool {
        guard let num = value as? NSNumber else { return value is Bool }
        return CFGetTypeID(num) == CFBooleanGetTypeID()
    }

    private static func extractOptionalBool(from arguments: [String: Any], key: String) throws -> Bool? {
        guard let raw = arguments[key], !(raw is NSNull) else { return nil }
        guard isJSONBool(raw), let flag = raw as? Bool else {
            throw AgentVMError.cliUsageError(detail: "Option '\(key)' must be a boolean (true or false).")
        }
        return flag
    }

    private static func extractOptionalInt(from arguments: [String: Any], key: String) throws -> Int? {
        guard let raw = arguments[key], !(raw is NSNull) else { return nil }
        guard !isJSONBool(raw), let num = raw as? NSNumber else {
            throw AgentVMError.cliUsageError(detail: "Option '\(key)' must be an integer.")
        }
        let d = num.doubleValue
        let i64 = num.int64Value
        guard d.isFinite, Double(i64) == d, let val = Int(exactly: i64) else {
            throw AgentVMError.cliUsageError(detail: "Option '\(key)' must be an integer.")
        }
        return val
    }

    private static func extractOptionalPositiveSeconds(
        from arguments: [String: Any],
        key: String
    ) throws -> TimeInterval? {
        guard let raw = arguments[key], !(raw is NSNull) else { return nil }
        guard !isJSONBool(raw), let num = raw as? NSNumber else {
            throw AgentVMError.cliUsageError(detail: "Option '\(key)' must be a positive number of seconds.")
        }
        let secs = num.doubleValue
        guard secs.isFinite && secs > 0 else {
            throw AgentVMError.cliUsageError(detail: "Option '\(key)' must be a finite number > 0.")
        }
        return secs
    }

    private static func extractOptionalString(from arguments: [String: Any], key: String) throws -> String? {
        guard let raw = arguments[key], !(raw is NSNull) else { return nil }
        guard let str = raw as? String else {
            throw AgentVMError.cliUsageError(detail: "Option '\(key)' must be a string.")
        }
        return str
    }

    private static func extractOptionalStringArray(from arguments: [String: Any], key: String) throws -> [String]? {
        guard let raw = arguments[key], !(raw is NSNull) else { return nil }
        guard let arr = raw as? [Any] else {
            throw AgentVMError.cliUsageError(detail: "Option '\(key)' must be an array of strings.")
        }
        var strings: [String] = []
        strings.reserveCapacity(arr.count)
        for item in arr {
            guard let s = item as? String else {
                throw AgentVMError.cliUsageError(detail: "Option '\(key)' must contain only string elements.")
            }
            strings.append(s)
        }
        return strings
    }

    private static func extractOptionalStringMap(
        from arguments: [String: Any],
        key: String
    ) throws -> [String: String]? {
        guard let raw = arguments[key], !(raw is NSNull) else { return nil }
        guard let dict = raw as? [String: Any] else {
            throw AgentVMError.cliUsageError(detail: "Option '\(key)' must be an object mapping string keys to string values.")
        }
        var result: [String: String] = [:]
        result.reserveCapacity(dict.count)
        for (k, v) in dict {
            guard !k.isEmpty, !k.contains("="), !k.contains("\0"), let sv = v as? String else {
                throw AgentVMError.cliUsageError(
                    detail: "Option '\(key)' contains invalid key '\(k)' or non-string value."
                )
            }
            result[k] = sv
        }
        return result
    }

    private static func parseMCPMountsArgument(
        _ rawMountsValue: Any?,
        language: AppLanguage
    ) throws -> [VirtioFSMountSpec] {
        guard let rawMountsValue, !(rawMountsValue is NSNull) else {
            return []
        }
        guard let rawList = rawMountsValue as? [Any] else {
            throw AgentVMError.cliUsageError(
                detail: "Option 'mounts' must be an array of {hostPath, guestPath, readOnly?} objects."
            )
        }

        var entries: [(rawLabel: String, hostPath: String, guestPath: String, readOnly: Bool)] = []
        entries.reserveCapacity(rawList.count)

        for (idx, item) in rawList.enumerated() {
            guard let dict = item as? [String: Any] else {
                throw AgentVMError.cliUsageError(
                    detail: "Invalid 'mounts[\(idx)]': expected an object with 'hostPath' and 'guestPath'."
                )
            }
            for key in dict.keys where key != "hostPath" && key != "guestPath" && key != "readOnly" {
                throw AgentVMError.cliUsageError(
                    detail: "Invalid 'mounts[\(idx)]': unknown field '\(key)' (expected 'hostPath', 'guestPath', optional 'readOnly')."
                )
            }
            guard let hostPath = dict["hostPath"] as? String else {
                throw AgentVMError.cliUsageError(
                    detail: "Invalid 'mounts[\(idx)]': 'hostPath' is required and must be a string."
                )
            }
            guard let guestPath = dict["guestPath"] as? String else {
                throw AgentVMError.cliUsageError(
                    detail: "Invalid 'mounts[\(idx)]': 'guestPath' is required and must be a string."
                )
            }
            let readOnly = try extractOptionalBool(from: dict, key: "readOnly") ?? false
            let label = "\(hostPath):\(guestPath)\(readOnly ? ":ro" : "")"
            entries.append((rawLabel: label, hostPath: hostPath, guestPath: guestPath, readOnly: readOnly))
        }

        switch AgentVMCLIRunner.validateAndBuildMountSpecs(entries, language: language) {
        case let .success(specs):
            return specs
        case let .failure(usageErr):
            throw AgentVMError.cliUsageError(detail: usageErr.message)
        }
    }

    // MARK: - VMID Resolution & JSON-RPC Framing

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

// MARK: - Bounded Thread-Safe Output Collector for MCP `agentvm_exec_command`

private final class BoundedMCPExecOutputCollector: @unchecked Sendable {
    private let lock = NSLock()
    private let maxBytes: Int
    private var stdoutBuffer = Data()
    private var stderrBuffer = Data()
    private var activeConnection: DaemonSocketConnection?
    private var overflowBytesRecorded: Int?

    init(maxBytes: Int) {
        self.maxBytes = max(1024, maxBytes)
    }

    func bindConnection(_ conn: DaemonSocketConnection) {
        let shouldCloseImmediately = lock.withLock { () -> Bool in
            activeConnection = conn
            return overflowBytesRecorded != nil
        }
        if shouldCloseImmediately {
            conn.close()
        }
    }

    func append(_ chunk: DaemonRPCExecOutputParams) {
        guard !chunk.data.isEmpty else { return }
        let connToAbort: DaemonSocketConnection? = lock.withLock {
            if overflowBytesRecorded != nil {
                return nil
            }
            let currentTotal = stdoutBuffer.count + stderrBuffer.count
            let nextTotal = currentTotal + chunk.data.count
            if nextTotal > maxBytes {
                overflowBytesRecorded = nextTotal
                return activeConnection
            }
            switch chunk.stream {
            case .stdout:
                stdoutBuffer.append(chunk.data)
            case .stderr:
                stderrBuffer.append(chunk.data)
            }
            return nil
        }
        connToAbort?.close()
    }

    var overflowAttemptedBytes: Int? {
        lock.withLock { overflowBytesRecorded }
    }

    func snapshot() -> (stdout: Data, stderr: Data) {
        lock.withLock { (stdoutBuffer, stderrBuffer) }
    }
}
