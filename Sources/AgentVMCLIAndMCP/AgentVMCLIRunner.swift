import AgentVMHypervisor
import AgentVMModels
import AgentVMNetSwitch
import AgentVMPluginHost
import AgentVMStorageCoW
import AgentVMStore
import AgentVMVsockRPC
import Foundation

// MARK: - Complete Headless Multi-Subcommand CLI Engine (`agentvm <subcommand>`)

public struct CLIExecutionOutcome: Codable, Hashable, Sendable {
    public var exitCode: Int32
    public var stdout: String
    public var stderr: String

    public init(exitCode: Int32, stdout: String = "", stderr: String = "") {
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
    }
}

public struct AgentVMCLIRunner: Sendable {
    public init() {}

    public static func defaultWorkspaceBundleURL() -> URL {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory())
        return appSupport
            .appendingPathComponent("AgentVM", isDirectory: true)
            .appendingPathComponent("DefaultFleet.agentvm", isDirectory: true)
    }

    public func execute(
        arguments: [String],
        bundleURLOverride: URL? = nil
    ) async -> CLIExecutionOutcome {
        if let cliLang = AppLanguage.extractCLILanguage(from: arguments) {
            await MainActor.run {
                AgentVMLocalizer.shared.setLanguage(cliLang, persist: false)
            }
        }
        var args = AppLanguage.strippingLanguageArguments(from: arguments)
        var resolvedBundleURL = bundleURLOverride ?? Self.defaultWorkspaceBundleURL()

        // Extract global --workspace <path> option if provided
        var cleaned: [String] = []
        var idx = 0
        while idx < args.count {
            if args[idx] == "--workspace" || args[idx] == "-w", idx + 1 < args.count {
                resolvedBundleURL = URL(fileURLWithPath: args[idx + 1])
                idx += 2
            } else {
                cleaned.append(args[idx])
                idx += 1
            }
        }
        args = cleaned

        guard let subcommand = args.first else {
            return CLIExecutionOutcome(exitCode: 0, stdout: Self.helpBanner())
        }
        let rest = Array(args.dropFirst())

        if subcommand == "--help" || subcommand == "-h" || subcommand == "help" {
            return CLIExecutionOutcome(exitCode: 0, stdout: Self.helpBanner())
        }
        if subcommand == "--version" || subcommand == "version" {
            return CLIExecutionOutcome(exitCode: 0, stdout: "agentvm \(SemanticVersion.current.description) (arm64-apple-darwin)\n")
        }

        do {
            let coordinator = try AgentVMFleetCoordinator(bundleURL: resolvedBundleURL)

            switch subcommand {
            case "doctor":
                return try await runDoctor(coordinator: coordinator)
            case "init":
                return try await runInit(coordinator: coordinator, args: rest)
            case "ps", "list":
                return try await runListVMs(coordinator: coordinator, asJSON: rest.contains("--json"))
            case "create":
                return try await runCreateVM(coordinator: coordinator, args: rest)
            case "up", "boot", "start":
                return try await runLifecycle(coordinator: coordinator, action: "boot", args: rest)
            case "pause":
                return try await runLifecycle(coordinator: coordinator, action: "pause", args: rest)
            case "resume":
                return try await runLifecycle(coordinator: coordinator, action: "resume", args: rest)
            case "halt", "stop":
                return try await runLifecycle(coordinator: coordinator, action: "halt", args: rest)
            case "branch", "fork":
                return try await runBranchFork(coordinator: coordinator, args: rest)
            case "snapshot":
                return try await runSnapshot(coordinator: coordinator, args: rest)
            case "restore":
                return try await runRestore(coordinator: coordinator, args: rest)
            case "exec":
                return try await runExec(coordinator: coordinator, args: rest)
            case "pcap":
                return try await runPCAP(coordinator: coordinator, args: rest)
            case "policy":
                return try await runPolicy(coordinator: coordinator, args: rest)
            case "plugin":
                return try await runPlugin(coordinator: coordinator, args: rest)
            case "export-hcl":
                return try await runExportHCL(coordinator: coordinator)
            case "export-html":
                return try await runExportHTML(coordinator: coordinator, args: rest)
            default:
                return CLIExecutionOutcome(
                    exitCode: 64,
                    stderr: "Unknown subcommand '\(subcommand)'. Run 'agentvm help' for usage.\n"
                )
            }
        } catch let err as AgentVMError {
            return CLIExecutionOutcome(
                exitCode: 1,
                stderr: "[\(err.errorCode)] \(err.localizedDescription)\nHint: \(err.remediationHint)\n"
            )
        } catch {
            return CLIExecutionOutcome(
                exitCode: 1,
                stderr: "Error: \(error.localizedDescription)\n"
            )
        }
    }

    // MARK: - Subcommand Implementations

    private func runDoctor(coordinator: AgentVMFleetCoordinator) async throws -> CLIExecutionOutcome {
        let caps = await coordinator.hostCapabilities()
        let issues = try await coordinator.store.verifyBundleIntegrity()
        let stats = try await coordinator.store.storageStatistics()
        var out = ""
        out += "AgentVM System Readiness Doctor v\(SemanticVersion.current.description)\n"
        out += "------------------------------------------------------------\n"
        out += "Host Architecture : \(caps.architecture) (macOS \(caps.macOSVersion))\n"
        out += "Physical / Logical: \(caps.physicalCores) / \(caps.logicalCores) cores (\(caps.hostMemoryGBFormatted))\n"
        out += "Apple VZ Support  : \(caps.isVirtualizationFrameworkSupported ? "PASS (com.apple.security.virtualization)" : "SIMULATION FALLBACK")\n"
        out += "APFS clonefile(2) : \(caps.isAPFSClonefileSupported ? "PASS (< 20ms CoW branching)" : "UNAVAILABLE")\n"
        out += "Rosetta x86_64    : \(caps.isRosettaLinuxShareAvailable ? "INSTALLED" : "NOT INSTALLED")\n"
        out += "Workspace Bundle  : \(ByteMetricsFormatter.scrubHomePath(coordinator.store.bundleURL.path))\n"
        out += "SQLite WAL Store  : \(ByteMetricsFormatter.formatBytes(stats.sqliteBytes + stats.walBytes))\n"
        out += "Integrity Issues  : \(issues.count)\n"
        return CLIExecutionOutcome(exitCode: issues.isEmpty ? 0 : 2, stdout: out)
    }

    private func runInit(coordinator: AgentVMFleetCoordinator, args: [String]) async throws -> CLIExecutionOutcome {
        if args.contains("--seed-demo") {
            try await coordinator.seedIndustrialDemonstrationFleetIfEmpty()
        }
        let manifest = try await coordinator.store.loadManifest()
        return CLIExecutionOutcome(
            exitCode: 0,
            stdout: "Initialized workspace '\(manifest.title)' (\(manifest.workspaceID.rawValue)) at \(ByteMetricsFormatter.scrubHomePath(coordinator.store.bundleURL.path))\n"
        )
    }

    private func runListVMs(coordinator: AgentVMFleetCoordinator, asJSON: Bool) async throws -> CLIExecutionOutcome {
        let vms = try await coordinator.store.listVMs()
        if asJSON {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(vms)
            return CLIExecutionOutcome(exitCode: 0, stdout: String(decoding: data, as: UTF8.self) + "\n")
        }
        if vms.isEmpty {
            return CLIExecutionOutcome(exitCode: 0, stdout: "No virtual machines in workspace. Run 'agentvm create <name>' or 'agentvm init --seed-demo'.\n")
        }
        var lines: [String] = []
        lines.append(String(format: "%-20s %-24s %-14s %-10s %-14s %-12s", "VM_ID", "NAME", "AGENT", "STATE", "IPV4", "COW_DIRTY"))
        for vm in vms {
            let ip = vm.spec.networkInterfaces.first?.ipv4Address ?? "-"
            let dirty = ByteMetricsFormatter.formatBytes(vm.telemetry.cowDirtyBytes)
            lines.append(String(
                format: "%-20s %-24s %-14s %-10s %-14s %-12s",
                (vm.id.rawValue as NSString).utf8String!,
                (String(vm.spec.name.prefix(23)) as NSString).utf8String!,
                (String(vm.spec.agentOwnerTag.prefix(13)) as NSString).utf8String!,
                (vm.telemetry.state.rawValue as NSString).utf8String!,
                (ip as NSString).utf8String!,
                (dirty as NSString).utf8String!
            ))
        }
        return CLIExecutionOutcome(exitCode: 0, stdout: lines.joined(separator: "\n") + "\n")
    }

    private func runCreateVM(coordinator: AgentVMFleetCoordinator, args: [String]) async throws -> CLIExecutionOutcome {
        let name = args.first(where: { !$0.hasPrefix("-") }) ?? "sandbox-01"
        let owner = optionValue("--owner", in: args) ?? "cli-agent"
        let cpus = optionValue("--cpus", in: args).flatMap(Int.init) ?? 2
        let mem = optionValue("--memory-mb", in: args).flatMap(UInt64.init) ?? 2048
        let summary = try await coordinator.createSandboxVM(
            name: name,
            agentOwnerTag: owner,
            vcpus: cpus,
            memoryMB: mem
        )
        return CLIExecutionOutcome(
            exitCode: 0,
            stdout: "Created VM '\(summary.vmRecord.spec.name)' (\(summary.vmRecord.id.rawValue)) with root snapshot \(summary.rootSnapshot.id.rawValue)\n"
        )
    }

    private func runLifecycle(coordinator: AgentVMFleetCoordinator, action: String, args: [String]) async throws -> CLIExecutionOutcome {
        guard let targetToken = args.first(where: { !$0.hasPrefix("-") }) else {
            throw AgentVMError.cliUsageError(detail: "Usage: agentvm \(action) <vm-id-or-name>")
        }
        let vmID = try await resolveVMID(targetToken, coordinator: coordinator)
        let updated: VMInstanceRecord
        switch action {
        case "boot": updated = try await coordinator.bootVM(vmID)
        case "pause": updated = try await coordinator.pauseVM(vmID)
        case "resume": updated = try await coordinator.resumeVM(vmID)
        default: updated = try await coordinator.haltVM(vmID)
        }
        return CLIExecutionOutcome(
            exitCode: 0,
            stdout: "VM '\(updated.spec.name)' (\(updated.id.rawValue)) -> \(updated.telemetry.state.rawValue)\n"
        )
    }

    private func runBranchFork(coordinator: AgentVMFleetCoordinator, args: [String]) async throws -> CLIExecutionOutcome {
        let positional = args.filter { !$0.hasPrefix("-") }
        guard positional.count >= 2 else {
            throw AgentVMError.cliUsageError(detail: "Usage: agentvm branch <source-vm> <new-branch-name> [--owner <agent>]")
        }
        let parentID = try await resolveVMID(positional[0], coordinator: coordinator)
        let branchName = positional[1]
        let owner = optionValue("--owner", in: args) ?? "branch-worker"
        let fork = try await coordinator.forkCoWBranch(
            fromVMID: parentID,
            branchName: branchName,
            agentOwnerTag: owner,
            bootImmediately: !args.contains("--no-boot")
        )
        return CLIExecutionOutcome(
            exitCode: 0,
            stdout: String(
                format: "Forked CoW branch '%@' (%@) in %.2f ms from snapshot %@\n",
                fork.childVM.spec.name,
                fork.childVM.id.rawValue,
                fork.cloneDurationMilliseconds,
                fork.forkPointSnapshot.id.rawValue
            )
        )
    }

    private func runSnapshot(coordinator: AgentVMFleetCoordinator, args: [String]) async throws -> CLIExecutionOutcome {
        let positional = args.filter { !$0.hasPrefix("-") }
        if positional.first == "list" || positional.isEmpty {
            let snaps = try await coordinator.store.listSnapshots()
            let lines = snaps.map {
                "\($0.id.rawValue)\t\($0.vmID.rawValue)\t[\($0.branchName)]\t\($0.kind.rawValue)\t\($0.title)"
            }
            return CLIExecutionOutcome(exitCode: 0, stdout: lines.joined(separator: "\n") + (lines.isEmpty ? "" : "\n"))
        }
        let vmID = try await resolveVMID(positional[0], coordinator: coordinator)
        let title = optionValue("--title", in: args) ?? (positional.count > 1 ? positional[1] : "CLI Checkpoint")
        let snap = try await coordinator.captureSnapshot(vmID: vmID, title: title)
        return CLIExecutionOutcome(
            exitCode: 0,
            stdout: "Captured snapshot \(snap.id.rawValue) ('\(snap.title)') for \(vmID.rawValue)\n"
        )
    }

    private func runRestore(coordinator: AgentVMFleetCoordinator, args: [String]) async throws -> CLIExecutionOutcome {
        guard let snapRaw = args.first else {
            throw AgentVMError.cliUsageError(detail: "Usage: agentvm restore <snapshot-id>")
        }
        let vm = try await coordinator.restoreToSnapshot(SnapshotID(snapRaw))
        return CLIExecutionOutcome(exitCode: 0, stdout: "Restored '\(vm.spec.name)' to snapshot \(snapRaw)\n")
    }

    private func runExec(coordinator: AgentVMFleetCoordinator, args: [String]) async throws -> CLIExecutionOutcome {
        guard let vmToken = args.first else {
            throw AgentVMError.cliUsageError(detail: "Usage: agentvm exec <vm-id-or-name> -- <command> [args...]")
        }
        let vmID = try await resolveVMID(vmToken, coordinator: coordinator)
        var cmdTokens = Array(args.dropFirst())
        if cmdTokens.first == "--" {
            cmdTokens.removeFirst()
        }
        guard let exe = cmdTokens.first else {
            throw AgentVMError.cliUsageError(detail: "Missing executable after VM identifier.")
        }
        let result = try await coordinator.executeInGuest(
            vmID: vmID,
            request: GuestExecRequest(executable: exe, arguments: Array(cmdTokens.dropFirst()))
        )
        return CLIExecutionOutcome(
            exitCode: result.exitCode,
            stdout: result.stdoutUTF8,
            stderr: result.stderrUTF8
        )
    }

    private func runPCAP(coordinator: AgentVMFleetCoordinator, args: [String]) async throws -> CLIExecutionOutcome {
        let filter = optionValue("--filter", in: args)
        if let outPath = optionValue("--export", in: args) {
            let data = await coordinator.l2Switch.exportPCAPNGData(filterQuery: filter)
            try data.write(to: URL(fileURLWithPath: outPath), options: .atomic)
            return CLIExecutionOutcome(exitCode: 0, stdout: "Exported \(data.count) bytes to \(outPath)\n")
        }
        let packets = await coordinator.l2Switch.recentPackets(limit: 50, filterQuery: filter)
        let lines = packets.map {
            "#\($0.sequenceNumber) [\($0.highestProtocol.rawValue)] \($0.sourceIP ?? $0.sourceMAC) -> \($0.destinationIP ?? $0.destinationMAC) [\($0.verdict.rawValue)] \($0.infoSummary)"
        }
        return CLIExecutionOutcome(exitCode: 0, stdout: lines.joined(separator: "\n") + (lines.isEmpty ? "" : "\n"))
    }

    private func runPolicy(coordinator: AgentVMFleetCoordinator, args: [String]) async throws -> CLIExecutionOutcome {
        if args.first == "airgap" {
            await coordinator.l2Switch.firewall.updatePolicy(.airgappedPreset())
            return CLIExecutionOutcome(exitCode: 0, stdout: "Engaged Total Air-Gap firewall policy.\n")
        } else if args.first == "strict" {
            await coordinator.l2Switch.firewall.updatePolicy(.strictAgentAllowlistPreset())
            return CLIExecutionOutcome(exitCode: 0, stdout: "Engaged Strict Coding-Agent Allowlist firewall policy.\n")
        }
        let current = await coordinator.l2Switch.firewall.currentPolicy()
        let lines = current.rules.map { "[\($0.priority)] \($0.name) -> \($0.verdict.rawValue)" }
        return CLIExecutionOutcome(exitCode: 0, stdout: "\(current.name) (\(current.rules.count) rules)\n" + lines.joined(separator: "\n") + "\n")
    }

    private func runPlugin(coordinator: AgentVMFleetCoordinator, args: [String]) async throws -> CLIExecutionOutcome {
        let statuses = await coordinator.pluginEngine.listPluginStatuses()
        let lines = statuses.map {
            "\($0.id.rawValue)\t\($0.isEnabled ? "ENABLED" : "DISABLED")\tv\($0.manifest.version.description)\t\($0.manifest.name)"
        }
        return CLIExecutionOutcome(exitCode: 0, stdout: lines.joined(separator: "\n") + "\n")
    }

    private func runExportHCL(coordinator: AgentVMFleetCoordinator) async throws -> CLIExecutionOutcome {
        let vms = try await coordinator.store.listVMs().map(\.spec)
        let policy = await coordinator.l2Switch.firewall.currentPolicy()
        let hcl = TopologyIACCodec().exportHCL(vms: vms, policy: policy)
        return CLIExecutionOutcome(exitCode: 0, stdout: hcl)
    }

    private func runExportHTML(coordinator: AgentVMFleetCoordinator, args: [String]) async throws -> CLIExecutionOutcome {
        if args.contains("--seed-demo") {
            try await coordinator.seedIndustrialDemonstrationFleetIfEmpty()
        }
        let outPath = args.first(where: { !$0.hasPrefix("-") }) ?? "fleet-audit-report.html"
        let exporter = HtmlFleetReportExporter()
        let html = try await exporter.renderStandaloneHTML(coordinator: coordinator)
        try Data(html.utf8).write(to: URL(fileURLWithPath: outPath), options: .atomic)
        return CLIExecutionOutcome(exitCode: 0, stdout: "Exported HTML fleet security report to \(outPath)\n")
    }

    private func resolveVMID(_ token: String, coordinator: AgentVMFleetCoordinator) async throws -> VMID {
        let vms = try await coordinator.store.listVMs()
        if let exactID = vms.first(where: { $0.id.rawValue == token }) {
            return exactID.id
        }
        if let byName = vms.first(where: { $0.spec.name.caseInsensitiveCompare(token) == .orderedSame }) {
            return byName.id
        }
        throw AgentVMError.vmNotFound(VMID(token))
    }

    private func optionValue(_ flag: String, in args: [String]) -> String? {
        guard let idx = args.firstIndex(of: flag), idx + 1 < args.count else { return nil }
        return args[idx + 1]
    }

    public static func helpBanner() -> String {
        """
        AgentVM v\(SemanticVersion.current.description) — Apple Silicon MicroVM Sandbox, APFS CoW & L2 DPI Engine

        USAGE:
          agentvm [--workspace <bundle.agentvm>] [--lang <zh|en>] <subcommand> [options]

        GLOBAL OPTIONS:
          --workspace, -w <bundle.agentvm>  Select target .agentvm bundle directory
          --lang <zh|en>                    Select interface language (zh-Hans or English; GUI + screenshot exporter)

        SUBCOMMANDS:
          doctor                          Probe Apple Virtualization, APFS clonefile & Rosetta readiness
          init [--seed-demo]              Initialize a .agentvm bundle (optionally seed 3-blade fleet)
          ps [--json]                     List sandbox VMs, states, IPv4 leases, and dirty CoW bytes
          create <name> [--cpus N]        Provision a new GPT + NoCloud ISO sandbox VM
          up | pause | resume | halt <vm> Control VZVirtualMachine lifecycle state
          branch <src-vm> <branch-name>   Fork an instant (<20 ms) APFS Copy-on-Write VM branch
          snapshot [list | <vm> <title>]  List or capture live RAM + CoW disk checkpoints
          restore <snapshot-id>           Roll back VM disk & topology to a snapshot node
          exec <vm> -- <cmd> [args...]    Execute command over AVM1 VirtioSocket with JS guardrails
          pcap [--filter <expr>] [--export <file.pcapng>]
          policy [strict | airgap]        Inspect or switch L2 DPI egress firewall preset
          plugin                          List JavaScriptCore security & automation extensions
          export-hcl                      Export fleet topology as declarative .avm.hcl
          export-html <output.html>       Export standalone Hallmark-clean fleet audit report
          mcp                             Run JSON-RPC 2.0 Model Context Protocol server over stdio
        """ + "\n"
    }
}
