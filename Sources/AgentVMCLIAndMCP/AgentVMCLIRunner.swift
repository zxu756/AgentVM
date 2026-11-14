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

    public static func defaultWorkspaceBundleURL(
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> URL {
        if let envPath = environment["AGENTVM_WORKSPACE"]?.trimmingCharacters(in: .whitespacesAndNewlines),
           !envPath.isEmpty {
            return URL(fileURLWithPath: envPath, isDirectory: true)
        }
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
        let language: AppLanguage
        if let cliLang = AppLanguage.extractCLILanguage(from: arguments) {
            await MainActor.run {
                AgentVMLocalizer.shared.setLanguage(cliLang, persist: false)
            }
            language = cliLang
        } else {
            language = await MainActor.run {
                AgentVMLocalizer.shared.language
            }
        }
        let isZh = (language == .zhHans)

        var args = AppLanguage.strippingLanguageArguments(from: arguments)
        var resolvedBundleURL = bundleURLOverride ?? Self.defaultWorkspaceBundleURL()
        var executionBackend: HypervisorExecutionBackend = .strictHardwareVZ
        var isSimulationFlagged = false

        // Extract global `--workspace` and `--backend` options anywhere prior to standalone `--`
        var cleaned: [String] = []
        var idx = 0
        while idx < args.count {
            let token = args[idx]
            if token == "--" {
                cleaned.append(contentsOf: args[idx...])
                break
            }
            if (token == "--workspace" || token == "-w"), idx + 1 < args.count {
                resolvedBundleURL = URL(fileURLWithPath: args[idx + 1], isDirectory: true)
                idx += 2
                continue
            }
            if token.hasPrefix("--workspace=") {
                let rawPath = String(token.dropFirst("--workspace=".count))
                resolvedBundleURL = URL(fileURLWithPath: rawPath, isDirectory: true)
                idx += 1
                continue
            }
            if token == "--backend" {
                guard idx + 1 < args.count else {
                    return CLIExecutionOutcome(
                        exitCode: 64,
                        stderr: isZh
                            ? "缺少 --backend 参数值（可选：hardware 或 simulation）。\n"
                            : "Missing value for --backend (expected 'hardware' or 'simulation').\n"
                    )
                }
                let rawBackend = args[idx + 1].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                switch rawBackend {
                case "simulation":
                    executionBackend = .deterministicSimulation
                    isSimulationFlagged = true
                case "hardware", "vz", "default":
                    executionBackend = .strictHardwareVZ
                    isSimulationFlagged = false
                default:
                    return CLIExecutionOutcome(
                        exitCode: 64,
                        stderr: isZh
                            ? "未知的 --backend 值「\(args[idx + 1])」（仅支持 hardware 或 simulation）。\n"
                            : "Unknown --backend value '\(args[idx + 1])' (supported: 'hardware', 'simulation').\n"
                    )
                }
                idx += 2
                continue
            }
            if token.hasPrefix("--backend=") {
                let rawBackend = String(token.dropFirst("--backend=".count))
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                    .lowercased()
                switch rawBackend {
                case "simulation":
                    executionBackend = .deterministicSimulation
                    isSimulationFlagged = true
                case "hardware", "vz", "default":
                    executionBackend = .strictHardwareVZ
                    isSimulationFlagged = false
                default:
                    return CLIExecutionOutcome(
                        exitCode: 64,
                        stderr: isZh
                            ? "未知的 --backend 值「\(rawBackend)」（仅支持 hardware 或 simulation）。\n"
                            : "Unknown --backend value '\(rawBackend)' (supported: 'hardware', 'simulation').\n"
                    )
                }
                idx += 1
                continue
            }
            cleaned.append(token)
            idx += 1
        }
        args = cleaned

        guard let subcommand = args.first else {
            return CLIExecutionOutcome(exitCode: 0, stdout: Self.helpBanner(language: language))
        }
        let rest = Array(args.dropFirst())

        if subcommand == "--help" || subcommand == "-h" || subcommand == "help" {
            return CLIExecutionOutcome(exitCode: 0, stdout: Self.helpBanner(language: language))
        }
        if subcommand == "--version" || subcommand == "version" || subcommand == "-v" {
            let text = isZh
                ? "agentvm \(SemanticVersion.current.description) (arm64-apple-darwin · 双语命令与工作台)\n"
                : "agentvm \(SemanticVersion.current.description) (arm64-apple-darwin)\n"
            return CLIExecutionOutcome(exitCode: 0, stdout: text)
        }

        guard Self.subcommandGrammars[subcommand] != nil else {
            return CLIExecutionOutcome(
                exitCode: 64,
                stderr: isZh
                    ? "未知子命令「\(subcommand)」。运行 'agentvm help' 查看用法。\n"
                    : "Unknown subcommand '\(subcommand)'. Run 'agentvm help' for usage.\n"
            )
        }

        // Reject options and arguments the subcommand does not define, before anything is created or changed.
        let parsed: ParsedSubcommandArguments
        switch Self.parseSubcommandArguments(subcommand: subcommand, arguments: rest, language: language) {
        case let .success(value):
            parsed = value
        case let .failure(usage):
            let rawStderr = usage.message + "\n"
            return CLIExecutionOutcome(
                exitCode: Self.usageErrorExitCode,
                stderr: isSimulationFlagged ? Self.prefixSimulatedLines(rawStderr) : rawStderr
            )
        }

        do {
            let coordinator = try AgentVMFleetCoordinator(
                bundleURL: resolvedBundleURL,
                executionBackend: executionBackend
            )

            let rawOutcome: CLIExecutionOutcome
            // How this subcommand's stdout can carry the simulation marker without breaking its format.
            var stdoutFormat: SimulationMarkedFormat = .textLines

            switch subcommand {
            case "doctor":
                rawOutcome = try await runDoctor(coordinator: coordinator, language: language)
            case "init":
                rawOutcome = try await runInit(coordinator: coordinator, parsed: parsed, language: language)
            case "ps", "list":
                let asJSON = parsed.flags.contains("--json")
                if asJSON { stdoutFormat = .json }
                rawOutcome = try await runListVMs(coordinator: coordinator, asJSON: asJSON, language: language)
            case "create":
                rawOutcome = try await runCreateVM(coordinator: coordinator, parsed: parsed, language: language)
            case "up", "boot", "start":
                rawOutcome = try await runLifecycle(coordinator: coordinator, action: "boot", parsed: parsed, language: language)
            case "pause":
                rawOutcome = try await runLifecycle(coordinator: coordinator, action: "pause", parsed: parsed, language: language)
            case "resume":
                rawOutcome = try await runLifecycle(coordinator: coordinator, action: "resume", parsed: parsed, language: language)
            case "halt", "stop":
                rawOutcome = try await runLifecycle(coordinator: coordinator, action: "halt", parsed: parsed, language: language)
            case "branch", "fork":
                rawOutcome = try await runBranchFork(coordinator: coordinator, parsed: parsed, language: language)
            case "snapshot":
                rawOutcome = try await runSnapshot(coordinator: coordinator, parsed: parsed, language: language)
            case "restore":
                rawOutcome = try await runRestore(coordinator: coordinator, parsed: parsed, language: language)
            case "exec":
                rawOutcome = try await runExec(coordinator: coordinator, args: rest, language: language)
            case "pcap":
                rawOutcome = try await runPCAP(
                    coordinator: coordinator,
                    parsed: parsed,
                    language: language,
                    isSimulation: isSimulationFlagged
                )
            case "policy":
                rawOutcome = try await runPolicy(coordinator: coordinator, parsed: parsed, language: language)
            case "plugin":
                rawOutcome = try await runPlugin(coordinator: coordinator, language: language)
            case "export-hcl":
                stdoutFormat = .hashCommented
                rawOutcome = try await runExportHCL(coordinator: coordinator)
            case "export-html":
                rawOutcome = try await runExportHTML(
                    coordinator: coordinator,
                    parsed: parsed,
                    language: language,
                    isSimulation: isSimulationFlagged
                )
            default:
                return CLIExecutionOutcome(
                    exitCode: 64,
                    stderr: isZh
                        ? "未知子命令「\(subcommand)」。运行 'agentvm help' 查看用法。\n"
                        : "Unknown subcommand '\(subcommand)'. Run 'agentvm help' for usage.\n"
                )
            }

            if isSimulationFlagged {
                return Self.markSimulatedOutcome(rawOutcome, stdoutFormat: stdoutFormat, language: language)
            }
            return rawOutcome
        } catch let err as AgentVMError {
            let localizedErr = err.localizedMessage(in: language)
            let hintLine: String
            if isZh {
                hintLine = "提示：查看审计日志抽屉或运行 'agentvm doctor' 进行环境自检。"
            } else {
                hintLine = "Hint: \(err.remediationHint)"
            }
            let rawStderr = "[\(err.errorCode)] \(localizedErr)\n\(hintLine)\n"
            return CLIExecutionOutcome(
                exitCode: 1,
                stderr: isSimulationFlagged ? Self.prefixSimulatedLines(rawStderr) : rawStderr
            )
        } catch {
            let prefix = isZh ? "错误：" : "Error: "
            let rawStderr = "\(prefix)\(error.localizedDescription)\n"
            return CLIExecutionOutcome(
                exitCode: 1,
                stderr: isSimulationFlagged ? Self.prefixSimulatedLines(rawStderr) : rawStderr
            )
        }
    }

    // MARK: - Subcommand Implementations

    private func runDoctor(coordinator: AgentVMFleetCoordinator, language: AppLanguage) async throws -> CLIExecutionOutcome {
        let caps = await coordinator.hostCapabilities()
        let issues = try await coordinator.store.verifyBundleIntegrity()
        let stats = try await coordinator.store.storageStatistics()
        let isZh = (language == .zhHans)

        var out = ""
        if isZh {
            out += "AgentVM 系统就绪自检 v\(SemanticVersion.current.description)\n"
            out += "------------------------------------------------------------\n"
            out += "宿主机架构        : \(caps.architecture) (macOS \(caps.macOSVersion))\n"
            out += "物理 / 逻辑核心   : \(caps.physicalCores) / \(caps.logicalCores) 核 (\(caps.hostMemoryGBFormatted))\n"
            out += "Apple VZ 虚拟化   : \(Self.virtualizationReadinessText(isSupported: caps.isVirtualizationFrameworkSupported, hasEntitlement: caps.hasVirtualizationEntitlement, language: language))\n"
            out += "APFS clonefile(2) : \(caps.isAPFSClonefileSupported ? "通过 (实测 clonefile(2) 写时复制克隆成功)" : "失败 (目标目录不支持 APFS clonefile(2))")\n"
            out += "Rosetta x86_64    : \(caps.isRosettaLinuxShareAvailable ? "已安装" : "未安装")\n"
            out += "工作区路径        : \(ByteMetricsFormatter.scrubHomePath(coordinator.store.bundleURL.path))\n"
            out += "SQLite WAL 存储   : \(ByteMetricsFormatter.formatBytes(stats.sqliteBytes + stats.walBytes))\n"
            out += "完整性问题        : \(issues.count)\n"
        } else {
            out += "AgentVM System Readiness Doctor v\(SemanticVersion.current.description)\n"
            out += "------------------------------------------------------------\n"
            out += "Host Architecture : \(caps.architecture) (macOS \(caps.macOSVersion))\n"
            out += "Physical / Logical: \(caps.physicalCores) / \(caps.logicalCores) cores (\(caps.hostMemoryGBFormatted))\n"
            out += "Apple VZ Support  : \(Self.virtualizationReadinessText(isSupported: caps.isVirtualizationFrameworkSupported, hasEntitlement: caps.hasVirtualizationEntitlement, language: language))\n"
            out += "APFS clonefile(2) : \(caps.isAPFSClonefileSupported ? "PASS (verified via live clonefile(2) probe)" : "FAIL (target volume does not support APFS clonefile(2))")\n"
            out += "Rosetta x86_64    : \(caps.isRosettaLinuxShareAvailable ? "INSTALLED" : "NOT INSTALLED")\n"
            out += "Workspace Bundle  : \(ByteMetricsFormatter.scrubHomePath(coordinator.store.bundleURL.path))\n"
            out += "SQLite WAL Store  : \(ByteMetricsFormatter.formatBytes(stats.sqliteBytes + stats.walBytes))\n"
            out += "Integrity Issues  : \(issues.count)\n"
        }
        return CLIExecutionOutcome(exitCode: issues.isEmpty ? 0 : 2, stdout: out)
    }

    /// The `doctor` virtualization line. "PASS" is printed only when the host supports Virtualization.framework
    /// *and* the running executable carries the virtualization entitlement (read from the process, see
    /// `HostHypervisorProbe.currentProcessHasBooleanEntitlement`).
    public static func virtualizationReadinessText(
        isSupported: Bool,
        hasEntitlement: Bool,
        language: AppLanguage
    ) -> String {
        let isZh = (language == .zhHans)
        guard isSupported else {
            return isZh
                ? "不可用 (宿主机不支持 Virtualization.framework)"
                : "UNAVAILABLE (this host does not support Virtualization.framework)"
        }
        guard hasEntitlement else {
            return isZh
                ? "系统支持虚拟化；当前可执行文件没有虚拟化权限，无法启动虚拟机 (缺少 com.apple.security.virtualization)"
                : "Host supports virtualization; this executable lacks the virtualization entitlement and cannot start virtual machines (com.apple.security.virtualization is missing)"
        }
        return isZh
            ? "通过 (系统支持虚拟化，当前可执行文件具备 com.apple.security.virtualization 权限)"
            : "PASS (host supports virtualization; this executable has com.apple.security.virtualization)"
    }

    private func runInit(coordinator: AgentVMFleetCoordinator, parsed: ParsedSubcommandArguments, language: AppLanguage) async throws -> CLIExecutionOutcome {
        let isZh = (language == .zhHans)
        let seedDemo = parsed.flags.contains("--seed-demo")
        if seedDemo {
            try await coordinator.seedIndustrialDemonstrationFleetIfEmpty()
        }
        let manifest = try await coordinator.store.loadManifest()
        let pathStr = ByteMetricsFormatter.scrubHomePath(coordinator.store.bundleURL.path)
        let out: String
        if seedDemo {
            out = isZh
                ? "[演示数据] 已初始化演示工作区「\(manifest.title)」（\(manifest.workspaceID.rawValue)）：\(pathStr)\n"
                : "[DEMO] Initialized workspace '\(manifest.title)' (\(manifest.workspaceID.rawValue)) with synthetic demo data at \(pathStr)\n"
        } else {
            out = isZh
                ? "已初始化空工作区「\(manifest.title)」（\(manifest.workspaceID.rawValue)）：\(pathStr)\n"
                : "Initialized workspace '\(manifest.title)' (\(manifest.workspaceID.rawValue)) at \(pathStr)\n"
        }
        return CLIExecutionOutcome(exitCode: 0, stdout: out)
    }

    private func runListVMs(coordinator: AgentVMFleetCoordinator, asJSON: Bool, language: AppLanguage) async throws -> CLIExecutionOutcome {
        // `listVMsForReporting` carries `telemetry.simulated`: true for state the simulator wrote (any backend
        // reading it) and for every record when this process itself runs the simulation backend.
        let vms = try await coordinator.listVMsForReporting()
        if asJSON {
            return CLIExecutionOutcome(exitCode: 0, stdout: try Self.encodeFleetJSON(vms) + "\n")
        }
        let isZh = (language == .zhHans)
        if vms.isEmpty {
            let emptyMsg = isZh
                ? "当前工作区中没有虚拟机。运行 'agentvm create <名称>' 创建，或运行 'agentvm init --seed-demo' 载入演示数据。\n"
                : "No virtual machines in workspace. Run 'agentvm create <name>' or 'agentvm init --seed-demo'.\n"
            return CLIExecutionOutcome(exitCode: 0, stdout: emptyMsg)
        }

        // A simulated non-stopped state is printed as `SIMULATED:<state>`; widen the column so it stays aligned.
        let stateTexts: [String] = vms.map { vm in
            vm.telemetry.markedStateLabel(
                localizedState: isZh ? Self.localizedStateLabelZh(vm.telemetry.state) : nil
            )
        }
        let stateColumnWidth = max(10, (stateTexts.map { Self.displayColumnWidth(of: $0) }.max() ?? 0) + 1)

        var lines: [String] = []
        if isZh {
            lines.append([
                Self.padDisplayColumn("虚拟机 ID", width: 20),
                Self.padDisplayColumn("名称", width: 22),
                Self.padDisplayColumn("智能体", width: 14),
                Self.padDisplayColumn("状态", width: stateColumnWidth),
                Self.padDisplayColumn("CPU", width: 8),
                Self.padDisplayColumn("内存", width: 10),
                Self.padDisplayColumn("IPv4", width: 15),
                "CoW 脏块"
            ].joined(separator: " "))
        } else {
            lines.append([
                Self.padDisplayColumn("VM_ID", width: 20),
                Self.padDisplayColumn("NAME", width: 22),
                Self.padDisplayColumn("AGENT", width: 14),
                Self.padDisplayColumn("STATE", width: stateColumnWidth),
                Self.padDisplayColumn("CPU", width: 8),
                Self.padDisplayColumn("MEMORY", width: 10),
                Self.padDisplayColumn("IPV4", width: 15),
                "COW_DIRTY"
            ].joined(separator: " "))
        }

        for (vm, stateText) in zip(vms, stateTexts) {
            let ip = vm.spec.networkInterfaces.first?.ipv4Address ?? "—"
            let dirty = ByteMetricsFormatter.formatBytes(vm.telemetry.cowDirtyBytes)
            lines.append([
                Self.padDisplayColumn(vm.id.rawValue, width: 20),
                Self.padDisplayColumn(Self.truncateDisplayColumn(vm.spec.name, maxWidth: 21), width: 22),
                Self.padDisplayColumn(Self.truncateDisplayColumn(vm.spec.agentOwnerTag, maxWidth: 13), width: 14),
                Self.padDisplayColumn(stateText, width: stateColumnWidth),
                Self.padDisplayColumn(vm.telemetry.formattedCPUUsage, width: 8),
                Self.padDisplayColumn(vm.telemetry.formattedMemoryResident, width: 10),
                Self.padDisplayColumn(ip, width: 15),
                dirty
            ].joined(separator: " "))
        }
        let simulatedActiveCount = vms.filter { $0.telemetry.isSimulatedActiveState }.count
        if simulatedActiveCount > 0 {
            lines.append(isZh
                ? "SIMULATED: 上面有 \(simulatedActiveCount) 台虚拟机的状态是 --backend simulation 写入的模拟状态，没有真实的客户机在运行。"
                : "SIMULATED: \(simulatedActiveCount) VM state(s) above were written by --backend simulation; no real guest is running.")
        }
        return CLIExecutionOutcome(exitCode: 0, stdout: lines.joined(separator: "\n") + "\n")
    }

    /// JSON used by `ps --json` and MCP `agentvm_list_fleet`: the plain `[VMInstanceRecord]` array, whose
    /// `telemetry.simulated` boolean sits next to `telemetry.state`.
    public static func encodeFleetJSON(_ vms: [VMInstanceRecord]) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return String(decoding: try encoder.encode(vms), as: UTF8.self)
    }

    private func runCreateVM(coordinator: AgentVMFleetCoordinator, parsed: ParsedSubcommandArguments, language: AppLanguage) async throws -> CLIExecutionOutcome {
        let isZh = (language == .zhHans)
        let name = parsed.positionals.first ?? "sandbox-01"
        let owner = parsed.options["--owner"] ?? "cli-agent"
        let cpus = parsed.options["--cpus"].flatMap(Int.init) ?? 2
        let mem = parsed.options["--memory-mb"].flatMap(UInt64.init) ?? 2048
        let summary = try await coordinator.createSandboxVM(
            name: name,
            agentOwnerTag: owner,
            vcpus: cpus,
            memoryMB: mem
        )
        let msg = isZh
            ? "已创建虚拟机「\(summary.vmRecord.spec.name)」（\(summary.vmRecord.id.rawValue)），根快照 \(summary.rootSnapshot.id.rawValue)（空稀疏 GPT 磁盘，未安装客户机系统）\n"
            : "Created VM '\(summary.vmRecord.spec.name)' (\(summary.vmRecord.id.rawValue)) with root snapshot \(summary.rootSnapshot.id.rawValue) (empty sparse GPT disk, no guest OS installed)\n"
        return CLIExecutionOutcome(exitCode: 0, stdout: msg)
    }

    private func runLifecycle(coordinator: AgentVMFleetCoordinator, action: String, parsed: ParsedSubcommandArguments, language: AppLanguage) async throws -> CLIExecutionOutcome {
        let isZh = (language == .zhHans)
        guard let targetToken = parsed.positionals.first else {
            throw AgentVMError.cliUsageError(
                detail: isZh ? "用法：agentvm \(action) <虚拟机ID或名称>" : "Usage: agentvm \(action) <vm-id-or-name>"
            )
        }
        let vmID = try await resolveVMID(targetToken, coordinator: coordinator)
        let updated: VMInstanceRecord
        switch action {
        case "boot": updated = try await coordinator.bootVM(vmID)
        case "pause": updated = try await coordinator.pauseVM(vmID)
        case "resume": updated = try await coordinator.resumeVM(vmID)
        default: updated = try await coordinator.haltVM(vmID)
        }
        let stateText = updated.telemetry.markedStateLabel(
            localizedState: isZh ? Self.localizedStateLabelZh(updated.telemetry.state) : nil
        )
        let msg = isZh
            ? "虚拟机「\(updated.spec.name)」（\(updated.id.rawValue)）-> \(stateText)\n"
            : "VM '\(updated.spec.name)' (\(updated.id.rawValue)) -> \(stateText)\n"
        return CLIExecutionOutcome(exitCode: 0, stdout: msg)
    }

    private func runBranchFork(coordinator: AgentVMFleetCoordinator, parsed: ParsedSubcommandArguments, language: AppLanguage) async throws -> CLIExecutionOutcome {
        let isZh = (language == .zhHans)
        let positional = parsed.positionals
        guard positional.count >= 2 else {
            throw AgentVMError.cliUsageError(
                detail: isZh
                    ? "用法：agentvm branch <源虚拟机> <新分支名> [--owner <智能体>]"
                    : "Usage: agentvm branch <source-vm> <new-branch-name> [--owner <agent>]"
            )
        }
        let parentID = try await resolveVMID(positional[0], coordinator: coordinator)
        let branchName = positional[1]
        let owner = parsed.options["--owner"] ?? "branch-worker"
        let parentRecord = try await coordinator.store.fetchVM(parentID)
        let shouldBoot: Bool
        if parsed.flags.contains("--no-boot") {
            shouldBoot = false
        } else if parsed.flags.contains("--boot") {
            shouldBoot = true
        } else {
            // Follow the parent only when its `running` state belongs to the backend this process uses:
            // a state the simulator wrote does not make the hardware backend boot the branch.
            let parentTelemetry = parentRecord?.telemetry
            let backendIsSimulation = await coordinator.currentExecutionBackend() == .deterministicSimulation
            shouldBoot = (parentTelemetry?.state == .running)
                && (backendIsSimulation || parentTelemetry?.simulated == false)
        }

        let fork = try await coordinator.forkCoWBranch(
            fromVMID: parentID,
            branchName: branchName,
            agentOwnerTag: owner,
            bootImmediately: shouldBoot
        )
        let msg: String
        if isZh {
            msg = String(
                format: "已通过 clonefile(2) 派生 CoW 分支「%@」（%@），耗时 %.2f ms，父快照 %@\n",
                fork.childVM.spec.name,
                fork.childVM.id.rawValue,
                fork.cloneDurationMilliseconds,
                fork.forkPointSnapshot.id.rawValue
            )
        } else {
            msg = String(
                format: "Forked CoW branch '%@' (%@) in %.2f ms from snapshot %@\n",
                fork.childVM.spec.name,
                fork.childVM.id.rawValue,
                fork.cloneDurationMilliseconds,
                fork.forkPointSnapshot.id.rawValue
            )
        }
        return CLIExecutionOutcome(exitCode: 0, stdout: msg)
    }

    private func runSnapshot(coordinator: AgentVMFleetCoordinator, parsed: ParsedSubcommandArguments, language: AppLanguage) async throws -> CLIExecutionOutcome {
        let isZh = (language == .zhHans)
        let positional = parsed.positionals
        if positional.first == "list" || positional.isEmpty {
            let snaps = try await coordinator.store.listSnapshots()
            let lines = snaps.map {
                "\($0.id.rawValue)\t\($0.vmID.rawValue)\t[\($0.branchName)]\t\($0.kind.rawValue)\t\($0.title)"
            }
            return CLIExecutionOutcome(exitCode: 0, stdout: lines.joined(separator: "\n") + (lines.isEmpty ? "" : "\n"))
        }
        let vmID = try await resolveVMID(positional[0], coordinator: coordinator)
        let title = parsed.options["--title"] ?? (positional.count > 1 ? positional[1] : (isZh ? "命令行检查点" : "CLI Checkpoint"))
        let snap = try await coordinator.captureSnapshot(vmID: vmID, title: title)
        let msg = isZh
            ? "已为 \(vmID.rawValue) 捕获快照 \(snap.id.rawValue)（「\(snap.title)」）\n"
            : "Captured snapshot \(snap.id.rawValue) ('\(snap.title)') for \(vmID.rawValue)\n"
        return CLIExecutionOutcome(exitCode: 0, stdout: msg)
    }

    private func runRestore(coordinator: AgentVMFleetCoordinator, parsed: ParsedSubcommandArguments, language: AppLanguage) async throws -> CLIExecutionOutcome {
        let isZh = (language == .zhHans)
        guard let snapRaw = parsed.positionals.first else {
            throw AgentVMError.cliUsageError(
                detail: isZh ? "用法：agentvm restore <快照ID>" : "Usage: agentvm restore <snapshot-id>"
            )
        }
        let vm = try await coordinator.restoreToSnapshot(SnapshotID(snapRaw))
        let msg = isZh
            ? "已将「\(vm.spec.name)」恢复至快照 \(snapRaw)\n"
            : "Restored '\(vm.spec.name)' to snapshot \(snapRaw)\n"
        return CLIExecutionOutcome(exitCode: 0, stdout: msg)
    }

    private func runExec(coordinator: AgentVMFleetCoordinator, args: [String], language: AppLanguage) async throws -> CLIExecutionOutcome {
        let isZh = (language == .zhHans)
        guard let vmToken = args.first else {
            throw AgentVMError.cliUsageError(
                detail: isZh
                    ? "用法：agentvm exec <虚拟机ID或名称> -- <命令> [参数...]"
                    : "Usage: agentvm exec <vm-id-or-name> -- <command> [args...]"
            )
        }
        let vmID = try await resolveVMID(vmToken, coordinator: coordinator)
        var cmdTokens = Array(args.dropFirst())
        if cmdTokens.first == "--" {
            cmdTokens.removeFirst()
        }
        guard let exe = cmdTokens.first else {
            throw AgentVMError.cliUsageError(
                detail: isZh ? "缺少要在客户机中执行的可执行命令。" : "Missing executable after VM identifier."
            )
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

    private func runPCAP(
        coordinator: AgentVMFleetCoordinator,
        parsed: ParsedSubcommandArguments,
        language: AppLanguage,
        isSimulation: Bool
    ) async throws -> CLIExecutionOutcome {
        let isZh = (language == .zhHans)
        let filter = parsed.options["--filter"]
        // The capture ring lives in the memory of one process and no guest NIC is attached to the switch
        // before M5, so a CLI process that did not inject frames itself always has 0 packets.
        let emptyNoteEn = "The capture ring is in-memory and per-process, and no guest traffic reaches the switch before M5."
        let emptyNoteZh = "抓包缓冲只在单个进程的内存里，而且 M5 之前没有客户机流量接入交换机。"
        if let outPath = parsed.options["--export"] {
            let packetCount = await coordinator.l2Switch.recentPackets(limit: Int.max, filterQuery: filter).count
            let data = await coordinator.l2Switch.exportPCAPNGData(
                filterQuery: filter,
                sectionComment: isSimulation ? Self.simulatedCaptureComment : nil
            )
            try data.write(to: URL(fileURLWithPath: outPath), options: .atomic)
            var msg: String
            if packetCount == 0 {
                msg = isZh
                    ? "已导出 0 个数据包（文件只有 \(data.count) 字节的 PCAPNG 文件头，没有任何报文）至 \(outPath)\n\(emptyNoteZh)\n"
                    : "Exported 0 packets (the file holds only the \(data.count)-byte PCAPNG header, no frames) to \(outPath)\n\(emptyNoteEn)\n"
            } else {
                msg = isZh
                    ? "已导出 \(packetCount) 个数据包（\(data.count) 字节 PCAPNG）至 \(outPath)\n"
                    : "Exported \(packetCount) packets (\(data.count) bytes of PCAPNG) to \(outPath)\n"
            }
            if isSimulation {
                msg += isZh
                    ? "文件的节注释里写有 SIMULATED 标记：其中的报文不来自真实客户机。\n"
                    : "The file's section comment carries a SIMULATED marker: its frames do not come from a real guest.\n"
            }
            return CLIExecutionOutcome(exitCode: 0, stdout: msg)
        }
        let packets = await coordinator.l2Switch.recentPackets(limit: 50, filterQuery: filter)
        if packets.isEmpty {
            let msg = isZh
                ? "0 个数据包。\(emptyNoteZh)\n"
                : "0 packets. \(emptyNoteEn)\n"
            return CLIExecutionOutcome(exitCode: 0, stdout: msg)
        }
        let lines = packets.map {
            "#\($0.sequenceNumber) [\($0.highestProtocol.rawValue)] \($0.sourceIP ?? $0.sourceMAC) -> \($0.destinationIP ?? $0.destinationMAC) [\($0.verdict.rawValue)] \($0.infoSummary)"
        }
        return CLIExecutionOutcome(exitCode: 0, stdout: lines.joined(separator: "\n") + "\n")
    }

    /// Section-header comment written into every `.pcapng` exported while the simulation backend is active.
    public static let simulatedCaptureComment =
        "SIMULATED: exported with --backend simulation. Frames in this capture were produced by the AgentVM host-side simulator, not captured from a real guest VM."

    private func runPolicy(coordinator: AgentVMFleetCoordinator, parsed: ParsedSubcommandArguments, language: AppLanguage) async throws -> CLIExecutionOutcome {
        let isZh = (language == .zhHans)
        // The selection is written to the workspace manifest, so the next process starts from it. The message
        // says what actually happened: a preset was selected and saved. Nothing is enforced on guest traffic
        // before M5, so it does not claim an air gap is "engaged".
        if parsed.positionals.first == "airgap" {
            try await coordinator.activateFirewallPolicy(.airgappedPreset())
            let msg = isZh
                ? "已把工作区的防火墙策略预设设为：全气隙隔离（Total Air-Gap），已保存到工作区。注意：M5 之前没有客户机流量经过这套策略，它现在不拦截任何真实流量。\n"
                : "Workspace firewall preset set to Total Air-Gap and saved to the workspace. Note: no guest traffic passes through this policy before M5, so nothing is enforced on real traffic yet.\n"
            return CLIExecutionOutcome(exitCode: 0, stdout: msg)
        } else if parsed.positionals.first == "strict" {
            try await coordinator.activateFirewallPolicy(.strictAgentAllowlistPreset())
            let msg = isZh
                ? "已把工作区的防火墙策略预设设为：编码智能体严格白名单（Strict Coding-Agent Allowlist），已保存到工作区。注意：M5 之前没有客户机流量经过这套策略，它现在不拦截任何真实流量。\n"
                : "Workspace firewall preset set to Strict Coding-Agent Allowlist and saved to the workspace. Note: no guest traffic passes through this policy before M5, so nothing is enforced on real traffic yet.\n"
            return CLIExecutionOutcome(exitCode: 0, stdout: msg)
        }
        let current = await coordinator.l2Switch.firewall.currentPolicy()
        let lines = current.rules.map { "[\($0.priority)] \($0.name) -> \($0.verdict.rawValue)" }
        let header = isZh
            ? "\(current.name)（共 \(current.rules.count) 条规则）\n"
            : "\(current.name) (\(current.rules.count) rules)\n"
        return CLIExecutionOutcome(exitCode: 0, stdout: header + lines.joined(separator: "\n") + "\n")
    }

    private func runPlugin(coordinator: AgentVMFleetCoordinator, language: AppLanguage) async throws -> CLIExecutionOutcome {
        let isZh = (language == .zhHans)
        let statuses = await coordinator.pluginEngine.listPluginStatuses()
        let lines = statuses.map { status -> String in
            let stateText = isZh
                ? (status.isEnabled ? "已启用" : "已停用")
                : (status.isEnabled ? "ENABLED" : "DISABLED")
            return "\(status.id.rawValue)\t\(stateText)\tv\(status.manifest.version.description)\t\(status.manifest.name)"
        }
        return CLIExecutionOutcome(exitCode: 0, stdout: lines.joined(separator: "\n") + "\n")
    }

    private func runExportHCL(coordinator: AgentVMFleetCoordinator) async throws -> CLIExecutionOutcome {
        let vms = try await coordinator.store.listVMs().map(\.spec)
        let policy = await coordinator.l2Switch.firewall.currentPolicy()
        let hcl = TopologyIACCodec().exportHCL(vms: vms, policy: policy)
        return CLIExecutionOutcome(exitCode: 0, stdout: hcl)
    }

    private func runExportHTML(
        coordinator: AgentVMFleetCoordinator,
        parsed: ParsedSubcommandArguments,
        language: AppLanguage,
        isSimulation: Bool
    ) async throws -> CLIExecutionOutcome {
        let isZh = (language == .zhHans)
        let seededNow = parsed.flags.contains("--seed-demo")
        if seededNow {
            try await coordinator.seedIndustrialDemonstrationFleetIfEmpty()
        }
        let manifest = try await coordinator.store.loadManifest()
        let isDemo = seededNow || manifest.isDemonstrationWorkspace
        let outPath = parsed.positionals.first ?? "fleet-audit-report.html"
        let exporter = HtmlFleetReportExporter()
        let html = try await exporter.renderStandaloneHTML(coordinator: coordinator, isDemoOverride: isDemo ? true : nil)
        try Data(html.utf8).write(to: URL(fileURLWithPath: outPath), options: .atomic)
        var msg: String
        if isDemo {
            msg = isZh
                ? "[演示数据] 已导出演示集群安全报告 HTML 至 \(outPath)\n"
                : "[DEMO] Exported synthetic demo HTML fleet security report to \(outPath)\n"
        } else {
            msg = isZh
                ? "已导出集群安全报告 HTML 至 \(outPath)\n"
                : "Exported HTML fleet security report to \(outPath)\n"
        }
        if isSimulation {
            msg += isZh
                ? "页面顶部带有 SIMULATED 横幅：其中的运行状态来自主机侧模拟，不是真实客户机。\n"
                : "The page carries a SIMULATED banner: the runtime state in it comes from the host-side simulator, not from real guests.\n"
        }
        return CLIExecutionOutcome(exitCode: 0, stdout: msg)
    }

    // MARK: - Formatting & Resolution Helpers

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

    // MARK: - Subcommand Argument Grammar (unknown options are errors, never ignored)

    /// Exit code for an option or argument a subcommand does not define.
    public static let usageErrorExitCode: Int32 = 2

    struct SubcommandGrammar: Sendable {
        var flags: Set<String> = []
        var valueOptions: Set<String> = []
        /// `nil` means the subcommand parses its own tail (`exec` hands everything after the VM to the guest).
        var maxPositionals: Int? = 0
        var allowedFirstPositional: Set<String>? = nil
    }

    struct ParsedSubcommandArguments: Sendable {
        var positionals: [String] = []
        var flags: Set<String> = []
        var options: [String: String] = [:]
    }

    struct SubcommandUsageError: Error, Sendable {
        var message: String
    }

    static let subcommandGrammars: [String: SubcommandGrammar] = {
        let lifecycle = SubcommandGrammar(maxPositionals: 1)
        let branch = SubcommandGrammar(flags: ["--no-boot", "--boot"], valueOptions: ["--owner"], maxPositionals: 2)
        let list = SubcommandGrammar(flags: ["--json"])
        return [
            "doctor": SubcommandGrammar(),
            "init": SubcommandGrammar(flags: ["--seed-demo"]),
            "ps": list,
            "list": list,
            "create": SubcommandGrammar(valueOptions: ["--owner", "--cpus", "--memory-mb"], maxPositionals: 1),
            "up": lifecycle, "boot": lifecycle, "start": lifecycle,
            "pause": lifecycle, "resume": lifecycle,
            "halt": lifecycle, "stop": lifecycle,
            "branch": branch, "fork": branch,
            "snapshot": SubcommandGrammar(valueOptions: ["--title"], maxPositionals: 2),
            "restore": SubcommandGrammar(maxPositionals: 1),
            "exec": SubcommandGrammar(maxPositionals: nil),
            "pcap": SubcommandGrammar(valueOptions: ["--filter", "--export"]),
            "policy": SubcommandGrammar(maxPositionals: 1, allowedFirstPositional: ["strict", "airgap"]),
            "plugin": SubcommandGrammar(),
            "export-hcl": SubcommandGrammar(),
            "export-html": SubcommandGrammar(flags: ["--seed-demo"], maxPositionals: 1)
        ]
    }()

    static func parseSubcommandArguments(
        subcommand: String,
        arguments: [String],
        language: AppLanguage
    ) -> Result<ParsedSubcommandArguments, SubcommandUsageError> {
        let isZh = (language == .zhHans)
        guard let grammar = subcommandGrammars[subcommand] else {
            return .success(ParsedSubcommandArguments())
        }
        guard let maxPositionals = grammar.maxPositionals else {
            return .success(ParsedSubcommandArguments(positionals: arguments))
        }
        let helpHintEn = "Run 'agentvm help' for usage."
        let helpHintZh = "运行 'agentvm help' 查看用法。"

        var parsed = ParsedSubcommandArguments()
        var idx = 0
        while idx < arguments.count {
            let token = arguments[idx]
            if token.hasPrefix("-") && token != "-" {
                var name = token
                var inlineValue: String?
                if let eq = token.firstIndex(of: "="), token.hasPrefix("--") {
                    name = String(token[..<eq])
                    inlineValue = String(token[token.index(after: eq)...])
                }
                if grammar.valueOptions.contains(name) {
                    if let inlineValue {
                        parsed.options[name] = inlineValue
                        idx += 1
                    } else if idx + 1 < arguments.count {
                        parsed.options[name] = arguments[idx + 1]
                        idx += 2
                    } else {
                        return .failure(SubcommandUsageError(message: isZh
                            ? "选项「\(name)」需要一个值。\(helpHintZh)"
                            : "Option '\(name)' requires a value. \(helpHintEn)"))
                    }
                    continue
                }
                if grammar.flags.contains(name), inlineValue == nil {
                    parsed.flags.insert(name)
                    idx += 1
                    continue
                }
                return .failure(SubcommandUsageError(message: isZh
                    ? "子命令「\(subcommand)」不认识选项「\(token)」。\(helpHintZh)"
                    : "Unknown option '\(token)' for '\(subcommand)'. \(helpHintEn)"))
            }
            if parsed.positionals.count >= maxPositionals {
                return .failure(SubcommandUsageError(message: isZh
                    ? "子命令「\(subcommand)」不接受多余的参数「\(token)」。\(helpHintZh)"
                    : "Unexpected argument '\(token)' for '\(subcommand)'. \(helpHintEn)"))
            }
            if parsed.positionals.isEmpty, let allowed = grammar.allowedFirstPositional, !allowed.contains(token) {
                let choices = allowed.sorted().joined(separator: isZh ? "、" : ", ")
                return .failure(SubcommandUsageError(message: isZh
                    ? "子命令「\(subcommand)」不认识参数「\(token)」（可选：\(choices)）。\(helpHintZh)"
                    : "Unknown argument '\(token)' for '\(subcommand)' (expected one of: \(choices)). \(helpHintEn)"))
            }
            parsed.positionals.append(token)
            idx += 1
        }
        return .success(parsed)
    }

    // MARK: - Simulation Markers (one exit point for every `--backend simulation` output)

    enum SimulationMarkedFormat: Sendable {
        /// Plain text: every line gets the `SIMULATED: ` prefix.
        case textLines
        /// JSON on stdout: left byte-for-byte parseable; records carry `"simulated": true` and stderr gets a marked note.
        case json
        /// A `#`-commented format (HCL): a `# SIMULATED:` comment line is added at the top.
        case hashCommented
    }

    static func markSimulatedOutcome(
        _ outcome: CLIExecutionOutcome,
        stdoutFormat: SimulationMarkedFormat,
        language: AppLanguage
    ) -> CLIExecutionOutcome {
        let isZh = (language == .zhHans)
        var stdout: String
        var stderr = prefixSimulatedLines(outcome.stderr)
        switch stdoutFormat {
        case .textLines:
            stdout = prefixSimulatedLines(outcome.stdout)
        case .json:
            stdout = outcome.stdout
            stderr += isZh
                ? "SIMULATED: 以上 JSON 由 --backend simulation 报告；每条记录的 telemetry.simulated 为 true，其中的运行状态不来自真实客户机。\n"
                : "SIMULATED: the JSON above is reported by --backend simulation; every record has telemetry.simulated = true and its runtime state does not come from a real guest.\n"
        case .hashCommented:
            stdout = "# SIMULATED: exported while --backend simulation was active. This file holds declarative specs only (no runtime state).\n"
                + outcome.stdout
        }
        // A simulated command that prints nothing (for example `exec vm -- true`) still has a simulated exit code.
        if stdout.isEmpty && stderr.isEmpty {
            stderr = isZh
                ? "SIMULATED: 没有输出；退出码 \(outcome.exitCode) 来自主机侧模拟，不来自真实客户机。\n"
                : "SIMULATED: no output; exit code \(outcome.exitCode) comes from the host-side simulator, not from a real guest.\n"
        }
        return CLIExecutionOutcome(exitCode: outcome.exitCode, stdout: stdout, stderr: stderr)
    }

    static func prefixSimulatedLines(_ text: String) -> String {
        guard !text.isEmpty else { return "" }
        let hasTrailingNewline = text.hasSuffix("\n")
        let rawLines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        let effective = hasTrailingNewline ? Array(rawLines.dropLast()) : rawLines
        let prefixed = effective.map { line -> String in
            if line.hasPrefix("SIMULATED:") {
                return line
            }
            return "SIMULATED: \(line)"
        }
        return prefixed.joined(separator: "\n") + (hasTrailingNewline ? "\n" : "")
    }

    private static func localizedStateLabelZh(_ state: VMLifecycleState) -> String {
        switch state {
        case .stopped: return "已停止"
        case .booting: return "启动中"
        case .running: return "运行中"
        case .pausing: return "暂停中"
        case .paused: return "已暂停"
        case .savingState: return "保存内存"
        case .restoringState: return "恢复中"
        case .branching: return "分叉中"
        case .stopping: return "停止中"
        case .crashed: return "故障"
        }
    }

    private static func displayColumnWidth(of text: String) -> Int {
        var total = 0
        for scalar in text.unicodeScalars {
            let v = scalar.value
            if (0x1100...0x115F).contains(v)
                || (0x2E80...0xA4CF).contains(v)
                || (0xAC00...0xD7A3).contains(v)
                || (0xF900...0xFAFF).contains(v)
                || (0xFE10...0xFE6F).contains(v)
                || (0xFF00...0xFF60).contains(v)
                || (0xFFE0...0xFFE6).contains(v)
                || (0x20000...0x3FFFD).contains(v) {
                total += 2
            } else {
                total += 1
            }
        }
        return total
    }

    private static func truncateDisplayColumn(_ text: String, maxWidth: Int) -> String {
        guard displayColumnWidth(of: text) > maxWidth else { return text }
        var out = ""
        var used = 0
        for ch in text {
            let w = displayColumnWidth(of: String(ch))
            if used + w > max(1, maxWidth - 1) {
                out.append("…")
                break
            }
            out.append(ch)
            used += w
        }
        return out
    }

    private static func padDisplayColumn(_ text: String, width: Int) -> String {
        let current = displayColumnWidth(of: text)
        guard current < width else { return text }
        return text + String(repeating: " ", count: width - current)
    }

    public static func helpBanner(language: AppLanguage = .en) -> String {
        if language == .zhHans {
            return """
            AgentVM v\(SemanticVersion.current.description) — Apple Silicon 本地微虚拟机工作台、APFS CoW 与二层协议审计命令行

            用法:
              agentvm [--workspace <bundle.agentvm>] [--lang <zh|en>] [--backend <hardware|simulation>] <子命令> [选项]

            全局选项:
              --workspace, -w <bundle.agentvm>  指定目标 .agentvm 工作区包目录（或设置 AGENTVM_WORKSPACE）
              --lang <zh|en>                    选择界面与命令行语言（zh-Hans 或 English）
              --backend <hardware|simulation>   默认使用真实虚拟化检查（hardware）；显式传入 simulation 启用主机侧模拟演练，
                                                此时每一种输出都带 SIMULATED 标记（文本逐行加前缀，JSON 带 "simulated": true，
                                                HCL 带注释行，导出的 .pcapng 和 HTML 文件内也有标记）

            不认识的选项或多余的参数不会被忽略：命令以退出码 2 结束，不做任何改动。

            子命令:
              doctor                          检测宿主机是否支持虚拟化、当前可执行文件是否具备虚拟化权限、APFS clonefile(2) 与 Rosetta
              init [--seed-demo]              初始化空 .agentvm 工作区（加 --seed-demo 显式载入带 [演示数据] 标记的合成演示集群）
              ps [--json]                     列出沙盒虚拟机、状态、CPU/内存遥测（未实测时显示 —）、IPv4 与 CoW 脏块；
                                              模拟后端写入的状态显示为 SIMULATED:<状态>，JSON 里是 telemetry.simulated = true
              create <名称> [--cpus N]        创建带空稀疏 GPT 磁盘与 NoCloud ISO 的虚拟机配置记录（名称在工作区内不能重复）
              up | pause | resume | halt <vm> 控制虚拟机生命周期（无客户机系统且未传 --backend simulation 时返回错误）
              branch <源虚拟机> <新分支名>    基于 APFS clonefile(2) 派生写时复制磁盘与快照分支
              snapshot [list | <vm> <标题>]   列出或捕获 CoW 磁盘快照检查点
              restore <快照ID>                将虚拟机磁盘回滚至指定快照节点
              exec <vm> -- <命令> [参数...]   在已连接客户机代理的虚拟机中执行命令（或配合 --backend simulation 演练协议栈）
              pcap [--filter <表达式>] [--export <文件.pcapng>]
              policy [strict | airgap]        查看或选择工作区的防火墙规则预设（选择会保存到工作区；M5 之前不作用于任何客户机流量）
              plugin                          列出 JavaScriptCore 扩展模块状态
              export-hcl                      导出 .avm.hcl 声明式拓扑配置
              export-html <输出.html>         导出离线双语集群审计报告 HTML
              mcp                             在 stdio 上运行 JSON-RPC 2.0 MCP 服务
            """ + "\n"
        }
        return """
        AgentVM v\(SemanticVersion.current.description) — Apple Silicon MicroVM Workbench, APFS CoW & L2 Protocol CLI

        USAGE:
          agentvm [--workspace <bundle.agentvm>] [--lang <zh|en>] [--backend <hardware|simulation>] <subcommand> [options]

        GLOBAL OPTIONS:
          --workspace, -w <bundle.agentvm>  Select target .agentvm bundle directory (or set AGENTVM_WORKSPACE)
          --lang <zh|en>                    Select CLI & GUI language (zh-Hans or English)
          --backend <hardware|simulation>   Defaults to hardware checks; pass 'simulation' explicitly for the host-side simulator.
                                            Every output is then marked SIMULATED (text lines are prefixed, JSON carries
                                            "simulated": true, HCL gets a comment line, exported .pcapng and HTML files are marked inside)

        Unknown options or extra arguments are never ignored: the command exits with code 2 and changes nothing.

        SUBCOMMANDS:
          doctor                          Check host virtualization support, this executable's virtualization entitlement, live APFS clonefile(2) & Rosetta
          init [--seed-demo]              Initialize an empty .agentvm bundle (pass --seed-demo for [DEMO]-labeled synthetic data)
          ps [--json]                     List sandbox VMs, states, telemetry ('—' when unmeasured), IPv4, and CoW dirty bytes;
                                          state written by the simulator shows as SIMULATED:<state> (JSON: telemetry.simulated = true)
          create <name> [--cpus N]        Provision a new empty GPT sparse disk + NoCloud ISO sandbox VM record (names are unique per workspace)
          up | pause | resume | halt <vm> Control VM lifecycle (fails honestly if disk has no bootable guest OS)
          branch <src-vm> <branch-name>   Fork an APFS clonefile(2) Copy-on-Write disk & snapshot branch
          snapshot [list | <vm> <title>]  List or capture CoW disk snapshot checkpoints
          restore <snapshot-id>           Roll back VM disk & topology to a snapshot node
          exec <vm> -- <cmd> [args...]    Execute command over AVM1 VirtioSocket (requires live guest agent or --backend simulation)
          pcap [--filter <expr>] [--export <file.pcapng>]
          policy [strict | airgap]        Inspect or select the workspace firewall preset (saved to the workspace; not enforced on guest traffic before M5)
          plugin                          List JavaScriptCore security & automation extensions
          export-hcl                      Export fleet topology as declarative .avm.hcl
          export-html <output.html>       Export standalone Hallmark-clean bilingual fleet report
          mcp                             Run JSON-RPC 2.0 Model Context Protocol server over stdio
        """ + "\n"
    }
}
