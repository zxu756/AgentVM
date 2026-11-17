import AgentVMHypervisor
import AgentVMModels
import AgentVMNetSwitch
import AgentVMPluginHost
import AgentVMStorageCoW
import AgentVMStore
import AgentVMVsockRPC
import Darwin
import Foundation

// MARK: - Complete Headless Multi-Subcommand CLI Engine (`agentvm <subcommand>`)

public final class CLIStandardStreamForwarder: @unchecked Sendable {
    private let lock = NSLock()
    private var forwardedStdoutBytes = Data()
    private var forwardedStderrBytes = Data()

    public init() {}

    public func writeStdoutChunk(_ chunkData: Data, to stdoutHandle: FileHandle = .standardOutput) {
        guard !chunkData.isEmpty else { return }
        lock.withLock {
            forwardedStdoutBytes.append(chunkData)
        }
        try? stdoutHandle.write(contentsOf: chunkData)
    }

    public func writeStderrChunk(_ chunkData: Data, to stderrHandle: FileHandle = .standardError) {
        guard !chunkData.isEmpty else { return }
        lock.withLock {
            forwardedStderrBytes.append(chunkData)
        }
        try? stderrHandle.write(contentsOf: chunkData)
    }

    /// Writes streamed raw bytes directly to `stdoutHandle` without retaining them in memory (Fixes A36).
    public func writeUnbufferedStdoutChunk(_ chunkData: Data, to stdoutHandle: FileHandle = .standardOutput) {
        guard !chunkData.isEmpty else { return }
        try? stdoutHandle.write(contentsOf: chunkData)
    }

    /// Writes streamed raw bytes directly to `stderrHandle` without retaining them in memory (Fixes A36).
    public func writeUnbufferedStderrChunk(_ chunkData: Data, to stderrHandle: FileHandle = .standardError) {
        guard !chunkData.isEmpty else { return }
        try? stderrHandle.write(contentsOf: chunkData)
    }

    public func writeProgress(_ chunk: String, to stderrHandle: FileHandle = .standardError) {
        guard !chunk.isEmpty else { return }
        writeStderrChunk(Data(chunk.utf8), to: stderrHandle)
    }

    public func unforwardedStdoutSuffix(of fullStdoutData: Data) -> Data {
        let prefix = lock.withLock { forwardedStdoutBytes }
        guard !prefix.isEmpty,
              fullStdoutData.count >= prefix.count,
              fullStdoutData.prefix(prefix.count) == prefix else {
            return fullStdoutData
        }
        return Data(fullStdoutData.dropFirst(prefix.count))
    }

    public func unforwardedSuffix(of fullStderrData: Data) -> Data {
        let prefix = lock.withLock { forwardedStderrBytes }
        guard !prefix.isEmpty,
              fullStderrData.count >= prefix.count,
              fullStderrData.prefix(prefix.count) == prefix else {
            return fullStderrData
        }
        return Data(fullStderrData.dropFirst(prefix.count))
    }
}

public struct CLIExecutionOutcome: Codable, Hashable, Sendable {
    public var exitCode: Int32
    public var stdoutData: Data
    public var stderrData: Data

    public var stdout: String {
        get { String(decoding: stdoutData, as: UTF8.self) }
        set { stdoutData = Data(newValue.utf8) }
    }

    public var stderr: String {
        get { String(decoding: stderrData, as: UTF8.self) }
        set { stderrData = Data(newValue.utf8) }
    }

    public init(exitCode: Int32, stdoutData: Data, stderrData: Data = Data()) {
        self.exitCode = exitCode
        self.stdoutData = stdoutData
        self.stderrData = stderrData
    }

    public init(exitCode: Int32, stdout: String = "", stderr: String = "") {
        self.exitCode = exitCode
        self.stdoutData = Data(stdout.utf8)
        self.stderrData = Data(stderr.utf8)
    }

    public func writeProcessOutput(
        stdoutHandle: FileHandle = .standardOutput,
        stderrHandle: FileHandle = .standardError,
        forwarder: CLIStandardStreamForwarder? = nil
    ) {
        let remainingStdout = forwarder?.unforwardedStdoutSuffix(of: stdoutData) ?? stdoutData
        if !remainingStdout.isEmpty {
            try? stdoutHandle.write(contentsOf: remainingStdout)
        }
        let remainingStderr = forwarder?.unforwardedSuffix(of: stderrData) ?? stderrData
        if !remainingStderr.isEmpty {
            try? stderrHandle.write(contentsOf: remainingStderr)
        }
    }
}

public struct ParsedRunArguments: Equatable, Sendable {
    public var vmToken: String
    public var verbose: Bool
    public var executable: String
    public var arguments: [String]

    public init(vmToken: String, verbose: Bool, executable: String, arguments: [String]) {
        self.vmToken = vmToken
        self.verbose = verbose
        self.executable = executable
        self.arguments = arguments
    }
}

public final class OneShotRunSignalController: @unchecked Sendable {
    private let lock = NSLock()
    private var recordedSignal: Int32?
    private var activeTask: Task<GuestExecResult, Error>?
    private var activeCoordinator: AgentVMFleetCoordinator?
    private var activeVMID: VMID?
    private var activeDaemonConnection: DaemonSocketConnection?

    public init() {}

    public static func exitCode(forSignal signalNumber: Int32) -> Int32? {
        switch signalNumber {
        case SIGINT:
            return 130
        case SIGTERM:
            return 143
        default:
            return signalNumber > 0 ? (128 + signalNumber) : nil
        }
    }

    public var terminationExitCode: Int32? {
        lock.withLock {
            guard let sig = recordedSignal else { return nil }
            return Self.exitCode(forSignal: sig)
        }
    }

    func registerActiveRun(
        coordinator: AgentVMFleetCoordinator,
        vmID: VMID,
        task: Task<GuestExecResult, Error>
    ) {
        let shouldInterruptImmediately: Bool = lock.withLock {
            activeCoordinator = coordinator
            activeVMID = vmID
            activeTask = task
            return recordedSignal != nil
        }
        if shouldInterruptImmediately {
            task.cancel()
            Task {
                await coordinator.interruptOneShotExecution(vmID)
            }
        }
    }

    func clearActiveRun() {
        lock.withLock {
            activeTask = nil
            activeCoordinator = nil
            activeVMID = nil
        }
    }

    func registerActiveDaemonExecConnection(_ conn: DaemonSocketConnection) {
        let shouldShutdownImmediately = lock.withLock { () -> Bool in
            activeDaemonConnection = conn
            return recordedSignal != nil
        }
        if shouldShutdownImmediately {
            conn.shutdownReadWrite()
        }
    }

    func clearActiveDaemonExecConnection() {
        lock.withLock {
            activeDaemonConnection = nil
        }
    }

    public func deliver(signal: Int32) {
        let snapshot: (Task<GuestExecResult, Error>?, AgentVMFleetCoordinator?, VMID?, DaemonSocketConnection?) = lock.withLock {
            if recordedSignal == nil {
                recordedSignal = signal
            }
            return (activeTask, activeCoordinator, activeVMID, activeDaemonConnection)
        }
        snapshot.3?.shutdownReadWrite()
        snapshot.0?.cancel()
        if let coordinator = snapshot.1, let vmID = snapshot.2 {
            Task {
                await coordinator.interruptOneShotExecution(vmID)
            }
        }
    }

    public nonisolated func installPOSIXSignalSources() -> [any DispatchSourceSignal] {
        let sigQueue = DispatchQueue(label: "io.zxu756.agentvm.cli.signals")
        Darwin.signal(SIGINT, SIG_IGN)
        Darwin.signal(SIGTERM, SIG_IGN)

        let sigintSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: sigQueue)
        sigintSource.setEventHandler { [weak self] in
            self?.deliver(signal: SIGINT)
        }
        sigintSource.resume()

        let sigtermSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: sigQueue)
        sigtermSource.setEventHandler { [weak self] in
            self?.deliver(signal: SIGTERM)
        }
        sigtermSource.resume()

        return [sigintSource, sigtermSource]
    }
}

private final class StreamedBinaryOutputCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var stdoutBuffer = Data()
    private var stderrBuffer = Data()

    func appendStdout(_ chunk: Data) {
        guard !chunk.isEmpty else { return }
        lock.withLock {
            stdoutBuffer.append(chunk)
        }
    }

    func appendStderr(_ chunk: Data) {
        guard !chunk.isEmpty else { return }
        lock.withLock {
            stderrBuffer.append(chunk)
        }
    }

    func snapshot() -> (stdout: Data, stderr: Data) {
        lock.withLock {
            (stdoutBuffer, stderrBuffer)
        }
    }
}

public struct AgentVMCLIRunner: Sendable {
    public static let cliSubcommands: Set<String> = [
        "doctor", "init", "ps", "list", "image", "create", "run",
        "daemon", "events",
        "up", "boot", "start", "pause", "resume", "halt", "stop",
        "branch", "fork", "snapshot", "restore",
        "exec", "pcap", "policy", "plugin",
        "export-hcl", "export-html",
        "help", "--help", "-h", "version", "--version", "-v"
    ]

    public static let runInfrastructureErrorExitCode: Int32 = 125

    public init() {}

    public static func parseRunArguments(
        _ arguments: [String],
        language: AppLanguage = .en
    ) -> Result<ParsedRunArguments, SubcommandUsageError> {
        let isZh = (language == .zhHans)
        let usageMsg = isZh
            ? "用法：agentvm run <vm> [--verbose] -- <命令> [参数...]。运行 'agentvm help' 查看用法。"
            : "Usage: agentvm run <vm> [--verbose] -- <command> [args...]. Run 'agentvm help' for usage."

        guard let separatorIndex = arguments.firstIndex(of: "--") else {
            return .failure(SubcommandUsageError(message: usageMsg))
        }

        let beforeSeparator = arguments[..<separatorIndex]
        let afterSeparator = Array(arguments[(separatorIndex + 1)...])

        var verbose = false
        var vmToken: String?
        for token in beforeSeparator {
            if token == "--verbose" {
                verbose = true
            } else if token.hasPrefix("-") && token != "-" {
                let err = isZh
                    ? "子命令「run」不认识选项「\(token)」。运行 'agentvm help' 查看用法。"
                    : "Unknown option '\(token)' for 'run'. Run 'agentvm help' for usage."
                return .failure(SubcommandUsageError(message: err))
            } else if vmToken == nil {
                let trimmed = token.trimmingCharacters(in: .whitespacesAndNewlines)
                if trimmed.isEmpty {
                    return .failure(SubcommandUsageError(message: usageMsg))
                }
                vmToken = trimmed
            } else {
                let err = isZh
                    ? "子命令「run」在「--」之前不接受多余的参数「\(token)」。运行 'agentvm help' 查看用法。"
                    : "Unexpected argument '\(token)' before '--' for 'run'. Run 'agentvm help' for usage."
                return .failure(SubcommandUsageError(message: err))
            }
        }

        guard let resolvedVM = vmToken else {
            let err = isZh
                ? "子命令「run」缺少 <vm> 参数。\(usageMsg)"
                : "Missing <vm> argument for 'run'. \(usageMsg)"
            return .failure(SubcommandUsageError(message: err))
        }

        guard let executable = afterSeparator.first, !executable.isEmpty else {
            let err = isZh
                ? "子命令「run」在「--」之后缺少要执行的 <命令>。\(usageMsg)"
                : "Missing <command> after '--' for 'run'. \(usageMsg)"
            return .failure(SubcommandUsageError(message: err))
        }

        return .success(ParsedRunArguments(
            vmToken: resolvedVM,
            verbose: verbose,
            executable: executable,
            arguments: Array(afterSeparator.dropFirst())
        ))
    }

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
        bundleURLOverride: URL? = nil,
        imageCacheURLOverride: URL? = nil,
        curatedEntriesOverride: [BaseImageCatalogEntry]? = nil,
        urlSessionConfiguration: URLSessionConfiguration? = nil,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        diskEngineOverride: APFSCoWDiskEngine? = nil,
        hardwareBackendOverride: (any HardwareVMLowLevelBackend)? = nil,
        hasEntitlementOverride: Bool? = nil,
        daemonSpawnOverride: DaemonSpawnCommandOverride? = nil,
        vsockConnectTimeoutNanosecondsOverride: UInt64? = nil,
        gracefulStopTimeoutNanosecondsOverride: UInt64? = nil,
        daemonRunProcessMode: Bool = false,
        signalController: OneShotRunSignalController? = nil,
        liveStderrHandler: (@Sendable (String) -> Void)? = nil,
        liveStdoutDataHandler: (@Sendable (Data) -> Void)? = nil,
        liveStderrDataHandler: (@Sendable (Data) -> Void)? = nil
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
        var resolvedBundleURL = bundleURLOverride ?? Self.defaultWorkspaceBundleURL(environment: environment)
        var explicitWorkspaceRawString: String?
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
                let rawPath = args[idx + 1]
                explicitWorkspaceRawString = rawPath
                resolvedBundleURL = URL(fileURLWithPath: rawPath, isDirectory: true)
                idx += 2
                continue
            }
            if token.hasPrefix("--workspace=") {
                let rawPath = String(token.dropFirst("--workspace=".count))
                explicitWorkspaceRawString = rawPath
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

        if subcommand == "image" {
            if let usageErr = Self.validateImageSubcommandUsage(parsed: parsed, language: language) {
                let rawStderr = usageErr + "\n"
                return CLIExecutionOutcome(
                    exitCode: Self.usageErrorExitCode,
                    stderr: isSimulationFlagged ? Self.prefixSimulatedLines(rawStderr) : rawStderr
                )
            }
        }

        if subcommand == "create" {
            if let usageErr = Self.validateCreateSubcommandUsage(parsed: parsed, language: language) {
                let rawStderr = usageErr + "\n"
                return CLIExecutionOutcome(
                    exitCode: Self.usageErrorExitCode,
                    stderr: isSimulationFlagged ? Self.prefixSimulatedLines(rawStderr) : rawStderr
                )
            }
        }
        if subcommand == "daemon" {
            if let usageErr = Self.validateDaemonSubcommandUsage(
                parsed: parsed,
                explicitWorkspaceRawString: explicitWorkspaceRawString,
                bundleURLOverride: bundleURLOverride,
                language: language
            ) {
                let rawStderr = usageErr + "\n"
                return CLIExecutionOutcome(
                    exitCode: Self.usageErrorExitCode,
                    stderr: isSimulationFlagged ? Self.prefixSimulatedLines(rawStderr) : rawStderr
                )
            }
        }
        if subcommand == "events" {
            if let usageErr = Self.validateEventsSubcommandUsage(parsed: parsed, language: language) {
                let rawStderr = usageErr + "\n"
                return CLIExecutionOutcome(
                    exitCode: Self.usageErrorExitCode,
                    stderr: isSimulationFlagged ? Self.prefixSimulatedLines(rawStderr) : rawStderr
                )
            }
        }
        var parsedRun: ParsedRunArguments?
        if subcommand == "run" {
            switch Self.parseRunArguments(rest, language: language) {
            case let .success(value):
                parsedRun = value
            case let .failure(usage):
                let rawStderr = usage.message + "\n"
                return CLIExecutionOutcome(
                    exitCode: Self.usageErrorExitCode,
                    stderr: isSimulationFlagged ? Self.prefixSimulatedLines(rawStderr) : rawStderr
                )
            }
        }

        let streamedProgressStderr = StreamedStderrCollector()
        let resolvedCacheURL = (
            imageCacheURLOverride ?? BaseImageRegistryCatalog.defaultCacheDirectoryURL(environment: environment)
        ).standardizedFileURL

        do {
            let rawOutcome: CLIExecutionOutcome
            // How this subcommand's stdout can carry the simulation marker without breaking its format.
            var stdoutFormat: SimulationMarkedFormat = .textLines

            if subcommand == "daemon" {
                let asJSON = parsed.flags.contains("--json")
                if asJSON { stdoutFormat = .json }
                if isSimulationFlagged {
                    let simMsg = isZh
                        ? "[ERR_SIMULATION_UNSUPPORTED] 守护进程仅管理真实硬件虚拟化，不在 '--backend simulation' 下运行。\n"
                        : "[ERR_SIMULATION_UNSUPPORTED] The workspace daemon only runs the hardware hypervisor backend and does not run under '--backend simulation'.\n"
                    return Self.markSimulatedOutcome(
                        CLIExecutionOutcome(exitCode: 1, stderr: simMsg),
                        stdoutFormat: stdoutFormat,
                        language: language
                    )
                }
                return try await runDaemon(
                    workspaceURL: resolvedBundleURL,
                    parsed: parsed,
                    language: language,
                    environment: environment,
                    daemonRunProcessMode: daemonRunProcessMode,
                    daemonSpawnOverride: daemonSpawnOverride
                )
            }

            if subcommand == "image" {
                let asJSON = parsed.flags.contains("--json")
                if asJSON { stdoutFormat = .json }
                let catalog = try BaseImageRegistryCatalog(
                    cacheDirectoryURL: resolvedCacheURL,
                    curatedEntries: curatedEntriesOverride,
                    urlSessionConfiguration: urlSessionConfiguration,
                    createIfMissing: false
                )
                rawOutcome = try await runImage(
                    catalog: catalog,
                    parsed: parsed,
                    language: language,
                    isSimulation: isSimulationFlagged,
                    environment: environment,
                    progressStderrCollector: streamedProgressStderr,
                    liveStderrHandler: isSimulationFlagged ? nil : liveStderrHandler
                )
                if isSimulationFlagged {
                    return Self.markSimulatedOutcome(rawOutcome, stdoutFormat: stdoutFormat, language: language)
                }
                return rawOutcome
            }

            // Preflight `create --image` BEFORE initializing the workspace bundle so a missing/unverified
            // cached image or a `--disk-size` smaller than the image creates zero directories or files.
            if subcommand == "create", let rawImage = parsed.options["--image"] {
                let trimmedImageID = rawImage.trimmingCharacters(in: .whitespacesAndNewlines)
                let preflightCatalog = try BaseImageRegistryCatalog(
                    cacheDirectoryURL: resolvedCacheURL,
                    curatedEntries: curatedEntriesOverride,
                    urlSessionConfiguration: urlSessionConfiguration,
                    createIfMissing: false
                )
                let cachedImageURL = try await preflightCatalog.verifiedCachedImageURL(forID: trimmedImageID)
                var cachedStat = stat()
                guard stat(cachedImageURL.path, &cachedStat) == 0, cachedStat.st_size > 0 else {
                    throw AgentVMError.diskImageOperationFailed(
                        path: cachedImageURL.path,
                        errnoCode: errno,
                        detail: "Unable to stat verified cached base image."
                    )
                }
                let imageBytes = UInt64(cachedStat.st_size)
                if let rawDiskSize = parsed.options["--disk-size"],
                   let requestedBytes = Self.parseDiskSizeBytes(rawDiskSize),
                   requestedBytes < imageBytes {
                    throw AgentVMError.diskSizeTooSmallForImage(
                        imageID: trimmedImageID,
                        requestedBytes: requestedBytes,
                        imageBytes: imageBytes
                    )
                }
            }

            let coordinator = try AgentVMFleetCoordinator(
                bundleURL: resolvedBundleURL,
                executionBackend: executionBackend,
                imageCacheDirectoryURL: resolvedCacheURL,
                curatedImageEntries: curatedEntriesOverride,
                diskEngine: diskEngineOverride ?? APFSCoWDiskEngine(),
                hardwareBackendOverride: hardwareBackendOverride,
                vsockConnectTimeoutNanoseconds: vsockConnectTimeoutNanosecondsOverride ?? 180_000_000_000,
                gracefulStopTimeoutNanoseconds: gracefulStopTimeoutNanosecondsOverride ?? 30_000_000_000
            )

            switch subcommand {
            case "doctor":
                rawOutcome = try await runDoctor(coordinator: coordinator, language: language)
            case "init":
                rawOutcome = try await runInit(coordinator: coordinator, parsed: parsed, language: language)
            case "ps", "list":
                let asJSON = parsed.flags.contains("--json")
                if asJSON { stdoutFormat = .json }
                rawOutcome = try await runListVMs(
                    coordinator: coordinator,
                    asJSON: asJSON,
                    isSimulation: isSimulationFlagged,
                    language: language
                )
            case "events":
                let asJSON = parsed.flags.contains("--json")
                if asJSON { stdoutFormat = .json }
                rawOutcome = try await runEvents(
                    coordinator: coordinator,
                    parsed: parsed,
                    asJSON: asJSON,
                    language: language
                )
            case "create":
                rawOutcome = try await runCreateVM(
                    coordinator: coordinator,
                    parsed: parsed,
                    language: language,
                    progressStderrCollector: streamedProgressStderr,
                    liveStderrHandler: isSimulationFlagged ? nil : liveStderrHandler
                )
            case "run":
                guard let parsedRun else {
                    return CLIExecutionOutcome(exitCode: Self.usageErrorExitCode)
                }
                rawOutcome = try await runOneShot(
                    coordinator: coordinator,
                    parsedRun: parsedRun,
                    signalController: signalController,
                    progressStderrCollector: streamedProgressStderr,
                    liveStderrHandler: isSimulationFlagged ? nil : liveStderrHandler,
                    liveStdoutDataHandler: isSimulationFlagged ? nil : liveStdoutDataHandler,
                    liveStderrDataHandler: isSimulationFlagged ? nil : liveStderrDataHandler
                )
            case "up", "boot", "start":
                rawOutcome = try await runLifecycle(
                    coordinator: coordinator,
                    action: "boot",
                    parsed: parsed,
                    language: language,
                    isSimulation: isSimulationFlagged,
                    environment: environment,
                    daemonSpawnOverride: daemonSpawnOverride,
                    checkProcessEntitlement: hardwareBackendOverride == nil || hasEntitlementOverride != nil,
                    hasEntitlementOverride: hasEntitlementOverride
                )
            case "pause":
                rawOutcome = try await runLifecycle(
                    coordinator: coordinator,
                    action: "pause",
                    parsed: parsed,
                    language: language,
                    isSimulation: isSimulationFlagged,
                    environment: environment,
                    daemonSpawnOverride: daemonSpawnOverride,
                    checkProcessEntitlement: false,
                    hasEntitlementOverride: nil
                )
            case "resume":
                rawOutcome = try await runLifecycle(
                    coordinator: coordinator,
                    action: "resume",
                    parsed: parsed,
                    language: language,
                    isSimulation: isSimulationFlagged,
                    environment: environment,
                    daemonSpawnOverride: daemonSpawnOverride,
                    checkProcessEntitlement: false,
                    hasEntitlementOverride: nil
                )
            case "halt", "stop":
                rawOutcome = try await runLifecycle(
                    coordinator: coordinator,
                    action: "halt",
                    parsed: parsed,
                    language: language,
                    isSimulation: isSimulationFlagged,
                    environment: environment,
                    daemonSpawnOverride: daemonSpawnOverride,
                    checkProcessEntitlement: false,
                    hasEntitlementOverride: nil
                )
            case "branch", "fork":
                rawOutcome = try await runBranchFork(coordinator: coordinator, parsed: parsed, language: language)
            case "snapshot":
                rawOutcome = try await runSnapshot(coordinator: coordinator, parsed: parsed, language: language)
            case "restore":
                rawOutcome = try await runRestore(coordinator: coordinator, parsed: parsed, language: language)
            case "exec":
                rawOutcome = try await runExec(
                    coordinator: coordinator,
                    args: rest,
                    isSimulation: isSimulationFlagged,
                    language: language,
                    signalController: signalController,
                    liveStdoutDataHandler: isSimulationFlagged ? nil : liveStdoutDataHandler,
                    liveStderrDataHandler: isSimulationFlagged ? nil : liveStderrDataHandler
                )
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
                if case .baseImageError = err {
                    hintLine = "提示：运行 'agentvm image list' 查看可用镜像条目，或运行 'agentvm image pull <id>' 下载镜像。"
                } else if case .diskSizeTooSmallForImage = err {
                    hintLine = "提示：请省略 --disk-size（默认等于镜像大小），或指定不小于镜像大小的容量（如 --disk-size 8G）。"
                } else if case let .persistentBootRequiresDaemon(vmName) = err {
                    hintLine = "提示：请改用 'agentvm run \(vmName) -- <命令>' 启动虚拟机、执行命令并关机。"
                } else if case .airgapPolicyUnsupportedBeforeM5 = err {
                    hintLine = "提示：请先运行 'agentvm policy strict' 切换出口策略，M5 之后才支持断网启动。"
                } else if case .runUnsupportedInSimulation = err {
                    hintLine = "提示：请去掉 '--backend simulation' 在真实虚拟机上运行。"
                } else if case .vmBusy = err {
                    hintLine = "提示：请等待当前正在使用该虚拟机的进程结束，或创建另一台虚拟机。"
                } else if case .execOutputBufferOverflow = err {
                    hintLine = "提示：请持续读取 'agentvm exec' 的标准输出/标准错误，或在客户机内将大输出重定向到文件。"
                } else if case let .vmLockedForDeferredMilestone(vmName, _, reason) = err {
                    switch reason {
                    case .liveSnapshotBranchRestoreScheduledForM3:
                        hintLine = "提示：请先运行 'agentvm halt \(vmName)' 停机；运行中的快照、分叉与回滚将在 M3 支持。"
                    case let .mcpAndStudioDaemonClientScheduledForM4(operation):
                        hintLine = "提示：请改用命令行 'agentvm \(operation) \(vmName)'；MCP 与界面接入守护进程将在 M4 支持。"
                    }
                } else {
                    hintLine = "提示：查看审计日志抽屉或运行 'agentvm doctor' 进行环境自检。"
                }
            } else {
                hintLine = "Hint: \(err.remediationHint)"
            }
            let rawStderr = streamedProgressStderr.snapshot() + "[\(err.errorCode)] \(localizedErr)\n\(hintLine)\n"
            let errorExitCode: Int32 = (subcommand == "run" || (subcommand == "exec" && !isSimulationFlagged))
                ? Self.runInfrastructureErrorExitCode
                : 1
            return CLIExecutionOutcome(
                exitCode: errorExitCode,
                stdoutData: Data(),
                stderrData: Data((isSimulationFlagged ? Self.prefixSimulatedLines(rawStderr) : rawStderr).utf8)
            )
        } catch let protoErr as DaemonRPCProtocolError {
            let localizedErr = protoErr.localizedMessage(in: language)
            let rawStderr = streamedProgressStderr.snapshot() + "[\(protoErr.errorCode)] \(localizedErr)\n"
            let errorExitCode: Int32 = (subcommand == "run" || subcommand == "exec") ? Self.runInfrastructureErrorExitCode : 1
            return CLIExecutionOutcome(
                exitCode: errorExitCode,
                stdoutData: Data(),
                stderrData: Data((isSimulationFlagged ? Self.prefixSimulatedLines(rawStderr) : rawStderr).utf8)
            )
        } catch let rpcErr as DaemonRPCError {
            let rawStderr = streamedProgressStderr.snapshot() + "[\(rpcErr.errorCode)] \(rpcErr.message)\n"
            let errorExitCode: Int32 = (subcommand == "run" || subcommand == "exec") ? Self.runInfrastructureErrorExitCode : 1
            return CLIExecutionOutcome(
                exitCode: errorExitCode,
                stdoutData: Data(),
                stderrData: Data((isSimulationFlagged ? Self.prefixSimulatedLines(rawStderr) : rawStderr).utf8)
            )
        } catch let launchErr as DaemonLaunchError {
            let localizedErr = launchErr.localizedMessage(in: language)
            let rawStderr = streamedProgressStderr.snapshot() + "[\(launchErr.errorCode)] \(localizedErr)\n"
            let errorExitCode: Int32 = (subcommand == "run" || subcommand == "exec") ? Self.runInfrastructureErrorExitCode : 1
            return CLIExecutionOutcome(
                exitCode: errorExitCode,
                stdoutData: Data(),
                stderrData: Data((isSimulationFlagged ? Self.prefixSimulatedLines(rawStderr) : rawStderr).utf8)
            )
        } catch let sockErr as DaemonSocketError {
            let localizedErr = sockErr.localizedMessage(in: language)
            let rawStderr = streamedProgressStderr.snapshot() + "[\(sockErr.errorCode)] \(localizedErr)\n"
            let errorExitCode: Int32 = (subcommand == "run" || subcommand == "exec") ? Self.runInfrastructureErrorExitCode : 1
            return CLIExecutionOutcome(
                exitCode: errorExitCode,
                stdoutData: Data(),
                stderrData: Data((isSimulationFlagged ? Self.prefixSimulatedLines(rawStderr) : rawStderr).utf8)
            )
        } catch let framingErr as DaemonRPCLineFramingError {
            let localizedErr = framingErr.localizedMessage(in: language)
            let rawStderr = streamedProgressStderr.snapshot() + "[\(framingErr.errorCode)] \(localizedErr)\n"
            let errorExitCode: Int32 = (subcommand == "run" || (subcommand == "exec" && !isSimulationFlagged))
                ? Self.runInfrastructureErrorExitCode
                : 1
            return CLIExecutionOutcome(
                exitCode: errorExitCode,
                stdoutData: Data(),
                stderrData: Data((isSimulationFlagged ? Self.prefixSimulatedLines(rawStderr) : rawStderr).utf8)
            )
        } catch {
            let prefix = isZh ? "错误：" : "Error: "
            let rawStderr = streamedProgressStderr.snapshot() + "\(prefix)\(error.localizedDescription)\n"
            let errorExitCode: Int32 = (subcommand == "run" || (subcommand == "exec" && !isSimulationFlagged))
                ? Self.runInfrastructureErrorExitCode
                : 1
            return CLIExecutionOutcome(
                exitCode: errorExitCode,
                stdoutData: Data(),
                stderrData: Data((isSimulationFlagged ? Self.prefixSimulatedLines(rawStderr) : rawStderr).utf8)
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

    private func runListVMs(
        coordinator: AgentVMFleetCoordinator,
        asJSON: Bool,
        isSimulation: Bool,
        language: AppLanguage
    ) async throws -> CLIExecutionOutcome {
        // Under hardware backend, query live daemon `list` RPC first (connect-only, never spawning);
        // if no daemon is running, fall back to SQLite + crash reconciliation (`VM_RUNTIME_LOST`).
        let vms: [VMInstanceRecord]
        if !isSimulation {
            let rpcOutcome = try DaemonClient.performUnaryCall(
                workspaceURL: coordinator.store.bundleURL,
                call: .list(DaemonRPCListParams(lang: language)),
                resultType: DaemonRPCListResult.self
            )
            switch rpcOutcome {
            case let .connected((_, listResult)):
                vms = listResult.vms
            case .daemonNotRunning:
                vms = try await coordinator.listVMsForReporting(language: language)
            }
        } else {
            vms = try await coordinator.listVMsForReporting(language: language)
        }
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

    private func runCreateVM(
        coordinator: AgentVMFleetCoordinator,
        parsed: ParsedSubcommandArguments,
        language: AppLanguage,
        progressStderrCollector: StreamedStderrCollector,
        liveStderrHandler: (@Sendable (String) -> Void)?
    ) async throws -> CLIExecutionOutcome {
        let isZh = (language == .zhHans)
        let name = parsed.positionals.first ?? "sandbox-01"
        let owner = parsed.options["--owner"] ?? "cli-agent"
        let cpus = parsed.options["--cpus"].flatMap(Int.init) ?? 2
        let mem = parsed.options["--memory-mb"].flatMap(UInt64.init) ?? 2048

        if let rawImage = parsed.options["--image"] {
            let imageID = rawImage.trimmingCharacters(in: .whitespacesAndNewlines)
            let requestedDiskBytes = parsed.options["--disk-size"].flatMap(Self.parseDiskSizeBytes)
            let summary = try await coordinator.createVMFromImage(
                name: name,
                imageID: imageID,
                requestedDiskBytes: requestedDiskBytes,
                agentOwnerTag: owner,
                vcpus: cpus,
                memoryMB: mem
            )
            if summary.diskCloneStrategy == .fullCopyFallback {
                let copyNote = isZh
                    ? "说明：镜像缓存与工作区不在同一个卷（无法使用 clonefile），已改为完整复制生成根磁盘。\n"
                    : "Note: image cache and workspace are not on the same volume (clonefile unavailable); fell back to a full copy for the root disk.\n"
                progressStderrCollector.emit(copyNote, liveHandler: liveStderrHandler)
            }
            let diskBytes = summary.vmRecord.spec.blockDevices.first?.virtualSizeBytes ?? summary.rootSnapshot.virtualDiskBytes
            let sizeStr = ByteMetricsFormatter.formatBytes(diskBytes)
            let msg: String
            if isZh {
                msg = "已从镜像「\(imageID)」创建虚拟机「\(summary.vmRecord.spec.name)」（\(summary.vmRecord.id.rawValue)），逻辑磁盘 \(sizeStr)，根快照 \(summary.rootSnapshot.id.rawValue)\n"
                    + "网络是系统 NAT，出口策略在 M5 之前不生效。\n"
            } else {
                msg = "Created VM '\(summary.vmRecord.spec.name)' (\(summary.vmRecord.id.rawValue)) from image '\(imageID)' (disk \(sizeStr)) with root snapshot \(summary.rootSnapshot.id.rawValue)\n"
                    + "Network uses system NAT; egress policies do not take effect before M5.\n"
            }
            return CLIExecutionOutcome(
                exitCode: 0,
                stdout: msg,
                stderr: progressStderrCollector.snapshot()
            )
        }

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

    private func runLifecycle(
        coordinator: AgentVMFleetCoordinator,
        action: String,
        parsed: ParsedSubcommandArguments,
        language: AppLanguage,
        isSimulation: Bool,
        environment: [String: String],
        daemonSpawnOverride: DaemonSpawnCommandOverride?,
        checkProcessEntitlement: Bool,
        hasEntitlementOverride: Bool?
    ) async throws -> CLIExecutionOutcome {
        let isZh = (language == .zhHans)
        guard let targetToken = parsed.positionals.first else {
            throw AgentVMError.cliUsageError(
                detail: isZh ? "用法：agentvm \(action) <虚拟机ID或名称>" : "Usage: agentvm \(action) <vm-id-or-name>"
            )
        }
        let vmID = try await resolveVMID(targetToken, coordinator: coordinator)
        let updated: VMInstanceRecord
        if action == "boot" && !isSimulation {
            let entProvider: (@Sendable () -> Bool)?
            if let explicitEnt = hasEntitlementOverride {
                entProvider = { explicitEnt }
            } else {
                entProvider = nil
            }
            _ = try await coordinator.preflightPersistentBoot(
                vmID,
                checkProcessEntitlement: checkProcessEntitlement,
                hasEntitlementOverride: entProvider
            )
            _ = try await DaemonProcessLauncher.launchOrConnect(
                workspaceURL: coordinator.store.bundleURL,
                language: language,
                environment: environment,
                spawnOverride: daemonSpawnOverride
            )
            let params = DaemonRPCVMLifecycleParams(vm: vmID.rawValue, lang: language)
            let rpcOutcome = try DaemonClient.performUnaryCall(
                workspaceURL: coordinator.store.bundleURL,
                call: .up(params),
                resultType: DaemonRPCVMLifecycleResult.self
            )
            switch rpcOutcome {
            case let .connected((_, lifeRes)):
                updated = lifeRes.vm
            case .daemonNotRunning:
                let paths = DaemonWorkspacePaths(workspaceURL: coordinator.store.bundleURL)
                throw AgentVMError.ipcDaemonUnavailable(
                    socketPath: paths.directSocketPath,
                    detail: "Workspace daemon closed connection before completing 'up'."
                )
            }
        } else if !isSimulation {
            let params = DaemonRPCVMLifecycleParams(vm: vmID.rawValue, lang: language)
            let call: DaemonRPCCall
            switch action {
            case "pause":
                call = .pause(params)
            case "resume":
                call = .resume(params)
            default:
                call = .halt(params)
            }
            let rpcOutcome = try DaemonClient.performUnaryCall(
                workspaceURL: coordinator.store.bundleURL,
                call: call,
                resultType: DaemonRPCVMLifecycleResult.self
            )
            switch rpcOutcome {
            case let .connected((_, lifeRes)):
                updated = lifeRes.vm
            case .daemonNotRunning:
                // Connect-only fallback: treat as "no machine running" (strips simulated state & reconciles crash).
                let prepared = try await coordinator.prepareDisconnectedVMForClientOperation(vmID, language: language)
                switch action {
                case "pause":
                    updated = try await coordinator.pauseVM(vmID)
                case "resume":
                    if prepared.telemetry.state != .stopped {
                        _ = try await coordinator.haltVM(vmID)
                    }
                    updated = try await coordinator.resumeVM(vmID)
                default:
                    updated = try await coordinator.haltVM(vmID)
                }
            }
        } else {
            switch action {
            case "boot": updated = try await coordinator.bootPersistentVM(vmID)
            case "pause": updated = try await coordinator.pauseVM(vmID)
            case "resume": updated = try await coordinator.resumeVM(vmID)
            default: updated = try await coordinator.haltVM(vmID)
            }
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

    private func runExec(
        coordinator: AgentVMFleetCoordinator,
        args: [String],
        isSimulation: Bool,
        language: AppLanguage,
        signalController: OneShotRunSignalController? = nil,
        liveStdoutDataHandler: (@Sendable (Data) -> Void)? = nil,
        liveStderrDataHandler: (@Sendable (Data) -> Void)? = nil
    ) async throws -> CLIExecutionOutcome {
        let isZh = (language == .zhHans)
        guard let vmToken = args.first else {
            throw AgentVMError.cliUsageError(
                detail: isZh
                    ? "用法：agentvm exec <虚拟机ID或名称> -- <命令> [参数...]"
                    : "Usage: agentvm exec <vm-id-or-name> -- <command> [args...]"
            )
        }
        var cmdTokens = Array(args.dropFirst())
        if cmdTokens.first == "--" {
            cmdTokens.removeFirst()
        }
        guard let exe = cmdTokens.first else {
            throw AgentVMError.cliUsageError(
                detail: isZh ? "缺少要在客户机中执行的可执行命令。" : "Missing executable after VM identifier."
            )
        }
        let vmID = try await resolveVMID(vmToken, coordinator: coordinator)

        if !isSimulation {
            if let earlySignalExit = signalController?.terminationExitCode {
                return CLIExecutionOutcome(exitCode: earlySignalExit, stdoutData: Data(), stderrData: Data())
            }
            let execParams = DaemonRPCExecParams(
                vm: vmID.rawValue,
                executable: exe,
                arguments: Array(cmdTokens.dropFirst()),
                workingDirectory: DaemonRPCExecParams.defaultWorkingDirectory,
                runAsUser: DaemonRPCExecParams.defaultRunAsUser,
                environment: [:],
                timeoutSeconds: DaemonRPCExecParams.defaultTimeoutSeconds,
                lang: language
            )
            let collector = StreamedBinaryOutputCollector()
            defer { signalController?.clearActiveDaemonExecConnection() }
            do {
                let rpcOutcome = try DaemonClient.performExecCall(
                    workspaceURL: coordinator.store.bundleURL,
                    params: execParams,
                    onConnectionEstablished: { conn in
                        signalController?.registerActiveDaemonExecConnection(conn)
                    },
                    onOutputChunk: { chunk in
                        guard !chunk.data.isEmpty else { return }
                        switch chunk.stream {
                        case .stdout:
                            if let liveStdoutDataHandler {
                                liveStdoutDataHandler(chunk.data)
                            } else {
                                collector.appendStdout(chunk.data)
                            }
                        case .stderr:
                            if let liveStderrDataHandler {
                                liveStderrDataHandler(chunk.data)
                            } else {
                                collector.appendStderr(chunk.data)
                            }
                        }
                    }
                )
                if let signalExitCode = signalController?.terminationExitCode {
                    let partial = collector.snapshot()
                    return CLIExecutionOutcome(
                        exitCode: signalExitCode,
                        stdoutData: partial.stdout,
                        stderrData: partial.stderr
                    )
                }
                switch rpcOutcome {
                case let .connected((_, execRes)):
                    let collected = collector.snapshot()
                    return CLIExecutionOutcome(
                        exitCode: execRes.exitCode,
                        stdoutData: collected.stdout,
                        stderrData: collected.stderr
                    )
                case .daemonNotRunning:
                    // A52: strip any state written by `--backend simulation` (and reconcile crashed running state)
                    // BEFORE formatting the `ERR_LIFECYCLE_STATE` message so we never report a fake simulated `running`.
                    let rec = try await coordinator.prepareDisconnectedVMForClientOperation(vmID, language: language)
                    let rpcErr = DaemonLifecycleErrorFormatter.execNotRunningRPCError(
                        vmName: rec.spec.name,
                        vmID: rec.id,
                        state: rec.telemetry.state,
                        language: language
                    )
                    return CLIExecutionOutcome(
                        exitCode: Self.runInfrastructureErrorExitCode,
                        stderr: DaemonLifecycleErrorFormatter.formatExecRPCErrorStderr(
                            rpcErr,
                            vmName: rec.spec.name,
                            language: language
                        )
                    )
                }
            } catch let rpcErr as DaemonRPCError {
                if let signalExitCode = signalController?.terminationExitCode {
                    let partial = collector.snapshot()
                    return CLIExecutionOutcome(
                        exitCode: signalExitCode,
                        stdoutData: partial.stdout,
                        stderrData: partial.stderr
                    )
                }
                return CLIExecutionOutcome(
                    exitCode: Self.runInfrastructureErrorExitCode,
                    stderr: DaemonLifecycleErrorFormatter.formatExecRPCErrorStderr(
                        rpcErr,
                        vmName: vmToken,
                        language: language
                    )
                )
            } catch {
                if let signalExitCode = signalController?.terminationExitCode {
                    let partial = collector.snapshot()
                    return CLIExecutionOutcome(
                        exitCode: signalExitCode,
                        stdoutData: partial.stdout,
                        stderrData: partial.stderr
                    )
                }
                throw error
            }
        }

        let result = try await coordinator.executeInGuest(
            vmID: vmID,
            request: GuestExecRequest(executable: exe, arguments: Array(cmdTokens.dropFirst()))
        )
        return CLIExecutionOutcome(
            exitCode: result.exitCode,
            stdoutData: result.stdoutData,
            stderrData: result.stderrData
        )
    }

    private func runEvents(
        coordinator: AgentVMFleetCoordinator,
        parsed: ParsedSubcommandArguments,
        asJSON: Bool,
        language: AppLanguage
    ) async throws -> CLIExecutionOutcome {
        let isZh = (language == .zhHans)
        let filterVMID: VMID?
        if let rawVM = parsed.options["--vm"] {
            let trimmed = rawVM.trimmingCharacters(in: .whitespacesAndNewlines)
            filterVMID = try await resolveVMID(trimmed, coordinator: coordinator)
        } else {
            filterVMID = nil
        }
        let limit = parsed.options["--limit"].flatMap(Int.init) ?? 200
        let rawEvents = try await coordinator.store.listDiagnostics(vmID: filterVMID, limit: limit)
        let localizedEvents: [DiagnosticEvent] = rawEvents.map { ev in
            var copy = ev
            copy.message = AgentVMFleetCoordinator.localizedDiagnosticMessage(for: ev, in: language)
            return copy
        }

        if asJSON {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(localizedEvents)
            return CLIExecutionOutcome(exitCode: 0, stdout: String(decoding: data, as: UTF8.self) + "\n")
        }

        if localizedEvents.isEmpty {
            let emptyMsg = isZh ? "暂无诊断事件。\n" : "No diagnostic events recorded.\n"
            return CLIExecutionOutcome(exitCode: 0, stdout: emptyMsg)
        }

        let vms = try await coordinator.store.listVMs()
        let namesByID = Dictionary(uniqueKeysWithValues: vms.map { ($0.id, $0.spec.name) })
        let iso = ISO8601DateFormatter()
        let lines: [String] = localizedEvents.map { ev in
            let ts = iso.string(from: ev.timestamp)
            let vmPart: String
            if let vid = ev.vmID {
                if let vmName = namesByID[vid] {
                    vmPart = " [\(vmName) / \(vid.rawValue)]"
                } else {
                    vmPart = " [\(vid.rawValue)]"
                }
            } else {
                vmPart = ""
            }
            return "\(ts) [\(ev.severity.rawValue.uppercased())] [\(ev.code)]\(vmPart) \(ev.message)"
        }
        return CLIExecutionOutcome(exitCode: 0, stdout: lines.joined(separator: "\n") + "\n")
    }

    private func runOneShot(
        coordinator: AgentVMFleetCoordinator,
        parsedRun: ParsedRunArguments,
        signalController: OneShotRunSignalController?,
        progressStderrCollector: StreamedStderrCollector,
        liveStderrHandler: (@Sendable (String) -> Void)?,
        liveStdoutDataHandler: (@Sendable (Data) -> Void)?,
        liveStderrDataHandler: (@Sendable (Data) -> Void)?
    ) async throws -> CLIExecutionOutcome {
        if await coordinator.currentExecutionBackend() == .deterministicSimulation {
            throw AgentVMError.runUnsupportedInSimulation(vmName: parsedRun.vmToken)
        }
        if let earlySignalExit = signalController?.terminationExitCode {
            return CLIExecutionOutcome(exitCode: earlySignalExit, stdoutData: Data(), stderrData: Data())
        }
        let vmID = try await resolveVMID(parsedRun.vmToken, coordinator: coordinator)
        if let earlySignalExit = signalController?.terminationExitCode {
            return CLIExecutionOutcome(exitCode: earlySignalExit, stdoutData: Data(), stderrData: Data())
        }
        let request = GuestExecRequest(
            executable: parsedRun.executable,
            arguments: parsedRun.arguments,
            workingDirectory: "/",
            runAsUser: "root",
            timeoutSeconds: 3600
        )
        let progressCallback: (@Sendable (String) -> Void)?
        if parsedRun.verbose {
            progressCallback = { message in
                progressStderrCollector.emit("[agentvm run] \(message)\n", liveHandler: liveStderrHandler)
            }
        } else {
            progressCallback = nil
        }

        let outputCollector = StreamedBinaryOutputCollector()
        let chunkCallback: (@Sendable (GuestExecOutputChunk) async -> Void) = { chunk in
            switch chunk.stream {
            case .stdout:
                outputCollector.appendStdout(chunk.data)
                liveStdoutDataHandler?(chunk.data)
            case .stderr, .systemNotice:
                outputCollector.appendStderr(chunk.data)
                liveStderrDataHandler?(chunk.data)
            }
        }

        let execTask = Task<GuestExecResult, Error> {
            try await coordinator.runOneShotCommand(
                vmID: vmID,
                request: request,
                onProgress: progressCallback,
                onOutputChunk: chunkCallback
            )
        }
        signalController?.registerActiveRun(coordinator: coordinator, vmID: vmID, task: execTask)
        defer { signalController?.clearActiveRun() }

        let taskResult = await execTask.result
        if let signalExitCode = signalController?.terminationExitCode {
            let partial = outputCollector.snapshot()
            let partialStderr: Data
            if parsedRun.verbose {
                var combined = Data(progressStderrCollector.snapshot().utf8)
                combined.append(partial.stderr)
                partialStderr = combined
            } else {
                partialStderr = partial.stderr
            }
            return CLIExecutionOutcome(
                exitCode: signalExitCode,
                stdoutData: partial.stdout,
                stderrData: partialStderr
            )
        }

        let execResult = try taskResult.get()

        let stderrData: Data
        if parsedRun.verbose {
            let prefixBytes = Data(progressStderrCollector.snapshot().utf8)
            var combined = Data()
            combined.reserveCapacity(prefixBytes.count + execResult.stderrData.count)
            combined.append(prefixBytes)
            combined.append(execResult.stderrData)
            stderrData = combined
        } else {
            stderrData = execResult.stderrData
        }

        return CLIExecutionOutcome(
            exitCode: execResult.exitCode,
            stdoutData: execResult.stdoutData,
            stderrData: stderrData
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

    // MARK: - Base Image Catalog Subcommands (`agentvm image list | pull <id> | verify <id>`)

    private struct ImageListJSONEntry: Codable, Sendable {
        var id: String
        var displayName: String
        var distribution: String
        var version: String
        var guestOS: String
        var supported: Bool
        var cached: Bool
        var cacheFileName: String?
        var expectedSizeBytes: UInt64?
        var expectedSHA512: String?
        var downloadURL: String?
        var simulated: Bool
    }

    private final class StreamedStderrCollector: @unchecked Sendable {
        private let lock = NSLock()
        private var buffer = ""
        private var lastPrintedPercentBucket: Int = -1
        private var lastPrintedBytes: UInt64 = 0

        func emit(_ line: String, liveHandler: (@Sendable (String) -> Void)?) {
            guard !line.isEmpty else { return }
            lock.lock()
            buffer += line
            lock.unlock()
            liveHandler?(line)
        }

        func shouldEmitDownloadProgress(receivedBytes: UInt64, totalBytes: UInt64?) -> Bool {
            lock.lock()
            defer { lock.unlock() }
            if let totalBytes, totalBytes > 0 {
                let pctBucket = Int((Double(receivedBytes) * 100.0 / Double(totalBytes)) / 5.0)
                if receivedBytes >= totalBytes
                    || lastPrintedPercentBucket < 0
                    || pctBucket > lastPrintedPercentBucket
                    || (receivedBytes - lastPrintedBytes) >= 128 * 1024 * 1024 {
                    lastPrintedPercentBucket = pctBucket
                    lastPrintedBytes = receivedBytes
                    return true
                }
                return false
            }
            if lastPrintedBytes == 0 || (receivedBytes - lastPrintedBytes) >= 64 * 1024 * 1024 {
                lastPrintedBytes = receivedBytes
                return true
            }
            return false
        }

        func snapshot() -> String {
            lock.lock()
            defer { lock.unlock() }
            return buffer
        }
    }

    private static func scrubPath(_ path: String, environment: [String: String]) -> String {
        if let envHome = environment["HOME"]?.trimmingCharacters(in: .whitespacesAndNewlines),
           !envHome.isEmpty {
            let normalizedHome = envHome.hasSuffix("/") ? String(envHome.dropLast()) : envHome
            if path == normalizedHome {
                return "~"
            }
            if path.hasPrefix(normalizedHome + "/") {
                return "~" + String(path.dropFirst(normalizedHome.count))
            }
        }
        return ByteMetricsFormatter.scrubHomePath(path)
    }

    private static func validateImageSubcommandUsage(
        parsed: ParsedSubcommandArguments,
        language: AppLanguage
    ) -> String? {
        let isZh = (language == .zhHans)
        let helpHintEn = "Run 'agentvm help' for usage."
        let helpHintZh = "运行 'agentvm help' 查看用法。"

        guard let action = parsed.positionals.first else {
            return isZh
                ? "子命令「image」缺少操作（可选：list、pull、verify）。\(helpHintZh)"
                : "Missing action for 'image' (expected one of: list, pull, verify). \(helpHintEn)"
        }

        switch action {
        case "list":
            if parsed.positionals.count > 1 {
                return isZh
                    ? "「image list」不接受多余参数「\(parsed.positionals[1])」。\(helpHintZh)"
                    : "Unexpected argument '\(parsed.positionals[1])' for 'image list'. \(helpHintEn)"
            }
            return nil
        case "pull", "verify":
            if parsed.flags.contains("--json") {
                return isZh
                    ? "选项「--json」仅支持「image list」，不支持「image \(action)」。\(helpHintZh)"
                    : "Option '--json' is only supported for 'image list', not 'image \(action)'. \(helpHintEn)"
            }
            if parsed.positionals.count < 2 {
                return isZh
                    ? "「image \(action)」缺少镜像条目 <id> 参数。\(helpHintZh)"
                    : "Missing <id> argument for 'image \(action)'. \(helpHintEn)"
            }
            return nil
        default:
            return isZh
                ? "未知的「image」操作「\(action)」（可选：list、pull、verify）。\(helpHintZh)"
                : "Unknown action '\(action)' for 'image' (expected: list, pull, verify). \(helpHintEn)"
        }
    }

    private static func validateCreateSubcommandUsage(
        parsed: ParsedSubcommandArguments,
        language: AppLanguage
    ) -> String? {
        let isZh = (language == .zhHans)
        let helpHintEn = "Run 'agentvm help' for usage."
        let helpHintZh = "运行 'agentvm help' 查看用法。"

        if let rawCPUs = parsed.options["--cpus"] {
            guard let cpus = Int(rawCPUs), cpus >= 1 else {
                return isZh
                    ? "无效的「--cpus」值「\(rawCPUs)」（需要 >= 1 的整数）。\(helpHintZh)"
                    : "Invalid '--cpus' value '\(rawCPUs)' (expected integer >= 1). \(helpHintEn)"
            }
        }
        if let rawMem = parsed.options["--memory-mb"] {
            guard let mem = UInt64(rawMem), mem >= 256 else {
                return isZh
                    ? "无效的「--memory-mb」值「\(rawMem)」（需要 >= 256 的整数）。\(helpHintZh)"
                    : "Invalid '--memory-mb' value '\(rawMem)' (expected integer >= 256). \(helpHintEn)"
            }
        }
        if parsed.options["--disk-size"] != nil && parsed.options["--image"] == nil {
            return isZh
                ? "选项「--disk-size」需要同时指定「--image <id>」。\(helpHintZh)"
                : "Option '--disk-size' requires '--image <id>'. \(helpHintEn)"
        }
        if let rawImage = parsed.options["--image"] {
            let trimmedImage = rawImage.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmedImage.isEmpty {
                return isZh
                    ? "选项「--image」需要非空的镜像 <id>。\(helpHintZh)"
                    : "Option '--image' requires a non-empty image <id>. \(helpHintEn)"
            }
            guard let name = parsed.positionals.first?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !name.isEmpty else {
                return isZh
                    ? "「create --image」必须提供虚拟机 <名称>。\(helpHintZh)"
                    : "Missing <name> argument for 'create --image'. \(helpHintEn)"
            }
            if let rawDiskSize = parsed.options["--disk-size"] {
                guard parseDiskSizeBytes(rawDiskSize) != nil else {
                    return isZh
                        ? "无效的「--disk-size」值「\(rawDiskSize)」（格式：<正整数>G，例如 8G）。\(helpHintZh)"
                        : "Invalid '--disk-size' value '\(rawDiskSize)' (expected <N>G, e.g. 8G). \(helpHintEn)"
                }
            }
        }
        return nil
    }

    /// Parses `<N>G` / `<N>GiB` / `<N>GB` (`N * 1024^3`) or `<N>M` / `<N>MiB` / `<N>MB` (`N * 1024^2`) for `N >= 1`.
    static func parseDiskSizeBytes(_ raw: String) -> UInt64? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let upper = trimmed.uppercased()
        let multiplier: UInt64
        let digitsPart: Substring
        if upper.hasSuffix("GIB") {
            multiplier = 1024 * 1024 * 1024
            digitsPart = upper.dropLast(3)
        } else if upper.hasSuffix("GB") {
            multiplier = 1024 * 1024 * 1024
            digitsPart = upper.dropLast(2)
        } else if upper.hasSuffix("G") {
            multiplier = 1024 * 1024 * 1024
            digitsPart = upper.dropLast(1)
        } else if upper.hasSuffix("MIB") {
            multiplier = 1024 * 1024
            digitsPart = upper.dropLast(3)
        } else if upper.hasSuffix("MB") {
            multiplier = 1024 * 1024
            digitsPart = upper.dropLast(2)
        } else if upper.hasSuffix("M") {
            multiplier = 1024 * 1024
            digitsPart = upper.dropLast(1)
        } else {
            return nil
        }
        guard !digitsPart.isEmpty,
              digitsPart.allSatisfy({ $0 >= "0" && $0 <= "9" }),
              let count = UInt64(digitsPart),
              count >= 1 else {
            return nil
        }
        let (bytes, overflow) = count.multipliedReportingOverflow(by: multiplier)
        return overflow ? nil : bytes
    }

    private func runImage(
        catalog: BaseImageRegistryCatalog,
        parsed: ParsedSubcommandArguments,
        language: AppLanguage,
        isSimulation: Bool,
        environment: [String: String],
        progressStderrCollector: StreamedStderrCollector,
        liveStderrHandler: (@Sendable (String) -> Void)?
    ) async throws -> CLIExecutionOutcome {
        let isZh = (language == .zhHans)
        let action = parsed.positionals[0]

        switch action {
        case "list":
            let entries = await catalog.allEntries()
            if parsed.flags.contains("--json") {
                var jsonItems: [ImageListJSONEntry] = []
                for entry in entries {
                    let cached = await catalog.isImageCached(id: entry.id)
                    jsonItems.append(
                        ImageListJSONEntry(
                            id: entry.id,
                            displayName: entry.displayName,
                            distribution: entry.distribution,
                            version: entry.version,
                            guestOS: entry.guestOS.rawValue,
                            supported: entry.isSupported,
                            cached: cached,
                            cacheFileName: entry.isSupported ? entry.cacheFileName : nil,
                            expectedSizeBytes: entry.expectedSizeBytes,
                            expectedSHA512: entry.expectedSHA512,
                            downloadURL: entry.downloadURL,
                            simulated: isSimulation
                        )
                    )
                }
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                let raw = try encoder.encode(jsonItems)
                return CLIExecutionOutcome(exitCode: 0, stdout: String(decoding: raw, as: UTF8.self) + "\n")
            }

            let cacheLabel = Self.scrubPath(catalog.cacheDirectoryURL.path, environment: environment)
            var out = ""
            if isZh {
                out += "共享镜像缓存目录：\(cacheLabel)\n"
                out += "\(Self.padDisplayColumn("镜像 ID", width: 34))  \(Self.padDisplayColumn("版本", width: 16))  \(Self.padDisplayColumn("支持状态", width: 12))  \(Self.padDisplayColumn("缓存状态", width: 12))  大小\n"
                out += String(repeating: "-", count: 90) + "\n"
                for entry in entries {
                    let cached = await catalog.isImageCached(id: entry.id)
                    let supportCol = entry.isSupported ? "可用" : "暂不支持"
                    let cacheCol = entry.isSupported ? (cached ? "已缓存" : "未缓存") : "—"
                    let sizeCol = entry.expectedSizeBytes.map { ByteMetricsFormatter.formatBytes($0) } ?? "—"
                    out += "\(Self.padDisplayColumn(entry.id, width: 34))  \(Self.padDisplayColumn(entry.version, width: 16))  \(Self.padDisplayColumn(supportCol, width: 12))  \(Self.padDisplayColumn(cacheCol, width: 12))  \(sizeCol)\n"
                }
            } else {
                out += "Shared Image Cache: \(cacheLabel)\n"
                out += "\(Self.padDisplayColumn("IMAGE ID", width: 34))  \(Self.padDisplayColumn("VERSION", width: 16))  \(Self.padDisplayColumn("SUPPORT", width: 13))  \(Self.padDisplayColumn("CACHE", width: 12))  SIZE\n"
                out += String(repeating: "-", count: 90) + "\n"
                for entry in entries {
                    let cached = await catalog.isImageCached(id: entry.id)
                    let supportCol = entry.isSupported ? "SUPPORTED" : "UNSUPPORTED"
                    let cacheCol = entry.isSupported ? (cached ? "CACHED" : "NOT CACHED") : "—"
                    let sizeCol = entry.expectedSizeBytes.map { ByteMetricsFormatter.formatBytes($0) } ?? "—"
                    out += "\(Self.padDisplayColumn(entry.id, width: 34))  \(Self.padDisplayColumn(entry.version, width: 16))  \(Self.padDisplayColumn(supportCol, width: 13))  \(Self.padDisplayColumn(cacheCol, width: 12))  \(sizeCol)\n"
                }
            }
            return CLIExecutionOutcome(exitCode: 0, stdout: out)

        case "pull":
            let imageID = parsed.positionals[1]
            let outcome = try await catalog.pullImage(id: imageID) { prog in
                let totalLabel = prog.totalBytes.map { ByteMetricsFormatter.formatBytes($0) } ?? "?"
                switch prog.phase {
                case .connecting:
                    let line: String
                    if prog.resumedFromOffset > 0 {
                        let resumeStr = ByteMetricsFormatter.formatBytes(prog.resumedFromOffset)
                        line = isZh
                            ? "正在连接并尝试从 \(resumeStr) 处断点续传「\(prog.imageID)」（共 \(totalLabel)）...\n"
                            : "Connecting to resume '\(prog.imageID)' from \(resumeStr) / \(totalLabel)...\n"
                    } else {
                        line = isZh
                            ? "正在连接并下载「\(prog.imageID)」（共 \(totalLabel)）...\n"
                            : "Connecting to download '\(prog.imageID)' (\(totalLabel))...\n"
                    }
                    progressStderrCollector.emit(line, liveHandler: liveStderrHandler)

                case .resuming:
                    let resumeStr = ByteMetricsFormatter.formatBytes(prog.resumedFromOffset)
                    let line = isZh
                        ? "服务器返回 HTTP 206，正在从字节 \(prog.resumedFromOffset)（\(resumeStr)）续传...\n"
                        : "HTTP 206 Partial Content: resuming from byte \(prog.resumedFromOffset) (\(resumeStr))...\n"
                    progressStderrCollector.emit(line, liveHandler: liveStderrHandler)

                case .restartedFullDownload:
                    let line = isZh
                        ? "服务器返回 HTTP 200（忽略 Range），已清空临时文件并从字节 0 重新下载...\n"
                        : "Server returned HTTP 200 (Range ignored); truncated .part and restarting from byte 0...\n"
                    progressStderrCollector.emit(line, liveHandler: liveStderrHandler)

                case .downloading:
                    guard progressStderrCollector.shouldEmitDownloadProgress(
                        receivedBytes: prog.receivedBytes,
                        totalBytes: prog.totalBytes
                    ) else { return }
                    let recvStr = ByteMetricsFormatter.formatBytes(prog.receivedBytes)
                    let pctStr: String
                    if let total = prog.totalBytes, total > 0 {
                        let pct = min(100.0, Double(prog.receivedBytes) * 100.0 / Double(total))
                        pctStr = String(format: "%.1f%%", pct)
                    } else {
                        pctStr = "—"
                    }
                    let line = isZh
                        ? "下载进度「\(prog.imageID)」：\(recvStr) / \(totalLabel)（\(pctStr)）\n"
                        : "Downloading '\(prog.imageID)': \(recvStr) / \(totalLabel) (\(pctStr))\n"
                    progressStderrCollector.emit(line, liveHandler: liveStderrHandler)

                case .verifying:
                    let recvStr = ByteMetricsFormatter.formatBytes(prog.receivedBytes)
                    let line = isZh
                        ? "正在校验文件大小与 SHA-512 校验和（\(recvStr)）...\n"
                        : "Verifying size and SHA-512 digest (\(recvStr))...\n"
                    progressStderrCollector.emit(line, liveHandler: liveStderrHandler)

                case .completed:
                    let recvStr = ByteMetricsFormatter.formatBytes(prog.receivedBytes)
                    let line = isZh
                        ? "校验通过并已设为只读（0444）：\(prog.imageID)（\(recvStr)）。\n"
                        : "Checksum verified and finalized read-only (0444): \(prog.imageID) (\(recvStr)).\n"
                    progressStderrCollector.emit(line, liveHandler: liveStderrHandler)

                case .alreadyCached:
                    break
                }
            }

            let scrubbedFile = Self.scrubPath(outcome.localFileURL.path, environment: environment)
            let sizeStr = ByteMetricsFormatter.formatBytes(outcome.sizeBytes)
            let stdout: String
            if outcome.wasAlreadyCached {
                stdout = isZh
                    ? "镜像「\(outcome.entry.id)」已在缓存中且已通过校验：\(scrubbedFile)（\(sizeStr)，未联网）。\n"
                    : "Image '\(outcome.entry.id)' is already cached and verified at \(scrubbedFile) (\(sizeStr), no network download performed).\n"
            } else {
                stdout = isZh
                    ? "镜像「\(outcome.entry.id)」已下载并校验通过：\(scrubbedFile)（\(sizeStr)，SHA-512：\(outcome.sha512Hex)）。\n"
                    : "Pulled and verified image '\(outcome.entry.id)' at \(scrubbedFile) (\(sizeStr), SHA-512: \(outcome.sha512Hex)).\n"
            }
            return CLIExecutionOutcome(
                exitCode: 0,
                stdout: stdout,
                stderr: progressStderrCollector.snapshot()
            )

        case "verify":
            let imageID = parsed.positionals[1]
            let report = try await catalog.verifyCuratedImageStrict(id: imageID)
            let scrubbedPath = Self.scrubPath(report.localPath, environment: environment)
            let sizeStr = ByteMetricsFormatter.formatBytes(report.logicalSizeBytes)
            let stdout = isZh
                ? "校验通过「\(report.imageID)」：\(scrubbedPath)（\(sizeStr)，SHA-512：\(report.actualSHA512)）\n"
                : "VERIFIED '\(report.imageID)' at \(scrubbedPath) (\(sizeStr), SHA-512: \(report.actualSHA512))\n"
            return CLIExecutionOutcome(exitCode: 0, stdout: stdout)

        default:
            return CLIExecutionOutcome(exitCode: Self.usageErrorExitCode)
        }
    }

    // MARK: - Workspace Daemon Subcommands (`agentvm daemon run | start | status | stop`)

    public static let daemonNotRunningExitCode: Int32 = 3

    private struct DaemonStatusCLIJSON: Codable, Sendable {
        var running: Bool
        var pid: Int32?
        var startedAt: Date?
        var socketPath: String?
        var workspacePath: String
        var executablePath: String?
        var protocolVersion: Int?
        var semanticVersion: SemanticVersion?
        var vms: [DaemonRPCStatusVM]?
    }

    private struct DaemonStopCLIJSON: Codable, Sendable {
        var running: Bool
        var stopped: Bool
        var pid: Int32?
        var stoppedVMIDs: [String]
    }

    private struct DaemonStartCLIJSON: Codable, Sendable {
        var running: Bool
        var alreadyRunning: Bool
        var pid: Int32
        var startedAt: Date
        var socketPath: String
        var workspacePath: String
        var executablePath: String
        var protocolVersion: Int
        var semanticVersion: SemanticVersion
    }

    private static func validateDaemonSubcommandUsage(
        parsed: ParsedSubcommandArguments,
        explicitWorkspaceRawString: String?,
        bundleURLOverride: URL?,
        language: AppLanguage
    ) -> String? {
        let isZh = (language == .zhHans)
        let helpHintEn = "Run 'agentvm help' for usage."
        let helpHintZh = "运行 'agentvm help' 查看用法。"

        guard let action = parsed.positionals.first else {
            return isZh
                ? "子命令「daemon」缺少操作（可选：run、start、status、stop）。\(helpHintZh)"
                : "Missing action for 'daemon' (expected one of: run, start, status, stop). \(helpHintEn)"
        }

        if action == "run" {
            if parsed.flags.contains("--json") {
                return isZh
                    ? "选项「--json」不支持「daemon run」。\(helpHintZh)"
                    : "Option '--json' is not supported for 'daemon run'. \(helpHintEn)"
            }
            let effectiveRawPath: String?
            if let explicitWorkspaceRawString {
                effectiveRawPath = explicitWorkspaceRawString.trimmingCharacters(in: .whitespacesAndNewlines)
            } else if let bundleURLOverride {
                effectiveRawPath = bundleURLOverride.path
            } else {
                effectiveRawPath = nil
            }
            guard let rawPath = effectiveRawPath, rawPath.hasPrefix("/") else {
                return isZh
                    ? "「daemon run」必须显式传入「--workspace <绝对路径>」。\(helpHintZh)"
                    : "'daemon run' requires an explicit '--workspace <absolute-path>'. \(helpHintEn)"
            }
        }
        return nil
    }

    private func runDaemon(
        workspaceURL: URL,
        parsed: ParsedSubcommandArguments,
        language: AppLanguage,
        environment: [String: String],
        daemonRunProcessMode: Bool,
        daemonSpawnOverride: DaemonSpawnCommandOverride?
    ) async throws -> CLIExecutionOutcome {
        let isZh = (language == .zhHans)
        let asJSON = parsed.flags.contains("--json")
        let action = parsed.positionals[0]
        let paths = DaemonWorkspacePaths(workspaceURL: workspaceURL)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601

        switch action {
        case "status":
            let statusResult = try DaemonClient.queryStatus(
                workspaceURL: paths.workspaceURL,
                language: language
            )
            switch statusResult {
            case .daemonNotRunning:
                if asJSON {
                    let payload = DaemonStatusCLIJSON(
                        running: false,
                        workspacePath: paths.canonicalWorkspacePath
                    )
                    let data = try encoder.encode(payload)
                    return CLIExecutionOutcome(
                        exitCode: Self.daemonNotRunningExitCode,
                        stdout: String(decoding: data, as: UTF8.self) + "\n"
                    )
                }
                let scrubbedWS = Self.scrubPath(paths.canonicalWorkspacePath, environment: environment)
                let msg = isZh
                    ? "守护进程未运行（工作区：\(scrubbedWS)）。\n"
                    : "Daemon is not running (workspace: \(scrubbedWS)).\n"
                return CLIExecutionOutcome(exitCode: Self.daemonNotRunningExitCode, stdout: msg)

            case let .connected(status):
                if asJSON {
                    let payload = DaemonStatusCLIJSON(
                        running: true,
                        pid: status.pid,
                        startedAt: status.startedAt,
                        socketPath: status.socketPath,
                        workspacePath: status.workspacePath,
                        executablePath: status.executablePath,
                        protocolVersion: status.protocolVersion,
                        semanticVersion: status.semanticVersion,
                        vms: status.vms
                    )
                    let data = try encoder.encode(payload)
                    return CLIExecutionOutcome(exitCode: 0, stdout: String(decoding: data, as: UTF8.self) + "\n")
                }
                let iso = ISO8601DateFormatter()
                let startedStr = iso.string(from: status.startedAt)
                let scrubbedWS = Self.scrubPath(status.workspacePath, environment: environment)
                let scrubbedSock = Self.scrubPath(status.socketPath, environment: environment)
                let scrubbedExe = Self.scrubPath(status.executablePath, environment: environment)
                let vmSummary: String
                if status.vms.isEmpty {
                    vmSummary = isZh ? "0 台" : "0"
                } else {
                    let names = status.vms.map { item -> String in
                        if let ver = item.guestAgentVersion, !ver.isEmpty {
                            return "\(item.spec.name) (\(item.id.rawValue), guestAgent=\(ver))"
                        }
                        return "\(item.spec.name) (\(item.id.rawValue))"
                    }.joined(separator: ", ")
                    vmSummary = "\(status.vms.count) [\(names)]"
                }
                let out: String
                if isZh {
                    out = """
                    守护进程状态      : 运行中
                    PID               : \(status.pid)
                    启动时间          : \(startedStr)
                    版本              : v\(status.semanticVersion.description)（协议 \(status.protocolVersion)）
                    套接字路径        : \(scrubbedSock)
                    工作区路径        : \(scrubbedWS)
                    可执行文件        : \(scrubbedExe)
                    持有虚拟机        : \(vmSummary)
                    """ + "\n"
                } else {
                    out = """
                    Daemon Status     : RUNNING
                    PID               : \(status.pid)
                    Started At        : \(startedStr)
                    Version           : v\(status.semanticVersion.description) (protocol \(status.protocolVersion))
                    Socket Path       : \(scrubbedSock)
                    Workspace         : \(scrubbedWS)
                    Executable        : \(scrubbedExe)
                    Held VMs          : \(vmSummary)
                    """ + "\n"
                }
                return CLIExecutionOutcome(exitCode: 0, stdout: out)
            }

        case "stop":
            let stopOutcome = try DaemonClient.stopDaemon(
                workspaceURL: paths.workspaceURL,
                language: language
            )
            switch stopOutcome {
            case .daemonNotRunning:
                if asJSON {
                    let payload = DaemonStopCLIJSON(
                        running: false,
                        stopped: false,
                        pid: nil,
                        stoppedVMIDs: []
                    )
                    let data = try encoder.encode(payload)
                    return CLIExecutionOutcome(exitCode: 0, stdout: String(decoding: data, as: UTF8.self) + "\n")
                }
                let msg = isZh
                    ? "守护进程未运行，无需停止。\n"
                    : "Daemon is not running; nothing to stop.\n"
                return CLIExecutionOutcome(exitCode: 0, stdout: msg)

            case let .connected((pid, res)):
                if asJSON {
                    let payload = DaemonStopCLIJSON(
                        running: false,
                        stopped: true,
                        pid: pid,
                        stoppedVMIDs: res.stoppedVMIDs.map(\.rawValue)
                    )
                    let data = try encoder.encode(payload)
                    return CLIExecutionOutcome(exitCode: 0, stdout: String(decoding: data, as: UTF8.self) + "\n")
                }
                let pidNoteZh = pid.map { "（PID \($0)）" } ?? ""
                let pidNoteEn = pid.map { " (PID \($0))" } ?? ""
                let msg = isZh
                    ? "已停止守护进程\(pidNoteZh)，已关闭 \(res.stoppedVMIDs.count) 台持有的虚拟机。\n"
                    : "Stopped daemon\(pidNoteEn); shut down \(res.stoppedVMIDs.count) held VM(s).\n"
                return CLIExecutionOutcome(exitCode: 0, stdout: msg)
            }

        case "run":
            if daemonRunProcessMode {
                try DaemonLogManager.redirectProcessStandardStreams(toLogURL: paths.daemonLogFileURL)
            }
            let startOutcome = try await WorkspaceDaemonServer.start(workspaceURL: paths.workspaceURL)
            switch startOutcome {
            case let .alreadyRunning(holder):
                let pidStr = holder.map { " (pid=\($0.pid))" } ?? ""
                let msg = isZh
                    ? "该工作区已有守护进程在运行\(pidStr)，本进程以退出码 0 退出。\n"
                    : "A daemon is already running for this workspace\(pidStr); exiting 0.\n"
                return CLIExecutionOutcome(exitCode: 0, stdout: msg)

            case let .started(server):
                let signalSources: [any DispatchSourceSignal]
                if daemonRunProcessMode {
                    signalSources = WorkspaceDaemonServer.installProcessSignalHandlers(for: server)
                } else {
                    signalSources = []
                }
                await server.waitUntilStopped()
                withExtendedLifetime(signalSources) {}
                return CLIExecutionOutcome(exitCode: 0)
            }

        case "start":
            let launchOutcome = try await DaemonProcessLauncher.launchOrConnect(
                workspaceURL: paths.workspaceURL,
                language: language,
                environment: environment,
                spawnOverride: daemonSpawnOverride
            )
            let status = launchOutcome.status
            if asJSON {
                let payload = DaemonStartCLIJSON(
                    running: true,
                    alreadyRunning: launchOutcome.wasAlreadyRunning,
                    pid: status.pid,
                    startedAt: status.startedAt,
                    socketPath: status.socketPath,
                    workspacePath: status.workspacePath,
                    executablePath: status.executablePath,
                    protocolVersion: status.protocolVersion,
                    semanticVersion: status.semanticVersion
                )
                let data = try encoder.encode(payload)
                return CLIExecutionOutcome(exitCode: 0, stdout: String(decoding: data, as: UTF8.self) + "\n")
            }
            let msg: String
            if launchOutcome.wasAlreadyRunning {
                msg = isZh
                    ? "工作区守护进程已在运行（pid=\(status.pid)）。\n"
                    : "Workspace daemon is already running (pid=\(status.pid)).\n"
            } else {
                msg = isZh
                    ? "已启动工作区守护进程（pid=\(status.pid)）。\n"
                    : "Started workspace daemon (pid=\(status.pid)).\n"
            }
            return CLIExecutionOutcome(exitCode: 0, stdout: msg)

        default:
            return CLIExecutionOutcome(exitCode: Self.usageErrorExitCode)
        }
    }

    private static func validateEventsSubcommandUsage(
        parsed: ParsedSubcommandArguments,
        language: AppLanguage
    ) -> String? {
        let isZh = (language == .zhHans)
        let helpHintEn = "Run 'agentvm help' for usage."
        let helpHintZh = "运行 'agentvm help' 查看用法。"

        if let rawVM = parsed.options["--vm"] {
            if rawVM.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                return isZh
                    ? "选项「--vm」需要非空的虚拟机名称或 ID。\(helpHintZh)"
                    : "Option '--vm' requires a non-empty VM name or ID. \(helpHintEn)"
            }
        }
        if let rawLimit = parsed.options["--limit"] {
            guard let n = Int(rawLimit), n >= 1 else {
                return isZh
                    ? "无效的「--limit」值「\(rawLimit)」（需要 >= 1 的整数）。\(helpHintZh)"
                    : "Invalid '--limit' value '\(rawLimit)' (expected integer >= 1). \(helpHintEn)"
            }
        }
        return nil
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

    public struct SubcommandUsageError: Error, Sendable {
        public var message: String

        public init(message: String) {
            self.message = message
        }
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
            "image": SubcommandGrammar(
                flags: ["--json"],
                maxPositionals: 2,
                allowedFirstPositional: ["list", "pull", "verify"]
            ),
            "daemon": SubcommandGrammar(
                flags: ["--json"],
                maxPositionals: 1,
                allowedFirstPositional: ["run", "start", "status", "stop"]
            ),
            "events": SubcommandGrammar(
                flags: ["--json"],
                valueOptions: ["--vm", "--limit"],
                maxPositionals: 0
            ),
            "create": SubcommandGrammar(
                valueOptions: ["--owner", "--cpus", "--memory-mb", "--image", "--disk-size"],
                maxPositionals: 1
            ),
            "up": lifecycle, "boot": lifecycle, "start": lifecycle,
            "pause": lifecycle, "resume": lifecycle,
            "halt": lifecycle, "stop": lifecycle,
            "branch": branch, "fork": branch,
            "snapshot": SubcommandGrammar(valueOptions: ["--title"], maxPositionals: 2),
            "restore": SubcommandGrammar(maxPositionals: 1),
            "run": SubcommandGrammar(maxPositionals: nil),
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
              events [--vm <名称>] [--limit N] [--json]
                                              读取工作区诊断事件账本（diagnostics 表），支持按虚拟机过滤与条数限制
              daemon start|status|stop [--json]
                                              启动、查询或停止本工作区的后台常驻守护进程（未运行时 status 返回退出码 3）；
                                              daemon run --workspace <绝对路径> 在前台运行守护进程本体
              image list [--json]             列出基础镜像目录条目、支持状态与共享缓存状态（默认 ~/Library/Caches/AgentVM/images）
              image pull <id>                 通过 HTTPS（支持断点续传）下载基础镜像至共享缓存并校验大小与 SHA-512
              image verify <id>               在本地重新计算缓存镜像的 SHA-512 与大小并核对固定目录记录（不联网）
              create <名称> [--image <id>] [--disk-size <N>G] [--cpus N] [--memory-mb MB]
                                              从已校验缓存镜像克隆创建虚拟机（不传 --image 则创建空稀疏 GPT 磁盘）
              up | pause | resume | halt <vm> 控制虚拟机生命周期（无客户机系统且未传 --backend simulation 时返回错误）
              branch <源虚拟机> <新分支名>    基于 APFS clonefile(2) 派生写时复制磁盘与快照分支
              snapshot [list | <vm> <标题>]   列出或捕获 CoW 磁盘快照检查点
              restore <快照ID>                将虚拟机磁盘回滚至指定快照节点
              run <vm> [--verbose] -- <命令> [参数...]
                                              单进程无界面启动真机、等待 vsock 守护进程、执行命令并关机（原始字节流直通）。
                                              退出码：客户机命令退出码（含 125，被信号 N 杀掉则为 128+N）原样返回；AgentVM 自身失败
                                              （启动失败、180 秒未连上、机器被占用、无可引导系统、airgap 策略等）统一返回 125，
                                              标准输出为空，原因写到标准错误（靠标准错误有无 AgentVM 报错与客户机退出码 125 区分）；
                                              收到 SIGINT / SIGTERM 停机放锁后返回 130 / 143
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
          events [--vm <name>] [--limit N] [--json]
                                          Read diagnostic events from the workspace diagnostics ledger
          daemon start|status|stop [--json]
                                          Start, inspect, or stop this workspace's background daemon (status exits 3 when not running);
                                          daemon run --workspace <abs-path> runs the daemon server in the foreground
          image list [--json]             List curated base images, support status, and shared cache status (AGENTVM_IMAGE_CACHE)
          image pull <id>                 Download base image over HTTPS (resumable Range) and verify size & SHA-512
          image verify <id>               Recompute cached image SHA-512 & size against pinned catalog entry (offline)
          create <name> [--image <id>] [--disk-size <N>G] [--cpus N] [--memory-mb MB]
                                          Provision a VM cloned from a verified cached image (or an empty GPT disk without --image)
          up | pause | resume | halt <vm> Control VM lifecycle (fails honestly if disk has no bootable guest OS)
          branch <src-vm> <branch-name>   Fork an APFS clonefile(2) Copy-on-Write disk & snapshot branch
          snapshot [list | <vm> <title>]  List or capture CoW disk snapshot checkpoints
          restore <snapshot-id>           Roll back VM disk & topology to a snapshot node
          run <vm> [--verbose] -- <cmd> [args...]
                                          Boot VM headlessly, wait for vsock guest daemon, execute command & shut down (byte-exact I/O).
                                          Exit codes: guest exit codes (including 125, or 128+N on signal N) pass through verbatim;
                                          AgentVM failures (boot error, 180s vsock timeout, VM locked/busy, unbootable disk, airgap policy)
                                          return 125 with empty stdout and an AgentVM error on stderr (distinguishing them from guest exit 125);
                                          SIGINT / SIGTERM shut down the VM, release the lock, and return 130 / 143
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
