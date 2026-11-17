import AgentVMModels
import Foundation
import JavaScriptCore

// MARK: - Typed Hook Outcomes Returned by Sandboxed JS Extensions

public enum PluginPacketHookDecision: Codable, Hashable, Sendable {
    case passThrough
    case overrideVerdict(FirewallVerdict, reason: String)
    case attachAuditNote(String)
}

public enum PluginExecHookDecision: Codable, Hashable, Sendable {
    case allow
    case requirePreExecSnapshot(reason: String)
    case vetoExecution(reason: String)
}

public enum PluginTelemetryDirective: Codable, Hashable, Sendable {
    case none
    case requestPauseVM(vmID: VMID, reason: String)
    case requestSnapshot(vmID: VMID, title: String)
}

public struct PluginDispatchSummary: Codable, Hashable, Sendable {
    public var evaluatedPluginCount: Int
    public var packetDecision: PluginPacketHookDecision
    public var triggeringPluginID: PluginID?
    public var totalDurationMicros: UInt64

    public init(
        evaluatedPluginCount: Int,
        packetDecision: PluginPacketHookDecision,
        triggeringPluginID: PluginID? = nil,
        totalDurationMicros: UInt64 = 0
    ) {
        self.evaluatedPluginCount = evaluatedPluginCount
        self.packetDecision = packetDecision
        self.triggeringPluginID = triggeringPluginID
        self.totalDurationMicros = totalDurationMicros
    }
}

// MARK: - Thread-Confined Per-Plugin JS Runtime & Preemptive Watchdog Gate

private struct UncheckedSendableBox<Value>: @unchecked Sendable {
    let value: Value
}

private struct RawHookExecutionOutcome: Sendable {
    let action: String?
    let reason: String?
    let updatedKV: [String: String]
    let emittedLogs: [(DiagnosticSeverity, String)]
    let runtimeError: String?
    let elapsedMicros: UInt64
}

private final class OneShotWatchdogGate<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, any Error>?
    private var completed = false

    init(_ continuation: CheckedContinuation<Value, any Error>) {
        self.continuation = continuation
    }

    func resolve(_ result: Result<Value, any Error>) {
        lock.lock()
        guard !completed, let cont = continuation else {
            lock.unlock()
            return
        }
        completed = true
        continuation = nil
        lock.unlock()
        cont.resume(with: result)
    }
}

/// Owns a dedicated serial `DispatchQueue`, `JSVirtualMachine`, and compiled `JSContext` for a single plugin.
/// Separating VM/context initialization from per-hook `fn.call` timing prevents cold JavaScriptCore page-ins
/// from triggering spurious `ERR_PLUGIN_TIMEOUT` (`A13`), while running `fn.call` on a dedicated queue lets
/// `OneShotWatchdogGate` preempt infinite/runaway JS loops deterministically within `timeoutMilliseconds`.
private final class IsolatedPluginRuntime: @unchecked Sendable {
    let queue: DispatchQueue
    private var jsVM: JSVirtualMachine?
    private var ctx: JSContext?
    private var compiledSource: String?

    private var activeConfig: [String: String] = [:]
    private var activeKV: [String: String] = [:]
    private var activeHasKVPerm: Bool = false
    private var emittedLogs: [(DiagnosticSeverity, String)] = []
    private var lastRuntimeError: String?

    init(pluginID: PluginID) {
        self.queue = DispatchQueue(
            label: "io.github.zxu756.AgentVM.jsc.\(pluginID.rawValue).\(UUID().uuidString.prefix(8))",
            qos: .userInitiated
        )
    }

    func ensureCompiledOnQueue(source: String, pluginID: PluginID) throws {
        if ctx != nil, compiledSource == source {
            return
        }

        guard let vm = JSVirtualMachine(), let context = JSContext(virtualMachine: vm) else {
            throw AgentVMError.pluginExecutionFailed(
                pluginID: pluginID,
                detail: "JSVirtualMachine allocation failed"
            )
        }

        self.lastRuntimeError = nil
        context.exceptionHandler = { [weak self] _, exc in
            self?.lastRuntimeError = exc?.toString() ?? "Unhandled JS error"
        }

        let logBlock: @convention(block) (String, String) -> Void = { [weak self] levelStr, message in
            let sev = DiagnosticSeverity(rawValue: levelStr.lowercased()) ?? .info
            self?.emittedLogs.append((sev, message))
        }
        let getConfigBlock: @convention(block) (String, String) -> String = { [weak self] key, fallback in
            self?.activeConfig[key] ?? fallback
        }
        let kvGetBlock: @convention(block) (String) -> String? = { [weak self] key in
            guard let self, self.activeHasKVPerm else { return nil }
            return self.activeKV[key]
        }
        let kvSetBlock: @convention(block) (String, String) -> Bool = { [weak self] key, val in
            guard let self, self.activeHasKVPerm else { return false }
            self.activeKV[key] = val
            return true
        }
        let sha256Block: @convention(block) (String) -> String = { text in
            BinaryChecksums.sha256Hex(Data(text.utf8))
        }
        let globBlock: @convention(block) (String, String) -> Bool = { pattern, candidate in
            GlobPatternMatcher.matches(pattern: pattern, candidate: candidate)
        }

        context.setObject(logBlock, forKeyedSubscript: "__avm_log" as NSString)
        context.setObject(getConfigBlock, forKeyedSubscript: "__avm_cfg" as NSString)
        context.setObject(kvGetBlock, forKeyedSubscript: "__avm_kv_get" as NSString)
        context.setObject(kvSetBlock, forKeyedSubscript: "__avm_kv_set" as NSString)
        context.setObject(sha256Block, forKeyedSubscript: "__avm_sha256" as NSString)
        context.setObject(globBlock, forKeyedSubscript: "__avm_glob" as NSString)

        context.evaluateScript("""
        const AgentVM = Object.freeze({
            log: (lvl, msg) => __avm_log(String(lvl || "info"), String(msg || "")),
            getConfig: (key, fallback = "") => __avm_cfg(String(key), String(fallback)),
            kvGet: (key) => __avm_kv_get(String(key)),
            kvSet: (key, val) => __avm_kv_set(String(key), String(val)),
            sha256: (text) => __avm_sha256(String(text || "")),
            matchesGlob: (pat, str) => __avm_glob(String(pat || ""), String(str || ""))
        });
        """)

        context.evaluateScript(source)
        if let err = self.lastRuntimeError {
            throw AgentVMError.pluginExecutionFailed(pluginID: pluginID, detail: err)
        }

        self.jsVM = vm
        self.ctx = context
        self.compiledSource = source
    }

    func executePreparedHookOnQueue(
        functionName: String,
        argument: [String: Any],
        config: [String: String],
        kvStore: [String: String],
        hasKVPerm: Bool
    ) -> RawHookExecutionOutcome {
        guard let context = self.ctx else {
            return RawHookExecutionOutcome(
                action: nil,
                reason: nil,
                updatedKV: kvStore,
                emittedLogs: [],
                runtimeError: "JSContext not initialized",
                elapsedMicros: 0
            )
        }

        self.activeConfig = config
        self.activeKV = kvStore
        self.activeHasKVPerm = hasKVPerm
        self.emittedLogs.removeAll(keepingCapacity: true)
        self.lastRuntimeError = nil

        guard let hookFn = context.objectForKeyedSubscript(functionName), !hookFn.isUndefined else {
            return RawHookExecutionOutcome(
                action: nil,
                reason: nil,
                updatedKV: self.activeKV,
                emittedLogs: [],
                runtimeError: nil,
                elapsedMicros: 0
            )
        }

        // Start per-hook watchdog clock strictly around JS hook function invocation
        let callStartNs = DispatchTime.now().uptimeNanoseconds
        let jsRet = hookFn.call(withArguments: [argument])
        let elapsedNs = DispatchTime.now().uptimeNanoseconds - callStartNs
        let elapsedMicros = elapsedNs / 1_000

        let dict = jsRet?.toDictionary()
        let action = dict?["action"] as? String
        let reason = dict?["reason"] as? String

        return RawHookExecutionOutcome(
            action: action,
            reason: reason,
            updatedKV: self.activeKV,
            emittedLogs: self.emittedLogs,
            runtimeError: self.lastRuntimeError,
            elapsedMicros: elapsedMicros
        )
    }
}

// MARK: - JavaScriptCore Sandboxed Extension Runtime

public actor AgentVMPluginEngine {
    private struct LoadedPluginSlot {
        var status: PluginRuntimeStatus
        var kvStore: [String: String]
        var runtime: IsolatedPluginRuntime?
    }

    private var slots: [PluginID: LoadedPluginSlot] = [:]
    private var orderedIDs: [PluginID] = []
    private var consoleRingBuffer: [PluginHookConsoleEntry] = []
    private let maxConsoleEntries: Int

    public init(
        loadBuiltIns: Bool = true,
        maxConsoleEntries: Int = 1_000
    ) {
        self.maxConsoleEntries = max(100, maxConsoleEntries)
        if loadBuiltIns {
            for manifest in BuiltInAgentPlugins.allManifests() {
                var defaults: [String: String] = [:]
                for field in manifest.configFields {
                    defaults[field.key] = field.defaultValue
                }
                let status = PluginRuntimeStatus(
                    manifest: manifest,
                    isEnabled: true,
                    grantedCapabilities: Set(manifest.requestedCapabilities),
                    configurationValues: defaults
                )
                slots[manifest.id] = LoadedPluginSlot(
                    status: status,
                    kvStore: [:],
                    runtime: IsolatedPluginRuntime(pluginID: manifest.id)
                )
                orderedIDs.append(manifest.id)
            }
        }
    }

    // MARK: - Registration & Capability Management

    public func registerPlugin(_ manifest: PluginManifest, enableImmediately: Bool = true) throws {
        if manifest.id.rawValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            throw AgentVMError.pluginExecutionFailed(pluginID: manifest.id, detail: "Plugin ID cannot be empty.")
        }
        // Validate syntax upfront in an ephemeral JSContext
        try verifyJavaScriptSyntax(source: manifest.entryPointSource, pluginID: manifest.id)

        var defaults: [String: String] = [:]
        for field in manifest.configFields {
            defaults[field.key] = field.defaultValue
        }
        let status = PluginRuntimeStatus(
            manifest: manifest,
            isEnabled: enableImmediately,
            grantedCapabilities: Set(manifest.requestedCapabilities),
            configurationValues: defaults
        )
        slots[manifest.id] = LoadedPluginSlot(
            status: status,
            kvStore: slots[manifest.id]?.kvStore ?? [:],
            runtime: IsolatedPluginRuntime(pluginID: manifest.id)
        )
        if !orderedIDs.contains(manifest.id) {
            orderedIDs.append(manifest.id)
        }
        appendLog(pluginID: manifest.id, level: .info, hook: "lifecycle", message: "Registered plugin v\(manifest.version.description)")
    }

    public func unregisterPlugin(_ id: PluginID) throws {
        guard let slot = slots[id] else { return }
        if slot.status.manifest.isBuiltIn {
            throw AgentVMError.pluginExecutionFailed(pluginID: id, detail: "Built-in security plugins can be disabled, not deleted.")
        }
        slots.removeValue(forKey: id)
        orderedIDs.removeAll { $0 == id }
    }

    public func setPluginEnabled(_ id: PluginID, enabled: Bool) {
        guard var slot = slots[id] else { return }
        slot.status.isEnabled = enabled
        slots[id] = slot
        appendLog(pluginID: id, level: .notice, hook: "lifecycle", message: enabled ? "Plugin enabled" : "Plugin disabled")
    }

    public func setCapability(_ capability: PluginCapability, granted: Bool, for id: PluginID) {
        guard var slot = slots[id] else { return }
        if granted {
            slot.status.grantedCapabilities.insert(capability)
        } else {
            slot.status.grantedCapabilities.remove(capability)
        }
        slots[id] = slot
    }

    public func updateConfiguration(pluginID: PluginID, key: String, value: String) {
        guard var slot = slots[pluginID] else { return }
        slot.status.configurationValues[key] = value
        slots[pluginID] = slot
    }

    public func listPluginStatuses() -> [PluginRuntimeStatus] {
        orderedIDs.compactMap { slots[$0]?.status }
    }

    public func recentConsoleLogs(limit: Int = 200, pluginID: PluginID? = nil) -> [PluginHookConsoleEntry] {
        let filtered: [PluginHookConsoleEntry]
        if let pluginID {
            filtered = consoleRingBuffer.filter { $0.pluginID == pluginID }
        } else {
            filtered = consoleRingBuffer
        }
        return Array(filtered.suffix(limit).reversed())
    }

    // MARK: - Network Packet DPI Hook (`onPacket(pkt)`)

    public func dispatchPacketHook(_ packet: CapturedPacket) async throws -> PluginDispatchSummary {
        var evaluated = 0
        var aggregateMicros: UInt64 = 0

        for id in orderedIDs {
            guard var slot = slots[id], slot.status.isEnabled else { continue }
            guard slot.status.manifest.requestedCapabilities.contains(.networkInspect) else { continue }
            guard slot.status.grantedCapabilities.contains(.networkInspect) else {
                throw AgentVMError.pluginPermissionDenied(pluginID: id, capability: PluginCapability.networkInspect.rawValue)
            }

            evaluated += 1
            let packetDict = encodePacketToDictionary(packet)
            let outcome = try await invokeHook(
                slot: &slot,
                functionName: "onPacket",
                argument: packetDict
            )
            slots[id] = slot
            aggregateMicros += outcome.elapsedMicros

            guard let action = outcome.action else { continue }
            let reason = outcome.reason ?? "Blocked by \(slot.status.manifest.name)"

            if action == "drop" || action == "sinkhole" {
                guard slot.status.grantedCapabilities.contains(.networkVerdictOverride) else {
                    throw AgentVMError.pluginPermissionDenied(
                        pluginID: id,
                        capability: PluginCapability.networkVerdictOverride.rawValue
                    )
                }
                slot.status.blockedActionsCount += 1
                slots[id] = slot
                let verdict: FirewallVerdict = action == "sinkhole" ? .dnsSinkhole : .pluginBlocked
                appendLog(
                    pluginID: id,
                    level: .warning,
                    hook: "onPacket",
                    message: "Overrode packet #\(packet.sequenceNumber) -> \(verdict.rawValue): \(reason)",
                    durationMicros: outcome.elapsedMicros
                )
                return PluginDispatchSummary(
                    evaluatedPluginCount: evaluated,
                    packetDecision: .overrideVerdict(verdict, reason: reason),
                    triggeringPluginID: id,
                    totalDurationMicros: aggregateMicros
                )
            } else if action == "annotate" {
                return PluginDispatchSummary(
                    evaluatedPluginCount: evaluated,
                    packetDecision: .attachAuditNote(reason),
                    triggeringPluginID: id,
                    totalDurationMicros: aggregateMicros
                )
            }
        }

        return PluginDispatchSummary(
            evaluatedPluginCount: evaluated,
            packetDecision: .passThrough,
            triggeringPluginID: nil,
            totalDurationMicros: aggregateMicros
        )
    }

    // MARK: - Guest Exec Pre-Flight Hook (`onBeforeExec(req)`)

    public func dispatchBeforeExecHook(_ request: GuestExecRequest, vmID: VMID) async throws -> PluginExecHookDecision {
        var needsSnapshotReason: String?

        for id in orderedIDs {
            guard var slot = slots[id], slot.status.isEnabled else { continue }
            guard slot.status.manifest.requestedCapabilities.contains(.commandExecInterception) else { continue }
            guard slot.status.grantedCapabilities.contains(.commandExecInterception) else {
                throw AgentVMError.pluginPermissionDenied(
                    pluginID: id,
                    capability: PluginCapability.commandExecInterception.rawValue
                )
            }

            let reqDict: [String: Any] = [
                "vmID": vmID.rawValue,
                "executable": request.executable,
                "arguments": request.arguments,
                "commandLine": request.commandLineSummary,
                "workingDirectory": request.workingDirectory,
                "environment": request.environment,
                "user": request.runAsUser
            ]

            let outcome = try await invokeHook(
                slot: &slot,
                functionName: "onBeforeExec",
                argument: reqDict
            )
            slots[id] = slot

            guard let action = outcome.action else { continue }
            let reason = outcome.reason ?? slot.status.manifest.name

            if action == "veto" {
                slot.status.blockedActionsCount += 1
                slots[id] = slot
                appendLog(
                    pluginID: id,
                    level: .error,
                    hook: "onBeforeExec",
                    message: "Vetoed guest command '\(request.commandLineSummary)': \(reason)",
                    durationMicros: outcome.elapsedMicros
                )
                return .vetoExecution(reason: reason)
            } else if action == "checkpoint" {
                guard slot.status.grantedCapabilities.contains(.snapshotCheckpoint) else {
                    throw AgentVMError.pluginPermissionDenied(
                        pluginID: id,
                        capability: PluginCapability.snapshotCheckpoint.rawValue
                    )
                }
                appendLog(
                    pluginID: id,
                    level: .notice,
                    hook: "onBeforeExec",
                    message: "Requested pre-exec CoW snapshot before '\(request.executable)': \(reason)",
                    durationMicros: outcome.elapsedMicros
                )
                needsSnapshotReason = reason
            }
        }

        if let needsSnapshotReason {
            return .requirePreExecSnapshot(reason: needsSnapshotReason)
        }
        return .allow
    }

    // MARK: - Live Telemetry Budget Hook (`onTelemetry(sample)`)

    public func dispatchTelemetryHook(_ record: VMInstanceRecord) async throws -> [PluginTelemetryDirective] {
        var directives: [PluginTelemetryDirective] = []

        for id in orderedIDs {
            guard var slot = slots[id], slot.status.isEnabled else { continue }
            guard slot.status.manifest.requestedCapabilities.contains(.vmLifecycleControl) else { continue }
            guard slot.status.grantedCapabilities.contains(.vmLifecycleControl) else {
                throw AgentVMError.pluginPermissionDenied(
                    pluginID: id,
                    capability: PluginCapability.vmLifecycleControl.rawValue
                )
            }

            let sampleDict: [String: Any] = [
                "vmID": record.id.rawValue,
                "name": record.spec.name,
                "state": record.telemetry.state.rawValue,
                "cpuPercent": record.telemetry.cpuUsagePercent ?? 0.0,
                "memoryResidentMB": record.telemetry.memoryResidentMB,
                "cowDirtyBytes": record.telemetry.cowDirtyBytes,
                "firewallDroppedPackets": record.telemetry.firewallDroppedPackets,
                "uptimeSeconds": record.telemetry.uptimeSeconds,
                "maxRuntimeMinutes": record.spec.maxRuntimeMinutes
            ]

            let outcome = try await invokeHook(
                slot: &slot,
                functionName: "onTelemetry",
                argument: sampleDict
            )
            slots[id] = slot

            guard let action = outcome.action else { continue }
            let reason = outcome.reason ?? "Triggered by \(slot.status.manifest.name)"

            if action == "pause" {
                slot.status.blockedActionsCount += 1
                slots[id] = slot
                appendLog(
                    pluginID: id,
                    level: .warning,
                    hook: "onTelemetry",
                    message: "Circuit-breaker paused '\(record.spec.name)': \(reason)",
                    durationMicros: outcome.elapsedMicros
                )
                directives.append(.requestPauseVM(vmID: record.id, reason: reason))
            } else if action == "snapshot" {
                directives.append(.requestSnapshot(vmID: record.id, title: reason))
            }
        }

        return directives
    }

    // MARK: - Interactive Scratchpad Evaluator for Plugin Studio UI

    public func evaluateScratchpadScript(
        source: String,
        samplePacket: CapturedPacket
    ) throws -> (outputJSON: String, consoleLines: [String], durationMicros: UInt64) {
        let scratchID = PluginID("scratchpad.live")
        try verifyJavaScriptSyntax(source: source, pluginID: scratchID)

        var scratchLines: [String] = []
        guard let vm = JSVirtualMachine(), let ctx = JSContext(virtualMachine: vm) else {
            throw AgentVMError.pluginExecutionFailed(pluginID: scratchID, detail: "Unable to allocate JSVirtualMachine.")
        }

        var capturedException: String?
        ctx.exceptionHandler = { _, exc in
            capturedException = exc?.toString() ?? "Unknown JavaScript exception"
        }

        let logFn: @convention(block) (String, String) -> Void = { level, msg in
            scratchLines.append("[\(level.uppercased())] \(msg)")
        }
        ctx.setObject(logFn, forKeyedSubscript: "__avm_log" as NSString)
        ctx.evaluateScript("""
        const AgentVM = {
            log: (level, msg) => __avm_log(String(level || "info"), String(msg || "")),
            getConfig: (k, d) => d
        };
        """)
        ctx.evaluateScript(source)
        if let capturedException {
            throw AgentVMError.pluginExecutionFailed(pluginID: scratchID, detail: capturedException)
        }

        let callStartNs = DispatchTime.now().uptimeNanoseconds
        var outputObj: Any = ["status": "loaded (define onPacket(pkt) to test packet verdict)"]
        if let fn = ctx.objectForKeyedSubscript("onPacket"), !fn.isUndefined {
            let ret = fn.call(withArguments: [encodePacketToDictionary(samplePacket)])
            if let capturedException {
                throw AgentVMError.pluginExecutionFailed(pluginID: scratchID, detail: capturedException)
            }
            if let dict = ret?.toDictionary() {
                outputObj = dict
            } else if let str = ret?.toString() {
                outputObj = ["returnValue": str]
            }
        }

        let elapsedMicros = (DispatchTime.now().uptimeNanoseconds - callStartNs) / 1_000
        let jsonData = try JSONSerialization.data(withJSONObject: outputObj, options: [.prettyPrinted, .sortedKeys])
        let jsonText = String(decoding: jsonData, as: UTF8.self)
        return (jsonText, scratchLines, elapsedMicros)
    }

    // MARK: - Internal Isolated JS Execution Engine

    private func verifyJavaScriptSyntax(source: String, pluginID: PluginID) throws {
        guard let vm = JSVirtualMachine(), let ctx = JSContext(virtualMachine: vm) else {
            throw AgentVMError.pluginExecutionFailed(pluginID: pluginID, detail: "Failed to initialize JSContext.")
        }
        var syntaxErr: String?
        ctx.exceptionHandler = { _, exception in
            syntaxErr = exception?.toString() ?? "Invalid JavaScript syntax"
        }
        ctx.evaluateScript("const AgentVM = { log: function(){}, getConfig: function(){ return ''; }, kvGet: function(){ return null; }, kvSet: function(){} };")
        ctx.evaluateScript(source)
        if let syntaxErr {
            throw AgentVMError.pluginExecutionFailed(pluginID: pluginID, detail: syntaxErr)
        }
    }

    private func invokeHook(
        slot: inout LoadedPluginSlot,
        functionName: String,
        argument: [String: Any]
    ) async throws -> (action: String?, reason: String?, elapsedMicros: UInt64) {
        let pluginID = slot.status.manifest.id
        let timeoutMs = max(20, slot.status.manifest.timeoutMilliseconds)
        let source = slot.status.manifest.entryPointSource

        let runtime: IsolatedPluginRuntime
        if let existing = slot.runtime {
            runtime = existing
        } else {
            let fresh = IsolatedPluginRuntime(pluginID: pluginID)
            slot.runtime = fresh
            runtime = fresh
        }

        // Phase 1: Ensure JSVirtualMachine + JSContext + bridges + script compilation complete BEFORE watchdog timer starts
        do {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, any Error>) in
                runtime.queue.async {
                    do {
                        try runtime.ensureCompiledOnQueue(source: source, pluginID: pluginID)
                        cont.resume()
                    } catch {
                        cont.resume(throwing: error)
                    }
                }
            }
        } catch {
            slot.status.lastError = error.localizedDescription
            throw error
        }

        // Phase 2: Execute hookFn.call under preemptive asynchronous watchdog timer
        let configSnapshot = slot.status.configurationValues
        let initialKV = slot.kvStore
        let hasKVPerm = slot.status.grantedCapabilities.contains(.pluginKVStore)
        let boxedArg = UncheckedSendableBox(value: argument)

        let outcome: RawHookExecutionOutcome
        do {
            outcome = try await withCheckedThrowingContinuation { (cont: CheckedContinuation<RawHookExecutionOutcome, any Error>) in
                let gate = OneShotWatchdogGate(cont)

                DispatchQueue.global(qos: .userInitiated).asyncAfter(
                    deadline: .now() + .milliseconds(timeoutMs)
                ) {
                    gate.resolve(.failure(AgentVMError.pluginTimedOut(pluginID: pluginID, limitMs: timeoutMs)))
                }

                runtime.queue.async {
                    let raw = runtime.executePreparedHookOnQueue(
                        functionName: functionName,
                        argument: boxedArg.value,
                        config: configSnapshot,
                        kvStore: initialKV,
                        hasKVPerm: hasKVPerm
                    )
                    gate.resolve(.success(raw))
                }
            }
        } catch let err as AgentVMError {
            // Discard wedged runtime queue/VM so subsequent invocations get a clean JSVirtualMachine
            slot.runtime = nil
            slot.status.lastError = "Exceeded \(timeoutMs) ms watchdog"
            throw err
        }

        for (sev, msg) in outcome.emittedLogs {
            appendLog(pluginID: pluginID, level: sev, hook: functionName, message: msg, durationMicros: outcome.elapsedMicros)
        }

        let elapsedMs = Int(outcome.elapsedMicros / 1_000)
        if elapsedMs > timeoutMs {
            slot.status.lastError = "Exceeded \(timeoutMs) ms watchdog (\(elapsedMs) ms)"
            throw AgentVMError.pluginTimedOut(pluginID: pluginID, limitMs: timeoutMs)
        }

        if let runtimeError = outcome.runtimeError {
            slot.status.lastError = runtimeError
            throw AgentVMError.pluginExecutionFailed(pluginID: pluginID, detail: runtimeError)
        }

        slot.kvStore = outcome.updatedKV
        slot.status.invocationCount += 1
        slot.status.lastInvokedAt = Date()
        slot.status.lastError = nil
        if slot.status.averageDurationMicros == 0 {
            slot.status.averageDurationMicros = outcome.elapsedMicros
        } else {
            slot.status.averageDurationMicros = (slot.status.averageDurationMicros * 3 + outcome.elapsedMicros) / 4
        }

        return (outcome.action, outcome.reason, outcome.elapsedMicros)
    }

    private func encodePacketToDictionary(_ packet: CapturedPacket) -> [String: Any] {
        let rawASCII = String(
            decoding: packet.rawFrame.prefix(512).map { ($0 >= 32 && $0 < 127) ? $0 : UInt8(ascii: ".") },
            as: UTF8.self
        )
        return [
            "id": packet.id.rawValue,
            "sequenceNumber": packet.sequenceNumber,
            "vmID": packet.vmID.rawValue,
            "direction": packet.direction.rawValue,
            "protocol": packet.highestProtocol.rawValue,
            "sourceIP": packet.sourceIP ?? "",
            "destinationIP": packet.destinationIP ?? "",
            "sourcePort": Int(packet.sourcePort ?? 0),
            "destinationPort": Int(packet.destinationPort ?? 0),
            "dnsQueryName": packet.dnsQueryName ?? "",
            "tlsSNI": packet.tlsSNI ?? "",
            "httpHost": packet.httpHost ?? "",
            "httpRequestLine": packet.httpRequestLine ?? "",
            "infoSummary": packet.infoSummary,
            "asciiPreview": rawASCII,
            "frameLength": packet.frameLength
        ]
    }

    private func appendLog(
        pluginID: PluginID,
        level: DiagnosticSeverity,
        hook: String,
        message: String,
        durationMicros: UInt64 = 0
    ) {
        consoleRingBuffer.append(PluginHookConsoleEntry(
            pluginID: pluginID,
            level: level,
            hookName: hook,
            message: message,
            durationMicros: durationMicros
        ))
        if consoleRingBuffer.count > maxConsoleEntries {
            consoleRingBuffer.removeFirst(consoleRingBuffer.count - maxConsoleEntries)
        }
    }
}
