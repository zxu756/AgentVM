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

// MARK: - JavaScriptCore Sandboxed Extension Runtime

public actor AgentVMPluginEngine {
    private struct LoadedPluginSlot {
        var status: PluginRuntimeStatus
        var kvStore: [String: String]
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
                slots[manifest.id] = LoadedPluginSlot(status: status, kvStore: [:])
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
        slots[manifest.id] = LoadedPluginSlot(status: status, kvStore: slots[manifest.id]?.kvStore ?? [:])
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

    public func dispatchPacketHook(_ packet: CapturedPacket) throws -> PluginDispatchSummary {
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
            let (resultDict, elapsedMicros) = try invokeHook(
                slot: &slot,
                functionName: "onPacket",
                argument: packetDict
            )
            slots[id] = slot
            aggregateMicros += elapsedMicros

            guard let action = resultDict?["action"] as? String else { continue }
            let reason = (resultDict?["reason"] as? String) ?? "Blocked by \(slot.status.manifest.name)"

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
                    durationMicros: elapsedMicros
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

    public func dispatchBeforeExecHook(_ request: GuestExecRequest, vmID: VMID) throws -> PluginExecHookDecision {
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

            let (resultDict, elapsedMicros) = try invokeHook(
                slot: &slot,
                functionName: "onBeforeExec",
                argument: reqDict
            )
            slots[id] = slot

            guard let action = resultDict?["action"] as? String else { continue }
            let reason = (resultDict?["reason"] as? String) ?? slot.status.manifest.name

            if action == "veto" {
                slot.status.blockedActionsCount += 1
                slots[id] = slot
                appendLog(
                    pluginID: id,
                    level: .error,
                    hook: "onBeforeExec",
                    message: "Vetoed guest command '\(request.commandLineSummary)': \(reason)",
                    durationMicros: elapsedMicros
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
                    durationMicros: elapsedMicros
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

    public func dispatchTelemetryHook(_ record: VMInstanceRecord) throws -> [PluginTelemetryDirective] {
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
                "cpuPercent": record.telemetry.cpuUsagePercent,
                "memoryResidentMB": record.telemetry.memoryResidentMB,
                "cowDirtyBytes": record.telemetry.cowDirtyBytes,
                "firewallDroppedPackets": record.telemetry.firewallDroppedPackets,
                "uptimeSeconds": record.telemetry.uptimeSeconds,
                "maxRuntimeMinutes": record.spec.maxRuntimeMinutes
            ]

            let (resultDict, elapsedMicros) = try invokeHook(
                slot: &slot,
                functionName: "onTelemetry",
                argument: sampleDict
            )
            slots[id] = slot

            guard let action = resultDict?["action"] as? String else { continue }
            let reason = (resultDict?["reason"] as? String) ?? "Triggered by \(slot.status.manifest.name)"

            if action == "pause" {
                slot.status.blockedActionsCount += 1
                slots[id] = slot
                appendLog(
                    pluginID: id,
                    level: .warning,
                    hook: "onTelemetry",
                    message: "Circuit-breaker paused '\(record.spec.name)': \(reason)",
                    durationMicros: elapsedMicros
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
        let startNs = DispatchTime.now().uptimeNanoseconds

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

        let elapsedMicros = (DispatchTime.now().uptimeNanoseconds - startNs) / 1_000
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
    ) throws -> ([AnyHashable: Any]?, UInt64) {
        let pluginID = slot.status.manifest.id
        let timeoutMs = max(20, slot.status.manifest.timeoutMilliseconds)
        let startNs = DispatchTime.now().uptimeNanoseconds

        guard let jsVM = JSVirtualMachine(), let ctx = JSContext(virtualMachine: jsVM) else {
            throw AgentVMError.pluginExecutionFailed(pluginID: pluginID, detail: "JSVirtualMachine allocation failed")
        }

        var runtimeError: String?
        ctx.exceptionHandler = { _, exc in
            runtimeError = exc?.toString() ?? "Unhandled JS error"
        }

        let configSnapshot = slot.status.configurationValues
        var localKV = slot.kvStore
        let hasKVPerm = slot.status.grantedCapabilities.contains(.pluginKVStore)
        var emittedLogs: [(DiagnosticSeverity, String)] = []

        let logBlock: @convention(block) (String, String) -> Void = { levelStr, message in
            let sev = DiagnosticSeverity(rawValue: levelStr.lowercased()) ?? .info
            emittedLogs.append((sev, message))
        }
        let getConfigBlock: @convention(block) (String, String) -> String = { key, fallback in
            configSnapshot[key] ?? fallback
        }
        let kvGetBlock: @convention(block) (String) -> String? = { key in
            guard hasKVPerm else { return nil }
            return localKV[key]
        }
        let kvSetBlock: @convention(block) (String, String) -> Bool = { key, val in
            guard hasKVPerm else { return false }
            localKV[key] = val
            return true
        }
        let sha256Block: @convention(block) (String) -> String = { text in
            BinaryChecksums.sha256Hex(Data(text.utf8))
        }
        let globBlock: @convention(block) (String, String) -> Bool = { pattern, candidate in
            GlobPatternMatcher.matches(pattern: pattern, candidate: candidate)
        }

        ctx.setObject(logBlock, forKeyedSubscript: "__avm_log" as NSString)
        ctx.setObject(getConfigBlock, forKeyedSubscript: "__avm_cfg" as NSString)
        ctx.setObject(kvGetBlock, forKeyedSubscript: "__avm_kv_get" as NSString)
        ctx.setObject(kvSetBlock, forKeyedSubscript: "__avm_kv_set" as NSString)
        ctx.setObject(sha256Block, forKeyedSubscript: "__avm_sha256" as NSString)
        ctx.setObject(globBlock, forKeyedSubscript: "__avm_glob" as NSString)

        ctx.evaluateScript("""
        const AgentVM = Object.freeze({
            log: (lvl, msg) => __avm_log(String(lvl || "info"), String(msg || "")),
            getConfig: (key, fallback = "") => __avm_cfg(String(key), String(fallback)),
            kvGet: (key) => __avm_kv_get(String(key)),
            kvSet: (key, val) => __avm_kv_set(String(key), String(val)),
            sha256: (text) => __avm_sha256(String(text || "")),
            matchesGlob: (pat, str) => __avm_glob(String(pat || ""), String(str || ""))
        });
        """)

        ctx.evaluateScript(slot.status.manifest.entryPointSource)
        if let runtimeError {
            slot.status.lastError = runtimeError
            throw AgentVMError.pluginExecutionFailed(pluginID: pluginID, detail: runtimeError)
        }

        guard let hookFn = ctx.objectForKeyedSubscript(functionName), !hookFn.isUndefined else {
            return (nil, 0)
        }

        let jsRet = hookFn.call(withArguments: [argument])
        let elapsedNs = DispatchTime.now().uptimeNanoseconds - startNs
        let elapsedMicros = elapsedNs / 1_000
        let elapsedMs = Int(elapsedMicros / 1_000)

        for (sev, msg) in emittedLogs {
            appendLog(pluginID: pluginID, level: sev, hook: functionName, message: msg, durationMicros: elapsedMicros)
        }

        if elapsedMs > timeoutMs {
            slot.status.lastError = "Exceeded \(timeoutMs) ms watchdog (\(elapsedMs) ms)"
            throw AgentVMError.pluginTimedOut(pluginID: pluginID, limitMs: timeoutMs)
        }

        if let runtimeError {
            slot.status.lastError = runtimeError
            throw AgentVMError.pluginExecutionFailed(pluginID: pluginID, detail: runtimeError)
        }

        slot.kvStore = localKV
        slot.status.invocationCount += 1
        slot.status.lastInvokedAt = Date()
        slot.status.lastError = nil
        if slot.status.averageDurationMicros == 0 {
            slot.status.averageDurationMicros = elapsedMicros
        } else {
            slot.status.averageDurationMicros = (slot.status.averageDurationMicros * 3 + elapsedMicros) / 4
        }

        return (jsRet?.toDictionary(), elapsedMicros)
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
