import AgentVMModels
import Foundation

// MARK: - Reversible Workspace Command Protocol & Summary Models

public protocol ReversibleWorkspaceCommand: Sendable {
    var commandID: UUID { get }
    var title: String { get }
    var timestamp: Date { get }

    func apply(to store: AgentVMProjectStore) async throws
    func revert(on store: AgentVMProjectStore) async throws
}

extension ReversibleWorkspaceCommand {
    internal var commandTypeIdentifier: String {
        String(describing: Self.self)
    }
}

public protocol SummarizableWorkspaceCommand: ReversibleWorkspaceCommand {
    var payloadSummary: String { get }
}

public enum UndoHistoryCapacity: Codable, Hashable, Sendable {
    case unlimited
    case bounded(Int)

    public var maxEntries: Int? {
        switch self {
        case .unlimited:
            return nil
        case let .bounded(limit):
            return max(1, limit)
        }
    }
}

public struct UndoCommandSummary: Codable, Hashable, Sendable, Identifiable {
    public var id: UUID { commandID }
    public var commandID: UUID
    public var commandType: String
    public var title: String
    public var timestamp: Date
    public var payloadSummary: String
    public var stackDepthIndex: Int

    public init(
        commandID: UUID,
        commandType: String,
        title: String,
        timestamp: Date,
        payloadSummary: String,
        stackDepthIndex: Int = 0
    ) {
        self.commandID = commandID
        self.commandType = commandType
        self.title = title
        self.timestamp = timestamp
        self.payloadSummary = payloadSummary
        self.stackDepthIndex = stackDepthIndex
    }
}

// MARK: - Thread-Safe Prior-State Box for Value-Semantics Commands

private final class LockedPriorStateBox<State: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: State?

    init(_ initial: State? = nil) {
        self.value = initial
    }

    func get() -> State? {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func setIfEmpty(_ newValue: State) {
        lock.lock()
        defer { lock.unlock() }
        if value == nil {
            value = newValue
        }
    }

    func set(_ newValue: State) {
        lock.lock()
        defer { lock.unlock() }
        value = newValue
    }
}

private enum PriorEntitySnapshot<Entity: Sendable>: Sendable {
    case existed(Entity)
    case didNotExist
}

// MARK: - Concrete Reversible Workspace Commands

/// Inserts a new `VMInstanceRecord` or updates an existing VM specification/state.
public struct UpsertVMCommand: SummarizableWorkspaceCommand {
    public let commandID: UUID
    public let title: String
    public let timestamp: Date
    public let record: VMInstanceRecord

    private let priorBox: LockedPriorStateBox<PriorEntitySnapshot<VMInstanceRecord>>

    public init(
        commandID: UUID = UUID(),
        title: String? = nil,
        timestamp: Date = Date(),
        record: VMInstanceRecord,
        previousRecord: VMInstanceRecord? = nil
    ) {
        self.commandID = commandID
        self.title = title ?? "Upsert VM '\(record.spec.name)' (\(record.id.rawValue))"
        self.timestamp = timestamp
        self.record = record
        if let previousRecord {
            self.priorBox = LockedPriorStateBox(.existed(previousRecord))
        } else {
            self.priorBox = LockedPriorStateBox(nil)
        }
    }

    public init(
        commandID: UUID = UUID(),
        title: String? = nil,
        timestamp: Date = Date(),
        newRecord: VMInstanceRecord,
        previousRecord: VMInstanceRecord?
    ) {
        self.init(
            commandID: commandID,
            title: title,
            timestamp: timestamp,
            record: newRecord,
            previousRecord: previousRecord
        )
    }

    public var payloadSummary: String {
        "vmID=\(record.id.rawValue) name=\(record.spec.name) vcpu=\(record.spec.compute.vcpuCount) memMB=\(record.spec.compute.memoryMB)"
    }

    public func apply(to store: AgentVMProjectStore) async throws {
        if priorBox.get() == nil {
            if let existing = try await store.fetchVM(record.id) {
                priorBox.setIfEmpty(.existed(existing))
            } else {
                priorBox.setIfEmpty(.didNotExist)
            }
        }
        try await store.upsertVM(record)
    }

    public func revert(on store: AgentVMProjectStore) async throws {
        switch priorBox.get() ?? .didNotExist {
        case let .existed(previous):
            try await store.upsertVM(previous)
        case .didNotExist:
            try await store.deleteVM(record.id)
        }
    }
}

/// Deletes an existing `VMInstanceRecord` while preserving its full specification and telemetry for undo restoration.
public struct DeleteVMCommand: SummarizableWorkspaceCommand {
    public let commandID: UUID
    public let title: String
    public let timestamp: Date
    public let vmID: VMID

    private let deletedRecordBox: LockedPriorStateBox<VMInstanceRecord>

    public init(
        commandID: UUID = UUID(),
        title: String? = nil,
        timestamp: Date = Date(),
        vmID: VMID,
        previousRecord: VMInstanceRecord? = nil
    ) {
        self.commandID = commandID
        self.title = title ?? "Delete VM '\(previousRecord?.spec.name ?? vmID.rawValue)'"
        self.timestamp = timestamp
        self.vmID = vmID
        self.deletedRecordBox = LockedPriorStateBox(previousRecord)
    }

    public init(
        commandID: UUID = UUID(),
        title: String? = nil,
        timestamp: Date = Date(),
        record: VMInstanceRecord
    ) {
        self.init(
            commandID: commandID,
            title: title ?? "Delete VM '\(record.spec.name)' (\(record.id.rawValue))",
            timestamp: timestamp,
            vmID: record.id,
            previousRecord: record
        )
    }

    public var payloadSummary: String {
        if let saved = deletedRecordBox.get() {
            return "vmID=\(vmID.rawValue) name=\(saved.spec.name)"
        }
        return "vmID=\(vmID.rawValue)"
    }

    public func apply(to store: AgentVMProjectStore) async throws {
        if deletedRecordBox.get() == nil {
            guard let existing = try await store.fetchVM(vmID) else {
                throw AgentVMError.vmNotFound(vmID)
            }
            deletedRecordBox.set(existing)
        }
        try await store.deleteVM(vmID)
    }

    public func revert(on store: AgentVMProjectStore) async throws {
        guard let restored = deletedRecordBox.get() else {
            throw AgentVMError.vmNotFound(vmID)
        }
        try await store.upsertVM(restored)
    }
}

/// Creates or updates a `FirewallPolicySet` and reverts cleanly to the previous rule table (or deletes if newly created).
public struct UpdateFirewallPolicyCommand: SummarizableWorkspaceCommand {
    public let commandID: UUID
    public let title: String
    public let timestamp: Date
    public let policy: FirewallPolicySet

    private let priorBox: LockedPriorStateBox<PriorEntitySnapshot<FirewallPolicySet>>

    public init(
        commandID: UUID = UUID(),
        title: String? = nil,
        timestamp: Date = Date(),
        policy: FirewallPolicySet,
        previousPolicy: FirewallPolicySet? = nil
    ) {
        self.commandID = commandID
        self.title = title ?? "Update Firewall Policy '\(policy.name)' (\(policy.rules.count) rules)"
        self.timestamp = timestamp
        self.policy = policy
        if let previousPolicy {
            self.priorBox = LockedPriorStateBox(.existed(previousPolicy))
        } else {
            self.priorBox = LockedPriorStateBox(nil)
        }
    }

    public init(
        commandID: UUID = UUID(),
        title: String? = nil,
        timestamp: Date = Date(),
        newPolicy: FirewallPolicySet,
        previousPolicy: FirewallPolicySet?
    ) {
        self.init(
            commandID: commandID,
            title: title,
            timestamp: timestamp,
            policy: newPolicy,
            previousPolicy: previousPolicy
        )
    }

    public var payloadSummary: String {
        "policyID=\(policy.id.rawValue) name=\(policy.name) rules=\(policy.rules.count) egress=\(policy.defaultEgressVerdict.rawValue)"
    }

    public func apply(to store: AgentVMProjectStore) async throws {
        if priorBox.get() == nil {
            if let existing = try await store.fetchFirewallPolicy(policy.id) {
                priorBox.setIfEmpty(.existed(existing))
            } else {
                priorBox.setIfEmpty(.didNotExist)
            }
        }
        try await store.upsertFirewallPolicy(policy)
    }

    public func revert(on store: AgentVMProjectStore) async throws {
        switch priorBox.get() ?? .didNotExist {
        case let .existed(previous):
            try await store.upsertFirewallPolicy(previous)
        case .didNotExist:
            try await store.deleteFirewallPolicy(policy.id)
        }
    }
}

/// Registers a new `SnapshotNode` in the CoW lineage DAG and optionally advances the owning VM's head snapshot pointer.
public struct RegisterSnapshotCommand: SummarizableWorkspaceCommand {
    private struct CapturedContext: Sendable {
        let priorSnapshot: PriorEntitySnapshot<SnapshotNode>
        let priorVMHeadSnapshotID: SnapshotID?
        let hadVMRecord: Bool
    }

    public let commandID: UUID
    public let title: String
    public let timestamp: Date
    public let snapshot: SnapshotNode
    public let updateVMHead: Bool

    private let contextBox = LockedPriorStateBox<CapturedContext>()

    public init(
        commandID: UUID = UUID(),
        title: String? = nil,
        timestamp: Date = Date(),
        snapshot: SnapshotNode,
        updateVMHead: Bool = true
    ) {
        self.commandID = commandID
        self.title = title ?? "Register Snapshot '\(snapshot.title)' on branch '\(snapshot.branchName)'"
        self.timestamp = timestamp
        self.snapshot = snapshot
        self.updateVMHead = updateVMHead
    }

    public var payloadSummary: String {
        "snapshotID=\(snapshot.id.rawValue) vmID=\(snapshot.vmID.rawValue) branch=\(snapshot.branchName) kind=\(snapshot.kind.rawValue)"
    }

    public func apply(to store: AgentVMProjectStore) async throws {
        if contextBox.get() == nil {
            let existingSnap = try await store.fetchSnapshot(snapshot.id)
            let existingVM = try await store.fetchVM(snapshot.vmID)
            contextBox.setIfEmpty(CapturedContext(
                priorSnapshot: existingSnap.map { .existed($0) } ?? .didNotExist,
                priorVMHeadSnapshotID: existingVM?.currentHeadSnapshotID,
                hadVMRecord: existingVM != nil
            ))
        }

        try await store.upsertSnapshot(snapshot)
        if updateVMHead, var vm = try await store.fetchVM(snapshot.vmID) {
            vm.currentHeadSnapshotID = snapshot.id
            try await store.upsertVM(vm)
        }
    }

    public func revert(on store: AgentVMProjectStore) async throws {
        let context = contextBox.get()
        if updateVMHead, let context, context.hadVMRecord, var vm = try await store.fetchVM(snapshot.vmID) {
            vm.currentHeadSnapshotID = context.priorVMHeadSnapshotID
            try await store.upsertVM(vm)
        }

        switch context?.priorSnapshot ?? .didNotExist {
        case let .existed(previous):
            try await store.upsertSnapshot(previous)
        case .didNotExist:
            try await store.deleteSnapshot(snapshot.id)
        }
    }
}

/// Deletes a `SnapshotNode` from the lineage DAG while capturing direct child parent-links and VM head references for lossless undo.
public struct DeleteSnapshotCommand: SummarizableWorkspaceCommand {
    private struct DeletedSnapshotContext: Sendable {
        let target: SnapshotNode
        let directChildren: [SnapshotNode]
        let affectedVMHeadWasTarget: Bool
    }

    public let commandID: UUID
    public let title: String
    public let timestamp: Date
    public let snapshotID: SnapshotID

    private let explicitTarget: SnapshotNode?
    private let contextBox = LockedPriorStateBox<DeletedSnapshotContext>()

    public init(
        commandID: UUID = UUID(),
        title: String? = nil,
        timestamp: Date = Date(),
        snapshotID: SnapshotID,
        previousSnapshot: SnapshotNode? = nil
    ) {
        self.commandID = commandID
        self.title = title ?? "Delete Snapshot '\(previousSnapshot?.title ?? snapshotID.rawValue)'"
        self.timestamp = timestamp
        self.snapshotID = snapshotID
        self.explicitTarget = previousSnapshot
    }

    public init(
        commandID: UUID = UUID(),
        title: String? = nil,
        timestamp: Date = Date(),
        snapshot: SnapshotNode
    ) {
        self.init(
            commandID: commandID,
            title: title ?? "Delete Snapshot '\(snapshot.title)' (\(snapshot.id.rawValue))",
            timestamp: timestamp,
            snapshotID: snapshot.id,
            previousSnapshot: snapshot
        )
    }

    public var payloadSummary: String {
        if let ctx = contextBox.get() {
            return "snapshotID=\(snapshotID.rawValue) vmID=\(ctx.target.vmID.rawValue) children=\(ctx.directChildren.count)"
        }
        return "snapshotID=\(snapshotID.rawValue)"
    }

    public func apply(to store: AgentVMProjectStore) async throws {
        let resolvedTarget: SnapshotNode
        if let saved = contextBox.get() {
            resolvedTarget = saved.target
        } else {
            guard let target = try await store.fetchSnapshot(snapshotID) ?? explicitTarget else {
                throw AgentVMError.snapshotNotFound(snapshotID)
            }
            let allSnapshots = try await store.listSnapshots()
            let directChildren = allSnapshots.filter { $0.parentSnapshotID == snapshotID }
            let vm = try await store.fetchVM(target.vmID)
            let headMatched = (vm?.currentHeadSnapshotID == snapshotID)

            contextBox.set(DeletedSnapshotContext(
                target: target,
                directChildren: directChildren,
                affectedVMHeadWasTarget: headMatched
            ))
            resolvedTarget = target
        }

        if let ctx = contextBox.get(), ctx.affectedVMHeadWasTarget, var vm = try await store.fetchVM(resolvedTarget.vmID) {
            vm.currentHeadSnapshotID = resolvedTarget.parentSnapshotID
            try await store.upsertVM(vm)
        }

        try await store.deleteSnapshot(snapshotID)
    }

    public func revert(on store: AgentVMProjectStore) async throws {
        guard let ctx = contextBox.get() else {
            if let explicitTarget {
                try await store.upsertSnapshot(explicitTarget)
                return
            }
            throw AgentVMError.snapshotNotFound(snapshotID)
        }

        try await store.upsertSnapshot(ctx.target)
        for child in ctx.directChildren {
            if var currentChild = try await store.fetchSnapshot(child.id) {
                currentChild.parentSnapshotID = snapshotID
                try await store.upsertSnapshot(currentChild)
            }
        }
        if ctx.affectedVMHeadWasTarget, var vm = try await store.fetchVM(ctx.target.vmID) {
            vm.currentHeadSnapshotID = snapshotID
            try await store.upsertVM(vm)
        }
    }
}

/// Updates workspace-wide `WorkspacePreferences` (and optional title) inside `manifest.json` with atomic undo restoration.
public struct UpdateManifestPreferencesCommand: SummarizableWorkspaceCommand {
    public let commandID: UUID
    public let title: String
    public let timestamp: Date
    public let newPreferences: WorkspacePreferences
    public let updatedWorkspaceTitle: String?

    private let priorManifestBox: LockedPriorStateBox<AgentVMProjectManifest>

    public init(
        commandID: UUID = UUID(),
        title: String = "Update Workspace Preferences",
        timestamp: Date = Date(),
        preferences: WorkspacePreferences,
        updatedWorkspaceTitle: String? = nil,
        previousManifest: AgentVMProjectManifest? = nil
    ) {
        self.commandID = commandID
        self.title = title
        self.timestamp = timestamp
        self.newPreferences = preferences
        self.updatedWorkspaceTitle = updatedWorkspaceTitle
        self.priorManifestBox = LockedPriorStateBox(previousManifest)
    }

    public init(
        commandID: UUID = UUID(),
        title: String = "Update Workspace Preferences",
        timestamp: Date = Date(),
        newPreferences: WorkspacePreferences,
        previousPreferences: WorkspacePreferences? = nil
    ) {
        let seededManifest = previousPreferences.map { prefs in
            AgentVMProjectManifest(preferences: prefs)
        }
        self.commandID = commandID
        self.title = title
        self.timestamp = timestamp
        self.newPreferences = newPreferences
        self.updatedWorkspaceTitle = nil
        self.priorManifestBox = LockedPriorStateBox(seededManifest)
    }

    public var payloadSummary: String {
        "maxRunningVMs=\(newPreferences.maxConcurrentRunningVMs) defaultVCPUs=\(newPreferences.defaultVCPUs) defaultMemMB=\(newPreferences.defaultMemoryMB) subnet=\(newPreferences.switchSubnetCIDR)"
    }

    public func apply(to store: AgentVMProjectStore) async throws {
        var current = try await store.loadManifest()
        priorManifestBox.setIfEmpty(current)

        current.preferences = newPreferences
        if let updatedWorkspaceTitle, !updatedWorkspaceTitle.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            current.title = updatedWorkspaceTitle
        }
        current.updatedAt = timestamp
        try await store.saveManifest(current)
    }

    public func revert(on store: AgentVMProjectStore) async throws {
        guard let prior = priorManifestBox.get() else { return }
        var restored = prior
        if restored.workspaceID.rawValue.isEmpty, let live = try? await store.loadManifest() {
            restored.workspaceID = live.workspaceID
        }
        try await store.saveManifest(restored)
    }
}

/// Groups multiple `ReversibleWorkspaceCommand` steps into a single atomic undoable unit with compensating rollback on partial failure.
public struct CompositeWorkspaceCommand: SummarizableWorkspaceCommand {
    public let commandID: UUID
    public let title: String
    public let timestamp: Date
    public let commands: [any ReversibleWorkspaceCommand]

    public init(
        commandID: UUID = UUID(),
        title: String,
        timestamp: Date = Date(),
        commands: [any ReversibleWorkspaceCommand]
    ) {
        self.commandID = commandID
        self.title = title
        self.timestamp = timestamp
        self.commands = commands
    }

    public var payloadSummary: String {
        "steps=\(commands.count) [\(commands.map(\.title).joined(separator: " -> "))]"
    }

    public func apply(to store: AgentVMProjectStore) async throws {
        var appliedCount = 0
        do {
            for cmd in commands {
                try await cmd.apply(to: store)
                appliedCount += 1
            }
        } catch {
            // Compensating rollback for already-applied prefix commands in reverse order.
            if appliedCount > 0 {
                for idx in stride(from: appliedCount - 1, through: 0, by: -1) {
                    try? await commands[idx].revert(on: store)
                }
            }
            throw error
        }
    }

    public func revert(on store: AgentVMProjectStore) async throws {
        for cmd in commands.reversed() {
            try await cmd.revert(on: store)
        }
    }
}

// MARK: - Workspace Undo / Redo Controller Actor

public actor UndoRedoController {
    public let capacity: UndoHistoryCapacity

    private var undoStack: [any ReversibleWorkspaceCommand] = []
    private var redoStack: [any ReversibleWorkspaceCommand] = []

    public init(capacity: UndoHistoryCapacity = .bounded(200)) {
        self.capacity = capacity
    }

    public init(maxDepth: Int) {
        if maxDepth <= 0 {
            self.capacity = .unlimited
        } else {
            self.capacity = .bounded(maxDepth)
        }
    }

    public func canUndo() -> Bool {
        !undoStack.isEmpty
    }

    public func canRedo() -> Bool {
        !redoStack.isEmpty
    }

    public var undoCount: Int { undoStack.count }
    public var redoCount: Int { redoStack.count }

    public func execute(
        _ command: any ReversibleWorkspaceCommand,
        on store: AgentVMProjectStore
    ) async throws {
        try await command.apply(to: store)

        let hadRedoEntries = !redoStack.isEmpty
        redoStack.removeAll()

        undoStack.append(command)

        var evictedIDs: [UUID] = []
        if let maxEntries = capacity.maxEntries, undoStack.count > maxEntries {
            let overflow = undoStack.count - maxEntries
            let evictedSlice = undoStack.prefix(overflow)
            evictedIDs = evictedSlice.map(\.commandID)
            undoStack.removeFirst(overflow)
        }

        let now = Date()
        if hadRedoEntries {
            try await store.supersedeUndoneJournalEntries(updatedAt: now)
        }
        for evictedID in evictedIDs {
            try await store.updateUndoJournalState(commandID: evictedID, state: .evicted, updatedAt: now)
        }

        let record = UndoJournalRecord(
            commandID: command.commandID,
            commandType: command.commandTypeIdentifier,
            title: command.title,
            state: .applied,
            payloadSummary: Self.extractPayloadSummary(from: command),
            createdAt: command.timestamp,
            updatedAt: now
        )
        try await store.recordUndoJournalEntry(record)
    }

    @discardableResult
    public func undo(on store: AgentVMProjectStore) async throws -> UndoCommandSummary {
        guard let command = undoStack.last else {
            throw AgentVMError.undoStackEmpty
        }

        try await command.revert(on: store)
        _ = undoStack.popLast()
        redoStack.append(command)

        try await store.updateUndoJournalState(
            commandID: command.commandID,
            state: .undone,
            updatedAt: Date()
        )

        return Self.makeSummary(for: command, index: 0)
    }

    @discardableResult
    public func redo(on store: AgentVMProjectStore) async throws -> UndoCommandSummary {
        guard let command = redoStack.last else {
            throw AgentVMError.redoStackEmpty
        }

        try await command.apply(to: store)
        _ = redoStack.popLast()
        undoStack.append(command)

        var evictedIDs: [UUID] = []
        if let maxEntries = capacity.maxEntries, undoStack.count > maxEntries {
            let overflow = undoStack.count - maxEntries
            evictedIDs = undoStack.prefix(overflow).map(\.commandID)
            undoStack.removeFirst(overflow)
        }

        let now = Date()
        for evictedID in evictedIDs {
            try await store.updateUndoJournalState(commandID: evictedID, state: .evicted, updatedAt: now)
        }
        try await store.updateUndoJournalState(
            commandID: command.commandID,
            state: .applied,
            updatedAt: now
        )

        return Self.makeSummary(for: command, index: 0)
    }

    /// Returns undo stack summaries ordered from top-of-stack (next command to undo at index 0) down to oldest.
    public func undoStackSummaries() -> [UndoCommandSummary] {
        undoStack.reversed().enumerated().map { idx, cmd in
            Self.makeSummary(for: cmd, index: idx)
        }
    }

    /// Returns redo stack summaries ordered from top-of-stack (next command to redo at index 0) down to oldest.
    public func redoStackSummaries() -> [UndoCommandSummary] {
        redoStack.reversed().enumerated().map { idx, cmd in
            Self.makeSummary(for: cmd, index: idx)
        }
    }

    public func clear() {
        undoStack.removeAll()
        redoStack.removeAll()
    }

    public func clear(alsoPurgingJournalIn store: AgentVMProjectStore) async throws {
        undoStack.removeAll()
        redoStack.removeAll()
        try await store.clearUndoJournal()
    }

    public func persistedAuditLedger(
        from store: AgentVMProjectStore,
        limit: Int = 200
    ) async throws -> [UndoJournalRecord] {
        try await store.listUndoJournal(limit: limit)
    }

    private static func makeSummary(
        for command: any ReversibleWorkspaceCommand,
        index: Int
    ) -> UndoCommandSummary {
        UndoCommandSummary(
            commandID: command.commandID,
            commandType: command.commandTypeIdentifier,
            title: command.title,
            timestamp: command.timestamp,
            payloadSummary: extractPayloadSummary(from: command),
            stackDepthIndex: index
        )
    }

    private static func extractPayloadSummary(from command: any ReversibleWorkspaceCommand) -> String {
        if let summarizable = command as? any SummarizableWorkspaceCommand {
            return summarizable.payloadSummary
        }
        return command.title
    }
}
