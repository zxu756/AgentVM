import AgentVMModels
import AgentVMStore
import Darwin
import Foundation
import Testing

@Suite("M02 SQLite WAL Store, v1->v4 Migrations, Undo/Redo, Catalog & Snapshot DAG", .timeLimit(.minutes(1)))
struct StoreMigrationsAndUndoTests {

    // MARK: - Helpers

    private func makeTemporaryDirectory(prefix: String = "avm-store") throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func posixStat(_ url: URL) throws -> Darwin.stat {
        var st = Darwin.stat()
        let rc = stat(url.path, &st)
        try #require(rc == 0, "stat failed for \(url.path) (errno=\(errno))")
        return st
    }

    private func makeCleanVMRecord(
        id: VMID = VMID("vm-alpha"),
        name: String = "alpha-blade",
        vcpus: Int = 2,
        memoryMB: UInt64 = 2048,
        diskPath: String? = nil,
        headSnapshotID: SnapshotID? = nil
    ) -> VMInstanceRecord {
        let blocks: [BlockDeviceSpec]
        if let diskPath {
            blocks = [
                BlockDeviceSpec(
                    label: "root",
                    imagePath: diskPath,
                    virtualSizeBytes: 16 * 1024 * 1024,
                    isBootVolume: true
                )
            ]
        } else {
            blocks = []
        }

        let spec = VMSpec(
            id: id,
            name: name,
            agentOwnerTag: "test-suite",
            compute: CPUAndMemorySpec(vcpuCount: vcpus, memoryMB: memoryMB, minBalloonMemoryMB: 512),
            blockDevices: blocks,
            networkInterfaces: [
                NetworkInterfaceSpec(macAddress: "52:54:00:aa:bb:01", ipv4Address: "10.211.55.10")
            ]
        )
        return VMInstanceRecord(
            spec: spec,
            currentHeadSnapshotID: headSnapshotID,
            telemetry: VMLiveTelemetry(vmID: id, state: .stopped)
        )
    }

    // MARK: - 1. SQLiteWALDatabase WAL Mode, Foreign Keys, Stepwise v1->v4 Migrations & Savepoints

    @Test("SQLiteWALDatabase enables WAL journal mode, foreign keys, and v1->v4 migrations on file-backed DB")
    func sqliteFileBackedWALAndMigrations() throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-sqlite-wal")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let dbURL = tempDir.appendingPathComponent("state.sqlite")
        let db = try SQLiteWALDatabase(fileURL: dbURL, runMigrations: false)
        #expect(try db.currentSchemaVersion() == 0)

        let diagBefore = try db.diagnostics()
        #expect(diagBefore.journalMode.lowercased() == "wal")
        #expect(diagBefore.foreignKeysEnabled == true)

        for target in 1...SQLiteWALDatabase.latestSchemaVersion {
            try db.migrateToLatest(targetVersion: target)
            #expect(try db.currentSchemaVersion() == target)
        }

        let migrations = try db.appliedMigrations()
        #expect(migrations.map(\.version) == [1, 2, 3, 4])
        #expect(migrations.allSatisfy { !$0.checksum.isEmpty })

        #expect(try db.integrityCheck().isEmpty)
        #expect(try db.foreignKeyViolations().isEmpty)

        let ckpt = try db.walCheckpoint(mode: .passive)
        #expect(ckpt.mode == .passive)
        #expect(ckpt.isFullyCheckpointed == true)
    }

    @Test("SQLiteWALDatabase detects tampered migration checksums in schema_migrations")
    func sqliteTamperedMigrationChecksumThrows() throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-sqlite-tamper")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let dbURL = tempDir.appendingPathComponent("tampered.sqlite")
        do {
            let db = try SQLiteWALDatabase(fileURL: dbURL, runMigrations: true)
            _ = try db.execute(
                "UPDATE schema_migrations SET checksum = ? WHERE version = 2;",
                bindables: ["deadbeef0000"]
            )
        }

        #expect(throws: AgentVMError.self) {
            _ = try SQLiteWALDatabase(fileURL: dbURL, runMigrations: true)
        }
    }

    @Test("SQLiteWALDatabase supports atomic transactions and nested savepoint partial rollbacks")
    func sqliteTransactionsAndNestedSavepoints() throws {
        let db = try SQLiteWALDatabase(inMemoryNamed: "sp-\(UUID().uuidString)", runMigrations: true)
        _ = try db.execute("CREATE TABLE kv_probe (k TEXT PRIMARY KEY, v INTEGER NOT NULL);")

        enum IntentionalAbort: Error { case abortInner }

        // Full transaction rollback on error
        #expect(throws: IntentionalAbort.self) {
            try db.inTransaction {
                _ = try db.execute("INSERT INTO kv_probe (k, v) VALUES ('rolled-back', 1);")
                throw IntentionalAbort.abortInner
            }
        }
        let countAfterAbort = try db.queryScalarInt64("SELECT COUNT(*) FROM kv_probe;") ?? -1
        #expect(countAfterAbort == 0)

        // Outer transaction commits while inner savepoint rolls back cleanly
        try db.inTransaction {
            _ = try db.execute("INSERT INTO kv_probe (k, v) VALUES ('outer-kept', 100);")

            do {
                try db.withSavepoint(name: "inner_attempt") {
                    _ = try db.execute("INSERT INTO kv_probe (k, v) VALUES ('inner-discarded', 200);")
                    try db.withSavepoint(name: "deepest_ok") {
                        _ = try db.execute("INSERT INTO kv_probe (k, v) VALUES ('deepest-discarded', 300);")
                    }
                    throw IntentionalAbort.abortInner
                }
            } catch IntentionalAbort.abortInner {
                // Expected partial rollback of inner_attempt
            }

            _ = try db.execute("INSERT INTO kv_probe (k, v) VALUES ('outer-after', 400);")
        }

        let keys = try db.query("SELECT k FROM kv_probe ORDER BY v ASC;").map { try $0.string("k") }
        #expect(keys == ["outer-kept", "outer-after"])
    }

    @Test("SQLiteWALDatabase enforces foreign key constraints across vms and snapshots")
    func sqliteForeignKeyConstraintEnforcement() throws {
        let db = try SQLiteWALDatabase(inMemoryNamed: "fk-\(UUID().uuidString)", runMigrations: true)

        // Inserting a snapshot referencing a nonexistent vm_id violates FOREIGN KEY
        #expect(throws: AgentVMError.self) {
            _ = try db.execute(
                """
                INSERT INTO snapshots (
                    id, vm_id, parent_snapshot_id, branch_name, title, notes, kind,
                    disk_clone_path, virtual_disk_bytes, allocated_disk_bytes, dirty_delta_bytes,
                    memory_state_bytes, spec_json, created_at, agent_actor, is_pinned, tags_json
                ) VALUES (?, ?, NULL, 'main', 'Orphan', '', 'baseGoldenImage', '/tmp/x', 0, 0, 0, 0, '{}', 0, 'test', 0, '[]');
                """,
                bindables: ["snap-orphan", "vm-does-not-exist"]
            )
        }
    }

    @Test("SQLiteWALDatabase(inMemoryNamed:) uses SQLite URI memory mode and creates zero files in working directory")
    func sqliteNamedInMemoryDatabaseCreatesZeroFilesOnDisk() throws {
        let uniqueName = "inmem-cwd-guard-\(UUID().uuidString)"
        let cwdURL = URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
        let leakedCandidate = cwdURL.appendingPathComponent(uniqueName)
        defer {
            try? FileManager.default.removeItem(at: leakedCandidate)
            try? FileManager.default.removeItem(at: URL(fileURLWithPath: leakedCandidate.path + "-wal"))
            try? FileManager.default.removeItem(at: URL(fileURLWithPath: leakedCandidate.path + "-shm"))
        }

        let db = try SQLiteWALDatabase(inMemoryNamed: uniqueName, runMigrations: true)
        _ = try db.execute("CREATE TABLE t (id INTEGER PRIMARY KEY); INSERT INTO t (id) VALUES (1);")
        #expect(FileManager.default.fileExists(atPath: leakedCandidate.path) == false)
        #expect(FileManager.default.fileExists(atPath: leakedCandidate.path + "-wal") == false)
        #expect(FileManager.default.fileExists(atPath: leakedCandidate.path + "-shm") == false)
        db.close()
    }

    // MARK: - 2. AgentVMProjectStore Full CRUD Round-Trips & Integrity/Stats

    @Test("AgentVMProjectStore initializes workspace bundle and persists manifest, VMs, and snapshots")
    func projectStoreManifestVMAndSnapshotCRUD() async throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-bundle-crud")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let bundleURL = tempDir.appendingPathComponent("TestFleet.agentvm", isDirectory: true)
        let store = try AgentVMProjectStore(bundleURL: bundleURL, createIfMissing: true)

        var manifest = try await store.loadManifest()
        manifest.title = "Production Fleet Sandbox"
        manifest.preferences.defaultVCPUs = 6
        try await store.saveManifest(manifest)
        let reloadedManifest = try await store.loadManifest()
        #expect(reloadedManifest.title == "Production Fleet Sandbox")
        #expect(reloadedManifest.preferences.defaultVCPUs == 6)

        let diskURL = store.disksDirectoryURL.appendingPathComponent("vm-alpha.raw")
        try Data(repeating: 0x11, count: 4096).write(to: diskURL)
        let snapDiskURL = store.snapshotsDirectoryURL.appendingPathComponent("snap-1.raw")
        try Data(repeating: 0x22, count: 4096).write(to: snapDiskURL)

        var vm = makeCleanVMRecord(id: VMID("vm-alpha"), name: "alpha-blade", diskPath: diskURL.path)
        try await store.upsertVM(vm)
        #expect(try await store.fetchVM(VMID("vm-alpha"))?.spec.name == "alpha-blade")

        let snap = SnapshotNode(
            id: SnapshotID("snap-1"),
            vmID: vm.id,
            parentSnapshotID: nil,
            branchName: "main",
            title: "Golden Root",
            kind: .baseGoldenImage,
            diskClonePath: snapDiskURL.path,
            virtualDiskBytes: 16 * 1024 * 1024,
            allocatedDiskBytes: 4096,
            dirtyDeltaBytes: 0,
            specSnapshot: vm.spec,
            isPinned: true,
            tags: ["golden"]
        )
        try await store.upsertSnapshot(snap)
        vm.currentHeadSnapshotID = snap.id
        try await store.upsertVM(vm)

        let listedSnaps = try await store.listSnapshots(forVM: vm.id)
        #expect(listedSnaps.count == 1)
        #expect(listedSnaps.first?.title == "Golden Root")

        // Clean bundle should have zero integrity issues
        let cleanIssues = try await store.verifyBundleIntegrity()
        #expect(cleanIssues.isEmpty)

        let stats = try await store.storageStatistics()
        #expect(stats.sqliteBytes > 0)
        #expect(stats.registeredVMCount == 1)
        #expect(stats.registeredSnapshotRecordCount == 1)
        #expect(stats.diskImageCount == 1)
        #expect(stats.snapshotCount == 1)

        // Deleting VM removes the VM record while preserving CoW snapshot lineage until explicitly deleted
        try await store.deleteVM(vm.id)
        #expect(try await store.fetchVM(vm.id) == nil)
        #expect(try await store.listSnapshots(forVM: vm.id).count == 1)
        try await store.deleteSnapshot(snap.id)
        #expect(try await store.listSnapshots(forVM: vm.id).isEmpty)
    }

    @Test("AgentVMProjectStore round-trips firewall policies, network flows, diagnostics, and exec history")
    func projectStoreFirewallFlowsDiagnosticsAndExecCRUD() async throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-telemetry")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let store = try AgentVMProjectStore(
            bundleURL: tempDir.appendingPathComponent("Telemetry.agentvm", isDirectory: true),
            createIfMissing: true
        )

        try await store.seedDefaultFirewallPresetsIfNeeded()
        let seededPolicies = try await store.listFirewallPolicies()
        #expect(seededPolicies.count == 2)

        // Idempotent second call does not duplicate presets
        try await store.seedDefaultFirewallPresetsIfNeeded()
        #expect(try await store.listFirewallPolicies().count == 2)

        let vm = makeCleanVMRecord(id: VMID("vm-net"), name: "net-blade")
        try await store.upsertVM(vm)

        let flow = NetworkFlowRecord(
            tuple: NetworkFlow5Tuple(
                vmID: vm.id,
                transport: .tcp,
                sourceIP: "10.211.55.10",
                sourcePort: 52100,
                destinationIP: "160.79.104.25",
                destinationPort: 443
            ),
            resolvedDomainOrSNI: "api.anthropic.com",
            tcpState: .established,
            packetsSent: 18,
            bytesSent: 8192,
            verdict: .allow
        )
        try await store.appendNetworkFlow(flow)
        let flows = try await store.listNetworkFlows(vmID: vm.id)
        #expect(flows.count == 1)
        #expect(flows.first?.resolvedDomainOrSNI == "api.anthropic.com")

        try await store.appendDiagnostic(DiagnosticEvent(
            severity: .info,
            subsystem: "Boot",
            vmID: vm.id,
            code: "BOOT_INFO",
            message: "Routine boot info"
        ))
        try await store.appendDiagnostic(DiagnosticEvent(
            severity: .error,
            subsystem: "Firewall",
            vmID: vm.id,
            code: "SSRF_DROP",
            message: "Blocked metadata probe"
        ))

        let errorEvents = try await store.listDiagnostics(vmID: vm.id, minSeverity: .warning)
        #expect(errorEvents.count == 1)
        #expect(errorEvents.first?.code == "SSRF_DROP")

        let execRes = GuestExecResult(
            requestID: UUID(),
            vmID: vm.id,
            commandLine: "uname -r",
            exitCode: 0,
            stdoutData: Data("6.8.0-agentvm\n".utf8),
            stderrData: Data(),
            durationMilliseconds: 9
        )
        try await store.appendExecResult(execRes)
        let execHistory = try await store.listExecResults(vmID: vm.id)
        #expect(execHistory.count == 1)
        #expect(execHistory.first?.stdoutUTF8 == "6.8.0-agentvm\n")

        // Prune telemetry keeping 0 rows
        let pruned = try await store.pruneTelemetryAndHistory(
            policy: TelemetryRetentionPolicy(
                maxFlowsPerVM: 0,
                maxDiagnosticsTotal: 1,
                maxExecResultsPerVM: 0,
                maxPortForwardAuditsTotal: 0
            )
        )
        #expect(pruned.deletedFlows == 1)
        #expect(pruned.deletedDiagnostics == 1)
        #expect(pruned.deletedExecResults == 1)
    }

    @Test("AgentVMProjectStore round-trips WorkbenchLayoutSnapshot, Plugin KV store, and PluginRuntimeStatus")
    func projectStoreLayoutsAndPluginStateCRUD() async throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-layouts")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let store = try AgentVMProjectStore(
            bundleURL: tempDir.appendingPathComponent("Layouts.agentvm", isDirectory: true),
            createIfMissing: true
        )

        let tabA = WorkbenchTabDescriptor(kind: .snapshotBranchDAG, isPinned: true)
        let tabB = WorkbenchTabDescriptor(kind: .packetWiretap, isPinned: false)
        let layout = WorkbenchLayoutSnapshot(
            workspaceID: WorkspaceID("ws-01"),
            showLeftFleetNavigator: false,
            showRightInspector: true,
            showBottomDrawer: true,
            activeBottomChannel: .pluginLogs,
            splitMode: .verticalTwoColumn,
            primaryTabs: [tabA],
            activePrimaryTabID: tabA.id,
            secondaryTabs: [tabB],
            activeSecondaryTabID: tabB.id,
            selectedVMID: VMID("vm-alpha")
        )
        try await store.saveLayout(layout)
        let loaded = try #require(try await store.loadLayout())
        #expect(loaded.splitMode == .verticalTwoColumn)
        #expect(loaded.activeBottomChannel == .pluginLogs)
        #expect(loaded.selectedVMID == VMID("vm-alpha"))

        try await store.saveNamedLayout(layout, slotKey: "debug-wiretap")
        #expect(try await store.loadNamedLayout(slotKey: "debug-wiretap")?.primaryTabs.first?.id == tabA.id)

        let pluginID = PluginID("custom.audit-plugin")
        try await store.setPluginKV(pluginID: pluginID, key: "hits", value: "42")
        try await store.setPluginKV(pluginID: pluginID, key: "last_domain", value: "api.anthropic.com")
        #expect(try await store.getPluginKV(pluginID: pluginID, key: "hits") == "42")
        #expect(try await store.listPluginKV(pluginID: pluginID).count == 2)

        try await store.deletePluginKV(pluginID: pluginID, key: "hits")
        #expect(try await store.getPluginKV(pluginID: pluginID, key: "hits") == nil)
        try await store.clearPluginKV(pluginID: pluginID)
        #expect(try await store.listPluginKV(pluginID: pluginID).isEmpty)

        let manifest = PluginManifest(
            id: pluginID,
            name: "Audit Plugin",
            author: "UnitTest",
            summary: "Verifies PluginRuntimeStatus persistence in SQLite store",
            requestedCapabilities: [.networkInspect],
            entryPointSource: "function onPacket(pkt) { return { action: 'allow' }; }"
        )
        let status = PluginRuntimeStatus(
            manifest: manifest,
            isEnabled: true,
            grantedCapabilities: [.networkInspect],
            invocationCount: 7,
            blockedActionsCount: 2
        )
        try await store.upsertPluginRuntimeStatus(status)
        let fetchedStatus = try #require(try await store.fetchPluginRuntimeStatus(pluginID))
        #expect(fetchedStatus.invocationCount == 7)
        #expect(fetchedStatus.blockedActionsCount == 2)
    }

    @Test("AgentVMProjectStore.verifyBundleIntegrity detects missing disk images and dangling head snapshots")
    func projectStoreDetectsIntegrityViolations() async throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-integrity")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let store = try AgentVMProjectStore(
            bundleURL: tempDir.appendingPathComponent("Broken.agentvm", isDirectory: true),
            createIfMissing: true
        )

        let missingDiskPath = store.disksDirectoryURL.appendingPathComponent("missing-root.raw").path
        let vm = makeCleanVMRecord(
            id: VMID("vm-broken"),
            name: "broken-vm",
            diskPath: missingDiskPath,
            headSnapshotID: SnapshotID("snap-ghost")
        )
        try await store.upsertVM(vm)

        let issues = try await store.verifyBundleIntegrity()
        let codes = Set(issues.map(\.code))
        #expect(!issues.isEmpty)
        #expect(codes.contains { $0.contains("MISSING") || $0.contains("BLOCK") || $0.contains("DISK") })
        #expect(codes.contains { $0.contains("HEAD") || $0.contains("SNAPSHOT") || $0.contains("DANGLING") })
    }

    // MARK: - 3. UndoRedoController Multi-Step Execute / Undo / Redo & SQLite Journal

    @Test("UndoRedoController executes, undoes, and redoes VM, Firewall, Snapshot, and Composite commands")
    func undoRedoMultiStepLifecycleAndAuditJournal() async throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-undo")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let store = try AgentVMProjectStore(
            bundleURL: tempDir.appendingPathComponent("UndoSuite.agentvm", isDirectory: true),
            createIfMissing: true
        )
        let undoRedo = UndoRedoController(capacity: .bounded(16))

        #expect(await undoRedo.canUndo() == false)
        #expect(await undoRedo.canRedo() == false)

        // Step 1: Create VM + Root Snapshot via CompositeWorkspaceCommand
        let vmV1 = makeCleanVMRecord(id: VMID("vm-1"), name: "blade-v1", vcpus: 2)
        let snap1 = SnapshotNode(
            id: SnapshotID("snap-1"),
            vmID: vmV1.id,
            parentSnapshotID: nil,
            branchName: "main",
            title: "Base Image",
            kind: .baseGoldenImage,
            diskClonePath: "/tmp/s1.raw",
            virtualDiskBytes: 1024,
            allocatedDiskBytes: 512,
            dirtyDeltaBytes: 0,
            specSnapshot: vmV1.spec
        )
        let step1 = CompositeWorkspaceCommand(
            title: "Create Blade + Root Snapshot",
            commands: [
                UpsertVMCommand(record: vmV1),
                RegisterSnapshotCommand(snapshot: snap1, updateVMHead: true)
            ]
        )
        try await undoRedo.execute(step1, on: store)
        #expect(try await store.fetchVM(vmV1.id)?.currentHeadSnapshotID == snap1.id)

        // Step 2: Update VM compute vCPUs to 8
        let vmV2 = makeCleanVMRecord(id: VMID("vm-1"), name: "blade-v2", vcpus: 8, headSnapshotID: snap1.id)
        try await undoRedo.execute(UpsertVMCommand(record: vmV2), on: store)
        #expect(try await store.fetchVM(vmV1.id)?.spec.compute.vcpuCount == 8)

        // Step 3: Apply Firewall Policy
        let customPolicy = FirewallPolicySet(
            id: PolicySetID("pol-test"),
            name: "Custom Egress Policy",
            summary: "Unit test custom HTTPS policy",
            defaultEgressVerdict: .drop,
            rules: [
                FirewallRule(
                    priority: 10,
                    name: "Allow HTTPS",
                    conditions: [.destinationPortRange(lower: 443, upper: 443)],
                    verdict: .allow
                )
            ]
        )
        try await undoRedo.execute(UpdateFirewallPolicyCommand(policy: customPolicy), on: store)
        #expect(try await store.fetchFirewallPolicy(PolicySetID("pol-test"))?.rules.count == 1)

        // Step 4: Delete VM
        try await undoRedo.execute(DeleteVMCommand(vmID: vmV1.id), on: store)
        #expect(try await store.fetchVM(vmV1.id) == nil)
        #expect(await undoRedo.undoCount == 4)

        // Undo Step 4 -> VM restored with 8 vCPUs
        let undone4 = try await undoRedo.undo(on: store)
        #expect(undone4.commandType == "DeleteVMCommand")
        #expect(try await store.fetchVM(vmV1.id)?.spec.compute.vcpuCount == 8)

        // Undo Step 3 -> Custom policy removed
        _ = try await undoRedo.undo(on: store)
        #expect(try await store.fetchFirewallPolicy(PolicySetID("pol-test")) == nil)

        // Undo Step 2 -> VM reverts to 2 vCPUs and name "blade-v1"
        _ = try await undoRedo.undo(on: store)
        #expect(try await store.fetchVM(vmV1.id)?.spec.compute.vcpuCount == 2)
        #expect(try await store.fetchVM(vmV1.id)?.spec.name == "blade-v1")

        // Redo Step 2 & Step 3
        _ = try await undoRedo.redo(on: store)
        _ = try await undoRedo.redo(on: store)
        #expect(try await store.fetchVM(vmV1.id)?.spec.compute.vcpuCount == 8)
        #expect(try await store.fetchFirewallPolicy(PolicySetID("pol-test")) != nil)
        #expect(await undoRedo.redoCount == 1) // Step 4 remains in redo stack

        // Executing a fresh command branches history and marks undone Step 4 as `.superseded` in SQLite journal
        var prefs = WorkspacePreferences()
        prefs.maxConcurrentRunningVMs = 12
        try await undoRedo.execute(UpdateManifestPreferencesCommand(preferences: prefs), on: store)
        #expect(await undoRedo.canRedo() == false)

        let supersededEntries = try await store.listUndoJournal(state: .superseded)
        #expect(supersededEntries.count == 1)
        #expect(supersededEntries.first?.commandType == "DeleteVMCommand")

        let appliedEntries = try await store.listUndoJournal(state: .applied)
        #expect(appliedEntries.count == 4)
    }

    @Test("UndoRedoController performs compensating rollback on failing CompositeWorkspaceCommand and enforces capacity eviction")
    func undoRedoCompositeRollbackAndBoundedEviction() async throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-undo-comp")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let store = try AgentVMProjectStore(
            bundleURL: tempDir.appendingPathComponent("Compensate.agentvm", isDirectory: true),
            createIfMissing: true
        )
        let controller = UndoRedoController(maxDepth: 2)

        // Empty undo/redo stacks throw typed errors
        await #expect(throws: AgentVMError.self) {
            _ = try await controller.undo(on: store)
        }
        await #expect(throws: AgentVMError.self) {
            _ = try await controller.redo(on: store)
        }

        // Composite command whose second child fails must roll back the first child
        let transientVM = makeCleanVMRecord(id: VMID("vm-transient"), name: "transient")
        let failingComposite = CompositeWorkspaceCommand(
            title: "Atomic Failing Provision",
            commands: [
                UpsertVMCommand(record: transientVM),
                DeleteSnapshotCommand(snapshotID: SnapshotID("snap-nonexistent"))
            ]
        )

        await #expect(throws: AgentVMError.self) {
            try await controller.execute(failingComposite, on: store)
        }
        #expect(try await store.fetchVM(transientVM.id) == nil)
        #expect(await controller.undoCount == 0)

        // Execute 3 commands on maxDepth=2 controller -> oldest transitions to `.evicted`
        for idx in 1...3 {
            let rec = makeCleanVMRecord(id: VMID("vm-cap-\(idx)"), name: "cap-\(idx)")
            try await controller.execute(UpsertVMCommand(record: rec), on: store)
        }
        #expect(await controller.undoCount == 2)
        let evicted = try await store.listUndoJournal(state: .evicted)
        #expect(evicted.count == 1)
    }

    // MARK: - 4. BaseImageRegistryCatalog SHA-256 Verification & LRU Eviction Planning

    @Test("BaseImageRegistryCatalog verifies SHA-256 digests and detects tampered cached images")
    func baseImageCatalogChecksumVerification() async throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-catalog")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let cacheDir = tempDir.appendingPathComponent("ImageCache", isDirectory: true)
        let catalog = try BaseImageRegistryCatalog(cacheDirectoryURL: cacheDir)

        let curated = BaseImageRegistryCatalog.builtInCuratedEntries()
        #expect(curated.count >= 6)

        let offlineFile = tempDir.appendingPathComponent("alpine-agent-golden.img")
        let imageBytes = Data((0..<32_768).map { UInt8(($0 * 13 + 5) & 0xFF) })
        try imageBytes.write(to: offlineFile)
        let expectedSHA = BinaryChecksums.sha512Hex(imageBytes)

        let registered = try await catalog.registerOfflineImage(
            fileURL: offlineFile,
            id: "custom-alpine",
            displayName: "Custom Alpine ARM64",
            copyIntoCacheDirectory: true
        )
        #expect(registered.expectedSHA512 == expectedSHA)

        let validReport = try await catalog.verifyCachedImage(id: "custom-alpine", enforceExpectedDigest: true)
        #expect(validReport.isValid == true)
        #expect(validReport.actualSHA512 == expectedSHA)

        // Tamper with the cached file inside cacheDir and verify mismatch detection
        let cachedURL = URL(fileURLWithPath: try #require(registered.cachedLocalPath))
        var corrupted = try Data(contentsOf: cachedURL)
        corrupted[0] ^= 0xFF
        try corrupted.write(to: cachedURL)

        let corruptedReport = try await catalog.verifyCachedImage(id: "custom-alpine", enforceExpectedDigest: true)
        #expect(corruptedReport.isValid == false)
        #expect(corruptedReport.failureReason != nil)

        // Staging a curated image with wrong digest throws when verifyChecksum == true
        let curatedID = try #require(curated.first?.id)
        await #expect(throws: AgentVMError.self) {
            _ = try await catalog.stageCachedCuratedImage(
                id: curatedID,
                from: offlineFile,
                verifyChecksum: true
            )
        }
    }

    @Test("BaseImageRegistryCatalog plans and executes LRU cache eviction while protecting pinned and custom images")
    func baseImageCatalogLRUEvictionPlanning() async throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-lru")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let cacheDir = tempDir.appendingPathComponent("CachePool", isDirectory: true)
        let catalog = try BaseImageRegistryCatalog(cacheDirectoryURL: cacheDir)
        let curated = BaseImageRegistryCatalog.builtInCuratedEntries()
        #expect(curated.count >= 3)

        let baseTime = Date(timeIntervalSince1970: 1_730_000_000)

        // Stage 3 curated images (bypassing upstream release SHA check) with distinct access timestamps
        for (idx, entry) in curated.prefix(3).enumerated() {
            let src = tempDir.appendingPathComponent("staged-\(idx).img")
            try Data(repeating: UInt8(0x30 + idx), count: 65_536).write(to: src)
            _ = try await catalog.stageCachedCuratedImage(id: entry.id, from: src, verifyChecksum: false)
            try await catalog.markImageAccessed(
                id: entry.id,
                at: baseTime.addingTimeInterval(Double(idx) * 3600.0)
            )
        }

        // Also register 1 custom offline image (protected when preserveCustomOfflineImages == true)
        let customSrc = tempDir.appendingPathComponent("team-offline.raw")
        try Data(repeating: 0xEE, count: 65_536).write(to: customSrc)
        _ = try await catalog.registerOfflineImage(
            fileURL: customSrc,
            id: "team-offline",
            displayName: "Team Offline Image",
            copyIntoCacheDirectory: true
        )
        try await catalog.markImageAccessed(id: "team-offline", at: baseTime.addingTimeInterval(-7200))

        let id0 = curated[0].id // oldest curated, pinned -> protected!
        let id1 = curated[1].id // second oldest curated -> should be evicted first!
        let id2 = curated[2].id // newest curated -> fits within footprint budget!

        // Budget allows ~2 images (custom + pinned + newest = 3 * 64KB, set footprint to ~200 KB so 1 of the 4 must be evicted)
        let allRecords = await catalog.cachedIndexRecords()
        let singleImagePhys = allRecords.first?.physicalBytes ?? 65_536
        let policy = ImageCacheEvictionPolicy(
            maxCacheFootprintBytes: singleImagePhys * 3,
            maxIdleAgeHours: nil,
            preserveCustomOfflineImages: true,
            pinnedImageIDs: [id0]
        )

        let plan = await catalog.planCacheEviction(
            policy: policy,
            referenceDate: baseTime.addingTimeInterval(10_000)
        )
        #expect(plan.candidateImageIDs == [id1])
        #expect(plan.protectedImageIDs.contains(id0))
        #expect(plan.protectedImageIDs.contains("team-offline"))
        #expect(plan.protectedImageIDs.contains(id2))

        let reclaimed = try await catalog.executeCacheEviction(plan)
        #expect(reclaimed > 0)
        let remainingIDs = Set(await catalog.cachedIndexRecords().map(\.id))
        #expect(!remainingIDs.contains(id1))
        #expect(remainingIDs.contains(id0))
        #expect(remainingIDs.contains(id2))
        #expect(remainingIDs.contains("team-offline"))
    }

    // MARK: - 5. SnapshotLineageQueryEngine Cycle Detection, Kahn Toposort, LCA, Diff & GC Reparenting

    private func makeSnapNode(
        id: String,
        parent: String?,
        vmID: String = "vm-dag",
        branch: String = "main",
        kind: SnapshotKind = .liveMemoryAndDisk,
        isPinned: Bool = false,
        dirtyBytes: UInt64 = 65_536,
        vcpus: Int = 2,
        createdOffsetSeconds: TimeInterval = 0
    ) -> SnapshotNode {
        let spec = VMSpec(
            id: VMID(vmID),
            name: "dag-\(vmID)",
            compute: CPUAndMemorySpec(vcpuCount: vcpus, memoryMB: 2048, minBalloonMemoryMB: 512)
        )
        return SnapshotNode(
            id: SnapshotID(id),
            vmID: VMID(vmID),
            parentSnapshotID: parent.map { SnapshotID($0) },
            branchName: branch,
            title: "Node \(id)",
            kind: kind,
            createdAt: Date(timeIntervalSince1970: 1_730_000_000 + createdOffsetSeconds),
            diskClonePath: "/tmp/\(id).raw",
            virtualDiskBytes: 16 * 1024 * 1024,
            allocatedDiskBytes: 262_144,
            dirtyDeltaBytes: dirtyBytes,
            specSnapshot: spec,
            isPinned: isPinned
        )
    }

    @Test("SnapshotLineageQueryEngine rejects self-loops and multi-node cycles with ERR_SNAPSHOT_CYCLE")
    func snapshotDAGCycleDetection() {
        let selfLoop = [
            makeSnapNode(id: "s-self", parent: "s-self")
        ]
        #expect(throws: AgentVMError.self) {
            _ = try SnapshotLineageQueryEngine(nodes: selfLoop)
        }

        let threeCycle = [
            makeSnapNode(id: "s-root", parent: nil),
            makeSnapNode(id: "s-a", parent: "s-c"),
            makeSnapNode(id: "s-b", parent: "s-a"),
            makeSnapNode(id: "s-c", parent: "s-b")
        ]
        do {
            _ = try SnapshotLineageQueryEngine(nodes: threeCycle)
            Issue.record("Expected SnapshotLineageQueryEngine to reject 3-node cycle")
        } catch let error as AgentVMError {
            #expect(error.errorCode == "ERR_SNAPSHOT_CYCLE")
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    @Test("SnapshotLineageQueryEngine computes deterministic Kahn toposort, ancestor paths, descendants, and LCA")
    func snapshotDAGToposortLCAAndTraversal() throws {
        // DAG:
        // s0 (main) -> s1 (main, forkPoint) -> s2 (main)
        //                                   \-> b1 (feat-auth) -> b2 (feat-auth)
        let s0 = makeSnapNode(id: "s0", parent: nil, branch: "main", kind: .baseGoldenImage, createdOffsetSeconds: 0)
        let s1 = makeSnapNode(id: "s1", parent: "s0", branch: "main", kind: .branchForkPoint, createdOffsetSeconds: 10)
        let s2 = makeSnapNode(id: "s2", parent: "s1", branch: "main", createdOffsetSeconds: 20)
        let b1 = makeSnapNode(id: "b1", parent: "s1", branch: "feat-auth", createdOffsetSeconds: 15)
        let b2 = makeSnapNode(id: "b2", parent: "b1", branch: "feat-auth", vcpus: 4, createdOffsetSeconds: 30)

        // Supply in intentionally scrambled order
        let engine = try SnapshotLineageQueryEngine(nodes: [b2, s2, b1, s0, s1])
        let topoIDs = engine.topologicalOrder.map(\.id.rawValue)

        // Every parent must precede its children in topological order
        let pos = Dictionary(uniqueKeysWithValues: topoIDs.enumerated().map { ($0.element, $0.offset) })
        #expect(try #require(pos["s0"]) < (try #require(pos["s1"])))
        #expect(try #require(pos["s1"]) < (try #require(pos["s2"])))
        #expect(try #require(pos["s1"]) < (try #require(pos["b1"])))
        #expect(try #require(pos["b1"]) < (try #require(pos["b2"])))

        let ancestorsOfB2 = try engine.ancestorPath(to: SnapshotID("b2")).map(\.id.rawValue)
        #expect(ancestorsOfB2 == ["s0", "s1", "b1", "b2"])

        let descOfS1 = try engine.descendants(of: SnapshotID("s1"), includeSelf: false).map(\.id.rawValue)
        #expect(Set(descOfS1) == Set(["s2", "b1", "b2"]))

        let lca = try engine.lowestCommonAncestor(of: SnapshotID("s2"), and: SnapshotID("b2"))
        #expect(lca.lowestCommonAncestorID == SnapshotID("s1"))
        #expect(lca.distanceFromLeft == 1)
        #expect(lca.distanceFromRight == 2)
        #expect(lca.leftDivergentChain.map(\.id.rawValue) == ["s2"])
        #expect(lca.rightDivergentChain.map(\.id.rawValue) == ["b1", "b2"])

        let leaves = Set(engine.leafSnapshots().map(\.id.rawValue))
        #expect(leaves == Set(["s2", "b2"]))

        let branchTips = engine.discoverBranchTips()
        #expect(branchTips.count == 2)
    }

    @Test("SnapshotLineageQueryEngine builds config & extent diffs and plans GC with interior child reparenting")
    func snapshotDAGDiffAndGarbageCollectionReparenting() async throws {
        // Linear chain: s0 (pinned base) -> s1 (unpinned old checkpoint) -> s2 (unpinned old checkpoint) -> s3 (active head)
        let s0 = makeSnapNode(
            id: "s0",
            parent: nil,
            kind: .baseGoldenImage,
            isPinned: true,
            dirtyBytes: 0,
            vcpus: 2,
            createdOffsetSeconds: 0
        )
        let s1 = makeSnapNode(
            id: "s1",
            parent: "s0",
            kind: .autoPreCommandCheckpoint,
            isPinned: false,
            dirtyBytes: 131_072,
            vcpus: 2,
            createdOffsetSeconds: 60
        )
        let s2 = makeSnapNode(
            id: "s2",
            parent: "s1",
            kind: .autoPreCommandCheckpoint,
            isPinned: false,
            dirtyBytes: 131_072,
            vcpus: 2,
            createdOffsetSeconds: 120
        )
        let s3 = makeSnapNode(
            id: "s3",
            parent: "s2",
            kind: .liveMemoryAndDisk,
            isPinned: false,
            dirtyBytes: 65_536,
            vcpus: 8,
            createdOffsetSeconds: 180
        )

        let leftExtents = [
            SparseExtent(offsetBytes: 0, lengthBytes: 65_536, kind: .allocatedClean, checksumCRC32: 0x1111_2222)
        ]
        let rightExtents = [
            SparseExtent(offsetBytes: 0, lengthBytes: 65_536, kind: .allocatedDirty, checksumCRC32: 0x9999_8888),
            SparseExtent(offsetBytes: 65_536, lengthBytes: 65_536, kind: .allocatedDirty, checksumCRC32: 0xABCD_EF01)
        ]

        let diff = try SnapshotLineageQueryEngine.buildDiffReport(
            left: s0.id,
            right: s3.id,
            in: [s0, s1, s2, s3],
            leftExtents: leftExtents,
            rightExtents: rightExtents,
            blockSizeBytes: 4096
        )
        #expect(diff.lowestCommonAncestorID == s0.id)
        #expect(diff.divergentBytes == 131_072)
        #expect(diff.configDiffs.contains { $0.fieldName == "compute.vcpuCount" && $0.leftValue == "2" && $0.rightValue == "8" })

        // Plan GC with maxUnpinnedPerBranch = 0 and age cutoff so s1 & s2 are pruned while s3 reparents directly to s0!
        let refDate = Date(timeIntervalSince1970: 1_730_000_000 + 86_400 * 30)
        let gcPolicy = GarbageCollectionPolicy(
            keepMinimumPerBranch: 1,
            maxUnpinnedAgeHours: 1,
            preserveBranchForkPoints: true
        )
        let plan = try SnapshotLineageQueryEngine.computeGarbageCollectionPlan(
            in: [s0, s1, s2, s3],
            policy: gcPolicy,
            activeHeadSnapshotIDs: [s3.id],
            referenceDate: refDate
        )
        #expect(Set(plan.candidateSnapshotIDs) == Set([s1.id, s2.id]))
        #expect(plan.protectedSnapshotIDs.contains(s0.id))
        #expect(plan.protectedSnapshotIDs.contains(s3.id))
        #expect(plan.reparentings[s3.id] == s0.id)

        // Verify store.executeGarbageCollectionPlan applies reparenting cleanly in SQLite
        let tempDir = try makeTemporaryDirectory(prefix: "avm-gc-exec")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let store = try AgentVMProjectStore(
            bundleURL: tempDir.appendingPathComponent("GCRun.agentvm", isDirectory: true),
            createIfMissing: true
        )
        let vm = makeCleanVMRecord(id: VMID("vm-dag"), name: "dag-vm-dag", headSnapshotID: s3.id)
        try await store.upsertVM(vm)
        for node in [s0, s1, s2, s3] {
            try await store.upsertSnapshot(node)
        }

        try await store.executeGarbageCollectionPlan(plan, unlinkSnapshotArtifactsInBundle: false)
        let remaining = try await store.listSnapshots(forVM: vm.id)
        #expect(Set(remaining.map(\.id)) == Set([s0.id, s3.id]))
        let updatedS3 = try #require(try await store.fetchSnapshot(s3.id))
        #expect(updatedS3.parentSnapshotID == s0.id)
    }

    @Test("AgentVMProjectStore records, filters, and prunes PortForwardAuditEntry telemetry")
    func portForwardAuditLogAppendFilterAndPrune() async throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-pf-audit")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let store = try AgentVMProjectStore(
            bundleURL: tempDir.appendingPathComponent("PortAudit.agentvm", isDirectory: true),
            createIfMissing: true
        )
        let vmA = makeCleanVMRecord(id: VMID("vm-pf-a"), name: "pf-a")
        let vmB = makeCleanVMRecord(id: VMID("vm-pf-b"), name: "pf-b")
        try await store.upsertVM(vmA)
        try await store.upsertVM(vmB)

        let oldTimestamp = Date(timeIntervalSince1970: 1_700_000_000)
        let recentTimestamp = Date(timeIntervalSince1970: 1_730_000_000)

        try await store.appendPortForwardAudit(PortForwardAuditEntry(
            vmID: vmA.id,
            ruleID: PortForwardID("fwd-http"),
            protocolType: .tcp,
            hostBindAddress: "127.0.0.1",
            hostPort: 18080,
            guestPort: 8080,
            eventKind: .bound,
            bytesRelayed: 0,
            detail: "Bound host listener 127.0.0.1:18080",
            timestamp: oldTimestamp
        ))
        try await store.appendPortForwardAudit(PortForwardAuditEntry(
            vmID: vmB.id,
            ruleID: PortForwardID("fwd-pg"),
            protocolType: .vsockStream,
            hostBindAddress: "127.0.0.1",
            hostPort: 15432,
            guestPort: 5432,
            eventKind: .connectionClosed,
            bytesRelayed: 131_072,
            detail: "Closed relayed stream",
            timestamp: recentTimestamp
        ))

        let allAudits = try await store.listPortForwardAudits(limit: 50)
        #expect(allAudits.count == 2)
        let onlyB = try await store.listPortForwardAudits(vmID: vmB.id, limit: 10)
        #expect(onlyB.count == 1)
        #expect(onlyB.first?.bytesRelayed == 131_072)

        let pruneSummary = try await store.pruneTelemetryAndHistory(
            policy: TelemetryRetentionPolicy(
                maxFlowsPerVM: 10,
                maxDiagnosticsTotal: 10,
                maxExecResultsPerVM: 10,
                maxPortForwardAuditsTotal: 1
            )
        )
        #expect(pruneSummary.deletedPortForwardAudits == 1)
        let surviving = try await store.listPortForwardAudits(limit: 50)
        #expect(surviving.count == 1)
        #expect(surviving.first?.vmID == vmB.id)
    }

    @Test("DeleteSnapshotCommand reparents child snapshots on execute and restores exact parent pointers and VM head on undo")
    func deleteSnapshotCommandReparentAndUndoRoundTrip() async throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-del-snap-undo")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let store = try AgentVMProjectStore(
            bundleURL: tempDir.appendingPathComponent("SnapUndo.agentvm", isDirectory: true),
            createIfMissing: true
        )
        let sRoot = makeSnapNode(id: "s-root", parent: nil, vmID: "vm-su", kind: .baseGoldenImage, isPinned: true)
        let sMid = makeSnapNode(id: "s-mid", parent: "s-root", vmID: "vm-su", createdOffsetSeconds: 10)
        let sLeaf = makeSnapNode(id: "s-leaf", parent: "s-mid", vmID: "vm-su", createdOffsetSeconds: 20)

        let vm = makeCleanVMRecord(id: VMID("vm-su"), name: "su-box", headSnapshotID: sMid.id)
        try await store.upsertVM(vm)
        for node in [sRoot, sMid, sLeaf] {
            try await store.upsertSnapshot(node)
        }

        let undoController = UndoRedoController()
        try await undoController.execute(DeleteSnapshotCommand(snapshotID: sMid.id), on: store)

        // While s-mid is deleted, SQLite ON DELETE SET NULL clears s-leaf's parent_snapshot_id and VM's currentHeadSnapshotID steps back to s-root
        #expect(try await store.fetchSnapshot(sMid.id) == nil)
        #expect(try await store.fetchSnapshot(sLeaf.id)?.parentSnapshotID == nil)
        #expect(try await store.fetchVM(vm.id)?.currentHeadSnapshotID == sRoot.id)

        // Undoing DeleteSnapshotCommand restores s-mid, reconnects s-leaf -> s-mid, and restores VM head -> s-mid
        _ = try await undoController.undo(on: store)
        #expect(try await store.fetchSnapshot(sMid.id)?.parentSnapshotID == sRoot.id)
        #expect(try await store.fetchSnapshot(sLeaf.id)?.parentSnapshotID == sMid.id)
        #expect(try await store.fetchVM(vm.id)?.currentHeadSnapshotID == sMid.id)
    }

    @Test("BaseImageRegistryCatalog supports OS/query filtering and standalone SHA-256 file verification")
    func baseImageCatalogSearchAndStandaloneVerification() async throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-cat-search")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let catalog = try BaseImageRegistryCatalog(
            cacheDirectoryURL: tempDir.appendingPathComponent("SearchCache", isDirectory: true)
        )

        let ubuntuMatches = await catalog.entries(matching: .linuxARM64, searchQuery: "ubuntu", cachedOnly: false)
        #expect(!ubuntuMatches.isEmpty)

        let cachedWhenEmpty = await catalog.entries(cachedOnly: true)
        #expect(cachedWhenEmpty.isEmpty)

        let standaloneURL = tempDir.appendingPathComponent("standalone-kernel.bin")
        let payload = Data("AgentVM-ARM64-Linux-Image-Payload".utf8)
        try payload.write(to: standaloneURL)
        let digest = BinaryChecksums.sha512Hex(payload)

        let okReport = try catalog.verifyStandaloneFile(at: standaloneURL, expectedSHA512: digest.uppercased())
        #expect(okReport.isValid == true)

        let badReport = try catalog.verifyStandaloneFile(
            at: standaloneURL,
            expectedSHA512: String(repeating: "0", count: 128)
        )
        #expect(badReport.isValid == false)
    }

    @Test("SnapshotLineageQueryEngine.diffVMSpecs detects granular changes across mounts, NICs, ports, labels, and cloud-init")
    func snapshotLineageVMSpecFieldDiffGranularity() {
        let left = VMSpec(
            id: VMID("vm-diff"),
            name: "alpha",
            guestOS: .linuxARM64,
            compute: CPUAndMemorySpec(vcpuCount: 2, memoryMB: 2048, minBalloonMemoryMB: 512),
            virtioFSMounts: [VirtioFSMountSpec(mountTag: "ws", hostDirectoryPath: "/tmp/a", guestMountPoint: "/workspace")],
            portForwards: [PortForwardRuleSpec(label: "HTTP", hostPort: 18080, guestPort: 8080)],
            cloudInit: CloudInitSpec(hostname: "alpha-host", aptPackages: ["curl"]),
            labels: ["env": "dev"]
        )
        let right = VMSpec(
            id: VMID("vm-diff"),
            name: "alpha-upgraded",
            guestOS: .linuxX86_64ViaRosetta,
            compute: CPUAndMemorySpec(vcpuCount: 4, memoryMB: 4096, minBalloonMemoryMB: 1024),
            virtioFSMounts: [
                VirtioFSMountSpec(mountTag: "ws", hostDirectoryPath: "/tmp/a", guestMountPoint: "/workspace"),
                VirtioFSMountSpec(mountTag: "cache", hostDirectoryPath: "/tmp/c", guestMountPoint: "/cache", readOnly: true)
            ],
            portForwards: [PortForwardRuleSpec(label: "HTTPS", hostPort: 18443, guestPort: 8443)],
            cloudInit: CloudInitSpec(hostname: "beta-host", aptPackages: ["curl", "jq"]),
            labels: ["env": "prod"]
        )

        let diffs = SnapshotLineageQueryEngine.diffVMSpecs(left: left, right: right)
        let changedFields = Set(diffs.map(\.fieldName))
        #expect(changedFields.contains("name"))
        #expect(changedFields.contains("guestOS"))
        #expect(changedFields.contains("compute.vcpuCount"))
        #expect(changedFields.contains("compute.memoryMB"))
        #expect(changedFields.contains { $0.hasPrefix("virtioFSMounts") })
        #expect(changedFields.contains { $0.hasPrefix("portForwards") })
        #expect(changedFields.contains { $0.hasPrefix("labels") })
    }

    // MARK: - 7. M1 Curated Catalog (A26), Shared Cache Path (A30) & Offline URLProtocol Pull/Verify Suite

    @Test("A26: builtInCuratedEntries pins Debian 12 Bookworm 20261112-2660 SHA-512/size and marks all other entries unsupported without fabricated checksums")
    func curatedCatalogPinsDebianAndMarksOthersUnsupported() throws {
        let entries = BaseImageRegistryCatalog.builtInCuratedEntries()
        #expect(entries.count == 6)

        let debian = try #require(entries.first(where: { $0.id == "debian-12-bookworm-arm64" }))
        #expect(debian.isSupported == true)
        #expect(debian.version == "20261112-2660")
        #expect(debian.guestOS == .linuxARM64)
        #expect(debian.downloadURL == "https://cloud.debian.org/images/cloud/bookworm/20261112-2660/debian-12-genericcloud-arm64-20261112-2660.raw")
        #expect(debian.expectedSizeBytes == 3_221_225_472)
        #expect(debian.defaultVirtualSizeBytes == 3_221_225_472)
        #expect(debian.expectedSHA512 == "708a1a19d3aa4f5441c8160f6493aafccd3c36bfee3113869fa9248965223b8d263a3fbb86b7cf282723fb011180ade0c4a75d331b1addc8d4d1687c897de58b")
        #expect(debian.expectedSHA512?.count == 128)
        #expect(debian.cacheFileName == "debian-12-bookworm-arm64.raw")
        #expect(debian.includesPreinstalledToolchains.contains("python3.11"))
        #expect(debian.includesPreinstalledToolchains.contains("cloud-init"))

        let others = entries.filter { $0.id != "debian-12-bookworm-arm64" }
        #expect(others.count == 5)
        for unsupported in others {
            #expect(unsupported.isSupported == false, "Expected \(unsupported.id) to be marked unsupported")
            #expect(unsupported.downloadURL == nil, "Expected \(unsupported.id) to have no downloadURL")
            #expect(unsupported.expectedSHA512 == nil, "Expected \(unsupported.id) to have no fabricated checksum")
            #expect(unsupported.expectedSizeBytes == nil, "Expected \(unsupported.id) to have no fabricated size")
            #expect(unsupported.defaultVirtualSizeBytes == 0)
            #expect(unsupported.includesPreinstalledToolchains.isEmpty)
        }
    }

    @Test("A30: defaultCacheDirectoryURL defaults to ~/Library/Caches/AgentVM/images and honors AGENTVM_IMAGE_CACHE")
    func sharedCacheDirectoryResolutionAndReadOnlyInit() throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-cache-env")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let mockHome = tempDir.appendingPathComponent("mock-home", isDirectory: true)
        let defaultURL = BaseImageRegistryCatalog.defaultCacheDirectoryURL(environment: [
            "HOME": mockHome.path
        ])
        let expectedDefault = mockHome
            .appendingPathComponent("Library/Caches/AgentVM/images", isDirectory: true)
            .standardizedFileURL
        #expect(defaultURL == expectedDefault)

        let explicitDir = tempDir.appendingPathComponent("explicit-cache", isDirectory: true).standardizedFileURL
        let overriddenURL = BaseImageRegistryCatalog.defaultCacheDirectoryURL(environment: [
            "HOME": mockHome.path,
            "AGENTVM_IMAGE_CACHE": explicitDir.path
        ])
        #expect(overriddenURL == explicitDir)

        let tildeURL = BaseImageRegistryCatalog.defaultCacheDirectoryURL(environment: [
            "HOME": mockHome.path,
            "AGENTVM_IMAGE_CACHE": "~/custom-pool/images"
        ])
        #expect(tildeURL == mockHome.appendingPathComponent("custom-pool/images", isDirectory: true).standardizedFileURL)

        // Read-only init (`createIfMissing: false` default) must not materialize the cache directory on disk.
        let uncreatedDir = tempDir.appendingPathComponent("uncreated-cache", isDirectory: true)
        _ = try BaseImageRegistryCatalog(cacheDirectoryURL: uncreatedDir)
        #expect(FileManager.default.fileExists(atPath: uncreatedDir.path) == false)
    }

    @Test("Offline URLProtocol stub: pullImage resumes with Range (206), restarts on 200, cleans up .part on mismatch, enforces HTTPS redirects, and rejects unsupported entries")
    func pullImageOfflineURLProtocolScenarios() async throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-pull-stub")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let payloadCount = 2 * 1024 * 1024 + 524_288 // 2.5 MiB
        var rawBytes = [UInt8](repeating: 0, count: payloadCount)
        for i in 0..<payloadCount {
            rawBytes[i] = UInt8((i &* 97 &+ 41) & 0xFF)
        }
        let fullPayload = Data(rawBytes)
        let fullSHA512 = BinaryChecksums.sha512Hex(fullPayload)

        // 1. Unsupported entry must fail immediately with zero network requests
        do {
            let sessionID = UUID().uuidString
            let config = CatalogStubURLProtocol.makeSessionConfiguration(sessionID: sessionID) { req in
                Issue.record("Unexpected network call for unsupported image: \(req.url?.absoluteString ?? "")")
                throw URLError(.cannotConnectToHost)
            }
            defer { CatalogStubURLProtocol.unregister(sessionID: sessionID) }

            let cacheDir = tempDir.appendingPathComponent("unsupported-cache", isDirectory: true)
            let catalog = try BaseImageRegistryCatalog(
                cacheDirectoryURL: cacheDir,
                urlSessionConfiguration: config
            )
            do {
                _ = try await catalog.pullImage(id: "ubuntu-24.04-noble-arm64")
                Issue.record("Expected unsupported image pull to throw")
            } catch let err as AgentVMError {
                #expect(err.errorCode == "ERR_IMAGE_UNSUPPORTED")
            }
            #expect(CatalogStubURLProtocol.recordedRequests(sessionID: sessionID).isEmpty)
        }

        // 2. Resume via HTTP 206 Partial Content + HTTPS 302 redirect preserving Range header
        do {
            let sessionID = UUID().uuidString
            let splitOffset = 1_048_576 // 1 MiB already in .part
            let primaryURL = "https://primary.stub.agentvm.invalid/images/test-debian.raw"
            let mirrorURL = "https://mirror.stub.agentvm.invalid/images/test-debian.raw"

            let config = CatalogStubURLProtocol.makeSessionConfiguration(sessionID: sessionID) { req in
                let urlStr = req.url?.absoluteString ?? ""
                if urlStr == primaryURL {
                    let redirectResp = HTTPURLResponse(
                        url: req.url!,
                        statusCode: 302,
                        httpVersion: "HTTP/1.1",
                        headerFields: ["Location": mirrorURL]
                    )!
                    return .redirect(response: redirectResp, newURL: URL(string: mirrorURL)!)
                }
                #expect(urlStr == mirrorURL)
                let rangeHeader = req.value(forHTTPHeaderField: "Range")
                #expect(rangeHeader == "bytes=\(splitOffset)-")
                let remaining = fullPayload.subdata(in: splitOffset..<payloadCount)
                let resp = HTTPURLResponse(
                    url: req.url!,
                    statusCode: 206,
                    httpVersion: "HTTP/1.1",
                    headerFields: [
                        "Accept-Ranges": "bytes",
                        "Content-Range": "bytes \(splitOffset)-\(payloadCount - 1)/\(payloadCount)",
                        "Content-Length": "\(remaining.count)"
                    ]
                )!
                return .chunks(response: resp, chunks: [
                    remaining.prefix(524_288),
                    remaining.dropFirst(524_288)
                ].map(Data.init))
            }
            defer { CatalogStubURLProtocol.unregister(sessionID: sessionID) }

            let cacheDir = tempDir.appendingPathComponent("resume-206-cache", isDirectory: true)
            try FileManager.default.createDirectory(at: cacheDir, withIntermediateDirectories: true)
            let partURL = cacheDir.appendingPathComponent("debian-12-bookworm-arm64.raw.part")
            try fullPayload.prefix(splitOffset).write(to: partURL)

            let testEntry = BaseImageCatalogEntry(
                id: "debian-12-bookworm-arm64",
                displayName: "Debian Test Resume",
                distribution: "debian",
                version: "20261112-2660",
                guestOS: .linuxARM64,
                isSupported: true,
                downloadURL: primaryURL,
                expectedSHA512: fullSHA512,
                expectedSizeBytes: UInt64(payloadCount),
                defaultVirtualSizeBytes: UInt64(payloadCount)
            )
            let catalog = try BaseImageRegistryCatalog(
                cacheDirectoryURL: cacheDir,
                curatedEntries: [testEntry],
                urlSessionConfiguration: config
            )

            let tracker = LockedProgressBox()
            let outcome = try await catalog.pullImage(id: "debian-12-bookworm-arm64") { prog in
                tracker.append(prog)
            }
            #expect(outcome.wasAlreadyCached == false)
            #expect(outcome.resumedFromBytes == UInt64(splitOffset))
            #expect(outcome.restartedFromZeroAfterRangeIgnored == false)
            #expect(outcome.sizeBytes == UInt64(payloadCount))
            #expect(outcome.sha512Hex == fullSHA512)
            #expect(FileManager.default.fileExists(atPath: partURL.path) == false)

            let finalURL = cacheDir.appendingPathComponent("debian-12-bookworm-arm64.raw")
            #expect(outcome.localFileURL == finalURL.standardizedFileURL)
            #expect(try Data(contentsOf: finalURL) == fullPayload)

            let st = try posixStat(finalURL)
            #expect((st.st_mode & 0o777) == 0o444, "Cached image must be read-only (0444)")

            let phases = tracker.snapshot().map(\.phase)
            #expect(phases.contains(.resuming))
            #expect(phases.contains(.verifying))
            #expect(phases.contains(.completed))
        }

        // 3. Server ignores Range and returns HTTP 200 -> truncates stale .part and restarts from byte 0
        do {
            let sessionID = UUID().uuidString
            let url = "https://origin200.stub.agentvm.invalid/images/debian.raw"
            let config = CatalogStubURLProtocol.makeSessionConfiguration(sessionID: sessionID) { req in
                #expect(req.value(forHTTPHeaderField: "Range") == "bytes=524288-")
                let resp = HTTPURLResponse(
                    url: req.url!,
                    statusCode: 200,
                    httpVersion: "HTTP/1.1",
                    headerFields: ["Content-Length": "\(payloadCount)"]
                )!
                return .chunks(response: resp, chunks: [fullPayload])
            }
            defer { CatalogStubURLProtocol.unregister(sessionID: sessionID) }

            let cacheDir = tempDir.appendingPathComponent("range-200-cache", isDirectory: true)
            try FileManager.default.createDirectory(at: cacheDir, withIntermediateDirectories: true)
            let partURL = cacheDir.appendingPathComponent("debian-12-bookworm-arm64.raw.part")
            // Fill .part with corrupted bytes (0xFF) so appending instead of truncating would fail size & SHA-512!
            try Data(repeating: 0xFF, count: 524_288).write(to: partURL)

            let testEntry = BaseImageCatalogEntry(
                id: "debian-12-bookworm-arm64",
                displayName: "Debian Test 200",
                distribution: "debian",
                version: "20261112-2660",
                guestOS: .linuxARM64,
                isSupported: true,
                downloadURL: url,
                expectedSHA512: fullSHA512,
                expectedSizeBytes: UInt64(payloadCount),
                defaultVirtualSizeBytes: UInt64(payloadCount)
            )
            let catalog = try BaseImageRegistryCatalog(
                cacheDirectoryURL: cacheDir,
                curatedEntries: [testEntry],
                urlSessionConfiguration: config
            )

            let outcome = try await catalog.pullImage(id: "debian-12-bookworm-arm64")
            #expect(outcome.wasAlreadyCached == false)
            #expect(outcome.restartedFromZeroAfterRangeIgnored == true)
            #expect(FileManager.default.fileExists(atPath: partURL.path) == false)
            let finalURL = cacheDir.appendingPathComponent("debian-12-bookworm-arm64.raw")
            #expect(try Data(contentsOf: finalURL) == fullPayload)
        }

        // 4. Checksum mismatch and size mismatch delete .part and leave zero cached image
        do {
            let sessionID = UUID().uuidString
            let badChecksumURL = "https://badsum.stub.agentvm.invalid/images/debian.raw"
            let badSizeURL = "https://badsize.stub.agentvm.invalid/images/debian.raw"
            let config = CatalogStubURLProtocol.makeSessionConfiguration(sessionID: sessionID) { req in
                let urlStr = req.url?.absoluteString ?? ""
                if urlStr == badChecksumURL {
                    var tampered = fullPayload
                    tampered[1024] ^= 0x5A
                    let resp = HTTPURLResponse(url: req.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
                    return .chunks(response: resp, chunks: [tampered])
                } else {
                    let truncated = fullPayload.prefix(65_536)
                    let resp = HTTPURLResponse(url: req.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
                    return .chunks(response: resp, chunks: [Data(truncated)])
                }
            }
            defer { CatalogStubURLProtocol.unregister(sessionID: sessionID) }

            let sumCacheDir = tempDir.appendingPathComponent("mismatch-sum-cache", isDirectory: true)
            let sumCatalog = try BaseImageRegistryCatalog(
                cacheDirectoryURL: sumCacheDir,
                curatedEntries: [
                    BaseImageCatalogEntry(
                        id: "debian-12-bookworm-arm64",
                        displayName: "Debian Bad Sum",
                        distribution: "debian",
                        version: "20261112-2660",
                        guestOS: .linuxARM64,
                        isSupported: true,
                        downloadURL: badChecksumURL,
                        expectedSHA512: fullSHA512,
                        expectedSizeBytes: UInt64(payloadCount)
                    )
                ],
                urlSessionConfiguration: config
            )
            do {
                _ = try await sumCatalog.pullImage(id: "debian-12-bookworm-arm64")
                Issue.record("Expected SHA-512 mismatch to throw")
            } catch let err as AgentVMError {
                #expect(err.errorCode == "ERR_IMAGE_CHECKSUM_MISMATCH")
            }
            #expect(!FileManager.default.fileExists(atPath: sumCacheDir.appendingPathComponent("debian-12-bookworm-arm64.raw.part").path))
            #expect(!FileManager.default.fileExists(atPath: sumCacheDir.appendingPathComponent("debian-12-bookworm-arm64.raw").path))
            #expect(await sumCatalog.isImageCached(id: "debian-12-bookworm-arm64") == false)

            let sizeCacheDir = tempDir.appendingPathComponent("mismatch-size-cache", isDirectory: true)
            let sizeCatalog = try BaseImageRegistryCatalog(
                cacheDirectoryURL: sizeCacheDir,
                curatedEntries: [
                    BaseImageCatalogEntry(
                        id: "debian-12-bookworm-arm64",
                        displayName: "Debian Bad Size",
                        distribution: "debian",
                        version: "20261112-2660",
                        guestOS: .linuxARM64,
                        isSupported: true,
                        downloadURL: badSizeURL,
                        expectedSHA512: fullSHA512,
                        expectedSizeBytes: UInt64(payloadCount)
                    )
                ],
                urlSessionConfiguration: config
            )
            do {
                _ = try await sizeCatalog.pullImage(id: "debian-12-bookworm-arm64")
                Issue.record("Expected size mismatch to throw")
            } catch let err as AgentVMError {
                #expect(err.errorCode == "ERR_IMAGE_SIZE_MISMATCH")
            }
            #expect(!FileManager.default.fileExists(atPath: sizeCacheDir.appendingPathComponent("debian-12-bookworm-arm64.raw.part").path))
            #expect(!FileManager.default.fileExists(atPath: sizeCacheDir.appendingPathComponent("debian-12-bookworm-arm64.raw").path))
        }

        // 5. Redirect from https:// to http:// is rejected and never connects to the http:// target
        do {
            let sessionID = UUID().uuidString
            let startHTTPS = "https://secure.stub.agentvm.invalid/images/debian.raw"
            let insecureHTTP = "http://insecure.stub.agentvm.invalid/images/debian.raw"
            let config = CatalogStubURLProtocol.makeSessionConfiguration(sessionID: sessionID) { req in
                let urlStr = req.url?.absoluteString ?? ""
                if urlStr == startHTTPS {
                    let redirect = HTTPURLResponse(
                        url: req.url!,
                        statusCode: 302,
                        httpVersion: "HTTP/1.1",
                        headerFields: ["Location": insecureHTTP]
                    )!
                    return .redirect(response: redirect, newURL: URL(string: insecureHTTP)!)
                }
                Issue.record("Must never request downgraded http:// target: \(urlStr)")
                throw URLError(.badURL)
            }
            defer { CatalogStubURLProtocol.unregister(sessionID: sessionID) }

            let cacheDir = tempDir.appendingPathComponent("http-redirect-cache", isDirectory: true)
            let catalog = try BaseImageRegistryCatalog(
                cacheDirectoryURL: cacheDir,
                curatedEntries: [
                    BaseImageCatalogEntry(
                        id: "debian-12-bookworm-arm64",
                        displayName: "Debian Redirect HTTP",
                        distribution: "debian",
                        version: "20261112-2660",
                        guestOS: .linuxARM64,
                        isSupported: true,
                        downloadURL: startHTTPS,
                        expectedSHA512: fullSHA512,
                        expectedSizeBytes: UInt64(payloadCount)
                    )
                ],
                urlSessionConfiguration: config
            )

            do {
                _ = try await catalog.pullImage(id: "debian-12-bookworm-arm64")
                Issue.record("Expected redirect to http:// to throw ERR_IMAGE_INSECURE_URL")
            } catch let err as AgentVMError {
                #expect(err.errorCode == "ERR_IMAGE_INSECURE_URL")
            }
            let urlsHit = CatalogStubURLProtocol.recordedRequests(sessionID: sessionID).compactMap { $0.url?.absoluteString }
            #expect(urlsHit == [startHTTPS])
            #expect(!urlsHit.contains(insecureHTTP))
        }
    }

    @Test("Local 3 MiB image file exercises cache-hit pullImage (zero network, inode/mtime untouched) and verifyCachedImage (APFS clone tamper detection)")
    func localMultiMBFileVerifyAndCacheHitZeroNetwork() async throws {
        let tempDir = try makeTemporaryDirectory(prefix: "avm-local-3mb")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        // Build a 3 MiB local payload in temporary storage
        let sizeBytes = 3 * 1024 * 1024
        var raw = [UInt8](repeating: 0, count: sizeBytes)
        for i in 0..<sizeBytes {
            raw[i] = UInt8((i &* 53 &+ 17) & 0xFF)
        }
        let localPayload = Data(raw)
        let expectedSHA512 = BinaryChecksums.sha512Hex(localPayload)
        let originURL = "https://local-seed.stub.agentvm.invalid/debian-3mb.raw"

        let testEntry = BaseImageCatalogEntry(
            id: "debian-12-bookworm-arm64",
            displayName: "Debian Local 3 MiB Verification Fixture",
            distribution: "debian",
            version: "20261112-2660",
            guestOS: .linuxARM64,
            isSupported: true,
            downloadURL: originURL,
            expectedSHA512: expectedSHA512,
            expectedSizeBytes: UInt64(sizeBytes),
            defaultVirtualSizeBytes: UInt64(sizeBytes)
        )

        let cacheDir = tempDir.appendingPathComponent("shared-cache", isDirectory: true)

        // Seed cache once via offline stub
        do {
            let seedSession = UUID().uuidString
            let seedConfig = CatalogStubURLProtocol.makeSessionConfiguration(sessionID: seedSession) { req in
                let resp = HTTPURLResponse(url: req.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
                return .chunks(response: resp, chunks: [localPayload])
            }
            defer { CatalogStubURLProtocol.unregister(sessionID: seedSession) }

            let seeder = try BaseImageRegistryCatalog(
                cacheDirectoryURL: cacheDir,
                curatedEntries: [testEntry],
                urlSessionConfiguration: seedConfig
            )
            let initialPull = try await seeder.pullImage(id: "debian-12-bookworm-arm64")
            #expect(initialPull.wasAlreadyCached == false)
        }

        let cachedImageURL = cacheDir.appendingPathComponent("debian-12-bookworm-arm64.raw")
        let manifestURL = cacheDir.appendingPathComponent("catalog-index.json")
        let beforeStat = try posixStat(cachedImageURL)
        let beforeIndexStat = try posixStat(manifestURL)

        // Re-open catalog in a new instance configured to FAIL if any network request is made
        let noNetSession = UUID().uuidString
        let noNetConfig = CatalogStubURLProtocol.makeSessionConfiguration(sessionID: noNetSession) { req in
            Issue.record("Cache-hit pullImage must NOT touch network: \(req.url?.absoluteString ?? "")")
            throw URLError(.notConnectedToInternet)
        }
        defer { CatalogStubURLProtocol.unregister(sessionID: noNetSession) }

        let offlineCatalog = try BaseImageRegistryCatalog(
            cacheDirectoryURL: cacheDir,
            curatedEntries: [testEntry],
            urlSessionConfiguration: noNetConfig
        )
        #expect(await offlineCatalog.isImageCached(id: "debian-12-bookworm-arm64") == true)
        #expect(try await offlineCatalog.verifiedCachedImageURL(forID: "debian-12-bookworm-arm64") == cachedImageURL.standardizedFileURL)

        // Cache-hit pullImage: 0 network calls, inode and mtime unchanged
        let cachedPull = try await offlineCatalog.pullImage(id: "debian-12-bookworm-arm64")
        #expect(cachedPull.wasAlreadyCached == true)
        #expect(CatalogStubURLProtocol.recordedRequests(sessionID: noNetSession).isEmpty)

        let afterPullStat = try posixStat(cachedImageURL)
        let afterPullIndexStat = try posixStat(manifestURL)
        #expect(afterPullStat.st_ino == beforeStat.st_ino)
        #expect(afterPullStat.st_mtimespec.tv_sec == beforeStat.st_mtimespec.tv_sec)
        #expect(afterPullStat.st_mtimespec.tv_nsec == beforeStat.st_mtimespec.tv_nsec)
        #expect(afterPullIndexStat.st_mtimespec.tv_sec == beforeIndexStat.st_mtimespec.tv_sec)
        #expect(afterPullIndexStat.st_mtimespec.tv_nsec == beforeIndexStat.st_mtimespec.tv_nsec)

        // verifyCachedImage on original cache passes and leaves catalog-index.json untouched
        let okVerify = try await offlineCatalog.verifyCachedImage(id: "debian-12-bookworm-arm64", enforceExpectedDigest: true)
        #expect(okVerify.isValid == true)
        #expect(okVerify.actualSHA512 == expectedSHA512)
        #expect(okVerify.logicalSizeBytes == UInt64(sizeBytes))

        let afterVerifyIndexStat = try posixStat(manifestURL)
        #expect(afterVerifyIndexStat.st_mtimespec.tv_sec == beforeIndexStat.st_mtimespec.tv_sec)
        #expect(afterVerifyIndexStat.st_mtimespec.tv_nsec == beforeIndexStat.st_mtimespec.tv_nsec)

        // APFS clonefile copy into separate temp cache dir, flip 1 byte -> verify fails on copy, still passes on original
        let clonedCacheDir = tempDir.appendingPathComponent("cloned-tampered-cache", isDirectory: true)
        try FileManager.default.createDirectory(at: clonedCacheDir, withIntermediateDirectories: true)
        let clonedImageURL = clonedCacheDir.appendingPathComponent("debian-12-bookworm-arm64.raw")
        #expect(Darwin.clonefile(cachedImageURL.path, clonedImageURL.path, 0) == 0)
        #expect(Darwin.chmod(clonedImageURL.path, 0o644) == 0)
        do {
            let handle = try FileHandle(forUpdating: clonedImageURL)
            try handle.seek(toOffset: UInt64(sizeBytes / 2))
            let origByte = localPayload[sizeBytes / 2]
            try handle.write(contentsOf: Data([origByte ^ 0x01]))
            try handle.close()
        }
        #expect(Darwin.chmod(clonedImageURL.path, 0o444) == 0)

        let tamperedCatalog = try BaseImageRegistryCatalog(
            cacheDirectoryURL: clonedCacheDir,
            curatedEntries: [testEntry],
            urlSessionConfiguration: noNetConfig
        )
        let badVerify = try await tamperedCatalog.verifyCachedImage(id: "debian-12-bookworm-arm64", enforceExpectedDigest: true)
        #expect(badVerify.isValid == false)
        #expect(badVerify.actualSHA512 != expectedSHA512)

        let stillGoodOriginal = try await offlineCatalog.verifyCachedImage(id: "debian-12-bookworm-arm64", enforceExpectedDigest: true)
        #expect(stillGoodOriginal.isValid == true)
    }
}

// MARK: - Offline URLProtocol Stub Harness (Zero Real Network Access)

private final class LockedProgressBox: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [BaseImagePullProgress] = []

    func append(_ item: BaseImagePullProgress) {
        lock.lock()
        defer { lock.unlock() }
        items.append(item)
    }

    func snapshot() -> [BaseImagePullProgress] {
        lock.lock()
        defer { lock.unlock() }
        return items
    }
}

private final class CatalogStubURLProtocol: URLProtocol, @unchecked Sendable {
    enum StubReply {
        case chunks(response: HTTPURLResponse, chunks: [Data])
        case redirect(response: HTTPURLResponse, newURL: URL)
    }

    typealias Handler = @Sendable (URLRequest) throws -> StubReply

    private static let sessionHeader = "X-AgentVM-Test-Stub-Session"
    private static let lock = NSLock()
    private nonisolated(unsafe) static var handlers: [String: Handler] = [:]
    private nonisolated(unsafe) static var requestsBySession: [String: [URLRequest]] = [:]

    static func makeSessionConfiguration(sessionID: String, handler: @escaping Handler) -> URLSessionConfiguration {
        lock.lock()
        handlers[sessionID] = handler
        requestsBySession[sessionID] = []
        lock.unlock()

        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [CatalogStubURLProtocol.self]
        config.httpAdditionalHeaders = [sessionHeader: sessionID]
        config.urlCache = nil
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        return config
    }

    static func unregister(sessionID: String) {
        lock.lock()
        handlers.removeValue(forKey: sessionID)
        requestsBySession.removeValue(forKey: sessionID)
        lock.unlock()
    }

    static func recordedRequests(sessionID: String) -> [URLRequest] {
        lock.lock()
        defer { lock.unlock() }
        return requestsBySession[sessionID] ?? []
    }

    override class func canInit(with request: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        let sessionID = request.value(forHTTPHeaderField: Self.sessionHeader) ?? ""
        Self.lock.lock()
        if !sessionID.isEmpty {
            Self.requestsBySession[sessionID, default: []].append(request)
        }
        let handler = Self.handlers[sessionID]
        Self.lock.unlock()

        guard let handler else {
            client?.urlProtocol(self, didFailWithError: URLError(.unsupportedURL))
            return
        }

        do {
            switch try handler(request) {
            case let .redirect(response, newURL):
                var redirected = request
                redirected.url = newURL
                client?.urlProtocol(self, wasRedirectedTo: redirected, redirectResponse: response)
                client?.urlProtocolDidFinishLoading(self)
            case let .chunks(response, chunks):
                client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
                for chunk in chunks where !chunk.isEmpty {
                    client?.urlProtocol(self, didLoad: chunk)
                }
                client?.urlProtocolDidFinishLoading(self)
            }
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}
