import AgentVMModels
import AgentVMStore
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
        let expectedSHA = BinaryChecksums.sha256Hex(imageBytes)

        let registered = try await catalog.registerOfflineImage(
            fileURL: offlineFile,
            id: "custom-alpine",
            displayName: "Custom Alpine ARM64",
            copyIntoCacheDirectory: true
        )
        #expect(registered.expectedSHA256 == expectedSHA)

        let validReport = try await catalog.verifyCachedImage(id: "custom-alpine", enforceExpectedDigest: true)
        #expect(validReport.isValid == true)
        #expect(validReport.actualSHA256 == expectedSHA)

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
        let digest = BinaryChecksums.sha256Hex(payload)

        let okReport = try catalog.verifyStandaloneFile(at: standaloneURL, expectedSHA256: digest.uppercased())
        #expect(okReport.isValid == true)

        let badReport = try catalog.verifyStandaloneFile(
            at: standaloneURL,
            expectedSHA256: String(repeating: "0", count: 64)
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
}
