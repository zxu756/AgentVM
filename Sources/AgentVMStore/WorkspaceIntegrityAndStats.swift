import AgentVMModels
import Foundation

// MARK: - Workspace Storage Accounting & v4 Audit Ledger Models

public struct WorkspaceStorageStats: Codable, Hashable, Sendable {
    public var sqliteBytes: UInt64
    public var walBytes: UInt64
    public var shmBytes: UInt64
    public var diskImageCount: Int
    public var diskImageBytes: UInt64
    public var diskImagePhysicalBytes: UInt64
    public var snapshotCount: Int
    public var snapshotBytes: UInt64
    public var snapshotPhysicalBytes: UInt64
    public var pcapCount: Int
    public var pcapBytes: UInt64
    public var isoCount: Int
    public var isoBytes: UInt64
    public var logFileCount: Int
    public var logBytes: UInt64
    public var registeredVMCount: Int
    public var registeredSnapshotRecordCount: Int
    public var computedAt: Date

    public init(
        sqliteBytes: UInt64,
        walBytes: UInt64,
        shmBytes: UInt64 = 0,
        diskImageCount: Int,
        diskImageBytes: UInt64,
        diskImagePhysicalBytes: UInt64 = 0,
        snapshotCount: Int,
        snapshotBytes: UInt64,
        snapshotPhysicalBytes: UInt64 = 0,
        pcapCount: Int,
        pcapBytes: UInt64,
        isoCount: Int = 0,
        isoBytes: UInt64 = 0,
        logFileCount: Int = 0,
        logBytes: UInt64 = 0,
        registeredVMCount: Int = 0,
        registeredSnapshotRecordCount: Int = 0,
        computedAt: Date = Date()
    ) {
        self.sqliteBytes = sqliteBytes
        self.walBytes = walBytes
        self.shmBytes = shmBytes
        self.diskImageCount = diskImageCount
        self.diskImageBytes = diskImageBytes
        self.diskImagePhysicalBytes = diskImagePhysicalBytes
        self.snapshotCount = snapshotCount
        self.snapshotBytes = snapshotBytes
        self.snapshotPhysicalBytes = snapshotPhysicalBytes
        self.pcapCount = pcapCount
        self.pcapBytes = pcapBytes
        self.isoCount = isoCount
        self.isoBytes = isoBytes
        self.logFileCount = logFileCount
        self.logBytes = logBytes
        self.registeredVMCount = registeredVMCount
        self.registeredSnapshotRecordCount = registeredSnapshotRecordCount
        self.computedAt = computedAt
    }

    public var totalSQLiteFootprintBytes: UInt64 {
        sqliteBytes + walBytes + shmBytes
    }

    public var totalBundleLogicalBytes: UInt64 {
        totalSQLiteFootprintBytes + diskImageBytes + snapshotBytes + pcapBytes + isoBytes + logBytes
    }

    public var totalBundlePhysicalBytes: UInt64 {
        let diskPhys = diskImagePhysicalBytes > 0 ? diskImagePhysicalBytes : diskImageBytes
        let snapPhys = snapshotPhysicalBytes > 0 ? snapshotPhysicalBytes : snapshotBytes
        return totalSQLiteFootprintBytes + diskPhys + snapPhys + pcapBytes + isoBytes + logBytes
    }

    public var cowAndSparseSavedBytes: UInt64 {
        let logicalPool = diskImageBytes + snapshotBytes
        let physicalPool = (diskImagePhysicalBytes > 0 ? diskImagePhysicalBytes : diskImageBytes)
            + (snapshotPhysicalBytes > 0 ? snapshotPhysicalBytes : snapshotBytes)
        return logicalPool > physicalPool ? (logicalPool - physicalPool) : 0
    }
}

public enum UndoJournalEntryState: String, Codable, Hashable, Sendable, CaseIterable {
    case applied
    case undone
    case superseded
    case evicted
}

public struct UndoJournalRecord: Codable, Hashable, Sendable, Identifiable {
    public var id: UUID { commandID }
    public var sequenceID: Int64
    public var commandID: UUID
    public var commandType: String
    public var title: String
    public var state: UndoJournalEntryState
    public var payloadSummary: String
    public var createdAt: Date
    public var updatedAt: Date

    public init(
        sequenceID: Int64 = 0,
        commandID: UUID,
        commandType: String,
        title: String,
        state: UndoJournalEntryState,
        payloadSummary: String,
        createdAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.sequenceID = sequenceID
        self.commandID = commandID
        self.commandType = commandType
        self.title = title
        self.state = state
        self.payloadSummary = payloadSummary
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

public struct CachedImageIndexRecord: Codable, Hashable, Sendable, Identifiable {
    public var id: String { entry.id }
    public var entry: BaseImageCatalogEntry
    public var fileName: String
    public var localPath: String
    public var sha512Hex: String
    public var logicalBytes: UInt64
    public var physicalBytes: UInt64
    public var virtualBytes: UInt64
    public var mtimeSeconds: Int64
    public var mtimeNanoseconds: Int64
    public var verified: Bool
    public var isCustomOffline: Bool
    public var verifiedAt: Date
    public var lastAccessedAt: Date
    public var accessCount: Int

    public init(
        entry: BaseImageCatalogEntry,
        fileName: String? = nil,
        localPath: String,
        sha512Hex: String,
        logicalBytes: UInt64 = 0,
        physicalBytes: UInt64,
        virtualBytes: UInt64,
        mtimeSeconds: Int64 = 0,
        mtimeNanoseconds: Int64 = 0,
        verified: Bool = true,
        isCustomOffline: Bool,
        verifiedAt: Date = Date(),
        lastAccessedAt: Date = Date(),
        accessCount: Int = 1
    ) {
        self.entry = entry
        let derivedFileName = URL(fileURLWithPath: localPath).lastPathComponent
        self.fileName = (fileName?.isEmpty == false) ? fileName! : (derivedFileName.isEmpty ? entry.cacheFileName : derivedFileName)
        self.localPath = localPath
        self.sha512Hex = sha512Hex
        self.logicalBytes = logicalBytes > 0 ? logicalBytes : physicalBytes
        self.physicalBytes = physicalBytes
        self.virtualBytes = virtualBytes
        self.mtimeSeconds = mtimeSeconds
        self.mtimeNanoseconds = mtimeNanoseconds
        self.verified = verified
        self.isCustomOffline = isCustomOffline
        self.verifiedAt = verifiedAt
        self.lastAccessedAt = lastAccessedAt
        self.accessCount = max(1, accessCount)
    }
}

public enum PortForwardAuditEventKind: String, Codable, Hashable, Sendable, CaseIterable {
    case bound
    case closed
    case connectionOpened = "connection_opened"
    case connectionClosed = "connection_closed"
    case bindFailed = "bind_failed"
}

public struct PortForwardAuditEntry: Codable, Hashable, Sendable, Identifiable {
    public var id: UUID
    public var vmID: VMID
    public var ruleID: PortForwardID
    public var protocolType: PortForwardProtocol
    public var hostBindAddress: String
    public var hostPort: UInt16
    public var guestPort: UInt16
    public var vsockCID: UInt32
    public var eventKind: PortForwardAuditEventKind
    public var bytesRelayed: UInt64
    public var detail: String
    public var timestamp: Date

    public init(
        id: UUID = UUID(),
        vmID: VMID,
        ruleID: PortForwardID,
        protocolType: PortForwardProtocol,
        hostBindAddress: String = "127.0.0.1",
        hostPort: UInt16,
        guestPort: UInt16,
        vsockCID: UInt32 = 3,
        eventKind: PortForwardAuditEventKind,
        bytesRelayed: UInt64 = 0,
        detail: String,
        timestamp: Date = Date()
    ) {
        self.id = id
        self.vmID = vmID
        self.ruleID = ruleID
        self.protocolType = protocolType
        self.hostBindAddress = hostBindAddress
        self.hostPort = hostPort
        self.guestPort = guestPort
        self.vsockCID = vsockCID
        self.eventKind = eventKind
        self.bytesRelayed = bytesRelayed
        self.detail = detail
        self.timestamp = timestamp
    }
}

public struct TelemetryRetentionPolicy: Codable, Hashable, Sendable {
    public var maxFlowsPerVM: Int
    public var maxDiagnosticsTotal: Int
    public var maxExecResultsPerVM: Int
    public var maxPortForwardAuditsTotal: Int

    public init(
        maxFlowsPerVM: Int = 5_000,
        maxDiagnosticsTotal: Int = 10_000,
        maxExecResultsPerVM: Int = 1_000,
        maxPortForwardAuditsTotal: Int = 2_000
    ) {
        self.maxFlowsPerVM = max(0, maxFlowsPerVM)
        self.maxDiagnosticsTotal = max(0, maxDiagnosticsTotal)
        self.maxExecResultsPerVM = max(0, maxExecResultsPerVM)
        self.maxPortForwardAuditsTotal = max(0, maxPortForwardAuditsTotal)
    }
}

public struct TelemetryPruneSummary: Codable, Hashable, Sendable {
    public var deletedFlows: Int
    public var deletedDiagnostics: Int
    public var deletedExecResults: Int
    public var deletedPortForwardAudits: Int

    public init(
        deletedFlows: Int,
        deletedDiagnostics: Int,
        deletedExecResults: Int,
        deletedPortForwardAudits: Int
    ) {
        self.deletedFlows = deletedFlows
        self.deletedDiagnostics = deletedDiagnostics
        self.deletedExecResults = deletedExecResults
        self.deletedPortForwardAudits = deletedPortForwardAudits
    }

    public var totalDeletedRows: Int {
        deletedFlows + deletedDiagnostics + deletedExecResults + deletedPortForwardAudits
    }
}

// MARK: - AgentVMProjectStore Integrity, Storage Stats & v4 Ledger Extensions

extension AgentVMProjectStore {
    // MARK: Bundle Integrity Verification

    public func verifyBundleIntegrity() throws -> [ValidationIssue] {
        var issues: [ValidationIssue] = []
        let fm = FileManager.default

        let expectedDirs: [(String, URL)] = [
            ("bundle", bundleURL),
            ("bundle.disks", disksDirectoryURL),
            ("bundle.snapshots", snapshotsDirectoryURL),
            ("bundle.pcap", pcapDirectoryURL),
            ("bundle.isos", isosDirectoryURL),
            ("bundle.logs", logsDirectoryURL)
        ]

        for (field, dirURL) in expectedDirs {
            var isDir: ObjCBool = false
            if !fm.fileExists(atPath: dirURL.path, isDirectory: &isDir) {
                issues.append(ValidationIssue(
                    fieldPath: field,
                    code: "MISSING_BUNDLE_SUBDIRECTORY",
                    severity: .error,
                    message: "Required bundle directory '\(dirURL.lastPathComponent)' is missing.",
                    remediation: "Re-open workspace with createIfMissing=true or recreate '\(dirURL.path)'."
                ))
            } else if !isDir.boolValue {
                issues.append(ValidationIssue(
                    fieldPath: field,
                    code: "BUNDLE_ENTRY_NOT_DIRECTORY",
                    severity: .critical,
                    message: "Expected directory at '\(dirURL.lastPathComponent)', found regular file.",
                    remediation: "Move or remove conflicting file at '\(dirURL.path)'."
                ))
            }
        }

        // Manifest verification
        do {
            let manifest = try loadManifest()
            if manifest.formatVersion < 1 || manifest.formatVersion > SQLiteWALDatabase.latestSchemaVersion {
                issues.append(ValidationIssue(
                    fieldPath: "manifest.formatVersion",
                    code: "UNSUPPORTED_MANIFEST_FORMAT",
                    severity: .warning,
                    message: "Manifest formatVersion \(manifest.formatVersion) outside expected 1...\(SQLiteWALDatabase.latestSchemaVersion).",
                    remediation: "Save manifest using current AgentVM runtime to normalize formatVersion."
                ))
            }
            if manifest.title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                issues.append(ValidationIssue(
                    fieldPath: "manifest.title",
                    code: "EMPTY_MANIFEST_TITLE",
                    severity: .warning,
                    message: "Workspace manifest title is blank.",
                    remediation: "Assign a descriptive project name in Workspace Preferences."
                ))
            }
            if IPv4CIDR(parsing: manifest.preferences.switchSubnetCIDR) == nil {
                issues.append(ValidationIssue(
                    fieldPath: "manifest.preferences.switchSubnetCIDR",
                    code: "INVALID_SWITCH_SUBNET_CIDR",
                    severity: .error,
                    message: "Invalid IPv4 CIDR '\(manifest.preferences.switchSubnetCIDR)' in workspace preferences.",
                    remediation: "Set a valid RFC1918 subnet such as '10.211.55.0/24'."
                ))
            }
            if IPv4Address(parsing: manifest.preferences.switchGatewayIP) == nil {
                issues.append(ValidationIssue(
                    fieldPath: "manifest.preferences.switchGatewayIP",
                    code: "INVALID_SWITCH_GATEWAY_IP",
                    severity: .error,
                    message: "Invalid gateway IPv4 '\(manifest.preferences.switchGatewayIP)'.",
                    remediation: "Configure a valid IPv4 address inside switchSubnetCIDR."
                ))
            }
            if IPv4Address(parsing: manifest.preferences.upstreamDNSServer) == nil {
                issues.append(ValidationIssue(
                    fieldPath: "manifest.preferences.upstreamDNSServer",
                    code: "INVALID_UPSTREAM_DNS_IP",
                    severity: .error,
                    message: "Invalid upstream DNS IPv4 '\(manifest.preferences.upstreamDNSServer)'.",
                    remediation: "Set a valid DNS resolver IPv4 such as '1.1.1.1' or '8.8.8.8'."
                ))
            }
        } catch {
            issues.append(ValidationIssue(
                fieldPath: "manifest.json",
                code: "CORRUPT_OR_MISSING_MANIFEST",
                severity: .critical,
                message: "Failed loading manifest.json: \(error.localizedDescription)",
                remediation: "Restore manifest.json from backup or regenerate default workspace manifest."
            ))
        }

        // SQLite B-Tree & Foreign-Key health
        let sqliteErrors = try db.integrityCheck(maxErrors: 10)
        for (idx, errText) in sqliteErrors.enumerated() {
            issues.append(ValidationIssue(
                fieldPath: "state.sqlite.integrity[\(idx)]",
                code: "SQLITE_CORRUPTION",
                severity: .critical,
                message: "SQLite page integrity check reported: \(errText)",
                remediation: "Export recoverable tables or restore state.sqlite from snapshot backup."
            ))
        }

        let fkErrors = try db.foreignKeyViolations()
        for (idx, fkText) in fkErrors.enumerated() {
            issues.append(ValidationIssue(
                fieldPath: "state.sqlite.foreignKeys[\(idx)]",
                code: "SQLITE_FOREIGN_KEY_VIOLATION",
                severity: .error,
                message: "SQLite foreign-key violation: \(fkText)",
                remediation: "Repair orphaned parent references in state.sqlite."
            ))
        }

        // Cross-check VMs, Firewall Policies, Snapshots, and backing disk files
        let vms = try listVMs()
        let policies = try listFirewallPolicies()
        let snapshots = try listSnapshots()

        let vmByID = Dictionary(uniqueKeysWithValues: vms.map { ($0.id, $0) })
        let policyByID = Dictionary(uniqueKeysWithValues: policies.map { ($0.id, $0) })
        let snapshotByID = Dictionary(uniqueKeysWithValues: snapshots.map { ($0.id, $0) })

        for vm in vms {
            let specIssues = vm.spec.validate()
            for specIssue in specIssues {
                issues.append(ValidationIssue(
                    fieldPath: "vms[\(vm.id.rawValue)].\(specIssue.fieldPath)",
                    code: specIssue.code,
                    severity: specIssue.severity,
                    message: specIssue.message,
                    remediation: specIssue.remediation
                ))
            }

            if let headID = vm.currentHeadSnapshotID, snapshotByID[headID] == nil {
                issues.append(ValidationIssue(
                    fieldPath: "vms[\(vm.id.rawValue)].currentHeadSnapshotID",
                    code: "DANGLING_HEAD_SNAPSHOT",
                    severity: .error,
                    message: "VM '\(vm.spec.name)' points to missing head snapshot '\(headID.rawValue)'.",
                    remediation: "Reset currentHeadSnapshotID or take a fresh baseline checkpoint."
                ))
            }

            if let forkedSnap = vm.spec.forkedFromSnapshotID, snapshotByID[forkedSnap] == nil {
                issues.append(ValidationIssue(
                    fieldPath: "vms[\(vm.id.rawValue)].forkedFromSnapshotID",
                    code: "MISSING_FORK_ORIGIN_SNAPSHOT",
                    severity: .warning,
                    message: "Forked VM '\(vm.spec.name)' references reclaimed origin snapshot '\(forkedSnap.rawValue)'.",
                    remediation: "Clear forkedFromSnapshotID if ancestor snapshot was intentionally garbage-collected."
                ))
            }

            for blk in vm.spec.blockDevices {
                let resolvedURL = resolveBundleRelativePath(blk.imagePath)
                if !fm.fileExists(atPath: resolvedURL.path) {
                    issues.append(ValidationIssue(
                        fieldPath: "vms[\(vm.id.rawValue)].blockDevices[\(blk.id.rawValue)].imagePath",
                        code: "MISSING_DISK_IMAGE",
                        severity: .error,
                        message: "Block device '\(blk.label)' backing file not found at '\(resolvedURL.path)'.",
                        remediation: "Re-clone base disk image into disks/ or detach missing block device."
                    ))
                }
            }

            for nic in vm.spec.networkInterfaces {
                if let polID = nic.firewallPolicyID, policyByID[polID] == nil {
                    issues.append(ValidationIssue(
                        fieldPath: "vms[\(vm.id.rawValue)].networkInterfaces[\(nic.id.rawValue)].firewallPolicyID",
                        code: "MISSING_FIREWALL_POLICY",
                        severity: .error,
                        message: "NIC '\(nic.interfaceName)' references missing firewall policy '\(polID.rawValue)'.",
                        remediation: "Re-bind NIC to an active FirewallPolicySet in Firewall Policy Studio."
                    ))
                }
            }
        }

        // Snapshot DAG cycle & backing file verification
        do {
            try SnapshotLineageQueryEngine.validateDAG(snapshots)
        } catch let AgentVMError.snapshotCycleDetected(cycleSnapID) {
            issues.append(ValidationIssue(
                fieldPath: "snapshots[\(cycleSnapID.rawValue)].parentSnapshotID",
                code: "SNAPSHOT_DAG_CYCLE",
                severity: .critical,
                message: "Cycle detected in snapshot lineage graph involving '\(cycleSnapID.rawValue)'.",
                remediation: "Break cyclic parentSnapshotID edge in state.sqlite."
            ))
        } catch {
            issues.append(ValidationIssue(
                fieldPath: "snapshots",
                code: "SNAPSHOT_DAG_VALIDATION_ERROR",
                severity: .error,
                message: "Snapshot lineage validation failed: \(error.localizedDescription)",
                remediation: "Inspect snapshot parent links in Snapshot & CoW DAG."
            ))
        }

        for snap in snapshots {
            if vmByID[snap.vmID] == nil {
                issues.append(ValidationIssue(
                    fieldPath: "snapshots[\(snap.id.rawValue)].vmID",
                    code: "ORPHANED_SNAPSHOT_VM",
                    severity: .warning,
                    message: "Snapshot '\(snap.title)' belongs to deleted VM '\(snap.vmID.rawValue)'.",
                    remediation: "Prune orphaned snapshot or re-attach its CoW clone to a new VM."
                ))
            }
            if let parentID = snap.parentSnapshotID, snapshotByID[parentID] == nil {
                issues.append(ValidationIssue(
                    fieldPath: "snapshots[\(snap.id.rawValue)].parentSnapshotID",
                    code: "DANGLING_PARENT_SNAPSHOT",
                    severity: .error,
                    message: "Snapshot '\(snap.title)' references missing parent '\(parentID.rawValue)'.",
                    remediation: "Reparent snapshot to root (nil) or nearest surviving ancestor."
                ))
            }
            let diskURL = resolveBundleRelativePath(snap.diskClonePath)
            if !fm.fileExists(atPath: diskURL.path) {
                issues.append(ValidationIssue(
                    fieldPath: "snapshots[\(snap.id.rawValue)].diskClonePath",
                    code: "MISSING_SNAPSHOT_DISK",
                    severity: .error,
                    message: "Snapshot '\(snap.title)' CoW disk clone missing at '\(diskURL.path)'.",
                    remediation: "Delete broken snapshot record from lineage ledger."
                ))
            }
            if let memPath = snap.memoryStatePath, !memPath.isEmpty {
                let memURL = resolveBundleRelativePath(memPath)
                if !fm.fileExists(atPath: memURL.path) {
                    issues.append(ValidationIssue(
                        fieldPath: "snapshots[\(snap.id.rawValue)].memoryStatePath",
                        code: "MISSING_SNAPSHOT_RAM_STATE",
                        severity: .error,
                        message: "Live snapshot '\(snap.title)' RAM state file missing at '\(memURL.path)'.",
                        remediation: "Downgrade snapshot kind to coldDiskOnly or remove snapshot record."
                    ))
                }
            }
        }

        return issues
    }

    // MARK: Workspace Storage Statistics

    public func storageStatistics() throws -> WorkspaceStorageStats {
        let dbDiag = try db.diagnostics()
        let disksScan = Self.scanDirectoryMetrics(at: disksDirectoryURL)
        let snapsScan = Self.scanDirectoryMetrics(at: snapshotsDirectoryURL)
        let pcapScan = Self.scanDirectoryMetrics(at: pcapDirectoryURL)
        let isosScan = Self.scanDirectoryMetrics(at: isosDirectoryURL)
        let logsScan = Self.scanDirectoryMetrics(at: logsDirectoryURL)

        let vmCount = Int(dbDiag.tableRowCounts["vms"] ?? 0)
        let snapRecordCount = Int(dbDiag.tableRowCounts["snapshots"] ?? 0)

        return WorkspaceStorageStats(
            sqliteBytes: dbDiag.databaseFileBytes,
            walBytes: dbDiag.walFileBytes,
            shmBytes: dbDiag.shmFileBytes,
            diskImageCount: disksScan.fileCount,
            diskImageBytes: disksScan.logicalBytes,
            diskImagePhysicalBytes: disksScan.physicalBytes,
            snapshotCount: snapsScan.fileCount,
            snapshotBytes: snapsScan.logicalBytes,
            snapshotPhysicalBytes: snapsScan.physicalBytes,
            pcapCount: pcapScan.fileCount,
            pcapBytes: pcapScan.logicalBytes,
            isoCount: isosScan.fileCount,
            isoBytes: isosScan.logicalBytes,
            logFileCount: logsScan.fileCount,
            logBytes: logsScan.logicalBytes,
            registeredVMCount: vmCount,
            registeredSnapshotRecordCount: snapRecordCount,
            computedAt: Date()
        )
    }

    // MARK: Database Diagnostics, Migrations & Maintenance

    public func databaseDiagnostics() throws -> SQLiteDatabaseDiagnostics {
        try db.diagnostics()
    }

    public func appliedSchemaMigrations() throws -> [SQLiteAppliedMigration] {
        try db.appliedMigrations()
    }

    @discardableResult
    public func performDatabaseMaintenance(
        checkpointMode: SQLiteWALCheckpointMode = .truncate,
        runVacuum: Bool = false
    ) throws -> SQLiteDatabaseDiagnostics {
        _ = try db.walCheckpoint(mode: checkpointMode)
        if runVacuum {
            try db.vacuum()
            _ = try db.walCheckpoint(mode: .truncate)
        }
        return try db.diagnostics()
    }

    public func pruneTelemetryAndHistory(
        policy: TelemetryRetentionPolicy = TelemetryRetentionPolicy()
    ) throws -> TelemetryPruneSummary {
        try db.inTransaction {
            var deletedFlows = 0
            let flowVMRows = try db.query("SELECT DISTINCT vm_id FROM network_flows;")
            for row in flowVMRows {
                let vmIDStr = try row.string("vm_id")
                deletedFlows += try db.execute(
                    """
                    DELETE FROM network_flows
                    WHERE vm_id = ? AND id NOT IN (
                        SELECT id FROM network_flows
                        WHERE vm_id = ?
                        ORDER BY timestamp DESC, id ASC
                        LIMIT ?
                    );
                    """,
                    bindings: [vmIDStr.sqliteValue, vmIDStr.sqliteValue, policy.maxFlowsPerVM.sqliteValue]
                )
            }

            let deletedDiagnostics = try db.execute(
                """
                DELETE FROM diagnostics
                WHERE id NOT IN (
                    SELECT id FROM diagnostics
                    ORDER BY timestamp DESC, id ASC
                    LIMIT ?
                );
                """,
                bindings: [policy.maxDiagnosticsTotal.sqliteValue]
            )

            var deletedExecs = 0
            let execVMRows = try db.query("SELECT DISTINCT vm_id FROM exec_history;")
            for row in execVMRows {
                let vmIDStr = try row.string("vm_id")
                deletedExecs += try db.execute(
                    """
                    DELETE FROM exec_history
                    WHERE vm_id = ? AND request_id NOT IN (
                        SELECT request_id FROM exec_history
                        WHERE vm_id = ?
                        ORDER BY timestamp DESC, request_id ASC
                        LIMIT ?
                    );
                    """,
                    bindings: [vmIDStr.sqliteValue, vmIDStr.sqliteValue, policy.maxExecResultsPerVM.sqliteValue]
                )
            }

            let deletedAudits = try db.execute(
                """
                DELETE FROM port_forward_audit
                WHERE id NOT IN (
                    SELECT id FROM port_forward_audit
                    ORDER BY timestamp DESC, id ASC
                    LIMIT ?
                );
                """,
                bindings: [policy.maxPortForwardAuditsTotal.sqliteValue]
            )

            return TelemetryPruneSummary(
                deletedFlows: deletedFlows,
                deletedDiagnostics: deletedDiagnostics,
                deletedExecResults: deletedExecs,
                deletedPortForwardAudits: deletedAudits
            )
        }
    }

    // MARK: v4 Undo Journal Persistence (undo_journal)

    public func recordUndoJournalEntry(_ record: UndoJournalRecord) throws {
        try db.execute(
            """
            INSERT INTO undo_journal (
                command_id, command_type, title, stack_state, payload_summary, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(command_id) DO UPDATE SET
                command_type = excluded.command_type,
                title = excluded.title,
                stack_state = excluded.stack_state,
                payload_summary = excluded.payload_summary,
                updated_at = excluded.updated_at;
            """,
            bindings: [
                record.commandID.sqliteValue,
                record.commandType.sqliteValue,
                record.title.sqliteValue,
                record.state.rawValue.sqliteValue,
                record.payloadSummary.sqliteValue,
                record.createdAt.sqliteValue,
                record.updatedAt.sqliteValue
            ]
        )
    }

    public func updateUndoJournalState(
        commandID: UUID,
        state: UndoJournalEntryState,
        updatedAt: Date = Date()
    ) throws {
        try db.execute(
            "UPDATE undo_journal SET stack_state = ?, updated_at = ? WHERE command_id = ?;",
            bindings: [state.rawValue.sqliteValue, updatedAt.sqliteValue, commandID.sqliteValue]
        )
    }

    public func supersedeUndoneJournalEntries(updatedAt: Date = Date()) throws {
        try db.execute(
            "UPDATE undo_journal SET stack_state = ?, updated_at = ? WHERE stack_state = ?;",
            bindings: [
                UndoJournalEntryState.superseded.rawValue.sqliteValue,
                updatedAt.sqliteValue,
                UndoJournalEntryState.undone.rawValue.sqliteValue
            ]
        )
    }

    public func listUndoJournal(
        state: UndoJournalEntryState? = nil,
        limit: Int = 200
    ) throws -> [UndoJournalRecord] {
        let clamped = max(0, limit)
        guard clamped > 0 else { return [] }
        let rows: [SQLiteRow]
        if let state {
            rows = try db.query(
                """
                SELECT sequence_id, command_id, command_type, title, stack_state, payload_summary, created_at, updated_at
                FROM undo_journal
                WHERE stack_state = ?
                ORDER BY sequence_id DESC
                LIMIT ?;
                """,
                bindings: [state.rawValue.sqliteValue, clamped.sqliteValue]
            )
        } else {
            rows = try db.query(
                """
                SELECT sequence_id, command_id, command_type, title, stack_state, payload_summary, created_at, updated_at
                FROM undo_journal
                ORDER BY sequence_id DESC
                LIMIT ?;
                """,
                bindings: [clamped.sqliteValue]
            )
        }
        return try rows.map { row in
            UndoJournalRecord(
                sequenceID: try row.int64("sequence_id"),
                commandID: try row.uuid("command_id"),
                commandType: try row.string("command_type"),
                title: try row.string("title"),
                state: UndoJournalEntryState(rawValue: try row.string("stack_state")) ?? .applied,
                payloadSummary: try row.string("payload_summary"),
                createdAt: try row.date("created_at"),
                updatedAt: try row.date("updated_at")
            )
        }
    }

    public func clearUndoJournal() throws {
        try db.execute("DELETE FROM undo_journal;")
    }

    // MARK: v4 Base Image Cache Index Persistence (image_cache_entries)

    public func upsertCachedImageRecord(_ record: CachedImageIndexRecord) throws {
        let entryJSON = try encodeCompactJSONString(record.entry, context: "BaseImageCatalogEntry")
        try db.execute(
            """
            INSERT INTO image_cache_entries (
                image_id, display_name, distribution, version, guest_os,
                local_path, sha256_hex, physical_bytes, virtual_bytes,
                is_custom_offline, verified_at, last_accessed_at, access_count, entry_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(image_id) DO UPDATE SET
                display_name = excluded.display_name,
                distribution = excluded.distribution,
                version = excluded.version,
                guest_os = excluded.guest_os,
                local_path = excluded.local_path,
                sha256_hex = excluded.sha256_hex,
                physical_bytes = excluded.physical_bytes,
                virtual_bytes = excluded.virtual_bytes,
                is_custom_offline = excluded.is_custom_offline,
                verified_at = excluded.verified_at,
                last_accessed_at = excluded.last_accessed_at,
                access_count = excluded.access_count,
                entry_json = excluded.entry_json;
            """,
            bindings: [
                record.entry.id.sqliteValue,
                record.entry.displayName.sqliteValue,
                record.entry.distribution.sqliteValue,
                record.entry.version.sqliteValue,
                record.entry.guestOS.rawValue.sqliteValue,
                record.localPath.sqliteValue,
                record.sha512Hex.sqliteValue,
                record.physicalBytes.sqliteValue,
                record.virtualBytes.sqliteValue,
                record.isCustomOffline.sqliteValue,
                record.verifiedAt.sqliteValue,
                record.lastAccessedAt.sqliteValue,
                record.accessCount.sqliteValue,
                entryJSON.sqliteValue
            ]
        )
    }

    public func listCachedImageRecords() throws -> [CachedImageIndexRecord] {
        let rows = try db.query(
            """
            SELECT
                local_path, sha256_hex, physical_bytes, virtual_bytes,
                is_custom_offline, verified_at, last_accessed_at, access_count, entry_json
            FROM image_cache_entries
            ORDER BY last_accessed_at DESC, image_id ASC;
            """
        )
        return try rows.map { row in
            let entry = try row.json(BaseImageCatalogEntry.self, column: "entry_json", decoder: jsonDecoder)
            let localPath = try row.string("local_path")
            let physicalBytes = try row.uint64("physical_bytes")
            return CachedImageIndexRecord(
                entry: entry,
                localPath: localPath,
                sha512Hex: try row.string("sha256_hex"),
                logicalBytes: entry.expectedSizeBytes ?? physicalBytes,
                physicalBytes: physicalBytes,
                virtualBytes: try row.uint64("virtual_bytes"),
                isCustomOffline: try row.bool("is_custom_offline"),
                verifiedAt: try row.date("verified_at"),
                lastAccessedAt: try row.date("last_accessed_at"),
                accessCount: try row.int("access_count")
            )
        }
    }

    public func deleteCachedImageRecord(_ imageID: String) throws {
        try db.execute("DELETE FROM image_cache_entries WHERE image_id = ?;", bindings: [imageID.sqliteValue])
    }

    // MARK: v4 Port Forward Audit Persistence (port_forward_audit)

    public func appendPortForwardAudit(_ entry: PortForwardAuditEntry) throws {
        try db.execute(
            """
            INSERT INTO port_forward_audit (
                id, vm_id, rule_id, protocol_type, host_bind_address,
                host_port, guest_port, vsock_cid, event_kind, bytes_relayed, detail, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                bytes_relayed = excluded.bytes_relayed,
                detail = excluded.detail,
                timestamp = excluded.timestamp;
            """,
            bindings: [
                entry.id.sqliteValue,
                entry.vmID.sqliteValue,
                entry.ruleID.sqliteValue,
                entry.protocolType.rawValue.sqliteValue,
                entry.hostBindAddress.sqliteValue,
                entry.hostPort.sqliteValue,
                entry.guestPort.sqliteValue,
                entry.vsockCID.sqliteValue,
                entry.eventKind.rawValue.sqliteValue,
                entry.bytesRelayed.sqliteValue,
                entry.detail.sqliteValue,
                entry.timestamp.sqliteValue
            ]
        )
    }

    public func listPortForwardAudits(
        vmID: VMID? = nil,
        limit: Int = 200
    ) throws -> [PortForwardAuditEntry] {
        let clamped = max(0, limit)
        guard clamped > 0 else { return [] }
        let rows: [SQLiteRow]
        if let vmID {
            rows = try db.query(
                """
                SELECT
                    id, vm_id, rule_id, protocol_type, host_bind_address,
                    host_port, guest_port, vsock_cid, event_kind, bytes_relayed, detail, timestamp
                FROM port_forward_audit
                WHERE vm_id = ?
                ORDER BY timestamp DESC, id ASC
                LIMIT ?;
                """,
                bindings: [vmID.sqliteValue, clamped.sqliteValue]
            )
        } else {
            rows = try db.query(
                """
                SELECT
                    id, vm_id, rule_id, protocol_type, host_bind_address,
                    host_port, guest_port, vsock_cid, event_kind, bytes_relayed, detail, timestamp
                FROM port_forward_audit
                ORDER BY timestamp DESC, id ASC
                LIMIT ?;
                """,
                bindings: [clamped.sqliteValue]
            )
        }
        return try rows.map { row in
            PortForwardAuditEntry(
                id: try row.uuid("id"),
                vmID: VMID(try row.string("vm_id")),
                ruleID: PortForwardID(try row.string("rule_id")),
                protocolType: PortForwardProtocol(rawValue: try row.string("protocol_type")) ?? .tcp,
                hostBindAddress: try row.string("host_bind_address"),
                hostPort: try row.uint16("host_port"),
                guestPort: try row.uint16("guest_port"),
                vsockCID: try row.uint32("vsock_cid"),
                eventKind: PortForwardAuditEventKind(rawValue: try row.string("event_kind")) ?? .bound,
                bytesRelayed: try row.uint64("bytes_relayed"),
                detail: try row.string("detail"),
                timestamp: try row.date("timestamp")
            )
        }
    }

    // MARK: Internal Filesystem Helpers

    private struct DirectoryScanMetrics {
        var fileCount: Int = 0
        var logicalBytes: UInt64 = 0
        var physicalBytes: UInt64 = 0
    }

    private static func scanDirectoryMetrics(at directoryURL: URL) -> DirectoryScanMetrics {
        let fm = FileManager.default
        guard fm.fileExists(atPath: directoryURL.path) else {
            return DirectoryScanMetrics()
        }
        let keys: [URLResourceKey] = [
            .isRegularFileKey,
            .isHiddenKey,
            .fileSizeKey,
            .totalFileAllocatedSizeKey,
            .fileAllocatedSizeKey
        ]
        guard let enumerator = fm.enumerator(
            at: directoryURL,
            includingPropertiesForKeys: keys,
            options: [.skipsPackageDescendants]
        ) else {
            return DirectoryScanMetrics()
        }

        var metrics = DirectoryScanMetrics()
        for case let fileURL as URL in enumerator {
            if fileURL.lastPathComponent == ".DS_Store" {
                continue
            }
            guard let values = try? fileURL.resourceValues(forKeys: Set(keys)),
                  values.isRegularFile == true else {
                continue
            }
            metrics.fileCount += 1
            let logical = UInt64(max(0, values.fileSize ?? 0))
            let allocated = UInt64(max(0, values.totalFileAllocatedSize ?? values.fileAllocatedSize ?? values.fileSize ?? 0))
            metrics.logicalBytes &+= logical
            metrics.physicalBytes &+= allocated
        }
        return metrics
    }

    internal nonisolated func resolveBundleRelativePath(_ rawPath: String) -> URL {
        let expanded = (rawPath as NSString).expandingTildeInPath
        if expanded.hasPrefix("/") {
            return URL(fileURLWithPath: expanded).standardizedFileURL
        }
        return bundleURL.appendingPathComponent(expanded, isDirectory: false).standardizedFileURL
    }
}
