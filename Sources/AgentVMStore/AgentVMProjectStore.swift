import AgentVMModels
import Foundation

// MARK: - Persistent Workspace Bundle Store (.agentvm)

public actor AgentVMProjectStore {
    public static let activeLayoutSlotKey = "active"

    public nonisolated let bundleURL: URL

    public nonisolated var disksDirectoryURL: URL {
        bundleURL.appendingPathComponent("disks", isDirectory: true)
    }

    public nonisolated var snapshotsDirectoryURL: URL {
        bundleURL.appendingPathComponent("snapshots", isDirectory: true)
    }

    public nonisolated var pcapDirectoryURL: URL {
        bundleURL.appendingPathComponent("pcap", isDirectory: true)
    }

    public nonisolated var isosDirectoryURL: URL {
        bundleURL.appendingPathComponent("isos", isDirectory: true)
    }

    public nonisolated var logsDirectoryURL: URL {
        bundleURL.appendingPathComponent("logs", isDirectory: true)
    }

    public nonisolated var locksDirectoryURL: URL {
        bundleURL.appendingPathComponent("locks", isDirectory: true)
    }

    public nonisolated var manifestFileURL: URL {
        bundleURL.appendingPathComponent("manifest.json", isDirectory: false)
    }

    public nonisolated var databaseFileURL: URL {
        bundleURL.appendingPathComponent("state.sqlite", isDirectory: false)
    }

    internal let db: SQLiteWALDatabase
    internal let jsonEncoder: JSONEncoder
    internal let compactEncoder: JSONEncoder
    internal let jsonDecoder: JSONDecoder

    public init(bundleURL: URL, createIfMissing: Bool = true) throws {
        let standardized = bundleURL.standardizedFileURL
        self.bundleURL = standardized

        let prettyEncoder = JSONEncoder()
        prettyEncoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        self.jsonEncoder = prettyEncoder

        let denseEncoder = JSONEncoder()
        denseEncoder.outputFormatting = [.sortedKeys]
        self.compactEncoder = denseEncoder

        self.jsonDecoder = JSONDecoder()

        let fm = FileManager.default
        var isDir: ObjCBool = false
        let bundleExists = fm.fileExists(atPath: standardized.path, isDirectory: &isDir)

        if bundleExists && !isDir.boolValue {
            throw AgentVMError.bundleIntegrityError(
                path: standardized.path,
                detail: "Expected directory for .agentvm workspace bundle, found regular file."
            )
        }

        if !bundleExists && !createIfMissing {
            throw AgentVMError.bundleIntegrityError(
                path: standardized.path,
                detail: "Workspace bundle directory does not exist and createIfMissing is false."
            )
        }

        let subdirs = [
            standardized.appendingPathComponent("disks", isDirectory: true),
            standardized.appendingPathComponent("snapshots", isDirectory: true),
            standardized.appendingPathComponent("pcap", isDirectory: true),
            standardized.appendingPathComponent("isos", isDirectory: true),
            standardized.appendingPathComponent("logs", isDirectory: true),
            standardized.appendingPathComponent("locks", isDirectory: true)
        ]

        if createIfMissing {
            do {
                try fm.createDirectory(at: standardized, withIntermediateDirectories: true)
                for dir in subdirs {
                    try fm.createDirectory(at: dir, withIntermediateDirectories: true)
                }
            } catch {
                throw AgentVMError.bundleIntegrityError(
                    path: standardized.path,
                    detail: "Failed initializing .agentvm directory hierarchy: \(error.localizedDescription)"
                )
            }
        }

        let manifestURL = standardized.appendingPathComponent("manifest.json", isDirectory: false)
        if !fm.fileExists(atPath: manifestURL.path) {
            if createIfMissing {
                let rawTitle = standardized.deletingPathExtension().lastPathComponent
                let resolvedTitle = rawTitle.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    ? "AgentVM Sandbox Fleet"
                    : rawTitle
                let initialManifest = AgentVMProjectManifest(title: resolvedTitle)
                do {
                    let encoded = try prettyEncoder.encode(initialManifest)
                    try encoded.write(to: manifestURL, options: [.atomic])
                } catch {
                    throw AgentVMError.bundleIntegrityError(
                        path: manifestURL.path,
                        detail: "Failed writing initial manifest.json: \(error.localizedDescription)"
                    )
                }
            } else {
                throw AgentVMError.bundleIntegrityError(
                    path: manifestURL.path,
                    detail: "Missing manifest.json inside existing .agentvm bundle."
                )
            }
        }

        let dbURL = standardized.appendingPathComponent("state.sqlite", isDirectory: false)
        if !createIfMissing && !fm.fileExists(atPath: dbURL.path) {
            throw AgentVMError.bundleIntegrityError(
                path: dbURL.path,
                detail: "Missing state.sqlite database inside existing .agentvm bundle."
            )
        }

        self.db = try SQLiteWALDatabase(fileURL: dbURL, runMigrations: true)
        try Self.ensureExecHistoryByteCountColumns(in: self.db)
        try Self.ensureSnapshotsPrivateBytesColumn(in: self.db)
    }

    private static func ensureSnapshotsPrivateBytesColumn(in db: SQLiteWALDatabase) throws {
        let cols = try db.query("PRAGMA table_info(snapshots);")
        let names = Set(try cols.map { try $0.string("name").lowercased() })
        if !names.contains("apfs_private_bytes") {
            do {
                try db.execute("ALTER TABLE snapshots ADD COLUMN apfs_private_bytes INTEGER;")
            } catch let err as AgentVMError {
                if !err.localizedMessage(in: .en).localizedCaseInsensitiveContains("duplicate column") {
                    throw err
                }
            }
        }
    }

    private static func ensureExecHistoryByteCountColumns(in db: SQLiteWALDatabase) throws {
        let cols = try db.query("PRAGMA table_info(exec_history);")
        let names = Set(try cols.map { try $0.string("name").lowercased() })
        if !names.contains("stdout_total_bytes") {
            do {
                try db.execute("ALTER TABLE exec_history ADD COLUMN stdout_total_bytes INTEGER;")
            } catch let err as AgentVMError {
                if !err.localizedMessage(in: .en).localizedCaseInsensitiveContains("duplicate column") {
                    throw err
                }
            }
        }
        if !names.contains("stderr_total_bytes") {
            do {
                try db.execute("ALTER TABLE exec_history ADD COLUMN stderr_total_bytes INTEGER;")
            } catch let err as AgentVMError {
                if !err.localizedMessage(in: .en).localizedCaseInsensitiveContains("duplicate column") {
                    throw err
                }
            }
        }
    }

    public func databaseJournalAndBusyTimeout() throws -> (journalMode: String, busyTimeoutMilliseconds: Int64) {
        let jmRow = try db.queryOne("PRAGMA journal_mode;")
        let btRow = try db.queryOne("PRAGMA busy_timeout;")
        let jmCol = jmRow?.columnNames.first ?? "journal_mode"
        let btCol = btRow?.columnNames.first ?? "timeout"
        let jm = (try jmRow?.optionalString(jmCol)) ?? ""
        let bt = (try btRow?.optionalInt64(btCol)) ?? 0
        return (jm, bt)
    }

    // MARK: - Project Manifest Persistence

    public func loadManifest() throws -> AgentVMProjectManifest {
        let data: Data
        do {
            data = try Data(contentsOf: manifestFileURL)
        } catch {
            throw AgentVMError.bundleIntegrityError(
                path: manifestFileURL.path,
                detail: "Unable to read manifest.json: \(error.localizedDescription)"
            )
        }
        do {
            return try jsonDecoder.decode(AgentVMProjectManifest.self, from: data)
        } catch {
            throw AgentVMError.bundleIntegrityError(
                path: manifestFileURL.path,
                detail: "Malformed manifest.json payload: \(error.localizedDescription)"
            )
        }
    }

    public func saveManifest(_ manifest: AgentVMProjectManifest) throws {
        do {
            let encoded = try jsonEncoder.encode(manifest)
            try encoded.write(to: manifestFileURL, options: [.atomic])
        } catch {
            throw AgentVMError.bundleIntegrityError(
                path: manifestFileURL.path,
                detail: "Failed saving manifest.json atomically: \(error.localizedDescription)"
            )
        }
    }

    // MARK: - Virtual Machine Fleet CRUD (v1: vms)

    public func upsertVM(_ record: VMInstanceRecord) throws {
        let specJSON = try encodeCompactJSONString(record.spec, context: "VMSpec")
        let telemetryJSON = try encodeCompactJSONString(record.telemetry, context: "VMLiveTelemetry")

        try db.execute(
            """
            INSERT INTO vms (
                id, name, agent_owner_tag, guest_os, lifecycle_state,
                vcpu_count, memory_mb, parent_vm_id, forked_from_snapshot_id,
                current_head_snapshot_id, spec_json, telemetry_json,
                last_booted_at, last_error_description, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                agent_owner_tag = excluded.agent_owner_tag,
                guest_os = excluded.guest_os,
                lifecycle_state = excluded.lifecycle_state,
                vcpu_count = excluded.vcpu_count,
                memory_mb = excluded.memory_mb,
                parent_vm_id = excluded.parent_vm_id,
                forked_from_snapshot_id = excluded.forked_from_snapshot_id,
                current_head_snapshot_id = excluded.current_head_snapshot_id,
                spec_json = excluded.spec_json,
                telemetry_json = excluded.telemetry_json,
                last_booted_at = excluded.last_booted_at,
                last_error_description = excluded.last_error_description,
                created_at = excluded.created_at,
                updated_at = excluded.updated_at;
            """,
            bindings: [
                record.id.sqliteValue,
                record.spec.name.sqliteValue,
                record.spec.agentOwnerTag.sqliteValue,
                record.spec.guestOS.rawValue.sqliteValue,
                record.telemetry.state.rawValue.sqliteValue,
                record.spec.compute.vcpuCount.sqliteValue,
                record.spec.compute.memoryMB.sqliteValue,
                record.spec.parentVMID.sqliteValue,
                record.spec.forkedFromSnapshotID.sqliteValue,
                record.currentHeadSnapshotID.sqliteValue,
                specJSON.sqliteValue,
                telemetryJSON.sqliteValue,
                record.lastBootedAt.sqliteValue,
                record.lastErrorDescription.sqliteValue,
                record.spec.createdAt.sqliteValue,
                record.spec.updatedAt.sqliteValue
            ]
        )
    }

    public func deleteVM(_ id: VMID) throws {
        try db.execute("DELETE FROM vms WHERE id = ?;", bindings: [id.sqliteValue])
    }

    public func fetchVM(_ id: VMID) throws -> VMInstanceRecord? {
        guard let row = try db.queryOne(
            """
            SELECT current_head_snapshot_id, spec_json, telemetry_json, last_booted_at, last_error_description
            FROM vms
            WHERE id = ?;
            """,
            bindings: [id.sqliteValue]
        ) else {
            return nil
        }
        return try decodeVMRow(row)
    }

    public func listVMs() throws -> [VMInstanceRecord] {
        let rows = try db.query(
            """
            SELECT current_head_snapshot_id, spec_json, telemetry_json, last_booted_at, last_error_description
            FROM vms
            ORDER BY created_at ASC, id ASC;
            """
        )
        return try rows.map(decodeVMRow)
    }

    private func decodeVMRow(_ row: SQLiteRow) throws -> VMInstanceRecord {
        let spec = try row.json(VMSpec.self, column: "spec_json", decoder: jsonDecoder)
        let telemetry = try row.json(VMLiveTelemetry.self, column: "telemetry_json", decoder: jsonDecoder)
        let headSnap = try row.optionalString("current_head_snapshot_id").map { SnapshotID($0) }
        let lastBooted = try row.optionalDate("last_booted_at")
        let lastError = try row.optionalString("last_error_description")
        return VMInstanceRecord(
            spec: spec,
            currentHeadSnapshotID: headSnap,
            telemetry: telemetry,
            lastBootedAt: lastBooted,
            lastErrorDescription: lastError
        )
    }

    // MARK: - Snapshot Lineage CRUD (v1: snapshots)

    public func upsertSnapshot(_ node: SnapshotNode) throws {
        let specJSON = try encodeCompactJSONString(node.specSnapshot, context: "SnapshotNode.specSnapshot")
        let tagsJSON = try encodeCompactJSONString(node.tags, context: "SnapshotNode.tags")

        try db.execute(
            """
            INSERT INTO snapshots (
                id, vm_id, parent_snapshot_id, branch_name, title, notes, kind,
                created_at, disk_clone_path, memory_state_path, virtual_disk_bytes,
                allocated_disk_bytes, dirty_delta_bytes, apfs_private_bytes, memory_state_bytes,
                spec_snapshot_json, agent_actor, trigger_command, is_pinned, tags_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                vm_id = excluded.vm_id,
                parent_snapshot_id = excluded.parent_snapshot_id,
                branch_name = excluded.branch_name,
                title = excluded.title,
                notes = excluded.notes,
                kind = excluded.kind,
                created_at = excluded.created_at,
                disk_clone_path = excluded.disk_clone_path,
                memory_state_path = excluded.memory_state_path,
                virtual_disk_bytes = excluded.virtual_disk_bytes,
                allocated_disk_bytes = excluded.allocated_disk_bytes,
                dirty_delta_bytes = excluded.dirty_delta_bytes,
                apfs_private_bytes = excluded.apfs_private_bytes,
                memory_state_bytes = excluded.memory_state_bytes,
                spec_snapshot_json = excluded.spec_snapshot_json,
                agent_actor = excluded.agent_actor,
                trigger_command = excluded.trigger_command,
                is_pinned = excluded.is_pinned,
                tags_json = excluded.tags_json;
            """,
            bindings: [
                node.id.sqliteValue,
                node.vmID.sqliteValue,
                node.parentSnapshotID.sqliteValue,
                node.branchName.sqliteValue,
                node.title.sqliteValue,
                node.notes.sqliteValue,
                node.kind.rawValue.sqliteValue,
                node.createdAt.sqliteValue,
                node.diskClonePath.sqliteValue,
                node.memoryStatePath.sqliteValue,
                node.virtualDiskBytes.sqliteValue,
                node.allocatedDiskBytes.sqliteValue,
                node.apfsPrivateBytes.sqliteValue,
                node.apfsPrivateBytes.sqliteValue,
                node.memoryStateBytes.sqliteValue,
                specJSON.sqliteValue,
                node.agentActor.sqliteValue,
                node.triggerCommand.sqliteValue,
                node.isPinned.sqliteValue,
                tagsJSON.sqliteValue
            ]
        )
    }

    public func deleteSnapshot(_ id: SnapshotID) throws {
        try db.execute("DELETE FROM snapshots WHERE id = ?;", bindings: [id.sqliteValue])
    }

    public func fetchSnapshot(_ id: SnapshotID) throws -> SnapshotNode? {
        guard let row = try db.queryOne(
            """
            SELECT
                id, vm_id, parent_snapshot_id, branch_name, title, notes, kind,
                created_at, disk_clone_path, memory_state_path, virtual_disk_bytes,
                allocated_disk_bytes, dirty_delta_bytes, apfs_private_bytes, memory_state_bytes,
                spec_snapshot_json, agent_actor, trigger_command, is_pinned, tags_json
            FROM snapshots
            WHERE id = ?;
            """,
            bindings: [id.sqliteValue]
        ) else {
            return nil
        }
        return try decodeSnapshotRow(row)
    }

    public func listSnapshots(forVM vmID: VMID? = nil) throws -> [SnapshotNode] {
        let rows: [SQLiteRow]
        if let vmID {
            rows = try db.query(
                """
                SELECT
                    id, vm_id, parent_snapshot_id, branch_name, title, notes, kind,
                    created_at, disk_clone_path, memory_state_path, virtual_disk_bytes,
                    allocated_disk_bytes, dirty_delta_bytes, apfs_private_bytes, memory_state_bytes,
                    spec_snapshot_json, agent_actor, trigger_command, is_pinned, tags_json
                FROM snapshots
                WHERE vm_id = ?
                ORDER BY created_at ASC, id ASC;
                """,
                bindings: [vmID.sqliteValue]
            )
        } else {
            rows = try db.query(
                """
                SELECT
                    id, vm_id, parent_snapshot_id, branch_name, title, notes, kind,
                    created_at, disk_clone_path, memory_state_path, virtual_disk_bytes,
                    allocated_disk_bytes, dirty_delta_bytes, apfs_private_bytes, memory_state_bytes,
                    spec_snapshot_json, agent_actor, trigger_command, is_pinned, tags_json
                FROM snapshots
                ORDER BY created_at ASC, id ASC;
                """
            )
        }
        return try rows.map(decodeSnapshotRow)
    }

    private func decodeSnapshotRow(_ row: SQLiteRow) throws -> SnapshotNode {
        let rawKind = try row.string("kind")
        let kind = SnapshotKind(rawValue: rawKind) ?? .coldDiskOnly
        let spec = try row.json(VMSpec.self, column: "spec_snapshot_json", decoder: jsonDecoder)
        let tags = try row.optionalJSON([String].self, column: "tags_json", decoder: jsonDecoder) ?? []
        let privateBytes: UInt64
        if row.hasColumn("apfs_private_bytes"), let explicitPriv = try row.optionalUInt64("apfs_private_bytes") {
            privateBytes = explicitPriv
        } else {
            privateBytes = try row.uint64("dirty_delta_bytes")
        }
        return SnapshotNode(
            id: SnapshotID(try row.string("id")),
            vmID: VMID(try row.string("vm_id")),
            parentSnapshotID: try row.optionalString("parent_snapshot_id").map { SnapshotID($0) },
            branchName: try row.string("branch_name"),
            title: try row.string("title"),
            notes: try row.string("notes"),
            kind: kind,
            createdAt: try row.date("created_at"),
            diskClonePath: try row.string("disk_clone_path"),
            memoryStatePath: try row.optionalString("memory_state_path"),
            virtualDiskBytes: try row.uint64("virtual_disk_bytes"),
            allocatedDiskBytes: try row.uint64("allocated_disk_bytes"),
            apfsPrivateBytes: privateBytes,
            memoryStateBytes: try row.uint64("memory_state_bytes"),
            specSnapshot: spec,
            agentActor: try row.string("agent_actor"),
            triggerCommand: try row.optionalString("trigger_command"),
            isPinned: try row.bool("is_pinned"),
            tags: tags
        )
    }

    // MARK: - Firewall Policy Sets CRUD (v1: firewall_policies)

    public func upsertFirewallPolicy(_ policy: FirewallPolicySet) throws {
        let rulesJSON = try encodeCompactJSONString(policy.rules, context: "FirewallPolicySet.rules")
        try db.execute(
            """
            INSERT INTO firewall_policies (
                id, name, summary, default_egress_verdict, default_ingress_verdict,
                block_private_metadata_ips, rules_json, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                summary = excluded.summary,
                default_egress_verdict = excluded.default_egress_verdict,
                default_ingress_verdict = excluded.default_ingress_verdict,
                block_private_metadata_ips = excluded.block_private_metadata_ips,
                rules_json = excluded.rules_json,
                updated_at = excluded.updated_at;
            """,
            bindings: [
                policy.id.sqliteValue,
                policy.name.sqliteValue,
                policy.summary.sqliteValue,
                policy.defaultEgressVerdict.rawValue.sqliteValue,
                policy.defaultIngressVerdict.rawValue.sqliteValue,
                policy.blockPrivateMetadataIPs.sqliteValue,
                rulesJSON.sqliteValue,
                policy.updatedAt.sqliteValue
            ]
        )
    }

    public func deleteFirewallPolicy(_ id: PolicySetID) throws {
        try db.execute("DELETE FROM firewall_policies WHERE id = ?;", bindings: [id.sqliteValue])
    }

    public func fetchFirewallPolicy(_ id: PolicySetID) throws -> FirewallPolicySet? {
        guard let row = try db.queryOne(
            """
            SELECT
                id, name, summary, default_egress_verdict, default_ingress_verdict,
                block_private_metadata_ips, rules_json, updated_at
            FROM firewall_policies
            WHERE id = ?;
            """,
            bindings: [id.sqliteValue]
        ) else {
            return nil
        }
        return try decodeFirewallPolicyRow(row)
    }

    public func listFirewallPolicies() throws -> [FirewallPolicySet] {
        let rows = try db.query(
            """
            SELECT
                id, name, summary, default_egress_verdict, default_ingress_verdict,
                block_private_metadata_ips, rules_json, updated_at
            FROM firewall_policies
            ORDER BY name ASC, id ASC;
            """
        )
        return try rows.map(decodeFirewallPolicyRow)
    }

    public func seedDefaultFirewallPresetsIfNeeded() throws {
        let presets = [
            FirewallPolicySet.strictAgentAllowlistPreset(),
            FirewallPolicySet.airgappedPreset()
        ]
        for preset in presets {
            if try fetchFirewallPolicy(preset.id) == nil {
                try upsertFirewallPolicy(preset)
            }
        }
    }

    private func decodeFirewallPolicyRow(_ row: SQLiteRow) throws -> FirewallPolicySet {
        let egress = FirewallVerdict(rawValue: try row.string("default_egress_verdict")) ?? .drop
        let ingress = FirewallVerdict(rawValue: try row.string("default_ingress_verdict")) ?? .allow
        let rules = try row.json([FirewallRule].self, column: "rules_json", decoder: jsonDecoder)
        return FirewallPolicySet(
            id: PolicySetID(try row.string("id")),
            name: try row.string("name"),
            summary: try row.string("summary"),
            defaultEgressVerdict: egress,
            defaultIngressVerdict: ingress,
            blockPrivateMetadataIPs: try row.bool("block_private_metadata_ips"),
            rules: rules,
            updatedAt: try row.date("updated_at")
        )
    }

    // MARK: - Network Flow Telemetry Ledger (v2: network_flows)

    public func appendNetworkFlow(_ flow: NetworkFlowRecord) throws {
        try db.execute(
            """
            INSERT INTO network_flows (
                id, vm_id, transport, source_ip, source_port, destination_ip, destination_port,
                resolved_domain_or_sni, tcp_state, packets_sent, packets_received,
                bytes_sent, bytes_received, verdict, matched_rule_id, first_seen_at, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                vm_id = excluded.vm_id,
                transport = excluded.transport,
                source_ip = excluded.source_ip,
                source_port = excluded.source_port,
                destination_ip = excluded.destination_ip,
                destination_port = excluded.destination_port,
                resolved_domain_or_sni = excluded.resolved_domain_or_sni,
                tcp_state = excluded.tcp_state,
                packets_sent = excluded.packets_sent,
                packets_received = excluded.packets_received,
                bytes_sent = excluded.bytes_sent,
                bytes_received = excluded.bytes_received,
                verdict = excluded.verdict,
                matched_rule_id = excluded.matched_rule_id,
                first_seen_at = excluded.first_seen_at,
                timestamp = excluded.timestamp;
            """,
            bindings: [
                flow.id.sqliteValue,
                flow.tuple.vmID.sqliteValue,
                flow.tuple.transport.rawValue.sqliteValue,
                flow.tuple.sourceIP.sqliteValue,
                flow.tuple.sourcePort.sqliteValue,
                flow.tuple.destinationIP.sqliteValue,
                flow.tuple.destinationPort.sqliteValue,
                flow.resolvedDomainOrSNI.sqliteValue,
                flow.tcpState?.rawValue.sqliteValue ?? .null,
                flow.packetsSent.sqliteValue,
                flow.packetsReceived.sqliteValue,
                flow.bytesSent.sqliteValue,
                flow.bytesReceived.sqliteValue,
                flow.verdict.rawValue.sqliteValue,
                flow.matchedRuleID.sqliteValue,
                flow.firstSeenAt.sqliteValue,
                flow.lastSeenAt.sqliteValue
            ]
        )
    }

    public func listNetworkFlows(vmID: VMID? = nil, limit: Int = 500) throws -> [NetworkFlowRecord] {
        let clampedLimit = max(0, limit)
        guard clampedLimit > 0 else { return [] }
        let rows: [SQLiteRow]
        if let vmID {
            rows = try db.query(
                """
                SELECT
                    id, vm_id, transport, source_ip, source_port, destination_ip, destination_port,
                    resolved_domain_or_sni, tcp_state, packets_sent, packets_received,
                    bytes_sent, bytes_received, verdict, matched_rule_id, first_seen_at, timestamp
                FROM network_flows
                WHERE vm_id = ?
                ORDER BY timestamp DESC, id ASC
                LIMIT ?;
                """,
                bindings: [vmID.sqliteValue, clampedLimit.sqliteValue]
            )
        } else {
            rows = try db.query(
                """
                SELECT
                    id, vm_id, transport, source_ip, source_port, destination_ip, destination_port,
                    resolved_domain_or_sni, tcp_state, packets_sent, packets_received,
                    bytes_sent, bytes_received, verdict, matched_rule_id, first_seen_at, timestamp
                FROM network_flows
                ORDER BY timestamp DESC, id ASC
                LIMIT ?;
                """,
                bindings: [clampedLimit.sqliteValue]
            )
        }
        return try rows.map(decodeNetworkFlowRow)
    }

    private func decodeNetworkFlowRow(_ row: SQLiteRow) throws -> NetworkFlowRecord {
        let proto = DissectedProtocolKind(rawValue: try row.string("transport")) ?? .unknown
        let tuple = NetworkFlow5Tuple(
            vmID: VMID(try row.string("vm_id")),
            transport: proto,
            sourceIP: try row.string("source_ip"),
            sourcePort: try row.uint16("source_port"),
            destinationIP: try row.string("destination_ip"),
            destinationPort: try row.uint16("destination_port")
        )
        let tcpState = try row.optionalString("tcp_state").flatMap(TCPFlowLifecycleState.init(rawValue:))
        let verdict = FirewallVerdict(rawValue: try row.string("verdict")) ?? .allow
        return NetworkFlowRecord(
            id: FlowID(try row.string("id")),
            tuple: tuple,
            resolvedDomainOrSNI: try row.optionalString("resolved_domain_or_sni"),
            tcpState: tcpState,
            packetsSent: try row.uint64("packets_sent"),
            packetsReceived: try row.uint64("packets_received"),
            bytesSent: try row.uint64("bytes_sent"),
            bytesReceived: try row.uint64("bytes_received"),
            verdict: verdict,
            matchedRuleID: try row.optionalString("matched_rule_id").map { RuleID($0) },
            firstSeenAt: try row.date("first_seen_at"),
            lastSeenAt: try row.date("timestamp")
        )
    }

    // MARK: - Structured Diagnostic Events Ledger (v2: diagnostics)

    public func appendDiagnostic(_ event: DiagnosticEvent) throws {
        let metadataJSON = try encodeCompactJSONString(event.metadata, context: "DiagnosticEvent.metadata")
        try db.execute(
            """
            INSERT INTO diagnostics (
                id, vm_id, timestamp, severity, severity_rank, subsystem, code, message, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                vm_id = excluded.vm_id,
                timestamp = excluded.timestamp,
                severity = excluded.severity,
                severity_rank = excluded.severity_rank,
                subsystem = excluded.subsystem,
                code = excluded.code,
                message = excluded.message,
                metadata_json = excluded.metadata_json;
            """,
            bindings: [
                event.id.sqliteValue,
                event.vmID.sqliteValue,
                event.timestamp.sqliteValue,
                event.severity.rawValue.sqliteValue,
                Self.severityRank(for: event.severity).sqliteValue,
                event.subsystem.sqliteValue,
                event.code.sqliteValue,
                event.message.sqliteValue,
                metadataJSON.sqliteValue
            ]
        )
    }

    public func listDiagnostics(
        vmID: VMID? = nil,
        minSeverity: DiagnosticSeverity? = nil,
        limit: Int = 500
    ) throws -> [DiagnosticEvent] {
        let clampedLimit = max(0, limit)
        guard clampedLimit > 0 else { return [] }

        var clauses: [String] = []
        var bindings: [SQLiteValue] = []
        if let vmID {
            clauses.append("vm_id = ?")
            bindings.append(vmID.sqliteValue)
        }
        if let minSeverity {
            clauses.append("severity_rank >= ?")
            bindings.append(Self.severityRank(for: minSeverity).sqliteValue)
        }
        bindings.append(clampedLimit.sqliteValue)

        let whereSQL = clauses.isEmpty ? "" : "WHERE " + clauses.joined(separator: " AND ")
        let rows = try db.query(
            """
            SELECT id, vm_id, timestamp, severity, subsystem, code, message, metadata_json
            FROM diagnostics
            \(whereSQL)
            ORDER BY timestamp DESC, id ASC
            LIMIT ?;
            """,
            bindings: bindings
        )
        return try rows.map(decodeDiagnosticRow)
    }

    /// Atomically transitions a non-simulated `running` VM record to `stopped` and appends a single
    /// `VM_RUNTIME_LOST` diagnostic inside one `BEGIN IMMEDIATE` transaction so concurrent reconcilers
    /// (`ps`, `daemon run`) never emit duplicate diagnostics for the same interruption.
    public func reconcileLostRunningVM(
        vmID: VMID,
        diagnostic: DiagnosticEvent
    ) throws -> (record: VMInstanceRecord?, didReconcile: Bool) {
        try db.inTransaction(mode: .immediate) {
            guard var current = try fetchVM(vmID) else {
                return (nil, false)
            }
            guard current.telemetry.state == .running, !current.telemetry.simulated else {
                return (current, false)
            }
            current.telemetry.state = .stopped
            current.telemetry.simulated = false
            current.telemetry.guestAgentConnected = false
            current.telemetry.hasLiveGuestTelemetry = false
            current.telemetry.vsockStreamsOpen = 0
            current.telemetry.cpuUsagePercent = nil
            current.telemetry.memoryResidentMB = 0
            current.telemetry.guestMemTotalBytes = nil
            current.telemetry.guestMemAvailableBytes = nil
            current.telemetry.guestAgentVersion = nil
            try upsertVM(current)
            try appendDiagnostic(diagnostic)
            return (current, true)
        }
    }

    private func decodeDiagnosticRow(_ row: SQLiteRow) throws -> DiagnosticEvent {
        let severity = DiagnosticSeverity(rawValue: try row.string("severity")) ?? .info
        let metadata = try row.optionalJSON([String: String].self, column: "metadata_json", decoder: jsonDecoder) ?? [:]
        return DiagnosticEvent(
            id: try row.uuid("id"),
            timestamp: try row.date("timestamp"),
            severity: severity,
            subsystem: try row.string("subsystem"),
            vmID: try row.optionalString("vm_id").map { VMID($0) },
            code: try row.string("code"),
            message: try row.string("message"),
            metadata: metadata
        )
    }

    private static func severityRank(for severity: DiagnosticSeverity) -> Int {
        switch severity {
        case .trace: return 0
        case .info: return 1
        case .notice: return 2
        case .warning: return 3
        case .error: return 4
        case .critical: return 5
        }
    }

    // MARK: - Guest Exec History Ledger (v2: exec_history)

    public func appendExecResult(_ result: GuestExecResult) throws {
        let cap = GuestExecResult.maxStoredOutputBytesPerStream
        let cappedStdout = result.stdoutData.count > cap ? Data(result.stdoutData.prefix(cap)) : result.stdoutData
        let cappedStderr = result.stderrData.count > cap ? Data(result.stderrData.prefix(cap)) : result.stderrData
        let stdoutTotal = max(UInt64(result.stdoutData.count), result.stdoutTotalBytes)
        let stderrTotal = max(UInt64(result.stderrData.count), result.stderrTotalBytes)

        try db.execute(
            """
            INSERT INTO exec_history (
                request_id, vm_id, timestamp, command_line, exit_code,
                stdout_data, stderr_data, stdout_total_bytes, stderr_total_bytes,
                duration_ms, timed_out, pre_checkpoint_snapshot_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(request_id) DO UPDATE SET
                vm_id = excluded.vm_id,
                timestamp = excluded.timestamp,
                command_line = excluded.command_line,
                exit_code = excluded.exit_code,
                stdout_data = excluded.stdout_data,
                stderr_data = excluded.stderr_data,
                stdout_total_bytes = excluded.stdout_total_bytes,
                stderr_total_bytes = excluded.stderr_total_bytes,
                duration_ms = excluded.duration_ms,
                timed_out = excluded.timed_out,
                pre_checkpoint_snapshot_id = excluded.pre_checkpoint_snapshot_id;
            """,
            bindings: [
                result.requestID.sqliteValue,
                result.vmID.sqliteValue,
                result.completedAt.sqliteValue,
                result.commandLine.sqliteValue,
                result.exitCode.sqliteValue,
                cappedStdout.sqliteValue,
                cappedStderr.sqliteValue,
                stdoutTotal.sqliteValue,
                stderrTotal.sqliteValue,
                result.durationMilliseconds.sqliteValue,
                result.timedOut.sqliteValue,
                result.preCheckpointSnapshotID.sqliteValue
            ]
        )
    }

    public func listExecResults(vmID: VMID? = nil, limit: Int = 200) throws -> [GuestExecResult] {
        let clampedLimit = max(0, limit)
        guard clampedLimit > 0 else { return [] }
        let rows: [SQLiteRow]
        if let vmID {
            rows = try db.query(
                """
                SELECT
                    request_id, vm_id, timestamp, command_line, exit_code,
                    stdout_data, stderr_data, stdout_total_bytes, stderr_total_bytes,
                    duration_ms, timed_out, pre_checkpoint_snapshot_id
                FROM exec_history
                WHERE vm_id = ?
                ORDER BY timestamp DESC, request_id ASC
                LIMIT ?;
                """,
                bindings: [vmID.sqliteValue, clampedLimit.sqliteValue]
            )
        } else {
            rows = try db.query(
                """
                SELECT
                    request_id, vm_id, timestamp, command_line, exit_code,
                    stdout_data, stderr_data, stdout_total_bytes, stderr_total_bytes,
                    duration_ms, timed_out, pre_checkpoint_snapshot_id
                FROM exec_history
                ORDER BY timestamp DESC, request_id ASC
                LIMIT ?;
                """,
                bindings: [clampedLimit.sqliteValue]
            )
        }
        return try rows.map(decodeExecResultRow)
    }

    private func decodeExecResultRow(_ row: SQLiteRow) throws -> GuestExecResult {
        let outData = try row.data("stdout_data")
        let errData = try row.data("stderr_data")
        let outTotal = try row.optionalUInt64("stdout_total_bytes") ?? UInt64(outData.count)
        let errTotal = try row.optionalUInt64("stderr_total_bytes") ?? UInt64(errData.count)
        return GuestExecResult(
            requestID: try row.uuid("request_id"),
            vmID: VMID(try row.string("vm_id")),
            commandLine: try row.string("command_line"),
            exitCode: try row.int32("exit_code"),
            stdoutData: outData,
            stderrData: errData,
            stdoutTotalBytes: outTotal,
            stderrTotalBytes: errTotal,
            durationMilliseconds: try row.int("duration_ms"),
            timedOut: try row.bool("timed_out"),
            preCheckpointSnapshotID: try row.optionalString("pre_checkpoint_snapshot_id").map { SnapshotID($0) },
            completedAt: try row.date("timestamp")
        )
    }

    // MARK: - Workbench Layout Persistence (v3: workspace_layouts)

    public func saveLayout(_ layout: WorkbenchLayoutSnapshot) throws {
        try saveNamedLayout(layout, slotKey: Self.activeLayoutSlotKey)
    }

    public func loadLayout() throws -> WorkbenchLayoutSnapshot? {
        try loadNamedLayout(slotKey: Self.activeLayoutSlotKey)
    }

    public func saveNamedLayout(_ layout: WorkbenchLayoutSnapshot, slotKey: String) throws {
        let normalizedSlot = slotKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? Self.activeLayoutSlotKey
            : slotKey
        let layoutJSON = try encodeCompactJSONString(layout, context: "WorkbenchLayoutSnapshot")
        try db.execute(
            """
            INSERT INTO workspace_layouts (slot_key, workspace_id, layout_json, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(slot_key) DO UPDATE SET
                workspace_id = excluded.workspace_id,
                layout_json = excluded.layout_json,
                updated_at = excluded.updated_at;
            """,
            bindings: [
                normalizedSlot.sqliteValue,
                layout.workspaceID.sqliteValue,
                layoutJSON.sqliteValue,
                Date().sqliteValue
            ]
        )
    }

    public func loadNamedLayout(slotKey: String) throws -> WorkbenchLayoutSnapshot? {
        guard let row = try db.queryOne(
            "SELECT layout_json FROM workspace_layouts WHERE slot_key = ?;",
            bindings: [slotKey.sqliteValue]
        ) else {
            return nil
        }
        return try row.json(WorkbenchLayoutSnapshot.self, column: "layout_json", decoder: jsonDecoder)
    }

    // MARK: - Sandboxed Plugin KV & Runtime State Store (v3: plugin_kv_store, plugin_runtime_state)

    public func setPluginKV(pluginID: PluginID, key: String, value: String) throws {
        try db.execute(
            """
            INSERT INTO plugin_kv_store (plugin_id, key, value, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(plugin_id, key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at;
            """,
            bindings: [
                pluginID.sqliteValue,
                key.sqliteValue,
                value.sqliteValue,
                Date().sqliteValue
            ]
        )
    }

    public func getPluginKV(pluginID: PluginID, key: String) throws -> String? {
        try db.queryScalarString(
            "SELECT value FROM plugin_kv_store WHERE plugin_id = ? AND key = ?;",
            bindings: [pluginID.sqliteValue, key.sqliteValue]
        )
    }

    public func listPluginKV(pluginID: PluginID) throws -> [String: String] {
        let rows = try db.query(
            "SELECT key, value FROM plugin_kv_store WHERE plugin_id = ? ORDER BY key ASC;",
            bindings: [pluginID.sqliteValue]
        )
        var kv: [String: String] = [:]
        kv.reserveCapacity(rows.count)
        for row in rows {
            kv[try row.string("key")] = try row.string("value")
        }
        return kv
    }

    public func deletePluginKV(pluginID: PluginID, key: String) throws {
        try db.execute(
            "DELETE FROM plugin_kv_store WHERE plugin_id = ? AND key = ?;",
            bindings: [pluginID.sqliteValue, key.sqliteValue]
        )
    }

    public func clearPluginKV(pluginID: PluginID) throws {
        try db.execute(
            "DELETE FROM plugin_kv_store WHERE plugin_id = ?;",
            bindings: [pluginID.sqliteValue]
        )
    }

    public func upsertPluginRuntimeStatus(_ status: PluginRuntimeStatus) throws {
        let grantedCapsJSON = try encodeCompactJSONString(
            Array(status.grantedCapabilities).sorted { $0.rawValue < $1.rawValue },
            context: "PluginRuntimeStatus.grantedCapabilities"
        )
        let configJSON = try encodeCompactJSONString(
            status.configurationValues,
            context: "PluginRuntimeStatus.configurationValues"
        )
        let manifestJSON = try encodeCompactJSONString(
            status.manifest,
            context: "PluginRuntimeStatus.manifest"
        )

        try db.execute(
            """
            INSERT INTO plugin_runtime_state (
                plugin_id, is_enabled, granted_capabilities_json, invocation_count,
                blocked_actions_count, average_duration_micros, last_error,
                last_invoked_at, configuration_json, manifest_json, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(plugin_id) DO UPDATE SET
                is_enabled = excluded.is_enabled,
                granted_capabilities_json = excluded.granted_capabilities_json,
                invocation_count = excluded.invocation_count,
                blocked_actions_count = excluded.blocked_actions_count,
                average_duration_micros = excluded.average_duration_micros,
                last_error = excluded.last_error,
                last_invoked_at = excluded.last_invoked_at,
                configuration_json = excluded.configuration_json,
                manifest_json = excluded.manifest_json,
                updated_at = excluded.updated_at;
            """,
            bindings: [
                status.id.sqliteValue,
                status.isEnabled.sqliteValue,
                grantedCapsJSON.sqliteValue,
                status.invocationCount.sqliteValue,
                status.blockedActionsCount.sqliteValue,
                status.averageDurationMicros.sqliteValue,
                status.lastError.sqliteValue,
                status.lastInvokedAt.sqliteValue,
                configJSON.sqliteValue,
                manifestJSON.sqliteValue,
                Date().sqliteValue
            ]
        )
    }

    public func fetchPluginRuntimeStatus(_ id: PluginID) throws -> PluginRuntimeStatus? {
        guard let row = try db.queryOne(
            """
            SELECT
                is_enabled, granted_capabilities_json, invocation_count,
                blocked_actions_count, average_duration_micros, last_error,
                last_invoked_at, configuration_json, manifest_json
            FROM plugin_runtime_state
            WHERE plugin_id = ?;
            """,
            bindings: [id.sqliteValue]
        ) else {
            return nil
        }
        return try decodePluginRuntimeRow(row)
    }

    public func listPluginRuntimeStatuses() throws -> [PluginRuntimeStatus] {
        let rows = try db.query(
            """
            SELECT
                is_enabled, granted_capabilities_json, invocation_count,
                blocked_actions_count, average_duration_micros, last_error,
                last_invoked_at, configuration_json, manifest_json
            FROM plugin_runtime_state
            ORDER BY plugin_id ASC;
            """
        )
        return try rows.map(decodePluginRuntimeRow)
    }

    public func deletePluginRuntimeStatus(_ id: PluginID) throws {
        try db.execute("DELETE FROM plugin_runtime_state WHERE plugin_id = ?;", bindings: [id.sqliteValue])
    }

    private func decodePluginRuntimeRow(_ row: SQLiteRow) throws -> PluginRuntimeStatus {
        let manifest = try row.json(PluginManifest.self, column: "manifest_json", decoder: jsonDecoder)
        let capsList = try row.json([PluginCapability].self, column: "granted_capabilities_json", decoder: jsonDecoder)
        let config = try row.optionalJSON([String: String].self, column: "configuration_json", decoder: jsonDecoder) ?? [:]
        return PluginRuntimeStatus(
            manifest: manifest,
            isEnabled: try row.bool("is_enabled"),
            grantedCapabilities: Set(capsList),
            invocationCount: try row.uint64("invocation_count"),
            blockedActionsCount: try row.uint64("blocked_actions_count"),
            averageDurationMicros: try row.uint64("average_duration_micros"),
            lastError: try row.optionalString("last_error"),
            lastInvokedAt: try row.optionalDate("last_invoked_at"),
            configurationValues: config
        )
    }

    // MARK: - Internal Serialization Helper

    internal func encodeCompactJSONString<T: Encodable>(_ value: T, context: String) throws -> String {
        do {
            let data = try compactEncoder.encode(value)
            return String(decoding: data, as: UTF8.self)
        } catch {
            throw AgentVMError.storageDatabaseError(
                code: -1,
                sql: "JSON_ENCODE(\(context))",
                detail: "Failed encoding \(context): \(error.localizedDescription)"
            )
        }
    }
}
