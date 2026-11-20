import Foundation

// MARK: - Snapshot Lineage & APFS Copy-on-Write Extent Models

public enum SnapshotKind: String, Codable, Hashable, Sendable, CaseIterable {
    case baseGoldenImage = "base-golden"
    case coldDiskOnly = "cold-disk"
    case liveDisk = "live-disk"
    case liveMemoryAndDisk = "live-ram-disk"
    case branchForkPoint = "cow-branch-fork"
    case autoPreCommandCheckpoint = "auto-pre-cmd"
    case budgetCircuitBreaker = "budget-breaker"

    public var displayName: String {
        switch self {
        case .baseGoldenImage: return "Golden Base"
        case .coldDiskOnly: return "Cold Disk Snapshot"
        case .liveDisk: return "Live Disk Snapshot"
        case .liveMemoryAndDisk: return "Live RAM + Disk"
        case .branchForkPoint: return "CoW Branch Fork"
        case .autoPreCommandCheckpoint: return "Pre-Exec Checkpoint"
        case .budgetCircuitBreaker: return "Circuit-Breaker Freeze"
        }
    }
}

public struct DiskFileSpaceMetrics: Codable, Hashable, Sendable {
    public var imagePath: String
    public var virtualSizeBytes: UInt64
    public var allocatedDiskBytes: UInt64
    /// Bytes private to this file and not shared with any other APFS clone (`ATTR_CMNEXT_PRIVATESIZE`).
    public var privateBytes: UInt64
    public var filesystemBlockSize: UInt32
    public var sampledAt: Date

    public init(
        imagePath: String,
        virtualSizeBytes: UInt64,
        allocatedDiskBytes: UInt64,
        privateBytes: UInt64,
        filesystemBlockSize: UInt32 = 4096,
        sampledAt: Date = Date()
    ) {
        self.imagePath = imagePath
        self.virtualSizeBytes = virtualSizeBytes
        self.allocatedDiskBytes = allocatedDiskBytes
        self.privateBytes = privateBytes
        self.filesystemBlockSize = filesystemBlockSize
        self.sampledAt = sampledAt
    }
}

public struct SnapshotNode: Codable, Hashable, Sendable, Identifiable {
    public var id: SnapshotID
    public var vmID: VMID
    public var parentSnapshotID: SnapshotID?
    public var branchName: String
    public var title: String
    public var notes: String
    public var kind: SnapshotKind
    public var createdAt: Date
    public var diskClonePath: String
    public var memoryStatePath: String?
    public var virtualDiskBytes: UInt64
    public var allocatedDiskBytes: UInt64
    /// Bytes on disk not shared with any other APFS clone (`ATTR_CMNEXT_PRIVATESIZE`).
    public var apfsPrivateBytes: UInt64
    public var memoryStateBytes: UInt64
    public var specSnapshot: VMSpec
    public var agentActor: String
    public var triggerCommand: String?
    public var isPinned: Bool
    public var tags: [String]

    /// Legacy Swift alias preserved for source compatibility with pre-M3 callers.
    public var dirtyDeltaBytes: UInt64 {
        get { apfsPrivateBytes }
        set { apfsPrivateBytes = newValue }
    }

    public init(
        id: SnapshotID = .generate(prefix: "snap"),
        vmID: VMID,
        parentSnapshotID: SnapshotID? = nil,
        branchName: String = "main",
        title: String,
        notes: String = "",
        kind: SnapshotKind = .coldDiskOnly,
        createdAt: Date = Date(),
        diskClonePath: String,
        memoryStatePath: String? = nil,
        virtualDiskBytes: UInt64,
        allocatedDiskBytes: UInt64,
        apfsPrivateBytes: UInt64? = nil,
        dirtyDeltaBytes: UInt64 = 0,
        memoryStateBytes: UInt64 = 0,
        specSnapshot: VMSpec,
        agentActor: String = "coordinator",
        triggerCommand: String? = nil,
        isPinned: Bool = false,
        tags: [String] = []
    ) {
        self.id = id
        self.vmID = vmID
        self.parentSnapshotID = parentSnapshotID
        self.branchName = branchName
        self.title = title
        self.notes = notes
        self.kind = kind
        self.createdAt = createdAt
        self.diskClonePath = diskClonePath
        self.memoryStatePath = memoryStatePath
        self.virtualDiskBytes = virtualDiskBytes
        self.allocatedDiskBytes = allocatedDiskBytes
        self.apfsPrivateBytes = apfsPrivateBytes ?? dirtyDeltaBytes
        self.memoryStateBytes = memoryStateBytes
        self.specSnapshot = specSnapshot
        self.agentActor = agentActor
        self.triggerCommand = triggerCommand
        self.isPinned = isPinned
        self.tags = tags
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case vmID
        case parentSnapshotID
        case branchName
        case title
        case notes
        case kind
        case createdAt
        case diskClonePath
        case memoryStatePath
        case virtualDiskBytes
        case allocatedDiskBytes
        case apfsPrivateBytes
        case dirtyDeltaBytes
        case memoryStateBytes
        case specSnapshot
        case agentActor
        case triggerCommand
        case isPinned
        case tags
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try container.decode(SnapshotID.self, forKey: .id)
        self.vmID = try container.decode(VMID.self, forKey: .vmID)
        self.parentSnapshotID = try container.decodeIfPresent(SnapshotID.self, forKey: .parentSnapshotID)
        self.branchName = try container.decodeIfPresent(String.self, forKey: .branchName) ?? "main"
        self.title = try container.decode(String.self, forKey: .title)
        self.notes = try container.decodeIfPresent(String.self, forKey: .notes) ?? ""
        let rawKind = try container.decode(String.self, forKey: .kind)
        self.kind = SnapshotKind(rawValue: rawKind) ?? .coldDiskOnly
        self.createdAt = try container.decode(Date.self, forKey: .createdAt)
        self.diskClonePath = try container.decode(String.self, forKey: .diskClonePath)
        self.memoryStatePath = try container.decodeIfPresent(String.self, forKey: .memoryStatePath)
        self.virtualDiskBytes = try container.decode(UInt64.self, forKey: .virtualDiskBytes)
        self.allocatedDiskBytes = try container.decodeIfPresent(UInt64.self, forKey: .allocatedDiskBytes) ?? 0
        let decodedPrivate = try container.decodeIfPresent(UInt64.self, forKey: .apfsPrivateBytes)
        let decodedLegacyDirty = try container.decodeIfPresent(UInt64.self, forKey: .dirtyDeltaBytes)
        self.apfsPrivateBytes = decodedPrivate ?? decodedLegacyDirty ?? 0
        self.memoryStateBytes = try container.decodeIfPresent(UInt64.self, forKey: .memoryStateBytes) ?? 0
        self.specSnapshot = try container.decode(VMSpec.self, forKey: .specSnapshot)
        self.agentActor = try container.decodeIfPresent(String.self, forKey: .agentActor) ?? "coordinator"
        self.triggerCommand = try container.decodeIfPresent(String.self, forKey: .triggerCommand)
        self.isPinned = try container.decodeIfPresent(Bool.self, forKey: .isPinned) ?? false
        self.tags = try container.decodeIfPresent([String].self, forKey: .tags) ?? []
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(vmID, forKey: .vmID)
        try container.encodeIfPresent(parentSnapshotID, forKey: .parentSnapshotID)
        try container.encode(branchName, forKey: .branchName)
        try container.encode(title, forKey: .title)
        try container.encode(notes, forKey: .notes)
        try container.encode(kind, forKey: .kind)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encode(diskClonePath, forKey: .diskClonePath)
        try container.encodeIfPresent(memoryStatePath, forKey: .memoryStatePath)
        try container.encode(virtualDiskBytes, forKey: .virtualDiskBytes)
        try container.encode(allocatedDiskBytes, forKey: .allocatedDiskBytes)
        try container.encode(apfsPrivateBytes, forKey: .apfsPrivateBytes)
        try container.encode(memoryStateBytes, forKey: .memoryStateBytes)
        try container.encode(specSnapshot, forKey: .specSnapshot)
        try container.encode(agentActor, forKey: .agentActor)
        try container.encodeIfPresent(triggerCommand, forKey: .triggerCommand)
        try container.encode(isPinned, forKey: .isPinned)
        try container.encode(tags, forKey: .tags)
    }

    public var hasLiveRAMState: Bool {
        memoryStatePath != nil && memoryStateBytes > 0
    }

    public var spaceSavingsPercent: Double {
        guard virtualDiskBytes > 0 else { return 0 }
        let used = min(virtualDiskBytes, apfsPrivateBytes > 0 ? apfsPrivateBytes : allocatedDiskBytes)
        return max(0.0, (1.0 - Double(used) / Double(virtualDiskBytes)) * 100.0)
    }
}

public enum SparseExtentKind: String, Codable, Hashable, Sendable, CaseIterable {
    case sparseHole = "hole"
    case allocatedClean = "shared-parent"
    case allocatedDirty = "cow-dirty"
}

public struct SparseExtent: Codable, Hashable, Sendable, Identifiable {
    public var id: String { "\(offsetBytes)-\(lengthBytes)-\(kind.rawValue)" }
    public var offsetBytes: UInt64
    public var lengthBytes: UInt64
    public var kind: SparseExtentKind
    public var checksumCRC32: UInt32?

    public init(
        offsetBytes: UInt64,
        lengthBytes: UInt64,
        kind: SparseExtentKind,
        checksumCRC32: UInt32? = nil
    ) {
        self.offsetBytes = offsetBytes
        self.lengthBytes = lengthBytes
        self.kind = kind
        self.checksumCRC32 = checksumCRC32
    }

    public var endOffsetBytes: UInt64 { offsetBytes + lengthBytes }
}

public struct DiskAllocationSummary: Codable, Hashable, Sendable {
    public var imagePath: String
    public var virtualSizeBytes: UInt64
    public var physicalAllocatedBytes: UInt64
    public var sparseHoleBytes: UInt64
    public var sharedWithParentBytes: UInt64
    public var uniqueDirtyBytes: UInt64
    public var filesystemBlockSize: UInt32
    public var extents: [SparseExtent]
    public var scannedAt: Date

    public init(
        imagePath: String,
        virtualSizeBytes: UInt64,
        physicalAllocatedBytes: UInt64,
        sparseHoleBytes: UInt64,
        sharedWithParentBytes: UInt64,
        uniqueDirtyBytes: UInt64,
        filesystemBlockSize: UInt32 = 4096,
        extents: [SparseExtent] = [],
        scannedAt: Date = Date()
    ) {
        self.imagePath = imagePath
        self.virtualSizeBytes = virtualSizeBytes
        self.physicalAllocatedBytes = physicalAllocatedBytes
        self.sparseHoleBytes = sparseHoleBytes
        self.sharedWithParentBytes = sharedWithParentBytes
        self.uniqueDirtyBytes = uniqueDirtyBytes
        self.filesystemBlockSize = filesystemBlockSize
        self.extents = extents
        self.scannedAt = scannedAt
    }

    public var allocationRatio: Double {
        guard virtualSizeBytes > 0 else { return 0 }
        return Double(physicalAllocatedBytes) / Double(virtualSizeBytes)
    }

    public var dirtyRatio: Double {
        guard virtualSizeBytes > 0 else { return 0 }
        return Double(uniqueDirtyBytes) / Double(virtualSizeBytes)
    }
}

public struct SnapshotConfigFieldDiff: Codable, Hashable, Sendable, Identifiable {
    public var id: String { fieldName }
    public var fieldName: String
    public var leftValue: String
    public var rightValue: String

    public init(fieldName: String, leftValue: String, rightValue: String) {
        self.fieldName = fieldName
        self.leftValue = leftValue
        self.rightValue = rightValue
    }
}

public struct SnapshotDiffReport: Codable, Hashable, Sendable {
    public var leftSnapshotID: SnapshotID
    public var rightSnapshotID: SnapshotID
    public var lowestCommonAncestorID: SnapshotID?
    public var ancestorDistanceLeft: Int
    public var ancestorDistanceRight: Int
    public var divergentBlockCount: Int
    public var divergentBytes: UInt64
    public var divergentExtents: [SparseExtent]
    public var configDiffs: [SnapshotConfigFieldDiff]
    public var computedAt: Date

    public init(
        leftSnapshotID: SnapshotID,
        rightSnapshotID: SnapshotID,
        lowestCommonAncestorID: SnapshotID?,
        ancestorDistanceLeft: Int,
        ancestorDistanceRight: Int,
        divergentBlockCount: Int,
        divergentBytes: UInt64,
        divergentExtents: [SparseExtent],
        configDiffs: [SnapshotConfigFieldDiff],
        computedAt: Date = Date()
    ) {
        self.leftSnapshotID = leftSnapshotID
        self.rightSnapshotID = rightSnapshotID
        self.lowestCommonAncestorID = lowestCommonAncestorID
        self.ancestorDistanceLeft = ancestorDistanceLeft
        self.ancestorDistanceRight = ancestorDistanceRight
        self.divergentBlockCount = divergentBlockCount
        self.divergentBytes = divergentBytes
        self.divergentExtents = divergentExtents
        self.configDiffs = configDiffs
        self.computedAt = computedAt
    }
}

public struct GarbageCollectionPolicy: Codable, Hashable, Sendable {
    public var keepMinimumPerBranch: Int
    public var maxUnpinnedAgeHours: Int
    public var preserveBranchForkPoints: Bool
    public var maxTotalSnapshotPoolBytes: UInt64

    public init(
        keepMinimumPerBranch: Int = 3,
        maxUnpinnedAgeHours: Int = 72,
        preserveBranchForkPoints: Bool = true,
        maxTotalSnapshotPoolBytes: UInt64 = 64 * 1024 * 1024 * 1024
    ) {
        self.keepMinimumPerBranch = keepMinimumPerBranch
        self.maxUnpinnedAgeHours = maxUnpinnedAgeHours
        self.preserveBranchForkPoints = preserveBranchForkPoints
        self.maxTotalSnapshotPoolBytes = maxTotalSnapshotPoolBytes
    }
}

public struct GarbageCollectionPlan: Codable, Hashable, Sendable {
    public var candidateSnapshotIDs: [SnapshotID]
    public var protectedSnapshotIDs: [SnapshotID]
    public var reclaimableDiskBytes: UInt64
    public var reclaimableMemoryStateBytes: UInt64
    public var reparentings: [SnapshotID: SnapshotID?]

    public init(
        candidateSnapshotIDs: [SnapshotID],
        protectedSnapshotIDs: [SnapshotID],
        reclaimableDiskBytes: UInt64,
        reclaimableMemoryStateBytes: UInt64,
        reparentings: [SnapshotID: SnapshotID?] = [:]
    ) {
        self.candidateSnapshotIDs = candidateSnapshotIDs
        self.protectedSnapshotIDs = protectedSnapshotIDs
        self.reclaimableDiskBytes = reclaimableDiskBytes
        self.reclaimableMemoryStateBytes = reclaimableMemoryStateBytes
        self.reparentings = reparentings
    }

    public var totalReclaimableBytes: UInt64 {
        reclaimableDiskBytes + reclaimableMemoryStateBytes
    }
}

// MARK: - Partition Table Metadata Models

public struct GPTPartitionEntrySummary: Codable, Hashable, Sendable, Identifiable {
    public var id: Int { index }
    public var index: Int
    public var typeGUID: String
    public var uniquePartitionGUID: String
    public var firstLBA: UInt64
    public var lastLBA: UInt64
    public var attributesFlags: UInt64
    public var name: String

    public init(
        index: Int,
        typeGUID: String,
        uniquePartitionGUID: String,
        firstLBA: UInt64,
        lastLBA: UInt64,
        attributesFlags: UInt64,
        name: String
    ) {
        self.index = index
        self.typeGUID = typeGUID
        self.uniquePartitionGUID = uniquePartitionGUID
        self.firstLBA = firstLBA
        self.lastLBA = lastLBA
        self.attributesFlags = attributesFlags
        self.name = name
    }

    public func sizeBytes(sectorSize: UInt64 = 512) -> UInt64 {
        guard lastLBA >= firstLBA else { return 0 }
        return (lastLBA - firstLBA + 1) * sectorSize
    }
}

public struct DiskContainerHeaderSummary: Codable, Hashable, Sendable {
    public var format: DiskImageFormat
    public var virtualSizeBytes: UInt64
    public var clusterOrSectorSize: UInt32
    public var backingFilePath: String?
    public var gptDiskGUID: String?
    public var partitions: [GPTPartitionEntrySummary]
    public var isoVolumeIdentifier: String?

    public init(
        format: DiskImageFormat,
        virtualSizeBytes: UInt64,
        clusterOrSectorSize: UInt32,
        backingFilePath: String? = nil,
        gptDiskGUID: String? = nil,
        partitions: [GPTPartitionEntrySummary] = [],
        isoVolumeIdentifier: String? = nil
    ) {
        self.format = format
        self.virtualSizeBytes = virtualSizeBytes
        self.clusterOrSectorSize = clusterOrSectorSize
        self.backingFilePath = backingFilePath
        self.gptDiskGUID = gptDiskGUID
        self.partitions = partitions
        self.isoVolumeIdentifier = isoVolumeIdentifier
    }
}
