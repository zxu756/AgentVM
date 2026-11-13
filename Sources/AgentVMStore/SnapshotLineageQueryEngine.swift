import AgentVMModels
import Foundation

// MARK: - Snapshot Lineage Graph Query Result Models

public struct SnapshotLCAResult: Codable, Hashable, Sendable {
    public var leftSnapshotID: SnapshotID
    public var rightSnapshotID: SnapshotID
    public var lowestCommonAncestorID: SnapshotID?
    public var distanceFromLeft: Int
    public var distanceFromRight: Int
    public var leftDivergentChain: [SnapshotNode]
    public var rightDivergentChain: [SnapshotNode]

    public init(
        leftSnapshotID: SnapshotID,
        rightSnapshotID: SnapshotID,
        lowestCommonAncestorID: SnapshotID?,
        distanceFromLeft: Int,
        distanceFromRight: Int,
        leftDivergentChain: [SnapshotNode],
        rightDivergentChain: [SnapshotNode]
    ) {
        self.leftSnapshotID = leftSnapshotID
        self.rightSnapshotID = rightSnapshotID
        self.lowestCommonAncestorID = lowestCommonAncestorID
        self.distanceFromLeft = distanceFromLeft
        self.distanceFromRight = distanceFromRight
        self.leftDivergentChain = leftDivergentChain
        self.rightDivergentChain = rightDivergentChain
    }
}

public struct SnapshotBranchSummary: Codable, Hashable, Sendable, Identifiable {
    public var id: String { branchName }
    public var branchName: String
    public var tipSnapshotID: SnapshotID
    public var leafSnapshotIDs: [SnapshotID]
    public var rootSnapshotID: SnapshotID
    public var forkOriginSnapshotID: SnapshotID?
    public var snapshotCount: Int
    public var pinnedCount: Int
    public var totalDirtyDeltaBytes: UInt64
    public var totalMemoryStateBytes: UInt64
    public var latestCreatedAt: Date

    public init(
        branchName: String,
        tipSnapshotID: SnapshotID,
        leafSnapshotIDs: [SnapshotID],
        rootSnapshotID: SnapshotID,
        forkOriginSnapshotID: SnapshotID?,
        snapshotCount: Int,
        pinnedCount: Int,
        totalDirtyDeltaBytes: UInt64,
        totalMemoryStateBytes: UInt64,
        latestCreatedAt: Date
    ) {
        self.branchName = branchName
        self.tipSnapshotID = tipSnapshotID
        self.leafSnapshotIDs = leafSnapshotIDs
        self.rootSnapshotID = rootSnapshotID
        self.forkOriginSnapshotID = forkOriginSnapshotID
        self.snapshotCount = snapshotCount
        self.pinnedCount = pinnedCount
        self.totalDirtyDeltaBytes = totalDirtyDeltaBytes
        self.totalMemoryStateBytes = totalMemoryStateBytes
        self.latestCreatedAt = latestCreatedAt
    }
}

// MARK: - Pure Algorithmic Snapshot Lineage DAG Engine

public struct SnapshotLineageQueryEngine: Sendable {
    public let nodesByID: [SnapshotID: SnapshotNode]
    public let childrenByParentID: [SnapshotID: [SnapshotID]]
    public let topologicalOrder: [SnapshotNode]
    public let depthBySnapshotID: [SnapshotID: Int]

    public init(nodes: [SnapshotNode]) throws {
        let sortedOrder = try Self.topologicalSort(nodes)
        var byID: [SnapshotID: SnapshotNode] = [:]
        byID.reserveCapacity(sortedOrder.count)
        for node in sortedOrder {
            byID[node.id] = node
        }

        var childrenMap: [SnapshotID: [SnapshotID]] = [:]
        for node in sortedOrder {
            if let parentID = node.parentSnapshotID, byID[parentID] != nil {
                childrenMap[parentID, default: []].append(node.id)
            }
        }

        var depths: [SnapshotID: Int] = [:]
        depths.reserveCapacity(sortedOrder.count)
        for node in sortedOrder {
            if let parentID = node.parentSnapshotID, let parentDepth = depths[parentID] {
                depths[node.id] = parentDepth + 1
            } else {
                depths[node.id] = 0
            }
        }

        self.nodesByID = byID
        self.childrenByParentID = childrenMap
        self.topologicalOrder = sortedOrder
        self.depthBySnapshotID = depths
    }

    // MARK: - Instance Convenience Queries Over Pre-Indexed DAG

    public func ancestorPath(to targetID: SnapshotID) throws -> [SnapshotNode] {
        try Self.ancestorPath(to: targetID, inMap: nodesByID)
    }

    public func descendants(of rootID: SnapshotID, includeSelf: Bool = false) throws -> [SnapshotNode] {
        guard let root = nodesByID[rootID] else {
            throw AgentVMError.snapshotNotFound(rootID)
        }
        var visited: Set<SnapshotID> = [rootID]
        var queue: [SnapshotID] = [rootID]
        var cursor = 0
        while cursor < queue.count {
            let current = queue[cursor]
            cursor += 1
            for childID in childrenByParentID[current] ?? [] where !visited.contains(childID) {
                visited.insert(childID)
                queue.append(childID)
            }
        }
        if !includeSelf {
            visited.remove(root.id)
        }
        return topologicalOrder.filter { visited.contains($0.id) }
    }

    public func lowestCommonAncestor(
        of leftID: SnapshotID,
        and rightID: SnapshotID
    ) throws -> SnapshotLCAResult {
        try Self.lowestCommonAncestor(of: leftID, and: rightID, inMap: nodesByID)
    }

    public func discoverBranchTips() -> [SnapshotBranchSummary] {
        Self.computeBranchSummaries(sortedNodes: topologicalOrder, nodesByID: nodesByID, childrenByParentID: childrenByParentID)
    }

    public func leafSnapshots() -> [SnapshotNode] {
        topologicalOrder.filter { (childrenByParentID[$0.id]?.isEmpty ?? true) }
    }

    public func buildDiffReport(
        left leftID: SnapshotID,
        right rightID: SnapshotID,
        leftExtents: [SparseExtent] = [],
        rightExtents: [SparseExtent] = [],
        blockSizeBytes: UInt64 = 4096
    ) throws -> SnapshotDiffReport {
        try Self.buildDiffReport(
            left: leftID,
            right: rightID,
            inMap: nodesByID,
            leftExtents: leftExtents,
            rightExtents: rightExtents,
            blockSizeBytes: blockSizeBytes
        )
    }

    public func computeGarbageCollectionPlan(
        policy: GarbageCollectionPolicy = GarbageCollectionPolicy(),
        activeHeadSnapshotIDs: Set<SnapshotID> = [],
        referenceDate: Date = Date()
    ) -> GarbageCollectionPlan {
        Self.computeGarbageCollectionPlanOnValidatedDAG(
            sortedNodes: topologicalOrder,
            nodesByID: nodesByID,
            childrenByParentID: childrenByParentID,
            policy: policy,
            activeHeadSnapshotIDs: activeHeadSnapshotIDs,
            referenceDate: referenceDate
        )
    }

    // MARK: - 1. Cycle Detection & DAG Validation

    public static func validateDAG(_ nodes: [SnapshotNode]) throws {
        var nodesByID: [SnapshotID: SnapshotNode] = [:]
        nodesByID.reserveCapacity(nodes.count)
        for node in nodes {
            nodesByID[node.id] = node
            if node.parentSnapshotID == node.id {
                throw AgentVMError.snapshotCycleDetected(node.id)
            }
        }

        // Three-color parent-chain cycle check in deterministic ID order:
        // 0 = unvisited, 1 = visiting (on current recursion stack), 2 = verified acyclic
        var color: [SnapshotID: UInt8] = [:]
        color.reserveCapacity(nodesByID.count)

        let deterministicIDs = nodesByID.keys.sorted()
        for startID in deterministicIDs where color[startID] == nil {
            var trail: [SnapshotID] = []
            var currentOpt: SnapshotID? = startID

            while let current = currentOpt {
                guard let node = nodesByID[current] else {
                    // Parent points outside the in-memory slice (e.g., pruned external root); chain terminates cleanly.
                    break
                }
                let state = color[current] ?? 0
                if state == 2 {
                    break
                }
                if state == 1 {
                    throw AgentVMError.snapshotCycleDetected(current)
                }
                color[current] = 1
                trail.append(current)
                currentOpt = node.parentSnapshotID
            }

            for visitedID in trail {
                color[visitedID] = 2
            }
        }
    }

    // MARK: - 2. Deterministic Topological Sort (Kahn's Algorithm)

    public static func topologicalSort(_ nodes: [SnapshotNode]) throws -> [SnapshotNode] {
        guard !nodes.isEmpty else { return [] }
        try validateDAG(nodes)

        // Deduplicate by SnapshotID (last-write-wins if duplicates exist in slice)
        var nodesByID: [SnapshotID: SnapshotNode] = [:]
        nodesByID.reserveCapacity(nodes.count)
        for node in nodes {
            nodesByID[node.id] = node
        }

        var inDegree: [SnapshotID: Int] = [:]
        var childrenByParent: [SnapshotID: [SnapshotID]] = [:]
        inDegree.reserveCapacity(nodesByID.count)

        for (id, node) in nodesByID {
            if let parentID = node.parentSnapshotID, nodesByID[parentID] != nil {
                inDegree[id] = 1
                childrenByParent[parentID, default: []].append(id)
            } else {
                inDegree[id] = 0
            }
        }

        var readyQueue: [SnapshotNode] = nodesByID.values.filter { (inDegree[$0.id] ?? 0) == 0 }
        readyQueue.sort(by: Self.chronologicalTieBreakOrder)

        var sortedOutput: [SnapshotNode] = []
        sortedOutput.reserveCapacity(nodesByID.count)

        while !readyQueue.isEmpty {
            let current = readyQueue.removeFirst()
            sortedOutput.append(current)

            if let childIDs = childrenByParent[current.id] {
                var newlyReadyAdded = false
                for childID in childIDs {
                    let updated = (inDegree[childID] ?? 1) - 1
                    inDegree[childID] = updated
                    if updated == 0, let childNode = nodesByID[childID] {
                        readyQueue.append(childNode)
                        newlyReadyAdded = true
                    }
                }
                if newlyReadyAdded {
                    readyQueue.sort(by: Self.chronologicalTieBreakOrder)
                }
            }
        }

        if sortedOutput.count < nodesByID.count {
            let emitted = Set(sortedOutput.map(\.id))
            if let stuckID = nodesByID.keys.sorted().first(where: { !emitted.contains($0) }) {
                throw AgentVMError.snapshotCycleDetected(stuckID)
            }
        }

        return sortedOutput
    }

    // MARK: - 3. Ancestor Path & Subtree Extraction

    public static func ancestorPath(
        to targetID: SnapshotID,
        in nodes: [SnapshotNode]
    ) throws -> [SnapshotNode] {
        var map: [SnapshotID: SnapshotNode] = [:]
        map.reserveCapacity(nodes.count)
        for n in nodes { map[n.id] = n }
        return try ancestorPath(to: targetID, inMap: map)
    }

    private static func ancestorPath(
        to targetID: SnapshotID,
        inMap nodesByID: [SnapshotID: SnapshotNode]
    ) throws -> [SnapshotNode] {
        guard let startNode = nodesByID[targetID] else {
            throw AgentVMError.snapshotNotFound(targetID)
        }

        var reversedChain: [SnapshotNode] = [startNode]
        var seen: Set<SnapshotID> = [targetID]
        var nextParentID = startNode.parentSnapshotID

        while let pid = nextParentID {
            if !seen.insert(pid).inserted {
                throw AgentVMError.snapshotCycleDetected(pid)
            }
            guard let parentNode = nodesByID[pid] else {
                break
            }
            reversedChain.append(parentNode)
            nextParentID = parentNode.parentSnapshotID
        }

        return reversedChain.reversed()
    }

    public static func descendants(
        of rootID: SnapshotID,
        in nodes: [SnapshotNode],
        includeSelf: Bool = false
    ) throws -> [SnapshotNode] {
        let engine = try SnapshotLineageQueryEngine(nodes: nodes)
        return try engine.descendants(of: rootID, includeSelf: includeSelf)
    }

    // MARK: - 4. Lowest Common Ancestor (LCA) Computation

    public static func lowestCommonAncestor(
        of leftID: SnapshotID,
        and rightID: SnapshotID,
        in nodes: [SnapshotNode]
    ) throws -> SnapshotLCAResult {
        var map: [SnapshotID: SnapshotNode] = [:]
        map.reserveCapacity(nodes.count)
        for n in nodes { map[n.id] = n }
        return try lowestCommonAncestor(of: leftID, and: rightID, inMap: map)
    }

    public static func lowestCommonAncestorID(
        of leftID: SnapshotID,
        and rightID: SnapshotID,
        in nodes: [SnapshotNode]
    ) throws -> SnapshotID? {
        try lowestCommonAncestor(of: leftID, and: rightID, in: nodes).lowestCommonAncestorID
    }

    private static func lowestCommonAncestor(
        of leftID: SnapshotID,
        and rightID: SnapshotID,
        inMap nodesByID: [SnapshotID: SnapshotNode]
    ) throws -> SnapshotLCAResult {
        // Validate both endpoints exist and extract root -> node ancestor paths (detecting any cycle).
        let leftPath = try ancestorPath(to: leftID, inMap: nodesByID)
        let rightPath = try ancestorPath(to: rightID, inMap: nodesByID)

        if leftID == rightID {
            return SnapshotLCAResult(
                leftSnapshotID: leftID,
                rightSnapshotID: rightID,
                lowestCommonAncestorID: leftID,
                distanceFromLeft: 0,
                distanceFromRight: 0,
                leftDivergentChain: [],
                rightDivergentChain: []
            )
        }

        // Map each ancestor on leftPath to its step distance from leftID (0 = leftID itself).
        var leftDistanceByID: [SnapshotID: Int] = [:]
        leftDistanceByID.reserveCapacity(leftPath.count)
        let leftLastIdx = leftPath.count - 1
        for (idx, node) in leftPath.enumerated() {
            leftDistanceByID[node.id] = leftLastIdx - idx
        }

        // Walk rightPath from rightID upward (reversed) to find the first node shared with leftPath.
        let rightLastIdx = rightPath.count - 1
        for idx in stride(from: rightLastIdx, through: 0, by: -1) {
            let candidate = rightPath[idx]
            if let distLeft = leftDistanceByID[candidate.id] {
                let distRight = rightLastIdx - idx
                let leftLCAIdx = leftLastIdx - distLeft
                let leftDivergent = Array(leftPath[(leftLCAIdx + 1)...])
                let rightDivergent = Array(rightPath[(idx + 1)...])
                return SnapshotLCAResult(
                    leftSnapshotID: leftID,
                    rightSnapshotID: rightID,
                    lowestCommonAncestorID: candidate.id,
                    distanceFromLeft: distLeft,
                    distanceFromRight: distRight,
                    leftDivergentChain: leftDivergent,
                    rightDivergentChain: rightDivergent
                )
            }
        }

        // Disjoint trees (no shared ancestor)
        return SnapshotLCAResult(
            leftSnapshotID: leftID,
            rightSnapshotID: rightID,
            lowestCommonAncestorID: nil,
            distanceFromLeft: leftPath.count,
            distanceFromRight: rightPath.count,
            leftDivergentChain: leftPath,
            rightDivergentChain: rightPath
        )
    }

    // MARK: - 5. Branch Tip & Leaf Discovery

    public static func discoverBranchTips(in nodes: [SnapshotNode]) throws -> [SnapshotBranchSummary] {
        let engine = try SnapshotLineageQueryEngine(nodes: nodes)
        return engine.discoverBranchTips()
    }

    public static func leafSnapshots(in nodes: [SnapshotNode]) throws -> [SnapshotNode] {
        let engine = try SnapshotLineageQueryEngine(nodes: nodes)
        return engine.leafSnapshots()
    }

    private static func computeBranchSummaries(
        sortedNodes: [SnapshotNode],
        nodesByID: [SnapshotID: SnapshotNode],
        childrenByParentID: [SnapshotID: [SnapshotID]]
    ) -> [SnapshotBranchSummary] {
        var groupedByBranch: [String: [SnapshotNode]] = [:]
        for node in sortedNodes {
            groupedByBranch[node.branchName, default: []].append(node)
        }

        var summaries: [SnapshotBranchSummary] = []
        summaries.reserveCapacity(groupedByBranch.count)

        for branchName in groupedByBranch.keys.sorted() {
            guard let branchNodes = groupedByBranch[branchName], !branchNodes.isEmpty else {
                continue
            }

            let branchIDSet = Set(branchNodes.map(\.id))

            // Leaves within this branch: snapshots that have NO child within the same branch.
            let sameBranchLeaves = branchNodes.filter { node in
                let children = childrenByParentID[node.id] ?? []
                return !children.contains(where: { branchIDSet.contains($0) })
            }

            let tipNode = (sameBranchLeaves.isEmpty ? branchNodes : sameBranchLeaves).max(by: Self.chronologicalTieBreakOrder)!
            let rootNode = branchNodes.first!

            // Fork origin: parent of the earliest node on this branch that lives on another branch.
            var forkOrigin: SnapshotID?
            for node in branchNodes {
                if let pid = node.parentSnapshotID, let parent = nodesByID[pid], parent.branchName != branchName {
                    forkOrigin = pid
                    break
                }
            }

            var dirtySum: UInt64 = 0
            var ramSum: UInt64 = 0
            var pinned = 0
            for node in branchNodes {
                dirtySum &+= node.dirtyDeltaBytes
                ramSum &+= node.memoryStateBytes
                if node.isPinned { pinned += 1 }
            }

            summaries.append(SnapshotBranchSummary(
                branchName: branchName,
                tipSnapshotID: tipNode.id,
                leafSnapshotIDs: sameBranchLeaves.map(\.id),
                rootSnapshotID: rootNode.id,
                forkOriginSnapshotID: forkOrigin,
                snapshotCount: branchNodes.count,
                pinnedCount: pinned,
                totalDirtyDeltaBytes: dirtySum,
                totalMemoryStateBytes: ramSum,
                latestCreatedAt: tipNode.createdAt
            ))
        }

        return summaries
    }

    // MARK: - 6. SnapshotDiffReport & VMSpec Deep Configuration Diff Builder

    public static func buildDiffReport(
        left leftID: SnapshotID,
        right rightID: SnapshotID,
        in nodes: [SnapshotNode],
        leftExtents: [SparseExtent] = [],
        rightExtents: [SparseExtent] = [],
        blockSizeBytes: UInt64 = 4096
    ) throws -> SnapshotDiffReport {
        try validateDAG(nodes)
        var map: [SnapshotID: SnapshotNode] = [:]
        map.reserveCapacity(nodes.count)
        for n in nodes { map[n.id] = n }
        return try buildDiffReport(
            left: leftID,
            right: rightID,
            inMap: map,
            leftExtents: leftExtents,
            rightExtents: rightExtents,
            blockSizeBytes: blockSizeBytes
        )
    }

    private static func buildDiffReport(
        left leftID: SnapshotID,
        right rightID: SnapshotID,
        inMap nodesByID: [SnapshotID: SnapshotNode],
        leftExtents: [SparseExtent],
        rightExtents: [SparseExtent],
        blockSizeBytes: UInt64
    ) throws -> SnapshotDiffReport {
        let lca = try lowestCommonAncestor(of: leftID, and: rightID, inMap: nodesByID)
        guard let leftNode = nodesByID[leftID] else {
            throw AgentVMError.snapshotNotFound(leftID)
        }
        guard let rightNode = nodesByID[rightID] else {
            throw AgentVMError.snapshotNotFound(rightID)
        }

        let configDiffs = diffVMSpecs(left: leftNode.specSnapshot, right: rightNode.specSnapshot)
        let effectiveBlockSize = max(512, blockSizeBytes)

        let divergentExtents: [SparseExtent]
        let divergentBytes: UInt64

        if leftID == rightID && leftExtents.isEmpty && rightExtents.isEmpty {
            divergentExtents = []
            divergentBytes = 0
        } else if !leftExtents.isEmpty || !rightExtents.isEmpty {
            divergentExtents = computeDivergentExtents(left: leftExtents, right: rightExtents)
            divergentBytes = divergentExtents.reduce(UInt64(0)) { $0 &+ $1.lengthBytes }
        } else {
            // Estimate upper-bound divergent CoW delta along both divergent lineage chains from LCA.
            let leftDelta = lca.leftDivergentChain.reduce(UInt64(0)) { acc, snap in
                let delta = snap.dirtyDeltaBytes > 0 ? snap.dirtyDeltaBytes : snap.allocatedDiskBytes
                return acc &+ delta
            }
            let rightDelta = lca.rightDivergentChain.reduce(UInt64(0)) { acc, snap in
                let delta = snap.dirtyDeltaBytes > 0 ? snap.dirtyDeltaBytes : snap.allocatedDiskBytes
                return acc &+ delta
            }
            let maxVirtual = max(leftNode.virtualDiskBytes, rightNode.virtualDiskBytes)
            let boundedBytes = maxVirtual > 0 ? min(maxVirtual, leftDelta &+ rightDelta) : (leftDelta &+ rightDelta)
            divergentBytes = boundedBytes
            if boundedBytes > 0 {
                divergentExtents = [
                    SparseExtent(offsetBytes: 0, lengthBytes: boundedBytes, kind: .allocatedDirty)
                ]
            } else {
                divergentExtents = []
            }
        }

        let divergentBlocks: Int
        if divergentBytes == 0 {
            divergentBlocks = 0
        } else {
            divergentBlocks = Int((divergentBytes + effectiveBlockSize - 1) / effectiveBlockSize)
        }

        return SnapshotDiffReport(
            leftSnapshotID: leftID,
            rightSnapshotID: rightID,
            lowestCommonAncestorID: lca.lowestCommonAncestorID,
            ancestorDistanceLeft: lca.distanceFromLeft,
            ancestorDistanceRight: lca.distanceFromRight,
            divergentBlockCount: divergentBlocks,
            divergentBytes: divergentBytes,
            divergentExtents: divergentExtents,
            configDiffs: configDiffs,
            computedAt: Date()
        )
    }

    public static func diffVMSpecs(left: VMSpec, right: VMSpec) -> [SnapshotConfigFieldDiff] {
        var diffs: [SnapshotConfigFieldDiff] = []

        func compareField<T: Equatable>(
            _ path: String,
            _ lhs: T,
            _ rhs: T,
            format: (T) -> String = { "\($0)" }
        ) {
            if lhs != rhs {
                diffs.append(SnapshotConfigFieldDiff(
                    fieldName: path,
                    leftValue: format(lhs),
                    rightValue: format(rhs)
                ))
            }
        }

        compareField("name", left.name, right.name)
        compareField("agentOwnerTag", left.agentOwnerTag, right.agentOwnerTag)
        compareField("guestOS", left.guestOS, right.guestOS) { $0.rawValue }
        compareField("bootLoader", left.bootLoader, right.bootLoader, format: Self.describeBootLoader)
        compareField("compute.vcpuCount", left.compute.vcpuCount, right.compute.vcpuCount)
        compareField("compute.memoryMB", left.compute.memoryMB, right.compute.memoryMB) { "\($0) MB" }
        compareField("compute.enableBalloonDevice", left.compute.enableBalloonDevice, right.compute.enableBalloonDevice)
        compareField("compute.minBalloonMemoryMB", left.compute.minBalloonMemoryMB, right.compute.minBalloonMemoryMB) { "\($0) MB" }
        compareField("compute.cpuQuotaPercent", left.compute.cpuQuotaPercent, right.compute.cpuQuotaPercent) { "\($0)%" }
        compareField("compute.enableEntropyDevice", left.compute.enableEntropyDevice, right.compute.enableEntropyDevice)
        compareField("enableVsockDevice", left.enableVsockDevice, right.enableVsockDevice)
        compareField("maxRuntimeMinutes", left.maxRuntimeMinutes, right.maxRuntimeMinutes) { "\($0) min" }

        // Block Devices
        compareField("blockDevices.count", left.blockDevices.count, right.blockDevices.count)
        let maxBlocks = max(left.blockDevices.count, right.blockDevices.count)
        for i in 0..<maxBlocks {
            let lBlk = i < left.blockDevices.count ? left.blockDevices[i] : nil
            let rBlk = i < right.blockDevices.count ? right.blockDevices[i] : nil
            let lDesc = lBlk.map { "\($0.label) (\($0.format.rawValue), \(ByteMetricsFormatter.formatBytes($0.virtualSizeBytes)), ro=\($0.readOnly))" } ?? "<none>"
            let rDesc = rBlk.map { "\($0.label) (\($0.format.rawValue), \(ByteMetricsFormatter.formatBytes($0.virtualSizeBytes)), ro=\($0.readOnly))" } ?? "<none>"
            if lDesc != rDesc {
                diffs.append(SnapshotConfigFieldDiff(
                    fieldName: "blockDevices[\(i)]",
                    leftValue: lDesc,
                    rightValue: rDesc
                ))
            }
        }

        // VirtioFS Mounts keyed by mountTag
        let leftMounts = Dictionary(left.virtioFSMounts.map { ($0.mountTag, $0) }, uniquingKeysWith: { first, _ in first })
        let rightMounts = Dictionary(right.virtioFSMounts.map { ($0.mountTag, $0) }, uniquingKeysWith: { first, _ in first })
        for tag in Set(leftMounts.keys).union(rightMounts.keys).sorted() {
            let lM = leftMounts[tag].map { "\($0.hostDirectoryPath) -> \($0.guestMountPoint) (ro=\($0.readOnly), rosetta=\($0.enableRosettaLinuxBinFmt))" } ?? "<unmounted>"
            let rM = rightMounts[tag].map { "\($0.hostDirectoryPath) -> \($0.guestMountPoint) (ro=\($0.readOnly), rosetta=\($0.enableRosettaLinuxBinFmt))" } ?? "<unmounted>"
            if lM != rM {
                diffs.append(SnapshotConfigFieldDiff(
                    fieldName: "virtioFSMounts[\(tag)]",
                    leftValue: lM,
                    rightValue: rM
                ))
            }
        }

        // Network Interfaces keyed by interfaceName
        let leftNICs = Dictionary(left.networkInterfaces.map { ($0.interfaceName, $0) }, uniquingKeysWith: { first, _ in first })
        let rightNICs = Dictionary(right.networkInterfaces.map { ($0.interfaceName, $0) }, uniquingKeysWith: { first, _ in first })
        for ifName in Set(leftNICs.keys).union(rightNICs.keys).sorted() {
            let lN = leftNICs[ifName]
            let rN = rightNICs[ifName]
            let lSummary = lN.map { "\($0.mode.rawValue) ip=\($0.ipv4Address) mac=\($0.macAddress) mtu=\($0.mtu) policy=\($0.firewallPolicyID?.rawValue ?? "none")" } ?? "<absent>"
            let rSummary = rN.map { "\($0.mode.rawValue) ip=\($0.ipv4Address) mac=\($0.macAddress) mtu=\($0.mtu) policy=\($0.firewallPolicyID?.rawValue ?? "none")" } ?? "<absent>"
            if lSummary != rSummary {
                diffs.append(SnapshotConfigFieldDiff(
                    fieldName: "networkInterfaces[\(ifName)]",
                    leftValue: lSummary,
                    rightValue: rSummary
                ))
            }
        }

        // Port Forwards keyed by hostPort
        let leftFwds = Dictionary(left.portForwards.map { ($0.hostPort, $0) }, uniquingKeysWith: { first, _ in first })
        let rightFwds = Dictionary(right.portForwards.map { ($0.hostPort, $0) }, uniquingKeysWith: { first, _ in first })
        for port in Set(leftFwds.keys).union(rightFwds.keys).sorted() {
            let lF = leftFwds[port].map { "\($0.protocolType.rawValue) \($0.hostBindAddress):\($0.hostPort)->\($0.guestPort) enabled=\($0.enabled)" } ?? "<unbound>"
            let rF = rightFwds[port].map { "\($0.protocolType.rawValue) \($0.hostBindAddress):\($0.hostPort)->\($0.guestPort) enabled=\($0.enabled)" } ?? "<unbound>"
            if lF != rF {
                diffs.append(SnapshotConfigFieldDiff(
                    fieldName: "portForwards[\(port)]",
                    leftValue: lF,
                    rightValue: rF
                ))
            }
        }

        // Serial & Display
        compareField(
            "serialAndDisplay.graphics",
            "\(left.serialAndDisplay.enableVirtioGraphics) (\(left.serialAndDisplay.displayWidthPx)x\(left.serialAndDisplay.displayHeightPx))",
            "\(right.serialAndDisplay.enableVirtioGraphics) (\(right.serialAndDisplay.displayWidthPx)x\(right.serialAndDisplay.displayHeightPx))"
        )

        // Cloud-Init
        compareField("cloudInit.hostname", left.cloudInit?.hostname ?? "<disabled>", right.cloudInit?.hostname ?? "<disabled>")
        compareField(
            "cloudInit.aptPackages",
            left.cloudInit?.aptPackages.joined(separator: ",") ?? "",
            right.cloudInit?.aptPackages.joined(separator: ",") ?? ""
        )
        compareField(
            "cloudInit.runCommands",
            left.cloudInit?.runCommands.joined(separator: " && ") ?? "",
            right.cloudInit?.runCommands.joined(separator: " && ") ?? ""
        )

        // Labels
        for labelKey in Set(left.labels.keys).union(right.labels.keys).sorted() {
            let lv = left.labels[labelKey] ?? "<unset>"
            let rv = right.labels[labelKey] ?? "<unset>"
            if lv != rv {
                diffs.append(SnapshotConfigFieldDiff(
                    fieldName: "labels.\(labelKey)",
                    leftValue: lv,
                    rightValue: rv
                ))
            }
        }

        return diffs
    }

    private static func describeBootLoader(_ spec: BootLoaderSpec) -> String {
        switch spec {
        case let .linuxKernel(vmlinuzPath, initrdPath, cmdline):
            return "linuxKernel(vmlinuz=\(vmlinuzPath), initrd=\(initrdPath ?? "none"), cmdline=\(cmdline))"
        case let .efiBoot(storePath, create):
            return "efiBoot(nvram=\(storePath), create=\(create))"
        case let .macOSBoot(hwPath, idPath, auxPath):
            return "macOSBoot(hw=\(hwPath), id=\(idPath), aux=\(auxPath))"
        }
    }

    private static func computeDivergentExtents(
        left: [SparseExtent],
        right: [SparseExtent]
    ) -> [SparseExtent] {
        var boundaries = Set<UInt64>([0])
        for ext in left where ext.lengthBytes > 0 {
            boundaries.insert(ext.offsetBytes)
            boundaries.insert(ext.endOffsetBytes)
        }
        for ext in right where ext.lengthBytes > 0 {
            boundaries.insert(ext.offsetBytes)
            boundaries.insert(ext.endOffsetBytes)
        }

        let sortedBounds = boundaries.sorted()
        guard sortedBounds.count >= 2 else { return [] }

        let sortedLeft = left.filter { $0.lengthBytes > 0 }.sorted { $0.offsetBytes < $1.offsetBytes }
        let sortedRight = right.filter { $0.lengthBytes > 0 }.sorted { $0.offsetBytes < $1.offsetBytes }

        func coveringExtent(in list: [SparseExtent], at offset: UInt64) -> SparseExtent? {
            var lo = 0
            var hi = list.count - 1
            while lo <= hi {
                let mid = (lo + hi) / 2
                let item = list[mid]
                if offset < item.offsetBytes {
                    hi = mid - 1
                } else if offset >= item.endOffsetBytes {
                    lo = mid + 1
                } else {
                    return item
                }
            }
            return nil
        }

        var rawDivergent: [SparseExtent] = []
        for i in 0..<(sortedBounds.count - 1) {
            let segStart = sortedBounds[i]
            let segEnd = sortedBounds[i + 1]
            let segLen = segEnd - segStart
            guard segLen > 0 else { continue }

            let lExt = coveringExtent(in: sortedLeft, at: segStart)
            let rExt = coveringExtent(in: sortedRight, at: segStart)

            let lKind = lExt?.kind ?? .sparseHole
            let rKind = rExt?.kind ?? .sparseHole

            let differs: Bool
            if lKind == .sparseHole && rKind == .sparseHole {
                differs = false
            } else if lKind != rKind {
                differs = true
            } else if let lCRC = lExt?.checksumCRC32, let rCRC = rExt?.checksumCRC32 {
                differs = (lCRC != rCRC)
            } else {
                differs = (lKind == .allocatedDirty || rKind == .allocatedDirty)
            }

            if differs {
                if let last = rawDivergent.last, last.endOffsetBytes == segStart {
                    rawDivergent[rawDivergent.count - 1] = SparseExtent(
                        offsetBytes: last.offsetBytes,
                        lengthBytes: last.lengthBytes + segLen,
                        kind: .allocatedDirty
                    )
                } else {
                    rawDivergent.append(SparseExtent(
                        offsetBytes: segStart,
                        lengthBytes: segLen,
                        kind: .allocatedDirty
                    ))
                }
            }
        }
        return rawDivergent
    }

    // MARK: - 7. GarbageCollectionPlan Computation Honoring GarbageCollectionPolicy

    public static func computeGarbageCollectionPlan(
        in nodes: [SnapshotNode],
        policy: GarbageCollectionPolicy = GarbageCollectionPolicy(),
        activeHeadSnapshotIDs: Set<SnapshotID> = [],
        referenceDate: Date = Date()
    ) throws -> GarbageCollectionPlan {
        let engine = try SnapshotLineageQueryEngine(nodes: nodes)
        return engine.computeGarbageCollectionPlan(
            policy: policy,
            activeHeadSnapshotIDs: activeHeadSnapshotIDs,
            referenceDate: referenceDate
        )
    }

    private static func computeGarbageCollectionPlanOnValidatedDAG(
        sortedNodes: [SnapshotNode],
        nodesByID: [SnapshotID: SnapshotNode],
        childrenByParentID: [SnapshotID: [SnapshotID]],
        policy: GarbageCollectionPolicy,
        activeHeadSnapshotIDs: Set<SnapshotID>,
        referenceDate: Date
    ) -> GarbageCollectionPlan {
        guard !sortedNodes.isEmpty else {
            return GarbageCollectionPlan(
                candidateSnapshotIDs: [],
                protectedSnapshotIDs: [],
                reclaimableDiskBytes: 0,
                reclaimableMemoryStateBytes: 0,
                reparentings: [:]
            )
        }

        var hardProtectedIDs: Set<SnapshotID> = []

        // Rule A: Protect pinned snapshots, golden base images, and active VM head snapshots.
        for node in sortedNodes {
            if node.isPinned || node.kind == .baseGoldenImage || activeHeadSnapshotIDs.contains(node.id) {
                hardProtectedIDs.insert(node.id)
            }
        }

        // Rule B: Protect structural branch fork points when preserveBranchForkPoints == true.
        if policy.preserveBranchForkPoints {
            for node in sortedNodes {
                let childIDs = childrenByParentID[node.id] ?? []
                let hasCrossBranchChild = childIDs.contains { cid in
                    guard let child = nodesByID[cid] else { return false }
                    return child.branchName != node.branchName
                }
                if node.kind == .branchForkPoint || childIDs.count >= 2 || hasCrossBranchChild {
                    hardProtectedIDs.insert(node.id)
                }
            }
        }

        // Rule C: Keep at least `keepMinimumPerBranch` newest snapshots on every branch.
        let minKeep = max(0, policy.keepMinimumPerBranch)
        if minKeep > 0 {
            var byBranch: [String: [SnapshotNode]] = [:]
            for node in sortedNodes {
                byBranch[node.branchName, default: []].append(node)
            }
            for (_, branchList) in byBranch {
                let newestFirst = branchList.sorted { a, b in
                    Self.chronologicalTieBreakOrder(b, a)
                }
                for protectedRecent in newestFirst.prefix(minKeep) {
                    hardProtectedIDs.insert(protectedRecent.id)
                }
            }
        }

        func snapshotFootprintBytes(_ snap: SnapshotNode) -> (disk: UInt64, memory: UInt64) {
            let diskReclaim = snap.dirtyDeltaBytes > 0 ? snap.dirtyDeltaBytes : snap.allocatedDiskBytes
            return (diskReclaim, snap.memoryStateBytes)
        }

        let maxAgeSeconds = Double(max(0, policy.maxUnpinnedAgeHours)) * 3600.0
        var candidateSet: Set<SnapshotID> = []

        // Pass 1: Age-based expiration on unprotected snapshots.
        for node in sortedNodes where !hardProtectedIDs.contains(node.id) {
            let ageSeconds = referenceDate.timeIntervalSince(node.createdAt)
            if ageSeconds >= maxAgeSeconds {
                candidateSet.insert(node.id)
            }
        }

        // Pass 2: Enforce maxTotalSnapshotPoolBytes across surviving pool (evicting oldest unprotected first).
        var survivingPoolBytes: UInt64 = 0
        for node in sortedNodes where !candidateSet.contains(node.id) {
            let fp = snapshotFootprintBytes(node)
            survivingPoolBytes &+= (fp.disk &+ fp.memory)
        }

        if survivingPoolBytes > policy.maxTotalSnapshotPoolBytes {
            let remainingEvictable = sortedNodes
                .filter { !hardProtectedIDs.contains($0.id) && !candidateSet.contains($0.id) }
                .sorted(by: Self.chronologicalTieBreakOrder) // Oldest first

            for node in remainingEvictable {
                guard survivingPoolBytes > policy.maxTotalSnapshotPoolBytes else { break }
                candidateSet.insert(node.id)
                let fp = snapshotFootprintBytes(node)
                let combined = fp.disk &+ fp.memory
                survivingPoolBytes = survivingPoolBytes > combined ? (survivingPoolBytes - combined) : 0
            }
        }

        // Compute deterministic candidate & protected lists plus exact byte totals and reparenting edges.
        var candidateIDs: [SnapshotID] = []
        var protectedIDs: [SnapshotID] = []
        var reclaimDisk: UInt64 = 0
        var reclaimRAM: UInt64 = 0
        var reparentings: [SnapshotID: SnapshotID?] = [:]

        for node in sortedNodes {
            if candidateSet.contains(node.id) {
                candidateIDs.append(node.id)
                let fp = snapshotFootprintBytes(node)
                reclaimDisk &+= fp.disk
                reclaimRAM &+= fp.memory
            } else {
                protectedIDs.append(node.id)
                if let directParentID = node.parentSnapshotID, candidateSet.contains(directParentID) {
                    // Walk upward through reclaimed ancestors until finding the nearest surviving ancestor (or nil root).
                    var cursorOpt: SnapshotID? = directParentID
                    var visitedHop: Set<SnapshotID> = []
                    while let cursor = cursorOpt, candidateSet.contains(cursor) {
                        if !visitedHop.insert(cursor).inserted { break }
                        cursorOpt = nodesByID[cursor]?.parentSnapshotID
                    }
                    reparentings.updateValue(cursorOpt, forKey: node.id)
                }
            }
        }

        return GarbageCollectionPlan(
            candidateSnapshotIDs: candidateIDs,
            protectedSnapshotIDs: protectedIDs,
            reclaimableDiskBytes: reclaimDisk,
            reclaimableMemoryStateBytes: reclaimRAM,
            reparentings: reparentings
        )
    }

    private static func chronologicalTieBreakOrder(_ lhs: SnapshotNode, _ rhs: SnapshotNode) -> Bool {
        if lhs.createdAt != rhs.createdAt {
            return lhs.createdAt < rhs.createdAt
        }
        return lhs.id < rhs.id
    }
}

// MARK: - Transactional GC Plan Executor on AgentVMProjectStore

extension AgentVMProjectStore {
    @discardableResult
    public func executeGarbageCollectionPlan(
        _ plan: GarbageCollectionPlan,
        unlinkSnapshotArtifactsInBundle: Bool = false
    ) throws -> Int {
        guard !plan.candidateSnapshotIDs.isEmpty else { return 0 }

        var artifactPathsToRemove: [URL] = []
        if unlinkSnapshotArtifactsInBundle {
            let bundleSnapRoot = snapshotsDirectoryURL.standardizedFileURL.path
            for snapID in plan.candidateSnapshotIDs {
                if let snap = try fetchSnapshot(snapID) {
                    let diskURL = resolveBundleRelativePath(snap.diskClonePath)
                    if diskURL.path.hasPrefix(bundleSnapRoot) {
                        artifactPathsToRemove.append(diskURL)
                    }
                    if let mem = snap.memoryStatePath, !mem.isEmpty {
                        let memURL = resolveBundleRelativePath(mem)
                        if memURL.path.hasPrefix(bundleSnapRoot) {
                            artifactPathsToRemove.append(memURL)
                        }
                    }
                }
            }
        }

        let deletedCount = try db.inTransaction {
            // Apply surviving child reparenting edges BEFORE deleting reclaimed interior nodes.
            for (childID, newParentOpt) in plan.reparentings {
                try db.execute(
                    "UPDATE snapshots SET parent_snapshot_id = ? WHERE id = ?;",
                    bindings: [newParentOpt.sqliteValue, childID.sqliteValue]
                )
            }

            var removed = 0
            for candidateID in plan.candidateSnapshotIDs {
                removed += try db.execute(
                    "DELETE FROM snapshots WHERE id = ?;",
                    bindings: [candidateID.sqliteValue]
                )
            }
            return removed
        }

        if unlinkSnapshotArtifactsInBundle {
            let fm = FileManager.default
            for url in artifactPathsToRemove where fm.fileExists(atPath: url.path) {
                try? fm.removeItem(at: url)
            }
        }

        return deletedCount
    }
}
