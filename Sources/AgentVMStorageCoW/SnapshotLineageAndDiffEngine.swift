import AgentVMModels
import Darwin
import Foundation

// MARK: - Snapshot Lineage DAG & Branch Telemetry Models

public struct SnapshotBranchSummary: Codable, Hashable, Sendable, Identifiable {
    public var id: String { branchName }
    public var branchName: String
    public var headSnapshotID: SnapshotID
    public var rootSnapshotID: SnapshotID
    public var snapshotCount: Int
    public var totalDirtyDeltaBytes: UInt64
    public var totalMemoryStateBytes: UInt64
    public var latestCreatedAt: Date

    public init(
        branchName: String,
        headSnapshotID: SnapshotID,
        rootSnapshotID: SnapshotID,
        snapshotCount: Int,
        totalDirtyDeltaBytes: UInt64,
        totalMemoryStateBytes: UInt64,
        latestCreatedAt: Date
    ) {
        self.branchName = branchName
        self.headSnapshotID = headSnapshotID
        self.rootSnapshotID = rootSnapshotID
        self.snapshotCount = snapshotCount
        self.totalDirtyDeltaBytes = totalDirtyDeltaBytes
        self.totalMemoryStateBytes = totalMemoryStateBytes
        self.latestCreatedAt = latestCreatedAt
    }
}

public struct SnapshotDAGValidationReport: Codable, Hashable, Sendable {
    public var totalNodeCount: Int
    public var rootSnapshotIDs: [SnapshotID]
    public var leafSnapshotIDs: [SnapshotID]
    public var forkPointSnapshotIDs: [SnapshotID]
    public var orphanParentReferences: [SnapshotID: SnapshotID]
    public var maxLineageDepth: Int
    public var branches: [SnapshotBranchSummary]

    public init(
        totalNodeCount: Int,
        rootSnapshotIDs: [SnapshotID],
        leafSnapshotIDs: [SnapshotID],
        forkPointSnapshotIDs: [SnapshotID],
        orphanParentReferences: [SnapshotID: SnapshotID],
        maxLineageDepth: Int,
        branches: [SnapshotBranchSummary]
    ) {
        self.totalNodeCount = totalNodeCount
        self.rootSnapshotIDs = rootSnapshotIDs
        self.leafSnapshotIDs = leafSnapshotIDs
        self.forkPointSnapshotIDs = forkPointSnapshotIDs
        self.orphanParentReferences = orphanParentReferences
        self.maxLineageDepth = maxLineageDepth
        self.branches = branches
    }
}

// MARK: - APFS CoW Snapshot Lineage, Binary Diff & Garbage Collection Engine

/// Manages Copy-on-Write snapshot lineage DAG invariants, Lowest Common Ancestor (LCA) queries,
/// binary disk block + `VMSpec` diffs (`SnapshotDiffReport`), and space-reclaiming GC plans (`GarbageCollectionPlan`).
public struct SnapshotLineageAndDiffEngine: Sendable {
    public let diskEngine: APFSCoWDiskEngine

    public init(diskEngine: APFSCoWDiskEngine = APFSCoWDiskEngine()) {
        self.diskEngine = diskEngine
    }

    // MARK: - Lineage DAG Cycle Verification & Topology Summary

    /// Validates that `snapshots` form a cycle-free forest, throwing `AgentVMError.snapshotCycleDetected`
    /// if any ancestor chain loops back onto itself, and returns topological branch & fork metrics.
    public func validateLineageDAG(snapshots: [SnapshotNode]) throws -> SnapshotDAGValidationReport {
        var byID: [SnapshotID: SnapshotNode] = [:]
        byID.reserveCapacity(snapshots.count)
        for snap in snapshots {
            byID[snap.id] = snap
        }

        // 3-color DFS cycle detection across parent pointers:
        // 0 = unvisited, 1 = visiting (on active ancestor stack), 2 = verified acyclic
        var visitState: [SnapshotID: UInt8] = [:]
        var depthByID: [SnapshotID: Int] = [:]
        var orphanRefs: [SnapshotID: SnapshotID] = [:]
        var childCounts: [SnapshotID: Int] = [:]

        for snap in snapshots {
            if let pid = snap.parentSnapshotID {
                if byID[pid] != nil {
                    childCounts[pid, default: 0] += 1
                } else {
                    orphanRefs[snap.id] = pid
                }
            }
        }

        func computeDepth(_ id: SnapshotID) throws -> Int {
            switch visitState[id] ?? 0 {
            case 1:
                throw AgentVMError.snapshotCycleDetected(id)
            case 2:
                return depthByID[id] ?? 1
            default:
                break
            }

            visitState[id] = 1
            var depth = 1
            if let node = byID[id], let parentID = node.parentSnapshotID, byID[parentID] != nil {
                depth = 1 + (try computeDepth(parentID))
            }
            visitState[id] = 2
            depthByID[id] = depth
            return depth
        }

        var maxDepth = 0
        for snap in snapshots {
            let d = try computeDepth(snap.id)
            if d > maxDepth { maxDepth = d }
        }

        let roots = snapshots
            .filter { snap in
                guard let pid = snap.parentSnapshotID else { return true }
                return byID[pid] == nil
            }
            .map(\.id)
            .sorted()

        let leaves = snapshots
            .filter { childCounts[$0.id, default: 0] == 0 }
            .map(\.id)
            .sorted()

        let forkPoints = snapshots
            .filter { childCounts[$0.id, default: 0] > 1 || $0.kind == .branchForkPoint }
            .map(\.id)
            .sorted()

        // Group branch summaries deterministically.
        let grouped = Dictionary(grouping: snapshots, by: \.branchName)
        var branchSummaries: [SnapshotBranchSummary] = []
        for branchName in grouped.keys.sorted() {
            let nodes = grouped[branchName]!.sorted { lhs, rhs in
                if lhs.createdAt != rhs.createdAt { return lhs.createdAt < rhs.createdAt }
                return lhs.id < rhs.id
            }
            guard let first = nodes.first, let last = nodes.last else { continue }
            let dirtyTotal = nodes.reduce(UInt64(0)) { $0 + $1.dirtyDeltaBytes }
            let memTotal = nodes.reduce(UInt64(0)) { $0 + $1.memoryStateBytes }
            branchSummaries.append(SnapshotBranchSummary(
                branchName: branchName,
                headSnapshotID: last.id,
                rootSnapshotID: first.id,
                snapshotCount: nodes.count,
                totalDirtyDeltaBytes: dirtyTotal,
                totalMemoryStateBytes: memTotal,
                latestCreatedAt: last.createdAt
            ))
        }

        return SnapshotDAGValidationReport(
            totalNodeCount: snapshots.count,
            rootSnapshotIDs: roots,
            leafSnapshotIDs: leaves,
            forkPointSnapshotIDs: forkPoints,
            orphanParentReferences: orphanRefs,
            maxLineageDepth: maxDepth,
            branches: branchSummaries
        )
    }

    // MARK: - Lowest Common Ancestor (LCA) Discovery

    /// Computes the Lowest Common Ancestor (`SnapshotID?`) and hop distances for `leftID` and `rightID`.
    public func findLowestCommonAncestor(
        leftID: SnapshotID,
        rightID: SnapshotID,
        in snapshots: [SnapshotNode]
    ) throws -> (lcaID: SnapshotID?, distanceLeft: Int, distanceRight: Int) {
        _ = try validateLineageDAG(snapshots: snapshots)

        var byID: [SnapshotID: SnapshotNode] = [:]
        for s in snapshots { byID[s.id] = s }

        guard byID[leftID] != nil else {
            throw AgentVMError.snapshotNotFound(leftID)
        }
        guard byID[rightID] != nil else {
            throw AgentVMError.snapshotNotFound(rightID)
        }

        var leftAncestors: [SnapshotID: Int] = [:]
        var cur: SnapshotID? = leftID
        var dist = 0
        while let cid = cur, let node = byID[cid] {
            leftAncestors[cid] = dist
            cur = node.parentSnapshotID
            dist += 1
        }

        var rCur: SnapshotID? = rightID
        var rDist = 0
        while let rid = rCur, let rNode = byID[rid] {
            if let lDist = leftAncestors[rid] {
                return (lcaID: rid, distanceLeft: lDist, distanceRight: rDist)
            }
            rCur = rNode.parentSnapshotID
            rDist += 1
        }

        return (lcaID: nil, distanceLeft: leftAncestors.count - 1, distanceRight: rDist - 1)
    }

    // MARK: - Binary Disk Extent & VM Configuration Diffing

    /// Computes a full `SnapshotDiffReport` between two snapshots, combining chunked 64 KiB binary disk
    /// divergence scanning with structured `VMSpec` field diffs.
    public func diffSnapshots(
        leftID: SnapshotID,
        rightID: SnapshotID,
        in snapshots: [SnapshotNode],
        computeChecksums: Bool = true
    ) throws -> SnapshotDiffReport {
        let lcaInfo = try findLowestCommonAncestor(leftID: leftID, rightID: rightID, in: snapshots)

        var byID: [SnapshotID: SnapshotNode] = [:]
        for s in snapshots { byID[s.id] = s }

        guard let leftNode = byID[leftID] else { throw AgentVMError.snapshotNotFound(leftID) }
        guard let rightNode = byID[rightID] else { throw AgentVMError.snapshotNotFound(rightID) }

        let configDiffs = computeVMSpecFieldDiffs(left: leftNode.specSnapshot, right: rightNode.specSnapshot)
        let leftURL = URL(fileURLWithPath: leftNode.diskClonePath)
        let rightURL = URL(fileURLWithPath: rightNode.diskClonePath)

        let divergent = try computeDivergentDiskExtents(
            leftURL: leftURL,
            rightURL: rightURL,
            computeChecksums: computeChecksums
        )

        return SnapshotDiffReport(
            leftSnapshotID: leftID,
            rightSnapshotID: rightID,
            lowestCommonAncestorID: lcaInfo.lcaID,
            ancestorDistanceLeft: lcaInfo.distanceLeft,
            ancestorDistanceRight: lcaInfo.distanceRight,
            divergentBlockCount: divergent.divergentChunkCount,
            divergentBytes: divergent.divergentBytes,
            divergentExtents: divergent.coalescedExtents,
            configDiffs: configDiffs,
            computedAt: Date()
        )
    }

    /// Scans two raw/CoW disk images directly and returns coalesced `SparseExtent` ranges (`.allocatedDirty`)
    /// wherever their 64 KiB blocks differ.
    public func computeDivergentDiskExtents(
        leftURL: URL,
        rightURL: URL,
        computeChecksums: Bool = false
    ) throws -> (divergentChunkCount: Int, divergentBytes: UInt64, coalescedExtents: [SparseExtent]) {
        let leftPath = leftURL.path
        let rightPath = rightURL.path

        let leftFD = Darwin.open(leftPath, O_RDONLY | O_CLOEXEC)
        guard leftFD >= 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: leftPath,
                errnoCode: err,
                detail: "Cannot open left snapshot disk for diff (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }
        defer { _ = Darwin.close(leftFD) }

        let rightFD = Darwin.open(rightPath, O_RDONLY | O_CLOEXEC)
        guard rightFD >= 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: rightPath,
                errnoCode: err,
                detail: "Cannot open right snapshot disk for diff (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }
        defer { _ = Darwin.close(rightFD) }

        var lStat = Darwin.stat()
        var rStat = Darwin.stat()
        guard Darwin.fstat(leftFD, &lStat) == 0, Darwin.fstat(rightFD, &rStat) == 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: rightPath,
                errnoCode: err,
                detail: "fstat failed during snapshot disk diff (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }

        let leftSize = UInt64(max(0, lStat.st_size))
        let rightSize = UInt64(max(0, rStat.st_size))
        let maxSize = max(leftSize, rightSize)
        if maxSize == 0 {
            return (0, 0, [])
        }

        let chunkCap = diskEngine.comparisonChunkBytes
        let lBuf = UnsafeMutableRawPointer.allocate(byteCount: chunkCap, alignment: 8)
        let rBuf = UnsafeMutableRawPointer.allocate(byteCount: chunkCap, alignment: 8)
        defer {
            lBuf.deallocate()
            rBuf.deallocate()
        }

        var divergentChunks = 0
        var divergentBytes: UInt64 = 0
        var extents: [SparseExtent] = []
        var activeStart: UInt64?
        var activeLen: UInt64 = 0
        var activeCRC = IncrementalCRC32()

        func flushActiveExtent() {
            guard let start = activeStart, activeLen > 0 else { return }
            extents.append(SparseExtent(
                offsetBytes: start,
                lengthBytes: activeLen,
                kind: .allocatedDirty,
                checksumCRC32: computeChecksums ? activeCRC.finalized : nil
            ))
            activeStart = nil
            activeLen = 0
        }

        var cursor: UInt64 = 0
        while cursor < maxSize {
            let nextLeft = cursor < leftSize
                ? APFSCoWDiskEngine.seekNextDataOffset(fd: leftFD, from: cursor, fileSize: leftSize)
                : nil
            let nextRight = cursor < rightSize
                ? APFSCoWDiskEngine.seekNextDataOffset(fd: rightFD, from: cursor, fileSize: rightSize)
                : nil

            // Account for virtual size mismatch even if tail of larger disk is a sparse hole:
            // within [min(leftSize, rightSize), maxSize), if both are zero/out-of-bounds, check whether tail differs.
            let earliestData: UInt64?
            switch (nextLeft, nextRight) {
            case (nil, nil): earliestData = nil
            case let (.some(l), nil): earliestData = l
            case let (nil, .some(r)): earliestData = r
            case let (.some(l), .some(r)): earliestData = min(l, r)
            }

            guard let start = earliestData, start < maxSize else {
                flushActiveExtent()
                break
            }

            if start > cursor {
                flushActiveExtent()
                cursor = start
            }

            let leftHole = cursor < leftSize
                ? APFSCoWDiskEngine.seekNextHoleOffset(fd: leftFD, from: cursor, fileSize: leftSize)
                : cursor
            let rightHole = cursor < rightSize
                ? APFSCoWDiskEngine.seekNextHoleOffset(fd: rightFD, from: cursor, fileSize: rightSize)
                : cursor
            let spanEnd = min(maxSize, max(leftHole, rightHole))

            var pos = cursor
            while pos < spanEnd {
                let len = Int(min(UInt64(chunkCap), spanEnd - pos))

                if pos >= leftSize {
                    memset(lBuf, 0, len)
                } else {
                    let lr = Int(min(UInt64(len), leftSize - pos))
                    try APFSCoWDiskEngine.preadExact(fd: leftFD, path: leftPath, into: lBuf, count: lr, offset: pos)
                    if lr < len { memset(lBuf.advanced(by: lr), 0, len - lr) }
                }

                if pos >= rightSize {
                    memset(rBuf, 0, len)
                } else {
                    let rr = Int(min(UInt64(len), rightSize - pos))
                    try APFSCoWDiskEngine.preadExact(fd: rightFD, path: rightPath, into: rBuf, count: rr, offset: pos)
                    if rr < len { memset(rBuf.advanced(by: rr), 0, len - rr) }
                }

                if memcmp(lBuf, rBuf, len) != 0 {
                    divergentChunks += 1
                    divergentBytes += UInt64(len)
                    let rSlice = UnsafeRawBufferPointer(start: rBuf, count: len)
                    if let curStart = activeStart, curStart + activeLen == pos {
                        activeLen += UInt64(len)
                        if computeChecksums { activeCRC.update(rSlice) }
                    } else {
                        flushActiveExtent()
                        activeStart = pos
                        activeLen = UInt64(len)
                        if computeChecksums {
                            activeCRC = IncrementalCRC32()
                            activeCRC.update(rSlice)
                        }
                    }
                } else {
                    flushActiveExtent()
                }

                pos += UInt64(len)
            }

            flushActiveExtent()
            cursor = spanEnd
        }

        return (divergentChunks, divergentBytes, extents)
    }

    /// Computes human-readable field differences across two `VMSpec` snapshots.
    public func computeVMSpecFieldDiffs(left: VMSpec, right: VMSpec) -> [SnapshotConfigFieldDiff] {
        var diffs: [SnapshotConfigFieldDiff] = []

        func check(_ path: String, _ lVal: String, _ rVal: String) {
            if lVal != rVal {
                diffs.append(SnapshotConfigFieldDiff(fieldName: path, leftValue: lVal, rightValue: rVal))
            }
        }

        check("name", left.name, right.name)
        check("guestOS", left.guestOS.rawValue, right.guestOS.rawValue)
        check("bootLoader", left.bootLoader.summaryLabel, right.bootLoader.summaryLabel)
        check("compute.vcpuCount", "\(left.compute.vcpuCount)", "\(right.compute.vcpuCount)")
        check("compute.memoryMB", "\(left.compute.memoryMB)", "\(right.compute.memoryMB)")
        check("compute.cpuQuotaPercent", "\(left.compute.cpuQuotaPercent)", "\(right.compute.cpuQuotaPercent)")
        check("compute.enableBalloonDevice", "\(left.compute.enableBalloonDevice)", "\(right.compute.enableBalloonDevice)")
        check("blockDevices.count", "\(left.blockDevices.count)", "\(right.blockDevices.count)")
        check("virtioFSMounts.count", "\(left.virtioFSMounts.count)", "\(right.virtioFSMounts.count)")
        check("networkInterfaces.count", "\(left.networkInterfaces.count)", "\(right.networkInterfaces.count)")

        if let lNIC = left.networkInterfaces.first, let rNIC = right.networkInterfaces.first {
            check("network[0].mode", lNIC.mode.rawValue, rNIC.mode.rawValue)
            check("network[0].ipv4Address", lNIC.ipv4Address, rNIC.ipv4Address)
            check("network[0].firewallPolicyID", lNIC.firewallPolicyID?.rawValue ?? "none", rNIC.firewallPolicyID?.rawValue ?? "none")
        }

        if let lCI = left.cloudInit, let rCI = right.cloudInit {
            check("cloudInit.hostname", lCI.hostname, rCI.hostname)
            check("cloudInit.defaultUser", lCI.defaultUser, rCI.defaultUser)
            check("cloudInit.aptPackages", lCI.aptPackages.joined(separator: ","), rCI.aptPackages.joined(separator: ","))
        } else if (left.cloudInit == nil) != (right.cloudInit == nil) {
            check("cloudInit", left.cloudInit == nil ? "disabled" : "enabled", right.cloudInit == nil ? "disabled" : "enabled")
        }

        return diffs
    }

    // MARK: - Policy-Driven Snapshot Garbage Collection Planner & Pruner

    /// Computes a deterministic `GarbageCollectionPlan` respecting `GarbageCollectionPolicy`, pinned nodes,
    /// active VM head snapshots, golden base images, branch fork points, and parent reparenting links.
    public func planGarbageCollection(
        snapshots: [SnapshotNode],
        activeHeadIDs: Set<SnapshotID> = [],
        policy: GarbageCollectionPolicy = GarbageCollectionPolicy(),
        referenceDate: Date = Date()
    ) throws -> GarbageCollectionPlan {
        let dagReport = try validateLineageDAG(snapshots: snapshots)

        var byID: [SnapshotID: SnapshotNode] = [:]
        for s in snapshots { byID[s.id] = s }

        var protected = Set<SnapshotID>()
        // 1. Protect explicitly active VM heads, pinned snapshots, and base golden images.
        for s in snapshots {
            if activeHeadIDs.contains(s.id) || s.isPinned || s.kind == .baseGoldenImage {
                protected.insert(s.id)
            }
        }

        // 2. Protect branch fork points if configured.
        if policy.preserveBranchForkPoints {
            for forkID in dagReport.forkPointSnapshotIDs {
                protected.insert(forkID)
            }
        }

        // 3. Keep at least `keepMinimumPerBranch` newest snapshots on every branch.
        let keepCount = max(0, policy.keepMinimumPerBranch)
        let byBranch = Dictionary(grouping: snapshots, by: \.branchName)
        for (_, branchNodes) in byBranch {
            let newestFirst = branchNodes.sorted { lhs, rhs in
                if lhs.createdAt != rhs.createdAt { return lhs.createdAt > rhs.createdAt }
                return lhs.id > rhs.id
            }
            for node in newestFirst.prefix(keepCount) {
                protected.insert(node.id)
            }
        }

        let maxAgeSeconds = Double(max(0, policy.maxUnpinnedAgeHours)) * 3600.0
        var totalPoolBytes = snapshots.reduce(UInt64(0)) { acc, node in
            let diskCost = node.dirtyDeltaBytes > 0 ? node.dirtyDeltaBytes : node.allocatedDiskBytes
            return acc + diskCost + node.memoryStateBytes
        }

        // Candidate selection: oldest unpinned non-protected snapshots first.
        let oldestFirst = snapshots.sorted { lhs, rhs in
            if lhs.createdAt != rhs.createdAt { return lhs.createdAt < rhs.createdAt }
            return lhs.id < rhs.id
        }

        var candidateSet = Set<SnapshotID>()
        var candidatesOrdered: [SnapshotID] = []
        var reclaimDisk: UInt64 = 0
        var reclaimMem: UInt64 = 0

        for node in oldestFirst {
            if protected.contains(node.id) { continue }
            let ageSeconds = referenceDate.timeIntervalSince(node.createdAt)
            let isExpired = ageSeconds >= maxAgeSeconds
            let overQuota = totalPoolBytes > policy.maxTotalSnapshotPoolBytes

            if isExpired || overQuota {
                candidateSet.insert(node.id)
                candidatesOrdered.append(node.id)
                let diskContribution = node.dirtyDeltaBytes > 0 ? node.dirtyDeltaBytes : node.allocatedDiskBytes
                reclaimDisk += diskContribution
                reclaimMem += node.memoryStateBytes
                let totalContribution = diskContribution + node.memoryStateBytes
                totalPoolBytes = totalPoolBytes > totalContribution ? (totalPoolBytes - totalContribution) : 0
            } else {
                protected.insert(node.id)
            }
        }

        // Compute safe parent reparentings for any surviving snapshot whose immediate parent is pruned.
        var reparentings: [SnapshotID: SnapshotID?] = [:]
        for node in snapshots where !candidateSet.contains(node.id) {
            guard let immediateParent = node.parentSnapshotID, candidateSet.contains(immediateParent) else {
                continue
            }
            var ancestor: SnapshotID? = immediateParent
            while let aid = ancestor, candidateSet.contains(aid) {
                ancestor = byID[aid]?.parentSnapshotID
            }
            reparentings[node.id] = ancestor
        }

        return GarbageCollectionPlan(
            candidateSnapshotIDs: candidatesOrdered,
            protectedSnapshotIDs: protected.sorted(),
            reclaimableDiskBytes: reclaimDisk,
            reclaimableMemoryStateBytes: reclaimMem,
            reparentings: reparentings
        )
    }

    /// Executes physical file deletion (`unlink`) for disk clones and live RAM state files listed in `plan`,
    /// returning the updated array of surviving `SnapshotNode` records with `reparentings` applied.
    public func executeGarbageCollection(
        plan: GarbageCollectionPlan,
        snapshots: [SnapshotNode]
    ) throws -> [SnapshotNode] {
        let candidateSet = Set(plan.candidateSnapshotIDs)
        for snap in snapshots where candidateSet.contains(snap.id) {
            if !snap.diskClonePath.isEmpty {
                if Darwin.unlink(snap.diskClonePath) != 0 && Darwin.errno != ENOENT {
                    let err = Darwin.errno
                    throw AgentVMError.diskImageOperationFailed(
                        path: snap.diskClonePath,
                        errnoCode: err,
                        detail: "Failed to unlink pruned CoW snapshot disk (\(APFSCoWDiskEngine.posixErrorString(err)))."
                    )
                }
            }
            if let memPath = snap.memoryStatePath, !memPath.isEmpty {
                if Darwin.unlink(memPath) != 0 && Darwin.errno != ENOENT {
                    let err = Darwin.errno
                    throw AgentVMError.diskImageOperationFailed(
                        path: memPath,
                        errnoCode: err,
                        detail: "Failed to unlink pruned snapshot memory state (\(APFSCoWDiskEngine.posixErrorString(err)))."
                    )
                }
            }
        }

        var survivors: [SnapshotNode] = []
        survivors.reserveCapacity(snapshots.count - candidateSet.count)
        for var snap in snapshots where !candidateSet.contains(snap.id) {
            if let newParentEntry = plan.reparentings[snap.id] {
                snap.parentSnapshotID = newParentEntry
            }
            survivors.append(snap)
        }
        return survivors
    }
}
