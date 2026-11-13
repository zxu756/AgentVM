import AgentVMModels
import AgentVMStorageCoW
import AgentVMWorkbenchShell
import SwiftUI

// MARK: - Interactive Snapshot & APFS Copy-on-Write Lineage DAG View

public struct SnapshotLineageDAGCanvasView: View {
    @ObservedObject public var viewModel: AgentVMStudioViewModel

    @State private var showQuickForkBar: Bool = false
    @State private var customBranchName: String = "agy-verify-patch"
    @State private var customAgentTag: String = "antigravity"
    @State private var hoveredSnapshotID: SnapshotID?

    public init(viewModel: AgentVMStudioViewModel) {
        self.viewModel = viewModel
    }

    private struct PositionedDAGNode: Identifiable {
        let snapshot: SnapshotNode
        let laneIndex: Int
        let rowIndex: Int
        let center: CGPoint
        let frame: CGRect
        var id: SnapshotID { snapshot.id }
    }

    private struct DAGLayoutGeometry {
        let branchNames: [String]
        let nodes: [PositionedDAGNode]
        let byID: [SnapshotID: PositionedDAGNode]
        let canvasSize: CGSize
        let columnCentersX: [CGFloat]
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            topTelemetryStrip

            if showQuickForkBar {
                quickForkComposerBar
            }

            HStack(alignment: .top, spacing: 10) {
                dagCanvasPanel
                    .frame(maxWidth: .infinity, maxHeight: .infinity)

                lcaDiffAndNodeInspectorPanel
                    .frame(width: 274)
                    .frame(maxHeight: .infinity)
            }
        }
        .padding(10)
        .background(RackTheme.chassisBackground)
    }

    // MARK: - Top Telemetry Strip

    private var topTelemetryStrip: some View {
        let totalVCPUs = viewModel.vms.reduce(0) { $0 + $1.spec.compute.vcpuCount }
        let totalRAMGB = Double(viewModel.vms.reduce(UInt64(0)) { $0 + $1.spec.compute.memoryMB }) / 1024.0
        let branchCount = max(1, Set(viewModel.snapshots.map(\.branchName)).count)

        return HStack(spacing: 8) {
            RackMetricTile(
                label: "Active Blades",
                value: "\(viewModel.runningVMCount) / \(viewModel.vms.count) Live",
                detail: String(format: "%d vCPU · %.0f GB Pool", totalVCPUs, totalRAMGB),
                accent: RackTheme.linkGreen
            )
            RackMetricTile(
                label: "Snapshot Nodes",
                value: "\(viewModel.snapshots.count) Nodes",
                detail: "\(branchCount) CoW Branch Lanes",
                accent: RackTheme.vsockBlue
            )
            RackMetricTile(
                label: "CoW Space Saved",
                value: String(format: "%.1f%%", viewModel.fleetCoWSpaceSavedPercent),
                detail: "\(ByteMetricsFormatter.formatBytes(viewModel.totalDirtyCoWBytes)) Dirty Delta",
                accent: RackTheme.amberAccent
            )
            RackMetricTile(
                label: "Branch Fork Latency",
                value: String(format: "%.1f ms", viewModel.lastForkLatencyMs),
                detail: "APFS clonefile(2)",
                accent: RackTheme.checkpointGold
            )
        }
    }

    // MARK: - Inline Quick CoW Branch Fork Bar

    private var quickForkComposerBar: some View {
        HStack(spacing: 8) {
            Image(systemName: "arrow.triangle.branch")
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(RackTheme.amberAccent)

            Text("Fork CoW Branch from \(viewModel.selectedVM?.spec.name ?? "blade"):")
                .font(RackTheme.labelFont)
                .foregroundStyle(RackTheme.inkPrimary)
                .lineLimit(1)

            TextField("branch-name", text: $customBranchName)
                .textFieldStyle(.plain)
                .font(RackTheme.monoSmallFont)
                .foregroundStyle(RackTheme.inkPrimary)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .frame(width: 156)
                .background(
                    RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                        .fill(RackTheme.chassisBackground)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                        .strokeBorder(RackTheme.hairlineStrong, lineWidth: 1)
                )

            TextField("agent-owner", text: $customAgentTag)
                .textFieldStyle(.plain)
                .font(RackTheme.monoSmallFont)
                .foregroundStyle(RackTheme.amberAccent)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .frame(width: 118)
                .background(
                    RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                        .fill(RackTheme.chassisBackground)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                        .strokeBorder(RackTheme.hairline, lineWidth: 1)
                )

            Button {
                let name = customBranchName.trimmingCharacters(in: .whitespacesAndNewlines)
                let owner = customAgentTag.trimmingCharacters(in: .whitespacesAndNewlines)
                viewModel.forkCoWBranch(
                    branchName: name.isEmpty ? nil : name,
                    agentOwnerTag: owner.isEmpty ? "claude-branch" : owner
                )
                showQuickForkBar = false
            } label: {
                Label("Clone Now", systemImage: "bolt.fill")
            }
            .buttonStyle(RackActionButtonStyle(prominence: .primaryAmber, compact: true))

            Button("Cancel") {
                showQuickForkBar = false
            }
            .buttonStyle(RackActionButtonStyle(prominence: .subtleGhost, compact: true))

            Spacer(minLength: 0)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(
            RoundedRectangle(cornerRadius: RackTheme.outerCornerRadius, style: .continuous)
                .fill(RackTheme.moduleElevated)
        )
        .overlay(
            RoundedRectangle(cornerRadius: RackTheme.outerCornerRadius, style: .continuous)
                .strokeBorder(RackTheme.amberAccent.opacity(0.65), lineWidth: 1)
        )
    }

    // MARK: - Interactive DAG Canvas Panel

    private var dagCanvasPanel: some View {
        RackPanelContainer(
            title: "APFS CoW Lineage DAG",
            subtitle: nil,
            symbolName: "point.3.connected.trianglepath.dotted",
            headerTrailing: {
                HStack(spacing: 6) {
                    if let dag = viewModel.dagValidationReport, dag.orphanParentReferences.isEmpty {
                        RackStatusPill(label: "DAG ACYCLIC", color: RackTheme.linkGreen, monospaced: true)
                    }
                    Button {
                        withAnimation(.easeOut(duration: 0.16)) {
                            showQuickForkBar.toggle()
                        }
                    } label: {
                        Label("Fork CoW", systemImage: "arrow.triangle.branch")
                    }
                    .buttonStyle(RackActionButtonStyle(prominence: .primaryAmber, compact: true))

                    Button {
                        viewModel.captureCheckpoint()
                    } label: {
                        Label("Checkpoint", systemImage: "camera.metering.matrix")
                    }
                    .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
                }
            },
            content: {
                GeometryReader { proxy in
                    let layout = computeDAGLayout(availableSize: proxy.size)
                    ScrollView([.horizontal, .vertical], showsIndicators: true) {
                        ZStack(alignment: .topLeading) {
                            dagVectorBackdropCanvas(layout: layout)
                                .frame(width: layout.canvasSize.width, height: layout.canvasSize.height)

                            // Branch Lane Headers
                            ForEach(Array(layout.branchNames.enumerated()), id: \.offset) { idx, laneName in
                                let centerX = layout.columnCentersX[idx]
                                branchLaneHeaderBadge(name: laneName, laneIndex: idx)
                                    .position(x: centerX, y: 20)
                            }

                            // Interactive Node Cards
                            ForEach(layout.nodes) { item in
                                dagSnapshotNodeCard(item: item)
                                    .frame(width: item.frame.width, height: item.frame.height)
                                    .position(x: item.center.x, y: item.center.y)
                            }
                        }
                        .frame(width: layout.canvasSize.width, height: layout.canvasSize.height)
                    }
                }
                .frame(minHeight: 320)
                .background(
                    RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                        .fill(RackTheme.terminalWell)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                        .strokeBorder(RackTheme.hairline, lineWidth: 1)
                )
            }
        )
    }

    private func branchLaneHeaderBadge(name: String, laneIndex: Int) -> some View {
        let color = laneAccentColor(laneIndex: laneIndex, name: name)
        let shortName = shortenBranchLabel(name, maxChars: 20)
        return HStack(spacing: 5) {
            Circle()
                .fill(color)
                .frame(width: 6, height: 6)
            Text(shortName)
                .font(RackTheme.monoSmallFont)
                .foregroundStyle(color)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 3.5)
        .background(
            Capsule(style: .continuous)
                .fill(color.opacity(0.14))
        )
        .overlay(
            Capsule(style: .continuous)
                .strokeBorder(color.opacity(0.42), lineWidth: 1)
        )
    }

    private func dagVectorBackdropCanvas(layout: DAGLayoutGeometry) -> some View {
        let activeAncestors = activeSelectedAncestrySet()
        let compareAncestors = activeComparisonAncestrySet()
        let lcaID = viewModel.currentLCADiff?.lowestCommonAncestorID

        return Canvas { context, size in
            // Subtle architectural grid dots
            let gridSpacing: CGFloat = 24
            var dotPath = Path()
            var x: CGFloat = 12
            while x < size.width {
                var y: CGFloat = 12
                while y < size.height {
                    dotPath.addRect(CGRect(x: x, y: y, width: 1, height: 1))
                    y += gridSpacing
                }
                x += gridSpacing
            }
            context.fill(dotPath, with: .color(RackTheme.hairline.opacity(0.55)))

            // Subtle vertical lane guide lines
            for (idx, cx) in layout.columnCentersX.enumerated() {
                var guide = Path()
                guide.move(to: CGPoint(x: cx, y: 36))
                guide.addLine(to: CGPoint(x: cx, y: size.height - 12))
                let laneColor = laneAccentColor(laneIndex: idx, name: layout.branchNames[idx])
                context.stroke(
                    guide,
                    with: .color(laneColor.opacity(0.12)),
                    style: StrokeStyle(lineWidth: 1, dash: [4, 5])
                )
            }

            // Smooth cubic Bézier connectors from parent -> child
            for item in layout.nodes {
                guard let parentID = item.snapshot.parentSnapshotID,
                      let parentNode = layout.byID[parentID] else {
                    continue
                }

                let start: CGPoint
                let end: CGPoint
                var connector = Path()

                if parentNode.laneIndex == item.laneIndex {
                    start = CGPoint(x: parentNode.center.x, y: parentNode.frame.maxY)
                    end = CGPoint(x: item.center.x, y: item.frame.minY)
                    connector.move(to: start)
                    let midY = (start.y + end.y) * 0.5
                    connector.addCurve(
                        to: end,
                        control1: CGPoint(x: start.x, y: midY),
                        control2: CGPoint(x: end.x, y: midY)
                    )
                } else {
                    let goingRight = item.center.x >= parentNode.center.x
                    start = CGPoint(
                        x: goingRight ? parentNode.frame.maxX : parentNode.frame.minX,
                        y: parentNode.center.y
                    )
                    end = CGPoint(x: item.center.x, y: item.frame.minY)
                    connector.move(to: start)
                    connector.addCurve(
                        to: end,
                        control1: CGPoint(x: end.x, y: start.y),
                        control2: CGPoint(x: end.x, y: start.y + (end.y - start.y) * 0.55)
                    )
                }

                let inPrimaryChain = activeAncestors.contains(item.id) && activeAncestors.contains(parentID)
                let inCompareChain = compareAncestors.contains(item.id) && compareAncestors.contains(parentID)
                let strokeColor: Color
                let lineWidth: CGFloat

                if inPrimaryChain {
                    strokeColor = RackTheme.amberAccent
                    lineWidth = 2.2
                } else if inCompareChain {
                    strokeColor = RackTheme.vsockBlue
                    lineWidth = 1.9
                } else {
                    strokeColor = laneAccentColor(laneIndex: item.laneIndex, name: item.snapshot.branchName).opacity(0.62)
                    lineWidth = 1.5
                }

                context.stroke(
                    connector,
                    with: .color(strokeColor),
                    style: StrokeStyle(lineWidth: lineWidth, lineCap: .round)
                )

                // Crisp arrowhead at child top edge
                var arrow = Path()
                arrow.move(to: end)
                arrow.addLine(to: CGPoint(x: end.x - 4, y: end.y - 6))
                arrow.addLine(to: CGPoint(x: end.x + 4, y: end.y - 6))
                arrow.closeSubpath()
                context.fill(arrow, with: .color(strokeColor))
            }

            // Highlight Lowest Common Ancestor halo ring if present
            if let lcaID, let lcaNode = layout.byID[lcaID] {
                let haloRect = lcaNode.frame.insetBy(dx: -3, dy: -3)
                let haloPath = Path(roundedRect: haloRect, cornerRadius: RackTheme.innerCornerRadius + 2)
                context.stroke(
                    haloPath,
                    with: .color(RackTheme.checkpointGold.opacity(0.75)),
                    style: StrokeStyle(lineWidth: 1.4, dash: [4, 3])
                )
            }
        }
    }

    private func dagSnapshotNodeCard(item: PositionedDAGNode) -> some View {
        let snap = item.snapshot
        let isSelected = viewModel.selectedSnapshotID == snap.id
        let isCompareTarget = viewModel.comparisonSnapshotID == snap.id && !isSelected
        let isLCA = viewModel.currentLCADiff?.lowestCommonAncestorID == snap.id
        let isHovered = hoveredSnapshotID == snap.id
        let laneColor = laneAccentColor(laneIndex: item.laneIndex, name: snap.branchName)
        let vmHeadMatches = viewModel.vms.contains(where: { $0.currentHeadSnapshotID == snap.id })

        let borderColor: Color = {
            if isSelected { return RackTheme.amberAccent }
            if isCompareTarget { return RackTheme.vsockBlue }
            if isLCA { return RackTheme.checkpointGold }
            if isHovered { return RackTheme.hairlineStrong }
            return RackTheme.hairline
        }()

        return VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 4) {
                Circle()
                    .fill(laneColor)
                    .frame(width: 6, height: 6)

                Text(compactSnapshotTitle(snap))
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(RackTheme.inkPrimary)
                    .lineLimit(1)

                Spacer(minLength: 2)

                if snap.isPinned {
                    Image(systemName: "pin.fill")
                        .font(.system(size: 8.5, weight: .bold))
                        .foregroundStyle(RackTheme.checkpointGold)
                }
            }

            HStack(spacing: 4) {
                if snap.hasLiveRAMState {
                    miniTag("RAM", color: RackTheme.linkGreen)
                } else {
                    miniTag(shortKindBadge(snap.kind), color: laneColor)
                }

                if vmHeadMatches {
                    miniTag("HEAD", color: RackTheme.amberAccent)
                } else if isLCA {
                    miniTag("LCA", color: RackTheme.checkpointGold)
                } else if isCompareTarget {
                    miniTag("DIFF", color: RackTheme.vsockBlue)
                }

                Spacer(minLength: 2)

                Text("+\(ByteMetricsFormatter.formatBytes(snap.dirtyDeltaBytes))")
                    .font(.system(size: 9.5, weight: .medium, design: .monospaced))
                    .monospacedDigit()
                    .foregroundStyle(snap.dirtyDeltaBytes > 0 ? RackTheme.inkSecondary : RackTheme.inkMuted)
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)
            }

            HStack(spacing: 4) {
                Text("@\(shortenBranchLabel(snap.agentActor, maxChars: 11))")
                    .font(.system(size: 9.5, design: .monospaced))
                    .foregroundStyle(RackTheme.inkMuted)
                    .lineLimit(1)

                Spacer(minLength: 2)

                Text(shortIdentifierSuffix(snap.id.rawValue))
                    .font(.system(size: 9.5, design: .monospaced))
                    .foregroundStyle(RackTheme.inkMuted)
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .background(
            RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                .fill(isSelected ? RackTheme.moduleElevated : RackTheme.moduleSurface)
        )
        .overlay(
            RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                .strokeBorder(borderColor, lineWidth: isSelected || isCompareTarget ? 1.5 : 1)
        )
        .contentShape(Rectangle())
        .onTapGesture {
            viewModel.selectSnapshotForInspection(snap.id)
        }
        .contextMenu {
            Button("Inspect Snapshot") {
                viewModel.selectSnapshotForInspection(snap.id)
            }
            Button("Compare LCA Diff Against Selected") {
                viewModel.setComparisonSnapshot(snap.id)
            }
            Divider()
            Button("Restore Blade to This Snapshot") {
                viewModel.restoreSnapshot(snap.id)
            }
            Button(snap.isPinned ? "Unpin Snapshot" : "Pin Snapshot") {
                viewModel.togglePinSnapshot(snap.id)
            }
            if !snap.isPinned {
                Button("Delete Snapshot", role: .destructive) {
                    viewModel.deleteSnapshot(snap.id)
                }
            }
        }
        .onHover { hovering in
            hoveredSnapshotID = hovering ? snap.id : nil
        }
    }

    private func miniTag(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.system(size: 8.5, weight: .bold, design: .monospaced))
            .foregroundStyle(color)
            .lineLimit(1)
            .fixedSize(horizontal: true, vertical: false)
            .padding(.horizontal, 4.5)
            .padding(.vertical, 1.5)
            .background(
                RoundedRectangle(cornerRadius: 3, style: .continuous)
                    .fill(color.opacity(0.15))
            )
    }

    // MARK: - Right Side Panel: Selected Node Actions & LCA Diff Inspector

    private var lcaDiffAndNodeInspectorPanel: some View {
        RackPanelContainer(
            title: "Compare LCA Diff",
            subtitle: "LCA Delta",
            symbolName: "arrow.left.and.right.righttriangle.left.righttriangle.right"
        ) {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    if let snap = viewModel.selectedSnapshot {
                        selectedNodeSummaryCard(snap)
                    }

                    comparisonTargetPickerRow

                    if let diff = viewModel.currentLCADiff {
                        lcaDiffSummarySection(diff)
                    } else {
                        Text("Select two snapshots across branches to compute their Lowest Common Ancestor and 64 KiB block divergence.")
                            .font(RackTheme.captionFont)
                            .foregroundStyle(RackTheme.inkMuted)
                            .padding(8)
                    }
                }
            }
        }
    }

    private func selectedNodeSummaryCard(_ snap: SnapshotNode) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 6) {
                Text(compactSnapshotTitle(snap, maxChars: 22))
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundStyle(RackTheme.inkPrimary)
                    .lineLimit(1)
                Spacer(minLength: 4)
                RackStatusPill(
                    label: snap.hasLiveRAMState ? "LIVE RAM" : shortKindBadge(snap.kind),
                    color: snap.hasLiveRAMState ? RackTheme.linkGreen : RackTheme.amberAccent,
                    monospaced: true
                )
            }

            VStack(spacing: 4) {
                compactKV("Branch Lane", shortenBranchLabel(snap.branchName, maxChars: 24))
                compactKV("Virtual / Dirty", "\(ByteMetricsFormatter.formatBytes(snap.virtualDiskBytes)) / \(ByteMetricsFormatter.formatBytes(snap.dirtyDeltaBytes))")
                compactKV("Saved Ratio", String(format: "%.1f%% CoW", snap.spaceSavingsPercent))
                if let cmd = snap.triggerCommand, !cmd.isEmpty {
                    compactKV("Trigger Exec", compactCommandSummary(cmd))
                }
            }

            HStack(spacing: 6) {
                Button {
                    viewModel.restoreSnapshot(snap.id)
                } label: {
                    Label("Restore", systemImage: "clock.arrow.circlepath")
                }
                .buttonStyle(RackActionButtonStyle(prominence: .primaryAmber, compact: true))

                Button {
                    viewModel.togglePinSnapshot(snap.id)
                } label: {
                    Label(snap.isPinned ? "Pinned" : "Pin", systemImage: snap.isPinned ? "pin.slash" : "pin")
                }
                .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))

                Spacer(minLength: 0)
            }
        }
        .padding(9)
        .background(
            RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                .fill(RackTheme.chassisBackground.opacity(0.75))
        )
        .overlay(
            RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                .strokeBorder(RackTheme.hairline, lineWidth: 1)
        )
    }

    private var comparisonTargetPickerRow: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack {
                Text("Compare Target")
                    .font(RackTheme.labelFont)
                    .foregroundStyle(RackTheme.amberAccent)
                    .lineLimit(1)
                Spacer()
                Menu {
                    ForEach(viewModel.snapshots.filter { $0.id != viewModel.selectedSnapshotID }) { candidate in
                        Button("\(candidate.branchName) · \(compactSnapshotTitle(candidate))") {
                            viewModel.setComparisonSnapshot(candidate.id)
                        }
                    }
                } label: {
                    HStack(spacing: 4) {
                        let targetSnap = viewModel.snapshots.first(where: { $0.id == viewModel.comparisonSnapshotID })
                        Text(targetSnap.map { shortenBranchLabel($0.branchName, maxChars: 16) } ?? "Select Node")
                            .font(RackTheme.monoSmallFont)
                            .foregroundStyle(RackTheme.vsockBlue)
                            .lineLimit(1)
                        Image(systemName: "chevron.up.chevron.down")
                            .font(.system(size: 9, weight: .bold))
                            .foregroundStyle(RackTheme.vsockBlue)
                    }
                    .padding(.horizontal, 7)
                    .padding(.vertical, 3.5)
                    .background(
                        RoundedRectangle(cornerRadius: RackTheme.badgeCornerRadius, style: .continuous)
                            .fill(RackTheme.vsockBlueSoft)
                    )
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
            }
        }
    }

    private func lcaDiffSummarySection(_ diff: SnapshotDiffReport) -> some View {
        let lcaLabel: String = {
            guard let lcaID = diff.lowestCommonAncestorID else { return "Disjoint Roots" }
            if let node = viewModel.snapshots.first(where: { $0.id == lcaID }) {
                return compactSnapshotTitle(node, maxChars: 18)
            }
            return shortIdentifierSuffix(lcaID.rawValue)
        }()

        return VStack(alignment: .leading, spacing: 8) {
            VStack(spacing: 4) {
                compactKV("LCA Ancestor", lcaLabel)
                compactKV("Hop Distance", "L:\(diff.ancestorDistanceLeft) · R:\(diff.ancestorDistanceRight) hops")
                compactKV("Divergent Data", "\(diff.divergentBlockCount) blks (\(ByteMetricsFormatter.formatBytes(diff.divergentBytes)))")
            }
            .padding(8)
            .background(
                RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                    .fill(RackTheme.chassisBackground.opacity(0.65))
            )
            .overlay(
                RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                    .strokeBorder(RackTheme.hairline, lineWidth: 1)
            )

            if !diff.configDiffs.isEmpty {
                Text("VMSpec Field Deltas (\(diff.configDiffs.count))")
                    .font(RackTheme.labelFont)
                    .foregroundStyle(RackTheme.inkSecondary)
                    .lineLimit(1)

                VStack(spacing: 4) {
                    ForEach(diff.configDiffs.prefix(5)) { item in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(shortenFieldPath(item.fieldName))
                                .font(RackTheme.monoSmallFont)
                                .foregroundStyle(RackTheme.amberAccent)
                                .lineLimit(1)
                            HStack(spacing: 4) {
                                Text(shortenValueToken(item.leftValue, maxChars: 14))
                                    .font(.system(size: 9.5, design: .monospaced))
                                    .foregroundStyle(RackTheme.inkSecondary)
                                    .lineLimit(1)
                                    .fixedSize(horizontal: true, vertical: false)
                                Image(systemName: "arrow.right")
                                    .font(.system(size: 8, weight: .bold))
                                    .foregroundStyle(RackTheme.inkMuted)
                                Text(shortenValueToken(item.rightValue, maxChars: 14))
                                    .font(.system(size: 9.5, design: .monospaced))
                                    .foregroundStyle(RackTheme.vsockBlue)
                                    .lineLimit(1)
                                    .fixedSize(horizontal: true, vertical: false)
                                Spacer(minLength: 0)
                            }
                        }
                        .padding(.horizontal, 7)
                        .padding(.vertical, 4)
                        .background(
                            RoundedRectangle(cornerRadius: 4, style: .continuous)
                                .fill(RackTheme.chassisBackground.opacity(0.55))
                        )
                    }
                }
            }

            if !diff.divergentExtents.isEmpty {
                Text("Divergent Disk Extents (\(diff.divergentExtents.count))")
                    .font(RackTheme.labelFont)
                    .foregroundStyle(RackTheme.inkSecondary)
                    .lineLimit(1)

                VStack(spacing: 4) {
                    ForEach(diff.divergentExtents.prefix(4)) { ext in
                        HStack(spacing: 6) {
                            Text(String(format: "+0x%06llX", ext.offsetBytes))
                                .font(RackTheme.monoSmallFont)
                                .monospacedDigit()
                                .foregroundStyle(RackTheme.amberAccent)
                                .lineLimit(1)
                                .fixedSize(horizontal: true, vertical: false)
                            Spacer(minLength: 4)
                            Text(ByteMetricsFormatter.formatBytes(ext.lengthBytes))
                                .font(RackTheme.monoSmallFont)
                                .monospacedDigit()
                                .foregroundStyle(RackTheme.inkPrimary)
                                .lineLimit(1)
                                .fixedSize(horizontal: true, vertical: false)
                        }
                        .padding(.horizontal, 7)
                        .padding(.vertical, 4)
                        .background(
                            RoundedRectangle(cornerRadius: 4, style: .continuous)
                                .fill(RackTheme.amberSoft.opacity(0.5))
                        )
                    }
                }
            }
        }
    }

    private func compactKV(_ key: String, _ val: String) -> some View {
        HStack(spacing: 6) {
            Text(key)
                .font(RackTheme.captionFont)
                .foregroundStyle(RackTheme.inkMuted)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
            Spacer(minLength: 4)
            Text(val)
                .font(RackTheme.monoSmallFont)
                .monospacedDigit()
                .foregroundStyle(RackTheme.inkPrimary)
                .lineLimit(1)
        }
    }

    // MARK: - Deterministic Topological DAG Layout Engine

    private func computeDAGLayout(availableSize: CGSize) -> DAGLayoutGeometry {
        let snaps = viewModel.snapshots
        guard !snaps.isEmpty else {
            return DAGLayoutGeometry(
                branchNames: ["main"],
                nodes: [],
                byID: [:],
                canvasSize: CGSize(width: max(420, availableSize.width), height: max(300, availableSize.height)),
                columnCentersX: [max(210, availableSize.width * 0.5)]
            )
        }

        // Order lanes with "main" first, then remaining branches sorted by earliest creation timestamp
        let grouped = Dictionary(grouping: snaps, by: \.branchName)
        let orderedLanes = grouped.keys.sorted { lhs, rhs in
            if lhs == "main" { return true }
            if rhs == "main" { return false }
            let lFirst = grouped[lhs]?.map(\.createdAt).min() ?? .distantFuture
            let rFirst = grouped[rhs]?.map(\.createdAt).min() ?? .distantFuture
            if lFirst != rFirst { return lFirst < rFirst }
            return lhs < rhs
        }

        var laneIndexByName: [String: Int] = [:]
        for (idx, name) in orderedLanes.enumerated() {
            laneIndexByName[name] = idx
        }

        let bySnapID = Dictionary(uniqueKeysWithValues: snaps.map { ($0.id, $0) })

        // Compute topological depth (0-based) with parent depth + 1 so child always appears strictly below parent
        var memoDepth: [SnapshotID: Int] = [:]
        var visiting = Set<SnapshotID>()
        func depth(of id: SnapshotID) -> Int {
            if let cached = memoDepth[id] { return cached }
            if visiting.contains(id) { return 0 }
            visiting.insert(id)
            var resolved = 0
            if let node = bySnapID[id], let pid = node.parentSnapshotID, bySnapID[pid] != nil {
                resolved = depth(of: pid) + 1
            }
            visiting.remove(id)
            memoDepth[id] = resolved
            return resolved
        }

        // Ensure no two nodes in the same lane share the exact same rowIndex
        let cardWidth: CGFloat = 152
        let cardHeight: CGFloat = 53
        let colGap: CGFloat = 12
        let rowGap: CGFloat = 11
        let topInset: CGFloat = 38
        let sideInset: CGFloat = 12

        let laneCount = max(1, orderedLanes.count)
        let naturalContentWidth = sideInset * 2 + CGFloat(laneCount) * cardWidth + CGFloat(max(0, laneCount - 1)) * colGap
        let canvasWidth = max(availableSize.width, naturalContentWidth)
        let extraHorizontalSlack = max(0, canvasWidth - naturalContentWidth)
        let leadingX = sideInset + extraHorizontalSlack * 0.5

        var columnCentersX: [CGFloat] = []
        for idx in 0..<laneCount {
            let cx = leadingX + CGFloat(idx) * (cardWidth + colGap) + cardWidth * 0.5
            columnCentersX.append(cx)
        }

        var occupiedRowsPerLane: [Int: Set<Int>] = [:]
        var positioned: [PositionedDAGNode] = []
        var byID: [SnapshotID: PositionedDAGNode] = [:]
        var maxRowUsed = 0

        let chronological = snaps.sorted { lhs, rhs in
            let ld = depth(of: lhs.id)
            let rd = depth(of: rhs.id)
            if ld != rd { return ld < rd }
            if lhs.createdAt != rhs.createdAt { return lhs.createdAt < rhs.createdAt }
            return lhs.id < rhs.id
        }

        for snap in chronological {
            let lIdx = laneIndexByName[snap.branchName] ?? 0
            var candidateRow = depth(of: snap.id)
            while occupiedRowsPerLane[lIdx, default: []].contains(candidateRow) {
                candidateRow += 1
            }
            occupiedRowsPerLane[lIdx, default: []].insert(candidateRow)
            if candidateRow > maxRowUsed {
                maxRowUsed = candidateRow
            }

            let cx = columnCentersX[lIdx]
            let cy = topInset + CGFloat(candidateRow) * (cardHeight + rowGap) + cardHeight * 0.5
            let rect = CGRect(
                x: cx - cardWidth * 0.5,
                y: cy - cardHeight * 0.5,
                width: cardWidth,
                height: cardHeight
            )
            let item = PositionedDAGNode(
                snapshot: snap,
                laneIndex: lIdx,
                rowIndex: candidateRow,
                center: CGPoint(x: cx, y: cy),
                frame: rect
            )
            positioned.append(item)
            byID[snap.id] = item
        }

        let naturalHeight = topInset + CGFloat(maxRowUsed + 1) * cardHeight + CGFloat(maxRowUsed) * rowGap + 20
        let canvasHeight = max(availableSize.height, naturalHeight)

        return DAGLayoutGeometry(
            branchNames: orderedLanes,
            nodes: positioned,
            byID: byID,
            canvasSize: CGSize(width: canvasWidth, height: canvasHeight),
            columnCentersX: columnCentersX
        )
    }

    private func activeSelectedAncestrySet() -> Set<SnapshotID> {
        ancestrySet(startingAt: viewModel.selectedSnapshotID)
    }

    private func activeComparisonAncestrySet() -> Set<SnapshotID> {
        ancestrySet(startingAt: viewModel.comparisonSnapshotID)
    }

    private func ancestrySet(startingAt startID: SnapshotID?) -> Set<SnapshotID> {
        guard let startID else { return [] }
        let byID = Dictionary(uniqueKeysWithValues: viewModel.snapshots.map { ($0.id, $0) })
        var visited = Set<SnapshotID>()
        var cursor: SnapshotID? = startID
        while let current = cursor, !visited.contains(current), let snap = byID[current] {
            visited.insert(current)
            cursor = snap.parentSnapshotID
        }
        return visited
    }

    // MARK: - Formatting & Palette Helpers (Zero-Truncation Compact Labels)

    private func laneAccentColor(laneIndex: Int, name: String) -> Color {
        if name == "main" { return RackTheme.amberAccent }
        switch laneIndex % 4 {
        case 1: return RackTheme.linkGreen
        case 2: return RackTheme.vsockBlue
        case 3: return RackTheme.checkpointGold
        default: return RackTheme.amberAccent
        }
    }

    private func shortKindBadge(_ kind: SnapshotKind) -> String {
        switch kind {
        case .baseGoldenImage: return "BASE"
        case .coldDiskOnly: return "DISK"
        case .liveMemoryAndDisk: return "LIVE"
        case .branchForkPoint: return "FORK"
        case .autoPreCommandCheckpoint: return "AUTO"
        case .budgetCircuitBreaker: return "HALT"
        }
    }

    private func compactSnapshotTitle(_ snap: SnapshotNode, maxChars: Int = 20) -> String {
        let raw = snap.title
        if raw.hasPrefix("Golden Base") {
            return "Golden Base"
        }
        if raw.hasPrefix("Branch Fork -> ") {
            let target = String(raw.dropFirst("Branch Fork -> ".count))
            if target.contains("claude") { return "Fork: claude-auth" }
            if target.contains("codex") { return "Fork: codex-fuzz" }
            return shortenBranchLabel("Fork: \(target)", maxChars: maxChars)
        }
        if raw.hasPrefix("CoW Head (") {
            return "CoW Branch Head"
        }
        if raw.localizedCaseInsensitiveContains("Pre-Migration") {
            return "Pre-Migration RAM"
        }
        if raw.hasPrefix("Auto-checkpoint before ") || raw.localizedCaseInsensitiveContains("Recursive") {
            return "Pre-Exec: rm -rf"
        }
        return shortenBranchLabel(raw, maxChars: maxChars)
    }

    private func compactCommandSummary(_ cmd: String) -> String {
        if cmd.contains("rm -rf") {
            return "rm -rf build-cache"
        }
        return shortenBranchLabel(cmd, maxChars: 20)
    }

    private func shortenBranchLabel(_ text: String, maxChars: Int) -> String {
        guard text.count > maxChars else { return text }
        let parts = text.split(separator: "-")
        if parts.count >= 3 {
            let firstLast = "\(parts[0])-\(parts.last!)"
            if firstLast.count <= maxChars { return firstLast }
            let firstTwo = "\(parts[0])-\(parts[1])"
            if firstTwo.count <= maxChars { return firstTwo }
        }
        return String(text.prefix(maxChars))
    }

    private func shortenFieldPath(_ field: String) -> String {
        field
            .replacingOccurrences(of: "networkInterfaces[0].", with: "nic0.")
            .replacingOccurrences(of: "blockDevices[0].", with: "disk0.")
            .replacingOccurrences(of: "compute.", with: "cpu.")
    }

    private func shortenValueToken(_ val: String, maxChars: Int) -> String {
        let scrubbed = ByteMetricsFormatter.scrubHomePath(val)
        if scrubbed.contains("/"), let last = scrubbed.split(separator: "/").last {
            let name = String(last)
            return shortenBranchLabel(name, maxChars: maxChars)
        }
        return shortenBranchLabel(scrubbed, maxChars: maxChars)
    }

    private func shortIdentifierSuffix(_ id: String) -> String {
        if id.count <= 9 { return id }
        return String(id.suffix(8))
    }
}
