import AgentVMModels
import AgentVMWorkbenchShell
import Foundation
import Testing

@Suite("M11.7c Workbench Shell (`FuzzyCommandScorer`, `SplitDockingController`, Palette & Toast)", .timeLimit(.minutes(1)))
struct WorkbenchShellTests {

    @Test("FuzzyCommandScorer ranks prefix and word-boundary matches above scattered subsequences and searchTokens")
    func fuzzyCommandScorerRankingInvariants() {
        let items = [
            CommandPaletteActionItem(
                id: "scattered",
                title: "Configure Background Worker Pool",
                subtitle: "Adjust worker concurrency",
                category: .workspaceView,
                sfSymbol: "gearshape",
                searchTokens: []
            ),
            CommandPaletteActionItem(
                id: "word-boundary",
                title: "Fork Copy-on-Write Branch",
                subtitle: "Clone VM disk",
                category: .cowBranching,
                sfSymbol: "arrow.triangle.branch",
                searchTokens: ["cow"]
            ),
            CommandPaletteActionItem(
                id: "exact-prefix",
                title: "Branch Lineage Inspector",
                subtitle: "Open DAG view",
                category: .cowBranching,
                sfSymbol: "point.3.connected.trianglepath.dotted",
                searchTokens: ["dag"]
            ),
            CommandPaletteActionItem(
                id: "token-only",
                title: "Export Capture File",
                subtitle: "Save network trace",
                category: .networkFirewall,
                sfSymbol: "square.and.arrow.up",
                searchTokens: ["wireshark", "pcapng"]
            )
        ]

        // Empty query preserves registration order with descending base scores
        let emptyRanked = FuzzyCommandScorer.rank(query: "   ", items: items)
        #expect(emptyRanked.count == 4)
        #expect(emptyRanked.map(\.item.id) == ["scattered", "word-boundary", "exact-prefix", "token-only"])

        // Prefix match ("Branch...") outranks later word-boundary match ("...Branch")
        let branchRanked = FuzzyCommandScorer.rank(query: "branch", items: items)
        #expect(branchRanked.count >= 2)
        #expect(branchRanked[0].item.id == "exact-prefix")
        #expect(branchRanked[1].item.id == "word-boundary")
        #expect(branchRanked[0].score > branchRanked[1].score)
        #expect(branchRanked[0].matchedTitleIndices == Set(0..<6))

        // Secondary searchTokens match ("pcapng") finds item even when title doesn't match
        let tokenRanked = FuzzyCommandScorer.rank(query: "pcapng", items: items)
        #expect(tokenRanked.count == 1)
        #expect(tokenRanked[0].item.id == "token-only")
        #expect(tokenRanked[0].matchedTitleIndices.isEmpty)
    }

    @Test("SplitDockingController enforces pin invariants, split/collapse state, dirty flags, and layout snapshot restore")
    @MainActor
    func splitDockingControllerStateInvariants() {
        let controller = SplitDockingController()
        #expect(controller.splitMode == .singlePane)
        #expect(controller.primaryTabs.count == 6)
        #expect(controller.focusedPaneIndex == 0)

        // Pinned primary tab (`snapshotBranchDAG`) cannot be closed while pinned
        let dagTab = controller.primaryTabs[0]
        #expect(dagTab.isPinned == true)
        controller.closeTab(id: dagTab.id, inSecondaryPane: false)
        #expect(controller.primaryTabs.count == 6)

        // Unpinning allows closing the tab and advances activePrimaryTabID cleanly
        controller.togglePin(id: dagTab.id, inSecondaryPane: false)
        #expect(controller.primaryTabs[0].isPinned == false)
        controller.closeTab(id: dagTab.id, inSecondaryPane: false)
        #expect(controller.primaryTabs.count == 5)
        #expect(controller.activePrimaryTabID == controller.primaryTabs[0].id)

        // Opening VM-specific console tab in secondary pane engages `.verticalTwoColumn` split
        let customVMID = VMID("vm-dock-test")
        controller.openOrFocus(kind: .vt100SerialConsole, vmID: customVMID, inSecondaryPane: true)
        #expect(controller.splitMode == .verticalTwoColumn)
        #expect(controller.focusedPaneIndex == 1)
        #expect(controller.activeSecondaryTab?.kind == .vt100SerialConsole)
        #expect(controller.activeSecondaryTab?.associatedVMID == customVMID)

        // Dirty indicator propagates across both primary and secondary panes for matching document kind
        controller.setDirty(true, for: .vt100SerialConsole)
        #expect(controller.primaryTabs.first(where: { $0.kind == .vt100SerialConsole })?.hasUnsavedChanges == true)
        #expect(controller.secondaryTabs.first(where: { $0.kind == .vt100SerialConsole })?.hasUnsavedChanges == true)

        // Ordinal selection & snapshot export -> restore round-trip
        controller.selectTabAtOrdinal(3)
        #expect(controller.activePrimaryTabID == controller.primaryTabs[2].id)

        let exported = controller.exportLayoutSnapshot(
            workspaceID: WorkspaceID("ws-dock-01"),
            selectedVMID: customVMID,
            selectedSnapshotID: SnapshotID("snap-01"),
            selectedPacketID: nil
        )
        let restored = SplitDockingController(restoring: exported)
        #expect(restored.splitMode == .verticalTwoColumn)
        #expect(restored.primaryTabs.count == 5)
        #expect(restored.activePrimaryTabID == exported.activePrimaryTabID)
        #expect(restored.secondaryTabs.count == exported.secondaryTabs.count)

        // Collapse split returns focus to primary pane
        restored.collapseSplit()
        #expect(restored.splitMode == .singlePane)
        #expect(restored.focusedPaneIndex == 0)
    }

    @Test("CommandPaletteController keyboard navigation & WorkbenchToastCenter 4-item FIFO cap")
    @MainActor
    func commandPaletteAndToastCenterInvariants() {
        let palette = CommandPaletteController()
        #expect(palette.isPresented == false)
        #expect(palette.registeredActions.count >= 12)

        var executedActionID: String?
        palette.onExecuteAction = { executedActionID = $0 }

        palette.toggleInstant()
        #expect(palette.isPresented == true)
        #expect(palette.selectedIndex == 0)

        // Wrap-around upward navigation selects the last match
        let totalCount = palette.rankedMatches.count
        palette.moveSelection(delta: -1)
        #expect(palette.selectedIndex == totalCount - 1)

        // Wrap-around downward navigation returns to 0
        palette.moveSelection(delta: 1)
        #expect(palette.selectedIndex == 0)

        palette.query = "pcapng"
        palette.selectedIndex = 0
        palette.executeSelected()
        #expect(palette.isPresented == false)
        #expect(executedActionID == "net.pcap.export")

        // WorkbenchToastCenter caps active stack at 4 toasts and supports explicit dismissal
        let toasts = WorkbenchToastCenter()
        for idx in 1...6 {
            toasts.post(
                title: "Toast #\(idx)",
                detail: "Event detail \(idx)",
                severity: .notice,
                autoDismissSeconds: 0
            )
        }
        #expect(toasts.activeToasts.count == 4)
        #expect(toasts.activeToasts.map(\.title) == ["Toast #3", "Toast #4", "Toast #5", "Toast #6"])

        let firstToastID = toasts.activeToasts[0].id
        toasts.dismiss(id: firstToastID)
        #expect(toasts.activeToasts.count == 3)
        #expect(!toasts.activeToasts.contains(where: { $0.id == firstToastID }))
    }
}
