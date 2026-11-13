import AgentVMModels
import Combine
import Foundation
import SwiftUI

// MARK: - Subsequence Fuzzy Matcher & Instant Cmd+K Command Palette (Zero Open/Close Animation)

public struct FuzzyPaletteMatch: Identifiable, Sendable {
    public var id: String { item.id }
    public let item: CommandPaletteActionItem
    public let score: Int
    public let matchedTitleIndices: Set<Int>

    public init(item: CommandPaletteActionItem, score: Int, matchedTitleIndices: Set<Int>) {
        self.item = item
        self.score = score
        self.matchedTitleIndices = matchedTitleIndices
    }
}

public enum FuzzyCommandScorer: Sendable {
    /// Scores subsequence character alignment with consecutive-run, word-boundary, and prefix bonuses.
    public static func rank(query: String, items: [CommandPaletteActionItem]) -> [FuzzyPaletteMatch] {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if trimmed.isEmpty {
            return items.enumerated().map { idx, item in
                FuzzyPaletteMatch(item: item, score: 1000 - idx, matchedTitleIndices: [])
            }
        }

        let queryChars = Array(trimmed)
        var results: [FuzzyPaletteMatch] = []
        results.reserveCapacity(items.count)

        for item in items {
            if let titleMatch = scoreCandidate(queryChars: queryChars, target: item.title) {
                results.append(FuzzyPaletteMatch(
                    item: item,
                    score: titleMatch.score + 50,
                    matchedTitleIndices: titleMatch.indices
                ))
                continue
            }

            let compositeHaystack = ([item.subtitle, item.category.rawValue] + item.searchTokens)
                .joined(separator: " ")
            if let secondary = scoreCandidate(queryChars: queryChars, target: compositeHaystack) {
                results.append(FuzzyPaletteMatch(
                    item: item,
                    score: secondary.score,
                    matchedTitleIndices: []
                ))
            }
        }

        return results.sorted { lhs, rhs in
            if lhs.score != rhs.score { return lhs.score > rhs.score }
            return lhs.item.title < rhs.item.title
        }
    }

    private static func scoreCandidate(
        queryChars: [Character],
        target: String
    ) -> (score: Int, indices: Set<Int>)? {
        let lowerChars = Array(target.lowercased())
        let rawChars = Array(target)
        var qi = 0
        var score = 0
        var consecutive = 0
        var matched = Set<Int>()

        for ti in lowerChars.indices {
            guard qi < queryChars.count else { break }
            if lowerChars[ti] == queryChars[qi] {
                matched.insert(ti)
                score += 12
                if ti == 0 {
                    score += 24 // Prefix bonus
                } else {
                    let prev = rawChars[ti - 1]
                    if prev == " " || prev == "-" || prev == "/" || prev == ":" {
                        score += 18 // Word boundary bonus
                    }
                }
                consecutive += 1
                score += consecutive * 7
                qi += 1
            } else {
                consecutive = 0
                score -= 1
            }
        }

        guard qi == queryChars.count else { return nil }
        return (score, matched)
    }
}

@MainActor
public final class CommandPaletteController: ObservableObject {
    @Published public var isPresented: Bool = false
    @Published public var query: String = ""
    @Published public var selectedIndex: Int = 0
    @Published public private(set) var registeredActions: [CommandPaletteActionItem] = []

    public var onExecuteAction: ((String) -> Void)?

    public init(actions: [CommandPaletteActionItem] = CommandPaletteController.defaultBuiltInActions()) {
        self.registeredActions = actions
    }

    public var rankedMatches: [FuzzyPaletteMatch] {
        FuzzyCommandScorer.rank(query: query, items: registeredActions)
    }

    public func registerActions(_ items: [CommandPaletteActionItem]) {
        var merged = registeredActions
        for item in items {
            if let idx = merged.firstIndex(where: { $0.id == item.id }) {
                merged[idx] = item
            } else {
                merged.append(item)
            }
        }
        registeredActions = merged
    }

    /// Toggle instantly without animation (Emil Kowalski rule: 100+ daily keyboard actions never animate).
    public func toggleInstant() {
        var transaction = Transaction(animation: nil)
        transaction.disablesAnimations = true
        withTransaction(transaction) {
            isPresented.toggle()
            if isPresented {
                query = ""
                selectedIndex = 0
            }
        }
    }

    public func dismissInstant() {
        var transaction = Transaction(animation: nil)
        transaction.disablesAnimations = true
        withTransaction(transaction) {
            isPresented = false
        }
    }

    public func moveSelection(delta: Int) {
        let count = rankedMatches.count
        guard count > 0 else {
            selectedIndex = 0
            return
        }
        selectedIndex = (selectedIndex + delta + count) % count
    }

    public func executeSelected() {
        let matches = rankedMatches
        guard matches.indices.contains(selectedIndex) else { return }
        let chosenID = matches[selectedIndex].item.id
        dismissInstant()
        onExecuteAction?(chosenID)
    }

    public static func defaultBuiltInActions() -> [CommandPaletteActionItem] {
        [
            CommandPaletteActionItem(
                id: "vm.branch.cow",
                title: "Fork Instant APFS Copy-on-Write Branch",
                subtitle: "Clones active VM disk via clonefile(2) in < 20 ms without halting parent",
                category: .cowBranching,
                keyEquivalentDisplay: "⌘B",
                sfSymbol: "arrow.triangle.branch",
                searchTokens: ["fork", "clonefile", "cow", "branch", "sandbox"]
            ),
            CommandPaletteActionItem(
                id: "vm.snapshot.live",
                title: "Capture Live RAM + Disk Checkpoint",
                subtitle: "Saves VZVirtualMachine memory state and CoW disk extent snapshot",
                category: .cowBranching,
                keyEquivalentDisplay: "⇧⌘S",
                sfSymbol: "camera.metering.matrix",
                searchTokens: ["snapshot", "checkpoint", "memory", "save"]
            ),
            CommandPaletteActionItem(
                id: "vm.lifecycle.boot",
                title: "Boot Selected Virtual Machine",
                subtitle: "Starts VZVirtualMachine hypervisor and attaches L2 switch port",
                category: .vmLifecycle,
                keyEquivalentDisplay: "⌘R",
                sfSymbol: "play.fill",
                searchTokens: ["start", "up", "run", "boot"]
            ),
            CommandPaletteActionItem(
                id: "vm.lifecycle.pause",
                title: "Pause / Resume Virtual Machine",
                subtitle: "Freezes guest vCPUs cleanly while preserving VirtioSocket state",
                category: .vmLifecycle,
                keyEquivalentDisplay: "⌘P",
                sfSymbol: "pause.fill",
                searchTokens: ["freeze", "suspend", "resume"]
            ),
            CommandPaletteActionItem(
                id: "net.pcap.export",
                title: "Export Captured Traffic as Wireshark PCAPNG",
                subtitle: "Writes Section Header, Interface Description & Enhanced Packet Blocks",
                category: .networkFirewall,
                keyEquivalentDisplay: "⇧⌘E",
                sfSymbol: "square.and.arrow.up",
                searchTokens: ["pcap", "pcapng", "wireshark", "packets"]
            ),
            CommandPaletteActionItem(
                id: "net.policy.strict",
                title: "Apply Strict Coding-Agent Egress Allowlist",
                subtitle: "Permits GitHub/PyPI/Anthropic TLS SNI; blocks 169.254.169.254 & webhook sinks",
                category: .networkFirewall,
                sfSymbol: "shield.checkered",
                searchTokens: ["firewall", "allowlist", "sni", "drop"]
            ),
            CommandPaletteActionItem(
                id: "net.policy.airgap",
                title: "Engage Total Air-Gap Mode",
                subtitle: "Drops all external L3/L4 packets; allows only local VirtioFS & Vsock",
                category: .networkFirewall,
                sfSymbol: "wifi.slash",
                searchTokens: ["offline", "isolate", "airgap"]
            ),
            CommandPaletteActionItem(
                id: "view.open.dag",
                title: "Focus Snapshot & CoW Lineage DAG",
                subtitle: "Inspect branching tree, LCA divergence extents, and restore points",
                category: .workspaceView,
                keyEquivalentDisplay: "⌘1",
                sfSymbol: "point.3.connected.trianglepath.dotted",
                searchTokens: ["dag", "tree", "lineage"]
            ),
            CommandPaletteActionItem(
                id: "view.open.wiretap",
                title: "Focus Layer-2 Packet Wiretap & Hex Dissector",
                subtitle: "3-pane protocol frame table, field dissection tree, and 16-byte hex view",
                category: .workspaceView,
                keyEquivalentDisplay: "⌘2",
                sfSymbol: "waveform.path.ecg.rectangle",
                searchTokens: ["wiretap", "hex", "dissector", "tls"]
            ),
            CommandPaletteActionItem(
                id: "view.open.console",
                title: "Focus Vsock & VT100 Serial Terminal",
                subtitle: "Interactive guest command runner over multiplexed AVM1 VirtioSocket",
                category: .workspaceView,
                keyEquivalentDisplay: "⌘3",
                sfSymbol: "terminal",
                searchTokens: ["tty", "pty", "shell", "exec"]
            ),
            CommandPaletteActionItem(
                id: "view.split.toggle",
                title: "Split Active Workbench Pane Right",
                subtitle: "Compare Snapshot DAG alongside live Packet Wiretap side by side",
                category: .workspaceView,
                keyEquivalentDisplay: "⌘\\",
                sfSymbol: "rectangle.split.2x1",
                searchTokens: ["split", "dock", "dual"]
            ),
            CommandPaletteActionItem(
                id: "workspace.undo",
                title: "Undo Last Topology or Policy Change",
                subtitle: "Reverts top ReversibleWorkspaceCommand from SQLite Undo Journal",
                category: .workspaceView,
                keyEquivalentDisplay: "⌘Z",
                sfSymbol: "arrow.uturn.backward",
                searchTokens: ["undo", "revert"]
            ),
            CommandPaletteActionItem(
                id: "plugins.export.html",
                title: "Export Standalone HTML Fleet Security Report",
                subtitle: "Generates self-contained Hallmark-audited compliance report",
                category: .pluginsAndAutomation,
                sfSymbol: "doc.richtext",
                searchTokens: ["html", "report", "audit"]
            )
        ]
    }
}

public struct CommandPaletteOverlayView: View {
    @ObservedObject public var controller: CommandPaletteController
    @FocusState private var searchFieldFocused: Bool

    public init(controller: CommandPaletteController) {
        self.controller = controller
    }

    public var body: some View {
        if controller.isPresented {
            ZStack(alignment: .top) {
                Color.black.opacity(0.52)
                    .ignoresSafeArea()
                    .onTapGesture {
                        controller.dismissInstant()
                    }

                VStack(spacing: 0) {
                    HStack(spacing: 10) {
                        Image(systemName: "magnifyingglass")
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundStyle(RackTheme.amberAccent)

                        TextField("Type a command, VM name, firewall preset, or snapshot action...", text: $controller.query)
                            .textFieldStyle(.plain)
                            .font(.system(size: 14, weight: .regular))
                            .foregroundStyle(RackTheme.inkPrimary)
                            .focused($searchFieldFocused)
                            .onChange(of: controller.query) { _, _ in
                                controller.selectedIndex = 0
                            }
                            .onSubmit {
                                controller.executeSelected()
                            }

                        RackKeyCapBadge("ESC")
                    }
                    .padding(.horizontal, 14)
                    .padding(.vertical, 12)
                    .background(RackTheme.moduleElevated)

                    Rectangle()
                        .fill(RackTheme.hairlineStrong)
                        .frame(height: 1)

                    let matches = controller.rankedMatches
                    if matches.isEmpty {
                        VStack(spacing: 6) {
                            Text("No matching workbench commands")
                                .font(RackTheme.sectionHeaderFont)
                                .foregroundStyle(RackTheme.inkSecondary)
                            Text("Try searching for 'branch', 'pcap', 'firewall', 'split', or 'snapshot'.")
                                .font(RackTheme.captionFont)
                                .foregroundStyle(RackTheme.inkMuted)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 28)
                    } else {
                        ScrollView {
                            LazyVStack(spacing: 2) {
                                ForEach(Array(matches.enumerated()), id: \.element.id) { index, match in
                                    let isSelected = index == controller.selectedIndex
                                    HStack(spacing: 10) {
                                        Image(systemName: match.item.sfSymbol)
                                            .font(.system(size: 13, weight: .medium))
                                            .foregroundStyle(isSelected ? RackTheme.amberAccent : RackTheme.inkSecondary)
                                            .frame(width: 22)

                                        VStack(alignment: .leading, spacing: 2) {
                                            highlightedTitle(match.item.title, indices: match.matchedTitleIndices)
                                                .font(.system(size: 12.5, weight: .medium))
                                                .lineLimit(1)
                                            Text(match.item.subtitle)
                                                .font(RackTheme.captionFont)
                                                .foregroundStyle(RackTheme.inkMuted)
                                                .lineLimit(1)
                                        }

                                        Spacer(minLength: 8)

                                        Text(match.item.category.rawValue)
                                            .font(RackTheme.captionFont)
                                            .foregroundStyle(RackTheme.inkMuted)
                                            .lineLimit(1)
                                            .fixedSize(horizontal: true, vertical: false)

                                        if let shortcut = match.item.keyEquivalentDisplay {
                                            RackKeyCapBadge(shortcut)
                                        }
                                    }
                                    .padding(.horizontal, 12)
                                    .padding(.vertical, 8)
                                    .background(
                                        RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                                            .fill(isSelected ? RackTheme.amberSoft : Color.clear)
                                    )
                                    .contentShape(Rectangle())
                                    .onTapGesture {
                                        controller.selectedIndex = index
                                        controller.executeSelected()
                                    }
                                }
                            }
                            .padding(6)
                        }
                        .frame(maxHeight: 340)
                    }
                }
                .frame(width: 640)
                .background(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill(RackTheme.moduleSurface)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .strokeBorder(RackTheme.hairlineStrong, lineWidth: 1)
                )
                .shadow(color: Color.black.opacity(0.55), radius: 26, x: 0, y: 14)
                .padding(.top, 68)
                .onAppear {
                    searchFieldFocused = true
                }
            }
        }
    }

    private func highlightedTitle(_ title: String, indices: Set<Int>) -> Text {
        guard !indices.isEmpty else {
            return Text(title).foregroundColor(RackTheme.inkPrimary)
        }
        var composed = Text("")
        for (idx, ch) in title.enumerated() {
            let part = Text(String(ch))
                .foregroundColor(indices.contains(idx) ? RackTheme.amberAccent : RackTheme.inkPrimary)
            composed = composed + part
        }
        return composed
    }
}
