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
                title: L("Fork Instant APFS Copy-on-Write Branch", "分叉瞬时 APFS 写时复制 (CoW) 分支"),
                subtitle: L(
                    "Clones active VM disk via clonefile(2) in < 20 ms without halting parent",
                    "基于 clonefile(2) 在 20ms 内零拷贝克隆虚拟机磁盘，无需停机父节点"
                ),
                category: .cowBranching,
                keyEquivalentDisplay: "⌘B",
                sfSymbol: "arrow.triangle.branch",
                searchTokens: ["fork", "clonefile", "cow", "branch", "sandbox", "分叉", "分支", "克隆", "写时复制"]
            ),
            CommandPaletteActionItem(
                id: "vm.snapshot.live",
                title: L("Capture Live RAM + Disk Checkpoint", "捕获实时内存 + 磁盘快照点"),
                subtitle: L(
                    "Saves VZVirtualMachine memory state and CoW disk extent snapshot",
                    "保存 VZVirtualMachine 实时内存状态与 CoW 磁盘区间快照"
                ),
                category: .cowBranching,
                keyEquivalentDisplay: "⇧⌘S",
                sfSymbol: "camera.metering.matrix",
                searchTokens: ["snapshot", "checkpoint", "memory", "save", "快照", "检查点", "内存"]
            ),
            CommandPaletteActionItem(
                id: "vm.lifecycle.boot",
                title: L("Boot Selected Virtual Machine", "启动当前选中的虚拟机"),
                subtitle: L(
                    "Starts VZVirtualMachine hypervisor and attaches L2 switch port",
                    "启动 VZVirtualMachine 虚拟化引擎并挂载二层交换机端口"
                ),
                category: .vmLifecycle,
                keyEquivalentDisplay: "⌘R",
                sfSymbol: "play.fill",
                searchTokens: ["start", "up", "run", "boot", "启动", "开机", "运行"]
            ),
            CommandPaletteActionItem(
                id: "vm.lifecycle.pause",
                title: L("Pause / Resume Virtual Machine", "暂停 / 恢复虚拟机运行"),
                subtitle: L(
                    "Freezes guest vCPUs cleanly while preserving VirtioSocket state",
                    "平滑冻结客户机 vCPU 并完整保留 VirtioSocket 通道状态"
                ),
                category: .vmLifecycle,
                keyEquivalentDisplay: "⌘P",
                sfSymbol: "pause.fill",
                searchTokens: ["freeze", "suspend", "resume", "暂停", "冻结", "恢复"]
            ),
            CommandPaletteActionItem(
                id: "net.pcap.export",
                title: L("Export Captured Traffic as Wireshark PCAPNG", "导出抓包流量为 Wireshark PCAPNG"),
                subtitle: L(
                    "Writes Section Header, Interface Description & Enhanced Packet Blocks",
                    "写入标准 Section Header、接口描述块与增强型数据包块 (.pcapng)"
                ),
                category: .networkFirewall,
                keyEquivalentDisplay: "⇧⌘E",
                sfSymbol: "square.and.arrow.up",
                searchTokens: ["pcap", "pcapng", "wireshark", "packets", "抓包", "导出", "流量"]
            ),
            CommandPaletteActionItem(
                id: "net.policy.strict",
                title: L("Apply Strict Coding-Agent Egress Allowlist", "应用编程智能体严格出站白名单"),
                subtitle: L(
                    "Permits GitHub/PyPI/Anthropic TLS SNI; blocks 169.254.169.254 & webhook sinks",
                    "放行 GitHub/PyPI/Anthropic TLS SNI；阻断 169.254.169.254 元数据与外泄接收端"
                ),
                category: .networkFirewall,
                sfSymbol: "shield.checkered",
                searchTokens: ["firewall", "allowlist", "sni", "drop", "防火墙", "白名单", "策略"]
            ),
            CommandPaletteActionItem(
                id: "net.policy.airgap",
                title: L("Engage Total Air-Gap Mode", "启用全气隙零出站隔离模式"),
                subtitle: L(
                    "Drops all external L3/L4 packets; allows only local VirtioFS & Vsock",
                    "阻断所有外部 L3/L4 数据包；仅保留本地 VirtioFS 与 Vsock 通道"
                ),
                category: .networkFirewall,
                sfSymbol: "wifi.slash",
                searchTokens: ["offline", "isolate", "airgap", "气隙", "断网", "隔离"]
            ),
            CommandPaletteActionItem(
                id: "view.open.dag",
                title: L("Focus Snapshot & CoW Lineage DAG", "聚焦快照与 CoW 血缘拓扑图"),
                subtitle: L(
                    "Inspect branching tree, LCA divergence extents, and restore points",
                    "查看分支演化树、最近公共祖先 (LCA) 块差异与回滚点"
                ),
                category: .workspaceView,
                keyEquivalentDisplay: "⌘1",
                sfSymbol: "point.3.connected.trianglepath.dotted",
                searchTokens: ["dag", "tree", "lineage", "血缘", "拓扑", "快照树"]
            ),
            CommandPaletteActionItem(
                id: "view.open.wiretap",
                title: L("Focus Layer-2 Packet Wiretap & Hex Dissector", "聚焦二层抓包与十六进制协议解析器"),
                subtitle: L(
                    "3-pane protocol frame table, field dissection tree, and 16-byte hex view",
                    "三栏式以太网帧列表、协议字段解析树与 16 字节十六进制联动视图"
                ),
                category: .workspaceView,
                keyEquivalentDisplay: "⌘2",
                sfSymbol: "waveform.path.ecg.rectangle",
                searchTokens: ["wiretap", "hex", "dissector", "tls", "抓包", "协议", "十六进制"]
            ),
            CommandPaletteActionItem(
                id: "view.open.console",
                title: L("Focus Vsock & VT100 Serial Terminal", "聚焦 Vsock 与 VT100 串口终端"),
                subtitle: L(
                    "Interactive guest command runner over multiplexed AVM1 VirtioSocket",
                    "通过多路复用 AVM1 VirtioSocket 交互执行客户机命令"
                ),
                category: .workspaceView,
                keyEquivalentDisplay: "⌘3",
                sfSymbol: "terminal",
                searchTokens: ["tty", "pty", "shell", "exec", "终端", "控制台", "命令行"]
            ),
            CommandPaletteActionItem(
                id: "view.split.toggle",
                title: L("Split Active Workbench Pane Right", "将当前工作台视图向右分屏"),
                subtitle: L(
                    "Compare Snapshot DAG alongside live Packet Wiretap side by side",
                    "左右并排对比快照血缘图、实时二层抓包或防火墙策略"
                ),
                category: .workspaceView,
                keyEquivalentDisplay: "⌘\\",
                sfSymbol: "rectangle.split.2x1",
                searchTokens: ["split", "dock", "dual", "分屏", "双栏", "并排"]
            ),
            CommandPaletteActionItem(
                id: "workspace.undo",
                title: L("Undo Last Topology or Policy Change", "撤销上一步拓扑或策略变更"),
                subtitle: L(
                    "Reverts top ReversibleWorkspaceCommand from SQLite Undo Journal",
                    "从 SQLite 可逆事务日志回滚最近一次工作区变更"
                ),
                category: .workspaceView,
                keyEquivalentDisplay: "⌘Z",
                sfSymbol: "arrow.uturn.backward",
                searchTokens: ["undo", "revert", "撤销", "回退"]
            ),
            CommandPaletteActionItem(
                id: "plugins.export.html",
                title: L("Export Standalone HTML Fleet Security Report", "导出独立双语 HTML 集群安全审计报告"),
                subtitle: L(
                    "Generates self-contained Hallmark-audited compliance report",
                    "生成零外部依赖、支持中英切换的 Hallmark 级安全合规档案"
                ),
                category: .pluginsAndAutomation,
                sfSymbol: "doc.richtext",
                searchTokens: ["html", "report", "audit", "dossier", "报告", "审计", "档案"]
            ),
            CommandPaletteActionItem(
                id: "app.language.toggle",
                title: L("Toggle Interface Language (中文 / EN)", "切换界面语言 (中文 / EN)"),
                subtitle: L(
                    "Switch all workbench panes, menus, and inspectors between English and Simplified Chinese",
                    "在简体中文与英文之间实时切换全部工作台面板、菜单与检查器"
                ),
                category: .workspaceView,
                keyEquivalentDisplay: "⇧⌘L",
                sfSymbol: "globe",
                searchTokens: ["language", "chinese", "english", "locale", "bilingual", "zh", "en", "语言", "中文", "英文", "双语"]
            )
        ]
    }
}

public struct CommandPaletteOverlayView: View {
    @ObservedObject public var controller: CommandPaletteController
    @ObservedObject private var localizer = AgentVMLocalizer.shared
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

                        TextField(
                            localizer.L(
                                "Type a command, VM name, firewall preset, or snapshot action...",
                                "输入命令、虚拟机名称、防火墙预设或快照操作..."
                            ),
                            text: $controller.query
                        )
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
                            Text(localizer.L("No matching workbench commands", "未找到匹配的工作台命令"))
                                .font(RackTheme.sectionHeaderFont)
                                .foregroundStyle(RackTheme.inkSecondary)
                            Text(localizer.L(
                                "Try searching for 'branch', 'pcap', 'firewall', 'split', or 'snapshot'.",
                                "可尝试搜索「分叉」「抓包」「防火墙」「分屏」「快照」或英文关键字。"
                            ))
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

                                        Text(match.item.category.localizedTitle)
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
