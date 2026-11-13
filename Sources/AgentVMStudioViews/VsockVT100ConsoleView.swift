import AgentVMModels
import AgentVMVsockRPC
import AgentVMWorkbenchShell
import SwiftUI

// MARK: - Vsock ("AVM1") Multiplexed RPC & VT100 Terminal Emulator Console View

public struct VsockVT100ConsoleView: View {
    @ObservedObject public var viewModel: AgentVMStudioViewModel
    @ObservedObject private var localizer = AgentVMLocalizer.shared

    private struct QuickGuestProbe: Identifiable {
        let label: String
        let command: String
        let isDestructiveCheckpointDemo: Bool
        var id: String { command }
    }

    private let quickProbes: [QuickGuestProbe] = [
        QuickGuestProbe(label: "uname -a", command: "uname -a", isDestructiveCheckpointDemo: false),
        QuickGuestProbe(label: "ip -br addr", command: "ip -br addr", isDestructiveCheckpointDemo: false),
        QuickGuestProbe(label: "df -h", command: "df -h", isDestructiveCheckpointDemo: false),
        QuickGuestProbe(label: "rm -rf /tmp/build-cache", command: "rm -rf /tmp/build-cache", isDestructiveCheckpointDemo: true)
    ]

    public init(viewModel: AgentVMStudioViewModel) {
        self.viewModel = viewModel
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            consoleProbeHeaderBar

            HStack(alignment: .top, spacing: 10) {
                vt100TerminalViewportPanel
                    .frame(maxWidth: .infinity, maxHeight: .infinity)

                portForwardsAndExecAuditRail
                    .frame(width: 300)
                    .frame(maxHeight: .infinity)
            }
        }
        .padding(10)
        .background(RackTheme.chassisBackground)
    }

    // MARK: - Top Quick Probe & AVM1 Telemetry Bar

    private var consoleProbeHeaderBar: some View {
        HStack(spacing: 8) {
            RackStatusPill(
                label: localizer.L("AVM1 VSOCK MUX · CRC32", "AVM1 VSOCK 多路复用 · CRC32"),
                color: RackTheme.vsockBlue,
                monospaced: true
            )

            Text(localizer.L("Quick Probes:", "快捷探测:"))
                .font(RackTheme.labelFont)
                .foregroundStyle(RackTheme.inkMuted)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)

            ForEach(quickProbes) { probe in
                Button {
                    viewModel.executeRawCommandLine(probe.command)
                } label: {
                    HStack(spacing: 4) {
                        if probe.isDestructiveCheckpointDemo {
                            Image(systemName: "shield.checkered")
                                .font(.system(size: 10, weight: .bold))
                        } else {
                            Image(systemName: "terminal")
                                .font(.system(size: 10, weight: .semibold))
                        }
                        Text(probe.label)
                    }
                }
                .buttonStyle(
                    RackActionButtonStyle(
                        prominence: probe.isDestructiveCheckpointDemo ? .primaryAmber : .secondaryModule,
                        compact: true
                    )
                )
            }

            Spacer(minLength: 4)

            Button {
                viewModel.clearTerminalScreen()
            } label: {
                Label(localizer.L("Clear TTY", "清空终端"), systemImage: "trash")
            }
            .buttonStyle(RackActionButtonStyle(prominence: .subtleGhost, compact: true))
        }
    }

    // MARK: - Left Pane: VT100 256-Color Grid & Interactive Prompt

    private var vt100TerminalViewportPanel: some View {
        let vmName = viewModel.selectedVM?.spec.name ?? "sandbox"
        let vp = viewModel.viewportSnapshot

        return RackPanelContainer(
            title: localizer.L("VT100 / Xterm-256Color Guest Console", "VT100 / Xterm-256 色客户机终端"),
            subtitle: localizer.L(
                "\(vp.columns)x\(vp.rows) cells · Cursor (\(vp.cursorRow), \(vp.cursorColumn)) · Scrollback \(vp.scrollbackLineCount) lines",
                "\(vp.columns)x\(vp.rows) 字符格 · 光标 (\(vp.cursorRow), \(vp.cursorColumn)) · 回滚 \(vp.scrollbackLineCount) 行"
            ),
            symbolName: "terminal.fill",
            headerTrailing: {
                RackStatusPill(
                    label: vp.isAlternateScreenActive
                        ? localizer.L("ALT SCREEN", "备用屏幕")
                        : localizer.L("PRIMARY TTY", "主终端缓冲区"),
                    color: RackTheme.linkGreen,
                    monospaced: true
                )
            },
            content: {
                VStack(spacing: 8) {
                    ScrollView([.vertical, .horizontal], showsIndicators: true) {
                        VStack(alignment: .leading, spacing: 1) {
                            ForEach(0..<vp.visibleGrid.count, id: \.self) { rowIdx in
                                terminalGridRowView(
                                    cells: vp.visibleGrid[rowIdx],
                                    rowIndex: rowIdx,
                                    cursorRow: vp.cursorRow,
                                    cursorCol: vp.cursorColumn,
                                    cursorVisible: vp.isCursorVisible
                                )
                            }
                        }
                        .padding(10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(
                        RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                            .fill(RackTheme.terminalWell)
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                            .strokeBorder(RackTheme.hairlineStrong, lineWidth: 1)
                    )

                    // Interactive Guest Exec Input Bar
                    HStack(spacing: 8) {
                        Text("agent@\(vmName):\(viewModel.consoleWorkingDirectory)$")
                            .font(RackTheme.monoBoldFont)
                            .foregroundStyle(RackTheme.linkGreen)
                            .lineLimit(1)
                            .fixedSize(horizontal: true, vertical: false)

                        TextField(
                            localizer.L("Enter guest command over Vsock RPC...", "通过 Vsock RPC 输入要在客户机执行的命令..."),
                            text: $viewModel.consoleCommandInput
                        )
                            .textFieldStyle(.plain)
                            .font(RackTheme.monoFont)
                            .foregroundStyle(RackTheme.inkPrimary)
                            .onSubmit {
                                viewModel.executeCurrentConsoleCommand()
                            }

                        Button {
                            viewModel.executeCurrentConsoleCommand()
                        } label: {
                            Label(localizer.L("Exec RPC", "执行 RPC"), systemImage: "paperplane.fill")
                        }
                        .buttonStyle(RackActionButtonStyle(prominence: .primaryAmber, compact: true))
                    }
                    .padding(.horizontal, 10)
                    .padding(.vertical, 7)
                    .background(
                        RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                            .fill(RackTheme.chassisBackground)
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                            .strokeBorder(RackTheme.hairlineStrong, lineWidth: 1)
                    )
                }
            }
        )
    }

    private func terminalGridRowView(
        cells: [TerminalCell],
        rowIndex: Int,
        cursorRow: Int,
        cursorCol: Int,
        cursorVisible: Bool
    ) -> some View {
        let attributed = buildAttributedLine(
            from: cells,
            isCursorLine: cursorVisible && rowIndex == cursorRow,
            cursorColumn: cursorCol
        )
        return Text(attributed)
            .font(.system(size: CGFloat(viewModel.preferences.terminalFontSize), design: .monospaced))
            .lineLimit(1)
            .fixedSize(horizontal: true, vertical: false)
    }

    private func buildAttributedLine(
        from cells: [TerminalCell],
        isCursorLine: Bool,
        cursorColumn: Int
    ) -> AttributedString {
        // Trim trailing untouched blank cells beyond cursor so rows stay fast and crisp
        var lastMeaningful = -1
        for idx in cells.indices {
            let c = cells[idx]
            if c.scalar != " " || c.bgANSI != TerminalCell.defaultBackgroundANSI || c.isInverse || c.isUnderline {
                lastMeaningful = idx
            }
        }
        if isCursorLine && cursorColumn > lastMeaningful && cursorColumn < cells.count {
            lastMeaningful = cursorColumn
        }
        guard lastMeaningful >= 0 else {
            return AttributedString(" ")
        }

        var output = AttributedString()
        var idx = 0
        let upper = min(cells.count - 1, lastMeaningful)

        while idx <= upper {
            let cell = cells[idx]
            let isCursorCell = isCursorLine && idx == cursorColumn

            if isCursorCell {
                var chAttr = AttributedString(String(cell.scalar))
                chAttr.foregroundColor = Color(red: 0.06, green: 0.07, blue: 0.08)
                chAttr.backgroundColor = RackTheme.amberAccent
                output.append(chAttr)
                idx += 1
                continue
            }

            // Coalesce consecutive cells with matching SGR rendition
            var runEnd = idx
            while runEnd + 1 <= upper {
                let nextIdx = runEnd + 1
                if isCursorLine && nextIdx == cursorColumn { break }
                let next = cells[nextIdx]
                if next.fgANSI == cell.fgANSI
                    && next.bgANSI == cell.bgANSI
                    && next.isBold == cell.isBold
                    && next.isDim == cell.isDim
                    && next.isUnderline == cell.isUnderline
                    && next.isInverse == cell.isInverse {
                    runEnd = nextIdx
                } else {
                    break
                }
            }

            let textSlice = String(cells[idx...runEnd].map(\.scalar))
            var runAttr = AttributedString(textSlice)

            let effectiveFGCode = cell.isInverse ? cell.bgANSI : cell.fgANSI
            let effectiveBGCode = cell.isInverse ? cell.fgANSI : cell.bgANSI

            var fgColor = ansi256ToSwiftUIColor(effectiveFGCode, isForeground: true, isBold: cell.isBold)
            if cell.isDim {
                fgColor = fgColor.opacity(0.65)
            }
            runAttr.foregroundColor = fgColor

            if cell.isInverse || effectiveBGCode != TerminalCell.defaultBackgroundANSI {
                runAttr.backgroundColor = ansi256ToSwiftUIColor(effectiveBGCode, isForeground: false, isBold: false)
            }
            if cell.isUnderline {
                runAttr.underlineStyle = .single
            }
            output.append(runAttr)
            idx = runEnd + 1
        }
        return output
    }

    // MARK: - Right Side Rail: Active Port Forwards & Guest Exec Audit Cards

    private var portForwardsAndExecAuditRail: some View {
        VStack(spacing: 8) {
            RackPanelContainer(
                title: localizer.L("Port-Forward Relays", "端口转发中继"),
                subtitle: localizer.L("Loopback TCP <-> Vsock CID 3", "本地回环 TCP <-> Vsock CID 3"),
                symbolName: "arrow.left.arrow.right.circle"
            ) {
                let bindings = effectivePortForwardRows()
                if bindings.isEmpty {
                    Text(localizer.L("No active port-forward bindings on this blade.", "当前刀片暂无活跃端口转发绑定。"))
                        .font(RackTheme.captionFont)
                        .foregroundStyle(RackTheme.inkMuted)
                } else {
                    VStack(spacing: 5) {
                        ForEach(bindings, id: \.id) { item in
                            HStack(spacing: 6) {
                                Circle()
                                    .fill(RackTheme.linkGreen)
                                    .frame(width: 6, height: 6)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(item.label)
                                        .font(.system(size: 11, weight: .semibold))
                                        .foregroundStyle(RackTheme.inkPrimary)
                                        .lineLimit(1)
                                    Text("127.0.0.1:\(item.hostPort) -> :\(item.guestPort)")
                                        .font(RackTheme.monoSmallFont)
                                        .monospacedDigit()
                                        .foregroundStyle(RackTheme.vsockBlue)
                                        .lineLimit(1)
                                }
                                Spacer(minLength: 4)
                                RackStatusPill(label: item.protoBadge, color: RackTheme.vsockBlue, monospaced: true)
                            }
                            .padding(.horizontal, 8)
                            .padding(.vertical, 5)
                            .background(
                                RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                                    .fill(RackTheme.chassisBackground.opacity(0.75))
                            )
                            .overlay(
                                RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                                    .strokeBorder(RackTheme.hairline, lineWidth: 1)
                            )
                        }
                    }
                }
            }

            RackPanelContainer(
                title: localizer.L("Guest Exec Audit Ledger", "客户机命令审计账本"),
                subtitle: localizer.L(
                    "\(viewModel.execResults.count) audited RPC invocations",
                    "已审计 \(viewModel.execResults.count) 次 RPC 调用"
                ),
                symbolName: "checklist.checked"
            ) {
                ScrollView {
                    LazyVStack(spacing: 6) {
                        ForEach(viewModel.execResults, id: \.requestID) { item in
                            execAuditCard(item)
                        }
                    }
                }
            }
            .frame(maxHeight: .infinity)
        }
    }

    private struct DisplayPortForwardRow {
        let id: String
        let label: String
        let hostPort: UInt16
        let guestPort: UInt16
        let protoBadge: String
    }

    private func effectivePortForwardRows() -> [DisplayPortForwardRow] {
        if !viewModel.portForwardBindings.isEmpty {
            return viewModel.portForwardBindings.map { b in
                DisplayPortForwardRow(
                    id: b.id.rawValue,
                    label: b.rule.label,
                    hostPort: b.actualBoundPort,
                    guestPort: b.rule.guestPort,
                    protoBadge: b.rule.protocolType == .vsockStream ? "VSOCK" : "TCP"
                )
            }
        }
        let rules = viewModel.vms.flatMap(\.spec.portForwards)
        return rules.map { r in
            DisplayPortForwardRow(
                id: r.id.rawValue,
                label: r.label,
                hostPort: r.hostPort,
                guestPort: r.guestPort,
                protoBadge: r.protocolType == .vsockStream ? "VSOCK" : "TCP"
            )
        }
    }

    private func execAuditCard(_ res: GuestExecResult) -> some View {
        let ok = res.exitCode == 0 && !res.timedOut
        let badgeColor = ok ? RackTheme.linkGreen : RackTheme.dropCrimson

        return VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 6) {
                RackStatusPill(
                    label: localizer.L("EXIT \(res.exitCode)", "退出码 \(res.exitCode)"),
                    color: badgeColor,
                    monospaced: true
                )
                Text("\(res.durationMilliseconds) ms")
                    .font(RackTheme.monoSmallFont)
                    .monospacedDigit()
                    .foregroundStyle(RackTheme.inkMuted)
                    .lineLimit(1)
                Spacer(minLength: 4)
                if res.preCheckpointSnapshotID != nil {
                    RackStatusPill(
                        label: localizer.L("AUTO-SNAP", "自动快照"),
                        color: RackTheme.checkpointGold,
                        monospaced: true
                    )
                }
            }

            Text(res.commandLine)
                .font(RackTheme.monoSmallFont)
                .foregroundStyle(RackTheme.inkPrimary)
                .lineLimit(1)

            let snippet = res.stdoutUTF8.trimmingCharacters(in: .whitespacesAndNewlines)
            if !snippet.isEmpty {
                Text(snippet)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(RackTheme.inkSecondary)
                    .lineLimit(2)
            }

            if let snapID = res.preCheckpointSnapshotID {
                Button {
                    viewModel.restoreSnapshot(snapID)
                } label: {
                    Label(localizer.L("Rewind Pre-Exec CoW", "回滚至执行前快照"), systemImage: "clock.arrow.circlepath")
                }
                .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
            }
        }
        .padding(8)
        .background(
            RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                .fill(RackTheme.chassisBackground.opacity(0.75))
        )
        .overlay(
            RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                .strokeBorder(res.preCheckpointSnapshotID != nil ? RackTheme.checkpointGold.opacity(0.55) : RackTheme.hairline, lineWidth: 1)
        )
    }

    // MARK: - Xterm-256 ANSI Color Decoder

    private func ansi256ToSwiftUIColor(_ code: UInt8, isForeground: Bool, isBold: Bool) -> Color {
        if isForeground && code == TerminalCell.defaultForegroundANSI && !isBold {
            return RackTheme.inkPrimary
        }
        if !isForeground && code == TerminalCell.defaultBackgroundANSI {
            return RackTheme.terminalWell
        }

        switch code {
        case 0: return Color(red: 0.10, green: 0.11, blue: 0.13)
        case 1: return RackTheme.dropCrimson
        case 2: return RackTheme.linkGreen
        case 3: return RackTheme.checkpointGold
        case 4: return RackTheme.vsockBlue
        case 5: return Color(red: 0.76, green: 0.48, blue: 0.92)
        case 6: return Color(red: 0.24, green: 0.76, blue: 0.80)
        case 7: return RackTheme.inkPrimary
        case 8: return RackTheme.inkMuted
        case 9: return Color(red: 0.95, green: 0.38, blue: 0.38)
        case 10: return Color(red: 0.30, green: 0.85, blue: 0.58)
        case 11: return Color(red: 0.96, green: 0.78, blue: 0.32)
        case 12: return Color(red: 0.42, green: 0.66, blue: 0.99)
        case 13: return Color(red: 0.86, green: 0.58, blue: 0.98)
        case 14: return Color(red: 0.38, green: 0.88, blue: 0.92)
        case 15: return Color.white
        case 16...231:
            let idx = Int(code - 16)
            let r = Double(idx / 36) / 5.0
            let g = Double((idx % 36) / 6) / 5.0
            let b = Double(idx % 6) / 5.0
            return Color(red: r, green: g, blue: b)
        default:
            let gray = Double(Int(code - 232) * 10 + 8) / 255.0
            return Color(white: gray)
        }
    }
}
