import AgentVMModels
import AgentVMPluginHost
import AgentVMWorkbenchShell
import SwiftUI

// MARK: - Sandboxed JavaScriptCore Plugin Host & Declarative HCL / Compose Studio

public struct PluginExtensionStudioView: View {
    @ObservedObject public var viewModel: AgentVMStudioViewModel
    @ObservedObject private var localizer = AgentVMLocalizer.shared
    @State private var isEditingScratchpad: Bool = false
    @State private var configDraftKey: String = ""
    @State private var configDraftValue: String = ""

    public init(viewModel: AgentVMStudioViewModel) {
        self.viewModel = viewModel
    }

    private var totalInvocations: UInt64 {
        viewModel.pluginStatuses.reduce(0) { $0 + $1.invocationCount }
    }

    private var totalInterceptions: UInt64 {
        viewModel.pluginStatuses.reduce(0) { $0 + $1.blockedActionsCount }
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            studioHeaderStrip

            pluginRosterPanel

            HStack(alignment: .top, spacing: 10) {
                scratchpadRunnerPanel
                    .frame(maxWidth: .infinity, maxHeight: .infinity)

                declarativeTopologyPanel
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .padding(12)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(RackTheme.chassisBackground)
        .onChange(of: viewModel.selectedPluginID) { _, _ in
            syncSelectedConfigDraft()
        }
        .onAppear {
            syncSelectedConfigDraft()
        }
    }

    private func syncSelectedConfigDraft() {
        guard let selected = viewModel.selectedPlugin,
              let firstField = selected.manifest.configFields.first else {
            configDraftKey = ""
            configDraftValue = ""
            return
        }
        configDraftKey = firstField.key
        configDraftValue = selected.configurationValues[firstField.key] ?? firstField.defaultValue
    }

    // MARK: - Header Telemetry Bar

    private var studioHeaderStrip: some View {
        HStack(spacing: 8) {
            Image(systemName: "puzzlepiece.extension.fill")
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(RackTheme.amberAccent)

            Text(localizer.L("JavaScriptCore Plugin Sandbox", "JavaScriptCore 插件沙盒"))
                .font(RackTheme.sectionHeaderFont)
                .foregroundStyle(RackTheme.inkPrimary)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)

            RackStatusPill(
                label: localizer.L(
                    "\(viewModel.activePluginsCount)/\(max(4, viewModel.pluginStatuses.count)) Active",
                    "\(viewModel.activePluginsCount)/\(max(4, viewModel.pluginStatuses.count)) 已启用"
                ),
                color: RackTheme.linkGreen,
                monospaced: true
            )

            RackStatusPill(
                label: localizer.L(
                    "\(totalInvocations) hooks · \(totalInterceptions) blocks",
                    "\(totalInvocations) 次调用 · \(totalInterceptions) 次拦截"
                ),
                color: totalInterceptions > 0 ? RackTheme.amberAccent : RackTheme.vsockBlue,
                monospaced: true
            )

            Spacer(minLength: 6)

            Button {
                viewModel.exportHCLDefault()
            } label: {
                Label(localizer.L("Export .avm.hcl", "导出 .avm.hcl"), systemImage: "square.and.arrow.up")
            }
            .buttonStyle(RackActionButtonStyle(prominence: .primaryAmber, compact: true))
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(
            RoundedRectangle(cornerRadius: RackTheme.outerCornerRadius, style: .continuous)
                .fill(RackTheme.moduleSurface)
        )
        .overlay(
            RoundedRectangle(cornerRadius: RackTheme.outerCornerRadius, style: .continuous)
                .strokeBorder(RackTheme.hairline, lineWidth: 1)
        )
    }

    // MARK: - 4 Sandboxed Plugins Grid + Selected Plugin Config Strip

    private var pluginRosterPanel: some View {
        RackPanelContainer(
            title: localizer.L("Extension Modules", "扩展安全模块"),
            subtitle: localizer.L("Zero Host FS/Net · 800ms Watchdog", "零宿主机文件/网络 · 800ms 看门狗"),
            symbolName: "cpu.fill",
            headerTrailing: {
                if let plugin = viewModel.selectedPlugin {
                    Button {
                        viewModel.loadSelectedPluginSourceIntoScratchpad()
                    } label: {
                        Label(localizer.L("Load in Scratchpad", "载入演练场"), systemImage: "curlybraces")
                    }
                    .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
                    .help(localizer.L(
                        "Copy \(plugin.manifest.name) source into Scratchpad",
                        "将「\(plugin.manifest.localizedName)」源码复制到演练场"
                    ))
                }
            },
            content: {
                VStack(alignment: .leading, spacing: 8) {
                    LazyVGrid(
                        columns: [
                            GridItem(.flexible(minimum: 240), spacing: 8),
                            GridItem(.flexible(minimum: 240), spacing: 8)
                        ],
                        spacing: 8
                    ) {
                        ForEach(viewModel.pluginStatuses) { status in
                            PluginModuleCard(
                                status: status,
                                isSelected: viewModel.selectedPlugin?.id == status.id,
                                onSelect: {
                                    viewModel.selectedPluginID = status.id
                                },
                                onToggleEnabled: {
                                    viewModel.togglePluginEnabled(status.id)
                                },
                                onToggleCapability: { cap in
                                    viewModel.togglePluginCapability(cap, for: status.id)
                                }
                            )
                        }
                    }

                    if let selected = viewModel.selectedPlugin {
                        selectedPluginInspectorBar(for: selected)
                    }
                }
                .padding(10)
            }
        )
    }

    private func selectedPluginInspectorBar(for status: PluginRuntimeStatus) -> some View {
        HStack(spacing: 8) {
            Text(status.manifest.id.rawValue)
                .font(RackTheme.monoSmallFont)
                .foregroundStyle(RackTheme.amberAccent)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)

            Text("v\(status.manifest.version.description)")
                .font(RackTheme.monoSmallFont)
                .foregroundStyle(RackTheme.inkMuted)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)

            Rectangle()
                .fill(RackTheme.hairline)
                .frame(width: 1, height: 14)

            if let field = status.manifest.configFields.first {
                Text("\(field.key):")
                    .font(RackTheme.monoSmallFont)
                    .foregroundStyle(RackTheme.inkSecondary)
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)

                TextField(field.defaultValue, text: $configDraftValue)
                    .textFieldStyle(.plain)
                    .font(RackTheme.monoSmallFont)
                    .foregroundStyle(RackTheme.inkPrimary)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 3)
                    .frame(maxWidth: 160)
                    .background(
                        RoundedRectangle(cornerRadius: RackTheme.badgeCornerRadius, style: .continuous)
                            .fill(RackTheme.terminalWell)
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: RackTheme.badgeCornerRadius, style: .continuous)
                            .strokeBorder(RackTheme.hairline, lineWidth: 1)
                    )
                    .onSubmit {
                        viewModel.updatePluginConfig(
                            pluginID: status.id,
                            key: field.key,
                            value: configDraftValue
                        )
                    }

                Button(localizer.L("Apply", "应用")) {
                    viewModel.updatePluginConfig(
                        pluginID: status.id,
                        key: field.key,
                        value: configDraftValue
                    )
                }
                .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
            } else {
                Text(status.manifest.localizedSummary)
                    .font(RackTheme.captionFont)
                    .foregroundStyle(RackTheme.inkSecondary)
                    .lineLimit(1)
            }

            Spacer(minLength: 4)

            Text(localizer.L("Timeout \(status.manifest.timeoutMilliseconds)ms", "超时 \(status.manifest.timeoutMilliseconds)ms"))
                .font(RackTheme.monoSmallFont)
                .monospacedDigit()
                .foregroundStyle(RackTheme.inkMuted)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(
            RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                .fill(RackTheme.bladeRecessed)
        )
        .overlay(
            RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                .strokeBorder(RackTheme.hairline, lineWidth: 1)
        )
    }

    // MARK: - Live JS Scratchpad Runner (`onPacket(pkt)`)

    private var scratchpadRunnerPanel: some View {
        RackPanelContainer(
            title: localizer.L("Live JS Scratchpad", "实时 JS 演练场"),
            subtitle: nil,
            symbolName: "bolt.horizontal.circle.fill",
            headerTrailing: {
                HStack(spacing: 6) {
                    RackStatusPill(
                        label: "\(viewModel.scratchpadDurationMicros) µs",
                        color: RackTheme.vsockBlue,
                        monospaced: true
                    )

                    Button {
                        isEditingScratchpad.toggle()
                    } label: {
                        Text(isEditingScratchpad ? localizer.L("Done", "完成") : localizer.L("Edit", "编辑"))
                    }
                    .buttonStyle(RackActionButtonStyle(prominence: .subtleGhost, compact: true))

                    Button {
                        viewModel.evaluateScratchpad()
                    } label: {
                        Label(localizer.L("Run", "运行"), systemImage: "play.fill")
                    }
                    .buttonStyle(RackActionButtonStyle(prominence: .primaryAmber, compact: true))
                }
            },
            content: {
                VStack(alignment: .leading, spacing: 8) {
                    // JS Code Well
                    Group {
                        if isEditingScratchpad {
                            TextEditor(text: $viewModel.scratchpadSource)
                                .font(RackTheme.monoSmallFont)
                                .scrollContentBackground(.hidden)
                                .foregroundStyle(RackTheme.inkPrimary)
                                .padding(6)
                        } else {
                            ScrollView([.vertical, .horizontal], showsIndicators: true) {
                                VStack(alignment: .leading, spacing: 2) {
                                    let lines = viewModel.scratchpadSource.components(separatedBy: "\n")
                                    ForEach(Array(lines.enumerated()), id: \.offset) { idx, line in
                                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                                            Text(String(format: "%2d", idx + 1))
                                                .font(RackTheme.monoSmallFont)
                                                .monospacedDigit()
                                                .foregroundStyle(RackTheme.inkMuted)
                                                .frame(width: 20, alignment: .trailing)

                                            syntaxHighlightedJSLine(line)
                                                .font(RackTheme.monoSmallFont)
                                                .lineLimit(1)
                                                .fixedSize(horizontal: true, vertical: false)
                                        }
                                    }
                                }
                                .padding(8)
                                .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(
                        RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                            .fill(RackTheme.terminalWell)
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                            .strokeBorder(RackTheme.hairline, lineWidth: 1)
                    )

                    // JSON Verdict + Console Output Box
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 6) {
                            Text(localizer.L("Hook Return Verdict (JSON)", "钩子返回判定 (JSON)"))
                                .font(RackTheme.labelFont)
                                .foregroundStyle(RackTheme.inkSecondary)
                                .lineLimit(1)
                                .fixedSize(horizontal: true, vertical: false)

                            Spacer(minLength: 4)

                            let isDropVerdict = viewModel.scratchpadOutputJSON.localizedCaseInsensitiveContains("\"drop\"")
                            RackStatusPill(
                                label: isDropVerdict
                                    ? localizer.L("VERDICT: DROP", "判定: 丢弃")
                                    : localizer.L("VERDICT: ALLOW", "判定: 放行"),
                                color: isDropVerdict ? RackTheme.dropCrimson : RackTheme.linkGreen,
                                monospaced: true
                            )
                        }

                        ScrollView(.vertical, showsIndicators: true) {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(viewModel.scratchpadOutputJSON)
                                    .font(RackTheme.monoSmallFont)
                                    .foregroundStyle(RackTheme.linkGreen)
                                    .frame(maxWidth: .infinity, alignment: .leading)

                                if !viewModel.scratchpadConsoleLines.isEmpty {
                                    Divider().overlay(RackTheme.hairline)
                                    ForEach(Array(viewModel.scratchpadConsoleLines.enumerated()), id: \.offset) { _, logLine in
                                        Text(logLine)
                                            .font(RackTheme.monoSmallFont)
                                            .foregroundStyle(RackTheme.amberAccent)
                                            .lineLimit(1)
                                    }
                                }
                            }
                            .padding(8)
                        }
                        .frame(height: 92)
                        .background(
                            RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                                .fill(RackTheme.terminalWell)
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                                .strokeBorder(RackTheme.hairline, lineWidth: 1)
                        )
                    }
                }
                .padding(10)
            }
        )
    }

    // MARK: - Declarative `.avm.hcl` & `compose.yaml` Live Topology Bridge

    private var declarativeTopologyPanel: some View {
        let showingHCL = viewModel.selectedIaCFormat != "compose"
        let activeDocumentText = showingHCL ? viewModel.hclPreview : viewModel.composePreview

        return RackPanelContainer(
            title: localizer.L("IaC Topology Bridge", "IaC 拓扑桥接"),
            subtitle: nil,
            symbolName: "doc.text.magnifyingglass",
            headerTrailing: {
                HStack(spacing: 4) {
                    iacFormatTabButton(label: ".avm.hcl", formatKey: "hcl")
                    iacFormatTabButton(label: "compose.yaml", formatKey: "compose")
                }
            },
            content: {
                VStack(alignment: .leading, spacing: 8) {
                    ScrollView([.vertical, .horizontal], showsIndicators: true) {
                        VStack(alignment: .leading, spacing: 2) {
                            let lines = activeDocumentText.components(separatedBy: "\n")
                            ForEach(Array(lines.prefix(90).enumerated()), id: \.offset) { idx, line in
                                HStack(alignment: .firstTextBaseline, spacing: 8) {
                                    Text(String(format: "%2d", idx + 1))
                                        .font(RackTheme.monoSmallFont)
                                        .monospacedDigit()
                                        .foregroundStyle(RackTheme.inkMuted)
                                        .frame(width: 22, alignment: .trailing)

                                    syntaxHighlightedIaCLine(line, isHCL: showingHCL)
                                        .font(RackTheme.monoSmallFont)
                                        .lineLimit(1)
                                        .fixedSize(horizontal: true, vertical: false)
                                }
                            }
                        }
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(
                        RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                            .fill(RackTheme.terminalWell)
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                            .strokeBorder(RackTheme.hairline, lineWidth: 1)
                    )

                    // Recent Plugin Hook Audit Feed
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(localizer.L("Recent Sandbox Hook Events", "近期沙盒钩子事件"))
                                .font(RackTheme.labelFont)
                                .foregroundStyle(RackTheme.inkSecondary)
                                .lineLimit(1)
                                .fixedSize(horizontal: true, vertical: false)
                            Spacer()
                            Text(localizer.L("\(viewModel.pluginLogs.count) events", "\(viewModel.pluginLogs.count) 条事件"))
                                .font(RackTheme.monoSmallFont)
                                .monospacedDigit()
                                .foregroundStyle(RackTheme.inkMuted)
                                .lineLimit(1)
                                .fixedSize(horizontal: true, vertical: false)
                        }

                        ScrollView(.vertical, showsIndicators: false) {
                            VStack(alignment: .leading, spacing: 4) {
                                ForEach(viewModel.pluginLogs.prefix(5)) { entry in
                                    HStack(spacing: 6) {
                                        Circle()
                                            .fill(RackTheme.severityColor(for: entry.level))
                                            .frame(width: 6, height: 6)

                                        Text(shortPluginSlug(entry.pluginID.rawValue))
                                            .font(.system(size: 9.5, weight: .semibold, design: .monospaced))
                                            .foregroundStyle(RackTheme.vsockBlue)
                                            .lineLimit(1)
                                            .fixedSize(horizontal: true, vertical: false)

                                        Text(compactHookMessage(entry.message))
                                            .font(.system(size: 10, weight: .regular))
                                            .foregroundStyle(RackTheme.inkPrimary)
                                            .lineLimit(1)
                                            .fixedSize(horizontal: true, vertical: false)

                                        Spacer(minLength: 2)

                                        if entry.durationMicros > 0 {
                                            Text("\(entry.durationMicros)µs")
                                                .font(RackTheme.monoSmallFont)
                                                .monospacedDigit()
                                                .foregroundStyle(RackTheme.inkMuted)
                                                .lineLimit(1)
                                                .fixedSize(horizontal: true, vertical: false)
                                        }
                                    }
                                }
                            }
                            .padding(8)
                        }
                        .frame(height: 92)
                        .background(
                            RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                                .fill(RackTheme.terminalWell)
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                                .strokeBorder(RackTheme.hairline, lineWidth: 1)
                        )
                    }
                }
                .padding(10)
            }
        )
    }

    private func iacFormatTabButton(label: String, formatKey: String) -> some View {
        let selected = viewModel.selectedIaCFormat == formatKey
        return Button {
            viewModel.selectedIaCFormat = formatKey
        } label: {
            Text(label)
                .font(RackTheme.monoSmallFont)
                .foregroundStyle(selected ? RackTheme.inkPrimary : RackTheme.inkMuted)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
                .padding(.horizontal, 8)
                .padding(.vertical, 3)
                .background(
                    RoundedRectangle(cornerRadius: RackTheme.badgeCornerRadius, style: .continuous)
                        .fill(selected ? RackTheme.amberSoft : RackTheme.bladeRecessed)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: RackTheme.badgeCornerRadius, style: .continuous)
                        .strokeBorder(selected ? RackTheme.amberAccent : RackTheme.hairline, lineWidth: 1)
                )
        }
        .buttonStyle(.plain)
    }

    private func shortPluginSlug(_ raw: String) -> String {
        switch raw {
        case "builtin.secret-leak-guard": return "secret-guard"
        case "builtin.runaway-budget-breaker": return "budget-guard"
        case "builtin.auto-git-checkpoint": return "git-snap"
        case "builtin.iac-compose-bridge": return "iac-bridge"
        default: return raw.replacingOccurrences(of: "builtin.", with: "")
        }
    }

    private func compactHookMessage(_ message: String) -> String {
        if message.localizedCaseInsensitiveContains("pre-exec") || message.localizedCaseInsensitiveContains("checkpoint") {
            return localizer.L("Pre-exec CoW snapshot", "执行前自动快照")
        }
        if message.localizedCaseInsensitiveContains("Overrode") {
            return localizer.L("Packet -> PLUGIN_DROP", "报文 -> 插件拦截")
        }
        if message.localizedCaseInsensitiveContains("Anthropic") || message.localizedCaseInsensitiveContains("Dropped outbound") {
            return localizer.L("Blocked API token leak", "已拦截密钥外泄")
        }
        if message.localizedCaseInsensitiveContains("Registered") {
            return localizer.L("Sandbox initialized", "沙盒已初始化")
        }
        return message.count <= 24 ? message : String(message.prefix(24))
    }

    // MARK: - Lightweight Deterministic Syntax Coloring

    private func syntaxHighlightedJSLine(_ line: String) -> Text {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("//") {
            return Text(line).foregroundColor(RackTheme.inkMuted)
        }
        if trimmed.hasPrefix("function ") || trimmed.hasPrefix("return ") || trimmed.hasPrefix("if ") || trimmed.hasPrefix("const ") {
            return Text(line).foregroundColor(RackTheme.amberAccent)
        }
        if line.contains("AgentVM.") {
            return Text(line).foregroundColor(RackTheme.vsockBlue)
        }
        if line.contains("\"") {
            return Text(line).foregroundColor(RackTheme.linkGreen)
        }
        return Text(line).foregroundColor(RackTheme.inkPrimary)
    }

    private func syntaxHighlightedIaCLine(_ line: String, isHCL: Bool) -> Text {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("#") || trimmed.hasPrefix("//") {
            return Text(line).foregroundColor(RackTheme.inkMuted)
        }
        if isHCL {
            if trimmed.hasPrefix("vm ") || trimmed.hasPrefix("firewall_policy ") || trimmed.hasPrefix("rule ") || trimmed.hasPrefix("workspace ") {
                return Text(line).foregroundColor(RackTheme.amberAccent)
            }
            if line.contains("=") {
                return Text(line).foregroundColor(RackTheme.inkPrimary)
            }
        } else {
            if trimmed.hasSuffix(":") && !trimmed.hasPrefix("-") {
                return Text(line).foregroundColor(RackTheme.vsockBlue)
            }
        }
        return Text(line).foregroundColor(RackTheme.inkSecondary)
    }
}

// MARK: - Individual Sandboxed Plugin Card

private struct PluginModuleCard: View {
    @ObservedObject private var localizer = AgentVMLocalizer.shared
    let status: PluginRuntimeStatus
    let isSelected: Bool
    let onSelect: () -> Void
    let onToggleEnabled: () -> Void
    let onToggleCapability: (PluginCapability) -> Void

    private var cardDisplayTitle: String {
        if localizer.isChinese {
            return status.manifest.localizedName
        }
        return status.manifest.id.rawValue.replacingOccurrences(of: "builtin.", with: "")
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Circle()
                    .fill(status.isEnabled ? RackTheme.linkGreen : RackTheme.inkMuted)
                    .frame(width: 7, height: 7)

                Text(cardDisplayTitle)
                    .font(localizer.isChinese ? .system(size: 11.5, weight: .semibold) : RackTheme.monoBoldFont)
                    .foregroundStyle(RackTheme.inkPrimary)
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)

                Spacer(minLength: 4)

                MachinedTogglePill(isOn: status.isEnabled, action: onToggleEnabled)
            }

            // Capability Badges Row
            HStack(spacing: 4) {
                ForEach(status.manifest.requestedCapabilities.prefix(3), id: \.self) { cap in
                    let isGranted = status.grantedCapabilities.contains(cap)
                    let tint = RackTheme.severityColor(for: cap.riskLevel)
                    Button {
                        onToggleCapability(cap)
                    } label: {
                        Text(cap.rawValue)
                            .font(.system(size: 9.5, weight: .medium, design: .monospaced))
                            .foregroundStyle(isGranted ? tint : RackTheme.inkMuted)
                            .lineLimit(1)
                            .fixedSize(horizontal: true, vertical: false)
                            .padding(.horizontal, 5)
                            .padding(.vertical, 2)
                            .background(
                                RoundedRectangle(cornerRadius: RackTheme.badgeCornerRadius, style: .continuous)
                                    .fill(isGranted ? tint.opacity(0.14) : RackTheme.chassisBackground)
                            )
                            .overlay(
                                RoundedRectangle(cornerRadius: RackTheme.badgeCornerRadius, style: .continuous)
                                    .strokeBorder(isGranted ? tint.opacity(0.35) : RackTheme.hairline, lineWidth: 1)
                            )
                    }
                    .buttonStyle(.plain)
                    .help(cap.localizedDescription)
                }
                Spacer(minLength: 0)
            }

            // Telemetry Counters Row
            HStack(spacing: 10) {
                Text(localizer.L("Calls \(status.invocationCount)", "调用 \(status.invocationCount)"))
                    .font(RackTheme.monoSmallFont)
                    .monospacedDigit()
                    .foregroundStyle(RackTheme.inkSecondary)
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)

                Text(localizer.L("Blocks \(status.blockedActionsCount)", "拦截 \(status.blockedActionsCount)"))
                    .font(RackTheme.monoSmallFont)
                    .monospacedDigit()
                    .foregroundStyle(status.blockedActionsCount > 0 ? RackTheme.dropCrimson : RackTheme.inkMuted)
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)

                Spacer(minLength: 2)

                Text("\(status.averageDurationMicros) µs")
                    .font(RackTheme.monoSmallFont)
                    .monospacedDigit()
                    .foregroundStyle(RackTheme.vsockBlue)
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(
            RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                .fill(isSelected ? RackTheme.moduleElevated : RackTheme.bladeRecessed)
        )
        .overlay(
            RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                .strokeBorder(isSelected ? RackTheme.amberAccent : RackTheme.hairline, lineWidth: 1)
        )
        .contentShape(Rectangle())
        .onTapGesture(perform: onSelect)
    }
}

private struct MachinedTogglePill: View {
    @ObservedObject private var localizer = AgentVMLocalizer.shared
    let isOn: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 4) {
                if isOn {
                    Text(localizer.L("ON", "启用"))
                        .font(.system(size: 9, weight: .bold, design: .monospaced))
                        .foregroundStyle(RackTheme.linkGreen)
                        .lineLimit(1)
                        .fixedSize(horizontal: true, vertical: false)
                }
                Circle()
                    .fill(isOn ? RackTheme.linkGreen : RackTheme.inkMuted)
                    .frame(width: 8, height: 8)
                if !isOn {
                    Text(localizer.L("OFF", "停用"))
                        .font(.system(size: 9, weight: .bold, design: .monospaced))
                        .foregroundStyle(RackTheme.inkMuted)
                        .lineLimit(1)
                        .fixedSize(horizontal: true, vertical: false)
                }
            }
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(
                Capsule(style: .continuous)
                    .fill(isOn ? RackTheme.linkGreenSoft : RackTheme.chassisBackground)
            )
            .overlay(
                Capsule(style: .continuous)
                    .strokeBorder(isOn ? RackTheme.linkGreen.opacity(0.45) : RackTheme.hairline, lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
    }
}
