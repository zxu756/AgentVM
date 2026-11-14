import AgentVMModels
import AgentVMNetSwitch
import AgentVMWorkbenchShell
import SwiftUI

// MARK: - 3-Pane L2 Packet Dissector & Synchronized Hex Dump

public struct WiresharkPacketWiretapView: View {
    @ObservedObject public var viewModel: AgentVMStudioViewModel
    @ObservedObject private var localizer = AgentVMLocalizer.shared

    @State private var newestFirst: Bool = true
    @State private var collapsedLayerIDs: Set<String> = []
    @State private var collapsedFieldIDs: Set<String> = []

    public init(viewModel: AgentVMStudioViewModel) {
        self.viewModel = viewModel
    }

    private var orderedDisplayPackets: [CapturedPacket] {
        newestFirst ? Array(viewModel.filteredPackets.reversed()) : viewModel.filteredPackets
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            liveTrafficM5NoticeBanner

            filterAndActionsToolbar

            upperPacketTablePane
                .frame(minHeight: 195, maxHeight: 260)

            HStack(alignment: .top, spacing: 8) {
                protocolDissectionTreePane
                    .frame(minWidth: 360, maxWidth: .infinity, maxHeight: .infinity)

                synchronizedHexAsciiDumpPane
                    .frame(minWidth: 452, idealWidth: 515, maxWidth: 550, maxHeight: .infinity)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .padding(10)
        .background(RackTheme.chassisBackground)
    }

    private var liveTrafficM5NoticeBanner: some View {
        HStack(spacing: 8) {
            Image(systemName: "info.circle.fill")
                .font(.system(size: 11.5, weight: .semibold))
                .foregroundStyle(RackTheme.amberAccent)
            if viewModel.isDemoMode {
                RackStatusPill(
                    label: viewModel.demoBadgeText,
                    color: RackTheme.amberAccent,
                    monospaced: true
                )
            }
            Text(viewModel.liveTrafficStatusNotice)
                .font(RackTheme.captionFont)
                .foregroundStyle(RackTheme.inkPrimary)
                .lineLimit(1)
            Spacer(minLength: 4)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(
            RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                .fill(RackTheme.amberSoft)
        )
        .overlay(
            RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                .strokeBorder(RackTheme.amberAccent.opacity(0.55), lineWidth: 1)
        )
    }

    // MARK: - Top Filter Query & Preset Bar

    private var filterAndActionsToolbar: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                HStack(spacing: 6) {
                    Image(systemName: "line.3.horizontal.decrease.circle.fill")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle( filterStatusColor )

                    TextField(
                        localizer.L(
                            "Boolean wiretap filter (e.g. proto == TLS || verdict == DROP)",
                            "布尔过滤表达式 (例如 proto == TLS || verdict == DROP)"
                        ),
                        text: Binding(
                            get: { viewModel.wiretapFilterText },
                            set: { viewModel.applyWiretapFilter($0) }
                        )
                    )
                    .textFieldStyle(.plain)
                    .font(RackTheme.monoFont)
                    .foregroundStyle(RackTheme.inkPrimary)

                    if !viewModel.wiretapFilterText.isEmpty {
                        Button {
                            viewModel.selectQuickWiretapPreset(.all)
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .font(.system(size: 11))
                                .foregroundStyle(RackTheme.inkMuted)
                        }
                        .buttonStyle(.plain)
                    }

                    RackStatusPill(
                        label: viewModel.parsedFilterQuery.usedSubstringFallback
                            ? localizer.L("SUBSTR", "子串匹配")
                            : localizer.L("AST OK", "语法就绪"),
                        color: filterStatusColor,
                        monospaced: true
                    )
                }
                .padding(.horizontal, 9)
                .padding(.vertical, 5)
                .background(
                    RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                        .fill(RackTheme.moduleSurface)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                        .strokeBorder(RackTheme.hairlineStrong, lineWidth: 1)
                )

                ForEach(WiretapQuickPreset.allCases) { preset in
                    let isActive = viewModel.activeQuickPreset == preset
                        && viewModel.wiretapFilterText == preset.queryExpression
                    Button {
                        viewModel.selectQuickWiretapPreset(preset)
                    } label: {
                        Text(preset.localizedLabel)
                    }
                    .buttonStyle(
                        RackActionButtonStyle(
                            prominence: isActive ? .primaryAmber : .secondaryModule,
                            compact: true
                        )
                    )
                }

                Menu {
                    ForEach(SyntheticPacketProbeKind.allCases) { probe in
                        Button(probe.localizedLabel) {
                            viewModel.injectSyntheticProbePacket(probe)
                        }
                    }
                } label: {
                    Label(localizer.L("Probe", "注入探测"), systemImage: "bolt.horizontal.circle")
                        .font(RackTheme.labelFont)
                        .foregroundStyle(RackTheme.inkPrimary)
                        .lineLimit(1)
                        .fixedSize(horizontal: true, vertical: false)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(
                            RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                                .fill(RackTheme.moduleElevated)
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                                .strokeBorder(RackTheme.hairlineStrong, lineWidth: 1)
                        )
                }
                .menuStyle(.borderlessButton)
                .fixedSize()

                Button {
                    viewModel.exportPCAPNGDefault()
                } label: {
                    Label(localizer.L("Export .pcapng", "导出 .pcapng"), systemImage: "square.and.arrow.up")
                }
                .buttonStyle(RackActionButtonStyle(prominence: .primaryAmber, compact: true))
            }

            HStack(spacing: 14) {
                telemetryStatBadge(
                    label: localizer.L("Captured", "已捕获"),
                    value: localizer.L(
                        "\(viewModel.filteredPackets.count) / \(viewModel.allPackets.count) frames",
                        "\(viewModel.filteredPackets.count) / \(viewModel.allPackets.count) 帧"
                    ),
                    color: RackTheme.vsockBlue
                )
                telemetryStatBadge(
                    label: localizer.L("Blocked", "已拦截"),
                    value: localizer.L("\(viewModel.droppedPacketCount) drops", "\(viewModel.droppedPacketCount) 次丢弃"),
                    color: viewModel.droppedPacketCount > 0 ? RackTheme.dropCrimson : RackTheme.inkMuted
                )
                telemetryStatBadge(
                    label: localizer.L("Active TCP Flows", "活跃 TCP 流"),
                    value: "\(viewModel.activeFlows.count)",
                    color: RackTheme.linkGreen
                )
                telemetryStatBadge(
                    label: localizer.L("DHCP Leases", "DHCP 租约"),
                    value: "\(viewModel.dhcpLeases.count)",
                    color: RackTheme.amberAccent
                )
                if let stats = viewModel.switchStatistics {
                    telemetryStatBadge(
                        label: localizer.L("Switch Subnet", "交换网段"),
                        value: stats.subnetCIDR,
                        color: RackTheme.inkSecondary
                    )
                }

                Spacer(minLength: 4)

                Button {
                    newestFirst.toggle()
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: newestFirst ? "arrow.down.to.line.compact" : "arrow.up.to.line.compact")
                            .font(.system(size: 10, weight: .bold))
                        Text(newestFirst
                            ? localizer.L("Order: Latest First", "排序: 最新优先")
                            : localizer.L("Order: Chronological", "排序: 时间顺序")
                        )
                            .font(RackTheme.monoSmallFont)
                            .lineLimit(1)
                            .fixedSize(horizontal: true, vertical: false)
                    }
                    .foregroundStyle(RackTheme.inkSecondary)
                }
                .buttonStyle(.plain)
            }
            .padding(.horizontal, 4)
        }
    }

    private var filterStatusColor: Color {
        viewModel.parsedFilterQuery.usedSubstringFallback ? RackTheme.checkpointGold : RackTheme.linkGreen
    }

    private func telemetryStatBadge(label: String, value: String, color: Color) -> some View {
        HStack(spacing: 5) {
            Text(label)
                .font(RackTheme.captionFont)
                .foregroundStyle(RackTheme.inkMuted)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
            Text(value)
                .font(RackTheme.monoSmallFont)
                .monospacedDigit()
                .foregroundStyle(color)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
        }
    }

    // MARK: - Pane 1: Upper Dense Tabular Packet List

    private var upperPacketTablePane: some View {
        VStack(spacing: 0) {
            packetTableHeaderRow

            Rectangle()
                .fill(RackTheme.hairlineStrong)
                .frame(height: 1)

            if orderedDisplayPackets.isEmpty {
                VStack(spacing: 6) {
                    Image(systemName: "waveform.slash")
                        .font(.system(size: 18))
                        .foregroundStyle(RackTheme.inkMuted)
                    Text(localizer.L(
                        "No captured Ethernet frames match '\(viewModel.wiretapFilterText)'.",
                        "没有匹配过滤条件「\(viewModel.wiretapFilterText)」的以太网数据帧。"
                    ))
                        .font(RackTheme.labelFont)
                        .foregroundStyle(RackTheme.inkMuted)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(RackTheme.terminalWell)
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(orderedDisplayPackets) { pkt in
                            packetTableRow(pkt)
                        }
                    }
                }
                .background(RackTheme.terminalWell)
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: RackTheme.outerCornerRadius, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: RackTheme.outerCornerRadius, style: .continuous)
                .strokeBorder(RackTheme.hairline, lineWidth: 1)
        )
    }

    private var packetTableHeaderRow: some View {
        HStack(spacing: 8) {
            colHeader(localizer.L("Seq", "序号"), width: 46, alignment: .trailing)
            colHeader(localizer.L("Proto", "协议"), width: 58, alignment: .leading)
            colHeader(localizer.L("Dir", "方向"), width: 44, alignment: .leading)
            colHeader(localizer.L("Source", "源地址"), width: 138, alignment: .leading)
            colHeader(localizer.L("Destination", "目的地址"), width: 142, alignment: .leading)
            colHeader(localizer.L("Len", "长度"), width: 50, alignment: .trailing)
            colHeader(localizer.L("Verdict", "判定"), width: 106, alignment: .leading)
            Text(localizer.L("Summary / TLS SNI", "报文摘要 / TLS SNI"))
                .font(.system(size: 10.5, weight: .semibold))
                .foregroundStyle(RackTheme.inkMuted)
                .lineLimit(1)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(RackTheme.moduleElevated)
    }

    private func colHeader(_ text: String, width: CGFloat, alignment: Alignment) -> some View {
        Text(text)
            .font(.system(size: 10.5, weight: .semibold))
            .foregroundStyle(RackTheme.inkMuted)
            .lineLimit(1)
            .fixedSize(horizontal: true, vertical: false)
            .frame(width: width, alignment: alignment)
    }

    private func packetTableRow(_ pkt: CapturedPacket) -> some View {
        let isSelected = viewModel.selectedPacket?.id == pkt.id
        let protoColor = RackTheme.protocolColor(for: pkt.highestProtocol)
        let verdictColor = RackTheme.verdictColor(for: pkt.verdict)

        let rowFill: Color = {
            if isSelected { return RackTheme.amberAccent.opacity(0.20) }
            if !pkt.verdict.isPermitted { return RackTheme.dropCrimson.opacity(0.06) }
            return Color.clear
        }()

        return HStack(spacing: 8) {
            Text("#\(pkt.sequenceNumber)")
                .font(RackTheme.monoSmallFont)
                .monospacedDigit()
                .foregroundStyle(isSelected ? RackTheme.amberAccent : RackTheme.inkMuted)
                .lineLimit(1)
                .frame(width: 46, alignment: .trailing)

            RackStatusPill(
                label: pkt.highestProtocol.rawValue,
                color: protoColor,
                monospaced: true
            )
            .frame(width: 58, alignment: .leading)

            Text(shortDirectionTag(pkt.direction))
                .font(RackTheme.monoSmallFont)
                .foregroundStyle(pkt.direction == .egress ? RackTheme.inkSecondary : RackTheme.vsockBlue)
                .lineLimit(1)
                .frame(width: 44, alignment: .leading)

            Text(endpointDisplay(ip: pkt.sourceIP, port: pkt.sourcePort, fallbackMAC: pkt.sourceMAC))
                .font(RackTheme.monoSmallFont)
                .monospacedDigit()
                .foregroundStyle(RackTheme.inkPrimary)
                .lineLimit(1)
                .frame(width: 138, alignment: .leading)

            Text(endpointDisplay(ip: pkt.destinationIP, port: pkt.destinationPort, fallbackMAC: pkt.destinationMAC))
                .font(RackTheme.monoSmallFont)
                .monospacedDigit()
                .foregroundStyle(RackTheme.inkPrimary)
                .lineLimit(1)
                .frame(width: 142, alignment: .leading)

            Text("\(pkt.frameLength) B")
                .font(RackTheme.monoSmallFont)
                .monospacedDigit()
                .foregroundStyle(RackTheme.inkSecondary)
                .lineLimit(1)
                .frame(width: 50, alignment: .trailing)

            RackStatusPill(
                label: pkt.verdict.localizedBadge,
                color: verdictColor,
                monospaced: true
            )
            .frame(width: 106, alignment: .leading)

            HStack(spacing: 6) {
                if let sni = pkt.tlsSNI, !sni.isEmpty {
                    Text("SNI: \(sni)")
                        .font(.system(size: 10, weight: .semibold, design: .monospaced))
                        .foregroundStyle(RackTheme.vsockBlue)
                        .lineLimit(1)
                        .fixedSize(horizontal: true, vertical: false)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1.5)
                        .background(
                            RoundedRectangle(cornerRadius: 3, style: .continuous)
                                .fill(RackTheme.vsockBlueSoft)
                        )
                } else if let qname = pkt.dnsQueryName, !qname.isEmpty {
                    Text("DNS: \(qname)")
                        .font(.system(size: 10, weight: .semibold, design: .monospaced))
                        .foregroundStyle(RackTheme.checkpointGold)
                        .lineLimit(1)
                        .fixedSize(horizontal: true, vertical: false)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1.5)
                        .background(
                            RoundedRectangle(cornerRadius: 3, style: .continuous)
                                .fill(RackTheme.checkpointSoft)
                        )
                }

                Text(compactPacketSummary(pkt))
                    .font(RackTheme.monoSmallFont)
                    .foregroundStyle(isSelected ? RackTheme.inkPrimary : RackTheme.inkSecondary)
                    .lineLimit(1)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 4.5)
        .background(rowFill)
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(RackTheme.hairline.opacity(0.45))
                .frame(height: 0.5)
        }
        .overlay(alignment: .leading) {
            if isSelected {
                Rectangle()
                    .fill(RackTheme.amberAccent)
                    .frame(width: 2.5)
            }
        }
        .contentShape(Rectangle())
        .onTapGesture {
            viewModel.selectPacket(pkt.id)
        }
    }

    // MARK: - Pane 2: Lower-Left Expandable Protocol Layer & Field Tree

    private var protocolDissectionTreePane: some View {
        RackPanelContainer(
            title: localizer.L("Protocol Layer & Field Tree", "协议分层与字段解析树"),
            subtitle: selectedPacketSubtitle,
            symbolName: "list.bullet.indent",
            headerTrailing: {
                if let range = viewModel.highlightedByteRange {
                    RackStatusPill(
                        label: localizer.L(
                            "BYTES [\(range.lowerBound)..<\(range.upperBound)]",
                            "字节 [\(range.lowerBound)..<\(range.upperBound)]"
                        ),
                        color: RackTheme.amberAccent,
                        monospaced: true
                    )
                }
            },
            content: {
                if let pkt = viewModel.selectedPacket {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 5) {
                            verdictBannerRow(for: pkt)

                            ForEach(pkt.dissectedLayers) { layer in
                                dissectedLayerGroup(layer)
                            }
                        }
                        .padding(4)
                    }
                    .background(
                        RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                            .fill(RackTheme.terminalWell)
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                            .strokeBorder(RackTheme.hairline, lineWidth: 1)
                    )
                } else {
                    Text(localizer.L(
                        "Select a captured packet above to inspect Ethernet, IPv4, TCP/UDP, DNS, HTTP, and TLS 1.3 layers.",
                        "在上方列表中选择任意数据帧，即可检视 Ethernet、IPv4、TCP/UDP、DNS、HTTP 与 TLS 1.3 分层字段。"
                    ))
                        .font(RackTheme.captionFont)
                        .foregroundStyle(RackTheme.inkMuted)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
        )
    }

    private var selectedPacketSubtitle: String {
        guard let pkt = viewModel.selectedPacket else { return localizer.L("No frame", "未选择帧") }
        return localizer.L(
            "#\(pkt.sequenceNumber) · \(pkt.frameLength) B · \(pkt.dissectedLayers.count)L",
            "#\(pkt.sequenceNumber) · \(pkt.frameLength) B · \(pkt.dissectedLayers.count) 层"
        )
    }

    private func verdictBannerRow(for pkt: CapturedPacket) -> some View {
        let color = RackTheme.verdictColor(for: pkt.verdict)
        return HStack(spacing: 7) {
            Image(systemName: pkt.verdict.isPermitted ? "checkmark.shield.fill" : "xmark.shield.fill")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(color)
            Text(pkt.verdict.localizedBadge)
                .font(.system(size: 10.5, weight: .bold, design: .monospaced))
                .foregroundStyle(color)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
            Text(compactVerdictReason(pkt.verdictReason))
                .font(RackTheme.captionFont)
                .foregroundStyle(RackTheme.inkSecondary)
                .lineLimit(1)
            Spacer(minLength: 4)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 5)
        .background(
            RoundedRectangle(cornerRadius: 4, style: .continuous)
                .fill(color.opacity(0.11))
        )
    }

    private func dissectedLayerGroup(_ layer: DissectedLayer) -> some View {
        let isExpanded = !collapsedLayerIDs.contains(layer.id)
        let isLayerHighlighted = viewModel.highlightedByteRange == layer.byteRange
            && viewModel.selectedDissectedFieldID == layer.id
        let protoColor = RackTheme.protocolColor(for: layer.protocolKind)

        return VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                Button {
                    if isExpanded {
                        collapsedLayerIDs.insert(layer.id)
                    } else {
                        collapsedLayerIDs.remove(layer.id)
                    }
                } label: {
                    Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundStyle(RackTheme.inkMuted)
                        .frame(width: 14, height: 14)
                }
                .buttonStyle(.plain)

                Text(layer.protocolKind.rawValue)
                    .font(.system(size: 9.5, weight: .bold, design: .monospaced))
                    .foregroundStyle(protoColor)
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1.5)
                    .background(
                        RoundedRectangle(cornerRadius: 3, style: .continuous)
                            .fill(protoColor.opacity(0.15))
                    )

                Text(compactLayerTitle(layer))
                    .font(.system(size: 11.5, weight: .semibold))
                    .foregroundStyle(RackTheme.inkPrimary)
                    .lineLimit(1)

                Spacer(minLength: 4)

                Text("[\(layer.byteRange.lowerBound)..<\(layer.byteRange.upperBound)]")
                    .font(RackTheme.monoSmallFont)
                    .monospacedDigit()
                    .foregroundStyle(isLayerHighlighted ? RackTheme.amberAccent : RackTheme.inkMuted)
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)
            }
            .padding(.horizontal, 7)
            .padding(.vertical, 4.5)
            .background(
                RoundedRectangle(cornerRadius: 4, style: .continuous)
                    .fill(isLayerHighlighted ? RackTheme.amberSoft : RackTheme.moduleSurface.opacity(0.75))
            )
            .contentShape(Rectangle())
            .onTapGesture {
                viewModel.highlightBytes(layer.byteRange, fieldID: layer.id)
            }

            if isExpanded {
                VStack(alignment: .leading, spacing: 1.5) {
                    ForEach(layer.fields) { field in
                        dissectedFieldRow(field, indentLevel: 1)
                    }
                }
                .padding(.leading, 12)
            }
        }
    }

    private func dissectedFieldRow(_ field: DissectedField, indentLevel: Int) -> AnyView {
        let isHighlighted = viewModel.highlightedByteRange == field.byteRange
            && (viewModel.selectedDissectedFieldID == field.id || viewModel.selectedDissectedFieldID == nil)
        let hasChildren = !field.children.isEmpty
        let isExpanded = !collapsedFieldIDs.contains(field.id)

        return AnyView(
            VStack(alignment: .leading, spacing: 1.5) {
                HStack(spacing: 5) {
                    if hasChildren {
                        Button {
                            if isExpanded {
                                collapsedFieldIDs.insert(field.id)
                            } else {
                                collapsedFieldIDs.remove(field.id)
                            }
                        } label: {
                            Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                                .font(.system(size: 8, weight: .bold))
                                .foregroundStyle(RackTheme.inkMuted)
                                .frame(width: 11, height: 11)
                        }
                        .buttonStyle(.plain)
                    } else {
                        Circle()
                            .fill(isHighlighted ? RackTheme.amberAccent : RackTheme.hairlineStrong)
                            .frame(width: 4.5, height: 4.5)
                            .padding(.horizontal, 3)
                    }

                    Text("\(localizedFieldLabel(field.label)):")
                        .font(.system(size: 10.5, weight: .medium))
                        .foregroundStyle(isHighlighted ? RackTheme.amberAccent : RackTheme.inkSecondary)
                        .lineLimit(1)
                        .fixedSize(horizontal: true, vertical: false)

                    Text(compactFieldValue(field.valueSummary))
                        .font(RackTheme.monoSmallFont)
                        .foregroundStyle(isHighlighted ? RackTheme.inkPrimary : RackTheme.inkPrimary.opacity(0.9))
                        .lineLimit(1)

                    Spacer(minLength: 4)

                    Text("[\(field.byteRange.lowerBound)..<\(field.byteRange.upperBound)]")
                        .font(.system(size: 9.5, design: .monospaced))
                        .monospacedDigit()
                        .foregroundStyle(isHighlighted ? RackTheme.amberAccent : RackTheme.inkMuted)
                        .lineLimit(1)
                        .fixedSize(horizontal: true, vertical: false)
                }
                .padding(.horizontal, 6)
                .padding(.vertical, 3)
                .background(
                    RoundedRectangle(cornerRadius: 3.5, style: .continuous)
                        .fill(isHighlighted ? RackTheme.amberAccent.opacity(0.22) : Color.clear)
                )
                .contentShape(Rectangle())
                .onTapGesture {
                    viewModel.highlightBytes(field.byteRange, fieldID: field.id)
                }

                if hasChildren && isExpanded {
                    VStack(alignment: .leading, spacing: 1.5) {
                        ForEach(field.children) { child in
                            dissectedFieldRow(child, indentLevel: indentLevel + 1)
                        }
                    }
                    .padding(.leading, 12)
                }
            }
        )
    }

    // MARK: - Pane 3: Lower-Right Synchronized 16-Byte Hex + ASCII Dump

    private var synchronizedHexAsciiDumpPane: some View {
        RackPanelContainer(
            title: localizer.L("16-Byte Hex + ASCII Dump", "16 字节十六进制与 ASCII 视图"),
            subtitle: hexSubtitleText,
            symbolName: "number.square",
            headerTrailing: {
                if viewModel.highlightedByteRange != nil {
                    Button(localizer.L("Clear", "清除")) {
                        viewModel.highlightBytes(nil)
                    }
                    .buttonStyle(RackActionButtonStyle(prominence: .subtleGhost, compact: true))
                }
            },
            content: {
                if let pkt = viewModel.selectedPacket {
                    let rows = buildHexRows(from: pkt.rawFrame)
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 2) {
                            ForEach(rows) { row in
                                hexDumpLineView(row: row, packet: pkt)
                            }
                        }
                        .padding(8)
                    }
                    .background(
                        RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                            .fill(RackTheme.terminalWell)
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                            .strokeBorder(RackTheme.hairline, lineWidth: 1)
                    )
                } else {
                    Text(localizer.L("No frame bytes loaded.", "暂无数据帧字节载荷。"))
                        .font(RackTheme.captionFont)
                        .foregroundStyle(RackTheme.inkMuted)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
        )
    }

    private var hexSubtitleText: String {
        if let r = viewModel.highlightedByteRange {
            return localizer.L(
                "Highlighted \(r.count) B @ 0x\(String(format: "%04X", r.lowerBound))",
                "高亮 \(r.count) B @ 0x\(String(format: "%04X", r.lowerBound))"
            )
        }
        return localizer.L("Click any layer, field, or octet", "点击任意协议层、字段或字节定位")
    }

    private struct HexDumpRow: Identifiable {
        let rowOffset: Int
        let bytes: [UInt8]
        var id: Int { rowOffset }
    }

    private func buildHexRows(from data: Data) -> [HexDumpRow] {
        let allBytes = [UInt8](data)
        guard !allBytes.isEmpty else { return [] }
        var rows: [HexDumpRow] = []
        var offset = 0
        while offset < allBytes.count {
            let end = min(offset + 16, allBytes.count)
            rows.append(HexDumpRow(rowOffset: offset, bytes: Array(allBytes[offset..<end])))
            offset += 16
        }
        return rows
    }

    private func hexDumpLineView(row: HexDumpRow, packet: CapturedPacket) -> some View {
        let range = viewModel.highlightedByteRange
        let rowIntersects = range.map { $0.overlaps(row.rowOffset..<(row.rowOffset + row.bytes.count)) } ?? false

        return HStack(spacing: 6) {
            Text(String(format: "%04X", row.rowOffset))
                .font(.system(size: 10, weight: .semibold, design: .monospaced))
                .monospacedDigit()
                .foregroundStyle(rowIntersects ? RackTheme.amberAccent : RackTheme.inkMuted)
                .lineLimit(1)
                .frame(width: 34, alignment: .leading)

            HStack(spacing: 2) {
                ForEach(0..<16, id: \.self) { col in
                    if col < row.bytes.count {
                        let byteIndex = row.rowOffset + col
                        let isHighlighted = range?.contains(byteIndex) ?? false
                        Text(String(format: "%02X", row.bytes[col]))
                            .font(.system(size: 10, weight: isHighlighted ? .bold : .regular, design: .monospaced))
                            .monospacedDigit()
                            .foregroundStyle(isHighlighted ? Color(red: 0.08, green: 0.08, blue: 0.09) : RackTheme.inkPrimary)
                            .padding(.horizontal, 1.5)
                            .padding(.vertical, 1)
                            .background(
                                RoundedRectangle(cornerRadius: 2.5, style: .continuous)
                                    .fill(isHighlighted ? RackTheme.amberAccent : Color.clear)
                            )
                            .onTapGesture {
                                selectFieldContainingByte(byteIndex, in: packet)
                            }
                    } else {
                        Text("  ")
                            .font(.system(size: 10, design: .monospaced))
                            .padding(.horizontal, 1.5)
                            .padding(.vertical, 1)
                    }
                    if col == 7 {
                        Spacer().frame(width: 4)
                    }
                }
            }

            HStack(spacing: 0) {
                Text("|")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(RackTheme.inkMuted)

                ForEach(0..<row.bytes.count, id: \.self) { col in
                    let byteIndex = row.rowOffset + col
                    let isHighlighted = range?.contains(byteIndex) ?? false
                    let ch = printableASCII(row.bytes[col])
                    Text(ch)
                        .font(.system(size: 10, weight: isHighlighted ? .bold : .regular, design: .monospaced))
                        .foregroundStyle(isHighlighted ? Color(red: 0.08, green: 0.08, blue: 0.09) : RackTheme.inkSecondary)
                        .background(isHighlighted ? RackTheme.amberAccent : Color.clear)
                        .onTapGesture {
                            selectFieldContainingByte(byteIndex, in: packet)
                        }
                }

                if row.bytes.count < 16 {
                    Text(String(repeating: " ", count: 16 - row.bytes.count))
                        .font(.system(size: 10, design: .monospaced))
                }

                Text("|")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(RackTheme.inkMuted)
            }
            .fixedSize(horizontal: true, vertical: false)
        }
        .padding(.vertical, 1)
        .padding(.horizontal, 3)
        .background(
            RoundedRectangle(cornerRadius: 3, style: .continuous)
                .fill(rowIntersects ? RackTheme.amberSoft.opacity(0.32) : Color.clear)
        )
    }

    private func selectFieldContainingByte(_ byteIndex: Int, in packet: CapturedPacket) {
        for layer in packet.dissectedLayers.reversed() {
            for field in layer.fields {
                for child in field.children where child.byteRange.contains(byteIndex) {
                    viewModel.highlightBytes(child.byteRange, fieldID: child.id)
                    return
                }
                if field.byteRange.contains(byteIndex) {
                    viewModel.highlightBytes(field.byteRange, fieldID: field.id)
                    return
                }
            }
            if layer.byteRange.contains(byteIndex) {
                viewModel.highlightBytes(layer.byteRange, fieldID: layer.id)
                return
            }
        }
        viewModel.highlightBytes(byteIndex..<(byteIndex + 1))
    }

    // MARK: - Compact Zero-Truncation String Formatters

    private func shortDirectionTag(_ dir: NetworkDirection) -> String {
        switch dir {
        case .egress: return localizer.L("OUT", "出站")
        case .ingress: return localizer.L("IN", "入站")
        case .lateralVMToVM: return localizer.L("VM2VM", "横向")
        }
    }

    private func endpointDisplay(ip: String?, port: UInt16?, fallbackMAC: String) -> String {
        if let ip, !ip.isEmpty {
            if let port, port > 0 {
                return "\(ip):\(port)"
            }
            return ip
        }
        return fallbackMAC
    }

    private func compactPacketSummary(_ pkt: CapturedPacket) -> String {
        if pkt.tlsSNI != nil {
            let alpn = pkt.tlsALPN.first ?? "h2"
            return "TLS 1.3 ClientHello · \(alpn)"
        }
        if pkt.dnsQueryName != nil {
            if pkt.verdict == .dnsSinkhole {
                return pkt.direction == .ingress
                    ? localizer.L("Sinkhole Reply 0.0.0.0", "黑洞应答 0.0.0.0")
                    : localizer.L("Query A (Sinkholed)", "A 记录查询 (已黑洞拦截)")
            }
            return pkt.direction == .ingress
                ? localizer.L("DNS Reply A 140.82.121.4", "DNS 应答 A 140.82.121.4")
                : localizer.L("DNS Standard Query A", "DNS 标准查询 A")
        }
        if let req = pkt.httpRequestLine, !req.isEmpty {
            return req
        }
        let scrubbed = ByteMetricsFormatter.scrubHomePath(pkt.infoSummary)
        return scrubbed.count <= 56 ? scrubbed : String(scrubbed.prefix(56))
    }

    private func compactVerdictReason(_ reason: String) -> String {
        if reason.contains("Allow GitHub TLS") {
            return localizer.L(
                "Matched rule 'Allow GitHub TLS (*.github.com)'",
                "命中规则「允许 GitHub TLS (*.github.com)」"
            )
        }
        if reason.contains("169.254.169.254") {
            return localizer.L(
                "Matched rule 'Block Cloud Instance Metadata SSRF'",
                "命中规则「阻断云实例元数据 SSRF (169.254.169.254)」"
            )
        }
        if reason.contains("Sinkhole") || reason.contains("Webhook") {
            return localizer.L(
                "Matched rule 'Sinkhole Exfiltration Pastebins & Webhook Sinks'",
                "命中规则「DNS 黑洞拦截外泄站点与 Webhook」"
            )
        }
        if reason.contains("secret-leak-guard") || reason.contains("Credential leak") {
            return localizer.L(
                reason,
                "secret-leak-guard: 已拦截出站凭据密钥外泄"
            )
        }
        if reason.count <= 56 { return reason }
        return String(reason.prefix(56))
    }

    private func compactLayerTitle(_ layer: DissectedLayer) -> String {
        if localizer.isChinese {
            switch layer.protocolKind {
            case .ethernet:
                return "Ethernet II 以太网数据链路层"
            case .arp:
                return "ARP 地址解析协议"
            case .ipv4:
                return "IPv4 互联网协议头"
            case .icmp:
                return "ICMP 控制报文协议"
            case .tcp:
                return "TCP 传输控制协议段"
            case .udp:
                return "UDP 用户数据报协议"
            case .dhcp:
                return "DHCP 动态主机配置协议"
            case .dns:
                return "DNS 域名解析报文"
            case .http:
                return "HTTP 明文应用层请求"
            case .tls:
                return "TLS 1.3 加密握手层 (ClientHello)"
            case .ssh:
                return "SSH 加密会话层"
            case .unknown:
                return "原始二进制载荷"
            }
        }
        if layer.title.count <= 44 { return layer.title }
        return String(layer.title.prefix(44))
    }

    private func localizedFieldLabel(_ raw: String) -> String {
        guard localizer.isChinese else { return raw }
        switch raw {
        case "Destination MAC": return "目的 MAC"
        case "Source MAC": return "源 MAC"
        case "EtherType": return "以太类型"
        case "Version / IHL": return "版本 / 首部长度"
        case "Total Length": return "总长度"
        case "TTL": return "生存跳数 TTL"
        case "Protocol": return "上层协议"
        case "Header Checksum": return "首部校验和"
        case "Source IP": return "源 IPv4"
        case "Destination IP": return "目的 IPv4"
        case "Source Port": return "源端口"
        case "Destination Port": return "目的端口"
        case "Sequence Number", "Sequence": return "序列号 Seq"
        case "Ack Number", "Acknowledgment": return "确认号 Ack"
        case "Header Length / Flags", "Flags": return "首部标志位"
        case "Window Size", "Window": return "窗口大小"
        case "Length": return "长度"
        case "Checksum": return "校验和"
        case "Record Content Type", "Content Type": return "记录内容类型"
        case "Record Version", "Legacy Version": return "记录协议版本"
        case "Record Length": return "记录长度"
        case "Handshake Type": return "握手消息类型"
        case "Client Version": return "客户端版本"
        case "Client Random": return "客户端随机数"
        case "Cipher Suites": return "密码套件列表"
        case "Extensions": return "TLS 扩展列表"
        case "Server Name (SNI)": return "服务器名称指示 (SNI)"
        case "ALPN Protocols", "ALPN": return "应用层协议协商 (ALPN)"
        case "Supported Versions": return "支持的 TLS 版本"
        case "Transaction ID": return "事务 ID"
        case "Questions": return "查询问题数"
        case "Query Name", "QNAME": return "查询域名"
        case "Request Line": return "请求行"
        case "Host": return "主机头 Host"
        default: return raw
        }
    }

    private func compactFieldValue(_ val: String) -> String {
        let scrubbed = ByteMetricsFormatter.scrubHomePath(val)
        if scrubbed.count <= 48 { return scrubbed }
        return String(scrubbed.prefix(48))
    }

    private func printableASCII(_ byte: UInt8) -> String {
        if byte >= 0x20 && byte <= 0x7E {
            return String(UnicodeScalar(byte))
        }
        return "."
    }
}
