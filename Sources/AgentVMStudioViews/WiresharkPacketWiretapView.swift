import AgentVMModels
import AgentVMNetSwitch
import AgentVMWorkbenchShell
import SwiftUI

// MARK: - Wireshark-Grade 3-Pane Live L2 Packet Dissector & Synchronized Hex Dump

public struct WiresharkPacketWiretapView: View {
    @ObservedObject public var viewModel: AgentVMStudioViewModel

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
            filterAndActionsToolbar

            upperPacketTablePane
                .frame(minHeight: 210, maxHeight: 275)

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

    // MARK: - Top Filter Query & Preset Bar

    private var filterAndActionsToolbar: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                HStack(spacing: 6) {
                    Image(systemName: "line.3.horizontal.decrease.circle.fill")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle( filterStatusColor )

                    TextField(
                        "Boolean wiretap filter (e.g. proto == TLS || verdict == DROP)",
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
                        label: viewModel.parsedFilterQuery.usedSubstringFallback ? "SUBSTR" : "AST OK",
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
                        Text(preset.rawValue)
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
                        Button(probe.rawValue) {
                            viewModel.injectSyntheticProbePacket(probe)
                        }
                    }
                } label: {
                    Label("Probe", systemImage: "bolt.horizontal.circle")
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
                    Label("Export .pcapng", systemImage: "square.and.arrow.up")
                }
                .buttonStyle(RackActionButtonStyle(prominence: .primaryAmber, compact: true))
            }

            HStack(spacing: 14) {
                telemetryStatBadge(
                    label: "Captured",
                    value: "\(viewModel.filteredPackets.count) / \(viewModel.allPackets.count) frames",
                    color: RackTheme.vsockBlue
                )
                telemetryStatBadge(
                    label: "Blocked",
                    value: "\(viewModel.droppedPacketCount) drops",
                    color: viewModel.droppedPacketCount > 0 ? RackTheme.dropCrimson : RackTheme.inkMuted
                )
                telemetryStatBadge(
                    label: "Active TCP Flows",
                    value: "\(viewModel.activeFlows.count)",
                    color: RackTheme.linkGreen
                )
                telemetryStatBadge(
                    label: "DHCP Leases",
                    value: "\(viewModel.dhcpLeases.count)",
                    color: RackTheme.amberAccent
                )
                if let stats = viewModel.switchStatistics {
                    telemetryStatBadge(
                        label: "Switch Subnet",
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
                        Text(newestFirst ? "Order: Latest First" : "Order: Chronological")
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
                    Text("No captured Ethernet frames match '\(viewModel.wiretapFilterText)'.")
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
            colHeader("Seq", width: 46, alignment: .trailing)
            colHeader("Proto", width: 58, alignment: .leading)
            colHeader("Dir", width: 44, alignment: .leading)
            colHeader("Source", width: 138, alignment: .leading)
            colHeader("Destination", width: 142, alignment: .leading)
            colHeader("Len", width: 50, alignment: .trailing)
            colHeader("Verdict", width: 106, alignment: .leading)
            Text("Summary / TLS SNI")
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
                label: pkt.verdict.rawValue,
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
            title: "Protocol Layer & Field Tree",
            subtitle: selectedPacketSubtitle,
            symbolName: "list.bullet.indent",
            headerTrailing: {
                if let range = viewModel.highlightedByteRange {
                    RackStatusPill(
                        label: "BYTES [\(range.lowerBound)..<\(range.upperBound)]",
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
                    Text("Select a captured packet above to inspect Ethernet, IPv4, TCP/UDP, DNS, HTTP, and TLS 1.3 layers.")
                        .font(RackTheme.captionFont)
                        .foregroundStyle(RackTheme.inkMuted)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
        )
    }

    private var selectedPacketSubtitle: String {
        guard let pkt = viewModel.selectedPacket else { return "No frame" }
        return "#\(pkt.sequenceNumber) · \(pkt.frameLength) B · \(pkt.dissectedLayers.count)L"
    }

    private func verdictBannerRow(for pkt: CapturedPacket) -> some View {
        let color = RackTheme.verdictColor(for: pkt.verdict)
        return HStack(spacing: 7) {
            Image(systemName: pkt.verdict.isPermitted ? "checkmark.shield.fill" : "xmark.shield.fill")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(color)
            Text(pkt.verdict.rawValue)
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

                    Text("\(field.label):")
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
            title: "16-Byte Hex + ASCII Dump",
            subtitle: hexSubtitleText,
            symbolName: "number.square",
            headerTrailing: {
                if viewModel.highlightedByteRange != nil {
                    Button("Clear") {
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
                    Text("No frame bytes loaded.")
                        .font(RackTheme.captionFont)
                        .foregroundStyle(RackTheme.inkMuted)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
        )
    }

    private var hexSubtitleText: String {
        if let r = viewModel.highlightedByteRange {
            return "Highlighted \(r.count) B @ 0x\(String(format: "%04X", r.lowerBound))"
        }
        return "Click any layer, field, or octet"
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
        case .egress: return "OUT"
        case .ingress: return "IN"
        case .lateralVMToVM: return "VM2VM"
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
                return pkt.direction == .ingress ? "Sinkhole Reply 0.0.0.0" : "Query A (Sinkholed)"
            }
            return pkt.direction == .ingress ? "DNS Reply A 140.82.121.4" : "DNS Standard Query A"
        }
        if let req = pkt.httpRequestLine, !req.isEmpty {
            return req
        }
        let scrubbed = ByteMetricsFormatter.scrubHomePath(pkt.infoSummary)
        return scrubbed.count <= 56 ? scrubbed : String(scrubbed.prefix(56))
    }

    private func compactVerdictReason(_ reason: String) -> String {
        if reason.contains("Allow GitHub TLS") {
            return "Matched rule 'Allow GitHub TLS (*.github.com)'"
        }
        if reason.contains("169.254.169.254") {
            return "Matched rule 'Block Cloud Instance Metadata SSRF'"
        }
        if reason.count <= 56 { return reason }
        return String(reason.prefix(56))
    }

    private func compactLayerTitle(_ layer: DissectedLayer) -> String {
        if layer.title.count <= 44 { return layer.title }
        return String(layer.title.prefix(44))
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
