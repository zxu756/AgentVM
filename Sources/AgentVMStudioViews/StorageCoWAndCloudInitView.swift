import AgentVMModels
import AgentVMStorageCoW
import AgentVMWorkbenchShell
import SwiftUI

// MARK: - APFS Copy-on-Write Extent Map, Disk Forensics & NoCloud ISO-9660 Studio

public struct StorageCoWAndCloudInitView: View {
    @ObservedObject public var viewModel: AgentVMStudioViewModel

    private let cloudInitTabNames = ["user-data", "network-config", "meta-data", "vendor-data"]

    public init(viewModel: AgentVMStudioViewModel) {
        self.viewModel = viewModel
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            storageMetricsStrip

            HStack(alignment: .top, spacing: 10) {
                VStack(spacing: 8) {
                    apfsExtentAllocationPanel
                        .frame(minHeight: 250, maxHeight: .infinity)

                    diskForensicsAndEntropyPanel
                        .frame(minHeight: 205, maxHeight: 245)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)

                noCloudISO9660StudioPanel
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .padding(10)
        .background(RackTheme.chassisBackground)
    }

    // MARK: - Top Storage Telemetry Strip

    private var storageMetricsStrip: some View {
        let alloc = viewModel.diskAllocation
        let vSize = alloc?.virtualSizeBytes ?? 0
        let holes = alloc?.sparseHoleBytes ?? 0
        let shared = alloc?.sharedWithParentBytes ?? 0
        let dirty = alloc?.uniqueDirtyBytes ?? 0
        let fsKind = viewModel.apfsCapabilities?.filesystemTypeName.uppercased() ?? "APFS"
        let partCount = viewModel.diskForensics?.containerSummary.partitions.count ?? 0

        return HStack(spacing: 8) {
            RackMetricTile(
                label: "Virtual Capacity",
                value: ByteMetricsFormatter.formatBytes(vSize),
                detail: "\(fsKind) · \(partCount) GPT Partitions",
                accent: RackTheme.inkPrimary
            )
            RackMetricTile(
                label: "Sparse Holes",
                value: ByteMetricsFormatter.formatBytes(holes),
                detail: "SEEK_HOLE Zero-Alloc",
                accent: RackTheme.linkGreen
            )
            RackMetricTile(
                label: "Shared Parent Blocks",
                value: ByteMetricsFormatter.formatBytes(shared),
                detail: "Inherited CoW Extents",
                accent: RackTheme.vsockBlue
            )
            RackMetricTile(
                label: "Unique CoW Dirty",
                value: ByteMetricsFormatter.formatBytes(dirty),
                detail: "Diverged Child Blocks",
                accent: RackTheme.amberAccent
            )
        }
    }

    // MARK: - Left Upper: Visual APFS Extent Allocation Map

    private var apfsExtentAllocationPanel: some View {
        RackPanelContainer(
            title: "APFS Extent Allocation Map",
            subtitle: nil,
            symbolName: "internaldrive.fill",
            headerTrailing: {
                Button {
                    viewModel.compactSelectedVMDiskZeroBlocks()
                } label: {
                    Label("Punch Zero Holes", systemImage: "scissors")
                }
                .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))
            },
            content: {
                if let alloc = viewModel.diskAllocation {
                    VStack(alignment: .leading, spacing: 8) {
                        proportionalExtentBar(alloc: alloc)

                        extentLegendRow(alloc: alloc)

                        extentTableHeader

                        ScrollView {
                            LazyVStack(spacing: 2) {
                                ForEach(alloc.extents) { ext in
                                    extentTableRow(ext)
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
                    }
                } else {
                    Text("Select a sandbox VM blade to scan APFS sparse extents.")
                        .font(RackTheme.captionFont)
                        .foregroundStyle(RackTheme.inkMuted)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
        )
    }

    private func proportionalExtentBar(alloc: DiskAllocationSummary) -> some View {
        GeometryReader { geo in
            let totalWidth = max(1, geo.size.width)
            let vTotal = Double(max(1, alloc.virtualSizeBytes))

            Canvas { context, size in
                let bgRect = CGRect(origin: .zero, size: size)
                context.fill(Path(bgRect), with: .color(RackTheme.terminalWell))

                var cursorX: CGFloat = 0
                for ext in alloc.extents {
                    let rawRatio = Double(ext.lengthBytes) / vTotal
                    // Ensure non-hole allocated extents remain at least 4pt wide so sub-MB CoW blocks are clearly visible
                    let minVisWidth: CGFloat = ext.kind == .sparseHole ? 1.0 : 5.0
                    let segW = max(minVisWidth, CGFloat(rawRatio) * totalWidth)
                    let clampedW = min(segW, max(0, totalWidth - cursorX))
                    guard clampedW > 0 else { continue }

                    let rect = CGRect(x: cursorX, y: 0, width: clampedW, height: size.height)
                    context.fill(Path(rect), with: .color(colorForExtent(ext.kind)))
                    cursorX += clampedW
                }
            }
        }
        .frame(height: 20)
        .clipShape(RoundedRectangle(cornerRadius: 4, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 4, style: .continuous)
                .strokeBorder(RackTheme.hairlineStrong, lineWidth: 1)
        )
    }

    private func extentLegendRow(alloc: DiskAllocationSummary) -> some View {
        HStack(spacing: 12) {
            legendSwatch(label: "Sparse Holes", color: colorForExtent(.sparseHole))
            legendSwatch(label: "Shared Parent Blocks", color: colorForExtent(.allocatedClean))
            legendSwatch(label: "Unique CoW Dirty", color: colorForExtent(.allocatedDirty))
            Spacer(minLength: 4)
            Text("Blk \(alloc.filesystemBlockSize) B")
                .font(RackTheme.monoSmallFont)
                .monospacedDigit()
                .foregroundStyle(RackTheme.inkMuted)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
        }
    }

    private func legendSwatch(label: String, color: Color) -> some View {
        HStack(spacing: 5) {
            RoundedRectangle(cornerRadius: 2, style: .continuous)
                .fill(color)
                .frame(width: 9, height: 9)
                .overlay(
                    RoundedRectangle(cornerRadius: 2, style: .continuous)
                        .strokeBorder(RackTheme.hairlineStrong, lineWidth: 0.5)
                )
            Text(label)
                .font(RackTheme.captionFont)
                .foregroundStyle(RackTheme.inkSecondary)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
        }
    }

    private var extentTableHeader: some View {
        HStack(spacing: 8) {
            Text("Byte Offset")
                .frame(width: 96, alignment: .leading)
            Text("Length")
                .frame(width: 78, alignment: .trailing)
            Text("Extent Class")
                .frame(width: 128, alignment: .leading)
            Text("CRC-32")
                .frame(maxWidth: .infinity, alignment: .trailing)
        }
        .font(.system(size: 10, weight: .semibold))
        .foregroundStyle(RackTheme.inkMuted)
        .padding(.horizontal, 8)
    }

    private func extentTableRow(_ ext: SparseExtent) -> some View {
        let pillColor: Color = {
            switch ext.kind {
            case .sparseHole: return RackTheme.inkMuted
            case .allocatedClean: return RackTheme.vsockBlue
            case .allocatedDirty: return RackTheme.amberAccent
            }
        }()
        let pillText: String = {
            switch ext.kind {
            case .sparseHole: return "SPARSE HOLE"
            case .allocatedClean: return "SHARED PARENT"
            case .allocatedDirty: return "COW DIRTY"
            }
        }()

        return HStack(spacing: 8) {
            Text(String(format: "0x%08llX", ext.offsetBytes))
                .font(RackTheme.monoSmallFont)
                .monospacedDigit()
                .foregroundStyle(RackTheme.inkPrimary)
                .lineLimit(1)
                .frame(width: 96, alignment: .leading)

            Text(ByteMetricsFormatter.formatBytes(ext.lengthBytes))
                .font(RackTheme.monoSmallFont)
                .monospacedDigit()
                .foregroundStyle(RackTheme.inkSecondary)
                .lineLimit(1)
                .frame(width: 78, alignment: .trailing)

            RackStatusPill(label: pillText, color: pillColor, monospaced: true)
                .frame(width: 128, alignment: .leading)

            Text(ext.checksumCRC32.map { String(format: "0x%08X", $0) } ?? "0x00000000")
                .font(RackTheme.monoSmallFont)
                .monospacedDigit()
                .foregroundStyle(RackTheme.inkMuted)
                .lineLimit(1)
                .frame(maxWidth: .infinity, alignment: .trailing)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 3.5)
    }

    private func colorForExtent(_ kind: SparseExtentKind) -> Color {
        switch kind {
        case .sparseHole:
            return Color(red: 0.16, green: 0.18, blue: 0.22)
        case .allocatedClean:
            return RackTheme.vsockBlue
        case .allocatedDirty:
            return RackTheme.amberAccent
        }
    }

    // MARK: - Left Lower: Disk Forensics, Superblock Magic & Shannon Entropy

    private var diskForensicsAndEntropyPanel: some View {
        RackPanelContainer(
            title: "Superblock & Shannon Entropy Forensics",
            subtitle: nil,
            symbolName: "waveform.badge.magnifyingglass",
            headerTrailing: {
                if let report = viewModel.diskForensics {
                    RackStatusPill(
                        label: String(format: "PEAK %.2f b/B", report.peakBlockEntropyBits),
                        color: RackTheme.checkpointGold,
                        monospaced: true
                    )
                }
            },
            content: {
                if let report = viewModel.diskForensics {
                    VStack(alignment: .leading, spacing: 7) {
                        // Shannon Entropy Heatmap Strip
                        entropyHeatmapStrip(samples: report.entropyHeatmapSamples)

                        HStack(spacing: 12) {
                            Text(String(format: "Mean Allocated H(X): %.2f bits/B", report.overallAllocatedEntropyBits))
                                .font(RackTheme.monoSmallFont)
                                .monospacedDigit()
                                .foregroundStyle(RackTheme.inkSecondary)
                                .lineLimit(1)
                            Spacer(minLength: 4)
                            Text("Format: \(report.containerSummary.format.rawValue)")
                                .font(RackTheme.monoSmallFont)
                                .foregroundStyle(RackTheme.amberAccent)
                                .lineLimit(1)
                        }

                        ScrollView {
                            VStack(alignment: .leading, spacing: 4) {
                                ForEach(report.detectedFilesystems) { fs in
                                    HStack(spacing: 6) {
                                        Image(systemName: fs.kind.sfSymbolName)
                                            .font(.system(size: 10.5, weight: .semibold))
                                            .foregroundStyle(RackTheme.linkGreen)
                                        Text(fs.kind.displayName)
                                            .font(.system(size: 11, weight: .semibold))
                                            .foregroundStyle(RackTheme.inkPrimary)
                                            .lineLimit(1)
                                        Spacer(minLength: 4)
                                        Text(fs.magicHexSummary)
                                            .font(RackTheme.monoSmallFont)
                                            .foregroundStyle(RackTheme.linkGreen)
                                            .lineLimit(1)
                                            .fixedSize(horizontal: true, vertical: false)
                                    }
                                    .padding(.horizontal, 7)
                                    .padding(.vertical, 4)
                                    .background(
                                        RoundedRectangle(cornerRadius: 4, style: .continuous)
                                            .fill(RackTheme.linkGreenSoft)
                                    )
                                }

                                ForEach(report.containerSummary.partitions) { part in
                                    HStack(spacing: 6) {
                                        RackStatusPill(label: "GPT #\(part.index)", color: RackTheme.vsockBlue, monospaced: true)
                                        Text(part.name)
                                            .font(.system(size: 11, weight: .semibold))
                                            .foregroundStyle(RackTheme.inkPrimary)
                                            .lineLimit(1)
                                        Spacer(minLength: 4)
                                        Text("LBA \(part.firstLBA)...\(part.lastLBA) (\(ByteMetricsFormatter.formatBytes(part.sizeBytes())))")
                                            .font(RackTheme.monoSmallFont)
                                            .monospacedDigit()
                                            .foregroundStyle(RackTheme.inkSecondary)
                                            .lineLimit(1)
                                            .fixedSize(horizontal: true, vertical: false)
                                    }
                                    .padding(.horizontal, 7)
                                    .padding(.vertical, 3.5)
                                    .background(
                                        RoundedRectangle(cornerRadius: 4, style: .continuous)
                                            .fill(RackTheme.chassisBackground.opacity(0.7))
                                    )
                                }
                            }
                        }
                    }
                } else {
                    Text("No forensics telemetry available.")
                        .font(RackTheme.captionFont)
                        .foregroundStyle(RackTheme.inkMuted)
                }
            }
        )
    }

    private func entropyHeatmapStrip(samples: [DiskEntropyBlockSample]) -> some View {
        Canvas { context, size in
            context.fill(Path(CGRect(origin: .zero, size: size)), with: .color(RackTheme.terminalWell))
            guard !samples.isEmpty else { return }
            let barW = size.width / CGFloat(samples.count)
            for (idx, sample) in samples.enumerated() {
                let color: Color = {
                    switch sample.regime {
                    case .sparseOrZero, .constantFill:
                        return Color(red: 0.16, green: 0.18, blue: 0.22)
                    case .lowEntropyMetadata:
                        return RackTheme.linkGreen
                    case .moderateStructuredBinary:
                        return RackTheme.vsockBlue
                    case .highEntropyCompressedOrEncrypted:
                        return RackTheme.amberAccent
                    }
                }()
                let normalizedH = sample.isSparseKernelHole
                    ? 0.16
                    : max(0.22, min(1.0, sample.shannonBitsPerByte / 8.0))
                let barH = size.height * CGFloat(normalizedH)
                let rect = CGRect(
                    x: CGFloat(idx) * barW,
                    y: size.height - barH,
                    width: max(1, barW - 0.8),
                    height: barH
                )
                context.fill(Path(rect), with: .color(color))
            }
        }
        .frame(height: 22)
        .clipShape(RoundedRectangle(cornerRadius: 4, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 4, style: .continuous)
                .strokeBorder(RackTheme.hairline, lineWidth: 1)
        )
    }

    // MARK: - Right Column: NoCloud `cidata` ISO-9660 + Rock Ridge Inspector & YAML Studio

    private var noCloudISO9660StudioPanel: some View {
        RackPanelContainer(
            title: "NoCloud 'cidata' ISO-9660 Studio",
            subtitle: nil,
            symbolName: "opticaldisc.fill",
            headerTrailing: {
                HStack(spacing: 6) {
                    if let iso = viewModel.isoInspection, iso.hasRockRidgeSUSP {
                        RackStatusPill(label: "ROCK RIDGE SUSP", color: RackTheme.linkGreen, monospaced: true)
                    }
                    Button {
                        viewModel.rebuildCloudInitISOForSelectedVM()
                    } label: {
                        Label("Rebuild ISO", systemImage: "arrow.triangle.2.circlepath")
                    }
                    .buttonStyle(RackActionButtonStyle(prominence: .primaryAmber, compact: true))
                }
            },
            content: {
                VStack(alignment: .leading, spacing: 8) {
                    // Quick Hostname & Default User Inline Editor
                    HStack(spacing: 8) {
                        Text("Hostname:")
                            .font(RackTheme.captionFont)
                            .foregroundStyle(RackTheme.inkMuted)
                            .lineLimit(1)
                            .fixedSize(horizontal: true, vertical: false)

                        TextField("hostname", text: $viewModel.editableCloudInit.hostname)
                            .textFieldStyle(.plain)
                            .font(RackTheme.monoSmallFont)
                            .foregroundStyle(RackTheme.inkPrimary)
                            .padding(.horizontal, 7)
                            .padding(.vertical, 4)
                            .background(
                                RoundedRectangle(cornerRadius: 4, style: .continuous)
                                    .fill(RackTheme.chassisBackground)
                            )
                            .overlay(
                                RoundedRectangle(cornerRadius: 4, style: .continuous)
                                    .strokeBorder(RackTheme.hairlineStrong, lineWidth: 1)
                            )

                        Text("User:")
                            .font(RackTheme.captionFont)
                            .foregroundStyle(RackTheme.inkMuted)
                            .lineLimit(1)
                            .fixedSize(horizontal: true, vertical: false)

                        TextField("agent", text: $viewModel.editableCloudInit.defaultUser)
                            .textFieldStyle(.plain)
                            .font(RackTheme.monoSmallFont)
                            .foregroundStyle(RackTheme.amberAccent)
                            .frame(width: 78)
                            .padding(.horizontal, 7)
                            .padding(.vertical, 4)
                            .background(
                                RoundedRectangle(cornerRadius: 4, style: .continuous)
                                    .fill(RackTheme.chassisBackground)
                            )
                            .overlay(
                                RoundedRectangle(cornerRadius: 4, style: .continuous)
                                    .strokeBorder(RackTheme.hairlineStrong, lineWidth: 1)
                            )
                    }

                    // ISO-9660 Sector & Rock Ridge Directory Table
                    if let iso = viewModel.isoInspection {
                        isoVolumeMetadataBanner(iso)
                        rockRidgeEntriesTable(iso)
                    }

                    // Cloud-Init Payload File Tabs
                    HStack(spacing: 5) {
                        ForEach(cloudInitTabNames, id: \.self) { name in
                            let selected = viewModel.selectedCloudInitFileTab == name
                            Button {
                                viewModel.selectedCloudInitFileTab = name
                            } label: {
                                Text(name)
                                    .font(RackTheme.monoSmallFont)
                                    .foregroundStyle(selected ? RackTheme.inkPrimary : RackTheme.inkMuted)
                                    .lineLimit(1)
                                    .fixedSize(horizontal: true, vertical: false)
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 4)
                                    .background(
                                        RoundedRectangle(cornerRadius: 4, style: .continuous)
                                            .fill(selected ? RackTheme.moduleElevated : RackTheme.chassisBackground.opacity(0.6))
                                    )
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 4, style: .continuous)
                                            .strokeBorder(selected ? RackTheme.amberAccent : RackTheme.hairline, lineWidth: 1)
                                    )
                            }
                            .buttonStyle(.plain)
                        }
                        Spacer(minLength: 0)
                    }

                    // Live YAML Preview
                    ScrollView([.vertical, .horizontal], showsIndicators: true) {
                        Text(activeCloudInitYAMLContent)
                            .font(RackTheme.monoSmallFont)
                            .foregroundStyle(RackTheme.inkPrimary)
                            .textSelection(.enabled)
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
                }
            }
        )
    }

    private func isoVolumeMetadataBanner(_ iso: ISOInspectionReport) -> some View {
        let totalBytes = UInt64(iso.volumeSpaceBlocks) * UInt64(iso.logicalBlockSize)
        return HStack(spacing: 10) {
            Text("VolID: \(iso.volumeIdentifier)")
                .font(RackTheme.monoBoldFont)
                .foregroundStyle(RackTheme.amberAccent)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
            Text("Sector: \(iso.logicalBlockSize) B")
                .font(RackTheme.monoSmallFont)
                .monospacedDigit()
                .foregroundStyle(RackTheme.inkSecondary)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
            Text("Sectors: \(iso.volumeSpaceBlocks) (\(ByteMetricsFormatter.formatBytes(totalBytes)))")
                .font(RackTheme.monoSmallFont)
                .monospacedDigit()
                .foregroundStyle(RackTheme.inkSecondary)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
            Spacer(minLength: 4)
            Text("L-Path LBA \(iso.typeLPathTableLBA)")
                .font(RackTheme.monoSmallFont)
                .monospacedDigit()
                .foregroundStyle(RackTheme.vsockBlue)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 5)
        .background(
            RoundedRectangle(cornerRadius: 4, style: .continuous)
                .fill(RackTheme.chassisBackground.opacity(0.75))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 4, style: .continuous)
                .strokeBorder(RackTheme.hairline, lineWidth: 1)
        )
    }

    private func rockRidgeEntriesTable(_ iso: ISOInspectionReport) -> some View {
        VStack(spacing: 2) {
            HStack(spacing: 8) {
                Text("Rock Ridge NM")
                    .frame(width: 112, alignment: .leading)
                Text("ISO 8.3 ID")
                    .frame(width: 96, alignment: .leading)
                Text("Sector LBA")
                    .frame(width: 72, alignment: .trailing)
                Text("Mode")
                    .frame(width: 48, alignment: .trailing)
                Text("Size")
                    .frame(width: 62, alignment: .trailing)
                Text("SHA-256")
                    .frame(maxWidth: .infinity, alignment: .trailing)
            }
            .font(.system(size: 10, weight: .semibold))
            .foregroundStyle(RackTheme.inkMuted)
            .padding(.horizontal, 8)
            .padding(.bottom, 2)

            ForEach(iso.entries) { entry in
                let isSelectedFile = entry.path == viewModel.selectedCloudInitFileTab
                HStack(spacing: 8) {
                    Text(entry.path)
                        .font(RackTheme.monoSmallFont)
                        .foregroundStyle(isSelectedFile ? RackTheme.amberAccent : RackTheme.inkPrimary)
                        .lineLimit(1)
                        .frame(width: 112, alignment: .leading)

                    Text(entry.isoLevel1Identifier)
                        .font(RackTheme.monoSmallFont)
                        .foregroundStyle(RackTheme.inkSecondary)
                        .lineLimit(1)
                        .frame(width: 96, alignment: .leading)

                    Text("LBA \(entry.extentLBA)")
                        .font(RackTheme.monoSmallFont)
                        .monospacedDigit()
                        .foregroundStyle(RackTheme.vsockBlue)
                        .lineLimit(1)
                        .frame(width: 72, alignment: .trailing)

                    Text(entry.posixMode.map { String(format: "0%o", $0) } ?? "0644")
                        .font(RackTheme.monoSmallFont)
                        .monospacedDigit()
                        .foregroundStyle(RackTheme.linkGreen)
                        .lineLimit(1)
                        .frame(width: 48, alignment: .trailing)

                    Text("\(entry.sizeBytes) B")
                        .font(RackTheme.monoSmallFont)
                        .monospacedDigit()
                        .foregroundStyle(RackTheme.inkPrimary)
                        .lineLimit(1)
                        .frame(width: 62, alignment: .trailing)

                    Text(String(entry.sha256Hex.prefix(10)))
                        .font(RackTheme.monoSmallFont)
                        .foregroundStyle(RackTheme.inkMuted)
                        .lineLimit(1)
                        .frame(maxWidth: .infinity, alignment: .trailing)
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 3.5)
                .background(
                    RoundedRectangle(cornerRadius: 3.5, style: .continuous)
                        .fill(isSelectedFile ? RackTheme.amberSoft.opacity(0.6) : RackTheme.terminalWell)
                )
                .contentShape(Rectangle())
                .onTapGesture {
                    if cloudInitTabNames.contains(entry.path) {
                        viewModel.selectedCloudInitFileTab = entry.path
                    }
                }
            }
        }
        .padding(6)
        .background(
            RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                .fill(RackTheme.terminalWell)
        )
        .overlay(
            RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                .strokeBorder(RackTheme.hairline, lineWidth: 1)
        )
    }

    private var activeCloudInitYAMLContent: String {
        if let entry = viewModel.isoRenderedFiles.first(where: { $0.path == viewModel.selectedCloudInitFileTab }),
           let text = entry.utf8String {
            return text
        }
        let fallbackFiles = ISO9660CloudInitBuilder().renderNoCloudFiles(from: viewModel.editableCloudInit)
        return fallbackFiles.first(where: { $0.path == viewModel.selectedCloudInitFileTab })?.utf8String ?? "# Empty"
    }
}
