import AgentVMModels
import Combine
import Foundation
import SwiftUI

// MARK: - Multi-Pane Split & Document Tabbing Controller

@MainActor
public final class SplitDockingController: ObservableObject {
    @Published public var showLeftNavigator: Bool
    @Published public var showRightInspector: Bool
    @Published public var showBottomDrawer: Bool
    @Published public var activeBottomChannel: BottomDrawerChannel
    @Published public var splitMode: WorkbenchSplitMode

    @Published public var primaryTabs: [WorkbenchTabDescriptor]
    @Published public var activePrimaryTabID: UUID?

    @Published public var secondaryTabs: [WorkbenchTabDescriptor]
    @Published public var activeSecondaryTabID: UUID?

    @Published public var focusedPaneIndex: Int = 0 // 0 = primary, 1 = secondary
    @Published public var leftRailWidth: CGFloat = 258
    @Published public var rightRailWidth: CGFloat = 286
    @Published public var bottomDrawerHeight: CGFloat = 178

    public init(restoring snapshot: WorkbenchLayoutSnapshot? = nil) {
        if let snapshot, !snapshot.primaryTabs.isEmpty {
            self.showLeftNavigator = snapshot.showLeftFleetNavigator
            self.showRightInspector = snapshot.showRightInspector
            self.showBottomDrawer = snapshot.showBottomDrawer
            self.activeBottomChannel = snapshot.activeBottomChannel
            self.splitMode = snapshot.splitMode
            self.primaryTabs = snapshot.primaryTabs
            self.activePrimaryTabID = snapshot.activePrimaryTabID ?? snapshot.primaryTabs.first?.id
            self.secondaryTabs = snapshot.secondaryTabs
            self.activeSecondaryTabID = snapshot.activeSecondaryTabID ?? snapshot.secondaryTabs.first?.id
        } else {
            let dagTab = WorkbenchTabDescriptor(kind: .snapshotBranchDAG, isPinned: true)
            let wiretapTab = WorkbenchTabDescriptor(kind: .packetWiretap, isPinned: true)
            let consoleTab = WorkbenchTabDescriptor(kind: .vt100SerialConsole)
            let policyTab = WorkbenchTabDescriptor(kind: .firewallPolicyStudio)
            let storageTab = WorkbenchTabDescriptor(kind: .storageAndCloudInit)
            let pluginTab = WorkbenchTabDescriptor(kind: .pluginExtensionStudio)

            self.showLeftNavigator = true
            self.showRightInspector = true
            self.showBottomDrawer = true
            self.activeBottomChannel = .firewallAlerts
            self.splitMode = .singlePane
            self.primaryTabs = [dagTab, wiretapTab, consoleTab, policyTab, storageTab, pluginTab]
            self.activePrimaryTabID = dagTab.id
            self.secondaryTabs = [wiretapTab]
            self.activeSecondaryTabID = wiretapTab.id
        }
    }

    public var activePrimaryTab: WorkbenchTabDescriptor? {
        guard let activePrimaryTabID else { return primaryTabs.first }
        return primaryTabs.first(where: { $0.id == activePrimaryTabID }) ?? primaryTabs.first
    }

    public var activeSecondaryTab: WorkbenchTabDescriptor? {
        guard let activeSecondaryTabID else { return secondaryTabs.first }
        return secondaryTabs.first(where: { $0.id == activeSecondaryTabID }) ?? secondaryTabs.first
    }

    public func openOrFocus(kind: WorkbenchDocumentKind, vmID: VMID? = nil, inSecondaryPane: Bool = false) {
        if inSecondaryPane {
            if splitMode == .singlePane {
                splitMode = .verticalTwoColumn
            }
            if let existing = secondaryTabs.first(where: { $0.kind == kind && ($0.associatedVMID == vmID || vmID == nil) }) {
                activeSecondaryTabID = existing.id
                focusedPaneIndex = 1
                return
            }
            let created = WorkbenchTabDescriptor(kind: kind, associatedVMID: vmID)
            secondaryTabs.append(created)
            activeSecondaryTabID = created.id
            focusedPaneIndex = 1
        } else {
            if let existing = primaryTabs.first(where: { $0.kind == kind && ($0.associatedVMID == vmID || vmID == nil) }) {
                activePrimaryTabID = existing.id
                focusedPaneIndex = 0
                return
            }
            let created = WorkbenchTabDescriptor(kind: kind, associatedVMID: vmID)
            primaryTabs.append(created)
            activePrimaryTabID = created.id
            focusedPaneIndex = 0
        }
    }

    public func closeTab(id: UUID, inSecondaryPane: Bool = false) {
        if inSecondaryPane {
            guard let idx = secondaryTabs.firstIndex(where: { $0.id == id }) else { return }
            if secondaryTabs[idx].isPinned && secondaryTabs.count == 1 { return }
            secondaryTabs.remove(at: idx)
            if secondaryTabs.isEmpty {
                splitMode = .singlePane
                activeSecondaryTabID = nil
                focusedPaneIndex = 0
            } else if activeSecondaryTabID == id {
                let nextIdx = min(idx, secondaryTabs.count - 1)
                activeSecondaryTabID = secondaryTabs[nextIdx].id
            }
        } else {
            guard primaryTabs.count > 1,
                  let idx = primaryTabs.firstIndex(where: { $0.id == id }),
                  !primaryTabs[idx].isPinned else {
                return
            }
            primaryTabs.remove(at: idx)
            if activePrimaryTabID == id {
                let nextIdx = min(idx, primaryTabs.count - 1)
                activePrimaryTabID = primaryTabs[nextIdx].id
            }
        }
    }

    public func togglePin(id: UUID, inSecondaryPane: Bool = false) {
        if inSecondaryPane {
            guard let idx = secondaryTabs.firstIndex(where: { $0.id == id }) else { return }
            secondaryTabs[idx].isPinned.toggle()
        } else {
            guard let idx = primaryTabs.firstIndex(where: { $0.id == id }) else { return }
            primaryTabs[idx].isPinned.toggle()
        }
    }

    public func setDirty(_ dirty: Bool, for kind: WorkbenchDocumentKind) {
        for idx in primaryTabs.indices where primaryTabs[idx].kind == kind {
            primaryTabs[idx].hasUnsavedChanges = dirty
        }
        for idx in secondaryTabs.indices where secondaryTabs[idx].kind == kind {
            secondaryTabs[idx].hasUnsavedChanges = dirty
        }
    }

    public func splitCurrentTabRight() {
        guard let current = activePrimaryTab else { return }
        splitMode = .verticalTwoColumn
        if !secondaryTabs.contains(where: { $0.kind == current.kind }) {
            let clone = WorkbenchTabDescriptor(
                kind: current.kind,
                title: current.title,
                associatedVMID: current.associatedVMID
            )
            secondaryTabs.append(clone)
            activeSecondaryTabID = clone.id
        } else if activeSecondaryTabID == nil {
            activeSecondaryTabID = secondaryTabs.first?.id
        }
        focusedPaneIndex = 1
    }

    public func collapseSplit() {
        splitMode = .singlePane
        focusedPaneIndex = 0
    }

    public func selectTabAtOrdinal(_ ordinal1Based: Int) {
        let idx = ordinal1Based - 1
        guard primaryTabs.indices.contains(idx) else { return }
        activePrimaryTabID = primaryTabs[idx].id
    }

    public func exportLayoutSnapshot(
        workspaceID: WorkspaceID,
        selectedVMID: VMID?,
        selectedSnapshotID: SnapshotID?,
        selectedPacketID: PacketID?
    ) -> WorkbenchLayoutSnapshot {
        WorkbenchLayoutSnapshot(
            workspaceID: workspaceID,
            showLeftFleetNavigator: showLeftNavigator,
            showRightInspector: showRightInspector,
            showBottomDrawer: showBottomDrawer,
            activeBottomChannel: activeBottomChannel,
            splitMode: splitMode,
            primaryTabs: primaryTabs,
            activePrimaryTabID: activePrimaryTabID,
            secondaryTabs: secondaryTabs,
            activeSecondaryTabID: activeSecondaryTabID,
            selectedVMID: selectedVMID,
            selectedSnapshotID: selectedSnapshotID,
            selectedPacketID: selectedPacketID
        )
    }
}

// MARK: - Docking Tab Strip Bar View

public struct DockingTabStripBar: View {
    @ObservedObject private var localizer = AgentVMLocalizer.shared
    public let tabs: [WorkbenchTabDescriptor]
    public let activeTabID: UUID?
    public let isSecondaryPane: Bool
    public let splitMode: WorkbenchSplitMode
    public let onSelect: (UUID) -> Void
    public let onClose: (UUID) -> Void
    public let onSplitRight: () -> Void
    public let onCollapseSplit: () -> Void

    public init(
        tabs: [WorkbenchTabDescriptor],
        activeTabID: UUID?,
        isSecondaryPane: Bool = false,
        splitMode: WorkbenchSplitMode = .singlePane,
        onSelect: @escaping (UUID) -> Void,
        onClose: @escaping (UUID) -> Void,
        onSplitRight: @escaping () -> Void,
        onCollapseSplit: @escaping () -> Void
    ) {
        self.tabs = tabs
        self.activeTabID = activeTabID
        self.isSecondaryPane = isSecondaryPane
        self.splitMode = splitMode
        self.onSelect = onSelect
        self.onClose = onClose
        self.onSplitRight = onSplitRight
        self.onCollapseSplit = onCollapseSplit
    }

    public var body: some View {
        HStack(spacing: 0) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 2) {
                    ForEach(tabs) { tab in
                        let isSelected = tab.id == activeTabID
                        TabItemButton(
                            tab: tab,
                            displayTitle: resolvedTabTitle(tab),
                            isSelected: isSelected,
                            canClose: !tab.isPinned && (isSecondaryPane || tabs.count > 1),
                            onSelect: { onSelect(tab.id) },
                            onClose: { onClose(tab.id) }
                        )
                    }
                }
                .padding(.horizontal, 6)
                .padding(.vertical, 4)
            }

            Spacer(minLength: 6)

            HStack(spacing: 4) {
                if splitMode == .singlePane && !isSecondaryPane {
                    Button(action: onSplitRight) {
                        Label(localizer.L("Split View", "分屏视图"), systemImage: "rectangle.split.2x1")
                    }
                    .buttonStyle(RackActionButtonStyle(prominence: .subtleGhost, compact: true))
                } else if isSecondaryPane {
                    Button(action: onCollapseSplit) {
                        Label(localizer.L("Unsplit", "取消分屏"), systemImage: "rectangle")
                    }
                    .buttonStyle(RackActionButtonStyle(prominence: .subtleGhost, compact: true))
                }
            }
            .padding(.trailing, 8)
        }
        .frame(height: 36)
        .background(RackTheme.bladeRecessed)
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(RackTheme.hairline)
                .frame(height: 1)
        }
    }

    private func resolvedTabTitle(_ tab: WorkbenchTabDescriptor) -> String {
        let standardTitles: Set<String> = [
            tab.kind.defaultTitle,
            "Lineage DAG", "Wiretap", "Console", "Firewall", "Storage & ISO", "Plugins", "Fleet Matrix", "Audit Ledger",
            "血缘拓扑", "二层抓包", "终端控制台", "防火墙策略", "存储与镜像", "JS 插件", "机架矩阵", "审计账本"
        ]
        if standardTitles.contains(tab.title) {
            return tab.kind.localizedCompactTitle
        }
        return tab.title
    }

    private struct TabItemButton: View {
        let tab: WorkbenchTabDescriptor
        let displayTitle: String
        let isSelected: Bool
        let canClose: Bool
        let onSelect: () -> Void
        let onClose: () -> Void
        @State private var isHovered = false

        var body: some View {
            HStack(spacing: 6) {
                Image(systemName: tab.kind.sfSymbolName)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(isSelected ? RackTheme.amberAccent : RackTheme.inkMuted)

                Text(displayTitle)
                    .font(RackTheme.labelFont)
                    .foregroundStyle(isSelected ? RackTheme.inkPrimary : RackTheme.inkSecondary)
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)

                if tab.hasUnsavedChanges {
                    Circle()
                        .fill(RackTheme.amberAccent)
                        .frame(width: 6, height: 6)
                } else if tab.isPinned {
                    Image(systemName: "pin.fill")
                        .font(.system(size: 8.5))
                        .foregroundStyle(RackTheme.inkMuted)
                } else if canClose && (isHovered || isSelected) {
                    Button(action: onClose) {
                        Image(systemName: "xmark")
                            .font(.system(size: 9, weight: .bold))
                            .foregroundStyle(RackTheme.inkMuted)
                            .frame(width: 14, height: 14)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(
                RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                    .fill(isSelected ? RackTheme.moduleSurface : (isHovered ? RackTheme.moduleSurface.opacity(0.45) : Color.clear))
            )
            .overlay(
                RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                    .strokeBorder(isSelected ? RackTheme.hairlineStrong : Color.clear, lineWidth: 1)
            )
            .overlay(alignment: .top) {
                if isSelected {
                    RoundedRectangle(cornerRadius: 1)
                        .fill(RackTheme.amberAccent)
                        .frame(height: 2)
                        .padding(.horizontal, 8)
                }
            }
            .contentShape(Rectangle())
            .onTapGesture(perform: onSelect)
            .onHover { isHovered = $0 }
        }
    }
}
