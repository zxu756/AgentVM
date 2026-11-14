import AgentVMHypervisor
import AgentVMModels
import AgentVMStudioViews
import AgentVMWorkbenchShell
import AppKit
import Foundation
import SwiftUI
import Testing

@Suite("M0 Studio Views Default Empty State, Explicit Demo Mode & M5 Notice", .timeLimit(.minutes(1)))
struct StudioViewsHonestyTests {
    private func makeTempDirectory(prefix: String) throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    @Test("GUI default bootstrap without --demo opens with 0 VMs, 0 packets, 0 alerts, em-dash unmeasured metrics, and zero <20ms palette claims")
    @MainActor
    func defaultBootstrapOpensCleanEmptyStateWithoutDemoSeeding() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-gui-empty")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let bundleURL = tempDir.appendingPathComponent("CleanStartup.agentvm", isDirectory: true)
        let viewModel = AgentVMStudioViewModel(bundleURL: bundleURL, isDemoMode: false)
        await viewModel.bootstrapWorkspace()

        #expect(viewModel.isDemoMode == false)
        #expect(viewModel.vms.isEmpty)
        #expect(viewModel.snapshots.isEmpty)
        #expect(viewModel.allPackets.isEmpty)
        #expect(viewModel.filteredPackets.isEmpty)
        #expect(viewModel.diagnostics.isEmpty)
        #expect(viewModel.manifest.isDemonstrationWorkspace == false)
        #expect(viewModel.scratchpadOutputJSON.isEmpty)
        #expect(viewModel.lastForkLatencyMs == nil)
        #expect(viewModel.fleetCoWSpaceSavedPercent == nil)
        #expect(viewModel.hasLiveConnectedTraffic == false)

        // Command palette actions must not advertise unverified "< 20 ms" / "20ms 内" claims in EN or ZH
        let previousLang = AgentVMLocalizer.shared.language
        defer { AgentVMLocalizer.shared.setLanguage(previousLang, persist: false) }

        AgentVMLocalizer.shared.setLanguage(.en, persist: false)
        let enActions = CommandPaletteController.defaultBuiltInActions()
        for item in enActions {
            #expect(!item.subtitle.contains("20 ms"))
            #expect(!item.subtitle.contains("20ms"))
        }

        AgentVMLocalizer.shared.setLanguage(.zhHans, persist: false)
        let zhActions = CommandPaletteController.defaultBuiltInActions()
        for item in zhActions {
            #expect(!item.subtitle.contains("20ms"))
            #expect(!item.subtitle.contains("20 毫秒"))
        }
    }

    @Test("Explicit Load Demo, M5 live-traffic notice bilingual parity, em-dash telemetry, and offscreen SwiftUI rasterization")
    @MainActor
    func explicitLoadDemoM5NoticeAndOffscreenRender() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-gui-demo")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        #expect(AgentVMStudioViewModel.extractDemoFlag(from: []) == false)
        #expect(AgentVMStudioViewModel.extractDemoFlag(from: ["--demo"]) == true)
        #expect(AgentVMStudioViewModel.extractDemoFlag(from: ["--", "--demo"]) == false)

        let bundleURL = tempDir.appendingPathComponent("ExplicitDemoCheck.agentvm", isDirectory: true)
        let coordinator = try AgentVMFleetCoordinator(
            bundleURL: bundleURL,
            executionBackend: .deterministicSimulation
        )
        let viewModel = AgentVMStudioViewModel(
            bundleURL: bundleURL,
            coordinator: coordinator,
            isDemoMode: false
        )
        await viewModel.bootstrapWorkspace()
        #expect(viewModel.vms.isEmpty)

        let previousLang = AgentVMLocalizer.shared.language
        defer { AgentVMLocalizer.shared.setLanguage(previousLang, persist: false) }

        AgentVMLocalizer.shared.setLanguage(.en, persist: false)
        #expect(viewModel.demoBadgeText == "[DEMO]")
        #expect(viewModel.liveTrafficStatusNotice == "Not connected to live traffic yet (scheduled for M5)")

        AgentVMLocalizer.shared.setLanguage(.zhHans, persist: false)
        #expect(viewModel.demoBadgeText == "[演示数据]")
        #expect(viewModel.liveTrafficStatusNotice == "尚未接入真实流量（排在 M5）")

        // Render empty-state window, wiretap M5 notice, and firewall M5 notice offscreen without crashing
        let hostMain = NSHostingView(
            rootView: AgentVMMainWindowView(viewModel: viewModel).frame(width: 1200, height: 760)
        )
        hostMain.frame = NSRect(x: 0, y: 0, width: 1200, height: 760)
        hostMain.layoutSubtreeIfNeeded()

        let hostWiretap = NSHostingView(
            rootView: WiresharkPacketWiretapView(viewModel: viewModel).frame(width: 1000, height: 640)
        )
        hostWiretap.frame = NSRect(x: 0, y: 0, width: 1000, height: 640)
        hostWiretap.layoutSubtreeIfNeeded()

        let hostFirewall = NSHostingView(
            rootView: FirewallPolicyStudioView(viewModel: viewModel).frame(width: 1000, height: 640)
        )
        hostFirewall.frame = NSRect(x: 0, y: 0, width: 1000, height: 640)
        hostFirewall.layoutSubtreeIfNeeded()

        // Explicit Load Demo populates synthetic demonstration VMs and marks workspace as demo
        try await viewModel.loadDemonstrationFleetAsync()
        #expect(viewModel.isDemoMode == true)
        #expect(viewModel.manifest.isDemonstrationWorkspace == true)
        #expect(viewModel.vms.count == 3)
        #expect(viewModel.allPackets.count >= 4)
        for vm in viewModel.vms {
            #expect(vm.telemetry.hasLiveGuestTelemetry == false)
            #expect(vm.telemetry.formattedCPUUsage == "—")
            #expect(vm.telemetry.formattedMemoryResident == "—")
            #expect(vm.telemetry.formattedBalloonReclaimed == "—")
            if vm.telemetry.state != .stopped {
                _ = try? await coordinator.haltVM(vm.id)
            }
        }
    }
}
