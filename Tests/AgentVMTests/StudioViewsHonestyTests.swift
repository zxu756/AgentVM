import AgentVMHypervisor
import AgentVMModels
import AgentVMNetSwitch
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

        // Windowless replacement for the old acceptance Row 8 (which launched the real GUI process):
        // build the default ViewModel exactly as the app does without `--demo`, never create a window,
        // and assert both the in-memory lists and the persisted workspace are empty.
        let bundleURL = tempDir.appendingPathComponent("CleanStartup.agentvm", isDirectory: true)
        let coordinator = try AgentVMFleetCoordinator(bundleURL: bundleURL)
        #expect(await coordinator.currentExecutionBackend() == .strictHardwareVZ)
        let viewModel = AgentVMStudioViewModel(bundleURL: bundleURL, coordinator: coordinator, isDemoMode: false)
        await viewModel.bootstrapWorkspace()

        // Persisted state after a default launch: 0 VMs, 0 snapshots, 0 diagnostics (alerts), 0 exec records, non-demo manifest.
        #expect(try await coordinator.store.listVMs().isEmpty)
        #expect(try await coordinator.store.listSnapshots().isEmpty)
        #expect(try await coordinator.store.listDiagnostics(limit: 50).isEmpty)
        #expect(try await coordinator.store.listExecResults(limit: 50).isEmpty)
        #expect(try await coordinator.store.loadManifest().isDemonstrationWorkspace == false)
        #expect(await coordinator.l2Switch.recentPackets(limit: 50).isEmpty)

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

    // MARK: - M0 Rework: simulated state, status bar, Probe frames

    @Test("A workspace holding simulator-written state opens with SIMULATED badges and 0 running VMs on the default backend")
    @MainActor
    func defaultWindowMarksSimulatedStateAndDoesNotCountItAsRunning() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-gui-simstate")
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let bundleURL = tempDir.appendingPathComponent("SimState.agentvm", isDirectory: true)

        // What `agentvm --backend simulation up a` leaves behind.
        let simulator = try AgentVMFleetCoordinator(bundleURL: bundleURL, executionBackend: .deterministicSimulation)
        let vm = try await simulator.createSandboxVM(name: "a", diskVirtualBytes: 16 * 1024 * 1024).vmRecord
        _ = try await simulator.bootVM(vm.id)

        // The window a user opens afterwards, without --demo.
        let coordinator = try AgentVMFleetCoordinator(bundleURL: bundleURL)
        let viewModel = AgentVMStudioViewModel(bundleURL: bundleURL, coordinator: coordinator, isDemoMode: false)
        await viewModel.bootstrapWorkspace()

        #expect(viewModel.isDemoMode == false)
        #expect(viewModel.isSimulationBackendActive == false)
        let shown = try #require(viewModel.vms.first)
        #expect(shown.telemetry.state == .running)
        #expect(shown.telemetry.simulated == true)
        #expect(viewModel.runningVMCount == 0, "a simulated running VM is counted as a live one")

        let previousLang = AgentVMLocalizer.shared.language
        defer { AgentVMLocalizer.shared.setLanguage(previousLang, persist: false) }
        AgentVMLocalizer.shared.setLanguage(.en, persist: false)
        #expect(shown.telemetry.localizedStateBadge == "SIMULATED · Running")
        AgentVMLocalizer.shared.setLanguage(.zhHans, persist: false)
        #expect(shown.telemetry.localizedStateBadge.contains("SIMULATED"))
        #expect(shown.telemetry.localizedStateBadge.contains("运行中"))

        // Plain states keep their plain badge.
        AgentVMLocalizer.shared.setLanguage(.en, persist: false)
        #expect(VMLiveTelemetry(vmID: VMID("vm-x"), state: .running).localizedStateBadge == "Running")
        #expect(VMLiveTelemetry(vmID: VMID("vm-x"), state: .stopped, simulated: true).localizedStateBadge == "Stopped")

        _ = try? await simulator.haltVM(vm.id)
    }

    @Test("Status bar says SIMULATED for a demonstration fleet and never says plain Apple VZ without the entitlement")
    @MainActor
    func statusBarHypervisorTextFollowsBackendAndEntitlement() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-gui-statusbar")
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let bundleURL = tempDir.appendingPathComponent("StatusBar.agentvm", isDirectory: true)

        let previousLang = AgentVMLocalizer.shared.language
        defer { AgentVMLocalizer.shared.setLanguage(previousLang, persist: false) }

        // Default launch: hardware backend.
        let coordinator = try AgentVMFleetCoordinator(bundleURL: bundleURL)
        let viewModel = AgentVMStudioViewModel(bundleURL: bundleURL, coordinator: coordinator, isDemoMode: false)
        await viewModel.bootstrapWorkspace()
        AgentVMLocalizer.shared.setLanguage(.en, persist: false)
        #expect(!viewModel.hypervisorStatusText.contains("SIMULATED"))
        let entitled = HostHypervisorProbe.currentProcessHasBooleanEntitlement(HostHypervisorProbe.virtualizationEntitlementKey)
        if entitled {
            #expect(viewModel.hypervisorStatusText.hasPrefix("Hypervisor: Apple VZ ("))
            #expect(viewModel.isHypervisorReadyForRealGuests == true)
        } else {
            #expect(viewModel.hypervisorStatusText.contains("no virtualization entitlement"), "status bar: \(viewModel.hypervisorStatusText)")
            #expect(viewModel.isHypervisorReadyForRealGuests == false)
            AgentVMLocalizer.shared.setLanguage(.zhHans, persist: false)
            #expect(viewModel.hypervisorStatusText.contains("没有虚拟化权限"))
        }

        // Load Demo: the fleet runs on the simulator, the coordinator is switched to it, and the bar says so.
        try await viewModel.loadDemonstrationFleetAsync()
        #expect(await coordinator.currentExecutionBackend() == .deterministicSimulation)
        #expect(viewModel.isSimulationBackendActive == true)
        #expect(viewModel.isHypervisorReadyForRealGuests == false)
        AgentVMLocalizer.shared.setLanguage(.en, persist: false)
        #expect(viewModel.hypervisorStatusText.contains("SIMULATED"))
        #expect(!viewModel.hypervisorStatusText.contains("Apple VZ"))
        AgentVMLocalizer.shared.setLanguage(.zhHans, persist: false)
        #expect(viewModel.hypervisorStatusText.contains("SIMULATED"))
        #expect(!viewModel.hypervisorStatusText.contains("Apple VZ"))

        // Every demonstration VM that is not stopped carries the simulated flag.
        for vm in viewModel.vms where vm.telemetry.state != .stopped {
            #expect(vm.telemetry.simulated == true)
            #expect(vm.telemetry.localizedStateBadge.contains("SIMULATED"))
        }
        // A capture exported from this window is labelled at file level.
        #expect(viewModel.captureFileOriginComment(for: viewModel.allPackets)?.contains("SIMULATED") == true)

        for vm in viewModel.vms where vm.telemetry.state != .stopped {
            _ = try? await coordinator.haltVM(vm.id)
        }
    }

    @Test("A frame injected from the Wiretap Probe menu outside demo mode is labelled SYNTHETIC PROBE in the capture table and in exports")
    @MainActor
    func probeFramesAreLabelledSyntheticOutsideDemoMode() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-gui-probe")
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let bundleURL = tempDir.appendingPathComponent("Probe.agentvm", isDirectory: true)

        let coordinator = try AgentVMFleetCoordinator(bundleURL: bundleURL)
        let vm = try await coordinator.createSandboxVM(name: "probe-target", diskVirtualBytes: 16 * 1024 * 1024).vmRecord
        let viewModel = AgentVMStudioViewModel(bundleURL: bundleURL, coordinator: coordinator, isDemoMode: false)
        await viewModel.bootstrapWorkspace()
        #expect(viewModel.isDemoMode == false)
        #expect(viewModel.allPackets.isEmpty)
        #expect(viewModel.captureFileOriginComment(for: []) == nil)

        // The same call the Probe menu action makes after crafting its frame.
        let crafter = PacketFrameCrafter()
        let nic = try #require(vm.spec.networkInterfaces.first)
        let srcMAC = try #require(MACAddress(parsing: nic.macAddress))
        let srcIP = try #require(IPv4Address(parsing: nic.ipv4Address))
        let frame = crafter.buildTCPFrame(
            srcMAC: srcMAC,
            dstMAC: .defaultGateway,
            srcIP: srcIP,
            dstIP: IPv4Address(a: 140, b: 82, c: 121, d: 6),
            srcPort: 54910,
            dstPort: 443,
            seq: 8192,
            ack: 1,
            flags: [.psh, .ack],
            payload: crafter.buildTLSClientHelloPayload(serverName: "api.github.com")
        )
        let captured = try await viewModel.injectLabelledProbeFrame(frame, vmID: vm.id)
        #expect(captured.infoSummary.hasPrefix("[SYNTHETIC PROBE] "))

        await viewModel.refreshAllState()
        #expect(viewModel.allPackets.count == 1)
        #expect(viewModel.allPackets.allSatisfy { $0.infoSummary.hasPrefix("[SYNTHETIC PROBE] ") })

        // Text surfaces that print the summary show the label, and a capture exported from the window says so too.
        let ringSummaries = await coordinator.l2Switch.recentPackets(limit: 10).map(\.infoSummary)
        #expect(ringSummaries.allSatisfy { $0.contains("SYNTHETIC PROBE") })
        let comment = try #require(viewModel.captureFileOriginComment(for: viewModel.allPackets))
        #expect(comment.contains("SYNTHETIC PROBE"))
        let exported = await coordinator.l2Switch.exportPCAPNGData(sectionComment: comment)
        let report = try PCAPNGCodec().inspectCapture(data: exported)
        #expect(report.enhancedPacketBlockCount == 1)
        #expect(report.sections.first?.comment?.contains("SYNTHETIC PROBE") == true)

        // A frame that really entered through the guest path keeps a plain summary.
        let plain = try await coordinator.processOutboundGuestFrame(vmID: vm.id, rawFrame: frame)
        #expect(!plain.infoSummary.contains("SYNTHETIC PROBE"))
    }
}
