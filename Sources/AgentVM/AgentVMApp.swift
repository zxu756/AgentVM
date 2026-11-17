import AgentVMCLIAndMCP
import AgentVMHypervisor
import AgentVMModels
import AgentVMStudioViews
import AgentVMWorkbenchShell
import AppKit
import Darwin
import Foundation
import SwiftUI

// MARK: - Unified Executable Entry Point (GUI Workbench + Headless CLI + Stdio MCP + Retina Screenshot Exporter)

@main
enum AgentVMEntryPoint {
    static func main() async {
        let rawArgs = Array(CommandLine.arguments.dropFirst())
        if let cliLanguage = AppLanguage.extractCLILanguage(from: rawArgs) {
            await MainActor.run {
                AgentVMLocalizer.shared.setLanguage(cliLanguage, persist: false)
            }
        }

        // 1. Deterministic 2x Retina Offscreen Screenshot Exporter (`--export-screenshots <output-dir> [--lang zh|en]`)
        if let exportDir = extractScreenshotExportDirectory(from: rawArgs) {
            do {
                try await exportAllRetinaScreenshots(to: exportDir)
                Darwin.exit(0)
            } catch {
                FileHandle.standardError.write(
                    Data("Screenshot export failed: \(error.localizedDescription)\n".utf8)
                )
                Darwin.exit(1)
            }
        }

        // 2. JSON-RPC 2.0 Model Context Protocol Server (`agentvm mcp`)
        if let mcpInvocation = extractMCPServerInvocation(from: rawArgs) {
            do {
                let coordinator = try AgentVMFleetCoordinator(
                    bundleURL: mcpInvocation.bundleURL,
                    executionBackend: mcpInvocation.backend
                )
                let server = AgentVMMCPServer(coordinator: coordinator)
                await server.runStdioLoop()
                Darwin.exit(0)
            } catch {
                FileHandle.standardError.write(
                    Data("AgentVM MCP server error: \(error.localizedDescription)\n".utf8)
                )
                Darwin.exit(1)
            }
        }

        // 3. Headless Multi-Subcommand CLI (`agentvm <subcommand> ...`)
        if isCLIInvocation(rawArgs) {
            let runner = AgentVMCLIRunner()
            let forwarder = CLIStandardStreamForwarder()
            var signalController: OneShotRunSignalController?
            var signalSources: [any DispatchSourceSignal] = []

            let subcmd = extractCLISubcommand(rawArgs)
            if subcmd == "run" {
                let controller = OneShotRunSignalController()
                signalController = controller
                signalSources = controller.installPOSIXSignalSources()
            }

            let outcome = await runner.execute(
                arguments: rawArgs,
                daemonRunProcessMode: subcmd == "daemon",
                signalController: signalController,
                liveStderrHandler: { forwarder.writeProgress($0) },
                liveStdoutDataHandler: { forwarder.writeStdoutChunk($0) },
                liveStderrDataHandler: { forwarder.writeStderrChunk($0) }
            )
            outcome.writeProcessOutput(forwarder: forwarder)
            withExtendedLifetime(signalSources) {}
            Darwin.exit(outcome.exitCode)
        }

        // 4. Native macOS SwiftUI Industrial Workbench GUI
        await MainActor.run {
            AgentVMStudioWorkbenchApp.main()
        }
    }

    // MARK: - Argument Parsing Helpers

    private static func extractScreenshotExportDirectory(from args: [String]) -> URL? {
        for (idx, arg) in args.enumerated() {
            if arg == "--" {
                break
            }
            if arg == "--export-screenshots" {
                if idx + 1 < args.count {
                    return URL(fileURLWithPath: args[idx + 1], isDirectory: true)
                }
                return URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
            }
            if arg.hasPrefix("--export-screenshots=") {
                let path = String(arg.dropFirst("--export-screenshots=".count))
                return URL(fileURLWithPath: path, isDirectory: true)
            }
        }
        return nil
    }

    private static func extractMCPServerInvocation(
        from args: [String]
    ) -> (bundleURL: URL, backend: HypervisorExecutionBackend)? {
        let stripped = AppLanguage.strippingLanguageArguments(from: args)
        var resolvedURL = AgentVMCLIRunner.defaultWorkspaceBundleURL()
        var backend: HypervisorExecutionBackend = .strictHardwareVZ
        var idx = 0
        var sawMCP = false
        while idx < stripped.count {
            let token = stripped[idx]
            if token == "--" {
                return nil
            }
            if (token == "--workspace" || token == "-w"), idx + 1 < stripped.count {
                resolvedURL = URL(fileURLWithPath: stripped[idx + 1], isDirectory: true)
                idx += 2
            } else if token.hasPrefix("--workspace=") {
                let path = String(token.dropFirst("--workspace=".count))
                resolvedURL = URL(fileURLWithPath: path, isDirectory: true)
                idx += 1
            } else if token == "--backend", idx + 1 < stripped.count {
                let raw = stripped[idx + 1].lowercased()
                if raw == "simulation" {
                    backend = .deterministicSimulation
                } else if raw == "hardware" || raw == "vz" || raw == "default" {
                    backend = .strictHardwareVZ
                } else {
                    return nil
                }
                idx += 2
            } else if token.hasPrefix("--backend=") {
                let raw = String(token.dropFirst("--backend=".count)).lowercased()
                if raw == "simulation" {
                    backend = .deterministicSimulation
                } else if raw == "hardware" || raw == "vz" || raw == "default" {
                    backend = .strictHardwareVZ
                } else {
                    return nil
                }
                idx += 1
            } else if token == "mcp" {
                sawMCP = true
                idx += 1
            } else {
                return nil
            }
        }
        return sawMCP ? (resolvedURL, backend) : nil
    }

    private static func extractCLISubcommand(_ args: [String]) -> String? {
        let stripped = AppLanguage.strippingLanguageArguments(from: args)
        let filtered = stripped.filter { arg in
            !arg.hasPrefix("-psn_")
                && arg != "-NSDocumentRevisionsDebugMode"
                && arg != "YES"
                && arg != "NO"
        }
        var idx = 0
        while idx < filtered.count {
            let token = filtered[idx]
            if token == "--" {
                return nil
            }
            if (token == "--workspace" || token == "-w"), idx + 1 < filtered.count {
                idx += 2
            } else if token.hasPrefix("--workspace=") {
                idx += 1
            } else if token == "--demo" {
                idx += 1
            } else if token == "--backend", idx + 1 < filtered.count {
                idx += 2
            } else if token.hasPrefix("--backend=") {
                idx += 1
            } else {
                return token
            }
        }
        return nil
    }

    private static func isCLIInvocation(_ args: [String]) -> Bool {
        let stripped = AppLanguage.strippingLanguageArguments(from: args)
        guard !stripped.isEmpty else { return false }
        // Ignore macOS LaunchServices / Xcode runtime arguments when launching GUI
        let filtered = stripped.filter { arg in
            !arg.hasPrefix("-psn_")
                && arg != "-NSDocumentRevisionsDebugMode"
                && arg != "YES"
                && arg != "NO"
        }
        guard !filtered.isEmpty else { return false }

        var idx = 0
        while idx < filtered.count {
            let token = filtered[idx]
            if (token == "--workspace" || token == "-w"), idx + 1 < filtered.count {
                idx += 2
            } else if token.hasPrefix("--workspace=") {
                idx += 1
            } else if token == "--demo" {
                idx += 1
            } else if token == "--backend", idx + 1 < filtered.count {
                idx += 2
            } else if token.hasPrefix("--backend=") {
                idx += 1
            } else {
                if AgentVMCLIRunner.cliSubcommands.contains(token) {
                    return true
                }
                // Any explicit non-system flag/subcommand routes to CLI for helpful usage reporting
                return !token.hasPrefix("-NS")
            }
        }
        return false
    }

    // MARK: - Deterministic 2x Retina (`2720 x 1680` px) Offscreen Screenshot Renderer

    @MainActor
    private static func exportAllRetinaScreenshots(to outputDirectoryURL: URL) async throws {
        // Initialize AppKit windowserver backing without stealing focus or Dock icon
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        app.appearance = NSAppearance(named: .darkAqua)

        try FileManager.default.createDirectory(
            at: outputDirectoryURL,
            withIntermediateDirectories: true
        )

        let tempContainerURL = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("avm-export-\(UUID().uuidString)", isDirectory: true)
        let tempBundleURL = tempContainerURL
            .appendingPathComponent("SandboxFleet.agentvm", isDirectory: true)
        defer {
            try? FileManager.default.removeItem(at: tempContainerURL)
        }

        let coordinator = try AgentVMFleetCoordinator(
            bundleURL: tempBundleURL,
            executionBackend: .deterministicSimulation
        )
        let viewModel = AgentVMStudioViewModel(
            bundleURL: tempBundleURL,
            coordinator: coordinator,
            isDemoMode: true
        )

        // Hydrate 3 VMs, CoW branches, snapshots, L2 dissected packets, ext4 superblocks, ISO-9660 & 4 JS plugins
        let hydrated = try await viewModel.buildHydratedSnapshot()
        viewModel.hydrateSynchronously(from: hydrated)
        viewModel.manifest.title = L("Sandbox Fleet", "沙盒集群")
        viewModel.refreshLocalizedChrome()

        let logicalWidth: CGFloat = 1360
        let logicalHeight: CGFloat = 840
        let retinaScale: CGFloat = 2.0
        let pixelWidth = Int(logicalWidth * retinaScale)
        let pixelHeight = Int(logicalHeight * retinaScale)

        let offscreenWindow = NSWindow(
            contentRect: NSRect(x: -16_000, y: -16_000, width: logicalWidth, height: logicalHeight),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        offscreenWindow.isReleasedWhenClosed = false
        offscreenWindow.appearance = NSAppearance(named: .darkAqua)
        offscreenWindow.backgroundColor = NSColor(
            srgbRed: 0x14 / 255.0,
            green: 0x15 / 255.0,
            blue: 0x17 / 255.0,
            alpha: 1.0
        )
        offscreenWindow.hasShadow = false
        offscreenWindow.alphaValue = 0.01
        offscreenWindow.orderBack(nil)
        defer {
            offscreenWindow.orderOut(nil)
            offscreenWindow.close()
        }

        for scenario in StudioScreenshotScenario.allCases {
            viewModel.configureScreenshotScenario(scenario)

            let rootCanvas = AgentVMMainWindowView(viewModel: viewModel)
                .frame(width: logicalWidth, height: logicalHeight)
                .environment(\.colorScheme, .dark)

            let hostingView = NSHostingView(rootView: rootCanvas)
            hostingView.appearance = NSAppearance(named: .darkAqua)
            hostingView.frame = NSRect(x: 0, y: 0, width: logicalWidth, height: logicalHeight)
            offscreenWindow.contentView = hostingView

            // Yield main actor briefly so NSScrollViews, LazyVStacks, NSTextFields, and SwiftUI Canvas finish layout
            for _ in 0..<4 {
                hostingView.needsLayout = true
                hostingView.layoutSubtreeIfNeeded()
                hostingView.displayIfNeeded()
                try await Task.sleep(nanoseconds: 45_000_000)
            }
            hostingView.layoutSubtreeIfNeeded()
            hostingView.displayIfNeeded()

            let pngData: Data
            if let bitmapRep = NSBitmapImageRep(
                bitmapDataPlanes: nil,
                pixelsWide: pixelWidth,
                pixelsHigh: pixelHeight,
                bitsPerSample: 8,
                samplesPerPixel: 4,
                hasAlpha: true,
                isPlanar: false,
                colorSpaceName: .deviceRGB,
                bytesPerRow: pixelWidth * 4,
                bitsPerPixel: 32
            ) {
                bitmapRep.size = NSSize(width: logicalWidth, height: logicalHeight)
                hostingView.cacheDisplay(in: hostingView.bounds, to: bitmapRep)
                if let encoded = bitmapRep.representation(using: .png, properties: [:]) {
                    pngData = encoded
                } else {
                    throw NSError(
                        domain: "AgentVM.ScreenshotExporter",
                        code: 2,
                        userInfo: [NSLocalizedDescriptionKey: "Failed to encode 2x Retina PNG for \(scenario.rawValue)."]
                    )
                }
            } else {
                // Fallback to SwiftUI ImageRenderer if NSBitmapImageRep allocation fails
                let renderer = ImageRenderer(content: rootCanvas)
                renderer.proposedSize = ProposedViewSize(width: logicalWidth, height: logicalHeight)
                renderer.scale = retinaScale
                renderer.isOpaque = true
                guard let cgImage = renderer.cgImage else {
                    throw NSError(
                        domain: "AgentVM.ScreenshotExporter",
                        code: 1,
                        userInfo: [NSLocalizedDescriptionKey: "ImageRenderer returned nil CGImage for \(scenario.rawValue)."]
                    )
                }
                let fallbackRep = NSBitmapImageRep(cgImage: cgImage)
                fallbackRep.size = NSSize(width: logicalWidth, height: logicalHeight)
                guard let encoded = fallbackRep.representation(using: .png, properties: [:]) else {
                    throw NSError(
                        domain: "AgentVM.ScreenshotExporter",
                        code: 2,
                        userInfo: [NSLocalizedDescriptionKey: "Failed to encode fallback PNG for \(scenario.rawValue)."]
                    )
                }
                pngData = encoded
            }

            let filename = scenario.localizedFilename(for: AgentVMLocalizer.shared.language)
            let fileURL = outputDirectoryURL.appendingPathComponent(filename)
            try pngData.write(to: fileURL, options: [.atomic])
            FileHandle.standardOutput.write(
                Data("Exported \(fileURL.path) (\(pixelWidth)x\(pixelHeight) px)\n".utf8)
            )
        }
    }
}

// MARK: - SwiftUI macOS App Scene & Settings Window

struct AgentVMStudioWorkbenchApp: App {
    @StateObject private var viewModel = AgentVMStudioViewModel()

    var body: some Scene {
        WindowGroup("AgentVM Studio") {
            AgentVMMainWindowView(viewModel: viewModel)
                .frame(minWidth: 1180, minHeight: 740)
        }
        .defaultSize(width: 1380, height: 860)
        .windowStyle(.hiddenTitleBar)
        .commands {
            AgentVMCommands(viewModel: viewModel)
        }

        Settings {
            WorkbenchPreferencesView(
                preferences: $viewModel.preferences,
                onSave: { updated in
                    viewModel.saveWorkspacePreferences(updated)
                }
            )
        }
    }
}
