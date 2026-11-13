import AgentVMHypervisor
import AgentVMModels
import AgentVMNetSwitch
import AgentVMPluginHost
import AgentVMStore
import Foundation

// MARK: - Hallmark-Audited Standalone HTML Security & Fleet Telemetry Exporter

public struct HtmlFleetReportExporter: Sendable {
    public init() {}

    public func renderStandaloneHTML(coordinator: AgentVMFleetCoordinator) async throws -> String {
        let manifest = try await coordinator.store.loadManifest()
        let vms = try await coordinator.store.listVMs()
        let snapshots = try await coordinator.store.listSnapshots()
        let packets = await coordinator.l2Switch.recentPackets(limit: 80)
        let policy = await coordinator.l2Switch.firewall.currentPolicy()
        let plugins = await coordinator.pluginEngine.listPluginStatuses()
        let caps = await coordinator.hostCapabilities()

        let activeCount = vms.filter { $0.telemetry.state == .running }.count
        let totalDirty = vms.reduce(UInt64(0)) { $0 + $1.telemetry.cowDirtyBytes }
        let droppedPkts = packets.filter { !$0.verdict.isPermitted }.count

        var vmRows = ""
        for vm in vms {
            let ip = escapeHTML(vm.spec.networkInterfaces.first?.ipv4Address ?? "-")
            let dirty = escapeHTML(ByteMetricsFormatter.formatBytes(vm.telemetry.cowDirtyBytes))
            let stateBadgeClass = vm.telemetry.state == .running ? "pill-allow" : "pill-amber"
            let mountsText = vm.spec.virtioFSMounts.map { ByteMetricsFormatter.scrubHomePath($0.hostDirectoryPath) }.joined(separator: ", ")
            vmRows += """
            <tr>
              <td class="mono">\(escapeHTML(ByteMetricsFormatter.scrubHomePath(vm.spec.name)))</td>
              <td>@\(escapeHTML(vm.spec.agentOwnerTag))</td>
              <td><span class="pill \(stateBadgeClass)">\(escapeHTML(vm.telemetry.state.badgeLabel))</span></td>
              <td class="mono">\(vm.spec.compute.vcpuCount) vCPU / \(vm.spec.compute.memoryMB) MB</td>
              <td class="mono">\(ip)</td>
              <td class="mono">\(dirty)\(mountsText.isEmpty ? "" : " (\(escapeHTML(mountsText)))")</td>
            </tr>
            """
        }

        var packetRows = ""
        for pkt in packets.prefix(24) {
            let vClass = pkt.verdict.isPermitted ? "pill-allow" : "pill-drop"
            let src = escapeHTML(pkt.sourceIP ?? pkt.sourceMAC)
            let dst = escapeHTML(pkt.destinationIP ?? pkt.destinationMAC)
            packetRows += """
            <tr>
              <td class="mono">#\(pkt.sequenceNumber)</td>
              <td class="mono">\(escapeHTML(pkt.highestProtocol.rawValue))</td>
              <td class="mono">\(src)</td>
              <td class="mono">\(dst)</td>
              <td><span class="pill \(vClass)">\(escapeHTML(pkt.verdict.rawValue))</span></td>
              <td>\(escapeHTML(ByteMetricsFormatter.scrubHomePath(pkt.infoSummary)))</td>
            </tr>
            """
        }

        var pluginRows = ""
        for plugin in plugins {
            let pClass = plugin.isEnabled ? "pill-allow" : "pill-amber"
            pluginRows += """
            <tr>
              <td class="mono">\(escapeHTML(plugin.id.rawValue))</td>
              <td>\(escapeHTML(plugin.manifest.name))</td>
              <td><span class="pill \(pClass)">\(plugin.isEnabled ? "Enabled" : "Disabled")</span></td>
              <td class="mono">\(plugin.invocationCount)</td>
              <td class="mono">\(plugin.blockedActionsCount)</td>
            </tr>
            """
        }

        let cleanTitle = escapeHTML(ByteMetricsFormatter.scrubHomePath(manifest.title))
        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta name="description" content="AgentVM microVM fleet security, Copy-on-Write storage lineage, and Layer-2 DPI firewall audit report.">
        <title>\(cleanTitle): AgentVM Security Audit</title>
        <style>
        /* Hallmark · v2.0.0 · scope: app · genre: modern-minimal · posture: restrained · shape: app screen · surface: absolute */
        /* hallmark · rack-graphite dark telemetry surface with tabular monospace counters */
        :root {
          --bg-chassis: #141517;
          --bg-surface: #1d2026;
          --bg-elevated: #252932;
          --border-line: #323844;
          --ink-primary: #edeff2;
          --ink-secondary: #a0a8b8;
          --ink-muted: #767f91;
          --signal-amber: #d97724;
          --signal-amber-soft: rgba(217, 119, 36, 0.16);
          --signal-green: #2a9d6f;
          --signal-green-soft: rgba(42, 157, 111, 0.16);
          --signal-crimson: #d64545;
          --signal-crimson-soft: rgba(214, 69, 69, 0.16);
          --font-sans: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", sans-serif;
          --font-mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
        }
        *, *::before, *::after { box-sizing: border-box; }
        html, body {
          margin: 0;
          padding: 0;
          overflow-x: clip;
          background: var(--bg-chassis);
          color: var(--ink-primary);
          font-family: var(--font-sans);
          font-size: 16px;
          line-height: 1.5;
        }
        .shell {
          max-width: 1180px;
          margin: 0 auto;
          padding: 2.25rem 1.5rem 3.5rem;
        }
        header.mast {
          display: flex;
          flex-wrap: wrap;
          justify-content: space-between;
          align-items: flex-end;
          gap: 1rem;
          padding-bottom: 1.25rem;
          border-bottom: 1px solid var(--border-line);
          margin-bottom: 1.75rem;
        }
        h1 {
          margin: 0;
          font-size: 1.75rem;
          font-weight: 600;
          letter-spacing: -0.02em;
          line-height: 1.15;
          color: var(--ink-primary);
          text-wrap: balance;
          overflow-wrap: break-word;
          min-width: 0;
        }
        h2 {
          margin: 2rem 0 0.75rem;
          font-size: 1.15rem;
          font-weight: 600;
          color: var(--ink-primary);
          text-wrap: balance;
        }
        p.lead {
          margin: 0.35rem 0 0;
          font-size: 0.95rem;
          color: var(--ink-secondary);
        }
        .metrics {
          display: grid;
          grid-template-columns: repeat(4, minmax(0, 1fr));
          gap: 1rem;
          margin-bottom: 2rem;
        }
        .metric-box {
          background: var(--bg-surface);
          border: 1px solid var(--border-line);
          border-radius: 8px;
          padding: 1rem 1.1rem;
        }
        .metric-label {
          font-size: 0.85rem;
          color: var(--ink-secondary);
          margin-bottom: 0.35rem;
        }
        .metric-value {
          font-family: var(--font-mono);
          font-variant-numeric: tabular-nums;
          font-size: 1.45rem;
          font-weight: 600;
          color: var(--ink-primary);
        }
        .table-wrap {
          background: var(--bg-surface);
          border: 1px solid var(--border-line);
          border-radius: 8px;
          overflow-x: auto;
        }
        table {
          width: 100%;
          border-collapse: collapse;
          text-align: left;
          font-size: 0.9rem;
        }
        th {
          font-weight: 500;
          color: var(--ink-secondary);
          background: var(--bg-elevated);
          padding: 0.65rem 0.9rem;
          border-bottom: 1px solid var(--border-line);
        }
        td {
          padding: 0.6rem 0.9rem;
          border-bottom: 1px solid var(--border-line);
          color: var(--ink-primary);
          vertical-align: middle;
        }
        tr:last-child td { border-bottom: none; }
        .mono {
          font-family: var(--font-mono);
          font-variant-numeric: tabular-nums;
          font-size: 0.84rem;
        }
        .pill {
          display: inline-block;
          padding: 0.15rem 0.55rem;
          border-radius: 4px;
          font-family: var(--font-mono);
          font-size: 0.78rem;
          white-space: nowrap;
        }
        .pill-allow {
          background: var(--signal-green-soft);
          color: var(--signal-green);
        }
        .pill-amber {
          background: var(--signal-amber-soft);
          color: var(--signal-amber);
        }
        .pill-drop {
          background: var(--signal-crimson-soft);
          color: var(--signal-crimson);
        }
        .filter-btn {
          appearance: none;
          background: var(--bg-elevated);
          color: var(--ink-primary);
          border: 1px solid var(--border-line);
          border-radius: 6px;
          padding: 0.45rem 0.85rem;
          font-family: var(--font-sans);
          font-size: 0.88rem;
          cursor: pointer;
          white-space: nowrap;
          transition: transform 140ms ease-out, opacity 140ms ease-out;
        }
        .filter-btn:hover { opacity: 0.92; }
        .filter-btn:active { transform: scale(0.97); }
        .filter-btn:focus-visible {
          outline: 2px solid var(--signal-amber);
          outline-offset: 2px;
        }
        .filter-btn:disabled { opacity: 0.45; cursor: not-allowed; }
        footer {
          margin-top: 2.5rem;
          padding-top: 1rem;
          border-top: 1px solid var(--border-line);
          font-size: 0.85rem;
          color: var(--ink-muted);
          display: flex;
          justify-content: space-between;
          flex-wrap: wrap;
          gap: 0.75rem;
        }
        @media (max-width: 820px) {
          .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        }
        @media (prefers-reduced-motion: reduce) {
          .filter-btn { transition: opacity 120ms ease; transform: none; }
        }
        </style>
        </head>
        <body>
        <main class="shell">
          <header class="mast">
            <div>
              <h1>\(cleanTitle)</h1>
              <p class="lead">Apple Virtualization (\(escapeHTML(caps.architecture))) Fleet, APFS Copy-on-Write Lineage &amp; Layer-2 DPI Firewall Audit</p>
            </div>
            <button class="filter-btn" type="button" onclick="window.print()">Print Compliance Snapshot</button>
          </header>

          <section class="metrics" aria-label="Fleet telemetry summary">
            <div class="metric-box">
              <div class="metric-label">Active Sandbox Blades</div>
              <div class="metric-value">\(activeCount) / \(vms.count)</div>
            </div>
            <div class="metric-box">
              <div class="metric-label">CoW Snapshot Nodes</div>
              <div class="metric-value">\(snapshots.count)</div>
            </div>
            <div class="metric-box">
              <div class="metric-label">Unique Dirty Disk Delta</div>
              <div class="metric-value">\(escapeHTML(ByteMetricsFormatter.formatBytes(totalDirty)))</div>
            </div>
            <div class="metric-box">
              <div class="metric-label">DPI Wiretap Drops</div>
              <div class="metric-value">\(droppedPkts) / \(packets.count)</div>
            </div>
          </section>

          <h2>MicroVM Sandbox Blades</h2>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Blade Name</th>
                  <th>Owner</th>
                  <th>Lifecycle</th>
                  <th>Compute</th>
                  <th>Switch IPv4</th>
                  <th>CoW Delta</th>
                </tr>
              </thead>
              <tbody>
                \(vmRows)
              </tbody>
            </table>
          </div>

          <h2>Layer-2 Switch Wiretap Ledger (\(escapeHTML(policy.name)))</h2>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Seq</th>
                  <th>Proto</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Verdict</th>
                  <th>Dissected Summary</th>
                </tr>
              </thead>
              <tbody>
                \(packetRows)
              </tbody>
            </table>
          </div>

          <h2>JavaScriptCore Extension Host Status</h2>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Plugin ID</th>
                  <th>Extension</th>
                  <th>State</th>
                  <th>Invocations</th>
                  <th>Interceptions</th>
                </tr>
              </thead>
              <tbody>
                \(pluginRows)
              </tbody>
            </table>
          </div>

          <footer>
            <span>Generated by AgentVM v\(SemanticVersion.current.description)</span>
            <span class="mono">Host macOS \(escapeHTML(caps.macOSVersion)) (\(caps.physicalCores) cores, \(escapeHTML(caps.hostMemoryGBFormatted)))</span>
          </footer>
        </main>
        </body>
        </html>
        """
    }

    private func escapeHTML(_ text: String) -> String {
        text.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
    }
}
