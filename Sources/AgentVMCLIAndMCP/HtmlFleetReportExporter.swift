import AgentVMHypervisor
import AgentVMModels
import AgentVMNetSwitch
import AgentVMPluginHost
import AgentVMStore
import Foundation

// MARK: - Hallmark-Audited Bilingual (`中文` / `EN`) Standalone HTML Security & Fleet Telemetry Exporter

public struct HtmlFleetReportExporter: Sendable {
    public init() {}

    public func renderStandaloneHTML(
        coordinator: AgentVMFleetCoordinator,
        isDemoOverride: Bool? = nil
    ) async throws -> String {
        let manifest = try await coordinator.store.loadManifest()
        let isDemo = isDemoOverride ?? manifest.isDemonstrationWorkspace
        // Records carry `telemetry.simulated` (see `AgentVMFleetCoordinator.listVMsForReporting`).
        let vms = try await coordinator.listVMsForReporting()
        let isSimulationBackend = await coordinator.currentExecutionBackend() == .deterministicSimulation
        let snapshots = try await coordinator.store.listSnapshots()
        let packets = await coordinator.l2Switch.recentPackets(limit: 80)
        let policy = await coordinator.l2Switch.firewall.currentPolicy()
        let plugins = await coordinator.pluginEngine.listPluginStatuses()
        let caps = await coordinator.hostCapabilities()

        // Only a `running` state that did not come from the simulator counts as an active blade.
        let activeCount = vms.filter { $0.telemetry.isRunningOutsideSimulation }.count
        let simulatedActiveCount = vms.filter { $0.telemetry.isSimulatedActiveState }.count
        let activeMetricText = simulatedActiveCount > 0
            ? "\(activeCount) / \(vms.count) (+\(simulatedActiveCount) SIMULATED)"
            : "\(activeCount) / \(vms.count)"
        let totalDirty = vms.reduce(UInt64(0)) { $0 + $1.telemetry.cowDirtyBytes }
        let droppedPkts = packets.filter { !$0.verdict.isPermitted }.count

        var vmRows = ""
        for vm in vms {
            let ip = escapeHTML(vm.spec.networkInterfaces.first?.ipv4Address ?? "-")
            let dirty = escapeHTML(ByteMetricsFormatter.formatBytes(vm.telemetry.cowDirtyBytes))
            let plainStateText = lifecycleBilingualLabels(vm.telemetry.state)
            let isSimulatedState = vm.telemetry.isSimulatedActiveState
            // A simulated state never gets the green "allow" pill and always names itself.
            let stateBadgeClass = (vm.telemetry.state == .running && !isSimulatedState) ? "pill-allow" : "pill-amber"
            let stateText: (en: String, zh: String) = isSimulatedState
                ? ("SIMULATED: \(plainStateText.en)", "SIMULATED 模拟: \(plainStateText.zh)")
                : plainStateText
            let mountsText = vm.spec.virtioFSMounts.map { ByteMetricsFormatter.scrubHomePath($0.hostDirectoryPath) }.joined(separator: ", ")
            vmRows += """
            <tr>
              <td class="mono">\(escapeHTML(ByteMetricsFormatter.scrubHomePath(vm.spec.name)))</td>
              <td>@\(escapeHTML(vm.spec.agentOwnerTag))</td>
              <td><span class="pill \(stateBadgeClass)" data-en="\(escapeHTML(stateText.en))" data-zh="\(escapeHTML(stateText.zh))">\(escapeHTML(stateText.en))</span></td>
              <td class="mono">\(vm.spec.compute.vcpuCount) vCPU / \(vm.spec.compute.memoryMB) MB</td>
              <td class="mono">\(ip)</td>
              <td class="mono">\(dirty)\(mountsText.isEmpty ? "" : " (\(escapeHTML(mountsText)))")</td>
            </tr>
            """
        }

        var packetRows = ""
        for pkt in packets.prefix(24) {
            let vClass = pkt.verdict.isPermitted ? "pill-allow" : "pill-drop"
            let verdictText = verdictBilingualLabels(pkt.verdict)
            let src = escapeHTML(pkt.sourceIP ?? pkt.sourceMAC)
            let dst = escapeHTML(pkt.destinationIP ?? pkt.destinationMAC)
            let safeSummary = sanitizeNoDashes(ByteMetricsFormatter.scrubHomePath(pkt.infoSummary))
            packetRows += """
            <tr>
              <td class="mono">#\(pkt.sequenceNumber)</td>
              <td class="mono">\(escapeHTML(pkt.highestProtocol.rawValue))</td>
              <td class="mono">\(src)</td>
              <td class="mono">\(dst)</td>
              <td><span class="pill \(vClass)" data-en="\(escapeHTML(verdictText.en))" data-zh="\(escapeHTML(verdictText.zh))">\(escapeHTML(verdictText.en))</span></td>
              <td>\(escapeHTML(safeSummary))</td>
            </tr>
            """
        }

        var pluginRows = ""
        for plugin in plugins {
            let pClass = plugin.isEnabled ? "pill-allow" : "pill-amber"
            let nameBilingual = pluginNameBilingualLabels(id: plugin.id.rawValue, fallback: plugin.manifest.name)
            let stateEn = plugin.isEnabled ? "Enabled" : "Disabled"
            let stateZh = plugin.isEnabled ? "已启用" : "已禁用"
            pluginRows += """
            <tr>
              <td class="mono">\(escapeHTML(plugin.id.rawValue))</td>
              <td data-en="\(escapeHTML(nameBilingual.en))" data-zh="\(escapeHTML(nameBilingual.zh))">\(escapeHTML(nameBilingual.en))</td>
              <td><span class="pill \(pClass)" data-en="\(stateEn)" data-zh="\(stateZh)">\(stateEn)</span></td>
              <td class="mono">\(plugin.invocationCount)</td>
              <td class="mono">\(plugin.blockedActionsCount)</td>
            </tr>
            """
        }

        let cleanTitle = escapeHTML(sanitizeNoDashes(ByteMetricsFormatter.scrubHomePath(manifest.title)))
        let displayTitleEn = isDemo ? "[DEMO] \(cleanTitle)" : cleanTitle
        let displayTitleZh = isDemo ? "[演示数据] \(cleanTitle)" : cleanTitle
        let demoBannerHTML: String = isDemo
            ? """
              <div class="demo-banner" role="note" data-en="[DEMO] Synthetic demonstration dataset: simulated microVMs, crafted Layer-2 frames, and sample audit metrics (not captured from live guest VMs)." data-zh="[演示数据] 合成演示数据集：模拟微虚拟机、构造的二层数据帧与示例审计指标（非真实客户机运行采集）。">[DEMO] Synthetic demonstration dataset: simulated microVMs, crafted Layer-2 frames, and sample audit metrics (not captured from live guest VMs).</div>
            """
            : ""
        let simulationBannerHTML: String
        if isSimulationBackend {
            simulationBannerHTML = """
              <div class="demo-banner" role="note" data-en="SIMULATED: this report was exported with --backend simulation. Lifecycle states, guest agent status and exec results in it come from the host-side simulator, not from real guest VMs." data-zh="SIMULATED 模拟: 本报告在 --backend simulation 下导出。其中的运行状态、客户机代理状态和命令结果来自主机侧模拟，不来自真实客户机。">SIMULATED: this report was exported with --backend simulation. Lifecycle states, guest agent status and exec results in it come from the host-side simulator, not from real guest VMs.</div>
            """
        } else if simulatedActiveCount > 0 {
            simulationBannerHTML = """
              <div class="demo-banner" role="note" data-en="SIMULATED: \(simulatedActiveCount) VM state(s) below were written by the simulation backend. No real guest is running behind them, and they are not counted as active." data-zh="SIMULATED 模拟: 下面有 \(simulatedActiveCount) 台虚拟机的状态是模拟后端写入的，背后没有真实客户机在运行，也不计入活跃数。">SIMULATED: \(simulatedActiveCount) VM state(s) below were written by the simulation backend. No real guest is running behind them, and they are not counted as active.</div>
            """
        } else {
            simulationBannerHTML = ""
        }
        let arch = escapeHTML(caps.architecture)
        let osVer = escapeHTML(caps.macOSVersion)
        let hostMem = escapeHTML(caps.hostMemoryGBFormatted)
        let policyNames = policyBilingualLabels(policy.name)
        let wiretapHeadingEn = "Layer-2 Switch Wiretap Ledger (\(escapeHTML(policyNames.en)))"
        let wiretapHeadingZh = "二层交换机抓包审计台账（\(escapeHTML(policyNames.zh))）"
        let leadEn = "Apple Virtualization (\(arch)) Fleet, APFS Copy-on-Write Lineage &amp; Layer-2 DPI Firewall Audit"
        let leadZh = "Apple Virtualization (\(arch)) 微虚拟机集群、APFS 写时复制血统与二层深度包检测防火墙审计"
        let genEn = "Generated by AgentVM v\(SemanticVersion.current.description)"
        let genZh = "由 AgentVM v\(SemanticVersion.current.description) 生成"
        let hostEn = "Host macOS \(osVer) (\(caps.physicalCores) cores, \(hostMem))"
        let hostZh = "宿主机 macOS \(osVer)（\(caps.physicalCores) 核，\(hostMem)）"

        return """
        <!DOCTYPE html>
        <html lang="en" data-title-en="\(displayTitleEn): AgentVM Security Audit" data-title-zh="\(displayTitleZh): AgentVM 安全合规审计档案">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta name="description" content="AgentVM microVM fleet security, Copy-on-Write storage lineage, and Layer-2 DPI firewall audit report.">
        <title>\(displayTitleEn): AgentVM Security Audit</title>
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
          --ink-on-amber: #141210;
          --signal-amber: #d97724;
          --signal-amber-soft: rgba(217, 119, 36, 0.16);
          --signal-green: #2a9d6f;
          --signal-green-soft: rgba(42, 157, 111, 0.16);
          --signal-crimson: #d64545;
          --signal-crimson-soft: rgba(214, 69, 69, 0.16);
          --font-sans: -apple-system, BlinkMacSystemFont, "SF Pro Text", "PingFang SC", "Hiragino Sans GB", "Segoe UI", sans-serif;
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
        .mast-actions {
          display: flex;
          align-items: center;
          gap: 0.65rem;
          flex-wrap: wrap;
        }
        .lang-pill {
          display: inline-flex;
          align-items: center;
          background: var(--bg-surface);
          border: 1px solid var(--border-line);
          border-radius: 6px;
          padding: 0.15rem;
          gap: 0.15rem;
        }
        .lang-radio {
          position: absolute;
          width: 1px;
          height: 1px;
          padding: 0;
          margin: -1px;
          overflow: hidden;
          clip-path: inset(50%);
          border: 0;
        }
        .lang-seg {
          display: inline-block;
          background: transparent;
          color: var(--ink-secondary);
          border-radius: 4px;
          padding: 0.28rem 0.62rem;
          font-family: var(--font-sans);
          font-size: 0.82rem;
          font-weight: 600;
          letter-spacing: 0;
          cursor: pointer;
          user-select: none;
          white-space: nowrap;
          transition: transform 140ms ease-out, opacity 140ms ease-out;
        }
        .lang-seg:hover { opacity: 0.92; }
        .lang-seg:active { transform: scale(0.97); }
        .lang-radio:focus-visible + .lang-seg {
          outline: 2px solid var(--signal-amber);
          outline-offset: 2px;
        }
        .lang-radio:checked + .lang-seg {
          background: var(--signal-amber);
          color: var(--ink-on-amber);
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
        .demo-banner {
          background: var(--signal-amber-soft);
          border: 1px solid var(--signal-amber);
          color: var(--signal-amber);
          border-radius: 8px;
          padding: 0.75rem 1rem;
          margin-bottom: 1.5rem;
          font-family: var(--font-mono);
          font-size: 0.85rem;
          font-weight: 600;
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
          white-space: nowrap;
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
          .filter-btn, .lang-seg { transition: opacity 120ms ease; transform: none; }
        }
        </style>
        </head>
        <body>
        <main class="shell">
          <header class="mast">
            <div>
              <h1 data-en="\(displayTitleEn)" data-zh="\(displayTitleZh)">\(displayTitleEn)</h1>
              <p class="lead" data-en="\(leadEn)" data-zh="\(leadZh)">\(leadEn)</p>
            </div>
            <div class="mast-actions">
              <div class="lang-pill" role="radiogroup" aria-label="Language toggle">
                <input class="lang-radio" type="radio" name="dossier-lang" id="dossier-lang-zh" value="zh" data-set-lang="zh">
                <label class="lang-seg" for="dossier-lang-zh">中文</label>
                <input class="lang-radio" type="radio" name="dossier-lang" id="dossier-lang-en" value="en" data-set-lang="en" checked>
                <label class="lang-seg" for="dossier-lang-en">EN</label>
              </div>
              <button class="filter-btn" type="button" onclick="window.print()" data-en="Print Compliance Snapshot" data-zh="打印合规审计快照">Print Compliance Snapshot</button>
            </div>
          </header>
          \(demoBannerHTML)
          \(simulationBannerHTML)

          <section class="metrics" aria-label="Fleet telemetry summary">
            <div class="metric-box">
              <div class="metric-label" data-en="Active Sandbox Blades" data-zh="活跃沙盒实例">Active Sandbox Blades</div>
              <div class="metric-value">\(activeMetricText)</div>
            </div>
            <div class="metric-box">
              <div class="metric-label" data-en="CoW Snapshot Nodes" data-zh="CoW 快照节点">CoW Snapshot Nodes</div>
              <div class="metric-value">\(snapshots.count)</div>
            </div>
            <div class="metric-box">
              <div class="metric-label" data-en="Unique Dirty Disk Delta" data-zh="独立脏页增量">Unique Dirty Disk Delta</div>
              <div class="metric-value">\(escapeHTML(ByteMetricsFormatter.formatBytes(totalDirty)))</div>
            </div>
            <div class="metric-box">
              <div class="metric-label" data-en="DPI Wiretap Drops" data-zh="DPI 抓包拦截">DPI Wiretap Drops</div>
              <div class="metric-value">\(droppedPkts) / \(packets.count)</div>
            </div>
          </section>

          <h2 data-en="MicroVM Sandbox Blades" data-zh="微虚拟机沙盒实例">MicroVM Sandbox Blades</h2>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th data-en="Blade Name" data-zh="实例名称">Blade Name</th>
                  <th data-en="Owner" data-zh="归属代理">Owner</th>
                  <th data-en="Lifecycle" data-zh="运行状态">Lifecycle</th>
                  <th data-en="Compute" data-zh="计算规格">Compute</th>
                  <th data-en="Switch IPv4" data-zh="交换机 IPv4">Switch IPv4</th>
                  <th data-en="CoW Delta" data-zh="CoW 增量">CoW Delta</th>
                </tr>
              </thead>
              <tbody>
                \(vmRows)
              </tbody>
            </table>
          </div>

          <h2 data-en="\(wiretapHeadingEn)" data-zh="\(wiretapHeadingZh)">\(wiretapHeadingEn)</h2>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th data-en="Seq" data-zh="序号">Seq</th>
                  <th data-en="Proto" data-zh="协议">Proto</th>
                  <th data-en="Source" data-zh="源地址">Source</th>
                  <th data-en="Destination" data-zh="目的地址">Destination</th>
                  <th data-en="Verdict" data-zh="裁决">Verdict</th>
                  <th data-en="Dissected Summary" data-zh="协议拆包摘要">Dissected Summary</th>
                </tr>
              </thead>
              <tbody>
                \(packetRows)
              </tbody>
            </table>
          </div>

          <h2 data-en="JavaScriptCore Extension Host Status" data-zh="JavaScriptCore 安全扩展宿主状态">JavaScriptCore Extension Host Status</h2>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th data-en="Plugin ID" data-zh="插件 ID">Plugin ID</th>
                  <th data-en="Extension" data-zh="扩展名称">Extension</th>
                  <th data-en="State" data-zh="状态">State</th>
                  <th data-en="Invocations" data-zh="调用次数">Invocations</th>
                  <th data-en="Interceptions" data-zh="拦截次数">Interceptions</th>
                </tr>
              </thead>
              <tbody>
                \(pluginRows)
              </tbody>
            </table>
          </div>

          <footer>
            <span data-en="\(genEn)" data-zh="\(genZh)">\(genEn)</span>
            <span class="mono" data-en="\(hostEn)" data-zh="\(hostZh)">\(hostEn)</span>
          </footer>
        </main>
        <script>
        (function () {
          var STORAGE_KEY = 'agentvm.dossier.lang';
          function detectPreferredLanguage() {
            try {
              var stored = window.localStorage.getItem(STORAGE_KEY);
              if (stored === 'zh' || stored === 'en') return stored;
            } catch (err) {}
            var browserLang = (window.navigator && window.navigator.language) ? window.navigator.language.toLowerCase() : 'en';
            return browserLang.startsWith('zh') ? 'zh' : 'en';
          }
          function setDossierLanguage(lang, shouldPersist) {
            var resolved = (lang === 'zh') ? 'zh' : 'en';
            var root = document.documentElement;
            root.lang = (resolved === 'zh') ? 'zh-CN' : 'en';
            var nextTitle = root.getAttribute(resolved === 'zh' ? 'data-title-zh' : 'data-title-en');
            if (nextTitle) document.title = nextTitle;
            var items = document.querySelectorAll('[data-en][data-zh]');
            for (var i = 0; i < items.length; i += 1) {
              var text = items[i].getAttribute(resolved === 'zh' ? 'data-zh' : 'data-en');
              if (text !== null) items[i].textContent = text;
            }
            var toggles = document.querySelectorAll('input[data-set-lang]');
            for (var j = 0; j < toggles.length; j += 1) {
              toggles[j].checked = (toggles[j].getAttribute('data-set-lang') === resolved);
            }
            if (shouldPersist) {
              try { window.localStorage.setItem(STORAGE_KEY, resolved); } catch (err) {}
            }
          }
          var radios = document.querySelectorAll('input[data-set-lang]');
          for (var k = 0; k < radios.length; k += 1) {
            radios[k].addEventListener('change', function (event) {
              var input = event.currentTarget;
              if (input && input.checked) setDossierLanguage(input.getAttribute('data-set-lang'), true);
            });
          }
          setDossierLanguage(detectPreferredLanguage(), false);
        })();
        </script>
        </body>
        </html>
        """
    }

    private func lifecycleBilingualLabels(_ state: VMLifecycleState) -> (en: String, zh: String) {
        switch state {
        case .stopped: return ("Stopped", "已停止")
        case .booting: return ("Booting", "启动中")
        case .running: return ("Running", "运行中")
        case .pausing: return ("Pausing", "暂停中")
        case .paused: return ("Paused", "已暂停")
        case .savingState: return ("Saving RAM", "保存内存")
        case .restoringState: return ("Restoring", "恢复中")
        case .branching: return ("CoW Forking", "CoW 分叉中")
        case .stopping: return ("Stopping", "停止中")
        case .crashed: return ("Faulted", "故障")
        }
    }

    private func verdictBilingualLabels(_ verdict: FirewallVerdict) -> (en: String, zh: String) {
        switch verdict {
        case .allow: return ("Allowed", "放行")
        case .drop: return ("Dropped", "丢弃")
        case .rejectRST: return ("Rejected RST", "拒绝 RST")
        case .dnsSinkhole: return ("DNS Sinkhole", "DNS 黑洞")
        case .rateLimited: return ("Rate Limited", "限速")
        case .pluginBlocked: return ("Plugin Blocked", "插件拦截")
        }
    }

    private func policyBilingualLabels(_ name: String) -> (en: String, zh: String) {
        let cleaned = sanitizeNoDashes(name)
        switch cleaned {
        case "Strict Coding-Agent Allowlist":
            return (cleaned, "编码代理严格白名单")
        case "Total Air-Gap", "Total Air-Gap Sandbox":
            return (cleaned, "完全气隙隔离策略")
        case "Permissive Local Research":
            return (cleaned, "宽松研究审计策略")
        default:
            return (cleaned, cleaned)
        }
    }

    private func pluginNameBilingualLabels(id: String, fallback: String) -> (en: String, zh: String) {
        let cleanedFallback = sanitizeNoDashes(fallback)
        switch id {
        case "builtin.secret-leak-guard":
            return (cleanedFallback, "密钥与 DNS 隧道外泄守卫")
        case "builtin.runaway-budget-breaker":
            return (cleanedFallback, "失控代理预算熔断器")
        case "builtin.auto-git-checkpoint":
            return (cleanedFallback, "破坏性命令前自动 CoW 快照")
        case "builtin.iac-compose-bridge":
            return (cleanedFallback, "IaC Compose 与 HCL 拓扑桥接器")
        default:
            return (cleanedFallback, cleanedFallback)
        }
    }

    private func sanitizeNoDashes(_ text: String) -> String {
        text.replacingOccurrences(of: "\u{2014}", with: ":")
            .replacingOccurrences(of: "\u{2013}", with: "-")
            .replacingOccurrences(of: "--", with: "-")
    }

    private func escapeHTML(_ text: String) -> String {
        text.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
    }
}
