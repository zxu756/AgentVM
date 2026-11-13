import AgentVMModels
import AgentVMNetSwitch
import AgentVMWorkbenchShell
import SwiftUI

// MARK: - Stateful L3/L4/L7 Firewall Policy Studio & Interactive Packet Simulator

public struct FirewallPolicyStudioView: View {
    @ObservedObject public var viewModel: AgentVMStudioViewModel

    @State private var showAddRuleComposer: Bool = false
    @State private var newRuleSNIGlob: String = "*.huggingface.co"

    public init(viewModel: AgentVMStudioViewModel) {
        self.viewModel = viewModel
    }

    private var isStrictPresetActive: Bool {
        viewModel.activeFirewallPolicy.id == PolicySetID("pol-strict-agent-allowlist")
    }

    private var isAirgapPresetActive: Bool {
        viewModel.activeFirewallPolicy.id == PolicySetID("pol-airgap")
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            presetAndLintHeaderBar

            if showAddRuleComposer {
                addSNIRuleBar
            }

            if !viewModel.policyConflicts.isEmpty {
                conflictFindingsBanner
            }

            priorityRulesTablePanel
                .frame(minHeight: 215, maxHeight: .infinity)

            interactivePolicySimulatorPanel
                .frame(minHeight: 225, maxHeight: .infinity)
        }
        .padding(10)
        .background(RackTheme.chassisBackground)
    }

    // MARK: - Top Preset Switcher & Conflict Linter Status

    private var presetAndLintHeaderBar: some View {
        HStack(spacing: 7) {
            Text("Preset:")
                .font(RackTheme.labelFont)
                .foregroundStyle(RackTheme.inkMuted)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)

            Button {
                viewModel.applyFirewallPreset(.strictAgentAllowlistPreset())
            } label: {
                Label("Strict Allowlist", systemImage: "checkmark.shield")
            }
            .buttonStyle(
                RackActionButtonStyle(
                    prominence: isStrictPresetActive ? .primaryAmber : .secondaryModule,
                    compact: true
                )
            )

            Button {
                viewModel.applyFirewallPreset(.airgappedPreset())
            } label: {
                Label("Air-Gap Sandbox", systemImage: "wifi.slash")
            }
            .buttonStyle(
                RackActionButtonStyle(
                    prominence: isAirgapPresetActive ? .destructiveCrimson : .secondaryModule,
                    compact: true
                )
            )

            Button {
                withAnimation(.easeOut(duration: 0.15)) {
                    showAddRuleComposer.toggle()
                }
            } label: {
                Label("Add SNI", systemImage: "plus")
            }
            .buttonStyle(RackActionButtonStyle(prominence: .secondaryModule, compact: true))

            Spacer(minLength: 4)

            if viewModel.policyConflicts.isEmpty {
                RackStatusPill(
                    label: "0 SHADOW CONFLICTS",
                    color: RackTheme.linkGreen,
                    monospaced: true
                )
            } else {
                RackStatusPill(
                    label: "\(viewModel.policyConflicts.count) CONFLICTS",
                    color: RackTheme.checkpointGold,
                    monospaced: true
                )
            }
        }
    }

    private var addSNIRuleBar: some View {
        HStack(spacing: 8) {
            Text("Allow TLS 443 SNI Glob:")
                .font(RackTheme.labelFont)
                .foregroundStyle(RackTheme.inkPrimary)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)

            TextField("*.domain.com", text: $newRuleSNIGlob)
                .textFieldStyle(.plain)
                .font(RackTheme.monoSmallFont)
                .foregroundStyle(RackTheme.inkPrimary)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .frame(width: 170)
                .background(
                    RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                        .fill(RackTheme.chassisBackground)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                        .strokeBorder(RackTheme.hairlineStrong, lineWidth: 1)
                )

            Button("Commit Rule") {
                viewModel.addFirewallAllowSNIRule(domainGlob: newRuleSNIGlob)
                showAddRuleComposer = false
            }
            .buttonStyle(RackActionButtonStyle(prominence: .primaryAmber, compact: true))

            Button("Cancel") {
                showAddRuleComposer = false
            }
            .buttonStyle(RackActionButtonStyle(prominence: .subtleGhost, compact: true))

            Spacer(minLength: 0)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .background(
            RoundedRectangle(cornerRadius: RackTheme.outerCornerRadius, style: .continuous)
                .fill(RackTheme.moduleElevated)
        )
        .overlay(
            RoundedRectangle(cornerRadius: RackTheme.outerCornerRadius, style: .continuous)
                .strokeBorder(RackTheme.amberAccent.opacity(0.6), lineWidth: 1)
        )
    }

    private var conflictFindingsBanner: some View {
        VStack(alignment: .leading, spacing: 3) {
            ForEach(viewModel.policyConflicts) { finding in
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 11))
                        .foregroundStyle(RackTheme.checkpointGold)
                    Text(finding.explanation)
                        .font(RackTheme.captionFont)
                        .foregroundStyle(RackTheme.inkPrimary)
                        .lineLimit(1)
                    Spacer(minLength: 0)
                }
            }
        }
        .padding(8)
        .background(
            RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                .fill(RackTheme.checkpointSoft)
        )
        .overlay(
            RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                .strokeBorder(RackTheme.checkpointGold.opacity(0.5), lineWidth: 1)
        )
    }

    // MARK: - Upper Panel: Priority Firewall Rule Table

    private var priorityRulesTablePanel: some View {
        let pol = viewModel.activeFirewallPolicy
        let sortedRules = pol.rules.sorted { $0.priority < $1.priority }

        return RackPanelContainer(
            title: "Priority L3/L4/L7 Egress Policy",
            subtitle: "Default \(pol.defaultEgressVerdict.rawValue)",
            symbolName: "shield.lefthalf.filled",
            headerTrailing: {
                HStack(spacing: 6) {
                    if pol.blockPrivateMetadataIPs {
                        RackStatusPill(label: "IMDS GUARD ON", color: RackTheme.amberAccent, monospaced: true)
                    }
                    RackStatusPill(
                        label: "\(viewModel.firewallMetrics.evaluatedPacketsTotal) PKTS",
                        color: RackTheme.vsockBlue,
                        monospaced: true
                    )
                }
            },
            content: {
                if sortedRules.isEmpty {
                    VStack(spacing: 5) {
                        Image(systemName: "lock.shield.fill")
                            .font(.system(size: 18))
                            .foregroundStyle(RackTheme.dropCrimson)
                        Text("Zero-Egress Air-Gap Active — All external L3/L4 packets default to DROP.")
                            .font(RackTheme.labelFont)
                            .foregroundStyle(RackTheme.inkSecondary)
                            .lineLimit(1)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(
                        RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                            .fill(RackTheme.terminalWell)
                    )
                } else {
                    ScrollView {
                        LazyVStack(spacing: 5) {
                            ForEach(sortedRules) { rule in
                                firewallRuleRow(rule)
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
            }
        )
    }

    private func firewallRuleRow(_ rule: FirewallRule) -> some View {
        let vColor = RackTheme.verdictColor(for: rule.verdict)

        return HStack(spacing: 8) {
            Button {
                viewModel.toggleFirewallRule(rule.id)
            } label: {
                HStack(spacing: 3.5) {
                    Circle()
                        .fill(rule.enabled ? RackTheme.linkGreen : RackTheme.inkMuted)
                        .frame(width: 6.5, height: 6.5)
                    Text(rule.enabled ? "ON" : "OFF")
                        .font(.system(size: 8.5, weight: .bold, design: .monospaced))
                        .foregroundStyle(rule.enabled ? RackTheme.linkGreen : RackTheme.inkMuted)
                        .lineLimit(1)
                        .fixedSize(horizontal: true, vertical: false)
                }
                .padding(.horizontal, 6)
                .padding(.vertical, 2.5)
                .background(
                    Capsule(style: .continuous)
                        .fill(rule.enabled ? RackTheme.linkGreenSoft : RackTheme.chassisBackground)
                )
                .overlay(
                    Capsule(style: .continuous)
                        .strokeBorder(rule.enabled ? RackTheme.linkGreen.opacity(0.42) : RackTheme.hairline, lineWidth: 1)
                )
            }
            .buttonStyle(.plain)

            Text("P\(rule.priority)")
                .font(RackTheme.monoBoldFont)
                .monospacedDigit()
                .foregroundStyle(rule.enabled ? RackTheme.amberAccent : RackTheme.inkMuted)
                .lineLimit(1)
                .frame(width: 34, alignment: .leading)

            VStack(alignment: .leading, spacing: 2) {
                Text(rule.name)
                    .font(.system(size: 11.5, weight: .semibold))
                    .foregroundStyle(rule.enabled ? RackTheme.inkPrimary : RackTheme.inkMuted)
                    .lineLimit(1)

                HStack(spacing: 6) {
                    Text(rule.conditions.map(\.humanReadableSummary).joined(separator: " && "))
                        .font(RackTheme.monoSmallFont)
                        .foregroundStyle(RackTheme.inkSecondary)
                        .lineLimit(1)

                    if let kbps = rule.rateLimitKbps {
                        Text("cap \(kbps / 1000) Mbps")
                            .font(.system(size: 9.5, weight: .semibold, design: .monospaced))
                            .foregroundStyle(RackTheme.checkpointGold)
                            .lineLimit(1)
                            .fixedSize(horizontal: true, vertical: false)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            RackStatusPill(
                label: rule.verdict.rawValue,
                color: rule.enabled ? vColor : RackTheme.inkMuted,
                monospaced: true
            )
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 5.5)
        .background(
            RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                .fill(RackTheme.moduleSurface.opacity(rule.enabled ? 0.85 : 0.4))
        )
        .overlay(
            RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                .strokeBorder(RackTheme.hairline, lineWidth: 1)
        )
    }

    // MARK: - Lower Panel: Interactive Dry-Run Packet Policy Simulator

    private var interactivePolicySimulatorPanel: some View {
        RackPanelContainer(
            title: "Dry-Run Packet Policy Simulator",
            subtitle: "Dry-Run Trace",
            symbolName: "waveform.and.magnifyingglass",
            headerTrailing: {
                HStack(spacing: 5) {
                    scenarioPresetButton("GitHub", proto: .tls, ip: "140.82.121.6", port: "443", sni: "api.github.com", dns: "")
                    scenarioPresetButton("SSRF", proto: .http, ip: "169.254.169.254", port: "80", sni: "", dns: "")
                    scenarioPresetButton("Sinkhole", proto: .dns, ip: "10.211.55.1", port: "53", sni: "", dns: "exfil.webhook.site")
                }
            },
            content: {
                VStack(alignment: .leading, spacing: 8) {
                    // Input Controls Row
                    HStack(spacing: 6) {
                        Picker("", selection: $viewModel.simProtocol) {
                            Text("TLS").tag(DissectedProtocolKind.tls)
                            Text("HTTP").tag(DissectedProtocolKind.http)
                            Text("DNS").tag(DissectedProtocolKind.dns)
                            Text("TCP").tag(DissectedProtocolKind.tcp)
                            Text("UDP").tag(DissectedProtocolKind.udp)
                        }
                        .labelsHidden()
                        .frame(width: 74)
                        .onChange(of: viewModel.simProtocol) { _, _ in
                            viewModel.runFirewallDryRunSimulation()
                        }

                        simTextField(placeholder: "Dst IP", text: $viewModel.simDestinationIP, width: 114)
                        simTextField(placeholder: "Port", text: $viewModel.simDestinationPort, width: 54)

                        if viewModel.simProtocol == .dns {
                            simTextField(placeholder: "DNS Query Domain", text: $viewModel.simDNSQuery, width: nil)
                        } else {
                            simTextField(placeholder: "TLS SNI / Hostname", text: $viewModel.simTLSSNI, width: nil)
                        }

                        Button {
                            viewModel.runFirewallDryRunSimulation()
                        } label: {
                            Label("Trace", systemImage: "play.fill")
                        }
                        .buttonStyle(RackActionButtonStyle(prominence: .primaryAmber, compact: true))
                    }

                    // Evaluation Trace Output
                    if let trace = viewModel.simulationTrace {
                        let winColor = RackTheme.verdictColor(for: trace.finalVerdict)
                        HStack(spacing: 8) {
                            RackStatusPill(
                                label: "VERDICT: \(trace.finalVerdict.rawValue)",
                                color: winColor,
                                monospaced: true
                            )
                            Text(compactTraceReason(trace.reason))
                                .font(RackTheme.monoSmallFont)
                                .foregroundStyle(RackTheme.inkPrimary)
                                .lineLimit(1)
                            Spacer(minLength: 0)
                        }
                        .padding(.horizontal, 8)
                        .padding(.vertical, 5)
                        .background(
                            RoundedRectangle(cornerRadius: 4, style: .continuous)
                                .fill(winColor.opacity(0.14))
                        )

                        ScrollView {
                            LazyVStack(spacing: 3.5) {
                                ForEach(trace.evaluatedSteps) { step in
                                    simulationStepRow(step, finalVerdict: trace.finalVerdict)
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
                }
            }
        )
    }

    private func scenarioPresetButton(
        _ title: String,
        proto: DissectedProtocolKind,
        ip: String,
        port: String,
        sni: String,
        dns: String
    ) -> some View {
        Button(title) {
            viewModel.simProtocol = proto
            viewModel.simDestinationIP = ip
            viewModel.simDestinationPort = port
            viewModel.simTLSSNI = sni
            viewModel.simDNSQuery = dns
            viewModel.runFirewallDryRunSimulation()
        }
        .buttonStyle(RackActionButtonStyle(prominence: .subtleGhost, compact: true))
    }

    private func simTextField(placeholder: String, text: Binding<String>, width: CGFloat?) -> some View {
        TextField(placeholder, text: text)
            .textFieldStyle(.plain)
            .font(RackTheme.monoSmallFont)
            .foregroundStyle(RackTheme.inkPrimary)
            .onSubmit {
                viewModel.runFirewallDryRunSimulation()
            }
            .padding(.horizontal, 7)
            .padding(.vertical, 4.5)
            .frame(width: width)
            .frame(maxWidth: width == nil ? .infinity : nil)
            .background(
                RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                    .fill(RackTheme.chassisBackground)
            )
            .overlay(
                RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                    .strokeBorder(RackTheme.hairlineStrong, lineWidth: 1)
            )
    }

    private func simulationStepRow(_ step: FirewallRuleStepEvaluation, finalVerdict: FirewallVerdict) -> some View {
        let hitColor = step.matched ? RackTheme.verdictColor(for: finalVerdict) : RackTheme.inkMuted

        return HStack(spacing: 7) {
            Image(systemName: step.matched ? "checkmark.circle.fill" : "circle.dotted")
                .font(.system(size: 10.5, weight: .bold))
                .foregroundStyle(hitColor)

            Text("P\(step.priority)")
                .font(RackTheme.monoSmallFont)
                .monospacedDigit()
                .foregroundStyle(step.matched ? hitColor : RackTheme.inkMuted)
                .lineLimit(1)
                .frame(width: 30, alignment: .leading)

            Text(step.ruleName)
                .font(.system(size: 11, weight: step.matched ? .semibold : .regular))
                .foregroundStyle(step.matched ? RackTheme.inkPrimary : RackTheme.inkSecondary)
                .lineLimit(1)

            Spacer(minLength: 6)

            Text(step.matched ? "MATCH" : "SKIP")
                .font(.system(size: 9.5, weight: .bold, design: .monospaced))
                .foregroundStyle(hitColor)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
                .padding(.horizontal, 5)
                .padding(.vertical, 1.5)
                .background(
                    RoundedRectangle(cornerRadius: 3, style: .continuous)
                        .fill(step.matched ? hitColor.opacity(0.18) : Color.clear)
                )
        }
        .padding(.horizontal, 7)
        .padding(.vertical, 3.5)
        .background(
            RoundedRectangle(cornerRadius: 4, style: .continuous)
                .fill(step.matched ? hitColor.opacity(0.11) : Color.clear)
        )
    }

    private func compactTraceReason(_ text: String) -> String {
        if text.contains("Allow GitHub TLS") {
            return "Rule P40 · Allow GitHub TLS (*.github.com)"
        }
        if text.contains("169.254.169.254") {
            return "Rule P30 · Block Cloud Instance Metadata SSRF"
        }
        if text.contains("Webhook") || text.contains("Sinkhole") {
            return "Rule P70 · DNS Sinkhole Exfiltration Domain"
        }
        if text.count <= 48 { return text }
        if let quoteEnd = text.firstIndex(of: "(") {
            return String(text[..<quoteEnd]).trimmingCharacters(in: .whitespaces) + "'"
        }
        return String(text.prefix(48))
    }
}
