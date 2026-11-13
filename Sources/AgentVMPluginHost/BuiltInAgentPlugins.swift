import AgentVMModels
import Foundation

// MARK: - 4 Official Built-In JavaScript Security & Automation Plugins

public enum BuiltInAgentPlugins {
    public static let secretLeakGuardID      = PluginID("builtin.secret-leak-guard")
    public static let runawayBudgetBreakerID = PluginID("builtin.runaway-budget-breaker")
    public static let autoGitCheckpointID    = PluginID("builtin.auto-git-checkpoint")
    public static let iacComposeBridgeID     = PluginID("builtin.iac-compose-bridge")

    public static func allManifests() -> [PluginManifest] {
        [
            secretLeakGuardManifest(),
            runawayBudgetBreakerManifest(),
            autoGitCheckpointManifest(),
            iacComposeBridgeManifest()
        ]
    }

    public static func secretLeakGuardManifest() -> PluginManifest {
        PluginManifest(
            id: secretLeakGuardID,
            name: "Secret & DNS-Tunnel Exfiltration Guard",
            version: SemanticVersion(major: 1, minor: 2, patch: 0),
            author: "AgentVM Core Security",
            summary: "Inspects outbound HTTP payloads, DNS labels (entropy tunneling), and guest exec invocations for API keys & private keys.",
            isBuiltIn: true,
            requestedCapabilities: [
                .networkInspect,
                .networkVerdictOverride,
                .commandExecInterception,
                .pluginKVStore
            ],
            timeoutMilliseconds: 200,
            configFields: [
                PluginConfigField(
                    key: "dnsMaxSubdomainEntropy",
                    label: "Max DNS Label Shannon Entropy",
                    valueType: "number",
                    defaultValue: "4.15",
                    helpText: "Sinkholes high-entropy base64/hex DNS exfiltration queries."
                ),
                PluginConfigField(
                    key: "blockCleartextBearer",
                    label: "Block Cleartext HTTP Authorization",
                    valueType: "boolean",
                    defaultValue: "true",
                    helpText: "Drops unencrypted HTTP frames carrying Bearer tokens or API keys."
                )
            ],
            entryPointSource: """
            const SECRET_REGEXES = [
                { name: "Anthropic Key", re: /sk-ant-[a-zA-Z0-9_-]{12,}/ },
                { name: "OpenAI Project Key", re: /sk-proj-[a-zA-Z0-9_-]{12,}/ },
                { name: "GitHub PAT", re: /(ghp_[a-zA-Z0-9]{20,}|github_pat_[a-zA-Z0-9_]{22,})/ },
                { name: "AWS Access Key", re: /AKIA[0-9A-Z]{16}/ },
                { name: "Slack Bot Token", re: /xoxb-[0-9]{8,}-[a-zA-Z0-9-]+/ },
                { name: "Private Key PEM", re: /BEGIN (OPENSSH|RSA|EC) PRIVATE KEY/ }
            ];

            function shannonEntropy(s) {
                if (!s || s.length === 0) return 0;
                const counts = {};
                for (let i = 0; i < s.length; i++) {
                    const ch = s[i];
                    counts[ch] = (counts[ch] || 0) + 1;
                }
                let ent = 0;
                const len = s.length;
                for (const k in counts) {
                    const p = counts[k] / len;
                    ent -= p * Math.log2(p);
                }
                return ent;
            }

            function onPacket(pkt) {
                const payload = (pkt.httpRequestLine || "") + " " + (pkt.asciiPreview || "");
                for (const item of SECRET_REGEXES) {
                    if (item.re.test(payload)) {
                        const hits = Number(AgentVM.kvGet("leaks_blocked") || "0") + 1;
                        AgentVM.kvSet("leaks_blocked", String(hits));
                        AgentVM.log("warning", "Dropped outbound packet leaking " + item.name);
                        return { action: "drop", reason: "Credential leak blocked (" + item.name + ")" };
                    }
                }

                if (AgentVM.getConfig("blockCleartextBearer", "true") === "true") {
                    if (pkt.protocol === "HTTP" && /Authorization:\\s*Bearer\\s+[A-Za-z0-9._-]{12,}/i.test(payload)) {
                        return { action: "drop", reason: "Unencrypted HTTP Bearer token blocked" };
                    }
                }

                if (pkt.dnsQueryName && pkt.dnsQueryName.length > 34) {
                    const firstLabel = pkt.dnsQueryName.split(".")[0] || "";
                    const maxEnt = parseFloat(AgentVM.getConfig("dnsMaxSubdomainEntropy", "4.15"));
                    if (firstLabel.length >= 24 && shannonEntropy(firstLabel) > maxEnt) {
                        AgentVM.log("warning", "Sinkholed suspected DNS tunnel label: " + firstLabel.slice(0, 16) + "...");
                        return { action: "sinkhole", reason: "High-entropy DNS exfiltration tunnel detected" };
                    }
                }
                return { action: "allow" };
            }

            function onBeforeExec(req) {
                const full = req.commandLine || "";
                for (const item of SECRET_REGEXES) {
                    if (item.re.test(full) && /(curl|wget|nc|ncat|python)/i.test(req.executable)) {
                        return { action: "veto", reason: "Vetoed network command containing inline " + item.name };
                    }
                }
                return { action: "allow" };
            }
            """
        )
    }

    public static func runawayBudgetBreakerManifest() -> PluginManifest {
        PluginManifest(
            id: runawayBudgetBreakerID,
            name: "Runaway Agent Circuit-Breaker",
            version: SemanticVersion(major: 1, minor: 0, patch: 0),
            author: "AgentVM Fleet Ops",
            summary: "Auto-pauses guest VMs when autonomous loops exceed dirty CoW disk quota, drop-storm thresholds, or runtime limits.",
            isBuiltIn: true,
            requestedCapabilities: [
                .vmLifecycleControl,
                .snapshotCheckpoint,
                .pluginKVStore
            ],
            timeoutMilliseconds: 150,
            configFields: [
                PluginConfigField(
                    key: "maxDirtyDiskMB",
                    label: "Max Branch CoW Dirty Delta (MB)",
                    valueType: "number",
                    defaultValue: "16384",
                    helpText: "Pauses branch VM if CoW divergence exceeds threshold."
                ),
                PluginConfigField(
                    key: "maxFirewallDropBurst",
                    label: "Max Firewall Dropped Packets",
                    valueType: "number",
                    defaultValue: "250",
                    helpText: "Freezes VM when scanning or exfiltration triggers repeated firewall drops."
                )
            ],
            entryPointSource: """
            function onTelemetry(sample) {
                if (sample.state !== "running") {
                    return { action: "none" };
                }
                const maxDirtyBytes = parseFloat(AgentVM.getConfig("maxDirtyDiskMB", "16384")) * 1024 * 1024;
                if (sample.cowDirtyBytes > maxDirtyBytes) {
                    return {
                        action: "pause",
                        reason: "Branch dirty CoW disk exceeded " + AgentVM.getConfig("maxDirtyDiskMB", "16384") + " MB ceiling"
                    };
                }
                const maxDrops = parseInt(AgentVM.getConfig("maxFirewallDropBurst", "250"), 10);
                if (sample.firewallDroppedPackets >= maxDrops) {
                    return {
                        action: "pause",
                        reason: "Firewall drop storm (" + sample.firewallDroppedPackets + " blocked packets)"
                    };
                }
                const maxSeconds = (sample.maxRuntimeMinutes || 180) * 60;
                if (sample.uptimeSeconds > maxSeconds) {
                    return {
                        action: "pause",
                        reason: "Sandbox runtime quota (" + sample.maxRuntimeMinutes + " min) reached"
                    };
                }
                return { action: "none" };
            }
            """
        )
    }

    public static func autoGitCheckpointManifest() -> PluginManifest {
        PluginManifest(
            id: autoGitCheckpointID,
            name: "Pre-Destructive CoW Auto-Checkpoint",
            version: SemanticVersion(major: 1, minor: 1, patch: 0),
            author: "AgentVM Storage Team",
            summary: "Automatically forks a sub-20ms APFS Copy-on-Write checkpoint before destructive shell, package, or database commands.",
            isBuiltIn: true,
            requestedCapabilities: [
                .commandExecInterception,
                .snapshotCheckpoint
            ],
            timeoutMilliseconds: 150,
            configFields: [
                PluginConfigField(
                    key: "checkpointPackageInstalls",
                    label: "Checkpoint Before apt/pip/npm Global Installs",
                    valueType: "boolean",
                    defaultValue: "true",
                    helpText: "Captures clean rollback point before mutating system packages."
                )
            ],
            entryPointSource: """
            const DESTRUCTIVE_PATTERNS = [
                { label: "Recursive delete", re: /\\brm\\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive)/ },
                { label: "Hard git reset/clean", re: /\\bgit\\s+(reset\\s+--hard|clean\\s+-[a-z]*f)/ },
                { label: "Raw block write", re: /\\b(dd\\s+if=|mkfs\\.|fdisk|parted)\\b/ },
                { label: "SQL destructive DDL", re: /\\b(DROP\\s+TABLE|DROP\\s+DATABASE|TRUNCATE\\s+TABLE)\\b/i },
                { label: "Recursive permission sweep", re: /\\bchmod\\s+-R\\s+777\\b/ }
            ];

            function onBeforeExec(req) {
                const cmd = req.commandLine || "";
                for (const rule of DESTRUCTIVE_PATTERNS) {
                    if (rule.re.test(cmd)) {
                        return {
                            action: "checkpoint",
                            reason: "Auto-checkpoint before " + rule.label
                        };
                    }
                }
                if (AgentVM.getConfig("checkpointPackageInstalls", "true") === "true") {
                    if (/\\b(apt|apt-get)\\s+(install|upgrade|dist-upgrade|remove)\\b/.test(cmd)) {
                        return {
                            action: "checkpoint",
                            reason: "Auto-checkpoint before system apt mutation"
                        };
                    }
                }
                return { action: "allow" };
            }
            """
        )
    }

    public static func iacComposeBridgeManifest() -> PluginManifest {
        PluginManifest(
            id: iacComposeBridgeID,
            name: "IaC Compose & HCL Topology Bridge",
            version: SemanticVersion(major: 1, minor: 0, patch: 0),
            author: "AgentVM Platform",
            summary: "Imports and exports multi-VM sandbox fleets as declarative .avm.hcl specs or Docker Compose manifests.",
            isBuiltIn: true,
            requestedCapabilities: [
                .topologyImportExport,
                .workbenchCommand
            ],
            timeoutMilliseconds: 200,
            configFields: [],
            entryPointSource: """
            function getCommands() {
                return [
                    { id: "plugin.iac.export.hcl", title: "Export Fleet as .avm.hcl Manifest" },
                    { id: "plugin.iac.export.compose", title: "Export Fleet as compose.yaml" }
                ];
            }
            """
        )
    }
}
