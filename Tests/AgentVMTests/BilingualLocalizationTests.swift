import AgentVMCLIAndMCP
import AgentVMHypervisor
import AgentVMModels
import AgentVMWorkbenchShell
import Foundation
import Testing

@Suite("M12 Bilingual Localization (`中文` / `EN`), Locale Priority & HTML Dossier", .timeLimit(.minutes(1)))
struct BilingualLocalizationTests {

    /// Tests must not touch `~/Library/Preferences`. A named `UserDefaults(suiteName:)` domain leaves a
    /// plist behind even after `removePersistentDomain`, so the localizer is exercised against this
    /// in-memory stand-in instead: every accessor the localizer uses is overridden and nothing reaches cfprefsd.
    private final class InMemoryUserDefaults: UserDefaults, @unchecked Sendable {
        private let lock = NSLock()
        private var storage: [String: Any] = [:]

        init() {
            // `suiteName: nil` binds no named domain; all reads and writes below are served from `storage`.
            super.init(suiteName: nil)!
        }

        override func object(forKey defaultName: String) -> Any? {
            lock.lock(); defer { lock.unlock() }
            return storage[defaultName]
        }

        override func string(forKey defaultName: String) -> String? {
            object(forKey: defaultName) as? String
        }

        override func set(_ value: Any?, forKey defaultName: String) {
            lock.lock(); defer { lock.unlock() }
            if let value {
                storage[defaultName] = value
            } else {
                storage.removeValue(forKey: defaultName)
            }
        }

        override func removeObject(forKey defaultName: String) {
            lock.lock(); defer { lock.unlock() }
            storage.removeValue(forKey: defaultName)
        }
    }

    private func makeIsolatedDefaults() -> UserDefaults {
        InMemoryUserDefaults()
    }

    @Test("AppLanguage CLI --lang parsing, argument stripping, and badge metadata")
    func appLanguageCLIParsingAndStripping() {
        #expect(AppLanguage.zhHans.rawValue == "zh-Hans")
        #expect(AppLanguage.zhHans.badge == "中文")
        #expect(AppLanguage.zhHans.displayName == "简体中文")
        #expect(AppLanguage.en.rawValue == "en")
        #expect(AppLanguage.en.badge == "EN")
        #expect(AppLanguage.en.displayName == "English")

        #expect(AppLanguage.parse("zh") == .zhHans)
        #expect(AppLanguage.parse("zh-Hans-CN") == .zhHans)
        #expect(AppLanguage.parse("zh_TW") == .zhHans)
        #expect(AppLanguage.parse("en") == .en)
        #expect(AppLanguage.parse("en-US") == .en)
        #expect(AppLanguage.parse("fr-FR") == nil)

        #expect(AppLanguage.extractCLILanguage(from: ["--export-screenshots", "/tmp/out", "--lang", "zh"]) == .zhHans)
        #expect(AppLanguage.extractCLILanguage(from: ["--lang=en", "doctor"]) == .en)
        #expect(AppLanguage.extractCLILanguage(from: ["ps", "--json"]) == nil)

        let stripped = AppLanguage.strippingLanguageArguments(
            from: ["--workspace", "/tmp/a.agentvm", "--lang", "zh", "ps", "--lang=en", "--json"]
        )
        #expect(stripped == ["--workspace", "/tmp/a.agentvm", "ps", "--json"])
    }

    @Test("AppLanguage resolution priority: CLI --lang > AGENTVM_LANG > UserDefaults > Locale.preferredLanguages")
    func appLanguageResolutionOrderAndChineseAutoDetection() throws {
        let defaults = makeIsolatedDefaults()

        // 1. Auto-detects Simplified Chinese when macOS primary preferred language starts with "zh"
        let autoZh = AppLanguage.resolve(
            arguments: [],
            environment: [:],
            userDefaults: defaults,
            preferredLanguages: ["zh-Hans-CN", "en-US"]
        )
        #expect(autoZh == .zhHans)

        let autoZhHant = AppLanguage.resolve(
            arguments: [],
            environment: [:],
            userDefaults: defaults,
            preferredLanguages: ["zh-Hant-HK"]
        )
        #expect(autoZhHant == .zhHans)

        // 2. Defaults to English when primary locale is non-Chinese
        let autoEn = AppLanguage.resolve(
            arguments: [],
            environment: [:],
            userDefaults: defaults,
            preferredLanguages: ["en-US", "zh-Hans-CN"]
        )
        #expect(autoEn == .en)

        // 3. UserDefaults overrides system locale
        defaults.set(AppLanguage.en.rawValue, forKey: AgentVMLocalizer.userDefaultsKey)
        let fromDefaults = AppLanguage.resolve(
            arguments: [],
            environment: [:],
            userDefaults: defaults,
            preferredLanguages: ["zh-Hans-CN"]
        )
        #expect(fromDefaults == .en)

        // 4. Environment variable AGENTVM_LANG overrides UserDefaults
        let fromEnv = AppLanguage.resolve(
            arguments: [],
            environment: ["AGENTVM_LANG": "zh"],
            userDefaults: defaults,
            preferredLanguages: ["en-US"]
        )
        #expect(fromEnv == .zhHans)

        // 5. CLI `--lang` overrides AGENTVM_LANG and UserDefaults
        let fromCLI = AppLanguage.resolve(
            arguments: ["--lang", "en"],
            environment: ["AGENTVM_LANG": "zh"],
            userDefaults: defaults,
            preferredLanguages: ["zh-Hans-CN"]
        )
        #expect(fromCLI == .en)
    }

    @Test("AgentVMLocalizer live zh-Hans <-> en toggle, persistence, and domain enum localization")
    @MainActor
    func localizerLiveTogglePersistenceAndDomainStrings() throws {
        let defaults = makeIsolatedDefaults()

        let localizer = AgentVMLocalizer(
            arguments: [],
            environment: [:],
            userDefaults: defaults,
            preferredLanguages: ["zh-Hans-CN"]
        )
        #expect(localizer.language == .zhHans)
        #expect(localizer.isChinese == true)
        #expect(localizer.L("Overview & CoW DAG", "总览与写时复制血统") == "总览与写时复制血统")

        let toggledToEn = localizer.toggleLanguage(persist: true)
        #expect(toggledToEn == .en)
        #expect(localizer.isChinese == false)
        #expect(localizer.L("Overview & CoW DAG", "总览与写时复制血统") == "Overview & CoW DAG")
        #expect(defaults.string(forKey: AgentVMLocalizer.userDefaultsKey) == "en")

        let toggledBackToZh = localizer.toggleLanguage(persist: true)
        #expect(toggledBackToZh == .zhHans)
        #expect(defaults.string(forKey: AgentVMLocalizer.userDefaultsKey) == "zh-Hans")

        // Verify shared localizer & workbench/model extensions switch cleanly without restart
        let previousShared = AgentVMLocalizer.shared.language
        defer { AgentVMLocalizer.shared.setLanguage(previousShared, persist: false) }

        AgentVMLocalizer.shared.setLanguage(.zhHans, persist: false)
        #expect(VMLifecycleState.running.localizedBadge == "运行中")
        #expect(WorkbenchDocumentKind.packetWiretap.localizedDefaultTitle == "二层抓包与解析")
        let zhPalette = CommandPaletteController.defaultBuiltInActions()
        #expect(zhPalette.contains(where: { $0.id == "app.language.toggle" && $0.keyEquivalentDisplay == "⇧⌘L" }))
        #expect(!FuzzyCommandScorer.rank(query: "快照", items: zhPalette).isEmpty)

        AgentVMLocalizer.shared.setLanguage(.en, persist: false)
        #expect(VMLifecycleState.running.localizedBadge == "Running")
        #expect(WorkbenchDocumentKind.packetWiretap.localizedDefaultTitle == "L2 Packet Wiretap")
    }

    @Test("AgentVMCLIRunner honors --lang flag and simulated demo HtmlFleetReportExporter emits Hallmark-clean bilingual dossier")
    func cliLanguageFlagAndBilingualHtmlDossierMarkers() async throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("avm-bilingual-html-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let bundleURL = tempDir.appendingPathComponent("BilingualDossier.agentvm", isDirectory: true)
        let coordinator = try AgentVMFleetCoordinator(
            bundleURL: bundleURL,
            executionBackend: .deterministicSimulation
        )
        try await coordinator.seedIndustrialDemonstrationFleetIfEmpty()
        for vm in try await coordinator.store.listVMs() where vm.telemetry.state != .stopped {
            _ = try? await coordinator.haltVM(vm.id)
        }

        // Verify CLI accepts `--lang zh` alongside `version` (`1.5.0`) and `export-html`
        let cli = AgentVMCLIRunner()
        let verOut = await cli.execute(arguments: ["--lang", "zh", "--version"], bundleURLOverride: bundleURL)
        #expect(verOut.exitCode == 0)
        #expect(verOut.stdout.contains("1.5.0"))

        let html = try await HtmlFleetReportExporter().renderStandaloneHTML(coordinator: coordinator)
        #expect(html.contains("data-set-lang=\"zh\""))
        #expect(html.contains("data-set-lang=\"en\""))
        #expect(html.contains("data-en=\"MicroVM Sandbox Blades\""))
        #expect(html.contains("data-zh=\"微虚拟机沙盒实例\""))
        #expect(html.contains("data-zh=\"打印合规审计快照\""))
        #expect(html.contains("localStorage"))
        #expect(html.contains("navigator.language"))
        #expect(html.contains("startsWith('zh')"))
        #expect(html.contains("AgentVM v1.5.0"))
        // Zero em-dashes in English or Chinese dossier output
        #expect(!html.contains("\u{2014}"))
    }
}
