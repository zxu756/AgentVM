import AgentVMCLIAndMCP
import AgentVMHypervisor
import AgentVMModels
import AgentVMStorageCoW
import AgentVMStore
import Darwin
import Foundation
import Testing
import Virtualization

@Suite("M4 Stage 1: VirtioFS Directory Sharing (--mount, cloud-init mounts:, preflight, branch --no-mounts)", .serialized, .timeLimit(.minutes(2)))
struct M4Stage1VirtioFSMountTests {

    private func makeTempDir(prefix: String) throws -> URL {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
            .standardizedFileURL
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        return base
    }

    private func makeFakeBootableImageFixture(
        in tempDir: URL,
        imageID: String = "fake-debian-12-arm64",
        sizeBytes: Int = 4 * 1024 * 1024
    ) async throws -> (cacheDir: URL, cachedFileURL: URL, entry: BaseImageCatalogEntry) {
        let cacheDir = tempDir.appendingPathComponent("ImageCache", isDirectory: true).standardizedFileURL
        try FileManager.default.createDirectory(at: cacheDir, withIntermediateDirectories: true)

        let stagingURL = tempDir.appendingPathComponent("staging-\(imageID).raw")
        try APFSCoWDiskEngine().createSparseRawDisk(
            at: stagingURL,
            virtualSizeBytes: UInt64(sizeBytes),
            overwrite: true
        )
        let parts = try PartitionAndContainerInspector().writeProtectiveMBRAndGPT(
            to: stagingURL,
            partitions: [
                (
                    name: "RootExt4",
                    typeGUID: GPTWellKnownTypeGUID.linuxRootARM64.rawValue,
                    sizeBytes: UInt64(max(512 * 1024, sizeBytes / 2))
                )
            ]
        )
        let part0Offset = parts[0].firstLBA * 512
        var ext4Super = [UInt8](repeating: 0, count: 256)
        ext4Super[0x38] = 0x53
        ext4Super[0x39] = 0xEF
        ext4Super[0x5C] = 0x04
        ext4Super[0x60] = 0xC0
        let fh = try FileHandle(forUpdating: stagingURL)
        try fh.seek(toOffset: part0Offset + 1024)
        try fh.write(contentsOf: Data(ext4Super))
        try fh.close()

        let sha512 = try BinaryChecksums.sha512HexFile(at: stagingURL)
        let entry = BaseImageCatalogEntry(
            id: imageID,
            displayName: "Fake Debian 12 ARM64",
            distribution: "debian",
            version: "test-12",
            guestOS: .linuxARM64,
            isSupported: true,
            downloadURL: "https://example.invalid/images/\(imageID).raw",
            expectedSHA512: sha512,
            expectedSizeBytes: UInt64(sizeBytes),
            defaultVirtualSizeBytes: UInt64(sizeBytes),
            includesPreinstalledToolchains: ["python3.11", "cloud-init"]
        )
        let catalog = try BaseImageRegistryCatalog(
            cacheDirectoryURL: cacheDir,
            curatedEntries: [entry],
            createIfMissing: true
        )
        let staged = try await catalog.stageCachedCuratedImage(id: imageID, from: stagingURL, verifyChecksum: true)
        try? FileManager.default.removeItem(at: stagingURL)
        let cachedFileURL = URL(fileURLWithPath: try #require(staged.cachedLocalPath)).standardizedFileURL
        _ = Darwin.chmod(cachedFileURL.path, 0o444)
        return (cacheDir, cachedFileURL, entry)
    }

    private func extractISOUserDataViaSystemTar(isoPath: String, scratchDir: URL) throws -> String {
        let outDir = scratchDir.appendingPathComponent("iso-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
        proc.arguments = ["-xf", isoPath, "-C", outDir.path]
        let errPipe = Pipe()
        proc.standardError = errPipe
        try proc.run()
        proc.waitUntilExit()
        let errText = String(decoding: errPipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        #expect(proc.terminationStatus == 0, "tar -xf failed: \(errText)")
        let userDataURL = outDir.appendingPathComponent("user-data")
        return try String(contentsOf: userDataURL, encoding: .utf8)
    }

    private func regularFiles(in dir: URL) -> [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: dir.path))?.sorted() ?? []
    }

    // MARK: - 1. create --mount grammar, exit codes, canonical host path, unique tags & zero leftover files

    @Test("create --mount supports repeatable mounts, canonicalizes host paths, enforces exit 2 for bad syntax/duplicates and exit 1 for missing/non-dir host paths without creating workspace files")
    func createMountParsingValidationCanonicalizationAndCleanup() async throws {
        let tempDir = try makeTempDir(prefix: "avm-m4-s1-parse")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let rwDir = tempDir.appendingPathComponent("real-rw", isDirectory: true)
        let roDir = tempDir.appendingPathComponent("real-ro", isDirectory: true)
        let nestedDummy = tempDir.appendingPathComponent("nested", isDirectory: true)
        let longDir1 = tempDir.appendingPathComponent("long-1", isDirectory: true)
        let longDir2 = tempDir.appendingPathComponent("long-2", isDirectory: true)
        for d in [rwDir, roDir, nestedDummy, longDir1, longDir2] {
            try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        }
        let regularFile = tempDir.appendingPathComponent("plain-file.txt")
        try Data("hello\n".utf8).write(to: regularFile)
        let missingDir = tempDir.appendingPathComponent("does-not-exist", isDirectory: true)

        let cli = AgentVMCLIRunner()

        // 1a. Syntax / usage errors -> exit 2, specific localized reason (NOT 'Unknown option --mount'), zero workspace created
        let freshWSUsage = tempDir.appendingPathComponent("NeverCreatedUsage.agentvm", isDirectory: true)
        let syntaxCases: [[String]] = [
            ["create", "m-noval", "--mount"],
            ["create", "m-nocolon", "--mount", rwDir.path],
            ["create", "m-emptyhost", "--mount", ":/workspace"],
            ["create", "m-relguest", "--mount", "\(rwDir.path):relative/guest"],
            ["create", "m-badsuffix", "--mount", "\(rwDir.path):/workspace:foo"],
            ["create", "m-extrasuffix", "--mount", "\(rwDir.path):/workspace:ro:extra"],
            ["create", "m-dup", "--mount", "\(rwDir.path):/workspace", "--mount", "\(roDir.path):/workspace:ro"],
            ["create", "m-dupslash", "--mount", "\(rwDir.path):/workspace", "--mount", "\(roDir.path):/workspace/:ro"]
        ]
        for args in syntaxCases {
            for lang in ["en", "zh"] {
                let out = await cli.execute(
                    arguments: ["--lang", lang] + args,
                    bundleURLOverride: freshWSUsage
                )
                #expect(out.exitCode == 2, "Expected exit 2 for \(args) (\(lang)), got \(out.exitCode): \(out.stderr)")
                #expect(!out.stderr.isEmpty)
                #expect(!out.stderr.contains("Unknown option '--mount'"))
                #expect(!out.stderr.contains("不认识选项「--mount」"))
            }
        }
        #expect(!FileManager.default.fileExists(atPath: freshWSUsage.path))

        // 1b. Host path missing or regular file -> exit 1, stderr names offending path, zero workspace created
        let freshWSHostErr = tempDir.appendingPathComponent("NeverCreatedHostErr.agentvm", isDirectory: true)
        for badHost in [missingDir.path, regularFile.path] {
            for lang in ["en", "zh"] {
                let out = await cli.execute(
                    arguments: ["--lang", lang, "create", "m-badhost", "--mount", "\(badHost):/workspace"],
                    bundleURLOverride: freshWSHostErr
                )
                #expect(out.exitCode == 1, "Expected exit 1 for host path \(badHost) (\(lang)), got \(out.exitCode): \(out.stderr)")
                #expect(out.stderr.contains(badHost))
            }
        }
        #expect(!FileManager.default.fileExists(atPath: freshWSHostErr.path))

        // 1c. Existing workspace with --image: failed --mount leaves zero partial VM records, disks, ISOs, or snapshots
        let fix = try await makeFakeBootableImageFixture(in: tempDir)
        defer { _ = Darwin.chmod(fix.cachedFileURL.path, 0o644) }

        let wsURL = tempDir.appendingPathComponent("MountFleet.agentvm", isDirectory: true)
        let initOut = await cli.execute(arguments: ["--lang", "en", "init"], bundleURLOverride: wsURL)
        #expect(initOut.exitCode == 0)

        let badImgHostOut = await cli.execute(
            arguments: [
                "--lang", "en",
                "create", "m-img-badhost",
                "--image", fix.entry.id,
                "--mount", "\(missingDir.path):/workspace"
            ],
            bundleURLOverride: wsURL,
            imageCacheURLOverride: fix.cacheDir,
            curatedEntriesOverride: [fix.entry]
        )
        #expect(badImgHostOut.exitCode == 1)
        #expect(badImgHostOut.stderr.contains(missingDir.path))

        let badImgFileOut = await cli.execute(
            arguments: [
                "--lang", "zh",
                "create", "m-img-file",
                "--image", fix.entry.id,
                "--mount", "\(regularFile.path):/workspace"
            ],
            bundleURLOverride: wsURL,
            imageCacheURLOverride: fix.cacheDir,
            curatedEntriesOverride: [fix.entry]
        )
        #expect(badImgFileOut.exitCode == 1)
        #expect(badImgFileOut.stderr.contains(regularFile.path))

        let checkCoord = try AgentVMFleetCoordinator(bundleURL: wsURL)
        let checkStore = checkCoord.store
        #expect(try await checkStore.listVMs().isEmpty)
        #expect(try await checkStore.listSnapshots().isEmpty)
        #expect(regularFiles(in: checkStore.disksDirectoryURL).isEmpty)
        #expect(regularFiles(in: checkStore.isosDirectoryURL).isEmpty)
        #expect(regularFiles(in: checkStore.snapshotsDirectoryURL).isEmpty)

        // 1d. Valid repeatable --mount (including non-normalized path with '..' & trailing slash, plus >36-byte guest paths)
        let unnormalizedRW = nestedDummy.path + "/../real-rw/"
        let createOK = await cli.execute(
            arguments: [
                "--lang", "en",
                "create", "m-ok",
                "--image", fix.entry.id,
                "--mount", "\(unnormalizedRW):/workspace",
                "--mount", "\(roDir.path):/mnt/ro:ro",
                "--mount", "\(longDir1.path):/opt/very-long-guest-mount-directory-name-exceeding-36-bytes/alpha",
                "--mount", "\(longDir2.path):/opt/very-long-guest-mount-directory-name-exceeding-36-bytes/beta:ro"
            ],
            bundleURLOverride: wsURL,
            imageCacheURLOverride: fix.cacheDir,
            curatedEntriesOverride: [fix.entry]
        )
        #expect(createOK.exitCode == 0, "Expected create --mount to exit 0, got \(createOK.exitCode): \(createOK.stderr)")

        let psOut = await cli.execute(arguments: ["--lang", "en", "ps", "--json"], bundleURLOverride: wsURL)
        #expect(psOut.exitCode == 0)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let records = try decoder.decode([VMInstanceRecord].self, from: Data(psOut.stdout.utf8))
        let vm = try #require(records.first { $0.spec.name == "m-ok" })
        #expect(vm.spec.validate().isEmpty)
        #expect(vm.spec.virtioFSMounts.count == 4)

        let m0 = vm.spec.virtioFSMounts[0]
        #expect(m0.hostDirectoryPath == rwDir.standardizedFileURL.path)
        #expect(m0.guestMountPoint == "/workspace")
        #expect(m0.readOnly == false)
        #expect(m0.mountTag == "workspace")

        let m1 = vm.spec.virtioFSMounts[1]
        #expect(m1.hostDirectoryPath == roDir.standardizedFileURL.path)
        #expect(m1.guestMountPoint == "/mnt/ro")
        #expect(m1.readOnly == true)

        let allTags = vm.spec.virtioFSMounts.map(\.mountTag)
        #expect(Set(allTags).count == 4)
        for tag in allTags {
            #expect((1...36).contains(tag.utf8.count), "Tag '\(tag)' outside 1...36 UTF-8 bytes")
        }
    }

    // MARK: - 2. cloud-init user-data bootcmd & mounts: synthesis and tar -xf ISO inspection

    @Test("ISO9660CloudInitBuilder and create --mount synthesize bootcmd mkdir -p (keeping /workspace first) and VirtioFS mounts: with systemd ordering in cidata ISO")
    func cloudInitISOBootcmdAndMountsExtraction() async throws {
        let tempDir = try makeTempDir(prefix: "avm-m4-s1-iso")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let rwDir = tempDir.appendingPathComponent("share-rw", isDirectory: true)
        let roDir = tempDir.appendingPathComponent("share-ro", isDirectory: true)
        try FileManager.default.createDirectory(at: rwDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: roDir, withIntermediateDirectories: true)

        // 2a. Coordinator createSandboxVM with sharedDirectories already populates cidata ISO
        let wsCoordURL = tempDir.appendingPathComponent("CoordISO.agentvm", isDirectory: true)
        let coordinator = try AgentVMFleetCoordinator(bundleURL: wsCoordURL)
        let created = try await coordinator.createSandboxVM(
            name: "iso-check",
            sharedDirectories: [
                VirtioFSMountSpec(
                    mountTag: "workspace",
                    hostDirectoryPath: rwDir.path,
                    guestMountPoint: "/workspace",
                    readOnly: false
                ),
                VirtioFSMountSpec(
                    mountTag: "mnt-ro",
                    hostDirectoryPath: roDir.path,
                    guestMountPoint: "/mnt/ro",
                    readOnly: true
                )
            ]
        )
        let coordISOPath = try #require(created.cloudInitISOPath)
        let coordUserData = try extractISOUserDataViaSystemTar(isoPath: coordISOPath, scratchDir: tempDir)

        let coordLines = coordUserData.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        let bootcmdIdx = try #require(coordLines.firstIndex(of: "bootcmd:"), "user-data missing bootcmd:")
        #expect(coordLines[bootcmdIdx + 1].contains("mkdir -p /workspace && chmod 0755 /workspace"))
        #expect(coordUserData.contains("/mnt/ro"))
        #expect(coordLines.contains("mounts:"))
        #expect(coordUserData.contains("rw,nofail,x-systemd.before=local-fs.target"))
        #expect(coordUserData.contains("ro,nofail,x-systemd.before=local-fs.target"))
        #expect(coordUserData.contains("virtiofs"))

        // 2b. End-to-end CLI `create m1 --mount ...` cidata ISO extracted via /usr/bin/tar -xf
        let wsCLIURL = tempDir.appendingPathComponent("CLIISO.agentvm", isDirectory: true)
        let cli = AgentVMCLIRunner()
        let cliCreate = await cli.execute(
            arguments: [
                "--lang", "en",
                "create", "m1",
                "--mount", "\(rwDir.path):/workspace",
                "--mount", "\(roDir.path):/mnt/ro:ro"
            ],
            bundleURLOverride: wsCLIURL
        )
        #expect(cliCreate.exitCode == 0, "CLI create failed: \(cliCreate.stderr)")
        let psOut = await cli.execute(arguments: ["--lang", "en", "ps", "--json"], bundleURLOverride: wsCLIURL)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let vms = try decoder.decode([VMInstanceRecord].self, from: Data(psOut.stdout.utf8))
        let m1 = try #require(vms.first { $0.spec.name == "m1" })
        let m1ISOPath = try #require(m1.spec.cloudInitISOPath)
        let m1UserData = try extractISOUserDataViaSystemTar(isoPath: m1ISOPath, scratchDir: tempDir)

        let m1Lines = m1UserData.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        let m1BootIdx = try #require(m1Lines.firstIndex(of: "bootcmd:"))
        #expect(m1Lines[m1BootIdx + 1].contains("mkdir -p /workspace && chmod 0755 /workspace"))
        let m1MountsIdx = try #require(m1Lines.firstIndex(of: "mounts:"))
        let mountsBlock = m1Lines[(m1MountsIdx + 1)...].prefix { $0.hasPrefix("  - ") }.joined(separator: "\n")
        #expect(mountsBlock.contains("/workspace"))
        #expect(mountsBlock.contains("rw,nofail,x-systemd.before=local-fs.target"))
        #expect(mountsBlock.contains("/mnt/ro"))
        #expect(mountsBlock.contains("ro,nofail,x-systemd.before=local-fs.target"))
    }

    // MARK: - 3. branch mount inheritance, --no-mounts, and bilingual --help warning

    @Test("branch inherits parent virtioFSMounts and cidata ISO mounts: by default, --no-mounts omits all mounts from spec and ISO, and bilingual --help warns about shared RW directories")
    func branchMountInheritanceNoMountsAndBilingualHelp() async throws {
        let tempDir = try makeTempDir(prefix: "avm-m4-s1-branch")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let rwDir = tempDir.appendingPathComponent("branch-rw", isDirectory: true)
        let roDir = tempDir.appendingPathComponent("branch-ro", isDirectory: true)
        try FileManager.default.createDirectory(at: rwDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: roDir, withIntermediateDirectories: true)

        let wsURL = tempDir.appendingPathComponent("BranchFleet.agentvm", isDirectory: true)
        let coordinator = try AgentVMFleetCoordinator(bundleURL: wsURL)
        _ = try await coordinator.createSandboxVM(
            name: "p1",
            sharedDirectories: [
                VirtioFSMountSpec(
                    mountTag: "workspace",
                    hostDirectoryPath: rwDir.standardizedFileURL.path,
                    guestMountPoint: "/workspace",
                    readOnly: false
                ),
                VirtioFSMountSpec(
                    mountTag: "mnt-ro",
                    hostDirectoryPath: roDir.standardizedFileURL.path,
                    guestMountPoint: "/mnt/ro",
                    readOnly: true
                )
            ]
        )

        let cli = AgentVMCLIRunner()

        // 3a. Default `branch p1 c1` inherits mounts in both VMSpec and child cidata ISO
        let b1Out = await cli.execute(
            arguments: ["--lang", "en", "branch", "p1", "c1"],
            bundleURLOverride: wsURL
        )
        #expect(b1Out.exitCode == 0, "branch p1 c1 failed: \(b1Out.stderr)")

        // 3b. `branch p1 c2 --no-mounts` clears virtioFSMounts and omits mounts: from child cidata ISO
        let b2Out = await cli.execute(
            arguments: ["--lang", "en", "branch", "p1", "c2", "--no-mounts"],
            bundleURLOverride: wsURL
        )
        #expect(b2Out.exitCode == 0, "branch p1 c2 --no-mounts failed: \(b2Out.stderr)")

        let psOut = await cli.execute(arguments: ["--lang", "en", "ps", "--json"], bundleURLOverride: wsURL)
        #expect(psOut.exitCode == 0)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let vms = try decoder.decode([VMInstanceRecord].self, from: Data(psOut.stdout.utf8))

        let p1 = try #require(vms.first { $0.spec.name == "p1" })
        let c1 = try #require(vms.first { $0.spec.name == "c1" })
        let c2 = try #require(vms.first { $0.spec.name == "c2" })

        #expect(c1.spec.virtioFSMounts == p1.spec.virtioFSMounts)
        let c1ISOPath = try #require(c1.spec.cloudInitISOPath)
        let c1UserData = try extractISOUserDataViaSystemTar(isoPath: c1ISOPath, scratchDir: tempDir)
        #expect(c1UserData.contains("mounts:"))
        #expect(c1UserData.contains("rw,nofail,x-systemd.before=local-fs.target"))
        #expect(c1UserData.contains("ro,nofail,x-systemd.before=local-fs.target"))
        #expect(c1UserData.contains("/mnt/ro"))

        #expect(c2.spec.virtioFSMounts.isEmpty)
        let c2ISOPath = try #require(c2.spec.cloudInitISOPath)
        let c2UserData = try extractISOUserDataViaSystemTar(isoPath: c2ISOPath, scratchDir: tempDir)
        #expect(!c2UserData.contains("mounts:"))
        #expect(!c2UserData.contains("virtiofs"))
        #expect(!c2UserData.contains("/mnt/ro"))

        // 3c. Bilingual --help documents --mount, --no-mounts, and shared RW overwrite warning
        let helpEn = AgentVMCLIRunner.helpBanner(language: .en)
        let helpZh = AgentVMCLIRunner.helpBanner(language: .zhHans)
        #expect(helpEn.contains("--mount"))
        #expect(helpEn.contains("--no-mounts"))
        #expect(helpEn.lowercased().contains("overwrite") || helpEn.lowercased().contains("modify"))
        #expect(helpZh.contains("--mount"))
        #expect(helpZh.contains("--no-mounts"))
        #expect(helpZh.contains("改写") || helpZh.contains("修改"))
    }

    // MARK: - 4. Pre-boot missing / non-directory host path fails explicitly instead of silent skip

    @Test("preflightPersistentBoot, VZConfigurationTranslator, and CLI up reject missing or non-directory VirtioFS host path without silent skip, keeping VM stopped")
    func prebootMissingOrNonDirectoryMountFailsWithoutSilentSkip() async throws {
        let tempDir = try makeTempDir(prefix: "avm-m4-s1-preflight")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let fix = try await makeFakeBootableImageFixture(in: tempDir)
        defer { _ = Darwin.chmod(fix.cachedFileURL.path, 0o644) }

        let rwDir = tempDir.appendingPathComponent("ephemeral-rw", isDirectory: true)
        try FileManager.default.createDirectory(at: rwDir, withIntermediateDirectories: true)

        let wsURL = tempDir.appendingPathComponent("PreflightFleet.agentvm", isDirectory: true)
        let coordinator = try AgentVMFleetCoordinator(
            bundleURL: wsURL,
            executionBackend: .strictHardwareVZ,
            imageCacheDirectoryURL: fix.cacheDir,
            curatedImageEntries: [fix.entry]
        )
        let created = try await coordinator.createVMFromImage(
            name: "t1",
            imageID: fix.entry.id,
            sharedDirectories: [
                VirtioFSMountSpec(
                    mountTag: "workspace",
                    hostDirectoryPath: rwDir.standardizedFileURL.path,
                    guestMountPoint: "/workspace",
                    readOnly: false
                )
            ]
        )
        let vmID = created.vmRecord.id
        let translator = VZConfigurationTranslator()

        // Sanity: while rwDir exists as a directory, buildVZConfiguration attaches 1 VirtioFS device
        let okCfg = try translator.buildVZConfiguration(from: created.vmRecord.spec, validateConfiguration: false)
        #expect(okCfg.directorySharingDevices.count == 1)

        // Delete rwDir -> buildVZConfiguration, preflightPersistentBoot, and CLI `up` must all fail naming rwDir.path
        try FileManager.default.removeItem(at: rwDir)

        do {
            _ = try translator.buildVZConfiguration(from: created.vmRecord.spec, validateConfiguration: false)
            Issue.record("Expected buildVZConfiguration to throw when VirtioFS host directory is missing")
        } catch let err as AgentVMError {
            #expect(err.localizedMessage(in: .en).contains(rwDir.standardizedFileURL.path))
            #expect(err.localizedMessage(in: .zhHans).contains(rwDir.standardizedFileURL.path))
        }

        let cli = AgentVMCLIRunner()
        let forbiddenSpawn = DaemonSpawnCommandOverride(
            executablePath: "/bin/sh",
            arguments: ["-c", "exit 98"],
            environment: [:]
        )
        for lang in ["en", "zh"] {
            let upMissing = await cli.execute(
                arguments: ["--lang", lang, "up", "t1"],
                bundleURLOverride: wsURL,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(upMissing.exitCode != 0)
            #expect(upMissing.stderr.contains(rwDir.standardizedFileURL.path))
        }
        let afterMissing = try #require(try await coordinator.store.fetchVM(vmID))
        #expect(afterMissing.telemetry.state == .stopped)

        // Replace rwDir path with a regular file -> must also fail naming rwDir.path and keep VM stopped
        try Data("not a directory\n".utf8).write(to: rwDir)
        do {
            _ = try translator.buildVZConfiguration(from: created.vmRecord.spec, validateConfiguration: false)
            Issue.record("Expected buildVZConfiguration to throw when VirtioFS host path is a regular file")
        } catch let err as AgentVMError {
            #expect(err.localizedMessage(in: .en).contains(rwDir.standardizedFileURL.path))
            #expect(err.localizedMessage(in: .zhHans).contains(rwDir.standardizedFileURL.path))
        }

        let upFile = await cli.execute(
            arguments: ["--lang", "en", "up", "t1"],
            bundleURLOverride: wsURL,
            hasEntitlementOverride: true,
            daemonSpawnOverride: forbiddenSpawn
        )
        #expect(upFile.exitCode != 0)
        #expect(upFile.stderr.contains(rwDir.standardizedFileURL.path))
        let afterFile = try #require(try await coordinator.store.fetchVM(vmID))
        #expect(afterFile.telemetry.state == .stopped)
    }

    // MARK: - 5. End-to-end readOnly flag propagation to VZSharedDirectory

    @Test("create --mount :ro propagates readOnly=true end-to-end into VZSharedDirectory while RW mount stays readOnly=false")
    func vzSharedDirectoryReadOnlyFlagPropagation() async throws {
        let tempDir = try makeTempDir(prefix: "avm-m4-s1-vz-ro")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let rwDir = tempDir.appendingPathComponent("vz-rw", isDirectory: true)
        let roDir = tempDir.appendingPathComponent("vz-ro", isDirectory: true)
        try FileManager.default.createDirectory(at: rwDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: roDir, withIntermediateDirectories: true)

        let wsURL = tempDir.appendingPathComponent("VZReadOnly.agentvm", isDirectory: true)
        let cli = AgentVMCLIRunner()
        let out = await cli.execute(
            arguments: [
                "--lang", "en",
                "create", "m-vz",
                "--mount", "\(rwDir.path):/workspace",
                "--mount", "\(roDir.path):/mnt/ro:ro"
            ],
            bundleURLOverride: wsURL
        )
        #expect(out.exitCode == 0, "create m-vz failed: \(out.stderr)")

        let coord = try AgentVMFleetCoordinator(bundleURL: wsURL)
        let vms = try await coord.store.listVMs()
        let vm = try #require(vms.first { $0.spec.name == "m-vz" })
        #expect(vm.spec.virtioFSMounts.count == 2)

        let vzConfig = try VZConfigurationTranslator().buildVZConfiguration(
            from: vm.spec,
            validateConfiguration: false
        )
        #expect(vzConfig.directorySharingDevices.count == 2)

        let dev0 = try #require(vzConfig.directorySharingDevices[0] as? VZVirtioFileSystemDeviceConfiguration)
        let share0 = try #require(dev0.share as? VZSingleDirectoryShare)
        #expect(dev0.tag == vm.spec.virtioFSMounts[0].mountTag)
        #expect(share0.directory.url.standardizedFileURL == rwDir.standardizedFileURL)
        #expect(share0.directory.isReadOnly == false)

        let dev1 = try #require(vzConfig.directorySharingDevices[1] as? VZVirtioFileSystemDeviceConfiguration)
        let share1 = try #require(dev1.share as? VZSingleDirectoryShare)
        #expect(dev1.tag == vm.spec.virtioFSMounts[1].mountTag)
        #expect(share1.directory.url.standardizedFileURL == roDir.standardizedFileURL)
        #expect(share1.directory.isReadOnly == true)
    }

    // MARK: - 6. DaemonRPCBranchParams backward compatibility & forkBranchInDaemon --no-mounts

    @Test("DaemonRPCBranchParams defaults inheritMounts=true for legacy payloads and forkBranchInDaemon honors inheritMounts=false")
    func daemonRPCBranchParamsAndDaemonForkInheritMounts() async throws {
        // Legacy JSON without inheritMounts decodes to true
        let legacyJSON = Data(#"{"vm":"p1","branchName":"c1","owner":"worker","lang":"en"}"#.utf8)
        let decodedLegacy = try JSONDecoder().decode(DaemonRPCBranchParams.self, from: legacyJSON)
        #expect(decodedLegacy.inheritMounts == true)

        let explicitNoMounts = DaemonRPCBranchParams(
            vm: "p1",
            branchName: "c2",
            owner: "worker",
            inheritMounts: false,
            lang: .zhHans
        )
        let encoded = try JSONEncoder().encode(explicitNoMounts)
        let roundTripped = try JSONDecoder().decode(DaemonRPCBranchParams.self, from: encoded)
        #expect(roundTripped.inheritMounts == false)

        let tempDir = try makeTempDir(prefix: "avm-m4-s1-daemon-fork")
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let rwDir = tempDir.appendingPathComponent("daemon-rw", isDirectory: true)
        try FileManager.default.createDirectory(at: rwDir, withIntermediateDirectories: true)

        let wsURL = tempDir.appendingPathComponent("DaemonFork.agentvm", isDirectory: true)
        let coordinator = try AgentVMFleetCoordinator(bundleURL: wsURL)
        let parent = try await coordinator.createSandboxVM(
            name: "dp1",
            sharedDirectories: [
                VirtioFSMountSpec(
                    mountTag: "workspace",
                    hostDirectoryPath: rwDir.standardizedFileURL.path,
                    guestMountPoint: "/workspace",
                    readOnly: false
                )
            ]
        )

        let inheritedRes = try await coordinator.forkBranchInDaemon(
            fromVMID: parent.vmRecord.id,
            branchName: "dc-inherit",
            agentOwnerTag: "worker",
            inheritMounts: true
        )
        #expect(inheritedRes.fork.childVM.spec.virtioFSMounts.count == 1)

        let strippedRes = try await coordinator.forkBranchInDaemon(
            fromVMID: parent.vmRecord.id,
            branchName: "dc-nomounts",
            agentOwnerTag: "worker",
            inheritMounts: false
        )
        #expect(strippedRes.fork.childVM.spec.virtioFSMounts.isEmpty)
        let strippedISO = try #require(strippedRes.fork.childVM.spec.cloudInitISOPath)
        let strippedUserData = try extractISOUserDataViaSystemTar(isoPath: strippedISO, scratchDir: tempDir)
        #expect(!strippedUserData.contains("mounts:"))
        #expect(!strippedUserData.contains("virtiofs"))
    }
}
