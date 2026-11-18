import AgentVMCLIAndMCP
import AgentVMHypervisor
import AgentVMModels
import AgentVMStorageCoW
import AgentVMStore
import AgentVMVsockRPC
import Darwin
import Foundation
import Testing
import Virtualization

@Suite("M3 Stage 2a: Child Guest Identity, NoCloud ISO Synthesis & Legacy Bootstrap Upgrade", .timeLimit(.minutes(2)))
struct M3Stage2aChildIdentityTests {

    private func makeTempDirectory(prefix: String = "avm-m3-s2a") throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString.lowercased())", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func stageSyntheticCuratedImage(in tempDir: URL) async throws -> (cacheDir: URL, entry: BaseImageCatalogEntry) {
        let cacheDir = tempDir.appendingPathComponent("image-cache", isDirectory: true)
        let imageID = "debian-12-bookworm-arm64"
        var payload = [UInt8](repeating: 0, count: 1024 * 1024)
        for idx in 0..<payload.count {
            payload[idx] = UInt8((idx * 23 + 5) & 0xFF)
        }
        let imgData = Data(payload)
        let entry = BaseImageCatalogEntry(
            id: imageID,
            displayName: "Debian 12 Stage2a Synthetic",
            distribution: "debian",
            version: "12",
            guestOS: .linuxARM64,
            isSupported: true,
            downloadURL: "https://offline.agentvm.invalid/debian-12.raw",
            expectedSHA512: BinaryChecksums.sha512Hex(imgData),
            expectedSizeBytes: UInt64(imgData.count),
            defaultVirtualSizeBytes: UInt64(imgData.count)
        )
        let stageFile = tempDir.appendingPathComponent("staging-debian.raw")
        try imgData.write(to: stageFile)
        let catalog = try BaseImageRegistryCatalog(
            cacheDirectoryURL: cacheDir,
            curatedEntries: [entry],
            createIfMissing: true
        )
        let record = try await catalog.stageCachedCuratedImage(id: imageID, from: stageFile, verifyChecksum: true)
        try? FileManager.default.removeItem(at: stageFile)
        if let localPath = record.cachedLocalPath {
            _ = Darwin.chmod(localPath, 0o444)
        }
        return (cacheDir, entry)
    }

    private func inspectISOFiles(at isoPath: String) throws -> [String: String] {
        let data = try Data(contentsOf: URL(fileURLWithPath: isoPath))
        let inspected = try ISO9660CloudInitBuilder().inspectISOImage(data: data)
        #expect(inspected.volumeID == "cidata")
        var textFiles: [String: String] = [:]
        for (path, fileData) in inspected.files {
            textFiles[path] = String(decoding: fileData, as: UTF8.self)
        }
        return textFiles
    }

    private func extractTopLevelYAMLListBlock(named key: String, from yaml: String) -> [String] {
        let lines = yaml.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        guard let headerIndex = lines.firstIndex(where: { $0 == "\(key):" }) else {
            return []
        }
        var items: [String] = []
        for idx in (headerIndex + 1)..<lines.count {
            let line = lines[idx]
            if line.isEmpty || line.hasPrefix("#") {
                continue
            }
            if !line.hasPrefix(" ") {
                break
            }
            items.append(line.trimmingCharacters(in: .whitespaces))
        }
        return items
    }

    private func isValidRFC1123Label(_ hostname: String) -> Bool {
        guard !hostname.isEmpty, hostname.utf8.count <= 63 else { return false }
        let bytes = Array(hostname.utf8)
        guard bytes.first != 0x2D, bytes.last != 0x2D else { return false }
        return bytes.allSatisfy { b in
            (b >= 0x61 && b <= 0x7A) || (b >= 0x30 && b <= 0x39) || b == 0x2D
        }
    }

    // MARK: - 1. Hostname Normalization (Underscore, Uppercase, Non-ASCII, Overlong >63)

    @Test("Hostname normalization enforces RFC 1123 ASCII [a-z0-9-] max 63 across create, create --image, and branch while keeping sanitizeFilename for paths")
    func hostnameSanitizationHandlesUnderscoreUppercaseNonASCIIAndMaxLengthAcrossCreateAndBranch() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-s2a-hostname")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let (cacheDir, imageEntry) = try await stageSyntheticCuratedImage(in: tempDir)
        let bundleURL = tempDir.appendingPathComponent("HostnameFleet.agentvm", isDirectory: true)
        let coordinator = try AgentVMFleetCoordinator(
            bundleURL: bundleURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [imageEntry]
        )

        // 1. createSandboxVM with uppercase + underscores: filename keeps '_', hostname converts '_' -> '-' and lowercases
        let createdMixed = try await coordinator.createSandboxVM(
            name: "Worker_Node_01",
            diskVirtualBytes: 16 * 1024 * 1024
        )
        let mixedHost = try #require(createdMixed.vmRecord.spec.cloudInit?.hostname)
        #expect(mixedHost == "worker-node-01")
        #expect(isValidRFC1123Label(mixedHost))
        let mixedISOPath = try #require(createdMixed.cloudInitISOPath)
        #expect(URL(fileURLWithPath: mixedISOPath).lastPathComponent == "worker_node_01-\(createdMixed.vmRecord.id.rawValue)-cidata.iso")
        let mixedISO = try inspectISOFiles(at: mixedISOPath)
        #expect(mixedISO["meta-data"]?.contains("local-hostname: worker-node-01\n") == true)
        #expect(mixedISO["user-data"]?.contains("hostname: worker-node-01\n") == true)
        #expect(mixedISO["user-data"]?.contains("fqdn: worker-node-01.agentvm.local\n") == true)

        // 2. createVMFromImage uses the exact same hostname normalization function
        let createdImageParent = try await coordinator.createVMFromImage(
            name: "Parent_Img_子机_01",
            imageID: imageEntry.id
        )
        let imageParentHost = try #require(createdImageParent.vmRecord.spec.cloudInit?.hostname)
        #expect(isValidRFC1123Label(imageParentHost))
        #expect(!imageParentHost.contains("_"))
        #expect(imageParentHost.hasPrefix("parent-img-"))
        #expect(imageParentHost.hasSuffix("-01"))

        // 3. Branch with underscore ('c_1') -> hostname 'c-1', ISO filename 'isos/c_1-<id>-cidata.iso'
        let childUnderscore = try await coordinator.forkCoWBranch(
            fromVMID: createdImageParent.vmRecord.id,
            branchName: "c_1",
            agentOwnerTag: "worker",
            bootImmediately: false
        )
        #expect(childUnderscore.childVM.spec.cloudInit?.hostname == "c-1")
        let c1ISOPath = try #require(childUnderscore.childVM.spec.cloudInitISOPath)
        #expect(URL(fileURLWithPath: c1ISOPath).lastPathComponent == "c_1-\(childUnderscore.childVM.id.rawValue)-cidata.iso")
        let c1ISO = try inspectISOFiles(at: c1ISOPath)
        #expect(c1ISO["meta-data"]?.contains("local-hostname: c-1\n") == true)
        #expect(c1ISO["user-data"]?.contains("hostname: c-1\n") == true)
        #expect(c1ISO["user-data"]?.contains("fqdn: c-1.agentvm.local\n") == true)

        // 4. Non-ASCII + leading/trailing underscores & hyphens, and pure non-ASCII fallback
        let childNonASCII = try await coordinator.forkCoWBranch(
            fromVMID: createdMixed.vmRecord.id,
            branchName: "__测试_Branch_🚀_名__",
            agentOwnerTag: "worker",
            bootImmediately: false
        )
        let nonASCIIHost = try #require(childNonASCII.childVM.spec.cloudInit?.hostname)
        #expect(isValidRFC1123Label(nonASCIIHost))
        #expect(nonASCIIHost == "branch")

        let pureNonASCII = try await coordinator.createSandboxVM(
            name: "___纯中文___",
            diskVirtualBytes: 16 * 1024 * 1024
        )
        let fallbackHost = try #require(pureNonASCII.vmRecord.spec.cloudInit?.hostname)
        #expect(isValidRFC1123Label(fallbackHost))

        // 5. Overlong (> 63 chars) truncation AND truncation landing on '_' / '-' at index 62 (63rd byte)
        let overlong80 = String(repeating: "A", count: 80)
        let childOverlong80 = try await coordinator.forkCoWBranch(
            fromVMID: createdMixed.vmRecord.id,
            branchName: overlong80,
            agentOwnerTag: "worker",
            bootImmediately: false
        )
        let host80 = try #require(childOverlong80.childVM.spec.cloudInit?.hostname)
        #expect(host80 == String(repeating: "a", count: 63))
        #expect(host80.utf8.count == 63)
        #expect(isValidRFC1123Label(host80))

        let boundary62Underscore = String(repeating: "B", count: 62) + "_tail"
        let childBoundary = try await coordinator.forkCoWBranch(
            fromVMID: createdMixed.vmRecord.id,
            branchName: boundary62Underscore,
            agentOwnerTag: "worker",
            bootImmediately: false
        )
        let hostBoundary = try #require(childBoundary.childVM.spec.cloudInit?.hostname)
        #expect(hostBoundary == String(repeating: "b", count: 62))
        #expect(hostBoundary.utf8.count == 62)
        #expect(isValidRFC1123Label(hostBoundary))
    }

    // MARK: - 2. Child ISO meta-data, network-config (dhcp-identifier: mac), user-data & Distinct Spec Identity

    @Test("create and branch emit dhcp-identifier: mac, and child VM gets its own cidata ISO, instance-id, hostname, fqdn, machine-id bootcmd, MAC, and machineIdentifier")
    func childBranchSynthesizesDistinctISOAndDHCPMacIdentifier() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-s2a-iso")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let (cacheDir, imageEntry) = try await stageSyntheticCuratedImage(in: tempDir)
        let bundleURL = tempDir.appendingPathComponent("ISOFleet.agentvm", isDirectory: true)
        let coordinator = try AgentVMFleetCoordinator(
            bundleURL: bundleURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [imageEntry]
        )

        // Check both empty-disk (`create a` -> `branch a a1`) and image-backed (`create p --image` -> `branch p c1`)
        let a = try await coordinator.createSandboxVM(name: "a", diskVirtualBytes: 16 * 1024 * 1024)
        let p = try await coordinator.createVMFromImage(name: "p", imageID: imageEntry.id)

        for created in [a, p] {
            let parentISOPath = try #require(created.cloudInitISOPath)
            let parentFiles = try inspectISOFiles(at: parentISOPath)
            let parentNet = try #require(parentFiles["network-config"])
            #expect(parentNet.contains("dhcp4: true"))
            #expect(parentNet.contains("dhcp-identifier: mac"))
        }

        let forkA1 = try await coordinator.forkCoWBranch(
            fromVMID: a.vmRecord.id,
            branchName: "a1",
            agentOwnerTag: "worker",
            bootImmediately: false
        )
        let forkC1 = try await coordinator.forkCoWBranch(
            fromVMID: p.vmRecord.id,
            branchName: "c1",
            agentOwnerTag: "worker",
            bootImmediately: false
        )

        for (parentSummary, forkResult, expectedName) in [(a, forkA1, "a1"), (p, forkC1, "c1")] {
            let parentSpec = parentSummary.vmRecord.spec
            let childSpec = forkResult.childVM.spec
            let childID = forkResult.childVM.id.rawValue

            let parentISOPath = try #require(parentSpec.cloudInitISOPath)
            let childISOPath = try #require(childSpec.cloudInitISOPath)
            #expect(childISOPath != parentISOPath)
            #expect(childISOPath == bundleURL.appendingPathComponent("isos/\(expectedName)-\(childID)-cidata.iso").path)
            #expect(FileManager.default.fileExists(atPath: childISOPath))
            #expect(forkResult.childInitialSnapshot.specSnapshot.cloudInitISOPath == childISOPath)
            #expect(forkResult.childInitialSnapshot.specSnapshot.cloudInit?.instanceID == childID)

            // MAC, VZGenericMachineIdentifier, and cloned NVRAM
            #expect(childSpec.networkInterfaces.first?.macAddress != parentSpec.networkInterfaces.first?.macAddress)
            let parentMID = try #require(parentSpec.machineIdentifierPath)
            let childMID = try #require(childSpec.machineIdentifierPath)
            #expect(childMID != parentMID)
            let parentMIDData = try Data(contentsOf: URL(fileURLWithPath: parentMID))
            let childMIDData = try Data(contentsOf: URL(fileURLWithPath: childMID))
            #expect(childMIDData != parentMIDData)
            #expect(VZGenericMachineIdentifier(dataRepresentation: childMIDData) != nil)

            if case let .efiBoot(parentNvram, _) = parentSpec.bootLoader,
               case let .efiBoot(childNvram, _) = childSpec.bootLoader {
                #expect(childNvram != parentNvram)
                #expect(FileManager.default.fileExists(atPath: childNvram))
            } else {
                Issue.record("Expected EFI variable store on both parent and child")
            }

            // Inspect child ISO contents via product's own ISO9660CloudInitBuilder reader
            let childFiles = try inspectISOFiles(at: childISOPath)
            let metaData = try #require(childFiles["meta-data"])
            let netConfig = try #require(childFiles["network-config"])
            let userData = try #require(childFiles["user-data"])

            #expect(metaData == "instance-id: \(childID)\nlocal-hostname: \(expectedName)\n")
            #expect(!metaData.contains(parentSpec.id.rawValue))

            #expect(netConfig.contains("dhcp4: true"))
            #expect(netConfig.contains("dhcp-identifier: mac"))

            #expect(userData.contains("hostname: \(expectedName)\n"))
            #expect(userData.contains("fqdn: \(expectedName).agentvm.local\n"))
            #expect(userData.contains("cloud-init-per"))
            #expect(userData.contains("avm-machine-id"))
            #expect(userData.contains("rm -f /etc/machine-id /var/lib/dbus/machine-id && systemd-machine-id-setup && ln -sf /etc/machine-id /var/lib/dbus/machine-id"))

            // Rebuilding machine-id MUST be in bootcmd and MUST NOT be in runcmd (Pitfall 4)
            let runcmdItems = extractTopLevelYAMLListBlock(named: "runcmd", from: userData)
            #expect(!runcmdItems.contains { $0.contains("machine-id") || $0.contains("avm-machine-id") })
        }
    }

    // MARK: - 3. user-data bootcmd Item 0 Preserves /workspace Creation

    @Test("Child user-data bootcmd keeps mkdir -p /workspace && chmod 0755 /workspace as item 0 and avm-machine-id as item 1 without duplicating across grandchild forks")
    func childUserDataBootcmdPreservesWorkspaceCreationFirstAndMachineIDResetSecond() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-s2a-bootcmd")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let bundleURL = tempDir.appendingPathComponent("BootcmdFleet.agentvm", isDirectory: true)
        let coordinator = try AgentVMFleetCoordinator(bundleURL: bundleURL)

        let parent = try await coordinator.createSandboxVM(name: "p0", diskVirtualBytes: 16 * 1024 * 1024)
        let parentISO = try inspectISOFiles(at: try #require(parent.cloudInitISOPath))
        let parentUserBootcmd = extractTopLevelYAMLListBlock(named: "bootcmd", from: try #require(parentISO["user-data"]))
        #expect(parentUserBootcmd.isEmpty)
        #expect(parentISO["vendor-data"]?.contains("mkdir -p /workspace && chmod 0755 /workspace") == true)

        let c1 = try await coordinator.forkCoWBranch(
            fromVMID: parent.vmRecord.id,
            branchName: "c1",
            agentOwnerTag: "worker",
            bootImmediately: false
        )
        let c2 = try await coordinator.forkCoWBranch(
            fromVMID: c1.childVM.id,
            branchName: "c2",
            agentOwnerTag: "worker",
            bootImmediately: false
        )

        for fork in [c1, c2] {
            let isoFiles = try inspectISOFiles(at: try #require(fork.childVM.spec.cloudInitISOPath))
            let userData = try #require(isoFiles["user-data"])
            let bootcmdItems = extractTopLevelYAMLListBlock(named: "bootcmd", from: userData)
            #expect(bootcmdItems.count == 2, "bootcmd items: \(bootcmdItems)")
            if bootcmdItems.count >= 2 {
                #expect(bootcmdItems[0] == "- [sh, '-c', 'mkdir -p /workspace && chmod 0755 /workspace']")
                #expect(bootcmdItems[1] == "- [cloud-init-per, instance, avm-machine-id, sh, '-c', 'rm -f /etc/machine-id /var/lib/dbus/machine-id && systemd-machine-id-setup && ln -sf /etc/machine-id /var/lib/dbus/machine-id']")
            }
        }
    }

    // MARK: - 4. Legacy CloudInitSpec / VMSpec Decoding Compatibility

    @Test("Legacy CloudInitSpec and SQLite spec_json without bootCommands decode cleanly, and new bootCommands round-trip losslessly")
    func legacyCloudInitSpecWithoutBootCommandsDecodesCleanlyAndNewBootCommandsRoundTrip() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-s2a-legacy-spec")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601

        // 1. Minimal pre-M3 CloudInitSpec JSON lacking bootCommands (and omitting optional array keys)
        let minimalLegacyCloudInitJSON = """
        {
          "defaultUser": "agent",
          "hostname": "legacy-host",
          "injectGuestVsockAgent": true,
          "instanceID": "vm-legacy-s2a",
          "timezone": "UTC"
        }
        """
        let decodedLegacyCI = try decoder.decode(CloudInitSpec.self, from: Data(minimalLegacyCloudInitJSON.utf8))
        #expect(decodedLegacyCI.instanceID == "vm-legacy-s2a")
        #expect(decodedLegacyCI.hostname == "legacy-host")

        // 2. CloudInitSpec JSON WITH bootCommands must decode and preserve bootCommands on re-encode
        let withBootCommandsJSON = """
        {
          "aptPackages": [],
          "bootCommands": [
            ["sh", "-c", "mkdir -p /workspace && chmod 0755 /workspace"],
            ["cloud-init-per", "instance", "avm-machine-id", "sh", "-c", "rm -f /etc/machine-id /var/lib/dbus/machine-id && systemd-machine-id-setup && ln -sf /etc/machine-id /var/lib/dbus/machine-id"]
          ],
          "defaultUser": "agent",
          "hostname": "forked-host",
          "injectGuestVsockAgent": true,
          "instanceID": "vm-forked-s2a",
          "nameservers": [],
          "runCommands": [],
          "sshAuthorizedKeys": [],
          "timezone": "UTC",
          "writeFiles": []
        }
        """
        let decodedWithBootCmds = try decoder.decode(CloudInitSpec.self, from: Data(withBootCommandsJSON.utf8))
        let reencodedData = try encoder.encode(decodedWithBootCmds)
        let reencodedObj = try #require(try JSONSerialization.jsonObject(with: reencodedData) as? [String: Any])
        let roundTrippedBootCmds = reencodedObj["bootCommands"] as? [[String]]
        #expect(roundTrippedBootCmds?.count == 2)
        #expect(roundTrippedBootCmds?.first == ["sh", "-c", "mkdir -p /workspace && chmod 0755 /workspace"])

        // 3. SQLite workspace containing a pre-M3 spec_json (explicitly stripped of bootCommands) decodes cleanly and forks
        let bundleURL = tempDir.appendingPathComponent("LegacySpecFleet.agentvm", isDirectory: true)
        var legacyParentID = VMID("vm-placeholder")
        do {
            let coordinator = try AgentVMFleetCoordinator(bundleURL: bundleURL)
            let created = try await coordinator.createSandboxVM(name: "legacy-db-vm", diskVirtualBytes: 16 * 1024 * 1024)
            legacyParentID = created.vmRecord.id
        }

        do {
            let rawDB = try SQLiteWALDatabase(
                fileURL: bundleURL.appendingPathComponent("state.sqlite"),
                runMigrations: false
            )
            let row = try #require(try rawDB.queryOne(
                "SELECT spec_json FROM vms WHERE id = ?;",
                bindings: [legacyParentID.rawValue.sqliteValue]
            ))
            let specJSON = try row.string("spec_json")
            var specObj = try #require(try JSONSerialization.jsonObject(with: Data(specJSON.utf8)) as? [String: Any])
            if var ciObj = specObj["cloudInit"] as? [String: Any] {
                ciObj.removeValue(forKey: "bootCommands")
                specObj["cloudInit"] = ciObj
            }
            let strippedSpecData = try JSONSerialization.data(withJSONObject: specObj, options: [.sortedKeys])
            let strippedSpecString = String(decoding: strippedSpecData, as: UTF8.self)
            #expect(!strippedSpecString.contains("bootCommands"))
            try rawDB.execute(
                "UPDATE vms SET spec_json = ? WHERE id = ?;",
                bindings: [strippedSpecString.sqliteValue, legacyParentID.rawValue.sqliteValue]
            )
        }

        let reopenedCoordinator = try AgentVMFleetCoordinator(bundleURL: bundleURL)
        let fetchedLegacyParent = try #require(try await reopenedCoordinator.store.fetchVM(legacyParentID))
        #expect(fetchedLegacyParent.spec.name == "legacy-db-vm")

        let forkedFromLegacy = try await reopenedCoordinator.forkCoWBranch(
            fromVMID: legacyParentID,
            branchName: "legacy-child",
            agentOwnerTag: "worker",
            bootImmediately: false
        )

        let verifyDB = try SQLiteWALDatabase(
            fileURL: bundleURL.appendingPathComponent("state.sqlite"),
            runMigrations: false
        )
        let childRow = try #require(try verifyDB.queryOne(
            "SELECT spec_json FROM vms WHERE id = ?;",
            bindings: [forkedFromLegacy.childVM.id.rawValue.sqliteValue]
        ))
        let childSpecJSON = try childRow.string("spec_json")
        #expect(childSpecJSON.contains("bootCommands"))
        #expect(childSpecJSON.contains("avm-machine-id"))
    }

    // MARK: - 5. Legacy v1.3.0 Guest Daemon Script & runCommands Replaced on Fork (Pitfall 1)

    @Test("Forking a legacy parent VM replaces stale v1.0.0 guest daemon writeFiles and runCommands with current v2 bootstrap while preserving custom user entries")
    func forkReplacesStaleParentGuestBootstrapFilesAndRunCommandsWithCurrentVersion() async throws {
        let tempDir = try makeTempDirectory(prefix: "avm-s2a-bootstrap-upgrade")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let bundleURL = tempDir.appendingPathComponent("UpgradeFleet.agentvm", isDirectory: true)
        let coordinator = try AgentVMFleetCoordinator(bundleURL: bundleURL)
        let currentBootstrap = GuestAgentBootstrapGenerator()

        let created = try await coordinator.createSandboxVM(
            name: "oldp",
            diskVirtualBytes: 16 * 1024 * 1024
        )
        let parentID = created.vmRecord.id

        // Mutate parent's persisted CloudInitSpec to match a pre-M2 (v1.2.0 / v1.3.0) VM with stale 1.0.0 daemon script
        var staleParent = try #require(try await coordinator.store.fetchVM(parentID))
        let staleScriptV1 = """
        #!/usr/bin/env python3
        AGENT_META = {"agentVersion": "1.0.0"}
        print("legacy-guestd-1.0.0")
        """
        let staleUnitV1 = """
        [Unit]
        Description=Legacy AgentVM v1.3.0 Unit
        [Service]
        WorkingDirectory=/workspace
        ExecStart=/usr/bin/python3 -u /usr/local/sbin/agentvm-guestd.py --port 1025
        """
        let staleModulesV1 = """
        # Legacy modules without virtio_console
        vsock
        vmw_vsock_virtio_transport
        """
        staleParent.spec.cloudInit = CloudInitSpec(
            instanceID: parentID.rawValue,
            hostname: "oldp",
            defaultUser: "agent",
            writeFiles: [
                CloudInitWriteFile(
                    guestPath: GuestAgentBootstrapGenerator.defaultModulesLoadGuestPath,
                    permissionsOctal: "0644",
                    owner: "root:root",
                    content: staleModulesV1
                ),
                CloudInitWriteFile(
                    guestPath: GuestAgentBootstrapGenerator.defaultDaemonGuestPath,
                    permissionsOctal: "0755",
                    owner: "root:root",
                    content: staleScriptV1
                ),
                CloudInitWriteFile(
                    guestPath: GuestAgentBootstrapGenerator.defaultSystemdUnitGuestPath,
                    permissionsOctal: "0644",
                    owner: "root:root",
                    content: staleUnitV1
                ),
                CloudInitWriteFile(
                    guestPath: "/etc/agentvm-custom-marker",
                    permissionsOctal: "0644",
                    owner: "root:root",
                    content: "custom-marker=keep\n"
                )
            ],
            runCommands: [
                "mkdir -p /workspace",
                "modprobe virtio_vsock || modprobe vmw_vsock_virtio_transport || true",
                "systemctl daemon-reload",
                "systemctl enable --now agentvm-guestd.service",
                "echo custom-user-runcmd"
            ],
            injectGuestVsockAgent: true
        )
        try await coordinator.store.upsertVM(staleParent)

        let forked = try await coordinator.forkCoWBranch(
            fromVMID: parentID,
            branchName: "oldc_cold",
            agentOwnerTag: "worker",
            bootImmediately: false
        )

        let childCI = try #require(forked.childVM.spec.cloudInit)

        // 1. Daemon script, systemd unit, and modules-load file must all be replaced (not skipped by deduplication!)
        let daemonEntries = childCI.writeFiles.filter {
            $0.guestPath == GuestAgentBootstrapGenerator.defaultDaemonGuestPath
        }
        #expect(daemonEntries.count == 1)
        #expect(daemonEntries.first?.content == currentBootstrap.pythonDaemonScript())
        #expect(daemonEntries.first?.content.contains("\"agentVersion\": \"2\"") == true)
        #expect(daemonEntries.first?.content.contains("legacy-guestd-1.0.0") == false)

        let unitEntries = childCI.writeFiles.filter {
            $0.guestPath == GuestAgentBootstrapGenerator.defaultSystemdUnitGuestPath
        }
        #expect(unitEntries.count == 1)
        #expect(unitEntries.first?.content == currentBootstrap.systemdServiceUnit())

        let modEntries = childCI.writeFiles.filter {
            $0.guestPath == GuestAgentBootstrapGenerator.defaultModulesLoadGuestPath
        }
        #expect(modEntries.count == 1)
        #expect(modEntries.first?.content == currentBootstrap.kernelModulesConfig())

        // Custom user writeFiles entry must be preserved
        #expect(childCI.writeFiles.contains { $0.guestPath == "/etc/agentvm-custom-marker" && $0.content == "custom-marker=keep\n" })

        // 2. runCommands must drop stale 'modprobe virtio_vsock ...', keep custom command, and place 'sync' BEFORE 'systemctl enable --now agentvm-guestd.service'
        #expect(!childCI.runCommands.contains("modprobe virtio_vsock || modprobe vmw_vsock_virtio_transport || true"))
        #expect(childCI.runCommands.contains("echo custom-user-runcmd"))
        let syncIdx = childCI.runCommands.firstIndex(of: "sync")
        let enableIdx = childCI.runCommands.firstIndex(of: "systemctl enable --now agentvm-guestd.service")
        #expect(syncIdx != nil)
        #expect(enableIdx != nil)
        if let syncIdx, let enableIdx {
            #expect(syncIdx < enableIdx)
        }

        // 3. Generated child ISO user-data must also contain the v2 script and NOT the legacy 1.0.0 script
        let childISOFiles = try inspectISOFiles(at: try #require(forked.childVM.spec.cloudInitISOPath))
        let childUserData = try #require(childISOFiles["user-data"])
        #expect(childUserData.contains("\"agentVersion\": \"2\""))
        #expect(!childUserData.contains("legacy-guestd-1.0.0"))
        #expect(childUserData.contains("/etc/agentvm-custom-marker"))
    }
}
