import AgentVMCLIAndMCP
import AgentVMHypervisor
import AgentVMModels
import AgentVMStorageCoW
import AgentVMStore
import AgentVMVsockRPC
import Darwin
import Foundation
import Testing

@Suite("M2 Stage 6: Live Guest Telemetry Fields, Heartbeat Mapping, 15s Expiration, SQLite Writeback, and ps JSON/Text", .serialized, .timeLimit(.minutes(2)))
struct CLIAndMCPDaemonStage6Tests {

    private static func makeShortDarwinTempWorkspaceBase(prefix: String = "avm-s6") throws -> String {
        var cTemplate = Array("/tmp/\(prefix).XXXXXX".utf8CString)
        let createdPtr = cTemplate.withUnsafeMutableBufferPointer { buf in
            Darwin.mkdtemp(buf.baseAddress)
        }
        guard let createdPtr else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(Darwin.errno))
        }
        let raw = String(cString: createdPtr)
        return DaemonSocketAddressResolver.canonicalRealPath(of: URL(fileURLWithPath: raw, isDirectory: true))
    }

    private static func sweepDarwinUserTempSymlinks(pointingUnder basePath: String) {
        guard let darwinTempDir = try? DaemonSocketAddressResolver.darwinUserTempDirectoryURL() else {
            return
        }
        let canonicalBase = DaemonSocketAddressResolver.canonicalRealPath(
            of: URL(fileURLWithPath: basePath, isDirectory: true)
        )
        var prefixes = [canonicalBase]
        if canonicalBase.hasPrefix("/private/tmp/") {
            prefixes.append(String(canonicalBase.dropFirst("/private".count)))
        } else if canonicalBase.hasPrefix("/tmp/") {
            prefixes.append("/private" + canonicalBase)
        }
        let uniquePrefixes = Array(Set(prefixes))

        guard let names = try? FileManager.default.contentsOfDirectory(atPath: darwinTempDir.path) else {
            return
        }
        for name in names where name.hasPrefix("avm-") {
            let linkPath = darwinTempDir.appendingPathComponent(name, isDirectory: false).path
            var st = Darwin.stat()
            guard Darwin.lstat(linkPath, &st) == 0, (st.st_mode & S_IFMT) == S_IFLNK else {
                continue
            }
            var buf = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
            let len = Darwin.readlink(linkPath, &buf, Int(PATH_MAX))
            guard len > 0 else { continue }
            let rawTarget = String(decoding: buf.prefix(len).map { UInt8(bitPattern: $0) }, as: UTF8.self)
            let resolvedTarget: String
            if rawTarget.hasPrefix("/") {
                resolvedTarget = DaemonSocketAddressResolver.canonicalRealPath(
                    of: URL(fileURLWithPath: rawTarget, isDirectory: true)
                )
            } else {
                resolvedTarget = DaemonSocketAddressResolver.canonicalRealPath(
                    of: darwinTempDir.appendingPathComponent(rawTarget, isDirectory: true)
                )
            }
            let matches = uniquePrefixes.contains { prefix in
                rawTarget == prefix
                    || rawTarget.hasPrefix(prefix + "/")
                    || resolvedTarget == prefix
                    || resolvedTarget.hasPrefix(prefix + "/")
            }
            if matches {
                _ = Darwin.unlink(linkPath)
            }
        }
    }

    private func stageBootableCachedImage(
        in baseDir: String,
        imageID: String = "debian-12-bookworm-arm64"
    ) async throws -> (cacheDir: URL, cachedFileURL: URL, entry: BaseImageCatalogEntry) {
        let cacheDir = URL(fileURLWithPath: "\(baseDir)/cache", isDirectory: true)
        let imageBytes = 4 * 1024 * 1024
        let stagingURL = URL(fileURLWithPath: "\(baseDir)/staging-\(UUID().uuidString).raw")
        try APFSCoWDiskEngine().createSparseRawDisk(at: stagingURL, virtualSizeBytes: UInt64(imageBytes), overwrite: true)
        let parts = try PartitionAndContainerInspector().writeProtectiveMBRAndGPT(
            to: stagingURL,
            partitions: [(name: "RootExt4", typeGUID: GPTWellKnownTypeGUID.linuxRootARM64.rawValue, sizeBytes: 2 * 1024 * 1024)]
        )
        var ext4Super = [UInt8](repeating: 0, count: 256)
        ext4Super[0x38] = 0x53
        ext4Super[0x39] = 0xEF
        ext4Super[0x5C] = 0x04
        ext4Super[0x60] = 0xC0
        let fh = try FileHandle(forUpdating: stagingURL)
        try fh.seek(toOffset: parts[0].firstLBA * 512 + 1024)
        try fh.write(contentsOf: Data(ext4Super))
        try fh.close()

        let sha512 = try BinaryChecksums.sha512HexFile(at: stagingURL)
        let entry = BaseImageCatalogEntry(
            id: imageID,
            displayName: "Debian 12 Test Image",
            distribution: "debian",
            version: "20261112-2660",
            guestOS: .linuxARM64,
            isSupported: true,
            downloadURL: "https://offline.agentvm.invalid/debian.raw",
            expectedSHA512: sha512,
            expectedSizeBytes: UInt64(imageBytes),
            defaultVirtualSizeBytes: UInt64(imageBytes)
        )
        let seeder = try BaseImageRegistryCatalog(cacheDirectoryURL: cacheDir, curatedEntries: [entry], createIfMissing: true)
        let staged = try await seeder.stageCachedCuratedImage(id: imageID, from: stagingURL, verifyChecksum: true)
        try? FileManager.default.removeItem(at: stagingURL)
        let cachedURL = URL(fileURLWithPath: try #require(staged.cachedLocalPath)).standardizedFileURL
        #expect(Darwin.chmod(cachedURL.path, 0o444) == 0)
        return (cacheDir, cachedURL, entry)
    }

    private static func parsePlainPSTableRow(
        stdout: String,
        vmName: String
    ) -> (state: String, cpu: String, memory: String)? {
        let lines = stdout
            .split(whereSeparator: \.isNewline)
            .map(String.init)
            .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
        guard lines.count >= 2 else { return nil }
        let header = lines[0]
        guard let stateRange = header.range(of: "STATE"),
              let cpuRange = header.range(of: "CPU"),
              let memRange = header.range(of: "MEMORY"),
              let ipRange = header.range(of: "IPV4") else {
            return nil
        }
        let stateOffset = header.distance(from: header.startIndex, to: stateRange.lowerBound)
        let cpuOffset = header.distance(from: header.startIndex, to: cpuRange.lowerBound)
        let memOffset = header.distance(from: header.startIndex, to: memRange.lowerBound)
        let ipOffset = header.distance(from: header.startIndex, to: ipRange.lowerBound)

        for row in lines.dropFirst() {
            guard row.contains(" \(vmName) "), row.count >= ipOffset else { continue }
            let sIdx = row.index(row.startIndex, offsetBy: stateOffset)
            let cIdx = row.index(row.startIndex, offsetBy: cpuOffset)
            let mIdx = row.index(row.startIndex, offsetBy: memOffset)
            let iIdx = row.index(row.startIndex, offsetBy: ipOffset)
            let stateVal = String(row[sIdx..<cIdx]).trimmingCharacters(in: .whitespaces)
            let cpuVal = String(row[cIdx..<mIdx]).trimmingCharacters(in: .whitespaces)
            let memVal = String(row[mIdx..<iIdx]).trimmingCharacters(in: .whitespaces)
            return (state: stateVal, cpu: cpuVal, memory: memVal)
        }
        return nil
    }

    private static func parseISO8601Timestamp(_ raw: String) -> Date? {
        let frac = ISO8601DateFormatter()
        frac.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = frac.date(from: raw) { return d }
        let basic = ISO8601DateFormatter()
        basic.formatOptions = [.withInternetDateTime]
        return basic.date(from: raw)
    }

    // MARK: - Item 1: `VMLiveTelemetry` New Optional Fields & Legacy `decodeIfPresent` Compatibility

    @Test("Item 1: VMLiveTelemetry preserves guestMemTotalBytes, guestMemAvailableBytes, and guestAgentVersion via Codable, while legacy JSON without new keys still decodes")
    func vmLiveTelemetryNewFieldsAndLegacyDecodeIfPresent() throws {
        // 1. Legacy JSON lacking `guestMemTotalBytes`, `guestMemAvailableBytes`, `guestAgentVersion`, and `cpuUsagePercent`.
        let base = VMLiveTelemetry(vmID: VMID("vm-legacy-s6"), state: .running, guestAgentConnected: true)
        var legacyDict = try #require(
            try JSONSerialization.jsonObject(with: JSONEncoder().encode(base)) as? [String: Any]
        )
        legacyDict.removeValue(forKey: "guestMemTotalBytes")
        legacyDict.removeValue(forKey: "guestMemAvailableBytes")
        legacyDict.removeValue(forKey: "guestAgentVersion")
        legacyDict.removeValue(forKey: "cpuUsagePercent")

        let legacyData = try JSONSerialization.data(withJSONObject: legacyDict)
        let decodedLegacy = try JSONDecoder().decode(VMLiveTelemetry.self, from: legacyData)
        #expect(decodedLegacy.vmID == VMID("vm-legacy-s6"))
        #expect(decodedLegacy.state == .running)
        #expect(decodedLegacy.formattedCPUUsage == "—")

        let reencodedLegacyDict = try #require(
            try JSONSerialization.jsonObject(with: JSONEncoder().encode(decodedLegacy)) as? [String: Any]
        )
        #expect(reencodedLegacyDict["guestMemTotalBytes"] == nil)
        #expect(reencodedLegacyDict["guestMemAvailableBytes"] == nil)
        #expect(reencodedLegacyDict["guestAgentVersion"] == nil)

        // 2. Populated JSON with `guestMemTotalBytes`, `guestMemAvailableBytes`, `guestAgentVersion`, and `cpuUsagePercent`.
        var fullDict = legacyDict
        fullDict["guestMemTotalBytes"] = UInt64(2_080_374_784)
        fullDict["guestMemAvailableBytes"] = UInt64(1_543_503_872)
        fullDict["guestAgentVersion"] = "2"
        fullDict["cpuUsagePercent"] = 41.25
        fullDict["hasLiveGuestTelemetry"] = true
        fullDict["memoryResidentMB"] = UInt64(512)

        let fullData = try JSONSerialization.data(withJSONObject: fullDict)
        let decodedFull = try JSONDecoder().decode(VMLiveTelemetry.self, from: fullData)
        let roundTrippedDict = try #require(
            try JSONSerialization.jsonObject(with: JSONEncoder().encode(decodedFull)) as? [String: Any]
        )
        #expect((roundTrippedDict["guestMemTotalBytes"] as? NSNumber)?.uint64Value == 2_080_374_784, "VMLiveTelemetry must decode and preserve guestMemTotalBytes")
        #expect((roundTrippedDict["guestMemAvailableBytes"] as? NSNumber)?.uint64Value == 1_543_503_872, "VMLiveTelemetry must decode and preserve guestMemAvailableBytes")
        #expect(roundTrippedDict["guestAgentVersion"] as? String == "2", "VMLiveTelemetry must decode and preserve guestAgentVersion")
        #expect((roundTrippedDict["cpuUsagePercent"] as? NSNumber)?.doubleValue == 41.25)
        #expect(decodedFull.formattedCPUUsage == "41.2%")
        #expect(decodedFull.formattedMemoryResident == "512 MB")
    }

    // MARK: - Items 2 & 5: Heartbeat Mapping, Unknown CPU Handling, `sampledAt` Receipt Time, Handshake Version, and `ps --json` / `ps` Text

    @Test("Items 2 & 5: daemon maps heartbeat memory/CPU/uptime/sampledAt/guestAgentVersion, keeps missing cpuUsagePercent unknown (not 0) on 1st beat and 1.0.0 guests, and formats ps --json & ps text")
    func daemonHeartbeatMappingUnknownCPUAndPSOutputs() async throws {
        let realBase = try Self.makeShortDarwinTempWorkspaceBase(prefix: "avm-s6-m25")
        defer {
            Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase)
            try? FileManager.default.removeItem(atPath: realBase)
        }

        let guestV2 = try Stage6UnixGuestTelemetryServer(tag: "s6g2", advertisedVersion: "2")
        defer { guestV2.shutdown() }

        let guestV1 = try Stage6UnixGuestTelemetryServer(tag: "s6g1", advertisedVersion: "1.0.0")
        defer { guestV1.shutdown() }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/MapS6.agentvm", isDirectory: true)
        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()
        let forbiddenSpawn = DaemonSpawnCommandOverride(
            executablePath: "/bin/sh",
            arguments: ["-c", "exit 96"],
            environment: env
        )

        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "create", "t1", "--image", entry.id],
            curatedEntriesOverride: [entry],
            environment: env
        ).exitCode == 0)
        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "create", "t2", "--image", entry.id],
            curatedEntriesOverride: [entry],
            environment: env
        ).exitCode == 0)

        let backend = Stage6PerVMUnixHardwareBackend(socketPathByVMName: [
            "t1": guestV2.sockPath,
            "t2": guestV1.sockPath
        ])

        let startOutcome = try await WorkspaceDaemonServer.start(
            workspaceURL: wsURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: backend,
            vsockConnectTimeoutNanoseconds: 5_000_000_000,
            vsockRetryIntervalNanoseconds: 100_000_000,
            gracefulStopTimeoutNanoseconds: 120_000_000
        )
        guard case let .started(server) = startOutcome else {
            Issue.record("Expected WorkspaceDaemonServer.start to succeed")
            return
        }
        defer {
            server.listener.close(unlinkSocket: true, removeSymlink: true)
            server.singletonLock.release(clearFile: true)
            server.logManager.close()
        }

        do {
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)

            // 1. Send Heartbeat #1 on `t1` (v2 guest): omits `cpuUsagePercent`, reports MemTotal=2048 MiB, MemAvailable=1536 MiB -> resident=512 MB.
            //    Use a 2023 guest `reportedAt` to prove `sampledAt` is host receipt time rather than guest clock.
            let hostBeforeBeat1 = Date()
            try guestV2.sendRawHeartbeatJSON([
                "hostname": "debian-t1",
                "kernelRelease": "6.1.0-27-arm64",
                "uptimeSeconds": 42.5,
                "loadAvg1": 0.12,
                "loadAvg5": 0.05,
                "loadAvg15": 0.01,
                "memTotalBytes": UInt64(2_147_483_648),
                "memAvailableBytes": UInt64(1_610_612_736),
                "rootFilesystemUsedBytes": UInt64(2_000_000_000),
                "rootFilesystemTotalBytes": UInt64(20_000_000_000),
                "topProcesses": [],
                "reportedAt": 1_700_000_000.0
            ])
            try await Task.sleep(nanoseconds: 150_000_000)
            let hostAfterBeat1 = Date()

            let psJSON1 = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "ps", "--json"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(psJSON1.exitCode == 0)
            let arr1 = try #require(try JSONSerialization.jsonObject(with: Data(psJSON1.stdout.utf8)) as? [[String: Any]])
            let t1Obj1 = try #require(arr1.first(where: { ($0["spec"] as? [String: Any])?["name"] as? String == "t1" }))
            let tel1 = try #require(t1Obj1["telemetry"] as? [String: Any])

            #expect(tel1["hasLiveGuestTelemetry"] as? Bool == true, "Heartbeat must set hasLiveGuestTelemetry = true")
            #expect((tel1["memoryResidentMB"] as? NSNumber)?.uint64Value == 512, "memoryResidentMB must equal (MemTotal - MemAvailable) / 1 MiB == 512")
            #expect((tel1["guestMemTotalBytes"] as? NSNumber)?.uint64Value == 2_147_483_648)
            #expect((tel1["guestMemAvailableBytes"] as? NSNumber)?.uint64Value == 1_610_612_736)
            #expect(tel1["guestAgentVersion"] as? String == "2", "ps --json telemetry must include negotiated guestAgentVersion")
            #expect((tel1["uptimeSeconds"] as? NSNumber)?.doubleValue == 42.5)
            #expect(tel1["cpuUsagePercent"] == nil, "Missing cpuUsagePercent in heartbeat must stay unknown (nil), NOT 0")

            let sampled1Raw = try #require(tel1["sampledAt"] as? String)
            let sampled1Date = try #require(Self.parseISO8601Timestamp(sampled1Raw))
            #expect(sampled1Date >= hostBeforeBeat1.addingTimeInterval(-2.0) && sampled1Date <= hostAfterBeat1.addingTimeInterval(2.0), "sampledAt must reflect host daemon receipt time, not guest reportedAt (got \(sampled1Raw))")

            let psText1 = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "ps"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(psText1.exitCode == 0)
            let row1 = try #require(Self.parsePlainPSTableRow(stdout: psText1.stdout, vmName: "t1"))
            #expect(row1.state == "running")
            #expect(row1.cpu == "—", "Plain ps CPU column must show '—' when heartbeat omits cpuUsagePercent, got '\(row1.cpu)'")
            #expect(row1.memory == "512 MB", "Plain ps MEMORY column must show '512 MB', got '\(row1.memory)'")

            // 2. Sleep 1.1s so ISO-8601 sampledAt advances, then send Heartbeat #2 WITH `cpuUsagePercent = 47.6` and MemAvailable=1024 MiB -> resident=1024 MB.
            try await Task.sleep(nanoseconds: 1_150_000_000)
            try guestV2.sendRawHeartbeatJSON([
                "hostname": "debian-t1",
                "kernelRelease": "6.1.0-27-arm64",
                "uptimeSeconds": 53.75,
                "loadAvg1": 0.85,
                "loadAvg5": 0.25,
                "loadAvg15": 0.05,
                "memTotalBytes": UInt64(2_147_483_648),
                "memAvailableBytes": UInt64(1_073_741_824),
                "cpuUsagePercent": 47.6,
                "rootFilesystemUsedBytes": UInt64(2_000_000_000),
                "rootFilesystemTotalBytes": UInt64(20_000_000_000),
                "topProcesses": [],
                "reportedAt": 1_700_000_010.0
            ])
            try await Task.sleep(nanoseconds: 150_000_000)

            let psJSON2 = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "ps", "--json"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            #expect(psJSON2.exitCode == 0)
            let arr2 = try #require(try JSONSerialization.jsonObject(with: Data(psJSON2.stdout.utf8)) as? [[String: Any]])
            let t1Obj2 = try #require(arr2.first(where: { ($0["spec"] as? [String: Any])?["name"] as? String == "t1" }))
            let tel2 = try #require(t1Obj2["telemetry"] as? [String: Any])

            let cpu2 = (tel2["cpuUsagePercent"] as? NSNumber)?.doubleValue
            #expect(cpu2 != nil)
            if let cpu2 {
                #expect(abs(cpu2 - 47.6) < 0.01)
            }
            #expect((tel2["memoryResidentMB"] as? NSNumber)?.uint64Value == 1024)
            #expect((tel2["uptimeSeconds"] as? NSNumber)?.doubleValue == 53.75)
            let sampled2Raw = try #require(tel2["sampledAt"] as? String)
            #expect(sampled2Raw != sampled1Raw, "sampledAt must advance across heartbeats")

            let psText2 = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "ps"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            let row2 = try #require(Self.parsePlainPSTableRow(stdout: psText2.stdout, vmName: "t1"))
            #expect(row2.cpu == "47.6%", "Plain ps CPU column must show '47.6%' when heartbeat includes cpuUsagePercent")
            #expect(row2.memory == "1024 MB")

            // 3. Boot `t2` backed by a `1.0.0` legacy guest sending heartbeats without `cpuUsagePercent`:
            //    `guestAgentVersion` is `"1.0.0"`, MEMORY is numeric (`256 MB`), and CPU remains `'—'` (unknown).
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t2"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)

            try guestV1.sendRawHeartbeatJSON([
                "hostname": "debian-legacy",
                "kernelRelease": "6.1.0-18-arm64",
                "uptimeSeconds": 19.0,
                "loadAvg1": 0.01,
                "loadAvg5": 0.01,
                "loadAvg15": 0.0,
                "memTotalBytes": UInt64(2_147_483_648),
                "memAvailableBytes": UInt64(1_879_048_192),
                "rootFilesystemUsedBytes": UInt64(1_500_000_000),
                "rootFilesystemTotalBytes": UInt64(20_000_000_000),
                "topProcesses": [],
                "reportedAt": 1_700_000_020.0
            ])
            try await Task.sleep(nanoseconds: 150_000_000)

            let psJSON3 = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "ps", "--json"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            let arr3 = try #require(try JSONSerialization.jsonObject(with: Data(psJSON3.stdout.utf8)) as? [[String: Any]])
            let t2Obj = try #require(arr3.first(where: { ($0["spec"] as? [String: Any])?["name"] as? String == "t2" }))
            let t2Tel = try #require(t2Obj["telemetry"] as? [String: Any])
            #expect(t2Tel["guestAgentVersion"] as? String == "1.0.0")
            #expect(t2Tel["hasLiveGuestTelemetry"] as? Bool == true)
            #expect((t2Tel["memoryResidentMB"] as? NSNumber)?.uint64Value == 256)
            #expect(t2Tel["cpuUsagePercent"] == nil)

            let psText3 = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "ps"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            let t2Row = try #require(Self.parsePlainPSTableRow(stdout: psText3.stdout, vmName: "t2"))
            #expect(t2Row.cpu == "—", "Legacy 1.0.0 guest without cpuUsagePercent must display CPU '—'")
            #expect(t2Row.memory == "256 MB")

            await server.stopAndCleanup()
        } catch {
            await server.stopAndCleanup()
            throw error
        }
    }

    // MARK: - Item 3: 15-Second Staleness Expiration, `pause`, and `halt` Reset `hasLiveGuestTelemetry = false` and `ps` `'—'`

    @Test("Item 3: hasLiveGuestTelemetry stays true under 15s, resets to false after 15s without heartbeat, and resets on pause and halt with ps showing '—'")
    func daemonTelemetryStaleAfter15SecondsAndOnPauseAndHalt() async throws {
        let realBase = try Self.makeShortDarwinTempWorkspaceBase(prefix: "avm-s6-exp")
        defer {
            Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase)
            try? FileManager.default.removeItem(atPath: realBase)
        }

        let guest = try Stage6UnixGuestTelemetryServer(tag: "s6ex", advertisedVersion: "2")
        defer { guest.shutdown() }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/ExpS6.agentvm", isDirectory: true)
        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()
        let forbiddenSpawn = DaemonSpawnCommandOverride(
            executablePath: "/bin/sh",
            arguments: ["-c", "exit 96"],
            environment: env
        )

        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "create", "t1", "--image", entry.id],
            curatedEntriesOverride: [entry],
            environment: env
        ).exitCode == 0)

        let backend = Stage6PerVMUnixHardwareBackend(socketPathByVMName: ["t1": guest.sockPath])
        let startOutcome = try await WorkspaceDaemonServer.start(
            workspaceURL: wsURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: backend,
            vsockConnectTimeoutNanoseconds: 5_000_000_000,
            vsockRetryIntervalNanoseconds: 100_000_000,
            gracefulStopTimeoutNanoseconds: 120_000_000
        )
        guard case let .started(server) = startOutcome else {
            Issue.record("Expected WorkspaceDaemonServer.start to succeed")
            return
        }
        defer {
            server.listener.close(unlinkSocket: true, removeSymlink: true)
            server.singletonLock.release(clearFile: true)
            server.logManager.close()
        }

        do {
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)

            // 1. Fresh heartbeat -> `hasLiveGuestTelemetry == true`, numeric CPU & MEMORY in `ps`.
            try guest.sendRawHeartbeatJSON([
                "hostname": "debian-t1",
                "kernelRelease": "6.1.0-27-arm64",
                "uptimeSeconds": 30.0,
                "loadAvg1": 0.3,
                "loadAvg5": 0.2,
                "loadAvg15": 0.1,
                "memTotalBytes": UInt64(2_097_152_000),
                "memAvailableBytes": UInt64(1_782_579_200),
                "cpuUsagePercent": 33.3,
                "rootFilesystemUsedBytes": UInt64(2_000_000_000),
                "rootFilesystemTotalBytes": UInt64(20_000_000_000),
                "topProcesses": [],
                "reportedAt": Date().timeIntervalSince1970
            ])
            try await Task.sleep(nanoseconds: 150_000_000)

            let freshText = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "ps"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            let freshRow = try #require(Self.parsePlainPSTableRow(stdout: freshText.stdout, vmName: "t1"))
            #expect(freshRow.cpu == "33.3%")
            #expect(freshRow.memory == "300 MB")

            // 2. At ~11.0s (< 15s threshold): still fresh!
            try await Task.sleep(nanoseconds: 11_000_000_000)
            let midText = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "ps"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            let midRow = try #require(Self.parsePlainPSTableRow(stdout: midText.stdout, vmName: "t1"))
            #expect(midRow.cpu == "33.3%", "Telemetry must remain live before 15s threshold")
            #expect(midRow.memory == "300 MB")

            // 3. At ~15.6s (> 15s without new heartbeat): must expire to `hasLiveGuestTelemetry = false` and `'—'`!
            try await Task.sleep(nanoseconds: 4_600_000_000)
            let staleJSON = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "ps", "--json"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            let staleArr = try #require(try JSONSerialization.jsonObject(with: Data(staleJSON.stdout.utf8)) as? [[String: Any]])
            let staleTel = try #require((staleArr.first?["telemetry"]) as? [String: Any])
            #expect(staleTel["hasLiveGuestTelemetry"] as? Bool == false, "15s without heartbeat must set hasLiveGuestTelemetry = false")

            let staleText = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "ps"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            let staleRow = try #require(Self.parsePlainPSTableRow(stdout: staleText.stdout, vmName: "t1"))
            #expect(staleRow.state == "running")
            #expect(staleRow.cpu == "—", "Expired telemetry must show CPU '—'")
            #expect(staleRow.memory == "—", "Expired telemetry must show MEMORY '—'")

            // 4. New heartbeat revives telemetry; then `pause t1` immediately clears `hasLiveGuestTelemetry` -> `'—'`.
            try guest.sendRawHeartbeatJSON([
                "hostname": "debian-t1",
                "kernelRelease": "6.1.0-27-arm64",
                "uptimeSeconds": 48.0,
                "loadAvg1": 0.2,
                "loadAvg5": 0.2,
                "loadAvg15": 0.1,
                "memTotalBytes": UInt64(2_097_152_000),
                "memAvailableBytes": UInt64(1_677_721_600),
                "cpuUsagePercent": 28.0,
                "rootFilesystemUsedBytes": UInt64(2_000_000_000),
                "rootFilesystemTotalBytes": UInt64(20_000_000_000),
                "topProcesses": [],
                "reportedAt": Date().timeIntervalSince1970
            ])
            try await Task.sleep(nanoseconds: 150_000_000)

            let revivedRow = try #require(Self.parsePlainPSTableRow(
                stdout: await cli.execute(arguments: ["--lang", "en", "--workspace", wsURL.path, "ps"], curatedEntriesOverride: [entry], environment: env, daemonSpawnOverride: forbiddenSpawn).stdout,
                vmName: "t1"
            ))
            #expect(revivedRow.cpu == "28.0%")
            #expect(revivedRow.memory == "400 MB")

            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "pause", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)

            let pausedJSON = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "ps", "--json"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            let pausedArr = try #require(try JSONSerialization.jsonObject(with: Data(pausedJSON.stdout.utf8)) as? [[String: Any]])
            let pausedTel = try #require((pausedArr.first?["telemetry"]) as? [String: Any])
            #expect(pausedTel["state"] as? String == "paused")
            #expect(pausedTel["hasLiveGuestTelemetry"] as? Bool == false)

            let pausedRow = try #require(Self.parsePlainPSTableRow(
                stdout: await cli.execute(arguments: ["--lang", "en", "--workspace", wsURL.path, "ps"], curatedEntriesOverride: [entry], environment: env, daemonSpawnOverride: forbiddenSpawn).stdout,
                vmName: "t1"
            ))
            #expect(pausedRow.state == "paused")
            #expect(pausedRow.cpu == "—")
            #expect(pausedRow.memory == "—")

            // 5. `resume t1` + fresh heartbeat -> live; then `halt t1` -> `stopped` + `hasLiveGuestTelemetry = false` + `'—'`.
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "resume", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)

            try guest.sendRawHeartbeatJSON([
                "hostname": "debian-t1",
                "kernelRelease": "6.1.0-27-arm64",
                "uptimeSeconds": 55.0,
                "loadAvg1": 0.1,
                "loadAvg5": 0.1,
                "loadAvg15": 0.1,
                "memTotalBytes": UInt64(2_097_152_000),
                "memAvailableBytes": UInt64(1_572_864_000),
                "cpuUsagePercent": 19.5,
                "rootFilesystemUsedBytes": UInt64(2_000_000_000),
                "rootFilesystemTotalBytes": UInt64(20_000_000_000),
                "topProcesses": [],
                "reportedAt": Date().timeIntervalSince1970
            ])
            try await Task.sleep(nanoseconds: 150_000_000)

            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)

            let stoppedJSON = await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "ps", "--json"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            )
            let stoppedArr = try #require(try JSONSerialization.jsonObject(with: Data(stoppedJSON.stdout.utf8)) as? [[String: Any]])
            let stoppedTel = try #require((stoppedArr.first?["telemetry"]) as? [String: Any])
            #expect(stoppedTel["state"] as? String == "stopped")
            #expect(stoppedTel["hasLiveGuestTelemetry"] as? Bool == false)

            let stoppedRow = try #require(Self.parsePlainPSTableRow(
                stdout: await cli.execute(arguments: ["--lang", "en", "--workspace", wsURL.path, "ps"], curatedEntriesOverride: [entry], environment: env, daemonSpawnOverride: forbiddenSpawn).stdout,
                vmName: "t1"
            ))
            #expect(stoppedRow.state == "stopped")
            #expect(stoppedRow.cpu == "—")
            #expect(stoppedRow.memory == "—")

            await server.stopAndCleanup()
        } catch {
            await server.stopAndCleanup()
            throw error
        }
    }

    // MARK: - Item 4: Daemon Persists Record to SQLite on Every State Change and Every Heartbeat

    @Test("Item 4: daemon writes VMInstanceRecord to SQLite on every state transition and every heartbeat so direct store readers (UI, MCP, ps fallback) observe current telemetry")
    func daemonPersistsEveryStateChangeAndEveryHeartbeatToSQLite() async throws {
        let realBase = try Self.makeShortDarwinTempWorkspaceBase(prefix: "avm-s6-db")
        defer {
            Self.sweepDarwinUserTempSymlinks(pointingUnder: realBase)
            try? FileManager.default.removeItem(atPath: realBase)
        }

        let guest = try Stage6UnixGuestTelemetryServer(tag: "s6db", advertisedVersion: "2")
        defer { guest.shutdown() }

        let (cacheDir, cachedURL, entry) = try await stageBootableCachedImage(in: realBase)
        defer { _ = Darwin.chmod(cachedURL.path, 0o644) }

        let wsURL = URL(fileURLWithPath: "\(realBase)/DbS6.agentvm", isDirectory: true)
        let isolatedHome = "\(realBase)/home"
        try FileManager.default.createDirectory(atPath: isolatedHome, withIntermediateDirectories: true)
        let env = [
            "HOME": isolatedHome,
            "CFFIXED_USER_HOME": isolatedHome,
            "AGENTVM_IMAGE_CACHE": cacheDir.path
        ]
        let cli = AgentVMCLIRunner()
        let forbiddenSpawn = DaemonSpawnCommandOverride(
            executablePath: "/bin/sh",
            arguments: ["-c", "exit 96"],
            environment: env
        )

        #expect(await cli.execute(
            arguments: ["--lang", "en", "--workspace", wsURL.path, "create", "t1", "--image", entry.id],
            curatedEntriesOverride: [entry],
            environment: env
        ).exitCode == 0)

        let backend = Stage6PerVMUnixHardwareBackend(socketPathByVMName: ["t1": guest.sockPath])
        let startOutcome = try await WorkspaceDaemonServer.start(
            workspaceURL: wsURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry],
            hardwareBackendOverride: backend,
            vsockConnectTimeoutNanoseconds: 5_000_000_000,
            vsockRetryIntervalNanoseconds: 100_000_000,
            gracefulStopTimeoutNanoseconds: 120_000_000
        )
        guard case let .started(server) = startOutcome else {
            Issue.record("Expected WorkspaceDaemonServer.start to succeed")
            return
        }
        defer {
            server.listener.close(unlinkSocket: true, removeSymlink: true)
            server.singletonLock.release(clearFile: true)
            server.logManager.close()
        }

        // Independent SQLite reader & coordinator (representing MCP / Studio UI / no-daemon fallback reader).
        let externalStore = try AgentVMProjectStore(bundleURL: wsURL, createIfMissing: false)
        let externalCoordinator = try AgentVMFleetCoordinator(
            bundleURL: wsURL,
            imageCacheDirectoryURL: cacheDir,
            curatedImageEntries: [entry]
        )

        do {
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "up", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                hasEntitlementOverride: true,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)

            let afterUp = try #require(try await externalStore.listVMs().first)
            #expect(afterUp.telemetry.state == .running)
            #expect(afterUp.telemetry.guestAgentConnected == true)

            // Heartbeat A -> persisted to SQLite without any RPC call.
            try guest.sendRawHeartbeatJSON([
                "hostname": "debian-t1",
                "kernelRelease": "6.1.0-27-arm64",
                "uptimeSeconds": 15.0,
                "loadAvg1": 0.2,
                "loadAvg5": 0.1,
                "loadAvg15": 0.05,
                "memTotalBytes": UInt64(2_147_483_648),
                "memAvailableBytes": UInt64(1_744_830_464),
                "cpuUsagePercent": 22.5,
                "rootFilesystemUsedBytes": UInt64(2_000_000_000),
                "rootFilesystemTotalBytes": UInt64(20_000_000_000),
                "topProcesses": [],
                "reportedAt": Date().timeIntervalSince1970
            ])
            try await Task.sleep(nanoseconds: 150_000_000)

            let dbBeatA = try #require(try await externalStore.listVMs().first)
            #expect(dbBeatA.telemetry.hasLiveGuestTelemetry == true, "Daemon must persist heartbeat A to SQLite")
            #expect(dbBeatA.telemetry.memoryResidentMB == 384)
            #expect(dbBeatA.telemetry.uptimeSeconds == 15.0)
            let dbDictA = try #require(
                try JSONSerialization.jsonObject(with: JSONEncoder().encode(dbBeatA.telemetry)) as? [String: Any]
            )
            #expect((dbDictA["guestMemTotalBytes"] as? NSNumber)?.uint64Value == 2_147_483_648)
            #expect((dbDictA["guestMemAvailableBytes"] as? NSNumber)?.uint64Value == 1_744_830_464)
            #expect(dbDictA["guestAgentVersion"] as? String == "2")
            #expect((dbDictA["cpuUsagePercent"] as? NSNumber)?.doubleValue == 22.5)

            // Heartbeat B -> persisted to SQLite with advanced sampledAt and updated values;
            // externalCoordinator.listVMsForReporting() (used by MCP/UI/ps fallback) sees live running telemetry!
            try await Task.sleep(nanoseconds: 50_000_000)
            try guest.sendRawHeartbeatJSON([
                "hostname": "debian-t1",
                "kernelRelease": "6.1.0-27-arm64",
                "uptimeSeconds": 20.0,
                "loadAvg1": 0.6,
                "loadAvg5": 0.2,
                "loadAvg15": 0.05,
                "memTotalBytes": UInt64(2_147_483_648),
                "memAvailableBytes": UInt64(1_476_395_008),
                "cpuUsagePercent": 61.0,
                "rootFilesystemUsedBytes": UInt64(2_000_000_000),
                "rootFilesystemTotalBytes": UInt64(20_000_000_000),
                "topProcesses": [],
                "reportedAt": Date().timeIntervalSince1970
            ])
            try await Task.sleep(nanoseconds: 150_000_000)

            let reportedViaStore = try #require(try await externalCoordinator.listVMsForReporting().first)
            #expect(reportedViaStore.telemetry.state == .running)
            #expect(reportedViaStore.telemetry.hasLiveGuestTelemetry == true)
            #expect(reportedViaStore.telemetry.memoryResidentMB == 640)
            #expect(reportedViaStore.telemetry.uptimeSeconds == 20.0)
            #expect(reportedViaStore.telemetry.sampledAt > dbBeatA.telemetry.sampledAt)
            #expect(reportedViaStore.telemetry.formattedCPUUsage == "61.0%")
            #expect(reportedViaStore.telemetry.formattedMemoryResident == "640 MB")

            // State changes (`pause`, `resume`, `halt`) also persist immediately to SQLite.
            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "pause", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
            let afterPause = try #require(try await externalStore.listVMs().first)
            #expect(afterPause.telemetry.state == .paused)
            #expect(afterPause.telemetry.hasLiveGuestTelemetry == false)

            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "resume", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
            let afterResume = try #require(try await externalStore.listVMs().first)
            #expect(afterResume.telemetry.state == .running)

            #expect(await cli.execute(
                arguments: ["--lang", "en", "--workspace", wsURL.path, "halt", "t1"],
                curatedEntriesOverride: [entry],
                environment: env,
                daemonSpawnOverride: forbiddenSpawn
            ).exitCode == 0)
            let afterHalt = try #require(try await externalStore.listVMs().first)
            #expect(afterHalt.telemetry.state == .stopped)
            #expect(afterHalt.telemetry.hasLiveGuestTelemetry == false)

            await server.stopAndCleanup()
        } catch {
            await server.stopAndCleanup()
            throw error
        }
    }
}

// MARK: - Simulated AF_UNIX Guest Telemetry Server & Hardware Backend

private final class Stage6UnixGuestTelemetryServer: @unchecked Sendable {
    let sockPath: String
    let advertisedVersion: String

    private let lock = NSLock()
    private let writeLock = NSLock()
    private var listenFD: Int32 = -1
    private var activeConnFD: Int32 = -1
    private var outboundSeq: UInt32 = 0
    private var acceptTask: Task<Void, Never>?

    init(tag: String, advertisedVersion: String) throws {
        let path = "/tmp/avm-\(tag)-\(UUID().uuidString.prefix(8)).sock"
        _ = Darwin.unlink(path)
        self.sockPath = path
        self.advertisedVersion = advertisedVersion

        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(Darwin.errno))
        }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8CString)
        withUnsafeMutableBytes(of: &addr.sun_path) { rawBuf in
            for (idx, b) in bytes.enumerated() {
                rawBuf[idx] = UInt8(bitPattern: b)
            }
        }
        let bindRC = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.bind(fd, saPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bindRC == 0, Darwin.listen(fd, 4) == 0 else {
            let err = Darwin.errno
            _ = Darwin.close(fd)
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(err))
        }
        self.listenFD = fd
        let versionStr = advertisedVersion

        self.acceptTask = Task.detached { [weak self] in
            let cfd = Darwin.accept(fd, nil, nil)
            guard cfd >= 0 else { return }
            var one: Int32 = 1
            _ = Darwin.setsockopt(cfd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            self?.setActiveConn(cfd)

            let codec = VsockWireCodec()
            let acc = VsockStreamAccumulator(codec: codec)
            var scratch = [UInt8](repeating: 0, count: 65_536)

            while !Task.isCancelled {
                let n = Darwin.read(cfd, &scratch, scratch.count)
                if n <= 0 { break }
                guard let frames = try? acc.ingest(Data(scratch.prefix(n))) else { break }
                for (header, _) in frames {
                    if header.channel == .control {
                        let pong = VsockControlEnvelope(kind: .pong, agentVersion: versionStr)
                        if let encoded = try? VsockWireJSON.encode(pong) {
                            _ = try? self?.sendFrame(
                                channel: .control,
                                flags: [.ack, .endOfMessage],
                                streamID: 0,
                                payload: encoded
                            )
                        }
                    }
                }
            }
        }
    }

    private func setActiveConn(_ fd: Int32) {
        lock.withLock { activeConnFD = fd }
    }

    func sendRawHeartbeatJSON(_ jsonObject: [String: Any]) throws {
        let payload = try JSONSerialization.data(withJSONObject: jsonObject)
        _ = try sendFrame(
            channel: .telemetryHeartbeat,
            flags: [.endOfMessage],
            streamID: 0,
            payload: payload
        )
    }

    @discardableResult
    private func sendFrame(
        channel: VsockChannelKind,
        flags: VsockFrameFlags,
        streamID: UInt32,
        payload: Data
    ) throws -> Bool {
        try writeLock.withLock {
            let cfd = lock.withLock { activeConnFD }
            guard cfd >= 0 else { return false }
            outboundSeq &+= 1
            let codec = VsockWireCodec()
            let wire = try codec.encodeFrame(
                channel: channel,
                flags: flags,
                streamID: streamID,
                sequence: outboundSeq,
                payload: payload,
                compressIfBeneficial: false
            )
            return wire.withUnsafeBytes { rawBuf -> Bool in
                guard let base = rawBuf.baseAddress else { return true }
                var offset = 0
                while offset < rawBuf.count {
                    let n = Darwin.write(cfd, base.advanced(by: offset), rawBuf.count - offset)
                    if n > 0 {
                        offset += n
                    } else if n < 0 && Darwin.errno == EINTR {
                        continue
                    } else {
                        return false
                    }
                }
                return true
            }
        }
    }

    func closeActiveConnection() {
        let cfd = lock.withLock { () -> Int32 in
            let cur = activeConnFD
            activeConnFD = -1
            return cur
        }
        if cfd >= 0 {
            _ = Darwin.shutdown(cfd, SHUT_RDWR)
            _ = Darwin.close(cfd)
        }
    }

    func shutdown() {
        acceptTask?.cancel()
        closeActiveConnection()
        let lfd = lock.withLock { () -> Int32 in
            let cur = listenFD
            listenFD = -1
            return cur
        }
        if lfd >= 0 {
            _ = Darwin.close(lfd)
        }
        _ = Darwin.unlink(sockPath)
    }
}

private final class Stage6PerVMUnixHardwareBackend: HardwareVMLowLevelBackend, @unchecked Sendable {
    private let socketPathByVMName: [String: String]

    init(socketPathByVMName: [String: String]) {
        self.socketPathByVMName = socketPathByVMName
    }

    func startMachine(
        spec: VMSpec,
        networkSocketFD: Int32?,
        consoleLogURL: URL,
        translator: VZConfigurationTranslator
    ) async throws -> any HardwareVMInstanceHandle {
        _ = try translator.buildVZConfiguration(
            from: spec,
            networkSocketFD: networkSocketFD,
            serialLogFileURL: consoleLogURL,
            validateConfiguration: false
        )
        let sockPath = socketPathByVMName[spec.name] ?? ""
        return Stage6UnixVMInstanceHandle(sockPath: sockPath)
    }
}

private final class Stage6UnixVMInstanceHandle: HardwareVMInstanceHandle, @unchecked Sendable {
    private let sockPath: String

    init(sockPath: String) {
        self.sockPath = sockPath
    }

    func prematureStopReason() -> String? { nil }

    func connectVsock(port: UInt32) async throws -> HardwareVsockFDDescriptor {
        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(Darwin.errno))
        }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(sockPath.utf8CString)
        withUnsafeMutableBytes(of: &addr.sun_path) { rawBuf in
            for (idx, b) in pathBytes.enumerated() {
                rawBuf[idx] = UInt8(bitPattern: b)
            }
        }
        let rc = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.connect(fd, saPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard rc == 0 else {
            let err = Darwin.errno
            _ = Darwin.close(fd)
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(err))
        }
        return HardwareVsockFDDescriptor(fileDescriptor: fd, closeWhenSessionEnds: true)
    }

    func closeVsockConnection() async {}
    func pause() async throws {}
    func resume() async throws {}
    func saveMachineState(to url: URL) async throws {}
    func shutdown(gracefulTimeoutNanoseconds: UInt64) async {}
}
