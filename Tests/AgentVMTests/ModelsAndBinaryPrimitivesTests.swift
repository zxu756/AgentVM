import AgentVMModels
import Foundation
import Testing

@Suite("M01 Models, Identifiers, Networking Primitives & Binary Checksums", .timeLimit(.minutes(1)))
struct ModelsAndBinaryPrimitivesTests {

    // MARK: - Helpers

    private func makeTemporaryDirectory(prefix: String = "avm-models") throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    // MARK: - 1. TypedIdentifier & Codable Invariants

    @Test("TypedIdentifier trims whitespace, generates prefixed IDs, and falls back on blank input")
    func typedIdentifierNormalizationAndCodable() throws {
        let trimmed = VMID("  vm-alpha-01 \n")
        #expect(trimmed.rawValue == "vm-alpha-01")
        #expect(trimmed.description == "vm-alpha-01")

        let literalID = SnapshotID("snap-root-0001")
        #expect(literalID.rawValue == "snap-root-0001")

        let fallback = BranchID("   \t\n  ")
        #expect(!fallback.rawValue.isEmpty)
        #expect(fallback.rawValue.count == 36)
        #expect(fallback.rawValue == fallback.rawValue.lowercased())

        let generated = PolicySetID.generate(prefix: "pol")
        #expect(generated.rawValue.hasPrefix("pol-"))
        #expect(generated.rawValue.count == 16) // "pol-" + 12 hex chars

        let sorted = [VMID("vm-c"), VMID("vm-a"), VMID("vm-b")].sorted()
        #expect(sorted.map(\.rawValue) == ["vm-a", "vm-b", "vm-c"])

        let encoded = try JSONEncoder().encode(trimmed)
        let decoded = try JSONDecoder().decode(VMID.self, from: encoded)
        #expect(decoded == trimmed)
    }

    // MARK: - 2. SemanticVersion Parsing & SemVer 2.0 Ordering

    @Test("SemanticVersion parses optional v-prefix and prerelease tags while rejecting malformed inputs")
    func semanticVersionParsing() {
        let release = SemanticVersion(parsing: "v2.4.9")
        #expect(release == SemanticVersion(major: 2, minor: 4, patch: 9))
        #expect(release?.description == "2.4.9")

        let pre = SemanticVersion(parsing: "  v1.0.0-alpha.2  ")
        #expect(pre == SemanticVersion(major: 1, minor: 0, patch: 0, prerelease: "alpha.2"))
        #expect(pre?.description == "1.0.0-alpha.2")

        #expect(SemanticVersion(parsing: "") == nil)
        #expect(SemanticVersion(parsing: "V1.0.0") == nil)
        #expect(SemanticVersion(parsing: "1.2") == nil)
        #expect(SemanticVersion(parsing: "1.2.3.4") == nil)
        #expect(SemanticVersion(parsing: "1.two.3") == nil)
        #expect(SemanticVersion(parsing: "-1.0.0") == nil)
    }

    @Test("SemanticVersion enforces SemVer precedence where prereleases sort strictly before release")
    func semanticVersionPrecedenceOrdering() throws {
        let v099 = try #require(SemanticVersion(parsing: "0.9.9"))
        let v100Alpha = try #require(SemanticVersion(parsing: "1.0.0-alpha"))
        let v100Beta = try #require(SemanticVersion(parsing: "1.0.0-beta"))
        let v100rc1 = try #require(SemanticVersion(parsing: "1.0.0-rc.1"))
        let v100 = try #require(SemanticVersion(parsing: "1.0.0"))
        let v101 = try #require(SemanticVersion(parsing: "1.0.1"))
        let v110 = try #require(SemanticVersion(parsing: "1.1.0"))
        let v200 = try #require(SemanticVersion(parsing: "2.0.0"))

        #expect(v100Alpha < v100)
        #expect(v100Alpha < v100Beta)
        #expect(v100Beta < v100rc1)
        #expect(v100rc1 < v100)

        let shuffled = [v110, v100, v200, v100Alpha, v099, v101, v100rc1, v100Beta]
        #expect(shuffled.sorted() == [v099, v100Alpha, v100Beta, v100rc1, v100, v101, v110, v200])
    }

    // MARK: - 3. MACAddress Parsing, Classification & Deterministic Generation

    @Test("MACAddress parses colon and hyphen forms and classifies unicast, multicast, and broadcast")
    func macAddressParsingAndFlags() throws {
        let parsedColon = try #require(MACAddress(parsing: "52:54:00:AB:CD:EF"))
        let parsedHyphen = try #require(MACAddress(parsing: "52-54-00-ab-cd-ef"))
        #expect(parsedColon == parsedHyphen)
        #expect(parsedColon.description == "52:54:00:ab:cd:ef")
        #expect(parsedColon.isLocallyAdministered == true)
        #expect(parsedColon.isMulticast == false)
        #expect(parsedColon.isBroadcast == false)

        #expect(MACAddress.broadcast.isBroadcast == true)
        #expect(MACAddress.broadcast.isMulticast == true)

        let ipv4Multicast = try #require(MACAddress(parsing: "01:00:5e:00:00:fb"))
        #expect(ipv4Multicast.isMulticast == true)
        #expect(ipv4Multicast.isBroadcast == false)
        #expect(ipv4Multicast.isLocallyAdministered == false)

        let detA1 = MACAddress.deterministicGuestMAC(seed: "blade-worker-01")
        let detA2 = MACAddress.deterministicGuestMAC(seed: "blade-worker-01")
        let detB = MACAddress.deterministicGuestMAC(seed: "blade-worker-02")
        #expect(detA1 == detA2)
        #expect(detA1 != detB)
        #expect(detA1.isLocallyAdministered == true)
        #expect(detA1.isMulticast == false)
        #expect(detA1.octets[0] == 0x52 && detA1.octets[1] == 0x54 && detA1.octets[2] == 0x00)

        #expect(MACAddress(parsing: "52:54:00:11:22") == nil)
        #expect(MACAddress(parsing: "52:54:00:11:22:GG") == nil)
        #expect(MACAddress(parsing: "52:54:00:11:22:33:44") == nil)
    }

    // MARK: - 4. IPv4Address & IPv4CIDR Netmask, Broadcast & Subnet Containment

    @Test("IPv4Address parses dotted quads and classifies RFC1918, loopback, link-local, and multicast")
    func ipv4AddressClassification() throws {
        let gw = try #require(IPv4Address(parsing: "10.211.55.1"))
        #expect(gw == .switchGateway)
        #expect(gw.octetsArray == [10, 211, 55, 1])
        #expect(gw.isPrivateRFC1918 == true)
        #expect(gw.isLoopback == false)
        #expect(gw.isLinkLocal == false)

        #expect(try #require(IPv4Address(parsing: "172.16.0.1")).isPrivateRFC1918 == true)
        #expect(try #require(IPv4Address(parsing: "172.31.255.254")).isPrivateRFC1918 == true)
        #expect(try #require(IPv4Address(parsing: "172.32.0.1")).isPrivateRFC1918 == false)
        #expect(try #require(IPv4Address(parsing: "192.168.1.42")).isPrivateRFC1918 == true)
        #expect(try #require(IPv4Address(parsing: "1.1.1.1")).isPrivateRFC1918 == false)

        #expect(IPv4Address.loopback.isLoopback == true)
        #expect(try #require(IPv4Address(parsing: "169.254.169.254")).isLinkLocal == true)
        #expect(try #require(IPv4Address(parsing: "224.0.0.251")).isMulticast == true)

        #expect(IPv4Address(parsing: "256.0.0.1") == nil)
        #expect(IPv4Address(parsing: "10.0.1") == nil)
        #expect(IPv4Address(parsing: "10.0.0.1.2") == nil)
    }

    @Test("IPv4CIDR computes canonical network address, netmask, broadcast, and boundary containment")
    func ipv4CIDRContainmentAndMasks() throws {
        let subnet = try #require(IPv4CIDR(parsing: "10.211.55.99/24"))
        #expect(subnet.networkAddress == IPv4Address(a: 10, b: 211, c: 55, d: 0))
        #expect(subnet.netmask == IPv4Address(a: 255, b: 255, c: 255, d: 0))
        #expect(subnet.broadcastAddress == IPv4Address(a: 10, b: 211, c: 55, d: 255))
        #expect(subnet.description == "10.211.55.0/24")

        #expect(subnet.contains(IPv4Address(a: 10, b: 211, c: 55, d: 0)) == true)
        #expect(subnet.contains(IPv4Address(a: 10, b: 211, c: 55, d: 1)) == true)
        #expect(subnet.contains(IPv4Address(a: 10, b: 211, c: 55, d: 255)) == true)
        #expect(subnet.contains(IPv4Address(a: 10, b: 211, c: 54, d: 255)) == false)
        #expect(subnet.contains(IPv4Address(a: 10, b: 211, c: 56, d: 0)) == false)

        let hostRoute = try #require(IPv4CIDR(parsing: "169.254.169.254"))
        #expect(hostRoute.prefixLength == 32)
        #expect(hostRoute.netmask == .broadcast)
        #expect(hostRoute.broadcastAddress == IPv4Address(a: 169, b: 254, c: 169, d: 254))
        #expect(hostRoute.contains(IPv4Address(a: 169, b: 254, c: 169, d: 254)) == true)
        #expect(hostRoute.contains(IPv4Address(a: 169, b: 254, c: 169, d: 253)) == false)

        let defaultRoute = try #require(IPv4CIDR(parsing: "0.0.0.0/0"))
        #expect(defaultRoute.netmask == .zero)
        #expect(defaultRoute.broadcastAddress == .broadcast)
        #expect(defaultRoute.contains(IPv4Address(a: 8, b: 8, c: 8, d: 8)) == true)

        #expect(IPv4CIDR(parsing: "10.0.0.0/33") == nil)
        #expect(IPv4CIDR(parsing: "10.0.0.0/-1") == nil)
    }

    // MARK: - 5. VMSpec Hardware & Topology Validation

    @Test("VMSpec.validate accepts well-formed hardware topologies without warnings")
    func vmSpecValidTopologyPasses() {
        let spec = VMSpec(
            name: "clean-sandbox-blade",
            compute: CPUAndMemorySpec(vcpuCount: 4, memoryMB: 4096, minBalloonMemoryMB: 1024),
            virtioFSMounts: [
                VirtioFSMountSpec(mountTag: "workspace", hostDirectoryPath: "/tmp/ws", guestMountPoint: "/workspace"),
                VirtioFSMountSpec(mountTag: "cache", hostDirectoryPath: "/tmp/cache", guestMountPoint: "/cache", readOnly: true)
            ],
            networkInterfaces: [
                NetworkInterfaceSpec(macAddress: "52:54:00:12:34:56", ipv4Address: "10.211.55.12", mtu: 1500)
            ],
            portForwards: [
                PortForwardRuleSpec(label: "http", hostPort: 18080, guestPort: 8080),
                PortForwardRuleSpec(label: "ephemeral-rpc", hostPort: 19090, guestPort: 9090)
            ]
        )

        let issues = spec.validate(maxHostCores: 16, maxHostMemoryMB: 65_536)
        #expect(issues.isEmpty)
    }

    @Test("VMSpec.validate catches duplicate VirtioFS tags, duplicate ports, invalid MAC, and balloon > total RAM")
    func vmSpecDetectsAllHardwareViolations() {
        let oversizedTag = String(repeating: "x", count: 37)
        let brokenSpec = VMSpec(
            name: "   ",
            compute: CPUAndMemorySpec(
                vcpuCount: 64,
                memoryMB: 2048,
                enableBalloonDevice: true,
                minBalloonMemoryMB: 4096
            ),
            virtioFSMounts: [
                VirtioFSMountSpec(mountTag: "shared", hostDirectoryPath: "/tmp/a", guestMountPoint: "/mnt/a"),
                VirtioFSMountSpec(mountTag: "shared", hostDirectoryPath: "/tmp/b", guestMountPoint: "/mnt/b"),
                VirtioFSMountSpec(mountTag: oversizedTag, hostDirectoryPath: "/tmp/c", guestMountPoint: "/mnt/c")
            ],
            networkInterfaces: [
                NetworkInterfaceSpec(macAddress: "not-a-valid-mac", mtu: 200)
            ],
            portForwards: [
                PortForwardRuleSpec(label: "web-1", hostPort: 8080, guestPort: 80),
                PortForwardRuleSpec(label: "web-2", hostPort: 8080, guestPort: 8081),
                PortForwardRuleSpec(label: "bad-zero", hostPort: 9000, guestPort: 0)
            ]
        )

        let issues = brokenSpec.validate(maxHostCores: 16, maxHostMemoryMB: 32_768)
        let codes = Set(issues.map(\.code))

        #expect(codes.contains("EMPTY_VM_NAME"))
        #expect(codes.contains("INVALID_VCPU_COUNT"))
        #expect(codes.contains("BALLOON_EXCEEDS_TOTAL"))
        #expect(codes.contains("DUPLICATE_VIRTIOFS_TAG"))
        #expect(codes.contains("INVALID_VIRTIOFS_TAG"))
        #expect(codes.contains("DUPLICATE_HOST_PORT"))
        #expect(codes.contains("ZERO_PORT_FORWARD"))
        #expect(codes.contains("INVALID_MAC"))
        #expect(codes.contains("INVALID_MTU"))
    }

    @Test("VMSpec.validate rejects guest RAM below 256 MB or above host limit")
    func vmSpecMemoryBoundsValidation() {
        let tooSmall = VMSpec(
            name: "tiny-ram",
            compute: CPUAndMemorySpec(vcpuCount: 1, memoryMB: 128, minBalloonMemoryMB: 64)
        )
        #expect(tooSmall.validate(maxHostCores: 8, maxHostMemoryMB: 16_384).map(\.code).contains("INVALID_MEMORY_MB"))

        let tooLarge = VMSpec(
            name: "huge-ram",
            compute: CPUAndMemorySpec(vcpuCount: 2, memoryMB: 65_536, minBalloonMemoryMB: 512)
        )
        #expect(tooLarge.validate(maxHostCores: 8, maxHostMemoryMB: 16_384).map(\.code).contains("INVALID_MEMORY_MB"))
    }

    // MARK: - 6. IEEE 802.3 CRC-32, RFC 1071 Checksum & CryptoKit SHA-256

    @Test("BinaryChecksums computes exact IEEE 802.3 CRC-32 canonical test vectors on Data and ArraySlice")
    func ieeeCRC32CanonicalVectors() {
        #expect(BinaryChecksums.crc32(Data()) == 0x0000_0000)

        let canonicalVector = Data("123456789".utf8)
        #expect(BinaryChecksums.crc32(canonicalVector) == 0xCBF4_3926)

        let padded: [UInt8] = [0xAA, 0xBB] + Array("123456789".utf8) + [0xCC, 0xDD]
        let slice = padded[2..<11]
        #expect(BinaryChecksums.crc32(slice) == 0xCBF4_3926)

        let quickFox = Data("The quick brown fox jumps over the lazy dog".utf8)
        #expect(BinaryChecksums.crc32(quickFox) == 0x414F_A339)
    }

    @Test("BinaryChecksums computes RFC 1071 ones-complement IPv4 header and pseudo-header transport checksums")
    func rfc1071ChecksumVerification() {
        // RFC 1071 / Wikipedia canonical 20-byte IPv4 header with zeroed checksum slot [10..11]:
        // 45 00 00 73 00 00 40 00 40 11 [00 00] c0 a8 00 01 c0 a8 00 c7 -> expected checksum 0xB861
        var ipv4Header: [UInt8] = [
            0x45, 0x00, 0x00, 0x73,
            0x00, 0x00, 0x40, 0x00,
            0x40, 0x11, 0x00, 0x00,
            0xC0, 0xA8, 0x00, 0x01,
            0xC0, 0xA8, 0x00, 0xC7
        ]
        let computed = BinaryChecksums.rfc1071Checksum(ipv4Header)
        #expect(computed == 0xB861)

        ipv4Header[10] = UInt8((computed >> 8) & 0xFF)
        ipv4Header[11] = UInt8(computed & 0xFF)
        // Recomputing RFC 1071 over a valid header with populated checksum yields 0x0000
        #expect(BinaryChecksums.rfc1071Checksum(ipv4Header) == 0x0000)

        // Odd-byte payload handling + UDP/TCP pseudo-header checksum verification
        let srcIP = IPv4Address(a: 10, b: 211, c: 55, d: 10)
        let dstIP = IPv4Address(a: 10, b: 211, c: 55, d: 1)
        var udpSegment: [UInt8] = [
            0xD4, 0x31, 0x00, 0x35, // srcPort 54321 -> dstPort 53
            0x00, 0x0D, 0x00, 0x00, // length 13, checksum 0
            0x61, 0x67, 0x65, 0x6E, 0x74 // "agent" (5 odd bytes)
        ]
        let udpCsum = BinaryChecksums.ipv4TransportChecksum(
            srcIP: srcIP,
            dstIP: dstIP,
            protocolNumber: 17,
            segmentBytes: udpSegment
        )
        #expect(udpCsum != 0)
        udpSegment[6] = UInt8((udpCsum >> 8) & 0xFF)
        udpSegment[7] = UInt8(udpCsum & 0xFF)
        // Re-running pseudo-header checksum with embedded checksum produces 0x0000 (or 0xFFFF mapped)
        let verifyZero = BinaryChecksums.ipv4TransportChecksum(
            srcIP: srcIP,
            dstIP: dstIP,
            protocolNumber: 17,
            segmentBytes: udpSegment
        )
        #expect(verifyZero == 0xFFFF || verifyZero == 0x0000)
    }

    @Test("BinaryChecksums computes NIST SHA-256 digests in memory and via streaming file chunks")
    func sha256MemoryAndStreamingFileVectors() throws {
        #expect(
            BinaryChecksums.sha256Hex(Data())
                == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        #expect(
            BinaryChecksums.sha256Hex(Data("abc".utf8))
                == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )

        let tempDir = try makeTemporaryDirectory(prefix: "avm-sha256")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        // Exceed 64 KiB streaming read chunk size (180 KiB deterministic payload)
        let largePayload = Data((0..<(180 * 1024)).map { UInt8(($0 * 73 + 19) & 0xFF) })
        let fileURL = tempDir.appendingPathComponent("multi-chunk.bin")
        try largePayload.write(to: fileURL)

        let expectedHex = BinaryChecksums.sha256Hex(largePayload)
        let streamedHex = try BinaryChecksums.sha256HexFile(at: fileURL)
        #expect(streamedHex == expectedHex)
    }

    // MARK: - 7. BinaryCursor & BinaryBufferWriter Round-Trips & Bounds Guards

    @Test("BinaryBufferWriter and BinaryCursor round-trip BE, LE, BothEndian, ASCII, padding, and patching")
    func binaryCursorAndWriterRoundTrip() throws {
        var writer = BinaryBufferWriter(capacity: 128)
        writer.appendUInt8(0x7F)
        writer.appendUInt16BE(0x1234)
        writer.appendUInt16LE(0xABCD)
        writer.appendUInt16BothEndian(0x0800) // ISO-9660 LSB+MSB = 4 bytes
        writer.appendUInt32BE(0xCAFE_BABE)
        writer.appendUInt32LE(0xDEAD_BEEF)
        writer.appendUInt32BothEndian(0x0001_0203) // 8 bytes
        writer.appendUInt64BE(0x0102_0304_0506_0708)
        writer.appendUInt64LE(0x8877_6655_4433_2211)
        writer.appendFixedASCII("CIDATA", length: 12, padByte: 0x20)
        writer.padToAlignment(16, fillByte: 0xEE)

        let patchPos16 = writer.count
        writer.appendUInt16BE(0x0000)
        let patchPos32LE = writer.count
        writer.appendUInt32LE(0x0000_0000)
        let patchPos32BE = writer.count
        writer.appendUInt32BE(0x0000_0000)

        writer.patchUInt16BE(0x9988, at: patchPos16)
        writer.patchUInt32LE(0x1122_3344, at: patchPos32LE)
        writer.patchUInt32BE(0x5566_7788, at: patchPos32BE)

        var cursor = BinaryCursor(data: writer.data)
        #expect(try cursor.readUInt8() == 0x7F)
        #expect(try cursor.readUInt16BE() == 0x1234)
        #expect(try cursor.readUInt16LE() == 0xABCD)
        #expect(try cursor.readUInt16LE() == 0x0800)
        #expect(try cursor.readUInt16BE() == 0x0800)
        #expect(try cursor.readUInt32BE() == 0xCAFE_BABE)
        #expect(try cursor.readUInt32LE() == 0xDEAD_BEEF)
        #expect(try cursor.readUInt32LE() == 0x0001_0203)
        #expect(try cursor.readUInt32BE() == 0x0001_0203)
        #expect(try cursor.readUInt64BE() == 0x0102_0304_0506_0708)
        #expect(try cursor.readUInt64LE() == 0x8877_6655_4433_2211)
        #expect(try cursor.readASCII(12, trimTrailingSpaces: true) == "CIDATA")

        try cursor.seek(to: patchPos16)
        #expect(try cursor.readUInt16BE() == 0x9988)
        #expect(try cursor.readUInt32LE() == 0x1122_3344)
        #expect(try cursor.readUInt32BE() == 0x5566_7788)
        #expect(cursor.isAtEnd == true)
        #expect(cursor.remaining == 0)
    }

    @Test("BinaryCursor throws ERR_NET_FRAME_MALFORMED on truncated reads, negative seeks, and out-of-bounds skips")
    func binaryCursorOutOfBoundsErrors() {
        let shortBytes: [UInt8] = [0x01, 0x02, 0x03]

        #expect(throws: AgentVMError.self) {
            var c = BinaryCursor(bytes: shortBytes)
            _ = try c.readUInt32BE()
        }

        #expect(throws: AgentVMError.self) {
            var c = BinaryCursor(bytes: shortBytes)
            _ = try c.readBytes(4)
        }

        #expect(throws: AgentVMError.self) {
            var c = BinaryCursor(bytes: shortBytes)
            try c.seek(to: -1)
        }

        #expect(throws: AgentVMError.self) {
            var c = BinaryCursor(bytes: shortBytes)
            try c.skip(5)
        }

        do {
            var c = BinaryCursor(bytes: shortBytes)
            _ = try c.readUInt64BE()
            Issue.record("Expected BinaryCursor.readUInt64BE to throw on 3-byte buffer")
        } catch let error as AgentVMError {
            #expect(error.errorCode == "ERR_NET_FRAME_MALFORMED")
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    // MARK: - 8. GlobPatternMatcher, ByteMetricsFormatter & Cloud-Init / Vsock Models

    @Test("GlobPatternMatcher supports case-insensitive multi-wildcard and single-char matching")
    func globPatternMatcherWildcards() {
        #expect(GlobPatternMatcher.matches(pattern: "*.anthropic.com", candidate: "api.anthropic.com") == true)
        #expect(GlobPatternMatcher.matches(pattern: "*.ANTHROPIC.COM", candidate: "claude.api.anthropic.com") == true)
        #expect(GlobPatternMatcher.matches(pattern: "*.anthropic.com", candidate: "anthropic.com") == false)
        #expect(GlobPatternMatcher.matches(pattern: "*webhook.site", candidate: "webhook.site") == true)
        #expect(GlobPatternMatcher.matches(pattern: "*webhook.site", candidate: "leak.webhook.site") == true)
        #expect(GlobPatternMatcher.matches(pattern: "api-v?.github.com", candidate: "api-v3.github.com") == true)
        #expect(GlobPatternMatcher.matches(pattern: "api-v?.github.com", candidate: "api-v12.github.com") == false)
        #expect(GlobPatternMatcher.matches(pattern: "**pypi**", candidate: "files.pypi.org") == true)
        #expect(GlobPatternMatcher.matches(pattern: "", candidate: "") == true)
        #expect(GlobPatternMatcher.matches(pattern: "", candidate: "nonempty") == false)
    }

    @Test("ByteMetricsFormatter scrubs NSHomeDirectory paths and formats signed CoW byte deltas")
    func byteMetricsFormatterHomeScrubbingAndDeltas() {
        let home = NSHomeDirectory()
        let rawPath = "\(home)/Projects/AgentVM/Fleet.agentvm/Disks/root.raw"
        let scrubbed = ByteMetricsFormatter.scrubHomePath(rawPath)
        #expect(!scrubbed.contains(home))
        #expect(scrubbed == "~/Projects/AgentVM/Fleet.agentvm/Disks/root.raw")

        let guestPath = "/workspace/src/main.rs"
        #expect(ByteMetricsFormatter.scrubHomePath(guestPath) == guestPath)

        #expect(ByteMetricsFormatter.formatBytes(0) == "0 B")
        #expect(ByteMetricsFormatter.formatSignedDeltaBytes(0) == "+0 B")
        #expect(ByteMetricsFormatter.formatSignedDeltaBytes(1024 * 1024).hasPrefix("+"))
        #expect(ByteMetricsFormatter.formatSignedDeltaBytes(-1024 * 1024).hasPrefix("-"))
    }

    @Test("FirewallRuleCondition human-readable summaries and preset factories maintain deterministic priorities")
    func firewallPresetsAndConditionSummaries() {
        let strict = FirewallPolicySet.strictAgentAllowlistPreset()
        #expect(strict.defaultEgressVerdict == .drop)
        #expect(strict.blockPrivateMetadataIPs == true)
        #expect(strict.rules.count >= 6)

        let priorities = strict.rules.map(\.priority)
        #expect(priorities == priorities.sorted())

        let airgap = FirewallPolicySet.airgappedPreset()
        #expect(airgap.defaultEgressVerdict == .drop)
        #expect(airgap.defaultIngressVerdict == .drop)
        #expect(airgap.rules.isEmpty)

        let condSummary = FirewallCondition.tlsSNIGlob("*.anthropic.com").humanReadableSummary
        #expect(condSummary.contains("*.anthropic.com"))
    }

    @Test("VsockFrameHeader, GuestExecRequest, and AgentVMError expose canonical wire constants and remediation hints")
    func vsockModelsAndErrorMetadata() {
        #expect(VsockFrameHeader.wireMagic == 0x4156_4D31)
        #expect(VsockFrameHeader.encodedByteSize == 24)

        let req = GuestExecRequest(
            executable: "/usr/bin/git",
            arguments: ["commit", "-m", "fix auth middleware"]
        )
        #expect(req.commandLineSummary == "/usr/bin/git commit -m fix auth middleware")

        let allSampleErrors: [AgentVMError] = [
            .invalidConfiguration(issues: [ValidationIssue(fieldPath: "name", code: "EMPTY", message: "Empty", remediation: "Supply a non-empty VM name")]),
            .vmNotFound(VMID("vm-missing")),
            .snapshotNotFound(SnapshotID("snap-missing")),
            .snapshotCycleDetected(SnapshotID("s1")),
            .invalidLifecycleTransition(vmID: VMID("vm-1"), from: "stopped", requested: "pause"),
            .resourceQuotaExceeded(resource: "ram", requested: "64GB", limit: "32GB"),
            .diskImageOperationFailed(path: "/tmp/d.raw", errnoCode: 2, detail: "ENOENT"),
            .cowCloneFailed(source: "/a", destination: "/b", errnoCode: 18),
            .partitionTableInvalid(detail: "Bad CRC"),
            .iso9660BuildFailed(detail: "Oversized"),
            .bundleIntegrityError(path: "/tmp/bundle", detail: "Missing manifest"),
            .storageDatabaseError(code: 1, sql: "SELECT 1;", detail: "SQL error"),
            .storageMigrationFailed(fromVersion: 1, toVersion: 2, detail: "Checksum drift"),
            .undoStackEmpty,
            .redoStackEmpty,
            .networkFrameMalformed(layer: "DNS", detail: "Pointer loop"),
            .pcapCorrupted(detail: "Bad block"),
            .firewallBlocked(ruleID: RuleID("r1"), reason: "Denied"),
            .vsockProtocolViolation(detail: "Bad magic"),
            .vsockCRCMismatch(expected: 1, actual: 2),
            .portForwardBindFailed(port: 80, errnoCode: 13),
            .pluginPermissionDenied(pluginID: PluginID("p1"), capability: "networkInspect"),
            .pluginExecutionFailed(pluginID: PluginID("p1"), detail: "SyntaxError"),
            .pluginTimedOut(pluginID: PluginID("p1"), limitMs: 100),
            .ipcDaemonUnavailable(socketPath: "/tmp/avm.sock", detail: "Connection refused"),
            .virtualizationUnsupported(reason: "Missing entitlement"),
            .cliUsageError(detail: "Missing VM name")
        ]

        for err in allSampleErrors {
            #expect(err.errorCode.hasPrefix("ERR_"))
            #expect(!(err.errorDescription ?? "").isEmpty)
            #expect(!err.remediationHint.isEmpty)
        }
    }

    @Test("VMSpec and CloudInitSpec preserve full JSON Codable fidelity across mounts, NICs, port forwards, and writeFiles")
    func cloudInitAndVMSpecCodableRoundTrip() throws {
        let writeFile = CloudInitWriteFile(
            guestPath: "/etc/agentvm/bootstrap.env",
            permissionsOctal: "0600",
            owner: "root:root",
            content: "AGENTVM_ENV=production\n"
        )
        let cloudInit = CloudInitSpec(
            instanceID: "i-agentvm-codable-01",
            hostname: "claude-runner-01",
            defaultUser: "agent",
            sshAuthorizedKeys: ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGoldenTestKey agent@mac"],
            aptPackages: ["git", "ripgrep", "python3", "bubblewrap"],
            writeFiles: [writeFile],
            runCommands: ["systemctl enable --now agentvm-guest-agent.service"],
            injectGuestVsockAgent: true
        )
        let original = VMSpec(
            id: VMID("vm-codable-full"),
            name: "claude-runner-01",
            agentOwnerTag: "claude-code",
            guestOS: .linuxARM64,
            bootLoader: .efiBoot(variableStorePath: "/tmp/efi.nvram", createVariableStoreIfMissing: true),
            compute: CPUAndMemorySpec(
                vcpuCount: 6,
                memoryMB: 8192,
                enableBalloonDevice: true,
                minBalloonMemoryMB: 2048,
                cpuQuotaPercent: 300
            ),
            blockDevices: [
                BlockDeviceSpec(
                    id: BlockDeviceID("blk-root"),
                    label: "root",
                    imagePath: "/tmp/debian-root.raw",
                    virtualSizeBytes: 32 * 1024 * 1024 * 1024,
                    format: .rawSparse,
                    isBootVolume: true
                )
            ],
            virtioFSMounts: [
                VirtioFSMountSpec(mountTag: "workspace", hostDirectoryPath: "/Users/Shared/repo", guestMountPoint: "/workspace", readOnly: false),
                VirtioFSMountSpec(mountTag: "toolchains", hostDirectoryPath: "/opt/toolchains", guestMountPoint: "/mnt/toolchains", readOnly: true)
            ],
            networkInterfaces: [
                NetworkInterfaceSpec(
                    id: NICID("nic-eth0"),
                    interfaceName: "eth0",
                    macAddress: "52:54:00:AB:CD:01",
                    mode: .userSpaceSwitch,
                    ipv4Address: "10.211.55.42",
                    subnetCIDR: "10.211.55.0/24",
                    gatewayIPv4: "10.211.55.1",
                    dnsServers: ["10.211.55.1", "1.1.1.1"],
                    mtu: 1500,
                    firewallPolicyID: PolicySetID("policy-strict")
                )
            ],
            portForwards: [
                PortForwardRuleSpec(label: "Jupyter", hostBindAddress: "127.0.0.1", hostPort: 18888, guestPort: 8888),
                PortForwardRuleSpec(label: "Vite", hostBindAddress: "127.0.0.1", hostPort: 15173, guestPort: 5173)
            ],
            cloudInit: cloudInit,
            labels: ["role": "swe-bench", "tier": "isolated"],
            createdAt: Date(timeIntervalSince1970: 1_730_000_000),
            updatedAt: Date(timeIntervalSince1970: 1_730_000_000)
        )

        #expect(original.validate().isEmpty)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let encoded = try encoder.encode(original)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(VMSpec.self, from: encoded)
        #expect(decoded == original)
        #expect(decoded.cloudInit?.writeFiles.first?.guestPath == "/etc/agentvm/bootstrap.env")
    }

    @Test("GuestHeartbeatPayload and GuestProcessSample preserve JSON Codable fidelity")
    func guestHeartbeatMemoryPressureAndTelemetryInvariants() throws {
        let procSample = GuestProcessSample(
            pid: 142,
            ppid: 1,
            user: "agent",
            cpuPercent: 18.5,
            rssBytes: 64 * 1024 * 1024,
            command: "python3 /usr/local/libexec/agentvm-guestd.py"
        )
        let normalBeat = GuestHeartbeatPayload(
            hostname: "ubuntu-box",
            kernelRelease: "6.8.0-48-generic",
            uptimeSeconds: 3600,
            loadAvg1: 0.42,
            loadAvg5: 0.31,
            loadAvg15: 0.18,
            memTotalBytes: 4_000_000_000,
            memAvailableBytes: 1_000_000_000,
            rootFilesystemUsedBytes: 5_000_000_000,
            rootFilesystemTotalBytes: 20_000_000_000,
            topProcesses: [procSample],
            reportedAt: Date(timeIntervalSince1970: 1_730_000_000)
        )
        #expect(normalBeat.topProcesses.count == 1)
        #expect(normalBeat.memTotalBytes - normalBeat.memAvailableBytes == 3_000_000_000)

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        let data = try encoder.encode(normalBeat)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        let roundTripped = try decoder.decode(GuestHeartbeatPayload.self, from: data)
        #expect(roundTripped == normalBeat)
    }

    @Test("AgentVMProjectManifest, WorkspacePreferences, and WorkbenchLayoutSnapshot maintain stable schema defaults")
    func projectManifestAndWorkbenchLayoutDefaults() throws {
        let manifest = AgentVMProjectManifest(
            title: "Flagship Fleet",
            preferences: WorkspacePreferences(
                maxConcurrentRunningVMs: 6,
                autoPauseIdleMinutes: 45,
                maxPCAPRingBufferPackets: 50_000,
                enablePreExecAutoSnapshot: true
            )
        )
        #expect(manifest.formatVersion == 4)
        #expect(manifest.preferences.maxConcurrentRunningVMs == 6)

        let tab = WorkbenchTabDescriptor(kind: .packetWiretap, isPinned: true)
        let layout = WorkbenchLayoutSnapshot(
            workspaceID: manifest.workspaceID,
            showLeftFleetNavigator: true,
            showRightInspector: true,
            showBottomDrawer: true,
            activeBottomChannel: .serialTTY,
            splitMode: .verticalTwoColumn,
            primaryTabs: [tab],
            activePrimaryTabID: tab.id,
            selectedVMID: VMID("vm-alpha")
        )
        let encoded = try JSONEncoder().encode(layout)
        let decoded = try JSONDecoder().decode(WorkbenchLayoutSnapshot.self, from: encoded)
        #expect(decoded == layout)
    }
}

// MARK: - Test-Suite Convenience VMSpec Initializer (Default UEFI BootLoader)

extension VMSpec {
    init(
        id: VMID = .generate(prefix: "vm"),
        name: String,
        agentOwnerTag: String = "coordinator",
        guestOS: GuestOSType = .linuxARM64,
        compute: CPUAndMemorySpec = CPUAndMemorySpec(),
        blockDevices: [BlockDeviceSpec] = [],
        virtioFSMounts: [VirtioFSMountSpec] = [],
        networkInterfaces: [NetworkInterfaceSpec] = [NetworkInterfaceSpec()],
        portForwards: [PortForwardRuleSpec] = [],
        serialAndDisplay: SerialAndDisplaySpec = SerialAndDisplaySpec(),
        cloudInit: CloudInitSpec? = CloudInitSpec(),
        enableVsockDevice: Bool = true,
        parentVMID: VMID? = nil,
        forkedFromSnapshotID: SnapshotID? = nil,
        maxRuntimeMinutes: Int = 180,
        labels: [String: String] = [:],
        createdAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.init(
            id: id,
            name: name,
            agentOwnerTag: agentOwnerTag,
            guestOS: guestOS,
            bootLoader: .efiBoot(variableStorePath: "/tmp/agentvm-test.nvram", createVariableStoreIfMissing: true),
            compute: compute,
            blockDevices: blockDevices,
            virtioFSMounts: virtioFSMounts,
            networkInterfaces: networkInterfaces,
            portForwards: portForwards,
            serialAndDisplay: serialAndDisplay,
            cloudInit: cloudInit,
            enableVsockDevice: enableVsockDevice,
            parentVMID: parentVMID,
            forkedFromSnapshotID: forkedFromSnapshotID,
            maxRuntimeMinutes: maxRuntimeMinutes,
            labels: labels,
            createdAt: createdAt,
            updatedAt: updatedAt
        )
    }
}
