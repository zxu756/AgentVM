import AgentVMModels
import Darwin
import Foundation

// MARK: - ISO-9660 File Entry & Inspection Models

/// A deterministic file payload to pack into an ISO-9660 + Rock Ridge (`cidata`) image.
public struct ISOFileEntry: Codable, Sendable, Hashable {
    public var path: String
    public var data: Data
    public var posixMode: UInt16

    public init(path: String, data: Data, posixMode: UInt16 = 0o644) {
        self.path = path
        self.data = data
        self.posixMode = posixMode
    }

    public init(path: String, utf8Content: String, posixMode: UInt16 = 0o644) {
        self.path = path
        self.data = Data(utf8Content.utf8)
        self.posixMode = posixMode
    }

    public var utf8String: String? {
        String(data: data, encoding: .utf8)
    }
}

/// Detailed structural inspection summary of an ISO-9660 + Rock Ridge image for Studio diagnostics.
public struct ISOInspectionEntryDetail: Codable, Hashable, Sendable, Identifiable {
    public var id: String { path }
    public var path: String
    public var isoLevel1Identifier: String
    public var extentLBA: UInt32
    public var sizeBytes: UInt32
    public var posixMode: UInt16?
    public var sha256Hex: String

    public init(
        path: String,
        isoLevel1Identifier: String,
        extentLBA: UInt32,
        sizeBytes: UInt32,
        posixMode: UInt16?,
        sha256Hex: String
    ) {
        self.path = path
        self.isoLevel1Identifier = isoLevel1Identifier
        self.extentLBA = extentLBA
        self.sizeBytes = sizeBytes
        self.posixMode = posixMode
        self.sha256Hex = sha256Hex
    }
}

public struct ISOInspectionReport: Codable, Hashable, Sendable {
    public var systemIdentifier: String
    public var volumeIdentifier: String
    public var logicalBlockSize: UInt16
    public var volumeSpaceBlocks: UInt32
    public var typeLPathTableLBA: UInt32
    public var typeMPathTableLBA: UInt32
    public var hasRockRidgeSUSP: Bool
    public var entries: [ISOInspectionEntryDetail]

    public init(
        systemIdentifier: String,
        volumeIdentifier: String,
        logicalBlockSize: UInt16,
        volumeSpaceBlocks: UInt32,
        typeLPathTableLBA: UInt32,
        typeMPathTableLBA: UInt32,
        hasRockRidgeSUSP: Bool,
        entries: [ISOInspectionEntryDetail]
    ) {
        self.systemIdentifier = systemIdentifier
        self.volumeIdentifier = volumeIdentifier
        self.logicalBlockSize = logicalBlockSize
        self.volumeSpaceBlocks = volumeSpaceBlocks
        self.typeLPathTableLBA = typeLPathTableLBA
        self.typeMPathTableLBA = typeMPathTableLBA
        self.hasRockRidgeSUSP = hasRockRidgeSUSP
        self.entries = entries
    }
}

// MARK: - Pure-Swift ISO-9660 + Rock Ridge Cloud-Init Builder & Reader

/// Pure-Swift, 100% deterministic ECMA-119 (ISO-9660) + IEEE P1282 (SUSP / Rock Ridge `SP`, `PX`, `NM`)
/// 2048-byte sector image synthesizer and parser for `NoCloud` (`cidata`) VM provisioning.
public struct ISO9660CloudInitBuilder: Sendable {
    public static let sectorSize: Int = 2048
    public static let workspaceInitBootCommand: [String] = [
        "sh", "-c", "mkdir -p /workspace && chmod 0755 /workspace"
    ]
    public static let machineIDResetBootCommand: [String] = [
        "cloud-init-per", "instance", "avm-machine-id",
        "sh", "-c",
        "rm -f /etc/machine-id /var/lib/dbus/machine-id && systemd-machine-id-setup && ln -sf /etc/machine-id /var/lib/dbus/machine-id"
    ]
    private static let systemAreaSectors: Int = 16
    private static let pvdSectorIndex: Int = 16
    private static let vdstSectorIndex: Int = 17
    private static let standardIdentifierASCII = "CD001"

    /// Fixed deterministic recording timestamp (`2026-01-01 00:00:00 UTC`) so identical specs yield
    /// bit-for-bit identical SHA-256 ISO images across builds and machines.
    private static let deterministicDirTimestamp: [UInt8] = [126, 1, 1, 0, 0, 0, 0]
    private static let deterministicPVDTimestampASCII = "2026010100000000"
    private static let zeroPVDTimestampASCII = "0000000000000000"

    public init() {}

    // MARK: - Cloud-Init NoCloud Payload Synthesis

    /// Renders deterministic `meta-data`, `#cloud-config` `user-data`, Netplan v2 `network-config`,
    /// and `vendor-data` files from a `CloudInitSpec`.
    public func renderNoCloudFiles(
        from spec: CloudInitSpec,
        guestAgentScript: String? = nil
    ) -> [ISOFileEntry] {
        let metaDataYAML = renderMetaDataYAML(from: spec)
        let userDataYAML = renderUserDataYAML(from: spec, guestAgentScript: guestAgentScript)
        let networkConfigYAML = renderNetworkConfigYAML(from: spec)
        let vendorDataYAML = renderVendorDataYAML(from: spec)

        return [
            ISOFileEntry(path: "meta-data", utf8Content: metaDataYAML, posixMode: 0o644),
            ISOFileEntry(path: "user-data", utf8Content: userDataYAML, posixMode: 0o644),
            ISOFileEntry(path: "network-config", utf8Content: networkConfigYAML, posixMode: 0o644),
            ISOFileEntry(path: "vendor-data", utf8Content: vendorDataYAML, posixMode: 0o644)
        ]
    }

    /// Synthesizes a complete Cloud-Init `cidata` ISO-9660 + Rock Ridge image directly to `outputURL`
    /// via POSIX file I/O and returns its `DiskContainerHeaderSummary`.
    public func buildCloudInitISO(
        from spec: CloudInitSpec,
        outputURL: URL,
        guestAgentScript: String? = nil
    ) throws -> DiskContainerHeaderSummary {
        let files = renderNoCloudFiles(from: spec, guestAgentScript: guestAgentScript)
        let isoData = try buildISOImageData(volumeIdentifier: "cidata", files: files)

        try APFSCoWDiskEngine.ensureParentDirectoryExists(for: outputURL)
        let outPath = outputURL.path

        if Darwin.unlink(outPath) != 0 && Darwin.errno != ENOENT {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: outPath,
                errnoCode: err,
                detail: "Failed to unlink pre-existing ISO image (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }

        let fd = Darwin.open(outPath, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, mode_t(0o644))
        guard fd >= 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: outPath,
                errnoCode: err,
                detail: "Cannot create output ISO file (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }
        defer { _ = Darwin.close(fd) }

        try isoData.withUnsafeBytes { rawBuf in
            if let base = rawBuf.baseAddress, !isoData.isEmpty {
                try APFSCoWDiskEngine.pwriteExact(
                    fd: fd,
                    path: outPath,
                    from: base,
                    count: isoData.count,
                    offset: 0
                )
            }
        }

        if Darwin.fsync(fd) != 0 {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: outPath,
                errnoCode: err,
                detail: "fsync failed while finalizing Cloud-Init ISO (\(APFSCoWDiskEngine.posixErrorString(err)))."
            )
        }

        return DiskContainerHeaderSummary(
            format: .iso9660,
            virtualSizeBytes: UInt64(isoData.count),
            clusterOrSectorSize: UInt32(Self.sectorSize),
            backingFilePath: nil,
            gptDiskGUID: nil,
            partitions: [],
            isoVolumeIdentifier: "cidata"
        )
    }

    // MARK: - Deterministic ISO-9660 + Rock Ridge Image Builder

    /// Builds an in-memory 2048-byte-sector ISO-9660 + Rock Ridge (`SP` / `PX` / `NM`) image containing `files`.
    public func buildISOImageData(
        volumeIdentifier: String = "cidata",
        files: [ISOFileEntry]
    ) throws -> Data {
        let trimmedVolumeID = volumeIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedVolumeID.isEmpty, trimmedVolumeID.utf8.count <= 32 else {
            throw AgentVMError.iso9660BuildFailed(
                detail: "ISO-9660 volume identifier must be 1...32 UTF-8 bytes (got '\(volumeIdentifier)')."
            )
        }

        // Normalize and validate relative paths.
        var normalizedEntries: [(components: [String], fullPath: String, entry: ISOFileEntry)] = []
        normalizedEntries.reserveCapacity(files.count)
        var seenPaths = Set<String>()

        for file in files {
            let cleaned = try Self.normalizeRelativePath(file.path)
            guard seenPaths.insert(cleaned.joined).inserted else {
                throw AgentVMError.iso9660BuildFailed(
                    detail: "Duplicate relative file path '\(cleaned.joined)' in ISO-9660 manifest."
                )
            }
            normalizedEntries.append((components: cleaned.components, fullPath: cleaned.joined, entry: file))
        }

        // Sort deterministically by lexicographic path so output bytes never depend on caller array order.
        normalizedEntries.sort { $0.fullPath < $1.fullPath }

        // Build directory hierarchy and assign BFS 1-based Path Table indices.
        let tree = try Self.buildDirectoryHierarchy(from: normalizedEntries)

        // Build Type-L (LE) and Type-M (BE) Path Tables once directory LBAs are computed.
        // First calculate exact sector count required by Path Tables (invariant with respect to LBA values).
        let rawPathTableByteLength = Self.computePathTableByteLength(directories: tree.directories)
        let pathTableSectors = max(1, (rawPathTableByteLength + Self.sectorSize - 1) / Self.sectorSize)

        // Pre-compute exact sector count for every directory extent (record byte lengths do not depend on LBAs).
        var directorySectorCounts = [Int](repeating: 1, count: tree.directories.count)
        for dirIdx in 0..<tree.directories.count {
            let dummyRecords = try Self.serializeDirectoryExtent(
                directoryIndex: dirIdx,
                tree: tree,
                directoryLBAs: [UInt32](repeating: 0, count: tree.directories.count),
                directoryByteLengths: [UInt32](repeating: 2048, count: tree.directories.count),
                fileLBAs: [UInt32](repeating: 0, count: tree.files.count)
            )
            directorySectorCounts[dirIdx] = max(1, dummyRecords.count / Self.sectorSize)
        }

        // Assign deterministic LBAs across Volume Descriptors, Path Tables, Directories, and File Extents.
        let typeLPathTableLBA = UInt32(18)
        let typeMPathTableLBA = UInt32(18 + pathTableSectors)
        var nextLBA = Int(typeMPathTableLBA) + pathTableSectors

        var directoryLBAs = [UInt32](repeating: 0, count: tree.directories.count)
        var directoryByteLengths = [UInt32](repeating: 0, count: tree.directories.count)
        for dirIdx in 0..<tree.directories.count {
            directoryLBAs[dirIdx] = UInt32(nextLBA)
            let sectors = directorySectorCounts[dirIdx]
            directoryByteLengths[dirIdx] = UInt32(sectors * Self.sectorSize)
            nextLBA += sectors
        }

        var fileLBAs = [UInt32](repeating: 0, count: tree.files.count)
        for fileIdx in 0..<tree.files.count {
            let byteCount = tree.files[fileIdx].entry.data.count
            guard UInt64(byteCount) <= UInt64(UInt32.max) else {
                throw AgentVMError.iso9660BuildFailed(
                    detail: "File '\(tree.files[fileIdx].fullPath)' exceeds 4 GiB single-extent ISO-9660 limit."
                )
            }
            fileLBAs[fileIdx] = UInt32(nextLBA)
            if byteCount > 0 {
                let fileSectors = (byteCount + Self.sectorSize - 1) / Self.sectorSize
                nextLBA += fileSectors
            }
        }

        let totalVolumeSectors = UInt32(nextLBA)
        let totalImageBytes = Int(totalVolumeSectors) * Self.sectorSize
        var imageWriter = BinaryBufferWriter(capacity: totalImageBytes)

        // 1. Sectors 0..15: 32,768-byte zeroed System Area.
        imageWriter.appendBytes([UInt8](repeating: 0, count: Self.systemAreaSectors * Self.sectorSize))

        // 2. Sector 16: Primary Volume Descriptor (PVD).
        let pvdSector = Self.encodePrimaryVolumeDescriptor(
            volumeIdentifier: trimmedVolumeID,
            volumeSpaceBlocks: totalVolumeSectors,
            pathTableByteSize: UInt32(rawPathTableByteLength),
            typeLPathTableLBA: typeLPathTableLBA,
            typeMPathTableLBA: typeMPathTableLBA,
            rootDirectoryLBA: directoryLBAs[0],
            rootDirectoryByteLength: directoryByteLengths[0]
        )
        precondition(pvdSector.count == Self.sectorSize)
        imageWriter.appendBytes(pvdSector)

        // 3. Sector 17: Volume Descriptor Set Terminator (VDST).
        var vdst = [UInt8](repeating: 0, count: Self.sectorSize)
        vdst[0] = 0xFF
        let cd001 = Array(Self.standardIdentifierASCII.utf8)
        for i in 0..<5 { vdst[1 + i] = cd001[i] }
        vdst[6] = 0x01
        imageWriter.appendBytes(vdst)

        // 4. Type-L Path Table (Little-Endian) padded to sector multiple.
        let lTableBytes = Self.encodePathTable(
            directories: tree.directories,
            directoryLBAs: directoryLBAs,
            bigEndian: false
        )
        precondition(lTableBytes.count == rawPathTableByteLength)
        imageWriter.appendBytes(lTableBytes)
        imageWriter.padToAlignment(Self.sectorSize, fillByte: 0x00)

        // 5. Type-M Path Table (Big-Endian) padded to sector multiple.
        let mTableBytes = Self.encodePathTable(
            directories: tree.directories,
            directoryLBAs: directoryLBAs,
            bigEndian: true
        )
        precondition(mTableBytes.count == rawPathTableByteLength)
        imageWriter.appendBytes(mTableBytes)
        imageWriter.padToAlignment(Self.sectorSize, fillByte: 0x00)

        // 6. Directory Extent Sectors (BFS order, starting with Root Directory).
        for dirIdx in 0..<tree.directories.count {
            let extentBytes = try Self.serializeDirectoryExtent(
                directoryIndex: dirIdx,
                tree: tree,
                directoryLBAs: directoryLBAs,
                directoryByteLengths: directoryByteLengths,
                fileLBAs: fileLBAs
            )
            precondition(extentBytes.count == Int(directoryByteLengths[dirIdx]))
            imageWriter.appendBytes(extentBytes)
        }

        // 7. File Extent Sectors (2048-byte zero-padded).
        for fileNode in tree.files where !fileNode.entry.data.isEmpty {
            imageWriter.appendData(fileNode.entry.data)
            imageWriter.padToAlignment(Self.sectorSize, fillByte: 0x00)
        }

        precondition(imageWriter.count == totalImageBytes)
        return imageWriter.data
    }

    // MARK: - Pure-Swift ISO-9660 + Rock Ridge Reader & Inspector

    /// Parses Sector 16 PVD, traverses Root and child directory extents, decodes Rock Ridge `NM`
    /// alternate names (or ISO-9660 identifiers), and extracts exact file payloads.
    public func inspectISOImage(data: Data) throws -> (volumeID: String, files: [String: Data]) {
        let parsed = try parseISOContainerInternal(data: data)
        return (volumeID: parsed.report.volumeIdentifier, files: parsed.extractedFiles)
    }

    /// Reads an ISO-9660 image from disk and returns a rich `ISOInspectionReport` for UI & CLI inspection.
    public func inspectISOImageFile(at url: URL) throws -> ISOInspectionReport {
        let data: Data
        do {
            data = try Data(contentsOf: url, options: [.mappedIfSafe])
        } catch {
            throw AgentVMError.iso9660BuildFailed(
                detail: "Unable to read ISO-9660 file at '\(url.path)': \(error.localizedDescription)"
            )
        }
        return try parseISOContainerInternal(data: data).report
    }

    // MARK: - NoCloud YAML Synthesis Helpers

    private func renderMetaDataYAML(from spec: CloudInitSpec) -> String {
        let host = CloudInitSpec.sanitizeHostname(spec.hostname)
        var lines: [String] = []
        lines.append("instance-id: \(Self.yamlScalar(spec.instanceID))")
        lines.append("local-hostname: \(Self.yamlScalar(host))")
        return lines.joined(separator: "\n") + "\n"
    }

    private func renderUserDataYAML(from spec: CloudInitSpec, guestAgentScript: String?) -> String {
        let host = CloudInitSpec.sanitizeHostname(spec.hostname)
        var lines: [String] = ["#cloud-config"]
        lines.append("hostname: \(Self.yamlScalar(host))")
        lines.append("fqdn: \(Self.yamlScalar("\(host).agentvm.local"))")
        let nonEmptyMounts = spec.mounts.filter { !$0.isEmpty }
        var mountDirBootCommands: [[String]] = []
        for entry in nonEmptyMounts where entry.count >= 2 {
            let guestPath = entry[1].trimmingCharacters(in: .whitespacesAndNewlines)
            if !guestPath.isEmpty && guestPath != "/workspace" {
                let mkdirCmd = ["mkdir", "-p", guestPath]
                if !mountDirBootCommands.contains(mkdirCmd) {
                    mountDirBootCommands.append(mkdirCmd)
                }
            }
        }

        if !spec.bootCommands.isEmpty || !nonEmptyMounts.isEmpty {
            lines.append("bootcmd:")
            var effectiveBootCommands: [[String]] = [Self.workspaceInitBootCommand]
            for mkdirCmd in mountDirBootCommands where !effectiveBootCommands.contains(mkdirCmd) {
                effectiveBootCommands.append(mkdirCmd)
            }
            for cmd in spec.bootCommands where !cmd.isEmpty {
                if effectiveBootCommands.contains(cmd) {
                    continue
                }
                effectiveBootCommands.append(cmd)
            }
            for cmd in effectiveBootCommands {
                let renderedArgs = cmd.map { Self.yamlScalar($0) }.joined(separator: ", ")
                lines.append("  - [\(renderedArgs)]")
            }
        }
        lines.append("manage_etc_hosts: true")
        lines.append("timezone: \(Self.yamlScalar(spec.timezone))")

        if !nonEmptyMounts.isEmpty {
            lines.append("mounts:")
            for entry in nonEmptyMounts {
                let renderedFields = entry.map { Self.yamlMountField($0) }.joined(separator: ", ")
                lines.append("  - [\(renderedFields)]")
            }
        }

        // Users & SSH keys
        lines.append("users:")
        lines.append("  - name: \(Self.yamlScalar(spec.defaultUser))")
        lines.append("    groups: [sudo, adm, systemd-journal]")
        lines.append("    shell: /bin/bash")
        lines.append("    sudo: ALL=(ALL) NOPASSWD:ALL")
        if let hash = spec.passwordHash, !hash.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            lines.append("    lock_passwd: false")
            lines.append("    passwd: \(Self.yamlScalar(hash))")
        } else {
            lines.append("    lock_passwd: true")
        }
        if !spec.sshAuthorizedKeys.isEmpty {
            lines.append("    ssh_authorized_keys:")
            for key in spec.sshAuthorizedKeys {
                lines.append("      - \(Self.yamlScalar(key.trimmingCharacters(in: .whitespacesAndNewlines)))")
            }
        }

        if spec.injectGuestVsockAgent {
            lines.append("output:")
            lines.append("  all: '| tee -a /var/log/cloud-init-output.log /dev/hvc0'")
        }

        // Write files (caller-enriched via GuestAgentBootstrapGenerator on port 1025, or explicit custom script)
        var effectiveFiles = spec.writeFiles
        if spec.injectGuestVsockAgent,
           let customScript = guestAgentScript,
           !customScript.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
           !effectiveFiles.contains(where: {
               $0.guestPath == "/usr/local/sbin/agentvm-guestd.py"
                   || $0.guestPath == "/usr/local/bin/agentvm-guest-agent"
           }) {
            effectiveFiles.append(CloudInitWriteFile(
                guestPath: "/usr/local/bin/agentvm-guest-agent",
                permissionsOctal: "0755",
                owner: "root:root",
                content: customScript
            ))
        }

        if !effectiveFiles.isEmpty {
            lines.append("write_files:")
            for wf in effectiveFiles {
                lines.append("  - path: \(Self.yamlScalar(wf.guestPath))")
                lines.append("    permissions: \(Self.yamlSingleQuoted(wf.permissionsOctal))")
                lines.append("    owner: \(Self.yamlScalar(wf.owner))")
                lines.append("    content: |")
                let normalizedContent = wf.content.replacingOccurrences(of: "\r\n", with: "\n")
                for contentLine in normalizedContent.split(separator: "\n", omittingEmptySubsequences: false) {
                    lines.append("      \(contentLine)")
                }
            }
        }

        // Run commands
        let effectiveRunCmds = spec.runCommands

        if !effectiveRunCmds.isEmpty {
            lines.append("runcmd:")
            for cmd in effectiveRunCmds {
                lines.append("  - \(Self.yamlSingleQuoted(cmd))")
            }
        }

        return lines.joined(separator: "\n") + "\n"
    }

    private func renderNetworkConfigYAML(from spec: CloudInitSpec) -> String {
        var lines: [String] = [
            "version: 2",
            "ethernets:",
            "  id0:",
            "    match:",
            "      name: \"e*\""
        ]

        if let staticCIDR = spec.staticIPv4CIDR?.trimmingCharacters(in: .whitespacesAndNewlines),
           !staticCIDR.isEmpty {
            lines.append("    dhcp4: false")
            lines.append("    addresses:")
            lines.append("      - \(Self.yamlScalar(staticCIDR))")
            if let gw = spec.gatewayIPv4?.trimmingCharacters(in: .whitespacesAndNewlines), !gw.isEmpty {
                lines.append("    routes:")
                lines.append("      - to: default")
                lines.append("        via: \(Self.yamlScalar(gw))")
            }
            if !spec.nameservers.isEmpty {
                lines.append("    nameservers:")
                lines.append("      addresses:")
                for ns in spec.nameservers {
                    lines.append("        - \(Self.yamlScalar(ns))")
                }
            }
        } else {
            lines.append("    dhcp4: true")
            lines.append("    dhcp-identifier: mac")
            if !spec.nameservers.isEmpty {
                lines.append("    nameservers:")
                lines.append("      addresses:")
                for ns in spec.nameservers {
                    lines.append("        - \(Self.yamlScalar(ns))")
                }
            }
        }

        return lines.joined(separator: "\n") + "\n"
    }

    private func renderVendorDataYAML(from spec: CloudInitSpec) -> String {
        let host = CloudInitSpec.sanitizeHostname(spec.hostname)
        var lines: [String] = [
            "#cloud-config",
            "# Generated deterministically by AgentVM ISO9660CloudInitBuilder",
            "bootcmd:",
            "  - [ sh, -c, \"mkdir -p /workspace && chmod 0755 /workspace\" ]",
            "final_message: \"AgentVM guest \(host) (\(spec.instanceID)) ready after $UPTIME seconds\""
        ]
        if spec.injectGuestVsockAgent {
            lines.insert("kernel_modules: [virtio_pci, virtio_blk, virtio_net, virtio_console, vsock, vmw_vsock_virtio_transport_common, vmw_vsock_virtio_transport]", at: 2)
        }
        return lines.joined(separator: "\n") + "\n"
    }

    private static func yamlScalar(_ raw: String) -> String {
        if raw.isEmpty {
            return "''"
        }
        let safeCharset = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./:@")
        let allSafe = raw.unicodeScalars.allSatisfy { safeCharset.contains($0) }
        let reserved = ["true", "false", "null", "yes", "no", "on", "off"]
        if allSafe && !reserved.contains(raw.lowercased()) && !raw.hasPrefix("-") && !raw.hasPrefix("@") {
            return raw
        }
        return yamlSingleQuoted(raw)
    }

    private static func yamlMountField(_ raw: String) -> String {
        if raw.isEmpty || raw.allSatisfy({ $0 >= "0" && $0 <= "9" }) {
            return yamlSingleQuoted(raw)
        }
        return yamlScalar(raw)
    }

    private static func yamlSingleQuoted(_ raw: String) -> String {
        let escaped = raw.replacingOccurrences(of: "'", with: "''")
        return "'\(escaped)'"
    }

    // MARK: - Internal Directory Hierarchy & ISO-9660 Encoding

    private struct DirectoryNode {
        var index: Int // 0-based (Path Table uses index + 1)
        var parentIndex: Int // 0 for Root
        var originalName: String // "" for Root
        var isoIdentifier: String // "" for Root; 1..8 uppercase [A-Z0-9_] for subdirs
        var childDirectoryIndices: [Int]
        var childFileIndices: [Int]
        var inodeNumber: UInt32
    }

    private struct FileNode {
        var index: Int
        var parentDirectoryIndex: Int
        var originalName: String
        var isoIdentifier: String // Uppercase 8.3 + ";1"
        var fullPath: String
        var entry: ISOFileEntry
        var inodeNumber: UInt32
    }

    private struct BuiltTree {
        var directories: [DirectoryNode]
        var files: [FileNode]
    }

    private static func normalizeRelativePath(_ rawPath: String) throws -> (components: [String], joined: String) {
        let trimmed = rawPath.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard !trimmed.isEmpty else {
            throw AgentVMError.iso9660BuildFailed(detail: "File path in ISO-9660 manifest must not be empty.")
        }
        let parts = trimmed.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        for part in parts {
            if part.isEmpty || part == "." || part == ".." {
                throw AgentVMError.iso9660BuildFailed(
                    detail: "Invalid path component '\(part)' in ISO-9660 path '\(rawPath)'."
                )
            }
            if part.utf8.count > 155 {
                throw AgentVMError.iso9660BuildFailed(
                    detail: "Filename '\(part)' exceeds 155-byte single Rock Ridge directory record limit."
                )
            }
        }
        return (components: parts, joined: parts.joined(separator: "/"))
    }

    private static func buildDirectoryHierarchy(
        from entries: [(components: [String], fullPath: String, entry: ISOFileEntry)]
    ) throws -> BuiltTree {
        final class MutableDir {
            let originalName: String
            var subdirs: [String: MutableDir] = [:]
            var files: [(name: String, fullPath: String, entry: ISOFileEntry)] = []
            var assignedBFSIndex: Int = 0
            var parentBFSIndex: Int = 0
            var isoIdentifier: String = ""

            init(originalName: String) {
                self.originalName = originalName
            }
        }

        let root = MutableDir(originalName: "")
        var depthLimitExceeded = false

        for item in entries {
            if item.components.count > 8 {
                // ECMA-119 Level 1 limits directory hierarchy depth to 8 levels (including root).
                depthLimitExceeded = true
            }
            var cur = root
            for dirPart in item.components.dropLast() {
                if let next = cur.subdirs[dirPart] {
                    cur = next
                } else {
                    let created = MutableDir(originalName: dirPart)
                    cur.subdirs[dirPart] = created
                    cur = created
                }
            }
            let leafName = item.components.last!
            cur.files.append((name: leafName, fullPath: item.fullPath, entry: item.entry))
        }

        if depthLimitExceeded {
            throw AgentVMError.iso9660BuildFailed(
                detail: "Directory depth exceeds ISO-9660 ECMA-119 maximum hierarchy depth of 8 levels."
            )
        }

        // BFS traversal so Path Table parent numbers are strictly non-decreasing per ECMA-119 9.4.
        var bfsQueue: [MutableDir] = [root]
        var head = 0
        while head < bfsQueue.count {
            let current = bfsQueue[head]
            current.assignedBFSIndex = head
            var usedDirISOIDs = Set<String>()
            let sortedSubNames = current.subdirs.keys.sorted()
            for subName in sortedSubNames {
                let child = current.subdirs[subName]!
                child.parentBFSIndex = head
                child.isoIdentifier = allocateUniqueISODirName(original: subName, used: &usedDirISOIDs)
                bfsQueue.append(child)
            }
            head += 1
        }

        guard bfsQueue.count <= Int(UInt16.max) else {
            throw AgentVMError.iso9660BuildFailed(detail: "Too many directories for 16-bit ISO-9660 Path Table.")
        }

        var directoryNodes: [DirectoryNode] = []
        directoryNodes.reserveCapacity(bfsQueue.count)
        var fileNodes: [FileNode] = []
        fileNodes.reserveCapacity(entries.count)
        var nextInode: UInt32 = 1

        for dir in bfsQueue {
            let dirInode = nextInode
            nextInode += 1

            let sortedSubNames = dir.subdirs.keys.sorted { lhs, rhs in
                dir.subdirs[lhs]!.isoIdentifier < dir.subdirs[rhs]!.isoIdentifier
            }
            let childDirIndices = sortedSubNames.map { dir.subdirs[$0]!.assignedBFSIndex }

            var usedFileISOIDs = Set<String>()
            var localFiles: [(isoID: String, name: String, fullPath: String, entry: ISOFileEntry)] = []
            for f in dir.files.sorted(by: { $0.name < $1.name }) {
                let isoID = allocateUniqueISOFileName(original: f.name, used: &usedFileISOIDs)
                localFiles.append((isoID: isoID, name: f.name, fullPath: f.fullPath, entry: f.entry))
            }
            // ECMA-119 9.3: sort directory records by ISO File Identifier ascending.
            localFiles.sort { $0.isoID < $1.isoID }

            var childFileIndices: [Int] = []
            for lf in localFiles {
                let fIdx = fileNodes.count
                fileNodes.append(FileNode(
                    index: fIdx,
                    parentDirectoryIndex: dir.assignedBFSIndex,
                    originalName: lf.name,
                    isoIdentifier: lf.isoID,
                    fullPath: lf.fullPath,
                    entry: lf.entry,
                    inodeNumber: nextInode
                ))
                nextInode += 1
                childFileIndices.append(fIdx)
            }

            directoryNodes.append(DirectoryNode(
                index: dir.assignedBFSIndex,
                parentIndex: dir.parentBFSIndex,
                originalName: dir.originalName,
                isoIdentifier: dir.isoIdentifier,
                childDirectoryIndices: childDirIndices,
                childFileIndices: childFileIndices,
                inodeNumber: dirInode
            ))
        }

        return BuiltTree(directories: directoryNodes, files: fileNodes)
    }

    private static func sanitizeISOCharacters(_ text: String, maxLen: Int) -> String {
        var result = ""
        result.reserveCapacity(maxLen)
        for scalar in text.uppercased().unicodeScalars {
            if result.count >= maxLen { break }
            let v = scalar.value
            let isAlpha = (v >= 0x41 && v <= 0x5A)
            let isDigit = (v >= 0x30 && v <= 0x39)
            if isAlpha || isDigit || v == 0x5F {
                result.unicodeScalars.append(scalar)
            } else {
                result.append("_")
            }
        }
        return result.isEmpty ? "FILE" : result
    }

    private static func allocateUniqueISODirName(original: String, used: inout Set<String>) -> String {
        let base = sanitizeISOCharacters(original, maxLen: 8)
        if used.insert(base).inserted {
            return base
        }
        for idx in 1...9999 {
            let suffix = String(idx)
            let prefixLen = max(1, 8 - suffix.count)
            let candidate = String(base.prefix(prefixLen)) + suffix
            if used.insert(candidate).inserted {
                return candidate
            }
        }
        return UUID().uuidString.replacingOccurrences(of: "-", with: "").uppercased().prefix(8).description
    }

    private static func allocateUniqueISOFileName(original: String, used: inout Set<String>) -> String {
        let parts = original.split(separator: ".", maxSplits: 1, omittingEmptySubsequences: false)
        let stemRaw = String(parts[0])
        let extRaw = parts.count > 1 ? String(parts[1]) : ""
        let stem = sanitizeISOCharacters(stemRaw.isEmpty ? "FILE" : stemRaw, maxLen: 8)
        let ext = extRaw.isEmpty ? "" : sanitizeISOCharacters(extRaw, maxLen: 3)

        let primary = "\(stem).\(ext);1"
        if used.insert(primary).inserted {
            return primary
        }
        for idx in 1...9999 {
            let suffix = String(idx)
            let prefixLen = max(1, 8 - suffix.count)
            let candidate = "\(stem.prefix(prefixLen))\(suffix).\(ext);1"
            if used.insert(candidate).inserted {
                return candidate
            }
        }
        let fallback = UUID().uuidString.replacingOccurrences(of: "-", with: "").uppercased().prefix(8)
        return "\(fallback).\(ext);1"
    }

    private static func computePathTableByteLength(directories: [DirectoryNode]) -> Int {
        var total = 0
        for dir in directories {
            let idLen = dir.index == 0 ? 1 : dir.isoIdentifier.utf8.count
            total += 8 + idLen + (idLen % 2 == 1 ? 1 : 0)
        }
        return total
    }

    private static func encodePathTable(
        directories: [DirectoryNode],
        directoryLBAs: [UInt32],
        bigEndian: Bool
    ) -> [UInt8] {
        var writer = BinaryBufferWriter(capacity: computePathTableByteLength(directories: directories))
        for dir in directories {
            let idBytes: [UInt8] = dir.index == 0 ? [0x00] : Array(dir.isoIdentifier.utf8)
            writer.appendUInt8(UInt8(idBytes.count))
            writer.appendUInt8(0) // Extended Attribute Record Length
            let lba = directoryLBAs[dir.index]
            let parentNumber = UInt16(dir.parentIndex + 1)
            if bigEndian {
                writer.appendUInt32BE(lba)
                writer.appendUInt16BE(parentNumber)
            } else {
                writer.appendUInt32LE(lba)
                writer.appendUInt16LE(parentNumber)
            }
            writer.appendBytes(idBytes)
            if idBytes.count % 2 == 1 {
                writer.appendUInt8(0x00)
            }
        }
        return writer.bytes
    }

    private static func encodePrimaryVolumeDescriptor(
        volumeIdentifier: String,
        volumeSpaceBlocks: UInt32,
        pathTableByteSize: UInt32,
        typeLPathTableLBA: UInt32,
        typeMPathTableLBA: UInt32,
        rootDirectoryLBA: UInt32,
        rootDirectoryByteLength: UInt32
    ) -> [UInt8] {
        var w = BinaryBufferWriter(capacity: sectorSize)
        w.appendUInt8(0x01) // Type 1: Primary Volume Descriptor
        w.appendFixedASCII(standardIdentifierASCII, length: 5, padByte: 0x20) // "CD001"
        w.appendUInt8(0x01) // Version 1
        w.appendUInt8(0x00) // Unused
        w.appendFixedASCII("AGENTVM HYPERVISOR", length: 32, padByte: 0x20) // System Identifier (8..<40)
        w.appendFixedASCII(volumeIdentifier, length: 32, padByte: 0x20) // Volume Identifier (40..<72)
        w.appendBytes([UInt8](repeating: 0x00, count: 8)) // Unused (72..<80)
        w.appendUInt32BothEndian(volumeSpaceBlocks) // Volume Space Size (80..<88)
        w.appendBytes([UInt8](repeating: 0x00, count: 32)) // Unused (88..<120)
        w.appendUInt16BothEndian(1) // Volume Set Size (120..<124)
        w.appendUInt16BothEndian(1) // Volume Sequence Number (124..<128)
        w.appendUInt16BothEndian(UInt16(sectorSize)) // Logical Block Size = 2048 (128..<132)
        w.appendUInt32BothEndian(pathTableByteSize) // Path Table Size (132..<140)
        w.appendUInt32LE(typeLPathTableLBA) // Location of Type-L Path Table (140..<144)
        w.appendUInt32LE(0) // Optional Type-L Path Table (144..<148)
        w.appendUInt32BE(typeMPathTableLBA) // Location of Type-M Path Table (148..<152)
        w.appendUInt32BE(0) // Optional Type-M Path Table (152..<156)

        // 34-byte Root Directory Record at offset 156..<190
        let rootRecord = encodeDirectoryRecord(
            extentLBA: rootDirectoryLBA,
            dataLength: rootDirectoryByteLength,
            isDirectory: true,
            isoIdentifierBytes: [0x00],
            systemUseBytes: []
        )
        precondition(rootRecord.count == 34)
        w.appendBytes(rootRecord)

        w.appendFixedASCII("AGENTVM_CLOUDINIT", length: 128, padByte: 0x20) // Volume Set ID (190..<318)
        w.appendFixedASCII("AGENTVM", length: 128, padByte: 0x20) // Publisher ID (318..<446)
        w.appendFixedASCII("AGENTVM ISO9660 BUILDER", length: 128, padByte: 0x20) // Data Preparer ID (446..<574)
        w.appendFixedASCII("AGENTVM STORAGE COW ENGINE", length: 128, padByte: 0x20) // Application ID (574..<702)
        w.appendFixedASCII("", length: 37, padByte: 0x20) // Copyright File ID (702..<739)
        w.appendFixedASCII("", length: 37, padByte: 0x20) // Abstract File ID (739..<776)
        w.appendFixedASCII("", length: 37, padByte: 0x20) // Bibliographical File ID (776..<813)

        // Four 17-byte ASCII timestamps (16 ASCII digits + 1 GMT offset byte)
        appendPVD17ByteTimestamp(&w, digits16: deterministicPVDTimestampASCII) // Creation (813..<830)
        appendPVD17ByteTimestamp(&w, digits16: deterministicPVDTimestampASCII) // Modification (830..<847)
        appendPVD17ByteTimestamp(&w, digits16: zeroPVDTimestampASCII)          // Expiration (847..<864)
        appendPVD17ByteTimestamp(&w, digits16: deterministicPVDTimestampASCII) // Effective (864..<881)

        w.appendUInt8(0x01) // File Structure Version = 1 (881)
        w.appendUInt8(0x00) // Unused (882)
        w.appendBytes([UInt8](repeating: 0x00, count: 512)) // Application Use (883..<1395)
        w.appendBytes([UInt8](repeating: 0x00, count: 653)) // Reserved (1395..<2048)

        return w.bytes
    }

    private static func appendPVD17ByteTimestamp(_ writer: inout BinaryBufferWriter, digits16: String) {
        writer.appendFixedASCII(digits16, length: 16, padByte: 0x30)
        writer.appendUInt8(0x00) // UTC offset (0 quarter-hours)
    }

    private static func serializeDirectoryExtent(
        directoryIndex: Int,
        tree: BuiltTree,
        directoryLBAs: [UInt32],
        directoryByteLengths: [UInt32],
        fileLBAs: [UInt32]
    ) throws -> [UInt8] {
        let dir = tree.directories[directoryIndex]
        let parentDir = tree.directories[dir.parentIndex]
        let dirLinks = UInt32(2 + dir.childDirectoryIndices.count)
        let parentLinks = UInt32(2 + parentDir.childDirectoryIndices.count)

        var records: [[UInt8]] = []

        // 1. "." self entry (id = [0x00]). Root "." carries SUSP `SP` signature (`0xBE, 0xEF`) + `PX`.
        var selfSU: [UInt8] = []
        if directoryIndex == 0 {
            selfSU.append(contentsOf: [0x53, 0x50, 7, 1, 0xBE, 0xEF, 0x00]) // "SP"
        }
        selfSU.append(contentsOf: encodeRockRidgePX(
            posixMode: 0o040755,
            nlink: dirLinks,
            inode: dir.inodeNumber
        ))
        records.append(encodeDirectoryRecord(
            extentLBA: directoryLBAs[directoryIndex],
            dataLength: directoryByteLengths[directoryIndex],
            isDirectory: true,
            isoIdentifierBytes: [0x00],
            systemUseBytes: selfSU
        ))

        // 2. ".." parent entry (id = [0x01]).
        let parentSU = encodeRockRidgePX(
            posixMode: 0o040755,
            nlink: parentLinks,
            inode: parentDir.inodeNumber
        )
        records.append(encodeDirectoryRecord(
            extentLBA: directoryLBAs[dir.parentIndex],
            dataLength: directoryByteLengths[dir.parentIndex],
            isDirectory: true,
            isoIdentifierBytes: [0x01],
            systemUseBytes: parentSU
        ))

        // 3. Merge child directories and child files sorted by ISO Level-1 Identifier per ECMA-119 9.3.
        struct ChildItem {
            var sortKey: String
            var recordBytes: [UInt8]
        }
        var children: [ChildItem] = []
        children.reserveCapacity(dir.childDirectoryIndices.count + dir.childFileIndices.count)

        for childDirIdx in dir.childDirectoryIndices {
            let childDir = tree.directories[childDirIdx]
            var su = encodeRockRidgePX(
                posixMode: 0o040755,
                nlink: UInt32(2 + childDir.childDirectoryIndices.count),
                inode: childDir.inodeNumber
            )
            su.append(contentsOf: encodeRockRidgeNM(name: childDir.originalName))
            let rec = encodeDirectoryRecord(
                extentLBA: directoryLBAs[childDirIdx],
                dataLength: directoryByteLengths[childDirIdx],
                isDirectory: true,
                isoIdentifierBytes: Array(childDir.isoIdentifier.utf8),
                systemUseBytes: su
            )
            children.append(ChildItem(sortKey: childDir.isoIdentifier, recordBytes: rec))
        }

        for childFileIdx in dir.childFileIndices {
            let childFile = tree.files[childFileIdx]
            let modeBits = UInt32(0o100000) | UInt32(childFile.entry.posixMode & 0o7777)
            var su = encodeRockRidgePX(
                posixMode: modeBits,
                nlink: 1,
                inode: childFile.inodeNumber
            )
            su.append(contentsOf: encodeRockRidgeNM(name: childFile.originalName))
            let rec = encodeDirectoryRecord(
                extentLBA: fileLBAs[childFileIdx],
                dataLength: UInt32(childFile.entry.data.count),
                isDirectory: false,
                isoIdentifierBytes: Array(childFile.isoIdentifier.utf8),
                systemUseBytes: su
            )
            children.append(ChildItem(sortKey: childFile.isoIdentifier, recordBytes: rec))
        }

        children.sort { $0.sortKey < $1.sortKey }
        for item in children {
            records.append(item.recordBytes)
        }

        // Pack records into 2048-byte sectors without crossing any sector boundary (ECMA-119 6.8.1.1).
        var extentWriter = BinaryBufferWriter(capacity: sectorSize)
        var currentSectorUsed = 0

        for rec in records {
            guard rec.count <= 254 else {
                throw AgentVMError.iso9660BuildFailed(
                    detail: "Encoded ISO-9660 directory record length \(rec.count) exceeds 254-byte maximum."
                )
            }
            if currentSectorUsed + rec.count > sectorSize {
                extentWriter.padToAlignment(sectorSize, fillByte: 0x00)
                currentSectorUsed = 0
            }
            extentWriter.appendBytes(rec)
            currentSectorUsed += rec.count
        }

        if extentWriter.count == 0 || (extentWriter.count % sectorSize != 0) {
            extentWriter.padToAlignment(sectorSize, fillByte: 0x00)
        }
        return extentWriter.bytes
    }

    private static func encodeDirectoryRecord(
        extentLBA: UInt32,
        dataLength: UInt32,
        isDirectory: Bool,
        isoIdentifierBytes: [UInt8],
        systemUseBytes: [UInt8]
    ) -> [UInt8] {
        var w = BinaryBufferWriter(capacity: 64 + systemUseBytes.count)
        w.appendUInt8(0) // Placeholder for Directory Record Length (patched below)
        w.appendUInt8(0) // Extended Attribute Record Length
        w.appendUInt32BothEndian(extentLBA)
        w.appendUInt32BothEndian(dataLength)
        w.appendBytes(deterministicDirTimestamp) // 7-byte recording timestamp
        w.appendUInt8(isDirectory ? 0x02 : 0x00) // File Flags (bit 1 = directory)
        w.appendUInt8(0) // File Unit Size
        w.appendUInt8(0) // Interleave Gap Size
        w.appendUInt16BothEndian(1) // Volume Sequence Number = 1
        w.appendUInt8(UInt8(isoIdentifierBytes.count))
        w.appendBytes(isoIdentifierBytes)

        // ECMA-119 9.1.12: Pad byte present iff File Identifier length is EVEN so System Use starts on even offset.
        if isoIdentifierBytes.count % 2 == 0 {
            w.appendUInt8(0x00)
        }

        if !systemUseBytes.isEmpty {
            w.appendBytes(systemUseBytes)
            if w.count % 2 != 0 {
                w.appendUInt8(0x00)
            }
        }

        var raw = w.bytes
        raw[0] = UInt8(raw.count)
        return raw
    }

    /// Encodes a 44-byte Rock Ridge `PX` (POSIX File Attributes, RRIP v1.12) System Use Entry.
    private static func encodeRockRidgePX(posixMode: UInt32, nlink: UInt32, inode: UInt32) -> [UInt8] {
        var w = BinaryBufferWriter(capacity: 44)
        w.appendUInt8(0x50) // 'P'
        w.appendUInt8(0x58) // 'X'
        w.appendUInt8(44)   // Length = 44
        w.appendUInt8(1)    // Version = 1
        w.appendUInt32BothEndian(posixMode)
        w.appendUInt32BothEndian(nlink)
        w.appendUInt32BothEndian(0) // uid = 0
        w.appendUInt32BothEndian(0) // gid = 0
        w.appendUInt32BothEndian(inode)
        return w.bytes
    }

    /// Encodes a Rock Ridge `NM` (Alternate Name) System Use Entry preserving exact case and punctuation.
    private static func encodeRockRidgeNM(name: String) -> [UInt8] {
        let utf8 = Array(name.utf8)
        var w = BinaryBufferWriter(capacity: 5 + utf8.count)
        w.appendUInt8(0x4E) // 'N'
        w.appendUInt8(0x4D) // 'M'
        w.appendUInt8(UInt8(5 + utf8.count))
        w.appendUInt8(1)    // Version = 1
        w.appendUInt8(0x00) // Flags = 0 (complete name in this NM entry)
        w.appendBytes(utf8)
        return w.bytes
    }

    // MARK: - Internal ISO-9660 + Rock Ridge Decoder

    private struct ParsedISOContainer {
        var report: ISOInspectionReport
        var extractedFiles: [String: Data]
    }

    private func parseISOContainerInternal(data: Data) throws -> ParsedISOContainer {
        guard data.count >= (Self.vdstSectorIndex + 1) * Self.sectorSize else {
            throw AgentVMError.iso9660BuildFailed(
                detail: "ISO-9660 image buffer too small (\(data.count) bytes; requires at least 36,864 bytes)."
            )
        }

        let bytes = [UInt8](data)
        var foundPVDSectorOffset: Int?

        // Scan Volume Descriptor Set starting at 32 KiB (offset 16 * 2048).
        var descriptorOffset = Self.pvdSectorIndex * Self.sectorSize
        while descriptorOffset + Self.sectorSize <= bytes.count && descriptorOffset < 64 * Self.sectorSize {
            let vdType = bytes[descriptorOffset]
            let ident = String(decoding: bytes[(descriptorOffset + 1)..<(descriptorOffset + 6)], as: UTF8.self)
            let version = bytes[descriptorOffset + 6]
            guard ident == Self.standardIdentifierASCII else {
                throw AgentVMError.iso9660BuildFailed(
                    detail: "Invalid ISO-9660 Volume Descriptor identifier '\(ident)' at offset \(descriptorOffset)."
                )
            }
            if vdType == 0x01 && version == 0x01 {
                foundPVDSectorOffset = descriptorOffset
            } else if vdType == 0xFF {
                break
            }
            descriptorOffset += Self.sectorSize
        }

        guard let pvdOffset = foundPVDSectorOffset else {
            throw AgentVMError.iso9660BuildFailed(
                detail: "Missing Primary Volume Descriptor (type 0x01, 'CD001') in ISO-9660 image."
            )
        }

        var pvdCursor = BinaryCursor(bytes: bytes, offset: pvdOffset)
        try pvdCursor.skip(8)
        let systemID = try pvdCursor.readASCII(32, trimTrailingSpaces: true)
        let volumeID = try pvdCursor.readASCII(32, trimTrailingSpaces: true)
        try pvdCursor.skip(8)
        let volumeSpaceLE = try pvdCursor.readUInt32LE()
        try pvdCursor.skip(4) // BE mirror
        try pvdCursor.skip(32 + 4 + 4)
        let logicalBlockSizeLE = try pvdCursor.readUInt16LE()
        try pvdCursor.skip(2) // BE mirror
        try pvdCursor.skip(8) // Path Table Size both-endian
        let typeLLBA = try pvdCursor.readUInt32LE()
        try pvdCursor.skip(4)
        let typeMLBA = try pvdCursor.readUInt32BE()
        try pvdCursor.skip(4)

        let blockSize = Int(logicalBlockSizeLE)
        guard blockSize >= 512 && (blockSize & (blockSize - 1)) == 0 else {
            throw AgentVMError.iso9660BuildFailed(
                detail: "Invalid ISO-9660 logical block size \(logicalBlockSizeLE)."
            )
        }

        // Parse 34-byte Root Directory Record at PVD + 156.
        let rootRecStart = pvdOffset + 156
        var rootRecCursor = BinaryCursor(bytes: bytes, offset: rootRecStart)
        let rootRecLen = Int(try rootRecCursor.readUInt8())
        guard rootRecLen >= 34 else {
            throw AgentVMError.iso9660BuildFailed(detail: "Malformed Root Directory Record in PVD (len=\(rootRecLen)).")
        }
        _ = try rootRecCursor.readUInt8()
        let rootExtentLBA = try rootRecCursor.readUInt32LE()
        try rootRecCursor.skip(4)
        let rootExtentLength = try rootRecCursor.readUInt32LE()

        var extractedFiles: [String: Data] = [:]
        var entryDetails: [ISOInspectionEntryDetail] = []
        var sawRockRidgeSP = false
        var visitedDirLBAs = Set<UInt32>()

        func traverseDirectory(extentLBA: UInt32, byteLength: UInt32, prefix: String) throws {
            guard visitedDirLBAs.insert(extentLBA).inserted else { return }
            let dirByteStart = Int(extentLBA) * blockSize
            let dirByteEnd = dirByteStart + Int(byteLength)
            guard dirByteStart >= 0 && dirByteEnd <= bytes.count else {
                throw AgentVMError.iso9660BuildFailed(
                    detail: "Directory extent LBA \(extentLBA) (\(byteLength) B) exceeds image bounds (\(bytes.count) B)."
                )
            }

            var pos = dirByteStart
            while pos < dirByteEnd {
                let recLen = Int(bytes[pos])
                if recLen == 0 {
                    // Advance to the start of the next logical sector per ECMA-119 6.8.1.1.
                    let nextSector = ((pos / blockSize) + 1) * blockSize
                    pos = nextSector
                    continue
                }
                guard recLen >= 34 && pos + recLen <= dirByteEnd else {
                    throw AgentVMError.iso9660BuildFailed(
                        detail: "Corrupt ISO-9660 directory record (len=\(recLen)) at byte offset \(pos)."
                    )
                }

                var rc = BinaryCursor(bytes: bytes, offset: pos + 2)
                let entryLBA = try rc.readUInt32LE()
                try rc.skip(4)
                let entrySize = try rc.readUInt32LE()
                try rc.skip(4)
                try rc.skip(7) // Recording timestamp
                let fileFlags = try rc.readUInt8()
                try rc.skip(6) // Unit size, gap size, volume seq number
                let idLen = Int(try rc.readUInt8())
                guard 33 + idLen <= recLen else {
                    throw AgentVMError.iso9660BuildFailed(
                        detail: "File identifier length \(idLen) overflows directory record (\(recLen) B)."
                    )
                }
                let idBytes = try rc.readBytes(idLen)

                // Locate System Use Area (even byte alignment after File Identifier).
                var suOffset = 33 + idLen + (idLen % 2 == 0 ? 1 : 0)
                var rrNameChunks: [UInt8] = []
                var hasRRName = false
                var rrPosixMode: UInt16?

                while suOffset + 4 <= recLen {
                    let sig0 = bytes[pos + suOffset]
                    let sig1 = bytes[pos + suOffset + 1]
                    let suLen = Int(bytes[pos + suOffset + 2])
                    if sig0 == 0 || suLen < 4 || suOffset + suLen > recLen {
                        break
                    }
                    if sig0 == 0x53 && sig1 == 0x50 && suLen >= 7 { // "SP"
                        if bytes[pos + suOffset + 4] == 0xBE && bytes[pos + suOffset + 5] == 0xEF {
                            sawRockRidgeSP = true
                        }
                    } else if sig0 == 0x50 && sig1 == 0x58 && suLen >= 36 { // "PX"
                        var pxCursor = BinaryCursor(bytes: bytes, offset: pos + suOffset + 4)
                        let mode32 = try pxCursor.readUInt32LE()
                        rrPosixMode = UInt16(mode32 & 0o7777)
                    } else if sig0 == 0x4E && sig1 == 0x4D && suLen >= 5 { // "NM"
                        let nmFlags = bytes[pos + suOffset + 4]
                        // Bits 1 (CURRENT) and 2 (PARENT) indicate '.' and '..'; bit 0 is CONTINUE.
                        if (nmFlags & 0x06) == 0 && suLen > 5 {
                            let nameSlice = bytes[(pos + suOffset + 5)..<(pos + suOffset + suLen)]
                            rrNameChunks.append(contentsOf: nameSlice)
                            hasRRName = true
                        }
                    }
                    suOffset += suLen
                }

                let isSelfEntry = (idBytes == [0x00])
                let isParentEntry = (idBytes == [0x01])

                if !isSelfEntry && !isParentEntry {
                    let isoNameRaw = String(decoding: idBytes, as: UTF8.self)
                    let resolvedName: String
                    if hasRRName, !rrNameChunks.isEmpty {
                        resolvedName = String(decoding: rrNameChunks, as: UTF8.self)
                    } else {
                        resolvedName = Self.cleanISO9660FallbackName(isoNameRaw)
                    }

                    let relPath = prefix.isEmpty ? resolvedName : "\(prefix)/\(resolvedName)"
                    let isDir = (fileFlags & 0x02) != 0

                    if isDir {
                        try traverseDirectory(extentLBA: entryLBA, byteLength: entrySize, prefix: relPath)
                    } else {
                        let fileStart = Int(entryLBA) * blockSize
                        let fileEnd = fileStart + Int(entrySize)
                        guard entrySize == 0 || (fileStart >= 0 && fileEnd <= bytes.count) else {
                            throw AgentVMError.iso9660BuildFailed(
                                detail: "File '\(relPath)' extent (LBA=\(entryLBA), size=\(entrySize)) exceeds ISO bounds."
                            )
                        }
                        let payload = entrySize == 0 ? Data() : Data(bytes[fileStart..<fileEnd])
                        extractedFiles[relPath] = payload
                        entryDetails.append(ISOInspectionEntryDetail(
                            path: relPath,
                            isoLevel1Identifier: isoNameRaw,
                            extentLBA: entryLBA,
                            sizeBytes: entrySize,
                            posixMode: rrPosixMode,
                            sha256Hex: BinaryChecksums.sha256Hex(payload)
                        ))
                    }
                }

                pos += recLen
            }
        }

        try traverseDirectory(extentLBA: rootExtentLBA, byteLength: rootExtentLength, prefix: "")

        let report = ISOInspectionReport(
            systemIdentifier: systemID,
            volumeIdentifier: volumeID,
            logicalBlockSize: logicalBlockSizeLE,
            volumeSpaceBlocks: volumeSpaceLE,
            typeLPathTableLBA: typeLLBA,
            typeMPathTableLBA: typeMLBA,
            hasRockRidgeSUSP: sawRockRidgeSP,
            entries: entryDetails.sorted { $0.path < $1.path }
        )

        return ParsedISOContainer(report: report, extractedFiles: extractedFiles)
    }

    private static func cleanISO9660FallbackName(_ raw: String) -> String {
        var name = raw
        if let semiRange = name.range(of: ";", options: .backwards) {
            name = String(name[..<semiRange.lowerBound])
        }
        if name.hasSuffix(".") {
            name.removeLast()
        }
        return name.lowercased()
    }
}
