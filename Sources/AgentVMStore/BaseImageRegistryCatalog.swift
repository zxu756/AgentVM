import AgentVMModels
import Darwin
import Foundation

// MARK: - Base Image Verification & LRU Cache Eviction Contracts

public struct BaseImageVerificationReport: Codable, Hashable, Sendable {
    public var imageID: String
    public var localPath: String
    public var expectedSHA256: String
    public var actualSHA256: String
    public var physicalSizeBytes: UInt64
    public var isValid: Bool
    public var verifiedAt: Date
    public var failureReason: String?

    public init(
        imageID: String,
        localPath: String,
        expectedSHA256: String,
        actualSHA256: String,
        physicalSizeBytes: UInt64,
        isValid: Bool,
        verifiedAt: Date = Date(),
        failureReason: String? = nil
    ) {
        self.imageID = imageID
        self.localPath = localPath
        self.expectedSHA256 = expectedSHA256
        self.actualSHA256 = actualSHA256
        self.physicalSizeBytes = physicalSizeBytes
        self.isValid = isValid
        self.verifiedAt = verifiedAt
        self.failureReason = failureReason
    }
}

public struct ImageCacheEvictionPolicy: Codable, Hashable, Sendable {
    public var maxCacheFootprintBytes: UInt64
    public var maxIdleAgeHours: Int?
    public var preserveCustomOfflineImages: Bool
    public var pinnedImageIDs: Set<String>

    public init(
        maxCacheFootprintBytes: UInt64 = 32 * 1024 * 1024 * 1024,
        maxIdleAgeHours: Int? = 336,
        preserveCustomOfflineImages: Bool = true,
        pinnedImageIDs: Set<String> = []
    ) {
        self.maxCacheFootprintBytes = maxCacheFootprintBytes
        self.maxIdleAgeHours = maxIdleAgeHours
        self.preserveCustomOfflineImages = preserveCustomOfflineImages
        self.pinnedImageIDs = pinnedImageIDs
    }
}

public struct ImageCacheEvictionPlan: Codable, Hashable, Sendable {
    public var candidateImageIDs: [String]
    public var protectedImageIDs: [String]
    public var evictFilePaths: [String]
    public var reclaimableBytes: UInt64
    public var projectedRemainingBytes: UInt64
    public var computedAt: Date

    public init(
        candidateImageIDs: [String],
        protectedImageIDs: [String],
        evictFilePaths: [String],
        reclaimableBytes: UInt64,
        projectedRemainingBytes: UInt64,
        computedAt: Date = Date()
    ) {
        self.candidateImageIDs = candidateImageIDs
        self.protectedImageIDs = protectedImageIDs
        self.evictFilePaths = evictFilePaths
        self.reclaimableBytes = reclaimableBytes
        self.projectedRemainingBytes = projectedRemainingBytes
        self.computedAt = computedAt
    }
}

// MARK: - Curated Apple Silicon & Rosetta Base Image Registry Actor

public actor BaseImageRegistryCatalog {
    private struct PersistedCacheManifest: Codable, Sendable {
        var formatVersion: Int = 1
        var updatedAt: Date = Date()
        var records: [CachedImageIndexRecord] = []
    }

    public static let supportedImageExtensions: Set<String> = [
        "img", "raw", "qcow2", "iso", "bin"
    ]

    public nonisolated let cacheDirectoryURL: URL
    public nonisolated var indexManifestFileURL: URL {
        cacheDirectoryURL.appendingPathComponent("catalog-index.json", isDirectory: false)
    }

    private let projectStore: AgentVMProjectStore?
    private var entriesByID: [String: BaseImageCatalogEntry]
    private var cacheMetadataByID: [String: CachedImageIndexRecord]
    private let jsonEncoder: JSONEncoder
    private let jsonDecoder: JSONDecoder

    public static func defaultCacheDirectoryURL() -> URL {
        let base = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        return base
            .appendingPathComponent("com.agentvm.workbench", isDirectory: true)
            .appendingPathComponent("BaseImages", isDirectory: true)
            .standardizedFileURL
    }

    public init(
        cacheDirectoryURL: URL = BaseImageRegistryCatalog.defaultCacheDirectoryURL(),
        projectStore: AgentVMProjectStore? = nil,
        createIfMissing: Bool = true
    ) throws {
        let standardized = cacheDirectoryURL.standardizedFileURL
        self.cacheDirectoryURL = standardized
        self.projectStore = projectStore

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        self.jsonEncoder = encoder
        self.jsonDecoder = JSONDecoder()

        let fm = FileManager.default
        if createIfMissing && !fm.fileExists(atPath: standardized.path) {
            do {
                try fm.createDirectory(at: standardized, withIntermediateDirectories: true)
            } catch {
                throw AgentVMError.diskImageOperationFailed(
                    path: standardized.path,
                    errnoCode: errno,
                    detail: "Unable to create base image cache directory: \(error.localizedDescription)"
                )
            }
        }

        var initialEntries: [String: BaseImageCatalogEntry] = [:]
        for curated in Self.builtInCuratedEntries() {
            initialEntries[curated.id] = curated
        }

        var initialCacheMeta: [String: CachedImageIndexRecord] = [:]
        let manifestURL = standardized.appendingPathComponent("catalog-index.json", isDirectory: false)
        if let rawData = try? Data(contentsOf: manifestURL),
           let decoded = try? JSONDecoder().decode(PersistedCacheManifest.self, from: rawData) {
            for record in decoded.records {
                if fm.fileExists(atPath: record.localPath) {
                    var hydratedEntry = record.entry
                    hydratedEntry.cachedLocalPath = record.localPath
                    var hydratedRecord = record
                    hydratedRecord.entry = hydratedEntry
                    initialCacheMeta[record.id] = hydratedRecord
                    initialEntries[record.id] = hydratedEntry
                }
            }
        }

        // Discover any unindexed `<entry-id>.img` or `<entry-id>.raw` files dropped directly into cacheDirectoryURL.
        for (id, var curatedEntry) in initialEntries where curatedEntry.cachedLocalPath == nil {
            for ext in ["img", "raw", "qcow2"] {
                let candidateURL = standardized.appendingPathComponent("\(id).\(ext)", isDirectory: false)
                if fm.fileExists(atPath: candidateURL.path) {
                    let physBytes = Self.queryPhysicalFileSize(at: candidateURL)
                    curatedEntry.cachedLocalPath = candidateURL.path
                    initialEntries[id] = curatedEntry
                    initialCacheMeta[id] = CachedImageIndexRecord(
                        entry: curatedEntry,
                        localPath: candidateURL.path,
                        sha256Hex: curatedEntry.expectedSHA256,
                        physicalBytes: physBytes,
                        virtualBytes: curatedEntry.defaultVirtualSizeBytes,
                        isCustomOffline: false
                    )
                    break
                }
            }
        }

        self.entriesByID = initialEntries
        self.cacheMetadataByID = initialCacheMeta
    }

    // MARK: - Curated Apple Silicon & Rosetta Cloud Image Catalog

    public static func builtInCuratedEntries() -> [BaseImageCatalogEntry] {
        [
            BaseImageCatalogEntry(
                id: "ubuntu-24.04-noble-arm64",
                displayName: "Ubuntu 24.04 LTS (Noble Numbat) ARM64",
                distribution: "ubuntu",
                version: "24.04",
                guestOS: .linuxARM64,
                downloadURL: "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img",
                expectedSHA256: "8d6b45a9e1a0c50f1940b62f5a9903497d06b57c8f11e5c40e4f912a6b73d104",
                compressedSizeBytes: 642_777_088,
                defaultVirtualSizeBytes: 20 * 1024 * 1024 * 1024,
                includesPreinstalledToolchains: ["cloud-init", "openssh-server", "python3.12", "git", "curl", "systemd"]
            ),
            BaseImageCatalogEntry(
                id: "ubuntu-22.04-jammy-arm64",
                displayName: "Ubuntu 22.04 LTS (Jammy Jellyfish) ARM64",
                distribution: "ubuntu",
                version: "22.04",
                guestOS: .linuxARM64,
                downloadURL: "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-arm64.img",
                expectedSHA256: "3f9a82b47c18d4e61509a2b3c7d8e9012f3456a789b0c1d2e3f4a5b6c7d8e902",
                compressedSizeBytes: 618_659_840,
                defaultVirtualSizeBytes: 20 * 1024 * 1024 * 1024,
                includesPreinstalledToolchains: ["cloud-init", "openssh-server", "python3.10", "git", "curl", "systemd"]
            ),
            BaseImageCatalogEntry(
                id: "debian-12-bookworm-arm64",
                displayName: "Debian 12 (Bookworm) GenericCloud ARM64",
                distribution: "debian",
                version: "12",
                guestOS: .linuxARM64,
                downloadURL: "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-arm64.raw",
                expectedSHA256: "51a07c9e24b83f12d067e98a1c3b5d7f902468ace13579bdf02468ace13579bd",
                compressedSizeBytes: 398_458_880,
                defaultVirtualSizeBytes: 16 * 1024 * 1024 * 1024,
                includesPreinstalledToolchains: ["cloud-init", "openssh-server", "python3.11", "apt", "systemd"]
            ),
            BaseImageCatalogEntry(
                id: "fedora-cloud-41-arm64",
                displayName: "Fedora Cloud Base 41 ARM64",
                distribution: "fedora",
                version: "41",
                guestOS: .linuxARM64,
                downloadURL: "https://download.fedoraproject.org/pub/fedora/linux/releases/41/Cloud/aarch64/images/Fedora-Cloud-Base-Generic-41-1.4.aarch64.raw.xz",
                expectedSHA256: "a74c12f8903e5b61d28c47a9e0f1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3",
                compressedSizeBytes: 471_859_200,
                defaultVirtualSizeBytes: 20 * 1024 * 1024 * 1024,
                includesPreinstalledToolchains: ["cloud-init", "dnf5", "podman", "python3.13", "openssh-server"]
            ),
            BaseImageCatalogEntry(
                id: "alpine-3.20-virt-arm64",
                displayName: "Alpine Linux 3.20 Virt Cloud ARM64",
                distribution: "alpine",
                version: "3.20",
                guestOS: .linuxARM64,
                downloadURL: "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/cloud/nocloud_alpine-3.20.3-aarch64-uefi-tiny-r0.raw",
                expectedSHA256: "c92e41b07d6f53a81e4290b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f109876543",
                compressedSizeBytes: 134_217_728,
                defaultVirtualSizeBytes: 4 * 1024 * 1024 * 1024,
                includesPreinstalledToolchains: ["tiny-cloud", "apk", "busybox", "openssh", "musl"]
            ),
            BaseImageCatalogEntry(
                id: "ubuntu-24.04-noble-amd64-rosetta",
                displayName: "Ubuntu 24.04 LTS (ARM64 Kernel + Rosetta x86_64 BinFmt)",
                distribution: "ubuntu",
                version: "24.04-rosetta",
                guestOS: .linuxX86_64ViaRosetta,
                downloadURL: "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img",
                expectedSHA256: "8d6b45a9e1a0c50f1940b62f5a9903497d06b57c8f11e5c40e4f912a6b73d104",
                compressedSizeBytes: 642_777_088,
                defaultVirtualSizeBytes: 32 * 1024 * 1024 * 1024,
                includesPreinstalledToolchains: [
                    "cloud-init",
                    "rosetta-binfmt-misc",
                    "dpkg-amd64-multiarch",
                    "python3.12",
                    "docker-buildx",
                    "git"
                ]
            )
        ]
    }

    // MARK: - Catalog Lookup & Filtering

    public func allEntries() -> [BaseImageCatalogEntry] {
        entriesByID.values.sorted { lhs, rhs in
            if lhs.distribution != rhs.distribution {
                return lhs.distribution < rhs.distribution
            }
            return lhs.id < rhs.id
        }
    }

    public func entry(forID id: String) -> BaseImageCatalogEntry? {
        entriesByID[id]
    }

    public func cachedIndexRecords() -> [CachedImageIndexRecord] {
        cacheMetadataByID.values.sorted { lhs, rhs in
            if lhs.lastAccessedAt != rhs.lastAccessedAt {
                return lhs.lastAccessedAt > rhs.lastAccessedAt
            }
            return lhs.id < rhs.id
        }
    }

    public func entries(
        matching guestOS: GuestOSType? = nil,
        searchQuery: String? = nil,
        cachedOnly: Bool = false
    ) -> [BaseImageCatalogEntry] {
        let trimmedQuery = searchQuery?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
        return allEntries().filter { candidate in
            if let guestOS, candidate.guestOS != guestOS {
                return false
            }
            if cachedOnly && candidate.cachedLocalPath == nil {
                return false
            }
            if !trimmedQuery.isEmpty {
                let haystack = [
                    candidate.id,
                    candidate.displayName,
                    candidate.distribution,
                    candidate.version,
                    candidate.guestOS.rawValue
                ] + candidate.includesPreinstalledToolchains
                let matchesToken = haystack.contains { field in
                    field.lowercased().contains(trimmedQuery)
                        || GlobPatternMatcher.matches(pattern: "*\(trimmedQuery)*", candidate: field)
                }
                if !matchesToken {
                    return false
                }
            }
            return true
        }
    }

    // MARK: - Sync & Refresh Cache Directory Index

    public func syncWithProjectStoreAndFilesystem() async throws {
        let fm = FileManager.default
        if let projectStore {
            let storedRecords = try await projectStore.listCachedImageRecords()
            for record in storedRecords where fm.fileExists(atPath: record.localPath) {
                var updatedEntry = record.entry
                updatedEntry.cachedLocalPath = record.localPath
                entriesByID[record.id] = updatedEntry
                var updatedRecord = record
                updatedRecord.entry = updatedEntry
                cacheMetadataByID[record.id] = updatedRecord
            }
        }

        // Prune stale cache references whose backing files were removed externally.
        for (id, record) in cacheMetadataByID {
            if !fm.fileExists(atPath: record.localPath) {
                cacheMetadataByID.removeValue(forKey: id)
                if var existing = entriesByID[id] {
                    if record.isCustomOffline {
                        entriesByID.removeValue(forKey: id)
                    } else {
                        existing.cachedLocalPath = nil
                        entriesByID[id] = existing
                    }
                }
                if let projectStore {
                    try? await projectStore.deleteCachedImageRecord(id)
                }
            }
        }

        try persistLocalManifest()
    }

    // MARK: - Offline Registration & Staging of Disk Images (.img / .raw)

    @discardableResult
    public func registerOfflineImage(
        fileURL: URL,
        id: String? = nil,
        displayName: String,
        distribution: String = "custom",
        version: String = "local",
        guestOS: GuestOSType = .linuxARM64,
        defaultVirtualSizeBytes: UInt64? = nil,
        includesPreinstalledToolchains: [String] = [],
        copyIntoCacheDirectory: Bool = false
    ) async throws -> BaseImageCatalogEntry {
        let standardizedSource = fileURL.standardizedFileURL
        let fm = FileManager.default
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: standardizedSource.path, isDirectory: &isDir), !isDir.boolValue else {
            throw AgentVMError.diskImageOperationFailed(
                path: standardizedSource.path,
                errnoCode: ENOENT,
                detail: "Offline base image file does not exist or is a directory."
            )
        }

        let ext = standardizedSource.pathExtension.lowercased()
        guard Self.supportedImageExtensions.contains(ext) else {
            throw AgentVMError.diskImageOperationFailed(
                path: standardizedSource.path,
                errnoCode: EINVAL,
                detail: "Unsupported offline image extension '.\(ext)'. Expected one of: \(Self.supportedImageExtensions.sorted().joined(separator: ", "))."
            )
        }

        let resolvedID: String
        if let id, !id.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            resolvedID = Self.sanitizeIdentifier(id)
        } else {
            let stem = standardizedSource.deletingPathExtension().lastPathComponent
            resolvedID = "offline-\(Self.sanitizeIdentifier(stem))"
        }

        let sha256Hex: String
        do {
            sha256Hex = try BinaryChecksums.sha256HexFile(at: standardizedSource)
        } catch {
            throw AgentVMError.diskImageOperationFailed(
                path: standardizedSource.path,
                errnoCode: EIO,
                detail: "Failed computing SHA-256 digest of offline image: \(error.localizedDescription)"
            )
        }

        let finalImageURL: URL
        if copyIntoCacheDirectory {
            if !fm.fileExists(atPath: cacheDirectoryURL.path) {
                try fm.createDirectory(at: cacheDirectoryURL, withIntermediateDirectories: true)
            }
            let targetURL = cacheDirectoryURL.appendingPathComponent("\(resolvedID).\(ext)", isDirectory: false)
            if targetURL.standardizedFileURL != standardizedSource {
                if fm.fileExists(atPath: targetURL.path) {
                    try fm.removeItem(at: targetURL)
                }
                do {
                    try fm.copyItem(at: standardizedSource, to: targetURL)
                } catch {
                    throw AgentVMError.diskImageOperationFailed(
                        path: targetURL.path,
                        errnoCode: errno,
                        detail: "Failed copying offline image into cache: \(error.localizedDescription)"
                    )
                }
            }
            finalImageURL = targetURL
        } else {
            finalImageURL = standardizedSource
        }

        let logicalSize = Self.queryLogicalFileSize(at: finalImageURL)
        let physicalSize = Self.queryPhysicalFileSize(at: finalImageURL)
        let virtualBytes = max(logicalSize, defaultVirtualSizeBytes ?? logicalSize)

        let entry = BaseImageCatalogEntry(
            id: resolvedID,
            displayName: displayName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? resolvedID : displayName,
            distribution: distribution,
            version: version,
            guestOS: guestOS,
            downloadURL: finalImageURL.absoluteString,
            expectedSHA256: sha256Hex,
            compressedSizeBytes: physicalSize,
            defaultVirtualSizeBytes: virtualBytes,
            includesPreinstalledToolchains: includesPreinstalledToolchains,
            cachedLocalPath: finalImageURL.path
        )

        let now = Date()
        let record = CachedImageIndexRecord(
            entry: entry,
            localPath: finalImageURL.path,
            sha256Hex: sha256Hex,
            physicalBytes: physicalSize,
            virtualBytes: virtualBytes,
            isCustomOffline: true,
            verifiedAt: now,
            lastAccessedAt: now,
            accessCount: 1
        )

        entriesByID[resolvedID] = entry
        cacheMetadataByID[resolvedID] = record
        try persistLocalManifest()
        if let projectStore {
            try await projectStore.upsertCachedImageRecord(record)
        }

        return entry
    }

    @discardableResult
    public func stageCachedCuratedImage(
        id: String,
        from stagedFileURL: URL,
        verifyChecksum: Bool = true
    ) async throws -> BaseImageCatalogEntry {
        guard var curated = entriesByID[id] else {
            throw AgentVMError.diskImageOperationFailed(
                path: stagedFileURL.path,
                errnoCode: ENOENT,
                detail: "Unknown curated catalog entry ID '\(id)'."
            )
        }

        let sourceURL = stagedFileURL.standardizedFileURL
        let actualSHA = try BinaryChecksums.sha256HexFile(at: sourceURL)
        if verifyChecksum && actualSHA.lowercased() != curated.expectedSHA256.lowercased() {
            throw AgentVMError.bundleIntegrityError(
                path: sourceURL.path,
                detail: "SHA-256 mismatch for '\(id)': expected \(curated.expectedSHA256), got \(actualSHA)."
            )
        }

        let fm = FileManager.default
        if !fm.fileExists(atPath: cacheDirectoryURL.path) {
            try fm.createDirectory(at: cacheDirectoryURL, withIntermediateDirectories: true)
        }
        let ext = sourceURL.pathExtension.isEmpty ? "img" : sourceURL.pathExtension.lowercased()
        let targetURL = cacheDirectoryURL.appendingPathComponent("\(id).\(ext)", isDirectory: false)
        if targetURL != sourceURL {
            if fm.fileExists(atPath: targetURL.path) {
                try fm.removeItem(at: targetURL)
            }
            try fm.copyItem(at: sourceURL, to: targetURL)
        }

        let physBytes = Self.queryPhysicalFileSize(at: targetURL)
        curated.cachedLocalPath = targetURL.path
        entriesByID[id] = curated

        let now = Date()
        let record = CachedImageIndexRecord(
            entry: curated,
            localPath: targetURL.path,
            sha256Hex: actualSHA,
            physicalBytes: physBytes,
            virtualBytes: curated.defaultVirtualSizeBytes,
            isCustomOffline: false,
            verifiedAt: now,
            lastAccessedAt: now,
            accessCount: 1
        )
        cacheMetadataByID[id] = record
        try persistLocalManifest()
        if let projectStore {
            try await projectStore.upsertCachedImageRecord(record)
        }
        return curated
    }

    // MARK: - SHA-256 Integrity Verification

    public func verifyCachedImage(
        id: String,
        enforceExpectedDigest: Bool = true
    ) async throws -> BaseImageVerificationReport {
        guard let entry = entriesByID[id] else {
            throw AgentVMError.diskImageOperationFailed(
                path: id,
                errnoCode: ENOENT,
                detail: "Base image '\(id)' is not registered in BaseImageRegistryCatalog."
            )
        }
        guard let localPath = entry.cachedLocalPath, !localPath.isEmpty else {
            return BaseImageVerificationReport(
                imageID: id,
                localPath: "",
                expectedSHA256: entry.expectedSHA256,
                actualSHA256: "",
                physicalSizeBytes: 0,
                isValid: false,
                failureReason: "Base image '\(id)' is not currently cached on local storage."
            )
        }

        let fileURL = URL(fileURLWithPath: localPath)
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return BaseImageVerificationReport(
                imageID: id,
                localPath: localPath,
                expectedSHA256: entry.expectedSHA256,
                actualSHA256: "",
                physicalSizeBytes: 0,
                isValid: false,
                failureReason: "Cached image file missing on disk at '\(localPath)'."
            )
        }

        let actualDigest = try BinaryChecksums.sha256HexFile(at: fileURL)
        let physSize = Self.queryPhysicalFileSize(at: fileURL)
        let matches = !enforceExpectedDigest || (actualDigest.lowercased() == entry.expectedSHA256.lowercased())

        let now = Date()
        if matches, var record = cacheMetadataByID[id] {
            record.sha256Hex = actualDigest
            record.physicalBytes = physSize
            record.verifiedAt = now
            cacheMetadataByID[id] = record
            try? persistLocalManifest()
            if let projectStore {
                try? await projectStore.upsertCachedImageRecord(record)
            }
        }

        return BaseImageVerificationReport(
            imageID: id,
            localPath: localPath,
            expectedSHA256: entry.expectedSHA256,
            actualSHA256: actualDigest,
            physicalSizeBytes: physSize,
            isValid: matches && physSize > 0,
            verifiedAt: now,
            failureReason: matches
                ? (physSize > 0 ? nil : "Cached image file is 0 bytes.")
                : "SHA-256 digest mismatch (expected \(entry.expectedSHA256), computed \(actualDigest))."
        )
    }

    public nonisolated func verifyStandaloneFile(
        at fileURL: URL,
        expectedSHA256: String,
        imageID: String = "standalone"
    ) throws -> BaseImageVerificationReport {
        let standardized = fileURL.standardizedFileURL
        guard FileManager.default.fileExists(atPath: standardized.path) else {
            return BaseImageVerificationReport(
                imageID: imageID,
                localPath: standardized.path,
                expectedSHA256: expectedSHA256,
                actualSHA256: "",
                physicalSizeBytes: 0,
                isValid: false,
                failureReason: "File does not exist at '\(standardized.path)'."
            )
        }
        let actual = try BinaryChecksums.sha256HexFile(at: standardized)
        let phys = Self.queryPhysicalFileSize(at: standardized)
        let matches = actual.lowercased() == expectedSHA256.lowercased()
        return BaseImageVerificationReport(
            imageID: imageID,
            localPath: standardized.path,
            expectedSHA256: expectedSHA256,
            actualSHA256: actual,
            physicalSizeBytes: phys,
            isValid: matches,
            failureReason: matches ? nil : "SHA-256 mismatch (expected \(expectedSHA256), actual \(actual))."
        )
    }

    // MARK: - LRU Access Tracking & Cache Eviction Planner

    public func markImageAccessed(id: String, at timestamp: Date = Date()) async throws {
        guard var record = cacheMetadataByID[id] else { return }
        record.lastAccessedAt = timestamp
        record.accessCount += 1
        cacheMetadataByID[id] = record
        try persistLocalManifest()
        if let projectStore {
            try await projectStore.upsertCachedImageRecord(record)
        }
    }

    public func planCacheEviction(
        policy: ImageCacheEvictionPolicy = ImageCacheEvictionPolicy(),
        referenceDate: Date = Date()
    ) -> ImageCacheEvictionPlan {
        let allCached = cacheMetadataByID.values.sorted { lhs, rhs in
            if lhs.lastAccessedAt != rhs.lastAccessedAt {
                return lhs.lastAccessedAt < rhs.lastAccessedAt // Oldest access first (LRU)
            }
            if lhs.accessCount != rhs.accessCount {
                return lhs.accessCount < rhs.accessCount
            }
            return lhs.id < rhs.id
        }

        let totalCurrentBytes = allCached.reduce(UInt64(0)) { $0 &+ $1.physicalBytes }
        var remainingBytes = totalCurrentBytes

        var candidates: [String] = []
        var protected: [String] = []
        var evictPaths: [String] = []
        var reclaimable: UInt64 = 0
        var uncommittedRecords: [CachedImageIndexRecord] = []

        // Pass 1: Partition protected entries vs idle-expired entries vs remaining LRU pool.
        for record in allCached {
            let isPinned = policy.pinnedImageIDs.contains(record.id)
            let isProtectedCustom = policy.preserveCustomOfflineImages && record.isCustomOffline
            if isPinned || isProtectedCustom {
                protected.append(record.id)
                continue
            }

            if let maxIdleHours = policy.maxIdleAgeHours {
                let idleSeconds = referenceDate.timeIntervalSince(record.lastAccessedAt)
                if idleSeconds >= Double(max(0, maxIdleHours)) * 3600.0 {
                    candidates.append(record.id)
                    evictPaths.append(record.localPath)
                    reclaimable &+= record.physicalBytes
                    remainingBytes = remainingBytes > record.physicalBytes ? (remainingBytes - record.physicalBytes) : 0
                    continue
                }
            }

            uncommittedRecords.append(record)
        }

        // Pass 2: Enforce maxCacheFootprintBytes in strict LRU order across remaining unprotected entries.
        for record in uncommittedRecords {
            if remainingBytes > policy.maxCacheFootprintBytes {
                candidates.append(record.id)
                evictPaths.append(record.localPath)
                reclaimable &+= record.physicalBytes
                remainingBytes = remainingBytes > record.physicalBytes ? (remainingBytes - record.physicalBytes) : 0
            } else {
                protected.append(record.id)
            }
        }

        return ImageCacheEvictionPlan(
            candidateImageIDs: candidates,
            protectedImageIDs: protected.sorted(),
            evictFilePaths: evictPaths,
            reclaimableBytes: reclaimable,
            projectedRemainingBytes: remainingBytes,
            computedAt: referenceDate
        )
    }

    @discardableResult
    public func executeCacheEviction(_ plan: ImageCacheEvictionPlan) async throws -> UInt64 {
        let fm = FileManager.default
        let standardizedCacheRoot = cacheDirectoryURL.standardizedFileURL.path
        var reclaimedBytes: UInt64 = 0

        for imageID in plan.candidateImageIDs {
            guard let record = cacheMetadataByID[imageID] else { continue }
            let fileURL = URL(fileURLWithPath: record.localPath).standardizedFileURL

            // Only unlink physical files residing inside cacheDirectoryURL so external user images are never destroyed.
            if fileURL.path.hasPrefix(standardizedCacheRoot), fm.fileExists(atPath: fileURL.path) {
                let bytes = Self.queryPhysicalFileSize(at: fileURL)
                try fm.removeItem(at: fileURL)
                reclaimedBytes &+= bytes
            }

            cacheMetadataByID.removeValue(forKey: imageID)
            if record.isCustomOffline {
                entriesByID.removeValue(forKey: imageID)
            } else if var curated = entriesByID[imageID] {
                curated.cachedLocalPath = nil
                entriesByID[imageID] = curated
            }

            if let projectStore {
                try await projectStore.deleteCachedImageRecord(imageID)
            }
        }

        try persistLocalManifest()
        return reclaimedBytes
    }

    // MARK: - Internal Persistence & File Size Helpers

    private func persistLocalManifest() throws {
        let fm = FileManager.default
        if !fm.fileExists(atPath: cacheDirectoryURL.path) {
            try fm.createDirectory(at: cacheDirectoryURL, withIntermediateDirectories: true)
        }
        let manifest = PersistedCacheManifest(
            formatVersion: 1,
            updatedAt: Date(),
            records: cacheMetadataByID.values.sorted { $0.id < $1.id }
        )
        let data = try jsonEncoder.encode(manifest)
        try data.write(to: indexManifestFileURL, options: [.atomic])
    }

    private static func sanitizeIdentifier(_ raw: String) -> String {
        let lowered = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let cleaned = lowered.replacingOccurrences(
            of: "[^a-z0-9._-]+",
            with: "-",
            options: .regularExpression
        ).trimmingCharacters(in: CharacterSet(charactersIn: "-_."))
        return cleaned.isEmpty ? UUID().uuidString.lowercased() : cleaned
    }

    private static func queryLogicalFileSize(at url: URL) -> UInt64 {
        guard let values = try? url.resourceValues(forKeys: [.fileSizeKey]),
              let size = values.fileSize else {
            return 0
        }
        return UInt64(max(0, size))
    }

    private static func queryPhysicalFileSize(at url: URL) -> UInt64 {
        guard let values = try? url.resourceValues(forKeys: [
            .totalFileAllocatedSizeKey,
            .fileAllocatedSizeKey,
            .fileSizeKey
        ]) else {
            return 0
        }
        let resolved = values.totalFileAllocatedSize ?? values.fileAllocatedSize ?? values.fileSize ?? 0
        return UInt64(max(0, resolved))
    }
}
