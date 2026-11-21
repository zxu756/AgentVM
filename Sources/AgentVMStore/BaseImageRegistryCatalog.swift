import AgentVMModels
import Darwin
import Foundation

// MARK: - Base Image Verification & LRU Cache Eviction Contracts

public struct BaseImageVerificationReport: Codable, Hashable, Sendable {
    public var imageID: String
    public var localPath: String
    public var expectedSHA512: String
    public var actualSHA512: String
    public var expectedSizeBytes: UInt64?
    public var logicalSizeBytes: UInt64
    public var physicalSizeBytes: UInt64
    public var isValid: Bool
    public var verifiedAt: Date
    public var failureReason: String?

    public init(
        imageID: String,
        localPath: String,
        expectedSHA512: String,
        actualSHA512: String,
        expectedSizeBytes: UInt64? = nil,
        logicalSizeBytes: UInt64 = 0,
        physicalSizeBytes: UInt64,
        isValid: Bool,
        verifiedAt: Date = Date(),
        failureReason: String? = nil
    ) {
        self.imageID = imageID
        self.localPath = localPath
        self.expectedSHA512 = expectedSHA512
        self.actualSHA512 = actualSHA512
        self.expectedSizeBytes = expectedSizeBytes
        self.logicalSizeBytes = logicalSizeBytes > 0 ? logicalSizeBytes : physicalSizeBytes
        self.physicalSizeBytes = physicalSizeBytes
        self.isValid = isValid
        self.verifiedAt = verifiedAt
        self.failureReason = failureReason
    }
}

public struct BaseImagePullProgress: Sendable, Equatable {
    public enum Phase: String, Sendable, Equatable {
        case connecting
        case resuming
        case restartedFullDownload
        case downloading
        case verifying
        case completed
        case alreadyCached
    }

    public var imageID: String
    public var phase: Phase
    public var receivedBytes: UInt64
    public var totalBytes: UInt64?
    public var resumedFromOffset: UInt64

    public init(
        imageID: String,
        phase: Phase,
        receivedBytes: UInt64,
        totalBytes: UInt64?,
        resumedFromOffset: UInt64 = 0
    ) {
        self.imageID = imageID
        self.phase = phase
        self.receivedBytes = receivedBytes
        self.totalBytes = totalBytes
        self.resumedFromOffset = resumedFromOffset
    }
}

public struct BaseImagePullOutcome: Sendable, Equatable {
    public var entry: BaseImageCatalogEntry
    public var localFileURL: URL
    public var sha512Hex: String
    public var sizeBytes: UInt64
    public var wasAlreadyCached: Bool
    public var resumedFromBytes: UInt64
    public var restartedFromZeroAfterRangeIgnored: Bool

    public init(
        entry: BaseImageCatalogEntry,
        localFileURL: URL,
        sha512Hex: String,
        sizeBytes: UInt64,
        wasAlreadyCached: Bool,
        resumedFromBytes: UInt64 = 0,
        restartedFromZeroAfterRangeIgnored: Bool = false
    ) {
        self.entry = entry
        self.localFileURL = localFileURL
        self.sha512Hex = sha512Hex
        self.sizeBytes = sizeBytes
        self.wasAlreadyCached = wasAlreadyCached
        self.resumedFromBytes = resumedFromBytes
        self.restartedFromZeroAfterRangeIgnored = restartedFromZeroAfterRangeIgnored
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

public enum ImageCacheSyncTarget: String, Sendable, Equatable {
    case partFile
    case cachedFile
    case cacheDirectory
}

public typealias ImageFileSyncHandler = @Sendable (
    _ fd: Int32,
    _ path: String,
    _ target: ImageCacheSyncTarget
) -> Int32

public actor BaseImageRegistryCatalog {
    private struct PersistedCacheManifest: Codable, Sendable {
        var formatVersion: Int = 2
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

    public static let cacheDirectoryEnvironmentKey = "AGENTVM_IMAGE_CACHE"

    private let projectStore: AgentVMProjectStore?
    private let urlSessionConfiguration: URLSessionConfiguration?
    private let fileSyncHandler: ImageFileSyncHandler
    private var entriesByID: [String: BaseImageCatalogEntry]
    private var cacheMetadataByID: [String: CachedImageIndexRecord]
    private let jsonEncoder: JSONEncoder
    private let jsonDecoder: JSONDecoder

    public nonisolated static func defaultSynchronizeDescriptor(
        fd: Int32,
        path: String,
        target: ImageCacheSyncTarget
    ) -> Int32 {
        while true {
            if Darwin.fcntl(fd, F_FULLFSYNC) == 0 {
                return 0
            }
            let code = Darwin.errno
            if code == EINTR {
                continue
            }
            if code == ENOTSUP || code == EINVAL {
                break
            }
            return code != 0 ? code : EIO
        }
        while true {
            if Darwin.fsync(fd) == 0 {
                return 0
            }
            let code = Darwin.errno
            if code == EINTR {
                continue
            }
            return code != 0 ? code : EIO
        }
    }

    public static func defaultCacheDirectoryURL(
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> URL {
        let homePath: String
        if let envHome = environment["HOME"]?.trimmingCharacters(in: .whitespacesAndNewlines),
           !envHome.isEmpty {
            homePath = envHome
        } else {
            homePath = NSHomeDirectory()
        }
        let homeURL = URL(fileURLWithPath: homePath, isDirectory: true).standardizedFileURL

        if let rawOverride = environment[cacheDirectoryEnvironmentKey]?.trimmingCharacters(in: .whitespacesAndNewlines),
           !rawOverride.isEmpty {
            let expandedPath: String
            if rawOverride == "~" {
                expandedPath = homeURL.path
            } else if rawOverride.hasPrefix("~/") {
                expandedPath = homeURL
                    .appendingPathComponent(String(rawOverride.dropFirst(2)), isDirectory: true)
                    .path
            } else {
                expandedPath = rawOverride
            }
            return URL(fileURLWithPath: expandedPath, isDirectory: true).standardizedFileURL
        }

        return homeURL
            .appendingPathComponent("Library/Caches/AgentVM/images", isDirectory: true)
            .standardizedFileURL
    }

    public init(
        cacheDirectoryURL: URL = BaseImageRegistryCatalog.defaultCacheDirectoryURL(),
        curatedEntries: [BaseImageCatalogEntry]? = nil,
        urlSessionConfiguration: URLSessionConfiguration? = nil,
        projectStore: AgentVMProjectStore? = nil,
        createIfMissing: Bool = false,
        fileSyncHandler: ImageFileSyncHandler? = nil
    ) throws {
        let standardized = cacheDirectoryURL.standardizedFileURL
        self.cacheDirectoryURL = standardized
        self.urlSessionConfiguration = urlSessionConfiguration
        self.fileSyncHandler = fileSyncHandler ?? Self.defaultSynchronizeDescriptor
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
        for curated in (curatedEntries ?? Self.builtInCuratedEntries()) {
            initialEntries[curated.id] = curated
        }

        var initialCacheMeta: [String: CachedImageIndexRecord] = [:]
        let manifestURL = standardized.appendingPathComponent("catalog-index.json", isDirectory: false)
        if let rawData = try? Data(contentsOf: manifestURL),
           let decoded = try? JSONDecoder().decode(PersistedCacheManifest.self, from: rawData) {
            for record in decoded.records {
                let candidateFileName = record.fileName.isEmpty ? record.entry.cacheFileName : record.fileName
                let resolvedURL: URL
                if record.isCustomOffline {
                    let inCacheCandidate = standardized.appendingPathComponent(candidateFileName, isDirectory: false)
                    if !candidateFileName.isEmpty && fm.fileExists(atPath: inCacheCandidate.path) {
                        resolvedURL = inCacheCandidate.standardizedFileURL
                    } else {
                        resolvedURL = URL(fileURLWithPath: record.localPath).standardizedFileURL
                    }
                } else {
                    resolvedURL = standardized
                        .appendingPathComponent(candidateFileName, isDirectory: false)
                        .standardizedFileURL
                }

                guard fm.fileExists(atPath: resolvedURL.path) else { continue }

                if var existingCurated = initialEntries[record.id], !record.isCustomOffline {
                    guard existingCurated.isSupported else { continue }
                    existingCurated.cachedLocalPath = resolvedURL.path
                    var hydratedRecord = record
                    hydratedRecord.entry = existingCurated
                    hydratedRecord.fileName = resolvedURL.lastPathComponent
                    hydratedRecord.localPath = resolvedURL.path
                    initialEntries[record.id] = existingCurated
                    initialCacheMeta[record.id] = hydratedRecord
                } else if record.isCustomOffline {
                    var hydratedEntry = record.entry
                    hydratedEntry.cachedLocalPath = resolvedURL.path
                    var hydratedRecord = record
                    hydratedRecord.entry = hydratedEntry
                    hydratedRecord.fileName = resolvedURL.lastPathComponent
                    hydratedRecord.localPath = resolvedURL.path
                    initialEntries[record.id] = hydratedEntry
                    initialCacheMeta[record.id] = hydratedRecord
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
                id: "debian-12-bookworm-arm64",
                displayName: "Debian 12 (Bookworm) GenericCloud ARM64",
                distribution: "debian",
                version: "20261112-2660",
                guestOS: .linuxARM64,
                isSupported: true,
                downloadURL: "https://cloud.debian.org/images/cloud/bookworm/20261112-2660/debian-12-genericcloud-arm64-20261112-2660.raw",
                expectedSHA512: "708a1a19d3aa4f5441c8160f6493aafccd3c36bfee3113869fa9248965223b8d263a3fbb86b7cf282723fb011180ade0c4a75d331b1addc8d4d1687c897de58b",
                expectedSizeBytes: 3_221_225_472,
                defaultVirtualSizeBytes: 3_221_225_472,
                includesPreinstalledToolchains: [
                    "linux-image-6.1.0-54-cloud-arm64",
                    "python3.11",
                    "cloud-init",
                    "cloud-initramfs-growroot",
                    "curl",
                    "openssh-server",
                    "sudo"
                ]
            ),
            BaseImageCatalogEntry(
                id: "ubuntu-24.04-noble-arm64",
                displayName: "Ubuntu 24.04 LTS (Noble Numbat) ARM64",
                distribution: "ubuntu",
                version: "24.04",
                guestOS: .linuxARM64,
                isSupported: false
            ),
            BaseImageCatalogEntry(
                id: "ubuntu-22.04-jammy-arm64",
                displayName: "Ubuntu 22.04 LTS (Jammy Jellyfish) ARM64",
                distribution: "ubuntu",
                version: "22.04",
                guestOS: .linuxARM64,
                isSupported: false
            ),
            BaseImageCatalogEntry(
                id: "fedora-cloud-41-arm64",
                displayName: "Fedora Cloud Base 41 ARM64",
                distribution: "fedora",
                version: "41",
                guestOS: .linuxARM64,
                isSupported: false
            ),
            BaseImageCatalogEntry(
                id: "alpine-3.20-virt-arm64",
                displayName: "Alpine Linux 3.20 Virt Cloud ARM64",
                distribution: "alpine",
                version: "3.20",
                guestOS: .linuxARM64,
                isSupported: false
            ),
            BaseImageCatalogEntry(
                id: "ubuntu-24.04-noble-amd64-rosetta",
                displayName: "Ubuntu 24.04 LTS (ARM64 Kernel + Rosetta x86_64 BinFmt)",
                distribution: "ubuntu",
                version: "24.04-rosetta",
                guestOS: .linuxX86_64ViaRosetta,
                isSupported: false
            )
        ]
    }

    // MARK: - Catalog Lookup & Filtering

    public func allEntries() -> [BaseImageCatalogEntry] {
        entriesByID.values.sorted { lhs, rhs in
            if lhs.isSupported != rhs.isSupported {
                return lhs.isSupported && !rhs.isSupported
            }
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

        let sha512Hex: String
        do {
            sha512Hex = try BinaryChecksums.sha512HexFile(at: standardizedSource)
        } catch {
            throw AgentVMError.diskImageOperationFailed(
                path: standardizedSource.path,
                errnoCode: EIO,
                detail: "Failed computing SHA-512 digest of offline image: \(error.localizedDescription)"
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
            try Self.synchronizeFile(
                at: targetURL,
                target: .cachedFile,
                detail: "Failed syncing copied offline image in cache directory.",
                using: fileSyncHandler
            )
            try Self.synchronizeDirectory(
                at: cacheDirectoryURL,
                detail: "Failed syncing cache directory after copying offline image.",
                using: fileSyncHandler
            )
            finalImageURL = targetURL
        } else {
            try Self.synchronizeFile(
                at: standardizedSource,
                target: .cachedFile,
                detail: "Failed syncing registered offline image.",
                using: fileSyncHandler
            )
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
            isSupported: true,
            downloadURL: finalImageURL.absoluteString,
            expectedSHA512: sha512Hex,
            expectedSizeBytes: logicalSize,
            defaultVirtualSizeBytes: virtualBytes,
            includesPreinstalledToolchains: includesPreinstalledToolchains,
            cachedLocalPath: finalImageURL.path
        )

        let st = Self.posixFileStat(at: finalImageURL.path)
        let now = Date()
        let record = CachedImageIndexRecord(
            entry: entry,
            fileName: finalImageURL.lastPathComponent,
            localPath: finalImageURL.path,
            sha512Hex: sha512Hex,
            logicalBytes: logicalSize,
            physicalBytes: physicalSize,
            virtualBytes: virtualBytes,
            mtimeSeconds: Int64(st?.st_mtimespec.tv_sec ?? 0),
            mtimeNanoseconds: Int64(st?.st_mtimespec.tv_nsec ?? 0),
            verified: true,
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
        let actualSHA = try BinaryChecksums.sha512HexFile(at: sourceURL)
        let expectedSHA = curated.expectedSHA512 ?? ""
        if verifyChecksum && (expectedSHA.isEmpty || actualSHA.lowercased() != expectedSHA.lowercased()) {
            throw AgentVMError.bundleIntegrityError(
                path: sourceURL.path,
                detail: "SHA-512 mismatch for '\(id)': expected \(expectedSHA), got \(actualSHA)."
            )
        }

        let fm = FileManager.default
        if !fm.fileExists(atPath: cacheDirectoryURL.path) {
            try fm.createDirectory(at: cacheDirectoryURL, withIntermediateDirectories: true)
        }
        let ext = sourceURL.pathExtension.isEmpty ? "raw" : sourceURL.pathExtension.lowercased()
        let targetURL = cacheDirectoryURL.appendingPathComponent("\(id).\(ext)", isDirectory: false)
        if targetURL != sourceURL {
            if fm.fileExists(atPath: targetURL.path) {
                _ = Darwin.chmod(targetURL.path, 0o644)
                try fm.removeItem(at: targetURL)
            }
            try fm.copyItem(at: sourceURL, to: targetURL)
        }
        try Self.synchronizeFile(
            at: targetURL,
            target: .cachedFile,
            detail: "Failed syncing staged curated image in cache directory.",
            using: fileSyncHandler
        )
        try Self.synchronizeDirectory(
            at: cacheDirectoryURL,
            detail: "Failed syncing cache directory after staging curated image.",
            using: fileSyncHandler
        )

        let logicalBytes = Self.queryLogicalFileSize(at: targetURL)
        let physBytes = Self.queryPhysicalFileSize(at: targetURL)
        let st = Self.posixFileStat(at: targetURL.path)
        curated.cachedLocalPath = targetURL.path
        entriesByID[id] = curated

        let now = Date()
        let record = CachedImageIndexRecord(
            entry: curated,
            fileName: targetURL.lastPathComponent,
            localPath: targetURL.path,
            sha512Hex: actualSHA,
            logicalBytes: logicalBytes,
            physicalBytes: physBytes,
            virtualBytes: max(logicalBytes, curated.defaultVirtualSizeBytes),
            mtimeSeconds: Int64(st?.st_mtimespec.tv_sec ?? 0),
            mtimeNanoseconds: Int64(st?.st_mtimespec.tv_nsec ?? 0),
            verified: true,
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

    // MARK: - HTTPS Pull & SHA-512 Integrity Verification

    @discardableResult
    public func pullImage(
        id: String,
        progress: (@Sendable (BaseImagePullProgress) -> Void)? = nil
    ) async throws -> BaseImagePullOutcome {
        guard var curated = entriesByID[id] else {
            throw AgentVMError.baseImageError(
                imageID: id,
                reason: .unknownImage(availableIDs: allEntries().map(\.id))
            )
        }
        guard curated.isSupported else {
            throw AgentVMError.baseImageError(imageID: id, reason: .unsupportedImage)
        }
        guard let rawURL = curated.downloadURL?.trimmingCharacters(in: .whitespacesAndNewlines),
              !rawURL.isEmpty,
              let remoteURL = URL(string: rawURL),
              remoteURL.scheme?.lowercased() == "https" else {
            throw AgentVMError.baseImageError(
                imageID: id,
                reason: .insecureDownloadURL(url: curated.downloadURL ?? "<nil>")
            )
        }
        guard let expectedSHA = curated.expectedSHA512?.trimmingCharacters(in: .whitespacesAndNewlines),
              !expectedSHA.isEmpty,
              let expectedSize = curated.expectedSizeBytes,
              expectedSize > 0 else {
            throw AgentVMError.baseImageError(imageID: id, reason: .unsupportedImage)
        }

        let finalURL = cacheDirectoryURL
            .appendingPathComponent(curated.cacheFileName, isDirectory: false)
            .standardizedFileURL

        // Fast path: cached file exists, index says verified, and both file size and mtime match.
        if let record = cacheMetadataByID[id],
           record.verified,
           record.sha512Hex.lowercased() == expectedSHA.lowercased(),
           Self.fileMatchesRecordedStat(at: finalURL, expectedSize: expectedSize, record: record) {
            progress?(BaseImagePullProgress(
                imageID: id,
                phase: .alreadyCached,
                receivedBytes: expectedSize,
                totalBytes: expectedSize,
                resumedFromOffset: 0
            ))
            if curated.cachedLocalPath != finalURL.path {
                curated.cachedLocalPath = finalURL.path
                entriesByID[id] = curated
            }
            return BaseImagePullOutcome(
                entry: curated,
                localFileURL: finalURL,
                sha512Hex: record.sha512Hex,
                sizeBytes: expectedSize,
                wasAlreadyCached: true,
                resumedFromBytes: 0,
                restartedFromZeroAfterRangeIgnored: false
            )
        }

        let fm = FileManager.default
        if let existingStat = Self.posixFileLstat(at: finalURL.path) {
            let isRegularFile = (existingStat.st_mode & S_IFMT) == S_IFREG
            let existingSize = UInt64(max(0, existingStat.st_size))
            var verifiedDigest: String?
            if isRegularFile && existingSize == expectedSize {
                progress?(BaseImagePullProgress(
                    imageID: id,
                    phase: .verifying,
                    receivedBytes: expectedSize,
                    totalBytes: expectedSize,
                    resumedFromOffset: 0
                ))
                if let digest = try? BinaryChecksums.sha512HexFile(at: finalURL),
                   digest.lowercased() == expectedSHA.lowercased() {
                    verifiedDigest = digest
                }
            }

            if let verifiedDigest {
                if (existingStat.st_mode & 0o777) != 0o444 {
                    guard Darwin.chmod(finalURL.path, 0o444) == 0 else {
                        let code = errno
                        throw AgentVMError.diskImageOperationFailed(
                            path: finalURL.path,
                            errnoCode: code,
                            detail: "Failed setting read-only mode (0444) on verified cached image."
                        )
                    }
                }
                try Self.synchronizeFile(
                    at: finalURL,
                    target: .cachedFile,
                    detail: "Failed syncing verified cached image file.",
                    using: fileSyncHandler
                )
                try Self.synchronizeDirectory(
                    at: cacheDirectoryURL,
                    detail: "Failed syncing cache directory for verified cached image.",
                    using: fileSyncHandler
                )
                guard let refreshedStat = Self.posixFileStat(at: finalURL.path) else {
                    throw AgentVMError.diskImageOperationFailed(
                        path: finalURL.path,
                        errnoCode: errno,
                        detail: "Unable to stat verified cached image file."
                    )
                }
                let physicalBytes = Self.queryPhysicalFileSize(at: finalURL)
                curated.cachedLocalPath = finalURL.path
                entriesByID[id] = curated
                let now = Date()
                let refreshedRecord = CachedImageIndexRecord(
                    entry: curated,
                    fileName: curated.cacheFileName,
                    localPath: finalURL.path,
                    sha512Hex: verifiedDigest,
                    logicalBytes: expectedSize,
                    physicalBytes: physicalBytes,
                    virtualBytes: max(expectedSize, curated.defaultVirtualSizeBytes),
                    mtimeSeconds: Int64(refreshedStat.st_mtimespec.tv_sec),
                    mtimeNanoseconds: Int64(refreshedStat.st_mtimespec.tv_nsec),
                    verified: true,
                    isCustomOffline: false,
                    verifiedAt: now,
                    lastAccessedAt: now,
                    accessCount: (cacheMetadataByID[id]?.accessCount ?? 0) + 1
                )
                cacheMetadataByID[id] = refreshedRecord
                try persistLocalManifest()
                if let projectStore {
                    try await projectStore.upsertCachedImageRecord(refreshedRecord)
                }
                progress?(BaseImagePullProgress(
                    imageID: id,
                    phase: .alreadyCached,
                    receivedBytes: expectedSize,
                    totalBytes: expectedSize,
                    resumedFromOffset: 0
                ))
                return BaseImagePullOutcome(
                    entry: curated,
                    localFileURL: finalURL,
                    sha512Hex: verifiedDigest,
                    sizeBytes: expectedSize,
                    wasAlreadyCached: true,
                    resumedFromBytes: 0,
                    restartedFromZeroAfterRangeIgnored: false
                )
            } else {
                if isRegularFile {
                    _ = Darwin.chmod(finalURL.path, 0o644)
                }
                do {
                    try fm.removeItem(at: finalURL)
                } catch {
                    throw AgentVMError.diskImageOperationFailed(
                        path: finalURL.path,
                        errnoCode: errno,
                        detail: "Unable to remove corrupted cached image before re-downloading: \(error.localizedDescription)"
                    )
                }
                try await clearCachedIndexRecord(forID: id)
                curated.cachedLocalPath = nil
            }
        } else if cacheMetadataByID[id] != nil || curated.cachedLocalPath != nil || localManifestContainsRecord(id: id) {
            try await clearCachedIndexRecord(forID: id)
            curated.cachedLocalPath = nil
        }

        if !fm.fileExists(atPath: cacheDirectoryURL.path) {
            do {
                try fm.createDirectory(at: cacheDirectoryURL, withIntermediateDirectories: true)
            } catch {
                throw AgentVMError.diskImageOperationFailed(
                    path: cacheDirectoryURL.path,
                    errnoCode: errno,
                    detail: "Unable to create shared image cache directory: \(error.localizedDescription)"
                )
            }
        }

        let partURL = cacheDirectoryURL
            .appendingPathComponent("\(curated.cacheFileName).part", isDirectory: false)
            .standardizedFileURL

        var resumeOffset: UInt64 = 0
        if let partStat = Self.posixFileStat(at: partURL.path),
           (partStat.st_mode & S_IFMT) == S_IFREG {
            let existingBytes = UInt64(max(0, partStat.st_size))
            if existingBytes > expectedSize {
                _ = Darwin.chmod(partURL.path, 0o644)
                try? fm.removeItem(at: partURL)
                resumeOffset = 0
            } else if existingBytes == expectedSize {
                if let partDigest = try? BinaryChecksums.sha512HexFile(at: partURL),
                   partDigest.lowercased() == expectedSHA.lowercased() {
                    try Self.synchronizeFile(
                        at: partURL,
                        target: .partFile,
                        detail: "Failed syncing pre-existing complete partial image file before finalization.",
                        using: fileSyncHandler
                    )
                    return try await finalizeVerifiedPartFile(
                        curated: curated,
                        partURL: partURL,
                        finalURL: finalURL,
                        actualSHA512: partDigest,
                        expectedSize: expectedSize,
                        resumedFromBytes: existingBytes,
                        restartedFromZero: false,
                        progress: progress
                    )
                } else {
                    _ = Darwin.chmod(partURL.path, 0o644)
                    try? fm.removeItem(at: partURL)
                    resumeOffset = 0
                }
            } else {
                resumeOffset = existingBytes
            }
        }

        progress?(BaseImagePullProgress(
            imageID: id,
            phase: .connecting,
            receivedBytes: resumeOffset,
            totalBytes: expectedSize,
            resumedFromOffset: resumeOffset
        ))

        let summary = try await Self.performStreamingHTTPSDownload(
            imageID: id,
            remoteURL: remoteURL,
            partURL: partURL,
            resumeOffset: resumeOffset,
            expectedTotalBytes: expectedSize,
            configurationOverride: urlSessionConfiguration,
            fileSyncHandler: fileSyncHandler,
            progress: progress
        )

        guard let postDownloadStat = Self.posixFileStat(at: partURL.path),
              (postDownloadStat.st_mode & S_IFMT) == S_IFREG else {
            throw AgentVMError.baseImageError(
                imageID: id,
                reason: .downloadFailed(detail: "Downloaded temporary file '\(partURL.lastPathComponent)' missing on disk.")
            )
        }
        let downloadedSize = UInt64(max(0, postDownloadStat.st_size))

        progress?(BaseImagePullProgress(
            imageID: id,
            phase: .verifying,
            receivedBytes: downloadedSize,
            totalBytes: expectedSize,
            resumedFromOffset: summary.resumedFromBytes
        ))

        if downloadedSize != expectedSize {
            _ = Darwin.chmod(partURL.path, 0o644)
            try? fm.removeItem(at: partURL)
            throw AgentVMError.baseImageError(
                imageID: id,
                reason: .sizeMismatch(expectedBytes: expectedSize, actualBytes: downloadedSize)
            )
        }

        let actualSHA512: String
        do {
            actualSHA512 = try BinaryChecksums.sha512HexFile(at: partURL)
        } catch {
            _ = Darwin.chmod(partURL.path, 0o644)
            try? fm.removeItem(at: partURL)
            throw AgentVMError.diskImageOperationFailed(
                path: partURL.path,
                errnoCode: EIO,
                detail: "Unable to hash downloaded image: \(error.localizedDescription)"
            )
        }

        if actualSHA512.lowercased() != expectedSHA.lowercased() {
            _ = Darwin.chmod(partURL.path, 0o644)
            try? fm.removeItem(at: partURL)
            throw AgentVMError.baseImageError(
                imageID: id,
                reason: .checksumMismatch(expectedSHA512: expectedSHA, actualSHA512: actualSHA512)
            )
        }

        return try await finalizeVerifiedPartFile(
            curated: curated,
            partURL: partURL,
            finalURL: finalURL,
            actualSHA512: actualSHA512,
            expectedSize: expectedSize,
            resumedFromBytes: summary.resumedFromBytes,
            restartedFromZero: summary.restartedFromZeroAfterRangeIgnored,
            progress: progress
        )
    }

    private func finalizeVerifiedPartFile(
        curated: BaseImageCatalogEntry,
        partURL: URL,
        finalURL: URL,
        actualSHA512: String,
        expectedSize: UInt64,
        resumedFromBytes: UInt64,
        restartedFromZero: Bool,
        progress: (@Sendable (BaseImagePullProgress) -> Void)?
    ) async throws -> BaseImagePullOutcome {
        let fm = FileManager.default
        guard Darwin.chmod(partURL.path, 0o444) == 0 else {
            let code = errno
            throw AgentVMError.diskImageOperationFailed(
                path: partURL.path,
                errnoCode: code,
                detail: "Failed setting read-only mode (0444) on verified image."
            )
        }

        if fm.fileExists(atPath: finalURL.path) {
            _ = Darwin.chmod(finalURL.path, 0o644)
        }
        guard Darwin.rename(partURL.path, finalURL.path) == 0 else {
            let code = errno
            throw AgentVMError.diskImageOperationFailed(
                path: finalURL.path,
                errnoCode: code,
                detail: "Atomic rename from '\(partURL.lastPathComponent)' to '\(finalURL.lastPathComponent)' failed."
            )
        }
        try Self.synchronizeDirectory(
            at: cacheDirectoryURL,
            detail: "Failed syncing base image cache directory after atomic rename.",
            using: fileSyncHandler
        )

        guard let finalStat = Self.posixFileStat(at: finalURL.path) else {
            throw AgentVMError.diskImageOperationFailed(
                path: finalURL.path,
                errnoCode: errno,
                detail: "Unable to stat finalized image file."
            )
        }

        let logicalBytes = UInt64(max(0, finalStat.st_size))
        let physicalBytes = Self.queryPhysicalFileSize(at: finalURL)
        var updatedEntry = curated
        updatedEntry.cachedLocalPath = finalURL.path
        entriesByID[curated.id] = updatedEntry

        let now = Date()
        let record = CachedImageIndexRecord(
            entry: updatedEntry,
            fileName: curated.cacheFileName,
            localPath: finalURL.path,
            sha512Hex: actualSHA512,
            logicalBytes: logicalBytes,
            physicalBytes: physicalBytes,
            virtualBytes: max(logicalBytes, curated.defaultVirtualSizeBytes),
            mtimeSeconds: Int64(finalStat.st_mtimespec.tv_sec),
            mtimeNanoseconds: Int64(finalStat.st_mtimespec.tv_nsec),
            verified: true,
            isCustomOffline: false,
            verifiedAt: now,
            lastAccessedAt: now,
            accessCount: 1
        )
        cacheMetadataByID[curated.id] = record
        try persistLocalManifest()
        if let projectStore {
            try await projectStore.upsertCachedImageRecord(record)
        }

        progress?(BaseImagePullProgress(
            imageID: curated.id,
            phase: .completed,
            receivedBytes: logicalBytes,
            totalBytes: expectedSize,
            resumedFromOffset: resumedFromBytes
        ))

        return BaseImagePullOutcome(
            entry: updatedEntry,
            localFileURL: finalURL,
            sha512Hex: actualSHA512,
            sizeBytes: logicalBytes,
            wasAlreadyCached: false,
            resumedFromBytes: resumedFromBytes,
            restartedFromZeroAfterRangeIgnored: restartedFromZero
        )
    }

    public func verifiedCachedImageURL(forID id: String) throws -> URL {
        guard let entry = entriesByID[id] else {
            throw AgentVMError.baseImageError(
                imageID: id,
                reason: .unknownImage(availableIDs: allEntries().map(\.id))
            )
        }
        guard entry.isSupported else {
            throw AgentVMError.baseImageError(imageID: id, reason: .unsupportedImage)
        }
        guard let record = cacheMetadataByID[id],
              record.verified,
              let expectedSHA = entry.expectedSHA512,
              record.sha512Hex.lowercased() == expectedSHA.lowercased() else {
            throw AgentVMError.baseImageError(imageID: id, reason: .missingFromCache)
        }
        let fileURL = URL(fileURLWithPath: record.localPath).standardizedFileURL
        let expectedSize = entry.expectedSizeBytes ?? record.logicalBytes
        guard Self.fileMatchesRecordedStat(at: fileURL, expectedSize: expectedSize, record: record) else {
            throw AgentVMError.baseImageError(imageID: id, reason: .missingFromCache)
        }
        return fileURL
    }

    public func isImageCached(id: String) -> Bool {
        guard let entry = entriesByID[id], entry.isSupported else {
            return false
        }
        if let record = cacheMetadataByID[id], record.verified {
            return FileManager.default.fileExists(atPath: record.localPath)
        }
        if let localPath = entry.cachedLocalPath, !localPath.isEmpty {
            return FileManager.default.fileExists(atPath: localPath)
        }
        return false
    }

    public func verifyCuratedImageStrict(id: String) async throws -> BaseImageVerificationReport {
        guard let entry = entriesByID[id] else {
            throw AgentVMError.baseImageError(
                imageID: id,
                reason: .unknownImage(availableIDs: allEntries().map(\.id))
            )
        }
        guard entry.isSupported,
              let expectedSHA = entry.expectedSHA512,
              !expectedSHA.isEmpty else {
            throw AgentVMError.baseImageError(imageID: id, reason: .unsupportedImage)
        }

        let resolvedPath: String
        if let cachedPath = entry.cachedLocalPath, !cachedPath.isEmpty {
            resolvedPath = cachedPath
        } else {
            resolvedPath = cacheDirectoryURL
                .appendingPathComponent(entry.cacheFileName, isDirectory: false)
                .standardizedFileURL
                .path
        }

        let fileURL = URL(fileURLWithPath: resolvedPath).standardizedFileURL
        guard let st = Self.posixFileStat(at: fileURL.path),
              (st.st_mode & S_IFMT) == S_IFREG else {
            throw AgentVMError.baseImageError(imageID: id, reason: .missingFromCache)
        }

        let logicalSize = UInt64(max(0, st.st_size))
        if let expectedSize = entry.expectedSizeBytes, logicalSize != expectedSize {
            throw AgentVMError.baseImageError(
                imageID: id,
                reason: .sizeMismatch(expectedBytes: expectedSize, actualBytes: logicalSize)
            )
        }

        let actualDigest = try BinaryChecksums.sha512HexFile(at: fileURL)
        if actualDigest.lowercased() != expectedSHA.lowercased() {
            throw AgentVMError.baseImageError(
                imageID: id,
                reason: .checksumMismatch(expectedSHA512: expectedSHA, actualSHA512: actualDigest)
            )
        }

        let physSize = Self.queryPhysicalFileSize(at: fileURL)
        return BaseImageVerificationReport(
            imageID: id,
            localPath: fileURL.path,
            expectedSHA512: expectedSHA,
            actualSHA512: actualDigest,
            expectedSizeBytes: entry.expectedSizeBytes,
            logicalSizeBytes: logicalSize,
            physicalSizeBytes: physSize,
            isValid: true,
            verifiedAt: Date(),
            failureReason: nil
        )
    }

    public func verifyCachedImage(
        id: String,
        enforceExpectedDigest: Bool = true
    ) async throws -> BaseImageVerificationReport {
        guard let entry = entriesByID[id] else {
            throw AgentVMError.baseImageError(
                imageID: id,
                reason: .unknownImage(availableIDs: allEntries().map(\.id))
            )
        }
        if enforceExpectedDigest && !entry.isSupported {
            throw AgentVMError.baseImageError(imageID: id, reason: .unsupportedImage)
        }

        let expectedSHA = entry.expectedSHA512 ?? ""
        let resolvedPath: String
        if let localPath = entry.cachedLocalPath, !localPath.isEmpty {
            resolvedPath = localPath
        } else {
            resolvedPath = cacheDirectoryURL
                .appendingPathComponent(entry.cacheFileName, isDirectory: false)
                .standardizedFileURL
                .path
        }

        let fileURL = URL(fileURLWithPath: resolvedPath).standardizedFileURL
        guard let st = Self.posixFileStat(at: fileURL.path),
              (st.st_mode & S_IFMT) == S_IFREG else {
            return BaseImageVerificationReport(
                imageID: id,
                localPath: fileURL.path,
                expectedSHA512: expectedSHA,
                actualSHA512: "",
                expectedSizeBytes: entry.expectedSizeBytes,
                physicalSizeBytes: 0,
                isValid: false,
                failureReason: "Cached image file missing on disk at '\(fileURL.path)'."
            )
        }

        let logicalSize = UInt64(max(0, st.st_size))
        let physSize = Self.queryPhysicalFileSize(at: fileURL)
        let actualDigest = try BinaryChecksums.sha512HexFile(at: fileURL)

        let sizeMatches: Bool
        if enforceExpectedDigest, let expectedSize = entry.expectedSizeBytes {
            sizeMatches = (logicalSize == expectedSize)
        } else {
            sizeMatches = (logicalSize > 0)
        }

        let shaMatches = !enforceExpectedDigest || (!expectedSHA.isEmpty && actualDigest.lowercased() == expectedSHA.lowercased())
        let isValid = sizeMatches && shaMatches && logicalSize > 0

        let failureReason: String?
        if isValid {
            failureReason = nil
        } else if !sizeMatches, let expectedSize = entry.expectedSizeBytes {
            failureReason = "Size mismatch (expected \(expectedSize) bytes, actual \(logicalSize) bytes)."
        } else if !shaMatches {
            failureReason = "SHA-512 digest mismatch (expected \(expectedSHA), computed \(actualDigest))."
        } else {
            failureReason = "Cached image file is 0 bytes."
        }

        return BaseImageVerificationReport(
            imageID: id,
            localPath: fileURL.path,
            expectedSHA512: expectedSHA,
            actualSHA512: actualDigest,
            expectedSizeBytes: entry.expectedSizeBytes,
            logicalSizeBytes: logicalSize,
            physicalSizeBytes: physSize,
            isValid: isValid,
            verifiedAt: Date(),
            failureReason: failureReason
        )
    }

    public nonisolated func verifyStandaloneFile(
        at fileURL: URL,
        expectedSHA512: String,
        imageID: String = "standalone"
    ) throws -> BaseImageVerificationReport {
        let standardized = fileURL.standardizedFileURL
        guard FileManager.default.fileExists(atPath: standardized.path) else {
            return BaseImageVerificationReport(
                imageID: imageID,
                localPath: standardized.path,
                expectedSHA512: expectedSHA512,
                actualSHA512: "",
                physicalSizeBytes: 0,
                isValid: false,
                failureReason: "File does not exist at '\(standardized.path)'."
            )
        }
        let actual = try BinaryChecksums.sha512HexFile(at: standardized)
        let logical = Self.queryLogicalFileSize(at: standardized)
        let phys = Self.queryPhysicalFileSize(at: standardized)
        let matches = actual.lowercased() == expectedSHA512.lowercased()
        return BaseImageVerificationReport(
            imageID: imageID,
            localPath: standardized.path,
            expectedSHA512: expectedSHA512,
            actualSHA512: actual,
            logicalSizeBytes: logical,
            physicalSizeBytes: phys,
            isValid: matches,
            failureReason: matches ? nil : "SHA-512 mismatch (expected \(expectedSHA512), actual \(actual))."
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
                _ = Darwin.chmod(fileURL.path, 0o644)
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

    // MARK: - Internal Persistence, POSIX Stat & Streaming HTTPS Download Helpers

    private func persistLocalManifest() throws {
        let fm = FileManager.default
        if !fm.fileExists(atPath: cacheDirectoryURL.path) {
            try fm.createDirectory(at: cacheDirectoryURL, withIntermediateDirectories: true)
        }
        let portableRecords: [CachedImageIndexRecord] = cacheMetadataByID.values
            .sorted { $0.id < $1.id }
            .map { record in
                guard !record.isCustomOffline else { return record }
                var copy = record
                copy.entry.cachedLocalPath = nil
                copy.localPath = record.fileName
                return copy
            }
        let manifest = PersistedCacheManifest(
            formatVersion: 2,
            updatedAt: Date(),
            records: portableRecords
        )
        let data = try jsonEncoder.encode(manifest)
        try data.write(to: indexManifestFileURL, options: [.atomic])
    }

    private func localManifestContainsRecord(id: String) -> Bool {
        guard let rawData = try? Data(contentsOf: indexManifestFileURL),
              let decoded = try? jsonDecoder.decode(PersistedCacheManifest.self, from: rawData) else {
            return false
        }
        return decoded.records.contains { $0.id == id }
    }

    private func clearCachedIndexRecord(forID id: String) async throws {
        let removedInMemory = (cacheMetadataByID.removeValue(forKey: id) != nil)
        let hadManifestEntry = localManifestContainsRecord(id: id)
        if var existing = entriesByID[id] {
            existing.cachedLocalPath = nil
            entriesByID[id] = existing
        }
        if (removedInMemory || hadManifestEntry) && FileManager.default.fileExists(atPath: cacheDirectoryURL.path) {
            try persistLocalManifest()
        }
        if let projectStore {
            try await projectStore.deleteCachedImageRecord(id)
        }
    }

    private nonisolated static func posixFileStat(at path: String) -> Darwin.stat? {
        var st = Darwin.stat()
        guard stat(path, &st) == 0 else {
            return nil
        }
        return st
    }

    private nonisolated static func posixFileLstat(at path: String) -> Darwin.stat? {
        var st = Darwin.stat()
        guard lstat(path, &st) == 0 else {
            return nil
        }
        return st
    }

    private nonisolated static func fileMatchesRecordedStat(
        at fileURL: URL,
        expectedSize: UInt64,
        record: CachedImageIndexRecord
    ) -> Bool {
        guard let st = posixFileStat(at: fileURL.path),
              (st.st_mode & S_IFMT) == S_IFREG else {
            return false
        }
        let sizeOnDisk = UInt64(max(0, st.st_size))
        guard sizeOnDisk == expectedSize, sizeOnDisk == record.logicalBytes else {
            return false
        }
        guard Int64(st.st_mtimespec.tv_sec) == record.mtimeSeconds,
              Int64(st.st_mtimespec.tv_nsec) == record.mtimeNanoseconds else {
            return false
        }
        return true
    }

    fileprivate struct StreamingDownloadSummary: Sendable {
        let resumedFromBytes: UInt64
        let bytesWritten: UInt64
        let restartedFromZeroAfterRangeIgnored: Bool
    }

    private nonisolated static func makeDefaultDownloadSessionConfiguration() -> URLSessionConfiguration {
        let config = URLSessionConfiguration.ephemeral
        config.urlCache = nil
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.timeoutIntervalForRequest = 120
        config.timeoutIntervalForResource = 7200
        return config
    }

    private nonisolated static func synchronizeFile(
        at fileURL: URL,
        target: ImageCacheSyncTarget,
        detail: String,
        using syncHandler: ImageFileSyncHandler
    ) throws {
        let standardizedPath = fileURL.standardizedFileURL.path
        let fd = Darwin.open(standardizedPath, O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else {
            let code = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: standardizedPath,
                errnoCode: code != 0 ? code : EIO,
                detail: "Unable to open '\(fileURL.lastPathComponent)' for durability sync."
            )
        }
        let syncErrno = syncHandler(fd, standardizedPath, target)
        let closeRC = Darwin.close(fd)
        let closeCode = closeRC != 0 ? (Darwin.errno != 0 ? Darwin.errno : EIO) : 0
        if syncErrno != 0 {
            throw AgentVMError.diskImageOperationFailed(
                path: standardizedPath,
                errnoCode: syncErrno,
                detail: detail
            )
        }
        if closeCode != 0 {
            throw AgentVMError.diskImageOperationFailed(
                path: standardizedPath,
                errnoCode: closeCode,
                detail: "Failed closing descriptor after durability sync on '\(fileURL.lastPathComponent)'."
            )
        }
    }

    private nonisolated static func synchronizeDirectory(
        at directoryURL: URL,
        detail: String,
        using syncHandler: ImageFileSyncHandler
    ) throws {
        let standardizedPath = directoryURL.standardizedFileURL.path
        let dirFD = Darwin.open(standardizedPath, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard dirFD >= 0 else {
            let code = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: standardizedPath,
                errnoCode: code != 0 ? code : EIO,
                detail: "Unable to open cache directory '\(directoryURL.lastPathComponent)' for durability sync."
            )
        }
        let syncErrno = syncHandler(dirFD, standardizedPath, .cacheDirectory)
        let closeRC = Darwin.close(dirFD)
        let closeCode = closeRC != 0 ? (Darwin.errno != 0 ? Darwin.errno : EIO) : 0
        if syncErrno != 0 {
            throw AgentVMError.diskImageOperationFailed(
                path: standardizedPath,
                errnoCode: syncErrno,
                detail: detail
            )
        }
        if closeCode != 0 {
            throw AgentVMError.diskImageOperationFailed(
                path: standardizedPath,
                errnoCode: closeCode,
                detail: "Failed closing cache directory descriptor after durability sync."
            )
        }
    }

    private nonisolated static func performStreamingHTTPSDownload(
        imageID: String,
        remoteURL: URL,
        partURL: URL,
        resumeOffset: UInt64,
        expectedTotalBytes: UInt64,
        configurationOverride: URLSessionConfiguration?,
        fileSyncHandler: @escaping ImageFileSyncHandler,
        progress: (@Sendable (BaseImagePullProgress) -> Void)?
    ) async throws -> StreamingDownloadSummary {
        let sessionConfig = configurationOverride ?? makeDefaultDownloadSessionConfiguration()
        let delegateQueue = OperationQueue()
        delegateQueue.name = "com.agentvm.image-pull.\(imageID)"
        delegateQueue.maxConcurrentOperationCount = 1

        var request = URLRequest(url: remoteURL)
        request.httpMethod = "GET"
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        if resumeOffset > 0 {
            request.setValue("bytes=\(resumeOffset)-", forHTTPHeaderField: "Range")
        }

        let delegate = StreamingImageDownloadDelegate(
            imageID: imageID,
            partURL: partURL,
            initialResumeOffset: resumeOffset,
            expectedTotalBytes: expectedTotalBytes,
            fileSyncHandler: fileSyncHandler,
            progressHandler: progress
        )
        let session = URLSession(
            configuration: sessionConfig,
            delegate: delegate,
            delegateQueue: delegateQueue
        )
        defer {
            session.invalidateAndCancel()
        }

        return try await withCheckedThrowingContinuation { continuation in
            delegate.start(task: session.dataTask(with: request), continuation: continuation)
        }
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

    private nonisolated static func queryLogicalFileSize(at url: URL) -> UInt64 {
        guard let values = try? url.resourceValues(forKeys: [.fileSizeKey]),
              let size = values.fileSize else {
            return 0
        }
        return UInt64(max(0, size))
    }

    private nonisolated static func queryPhysicalFileSize(at url: URL) -> UInt64 {
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

// MARK: - Dense Offset-Based .part Writer (POSIX write + Offset-Based HTTP 206 Resume)

private struct OffsetPartFileWriter {
    let fd: Int32
    private(set) var logicalOffset: UInt64
    private var fdOffset: UInt64

    init(fd: Int32, startOffset: UInt64) {
        self.fd = fd
        self.logicalOffset = startOffset
        self.fdOffset = startOffset
    }

    private mutating func seekDescriptorIfNeeded(to targetOffset: UInt64) -> Int32 {
        guard fdOffset != targetOffset else { return 0 }
        guard targetOffset <= UInt64(Int64.max) else { return EOVERFLOW }
        let res = Darwin.lseek(fd, off_t(targetOffset), SEEK_SET)
        if res < 0 || UInt64(res) != targetOffset {
            let code = Darwin.errno
            return code != 0 ? code : EIO
        }
        fdOffset = targetOffset
        return 0
    }

    private static let maxSingleWriteBytes = 16 * 1024 * 1024

    private mutating func writeRawBytes(_ base: UnsafeRawPointer, count: Int) -> Int32 {
        guard count > 0 else { return 0 }
        let seekErr = seekDescriptorIfNeeded(to: logicalOffset)
        if seekErr != 0 { return seekErr }
        var remaining = count
        var localOff = 0
        while remaining > 0 {
            // Darwin write(2) returns EINVAL if nbyte > INT32_MAX; cap each syscall to 16 MiB.
            let step = min(remaining, Self.maxSingleWriteBytes)
            let written = Darwin.write(fd, base.advanced(by: localOff), step)
            if written > 0 {
                localOff += written
                remaining -= written
                logicalOffset &+= UInt64(written)
                fdOffset &+= UInt64(written)
            } else if written < 0 && Darwin.errno == EINTR {
                continue
            } else {
                let code = Darwin.errno
                return code != 0 ? code : EIO
            }
        }
        return 0
    }

    mutating func append(_ data: Data) -> Int32 {
        for region in data.regions where !region.isEmpty {
            let err = region.withUnsafeBytes { rawBuf -> Int32 in
                guard let base = rawBuf.baseAddress, rawBuf.count > 0 else { return 0 }
                return writeRawBytes(base, count: rawBuf.count)
            }
            if err != 0 { return err }
        }
        return 0
    }

    mutating func finalizeLength() -> Int32 {
        guard logicalOffset <= UInt64(Int64.max) else { return EOVERFLOW }
        var st = Darwin.stat()
        if Darwin.fstat(fd, &st) == 0, st.st_size == off_t(logicalOffset) {
            return 0
        }
        while true {
            if Darwin.ftruncate(fd, off_t(logicalOffset)) == 0 {
                break
            }
            let code = Darwin.errno
            if code == EINTR {
                continue
            }
            return code != 0 ? code : EIO
        }
        return 0
    }
}

// MARK: - Streaming URLSession Delegate (HTTPS Redirect Gate + Range 206 / 200 Dense Offset File Writer)

private final class StreamingImageDownloadDelegate: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let imageID: String
    private let partURL: URL
    private let initialResumeOffset: UInt64
    private let expectedTotalBytes: UInt64
    private let fileSyncHandler: ImageFileSyncHandler
    private let progressHandler: (@Sendable (BaseImagePullProgress) -> Void)?

    private let lock = NSLock()
    private var continuation: CheckedContinuation<BaseImageRegistryCatalog.StreamingDownloadSummary, Error>?
    private var fileDescriptor: Int32 = -1
    private var partWriter: OffsetPartFileWriter?
    private var activeStartOffset: UInt64 = 0
    private var bytesWrittenThisAttempt: UInt64 = 0
    private var lastReportedBytes: UInt64 = 0
    private var restartedFromZero: Bool = false
    private var resolvedTotalBytes: UInt64?
    private var terminalError: Error?

    init(
        imageID: String,
        partURL: URL,
        initialResumeOffset: UInt64,
        expectedTotalBytes: UInt64,
        fileSyncHandler: @escaping ImageFileSyncHandler,
        progressHandler: (@Sendable (BaseImagePullProgress) -> Void)?
    ) {
        self.imageID = imageID
        self.partURL = partURL.standardizedFileURL
        self.initialResumeOffset = initialResumeOffset
        self.expectedTotalBytes = expectedTotalBytes
        self.resolvedTotalBytes = expectedTotalBytes
        self.fileSyncHandler = fileSyncHandler
        self.progressHandler = progressHandler
        super.init()
    }

    deinit {
        if fileDescriptor >= 0 {
            _ = Darwin.close(fileDescriptor)
        }
    }

    func start(
        task: URLSessionDataTask,
        continuation: CheckedContinuation<BaseImageRegistryCatalog.StreamingDownloadSummary, Error>
    ) {
        lock.lock()
        self.continuation = continuation
        lock.unlock()
        task.resume()
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        let targetString = request.url?.absoluteString ?? "<nil>"
        guard let scheme = request.url?.scheme?.lowercased(), scheme == "https" else {
            lock.lock()
            if terminalError == nil {
                terminalError = AgentVMError.baseImageError(
                    imageID: imageID,
                    reason: .insecureRedirect(targetURL: targetString)
                )
            }
            lock.unlock()
            task.cancel()
            completionHandler(nil)
            return
        }

        var forwarded = request
        if initialResumeOffset > 0 {
            forwarded.setValue("bytes=\(initialResumeOffset)-", forHTTPHeaderField: "Range")
        }
        completionHandler(forwarded)
    }

    func urlSession(
        _ session: URLSession,
        dataTask: URLSessionDataTask,
        didReceive response: URLResponse,
        completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
    ) {
        lock.lock()
        let alreadyFailed = (terminalError != nil)
        lock.unlock()
        if alreadyFailed {
            completionHandler(.cancel)
            return
        }

        guard let http = response as? HTTPURLResponse else {
            recordFailure(
                AgentVMError.baseImageError(
                    imageID: imageID,
                    reason: .downloadFailed(detail: "Received non-HTTP response from server.")
                )
            )
            completionHandler(.cancel)
            return
        }

        guard http.url?.scheme?.lowercased() == "https" else {
            recordFailure(
                AgentVMError.baseImageError(
                    imageID: imageID,
                    reason: .insecureDownloadURL(url: http.url?.absoluteString ?? "<nil>")
                )
            )
            completionHandler(.cancel)
            return
        }

        closeFileDescriptorIfOpen()

        switch http.statusCode {
        case 206 where initialResumeOffset > 0:
            if let contentRange = http.value(forHTTPHeaderField: "Content-Range"),
               let parsedStart = Self.parseContentRangeStartOffset(contentRange),
               parsedStart != initialResumeOffset {
                recordFailure(
                    AgentVMError.baseImageError(
                        imageID: imageID,
                        reason: .downloadFailed(
                            detail: "HTTP 206 Content-Range '\(contentRange)' did not start at requested byte offset \(initialResumeOffset)."
                        )
                    )
                )
                completionHandler(.cancel)
                return
            }

            // Open without O_APPEND so explicit byte offsets work across HTTP 206 resume.
            let fd = Darwin.open(partURL.path, O_RDWR | O_CREAT | O_CLOEXEC, 0o644)
            guard fd >= 0 else {
                let code = Darwin.errno
                recordFailure(
                    AgentVMError.diskImageOperationFailed(
                        path: partURL.path,
                        errnoCode: code != 0 ? code : EIO,
                        detail: "Unable to open partial download file for offset-based resume."
                    )
                )
                completionHandler(.cancel)
                return
            }

            var st = Darwin.stat()
            guard Darwin.fstat(fd, &st) == 0 else {
                let code = Darwin.errno
                _ = Darwin.close(fd)
                recordFailure(
                    AgentVMError.diskImageOperationFailed(
                        path: partURL.path,
                        errnoCode: code != 0 ? code : EIO,
                        detail: "Unable to fstat partial download file during HTTP 206 resume."
                    )
                )
                completionHandler(.cancel)
                return
            }

            let currentSize = UInt64(max(0, st.st_size))
            if currentSize < initialResumeOffset {
                _ = Darwin.close(fd)
                recordFailure(
                    AgentVMError.diskImageOperationFailed(
                        path: partURL.path,
                        errnoCode: EINVAL,
                        detail: "Partial download file size (\(currentSize)) is smaller than resume offset (\(initialResumeOffset))."
                    )
                )
                completionHandler(.cancel)
                return
            }
            if currentSize > initialResumeOffset {
                if Darwin.ftruncate(fd, off_t(initialResumeOffset)) != 0 {
                    let code = Darwin.errno
                    _ = Darwin.close(fd)
                    recordFailure(
                        AgentVMError.diskImageOperationFailed(
                            path: partURL.path,
                            errnoCode: code != 0 ? code : EIO,
                            detail: "Failed truncating partial file to resume offset \(initialResumeOffset)."
                        )
                    )
                    completionHandler(.cancel)
                    return
                }
            }

            let seekRes = Darwin.lseek(fd, off_t(initialResumeOffset), SEEK_SET)
            guard seekRes >= 0, UInt64(seekRes) == initialResumeOffset else {
                let code = Darwin.errno
                _ = Darwin.close(fd)
                recordFailure(
                    AgentVMError.diskImageOperationFailed(
                        path: partURL.path,
                        errnoCode: code != 0 ? code : EIO,
                        detail: "Failed seeking partial download file to resume offset \(initialResumeOffset)."
                    )
                )
                completionHandler(.cancel)
                return
            }

            lock.lock()
            fileDescriptor = fd
            partWriter = OffsetPartFileWriter(fd: fd, startOffset: initialResumeOffset)
            activeStartOffset = initialResumeOffset
            bytesWrittenThisAttempt = 0
            lastReportedBytes = initialResumeOffset
            restartedFromZero = false
            lock.unlock()

            progressHandler?(BaseImagePullProgress(
                imageID: imageID,
                phase: .resuming,
                receivedBytes: initialResumeOffset,
                totalBytes: resolvedTotalBytes,
                resumedFromOffset: initialResumeOffset
            ))
            completionHandler(.allow)

        case 200:
            if FileManager.default.fileExists(atPath: partURL.path) {
                _ = Darwin.chmod(partURL.path, 0o644)
            }
            let fd = Darwin.open(partURL.path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0o644)
            guard fd >= 0 else {
                let code = Darwin.errno
                recordFailure(
                    AgentVMError.diskImageOperationFailed(
                        path: partURL.path,
                        errnoCode: code != 0 ? code : EIO,
                        detail: "Unable to create/truncate temporary download file."
                    )
                )
                completionHandler(.cancel)
                return
            }

            let wasRangeIgnored = (initialResumeOffset > 0)
            lock.lock()
            fileDescriptor = fd
            partWriter = OffsetPartFileWriter(fd: fd, startOffset: 0)
            activeStartOffset = 0
            bytesWrittenThisAttempt = 0
            lastReportedBytes = 0
            restartedFromZero = wasRangeIgnored
            lock.unlock()

            if wasRangeIgnored {
                progressHandler?(BaseImagePullProgress(
                    imageID: imageID,
                    phase: .restartedFullDownload,
                    receivedBytes: 0,
                    totalBytes: resolvedTotalBytes,
                    resumedFromOffset: 0
                ))
            }
            completionHandler(.allow)

        default:
            recordFailure(
                AgentVMError.baseImageError(
                    imageID: imageID,
                    reason: .downloadFailed(detail: "Unexpected HTTP status \(http.statusCode).")
                )
            )
            completionHandler(.cancel)
        }
    }

    func urlSession(
        _ session: URLSession,
        dataTask: URLSessionDataTask,
        didReceive data: Data
    ) {
        guard !data.isEmpty else { return }

        lock.lock()
        let fd = fileDescriptor
        let failed = (terminalError != nil)
        var writer = partWriter
        lock.unlock()

        guard !failed, fd >= 0, writer != nil else { return }

        let writeErrno = writer!.append(data)

        lock.lock()
        if fileDescriptor == fd {
            partWriter = writer
        }
        lock.unlock()

        if writeErrno != 0 {
            recordFailure(
                AgentVMError.diskImageOperationFailed(
                    path: partURL.path,
                    errnoCode: writeErrno,
                    detail: "Failed streaming image chunk to disk."
                )
            )
            closeFileDescriptorIfOpen()
            dataTask.cancel()
            return
        }

        var progressToEmit: BaseImagePullProgress?
        lock.lock()
        let wasFirstChunk = (bytesWrittenThisAttempt == 0)
        bytesWrittenThisAttempt &+= UInt64(data.count)
        let currentTotal = activeStartOffset &+ bytesWrittenThisAttempt
        if wasFirstChunk
            || (currentTotal - lastReportedBytes) >= 512 * 1024
            || currentTotal >= expectedTotalBytes {
            lastReportedBytes = currentTotal
            progressToEmit = BaseImagePullProgress(
                imageID: imageID,
                phase: .downloading,
                receivedBytes: currentTotal,
                totalBytes: resolvedTotalBytes,
                resumedFromOffset: activeStartOffset
            )
        }
        lock.unlock()

        if let progressToEmit {
            progressHandler?(progressToEmit)
        }
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didCompleteWithError error: Error?
    ) {
        lock.lock()
        let hadTerminalFailure = (terminalError != nil)
        lock.unlock()

        let finalizeAndCloseError = finalizeSyncAndCloseDescriptor(
            isCleanStreamCompletion: !hadTerminalFailure && (error == nil),
            flushPartialOnInterruption: !hadTerminalFailure && (error != nil)
        )

        lock.lock()
        let cont = continuation
        continuation = nil
        let recordedErr = terminalError
        let summary = BaseImageRegistryCatalog.StreamingDownloadSummary(
            resumedFromBytes: activeStartOffset,
            bytesWritten: bytesWrittenThisAttempt,
            restartedFromZeroAfterRangeIgnored: restartedFromZero
        )
        lock.unlock()

        guard let cont else { return }

        if let recordedErr {
            cont.resume(throwing: recordedErr)
        } else if let finalizeAndCloseError {
            cont.resume(throwing: finalizeAndCloseError)
        } else if let error {
            if let avmErr = error as? AgentVMError {
                cont.resume(throwing: avmErr)
            } else {
                cont.resume(
                    throwing: AgentVMError.baseImageError(
                        imageID: imageID,
                        reason: .downloadFailed(detail: error.localizedDescription)
                    )
                )
            }
        } else {
            cont.resume(returning: summary)
        }
    }

    private func recordFailure(_ error: Error) {
        lock.lock()
        if terminalError == nil {
            terminalError = error
        }
        lock.unlock()
    }

    private func closeFileDescriptorIfOpen() {
        _ = finalizeSyncAndCloseDescriptor(
            isCleanStreamCompletion: false,
            flushPartialOnInterruption: false
        )
    }

    private func finalizeSyncAndCloseDescriptor(
        isCleanStreamCompletion: Bool,
        flushPartialOnInterruption: Bool
    ) -> Error? {
        lock.lock()
        let fd = fileDescriptor
        fileDescriptor = -1
        var writer = partWriter
        partWriter = nil
        let wroteBytes = bytesWrittenThisAttempt
        lock.unlock()

        guard fd >= 0 else { return nil }

        var primaryError: Error?
        if (isCleanStreamCompletion || (flushPartialOnInterruption && wroteBytes > 0)),
           writer != nil {
            let finErrno = writer!.finalizeLength()
            if finErrno != 0 {
                primaryError = AgentVMError.diskImageOperationFailed(
                    path: partURL.path,
                    errnoCode: finErrno,
                    detail: "Failed finalizing file length (\(writer!.logicalOffset) bytes) on downloaded image."
                )
            }
        }

        if primaryError == nil && isCleanStreamCompletion {
            let syncErrno = fileSyncHandler(fd, partURL.path, .partFile)
            if syncErrno != 0 {
                primaryError = AgentVMError.diskImageOperationFailed(
                    path: partURL.path,
                    errnoCode: syncErrno,
                    detail: "Failed syncing downloaded partial image file to stable storage."
                )
            }
        }

        if Darwin.close(fd) != 0 {
            let code = Darwin.errno
            if primaryError == nil {
                primaryError = AgentVMError.diskImageOperationFailed(
                    path: partURL.path,
                    errnoCode: code != 0 ? code : EIO,
                    detail: "Failed closing downloaded partial image file."
                )
            }
        }

        return primaryError
    }

    private static func parseContentRangeStartOffset(_ header: String) -> UInt64? {
        // Expected format: "bytes <start>-<end>/<total>"
        let trimmed = header.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.lowercased().hasPrefix("bytes ") else { return nil }
        let rangePart = trimmed.dropFirst("bytes ".count).trimmingCharacters(in: .whitespaces)
        guard let dashIdx = rangePart.firstIndex(of: "-") else { return nil }
        return UInt64(rangePart[..<dashIdx])
    }
}
