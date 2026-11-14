import AgentVMModels
import Foundation
import SQLite3

// MARK: - SQLite Destructor & Typed Value Primitives

private let sqliteTransientDestructor = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

public enum SQLiteValue: Sendable, Hashable, CustomStringConvertible {
    case integer(Int64)
    case real(Double)
    case text(String)
    case blob(Data)
    case null

    public var isNull: Bool {
        if case .null = self { return true }
        return false
    }

    public var description: String {
        switch self {
        case let .integer(v):
            return "\(v)"
        case let .real(v):
            return String(format: "%.6f", v)
        case let .text(s):
            return "'\(s)'"
        case let .blob(d):
            return "<BLOB \(d.count) bytes>"
        case .null:
            return "NULL"
        }
    }
}

public protocol SQLiteBindable: Sendable {
    var sqliteValue: SQLiteValue { get }
}

extension SQLiteValue: SQLiteBindable {
    public var sqliteValue: SQLiteValue { self }
}

extension Int64: SQLiteBindable {
    public var sqliteValue: SQLiteValue { .integer(self) }
}

extension Int: SQLiteBindable {
    public var sqliteValue: SQLiteValue { .integer(Int64(self)) }
}

extension Int32: SQLiteBindable {
    public var sqliteValue: SQLiteValue { .integer(Int64(self)) }
}

extension Int16: SQLiteBindable {
    public var sqliteValue: SQLiteValue { .integer(Int64(self)) }
}

extension Int8: SQLiteBindable {
    public var sqliteValue: SQLiteValue { .integer(Int64(self)) }
}

extension UInt64: SQLiteBindable {
    public var sqliteValue: SQLiteValue { .integer(Int64(bitPattern: self)) }
}

extension UInt32: SQLiteBindable {
    public var sqliteValue: SQLiteValue { .integer(Int64(self)) }
}

extension UInt16: SQLiteBindable {
    public var sqliteValue: SQLiteValue { .integer(Int64(self)) }
}

extension UInt8: SQLiteBindable {
    public var sqliteValue: SQLiteValue { .integer(Int64(self)) }
}

extension Bool: SQLiteBindable {
    public var sqliteValue: SQLiteValue { .integer(self ? 1 : 0) }
}

extension Double: SQLiteBindable {
    public var sqliteValue: SQLiteValue { .real(self) }
}

extension Float: SQLiteBindable {
    public var sqliteValue: SQLiteValue { .real(Double(self)) }
}

extension String: SQLiteBindable {
    public var sqliteValue: SQLiteValue { .text(self) }
}

extension Data: SQLiteBindable {
    public var sqliteValue: SQLiteValue { .blob(self) }
}

extension UUID: SQLiteBindable {
    public var sqliteValue: SQLiteValue { .text(uuidString.lowercased()) }
}

extension Date: SQLiteBindable {
    /// Uses `timeIntervalSinceReferenceDate` for lossless IEEE-754 round-trip fidelity with `Foundation.Date`.
    public var sqliteValue: SQLiteValue { .real(timeIntervalSinceReferenceDate) }
}

extension TypedIdentifier: SQLiteBindable {
    public var sqliteValue: SQLiteValue { .text(rawValue) }
}

extension Optional: SQLiteBindable where Wrapped: SQLiteBindable {
    public var sqliteValue: SQLiteValue {
        switch self {
        case let .some(wrapped):
            return wrapped.sqliteValue
        case .none:
            return .null
        }
    }
}

// MARK: - Materialized Row Reader

public struct SQLiteRow: Sendable, Equatable {
    public let columnNames: [String]
    public let values: [SQLiteValue]
    private let lookup: [String: Int]

    public init(columnNames: [String], values: [SQLiteValue]) {
        self.columnNames = columnNames
        self.values = values
        var indexMap: [String: Int] = [:]
        indexMap.reserveCapacity(columnNames.count * 2)
        for (idx, name) in columnNames.enumerated() {
            if indexMap[name] == nil {
                indexMap[name] = idx
            }
            let lower = name.lowercased()
            if indexMap[lower] == nil {
                indexMap[lower] = idx
            }
        }
        self.lookup = indexMap
    }

    public var columnCount: Int { values.count }

    public func value(at index: Int) -> SQLiteValue {
        guard index >= 0 && index < values.count else { return .null }
        return values[index]
    }

    public func value(forColumn column: String) throws -> SQLiteValue {
        if let idx = lookup[column] ?? lookup[column.lowercased()] {
            return values[idx]
        }
        throw AgentVMError.storageDatabaseError(
            code: SQLITE_RANGE,
            sql: "ROW_READ(\(column))",
            detail: "Column '\(column)' not present in result set [\(columnNames.joined(separator: ", "))]."
        )
    }

    public func hasColumn(_ column: String) -> Bool {
        lookup[column] != nil || lookup[column.lowercased()] != nil
    }

    public func optionalInt64(_ column: String) throws -> Int64? {
        switch try value(forColumn: column) {
        case .null:
            return nil
        case let .integer(v):
            return v
        case let .real(v):
            return Int64(v)
        case let .text(s):
            return Int64(s)
        case .blob:
            throw typeMismatchError(column: column, expected: "INTEGER")
        }
    }

    public func int64(_ column: String) throws -> Int64 {
        guard let v = try optionalInt64(column) else {
            throw unexpectedNullError(column: column, expected: "INTEGER")
        }
        return v
    }

    public func optionalInt(_ column: String) throws -> Int? {
        guard let raw = try optionalInt64(column) else { return nil }
        return Int(truncatingIfNeeded: raw)
    }

    public func int(_ column: String) throws -> Int {
        Int(truncatingIfNeeded: try int64(column))
    }

    public func optionalInt32(_ column: String) throws -> Int32? {
        guard let raw = try optionalInt64(column) else { return nil }
        return Int32(truncatingIfNeeded: raw)
    }

    public func int32(_ column: String) throws -> Int32 {
        Int32(truncatingIfNeeded: try int64(column))
    }

    public func optionalUInt64(_ column: String) throws -> UInt64? {
        guard let raw = try optionalInt64(column) else { return nil }
        return UInt64(bitPattern: raw)
    }

    public func uint64(_ column: String) throws -> UInt64 {
        UInt64(bitPattern: try int64(column))
    }

    public func optionalUInt32(_ column: String) throws -> UInt32? {
        guard let raw = try optionalInt64(column) else { return nil }
        return UInt32(clamping: max(0, raw))
    }

    public func uint32(_ column: String) throws -> UInt32 {
        UInt32(clamping: max(0, try int64(column)))
    }

    public func optionalUInt16(_ column: String) throws -> UInt16? {
        guard let raw = try optionalInt64(column) else { return nil }
        return UInt16(clamping: max(0, raw))
    }

    public func uint16(_ column: String) throws -> UInt16 {
        UInt16(clamping: max(0, try int64(column)))
    }

    public func optionalBool(_ column: String) throws -> Bool? {
        guard let raw = try optionalInt64(column) else { return nil }
        return raw != 0
    }

    public func bool(_ column: String) throws -> Bool {
        (try int64(column)) != 0
    }

    public func optionalDouble(_ column: String) throws -> Double? {
        switch try value(forColumn: column) {
        case .null:
            return nil
        case let .real(v):
            return v
        case let .integer(v):
            return Double(v)
        case let .text(s):
            return Double(s)
        case .blob:
            throw typeMismatchError(column: column, expected: "REAL")
        }
    }

    public func double(_ column: String) throws -> Double {
        guard let v = try optionalDouble(column) else {
            throw unexpectedNullError(column: column, expected: "REAL")
        }
        return v
    }

    public func optionalString(_ column: String) throws -> String? {
        switch try value(forColumn: column) {
        case .null:
            return nil
        case let .text(s):
            return s
        case let .integer(v):
            return String(v)
        case let .real(v):
            return String(v)
        case let .blob(d):
            return String(data: d, encoding: .utf8)
        }
    }

    public func string(_ column: String) throws -> String {
        guard let s = try optionalString(column) else {
            throw unexpectedNullError(column: column, expected: "TEXT")
        }
        return s
    }

    public func optionalData(_ column: String) throws -> Data? {
        switch try value(forColumn: column) {
        case .null:
            return nil
        case let .blob(d):
            return d
        case let .text(s):
            return Data(s.utf8)
        case .integer, .real:
            throw typeMismatchError(column: column, expected: "BLOB")
        }
    }

    public func data(_ column: String) throws -> Data {
        guard let d = try optionalData(column) else {
            throw unexpectedNullError(column: column, expected: "BLOB")
        }
        return d
    }

    public func optionalDate(_ column: String) throws -> Date? {
        guard let seconds = try optionalDouble(column) else { return nil }
        return Date(timeIntervalSinceReferenceDate: seconds)
    }

    public func date(_ column: String) throws -> Date {
        Date(timeIntervalSinceReferenceDate: try double(column))
    }

    public func optionalUUID(_ column: String) throws -> UUID? {
        guard let raw = try optionalString(column) else { return nil }
        guard let parsed = UUID(uuidString: raw) else {
            throw AgentVMError.storageDatabaseError(
                code: SQLITE_MISMATCH,
                sql: "ROW_UUID(\(column))",
                detail: "Malformed UUID string '\(raw)' in column '\(column)'."
            )
        }
        return parsed
    }

    public func uuid(_ column: String) throws -> UUID {
        guard let id = try optionalUUID(column) else {
            throw unexpectedNullError(column: column, expected: "UUID TEXT")
        }
        return id
    }

    public func optionalJSON<T: Decodable>(
        _ type: T.Type,
        column: String,
        decoder: JSONDecoder = JSONDecoder()
    ) throws -> T? {
        guard let text = try optionalString(column) else { return nil }
        do {
            return try decoder.decode(T.self, from: Data(text.utf8))
        } catch {
            throw AgentVMError.storageDatabaseError(
                code: SQLITE_MISMATCH,
                sql: "ROW_JSON(\(column))",
                detail: "Failed decoding \(T.self) from column '\(column)': \(error.localizedDescription)"
            )
        }
    }

    public func json<T: Decodable>(
        _ type: T.Type,
        column: String,
        decoder: JSONDecoder = JSONDecoder()
    ) throws -> T {
        guard let decoded = try optionalJSON(type, column: column, decoder: decoder) else {
            throw unexpectedNullError(column: column, expected: "JSON TEXT (\(T.self))")
        }
        return decoded
    }

    private func unexpectedNullError(column: String, expected: String) -> AgentVMError {
        .storageDatabaseError(
            code: SQLITE_MISMATCH,
            sql: "ROW_READ(\(column))",
            detail: "Expected non-null \(expected) in column '\(column)', found NULL."
        )
    }

    private func typeMismatchError(column: String, expected: String) -> AgentVMError {
        .storageDatabaseError(
            code: SQLITE_MISMATCH,
            sql: "ROW_READ(\(column))",
            detail: "Column '\(column)' value incompatible with \(expected)."
        )
    }
}

// MARK: - Prepared Statement Wrapper

public final class SQLitePreparedStatement {
    public let sql: String
    private let databaseHandle: OpaquePointer
    private var statementHandle: OpaquePointer?
    private let cachedColumnNames: [String]

    init(databaseHandle: OpaquePointer, sql: String) throws {
        self.databaseHandle = databaseHandle
        self.sql = sql
        var stmt: OpaquePointer?
        let rc = sqlite3_prepare_v2(databaseHandle, sql, -1, &stmt, nil)
        guard rc == SQLITE_OK, let compiled = stmt else {
            let msg = sqlite3_errmsg(databaseHandle).map { String(cString: $0) } ?? "Unknown prepare error"
            if let stmt {
                sqlite3_finalize(stmt)
            }
            throw AgentVMError.storageDatabaseError(code: rc, sql: sql, detail: msg)
        }
        self.statementHandle = compiled

        let colCount = Int(sqlite3_column_count(compiled))
        var names: [String] = []
        names.reserveCapacity(colCount)
        for i in 0..<colCount {
            if let cName = sqlite3_column_name(compiled, Int32(i)) {
                names.append(String(cString: cName))
            } else {
                names.append("col_\(i)")
            }
        }
        self.cachedColumnNames = names
    }

    deinit {
        finalize()
    }

    public var parameterCount: Int {
        guard let stmt = statementHandle else { return 0 }
        return Int(sqlite3_bind_parameter_count(stmt))
    }

    public func bind(_ value: SQLiteValue, at oneBasedIndex: Int32) throws {
        let stmt = try requireHandle()
        let rc: Int32
        switch value {
        case let .integer(v):
            rc = sqlite3_bind_int64(stmt, oneBasedIndex, v)
        case let .real(v):
            rc = sqlite3_bind_double(stmt, oneBasedIndex, v)
        case let .text(s):
            rc = s.withCString { cStr in
                sqlite3_bind_text(stmt, oneBasedIndex, cStr, -1, sqliteTransientDestructor)
            }
        case let .blob(data):
            if data.isEmpty {
                rc = sqlite3_bind_zeroblob(stmt, oneBasedIndex, 0)
            } else {
                rc = data.withUnsafeBytes { rawBuf in
                    sqlite3_bind_blob(
                        stmt,
                        oneBasedIndex,
                        rawBuf.baseAddress,
                        Int32(clamping: data.count),
                        sqliteTransientDestructor
                    )
                }
            }
        case .null:
            rc = sqlite3_bind_null(stmt, oneBasedIndex)
        }

        guard rc == SQLITE_OK else {
            throw databaseError(code: rc, context: "bind(index=\(oneBasedIndex))")
        }
    }

    public func bind(_ bindable: (any SQLiteBindable)?, at oneBasedIndex: Int32) throws {
        try bind(bindable?.sqliteValue ?? .null, at: oneBasedIndex)
    }

    public func bindAll(_ values: [SQLiteValue]) throws {
        for (offset, val) in values.enumerated() {
            try bind(val, at: Int32(offset + 1))
        }
    }

    public func bindNamed(_ namedValues: [String: SQLiteValue]) throws {
        let stmt = try requireHandle()
        for (rawKey, value) in namedValues {
            let candidates: [String]
            if rawKey.hasPrefix(":") || rawKey.hasPrefix("@") || rawKey.hasPrefix("$") {
                candidates = [rawKey]
            } else {
                candidates = [":\(rawKey)", "@\(rawKey)", "$\(rawKey)"]
            }
            var resolvedIndex: Int32 = 0
            for candidate in candidates {
                let idx = sqlite3_bind_parameter_index(stmt, candidate)
                if idx > 0 {
                    resolvedIndex = idx
                    break
                }
            }
            guard resolvedIndex > 0 else {
                throw AgentVMError.storageDatabaseError(
                    code: SQLITE_RANGE,
                    sql: sql,
                    detail: "Named parameter '\(rawKey)' not found in prepared statement."
                )
            }
            try bind(value, at: resolvedIndex)
        }
    }

    public func stepExecute() throws {
        let stmt = try requireHandle()
        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE || rc == SQLITE_ROW else {
            throw databaseError(code: rc, context: "stepExecute")
        }
    }

    public func stepRow() throws -> SQLiteRow? {
        let stmt = try requireHandle()
        let rc = sqlite3_step(stmt)
        if rc == SQLITE_DONE {
            return nil
        }
        guard rc == SQLITE_ROW else {
            throw databaseError(code: rc, context: "stepRow")
        }
        let colCount = cachedColumnNames.count
        var rowValues: [SQLiteValue] = []
        rowValues.reserveCapacity(colCount)
        for col in 0..<colCount {
            let cIdx = Int32(col)
            let colType = sqlite3_column_type(stmt, cIdx)
            switch colType {
            case SQLITE_INTEGER:
                rowValues.append(.integer(sqlite3_column_int64(stmt, cIdx)))
            case SQLITE_FLOAT:
                rowValues.append(.real(sqlite3_column_double(stmt, cIdx)))
            case SQLITE_TEXT:
                if let ptr = sqlite3_column_text(stmt, cIdx) {
                    let byteLen = Int(sqlite3_column_bytes(stmt, cIdx))
                    let buf = UnsafeBufferPointer(start: ptr, count: max(0, byteLen))
                    rowValues.append(.text(String(decoding: buf, as: UTF8.self)))
                } else {
                    rowValues.append(.text(""))
                }
            case SQLITE_BLOB:
                let byteLen = Int(sqlite3_column_bytes(stmt, cIdx))
                if byteLen <= 0 {
                    rowValues.append(.blob(Data()))
                } else if let rawPtr = sqlite3_column_blob(stmt, cIdx) {
                    rowValues.append(.blob(Data(bytes: rawPtr, count: byteLen)))
                } else {
                    rowValues.append(.blob(Data()))
                }
            default:
                rowValues.append(.null)
            }
        }
        return SQLiteRow(columnNames: cachedColumnNames, values: rowValues)
    }

    public func fetchAll() throws -> [SQLiteRow] {
        var rows: [SQLiteRow] = []
        while let row = try stepRow() {
            rows.append(row)
        }
        return rows
    }

    public func reset(clearBindings: Bool = true) throws {
        let stmt = try requireHandle()
        let rc = sqlite3_reset(stmt)
        if clearBindings {
            sqlite3_clear_bindings(stmt)
        }
        guard rc == SQLITE_OK else {
            throw databaseError(code: rc, context: "reset")
        }
    }

    public func finalize() {
        if let stmt = statementHandle {
            sqlite3_finalize(stmt)
            statementHandle = nil
        }
    }

    private func requireHandle() throws -> OpaquePointer {
        guard let stmt = statementHandle else {
            throw AgentVMError.storageDatabaseError(
                code: SQLITE_MISUSE,
                sql: sql,
                detail: "Attempted to use finalized SQLitePreparedStatement."
            )
        }
        return stmt
    }

    private func databaseError(code: Int32, context: String) -> AgentVMError {
        let msg = sqlite3_errmsg(databaseHandle).map { String(cString: $0) } ?? "SQLite error"
        return .storageDatabaseError(code: code, sql: sql, detail: "\(context): \(msg)")
    }
}

// MARK: - Transaction, WAL Checkpoint & Diagnostics Contracts

public enum SQLiteTransactionMode: String, Codable, Hashable, Sendable, CaseIterable {
    case deferred = "DEFERRED"
    case immediate = "IMMEDIATE"
    case exclusive = "EXCLUSIVE"
}

public enum SQLiteWALCheckpointMode: String, Codable, Hashable, Sendable, CaseIterable {
    case passive
    case full
    case restart
    case truncate

    fileprivate var cFlag: Int32 {
        switch self {
        case .passive: return SQLITE_CHECKPOINT_PASSIVE
        case .full: return SQLITE_CHECKPOINT_FULL
        case .restart: return SQLITE_CHECKPOINT_RESTART
        case .truncate: return SQLITE_CHECKPOINT_TRUNCATE
        }
    }
}

public struct SQLiteWALCheckpointResult: Codable, Hashable, Sendable {
    public var mode: SQLiteWALCheckpointMode
    public var totalWALFrames: Int32
    public var checkpointedFrames: Int32

    public init(mode: SQLiteWALCheckpointMode, totalWALFrames: Int32, checkpointedFrames: Int32) {
        self.mode = mode
        self.totalWALFrames = totalWALFrames
        self.checkpointedFrames = checkpointedFrames
    }

    public var isFullyCheckpointed: Bool {
        totalWALFrames <= 0 || checkpointedFrames >= totalWALFrames
    }
}

public struct SQLiteDatabaseDiagnostics: Codable, Hashable, Sendable {
    public var databasePath: String
    public var schemaVersion: Int
    public var sqliteLibraryVersion: String
    public var journalMode: String
    public var synchronousMode: Int
    public var foreignKeysEnabled: Bool
    public var pageSizeBytes: Int64
    public var pageCount: Int64
    public var freelistPageCount: Int64
    public var databaseFileBytes: UInt64
    public var walFileBytes: UInt64
    public var shmFileBytes: UInt64
    public var tableRowCounts: [String: Int64]

    public init(
        databasePath: String,
        schemaVersion: Int,
        sqliteLibraryVersion: String,
        journalMode: String,
        synchronousMode: Int,
        foreignKeysEnabled: Bool,
        pageSizeBytes: Int64,
        pageCount: Int64,
        freelistPageCount: Int64,
        databaseFileBytes: UInt64,
        walFileBytes: UInt64,
        shmFileBytes: UInt64,
        tableRowCounts: [String: Int64]
    ) {
        self.databasePath = databasePath
        self.schemaVersion = schemaVersion
        self.sqliteLibraryVersion = sqliteLibraryVersion
        self.journalMode = journalMode
        self.synchronousMode = synchronousMode
        self.foreignKeysEnabled = foreignKeysEnabled
        self.pageSizeBytes = pageSizeBytes
        self.pageCount = pageCount
        self.freelistPageCount = freelistPageCount
        self.databaseFileBytes = databaseFileBytes
        self.walFileBytes = walFileBytes
        self.shmFileBytes = shmFileBytes
        self.tableRowCounts = tableRowCounts
    }

    public var logicalDatabaseBytes: UInt64 {
        UInt64(max(0, pageSizeBytes) * max(0, pageCount))
    }

    public var reclaimableFreelistBytes: UInt64 {
        UInt64(max(0, pageSizeBytes) * max(0, freelistPageCount))
    }

    public var totalOnDiskBytes: UInt64 {
        databaseFileBytes + walFileBytes + shmFileBytes
    }
}

// MARK: - Versioned Schema Migration Definitions (v0 -> v4)

public struct SQLiteSchemaMigration: Sendable {
    public let version: Int
    public let name: String
    public let sqlStatements: [String]
    public let checksum: String

    public init(version: Int, name: String, sqlStatements: [String]) {
        self.version = version
        self.name = name
        self.sqlStatements = sqlStatements
        let canonical = "v\(version):\(name)\n" + sqlStatements.map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }.joined(separator: "\n---\n")
        self.checksum = BinaryChecksums.sha256Hex(Data(canonical.utf8))
    }
}

public struct SQLiteAppliedMigration: Codable, Hashable, Sendable, Identifiable {
    public var id: Int { version }
    public var version: Int
    public var name: String
    public var checksum: String
    public var appliedAt: Date
    public var executionMilliseconds: Int

    public init(
        version: Int,
        name: String,
        checksum: String,
        appliedAt: Date,
        executionMilliseconds: Int = 0
    ) {
        self.version = version
        self.name = name
        self.checksum = checksum
        self.appliedAt = appliedAt
        self.executionMilliseconds = executionMilliseconds
    }
}

// MARK: - Thread-Safe SQLite3 WAL Database Engine

public final class SQLiteWALDatabase: @unchecked Sendable {
    public static let latestSchemaVersion: Int = 4

    public let databasePath: String
    public let isInMemory: Bool

    private let lock = NSRecursiveLock()
    private var dbHandle: OpaquePointer?
    private var transactionDepth: Int = 0
    private var savepointCounter: UInt64 = 0

    public convenience init(fileURL: URL, runMigrations: Bool = true) throws {
        let standardized = fileURL.standardizedFileURL
        let parentDir = standardized.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: parentDir.path) {
            do {
                try FileManager.default.createDirectory(at: parentDir, withIntermediateDirectories: true)
            } catch {
                throw AgentVMError.bundleIntegrityError(
                    path: parentDir.path,
                    detail: "Failed creating parent directory for SQLite database: \(error.localizedDescription)"
                )
            }
        }
        try self.init(path: standardized.path, isInMemory: false, runMigrations: runMigrations)
    }

    public convenience init(inMemoryNamed name: String = ":memory:", runMigrations: Bool = true) throws {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let resolved: String
        if trimmed.isEmpty || trimmed == ":memory:" {
            resolved = ":memory:"
        } else if trimmed.hasPrefix("file:") {
            resolved = trimmed
        } else {
            let safeName = trimmed.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? trimmed
            resolved = "file:\(safeName)?mode=memory&cache=shared"
        }
        try self.init(path: resolved, isInMemory: true, runMigrations: runMigrations)
    }

    private init(path: String, isInMemory: Bool, runMigrations: Bool) throws {
        self.databasePath = path
        self.isInMemory = isInMemory
        self.lock.name = "com.agentvm.store.sqlite.lock"

        var openedHandle: OpaquePointer?
        var openFlags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_EXRESCODE
        if isInMemory || path.hasPrefix("file:") {
            openFlags |= SQLITE_OPEN_URI
        }
        let rc = sqlite3_open_v2(path, &openedHandle, openFlags, nil)
        guard rc == SQLITE_OK, let handle = openedHandle else {
            let msg = openedHandle.flatMap { sqlite3_errmsg($0) }.map { String(cString: $0) }
                ?? "Unable to open SQLite handle"
            if let openedHandle {
                sqlite3_close_v2(openedHandle)
            }
            throw AgentVMError.storageDatabaseError(code: rc, sql: "OPEN \(path)", detail: msg)
        }
        self.dbHandle = handle

        do {
            try configureConnectionPragmas()
            if runMigrations {
                try migrateToLatest()
            }
        } catch {
            sqlite3_close_v2(handle)
            self.dbHandle = nil
            throw error
        }
    }

    deinit {
        close()
    }

    public func close() {
        lock.lock()
        defer { lock.unlock() }
        if let handle = dbHandle {
            sqlite3_close_v2(handle)
            dbHandle = nil
        }
        transactionDepth = 0
    }

    public var isOpen: Bool {
        lock.lock()
        defer { lock.unlock() }
        return dbHandle != nil
    }

    // MARK: - Core Query & Execution Primitives

    public func withPreparedStatement<R>(
        _ sql: String,
        _ body: (SQLitePreparedStatement) throws -> R
    ) throws -> R {
        try withLock {
            let handle = try requireOpenHandle(sql: sql)
            let stmt = try SQLitePreparedStatement(databaseHandle: handle, sql: sql)
            defer { stmt.finalize() }
            return try body(stmt)
        }
    }

    @discardableResult
    public func execute(_ sql: String, bindings: [SQLiteValue] = []) throws -> Int {
        try withLock {
            let handle = try requireOpenHandle(sql: sql)
            let stmt = try SQLitePreparedStatement(databaseHandle: handle, sql: sql)
            defer { stmt.finalize() }
            if !bindings.isEmpty {
                try stmt.bindAll(bindings)
            }
            try stmt.stepExecute()
            return Int(sqlite3_changes(handle))
        }
    }

    @discardableResult
    public func execute(_ sql: String, bindables: [(any SQLiteBindable)?]) throws -> Int {
        try execute(sql, bindings: bindables.map { $0?.sqliteValue ?? .null })
    }

    public func executeScript(_ multiStatementSQL: String) throws {
        try withLock {
            let handle = try requireOpenHandle(sql: multiStatementSQL)
            var errMsgPtr: UnsafeMutablePointer<CChar>?
            let rc = sqlite3_exec(handle, multiStatementSQL, nil, nil, &errMsgPtr)
            if rc != SQLITE_OK {
                let detail: String
                if let errMsgPtr {
                    detail = String(cString: errMsgPtr)
                    sqlite3_free(errMsgPtr)
                } else {
                    detail = sqlite3_errmsg(handle).map { String(cString: $0) } ?? "sqlite3_exec failed"
                }
                throw AgentVMError.storageDatabaseError(code: rc, sql: multiStatementSQL, detail: detail)
            }
        }
    }

    @discardableResult
    public func executeBatch(_ sql: String, parameterSets: [[SQLiteValue]]) throws -> Int {
        guard !parameterSets.isEmpty else { return 0 }
        return try inTransaction {
            let handle = try requireOpenHandle(sql: sql)
            let stmt = try SQLitePreparedStatement(databaseHandle: handle, sql: sql)
            defer { stmt.finalize() }
            var totalChanges = 0
            for params in parameterSets {
                try stmt.reset(clearBindings: true)
                try stmt.bindAll(params)
                try stmt.stepExecute()
                totalChanges += Int(sqlite3_changes(handle))
            }
            return totalChanges
        }
    }

    public func query(_ sql: String, bindings: [SQLiteValue] = []) throws -> [SQLiteRow] {
        try withLock {
            let handle = try requireOpenHandle(sql: sql)
            let stmt = try SQLitePreparedStatement(databaseHandle: handle, sql: sql)
            defer { stmt.finalize() }
            if !bindings.isEmpty {
                try stmt.bindAll(bindings)
            }
            return try stmt.fetchAll()
        }
    }

    public func query(_ sql: String, bindables: [(any SQLiteBindable)?]) throws -> [SQLiteRow] {
        try query(sql, bindings: bindables.map { $0?.sqliteValue ?? .null })
    }

    public func queryOne(_ sql: String, bindings: [SQLiteValue] = []) throws -> SQLiteRow? {
        try withLock {
            let handle = try requireOpenHandle(sql: sql)
            let stmt = try SQLitePreparedStatement(databaseHandle: handle, sql: sql)
            defer { stmt.finalize() }
            if !bindings.isEmpty {
                try stmt.bindAll(bindings)
            }
            return try stmt.stepRow()
        }
    }

    public func queryScalarInt64(_ sql: String, bindings: [SQLiteValue] = []) throws -> Int64? {
        guard let row = try queryOne(sql, bindings: bindings), row.columnCount > 0 else {
            return nil
        }
        switch row.value(at: 0) {
        case let .integer(v): return v
        case let .real(v): return Int64(v)
        case let .text(s): return Int64(s)
        default: return nil
        }
    }

    public func queryScalarString(_ sql: String, bindings: [SQLiteValue] = []) throws -> String? {
        guard let row = try queryOne(sql, bindings: bindings), row.columnCount > 0 else {
            return nil
        }
        switch row.value(at: 0) {
        case let .text(s): return s
        case let .integer(v): return String(v)
        case let .real(v): return String(v)
        default: return nil
        }
    }

    // MARK: - Explicit Transactions & Nested Savepoints

    public func inTransaction<R>(
        mode: SQLiteTransactionMode = .immediate,
        _ body: () throws -> R
    ) throws -> R {
        try withLock {
            if transactionDepth > 0 {
                return try withSavepointUnlocked(name: nil, body)
            }
            _ = try requireOpenHandle(sql: "BEGIN")
            try executeScript("BEGIN \(mode.rawValue) TRANSACTION;")
            transactionDepth = 1
            do {
                let result = try body()
                try executeScript("COMMIT TRANSACTION;")
                transactionDepth = 0
                return result
            } catch {
                try? executeScript("ROLLBACK TRANSACTION;")
                transactionDepth = 0
                throw error
            }
        }
    }

    public func withSavepoint<R>(
        name: String? = nil,
        _ body: () throws -> R
    ) throws -> R {
        try withLock {
            try withSavepointUnlocked(name: name, body)
        }
    }

    private func withSavepointUnlocked<R>(
        name: String?,
        _ body: () throws -> R
    ) throws -> R {
        savepointCounter &+= 1
        let sanitizedCustom = name?.replacingOccurrences(
            of: "[^A-Za-z0-9_]",
            with: "_",
            options: .regularExpression
        )
        let spIdentifier = sanitizedCustom.flatMap { $0.isEmpty ? nil : "sp_\($0)_\(savepointCounter)" }
            ?? "sp_nested_\(savepointCounter)"

        try executeScript("SAVEPOINT \(spIdentifier);")
        transactionDepth += 1
        do {
            let result = try body()
            try executeScript("RELEASE SAVEPOINT \(spIdentifier);")
            transactionDepth = max(0, transactionDepth - 1)
            return result
        } catch {
            try? executeScript("ROLLBACK TO SAVEPOINT \(spIdentifier);")
            try? executeScript("RELEASE SAVEPOINT \(spIdentifier);")
            transactionDepth = max(0, transactionDepth - 1)
            throw error
        }
    }

    // MARK: - WAL Checkpointing, Vacuum & Diagnostics

    private func configureConnectionPragmas() throws {
        try executeScript("PRAGMA busy_timeout = 5000;")
        _ = try queryOne("PRAGMA journal_mode = WAL;")
        try executeScript("PRAGMA synchronous = NORMAL;")
        try executeScript("PRAGMA foreign_keys = ON;")
        try executeScript("PRAGMA temp_store = MEMORY;")
    }

    public func vacuum() throws {
        try withLock {
            guard transactionDepth == 0 else {
                throw AgentVMError.storageDatabaseError(
                    code: SQLITE_ERROR,
                    sql: "VACUUM;",
                    detail: "VACUUM cannot be executed inside an active transaction."
                )
            }
            try executeScript("VACUUM;")
        }
    }

    @discardableResult
    public func walCheckpoint(
        mode: SQLiteWALCheckpointMode = .passive
    ) throws -> SQLiteWALCheckpointResult {
        try withLock {
            let handle = try requireOpenHandle(sql: "PRAGMA wal_checkpoint(\(mode.rawValue))")
            var logFrames: Int32 = 0
            var checkpointed: Int32 = 0
            let rc = sqlite3_wal_checkpoint_v2(
                handle,
                nil,
                mode.cFlag,
                &logFrames,
                &checkpointed
            )
            guard rc == SQLITE_OK else {
                let msg = sqlite3_errmsg(handle).map { String(cString: $0) } ?? "WAL checkpoint error"
                throw AgentVMError.storageDatabaseError(
                    code: rc,
                    sql: "wal_checkpoint_v2(\(mode.rawValue))",
                    detail: msg
                )
            }
            return SQLiteWALCheckpointResult(
                mode: mode,
                totalWALFrames: logFrames,
                checkpointedFrames: checkpointed
            )
        }
    }

    public func integrityCheck(maxErrors: Int = 10) throws -> [String] {
        let clamped = max(1, min(maxErrors, 100))
        let rows = try query("PRAGMA integrity_check(\(clamped));")
        var issues: [String] = []
        for row in rows {
            if let text = try row.optionalString(row.columnNames.first ?? "integrity_check"),
               text.lowercased() != "ok" {
                issues.append(text)
            }
        }
        return issues
    }

    public func foreignKeyViolations() throws -> [String] {
        let rows = try query("PRAGMA foreign_key_check;")
        var violations: [String] = []
        for row in rows {
            let table = (try? row.optionalString("table")) ?? "?"
            let rowid = (try? row.optionalInt64("rowid")).map(String.init) ?? "?"
            let parent = (try? row.optionalString("parent")) ?? "?"
            let fkid = (try? row.optionalInt64("fkid")).map(String.init) ?? "?"
            violations.append("table=\(table) rowid=\(rowid) references parent=\(parent) fkid=\(fkid)")
        }
        return violations
    }

    public func diagnostics() throws -> SQLiteDatabaseDiagnostics {
        try withLock {
            let version = try currentSchemaVersion()
            let libVersion = String(cString: sqlite3_libversion())
            let journalMode = (try queryScalarString("PRAGMA journal_mode;")) ?? "unknown"
            let syncMode = Int(try queryScalarInt64("PRAGMA synchronous;") ?? 0)
            let fkEnabled = (try queryScalarInt64("PRAGMA foreign_keys;") ?? 0) != 0
            let pageSize = try queryScalarInt64("PRAGMA page_size;") ?? 4096
            let pageCount = try queryScalarInt64("PRAGMA page_count;") ?? 0
            let freelist = try queryScalarInt64("PRAGMA freelist_count;") ?? 0

            let dbBytes: UInt64
            let walBytes: UInt64
            let shmBytes: UInt64
            if isInMemory {
                dbBytes = UInt64(max(0, pageSize * pageCount))
                walBytes = 0
                shmBytes = 0
            } else {
                dbBytes = Self.fileSizeBytes(atPath: databasePath)
                walBytes = Self.fileSizeBytes(atPath: databasePath + "-wal")
                shmBytes = Self.fileSizeBytes(atPath: databasePath + "-shm")
            }

            let tableNamesRows = try query(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name ASC;
                """
            )
            var counts: [String: Int64] = [:]
            for tRow in tableNamesRows {
                let tableName = try tRow.string("name")
                let safeIdent = tableName.replacingOccurrences(of: "\"", with: "\"\"")
                let count = try queryScalarInt64("SELECT COUNT(*) FROM \"\(safeIdent)\";") ?? 0
                counts[tableName] = count
            }

            return SQLiteDatabaseDiagnostics(
                databasePath: databasePath,
                schemaVersion: version,
                sqliteLibraryVersion: libVersion,
                journalMode: journalMode,
                synchronousMode: syncMode,
                foreignKeysEnabled: fkEnabled,
                pageSizeBytes: pageSize,
                pageCount: pageCount,
                freelistPageCount: freelist,
                databaseFileBytes: dbBytes,
                walFileBytes: walBytes,
                shmFileBytes: shmBytes,
                tableRowCounts: counts
            )
        }
    }

    // MARK: - Versioned Schema Migration Engine (v0 -> v1 -> v2 -> v3 -> v4)

    public func currentSchemaVersion() throws -> Int {
        try withLock {
            try ensureMigrationLedgerTableExists()
            let maxVer = try queryScalarInt64("SELECT COALESCE(MAX(version), 0) FROM schema_migrations;") ?? 0
            return Int(maxVer)
        }
    }

    public func appliedMigrations() throws -> [SQLiteAppliedMigration] {
        try withLock {
            try ensureMigrationLedgerTableExists()
            let rows = try query(
                """
                SELECT version, name, checksum, applied_at, execution_ms
                FROM schema_migrations
                ORDER BY version ASC;
                """
            )
            return try rows.map { row in
                SQLiteAppliedMigration(
                    version: try row.int("version"),
                    name: try row.string("name"),
                    checksum: try row.string("checksum"),
                    appliedAt: try row.date("applied_at"),
                    executionMilliseconds: try row.int("execution_ms")
                )
            }
        }
    }

    public func migrateToLatest(targetVersion: Int = SQLiteWALDatabase.latestSchemaVersion) throws {
        try withLock {
            try ensureMigrationLedgerTableExists()
            let catalog = Self.builtInMigrations()
            guard targetVersion >= 0 && targetVersion <= Self.latestSchemaVersion else {
                throw AgentVMError.storageMigrationFailed(
                    fromVersion: 0,
                    toVersion: targetVersion,
                    detail: "Requested schema version \(targetVersion) outside supported 0...\(Self.latestSchemaVersion)."
                )
            }

            let existing = try appliedMigrations()
            var existingByVersion: [Int: SQLiteAppliedMigration] = [:]
            for record in existing {
                existingByVersion[record.version] = record
            }

            let startingVersion = existing.map(\.version).max() ?? 0
            if startingVersion > Self.latestSchemaVersion {
                throw AgentVMError.storageMigrationFailed(
                    fromVersion: startingVersion,
                    toVersion: targetVersion,
                    detail: "Database schema version v\(startingVersion) is newer than engine v\(Self.latestSchemaVersion)."
                )
            }

            // Verify checksums of all previously applied migrations to catch tampering or drift.
            for migration in catalog where migration.version <= startingVersion {
                guard let applied = existingByVersion[migration.version] else {
                    throw AgentVMError.storageMigrationFailed(
                        fromVersion: startingVersion,
                        toVersion: targetVersion,
                        detail: "Missing migration ledger entry for v\(migration.version) (\(migration.name))."
                    )
                }
                if applied.checksum != migration.checksum {
                    throw AgentVMError.storageMigrationFailed(
                        fromVersion: migration.version,
                        toVersion: targetVersion,
                        detail: "Checksum mismatch on applied migration v\(migration.version) (\(migration.name)): stored=\(applied.checksum), expected=\(migration.checksum)."
                    )
                }
            }

            // Apply pending migrations sequentially inside atomic per-version transactions.
            for migration in catalog where migration.version > startingVersion && migration.version <= targetVersion {
                let prevVersion = migration.version - 1
                let started = DispatchTime.now().uptimeNanoseconds
                do {
                    try inTransaction(mode: .exclusive) {
                        for statement in migration.sqlStatements {
                            try executeScript(statement)
                        }
                        let elapsedNs = DispatchTime.now().uptimeNanoseconds - started
                        let elapsedMs = Int(elapsedNs / 1_000_000)
                        try execute(
                            """
                            INSERT INTO schema_migrations (version, name, checksum, applied_at, execution_ms)
                            VALUES (?, ?, ?, ?, ?);
                            """,
                            bindings: [
                                .integer(Int64(migration.version)),
                                .text(migration.name),
                                .text(migration.checksum),
                                Date().sqliteValue,
                                .integer(Int64(elapsedMs))
                            ]
                        )
                        try executeScript("PRAGMA user_version = \(migration.version);")
                    }
                } catch let vmErr as AgentVMError {
                    throw AgentVMError.storageMigrationFailed(
                        fromVersion: prevVersion,
                        toVersion: migration.version,
                        detail: vmErr.localizedDescription
                    )
                } catch {
                    throw AgentVMError.storageMigrationFailed(
                        fromVersion: prevVersion,
                        toVersion: migration.version,
                        detail: error.localizedDescription
                    )
                }
            }
        }
    }

    private func ensureMigrationLedgerTableExists() throws {
        try executeScript(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY NOT NULL,
                name TEXT NOT NULL,
                checksum TEXT NOT NULL,
                applied_at REAL NOT NULL,
                execution_ms INTEGER NOT NULL DEFAULT 0
            );
            """
        )
    }

    public static func builtInMigrations() -> [SQLiteSchemaMigration] {
        [
            // v1: vms, snapshots (with parent foreign keys, branch indices), firewall_policies
            SQLiteSchemaMigration(
                version: 1,
                name: "v1_core_vms_snapshots_firewall_policies",
                sqlStatements: [
                    """
                    CREATE TABLE IF NOT EXISTS vms (
                        id TEXT PRIMARY KEY NOT NULL,
                        name TEXT NOT NULL,
                        agent_owner_tag TEXT NOT NULL,
                        guest_os TEXT NOT NULL,
                        lifecycle_state TEXT NOT NULL,
                        vcpu_count INTEGER NOT NULL,
                        memory_mb INTEGER NOT NULL,
                        parent_vm_id TEXT,
                        forked_from_snapshot_id TEXT,
                        current_head_snapshot_id TEXT,
                        spec_json TEXT NOT NULL,
                        telemetry_json TEXT NOT NULL,
                        last_booted_at REAL,
                        last_error_description TEXT,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL
                    );
                    """,
                    "CREATE INDEX IF NOT EXISTS idx_vms_agent_owner ON vms(agent_owner_tag);",
                    "CREATE INDEX IF NOT EXISTS idx_vms_created_at ON vms(created_at ASC, id ASC);",
                    """
                    CREATE TABLE IF NOT EXISTS snapshots (
                        id TEXT PRIMARY KEY NOT NULL,
                        vm_id TEXT NOT NULL,
                        parent_snapshot_id TEXT,
                        branch_name TEXT NOT NULL,
                        title TEXT NOT NULL,
                        notes TEXT NOT NULL,
                        kind TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        disk_clone_path TEXT NOT NULL,
                        memory_state_path TEXT,
                        virtual_disk_bytes INTEGER NOT NULL,
                        allocated_disk_bytes INTEGER NOT NULL,
                        dirty_delta_bytes INTEGER NOT NULL,
                        memory_state_bytes INTEGER NOT NULL,
                        spec_snapshot_json TEXT NOT NULL,
                        agent_actor TEXT NOT NULL,
                        trigger_command TEXT,
                        is_pinned INTEGER NOT NULL DEFAULT 0,
                        tags_json TEXT NOT NULL DEFAULT '[]',
                        FOREIGN KEY (parent_snapshot_id) REFERENCES snapshots(id) ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED
                    );
                    """,
                    "CREATE INDEX IF NOT EXISTS idx_snapshots_vm_branch ON snapshots(vm_id, branch_name, created_at ASC);",
                    "CREATE INDEX IF NOT EXISTS idx_snapshots_parent ON snapshots(parent_snapshot_id);",
                    "CREATE INDEX IF NOT EXISTS idx_snapshots_vm_created ON snapshots(vm_id, created_at ASC, id ASC);",
                    """
                    CREATE TABLE IF NOT EXISTS firewall_policies (
                        id TEXT PRIMARY KEY NOT NULL,
                        name TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        default_egress_verdict TEXT NOT NULL,
                        default_ingress_verdict TEXT NOT NULL,
                        block_private_metadata_ips INTEGER NOT NULL DEFAULT 1,
                        rules_json TEXT NOT NULL,
                        updated_at REAL NOT NULL
                    );
                    """,
                    "CREATE INDEX IF NOT EXISTS idx_firewall_policies_name ON firewall_policies(name ASC, id ASC);"
                ]
            ),

            // v2: network_flows, diagnostics, exec_history (with composite (vm_id, timestamp) indices)
            SQLiteSchemaMigration(
                version: 2,
                name: "v2_telemetry_flows_diagnostics_exec_history",
                sqlStatements: [
                    """
                    CREATE TABLE IF NOT EXISTS network_flows (
                        id TEXT PRIMARY KEY NOT NULL,
                        vm_id TEXT NOT NULL,
                        transport TEXT NOT NULL,
                        source_ip TEXT NOT NULL,
                        source_port INTEGER NOT NULL,
                        destination_ip TEXT NOT NULL,
                        destination_port INTEGER NOT NULL,
                        resolved_domain_or_sni TEXT,
                        tcp_state TEXT,
                        packets_sent INTEGER NOT NULL DEFAULT 0,
                        packets_received INTEGER NOT NULL DEFAULT 0,
                        bytes_sent INTEGER NOT NULL DEFAULT 0,
                        bytes_received INTEGER NOT NULL DEFAULT 0,
                        verdict TEXT NOT NULL,
                        matched_rule_id TEXT,
                        first_seen_at REAL NOT NULL,
                        timestamp REAL NOT NULL
                    );
                    """,
                    "CREATE INDEX IF NOT EXISTS idx_network_flows_vm_timestamp ON network_flows(vm_id, timestamp DESC);",
                    "CREATE INDEX IF NOT EXISTS idx_network_flows_timestamp ON network_flows(timestamp DESC);",
                    """
                    CREATE TABLE IF NOT EXISTS diagnostics (
                        id TEXT PRIMARY KEY NOT NULL,
                        vm_id TEXT,
                        timestamp REAL NOT NULL,
                        severity TEXT NOT NULL,
                        severity_rank INTEGER NOT NULL,
                        subsystem TEXT NOT NULL,
                        code TEXT NOT NULL,
                        message TEXT NOT NULL,
                        metadata_json TEXT NOT NULL DEFAULT '{}'
                    );
                    """,
                    "CREATE INDEX IF NOT EXISTS idx_diagnostics_vm_timestamp ON diagnostics(vm_id, timestamp DESC);",
                    "CREATE INDEX IF NOT EXISTS idx_diagnostics_severity_timestamp ON diagnostics(severity_rank, timestamp DESC);",
                    """
                    CREATE TABLE IF NOT EXISTS exec_history (
                        request_id TEXT PRIMARY KEY NOT NULL,
                        vm_id TEXT NOT NULL,
                        timestamp REAL NOT NULL,
                        command_line TEXT NOT NULL,
                        exit_code INTEGER NOT NULL,
                        stdout_data BLOB NOT NULL,
                        stderr_data BLOB NOT NULL,
                        duration_ms INTEGER NOT NULL,
                        timed_out INTEGER NOT NULL DEFAULT 0,
                        pre_checkpoint_snapshot_id TEXT
                    );
                    """,
                    "CREATE INDEX IF NOT EXISTS idx_exec_history_vm_timestamp ON exec_history(vm_id, timestamp DESC);",
                    "CREATE INDEX IF NOT EXISTS idx_exec_history_timestamp ON exec_history(timestamp DESC);"
                ]
            ),

            // v3: plugin_kv_store, plugin_runtime_state, workspace_layouts
            SQLiteSchemaMigration(
                version: 3,
                name: "v3_plugins_and_workspace_layouts",
                sqlStatements: [
                    """
                    CREATE TABLE IF NOT EXISTS plugin_kv_store (
                        plugin_id TEXT NOT NULL,
                        key TEXT NOT NULL,
                        value TEXT NOT NULL,
                        updated_at REAL NOT NULL,
                        PRIMARY KEY (plugin_id, key)
                    );
                    """,
                    "CREATE INDEX IF NOT EXISTS idx_plugin_kv_plugin ON plugin_kv_store(plugin_id, key ASC);",
                    """
                    CREATE TABLE IF NOT EXISTS plugin_runtime_state (
                        plugin_id TEXT PRIMARY KEY NOT NULL,
                        is_enabled INTEGER NOT NULL DEFAULT 1,
                        granted_capabilities_json TEXT NOT NULL,
                        invocation_count INTEGER NOT NULL DEFAULT 0,
                        blocked_actions_count INTEGER NOT NULL DEFAULT 0,
                        average_duration_micros INTEGER NOT NULL DEFAULT 0,
                        last_error TEXT,
                        last_invoked_at REAL,
                        configuration_json TEXT NOT NULL DEFAULT '{}',
                        manifest_json TEXT NOT NULL,
                        updated_at REAL NOT NULL
                    );
                    """,
                    """
                    CREATE TABLE IF NOT EXISTS workspace_layouts (
                        slot_key TEXT PRIMARY KEY NOT NULL,
                        workspace_id TEXT NOT NULL,
                        layout_json TEXT NOT NULL,
                        updated_at REAL NOT NULL
                    );
                    """
                ]
            ),

            // v4: undo_journal, image_cache_entries, port_forward_audit
            SQLiteSchemaMigration(
                version: 4,
                name: "v4_undo_journal_image_cache_port_forward_audit",
                sqlStatements: [
                    """
                    CREATE TABLE IF NOT EXISTS undo_journal (
                        sequence_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        command_id TEXT NOT NULL UNIQUE,
                        command_type TEXT NOT NULL,
                        title TEXT NOT NULL,
                        stack_state TEXT NOT NULL,
                        payload_summary TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL
                    );
                    """,
                    "CREATE INDEX IF NOT EXISTS idx_undo_journal_state_seq ON undo_journal(stack_state, sequence_id DESC);",
                    """
                    CREATE TABLE IF NOT EXISTS image_cache_entries (
                        image_id TEXT PRIMARY KEY NOT NULL,
                        display_name TEXT NOT NULL,
                        distribution TEXT NOT NULL,
                        version TEXT NOT NULL,
                        guest_os TEXT NOT NULL,
                        local_path TEXT NOT NULL,
                        sha256_hex TEXT NOT NULL,
                        physical_bytes INTEGER NOT NULL,
                        virtual_bytes INTEGER NOT NULL,
                        is_custom_offline INTEGER NOT NULL DEFAULT 0,
                        verified_at REAL NOT NULL,
                        last_accessed_at REAL NOT NULL,
                        access_count INTEGER NOT NULL DEFAULT 1,
                        entry_json TEXT NOT NULL
                    );
                    """,
                    "CREATE INDEX IF NOT EXISTS idx_image_cache_lru ON image_cache_entries(last_accessed_at ASC);",
                    """
                    CREATE TABLE IF NOT EXISTS port_forward_audit (
                        id TEXT PRIMARY KEY NOT NULL,
                        vm_id TEXT NOT NULL,
                        rule_id TEXT NOT NULL,
                        protocol_type TEXT NOT NULL,
                        host_bind_address TEXT NOT NULL,
                        host_port INTEGER NOT NULL,
                        guest_port INTEGER NOT NULL,
                        vsock_cid INTEGER NOT NULL,
                        event_kind TEXT NOT NULL,
                        bytes_relayed INTEGER NOT NULL DEFAULT 0,
                        detail TEXT NOT NULL,
                        timestamp REAL NOT NULL
                    );
                    """,
                    "CREATE INDEX IF NOT EXISTS idx_port_forward_audit_vm_timestamp ON port_forward_audit(vm_id, timestamp DESC);"
                ]
            )
        ]
    }

    // MARK: - Internal Helpers

    private func withLock<R>(_ body: () throws -> R) rethrows -> R {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }

    private func requireOpenHandle(sql: String) throws -> OpaquePointer {
        guard let handle = dbHandle else {
            throw AgentVMError.storageDatabaseError(
                code: SQLITE_MISUSE,
                sql: sql,
                detail: "SQLiteWALDatabase at '\(databasePath)' is already closed."
            )
        }
        return handle
    }

    private static func fileSizeBytes(atPath path: String) -> UInt64 {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
              let size = attrs[.size] as? NSNumber else {
            return 0
        }
        return size.uint64Value
    }
}
