import AgentVMModels
import Foundation

// MARK: - Terminal Cell & Rendition Models

/// Single character cell with SGR rendition attributes inside a `VT100ScreenBuffer`.
public struct TerminalCell: Hashable, Sendable {
    public static let defaultForegroundANSI: UInt8 = 7
    public static let defaultBackgroundANSI: UInt8 = 0
    public static let blank = TerminalCell()

    public var scalar: Character
    public var fgANSI: UInt8
    public var bgANSI: UInt8
    public var isBold: Bool
    public var isDim: Bool
    public var isUnderline: Bool
    public var isInverse: Bool

    public init(
        scalar: Character = " ",
        fgANSI: UInt8 = Self.defaultForegroundANSI,
        bgANSI: UInt8 = Self.defaultBackgroundANSI,
        isBold: Bool = false,
        isDim: Bool = false,
        isUnderline: Bool = false,
        isInverse: Bool = false
    ) {
        self.scalar = scalar
        self.fgANSI = fgANSI
        self.bgANSI = bgANSI
        self.isBold = isBold
        self.isDim = isDim
        self.isUnderline = isUnderline
        self.isInverse = isInverse
    }
}

/// Immutable point-in-time terminal viewport snapshot for SwiftUI / AppKit console rendering.
public struct VT100ViewportSnapshot: Hashable, Sendable {
    public var columns: Int
    public var rows: Int
    public var cursorRow: Int
    public var cursorColumn: Int
    public var isCursorVisible: Bool
    public var isAlternateScreenActive: Bool
    public var windowTitle: String
    public var scrollbackLineCount: Int
    public var visibleGrid: [[TerminalCell]]

    public init(
        columns: Int,
        rows: Int,
        cursorRow: Int,
        cursorColumn: Int,
        isCursorVisible: Bool,
        isAlternateScreenActive: Bool,
        windowTitle: String,
        scrollbackLineCount: Int,
        visibleGrid: [[TerminalCell]]
    ) {
        self.columns = columns
        self.rows = rows
        self.cursorRow = cursorRow
        self.cursorColumn = cursorColumn
        self.isCursorVisible = isCursorVisible
        self.isAlternateScreenActive = isAlternateScreenActive
        self.windowTitle = windowTitle
        self.scrollbackLineCount = scrollbackLineCount
        self.visibleGrid = visibleGrid
    }
}

// MARK: - VT100 / ANSI / Xterm Escape Sequence State Machine & Screen Buffer

/// Thread-safe DEC VT100 / ANSI X3.64 / xterm-256color terminal emulator screen buffer.
///
/// Implements the Paul Williams VT500-series state machine (`ground`, `escape`, `csiEntry`, `csiParam`,
/// `oscString`), delayed right-margin wrap (`DECAWM`), top/bottom scroll margins (`DECSTBM`), alternate
/// screen switching (`?1049h`/`?1049l`), SGR 16/256/TrueColor rendition attributes, incremental UTF-8
/// multi-byte reassembly across packet boundaries, and a fixed-capacity `O(1)` scrollback ring buffer.
public final class VT100ScreenBuffer: @unchecked Sendable {
    public enum ParserState: String, Sendable {
        case ground
        case escape
        case escapeIntermediate
        case csiEntry
        case csiParam
        case csiIgnore
        case oscString
        case oscEscape
        case dcsPassthrough
        case dcsEscape
    }

    private struct SGRBrush: Hashable, Sendable {
        var fgANSI: UInt8 = TerminalCell.defaultForegroundANSI
        var bgANSI: UInt8 = TerminalCell.defaultBackgroundANSI
        var isBold: Bool = false
        var isDim: Bool = false
        var isUnderline: Bool = false
        var isInverse: Bool = false

        mutating func reset() {
            self = SGRBrush()
        }

        func makeCell(_ character: Character = " ") -> TerminalCell {
            TerminalCell(
                scalar: character,
                fgANSI: fgANSI,
                bgANSI: bgANSI,
                isBold: isBold,
                isDim: isDim,
                isUnderline: isUnderline,
                isInverse: isInverse
            )
        }
    }

    private struct SavedCursorState: Sendable {
        var row: Int = 0
        var column: Int = 0
        var brush: SGRBrush = SGRBrush()
        var pendingWrap: Bool = false
    }

    // MARK: Private Synchronized State

    private let lock = NSLock()

    private var gridColumns: Int
    private var gridRows: Int
    public let maxScrollbackLines: Int

    private var grid: [[TerminalCell]]
    private var primaryScreenBackup: [[TerminalCell]]?
    private var primarySavedCursorBackup: SavedCursorState?
    private var alternateScreenActive: Bool = false

    // Fixed-capacity O(1) circular scrollback ring buffer
    private var scrollbackRing: [[TerminalCell]]
    private var scrollbackHead: Int = 0
    private var scrollbackStoredCount: Int = 0

    // Cursor & Margin Geometry
    private var curRow: Int = 0
    private var curCol: Int = 0
    private var pendingWrap: Bool = false
    private var autoWrapEnabled: Bool = true
    private var cursorVisible: Bool = true
    private var scrollTopRow: Int = 0
    private var scrollBottomRow: Int
    private var savedCursor = SavedCursorState()

    // SGR & Parser State Machine
    private var brush = SGRBrush()
    private var state: ParserState = .ground
    private var csiPrivatePrefix: UInt8 = 0
    private var csiIntermediateByte: UInt8 = 0
    private var csiParamBuffer: [UInt8] = []
    private var oscByteBuffer: [UInt8] = []
    private var utf8IncompleteBytes: [UInt8] = []
    private var utf8ExpectedLength: Int = 0

    private var currentWindowTitle: String = ""
    private var bellCountValue: UInt64 = 0
    private var ingestedBytesTotal: UInt64 = 0

    private static let maxCSIParamBytes = 256
    private static let maxOSCStringBytes = 4096

    // MARK: Initialization

    public init(columns: Int = 120, rows: Int = 36, maxScrollbackLines: Int = 5_000) {
        let clampedCols = max(4, min(512, columns))
        let clampedRows = max(2, min(256, rows))
        let clampedScrollback = max(0, min(50_000, maxScrollbackLines))

        self.gridColumns = clampedCols
        self.gridRows = clampedRows
        self.maxScrollbackLines = clampedScrollback
        self.scrollBottomRow = clampedRows - 1
        self.grid = Self.makeBlankGrid(columns: clampedCols, rows: clampedRows, fill: .blank)
        self.scrollbackRing = []
        self.scrollbackRing.reserveCapacity(min(clampedScrollback, 256))
    }

    // MARK: Thread-Safe Read Properties

    public var columns: Int {
        lock.lock()
        defer { lock.unlock() }
        return gridColumns
    }

    public var rows: Int {
        lock.lock()
        defer { lock.unlock() }
        return gridRows
    }

    public var cursorRow: Int {
        lock.lock()
        defer { lock.unlock() }
        return curRow
    }

    public var cursorColumn: Int {
        lock.lock()
        defer { lock.unlock() }
        return curCol
    }

    public var cursorPosition: (row: Int, column: Int) {
        lock.lock()
        defer { lock.unlock() }
        return (curRow, curCol)
    }

    public var isCursorVisible: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cursorVisible
    }

    public var isAlternateScreen: Bool {
        lock.lock()
        defer { lock.unlock() }
        return alternateScreenActive
    }

    public var windowTitle: String {
        lock.lock()
        defer { lock.unlock() }
        return currentWindowTitle
    }

    public var parserState: ParserState {
        lock.lock()
        defer { lock.unlock() }
        return state
    }

    public var scrollbackCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return scrollbackStoredCount
    }

    public var bellCount: UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return bellCountValue
    }

    public var totalBytesIngested: UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return ingestedBytesTotal
    }

    // MARK: Public Ingestion & Mutation Entry Points

    /// Feeds raw PTY / serial console bytes into the VT100 state machine.
    public func feed(_ data: Data) {
        lock.lock()
        defer { lock.unlock() }
        ingestBytesLocked(data)
    }

    /// Feeds a UTF-8 string into the VT100 state machine.
    public func feed(_ text: String) {
        feed(Data(text.utf8))
    }

    /// Alias for `feed(_:)` supporting stream-writer conventions.
    public func write(_ data: Data) {
        feed(data)
    }

    /// Alias for `feed(_:)` supporting string stream-writer conventions.
    public func write(_ text: String) {
        feed(Data(text.utf8))
    }

    /// Alias for `feed(_:)` matching accumulator naming.
    public func ingest(_ data: Data) {
        feed(data)
    }

    /// Resizes the visible terminal grid while preserving existing visible rows and clamping cursor coordinates.
    public func resize(columns newColumns: Int, rows newRows: Int) {
        lock.lock()
        defer { lock.unlock() }

        let targetCols = max(4, min(512, newColumns))
        let targetRows = max(2, min(256, newRows))
        guard targetCols != gridColumns || targetRows != gridRows else { return }

        var resized = Self.makeBlankGrid(columns: targetCols, rows: targetRows, fill: .blank)

        if targetRows < gridRows && !alternateScreenActive {
            // Push overflow top lines into scrollback so content above cursor is preserved.
            let overflow = max(0, (curRow + 1) - targetRows)
            if overflow > 0 {
                for r in 0..<min(overflow, gridRows) {
                    pushScrollbackLineLocked(grid[r])
                }
                let remaining = Array(grid.dropFirst(min(overflow, gridRows)))
                for (rIdx, srcRow) in remaining.prefix(targetRows).enumerated() {
                    let copyCount = min(targetCols, srcRow.count)
                    for cIdx in 0..<copyCount {
                        resized[rIdx][cIdx] = srcRow[cIdx]
                    }
                }
                curRow = max(0, curRow - overflow)
            } else {
                for rIdx in 0..<min(targetRows, gridRows) {
                    let copyCount = min(targetCols, grid[rIdx].count)
                    for cIdx in 0..<copyCount {
                        resized[rIdx][cIdx] = grid[rIdx][cIdx]
                    }
                }
            }
        } else {
            for rIdx in 0..<min(targetRows, gridRows) {
                let copyCount = min(targetCols, grid[rIdx].count)
                for cIdx in 0..<copyCount {
                    resized[rIdx][cIdx] = grid[rIdx][cIdx]
                }
            }
        }

        gridColumns = targetCols
        gridRows = targetRows
        grid = resized
        scrollTopRow = 0
        scrollBottomRow = targetRows - 1
        curRow = max(0, min(targetRows - 1, curRow))
        curCol = max(0, min(targetCols - 1, curCol))
        pendingWrap = false
    }

    /// Clears the visible screen grid (and optionally the scrollback ring buffer) and homes the cursor.
    public func clear(includeScrollback: Bool = false) {
        lock.lock()
        defer { lock.unlock() }
        let blankFill = brush.makeCell(" ")
        grid = Self.makeBlankGrid(columns: gridColumns, rows: gridRows, fill: blankFill)
        curRow = 0
        curCol = 0
        pendingWrap = false
        if includeScrollback {
            clearScrollbackLocked()
        }
    }

    /// Full hardware reset (`RIS` / `ESC c`) restoring initial modes, attributes, margins, and primary screen.
    public func reset() {
        lock.lock()
        defer { lock.unlock() }
        fullResetLocked()
    }

    // MARK: Snapshot & Plain-Text Rendering APIs

    /// Returns a deep value-type copy of the visible `rows x columns` `TerminalCell` matrix.
    public func snapshotVisibleGrid() -> [[TerminalCell]] {
        lock.lock()
        defer { lock.unlock() }
        return grid
    }

    /// Captures a coherent atomic snapshot of cursor coordinates, mode flags, window title, and visible cells.
    public func snapshotViewport() -> VT100ViewportSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return VT100ViewportSnapshot(
            columns: gridColumns,
            rows: gridRows,
            cursorRow: curRow,
            cursorColumn: curCol,
            isCursorVisible: cursorVisible,
            isAlternateScreenActive: alternateScreenActive,
            windowTitle: currentWindowTitle,
            scrollbackLineCount: scrollbackStoredCount,
            visibleGrid: grid
        )
    }

    /// Returns all retained scrollback lines in chronological oldest-to-newest order.
    public func snapshotScrollbackLines() -> [[TerminalCell]] {
        lock.lock()
        defer { lock.unlock() }
        return orderedScrollbackLinesLocked()
    }

    /// Renders the terminal screen (and optionally retained scrollback history) as plain UTF-8 strings per line.
    public func renderPlainTextLines(
        includeScrollback: Bool = false,
        trimTrailingSpaces: Bool = true
    ) -> [String] {
        lock.lock()
        defer { lock.unlock() }

        var lines: [String] = []
        if includeScrollback && scrollbackStoredCount > 0 {
            lines.reserveCapacity(scrollbackStoredCount + gridRows)
            for rowCells in orderedScrollbackLinesLocked() {
                lines.append(Self.renderRowToString(rowCells, trimTrailingSpaces: trimTrailingSpaces))
            }
        } else {
            lines.reserveCapacity(gridRows)
        }

        for rowCells in grid {
            lines.append(Self.renderRowToString(rowCells, trimTrailingSpaces: trimTrailingSpaces))
        }
        return lines
    }

    /// Renders the visible grid (and optionally scrollback) into a single newline-delimited string,
    /// stripping trailing completely blank screen rows for clean CLI / log presentation.
    public func renderPlainText(includeScrollback: Bool = false) -> String {
        var lines = renderPlainTextLines(includeScrollback: includeScrollback, trimTrailingSpaces: true)
        while let last = lines.last, last.isEmpty && lines.count > 1 {
            lines.removeLast()
        }
        return lines.joined(separator: "\n")
    }

    // MARK: Core VT100 Byte-Level State Machine

    private func ingestBytesLocked(_ data: Data) {
        guard !data.isEmpty else { return }
        ingestedBytesTotal &+= UInt64(data.count)

        for byte in data {
            // If we are mid multi-byte UTF-8 sequence in ground state, complete or abort it first.
            if state == .ground && !utf8IncompleteBytes.isEmpty {
                if (byte & 0xC0) == 0x80 {
                    utf8IncompleteBytes.append(byte)
                    if utf8IncompleteBytes.count == utf8ExpectedLength {
                        let decoded = String(decoding: utf8IncompleteBytes, as: UTF8.self)
                        utf8IncompleteBytes.removeAll(keepingCapacity: true)
                        utf8ExpectedLength = 0
                        for ch in decoded {
                            putGraphicCharacterLocked(ch)
                        }
                    }
                    continue
                } else {
                    // Interrupted UTF-8 sequence (e.g. ESC mid-character): flush replacement and process current byte.
                    utf8IncompleteBytes.removeAll(keepingCapacity: true)
                    utf8ExpectedLength = 0
                    putGraphicCharacterLocked("\u{FFFD}")
                }
            }

            // CAN (0x18) and SUB (0x1A) immediately cancel escape/CSI sequences per DEC VT100 spec.
            if (byte == 0x18 || byte == 0x1A) && state != .oscString && state != .dcsPassthrough {
                state = .ground
                resetCSIContextLocked()
                continue
            }

            switch state {
            case .ground:
                stepGroundLocked(byte)
            case .escape:
                stepEscapeLocked(byte)
            case .escapeIntermediate:
                stepEscapeIntermediateLocked(byte)
            case .csiEntry:
                stepCSIEntryLocked(byte)
            case .csiParam:
                stepCSIParamLocked(byte)
            case .csiIgnore:
                if (0x40...0x7E).contains(byte) {
                    state = .ground
                }
            case .oscString:
                stepOSCStringLocked(byte)
            case .oscEscape:
                stepOSCEscapeLocked(byte)
            case .dcsPassthrough:
                if byte == 0x1B {
                    state = .dcsEscape
                } else if byte == 0x07 || byte == 0x9C {
                    state = .ground
                }
            case .dcsEscape:
                state = .ground
                if byte != UInt8(ascii: "\\") {
                    stepEscapeLocked(byte)
                }
            }
        }
    }

    private func stepGroundLocked(_ byte: UInt8) {
        switch byte {
        case 0x00...0x1F:
            executeC0ControlLocked(byte)
        case 0x20...0x7E:
            putGraphicCharacterLocked(Character(UnicodeScalar(byte)))
        case 0x7F:
            // DEL is ignored in ground state.
            break
        case 0xC2...0xDF:
            utf8IncompleteBytes = [byte]
            utf8ExpectedLength = 2
        case 0xE0...0xEF:
            utf8IncompleteBytes = [byte]
            utf8ExpectedLength = 3
        case 0xF0...0xF4:
            utf8IncompleteBytes = [byte]
            utf8ExpectedLength = 4
        default:
            // Invalid standalone UTF-8 lead/continuation byte (0x80..0xC1, 0xF5..0xFF)
            if byte == 0x9B {
                // 8-bit C1 CSI
                resetCSIContextLocked()
                state = .csiEntry
            } else {
                putGraphicCharacterLocked("\u{FFFD}")
            }
        }
    }

    private func executeC0ControlLocked(_ byte: UInt8) {
        switch byte {
        case 0x07: // BEL
            bellCountValue &+= 1
        case 0x08: // BS
            pendingWrap = false
            if curCol > 0 {
                curCol -= 1
            }
        case 0x09: // HT (Horizontal Tab to next 8-column stop)
            pendingWrap = false
            let nextStop = ((curCol / 8) + 1) * 8
            curCol = min(gridColumns - 1, nextStop)
        case 0x0A, 0x0B, 0x0C: // LF, VT, FF
            pendingWrap = false
            lineFeedLocked()
        case 0x0D: // CR
            pendingWrap = false
            curCol = 0
        case 0x1B: // ESC
            state = .escape
            csiIntermediateByte = 0
        default:
            break
        }
    }

    private func stepEscapeLocked(_ byte: UInt8) {
        switch byte {
        case UInt8(ascii: "["): // CSI
            resetCSIContextLocked()
            state = .csiEntry
        case UInt8(ascii: "]"): // OSC
            oscByteBuffer.removeAll(keepingCapacity: true)
            state = .oscString
        case UInt8(ascii: "P"), UInt8(ascii: "X"), UInt8(ascii: "^"), UInt8(ascii: "_"): // DCS / SOS / PM / APC
            state = .dcsPassthrough
        case UInt8(ascii: "D"): // IND (Index)
            pendingWrap = false
            lineFeedLocked()
            state = .ground
        case UInt8(ascii: "E"): // NEL (Next Line)
            pendingWrap = false
            curCol = 0
            lineFeedLocked()
            state = .ground
        case UInt8(ascii: "M"): // RI (Reverse Index)
            pendingWrap = false
            reverseLineFeedLocked()
            state = .ground
        case UInt8(ascii: "7"): // DECSC (Save Cursor)
            savedCursor = SavedCursorState(row: curRow, column: curCol, brush: brush, pendingWrap: pendingWrap)
            state = .ground
        case UInt8(ascii: "8"): // DECRC (Restore Cursor)
            curRow = max(0, min(gridRows - 1, savedCursor.row))
            curCol = max(0, min(gridColumns - 1, savedCursor.column))
            brush = savedCursor.brush
            pendingWrap = savedCursor.pendingWrap
            state = .ground
        case UInt8(ascii: "c"): // RIS (Full Reset)
            fullResetLocked()
            state = .ground
        case 0x20...0x2F: // Intermediate charset / DEC sequences e.g. ESC ( B, ESC # 8
            csiIntermediateByte = byte
            state = .escapeIntermediate
        case 0x1B:
            state = .escape
        default:
            state = .ground
        }
    }

    private func stepEscapeIntermediateLocked(_ byte: UInt8) {
        if (0x20...0x2F).contains(byte) {
            csiIntermediateByte = byte
            return
        }
        if csiIntermediateByte == UInt8(ascii: "#") && byte == UInt8(ascii: "8") {
            // DECALN screen alignment pattern ('E')
            let alignCell = SGRBrush().makeCell("E")
            grid = Self.makeBlankGrid(columns: gridColumns, rows: gridRows, fill: alignCell)
            curRow = 0
            curCol = 0
            pendingWrap = false
        }
        state = .ground
    }

    private func stepCSIEntryLocked(_ byte: UInt8) {
        if byte < 0x20 {
            executeC0ControlLocked(byte)
            return
        }
        if byte == UInt8(ascii: "?") || byte == UInt8(ascii: ">") || byte == UInt8(ascii: "=") {
            csiPrivatePrefix = byte
            state = .csiParam
            return
        }
        stepCSIParamLocked(byte)
    }

    private func stepCSIParamLocked(_ byte: UInt8) {
        if byte < 0x20 {
            executeC0ControlLocked(byte)
            return
        }
        switch byte {
        case UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: ";"), UInt8(ascii: ":"):
            if csiParamBuffer.count < Self.maxCSIParamBytes {
                csiParamBuffer.append(byte)
                state = .csiParam
            } else {
                state = .csiIgnore
            }
        case 0x20...0x2F:
            csiIntermediateByte = byte
            state = .csiParam
        case 0x3C...0x3F:
            // Unexpected private marker mid-params -> ignore malformed sequence
            state = .csiIgnore
        case 0x40...0x7E:
            dispatchCSIFinalLocked(byte)
            state = .ground
        default:
            state = .ground
        }
    }

    private func stepOSCStringLocked(_ byte: UInt8) {
        if byte == 0x07 || byte == 0x9C { // BEL or 8-bit ST terminates OSC
            commitOSCStringLocked()
            state = .ground
        } else if byte == 0x1B {
            state = .oscEscape
        } else if oscByteBuffer.count < Self.maxOSCStringBytes {
            oscByteBuffer.append(byte)
        }
    }

    private func stepOSCEscapeLocked(_ byte: UInt8) {
        if byte == UInt8(ascii: "\\") { // 7-bit ST ("ESC \")
            commitOSCStringLocked()
            state = .ground
        } else {
            commitOSCStringLocked()
            state = .escape
            stepEscapeLocked(byte)
        }
    }

    private func commitOSCStringLocked() {
        defer { oscByteBuffer.removeAll(keepingCapacity: true) }
        guard !oscByteBuffer.isEmpty else { return }
        let raw = String(decoding: oscByteBuffer, as: UTF8.self)
        guard let semi = raw.firstIndex(of: ";") else { return }
        let codePart = raw[..<semi]
        let payloadPart = String(raw[raw.index(after: semi)...])
        if codePart == "0" || codePart == "2" {
            currentWindowTitle = payloadPart
        }
    }

    // MARK: Graphic Printing & Scrolling Operations

    private func putGraphicCharacterLocked(_ ch: Character) {
        if pendingWrap {
            if autoWrapEnabled {
                curCol = 0
                lineFeedLocked()
            }
            pendingWrap = false
        }

        grid[curRow][curCol] = brush.makeCell(ch)

        if curCol + 1 < gridColumns {
            curCol += 1
        } else if autoWrapEnabled {
            pendingWrap = true
        }
    }

    private func lineFeedLocked() {
        if curRow == scrollBottomRow {
            scrollUpRegionLocked(lines: 1)
        } else if curRow + 1 < gridRows {
            curRow += 1
        }
    }

    private func reverseLineFeedLocked() {
        if curRow == scrollTopRow {
            scrollDownRegionLocked(lines: 1)
        } else if curRow > 0 {
            curRow -= 1
        }
    }

    private func scrollUpRegionLocked(lines count: Int) {
        let top = max(0, min(gridRows - 1, scrollTopRow))
        let bottom = max(top, min(gridRows - 1, scrollBottomRow))
        let regionHeight = bottom - top + 1
        let shift = max(1, min(regionHeight, count))
        let blankFill = brush.makeCell(" ")

        for _ in 0..<shift {
            let evictedRow = grid[top]
            if top == 0 && !alternateScreenActive {
                pushScrollbackLineLocked(evictedRow)
            }
            if top < bottom {
                for r in top..<bottom {
                    grid[r] = grid[r + 1]
                }
            }
            grid[bottom] = [TerminalCell](repeating: blankFill, count: gridColumns)
        }
    }

    private func scrollDownRegionLocked(lines count: Int) {
        let top = max(0, min(gridRows - 1, scrollTopRow))
        let bottom = max(top, min(gridRows - 1, scrollBottomRow))
        let regionHeight = bottom - top + 1
        let shift = max(1, min(regionHeight, count))
        let blankFill = brush.makeCell(" ")

        for _ in 0..<shift {
            if bottom > top {
                for r in stride(from: bottom, through: top + 1, by: -1) {
                    grid[r] = grid[r - 1]
                }
            }
            grid[top] = [TerminalCell](repeating: blankFill, count: gridColumns)
        }
    }

    // MARK: CSI Command Dispatcher

    private func resetCSIContextLocked() {
        csiPrivatePrefix = 0
        csiIntermediateByte = 0
        csiParamBuffer.removeAll(keepingCapacity: true)
    }

    private func parseCSIParametersLocked() -> [Int] {
        guard !csiParamBuffer.isEmpty else { return [] }
        // Normalize ISO 8613-6 colon sub-separators into semicolons for SGR extended color parsing.
        let text = String(decoding: csiParamBuffer, as: UTF8.self)
            .replacingOccurrences(of: ":", with: ";")
        let parts = text.split(separator: ";", omittingEmptySubsequences: false)
        return parts.map { Int($0) ?? 0 }
    }

    private func dispatchCSIFinalLocked(_ finalByte: UInt8) {
        let params = parseCSIParametersLocked()
        let p0 = params.first ?? 0
        let p1 = params.count > 1 ? params[1] : 0

        if csiPrivatePrefix == UInt8(ascii: "?") {
            dispatchDECPrivateModeLocked(finalByte: finalByte, params: params)
            return
        }

        switch finalByte {
        case UInt8(ascii: "A"): // CUU - Cursor Up
            pendingWrap = false
            curRow = max(0, curRow - max(1, p0))

        case UInt8(ascii: "B"): // CUD - Cursor Down
            pendingWrap = false
            curRow = min(gridRows - 1, curRow + max(1, p0))

        case UInt8(ascii: "C"): // CUF - Cursor Forward
            pendingWrap = false
            curCol = min(gridColumns - 1, curCol + max(1, p0))

        case UInt8(ascii: "D"): // CUB - Cursor Backward
            pendingWrap = false
            curCol = max(0, curCol - max(1, p0))

        case UInt8(ascii: "E"): // CNL - Cursor Next Line
            pendingWrap = false
            curRow = min(gridRows - 1, curRow + max(1, p0))
            curCol = 0

        case UInt8(ascii: "F"): // CPL - Cursor Preceding Line
            pendingWrap = false
            curRow = max(0, curRow - max(1, p0))
            curCol = 0

        case UInt8(ascii: "G"), UInt8(ascii: "`"): // CHA - Cursor Horizontal Absolute (1-based)
            pendingWrap = false
            let targetCol = max(1, p0) - 1
            curCol = max(0, min(gridColumns - 1, targetCol))

        case UInt8(ascii: "H"), UInt8(ascii: "f"): // CUP / HVP - Cursor Position (1-based row;col)
            pendingWrap = false
            let targetRow = max(1, p0) - 1
            let targetCol = max(1, p1) - 1
            curRow = max(0, min(gridRows - 1, targetRow))
            curCol = max(0, min(gridColumns - 1, targetCol))

        case UInt8(ascii: "d"): // VPA - Vertical Line Position Absolute (1-based)
            pendingWrap = false
            let targetRow = max(1, p0) - 1
            curRow = max(0, min(gridRows - 1, targetRow))

        case UInt8(ascii: "J"): // ED - Erase in Display
            pendingWrap = false
            eraseInDisplayLocked(mode: p0)

        case UInt8(ascii: "K"): // EL - Erase in Line
            pendingWrap = false
            eraseInLineLocked(mode: p0)

        case UInt8(ascii: "X"): // ECH - Erase Characters
            pendingWrap = false
            let count = max(1, p0)
            let blankFill = brush.makeCell(" ")
            for col in curCol..<min(gridColumns, curCol + count) {
                grid[curRow][col] = blankFill
            }

        case UInt8(ascii: "L"): // IL - Insert Lines
            pendingWrap = false
            insertLinesLocked(count: max(1, p0))

        case UInt8(ascii: "M"): // DL - Delete Lines
            pendingWrap = false
            deleteLinesLocked(count: max(1, p0))

        case UInt8(ascii: "@"): // ICH - Insert Blank Characters
            pendingWrap = false
            insertCharactersLocked(count: max(1, p0))

        case UInt8(ascii: "P"): // DCH - Delete Characters
            pendingWrap = false
            deleteCharactersLocked(count: max(1, p0))

        case UInt8(ascii: "S"): // SU - Scroll Up
            scrollUpRegionLocked(lines: max(1, p0))

        case UInt8(ascii: "T"): // SD - Scroll Down
            scrollDownRegionLocked(lines: max(1, p0))

        case UInt8(ascii: "r"): // DECSTBM - Set Top and Bottom Margins
            let top = max(1, p0) - 1
            let bottom = (p1 == 0 ? gridRows : p1) - 1
            if top >= 0 && bottom < gridRows && top < bottom {
                scrollTopRow = top
                scrollBottomRow = bottom
            } else {
                scrollTopRow = 0
                scrollBottomRow = gridRows - 1
            }
            curRow = 0
            curCol = 0
            pendingWrap = false

        case UInt8(ascii: "s"): // SCP - Save Cursor Position
            savedCursor = SavedCursorState(row: curRow, column: curCol, brush: brush, pendingWrap: pendingWrap)

        case UInt8(ascii: "u"): // RCP - Restore Cursor Position
            curRow = max(0, min(gridRows - 1, savedCursor.row))
            curCol = max(0, min(gridColumns - 1, savedCursor.column))
            pendingWrap = savedCursor.pendingWrap

        case UInt8(ascii: "m"): // SGR - Select Graphic Rendition
            applySGRParametersLocked(params.isEmpty ? [0] : params)

        default:
            break
        }
    }

    private func dispatchDECPrivateModeLocked(finalByte: UInt8, params: [Int]) {
        guard finalByte == UInt8(ascii: "h") || finalByte == UInt8(ascii: "l") else { return }
        let enabled = (finalByte == UInt8(ascii: "h"))

        for mode in params {
            switch mode {
            case 7: // DECAWM - Auto-Wrap Mode
                autoWrapEnabled = enabled
                if !enabled { pendingWrap = false }
            case 25: // DECTCEM - Text Cursor Enable Mode
                cursorVisible = enabled
            case 47, 1047, 1049: // Alternate Screen Buffer
                setAlternateScreenLocked(enabled: enabled, saveCursor: mode == 1049)
            default:
                break
            }
        }
    }

    private func setAlternateScreenLocked(enabled: Bool, saveCursor: Bool) {
        if enabled && !alternateScreenActive {
            primaryScreenBackup = grid
            if saveCursor {
                primarySavedCursorBackup = SavedCursorState(
                    row: curRow,
                    column: curCol,
                    brush: brush,
                    pendingWrap: pendingWrap
                )
            }
            alternateScreenActive = true
            grid = Self.makeBlankGrid(columns: gridColumns, rows: gridRows, fill: brush.makeCell(" "))
            curRow = 0
            curCol = 0
            pendingWrap = false
            scrollTopRow = 0
            scrollBottomRow = gridRows - 1
        } else if !enabled && alternateScreenActive {
            alternateScreenActive = false
            if let backup = primaryScreenBackup,
               backup.count == gridRows,
               backup.first?.count == gridColumns {
                grid = backup
            } else {
                grid = Self.makeBlankGrid(columns: gridColumns, rows: gridRows, fill: .blank)
            }
            primaryScreenBackup = nil
            if let saved = primarySavedCursorBackup {
                curRow = max(0, min(gridRows - 1, saved.row))
                curCol = max(0, min(gridColumns - 1, saved.column))
                brush = saved.brush
                pendingWrap = saved.pendingWrap
                primarySavedCursorBackup = nil
            }
            scrollTopRow = 0
            scrollBottomRow = gridRows - 1
        }
    }

    // MARK: Erase & Line Edit Helpers

    private func eraseInDisplayLocked(mode: Int) {
        let blankFill = brush.makeCell(" ")
        switch mode {
        case 0: // Cursor through end of screen
            for c in curCol..<gridColumns {
                grid[curRow][c] = blankFill
            }
            if curRow + 1 < gridRows {
                for r in (curRow + 1)..<gridRows {
                    grid[r] = [TerminalCell](repeating: blankFill, count: gridColumns)
                }
            }
        case 1: // Start of screen through cursor (inclusive)
            for r in 0..<curRow {
                grid[r] = [TerminalCell](repeating: blankFill, count: gridColumns)
            }
            for c in 0...min(gridColumns - 1, curCol) {
                grid[curRow][c] = blankFill
            }
        case 2: // Entire visible screen
            grid = Self.makeBlankGrid(columns: gridColumns, rows: gridRows, fill: blankFill)
        case 3: // Entire visible screen + scrollback buffer
            grid = Self.makeBlankGrid(columns: gridColumns, rows: gridRows, fill: blankFill)
            clearScrollbackLocked()
        default:
            break
        }
    }

    private func eraseInLineLocked(mode: Int) {
        let blankFill = brush.makeCell(" ")
        switch mode {
        case 0: // Cursor to end of line
            for c in curCol..<gridColumns {
                grid[curRow][c] = blankFill
            }
        case 1: // Start of line to cursor (inclusive)
            for c in 0...min(gridColumns - 1, curCol) {
                grid[curRow][c] = blankFill
            }
        case 2: // Entire line
            grid[curRow] = [TerminalCell](repeating: blankFill, count: gridColumns)
        default:
            break
        }
    }

    private func insertLinesLocked(count: Int) {
        guard curRow >= scrollTopRow && curRow <= scrollBottomRow else { return }
        let blankFill = brush.makeCell(" ")
        let maxInsert = scrollBottomRow - curRow + 1
        let shift = min(count, maxInsert)
        for _ in 0..<shift {
            if scrollBottomRow > curRow {
                for r in stride(from: scrollBottomRow, through: curRow + 1, by: -1) {
                    grid[r] = grid[r - 1]
                }
            }
            grid[curRow] = [TerminalCell](repeating: blankFill, count: gridColumns)
        }
    }

    private func deleteLinesLocked(count: Int) {
        guard curRow >= scrollTopRow && curRow <= scrollBottomRow else { return }
        let blankFill = brush.makeCell(" ")
        let maxDelete = scrollBottomRow - curRow + 1
        let shift = min(count, maxDelete)
        for _ in 0..<shift {
            if curRow < scrollBottomRow {
                for r in curRow..<scrollBottomRow {
                    grid[r] = grid[r + 1]
                }
            }
            grid[scrollBottomRow] = [TerminalCell](repeating: blankFill, count: gridColumns)
        }
    }

    private func insertCharactersLocked(count: Int) {
        let blankFill = brush.makeCell(" ")
        let shift = min(count, gridColumns - curCol)
        guard shift > 0 else { return }
        for c in stride(from: gridColumns - 1, through: curCol + shift, by: -1) {
            grid[curRow][c] = grid[curRow][c - shift]
        }
        for c in curCol..<(curCol + shift) {
            grid[curRow][c] = blankFill
        }
    }

    private func deleteCharactersLocked(count: Int) {
        let blankFill = brush.makeCell(" ")
        let shift = min(count, gridColumns - curCol)
        guard shift > 0 else { return }
        for c in curCol..<(gridColumns - shift) {
            grid[curRow][c] = grid[curRow][c + shift]
        }
        for c in (gridColumns - shift)..<gridColumns {
            grid[curRow][c] = blankFill
        }
    }

    // MARK: SGR 16 / 256 / TrueColor Attribute Parser

    private func applySGRParametersLocked(_ codes: [Int]) {
        var idx = 0
        while idx < codes.count {
            let code = codes[idx]
            switch code {
            case 0:
                brush.reset()
            case 1:
                brush.isBold = true
            case 2:
                brush.isDim = true
            case 4:
                brush.isUnderline = true
            case 7:
                brush.isInverse = true
            case 21, 22:
                brush.isBold = false
                brush.isDim = false
            case 24:
                brush.isUnderline = false
            case 27:
                brush.isInverse = false
            case 30...37:
                brush.fgANSI = UInt8(code - 30)
            case 39:
                brush.fgANSI = TerminalCell.defaultForegroundANSI
            case 40...47:
                brush.bgANSI = UInt8(code - 40)
            case 49:
                brush.bgANSI = TerminalCell.defaultBackgroundANSI
            case 90...97:
                brush.fgANSI = UInt8(code - 90 + 8)
            case 100...107:
                brush.bgANSI = UInt8(code - 100 + 8)
            case 38, 48:
                let isForeground = (code == 38)
                if idx + 2 < codes.count && codes[idx + 1] == 5 {
                    let paletteIndex = UInt8(clamping: max(0, min(255, codes[idx + 2])))
                    if isForeground {
                        brush.fgANSI = paletteIndex
                    } else {
                        brush.bgANSI = paletteIndex
                    }
                    idx += 3
                    continue
                } else if idx + 4 < codes.count && codes[idx + 1] == 2 {
                    let r = max(0, min(255, codes[idx + 2]))
                    let g = max(0, min(255, codes[idx + 3]))
                    let b = max(0, min(255, codes[idx + 4]))
                    let paletteIndex = Self.quantizeRGBToXterm256(r: r, g: g, b: b)
                    if isForeground {
                        brush.fgANSI = paletteIndex
                    } else {
                        brush.bgANSI = paletteIndex
                    }
                    idx += 5
                    continue
                }
            default:
                break
            }
            idx += 1
        }
    }

    private static func quantizeRGBToXterm256(r: Int, g: Int, b: Int) -> UInt8 {
        if r == g && g == b {
            if r < 8 { return 16 }
            if r > 248 { return 231 }
            return UInt8(232 + ((r - 8) * 24) / 247)
        }
        let r6 = (r * 5 + 127) / 255
        let g6 = (g * 5 + 127) / 255
        let b6 = (b * 5 + 127) / 255
        return UInt8(16 + (36 * r6) + (6 * g6) + b6)
    }

    // MARK: O(1) Scrollback Ring Buffer Operations

    private func pushScrollbackLineLocked(_ rowCells: [TerminalCell]) {
        guard maxScrollbackLines > 0 else { return }
        if scrollbackRing.count < maxScrollbackLines {
            scrollbackRing.append(rowCells)
            scrollbackStoredCount = scrollbackRing.count
        } else {
            scrollbackRing[scrollbackHead] = rowCells
            scrollbackHead = (scrollbackHead + 1) % maxScrollbackLines
            scrollbackStoredCount = maxScrollbackLines
        }
    }

    private func orderedScrollbackLinesLocked() -> [[TerminalCell]] {
        guard scrollbackStoredCount > 0 else { return [] }
        if scrollbackStoredCount < maxScrollbackLines || scrollbackHead == 0 {
            return Array(scrollbackRing.prefix(scrollbackStoredCount))
        }
        var result: [[TerminalCell]] = []
        result.reserveCapacity(scrollbackStoredCount)
        result.append(contentsOf: scrollbackRing[scrollbackHead..<scrollbackRing.count])
        result.append(contentsOf: scrollbackRing[0..<scrollbackHead])
        return result
    }

    private func clearScrollbackLocked() {
        scrollbackRing.removeAll(keepingCapacity: false)
        scrollbackHead = 0
        scrollbackStoredCount = 0
    }

    private func fullResetLocked() {
        alternateScreenActive = false
        primaryScreenBackup = nil
        primarySavedCursorBackup = nil
        brush.reset()
        grid = Self.makeBlankGrid(columns: gridColumns, rows: gridRows, fill: .blank)
        clearScrollbackLocked()
        curRow = 0
        curCol = 0
        pendingWrap = false
        autoWrapEnabled = true
        cursorVisible = true
        scrollTopRow = 0
        scrollBottomRow = gridRows - 1
        savedCursor = SavedCursorState()
        state = .ground
        resetCSIContextLocked()
        oscByteBuffer.removeAll(keepingCapacity: false)
        utf8IncompleteBytes.removeAll(keepingCapacity: false)
        utf8ExpectedLength = 0
        currentWindowTitle = ""
    }

    private static func makeBlankGrid(columns: Int, rows: Int, fill: TerminalCell) -> [[TerminalCell]] {
        let blankRow = [TerminalCell](repeating: fill, count: columns)
        return [[TerminalCell]](repeating: blankRow, count: rows)
    }

    private static func renderRowToString(_ cells: [TerminalCell], trimTrailingSpaces: Bool) -> String {
        var end = cells.count
        if trimTrailingSpaces {
            while end > 0 && cells[end - 1].scalar == " " {
                end -= 1
            }
        }
        guard end > 0 else { return "" }
        var text = String()
        text.reserveCapacity(end)
        for idx in 0..<end {
            text.append(cells[idx].scalar)
        }
        return text
    }
}
