import AppKit
import AgentVMModels
import SwiftUI

// MARK: - Industrial Rack Graphite & Hardware Amber Design Tokens

public enum RackTheme {
    // Surfaces
    public static let chassisBackground = Color(red: 0x14 / 255.0, green: 0x15 / 255.0, blue: 0x17 / 255.0)
    public static let bladeRecessed     = Color(red: 0x19 / 255.0, green: 0x1B / 255.0, blue: 0x1F / 255.0)
    public static let moduleSurface     = Color(red: 0x20 / 255.0, green: 0x23 / 255.0, blue: 0x29 / 255.0)
    public static let moduleElevated    = Color(red: 0x27 / 255.0, green: 0x2B / 255.0, blue: 0x33 / 255.0)
    public static let terminalWell      = Color(red: 0x0E / 255.0, green: 0x10 / 255.0, blue: 0x13 / 255.0)

    // Machined Borders & Hairlines
    public static let hairline          = Color(red: 0x2F / 255.0, green: 0x34 / 255.0, blue: 0x3F / 255.0)
    public static let hairlineStrong    = Color(red: 0x3F / 255.0, green: 0x46 / 255.0, blue: 0x54 / 255.0)
    public static let topBevelHighlight = Color.white.opacity(0.055)

    // Ink Hierarchy
    public static let inkPrimary        = Color(red: 0xED / 255.0, green: 0xEF / 255.0, blue: 0xF2 / 255.0)
    public static let inkSecondary      = Color(red: 0x9E / 255.0, green: 0xA6 / 255.0, blue: 0xB4 / 255.0)
    public static let inkMuted          = Color(red: 0x6E / 255.0, green: 0x76 / 255.0, blue: 0x85 / 255.0)

    // Hardware Signal LEDs
    public static let amberAccent       = Color(red: 0xD9 / 255.0, green: 0x77 / 255.0, blue: 0x24 / 255.0)
    public static let amberSoft         = Color(red: 0xD9 / 255.0, green: 0x77 / 255.0, blue: 0x24 / 255.0).opacity(0.16)
    public static let linkGreen         = Color(red: 0x2A / 255.0, green: 0x9D / 255.0, blue: 0x6F / 255.0)
    public static let linkGreenSoft     = Color(red: 0x2A / 255.0, green: 0x9D / 255.0, blue: 0x6F / 255.0).opacity(0.16)
    public static let vsockBlue         = Color(red: 0x3B / 255.0, green: 0x82 / 255.0, blue: 0xF6 / 255.0)
    public static let vsockBlueSoft     = Color(red: 0x3B / 255.0, green: 0x82 / 255.0, blue: 0xF6 / 255.0).opacity(0.16)
    public static let dropCrimson       = Color(red: 0xD6 / 255.0, green: 0x45 / 255.0, blue: 0x45 / 255.0)
    public static let dropCrimsonSoft   = Color(red: 0xD6 / 255.0, green: 0x45 / 255.0, blue: 0x45 / 255.0).opacity(0.16)
    public static let checkpointGold    = Color(red: 0xD4 / 255.0, green: 0xA0 / 255.0, blue: 0x24 / 255.0)
    public static let checkpointSoft    = Color(red: 0xD4 / 255.0, green: 0xA0 / 255.0, blue: 0x24 / 255.0).opacity(0.16)

    // Typography Helpers (Optical hierarchy, tabular numerals, untracked sentence-case labels)
    public static let displayTitleFont  = Font.system(size: 18, weight: .semibold, design: .default)
    public static let sectionHeaderFont = Font.system(size: 13, weight: .semibold, design: .default)
    public static let bodyFont          = Font.system(size: 12.5, weight: .regular, design: .default)
    public static let labelFont         = Font.system(size: 11.5, weight: .medium, design: .default)
    public static let captionFont       = Font.system(size: 11, weight: .regular, design: .default)
    public static let monoFont          = Font.system(size: 11.5, weight: .regular, design: .monospaced)
    public static let monoBoldFont      = Font.system(size: 11.5, weight: .semibold, design: .monospaced)
    public static let monoSmallFont     = Font.system(size: 10.5, weight: .regular, design: .monospaced)

    // Radii Scale (strictly nested: outer 8, inner 6, badge 4)
    public static let outerCornerRadius: CGFloat = 8
    public static let innerCornerRadius: CGFloat = 6
    public static let badgeCornerRadius: CGFloat = 4

    public static func signalColor(for state: VMLifecycleState) -> Color {
        switch state {
        case .running:
            return linkGreen
        case .booting, .branching, .restoringState:
            return amberAccent
        case .paused, .pausing, .savingState:
            return checkpointGold
        case .crashed:
            return dropCrimson
        case .stopped, .stopping:
            return inkMuted
        }
    }

    public static func verdictColor(for verdict: FirewallVerdict) -> Color {
        switch verdict {
        case .allow:
            return linkGreen
        case .drop, .rejectRST, .pluginBlocked:
            return dropCrimson
        case .dnsSinkhole, .rateLimited:
            return checkpointGold
        }
    }

    public static func protocolColor(for proto: DissectedProtocolKind) -> Color {
        switch proto {
        case .tls: return linkGreen
        case .dns, .dhcp: return amberAccent
        case .tcp, .ssh, .http: return vsockBlue
        case .arp, .icmp: return checkpointGold
        case .udp, .ipv4, .ethernet, .unknown: return inkSecondary
        }
    }

    public static func severityColor(for severity: DiagnosticSeverity) -> Color {
        switch severity {
        case .critical, .error: return dropCrimson
        case .warning: return amberAccent
        case .notice: return checkpointGold
        case .info: return vsockBlue
        case .trace: return inkMuted
        }
    }
}

// MARK: - Responsive Press-Feedback Button Styles (Emil Kowalski + Apple Fluid Motion)

public enum RackButtonProminence: Sendable {
    case primaryAmber
    case secondaryModule
    case subtleGhost
    case destructiveCrimson
}

public struct RackActionButtonStyle: ButtonStyle {
    public let prominence: RackButtonProminence
    public let compact: Bool

    public init(prominence: RackButtonProminence = .secondaryModule, compact: Bool = false) {
        self.prominence = prominence
        self.compact = compact
    }

    public func makeBody(configuration: Configuration) -> some View {
        RackActionButtonBody(
            configuration: configuration,
            prominence: prominence,
            compact: compact
        )
    }

    private struct RackActionButtonBody: View {
        let configuration: Configuration
        let prominence: RackButtonProminence
        let compact: Bool
        @State private var isHovered = false
        @Environment(\.isEnabled) private var isEnabled

        var body: some View {
            configuration.label
                .font(RackTheme.labelFont)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
                .foregroundStyle(foregroundColor)
                .padding(.horizontal, compact ? 8 : 11)
                .padding(.vertical, compact ? 4 : 6)
                .background(
                    RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                        .fill(backgroundColor)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: RackTheme.innerCornerRadius, style: .continuous)
                        .strokeBorder(borderColor, lineWidth: 1)
                )
                .scaleEffect(configuration.isPressed ? 0.97 : 1.0)
                .animation(.easeOut(duration: 0.12), value: configuration.isPressed)
                .opacity(isEnabled ? 1.0 : 0.45)
                .onHover { hovering in
                    isHovered = hovering
                }
        }

        private var foregroundColor: Color {
            switch prominence {
            case .primaryAmber:
                return Color(red: 0.08, green: 0.07, blue: 0.06)
            case .destructiveCrimson:
                return Color.white
            case .secondaryModule:
                return RackTheme.inkPrimary
            case .subtleGhost:
                return isHovered ? RackTheme.inkPrimary : RackTheme.inkSecondary
            }
        }

        private var backgroundColor: Color {
            switch prominence {
            case .primaryAmber:
                if configuration.isPressed { return RackTheme.amberAccent.opacity(0.85) }
                return isHovered ? Color(red: 0xE6 / 255.0, green: 0x86 / 255.0, blue: 0x32 / 255.0) : RackTheme.amberAccent
            case .destructiveCrimson:
                if configuration.isPressed { return RackTheme.dropCrimson.opacity(0.85) }
                return isHovered ? RackTheme.dropCrimson.opacity(0.92) : RackTheme.dropCrimson
            case .secondaryModule:
                if configuration.isPressed { return RackTheme.bladeRecessed }
                return isHovered ? RackTheme.moduleElevated : RackTheme.moduleSurface
            case .subtleGhost:
                if configuration.isPressed { return RackTheme.moduleSurface }
                return isHovered ? RackTheme.moduleSurface.opacity(0.7) : Color.clear
            }
        }

        private var borderColor: Color {
            switch prominence {
            case .primaryAmber:
                return Color.white.opacity(0.18)
            case .destructiveCrimson:
                return Color.white.opacity(0.16)
            case .secondaryModule:
                return isHovered ? RackTheme.hairlineStrong : RackTheme.hairline
            case .subtleGhost:
                return isHovered ? RackTheme.hairline : Color.clear
            }
        }
    }
}

// MARK: - Reusable Industrial Surface & Telemetry Components

public struct RackPanelContainer<HeaderContent: View, BodyContent: View>: View {
    private let title: String
    private let subtitle: String?
    private let symbolName: String?
    private let headerTrailing: HeaderContent
    private let content: BodyContent

    public init(
        title: String,
        subtitle: String? = nil,
        symbolName: String? = nil,
        @ViewBuilder headerTrailing: () -> HeaderContent,
        @ViewBuilder content: () -> BodyContent
    ) {
        self.title = title
        self.subtitle = subtitle
        self.symbolName = symbolName
        self.headerTrailing = headerTrailing()
        self.content = content()
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 8) {
                if let symbolName {
                    Image(systemName: symbolName)
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(RackTheme.amberAccent)
                }
                Text(title)
                    .font(RackTheme.sectionHeaderFont)
                    .foregroundStyle(RackTheme.inkPrimary)
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)

                if let subtitle, !subtitle.isEmpty {
                    Text(subtitle)
                        .font(RackTheme.captionFont)
                        .foregroundStyle(RackTheme.inkMuted)
                        .lineLimit(1)
                }
                Spacer(minLength: 8)
                headerTrailing
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 9)
            .background(RackTheme.moduleElevated.opacity(0.55))

            Rectangle()
                .fill(RackTheme.hairline)
                .frame(height: 1)

            content
        }
        .background(
            RoundedRectangle(cornerRadius: RackTheme.outerCornerRadius, style: .continuous)
                .fill(RackTheme.moduleSurface)
        )
        .overlay(
            RoundedRectangle(cornerRadius: RackTheme.outerCornerRadius, style: .continuous)
                .strokeBorder(RackTheme.hairline, lineWidth: 1)
        )
    }
}

extension RackPanelContainer where HeaderContent == EmptyView {
    public init(
        title: String,
        subtitle: String? = nil,
        symbolName: String? = nil,
        @ViewBuilder content: () -> BodyContent
    ) {
        self.init(
            title: title,
            subtitle: subtitle,
            symbolName: symbolName,
            headerTrailing: { EmptyView() },
            content: content
        )
    }
}

public struct RackStatusPill: View {
    public let label: String
    public let color: Color
    public let monospaced: Bool

    public init(label: String, color: Color, monospaced: Bool = false) {
        self.label = label
        self.color = color
        self.monospaced = monospaced
    }

    public var body: some View {
        HStack(spacing: 5) {
            Circle()
                .fill(color)
                .frame(width: 6, height: 6)
            Text(label)
                .font(monospaced ? RackTheme.monoSmallFont : RackTheme.captionFont)
                .fontWeight(.medium)
                .foregroundStyle(color)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
        }
        .padding(.horizontal, 7)
        .padding(.vertical, 3)
        .background(
            RoundedRectangle(cornerRadius: RackTheme.badgeCornerRadius, style: .continuous)
                .fill(color.opacity(0.14))
        )
        .overlay(
            RoundedRectangle(cornerRadius: RackTheme.badgeCornerRadius, style: .continuous)
                .strokeBorder(color.opacity(0.32), lineWidth: 1)
        )
    }
}

public struct RackMetricTile: View {
    public let label: String
    public let value: String
    public let detail: String
    public let accent: Color

    public init(label: String, value: String, detail: String, accent: Color = RackTheme.amberAccent) {
        self.label = label
        self.value = value
        self.detail = detail
        self.accent = accent
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 6) {
                RoundedRectangle(cornerRadius: 1.5)
                    .fill(accent)
                    .frame(width: 3, height: 12)
                Text(label)
                    .font(RackTheme.labelFont)
                    .foregroundStyle(RackTheme.inkSecondary)
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)
                Spacer(minLength: 0)
            }
            Text(value)
                .font(.system(size: 19, weight: .semibold, design: .monospaced))
                .monospacedDigit()
                .foregroundStyle(RackTheme.inkPrimary)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
            Text(detail)
                .font(RackTheme.captionFont)
                .foregroundStyle(RackTheme.inkMuted)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: RackTheme.outerCornerRadius, style: .continuous)
                .fill(RackTheme.moduleSurface)
        )
        .overlay(
            RoundedRectangle(cornerRadius: RackTheme.outerCornerRadius, style: .continuous)
                .strokeBorder(RackTheme.hairline, lineWidth: 1)
        )
    }
}

public struct RackKeyCapBadge: View {
    public let shortcut: String

    public init(_ shortcut: String) {
        self.shortcut = shortcut
    }

    public var body: some View {
        Text(shortcut)
            .font(RackTheme.monoSmallFont)
            .foregroundStyle(RackTheme.inkSecondary)
            .lineLimit(1)
            .fixedSize(horizontal: true, vertical: false)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(
                RoundedRectangle(cornerRadius: RackTheme.badgeCornerRadius, style: .continuous)
                    .fill(RackTheme.bladeRecessed)
            )
            .overlay(
                RoundedRectangle(cornerRadius: RackTheme.badgeCornerRadius, style: .continuous)
                    .strokeBorder(RackTheme.hairlineStrong, lineWidth: 1)
            )
    }
}
