import AppKit
import CoreGraphics
import Foundation

let outPath = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "AppIcon.png"
let size = 1024
let colorSpace = CGColorSpaceCreateDeviceRGB()
guard let ctx = CGContext(
    data: nil,
    width: size,
    height: size,
    bitsPerComponent: 8,
    bytesPerRow: 0,
    space: colorSpace,
    bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
) else {
    fatalError("Failed to allocate icon context")
}

// Industrial Rack Graphite chassis rounded squircle
let rect = CGRect(x: 56, y: 56, width: 912, height: 912)
let chassisPath = CGPath(roundedRect: rect, cornerWidth: 210, cornerHeight: 210, transform: nil)
ctx.addPath(chassisPath)
ctx.setFillColor(CGColor(red: 0.082, green: 0.088, blue: 0.102, alpha: 1.0))
ctx.fillPath()

ctx.addPath(chassisPath)
ctx.setStrokeColor(CGColor(red: 0.22, green: 0.24, blue: 0.28, alpha: 1.0))
ctx.setLineWidth(14)
ctx.strokePath()

// Three stacked hypervisor blade slots
for idx in 0..<3 {
    let slotY = CGFloat(610 - idx * 195)
    let blade = CGRect(x: 152, y: slotY, width: 720, height: 146)
    let bladePath = CGPath(roundedRect: blade, cornerWidth: 32, cornerHeight: 32, transform: nil)
    ctx.addPath(bladePath)
    ctx.setFillColor(CGColor(red: 0.125, green: 0.137, blue: 0.161, alpha: 1.0))
    ctx.fillPath()
    ctx.addPath(bladePath)
    ctx.setStrokeColor(CGColor(red: 0.19, green: 0.21, blue: 0.25, alpha: 1.0))
    ctx.setLineWidth(6)
    ctx.strokePath()

    // Status LED (Amber on primary parent blade, Green on CoW child blades)
    let ledRect = CGRect(x: 204, y: slotY + 51, width: 44, height: 44)
    ctx.fillEllipse(in: ledRect)
    if idx == 0 {
        ctx.setFillColor(CGColor(red: 0.851, green: 0.467, blue: 0.141, alpha: 1.0))
    } else {
        ctx.setFillColor(CGColor(red: 0.165, green: 0.616, blue: 0.435, alpha: 1.0))
    }
    ctx.fillEllipse(in: ledRect)

    // Telemetry bars
    for bar in 0..<4 {
        let bx = CGFloat(296 + bar * 124)
        let bw: CGFloat = bar == 3 ? 92 : 104
        let barRect = CGRect(x: bx, y: slotY + 57, width: bw, height: 32)
        let bp = CGPath(roundedRect: barRect, cornerWidth: 8, cornerHeight: 8, transform: nil)
        ctx.addPath(bp)
        let alpha: CGFloat = (idx == 0 && bar < 3) ? 0.88 : 0.42
        ctx.setFillColor(CGColor(red: 0.851, green: 0.467, blue: 0.141, alpha: alpha))
        ctx.fillPath()
    }
}

// CoW Branching Spine line connecting blade 0 -> 1 -> 2
ctx.setStrokeColor(CGColor(red: 0.851, green: 0.467, blue: 0.141, alpha: 0.95))
ctx.setLineWidth(12)
ctx.move(to: CGPoint(x: 226, y: 661))
ctx.addLine(to: CGPoint(x: 226, y: 266))
ctx.strokePath()

guard let cgImage = ctx.makeImage() else { fatalError("Failed to render icon") }
let rep = NSBitmapImageRep(cgImage: cgImage)
guard let pngData = rep.representation(using: .png, properties: [:]) else {
    fatalError("Failed to encode PNG")
}
try pngData.write(to: URL(fileURLWithPath: outPath))
