// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AgentVM",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(name: "AgentVMModels", targets: ["AgentVMModels"]),
        .library(name: "AgentVMStore", targets: ["AgentVMStore"]),
        .library(name: "AgentVMStorageCoW", targets: ["AgentVMStorageCoW"]),
        .library(name: "AgentVMNetSwitch", targets: ["AgentVMNetSwitch"]),
        .library(name: "AgentVMVsockRPC", targets: ["AgentVMVsockRPC"]),
        .library(name: "AgentVMHypervisor", targets: ["AgentVMHypervisor"]),
        .library(name: "AgentVMPluginHost", targets: ["AgentVMPluginHost"]),
        .library(name: "AgentVMCLIAndMCP", targets: ["AgentVMCLIAndMCP"]),
        .library(name: "AgentVMWorkbenchShell", targets: ["AgentVMWorkbenchShell"]),
        .library(name: "AgentVMStudioViews", targets: ["AgentVMStudioViews"]),
        .executable(name: "AgentVM", targets: ["AgentVM"])
    ],
    targets: [
        .target(
            name: "AgentVMModels",
            dependencies: []
        ),
        .target(
            name: "AgentVMStore",
            dependencies: ["AgentVMModels"],
            linkerSettings: [
                .linkedLibrary("sqlite3")
            ]
        ),
        .target(
            name: "AgentVMStorageCoW",
            dependencies: ["AgentVMModels"],
            linkerSettings: [
                .linkedLibrary("z")
            ]
        ),
        .target(
            name: "AgentVMNetSwitch",
            dependencies: ["AgentVMModels"]
        ),
        .target(
            name: "AgentVMVsockRPC",
            dependencies: ["AgentVMModels"],
            linkerSettings: [
                .linkedLibrary("z")
            ]
        ),
        .target(
            name: "AgentVMPluginHost",
            dependencies: [
                "AgentVMModels",
                "AgentVMStore",
                "AgentVMNetSwitch"
            ],
            linkerSettings: [
                .linkedFramework("JavaScriptCore")
            ]
        ),
        .target(
            name: "AgentVMHypervisor",
            dependencies: [
                "AgentVMModels",
                "AgentVMStore",
                "AgentVMStorageCoW",
                "AgentVMNetSwitch",
                "AgentVMVsockRPC",
                "AgentVMPluginHost"
            ],
            linkerSettings: [
                .linkedFramework("Virtualization")
            ]
        ),
        .target(
            name: "AgentVMCLIAndMCP",
            dependencies: [
                "AgentVMModels",
                "AgentVMStore",
                "AgentVMStorageCoW",
                "AgentVMNetSwitch",
                "AgentVMVsockRPC",
                "AgentVMHypervisor",
                "AgentVMPluginHost"
            ]
        ),
        .target(
            name: "AgentVMWorkbenchShell",
            dependencies: [
                "AgentVMModels",
                "AgentVMStore",
                "AgentVMPluginHost"
            ],
            linkerSettings: [
                .linkedFramework("AppKit"),
                .linkedFramework("SwiftUI")
            ]
        ),
        .target(
            name: "AgentVMStudioViews",
            dependencies: [
                "AgentVMModels",
                "AgentVMStore",
                "AgentVMStorageCoW",
                "AgentVMNetSwitch",
                "AgentVMVsockRPC",
                "AgentVMHypervisor",
                "AgentVMPluginHost",
                "AgentVMCLIAndMCP",
                "AgentVMWorkbenchShell"
            ],
            linkerSettings: [
                .linkedFramework("AppKit"),
                .linkedFramework("SwiftUI")
            ]
        ),
        .executableTarget(
            name: "AgentVM",
            dependencies: [
                "AgentVMModels",
                "AgentVMStore",
                "AgentVMStorageCoW",
                "AgentVMNetSwitch",
                "AgentVMVsockRPC",
                "AgentVMHypervisor",
                "AgentVMPluginHost",
                "AgentVMCLIAndMCP",
                "AgentVMWorkbenchShell",
                "AgentVMStudioViews"
            ]
        ),
        .testTarget(
            name: "AgentVMTests",
            dependencies: [
                "AgentVMModels",
                "AgentVMStore",
                "AgentVMStorageCoW",
                "AgentVMNetSwitch",
                "AgentVMVsockRPC",
                "AgentVMHypervisor",
                "AgentVMPluginHost",
                "AgentVMCLIAndMCP",
                "AgentVMWorkbenchShell"
            ]
        )
    ]
)
