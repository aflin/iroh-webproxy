// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "irohWebProxy",
    platforms: [
        .macOS(.v11)
    ],
    targets: [
        .executableTarget(
            name: "irohWebProxy",
            path: "Sources/irohWebProxy",
            linkerSettings: [
                .linkedFramework("AppKit"),
                .linkedFramework("ServiceManagement"),
            ]
        )
    ]
)
