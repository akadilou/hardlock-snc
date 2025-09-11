// swift-tools-version: 5.9
import PackageDescription
let package = Package(
    name: "HardlockSNC",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "HardlockSNC", targets: ["HardlockSNC"])
    ],
    targets: [
        .systemLibrary(name: "CHardlockSNC"),
        .target(name: "HardlockSNC", dependencies: ["CHardlockSNC"])
    ]
)
