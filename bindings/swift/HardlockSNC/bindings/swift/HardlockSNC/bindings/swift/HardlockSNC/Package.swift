import PackageDescription

let package = Package(
    name: "HardlockSNC",
    platforms: [
        .iOS(.v13), .macOS(.v11)
    ],
    products: [
        .library(name: "HardlockSNC", targets: ["HardlockSNC"])
    ],
    targets: [
        .target(
            name: "CHardlockSNC",
            publicHeadersPath: "."
        ),
        .target(
            name: "HardlockSNC",
            dependencies: ["CHardlockSNC"]
        )
    ]
)
