// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AppSweep",
    platforms: [
        .macOS(.v12)
    ],
    products: [
        .executable(name: "app-sweep", targets: ["AppSweepCLI"]),
        .executable(name: "AppSweepApp", targets: ["AppSweepApp"])
    ],
    targets: [
        .executableTarget(
            name: "AppSweepCLI",
            path: "Sources/AppSweepCLI"
        ),
        .executableTarget(
            name: "AppSweepApp",
            path: "Sources/AppSweepApp"
        )
    ]
)
