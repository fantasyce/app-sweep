// swift-tools-version: 6.0
import PackageDescription
var products: [Product] = [.library(name: "AppSweepCore", targets: ["AppSweepCore"]), .executable(name: "app-sweep", targets: ["AppSweepCLI"])]
var targets: [Target] = [
    .target(name: "CFSafety", linkerSettings: [.linkedLibrary("bsm", .when(platforms: [.macOS]))]),
    .target(name: "AppSweepCore", dependencies: ["CFSafety"]),
    .executableTarget(name: "AppSweepCLI", dependencies: ["AppSweepCore"], swiftSettings: [.unsafeFlags(["-parse-as-library"])]),
    .testTarget(name: "AppSweepCoreTests", dependencies: ["AppSweepCore", "AppSweepCLI"], resources: [.copy("Fixtures")])
]
#if os(macOS)
products.append(.executable(name: "AppSweepApp", targets: ["AppSweepApp"]))
products.append(.executable(name: "AppSweepSystemService", targets: ["AppSweepSystemService"]))
products.append(.executable(name: "AppSweepServiceInstaller", targets: ["AppSweepServiceInstaller"]))
targets.append(.executableTarget(name: "AppSweepSystemService", dependencies: ["AppSweepCore"]))
targets.append(.executableTarget(name: "AppSweepServiceInstaller", dependencies: ["AppSweepCore"]))
targets.append(.executableTarget(name: "AppSweepApp", dependencies: ["AppSweepCore"], path: "Sources/AppSweepAppV2", resources: [.copy("Resources")]))
targets.first { $0.name == "AppSweepCoreTests" }?.dependencies.append(.target(name: "AppSweepApp"))
#endif
let package = Package(name: "AppSweep", platforms: [.macOS(.v12)], products: products, targets: targets)
