import Foundation
import Darwin
@testable import AppSweepCore

@MainActor func runningScanChecks() async throws {
    let f = try OwnedFixture(), engine = try f.engine(rules: [DarwinCacheRule.name])
    let infoPath = f.app + "/Contents/Info.plist"
    var info = try PropertyListSerialization.propertyList(from: Data(contentsOf: URL(fileURLWithPath: infoPath)), format: nil) as! [String: Any]
    info["CrProductDirName"] = "Owned Browser"
    try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: URL(fileURLWithPath: infoPath))
    let profile = f.home + "/Library/Application Support/Owned Browser"
    try fm.createDirectory(atPath: profile, withIntermediateDirectories: false)
    let darwin = f.home + "/DarwinCache/" + f.identifier
    try fm.createDirectory(atPath: darwin, withIntermediateDirectories: false)
    let component = f.app + "/Contents/Library/LoginItems/Worker.app/Contents"
    try fm.createDirectory(atPath: component, withIntermediateDirectories: true)
    try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier": f.identifier + ".worker", "CFBundlePackageType": "APPL", "CFBundleExecutable": "worker"], format: .xml, options: 0).write(to: URL(fileURLWithPath: component + "/Info.plist"))
    let componentCache = f.home + "/Library/Caches/" + f.identifier + ".worker"
    try fm.createDirectory(atPath: componentCache, withIntermediateDirectories: true)
    let process = Process()
    process.executableURL = URL(fileURLWithPath: f.binary); process.arguments = ["30"]
    try process.run()
    defer { if process.isRunning { process.terminate(); process.waitUntilExit() } }
    // The running body must be retained before any recursive snapshot encounters
    // this special file. It is never read; it lives only in this owned sample.
    let pipe = f.app + "/Contents/Resources/must-not-inspect"
    try check(mkfifo(pipe, 0o600) == 0, "Owned FIFO creation failed")
    let report = try await engine.scanApplication(f.app)
    guard let body = report.candidates.first(where: { $0.path == f.app }) else { throw CheckFailure("Running body disappeared") }
    try check(!body.allowed && body.identity == nil, "Running app should not need a recursive snapshot")
    try check(body.retentionReason?.contains("请先彻底关闭") == true, "Running-state refusal must precede deep tree work: " + (body.retentionReason ?? "none"))
    try check(report.candidates.contains(where: { $0.path == profile && !$0.allowed && $0.identity == nil }), "Unverified namespace must remain a cheap retained discovery hint")
    for path in [darwin, componentCache] {
        try check(report.candidates.contains(where: { $0.path == path && !$0.allowed && $0.identity == nil }), "Running app lost retained discovery: " + path)
    }
    try check(process.isRunning, "Scan must not stop the running app")
    process.terminate(); process.waitUntilExit()
    let stopped = try await engine.scanApplication(f.app)
    try check(!stopped.candidates.contains(where: { $0.path == f.app && $0.allowed }), "Stopped status cannot authorize an unsafe body")
    print("PASS running-state refusal precedes deep scan; after exit unsafe structure stays blocked")
    try f.finish()
}
