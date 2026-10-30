import Foundation
import Darwin
@testable import AppSweepCore

@MainActor func genericStorageChecks() async throws {
    let f = try OwnedFixture(), rule = "application-web-data-v1"
    let http = f.home + "/Library/HTTPStorages/" + f.identifier
    let web = f.home + "/Library/WebKit/" + f.identifier
    let cookie = http + ".binarycookies"
    let expected = [http, web, cookie]
    for path in [http, web, http + ".other", f.home + "/Library/WebKit/Other App",
                 f.home + "/Library/Application Support/Codex/Default/chrome_cart_db",
                 f.home + "/.codex/packages", f.home + "/.cmake/packages"] {
        try fm.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try Data("owned test data".utf8).write(to: URL(fileURLWithPath: path + "/record"))
    }
    try Data("cook-owned-test-cookie".utf8).write(to: URL(fileURLWithPath: cookie))
    let before = try expected.map { try SafeFilesystem.snapshot($0) }
    let engine = try f.engine(rules: [rule])
    var report = try await settledApplication(engine, app: f.app)
    let data = report.candidates.filter { $0.rule == rule && $0.executionAllowed }
    try check(Set(data.map(\.path)) == Set(expected), "Exact HTTPStorages/WebKit data missing or overbroad")
    try check(data.allSatisfy { $0.userData && !$0.selectedByDefault }, "Web data must require user-data opt-in")
    try check(!report.selectableCandidates(includeUserData: false).contains { expected.contains($0.path) }, "Default selection included login or website data")
    print("PASS generic exact web data discovered for arbitrary signed app; default keeps user data")
    let body = try selectedBody(report, app: f.app)
    let ids = Set(data.map(\.id) + [body.id])
    do {
        _ = try await engine.makePlan(reportID: report.id, selected: ids, includeUserData: false)
        throw CheckFailure("Web data plan accepted without opt-in")
    } catch let error as CheckFailure { throw error }
    catch { print("PASS web data cannot bypass explicit opt-in") }
    let plan = try await engine.makePlan(reportID: report.id, selected: ids, includeUserData: true)
    let batch = try await engine.execute(planID: plan.id)
    try check(batch.status == .isolated, "Web data isolation failed: " + (batch.issue ?? ""))
    try check(expected.allSatisfy { !fm.fileExists(atPath: $0) }, "Web data was not isolated")
    // A regenerated original must survive recovery without an overwrite.
    try fm.createDirectory(atPath: web, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    try Data("new user data".utf8).write(to: URL(fileURLWithPath: web + "/new"))
    let conflict = try await f.engine(rules: [rule]).restore(batchID: batch.id)
    try check(conflict.status != .restored, "Recovery overwrote a regenerated web data directory")
    try check(String(contentsOfFile: web + "/new", encoding: .utf8) == "new user data", "Recovery changed the conflict")
    try fm.moveItem(atPath: web, toPath: f.home + "/preserved-regenerated-web-data")
    let restored = try await f.engine(rules: [rule]).restore(batchID: batch.id)
    try check(restored.status == .restored, "Web data retry restore failed: " + restored.entries.compactMap(\.message).joined(separator: "; "))
    for (index, path) in expected.enumerated() {
        let after = try SafeFilesystem.snapshot(path)
        try check(after.identity.inode == before[index].identity.inode && after.tree == before[index].tree, "Recovery changed original web data")
    }
    print("PASS full application/web data isolation and fresh-engine conflict-safe restore")
    let duplicate = f.home + "/Applications/Duplicate.app"
    try fm.copyItem(atPath: f.app, toPath: duplicate)
    report = try await engine.scanApplication(f.app)
    try check(!report.candidates.contains { $0.rule == rule && $0.executionAllowed }, "Duplicate owner authorized web data")
    try fm.removeItem(atPath: duplicate)
    let outside = f.home + "/outside"
    try Data("untouched".utf8).write(to: URL(fileURLWithPath: outside))
    try fm.createSymbolicLink(atPath: web + "/escape", withDestinationPath: outside)
    report = try await engine.scanApplication(f.app)
    try check(!report.candidates.contains { $0.path == web && $0.executionAllowed }, "Web data followed an external link")
    try check(String(contentsOfFile: outside, encoding: .utf8) == "untouched", "External data changed")
    try fm.removeItem(atPath: web + "/escape")
    try check(chmod(f.home + "/Library/WebKit", 0o777) == 0, "Cannot set fixture shared ancestor")
    report = try await engine.scanApplication(f.app)
    try check(!report.candidates.contains { $0.path == web && $0.executionAllowed }, "Shared ancestor authorized web data")
    try check(chmod(f.home + "/Library/WebKit", 0o700) == 0, "Cannot restore fixture ancestor permissions")
    print("PASS duplicate owner, symlink and shared ancestor block web data")
    try check(chmod(web, 0o777) == 0, "Cannot share fixture web root")
    try reject("shared web data root retained") { try ApplicationStorageRule.verify(path: web, home: f.home, identifier: f.identifier) }
    try check(chmod(web, 0o700) == 0, "Cannot restore fixture web root")
    try check(chmod(web + "/record", 0o666) == 0, "Cannot share fixture web file")
    try reject("shared web data child retained") { try ApplicationStorageRule.verify(path: web, home: f.home, identifier: f.identifier) }
    try check(chmod(web + "/record", 0o644) == 0, "Cannot restore fixture web file")
    let policy = SafetyPolicy(home: f.home, acceptedPlatform: true, validatedRules: [rule])
    for path in [f.home + "/Library/WebKit", f.home + "/Library/HTTPStorages", f.home + "/Library/WebKit/com.apple.Safari", "/private/var/folders/cache"] {
        try check(policy.denial(path: path, category: .userData, rule: rule) != nil, "Forged web path accepted")
    }
    try check(policy.denial(path: web, category: .cache, rule: rule) != nil, "Web user data classified as cache")
    print("PASS forged web rules and user-data category substitution rejected")
    let process = Process()
    process.executableURL = URL(fileURLWithPath: f.binary)
    process.arguments = ["20"]
    try process.run()
    do {
        report = try await engine.scanApplication(f.app)
        try check(!report.candidates.contains { $0.rule == rule && $0.executionAllowed }, "Running app authorized web data")
    } catch {
        if process.isRunning { process.terminate() }
        throw error
    }
    if process.isRunning { process.terminate() }
    let deadline = Date().addingTimeInterval(5)
    while process.isRunning && Date() < deadline { try await Task.sleep(nanoseconds: 50_000_000) }
    try check(!process.isRunning, "Owned activity fixture did not exit")
    print("PASS running application blocks its exact web data")
    try f.finish()
}
