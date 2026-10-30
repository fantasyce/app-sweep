#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

final class FirefoxNativeTests: XCTestCase, @unchecked Sendable {
    func testOfficialFirefoxCacheRestoresAndRegeneratesWithoutMovingPersistentData() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_FIREFOX_ACCEPTANCE"] == "1",
              try BoundedProcess.run("/usr/sbin/sysctl", arguments: ["-n", "hw.model"], timeout: 3).hasPrefix("VirtualMac") else {
            throw XCTSkip("Requires the explicitly prepared disposable Firefox VM")
        }
        let rule = ProcessInfo.processInfo.environment["APP_SWEEP_FIREFOX_FORMAT"] == "4" ? FirefoxFormatRule.name : FirefoxRule.name
        let profileName = ProcessInfo.processInfo.environment["APP_SWEEP_FIREFOX_PROFILE"]
        if let profileName { guard !profileName.isEmpty, profileName.count <= 64, profileName.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [45,95].contains($0) }) else { throw SweepError.invalid("Invalid disposable profile name") } }
        let home = try SystemIdentity.home()
        for component in try AppInspector.inventory(home:home) where component.bundleIdentifier.isEmpty || component.bundleIdentifier.lowercased().hasPrefix("org.mozilla.") { print("Native inventory: \(component.path): \(component.bundleIdentifier): \(component.protectedReason ?? "installed")") }
        let task = home + "/AppSweepAcceptance"
        let app = home + "/Applications/Firefox.app"
        let fm = FileManager.default
        let engine = SweepEngine(policy: SafetyPolicy(home: home, acceptedPlatform: true, validatedRules: [rule]), vaultPath: home + "/Library/Application Support/App Sweep/Recovery", fixture: false)
        // A previous interrupted acceptance attempt is recovered through the same
        // product API; no fixture driver deletes or rewrites the journal.
        for batch in try await engine.recoveryBatches() where batch.status == .needsAttention && batch.entries.allSatisfy({ $0.original.rule == rule }) {
            try preserveRegeneratedConflict(batch, home: home, app: app, task: task)
            try await waitForObjects(batch, home: home)
            let recovered = try await restoreWhenUnused(batch, engine: engine, home: home)
            guard recovered.status == .restored else { XCTFail(recovered.entries.compactMap(\.message).joined(separator: "\n")); return }
        }
        let report = try await engine.scanJunk()
        XCTAssertTrue(report.complete, report.issues.joined(separator: "\n"))
        let inspected = try AppInspector.inspect(app)
        let item = try XCTUnwrap(report.candidates.first { $0.rule == rule && $0.allowed }, report.candidates.map { $0.path + ": " + ($0.retentionReason ?? "eligible") }.joined(separator: "\n") + "\nApp: " + String(describing: inspected))
        let leaf = try XCTUnwrap(FirefoxRule.cacheLeaf(item.path, home: home))
        let profile = home + "/Library/Application Support/Firefox/Profiles/" + leaf
        let persistent = try ["places.sqlite", "key4.db", "prefs.js"].map { ($0, try Data(contentsOf: URL(fileURLWithPath: profile + "/" + $0))) }
        let original = try SafeFilesystem.snapshot(item.path)
        XCTAssertTrue(original.tree.contains { $0.relative.hasPrefix("entries/") && $0.identity.size > 0 })
        let plan = try await engine.makePlan(reportID: report.id, selected: [item.id], includeUserData: false)
        let moved = try await engine.execute(planID: plan.id)
        XCTAssertEqual(moved.status, .isolated, moved.issue ?? "")
        XCTAssertFalse(fm.fileExists(atPath: item.path))
        for (name, data) in persistent { XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: profile + "/" + name)), data) }
        try await waitForObjects(moved, home: home)
        let restored = try await restoreWhenUnused(moved, engine: engine, home: home)
        guard restored.status == .restored else { XCTFail(restored.entries.compactMap(\.message).joined(separator: "\n")); return }
        XCTAssertEqual(try SafeFilesystem.snapshot(item.path).tree, original.tree)
        for (name, data) in persistent { XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: profile + "/" + name)), data) }
        let secondReport = try await engine.scanJunk()
        let second = try XCTUnwrap(secondReport.candidates.first { $0.path == item.path && $0.allowed })
        let secondPlan = try await engine.makePlan(reportID: secondReport.id, selected: [second.id], includeUserData: false)
        let secondMoved = try await engine.execute(planID: secondPlan.id)
        XCTAssertEqual(secondMoved.status, .isolated, secondMoved.issue ?? "")
        let screenshot = task + "/output/firefox-regenerated-" + (profileName ?? "default") + ".png"
        let run = try BoundedProcess.capture(app + "/Contents/MacOS/firefox", arguments: (profileName.map { ["-P", $0] } ?? []) + ["-headless", "--screenshot", screenshot, "--window-size", "800,600", "http://127.0.0.1:18744/"], timeout: 30, mergeStderr: true)
        XCTAssertEqual(run.status, 0, run.text)
        XCTAssertTrue(fm.fileExists(atPath: screenshot))
        let regenerated = try SafeFilesystem.snapshot(item.path)
        XCTAssertTrue(regenerated.tree.contains { $0.relative.hasPrefix("entries/") && $0.identity.size > 0 })
        XCTAssertNotEqual(regenerated.identity.inode, original.identity.inode)
        for (name, _) in persistent { XCTAssertTrue(fm.fileExists(atPath: profile + "/" + name)) }
        let conflict = try await engine.restore(batchID: secondMoved.id)
        XCTAssertEqual(conflict.status, .needsAttention)
        XCTAssertEqual(try SafeFilesystem.snapshot(item.path).tree, regenerated.tree)
        // Explicit test-driver handling of the known generated fixture, after
        // verifying the product refused to overwrite it. Production never does this.
        try preserveRegeneratedConflict(conflict, home: home, app: app, task: task)
        try await waitForObjects(conflict, home: home)
        let finalRestore = try await restoreWhenUnused(conflict, engine: engine, home: home)
        XCTAssertEqual(finalRestore.status, .restored, finalRestore.entries.compactMap(\.message).joined(separator: "\n"))
    }
    private func restoreWhenUnused(_ batch: RecoveryManifest, engine: SweepEngine, home: String) async throws -> RecoveryManifest {
        var result = batch
        for _ in 0..<8 {
            try await waitForObjects(result, home: home)
            result = try await engine.restore(batchID: batch.id)
            if result.status == .restored { return result }
            // An indexer may start between the harness check and the core's check.
            // Retry only that observed busy condition through the regular recovery API.
            guard result.entries.compactMap(\.message).contains(where: { $0.contains("文件占用状态未确认") || $0.contains("文件仍被进程使用") }) else { return result }
            try await Task.sleep(nanoseconds: 500_000_000)
        }
        return result
    }
    private func preserveRegeneratedConflict(_ batch: RecoveryManifest, home: String, app: String, task: String) throws {
        let destination = try SafeDirectory(path: task + "/fixtures").privateChild("firefox-regenerated")
        for entry in batch.entries where entry.state == .conflict {
            guard try SafeFilesystem.presence(entry.original.path) else { continue }
            if entry.original.rule == FirefoxFormatRule.name { try FirefoxFormatRule.verify(entry.original.path, home: home, applicationPath: app) }
            else { try FirefoxRule.verify(entry.original.path, home: home, applicationPath: app) }
            let snapshot = try SafeFilesystem.snapshot(entry.original.path)
            try BusyInspector.ensureUnused(snapshot)
            try SafeFilesystem.move(snapshot, into: destination, name: UUID().uuidString)
        }
    }
    private func waitForObjects(_ batch: RecoveryManifest, home: String) async throws {
        for entry in batch.entries where entry.state != .restored && entry.state != .purged {
            let path = home + "/Library/Application Support/App Sweep/Recovery/" + batch.id.uuidString + "/" + batch.objectsDirectory + "/" + entry.id.uuidString
            var last: Error = SweepError.incomplete("Owned cache remains occupied")
            for attempt in 0..<40 {
                do { try BusyInspector.ensureUnused(SafeFilesystem.snapshot(path)); break }
                catch { last = error; if attempt == 39 { throw last }; try await Task.sleep(nanoseconds: 250_000_000) }
            }
        }
    }
}
#endif
