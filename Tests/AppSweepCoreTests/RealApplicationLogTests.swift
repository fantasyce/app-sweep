#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

final class RealApplicationLogTests: XCTestCase, @unchecked Sendable {
    func testOfficialFirefoxLogsRestoreAndContinueGenerating() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_REAL_LOG_ACCEPTANCE"] == "1",
              try BoundedProcess.run("/usr/sbin/sysctl", arguments: ["-n", "hw.model"], timeout: 3).hasPrefix("VirtualMac") else { throw XCTSkip("Explicit disposable VM log acceptance required") }
        let home = try SystemIdentity.home(), fm = FileManager.default
        let task = home + "/AppSweepAcceptanceGeneral-20261016", id = UUID().uuidString
        let app = home + "/Applications/Firefox.app", identifier = "org.mozilla.firefox"
        let owned = task + "/log-consumer.noindex/" + id
        let logs = ApplicationLogRule.root(home: home, identifier: identifier) + "/appsweep-" + id
        guard !fm.fileExists(atPath: owned), !fm.fileExists(atPath: logs) else { throw SweepError.denied("Owned consumer path already exists") }
        let appBefore = try AppInspector.inspect(app)
        guard appBefore.signed, AppInspector.signedByTeam(path: app, team: "43AQ936H96") else { throw SweepError.denied("Official Firefox signature required") }
        try ActivityInspector.ensureStopped(bundleID: identifier, applicationPath: app)
        try fm.createDirectory(atPath: owned + "/profile", withIntermediateDirectories: true)
        try fm.createDirectory(atPath: logs, withIntermediateDirectories: true)
        try Data("AppSweep disposable Firefox log consumer\n".utf8).write(to: URL(fileURLWithPath: owned + "/ownership.txt"))
        try Data("<html><body>App Sweep local log fixture</body></html>".utf8).write(to: URL(fileURLWithPath: owned + "/page.html"))
        func run(_ name: String) throws {
            let result = try BoundedProcess.capture(app + "/Contents/MacOS/firefox", arguments: ["-no-remote", "-profile", owned + "/profile", "-headless", "--screenshot", owned + "/" + name + ".png", "-MOZ_LOG=timestamp,sync,nsDocShell:5,nsHttp:5", "-MOZ_LOG_FILE=" + logs + "/" + name, URL(fileURLWithPath: owned + "/page.html").absoluteString], timeout: 30, mergeStderr: true)
            guard result.status == 0, fm.fileExists(atPath: owned + "/" + name + ".png") else { throw SweepError.incomplete("Official log consumer failed: " + result.text) }
            try ActivityInspector.ensureStopped(bundleID: identifier, applicationPath: app)
        }
        try run("before")
        let snapshot = try SafeFilesystem.snapshot(logs)
        let files = snapshot.tree.filter { !$0.identity.isDirectory && $0.identity.size > 0 && ApplicationLogRule.matches(path: logs + "/" + $0.relative, home: home, identifier: identifier) }
        XCTAssertFalse(files.isEmpty, "The official application must generate actual log bytes")
        guard !files.isEmpty else { return }
        var contents: [String: Data] = [:]
        for file in files {
            let path = logs + "/" + file.relative
            contents[path] = try Data(contentsOf: URL(fileURLWithPath: path))
            try fm.setAttributes([.modificationDate: Date().addingTimeInterval(-31 * 86400)], ofItemAtPath: path)
        }
        let engine = ProcessInfo.processInfo.environment["APP_SWEEP_PUBLIC_LOG_ACCEPTANCE"] == "1" ? SweepEngine() : SweepEngine(policy: SafetyPolicy(home: home, acceptedPlatform: true, validatedRules: [ApplicationLogRule.name]), vaultPath: home + "/Library/Application Support/App Sweep/Recovery", fixture: false)
        let report = try await engine.scanJunk()
        let selected = report.selectableCandidates(includeUserData: false).filter { contents[$0.path] != nil && [ApplicationLogRule.name,ApplicationLogRule.currentName].contains($0.rule) }
        XCTAssertEqual(Set(selected.map(\.path)), Set(contents.keys), report.unconfirmedIssues.joined(separator: "; "))
        guard selected.count == files.count else { return }
        let plan = try await engine.makePlan(reportID: report.id, selected: Set(selected.map(\.id)), includeUserData: false)
        let batch = try await engine.execute(planID: plan.id)
        XCTAssertEqual(batch.status, .isolated, batch.issue ?? "")
        print("Official log consumer batch " + batch.id.uuidString + "; fixture=" + owned + "; logs=" + logs)
        guard batch.status == .isolated else { return }
        try run("after")
        let after = try SafeFilesystem.snapshot(logs)
        XCTAssertTrue(after.tree.contains { $0.relative.hasPrefix("after") && $0.identity.size > 0 })
        let restored = try await engine.restore(batchID: batch.id)
        XCTAssertEqual(restored.status, .restored, restored.entries.compactMap(\.message).joined(separator: "; "))
        for (path, bytes) in contents { XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path)), bytes) }
        XCTAssertTrue(try AppInspector.inspect(app).signed)
        print("Official Firefox actual logs isolated, restored byte-for-byte and new logs generated; original app signature retained. Only owned log files selected.")
    }
}
#endif
