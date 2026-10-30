import Foundation
import XCTest
@testable import AppSweepCore

final class LegacyCrashRuleTests: XCTestCase {
    static func report(identifier: String = "org.example.sweepfixture", executable: String = "/Applications/Example.app/Contents/MacOS/example") -> Data {
        Data("""
        Process: example [123]
        Path: \(executable)
        Identifier: \(identifier)
        Version: 1.0 (1)
        Code Type: ARM-64 (Native)
        Report Version: 12

        Exception Type: EXC_BAD_ACCESS (SIGSEGV)
        Crashed Thread: 0

        Thread 0 Crashed:
        0 example 0x0 synthetic test data

        """.utf8)
    }
    func testTextReportMatchesExactIdentifierAndExecutableBundle() {
        let data = Self.report()
        XCTAssertEqual(LegacyCrashRule.headerIdentifier(data), "org.example.sweepfixture")
        XCTAssertTrue(LegacyCrashRule.owns(data, identifier: "org.example.sweepfixture", applicationPath: "/Applications/Example.app"))
        XCTAssertFalse(LegacyCrashRule.owns(data, identifier: "org.example", applicationPath: "/Applications/Example.app"))
        XCTAssertFalse(LegacyCrashRule.owns(data, identifier: "org.example.sweepfixture", applicationPath: "/Applications/Example.app.sibling"))
    }
    func testAmbiguousRedactedAliasedSystemAndIncompleteHeadersAreRetained() {
        let sample = String(decoding: Self.report(), as: UTF8.self)
        for text in [
            sample.replacingOccurrences(of: "Version: 1.0", with: "Identifier: org.example.other\nVersion: 1.0"),
            sample.replacingOccurrences(of: "Path: /", with: "Path: /Users/USER/*/"),
            sample.replacingOccurrences(of: "/Contents/MacOS", with: "/Contents/../MacOS"),
            sample.replacingOccurrences(of: "Report Version: 12", with: "Report Version: unknown"),
            sample.replacingOccurrences(of: "org.example.sweepfixture", with: "com.apple.finder"),
            sample.replacingOccurrences(of: "org.example.sweepfixture", with: "org.example.appsweep"),
            sample.replacingOccurrences(of: "example [123]", with: "example\0 [123]"),
            "Identifier: org.example.sweepfixture\nPath: /Applications/Example.app/Contents/MacOS/example\n"
        ] {
            XCTAssertFalse(LegacyCrashRule.owns(Data(text.utf8), identifier: "org.example.sweepfixture", applicationPath: "/Applications/Example.app"), text)
        }
    }
    func testBodyTextCannotReplaceHeaderOwnershipAndCRLFIsSupported() {
        var text = String(decoding: Self.report(), as: UTF8.self)
        text += "Identifier: org.example.other\nPath: /Applications/Other.app/Contents/MacOS/other\n"
        XCTAssertTrue(LegacyCrashRule.owns(Data(text.utf8), identifier: "org.example.sweepfixture", applicationPath: "/Applications/Example.app"))
        XCTAssertTrue(LegacyCrashRule.owns(Data(text.replacingOccurrences(of: "\n", with: "\r\n").utf8), identifier: "org.example.sweepfixture", applicationPath: "/Applications/Example.app"))
        XCTAssertNil(LegacyCrashRule.headerIdentifier(Data(repeating: 65, count: 2 * 1024 * 1024 + 1)))
    }
    func testKnownTranslatedReportPreambleAndUTF8BOMAreSupported() {
        let body = String(decoding: Self.report(), as: UTF8.self).replacingOccurrences(of: "Report Version: 12", with: "Report Version: 104")
        let preamble = "-------------------------------------\nTranslated Report (Full Report Below)\n-------------------------------------\n\n"
        for text in [preamble + body, "\u{feff}" + body, "\u{feff}" + preamble + body] {
            XCTAssertTrue(LegacyCrashRule.owns(Data(text.utf8), identifier: "org.example.sweepfixture", applicationPath: "/Applications/Example.app"))
        }
        XCTAssertFalse(LegacyCrashRule.owns(Data(("arbitrary unrelated text\n\n" + body).utf8), identifier: "org.example.sweepfixture", applicationPath: "/Applications/Example.app"))
    }
}

#if os(macOS)
final class RealLegacyCrashTests: XCTestCase, @unchecked Sendable {
    func testPublicEngineSignedFirefoxSyntheticOldReportRoundtrip() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_PUBLIC_DIAGNOSTIC_ACCEPTANCE"] == "1",
              try BoundedProcess.run("/usr/sbin/sysctl", arguments: ["-n", "hw.model"], timeout: 3).hasPrefix("VirtualMac") else { throw XCTSkip("Explicit disposable VM public diagnostic acceptance required") }
        let home = try SystemIdentity.home(), task = try SafeDirectory(path: home + "/AppSweepAcceptanceGeneral-20261016")
        let operation = try task.privateChild("diagnostic-public.noindex").privateChild(UUID().uuidString)
        let app = home + "/Applications/Firefox.app", identifier = "org.mozilla.firefox"
        guard AppInspector.signatureMatches(path: app, identifier: identifier), AppInspector.signedByTeam(path: app, team: "43AQ936H96") else { throw SweepError.denied("Existing official test Firefox required") }
        try ActivityInspector.ensureStopped(bundleID: identifier, applicationPath: app)
        let root = home + "/Library/Logs/DiagnosticReports"
        try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
        let name = "AppSweep-owned-" + UUID().uuidString + ".crash", path = root + "/" + name
        guard try !SafeFilesystem.presence(path) else { throw SweepError.denied("Test report exists; no overwrite") }
        try operation.write(JSONSerialization.data(withJSONObject: ["path":path,"purpose":"independently authored synthetic text report; not an observed Firefox crash"], options:[.sortedKeys]), name:"ownership.json")
        let contents = LegacyCrashRuleTests.report(identifier: identifier, executable: app + "/Contents/MacOS/firefox")
        try contents.write(to: URL(fileURLWithPath:path), options:.withoutOverwriting)
        try FileManager.default.setAttributes([.modificationDate: Date().addingTimeInterval(-31 * 86400)], ofItemAtPath:path)
        let original = try SafeFilesystem.snapshot(path)
        try operation.write(JSONEncoder().encode(original.identity), name:"source-identity.json")
        try operation.write(Data(try VerifiedFileStream.digest(original).utf8), name:"source-digest.txt")
        let engine = SweepEngine(), report = try await engine.scanJunk()
        let discovered = report.candidates.first { $0.path == path && $0.rule == LegacyCrashRule.name }
        let item = try XCTUnwrap(report.selectableCandidates(includeUserData:false).first { $0.path == path && $0.rule == LegacyCrashRule.name }, discovered?.retentionReason ?? report.unconfirmedIssues.joined(separator:"; "))
        let plan = try await engine.makePlan(reportID:report.id,selected:[item.id],includeUserData:false)
        let batch = try await engine.execute(planID:plan.id)
        print("Public synthetic crash batch=" + batch.id.uuidString + "; receipt=" + operation.path + "/ownership.json")
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        guard batch.status == .isolated else { return }
        let restored = try await SweepEngine().restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:"; "))
        guard restored.status == .restored else { return }
        XCTAssertEqual(try SafeFilesystem.readMetadata(path),contents)
        let snapshot = try SafeFilesystem.snapshot(path)
        try SafeFilesystem.move(snapshot,into:operation,name:name)
        XCTAssertTrue(AppInspector.signatureMatches(path:app,identifier:identifier))
        print("Public default engine text report isolation/fresh-engine recovery complete; synthetic own report retained beside its receipt.")
    }
}
final class NativeLegacyCrashTests: XCTestCase, @unchecked Sendable {
    func testRunningDiagnosticOwnerIsRetainedWithoutTerminatingIt() async throws {
        let f = try NativeAcceptanceTests.NativeFixture(additionalRules: [LegacyCrashRule.name])
        let process = Process()
        // Retain the fixture if shutdown fails; never remove a live app's files.
        defer { if !process.isRunning { try? f.clean() } }
        let fm = FileManager.default, root = f.home + "/Library/Logs/DiagnosticReports", path = root + "/running.crash"
        try fm.createDirectory(atPath: root, withIntermediateDirectories: true)
        try LegacyCrashRuleTests.report(executable: f.executable).write(to: URL(fileURLWithPath: path))
        try fm.setAttributes([.modificationDate: Date().addingTimeInterval(-31 * 86400)], ofItemAtPath: path)
        process.executableURL = URL(fileURLWithPath:f.executable); process.arguments = ["--wait",f.home]
        let stopped = expectation(description: "Owned diagnostic fixture exited")
        process.terminationHandler = { _ in stopped.fulfill() }
        try process.run()
        var bodyError: Error?
        do {
            for _ in 0..<100 where !fm.fileExists(atPath:f.home + "/wait-ready") { try await Task.sleep(nanoseconds:50_000_000) }
            guard fm.fileExists(atPath:f.home + "/wait-ready"), process.isRunning else { throw SweepError.incomplete("Owned test process never reached its barrier") }
            let report = try await f.engine.scanJunk()
            let item = try XCTUnwrap(report.candidates.first { $0.path == path })
            XCTAssertFalse(item.allowed)
            XCTAssertTrue(item.retentionReason?.contains("关闭") == true, item.retentionReason ?? "")
            XCTAssertFalse(report.selectableCandidates(includeUserData:false).contains { $0.id == item.id })
            XCTAssertTrue(process.isRunning)
            XCTAssertTrue(fm.fileExists(atPath:path))
        } catch { bodyError = error }
        try Data().write(to:URL(fileURLWithPath:f.home + "/release-wait"))
        // Synchronous waitUntilExit can strand a cooperative XCTest worker even
        // after the child exits. Observe termination asynchronously and boundedly.
        await fulfillment(of: [stopped], timeout: 10)
        guard !process.isRunning else { throw SweepError.incomplete("Owned diagnostic fixture did not exit; retained at " + f.home) }
        XCTAssertEqual(process.terminationStatus, 0)
        if let bodyError { throw bodyError }
    }
    func testChangedReportAfterReviewStopsBeforeAnyMove() async throws {
        let f = try NativeAcceptanceTests.NativeFixture(additionalRules: [LegacyCrashRule.name])
        defer { try? f.clean() }
        let fm = FileManager.default, root = f.home + "/Library/Logs/DiagnosticReports"
        try fm.createDirectory(atPath: root, withIntermediateDirectories: true)
        let path = root + "/changed.crash"
        try LegacyCrashRuleTests.report(executable: f.executable).write(to: URL(fileURLWithPath: path))
        try fm.setAttributes([.modificationDate: Date().addingTimeInterval(-31 * 86400)], ofItemAtPath: path)
        let report = try await f.engine.scanJunk()
        let item = try XCTUnwrap(report.selectableCandidates(includeUserData: false).first { $0.path == path })
        let plan = try await f.engine.makePlan(reportID: report.id, selected: [item.id], includeUserData: false)
        let replacement = LegacyCrashRuleTests.report(identifier: "org.example.other", executable: f.executable)
        try replacement.write(to: URL(fileURLWithPath: path))
        do { _ = try await f.engine.execute(planID: plan.id); XCTFail("A changed diagnostic report must invalidate the reviewed plan") }
        catch { }
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path)), replacement)
        let batches = try await f.engine.recoveryBatches()
        XCTAssertTrue(batches.isEmpty)
        XCTAssertTrue(try AppInspector.inspect(f.app).signed)
    }
    func testSignedOwnerOldReportIsolationRestoreAndRetainedPeers() async throws { try await roundtrip(helperDeclaration: false) }
    func testUninstalledHelperDeclarationDoesNotHideVerifiedDiagnosticOwnership() async throws { try await roundtrip(helperDeclaration: true) }
    private func roundtrip(helperDeclaration: Bool) async throws {
        let f = try NativeAcceptanceTests.NativeFixture(additionalRules: [LegacyCrashRule.name])
        defer { try? f.clean() }
        if helperDeclaration {
            let metadata = f.app + "/Contents/Info.plist"
            var info = try XCTUnwrap(try PropertyListSerialization.propertyList(from: Data(contentsOf: URL(fileURLWithPath: metadata)), format: nil) as? [String: Any])
            info["SMPrivilegedExecutables"] = ["org.example.absent-" + UUID().uuidString:"identifier org.example.absent"]
            try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: URL(fileURLWithPath: metadata))
            _ = try BoundedProcess.run("/usr/bin/codesign", arguments:["--force","--sign","-",f.app], timeout:10)
            XCTAssertNotNil(try AppInspector.inspect(f.app).protectedReason)
            _ = try AppInspector.verifiedDataOwner(path:f.app,identifier:"org.example.sweepfixture",home:f.home)
        }
        let fm = FileManager.default, root = f.home + "/Library/Logs/DiagnosticReports"
        try fm.createDirectory(atPath: root, withIntermediateDirectories: true)
        let selected = root + "/old-matching.crash", recent = root + "/recent.crash", mismatch = root + "/old-other.crash"
        let contents = LegacyCrashRuleTests.report(executable: f.executable)
        try contents.write(to: URL(fileURLWithPath: selected)); try contents.write(to: URL(fileURLWithPath: recent))
        try LegacyCrashRuleTests.report(executable: "/Applications/Other.app/Contents/MacOS/example").write(to: URL(fileURLWithPath: mismatch))
        for path in [selected, mismatch] { try fm.setAttributes([.modificationDate: Date().addingTimeInterval(-31 * 86400)], ofItemAtPath: path) }
        let report = try await f.engine.scanJunk()
        let item = try XCTUnwrap(report.selectableCandidates(includeUserData: false).first { $0.path == selected })
        XCTAssertEqual(item.rule, LegacyCrashRule.name)
        XCTAssertFalse(report.selectableCandidates(includeUserData: false).contains { $0.path == recent || $0.path == mismatch })
        let plan = try await f.engine.makePlan(reportID: report.id, selected: [item.id], includeUserData: false)
        let batch = try await f.engine.execute(planID: plan.id)
        XCTAssertEqual(batch.status, .isolated, batch.issue ?? "")
        guard batch.status == .isolated else { return }
        XCTAssertFalse(fm.fileExists(atPath: selected)); XCTAssertTrue(fm.fileExists(atPath: recent)); XCTAssertTrue(fm.fileExists(atPath: mismatch))
        let restored = try await f.restoreWhenUnused(batch)
        XCTAssertEqual(restored.status, .restored)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: selected)), contents)
        XCTAssertTrue(try AppInspector.inspect(f.app).signed)
    }
}
#endif
