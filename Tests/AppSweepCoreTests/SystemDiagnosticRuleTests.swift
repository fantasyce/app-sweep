import XCTest
@testable import AppSweepCore

final class SystemDiagnosticRuleTests: XCTestCase {
    private let identifier = "com.apple.textkit.nsattributedstringagent"
    private let executable = "/System/Library/PrivateFrameworks/UIFoundation.framework/Versions/A/XPCServices/nsattributedstringagent.xpc/Contents/MacOS/nsattributedstringagent"
    private let incident = "12345678-1234-4234-8234-123456789ABC"
    private func report(headerChanges: [String: Any] = [:], bodyChanges: [String: Any] = [:]) throws -> Data {
        var header: [String: Any] = ["bundleID": identifier, "bug_type": "309", "incident_id": incident]
        var body: [String: Any] = ["bundleInfo": ["CFBundleIdentifier": identifier], "codeSigningID": identifier,
            "procPath": executable, "incident": incident, "bug_type": "309", "threads": [["id": 1]], "usedImages": [["name": "test"]]]
        header.merge(headerChanges) { _, new in new }; body.merge(bodyChanges) { _, new in new }
        return try JSONSerialization.data(withJSONObject: header) + Data([10]) + JSONSerialization.data(withJSONObject: body)
    }
    func testProductionRuleRequiresAcceptedARMPlatform() {
        let accepted = PlatformStamp(major: 27, minor: 0, patch: 1, build: "26A434", architecture: "arm64")
        XCTAssertTrue(NativeAcceptance.systemRules(for: accepted).contains(SystemDiagnosticRule.name))
        XCTAssertFalse(NativeAcceptance.systemRules(for: nil).contains(SystemDiagnosticRule.name))
        let unaccepted = PlatformStamp(major: 27, minor: 0, patch: 1, build: "different", architecture: "arm64")
        XCTAssertFalse(NativeAcceptance.systemRules(for: unaccepted).contains(SystemDiagnosticRule.name))
        let intel = PlatformStamp(major: 13, minor: 7, patch: 8, build: "22H730", architecture: "x86_64")
        XCTAssertFalse(NativeAcceptance.systemRules(for: intel).contains(SystemDiagnosticRule.name))
    }
    func testCompleteMatchingAppleReportProducesEvidenceOnly() throws {
        let evidence = SystemDiagnosticRule.metadata(try report())
        XCTAssertEqual(evidence?.identifier, identifier)
        XCTAssertEqual(evidence?.executable, executable)
    }
    func testHeaderNameCannotAuthorizeMismatchedOrIncompleteBody() throws {
        for changes in [["codeSigningID": "com.apple.other"], ["incident": UUID().uuidString],
                                       ["bundleInfo": ["CFBundleIdentifier": "org.example.app"]],
                                       ["threads": NSNull()], ["usedImages": NSNull()], ["bug_type": "other"]] as [[String: Any]] {
            XCTAssertNil(SystemDiagnosticRule.metadata(try report(bodyChanges: changes)))
        }
        XCTAssertNil(SystemDiagnosticRule.metadata(Data("{\"bundleID\":\"com.apple.example\"}".utf8)))
    }
    func testExecutableMustBeCanonicalImmutableSystemLocation() throws {
        for path in ["/Applications/Fake.app/Contents/MacOS/fake", "/Library/fake", "/System/Library/../fake",
                     "/System//Library/fake", "/System/Library/fake/", "/System/Library/<redacted>"] {
            XCTAssertNil(SystemDiagnosticRule.metadata(try report(bodyChanges: ["procPath": path])))
        }
    }
    func testThirdPartyAndOversizeReportsRemainOutsideRule() throws {
        XCTAssertNil(SystemDiagnosticRule.metadata(try report(headerChanges: ["bundleID": "org.example.app"])))
        XCTAssertNil(SystemDiagnosticRule.metadata(Data(repeating: 32, count: 2 * 1024 * 1024 + 1)))
    }
    func testOnlyDirectIPSFilesMatchAndAgeAloneIsNotAuthority() {
        let root = "/Library"
        XCTAssertTrue(SystemDiagnosticRule.matches("/Library/Logs/DiagnosticReports/example.ips", libraryRoot: root))
        for path in ["/Library/Logs/DiagnosticReports", "/Library/Logs/DiagnosticReports/Retired/example.ips",
                     "/Library/Logs/DiagnosticReports/../example.ips", "/private/var/log/example.ips",
                     "/Library/Logs/DiagnosticReports/example.log", "/Library/Logs/DiagnosticReports//example.ips"] {
            XCTAssertFalse(SystemDiagnosticRule.matches(path, libraryRoot: root))
        }
    }
    #if os(macOS)
    func testNativeAnalyticsDirectoryAndOrdinaryUserDirectoryAreDistinct() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let actual = try SafeDirectory(path: "/Library/Logs/DiagnosticReports")
        XCTAssertTrue(SystemDiagnosticRule.trustedSystemReportDirectory(actual.fd))
        let privateDirectory = try SafeDirectory(path: f.home)
        XCTAssertFalse(SystemDiagnosticRule.trustedSystemReportDirectory(privateDirectory.fd))
    }
    func testAppleReportFixtureRoundTripRetainsRecentAndConflicts() async throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let library = f.home + "/MachineLibrary", root = library + "/Logs/DiagnosticReports"
        let fm = FileManager.default
        try fm.createDirectory(atPath: root, withIntermediateDirectories: true)
        let scope = try SystemCleanupScope.fixture(libraryRoot: library, applicationsRoot: f.home + "/Applications", userHome: f.home, requesterUID: UInt32(getuid()))
        let old = root + "/old.ips", recent = root + "/recent.ips"
        let producer = "com.apple.ProblemReporter"
        let bytes = try report(headerChanges: ["bundleID": producer], bodyChanges: ["bundleInfo": ["CFBundleIdentifier": producer], "codeSigningID": producer, "procPath": "/System/Library/CoreServices/Problem Reporter.app/Contents/MacOS/Problem Reporter"])
        for path in [old, recent] { try bytes.write(to: URL(fileURLWithPath: path)) }
        try fm.setAttributes([.modificationDate: Date().addingTimeInterval(-31 * 86400)], ofItemAtPath: old)
        let before = try SafeFilesystem.snapshot(old)
        do { _ = try SystemDiagnosticRule.inspect(old, scope: scope) } catch { XCTFail("Report evidence: " + error.localizedDescription); return }
        let engine = try SystemCleanupEngine(scope: scope), scan = try await engine.scan(.logs)
        let item = try XCTUnwrap(scan.selectableCandidates(includeUserData: false).first { $0.path == old }, scan.unconfirmedIssues.joined(separator: "; ") + scan.candidates.map { $0.retentionReason ?? "selectable" }.joined(separator: "; "))
        XCTAssertFalse(scan.selectableCandidates(includeUserData: false).contains { $0.path == recent })
        let plan = try await engine.makePlan(reportID: scan.id, selected: [item.id])
        let batch = try await engine.execute(planID: plan.id)
        XCTAssertEqual(batch.status, .isolated, batch.issue ?? "")
        XCTAssertFalse(fm.fileExists(atPath: old)); XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: recent)), bytes)
        try Data("conflict sentinel".utf8).write(to: URL(fileURLWithPath: old))
        let conflict = try await engine.restore(batchID: batch.id)
        XCTAssertNotEqual(conflict.status, .restored)
        XCTAssertEqual(try String(contentsOfFile: old, encoding: .utf8), "conflict sentinel")
        try fm.moveItem(atPath: old, toPath: root + "/conflict-sentinel-retained")
        let restored = try await engine.restore(batchID: batch.id)
        XCTAssertEqual(restored.status, .restored, restored.issue ?? "")
        let after = try SafeFilesystem.snapshot(old).identity
        XCTAssertTrue(after.sameObject(as: before.identity))
        XCTAssertEqual(after.mode, before.identity.mode); XCTAssertEqual(after.owner, before.identity.owner)
        XCTAssertEqual(after.links, before.identity.links); XCTAssertEqual(after.size, before.identity.size)
        XCTAssertEqual(after.modifiedSeconds, before.identity.modifiedSeconds)
        XCTAssertEqual(after.modifiedNanoseconds, before.identity.modifiedNanoseconds)
        // rename changes ctime; it is not a restorable content timestamp.
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: old)), bytes)
    }
    func testRecentSharedAndWritableReportsAreRejectedBeforeExecution() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let library = f.home + "/MachineLibrary", root = library + "/Logs/DiagnosticReports"
        let fm = FileManager.default
        try fm.createDirectory(atPath: root, withIntermediateDirectories: true)
        let scope = try SystemCleanupScope.fixture(libraryRoot: library, applicationsRoot: f.home + "/Applications", userHome: f.home, requesterUID: UInt32(getuid()))
        let path = root + "/independent-test.ips"
        try report().write(to: URL(fileURLWithPath: path))
        XCTAssertThrowsError(try SystemDiagnosticRule.inspect(path, scope: scope))
        try fm.setAttributes([.modificationDate: Date().addingTimeInterval(-31 * 86400), .posixPermissions: 0o666], ofItemAtPath: path)
        XCTAssertThrowsError(try SystemDiagnosticRule.inspect(path, scope: scope))
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
        try fm.linkItem(atPath: path, toPath: root + "/second-link.ips")
        XCTAssertThrowsError(try SystemDiagnosticRule.inspect(path, scope: scope))
    }
    func testAgedReportStillNeedsRealMatchingAppleCodeSignature() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let library = f.home + "/MachineLibrary", root = library + "/Logs/DiagnosticReports"
        let fm = FileManager.default
        try fm.createDirectory(atPath: root, withIntermediateDirectories: true)
        let scope = try SystemCleanupScope.fixture(libraryRoot: library, applicationsRoot: f.home + "/Applications", userHome: f.home, requesterUID: UInt32(getuid()))
        let path = root + "/forged.ips"
        try report(bodyChanges: ["procPath": "/System/Library/nonexistent-test-executable"]).write(to: URL(fileURLWithPath: path))
        try fm.setAttributes([.modificationDate: Date().addingTimeInterval(-31 * 86400)], ofItemAtPath: path)
        XCTAssertThrowsError(try SystemDiagnosticRule.inspect(path, scope: scope))
        XCTAssertTrue(fm.fileExists(atPath: path))
    }
    #endif

}
