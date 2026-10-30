import XCTest
@testable import AppSweepCore
#if os(macOS)
import Darwin
#else
import Glibc
#endif

final class ScannerTests: XCTestCase, @unchecked Sendable {
    func testCancellationWithoutAnotherDirectoryLoopDoesNotReturnReport() async throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let home = f.home
        let scan = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try Scanner(policy: SafetyPolicy(home: home, acceptedPlatform: true)).known(identifier: "org.example.absent", name: "Absent")
        }
        do { _ = try await scan.value; XCTFail("Cancellation must escape even if the final scopes contain no directory loop") }
        catch is CancellationError { }
    }
    func testCancelledCoreInvocationCannotRegisterKnownScan() async throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let engine = f.engine()
        let scan = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await engine.scanKnown(bundleIdentifier: "org.example.absent", displayName: "Absent")
        }
        do { _ = try await scan.value; XCTFail("A cancelled core scan must not register a partial report") }
        catch is CancellationError { }
    }
    func testCaseVariantIdentifiersCannotClaimExclusiveFilesystemOwnership() {
        let first = ApplicationIdentity(path: "/Applications/First.app", name: "First", bundleIdentifier: "org.example.Cache", signed: true, protectedReason: nil)
        let second = ApplicationIdentity(path: "/Applications/Second.app", name: "Second", bundleIdentifier: "ORG.EXAMPLE.cache", signed: true, protectedReason: nil)
        XCTAssertFalse(AppInspector.uniqueOwner(identifier: first.bundleIdentifier, path: first.path, inventory: [first, second]))
        XCTAssertFalse(AppInspector.uniqueOwner(identifier: second.bundleIdentifier, path: second.path, inventory: [first, second]))
    }
    func testMixedCaseAppleIdentifierIsProtectedDuringInspection() throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let app = f.home + "/Applications/Protected.app"
        try FileManager.default.createDirectory(atPath: app + "/Contents", withIntermediateDirectories: true)
        try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier":"Com.Apple.TestFixture", "CFBundleName":"Protected"], format: .xml, options: 0).write(to: URL(fileURLWithPath: app + "/Contents/Info.plist"))
        XCTAssertNotNil(try AppInspector.inspect(app, verifySignature: false).protectedReason)
    }
    func testFIFOApplicationMetadataAndOldDiagnosticStayUnconfirmed() throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let contents = f.home + "/Applications/Unknown.app/Contents"
        let logs = f.home + "/Library/Logs/DiagnosticReports"
        try FileManager.default.createDirectory(atPath: contents, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: logs, withIntermediateDirectories: true)
        XCTAssertEqual(mkfifo(contents + "/Info.plist", 0o600), 0)
        XCTAssertEqual(mkfifo(logs + "/old.ips", 0o600), 0)
        try FileManager.default.setAttributes([.modificationDate:Date().addingTimeInterval(-31 * 86400)], ofItemAtPath: logs + "/old.ips")
        let start = Date()
        XCTAssertThrowsError(try AppInspector.inspect(f.home + "/Applications/Unknown.app", verifySignature:false))
        XCTAssertLessThan(Date().timeIntervalSince(start),2,"FIFO metadata must be rejected without waiting for a writer")
        let apps = try AppInspector.inventory(home: f.home)
        XCTAssertTrue(apps.contains { $0.path.hasSuffix("Unknown.app") && $0.bundleIdentifier.isEmpty })
        let result = try Scanner(policy: SafetyPolicy(home: f.home, acceptedPlatform: true)).junk()
        XCTAssertFalse(result.report.complete)
        XCTAssertTrue(result.report.issues.contains { $0.contains("不是普通文件") })
    }
    func testInventoryFindsCopiesInOrdinaryDirectoriesForOwnershipChecks() throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        for leaf in ["First.app", "Archive/Second.app"] {
            let app = f.home + "/Applications/" + leaf
            try FileManager.default.createDirectory(atPath: app + "/Contents", withIntermediateDirectories: true)
            try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier":"org.example.duplicate", "CFBundleName":"Duplicate"], format: .xml, options: 0).write(to: URL(fileURLWithPath: app + "/Contents/Info.plist"))
        }
        let apps = try AppInspector.inventory(home: f.home).filter { $0.bundleIdentifier == "org.example.duplicate" }
        XCTAssertEqual(apps.count, 2)
        XCTAssertNil(apps.first { $0.path.contains("/Archive/") }?.protectedReason, "An ordinary installation subdirectory is not an embedded component")
    }
    func testPackageEmbeddedApplicationPreventsExclusiveOwnership() throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let direct = f.home + "/Applications/First.app"
        let embedded = f.home + "/Applications/Outer.app/Contents/Helpers/Second.app"
        for (path, identifier) in [(direct, "org.example.duplicate"), (f.home + "/Applications/Outer.app", "org.example.outer"), (embedded, "org.example.duplicate")] {
            try FileManager.default.createDirectory(atPath: path + "/Contents", withIntermediateDirectories: true)
            try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier":identifier], format:.xml, options:0).write(to:URL(fileURLWithPath:path + "/Contents/Info.plist"))
        }
        let alias=f.home + "/Applications/Outer.app/Contents/Helpers/InternalAlias.app"
        try FileManager.default.createSymbolicLink(atPath:alias,withDestinationPath:"Second.app")
        let apps = try AppInspector.inventory(home:f.home)
        for app in apps where app.bundleIdentifier.isEmpty { print("Unconfirmed installed component: \(app.path): \(app.protectedReason ?? "unknown")") }
        XCTAssertEqual(apps.filter { $0.bundleIdentifier == "org.example.duplicate" }.count, 2)
        XCTAssertFalse(AppInspector.uniqueOwner(identifier:"org.example.duplicate",path:direct,inventory:apps))
        XCTAssertNotNil(apps.first { $0.path == embedded }?.protectedReason)
        XCTAssertFalse(apps.contains { $0.path == alias },"An internal alias must not invent another owner or follow a link")
    }
    func testFlatEmbeddedOwnersAndUnbuiltTemplatesAreDistinguished() throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let outer=f.home + "/Applications/Outer.app", flat=outer + "/Contents/Helpers/Flat.app", template=outer + "/Contents/Resources/Template.app/Contents"
        try FileManager.default.createDirectory(atPath:flat,withIntermediateDirectories:true)
        try FileManager.default.createDirectory(atPath:template,withIntermediateDirectories:true)
        for (path,info) in [(outer + "/Contents/Info.plist",["CFBundleIdentifier":"org.example.outer"]),(flat + "/Info.plist",["CFBundleIdentifier":"org.example.flat","CFBundlePackageType":"APPL"]),(template + "/Info.plist",["CFBundleIdentifier":"WRAPPEDPRODUCTBUNDLEIDENTIFIER","CFBundleExecutable":"WRAPPEDPRODUCTNAME","CFBundlePackageType":"APPL"])] {
            try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:path))
        }
        let apps=try AppInspector.inventory(home:f.home)
        XCTAssertEqual(apps.first { $0.path == flat }?.bundleIdentifier,"org.example.flat")
        XCTAssertNotNil(apps.first { $0.path == flat }?.protectedReason)
        XCTAssertFalse(apps.contains { $0.path.hasPrefix(template) || ($0.path.contains("Template.app") && $0.bundleIdentifier.isEmpty) })
        try FileManager.default.createDirectory(atPath:template + "/MacOS",withIntermediateDirectories:true)
        try Data("owned executable placeholder".utf8).write(to:URL(fileURLWithPath:template + "/MacOS/WRAPPEDPRODUCTNAME"))
        let withExecutable=try AppInspector.inventory(home:f.home)
        XCTAssertTrue(withExecutable.contains { $0.path.contains("Template.app") && $0.bundleIdentifier.isEmpty }, "An existing executable with unknown identity must block ownership")
    }
    func testQuotedEmbeddedIdentifierIsOnlyAConflictHint() throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let direct=f.home + "/Applications/First.app", nested=f.home + "/Applications/Outer.app/Contents/Helpers/Quoted.app"
        for (path,id) in [(direct,"org.example.duplicate"),(f.home + "/Applications/Outer.app","org.example.outer"),(nested,"\"org.example.duplicate\"")] {
            try FileManager.default.createDirectory(atPath:path + "/Contents",withIntermediateDirectories:true)
            try PropertyListSerialization.data(fromPropertyList:["CFBundleIdentifier":id],format:.xml,options:0).write(to:URL(fileURLWithPath:path + "/Contents/Info.plist"))
        }
        let apps=try AppInspector.inventory(home:f.home)
        XCTAssertEqual(apps.filter { $0.bundleIdentifier == "org.example.duplicate" }.count,2)
        XCTAssertFalse(AppInspector.uniqueOwner(identifier:"org.example.duplicate",path:direct,inventory:apps))
        let hint=try XCTUnwrap(apps.first { $0.path == nested })
        XCTAssertFalse(hint.signed); XCTAssertNotNil(hint.protectedReason)
        XCTAssertThrowsError(try AppInspector.inspect(nested,verifySignature:false))
    }
    func testEmbeddedExternalDirectoryLinkIsNotTraversedOrIgnored() throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let outer=f.home + "/Applications/Outer.app", outside=f.home + "/outside/Hidden.app"
        for (path,id) in [(outer,"org.example.outer"),(outside,"org.example.hidden")] {
            try FileManager.default.createDirectory(atPath:path + "/Contents",withIntermediateDirectories:true)
            try PropertyListSerialization.data(fromPropertyList:["CFBundleIdentifier":id],format:.xml,options:0).write(to:URL(fileURLWithPath:path + "/Contents/Info.plist"))
        }
        let link=outer + "/Contents/LinkedHelpers"
        try FileManager.default.createSymbolicLink(atPath:link,withDestinationPath:f.home + "/outside")
        let apps=try AppInspector.inventory(home:f.home)
        XCTAssertFalse(apps.contains { $0.bundleIdentifier == "org.example.hidden" })
        XCTAssertTrue(apps.contains { $0.path == link && $0.bundleIdentifier.isEmpty })
        XCTAssertFalse(AppInspector.uniqueOwner(identifier:"org.example.outer",path:outer,inventory:apps))
    }
    func testVendorAndSimilarNameRemainHints() {
        XCTAssertFalse(Attribution.canAuthorize(hints: [.init(kind: .vendorHint, detail: "com.vendor", verified: true), .init(kind: .nameHint, detail: "Chat", verified: true)]))
    }
    func testContainerMetadataMustExactlyMatchAndBeExclusive() {
        XCTAssertTrue(Attribution.exclusiveContainer(identifier: "org.example.a", target: "org.example.a", associated: ["org.example.a"]))
        XCTAssertFalse(Attribution.exclusiveContainer(identifier: "org.example.a", target: "org.example.a", associated: ["org.example.a", "org.example.b"]))
        XCTAssertFalse(Attribution.exclusiveContainer(identifier: "org.example.ab", target: "org.example.a", associated: []))
        XCTAssertFalse(Attribution.exclusiveContainer(identifier: "org.example.a", target: "org.example.a", associated: []))
    }
    func testLogAgeIsStrictlyOlderThanThirtyDays() {
        let now = Date(timeIntervalSince1970: 10_000_000)
        XCTAssertFalse(Attribution.oldLog(modified: now.addingTimeInterval(-30 * 86400), now: now))
        XCTAssertTrue(Attribution.oldLog(modified: now.addingTimeInterval(-31 * 86400), now: now))
    }
    func testIncompleteScanCannotIssuePlan() async throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }; let engine = f.engine()
        let report = await engine.adoptFixture([f.candidate], snapshots: [f.candidate.id:f.snapshot], complete: false)
        do { _ = try await engine.makePlan(reportID: report.id, selected: [f.candidate.id], includeUserData: false); XCTFail("Incomplete report authorized execution") } catch { }
    }
    func testOrphanReportHasNoInventedApplicationPath() async throws {
        let engine = SweepEngine()
        let report = try await engine.scanKnown(bundleIdentifier: "org.example.missing", displayName: "Missing")
        XCTAssertNil(report.applicationPath)
        XCTAssertFalse(report.candidates.contains { $0.category == .application })
    }
    func testRunningStateFailureIsUnknownInsteadOfEmpty() {
        XCTAssertThrowsError(try BoundedProcess.run("/does/not/exist", arguments: [], timeout: 0.1))
    }
    func testUnvalidatedCacheIsReportedWithoutTraversingItsContents() throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        try FileManager.default.createSymbolicLink(atPath: f.source + "/link", withDestinationPath: "/private/var/folders")
        let output = try Scanner(policy: SafetyPolicy(home: f.home, acceptedPlatform: true)).known(identifier: "org.example.fixture", name: "Fixture")
        XCTAssertTrue(output.report.complete)
        XCTAssertEqual(output.report.candidates.count, 1)
        guard output.report.candidates.count == 1 else { return }
        XCTAssertFalse(output.report.candidates[0].allowed)
        XCTAssertNotNil(output.report.candidates[0].retentionReason)
    }
    func testDanglingCandidateLinkIsReportedInsteadOfMissing() throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let path = f.home + "/Library/Caches/org.example.missing"
        try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: f.home + "/absent")
        let output = try Scanner(policy: SafetyPolicy(home: f.home, acceptedPlatform: true)).known(identifier: "org.example.missing", name: "Missing")
        XCTAssertEqual(output.report.candidates.count, 1)
        guard output.report.candidates.count == 1 else { return }
        XCTAssertFalse(output.report.candidates[0].allowed)
    }

}
