import Foundation
import XCTest
@testable import AppSweepCore
#if os(macOS)
import Darwin
#else
import Glibc
#endif

final class CacheDiscoveryTests: XCTestCase, @unchecked Sendable {
    private func scan(_ f: RecoveryTests.Fixture) throws -> ScanOutput {
        try Scanner(policy: SafetyPolicy(home:f.home,acceptedPlatform:true)).junk(indexLookup:{ _ in [] })
    }
    func testUnknownNamespacesAreDiscoveredWithoutInventingOwnersOrPermission() throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let names=["Plain Cache", "org.example.removed", "Shared Vendor", "com.apple.fixture"]
        for name in names {
            let path=f.home + "/Library/Caches/" + name
            try FileManager.default.createDirectory(atPath:path,withIntermediateDirectories:false)
            try Data("unattributed payload".utf8).write(to:URL(fileURLWithPath:path + "/payload"))
        }
        let result=try scan(f)
        for name in names {
            let path=f.home + "/Library/Caches/" + name
            let item=try XCTUnwrap(result.report.candidates.first { $0.path == path },"Missing discovered namespace: " + name)
            XCTAssertEqual(item.category,.cache);XCTAssertNil(item.applicationPath);XCTAssertNil(item.bundleIdentifier)
            XCTAssertFalse(item.allowed);XCTAssertFalse(item.selectedByDefault);XCTAssertEqual(item.allowedActions,[.report])
            XCTAssertNil(item.identity);XCTAssertNil(result.snapshots[item.id]);XCTAssertFalse(item.evidence.contains(where:\.authorizes))
            XCTAssertNotNil(item.retentionReason)
        }
    }
    func testLinksAndSpecialFilesAreVisibleWithoutTraversingTheirTargets() throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let root=f.home + "/Library/Caches",outside=f.home + "/outside"
        try FileManager.default.createDirectory(atPath:outside,withIntermediateDirectories:false)
        try Data("preserve this independent sentinel".utf8).write(to:URL(fileURLWithPath:outside + "/sentinel"))
        try FileManager.default.createSymbolicLink(atPath:root + "/linked",withDestinationPath:outside)
        try FileManager.default.createSymbolicLink(atPath:root + "/dangling",withDestinationPath:outside + "/missing")
        XCTAssertEqual(mkfifo(root + "/pipe",0o600),0)
        try FileManager.default.createSymbolicLink(atPath:f.source + "/nested-link",withDestinationPath:outside)
        let result=try scan(f)
        for name in ["linked","dangling","pipe","org.example.fixture"] {
            let item=try XCTUnwrap(result.report.candidates.first { $0.path == root + "/" + name })
            XCTAssertFalse(item.allowed);XCTAssertNil(item.identity)
        }
        XCTAssertFalse(result.report.candidates.contains { $0.path.contains("nested-link/") || $0.path.hasPrefix(outside) })
        XCTAssertEqual(try String(contentsOfFile:outside + "/sentinel",encoding:.utf8),"preserve this independent sentinel")
    }
    func testLinkedCacheRootIsUnconfirmedAndNeverEnumeratesItsDestination() throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let root=f.home + "/Library/Caches",saved=f.home + "/cache-original"
        try FileManager.default.moveItem(atPath:root,toPath:saved)
        try FileManager.default.createSymbolicLink(atPath:root,withDestinationPath:saved)
        let result=try scan(f)
        XCTAssertFalse(result.report.complete,"A cache discovery root failure must not appear as an empty successful scan")
        XCTAssertTrue(result.report.issues.contains { $0.contains(root) })
        // Fixed-path rules may report a blocked location without enumerating it.
        let retained = result.report.candidates.filter { $0.path.hasPrefix(root + "/") }
        XCTAssertTrue(retained.allSatisfy { !$0.allowed && !$0.selectedByDefault && $0.identity == nil && result.snapshots[$0.id] == nil })
        XCTAssertFalse(result.report.candidates.contains { $0.path == root + "/org.example.fixture/data" })
        XCTAssertEqual(try String(contentsOfFile:saved + "/org.example.fixture/data",encoding:.utf8),"regenerable")
    }
    func testMissingCacheRootAndDeniedCacheRootHaveDifferentResults() throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let root=f.home + "/Library/Caches",saved=f.home + "/cache-original"
        try FileManager.default.moveItem(atPath:root,toPath:saved)
        XCTAssertFalse(try scan(f).report.issues.contains { $0.contains(root) },"An absent cache root is an empty discovered range")
        try FileManager.default.moveItem(atPath:saved,toPath:root)
        XCTAssertEqual(chmod(root,0o000),0)
        defer { _=chmod(root,0o700) }
        let denied=try scan(f)
        XCTAssertFalse(denied.report.complete)
        XCTAssertTrue(denied.report.issues.contains { $0.contains(root) },"Inaccessible must not become absent")
    }
    func testInstallationDiscoveryFailureDoesNotHideIndependentCacheHints() throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let result=try Scanner(policy:SafetyPolicy(home:f.home,acceptedPlatform:true)).junk(indexLookup:{ _ in throw SweepError.incomplete("fixture installation query denied") })
        XCTAssertFalse(result.report.complete)
        let hint=try XCTUnwrap(result.report.candidates.first { $0.path == f.source })
        XCTAssertFalse(hint.allowed);XCTAssertNil(hint.applicationPath)
        XCTAssertTrue(result.report.issues.contains { $0.contains("fixture installation query denied") })
    }
    func testEnumeratingTooManyNamespacesIsUnconfirmedRatherThanPartialSuccess() throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let root=f.home + "/Library/Caches"
        for i in 0..<4096 { try Data().write(to:URL(fileURLWithPath:root + "/entry-" + String(i)),options:.withoutOverwriting) }
        let result=try scan(f)
        XCTAssertFalse(result.report.complete)
        XCTAssertTrue(result.report.issues.contains { $0.contains(root) })
        XCTAssertFalse(result.report.candidates.contains { $0.rule == "cache-discovery-only-v1" },"Truncated namespace enumeration must not report a complete subset")
    }
    func testDiscoveryHintsParticipateInIgnorePolicyButCannotCreatePlans() async throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let engine=f.engine(),report=try await engine.scanJunk()
        let item=try XCTUnwrap(report.candidates.first { $0.path == f.source })
        let forged=Candidate(id:item.id,path:item.path,category:.cache,bundleIdentifier:"org.example.forged",evidence:[.init(kind:.validatedRule,detail:"fabricated presentation",verified:true)],rule:"cache-exact-domain-v1",identity:f.snapshot.identity,bytes:11,retentionReason:nil,executionAllowed:true)
        XCTAssertTrue(forged.allowed,"Forged presentation deliberately looks executable")
        do { _=try await engine.makePlan(reportID:report.id,selected:[forged.id],includeUserData:false);XCTFail("Discovery is not execution authority; only the engine's retained report counts") } catch { }
        let list=try await engine.cleanupIgnores()
        _=try await engine.addCleanupIgnore(path:item.path,expectedRevision:list.revision)
        let again=try await engine.scanJunk(),ignored=try XCTUnwrap(again.candidates.first { $0.path == f.source })
        XCTAssertNotNil(ignored.ignoredReason);XCTAssertEqual(ignored.allowedActions,[.report])
        XCTAssertEqual(try String(contentsOfFile:f.source + "/data",encoding:.utf8),"regenerable")
    }
    #if os(macOS)
    func testNestedUnverifiedFirefoxRuleRetainsItsCacheWithoutDuplicateParentOrAuthorization() async throws {
        let f=try NativeAcceptanceTests.NativeFixture();defer { try? f.clean() }
        let infoPath=f.app + "/Contents/Info.plist"
        var info=try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:infoPath)),format:nil) as? [String:Any])
        info["CFBundleIdentifier"]="org.mozilla.firefox"
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:infoPath))
        let signed=try BoundedProcess.capture("/usr/bin/codesign",arguments:["--force","--sign","-",f.app],timeout:10,mergeStderr:true)
        XCTAssertEqual(signed.status,0,signed.text)
        let support=f.home + "/Library/Application Support/Firefox",root=f.home + "/Library/Caches/Firefox",cache=root + "/Profiles/owned.default/cache2"
        try FileManager.default.createDirectory(atPath:support,withIntermediateDirectories:true)
        try FileManager.default.createDirectory(atPath:cache,withIntermediateDirectories:true)
        try Data("[Profile0]\nName=owned\nIsRelative=1\nPath=Profiles/owned.default\n".utf8).write(to:URL(fileURLWithPath:support + "/profiles.ini"))
        let report=try await f.engine.scanJunk()
        let candidate=try XCTUnwrap(report.candidates.first { $0.path == cache })
        XCTAssertFalse(candidate.allowed,"A self-signed fixture is not the official Firefox publisher")
        XCTAssertNotNil(candidate.retentionReason)
        XCTAssertFalse(report.candidates.contains { $0.path == root },"The nested retained rule already explains the known namespace")
    }
    func testTruncatedGeneralDiscoveryDoesNotDisableConfirmedCacheMembers() async throws {
        let f=try NativeAcceptanceTests.NativeFixture(additionalRules:["cache-exact-domain-v1"]); defer { try? f.clean() }
        try f.generate()
        let root=f.home + "/Library/Caches"
        for i in 0..<4096 { try Data().write(to:URL(fileURLWithPath:root + "/entry-" + String(i)),options:.withoutOverwriting) }
        let report=try await f.engine.scanJunk()
        XCTAssertFalse(report.complete)
        let payload=try XCTUnwrap(report.selectableCandidates(includeUserData:false).first { $0.path == root + "/org.example.sweepfixture/payload" })
        let plan=try await f.engine.makePlan(reportID:report.id,selected:[payload.id],includeUserData:false)
        XCTAssertEqual(plan.items.count,1);XCTAssertFalse(plan.retainedIssues?.isEmpty ?? true)
    }
    func testKnownCacheMembersDoNotGainAnOverlappingParentCandidate() async throws {
        let f=try NativeAcceptanceTests.NativeFixture(additionalRules:["cache-exact-domain-v1"]); defer { try? f.clean() }
        try f.generate()
        let report=try await f.engine.scanJunk(),root=f.home + "/Library/Caches/org.example.sweepfixture"
        XCTAssertTrue(report.candidates.contains { $0.path == root + "/payload" && $0.rule == "cache-exact-domain-v1" })
        XCTAssertFalse(report.candidates.contains { $0.path == root })
    }
    #endif
}
