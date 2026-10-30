#if os(macOS)
import Foundation
import XCTest
import Darwin
@testable import AppSweepCore

final class UserCacheNamespaceTests: XCTestCase, @unchecked Sendable {
    private let rule = "cache-user-namespace-v1"
    private func engine(_ f: RecoveryTests.Fixture, failure: FailurePoint? = nil) -> SweepEngine {
        SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[rule]),
                    vaultPath:f.home + "/Library/Application Support/App Sweep/Recovery",failurePoint:failure,fixture:true)
    }
    private func namespace(_ f: RecoveryTests.Fixture, name: String = "Uninstalled Cache") throws -> String {
        let root = f.home + "/Library/Caches/" + name
        try FileManager.default.createDirectory(atPath:f.home + "/Library/Application Support",withIntermediateDirectories:true)
        try FileManager.default.createDirectory(atPath:root + "/objects",withIntermediateDirectories:true)
        try Data("independent regenerable payload".utf8).write(to:URL(fileURLWithPath:root + "/objects/data"))
        try Data("whole cache index".utf8).write(to:URL(fileURLWithPath:root + "/index"))
        return root
    }
    // Historical generic-cache batches still need the native recovery checks.
    // Only DEBUG can register these fixtures; production scanning no longer
    // grants authority without an owner whose stopped state can be checked.
    private func legacyReport(_ engine: SweepEngine, root: String) async throws -> ScanReport {
        let home=URL(fileURLWithPath:root).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().path
        _=try SafeDirectory(path:home + "/Library/Application Support").privateChild("App Sweep")
        var items:[Candidate]=[],snapshots:[UUID:FileSnapshot]=[:]
        for path in try CacheDomainRule.members(root:root).sorted() {
            let snapshot=try SafeFilesystem.snapshot(path),id=UUID()
            items.append(Candidate(id:id,path:path,category:.cache,bundleIdentifier:nil,evidence:[.init(kind:.validatedRule,detail:"Historical test-only cache batch",verified:true)],rule:rule,identity:snapshot.identity,bytes:snapshot.bytes,retentionReason:nil))
            snapshots[id]=snapshot
        }
        return await engine.adoptFixture(items,snapshots:snapshots)
    }
    func testUnmappedNamespaceIsRetainedWithoutInventingAnApplication() throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let root=try namespace(f)
        let output=try Scanner(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[rule])).junk(indexLookup:{_ in []})
        let item=try XCTUnwrap(output.report.candidates.first { $0.path == root })
        XCTAssertFalse(item.allowed)
        XCTAssertTrue(item.retentionReason?.contains("归属") == true,item.retentionReason ?? "")
        XCTAssertNil(item.bundleIdentifier);XCTAssertNil(item.applicationPath)
        XCTAssertFalse(output.report.selectableCandidates(includeUserData:true).contains { $0.path.hasPrefix(root + "/") })
    }
    func testEmptyUnmappedNamespaceIsNotShownAsRetainedJunk() throws {
        let f=try RecoveryTests.Fixture();defer{try? f.clean()}
        let empty=f.home + "/Library/Caches/EmptyNamespace"
        try FileManager.default.createDirectory(atPath:empty,withIntermediateDirectories:true)
        let output=try Scanner(policy:SafetyPolicy(home:f.home,acceptedPlatform:false)).junk(indexLookup:{_ in []})
        XCTAssertFalse(output.report.candidates.contains{$0.path == empty})
        XCTAssertTrue(FileManager.default.fileExists(atPath:empty),"Empty directory remains in place")
    }
    func testProtectedDirectMemberRetainsTheCompleteUnmappedNamespace() async throws {
        let f=try RecoveryTests.Fixture();defer{try? f.clean()};let root=try namespace(f)
        try Data("protected cache member".utf8).write(to:URL(fileURLWithPath:root + "/com.apple.shared-index"))
        let report=try await engine(f).scanJunk()
        XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains{$0.path.hasPrefix(root + "/")},"A required cache group cannot offer only its unprotected siblings")
    }
    func testLegacyArchiveMovesTheCompleteCacheGroupAndFreshEngineRestoresIt() async throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let root=try namespace(f,name:"org.example.removed." + UUID().uuidString),rootBefore=try SafeDirectory(path:root).ownIdentity
        let before=try SafeFilesystem.snapshot(root),e=engine(f),report=try await legacyReport(e,root:root)
        let members=report.candidates.filter { $0.path.hasPrefix(root + "/") && $0.rule == rule }
        XCTAssertEqual(members.count,2)
        let first=try XCTUnwrap(members.first)
        do { _=try await e.makePlan(reportID:report.id,selected:[first.id],includeUserData:false); XCTFail("Do not split a cache index from its objects") } catch { }
        let plan=try await e.makePlan(reportID:report.id,selected:Set(members.map(\.id)),includeUserData:false)
        let batch=try await e.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        XCTAssertEqual(try CacheDomainRule.members(root:root),[])
        XCTAssertEqual(try SafeDirectory(path:root).ownIdentity.inode,rootBefore.inode)
        XCTAssertEqual(try SafeDirectory(path:root).ownIdentity.device,rootBefore.device)
        XCTAssertTrue(batch.entries.allSatisfy { $0.backupFormat == "cache-tree-v1" && $0.backupDigest != nil })
        let restored=try await engine(f).restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        let after=try SafeFilesystem.snapshot(root)
        XCTAssertEqual(after.tree.map(\.relative),before.tree.map(\.relative))
        for (current,original) in zip(after.tree,before.tree) { XCTAssertTrue(current.identity.sameObject(as:original.identity),original.relative) }
        XCTAssertEqual(try String(contentsOfFile:root + "/objects/data",encoding:.utf8),"independent regenerable payload")
        XCTAssertEqual(try String(contentsOfFile:f.source + "/data",encoding:.utf8),"regenerable")
    }
    func testUnsafeNamespacesRemainWholeAndDoNotAuthorizeSafeLookingSiblings() throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let linked=try namespace(f,name:"Linked Cache"),shared=try namespace(f,name:"Shared Cache"),apple=try namespace(f,name:"com.apple.fixture")
        try FileManager.default.createSymbolicLink(atPath:linked + "/outside",withDestinationPath:f.home)
        XCTAssertEqual(chmod(shared + "/objects",0o777),0)
        defer { _=chmod(shared + "/objects",0o755) }
        let output=try Scanner(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[rule])).junk(indexLookup:{_ in []})
        for root in [linked,shared,apple] {
            XCTAssertFalse(output.report.candidates.contains { ($0.path == root || $0.path.hasPrefix(root + "/")) && $0.allowed },root)
            XCTAssertTrue(FileManager.default.fileExists(atPath:root + "/index"))
        }
        XCTAssertFalse(output.report.candidates.contains { $0.path.contains("/outside/") })
    }
    func testOpenCacheFileIsRetainedAtScanAndCannotBePlanned() async throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let root=try namespace(f),fd=open(root + "/objects/data",O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd,0); defer { if fd >= 0 { close(fd) } }
        let e=engine(f),report=try await e.scanJunk()
        XCTAssertFalse(report.candidates.contains { $0.path.hasPrefix(root + "/") && $0.allowed },"A busy namespace stays whole")
        if let item=report.candidates.first(where: { $0.path == root || $0.path.hasPrefix(root + "/") }) {
            do { _=try await e.makePlan(reportID:report.id,selected:[item.id],includeUserData:false); XCTFail("Busy cache became executable") } catch { }
        }
    }
    func testLegacyRegeneratedMemberPreventsTheWholeGroupFromBeingOverwritten() async throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let root=try namespace(f),e=engine(f),report=try await legacyReport(e,root:root)
        let members=report.candidates.filter { $0.path.hasPrefix(root + "/") && $0.rule == rule }
        let plan=try await e.makePlan(reportID:report.id,selected:Set(members.map(\.id)),includeUserData:false)
        let batch=try await e.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        try Data("new consumer generation".utf8).write(to:URL(fileURLWithPath:root + "/index"),options:.withoutOverwriting)
        let conflict=try await engine(f).restore(batchID:batch.id)
        XCTAssertEqual(conflict.status,.needsAttention)
        XCTAssertEqual(try String(contentsOfFile:root + "/index",encoding:.utf8),"new consumer generation")
        XCTAssertFalse(FileManager.default.fileExists(atPath:root + "/objects"),"Conflict is checked before any member is restored")
        let saved=f.home + "/new-generation"
        try FileManager.default.moveItem(atPath:root + "/index",toPath:saved)
        let restored=try await engine(f).restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        XCTAssertEqual(try String(contentsOfFile:saved,encoding:.utf8),"new consumer generation")
    }
    func testLegacyReplacedNamespaceStopsBeforeAnyCacheIsMoved() async throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let root=try namespace(f),e=engine(f),report=try await legacyReport(e,root:root)
        let members=report.candidates.filter { $0.path.hasPrefix(root + "/") && $0.rule == rule }
        let plan=try await e.makePlan(reportID:report.id,selected:Set(members.map(\.id)),includeUserData:false)
        let saved=f.home + "/original-cache"
        try FileManager.default.moveItem(atPath:root,toPath:saved)
        try FileManager.default.createSymbolicLink(atPath:root,withDestinationPath:saved)
        do { _=try await e.execute(planID:plan.id); XCTFail("Replaced namespace escaped the plan") } catch { }
        XCTAssertEqual(try String(contentsOfFile:saved + "/index",encoding:.utf8),"whole cache index")
    }
    func testSecurityAndOwnNamespacesNeverBecomeGenericCacheAuthority() throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let roots=try ["Keychains","private.keychain-db","App Sweep","com.example.appsweep.state"].map { try namespace(f,name:$0) }
        let result=try Scanner(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[rule])).junk(indexLookup:{_ in []})
        for root in roots { XCTAssertFalse(result.report.candidates.contains { ($0.path == root || $0.path.hasPrefix(root + "/")) && $0.allowed },root) }
    }
    func testLegacyFailureBeforeSecondMoveRollsBackTheGroupWithoutAnApplication() async throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let root=try namespace(f),e=engine(f,failure:.beforeSecondMove),report=try await legacyReport(e,root:root)
        let items=report.candidates.filter { $0.rule == rule && $0.path.hasPrefix(root + "/") }
        let plan=try await e.makePlan(reportID:report.id,selected:Set(items.map(\.id)),includeUserData:false)
        let result=try await e.execute(planID:plan.id)
        XCTAssertEqual(result.status,.rolledBack,result.issue ?? "")
        XCTAssertEqual(try String(contentsOfFile:root + "/index",encoding:.utf8),"whole cache index")
        XCTAssertEqual(try String(contentsOfFile:root + "/objects/data",encoding:.utf8),"independent regenerable payload")
    }
    func testLegacyPublicFoundationConsumerReadsRestoredCacheAndRegeneratesAfterIsolation() async throws {
        let f=try CacheRuleTests.Fixture(); defer { try? f.clean() }
        let root=f.home + "/Library/Caches/Readable Network Cache",vault=f.home + "/Library/Application Support/App Sweep/Recovery"
        try FileManager.default.moveItem(atPath:f.root,toPath:root)
        func fresh() -> SweepEngine { SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[rule]),vaultPath:vault,fixture:true) }
        func consume(_ mode: String) throws -> String {
            try BoundedProcess.run(f.executable,arguments:[mode,root],timeout:10).trimmingCharacters(in:.whitespacesAndNewlines)
        }
        XCTAssertEqual(try consume("--read"),"524288")
        let original=try SafeFilesystem.snapshot(root),originalApp=try SafeFilesystem.snapshot(f.app,allowInternalLinks:true)
        for round in 0..<2 {
            let e=fresh(),report=try await legacyReport(e,root:root)
            let items=report.selectableCandidates(includeUserData:false).filter { $0.rule == rule && $0.path.hasPrefix(root + "/") }
            XCTAssertFalse(items.isEmpty)
            let plan=try await e.makePlan(reportID:report.id,selected:Set(items.map(\.id)),includeUserData:false)
            let moved=try await e.execute(planID:plan.id)
            XCTAssertEqual(moved.status,.isolated,moved.issue ?? "")
            if round == 0 {
                let restored=try await fresh().restore(batchID:moved.id)
                XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
                XCTAssertEqual(try consume("--read"),"524288")
            } else {
                XCTAssertEqual(try consume("--generate"),"524288")
                let conflict=try await fresh().restore(batchID:moved.id)
                XCTAssertEqual(conflict.status,.needsAttention)
                XCTAssertEqual(try consume("--read"),"524288")
                let newGeneration=f.home + "/regenerated-cache"
                try FileManager.default.createDirectory(atPath:newGeneration,withIntermediateDirectories:false)
                for name in try FileManager.default.contentsOfDirectory(atPath:root) {
                    try FileManager.default.moveItem(atPath:root + "/" + name,toPath:newGeneration + "/" + name)
                }
                let restored=try await fresh().restore(batchID:moved.id)
                XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
                XCTAssertEqual(try consume("--read"),"524288")
                XCTAssertTrue(FileManager.default.fileExists(atPath:newGeneration + "/Cache.db"))
            }
        }
        XCTAssertEqual(try SafeDirectory(path:root).ownIdentity.inode,original.identity.inode)
        try SafeFilesystem.verify(originalApp)
    }
    func testOversizedCacheGroupIsRetainedInsteadOfOfferingAnUnexecutablePlan() throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let root=try namespace(f)
        for i in 0..<1000 { try Data().write(to:URL(fileURLWithPath:root + "/entry-" + String(i)),options:.withoutOverwriting) }
        let report=try Scanner(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[rule])).junk(indexLookup:{_ in []}).report
        XCTAssertFalse(report.selectableCandidates(includeUserData:false).contains { $0.path.hasPrefix(root + "/") },"A mandatory group larger than the 1000-item plan limit must not look executable")
    }
    func testDefaultUserContextRetainsUnattributedRegisteredNamespace() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_USER_CACHE_DEFAULT_ACCEPTANCE"] == "AppSweep-General-20261016" else { throw XCTSkip("Explicit disposable VM default-context acceptance only") }
        guard getuid() == 501, try SystemIdentity.home() == "/Users/localtest",
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).trimmingCharacters(in:.whitespacesAndNewlines) == "VirtualMac2,1" else { throw SweepError.denied("Default user-cache acceptance requires the registered disposable VM") }
        let task="/Users/localtest/AppSweepAcceptanceGeneral-20261016"
        let info=try XCTUnwrap(try JSONSerialization.jsonObject(with:Data(contentsOf:URL(fileURLWithPath:task + "/user-cache-default-current.json"))) as? [String:Any])
        let root=try XCTUnwrap(info["path"] as? String),name=URL(fileURLWithPath:root).lastPathComponent
        guard root == "/Users/localtest/Library/Caches/" + name, name.hasPrefix("DisposableCache-"), UUID(uuidString:String(name.dropFirst("DisposableCache-".count))) != nil else { throw SweepError.denied("Default acceptance fixture path is not its exact private namespace") }
        let before=try SafeFilesystem.snapshot(root)
        XCTAssertEqual(before.identity.inode,try XCTUnwrap(info["inode"] as? NSNumber).uint64Value)
        XCTAssertEqual(before.identity.device,try XCTUnwrap(info["device"] as? NSNumber).uint64Value)
        XCTAssertEqual(try String(contentsOfFile:root + "/index",encoding:.utf8),"registered disposable index")
        XCTAssertEqual(try String(contentsOfFile:root + "/objects/data",encoding:.utf8),"registered disposable payload")
        let report=try await SweepEngine().scanJunk()
        XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains { $0.path == root || $0.path.hasPrefix(root + "/") })
        try SafeFilesystem.verify(before)
        XCTAssertEqual(try String(contentsOfFile:root + "/index",encoding:.utf8),"registered disposable index")
        XCTAssertEqual(try String(contentsOfFile:root + "/objects/data",encoding:.utf8),"registered disposable payload")

    }
}
#endif
