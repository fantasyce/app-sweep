import Foundation
import XCTest
import CFSafety
@testable import AppSweepCore
#if os(macOS)
@testable import AppSweepApp
#endif

final class CleanupCategoryIgnoreTests: XCTestCase, @unchecked Sendable {
    private func data(schema: Int = 2, revision: UUID = UUID(), categories: [String]?, paths: [String] = []) throws -> Data {
        var json: [String:Any] = ["schemaVersion":schema,"revision":revision.uuidString,"paths":paths]
        if let categories { json["categories"] = categories }
        return try JSONSerialization.data(withJSONObject:json)
    }
    private func persist(_ data: Data, home: String) throws {
        let path = home + "/Library/Application Support/App Sweep/Settings.noindex"
        try FileManager.default.createDirectory(atPath:path,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
        try SafeDirectory(path:path).write(data,name:"cleanup-ignores.json")
    }
    // A reader that silently drops category restrictions would make retained cache selectable.
    func testCategoryRestrictionSurvivesLoadingAndProtectsOnlyItsCategory() async throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        try persist(data(categories:["cache"]),home:f.home)
        let engine = f.engine(), scan = await engine.adoptFixture([f.candidate],snapshots:[f.candidate.id:f.snapshot])
        XCTAssertTrue(scan.selectableCandidates(includeUserData:true).isEmpty)
        XCTAssertNotNil(scan.candidates.first?.ignoredReason)
        let list = try await engine.cleanupIgnores()
        let other = Candidate(id:UUID(),path:f.home + "/unrelated.log",category:.log,bundleIdentifier:f.candidate.bundleIdentifier,
                              evidence:f.candidate.evidence,rule:f.candidate.rule,identity:f.snapshot.identity,bytes:10,retentionReason:nil,executionAllowed:true)
        let report = ScanReport(schemaVersion:1,id:UUID(),createdAt:Date(),ruleVersion:SweepEngine.ruleVersion,applicationPath:nil,
                                candidates:[other],complete:true,issues:[],platformLimitation:nil)
        XCTAssertNil(list.applying(to:report).candidates.first?.ignoredReason)
        do { _ = try await engine.makePlan(reportID:scan.id,selected:[f.candidate.id],includeUserData:false); XCTFail("Category restriction bypassed") } catch { }
        XCTAssertTrue(FileManager.default.fileExists(atPath:f.source + "/data"))
        XCTAssertFalse(FileManager.default.fileExists(atPath:f.vault))
    }
    // Legacy readers must not mistake a policy carrying new restrictions for a path-only list.
    func testLegacyPolicyCannotSmuggleCategoryRestrictionsPastVersionValidation() throws {
        let list = try JSONDecoder().decode(CleanupIgnoreList.self,from:data(schema:1,categories:["cache"]))
        XCTAssertThrowsError(try list.validate())
        let legacy = try JSONDecoder().decode(CleanupIgnoreList.self,from:data(schema:1,categories:nil,paths:["/fixture/keep"]))
        XCTAssertNoThrow(try legacy.validate())
        XCTAssertNotNil(legacy.reason(for:"/fixture/keep/file"))
    }
    func testMalformedCategoryPoliciesCannotBecomeEmptyRestrictions() async throws {
        for categories in [nil,["cache","cache"],["not-a-category"],["application"],["protected"]] as [[String]?] {
            let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
            try persist(data(categories:categories),home:f.home)
            do { _ = try await f.engine().cleanupIgnores(); XCTFail("Malformed policy accepted: \(String(describing:categories))") } catch { }
            XCTAssertTrue(FileManager.default.fileExists(atPath:f.source + "/data"))
        }
    }
    // Changing category content while reusing the revision must still invalidate a reviewed plan.
    func testSameRevisionCategoryChangeBlocksExecutionWithoutBlockingRecovery() async throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let revision = UUID()
        try persist(data(revision:revision,categories:[]),home:f.home)
        let engine = f.engine(), scan = await engine.adoptFixture([f.candidate],snapshots:[f.candidate.id:f.snapshot])
        let plan = try await engine.makePlan(reportID:scan.id,selected:[f.candidate.id],includeUserData:false)
        try persist(data(revision:revision,categories:["cache"]),home:f.home)
        do { _ = try await engine.execute(planID:plan.id); XCTFail("Changed restriction bypassed") } catch { }
        XCTAssertTrue(FileManager.default.fileExists(atPath:f.source + "/data"))
        XCTAssertFalse(FileManager.default.fileExists(atPath:f.vault))
        try persist(data(categories:[]),home:f.home)
        let fresh = f.engine(), rescan = await fresh.adoptFixture([f.candidate],snapshots:[f.candidate.id:f.snapshot])
        let reviewed = try await fresh.makePlan(reportID:rescan.id,selected:[f.candidate.id],includeUserData:false)
        let batch = try await fresh.execute(planID:reviewed.id)
        try persist(data(categories:["cache"]),home:f.home)
        let restored = try await f.engine().restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:f.source + "/data")),Data("regenerable".utf8))
    }
    func testChangingPathsNeverErasesAnExistingCategoryRestriction() async throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        try persist(data(categories:["cache"]),home:f.home)
        let engine = f.engine(), old = try await engine.cleanupIgnores()
        let added = try await engine.addCleanupIgnore(path:f.home + "/keep.log",expectedRevision:old.revision)
        let removed = try await engine.removeCleanupIgnore(path:f.home + "/keep.log",expectedRevision:added.revision)
        let scan = await engine.adoptFixture([f.candidate],snapshots:[f.candidate.id:f.snapshot])
        XCTAssertTrue(scan.selectableCandidates(includeUserData:true).isEmpty)
        XCTAssertNotNil(scan.candidates.first?.ignoredReason)
        XCTAssertNotNil(removed.reason(for:f.candidate))
    }
    func testCategoryWriterPreservesLegacyPathsChecksRevisionAndRequiresRescan() async throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        try persist(data(schema:1,categories:nil,paths:[f.home + "/keep"]),home:f.home)
        let engine = f.engine(), old = try await engine.cleanupIgnores()
        let scan = await engine.adoptFixture([f.candidate],snapshots:[f.candidate.id:f.snapshot])
        let added = try await engine.setCleanupCategoryIgnored(.cache,ignored:true,expectedRevision:old.revision)
        XCTAssertEqual(added.paths,[f.home + "/keep"])
        XCTAssertEqual(added.categories,[.cache])
        let loaded = try await f.engine().cleanupIgnores(); XCTAssertEqual(loaded,added)
        let noOp = try await engine.setCleanupCategoryIgnored(.cache,ignored:true,expectedRevision:added.revision)
        XCTAssertEqual(noOp,added)
        do { _ = try await engine.setCleanupCategoryIgnored(.cache,ignored:false,expectedRevision:old.revision); XCTFail("Stale writer removed a restriction") } catch { }
        for category in [CandidateCategory.application,.protected] {
            do { _ = try await engine.setCleanupCategoryIgnored(category,ignored:true,expectedRevision:added.revision); XCTFail("Unsupported category accepted") } catch { }
        }
        do { _ = try await engine.makePlan(reportID:scan.id,selected:[f.candidate.id],includeUserData:false); XCTFail("Old scan reused") } catch { }
        let removed = try await engine.setCleanupCategoryIgnored(.cache,ignored:false,expectedRevision:added.revision)
        XCTAssertEqual(removed.paths,[f.home + "/keep"]); XCTAssertTrue(removed.categories.isEmpty)
        let rescanned = await engine.adoptFixture([f.candidate],snapshots:[f.candidate.id:f.snapshot])
        let plan = try await engine.makePlan(reportID:rescanned.id,selected:[f.candidate.id],includeUserData:false)
        XCTAssertEqual(plan.items.map(\.id),[f.candidate.id])
    }
    func testCategoryWriterCannotRaceAnExecutionLease() throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let store = CleanupIgnoreStore(home:f.home,ownerUID:as_current_uid()), old = try store.read()
        try withExtendedLifetime(store.executionLease(old)) {
            XCTAssertThrowsError(try store.update(category:.cache,ignored:true,expectedRevision:old.revision))
            XCTAssertFalse(FileManager.default.fileExists(atPath:f.home + "/Library/Application Support/App Sweep/Settings.noindex"))
        }
        let added = try store.update(category:.cache,ignored:true,expectedRevision:old.revision)
        try withExtendedLifetime(store.executionLease(added)) {
            XCTAssertThrowsError(try store.update(category:.cache,ignored:false,expectedRevision:added.revision))
            XCTAssertEqual(try store.read(),added)
        }
    }
    #if os(macOS)
    @MainActor
    func testGUICategoryChangeInvalidatesBothWorkflowsAndRetainsPaths() async throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let engine = f.engine(), old = try await engine.cleanupIgnores()
        _ = try await engine.addCleanupIgnore(path:f.home + "/keep",expectedRevision:old.revision)
        let scan = await engine.adoptFixture([f.candidate],snapshots:[f.candidate.id:f.snapshot])
        let store = SweepStore(engine:engine)
        store.loadIgnores()
        let limit = ProcessInfo.processInfo.systemUptime + 10
        while store.busy && ProcessInfo.processInfo.systemUptime < limit { try await Task.sleep(for:.milliseconds(25)) }
        XCTAssertFalse(store.busy)
        store.report = scan; store.selected = [f.candidate.id]
        store.overview = .init(id:UUID(),sections:[.init(source:.user,report:scan,issue:nil)])
        store.plan = try await engine.makePlan(reportID:scan.id,selected:[f.candidate.id],includeUserData:false)
        store.combinedReview = .init(id:UUID(),overviewID:store.overview!.id,items:[f.candidate],retainedIssues:[])
        store.setCategoryIgnored(.cache,ignored:true)
        let changedLimit = ProcessInfo.processInfo.systemUptime + 10
        while store.busy && ProcessInfo.processInfo.systemUptime < changedLimit { try await Task.sleep(for:.milliseconds(25)) }
        XCTAssertFalse(store.busy); XCTAssertFalse(store.error,store.message)
        XCTAssertEqual(store.ignoreList?.categories,[.cache]); XCTAssertEqual(store.ignoreList?.paths,[f.home + "/keep"])
        XCTAssertNil(store.report); XCTAssertNil(store.overview); XCTAssertNil(store.plan); XCTAssertNil(store.combinedReview)
        XCTAssertTrue(store.selected.isEmpty)
        // A second instance's newer restriction must survive a stale UI toggle.
        _ = try await f.engine().addCleanupIgnore(path:f.home + "/newer",expectedRevision:store.ignoreList!.revision)
        store.setCategoryIgnored(.cache,ignored:false)
        let staleLimit = ProcessInfo.processInfo.systemUptime + 10
        while store.busy && ProcessInfo.processInfo.systemUptime < staleLimit { try await Task.sleep(for:.milliseconds(25)) }
        XCTAssertFalse(store.busy); XCTAssertTrue(store.error)
        let kept = try await engine.cleanupIgnores(); XCTAssertEqual(kept.categories,[.cache]); XCTAssertTrue(kept.paths.contains(f.home + "/newer"))
    }
    func testCLIExposesCategoryRestrictionsAndRejectsAmbiguousInputs() throws {
        let executable = Bundle(for:Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("app-sweep").path
        let help = try BoundedProcess.capture(executable,arguments:["--help"],timeout:10,mergeStderr:true)
        XCTAssertEqual(help.status,0); XCTAssertTrue(help.text.contains("--category CATEGORY"))
        for arguments in [["ignore-add","--category","not-a-category"],["ignore-remove","--category","application"],
                          ["ignore-add","--category","cache","--path","/System"],["ignore-list","--category","cache"]] {
            let result = try BoundedProcess.capture(executable,arguments:arguments,timeout:10,mergeStderr:true)
            XCTAssertNotEqual(result.status,0)
        }
    }
    #endif
}
