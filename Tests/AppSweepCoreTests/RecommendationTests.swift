import Foundation
import XCTest
@testable import AppSweepCore
#if os(macOS)
@testable import AppSweepApp
#endif

final class RecommendationTests: XCTestCase {
    private func candidate(execute: Bool = true, category: CandidateCategory = .cache, reason: String? = nil) -> Candidate {
        Candidate(id:UUID(),path:"/fixture/cache/payload",category:category,bundleIdentifier:"org.example.selection",evidence:[.init(kind:.validatedRule,detail:"independent fixture",verified:true)],rule:"fixture-v1",identity:FileIdentity(device:1,inode:10,mode:0o100600,owner:501,links:1,size:64,modifiedSeconds:1,modifiedNanoseconds:0,changedSeconds:1,changedNanoseconds:0),bytes:64,retentionReason:reason,executionAllowed:execute)
    }
    private func decoded(_ item: Candidate, recommendation: String) throws -> Candidate {
        var json = try XCTUnwrap(JSONSerialization.jsonObject(with:JSONEncoder().encode(item)) as? [String:Any])
        json["recommendation"] = recommendation
        json["selectedByDefault"] = true
        return try JSONDecoder().decode(Candidate.self,from:JSONSerialization.data(withJSONObject:json))
    }
    func testPreviewOnlyCandidateRequiresManualSelectionWithoutLosingReviewCapability() {
        let item = candidate(execute:false)
        XCTAssertFalse(item.selectedByDefault)
        XCTAssertEqual(item.allowedActions,[.report,.reviewPlan])
    }
    func testManualRecommendationDoesNotRemoveExplicitSelectionOrGrantPermission() throws {
        let item = try decoded(candidate(),recommendation:"manual")
        XCTAssertFalse(item.selectedByDefault)
        XCTAssertEqual(item.allowedActions,[.report,.reviewPlan,.isolate])
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with:JSONEncoder().encode(item)) as? [String:Any])
        XCTAssertEqual(json["recommendation"] as? String,"manual")
    }
    func testRecommendationCannotOverridePersonalDataOrRetention() throws {
        XCTAssertFalse(try decoded(candidate(category:.deviceBackup),recommendation:"recommended").selectedByDefault)
        XCTAssertFalse(try decoded(candidate(category:.userData),recommendation:"recommended").selectedByDefault)
        let retained = try decoded(candidate(reason:"ownership unknown"),recommendation:"recommended")
        XCTAssertFalse(retained.selectedByDefault)
        XCTAssertEqual(retained.allowedActions,[.report])
    }
    func testUnknownRecommendationCannotBeDecodedAsRecommended() {
        XCTAssertThrowsError(try decoded(candidate(),recommendation:"forceEverything"))
    }
    func testLegacyCandidateWithoutRecommendationKeepsSafeCategoryDefault() throws {
        let normal = try JSONDecoder().decode(Candidate.self,from:JSONEncoder().encode(candidate()))
        XCTAssertTrue(normal.selectedByDefault)
        XCTAssertNil(normal.recommendation)
        XCTAssertFalse(candidate(category:.protected).selectedByDefault)
    }
    private func report(_ items: [Candidate]) -> ScanReport {
        ScanReport(schemaVersion:1,id:UUID(),createdAt:Date(),ruleVersion:SweepEngine.ruleVersion,applicationPath:nil,candidates:items,complete:true,issues:[],platformLimitation:nil)
    }
    private func member(_ name: String, manual: Bool) -> Candidate {
        Candidate(id:UUID(),path:"/fixture/cache/" + name,category:.cache,bundleIdentifier:"org.example.selection",evidence:[.init(kind:.validatedRule,detail:"independent group",verified:true)],rule:CacheDomainRule.name,identity:candidate().identity,bytes:64,retentionReason:nil,executionAllowed:true,recommendation:manual ? .manual : .recommended)
    }
    func testOneManualMemberKeepsEntireCacheGroupOutOfRecommendations() {
        let database = member("Cache.db",manual:false), journal = member("Cache.db-wal",manual:true)
        let scan = report([database,journal])
        XCTAssertTrue(scan.recommendedSelectionIDs().isEmpty)
        XCTAssertEqual(scan.selectionIDs(for:journal.id,includeUserData:false),[database.id,journal.id],"Manual selection still selects the coherent cache group")
        let recommendedJournal = member("Cache.db-wal",manual:false)
        XCTAssertEqual(report([database,recommendedJournal]).recommendedSelectionIDs(),[database.id,recommendedJournal.id])
    }
    func testFailedIndependentScopeDoesNotEraseVerifiedRecommendations() {
        var good = candidate(), bad = candidate()
        good.scanScopeID = "verified"; bad.scanScopeID = "unknown"
        // Distinct roots matter: an overlapping failed scope correctly blocks
        // its dependants and is covered by SelectionTests.
        bad = Candidate(id:bad.id,path:"/fixture/unknown/item",category:bad.category,bundleIdentifier:bad.bundleIdentifier,scanScopeID:"unknown",evidence:bad.evidence,rule:bad.rule,identity:bad.identity,bytes:bad.bytes,retentionReason:nil,executionAllowed:true)
        let scan = ScanReport(schemaVersion:2,id:UUID(),createdAt:Date(),ruleVersion:SweepEngine.ruleVersion,applicationPath:nil,candidates:[good,bad],complete:false,issues:["permission denied"],platformLimitation:nil,scopes:[
            .init(id:"verified",root:"/fixture/cache",complete:true,candidateIDs:[good.id],issues:[]),
            .init(id:"unknown",root:"/fixture/unknown",complete:false,candidateIDs:[bad.id],issues:["permission denied"])
        ])
        XCTAssertEqual(scan.recommendedSelectionIDs(),[good.id])
    }
    #if os(macOS)
    @MainActor
    func testGUIRecommendationsReplaceSelectionButKeepManualChoiceAvailable() throws {
        let normal = candidate(), manual = try decoded(candidate(),recommendation:"manual"), preview = candidate(execute:false), personal = candidate(category:.deviceBackup)
        let scan = report([normal,manual,preview,personal])
        let store = SweepStore()
        store.workspace = .junk
        store.includeUserData = true
        store.overview = .init(id:UUID(),sections:[.init(source:.user,report:scan,issue:nil)])
        store.selected = [personal.id,manual.id,preview.id]
        store.plan = .init(schemaVersion:1,id:UUID(),reportID:scan.id,createdAt:Date(),ruleVersion:SweepEngine.ruleVersion,items:[manual],includeUserData:true)
        store.combinedReview = .init(id:UUID(),overviewID:store.overview!.id,items:[manual],retainedIssues:[])
        store.selectRecommended()
        XCTAssertEqual(store.selected,[normal.id])
        XCTAssertNil(store.plan); XCTAssertNil(store.combinedReview)
        store.select(manual,enabled:true)
        XCTAssertEqual(store.selected,[normal.id,manual.id])
        store.clearSelection()
        XCTAssertTrue(store.selected.isEmpty)
        // Uninstall uses its own current report, not an old junk overview.
        store.workspace = .uninstall; store.report = report([manual])
        store.selectRecommended()
        XCTAssertTrue(store.selected.isEmpty)
        store.select(manual,enabled:true)
        XCTAssertEqual(store.selected,[manual.id])
    }
    @MainActor
    func testGUISelectionActionsLeaveBusyOperationUnchanged() {
        let normal = candidate(), scan = report([normal]), store = SweepStore()
        store.workspace = .uninstall; store.report = scan; store.selected = [normal.id]
        store.plan = .init(schemaVersion:1,id:UUID(),reportID:scan.id,createdAt:Date(),ruleVersion:SweepEngine.ruleVersion,items:[normal],includeUserData:false)
        let planID = store.plan?.id
        store.busy = true
        store.clearSelection(); store.selectRecommended()
        XCTAssertEqual(store.selected,[normal.id]); XCTAssertEqual(store.plan?.id,planID)
    }
    #endif
}
