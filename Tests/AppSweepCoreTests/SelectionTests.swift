import XCTest
@testable import AppSweepCore

final class SelectionTests: XCTestCase {
    private func candidate(_ category: CandidateCategory = .cache, reason: String? = nil, review: Bool = true, execute: Bool = true) -> Candidate {
        Candidate(id: UUID(), path: "/fixture/" + UUID().uuidString, category: category, bundleIdentifier: "org.example.fixture", evidence: [.init(kind: .validatedRule, detail: "fixture", verified: true)], rule: "fixture-v1", identity: FileIdentity(device: 1, inode: 1, mode: 0o100600, owner: 501, links: 1, size: 10, modifiedSeconds: 1, modifiedNanoseconds: 0, changedSeconds: 1, changedNanoseconds: 0), bytes: 10, retentionReason: reason, allowsPlanReview: review, executionAllowed: execute)
    }
    private func report(_ items: [Candidate], complete: Bool = true) -> ScanReport {
        ScanReport(schemaVersion: 1, id: UUID(), createdAt: Date(), ruleVersion: SweepEngine.ruleVersion, applicationPath: nil, candidates: items, complete: complete, issues: complete ? [] : ["incomplete"], platformLimitation: nil)
    }
    func testMixedReportOnlySelectsReviewableCandidates() {
        let eligible = candidate(), retained = candidate(reason: "unknown"), blocked = candidate(review: false)
        XCTAssertEqual(report([eligible, retained, blocked]).selectableCandidates(includeUserData: false).map(\.id), [eligible.id])
    }
    func testUserDataRequiresExplicitOptIn() {
        let cache = candidate(), data = candidate(.userData)
        let scan = report([cache, data])
        XCTAssertEqual(scan.selectableCandidates(includeUserData: false).map(\.id), [cache.id])
        XCTAssertEqual(scan.selectableCandidates(includeUserData: true).map(\.id), [cache.id, data.id])
    }
    func testIncompleteReportHasNoSelectableCandidates() {
        XCTAssertTrue(report([candidate()], complete: false).selectableCandidates(includeUserData: true).isEmpty)
    }
    private func scopedReport(_ items: [Candidate], membership: [String], scopes: [[String: Any]], overallComplete: Bool = false) throws -> ScanReport {
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with:JSONEncoder().encode(report(items,complete:false))) as? [String:Any])
        var candidates = try XCTUnwrap(object["candidates"] as? [[String:Any]])
        for index in candidates.indices { candidates[index]["scanScopeID"] = membership[index] }
        object["schemaVersion"] = 2; object["candidates"] = candidates; object["scopes"] = scopes; object["complete"] = overallComplete
        return try JSONDecoder().decode(ScanReport.self,from:JSONSerialization.data(withJSONObject:object))
    }
    func testPartialReportOffersOnlyMembersOfOneVerifiedScope() throws {
        let eligible=candidate(), blocked=candidate(), unlisted=candidate()
        let scan=try scopedReport([eligible,blocked,unlisted],membership:["cache-a","cache-b","cache-a"],scopes:[
            ["id":"cache-a","root":"/fixture/a","complete":true,"candidateIDs":[eligible.id.uuidString],"issues":[]],
            ["id":"cache-b","root":"/fixture/b","complete":false,"candidateIDs":[blocked.id.uuidString],"issues":["access denied"]]
        ])
        XCTAssertFalse(scan.complete)
        XCTAssertEqual(scan.selectableCandidates(includeUserData:false).map(\.id),[eligible.id])
    }
    func testScopeWithIssuesCannotAuthorizeEvenIfMarkedComplete() throws {
        let item=candidate()
        let scan=try scopedReport([item],membership:["a"],scopes:[["id":"a","root":"/fixture/a","complete":true,"candidateIDs":[item.id.uuidString],"issues":["truncated"]]])
        XCTAssertTrue(scan.selectableCandidates(includeUserData:true).isEmpty)
    }
    func testFailedOverlappingScopeBlocksAnOtherwiseVerifiedCandidate() throws {
        let item=candidate()
        let scan=try scopedReport([item],membership:["a"],scopes:[
            ["id":"a","root":item.path,"complete":true,"candidateIDs":[item.id.uuidString],"issues":[]],
            ["id":"b","root":"/fixture","complete":false,"candidateIDs":[],"issues":["truncated parent"]]
        ])
        XCTAssertTrue(scan.selectableCandidates(includeUserData:true).isEmpty)
    }
    func testDuplicateScopeMembershipCannotAuthorizeSelection() throws {
        let item=candidate()
        let scan=try scopedReport([item],membership:["a"],scopes:[
            ["id":"a","root":"/fixture/a","complete":true,"candidateIDs":[item.id.uuidString],"issues":[]],
            ["id":"b","root":"/fixture/b","complete":true,"candidateIDs":[item.id.uuidString],"issues":[]]
        ])
        XCTAssertTrue(scan.selectableCandidates(includeUserData:true).isEmpty)
    }
    func testOnlyRegisteredVerifiedPartialScopeCanIssuePlan() async throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let scan=try scopedReport([f.candidate],membership:["a"],scopes:[["id":"a","root":f.source,"complete":true,"candidateIDs":[f.candidate.id.uuidString],"issues":[]]])
        let engine=f.engine()
        do { _ = try await engine.makePlan(reportID:scan.id,selected:[f.candidate.id],includeUserData:false); XCTFail("Decoded scope is not engine authority") } catch { }
        await engine.register(scan,snapshots:[f.candidate.id:f.snapshot])
        let plan=try await engine.makePlan(reportID:scan.id,selected:[f.candidate.id],includeUserData:false)
        XCTAssertEqual(plan.items.map(\.id),[f.candidate.id])
        do { _ = try await engine.makePlan(reportID:scan.id,selected:[UUID()],includeUserData:false); XCTFail("Unlisted candidate must be refused") } catch { }
    }
    func testIncompleteScopeCannotIssuePlanEvenWhenOverallFlagIsTrue() async throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let scan=try scopedReport([f.candidate],membership:["a"],scopes:[["id":"a","root":f.source,"complete":false,"candidateIDs":[f.candidate.id.uuidString],"issues":["access denied"]]],overallComplete:true)
        let engine=f.engine(); await engine.register(scan,snapshots:[f.candidate.id:f.snapshot])
        do { _ = try await engine.makePlan(reportID:scan.id,selected:[f.candidate.id],includeUserData:false); XCTFail("Overall flag cannot override failed dependency scope") } catch { }
    }
    func testPlanAndRecoveryRecordKeepUnconfirmedScopeWarnings() async throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let scan=try scopedReport([f.candidate],membership:["a"],scopes:[
            ["id":"a","root":f.source,"complete":true,"candidateIDs":[f.candidate.id.uuidString],"issues":[]],
            ["id":"b","root":f.home + "/Library/Preferences","complete":false,"candidateIDs":[],"issues":["access denied"]]
        ])
        let engine=f.engine(); await engine.register(scan,snapshots:[f.candidate.id:f.snapshot])
        let plan=try await engine.makePlan(reportID:scan.id,selected:[f.candidate.id],includeUserData:false)
        let encoded=try XCTUnwrap(JSONSerialization.jsonObject(with:JSONEncoder().encode(plan)) as? [String:Any])
        XCTAssertEqual(encoded["retainedIssues"] as? [String],["access denied","incomplete"])
        let moved=try await engine.execute(planID:plan.id)
        XCTAssertEqual(moved.status,.isolated)
        let readBack=try await engine.recoveryBatches()
        let batch=try XCTUnwrap(readBack.first)
        let saved=try XCTUnwrap(JSONSerialization.jsonObject(with:JSONEncoder().encode(batch)) as? [String:Any])
        XCTAssertEqual(saved["retainedIssues"] as? [String],["access denied","incomplete"])
        let restored=try await engine.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:f.source + "/data")),Data("regenerable".utf8))
    }
    func testReadOnlyCandidateCanBePreviewedWithoutIsolationAction() {
        let item = candidate(execute: false)
        XCTAssertEqual(report([item]).selectableCandidates(includeUserData: false).map(\.id), [item.id])
        XCTAssertFalse(item.allowedActions.contains(.isolate))
    }
    func testLargeResponseReportCanBeSelectedWithinInteractiveBudget() throws {
        let items = (0..<10_000).map { _ in candidate() }
        let scan = try scopedReport(items, membership: Array(repeating: "cache", count: items.count), scopes: [
            ["id": "cache", "root": "/fixture", "complete": true, "candidateIDs": items.map { $0.id.uuidString }, "issues": []]
        ])
        let start = Date()
        XCTAssertEqual(scan.selectableCandidates(includeUserData: false).count, items.count)
        XCTAssertLessThan(Date().timeIntervalSince(start), 3, "A supported response cache must not stall selection on the main actor")
    }
}
