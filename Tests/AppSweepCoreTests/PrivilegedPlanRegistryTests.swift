import Foundation
import XCTest
@testable import AppSweepCore

final class PrivilegedPlanRegistryTests: XCTestCase {
    let peer = AuthenticatedLocalPeer(uid: 501, pid: 123, auditToken: Data(repeating: 7, count: 32))
    let nonce = Data(repeating: 8, count: 32)
    func report() -> ScanReport {
        let identity = FileIdentity(device: 1, inode: 2, mode: 0o100600, owner: 0, links: 1, size: 5, modifiedSeconds: 1, modifiedNanoseconds: 0, changedSeconds: 1, changedNanoseconds: 0)
        let item = Candidate(id: UUID(), path: "/Library/Logs/org.example.fixture/old.log", category: .log,
                             bundleIdentifier: "org.example.fixture", evidence: [.init(kind: .bundleIdentifier, detail: "fixture", verified: true)],
                             rule: "system-log-v1", identity: identity, bytes: 5, retentionReason: nil, executionAllowed: true)
        return ScanReport(schemaVersion: 1, id: UUID(), createdAt: Date(), ruleVersion: SweepEngine.ruleVersion,
                          applicationPath: nil, candidates: [item], complete: true, issues: [], platformLimitation: nil)
    }
    func testOnlyRegisteredScanIDsAndExactSelectionsCanIssueOneUsePlan() throws {
        var registry = try PrivilegedPlanRegistry(peer: peer, nonce: nonce)
        let scan = report(), ids = scan.candidates.map(\.id)
        XCTAssertThrowsError(try registry.review(scanID: scan.id, selected: ids, peer: peer, nonce: nonce, uptime: 10))
        try registry.register(scan, peer: peer, nonce: nonce, uptime: 10)
        XCTAssertThrowsError(try registry.review(scanID: UUID(), selected: ids, peer: peer, nonce: nonce, uptime: 11))
        XCTAssertThrowsError(try registry.review(scanID: scan.id, selected: [UUID()], peer: peer, nonce: nonce, uptime: 11))
        XCTAssertThrowsError(try registry.review(scanID: scan.id, selected: ids + ids, peer: peer, nonce: nonce, uptime: 11))
        let plan = try registry.review(scanID: scan.id, selected: ids, peer: peer, nonce: nonce, uptime: 11)
        XCTAssertEqual(plan.items, scan.candidates)
        XCTAssertFalse(plan.includeUserData)
        XCTAssertEqual(try registry.consume(planID: plan.id, peer: peer, nonce: nonce, uptime: 12).id, plan.id)
        XCTAssertThrowsError(try registry.consume(planID: plan.id, peer: peer, nonce: nonce, uptime: 12))
    }
    func testEnginePlanRegistrationPreservesItsIDAndRejectsAlteredEvidenceOrPaths() throws {
        var registry = try PrivilegedPlanRegistry(peer:peer,nonce:nonce)
        let scan = report(), item = try XCTUnwrap(scan.candidates.first)
        try registry.register(scan,peer:peer,nonce:nonce,uptime:10)
        func plan(_ items: [Candidate], includeUserData: Bool = false, issues: [String]? = nil) -> CleanupPlan {
            .init(schemaVersion:1,id:UUID(),reportID:scan.id,createdAt:Date(),ruleVersion:scan.ruleVersion,items:items,includeUserData:includeUserData,retainedIssues:issues)
        }
        let changed = Candidate(id:item.id,path:"/Library/Logs/org.example.other/old.log",category:item.category,
                                bundleIdentifier:item.bundleIdentifier,evidence:item.evidence,rule:item.rule,identity:item.identity,
                                bytes:item.bytes,retentionReason:nil,executionAllowed:true)
        for forged in [plan([changed]),plan([item,item]),plan([item],includeUserData:true),plan([item],issues:["altered scope evidence"])] {
            XCTAssertThrowsError(try registry.registerReviewed(forged,peer:peer,nonce:nonce,uptime:11))
        }
        let actual = plan([item])
        try registry.registerReviewed(actual,peer:peer,nonce:nonce,uptime:11)
        XCTAssertThrowsError(try registry.registerReviewed(actual,peer:peer,nonce:nonce,uptime:11))
        let accepted = try registry.consume(planID:actual.id,peer:peer,nonce:nonce,uptime:12)
        XCTAssertEqual(accepted.id,actual.id)
        XCTAssertEqual(accepted.items,actual.items)
    }
    func testPeerSessionRuleAndMonotonicExpiryCannotBeSubstituted() throws {
        var registry = try PrivilegedPlanRegistry(peer: peer, nonce: nonce)
        let scan = report(), ids = scan.candidates.map(\.id)
        try registry.register(scan, peer: peer, nonce: nonce, uptime: 100)
        let other = AuthenticatedLocalPeer(uid: peer.uid, pid: peer.pid, auditToken: Data(repeating: 6, count: 32))
        XCTAssertThrowsError(try registry.review(scanID: scan.id, selected: ids, peer: other, nonce: nonce, uptime: 101))
        XCTAssertThrowsError(try registry.review(scanID: scan.id, selected: ids, peer: peer, nonce: Data(repeating: 9, count: 32), uptime: 101))
        XCTAssertThrowsError(try registry.review(scanID: scan.id, selected: ids, peer: peer, nonce: nonce, uptime: 99))
        let plan = try registry.review(scanID: scan.id, selected: ids, peer: peer, nonce: nonce, uptime: 101)
        XCTAssertThrowsError(try registry.consume(planID: plan.id, peer: other, nonce: nonce, uptime: 102))
        XCTAssertEqual(try registry.consume(planID: plan.id, peer: peer, nonce: nonce, uptime: 102).id, plan.id)
        XCTAssertThrowsError(try registry.review(scanID: scan.id, selected: ids, peer: peer, nonce: nonce, uptime: 400))
    }
    func testPlanExpiryAndSessionCapacityAreBounded() throws {
        var registry = try PrivilegedPlanRegistry(peer: peer, nonce: nonce)
        let scan = report(), ids = scan.candidates.map(\.id)
        try registry.register(scan, peer: peer, nonce: nonce, uptime: 10)
        for _ in 0..<3 { try registry.register(report(), peer: peer, nonce: nonce, uptime: 10) }
        XCTAssertThrowsError(try registry.register(report(), peer: peer, nonce: nonce, uptime: 10))
        var plans: [CleanupPlan] = []
        for _ in 0..<8 { plans.append(try registry.review(scanID: scan.id, selected: ids, peer: peer, nonce: nonce, uptime: 11)) }
        XCTAssertThrowsError(try registry.review(scanID: scan.id, selected: ids, peer: peer, nonce: nonce, uptime: 11))
        XCTAssertEqual(try registry.consume(planID: plans[0].id, peer: peer, nonce: nonce, uptime: 12).id, plans[0].id)
        _ = try registry.review(scanID: scan.id, selected: ids, peer: peer, nonce: nonce, uptime: 12)
        XCTAssertThrowsError(try registry.consume(planID: plans[1].id, peer: peer, nonce: nonce, uptime: 311))
        try registry.register(report(), peer: peer, nonce: nonce, uptime: 311)
    }
    func testUnconfirmedScopesAndUnsupportedRulesCannotIssueExecutablePlan() throws {
        var registry = try PrivilegedPlanRegistry(peer: peer, nonce: nonce)
        let original = report()
        let stale = ScanReport(schemaVersion: 1, id: UUID(), createdAt: Date(), ruleVersion: "old-rule",
                               applicationPath: nil, candidates: original.candidates, complete: true, issues: [], platformLimitation: nil)
        XCTAssertThrowsError(try registry.register(stale, peer: peer, nonce: nonce, uptime: 10))
        let incomplete = ScanReport(schemaVersion: 1, id: UUID(), createdAt: Date(), ruleVersion: SweepEngine.ruleVersion,
                                    applicationPath: nil, candidates: original.candidates, complete: false, issues: ["permission unknown"], platformLimitation: nil)
        try registry.register(incomplete, peer: peer, nonce: nonce, uptime: 10)
        XCTAssertThrowsError(try registry.review(scanID: incomplete.id, selected: incomplete.candidates.map(\.id), peer: peer, nonce: nonce, uptime: 11))
    }
}
