#if os(macOS)
import XCTest
@testable import AppSweepCore
@testable import AppSweepApp

final class WorkspaceFlowTests: XCTestCase {
    @MainActor
    func testRecoveryRetainsResultsAndInvalidatesOnlyRelatedCandidates() throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        var related = f.candidate
        related.applicationPath = "/fixture/Applications/One.app"
        var unrelated = Candidate.fixture(path: "/fixture/Library/Caches/other/value", userData: false)
        unrelated.applicationPath = "/fixture/Applications/Other.app"
        let scan = ScanReport(schemaVersion: 1, id: UUID(), createdAt: Date(), ruleVersion: SweepEngine.ruleVersion,
                              applicationPath: nil, candidates: [related, unrelated], complete: true, issues: [], platformLimitation: nil)
        let store = SweepStore()
        store.report = scan; store.overview = .init(id: UUID(), sections: [.init(source: .user, report: scan, issue: nil)])
        let overviewID = store.overview?.id
        store.selected = [related.id, unrelated.id]
        store.query = "existing search"
        store.retainResultsAfterRecoveryChange([related])
        XCTAssertEqual(store.report?.id, scan.id)
        XCTAssertEqual(store.overview?.id, overviewID)
        XCTAssertEqual(store.report?.candidates.map(\.id), [related.id, unrelated.id])
        XCTAssertFalse(try XCTUnwrap(store.report?.candidates.first).allowsPlanReview)
        XCTAssertFalse(try XCTUnwrap(store.overview?.candidates.first).allowsPlanReview)
        XCTAssertEqual(store.report?.candidates.last, unrelated)
        XCTAssertFalse(store.selected.contains(related.id))
        XCTAssertTrue(store.selected.contains(unrelated.id))
        XCTAssertEqual(store.query, "existing search")
        store.cancel()
    }
}
#endif
