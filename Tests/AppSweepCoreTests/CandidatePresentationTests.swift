#if os(macOS)
import XCTest
@testable import AppSweepCore
@testable import AppSweepApp

final class CandidatePresentationTests: XCTestCase {
    private func candidate(_ path: String, rule: String, category: CandidateCategory = .userData,
                           bytes: Int64 = 100, measured: Bool = true, executable: Bool = true) -> Candidate {
        let identity = measured ? FileIdentity(device: 1, inode: 1, mode: 0o100600, owner: 501, links: 1,
            size: bytes, modifiedSeconds: 1, modifiedNanoseconds: 0, changedSeconds: 1, changedNanoseconds: 0) : nil
        var item = Candidate(id: UUID(), path: path, category: category, bundleIdentifier: nil,
            evidence: [.init(kind: .validatedRule, detail: "Presentation test input", verified: true)],
            rule: rule, identity: identity, bytes: bytes, retentionReason: nil)
        item.executionAllowed = executable
        return item
    }

    func testManagementRulesRemainSeparateAndNeverBecomeRecommended() {
        let expected: [(String, CandidateDisplaySection)] = [
            ("document-history-versions-v1", .documentHistory),
            ("corrupt-preference-file-v1", .corruptPreferences),
            ("stale-user-launch-agent-v1", .staleAgents),
            ("xcode-archive-management-v1", .developmentArchives),
            ("xcode-device-symbols-v1", .deviceSymbols),
            ("deleted-user-archive-v1", .deletedUserArchives),
            ("current-user-trash-entry-v1", .trash),
            ("mail-download-copy-v1", .mailDownloads),
            ("ai-huggingface-local-repository-v1", .aiModels)
        ]
        for (rule, section) in expected {
            let item = candidate("/presentation/" + rule, rule: rule)
            XCTAssertEqual(CandidateDisplaySection.section(for: item), section, rule)
            XCTAssertFalse(item.selectedByDefault, "Display grouping must preserve personal-data defaults")
        }
        XCTAssertEqual(CandidateDisplaySection.section(for: candidate("/presentation/backup", rule: "local-device-backup-v1", category: .deviceBackup)), .deviceBackup)
        XCTAssertEqual(CandidateDisplaySection.section(for: candidate("/presentation/unknown", rule: "future-rule")), .userData)
    }

    func testCacheGroupAppearsOnceAndRequiresEveryMemberToBeSelectable() throws {
        let first = candidate("/presentation/Caches/org.example/payload", rule: "cache-exact-domain-v1", category: .cache, bytes: 120)
        let second = candidate("/presentation/Caches/org.example/index", rule: "cache-exact-domain-v1", category: .cache, bytes: 80)
        let projection = CandidateListProjection(candidates: [first, second, first], selectableIDs: [first.id, second.id])
        let row = try XCTUnwrap(projection.rows.first)
        XCTAssertEqual(projection.rows.count, 1)
        XCTAssertEqual(row.members.count, 2)
        XCTAssertEqual(row.knownBytes, 200)
        XCTAssertEqual(row.unknownCount, 0)
        XCTAssertTrue(row.actionable)
        let incomplete = CandidateListProjection(candidates: [first, second], selectableIDs: [first.id])
        XCTAssertFalse(try XCTUnwrap(incomplete.rows.first).actionable, "A presentation row must not allow a partial cache group")
    }

    func testUnknownBytesStayUnknownAndRetainedRowsRemainVisible() throws {
        let known = candidate("/presentation/known", rule: "document-history-versions-v1", bytes: 64)
        let unknown = candidate("/presentation/unknown", rule: "ai-huggingface-local-repository-v1", bytes: 999, measured: false, executable: false)
        let projection = CandidateListProjection(candidates: [known, unknown], selectableIDs: [known.id])
        XCTAssertEqual(projection.rows.count, 2)
        XCTAssertEqual(projection.sections, [.documentHistory, .aiModels])
        XCTAssertEqual(projection.rows.reduce(0) { $0 + $1.knownBytes }, 64)
        XCTAssertEqual(projection.rows.reduce(0) { $0 + $1.unknownCount }, 1)
        let retained = try XCTUnwrap(projection.rows.first { $0.id == unknown.id })
        XCTAssertFalse(retained.actionable)
        XCTAssertEqual(retained.unknownCount, 1)
    }

    func testExecutionUnavailableMemberKeepsEntireCacheGroupRetained() throws {
        let first = candidate("/presentation/cache/payload", rule: "cache-exact-domain-v1", category: .cache)
        let retained = candidate("/presentation/cache/index", rule: "cache-exact-domain-v1", category: .cache, executable: false)
        let projection = CandidateListProjection(candidates: [first, retained], selectableIDs: [first.id, retained.id])
        XCTAssertFalse(try XCTUnwrap(projection.rows.first).actionable)
    }
}
#endif
