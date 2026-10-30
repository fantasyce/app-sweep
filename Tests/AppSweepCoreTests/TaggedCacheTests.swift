#if os(macOS)
import XCTest
@testable import AppSweepCore

final class TaggedCacheTests: XCTestCase, @unchecked Sendable {
    private let marker = Data("Signature: 8a477f597d28d172789f06886806bc55\n# Independent disposable test cache\n".utf8)
    func testProducerTaggedCacheWithoutInstalledBodyHasReversiblePlan() async throws {
        let f = try NativeAcceptanceTests.NativeFixture(additionalRules: [UserCacheNamespaceRule.name]); defer { try? f.clean() }
        let root = f.home + "/Library/Caches/RemovedProducer-" + UUID().uuidString
        try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
        try marker.write(to: URL(fileURLWithPath: root + "/CACHEDIR.TAG"))
        let bytes = Data("regenerable test bytes".utf8)
        try bytes.write(to: URL(fileURLWithPath: root + "/payload"))
        let report = try await f.engine.scanJunk()
        let items = report.selectableCandidates(includeUserData: false).filter { $0.path.hasPrefix(root + "/") }
        XCTAssertEqual(items.count, 2, report.candidates.filter { $0.path.hasPrefix(root) }.compactMap(\.retentionReason).joined(separator: "; "))
        guard items.count == 2 else { return }
        XCTAssertTrue(items.allSatisfy { $0.applicationPath == nil && $0.bundleIdentifier == nil && !$0.selectedByDefault })
        let plan = try await f.engine.makePlan(reportID: report.id, selected: Set(items.map(\.id)), includeUserData: false)
        let isolated = try await f.engine.execute(planID: plan.id)
        XCTAssertEqual(isolated.status, .isolated, isolated.issue ?? "")
        let restored = try await f.engine.restore(batchID: isolated.id)
        XCTAssertEqual(restored.status, .restored, restored.issue ?? "")
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: root + "/payload")), bytes)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: root + "/CACHEDIR.TAG")), marker)
    }
    func testWrongTagAndAppleNamespaceCannotAuthorizeContents() async throws {
        let f = try NativeAcceptanceTests.NativeFixture(additionalRules: [UserCacheNamespaceRule.name]); defer { try? f.clean() }
        let roots = [f.home + "/Library/Caches/Unmarked-" + UUID().uuidString, f.home + "/Library/Caches/com.apple.tagged-test"]
        for (index, root) in roots.enumerated() {
            try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
            try (index == 0 ? Data("not a cache marker".utf8) : marker).write(to: URL(fileURLWithPath: root + "/CACHEDIR.TAG"))
            try Data("must remain".utf8).write(to: URL(fileURLWithPath: root + "/payload"))
        }
        let report = try await f.engine.scanJunk()
        XCTAssertFalse(report.selectableCandidates(includeUserData: true).contains { item in roots.contains { item.path.hasPrefix($0 + "/") } })
    }
}
#endif
