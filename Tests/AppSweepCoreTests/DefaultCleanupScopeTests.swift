import Foundation
import XCTest
@testable import AppSweepCore

private final class CleanupStageRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var stages: [String] = []
    func append(_ stage: String) { lock.lock(); defer { lock.unlock() }; stages.append(stage) }
    var values: [String] { lock.lock(); defer { lock.unlock() }; return stages }
}

final class DefaultCleanupScopeTests: XCTestCase, @unchecked Sendable {
    func testDefaultScanListsManualManagementWithoutSelectingPersonalData() throws {
        let fixture = try RecoveryTests.Fixture(); defer { try? fixture.clean() }
        let recorder = CleanupStageRecorder()
        let output = try Scanner(policy: SafetyPolicy(home: fixture.home, acceptedPlatform: false)).junk(indexLookup: { _ in [] }, progress: { recorder.append($0.stage) })
        let manualStages = ["检查文稿历史版本", "检查应用偏好文件", "检查设备备份", "检查失效后台项目", "检查项目归档", "检查设备调试符号"]
        for stage in manualStages { XCTAssertTrue(recorder.values.contains(stage), "Manual management scope missing: " + stage) }
        XCTAssertFalse(output.report.candidates.contains { $0.userData && $0.selectedByDefault })
        XCTAssertFalse(output.report.selectableCandidates(includeUserData:false).contains { $0.userData })
        XCTAssertTrue(output.report.candidates.contains { $0.path == fixture.source }, "The ordinary cache scope must still be discovered")
    }
    #if os(macOS)
    func testSystemDefaultsExcludeArchivesAndComponentManagementEvenWhenServiceIsUnavailable() async throws {
        let fixture = try RecoveryTests.Fixture(); defer { try? fixture.clean() }
        let coordinator = try CleanupCoordinator.fixture(engine: fixture.engine(), systemFactory: { throw SweepError.denied("fixture service unavailable") })
        let result = try await coordinator.scanJunk()
        XCTAssertEqual(result.sections.map(\.source), [.user, .systemCaches, .systemLogs])
        await coordinator.close()
    }
    #endif
}
