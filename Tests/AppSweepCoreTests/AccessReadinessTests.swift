import Foundation
import XCTest
@testable import AppSweepCore

final class AccessReadinessTests: XCTestCase {
    #if os(macOS)
    func testProbeFailureNeverConfusesMissingOrUnreadableWithAuthorization() {
        XCTAssertEqual(AccessPreparationProbe.failure(EPERM), .denied)
        XCTAssertEqual(AccessPreparationProbe.failure(EACCES), .denied)
        XCTAssertEqual(AccessPreparationProbe.failure(ENOENT), .missing)
        XCTAssertEqual(AccessPreparationProbe.failure(ELOOP), .unknown)
        XCTAssertEqual(AccessPreparationProbe.failure(EIO), .unknown)
    }
    #endif
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    private func evidence(_ scope: AccessReadiness.Scope, _ result: AccessReadiness.Result, subject: String? = nil, age: TimeInterval = 0) -> AccessReadiness.Evidence {
        .init(scope: scope, result: result, subject: subject ?? (scope == .user ? "app-current" : "service-current"), checkedAt: now.addingTimeInterval(-age))
    }
    private func state(_ evidence: [AccessReadiness.Evidence], relaunch: Bool = false) -> AccessReadiness.State {
        AccessReadinessEvaluator.evaluate(.init(userSubject: "app-current", systemSubject: "service-current", evidence: evidence, relaunchRequired: relaunch), now: now).state
    }
    func testNoEvidenceIsNotChecked() { XCTAssertEqual(state([]), .notChecked) }
    func testMissingProbeIsUnknown() { XCTAssertEqual(state([evidence(.user, .missing), evidence(.system, .readable)]), .limited) }
    func testServiceConnectionIsNotAccessProof() { XCTAssertEqual(state([evidence(.user, .readable), evidence(.system, .unknown)]), .limited) }
    func testBothSubjectsNeedFreshReadEvidence() { XCTAssertEqual(state([evidence(.user, .readable), evidence(.system, .readable)]), .ready) }
    func testOldIdentityCannotGrantAccess() { XCTAssertEqual(state([evidence(.user, .readable, subject: "app-old"), evidence(.system, .readable)]), .limited) }
    func testExpiredOrFutureEvidenceCannotGrantAccess() {
        for age in [301.0, -1.0] { XCTAssertEqual(state([evidence(.user, .readable, age: age), evidence(.system, .readable)]), .limited) }
    }
    func testDeniedOrUnavailableScopeStaysLimited() {
        for result in [AccessReadiness.Result.denied, .unavailable] {
            XCTAssertEqual(state([evidence(.user, .readable), evidence(.system, result)]), .limited)
        }
    }
    func testBothDeniedIsBlocked() { XCTAssertEqual(state([evidence(.user, .denied), evidence(.system, .denied)]), .blocked) }
    func testRelaunchCannotBeReplacedByPastReadEvidence() { XCTAssertEqual(state([evidence(.user, .readable), evidence(.system, .readable)], relaunch: true), .needsRelaunch) }
    func testLatestRevocationWinsOverEarlierRead() {
        XCTAssertEqual(state([evidence(.user, .denied), evidence(.user, .readable, age: 10), evidence(.system, .readable)]), .limited)
    }
    func testConflictingSameTimeEvidenceFailsClosed() {
        for results in [[AccessReadiness.Result.readable, .denied], [.denied, .readable]] {
            XCTAssertEqual(state(results.map { evidence(.user, $0) } + [evidence(.system, .readable)]), .limited)
        }
    }
}
