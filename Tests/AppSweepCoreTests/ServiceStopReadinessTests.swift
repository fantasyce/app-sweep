#if os(macOS)
import Foundation
import Darwin
import XCTest
@testable import AppSweepCore

final class ServiceStopReadinessTests: XCTestCase, @unchecked Sendable {
    func testWaitsForDelayedUnregistrationWithoutIssuingAnotherStop() async throws {
        var observations = 0
        try await ServiceStopReadiness.wait(timeout:0.5) { remaining in
            XCTAssertGreaterThan(remaining,0); XCTAssertLessThanOrEqual(remaining,0.5)
            observations += 1
            return observations < 3
        }
        XCTAssertEqual(observations,3)
    }
    func testAlreadyAbsentReturnsAfterOneConfirmedObservation() async throws {
        var observations = 0
        try await ServiceStopReadiness.wait(timeout:0.5) { _ in observations += 1; return false }
        XCTAssertEqual(observations,1)
    }
    func testUnknownRegistrationErrorStopsWithoutRetry() async throws {
        var observations = 0
        do {
            try await ServiceStopReadiness.wait(timeout:0.5) { _ in observations += 1; throw SweepError.incomplete("unconfirmed launchd state") }
            XCTFail("Unknown state cannot authorize component replacement")
        } catch { XCTAssertEqual(observations,1) }
    }
    func testRegisteredJobExpiresWithoutBusyLoopingOrSuccess() async throws {
        let start = ProcessInfo.processInfo.systemUptime
        var observations = 0
        do {
            try await ServiceStopReadiness.wait(timeout:0.08) { _ in observations += 1; return true }
            XCTFail("A registered job is not stopped")
        } catch {
            let elapsed = ProcessInfo.processInfo.systemUptime-start
            XCTAssertGreaterThanOrEqual(elapsed,0.07); XCTAssertLessThan(elapsed,1)
            XCTAssertGreaterThan(observations,0); XCTAssertLessThanOrEqual(observations,3)
        }
    }
    func testLateAbsenceCannotAuthorizeReplacement() async throws {
        do {
            try await ServiceStopReadiness.wait(timeout:0.005) { _ in usleep(20_000); return false }
            XCTFail("No success beyond the total deadline")
        } catch { }
    }
    func testCancelledWaitDoesNotQueryRegistration() async throws {
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            try await ServiceStopReadiness.wait(timeout:0.5) { _ in
                XCTFail("Cancellation must stop before querying launchd"); return false
            }
        }
        do { try await task.value; XCTFail("Cancellation must propagate") }
        catch is CancellationError { }
        catch { XCTFail("Unexpected cancellation result: \(error)") }
    }
    func testInvalidDeadlineDoesNotStartQuery() async throws {
        for timeout in [0.0,-1,.infinity,.nan,5.1] {
            do {
                try await ServiceStopReadiness.wait(timeout:timeout) { _ in
                    XCTFail("Invalid deadline must not query launchd"); return false
                }
                XCTFail("Invalid deadline accepted")
            } catch { }
        }
    }
}
#endif
