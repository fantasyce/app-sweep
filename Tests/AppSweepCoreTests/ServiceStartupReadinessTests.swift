#if os(macOS)
import Foundation
import Darwin
import XCTest
@testable import AppSweepCore

final class ServiceStartupReadinessTests: XCTestCase, @unchecked Sendable {
    func testWaitsForDelayedSocketThenReturnsRealDescriptor() async throws {
        var pair:[Int32] = [-1,-1]
        XCTAssertEqual(socketpair(AF_UNIX,SOCK_STREAM,0,&pair),0)
        defer { pair.forEach { if $0 >= 0 { close($0) } } }
        var attempts = 0
        let fd = try await ServiceStartupReadiness.connect(timeout:0.5) { remaining in
            XCTAssertGreaterThan(remaining,0); XCTAssertLessThanOrEqual(remaining,500)
            attempts += 1
            return attempts < 3 ? (-1,ENOENT) : (dup(pair[0]),0)
        }
        defer { close(fd) }
        XCTAssertEqual(attempts,3)
        XCTAssertEqual(write(pair[1],"ok",2),2)
        var bytes = [UInt8](repeating:0,count:2)
        XCTAssertEqual(read(fd,&bytes,2),2); XCTAssertEqual(bytes,[111,107])
    }
    func testUnsafeMetadataAndOtherErrorsStopWithoutRetry() async throws {
        for failure in [EPERM,ESTALE,EACCES] {
            var attempts = 0
            do {
                _ = try await ServiceStartupReadiness.connect(timeout:0.5) { _ in attempts += 1; return (-1,failure) }
                XCTFail("Unsafe or unknown socket failure cannot become startup readiness")
            } catch { XCTAssertEqual(attempts,1) }
        }
    }
    func testValidatedSocketRefusalDuringActivationWaitsForListener() async throws {
        var pair:[Int32] = [-1,-1]
        XCTAssertEqual(socketpair(AF_UNIX,SOCK_STREAM,0,&pair),0)
        defer { pair.forEach { if $0 >= 0 { close($0) } } }
        var attempts = 0
        let fd = try await ServiceStartupReadiness.connect(timeout:0.5) { _ in
            attempts += 1
            return attempts < 3 ? (-1,ECONNREFUSED) : (dup(pair[0]),0)
        }
        defer { close(fd) }
        XCTAssertEqual(attempts,3)
        XCTAssertEqual(write(pair[1],"ok",2),2)
        var bytes = [UInt8](repeating:0,count:2)
        XCTAssertEqual(read(fd,&bytes,2),2); XCTAssertEqual(bytes,[111,107])
    }
    func testMissingSocketHasTotalDeadlineAndDoesNotSpin() async throws {
        let start = ProcessInfo.processInfo.systemUptime
        var attempts = 0
        do {
            _ = try await ServiceStartupReadiness.connect(timeout:0.08) { _ in attempts += 1; return (-1,ENOENT) }
            XCTFail("Missing socket cannot become success")
        } catch {
            let elapsed = ProcessInfo.processInfo.systemUptime-start
            XCTAssertGreaterThanOrEqual(elapsed,0.07); XCTAssertLessThan(elapsed,1)
            XCTAssertGreaterThan(attempts,0); XCTAssertLessThanOrEqual(attempts,3)
        }
    }
    func testLateSuccessfulDescriptorIsClosedAndNotAccepted() async throws {
        var returned:Int32 = -1
        do {
            _ = try await ServiceStartupReadiness.connect(timeout:0.005) { _ in
                usleep(20_000); returned = open("/dev/null",O_RDONLY|O_CLOEXEC); return (returned,0)
            }
            XCTFail("No success beyond the total deadline")
        } catch {
            XCTAssertGreaterThanOrEqual(returned,0)
            XCTAssertEqual(fcntl(returned,F_GETFD),-1); XCTAssertEqual(errno,EBADF)
        }
    }
    func testCancelledWaitDoesNotBeginAnotherConnection() async throws {
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await ServiceStartupReadiness.connect(timeout:0.5) { _ in
                XCTFail("Cancelled startup must not connect"); return (-1,ENOENT)
            }
        }
        do { _ = try await task.value; XCTFail("Cancellation must propagate") } catch is CancellationError { } catch { XCTFail("Unexpected cancellation result: \(error)") }
    }
}
#endif
