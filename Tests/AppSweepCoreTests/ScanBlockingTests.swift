import Foundation
import XCTest
@testable import AppSweepCore

final class ScanBlockingTests: XCTestCase, @unchecked Sendable {
    private final class Feedback: @unchecked Sendable {
        let lock = NSLock()
        private var events: [ScanProgress] = []
        func append(_ value: ScanProgress) { lock.lock(); if events.count < 1024 { events.append(value) }; lock.unlock() }
        var values: [ScanProgress] { lock.lock(); defer { lock.unlock() }; return events }
    }

    func testTimedOutReadOnlyResultAndFeedbackAreDiscardedAndCapacityIsBounded() async throws {
        let pool = ReadOnlyScanPool(maximum:1), release = DispatchSemaphore(value:0), feedback = Feedback()
        let started = expectation(description:"Read-only stage entered"), finished = expectation(description:"Native call finally returned")
        let observed = Task.detached {
            let began = ProcessInfo.processInfo.systemUptime
            do {
                let _: Int = try pool.run(stage:"controlled native access",timeout:0.15,maximumDuration:1,progress:{ feedback.append($0) }) { update in
                    started.fulfill(); update(.init(stage:"early",discoveredCount:1))
                    release.wait()
                    defer { finished.fulfill() }
                    update(.init(stage:"late",discoveredCount:999))
                    return 999
                }
                XCTFail("A result arriving after timeout cannot authorize selection")
            } catch let error as SweepError {
                guard case .incomplete = error else { XCTFail("Timeout must be unconfirmed, not an empty successful report"); return }
            } catch { XCTFail("Unexpected failure: \(error)") }
            XCTAssertLessThan(ProcessInfo.processInfo.systemUptime-began,1)
        }
        await fulfillment(of:[started],timeout:2)
        await observed.value
        XCTAssertThrowsError(try pool.run(stage:"second request") { _ in
            XCTFail("A retry cannot launch additional work while native I/O occupies the only slot")
            return 1
        })
        release.signal()
        await fulfillment(of:[finished],timeout:2)
        XCTAssertEqual(feedback.values.map(\.stage),["early"],"Expired discovery cannot overwrite the next stage's feedback")
        // Completion and permit release are deliberately synchronized before
        // accepting another real read; an abandoned task does not own a slot forever.
        let deadline = ProcessInfo.processInfo.systemUptime + 2
        var next: Int?
        while next == nil && ProcessInfo.processInfo.systemUptime < deadline {
            next = try? pool.run(stage:"fresh request") { _ in 7 }
            if next == nil { try await Task.sleep(for:.milliseconds(10)) }
        }
        XCTAssertEqual(next,7)
    }

    func testHealthyFeedbackExtendsIdleDeadlineButNotAbsoluteDeadline() async throws {
        let pool = ReadOnlyScanPool(maximum:1), finished = expectation(description:"Cancelled work exits"), feedback = Feedback()
        let began = ProcessInfo.processInfo.systemUptime
        XCTAssertThrowsError(try pool.run(stage:"active but excessive discovery",timeout:0.15,maximumDuration:0.5,progress:{ feedback.append($0) }) { update in
            defer { finished.fulfill() }
            // Continuous active work avoids relying on the guest's coalesced
            // low-priority sleep timers to manufacture heartbeat timing.
            for index in 0..<Int.max {
                try ScanCancellation.check()
                update(.init(stage:"still active",discoveredCount:index))
            }
            return 1
        })
        XCTAssertGreaterThan(ProcessInfo.processInfo.systemUptime-began,0.3,"Healthy feedback must not expire at the initial idle deadline; delivered \(feedback.values.count) updates")
        XCTAssertLessThan(ProcessInfo.processInfo.systemUptime-began,1.5,"Feedback cannot extend discovery forever")
        await fulfillment(of:[finished],timeout:2)
    }

    func testSuccessfulFilesystemSnapshotsRenewIdleWaitWithoutDisplayFeedback() async throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let pool = ReadOnlyScanPool(maximum:1), source = f.source
        let finished = expectation(description:"Native snapshots have stopped before fixture cleanup")
        do {
            let count = try pool.run(stage:"healthy filesystem reads",timeout:0.15,maximumDuration:2) { _ in
                defer { finished.fulfill() }
                let until = ProcessInfo.processInfo.systemUptime + 0.4
                var count = 0
                while ProcessInfo.processInfo.systemUptime < until {
                    try ScanCancellation.check()
                    _ = try SafeFilesystem.snapshot(source)
                    count += 1
                }
                return count
            }
            XCTAssertGreaterThan(count,1)
        } catch { XCTFail("Successful native work must renew inactivity even when the phase emits no display feedback: \(error)") }
        await fulfillment(of:[finished],timeout:3)
        XCTAssertEqual(try String(contentsOfFile:source + "/data",encoding:.utf8),"regenerable")
    }

    func testFailedReadDoesNotConsumeCapacityOrChangeItsError() throws {
        let pool = ReadOnlyScanPool(maximum:1)
        XCTAssertThrowsError(try pool.run(stage:"denied read") { _ -> Int in throw SweepError.denied("owned denied fixture") }) { error in
            XCTAssertEqual(error.localizedDescription,"owned denied fixture")
        }
        XCTAssertEqual(try pool.run(stage:"independent read") { _ in 42 },42)
    }

    func testTimedOutStageKeepsCompletedIndependentScopeAndRejectsLateObjects() async throws {
        let f=try RecoveryTests.Fixture();defer{try? f.clean()}
        let item=f.candidate,snapshot=f.snapshot,home=f.home
        let release=DispatchSemaphore(value:0),finished=expectation(description:"Abandoned native work returned")
        let scan=Task.detached {
            let policy=SafetyPolicy(home:home,acceptedPlatform:true,validatedRules:["fixture-v1"])
            var builder=Scanner.Builder(policy:policy)
            try Scanner(policy:policy).boundedStage("independent scopes",builder:&builder,progress:nil,timeout:0.15,maximumDuration:1) { part,_ in
                defer{finished.fulfill()}
                try part.scoped(root:item.path) { scope in
                    scope.items.append(item);scope.snapshots[item.id]=snapshot
                }
                try part.scoped(root:home + "/Library/Caches/blocked") { scope in
                    release.wait();try ScanCancellation.check()
                    scope.reportProtected(home + "/late",reason:"A late finding cannot join an expired scan")
                }
            }
            return builder.finish(applicationPath:nil)
        }
        let output=try await scan.value
        release.signal();await fulfillment(of:[finished],timeout:2)
        XCTAssertEqual(output.report.candidates.map(\.id),[item.id],"A later blocked scope must not discard an already completed independent scope")
        XCTAssertNotNil(output.snapshots[item.id])
        XCTAssertFalse(output.report.complete)
        XCTAssertEqual(output.report.selectableCandidates(includeUserData:false).map(\.id),[item.id])
        XCTAssertFalse(output.report.candidates.contains{$0.path == home + "/late"})
    }

    func testTimedOutEnclosingScopeCannotAuthorizeEarlierDescendant() async throws {
        let f=try RecoveryTests.Fixture();defer{try? f.clean()}
        let item=f.candidate,snapshot=f.snapshot,home=f.home
        let release=DispatchSemaphore(value:0),finished=expectation(description:"Enclosing read returned")
        let scan=Task.detached {
            let policy=SafetyPolicy(home:home,acceptedPlatform:true,validatedRules:["fixture-v1"])
            var builder=Scanner.Builder(policy:policy)
            try Scanner(policy:policy).boundedStage("dependent scopes",builder:&builder,progress:nil,timeout:0.15,maximumDuration:1) { part,_ in
                defer{finished.fulfill()}
                try part.scoped(root:item.path) { scope in scope.items.append(item);scope.snapshots[item.id]=snapshot }
                try part.scoped(root:home + "/Library") { _ in release.wait();try ScanCancellation.check() }
            }
            return builder.finish(applicationPath:nil)
        }
        let output=try await scan.value
        release.signal();await fulfillment(of:[finished],timeout:2)
        XCTAssertTrue(output.report.selectableCandidates(includeUserData:true).isEmpty,"An unfinished ownership ancestor still blocks its dependent candidates")
        XCTAssertFalse(output.report.complete)
    }
    func testWholeScanDeadlineStopsBeforeStartingLaterNativeStages() async throws {
        let f=try RecoveryTests.Fixture();defer{try? f.clean()}
        let home=f.home,release=DispatchSemaphore(value:0),finished=expectation(description:"Expired inventory returned")
        let feedback=Feedback(),began=ProcessInfo.processInfo.systemUptime
        DispatchQueue.global().asyncAfter(deadline:.now() + 1){release.signal()}
        let scan=Task.detached {
            try Scanner(policy:SafetyPolicy(home:home,acceptedPlatform:false)).junk(maximumDuration:0.15,indexLookup:{ _ in
                defer{finished.fulfill()};release.wait();try ScanCancellation.check();return []
            },progress:{feedback.append($0)})
        }
        let output=try await scan.value
        XCTAssertLessThan(ProcessInfo.processInfo.systemUptime-began,0.7)
        XCTAssertFalse(output.report.complete)
        XCTAssertFalse(feedback.values.contains{$0.detail == "org.example.fixture"},"An expired scan must not start another native namespace inspection")
        await fulfillment(of:[finished],timeout:2)
        XCTAssertEqual(try String(contentsOfFile:f.source + "/data",encoding:.utf8),"regenerable")
    }

    func testBlockedInventoryTimesOutWithoutHidingIndependentFindings() async throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let returned = expectation(description:"Timed-out source does not block remaining discovery")
        let nativeReturned = expectation(description:"Released native call has no more filesystem work")
        let release = DispatchSemaphore(value:0), home = f.home
        let scan = Task.detached {
            defer { returned.fulfill() }
            return try Scanner(policy:SafetyPolicy(home:home,acceptedPlatform:false)).junk(indexLookup:{ _ in
                defer { nativeReturned.fulfill() }
                release.wait(); try ScanCancellation.check(); return []
            })
        }
        await fulfillment(of:[returned],timeout:35)
        release.signal()
        let output = try await scan.value
        await fulfillment(of:[nativeReturned],timeout:2)
        XCTAssertFalse(output.report.complete,"A timed-out installation inventory is not a successful empty scan")
        XCTAssertTrue(output.report.issues.contains { $0.contains("超时") })
        XCTAssertTrue(output.report.candidates.contains { $0.path == f.source },"Independent cache discovery still needs to report its retained finding")
        XCTAssertEqual(try String(contentsOfFile:f.source + "/data",encoding:.utf8),"regenerable")
    }

    func testCancelReturnsWhileNativeDiscoveryIsStillBlocked() async throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let entered = expectation(description:"Native discovery entered")
        let returned = expectation(description:"Cancelled scan returned without waiting for native I/O")
        let nativeReturned = expectation(description:"Cancelled native callback released")
        let release = DispatchSemaphore(value:0), home = f.home
        let scan = Task.detached {
            defer { returned.fulfill() }
            do {
                _ = try Scanner(policy:SafetyPolicy(home:home,acceptedPlatform:false)).junk(indexLookup:{ _ in
                    defer { nativeReturned.fulfill() }
                    entered.fulfill(); release.wait(); try ScanCancellation.check(); return []
                })
                XCTFail("Cancelled discovery must never publish an executable report")
            } catch is CancellationError { }
            catch { XCTFail("Expected cancellation, got \(error)") }
        }
        await fulfillment(of:[entered],timeout:3)
        scan.cancel()
        await fulfillment(of:[returned],timeout:1)
        release.signal()
        await scan.value
        await fulfillment(of:[nativeReturned],timeout:2)
        XCTAssertEqual(try String(contentsOfFile:f.source + "/data",encoding:.utf8),"regenerable")
    }
}
