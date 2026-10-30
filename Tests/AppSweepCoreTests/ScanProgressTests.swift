import Foundation
import XCTest
@testable import AppSweepCore

private final class ScanProgressRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [ScanProgress] = []
    func append(_ value: ScanProgress) { lock.lock(); defer { lock.unlock() }; recorded.append(value) }
    var values: [ScanProgress] { lock.lock(); defer { lock.unlock() }; return recorded }
}

private final class IndependentScanGate: @unchecked Sendable {
    private let condition = NSCondition()
    private var connected = false
    private(set) var connectionStartedDuringUserScan = false
    func userStarted() {
        condition.lock(); defer { condition.unlock() }
        let deadline = Date().addingTimeInterval(2)
        while !connected && condition.wait(until:deadline) { }
        connectionStartedDuringUserScan = connected
    }
    func systemStarted() {
        condition.lock(); defer { condition.unlock() }
        connected = true; condition.broadcast()
    }
}

#if os(macOS)
@testable import AppSweepApp
private actor ScanProgressConnectionGate {
    private var continuation: CheckedContinuation<Void,Never>?
    private var released = false
    private(set) var entered = false
    func wait() async {
        entered = true
        if released { return }
        await withCheckedContinuation { continuation = $0 }
    }
    func release() { released = true; continuation?.resume(); continuation = nil }
}
#endif

final class ScanProgressTests: XCTestCase, @unchecked Sendable {
    func testUserScanReportsDiscoveryBeforeInventoryAndBetweenCacheNamespaces() throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let second = f.home + "/Library/Caches/org.example.second"
        try FileManager.default.createDirectory(atPath:second,withIntermediateDirectories:true)
        try Data("independent cache discovery".utf8).write(to:URL(fileURLWithPath:second + "/payload"))
        let recorder = ScanProgressRecorder()
        let output = try Scanner(policy:SafetyPolicy(home:f.home,acceptedPlatform:false)).junk(indexLookup:{ _ in
            XCTAssertFalse(recorder.values.isEmpty,"Discovery must report its inventory stage before potentially slow installed-app discovery")
            return []
        },progress:{ recorder.append($0) })
        let events = recorder.values
        XCTAssertEqual(events.first?.discoveredCount,0)
        XCTAssertNotNil(events.first { $0.detail == "org.example.fixture" },"Each uncategorized cache namespace must identify ongoing work before inspecting its tree")
        XCTAssertNotNil(events.first { $0.detail == "org.example.second" })
        XCTAssertTrue(events.contains { $0.discoveredCount > 0 && $0.discoveredCount < output.report.candidates.count },"Candidate counts must update during scanning rather than only on return")
        XCTAssertEqual(events.last?.discoveredCount,output.report.candidates.count)
        XCTAssertTrue(zip(events,events.dropFirst()).allSatisfy { pair in pair.0.discoveredCount <= pair.1.discoveredCount })
        XCTAssertTrue(FileManager.default.fileExists(atPath:f.source + "/data"))
        XCTAssertTrue(FileManager.default.fileExists(atPath:second + "/payload"))
    }

    func testCancelledDiscoveryStopsFeedbackAndDoesNotReturnAPartialReport() async throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let recorder = ScanProgressRecorder(), home = f.home
        let operation = Task.detached {
            try Scanner(policy:SafetyPolicy(home:home,acceptedPlatform:false)).junk(indexLookup:{ _ in [] },progress:{ value in
                recorder.append(value)
                // Cancel at the observable discovery boundary, before a real
                // namespace is inspected, without timer or scheduling races.
                if value.detail == "org.example.fixture" { withUnsafeCurrentTask { $0?.cancel() } }
            })
        }
        do { _ = try await operation.value; XCTFail("Cancellation must not publish a final or partial report") }
        catch is CancellationError { }
        XCTAssertEqual(recorder.values.last?.detail,"org.example.fixture","Cancelled work must not keep emitting later stages")
        XCTAssertEqual(try String(contentsOfFile:f.source + "/data",encoding:.utf8),"regenerable")
    }

    #if os(macOS)
    func testUserDiscoveryCannotConsumeTheSystemDiscoveryBudget() async throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let gate = IndependentScanGate()
        let coordinator = try CleanupCoordinator.fixture(engine:f.engine(),systemFactory:{
            gate.systemStarted()
            throw SweepError.denied("Controlled unavailable service")
        })
        _ = try await coordinator.scanJunk(progress:{ value in
            if value.stage == "核对已安装应用" { gate.userStarted() }
        })
        XCTAssertTrue(gate.connectionStartedDuringUserScan,"System discovery must start independently before a slow user scan exhausts their shared deadline")
        await coordinator.close()
    }
    func testNewestHeartbeatCannotDiscardTheCompletedScopePreview() async throws {
        let f=try RecoveryTests.Fixture();defer{try? f.clean()}
        let report=ScanReport(schemaVersion:1,id:UUID(),createdAt:Date(),ruleVersion:SweepEngine.ruleVersion,applicationPath:nil,candidates:[f.candidate],complete:true,issues:[],platformLimitation:nil)
        let relay=ScanPreviewProgress(),(updates,continuation)=AsyncStream<ScanProgress>.makeStream(bufferingPolicy:.bufferingNewest(1))
        continuation.yield(relay.merging(.init(stage:"completed",discoveredCount:1,completedReports:["user":report])))
        continuation.yield(relay.merging(.init(stage:"waiting for next source",discoveredCount:1)))
        continuation.finish()
        var buffered:[ScanProgress]=[]
        for await update in updates{buffered.append(update)}
        XCTAssertEqual(buffered.count,1)
        XCTAssertEqual(buffered.first?.stage,"waiting for next source")
        XCTAssertEqual(buffered.first?.completedReports["user"]?.candidates.first?.path,f.source,"The newest event must still contain renderable findings while the next source waits")
    }
    func testCoordinatorKeepsUserDiscoveryVisibleWhileSystemConnectionWaits() async throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let recorder = ScanProgressRecorder(), gate = ScanProgressConnectionGate()
        let coordinator = try CleanupCoordinator.fixture(engine:f.engine(),systemFactory:{
            await gate.wait()
            throw SweepError.denied("Controlled unavailable system service")
        })
        let scan = Task { try await coordinator.scanJunk(progress:{ recorder.append($0) }) }
        do {
            let deadline = ProcessInfo.processInfo.systemUptime + 120
            while !(await gate.entered) && ProcessInfo.processInfo.systemUptime < deadline {
                try await Task.sleep(for:.milliseconds(50))
            }
            guard await gate.entered else { throw SweepError.incomplete("User scan did not reach the controlled connection") }
            // Both sources now start independently; wait for the user source
            // while the system connection remains deliberately blocked.
            while !recorder.values.contains(where:{$0.completedReports["user"] != nil}) && ProcessInfo.processInfo.systemUptime < deadline {
                try await Task.sleep(for:.milliseconds(50))
            }
            let beforeSystem = recorder.values
            XCTAssertGreaterThan(beforeSystem.last?.discoveredCount ?? 0,0,"Waiting for another source must not hide already discovered user findings")
            XCTAssertTrue(beforeSystem.contains{$0.completedReports["user"]?.candidates.contains{$0.path == f.source} == true},"Completed candidates must be available to render before another source replies")
            XCTAssertGreaterThan(Set(beforeSystem.map(\.stage)).count,1,"Coordinator must expose the handoff from user discovery to the system service")
            await gate.release()
            let overview = try await scan.value
            XCTAssertEqual(recorder.values.last?.discoveredCount,overview.candidates.count)
            XCTAssertTrue(overview.sections.contains { $0.source == .systemCaches && $0.report == nil && $0.issue != nil },"Progress cannot turn a failed source into a successful empty scan")
            await coordinator.close()
        } catch {
            await gate.release(); scan.cancel(); _ = try? await scan.value
            await coordinator.close(); throw error
        }
    }
    #endif
}
