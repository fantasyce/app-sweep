#if os(macOS)
import Foundation
import XCTest
import Darwin
@testable import AppSweepCore

/// Acceptance of the actual disposable VM's default user context, rather than
/// a synthetic home or an engine with overridden rule/platform validation.
final class DefaultWorkflowReadOnlyTests: XCTestCase, @unchecked Sendable {
    func testDefaultScanOffersSelectableItemsAndMakesAReadOnlyPlan() async throws {
        guard getuid() == 501, geteuid() == 501, NSHomeDirectory() == "/Users/localtest",
              ProcessInfo.processInfo.environment["APP_SWEEP_DEFAULT_READONLY_ACCEPTANCE"] == "AppSweep-General-20261016" else {
            throw XCTSkip("Explicit disposable VM default-context acceptance only")
        }
        guard try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3)
            .trimmingCharacters(in:.whitespacesAndNewlines) == "VirtualMac2,1" else {
            throw SweepError.denied("Default-context acceptance requires the disposable VM")
        }
        let engine = SweepEngine()
        let report = try await engine.scanJunk()
        let selectable = report.selectableCandidates(includeUserData:false)
        XCTAssertFalse(selectable.isEmpty,"Default scanning must offer a usable selection in the prepared test VM; flags alone do not prove selection")
        XCTAssertTrue(selectable.allSatisfy { !$0.userData && $0.allowedActions.contains(.reviewPlan) })
        // A small old log avoids making a large test cache the verification input.
        let item = try XCTUnwrap(selectable.filter { $0.category == .log && $0.selectedByDefault }
            .min { $0.bytes < $1.bytes })
        let ids = report.selectionIDs(for:item.id,includeUserData:false)
        XCTAssertFalse(ids.isEmpty)
        let before = try SafeFilesystem.snapshot(item.path)
        let plan = try await engine.makePlan(reportID:report.id,selected:ids,includeUserData:false)
        XCTAssertEqual(Set(plan.items.map(\.id)),ids)
        XCTAssertFalse(plan.includeUserData)
        XCTAssertTrue(plan.items.allSatisfy { !$0.userData })
        try SafeFilesystem.verify(before)
        print("Default user scan: \(report.candidates.count) candidates, \(selectable.count) selectable; explicit selection produced a read-only plan for \(plan.items.count) item(s). No execute, restore or purge called.")
    }
}
#endif
