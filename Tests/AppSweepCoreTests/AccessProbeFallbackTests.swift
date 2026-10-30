import XCTest
@testable import AppSweepCore

final class AccessProbeFallbackTests: XCTestCase {
    func testMissingUserDatabaseUsesOnlyFixedSystemProbe() {
        var paths: [String] = []
        let result = AccessPreparationProbe.user(home: "/Users/test", probe: { path in
            paths.append(path)
            return paths.count == 1 ? .missing : .readable
        })
        XCTAssertEqual(result, .readable)
        XCTAssertEqual(paths, ["/Users/test/Library/Application Support/com.apple.TCC", "/Library/Application Support/com.apple.TCC"])
    }
    func testDeniedOrUnknownUserProbeIsNeverOverridden() {
        for initial: AccessReadiness.Result in [.denied, .unknown, .readable, .unavailable] {
            var calls = 0
            XCTAssertEqual(AccessPreparationProbe.user(home: "/Users/test", probe: { _ in calls += 1; return initial }), initial)
            XCTAssertEqual(calls, 1)
        }
    }
    func testMissingBothIsNotPermissionSuccess() {
        XCTAssertEqual(AccessPreparationProbe.user(home: "/Users/test", probe: { _ in .missing }), .missing)
    }
}
