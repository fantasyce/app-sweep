#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

final class SignaturePreflightTests: XCTestCase {
    func testProtectedToolchainIsRejectedWithoutAnExpensiveResourceValidation() throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_PROTECTED_PREFLIGHT"] == "1" else { throw XCTSkip("Explicit read-only preflight performance case") }
        let home = try SystemIdentity.home()
        let path = ProcessInfo.processInfo.environment["APP_SWEEP_PROTECTED_APP"] ?? home + "/AppSweepAcceptanceGeneral-20261016/developer/Xcode.app"
        guard ["/Applications/Xcode.app", home + "/AppSweepAcceptanceGeneral-20261016/developer/Xcode.app"].contains(path) else { throw SweepError.denied("Only the already prepared toolchain may be used") }
        let metadata = try AppInspector.metadata(path, component: false).0
        let identifier = try XCTUnwrap(metadata["CFBundleIdentifier"] as? String)
        guard identifier.hasPrefix("com.apple.") else { throw SweepError.denied("Protected Apple toolchain required") }
        let started = ProcessInfo.processInfo.systemUptime
        XCTAssertThrowsError(try AppInspector.verifiedDataOwner(path: path, identifier: identifier, home: home))
        XCTAssertLessThan(ProcessInfo.processInfo.systemUptime - started, 2, "A protected application must not repeatedly validate its entire SDK while scanning unrelated caches")
    }
}
#endif
