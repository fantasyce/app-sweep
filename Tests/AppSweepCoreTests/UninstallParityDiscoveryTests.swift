import XCTest
@testable import AppSweepCore

final class UninstallParityDiscoveryTests: XCTestCase {
    private func requireHostReadOnly() throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_PARITY_READONLY"] == "1" else {
            throw XCTSkip("Explicit installed-app read-only parity check")
        }
    }

    func testUninstallIncludesOnlySelectedApplicationsDarwinNamespace() throws {
        try requireHostReadOnly()
        let scope = try DarwinCacheScope.current()
        let root = scope.root + "/org.godotengine.godot"
        guard try SafeFilesystem.presence(root) else { throw XCTSkip("Godot-generated cache required") }
        let report = try Scanner(policy: .current).application("/Applications/Godot.app").report
        XCTAssertTrue(report.candidates.contains { $0.path == root || $0.path.hasPrefix(root + "/") })
        XCTAssertFalse(report.candidates.contains { $0.path.hasPrefix(scope.root + "/com.sublimetext.4") })
    }

    func testBlockedChromeStillShowsSignedDefaultCacheNamespace() throws {
        try requireHostReadOnly()
        let path = try SystemIdentity.home() + "/Library/Caches/Google/Chrome"
        guard try SafeFilesystem.presence(path) else { throw XCTSkip("Chrome-generated cache required") }
        let report = try Scanner(policy: .current).application("/Applications/Google Chrome.app").report
        guard report.candidates.first(where: { $0.category == .application })?.retentionReason != nil else {
            throw XCTSkip("This read-only regression requires a blocked application body")
        }
        let candidate = try XCTUnwrap(report.candidates.first { $0.path == path })
        XCTAssertNotNil(candidate.retentionReason)
        XCTAssertFalse(candidate.executionAllowed)
    }
}
