import XCTest
@testable import AppSweepCore

final class SafetyTests: XCTestCase {
    func testCaseVariantsOfProtectedNamesRemainDenied() {
        let policy = SafetyPolicy(home: "/Users/test", acceptedPlatform: true)
        for path in ["/Users/test/Library/Caches/Com.Apple.Fonts/fsCachedData", "/Users/test/Library/Application Support/aPp sWeEp/objects", "/Users/test/Library/kEyChAiNs/login.keychain-db", "/Users/test/Library/Caches/org.example.cache/APP SWEEP.APP"] {
            XCTAssertNotNil(policy.lexicalDenial(path), path)
        }
    }
    func testCursorNeverAuthorizesSystemState() throws {
        let policy = SafetyPolicy(home: "/Users/test", acceptedPlatform: true)
        for path in ["/private/var/folders/a/b/C/com.todesktop.230313mzl4w4u92", "/var/folders/a/b/C/Cursor", "/System/Library/Caches/Cursor", "/Library/Caches/Cursor", "/Users/other/Library/Caches/Cursor", "/Users/test/Library/Keychains/login.keychain-db", "/Users/test/Library/Application Support/com.apple.TCC"] {
            XCTAssertNotNil(policy.lexicalDenial(path), path)
        }
    }
    func testNamesAndVendorPrefixesNeverProveOwnership() {
        XCTAssertFalse(OwnershipEvidence(kind: .nameHint, detail: "com.vendor", verified: true).authorizes)
        XCTAssertFalse(OwnershipEvidence(kind: .vendorHint, detail: "Cursor", verified: true).authorizes)
    }
    func testUnknownPlatformIsReadOnly() {
        XCTAssertFalse(SafetyPolicy(home: "/Users/test", acceptedPlatform: false).executionEnabled)
    }
    func testUserDataRequiresExplicitChoice() {
        let item = Candidate.fixture(path: "/Users/test/Library/Preferences/org.example.app.plist", userData: true)
        XCTAssertFalse(item.selectedByDefault)
    }
}
