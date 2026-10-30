#if os(macOS)
import XCTest
@testable import AppSweepCore

final class PreferenceReaderInstallationTests: XCTestCase {
    func testInstallationExceptionIsBoundToExactDirectory() throws {
        let applications=try SafeDirectory(path:"/Applications")
        XCTAssertFalse(PreferenceDomainReader.trustedInstallationDirectory(path:"/tmp",fd:applications.fd))
        XCTAssertFalse(PreferenceDomainReader.trustedInstallationDirectory(path:"/Applications/Other",fd:applications.fd))
        let root=try SafeDirectory(path:"/")
        XCTAssertFalse(PreferenceDomainReader.trustedInstallationDirectory(path:"/Applications",fd:root.fd))
        XCTAssertFalse(PreferenceDomainReader.trustedInstallationDirectory(path:"/Applications",fd:-1))
    }
}
#endif
