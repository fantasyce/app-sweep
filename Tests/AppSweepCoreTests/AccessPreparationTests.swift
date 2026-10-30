#if os(macOS)
import XCTest
@testable import AppSweepApp

final class AccessPreparationTests: XCTestCase {
    @MainActor
    func testPreparationDoesNotStartScanOrCatalogOrRecovery() {
        let store = SweepStore()
        store.preparationRequired = true
        store.scan()
        XCTAssertFalse(store.busy)
        store.loadApps()
        XCTAssertFalse(store.busy)
        store.loadRecovery()
        XCTAssertFalse(store.busy)
        store.switchWorkspace(.uninstall)
        XCTAssertEqual(store.workspace, .junk)
        store.cancel()
    }
}
#endif
