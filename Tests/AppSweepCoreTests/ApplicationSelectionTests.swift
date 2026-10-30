#if os(macOS)
import XCTest
@testable import AppSweepCore
@testable import AppSweepApp

final class ApplicationSelectionTests: XCTestCase {
    private func app(_ name: String, protected: Bool = false) -> ApplicationIdentity {
        .init(path:"/fixture/Applications/\(name).app",name:name,bundleIdentifier:"org.example.\(name.lowercased())",signed:true,protectedReason:protected ? "系统保护" : nil)
    }
    @MainActor
    func testSearchCannotKeepAnInvisibleUninstallOrOptimizationTarget() {
        let first = app("First"), second = app("Second"), store = SweepStore()
        store.apps = [first,second]; store.selectedApp = first.path
        store.query = "second"
        XCTAssertEqual(store.filteredApps.map(\.path),[second.path])
        XCTAssertNil(store.selectedApp)
        store.openOptimization()
        XCTAssertNil(store.optimizationSelection)
    }
    @MainActor
    func testSearchKeepsVisibleSelectionAndClearsItOnNoMatch() {
        let item = app("First"), store = SweepStore()
        store.apps = [item]; store.selectedApp = item.path
        store.query = "FIRST"
        XCTAssertEqual(store.selectedApp,item.path)
        store.query = "no-match"
        XCTAssertNil(store.selectedApp)
        store.query = ""
        XCTAssertNil(store.selectedApp,"Clearing search must not silently resurrect the old target")
    }
    @MainActor
    func testHidingProtectedApplicationsClearsHiddenSelection() {
        let item = app("Protected",protected:true), store = SweepStore()
        store.apps = [item]; store.showRetainedApps = true; store.selectedApp = item.path
        store.showRetainedApps = false
        XCTAssertNil(store.selectedApp)
    }
    @MainActor
    func testCatalogRefreshDropsRemovedTargetButPreservesExplicitExternalSelection() {
        let item = app("First"), store = SweepStore()
        store.apps = [item]; store.selectedApp = item.path
        store.apps = []
        XCTAssertNil(store.selectedApp)
        store.selectedApp = "/fixture/Downloads/Chosen.app"
        store.apps = [item]
        XCTAssertEqual(store.selectedApp,"/fixture/Downloads/Chosen.app")
        store.query = "first"
        XCTAssertNil(store.selectedApp)
    }
}
#endif
