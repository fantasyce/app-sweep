import Foundation
import XCTest
@testable import AppSweepCore

final class CatalogBlockingTests: XCTestCase, @unchecked Sendable {
    func testCancelCatalogReleasesEngineWhileNativeLookupStillWaits() async throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let engine = SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:false),vaultPath:f.vault)
        let entered = expectation(description:"Catalog entered native discovery")
        let returned = expectation(description:"Cancellation returned before native lookup")
        let available = expectation(description:"Same engine accepts next read")
        let nativeReturned = expectation(description:"Native worker ended before fixture cleanup")
        let release = DispatchSemaphore(value:0)
        let catalog = Task {
            defer { returned.fulfill() }
            do {
                _ = try await engine.applicationCatalog(indexLookup:{ _ in
                    defer { nativeReturned.fulfill() }
                    entered.fulfill(); release.wait(); try ScanCancellation.check(); return []
                })
                XCTFail("Cancelled catalog must not publish findings")
            } catch is CancellationError { }
            catch { XCTFail("Expected cancellation, got \(error)") }
        }
        await fulfillment(of:[entered],timeout:3)
        catalog.cancel()
        let next = Task { _ = try? await engine.cleanupIgnores(); available.fulfill() }
        await fulfillment(of:[returned,available],timeout:1)
        release.signal()
        await catalog.value; await next.value
        await fulfillment(of:[nativeReturned],timeout:2)
        XCTAssertFalse(FileManager.default.fileExists(atPath:f.vault))
    }
}
