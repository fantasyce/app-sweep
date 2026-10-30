#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

final class ApplicationIndexTests: XCTestCase, @unchecked Sendable {
    func testHTTPStorageNamespaceEndingInAppDoesNotBecomeAnUnconfirmedInstallation() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let storage = f.home + "/Library/HTTPStorages/local.fixture.app"
        try FileManager.default.createDirectory(atPath:storage,withIntermediateDirectories:true)
        try Data("HTTP storage fixture".utf8).write(to:URL(fileURLWithPath:storage + "/httpstorages.sqlite"))
        let inventory = try AppInspector.inventorySnapshot(home:f.home,registryLookup:{ _ in [] },indexLookup:{ _ in [storage] })
        XCTAssertTrue(inventory.issues.isEmpty)
        XCTAssertFalse(inventory.applications.contains { $0.path == storage })
        XCTAssertEqual(try String(contentsOfFile:storage + "/httpstorages.sqlite",encoding:.utf8),"HTTP storage fixture")
    }
    func testIndexOutputIsBoundedCanonicalAndRestrictedToItsHome() throws {
        let home = "/Users/fixture"
        XCTAssertEqual(try ApplicationIndex.paths("", home: home), [])
        XCTAssertEqual(try ApplicationIndex.paths(home + "/Downloads/Portable.app\0" + home + "/Downloads/Portable.app\0", home: home), [home + "/Downloads/Portable.app"])
        for output in [home + "/Incomplete.app", "/Users/other/App.app\0", home + "/../Other.app\0", home + "/../document.txt\0"] {
            XCTAssertThrowsError(try ApplicationIndex.paths(output, home: home))
        }
    }
    func testCanonicalNonApplicationMetadataHitDoesNotHideValidIndexedApplication() throws {
        let output = "/Users/fixture/Library/HTTPStorages/com.apple.ctcategories.service\0/Users/fixture/Downloads/Portable.app\0/Users/fixture/notes.txt\0"
        XCTAssertEqual(try ApplicationIndex.paths(output,home:"/Users/fixture"),["/Users/fixture/Downloads/Portable.app"])
    }
    func testIndexedApplicationScriptsNamespaceEndingInAppIsNotAnInstalledOwner() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let storage = f.home + "/Library/Application Scripts/group.is.workflow.my.app"
        try FileManager.default.createDirectory(atPath: storage, withIntermediateDirectories: true)
        try Data("script data".utf8).write(to: URL(fileURLWithPath: storage + "/storage"))
        let inventory = try AppInspector.inventorySnapshot(home: f.home, registryLookup: { _ in [] }, indexLookup: { _ in [storage] })
        XCTAssertTrue(inventory.issues.isEmpty, "A native scripts namespace is storage even when its identifier ends in .app")
        XCTAssertFalse(inventory.applications.contains { $0.path == storage })
        XCTAssertTrue(inventory.applications.contains { $0.path == f.app })
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: storage + "/storage")), Data("script data".utf8))
    }
    func testApplicationAndUnconfirmedContentsInsideScriptsStorageRemainOwnershipEvidence() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let root = f.home + "/Library/Application Scripts"
        try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
        let app = root + "/group.fixture.real.app", alias = root + "/group.fixture.alias.app"
        try FileManager.default.copyItem(atPath: f.app, toPath: app)
        try FileManager.default.createDirectory(atPath: alias, withIntermediateDirectories: false)
        try FileManager.default.createSymbolicLink(atPath: alias + "/Contents", withDestinationPath: app + "/Contents")
        let inventory = try AppInspector.inventorySnapshot(home: f.home, registryLookup: { _ in [] }, indexLookup: { _ in [app, alias] })
        XCTAssertTrue(inventory.applications.contains { $0.path == app })
        XCTAssertFalse(AppInspector.uniqueOwner(identifier: "org.example.sweepfixture", path: f.app, inventory: inventory.applications))
        XCTAssertTrue(inventory.issues.contains { $0.contains(alias) })
    }
    func testIndexFailureRetainsKnownApplicationsAndReportsTheUnknownDiscoveryScope() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let inventory = try AppInspector.inventorySnapshot(home: f.home, registryLookup: { _ in [] }, indexLookup: { _ in throw SweepError.incomplete("index unavailable") })
        XCTAssertTrue(inventory.applications.contains { $0.path == f.app })
        XCTAssertTrue(AppInspector.uniqueOwner(identifier: "org.example.sweepfixture", path: f.app, inventory: inventory.applications))
        XCTAssertTrue(inventory.issues.contains { $0.contains("index unavailable") })
    }
    func testDiscoveryFailureDoesNotBlockAnIndependentlyConfirmedCacheScope() throws {
        let f = try NativeAcceptanceTests.NativeFixture(additionalRules: [CacheDomainRule.name]); defer { try? f.clean() }; try f.generate()
        let output = try Scanner(policy: SafetyPolicy(home: f.home, acceptedPlatform: true, validatedRules: [CacheDomainRule.name])).junk(indexLookup: { _ in throw SweepError.incomplete("supplemental index unavailable") })
        XCTAssertFalse(output.report.complete)
        XCTAssertTrue(output.report.issues.contains { $0.contains("supplemental index unavailable") })
        XCTAssertTrue(output.report.selectableCandidates(includeUserData: false).contains { $0.rule == CacheDomainRule.name }, "A discovery warning must not invalidate verified filesystem scopes")
    }
    func testIndexedPortableCopyAndEmbeddedComponentsAreInspectedWithoutFollowingAliases() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let portable = f.home + "/Downloads/Portable.app", embedded = portable + "/Contents/Helpers/Embedded.app", alias = f.home + "/Downloads/Alias.app"
        try FileManager.default.createDirectory(atPath: f.home + "/Downloads", withIntermediateDirectories: true)
        try FileManager.default.copyItem(atPath: f.app, toPath: portable)
        try FileManager.default.createDirectory(atPath: portable + "/Contents/Helpers", withIntermediateDirectories: true)
        try FileManager.default.copyItem(atPath: f.app, toPath: embedded)
        try FileManager.default.createSymbolicLink(atPath: alias, withDestinationPath: portable)
        let inventory = try AppInspector.inventorySnapshot(home: f.home, registryLookup: { _ in [] }, indexLookup: { _ in [portable, portable, embedded, alias, f.home + "/missing.app"] })
        XCTAssertEqual(inventory.applications.filter { $0.bundleIdentifier == "org.example.sweepfixture" }.count, 3)
        XCTAssertFalse(inventory.applications.contains { $0.path == alias || $0.path.hasSuffix("/missing.app") })
        XCTAssertNotNil(inventory.applications.first { $0.path == embedded }?.protectedReason)
        XCTAssertTrue(inventory.issues.contains { $0.contains("Alias.app") })
        XCTAssertFalse(AppInspector.uniqueOwner(identifier: "org.example.sweepfixture", path: f.app, inventory: inventory.applications))
    }
    func testPublicCatalogFindsAnExistingIndexedPortableFixture() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_INDEX_ACCEPTANCE"] == "1" else { throw XCTSkip("Explicit existing indexed fixture acceptance") }
        let task = try SystemIdentity.home() + "/AppSweepAcceptanceGeneral-20261016"
        let home = try String(contentsOfFile: task + "/ui-fixture-home.txt", encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        guard home.hasPrefix(task + "/fixtures/"), UUID(uuidString: URL(fileURLWithPath: home).lastPathComponent) != nil else { throw SweepError.invalid("Owned fixture marker is not valid") }
        let target = home + "/Downloads/Portable Fixture.app"
        _ = try AppInspector.inspect(target, verifySignature: false)
        let indexed = try ApplicationIndex.systemPaths(home:SystemIdentity.home())
        let catalog = try await SweepEngine().applicationCatalog()
        print("Portable discovery evidence: indexed=\(indexed.contains(target)), indexCount=\(indexed.count), catalogCount=\(catalog.applications.count), issues=\(catalog.unconfirmedIssues)")
        XCTAssertTrue(catalog.applications.contains { $0.path == target }, "An existing indexed app outside both Applications directories must be shown")
        print("Existing portable fixture catalog path: " + target)
    }
}
#endif
