#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

final class ApplicationRegistryTests: XCTestCase, @unchecked Sendable {
    func testUUIDRegistrationRemainsAReadOnlyConflictHint() throws {
        let f=try NativeAcceptanceTests.NativeFixture();defer{try? f.clean()}
        let stored=f.home + "/" + UUID().uuidString
        try FileManager.default.copyItem(atPath:f.app,toPath:stored)
        let urls=try ApplicationRegistry.locations(identifiers:["org.example.sweepfixture"],lookup:{_ in [URL(fileURLWithPath:stored)]})
        XCTAssertEqual(urls.first?.path,stored)
        let inventory=try AppInspector.inventory(home:f.home,registryLookup:{id in id == "org.example.sweepfixture" ? [URL(fileURLWithPath:stored)] : []})
        XCTAssertFalse(AppInspector.uniqueOwner(identifier:"org.example.sweepfixture",path:f.app,inventory:inventory))
        XCTAssertNotNil(inventory.first{$0.path == stored}?.protectedReason)
        XCTAssertFalse(SelectedApplicationRule.matches(path:stored,policy:SafetyPolicy(home:f.home,acceptedPlatform:false)))
    }
    func testRegisteredCopyOutsideApplicationsPreventsExclusiveDataOwnership() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let duplicate = f.home + "/Downloads/Second.app"
        try FileManager.default.createDirectory(atPath: f.home + "/Downloads", withIntermediateDirectories: true)
        try FileManager.default.copyItem(atPath: f.app, toPath: duplicate)
        let apps = try AppInspector.inventory(home: f.home, registryLookup: { id in id == "org.example.sweepfixture" ? [URL(fileURLWithPath: duplicate)] : [] })
        XCTAssertEqual(apps.filter { $0.bundleIdentifier == "org.example.sweepfixture" }.count, 2)
        XCTAssertFalse(AppInspector.uniqueOwner(identifier: "org.example.sweepfixture", path: f.app, inventory: apps))
    }
    func testStaleAndDuplicateRegistrationsDoNotInventOwners() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let apps = try AppInspector.inventory(home: f.home, selectedApplication: f.app, registryLookup: { id in
            id == "org.example.sweepfixture" ? [URL(fileURLWithPath: f.app), URL(fileURLWithPath: f.app), URL(fileURLWithPath: f.home + "/missing.app")] : []
        })
        XCTAssertEqual(apps.filter { $0.bundleIdentifier == "org.example.sweepfixture" }.count, 1)
        XCTAssertTrue(AppInspector.uniqueOwner(identifier: "org.example.sweepfixture", path: f.app, inventory: apps))
        let absent = try AppInspector.inventory(home: f.home, ownershipIdentifier: "org.example.absent", registryLookup: { _ in [URL(fileURLWithPath: f.home + "/missing.app")] })
        XCTAssertFalse(absent.contains { $0.path.hasSuffix("/missing.app") })
    }
    func testMalformedRegisteredCopyRemainsAConflictForItsQueriedIdentifier() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let unknown = f.home + "/Downloads/Unknown.app"
        try FileManager.default.createDirectory(atPath: unknown, withIntermediateDirectories: true)
        let apps = try AppInspector.inventory(home: f.home, registryLookup: { id in id == "org.example.sweepfixture" ? [URL(fileURLWithPath: unknown)] : [] })
        XCTAssertFalse(AppInspector.uniqueOwner(identifier: "org.example.sweepfixture", path: f.app, inventory: apps))
        let hint = try XCTUnwrap(apps.first { $0.path == unknown })
        XCTAssertEqual(hint.bundleIdentifier, "org.example.sweepfixture"); XCTAssertFalse(hint.signed); XCTAssertNotNil(hint.protectedReason)
    }
    func testRegisteredAliasIsNotFollowedOrUsedToAuthorizeData() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let alias = f.home + "/Downloads/Link.app"
        try FileManager.default.createDirectory(atPath: f.home + "/Downloads", withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: alias, withDestinationPath: f.app)
        let apps = try AppInspector.inventory(home: f.home, registryLookup: { id in id == "org.example.sweepfixture" ? [URL(fileURLWithPath: alias)] : [] })
        XCTAssertFalse(AppInspector.uniqueOwner(identifier: "org.example.sweepfixture", path: f.app, inventory: apps))
        XCTAssertEqual(apps.first { $0.path == alias }?.bundleIdentifier, "org.example.sweepfixture")
        XCTAssertTrue(FileManager.default.fileExists(atPath: f.app))
    }
    func testNestedComponentsOfSelectedPortableAppStillBlockSharedData() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let portable = f.home + "/Downloads/Portable.app", embedded = portable + "/Contents/Helpers/Inner.app"
        try FileManager.default.createDirectory(atPath: f.home + "/Downloads", withIntermediateDirectories: true)
        try FileManager.default.copyItem(atPath: f.app, toPath: portable)
        try FileManager.default.createDirectory(atPath: portable + "/Contents/Helpers", withIntermediateDirectories: true)
        try FileManager.default.copyItem(atPath: f.app, toPath: embedded)
        let apps = try AppInspector.inventory(home: f.home, selectedApplication: portable, registryLookup: { _ in [] })
        XCTAssertEqual(apps.filter { $0.bundleIdentifier == "org.example.sweepfixture" }.count, 3)
        XCTAssertNotNil(apps.first { $0.path == embedded }?.protectedReason)
        XCTAssertFalse(AppInspector.uniqueOwner(identifier: "org.example.sweepfixture", path: portable, inventory: apps))
    }
    func testRegistryErrorsAndMalformedURLsNeverBecomeNoOtherApplications() throws {
        XCTAssertThrowsError(try ApplicationRegistry.locations(identifiers: ["org.example.valid"], lookup: { _ in throw SweepError.incomplete("denied") }))
        XCTAssertThrowsError(try ApplicationRegistry.locations(identifiers: ["org.example.valid"], lookup: { _ in [URL(string: "https://example.org/Test.app")!] }))
        XCTAssertThrowsError(try ApplicationRegistry.locations(identifiers: ["invalid/identifier"], lookup: { _ in [] }))
        XCTAssertEqual(try ApplicationRegistry.locations(identifiers: ["newMaonoLinkMacOS"], lookup: { _ in [] }), [])
    }
    func testUnrelatedRegistryFailureOnlyBlocksThatApplicationData() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let unrelated = f.home + "/Applications/Unrelated.app/Contents"
        try FileManager.default.createDirectory(atPath: unrelated, withIntermediateDirectories: true)
        try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier":"org.example.unrelated"], format: .xml, options: 0).write(to: URL(fileURLWithPath: unrelated + "/Info.plist"))
        let apps = try AppInspector.inventory(home: f.home, registryLookup: { identifier in
            if identifier == "org.example.unrelated" { throw SweepError.incomplete("registration temporarily unavailable") }
            return []
        })
        XCTAssertTrue(AppInspector.uniqueOwner(identifier: "org.example.sweepfixture", path: f.app, inventory: apps))
        XCTAssertFalse(AppInspector.uniqueOwner(identifier: "org.example.unrelated", path: f.home + "/Applications/Unrelated.app", inventory: apps))
        XCTAssertTrue(apps.contains { $0.bundleIdentifier == "org.example.unrelated" && $0.path.isEmpty && $0.protectedReason != nil })
    }
    func testPublicRegistryReadOnlyWithExistingOfficialTestApplication() throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_REGISTRY_ACCEPTANCE"] == "1" else { throw XCTSkip("Explicit existing-consumer registration acceptance") }
        let path = FileManager.default.homeDirectoryForCurrentUser.path + "/Applications/Firefox.app"
        XCTAssertEqual(try AppInspector.inspect(path, verifySignature: false).bundleIdentifier, "org.mozilla.firefox")
        let urls = try ApplicationRegistry.systemLocations("org.mozilla.firefox")
        XCTAssertTrue(urls.contains { $0.path == path }, "The normally launched official test application must be discoverable")
        for identifier in ["org.mozilla.firefox", "uk.co.opencommunity.vienna2"] {
            for url in try ApplicationRegistry.systemLocations(identifier) { print("Registered consumer " + identifier + " at " + url.path + "; exists=" + String(FileManager.default.fileExists(atPath: url.path))) }
        }
        let none = try ApplicationRegistry.systemLocations("org.example.missing." + UUID().uuidString)
        XCTAssertTrue(none.isEmpty)
        print("Read-only public registration acceptance: existing Firefox found; absent random ID confirmed; no registrations changed")
    }
}
#endif
