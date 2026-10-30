#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

final class AttributionInventoryRegressionTests: XCTestCase, @unchecked Sendable {
    private func bundle(_ path: String, identifier: String, executable: String = "fixture", flat: Bool = false) throws {
        let body = flat ? path : path + "/Contents"
        try FileManager.default.createDirectory(atPath:body,withIntermediateDirectories:true)
        let info = ["CFBundleIdentifier":identifier,"CFBundleExecutable":executable,"CFBundlePackageType":"APPL"]
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:body + "/Info.plist"))
    }
    private func installOddities(_ home: String) throws -> (String,String,String) {
        let plain = home + "/Applications/Dotless.app"
        try bundle(plain,identifier:"newMaonoLinkMacOS")
        let wrapped = home + "/Applications/Mobile.app", inner = wrapped + "/Wrapper/Mobile.app"
        try bundle(inner,identifier:"org.example.mobile",flat:true)
        try FileManager.default.createSymbolicLink(atPath:wrapped + "/WrappedBundle",withDestinationPath:"Wrapper/Mobile.app")
        let bridge = home + "/Applications/Bridge.app"
        try bundle(bridge,identifier:"org.example.bridge",executable:"bridge")
        try FileManager.default.createDirectory(atPath:bridge + "/Contents/MacOS",withIntermediateDirectories:true)
        // The target must never be traversed to classify the declared executable.
        try FileManager.default.createSymbolicLink(atPath:bridge + "/Contents/MacOS/bridge",withDestinationPath:home + "/outside-unreadable-executable")
        return (plain,wrapped,bridge)
    }
    func testDotlessMetadataIdentityDoesNotInventAnUnknownInstalledOwner() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let path = f.home + "/Applications/Dotless.app"
        try bundle(path,identifier:"newMaonoLinkMacOS")
        let apps = try AppInspector.inventory(home:f.home,registryLookup:{ _ in [] },indexLookup:{ _ in [] })
        XCTAssertEqual(apps.first { $0.path == path }?.bundleIdentifier,"newMaonoLinkMacOS")
        XCTAssertTrue(AppInspector.uniqueOwner(identifier:"org.example.sweepfixture",path:f.app,inventory:apps))
        for value in ["", ".", "..", "../escape", "name/escape", "name\0escape", "name with spaces"] {
            XCTAssertFalse(AppInspector.validIdentifier(value),value)
        }
    }
    func testWrappedMobileMetadataIsConflictEvidenceAndDoesNotAuthorizeItsBody() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let path = f.home + "/Applications/Mobile.app", inner = path + "/Wrapper/Mobile.app"
        try bundle(inner,identifier:"org.example.mobile",flat:true)
        try FileManager.default.createSymbolicLink(atPath:path + "/WrappedBundle",withDestinationPath:"Wrapper/Mobile.app")
        let apps = try AppInspector.inventory(home:f.home,registryLookup:{ _ in [] },indexLookup:{ _ in [] })
        XCTAssertFalse(apps.contains { $0.bundleIdentifier.isEmpty })
        let outer = try XCTUnwrap(apps.first { $0.path == path })
        XCTAssertEqual(outer.bundleIdentifier,"org.example.mobile")
        XCTAssertFalse(outer.signed); XCTAssertNotNil(outer.protectedReason)
        XCTAssertTrue(apps.contains { $0.path == inner && $0.bundleIdentifier == "org.example.mobile" })
        XCTAssertTrue(AppInspector.uniqueOwner(identifier:"org.example.sweepfixture",path:f.app,inventory:apps))
        XCTAssertThrowsError(try AppInspector.inspect(path),"Read-only wrapper recognition cannot create ordinary bundle execution authority")
    }
    func testDeclaredExternalExecutableAliasBlocksItsOwnDataWithoutBlockingOtherOwners() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let bridge = f.home + "/Applications/Bridge.app"
        try bundle(bridge,identifier:"org.example.bridge",executable:"bridge")
        try FileManager.default.createDirectory(atPath:bridge + "/Contents/MacOS",withIntermediateDirectories:true)
        let alias = bridge + "/Contents/MacOS/bridge"
        try FileManager.default.createSymbolicLink(atPath:alias,withDestinationPath:f.home + "/absent-outside")
        let apps = try AppInspector.inventory(home:f.home,registryLookup:{ _ in [] },indexLookup:{ _ in [] })
        XCTAssertEqual(apps.first { $0.path == alias }?.bundleIdentifier,"org.example.bridge")
        XCTAssertFalse(AppInspector.uniqueOwner(identifier:"org.example.bridge",path:bridge,inventory:apps),"The external dependency must not authorize its own app data")
        XCTAssertTrue(AppInspector.uniqueOwner(identifier:"org.example.sweepfixture",path:f.app,inventory:apps))
        XCTAssertFalse(FileManager.default.fileExists(atPath:f.home + "/absent-outside"))
    }
    func testQuotedMetadataPeerRetainsConflictEvidenceWithoutBlockingUnrelatedRuntime() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let peer = f.home + "/Applications/Peer.app", preview = peer + "/Contents/Helpers/Preview.app"
        try bundle(peer,identifier:"org.example.peer")
        try bundle(preview,identifier:"\"org.example.preview\"")
        try FileManager.default.createDirectory(atPath:preview + "/Contents/MacOS",withIntermediateDirectories:true)
        try Data("declared component executable".utf8).write(to:URL(fileURLWithPath:preview + "/Contents/MacOS/fixture"))
        var apps = try AppInspector.inventory(home:f.home,registryLookup:{ _ in [] },indexLookup:{ _ in [] })
        let hint = try XCTUnwrap(apps.first { $0.path == preview })
        XCTAssertEqual(hint.bundleIdentifier,"org.example.preview")
        XCTAssertEqual(hint.attributionRawIdentifier,"\"org.example.preview\"")
        XCTAssertFalse(hint.signed)
        XCTAssertNotNil(hint.protectedReason)
        XCTAssertNoThrow(try ChromiumCacheRule.verifyNoRuntimeOverlap(identifier:"org.example.sweepfixture",inventory:apps))
        let plist = preview + "/Contents/Info.plist"
        var info = try XCTUnwrap(PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:plist)),format:nil) as? [String:Any])
        info["CrProductDirName"] = "org.example.sweepfixture"
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:plist))
        apps = try AppInspector.inventory(home:f.home,registryLookup:{ _ in [] },indexLookup:{ _ in [] })
        XCTAssertThrowsError(try ChromiumCacheRule.verifyNoRuntimeOverlap(identifier:"org.example.sweepfixture",inventory:apps)) { error in
            XCTAssertTrue(error.localizedDescription.contains("命名空间重叠"),error.localizedDescription)
        }
        info["CFBundleIdentifier"] = "org.example.changed"
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:plist))
        XCTAssertThrowsError(try ChromiumCacheRule.verifyNoRuntimeOverlap(identifier:"unrelated",inventory:apps)) { error in
            XCTAssertTrue(error.localizedDescription.contains("标识已改变"),error.localizedDescription)
        }
    }
    func testGenuinelyUnknownBundleStillBlocksOwnership() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        try FileManager.default.createDirectory(atPath:f.home + "/Applications/Unknown.app/Contents",withIntermediateDirectories:true)
        let apps = try AppInspector.inventory(home:f.home,registryLookup:{ _ in [] },indexLookup:{ _ in [] })
        XCTAssertTrue(apps.contains { $0.bundleIdentifier.isEmpty })
        XCTAssertFalse(AppInspector.uniqueOwner(identifier:"org.example.sweepfixture",path:f.app,inventory:apps))
    }
    func testWrappedApplicationDoesNotHideOtherPhysicalOwnersOrUnknownContents() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let outer = f.home + "/Applications/Mobile.app"
        try bundle(outer + "/Wrapper/Mobile.app",identifier:"org.example.mobile",flat:true)
        try bundle(outer + "/Other.app",identifier:"org.example.sweepfixture")
        var apps = try AppInspector.inventory(home:f.home,registryLookup:{ _ in [] },indexLookup:{ _ in [] })
        XCTAssertFalse(AppInspector.uniqueOwner(identifier:"org.example.sweepfixture",path:f.app,inventory:apps))
        XCTAssertTrue(apps.contains { $0.path == outer + "/Other.app" })
        try FileManager.default.createDirectory(atPath:outer + "/Unknown.app/Contents",withIntermediateDirectories:true)
        apps = try AppInspector.inventory(home:f.home,registryLookup:{ _ in [] },indexLookup:{ _ in [] })
        XCTAssertTrue(apps.contains { $0.path == outer + "/Unknown.app" && $0.bundleIdentifier.isEmpty })
    }
    func testAmbiguousOrLinkedWrapperRemainsUnknownWithoutFollowingIt() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let ambiguous = f.home + "/Applications/Ambiguous.app"
        try bundle(ambiguous + "/Wrapper/First.app",identifier:"org.example.first",flat:true)
        try bundle(ambiguous + "/Wrapper/Second.app",identifier:"org.example.second",flat:true)
        let linked = f.home + "/Applications/Linked.app"
        try FileManager.default.createDirectory(atPath:linked,withIntermediateDirectories:true)
        try FileManager.default.createSymbolicLink(atPath:linked + "/Wrapper",withDestinationPath:ambiguous + "/Wrapper")
        let apps = try AppInspector.inventory(home:f.home,registryLookup:{ _ in [] },indexLookup:{ _ in [] })
        for path in [ambiguous,linked] { XCTAssertTrue(apps.contains { $0.path == path && $0.bundleIdentifier.isEmpty }) }
        XCTAssertFalse(apps.contains { $0.path.hasPrefix(linked + "/Wrapper/") })
    }
    func testExternalExecutableOwnerStillContributesRuntimeNamespaceConflicts() async throws {
        let f = try NativeAcceptanceTests.NativeFixture(additionalRules:[SelectedApplicationRule.name,CacheDomainRule.name]); defer { try? f.clean() }
        try f.generate(); let (_,_,bridge) = try installOddities(f.home)
        let plist = bridge + "/Contents/Info.plist"
        var info = try XCTUnwrap(PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:plist)),format:nil) as? [String:Any])
        info["CrProductDirName"] = "org.example.sweepfixture"
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:plist))
        let report = try await f.engine.scanApplication(f.app)
        XCTAssertFalse(report.selectableCandidates(includeUserData:false).contains { $0.rule == CacheDomainRule.name })
        XCTAssertTrue(report.candidates.contains { $0.retentionReason?.contains("命名空间重叠") == true })
        XCTAssertEqual(try String(contentsOfFile:f.home + "/Library/Caches/org.example.sweepfixture/payload",encoding:.utf8),"HTTP fixture content")
    }
    func testSignedAppAndCacheCanBePlannedIsolatedAndRestoredBesideUnrelatedInstallOddities() async throws {
        let f = try NativeAcceptanceTests.NativeFixture(additionalRules:[SelectedApplicationRule.name,CacheDomainRule.name]); defer { try? f.clean() }
        try f.generate(); _ = try installOddities(f.home)
        try await f.waitUntilUnused(f.app)
        let root = f.home + "/Library/Caches/org.example.sweepfixture", before = try SafeDirectory(path:root).ownIdentity
        let bytes = try Data(contentsOf:URL(fileURLWithPath:root + "/payload"))
        let report = try await f.engine.scanApplication(f.app)
        let caches = report.selectableCandidates(includeUserData:false).filter { $0.rule == CacheDomainRule.name && $0.path.hasPrefix(root + "/") }
        XCTAssertFalse(caches.isEmpty,"An unrelated executable alias, dotless ID and wrapper must not invalidate a uniquely verified signed cache owner: \(report.candidates.filter { $0.path.hasPrefix(root) }); issues: \(report.issues)")
        guard !caches.isEmpty else { return }
        let body = try XCTUnwrap(report.selectableCandidates(includeUserData:false).first { $0.path == f.app && $0.category == .application })
        let ids = Set(([body] + caches).map(\.id))
        let plan = try await f.engine.makePlan(reportID:report.id,selected:ids,includeUserData:false)
        let moved = try await f.engine.execute(planID:plan.id)
        XCTAssertEqual(moved.status,.isolated,moved.issue ?? "")
        XCTAssertFalse(FileManager.default.fileExists(atPath:f.app))
        for item in caches { XCTAssertFalse(FileManager.default.fileExists(atPath:item.path)) }
        let restored = try await f.restoreWhenUnused(moved)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        XCTAssertEqual(try SafeDirectory(path:root).ownIdentity.inode,before.inode)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:root + "/payload")),bytes)
        XCTAssertTrue(FileManager.default.fileExists(atPath:f.app))
        try f.generate()
    }
}
#endif
