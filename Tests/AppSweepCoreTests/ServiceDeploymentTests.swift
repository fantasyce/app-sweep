#if os(macOS)
import Foundation
import Darwin
import XCTest
import CFSafety
@testable import AppSweepCore

private actor FixtureDeploymentLifecycle: ServiceDeploymentLifecycle {
    var failNextStart: Bool
    private var onStop: (@Sendable () throws -> Void)?
    private var onStart: (@Sendable () throws -> Void)?
    init(failNextStart: Bool = false, onStop: (@Sendable () throws -> Void)? = nil, onStart: (@Sendable () throws -> Void)? = nil) { self.failNextStart = failNextStart; self.onStop = onStop; self.onStart = onStart }
    func stop() async throws { if let action = onStop { onStop = nil; try action() } }
    func start() async throws {
        if failNextStart { failNextStart = false; throw SweepError.filesystem("Fixture service startup failure") }
        if let action = onStart { onStart = nil; try action() }
    }
}

final class ServiceDeploymentTests: XCTestCase, @unchecked Sendable {
    private func fixture() throws -> (NativeAcceptanceTests.NativeFixture,String) {
        let f = try NativeAcceptanceTests.NativeFixture(), library = f.home + "/MachineLibrary"
        try FileManager.default.createDirectory(atPath:library,withIntermediateDirectories:true)
        return (f,library)
    }
    private func payload(_ version: String) throws -> ServiceDeploymentPayload {
        let pins = RootServicePins(schemaVersion:1,serviceBuild:version,clientCodeHashes:[String(repeating:"a",count:40)],serviceCodeHashes:[String(repeating:"b",count:40)])
        return try .fixture(program:Data(("fixture-program-" + version).utf8),configuration:pins.encode())
    }
    private func program(_ library: String) -> String { library + "/Application Support/App Sweep/Service/AppSweepSystemService" }
    private func config(_ library: String) -> String { library + "/Application Support/App Sweep/Service/config.json" }
    private func legacyDeviceJournal(_ path:String,replacedAncestor:Bool=false)throws->Data {
        let url=URL(fileURLWithPath:path)
        var value=try XCTUnwrap(JSONSerialization.jsonObject(with:Data(contentsOf:url))as? [String:Any])
        var seal=try XCTUnwrap(value["seal"]as? [[String:Any]])
        for i in seal.indices {seal[i]["device"]=(seal[i]["device"]as! NSNumber).uint64Value+17;seal[i].removeValue(forKey:"volumeUUID")}
        if replacedAncestor {seal[seal.count-1]["inode"]=(seal[seal.count-1]["inode"]as! NSNumber).uint64Value+1}
        value["seal"]=seal
        let data=try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys]);try data.write(to:url,options:.atomic);return data
    }
    func testCompletedLegacyHistoryDoesNotBlockFreshUpgradeOrRewriteOldJournal()async throws{
        let(f,library)=try fixture();defer{try? f.clean()}
        let first=try await ServiceDeployment.fixture(libraryRoot:library).install(payload("one"),lifecycle:FixtureDeploymentLifecycle())
        let legacy=try legacyDeviceJournal(first.journalPath)
        let second=try await ServiceDeployment.fixture(libraryRoot:library).install(payload("two"),lifecycle:FixtureDeploymentLifecycle())
        XCTAssertEqual(second.status,.installed)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:program(library))),Data("fixture-program-two".utf8))
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:first.journalPath)),legacy)
    }
    func testUnfinishedLegacyJournalCannotAuthorizeUpgradeOrRecoveryOnUnconfirmedVolume()async throws{
        let(f,library)=try fixture();defer{try? f.clean()}
        let interrupted=try ServiceDeployment.fixture(libraryRoot:library,failurePoint:.interruptAfterProgramPublication)
        do{_=try await interrupted.install(payload("one"),lifecycle:FixtureDeploymentLifecycle());XCTFail("Expected interrupted component publication")}catch{}
        let vault=library+"/Application Support/App Sweep/Installation.noindex",names=try FileManager.default.contentsOfDirectory(atPath:vault)
        XCTAssertEqual(names.count,1);let path=vault+"/"+(try XCTUnwrap(names.first))+"/installation.json",legacy=try legacyDeviceJournal(path)
        let before=try Data(contentsOf:URL(fileURLWithPath:program(library)))
        do{_=try await ServiceDeployment.fixture(libraryRoot:library).install(payload("two"),lifecycle:FixtureDeploymentLifecycle());XCTFail("Unconfirmed pending scope authorized upgrade")}catch{}
        do{_=try await ServiceDeployment.fixture(libraryRoot:library).recover(lifecycle:FixtureDeploymentLifecycle());XCTFail("Unconfirmed pending scope authorized recovery")}catch{}
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:program(library))),before)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:path)),legacy)
    }
    func testCompletedLegacyJournalWithChangedAncestorStillBlocksUpgrade()async throws{
        let(f,library)=try fixture();defer{try? f.clean()}
        let first=try await ServiceDeployment.fixture(libraryRoot:library).install(payload("one"),lifecycle:FixtureDeploymentLifecycle())
        let legacy=try legacyDeviceJournal(first.journalPath,replacedAncestor:true)
        do{_=try await ServiceDeployment.fixture(libraryRoot:library).install(payload("two"),lifecycle:FixtureDeploymentLifecycle());XCTFail("Replaced ancestor was accepted as completed history")}catch{}
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:program(library))),Data("fixture-program-one".utf8))
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:first.journalPath)),legacy)
    }
    private func marker(_ library: String) throws -> String {
        let path = library + "/Application Support/App Sweep/Recovery.noindex/501/preserved-data"
        try FileManager.default.createDirectory(atPath:URL(fileURLWithPath:path).deletingLastPathComponent().path,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
        try Data("keep recovery data".utf8).write(to:URL(fileURLWithPath:path))
        return path
    }
    func testInstallAndUpgradeKeepRecoveryDataAndUseOnlyFixedDestinations() async throws {
        let (f,library) = try fixture(); defer { try? f.clean() }
        let preserved = try marker(library)
        let deployment = try ServiceDeployment.fixture(libraryRoot:library), lifecycle = FixtureDeploymentLifecycle()
        let first = try await deployment.install(payload("one"),lifecycle:lifecycle)
        XCTAssertEqual(first.status,.installed)
        let second = try await deployment.install(payload("two"),lifecycle:lifecycle)
        XCTAssertEqual(second.status,.installed)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:program(library))),Data("fixture-program-two".utf8))
        XCTAssertEqual(try RootServicePins.decode(Data(contentsOf:URL(fileURLWithPath:config(library)))).serviceBuild,"two")
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:preserved)),Data("keep recovery data".utf8))
        XCTAssertEqual(try SafeFilesystem.snapshot(program(library)).identity.mode & 0o777,0o755)
        XCTAssertEqual(try SafeFilesystem.snapshot(config(library)).identity.mode & 0o777,0o644)
        XCTAssertTrue(FileManager.default.fileExists(atPath:library + "/LaunchDaemons/org.appsweep.system-service.plist"))
        XCTAssertTrue(FileManager.default.fileExists(atPath:second.journalPath))
    }
    func testRequestedScansUseStandardScheduling() async throws {
        let (f,library) = try fixture(); defer { try? f.clean() }
        _ = try await ServiceDeployment.fixture(libraryRoot:library).install(payload("one"),lifecycle:FixtureDeploymentLifecycle())
        let data = try Data(contentsOf:URL(fileURLWithPath:library + "/LaunchDaemons/org.appsweep.system-service.plist"))
        let declaration = try XCTUnwrap(PropertyListSerialization.propertyList(from:data,format:nil) as? [String:Any])
        XCTAssertEqual(declaration["ProcessType"] as? String,"Standard","User-requested bounded occupancy checks must not inherit background I/O throttling")
    }
    func testLegacyBackgroundDeclarationUpgradesAndRollbackPreservesIt() async throws {
        let (f,library) = try fixture(); defer { try? f.clean() }
        let deployment = try ServiceDeployment.fixture(libraryRoot:library)
        _ = try await deployment.install(payload("one"),lifecycle:FixtureDeploymentLifecycle())
        let url = URL(fileURLWithPath:library + "/LaunchDaemons/org.appsweep.system-service.plist")
        var declaration = try XCTUnwrap(PropertyListSerialization.propertyList(from:Data(contentsOf:url),format:nil) as? [String:Any])
        declaration["ProcessType"] = "Background"
        let legacy = try PropertyListSerialization.data(fromPropertyList:declaration,format:.xml,options:0)
        try legacy.write(to:url)
        let failed = try await deployment.install(payload("two"),lifecycle:FixtureDeploymentLifecycle(failNextStart:true))
        XCTAssertEqual(failed.status,.rolledBack)
        XCTAssertEqual(try Data(contentsOf:url),legacy)
        let upgraded = try await deployment.install(payload("three"),lifecycle:FixtureDeploymentLifecycle())
        XCTAssertEqual(upgraded.status,.installed)
        let current = try XCTUnwrap(PropertyListSerialization.propertyList(from:Data(contentsOf:url),format:nil) as? [String:Any])
        XCTAssertEqual(current["ProcessType"] as? String,"Standard")
    }
    func testLegacyDeclarationWithChangedProgramRemainsRejected() async throws {
        let (f,library) = try fixture(); defer { try? f.clean() }
        let deployment = try ServiceDeployment.fixture(libraryRoot:library)
        _ = try await deployment.install(payload("one"),lifecycle:FixtureDeploymentLifecycle())
        let url = URL(fileURLWithPath:library + "/LaunchDaemons/org.appsweep.system-service.plist")
        var declaration = try XCTUnwrap(PropertyListSerialization.propertyList(from:Data(contentsOf:url),format:nil) as? [String:Any])
        declaration["ProcessType"] = "Background"
        declaration["ProgramArguments"] = ["/tmp/other-program"]
        let changed = try PropertyListSerialization.data(fromPropertyList:declaration,format:.xml,options:0)
        try changed.write(to:url)
        do { _ = try await deployment.install(payload("two"),lifecycle:FixtureDeploymentLifecycle()); XCTFail("Changed program accepted") } catch { }
        XCTAssertEqual(try Data(contentsOf:url),changed)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:program(library))),Data("fixture-program-one".utf8))
    }
    func testFailedStartupRestoresThePreviousCompleteComponentSet() async throws {
        let (f,library) = try fixture(); defer { try? f.clean() }
        let deployment = try ServiceDeployment.fixture(libraryRoot:library)
        _ = try await deployment.install(payload("one"),lifecycle:FixtureDeploymentLifecycle())
        let beforeProgram = try Data(contentsOf:URL(fileURLWithPath:program(library))), beforeConfig = try Data(contentsOf:URL(fileURLWithPath:config(library)))
        let result = try await deployment.install(payload("two"),lifecycle:FixtureDeploymentLifecycle(failNextStart:true))
        XCTAssertEqual(result.status,.rolledBack)
        XCTAssertNotNil(result.issue)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:program(library))),beforeProgram)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:config(library))),beforeConfig)
    }
    func testInterruptedReplacementCanBeRecoveredByANewInstance() async throws {
        let (f,library) = try fixture(); defer { try? f.clean() }
        let deployment = try ServiceDeployment.fixture(libraryRoot:library)
        _ = try await deployment.install(payload("one"),lifecycle:FixtureDeploymentLifecycle())
        let interrupted = try ServiceDeployment.fixture(libraryRoot:library,failurePoint:.interruptAfterProgramPublication)
        do { _ = try await interrupted.install(payload("two"),lifecycle:FixtureDeploymentLifecycle()); XCTFail("Injected interruption must not be reported installed") } catch { }
        let fresh = try ServiceDeployment.fixture(libraryRoot:library)
        let result = try await fresh.recover(lifecycle:FixtureDeploymentLifecycle())
        XCTAssertEqual(result.status,.rolledBack)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:program(library))),Data("fixture-program-one".utf8))
        XCTAssertEqual(try RootServicePins.decode(Data(contentsOf:URL(fileURLWithPath:config(library)))).serviceBuild,"one")
    }
    func testInterruptedStagingRecoversWithoutTouchingTheInstalledVersion() async throws {
        let (f,library) = try fixture(); defer { try? f.clean() }
        _ = try await ServiceDeployment.fixture(libraryRoot:library).install(payload("one"),lifecycle:FixtureDeploymentLifecycle())
        let interrupted = try ServiceDeployment.fixture(libraryRoot:library,failurePoint:.interruptAfterStagingProgram)
        do { _ = try await interrupted.install(payload("two"),lifecycle:FixtureDeploymentLifecycle()); XCTFail("Expected staging interruption") } catch { }
        let fresh = try ServiceDeployment.fixture(libraryRoot:library)
        let result = try await fresh.recover(lifecycle:FixtureDeploymentLifecycle())
        XCTAssertEqual(result.status,.rolledBack)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:program(library))),Data("fixture-program-one".utf8))
        XCTAssertEqual(try RootServicePins.decode(Data(contentsOf:URL(fileURLWithPath:config(library)))).serviceBuild,"one")
        let next = try await fresh.install(payload("three"),lifecycle:FixtureDeploymentLifecycle())
        XCTAssertEqual(next.status,.installed)
    }
    func testDirectorySwapDuringStopNeverWritesIntoDetachedDirectory() async throws {
        let (f,library) = try fixture(); defer { try? f.clean() }
        let deployment = try ServiceDeployment.fixture(libraryRoot:library)
        _ = try await deployment.install(payload("one"),lifecycle:FixtureDeploymentLifecycle())
        let service = library + "/Application Support/App Sweep/Service", detached = f.home + "/detached-service"
        let lifecycle = FixtureDeploymentLifecycle(onStop:{
            let fm = FileManager.default
            try fm.moveItem(atPath:service,toPath:detached)
            try fm.createDirectory(atPath:service,withIntermediateDirectories:false)
            for name in ["AppSweepSystemService","config.json"] { try fm.moveItem(atPath:detached + "/" + name,toPath:service + "/" + name) }
        })
        let result = try await deployment.install(payload("two"),lifecycle:lifecycle)
        XCTAssertEqual(result.status,.needsAttention)
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath:detached).isEmpty,"A stale directory descriptor must not receive a new component")
        XCTAssertTrue(FileManager.default.fileExists(atPath:program(library)),"Changing a parent must stop before any original file moves")
        if FileManager.default.fileExists(atPath:program(library)) { XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:program(library))),Data("fixture-program-one".utf8)) }
    }
    func testInterruptedBatchCreationCanBeExplicitlyRecoveredWithoutStoppingTheOldService() async throws {
        let (f,library) = try fixture(); defer { try? f.clean() }
        _ = try await ServiceDeployment.fixture(libraryRoot:library).install(payload("one"),lifecycle:FixtureDeploymentLifecycle())
        let interrupted = try ServiceDeployment.fixture(libraryRoot:library,failurePoint:.interruptAfterBatchCreation)
        do { _ = try await interrupted.install(payload("two"),lifecycle:FixtureDeploymentLifecycle()); XCTFail("Expected creation interruption") } catch { }
        let fresh = try ServiceDeployment.fixture(libraryRoot:library)
        let recovered = try await fresh.recover(lifecycle:FixtureDeploymentLifecycle(onStop:{ throw SweepError.denied("An unrecorded empty staging directory must not stop the installed service") }))
        XCTAssertEqual(recovered.status,.rolledBack)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:program(library))),Data("fixture-program-one".utf8))
        let next = try await fresh.install(payload("three"),lifecycle:FixtureDeploymentLifecycle())
        XCTAssertEqual(next.status,.installed)
    }
    func testRollbackRevalidatesOldFilesAfterRestartBeforeReportingSuccess() async throws {
        let (f,library) = try fixture(); defer { try? f.clean() }
        let deployment = try ServiceDeployment.fixture(libraryRoot:library)
        _ = try await deployment.install(payload("one"),lifecycle:FixtureDeploymentLifecycle())
        let path = config(library), changed = Data("unexpected config during startup".utf8)
        let lifecycle = FixtureDeploymentLifecycle(failNextStart:true,onStart:{ try changed.write(to:URL(fileURLWithPath:path)) })
        let result = try await deployment.install(payload("two"),lifecycle:lifecycle)
        XCTAssertEqual(result.status,.needsAttention,"A restart is not proof that the restored component set is unchanged")
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:path)),changed)
    }
    func testActiveSystemTransactionLockStopsAnUpgradeBeforeAnyFileChanges() async throws {
        let (f,library) = try fixture(); defer { try? f.clean() }
        let deployment = try ServiceDeployment.fixture(libraryRoot:library)
        _ = try await deployment.install(payload("one"),lifecycle:FixtureDeploymentLifecycle())
        let recovery = try SafeDirectory(path:library + "/Application Support/App Sweep/Recovery.noindex")
        XCTAssertEqual(as_lock(recovery.fd),0)
        do { _ = try await deployment.install(payload("two"),lifecycle:FixtureDeploymentLifecycle()); XCTFail("An active system transaction must exclude installation") } catch { }
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:program(library))),Data("fixture-program-one".utf8))
    }
    func testForeignOwnerInRecoveryJournalCannotAuthorizeAnyComponentMove() async throws {
        let (f,library) = try fixture(); defer { try? f.clean() }
        _ = try await ServiceDeployment.fixture(libraryRoot:library).install(payload("one"),lifecycle:FixtureDeploymentLifecycle())
        let interrupted = try ServiceDeployment.fixture(libraryRoot:library,failurePoint:.interruptAfterProgramPublication)
        do { _ = try await interrupted.install(payload("two"),lifecycle:FixtureDeploymentLifecycle()); XCTFail("Expected interruption") } catch { }
        let before = try Data(contentsOf:URL(fileURLWithPath:program(library)))
        let vault = try SafeDirectory(path:library + "/Application Support/App Sweep/Installation.noindex")
        for name in try FileManager.default.contentsOfDirectory(atPath:vault.path) {
            let batch = try vault.existingPrivateChild(name)
            var object = try XCTUnwrap(JSONSerialization.jsonObject(with:batch.read("installation.json")) as? [String:Any])
            if object["state"] as? String == "replacing" {
                object["owner"] = getuid() + 1
                try batch.write(JSONSerialization.data(withJSONObject:object),name:"installation.json")
            }
        }
        do { _ = try await ServiceDeployment.fixture(libraryRoot:library).recover(lifecycle:FixtureDeploymentLifecycle()); XCTFail("Foreign-owner journal must not authorize recovery") } catch { }
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:program(library))),before)
    }
    func testStickySourceDirectoryCannotBypassGrantACLChecks() throws {
        let (f,library) = try fixture(); defer { try? f.clean() }
        let directory = try SafeDirectory(path:library)
        try FileManager.default.setAttributes([.posixPermissions:0o1777],ofItemAtPath:library)
        XCTAssertEqual(as_no_grant_acl_descriptor(directory.fd),1)
        _ = try BoundedProcess.run("/bin/chmod",arguments:["+a","everyone allow add_file",library],timeout:5)
        XCTAssertEqual(as_no_grant_acl_descriptor(directory.fd),0,"A sticky temporary ancestor must not bypass ACL inspection")
    }
    func testEveryPayloadInternalDirectoryMustBeUnsharedBeforeReadingAnyBytes() throws {
        let (f,library) = try fixture(); defer { try? f.clean() }
        let service = library + "/Library/Application Support/App Sweep/Service", launch = library + "/Library/LaunchDaemons"
        for path in [service,launch] { try FileManager.default.createDirectory(atPath:path,withIntermediateDirectories:true,attributes:[.posixPermissions:0o755]) }
        _ = try ServiceDeploymentPayload.verifyContentsDirectories(library,owner:getuid())
        for path in [library + "/Library",library + "/Library/Application Support",library + "/Library/Application Support/App Sweep",service,launch] {
            try FileManager.default.setAttributes([.posixPermissions:0o777],ofItemAtPath:path)
            XCTAssertThrowsError(try ServiceDeploymentPayload.verifyContentsDirectories(library,owner:getuid()),"Writable interior directory must be rejected: " + path)
            try FileManager.default.setAttributes([.posixPermissions:0o755],ofItemAtPath:path)
        }
        _ = try BoundedProcess.run("/bin/chmod",arguments:["+a","everyone allow add_file",service],timeout:5)
        XCTAssertThrowsError(try ServiceDeploymentPayload.verifyContentsDirectories(library,owner:getuid()))
    }
    func testOrdinaryUserCannotReadRootPackageOrConstructProductionDeployment() throws {
        let (f,library) = try fixture(); defer { try? f.clean() }
        XCTAssertThrowsError(try ServiceDeploymentPayload.loadRootPackage(library))
        XCTAssertThrowsError(try ServiceDeployment.production())
        XCTAssertThrowsError(try LaunchdServiceLifecycle())
    }
    func testDirectoryLinkCannotRedirectAnyDeploymentWrite() async throws {
        let (f,library) = try fixture(); defer { try? f.clean() }
        let outside = f.home + "/untouched"
        try FileManager.default.createDirectory(atPath:outside,withIntermediateDirectories:true)
        try FileManager.default.createDirectory(atPath:library + "/Application Support",withIntermediateDirectories:true)
        try FileManager.default.createSymbolicLink(atPath:library + "/Application Support/App Sweep",withDestinationPath:outside)
        do {
            let deployment = try ServiceDeployment.fixture(libraryRoot:library)
            _ = try await deployment.install(payload("one"),lifecycle:FixtureDeploymentLifecycle())
            XCTFail("Linked installation ancestors must fail closed")
        } catch { }
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath:outside).isEmpty)
    }
}
#endif
