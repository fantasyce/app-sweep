#if os(macOS)
import Foundation
import Darwin
import XCTest
import CFSafety
@testable import AppSweepCore

private actor RemovalLifecycle: ServiceDeploymentLifecycle {
    private(set) var stops = 0
    private(set) var starts = 0
    let failStop: Bool
    let onStop: (@Sendable () throws -> Void)?
    init(failStop: Bool = false, onStop: (@Sendable () throws -> Void)? = nil) { self.failStop = failStop; self.onStop = onStop }
    func stop() throws { stops += 1; if failStop { throw SweepError.denied("Stop not confirmed") }; try onStop?() }
    func start() { starts += 1 }
}

final class ServiceRemovalTests: XCTestCase, @unchecked Sendable {
    private func fixture() async throws -> (NativeAcceptanceTests.NativeFixture,String,ServiceDeployment) {
        let f = try NativeAcceptanceTests.NativeFixture(), library = f.home + "/MachineLibrary"
        try FileManager.default.createDirectory(atPath:library,withIntermediateDirectories:true)
        let deployment = try ServiceDeployment.fixture(libraryRoot:library)
        let pins = RootServicePins(schemaVersion:1,serviceBuild:"removal-fixture",clientCodeHashes:[String(repeating:"a",count:40)],serviceCodeHashes:[String(repeating:"b",count:40)])
        _ = try await deployment.install(.fixture(program:Data("removal fixture program".utf8),configuration:pins.encode()),lifecycle:RemovalLifecycle())
        return (f,library,deployment)
    }
    private func paths(_ library: String) -> [String] { [library + "/Application Support/App Sweep/Service/AppSweepSystemService",library + "/Application Support/App Sweep/Service/config.json",library + "/LaunchDaemons/org.appsweep.system-service.plist"] }
    func testStableVolumeSealAllowsRemovalUndoAfterNativeDeviceReassignment()async throws{
        let(f,library,deployment)=try await fixture();defer{try? f.clean()}
        let originals=try paths(library).map{try SafeFilesystem.snapshot($0)},removed=try await deployment.remove(lifecycle:RemovalLifecycle())
        let url=URL(fileURLWithPath:removed.journalPath)
        var value=try XCTUnwrap(JSONSerialization.jsonObject(with:Data(contentsOf:url))as? [String:Any]),seal=try XCTUnwrap(value["seal"]as? [[String:Any]])
        guard seal.allSatisfy({($0["volumeUUID"]as? String).flatMap(UUID.init(uuidString:)) != nil})else{throw XCTSkip("Native stable-volume metadata required")}
        for index in seal.indices{seal[index]["device"]=(seal[index]["device"]as! NSNumber).uint64Value+17}
        value["seal"]=seal;try JSONSerialization.data(withJSONObject:value).write(to:url,options:.atomic)
        let id=try XCTUnwrap(UUID(uuidString:url.deletingLastPathComponent().lastPathComponent))
        let restored=try await ServiceDeployment.fixture(libraryRoot:library).restoreRemoval(id,lifecycle:RemovalLifecycle())
        XCTAssertEqual(restored.status,.rolledBack)
        for original in originals{XCTAssertTrue(try SafeFilesystem.snapshot(original.path).identity.sameObject(as:original.identity))}
    }
    func testRemovalPreservesRecoveryAndCanBeUndoneByANewInstance() async throws {
        let (f,library,deployment) = try await fixture(); defer { try? f.clean() }
        let originals = try paths(library).map { try SafeFilesystem.snapshot($0) }
        let recovery = try SafeDirectory(path:library + "/Application Support/App Sweep/Recovery.noindex")
        try recovery.write(Data("preserved user recovery".utf8),name:"owned-marker")
        let lifecycle = RemovalLifecycle(), removed = try await deployment.remove(lifecycle:lifecycle)
        XCTAssertEqual(removed.status,.removed)
        for path in paths(library) { XCTAssertFalse(try SafeFilesystem.presence(path)) }
        XCTAssertEqual(try recovery.read("owned-marker"),Data("preserved user recovery".utf8))
        let id = try XCTUnwrap(UUID(uuidString:URL(fileURLWithPath:removed.journalPath).deletingLastPathComponent().lastPathComponent))
        let restored = try await ServiceDeployment.fixture(libraryRoot:library).restoreRemoval(id,lifecycle:lifecycle)
        XCTAssertEqual(restored.status,.rolledBack)
        for original in originals { XCTAssertTrue(try SafeFilesystem.snapshot(original.path).identity.sameObject(as:original.identity)) }
        XCTAssertEqual(try recovery.read("owned-marker"),Data("preserved user recovery".utf8))
        let starts = await lifecycle.starts; XCTAssertEqual(starts,1)
    }
    func testInterruptedRemovalRestoresEveryComponentThroughExplicitRecovery() async throws {
        let (f,library,_) = try await fixture(); defer { try? f.clean() }
        let snapshots = try paths(library).map { try SafeFilesystem.snapshot($0) }
        let interrupted = try ServiceDeployment.fixture(libraryRoot:library,failurePoint:.interruptAfterProgramRemoval)
        do { _ = try await interrupted.remove(lifecycle:RemovalLifecycle()); XCTFail("Interruption cannot claim removal") } catch { }
        let result = try await ServiceDeployment.fixture(libraryRoot:library).recover(lifecycle:RemovalLifecycle())
        XCTAssertEqual(result.status,.rolledBack)
        for snapshot in snapshots { XCTAssertTrue(try SafeFilesystem.snapshot(snapshot.path).identity.sameObject(as:snapshot.identity)) }
    }
    func testUnconfirmedStopDoesNotMoveOrRestartAnyComponent() async throws {
        let (f,library,deployment) = try await fixture(); defer { try? f.clean() }
        let snapshots = try paths(library).map { try SafeFilesystem.snapshot($0) }
        let lifecycle = RemovalLifecycle(failStop:true), result = try await deployment.remove(lifecycle:lifecycle)
        XCTAssertEqual(result.status,.needsAttention)
        for snapshot in snapshots { XCTAssertTrue(try SafeFilesystem.snapshot(snapshot.path).identity.sameObject(as:snapshot.identity)) }
        let starts = await lifecycle.starts; XCTAssertEqual(starts,0)
    }
    func testRestoreConflictDoesNotOverwriteOrStopANewComponent() async throws {
        let (f,library,deployment) = try await fixture(); defer { try? f.clean() }
        let removed = try await deployment.remove(lifecycle:RemovalLifecycle())
        let path = paths(library)[0]
        try Data("different new component".utf8).write(to:URL(fileURLWithPath:path),options:.withoutOverwriting)
        let id = try XCTUnwrap(UUID(uuidString:URL(fileURLWithPath:removed.journalPath).deletingLastPathComponent().lastPathComponent)), lifecycle = RemovalLifecycle()
        do { _ = try await deployment.restoreRemoval(id,lifecycle:lifecycle); XCTFail("Conflict must refuse restoration") } catch { }
        XCTAssertEqual(try SafeFilesystem.readMetadata(path),Data("different new component".utf8))
        let stops = await lifecycle.stops; XCTAssertEqual(stops,0)
    }
    func testSystemTransactionLockExcludesRemovalBeforeStop() async throws {
        let (f,library,deployment) = try await fixture(); defer { try? f.clean() }
        let recovery = try SafeDirectory(path:library + "/Application Support/App Sweep/Recovery.noindex")
        XCTAssertEqual(as_lock(recovery.fd),0)
        let lifecycle = RemovalLifecycle()
        do { _ = try await deployment.remove(lifecycle:lifecycle); XCTFail("Global recovery lock must block removal") } catch { }
        let stops = await lifecycle.stops; XCTAssertEqual(stops,0)
        for path in paths(library) { XCTAssertTrue(try SafeFilesystem.presence(path)) }
    }
    func testAlreadySharedLibraryRefusesRemovalBeforeStoppingTheService() async throws {
        let (f,library,deployment) = try await fixture(); defer { try? f.clean() }
        _ = try BoundedProcess.run("/bin/chmod",arguments:["+a","everyone allow add_file",library],timeout:5)
        let lifecycle = RemovalLifecycle()
        do { _ = try await deployment.remove(lifecycle:lifecycle); XCTFail("An already shared ancestor must refuse before lifecycle actions") } catch { }
        let stops = await lifecycle.stops; XCTAssertEqual(stops,0)
        for path in paths(library) { XCTAssertTrue(try SafeFilesystem.presence(path)) }
    }
    func testGrantACLIntroducedDuringStopPreventsEveryComponentMove() async throws {
        let (f,library,deployment) = try await fixture(); defer { try? f.clean() }
        let originals = try paths(library).map { try SafeFilesystem.snapshot($0) }
        let service = library + "/Application Support/App Sweep/Service"
        do {
            let result = try await deployment.remove(lifecycle:RemovalLifecycle(onStop:{
                _ = try BoundedProcess.run("/bin/chmod",arguments:["+a","everyone allow add_file",service],timeout:5)
            }))
            XCTAssertEqual(result.status,.needsAttention,"A newly shared parent must never authorize removal")
        } catch { /* Refusal without further file movement also preserves the boundary. */ }
        for original in originals {
            XCTAssertTrue(try SafeFilesystem.presence(original.path),"A changed grant ACL must stop the entire set before movement")
            if try SafeFilesystem.presence(original.path) { XCTAssertTrue(try SafeFilesystem.snapshot(original.path).identity.sameObject(as:original.identity)) }
        }
    }
    func testReplacedDirectoryDuringStopDoesNotReceiveOrLoseComponents() async throws {
        let (f,library,deployment) = try await fixture(); defer { try? f.clean() }
        let service = library + "/Application Support/App Sweep/Service", detached = f.home + "/detached-removal"
        let result = try await deployment.remove(lifecycle:RemovalLifecycle(onStop:{
            try FileManager.default.moveItem(atPath:service,toPath:detached)
            try FileManager.default.createDirectory(atPath:service,withIntermediateDirectories:false)
        }))
        XCTAssertEqual(result.status,.needsAttention)
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath:service).isEmpty)
        XCTAssertTrue(try SafeFilesystem.presence(detached + "/AppSweepSystemService"))
        XCTAssertTrue(try SafeFilesystem.presence(library + "/LaunchDaemons/org.appsweep.system-service.plist"))
    }
}
#endif
