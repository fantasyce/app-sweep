#if os(macOS)
import Foundation
import Darwin
import XCTest
import CFSafety
@testable import AppSweepCore

final class SystemCleanupEngineTests: XCTestCase, @unchecked Sendable {
    private let identifier="org.example.systemcleanup." + UUID().uuidString.lowercased()
    private func fixture() throws -> NativeAcceptanceTests.NativeFixture {
        let f=try NativeAcceptanceTests.NativeFixture(),path=f.app + "/Contents/Info.plist"
        var info=try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:path)),format:nil)as? [String:Any])
        info["CFBundleIdentifier"]=identifier
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:path))
        _=try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-",f.app],timeout:10)
        return f
    }
    func testRecentAndExactLooseSystemLogsAreManualAndRestoreWithoutSelectingAnotherOwner() async throws {
        let (f,scope,_)=try prepared();defer{try? f.clean()}
        let fm=FileManager.default,root=scope.libraryRoot + "/Logs",domain=root + "/\(identifier)"
        try fm.createDirectory(atPath:domain,withIntermediateDirectories:true)
        let old=domain + "/old.log",recent=domain + "/recent.log",loose=root + "/\(identifier).log",rotation=loose + ".2.gz",other=root + "/\(identifier).helper.log"
        for path in [old,recent,loose,rotation,other]{try Data("independent system log bytes".utf8).write(to:URL(fileURLWithPath:path))}
        try fm.setAttributes([.modificationDate:Date().addingTimeInterval(-31*86400)],ofItemAtPath:old)
        let engine=try SystemCleanupEngine(scope:scope),report=try await engine.scan(.logs)
        let items=report.selectableCandidates(includeUserData:false)
        XCTAssertEqual(Set(items.map(\.path)),[old,recent,loose,rotation],report.unconfirmedIssues.joined(separator:"; "))
        guard let recentItem=items.first(where:{$0.path == recent}),let looseItem=items.first(where:{$0.path == loose}) else{return}
        XCTAssertTrue(items.first(where:{$0.path == old})?.selectedByDefault == true)
        XCTAssertFalse(recentItem.selectedByDefault);XCTAssertFalse(looseItem.selectedByDefault)
        let before=try SafeFilesystem.snapshot(recent),plan=try await engine.makePlan(reportID:report.id,selected:[recentItem.id,looseItem.id]),batch=try await engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        for path in [old,rotation,other]{XCTAssertTrue(fm.fileExists(atPath:path))}
        let fresh=try SystemCleanupEngine(scope:scope),restored=try await fresh.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        XCTAssertEqual(try SafeFilesystem.snapshot(recent).identity.inode,before.identity.inode)
        XCTAssertEqual(try String(contentsOfFile:loose,encoding:.utf8),"independent system log bytes")
    }
    func testSystemLogsRetainAnOpenFileAndDatabaseWithLogSuffix() async throws {
        let (f,scope,_)=try prepared();defer{try? f.clean()}
        let domain=scope.libraryRoot + "/Logs/\(identifier)";try FileManager.default.createDirectory(atPath:domain,withIntermediateDirectories:true)
        let open=domain + "/opened.log",database=domain + "/state.log"
        try Data("active log".utf8).write(to:URL(fileURLWithPath:open))
        try (Data("SQLite format 3\0".utf8)+Data(repeating:0,count:64)).write(to:URL(fileURLWithPath:database))
        for path in [open,database]{try FileManager.default.setAttributes([.modificationDate:Date().addingTimeInterval(-40*86400)],ofItemAtPath:path)}
        let handle=try FileHandle(forReadingFrom:URL(fileURLWithPath:open));defer{try? handle.close()}
        let report=try await SystemCleanupEngine(scope:scope).scan(.logs)
        XCTAssertFalse(report.selectableCandidates(includeUserData:false).contains{$0.path == open || $0.path == database})
        XCTAssertTrue(FileManager.default.fileExists(atPath:open));XCTAssertTrue(FileManager.default.fileExists(atPath:database))
    }
    func testLogDomainChangeAfterReviewStopsBeforeAnySourceMove() async throws {
        let (f,scope,_) = try prepared(); defer { try? f.clean() }
        let fm = FileManager.default, root = scope.libraryRoot + "/Logs/\(identifier)", path = root + "/old.log"
        try fm.createDirectory(atPath:root,withIntermediateDirectories:true)
        try Data("owned old log".utf8).write(to:URL(fileURLWithPath:path))
        try fm.setAttributes([.modificationDate:Date().addingTimeInterval(-31 * 86400)],ofItemAtPath:path)
        let engine = try SystemCleanupEngine(scope:scope), report = try await engine.scan(.logs)
        let selected = report.selectableCandidates(includeUserData:false)
        XCTAssertEqual(selected.map(\.path),[path])
        let plan = try await engine.makePlan(reportID:report.id,selected:Set(selected.map(\.id)))
        let link = root + "/unconfirmed-owner-link"
        try fm.createSymbolicLink(atPath:link,withDestinationPath:f.home + "/Library/Application Support")
        do { _ = try await engine.execute(planID:plan.id); XCTFail("A log domain which no longer meets the scan ownership proof must stop before any move") } catch { }
        XCTAssertTrue(fm.fileExists(atPath:path))
        XCTAssertEqual(try fm.destinationOfSymbolicLink(atPath:link),f.home + "/Library/Application Support")
        let batches = try await engine.recoveryBatches()
        XCTAssertTrue(batches.isEmpty)
    }
    func testSystemPurgeRequiresExactConfirmationAndNeverRemovesRestoredSources() async throws {
        for restoreFirst in [false,true] {
            let (f,scope,files) = try prepared(); defer { try? f.clean() }
            let engine = try SystemCleanupEngine(scope:scope), report = try await engine.scan(.caches)
            let plan = try await engine.makePlan(reportID:report.id,selected:Set(report.selectableCandidates(includeUserData:false).map(\.id)))
            let batch = try await engine.execute(planID:plan.id)
            XCTAssertEqual(batch.status,.isolated)
            guard batch.status == .isolated else { return }
            let directory = try SafeDirectory(path:scope.vaultPath).existingPrivateChild(batch.id.uuidString)
            let backups = try directory.existingPrivateChild(batch.backupsDirectory)
            if restoreFirst {
                let restored = try await engine.restore(batchID:batch.id)
                XCTAssertEqual(restored.status,.restored)
            }
            do { _ = try await engine.purge(batchID:batch.id,confirmation:"yes"); XCTFail("System purge requires its own exact batch confirmation") } catch { }
            for entry in batch.entries { XCTAssertTrue(try SafeFilesystem.presence(backups.path + "/" + entry.id.uuidString)) }
            let fresh = try SystemCleanupEngine(scope:scope)
            let purged = try await fresh.purge(batchID:batch.id,confirmation:"永久清空 " + batch.id.uuidString)
            XCTAssertEqual(purged.status,.purged,purged.issue ?? "")
            XCTAssertFalse(purged.hasIndependentBackups)
            for entry in batch.entries { XCTAssertFalse(try SafeFilesystem.presence(backups.path + "/" + entry.id.uuidString)) }
            for (path,bytes) in files {
                if restoreFirst { XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:path)),bytes) }
                else { XCTAssertFalse(FileManager.default.fileExists(atPath:path)) }
            }
        }
    }
    func testSystemCacheRebuildsReclaimedObjectsFromIndependentBytes() async throws {
        let (f,scope,files) = try prepared(); defer { try? f.clean() }
        let engine = try SystemCleanupEngine(scope:scope), report = try await engine.scan(.caches)
        let plan = try await engine.makePlan(reportID:report.id,selected:Set(report.selectableCandidates(includeUserData:false).map(\.id)))
        let batch = try await engine.execute(planID:plan.id); XCTAssertEqual(batch.status,.isolated)
        guard batch.status == .isolated else { return }
        let objects = try SafeDirectory(path:scope.vaultPath).existingPrivateChild(batch.id.uuidString).existingPrivateChild(batch.objectsDirectory)
        for entry in batch.entries {
            let stored = try SafeFilesystem.snapshot(objects.path + "/" + entry.id.uuidString)
            XCTAssertTrue(SafeFilesystem.removeVerified(in:objects,name:entry.id.uuidString,identity:stored.identity,contents:stored.tree))
        }
        let fresh = try SystemCleanupEngine(scope:scope), restored = try await fresh.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:"; "))
        for (path,bytes) in files { XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:path)),bytes) }
        XCTAssertTrue(restored.hasIndependentBackups,"Independent bytes remain until an explicit purge")
    }
    func testSystemRecoveryPreservesNewCacheAndStopsTheWholeGroup() async throws {
        let (f,scope,files) = try prepared(); defer { try? f.clean() }
        let engine = try SystemCleanupEngine(scope:scope), report = try await engine.scan(.caches)
        let plan = try await engine.makePlan(reportID:report.id,selected:Set(report.selectableCandidates(includeUserData:false).map(\.id)))
        let batch = try await engine.execute(planID:plan.id); XCTAssertEqual(batch.status,.isolated)
        guard batch.status == .isolated else { return }
        let path = try XCTUnwrap(files.keys.sorted().first), newBytes = Data("new generated cache".utf8)
        try newBytes.write(to:URL(fileURLWithPath:path))
        let fresh = try SystemCleanupEngine(scope:scope), conflict = try await fresh.restore(batchID:batch.id)
        XCTAssertEqual(conflict.status,.needsAttention)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:path)),newBytes)
        for other in files.keys where other != path { XCTAssertFalse(FileManager.default.fileExists(atPath:other)) }
        let preserved = try SafeDirectory(path:scope.libraryRoot).privateChild("regenerated.noindex")
        try SafeFilesystem.move(SafeFilesystem.snapshot(path),into:preserved,name:"cache.db")
        let restored = try await fresh.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored)
        for (original,bytes) in files { XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:original)),bytes) }
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:preserved.path + "/cache.db")),newBytes)
    }
    func testSharedWritableSystemDomainsNeverBecomeCleanupCandidates() async throws {
        for category in [SystemCleanupCategory.caches, .logs] {
            let (f,scope,files) = try prepared(); defer { try? f.clean() }
            let root = scope.libraryRoot + (category == .caches ? "/Caches/" : "/Logs/") + "\(identifier)"
            if category == .logs {
                try FileManager.default.createDirectory(atPath:root,withIntermediateDirectories:true)
                let path = root + "/old.log"
                try Data("owned old log".utf8).write(to:URL(fileURLWithPath:path))
                try FileManager.default.setAttributes([.modificationDate:Date().addingTimeInterval(-40*86400)],ofItemAtPath:path)
            }
            try FileManager.default.setAttributes([.posixPermissions:0o770],ofItemAtPath:root)
            let report = try await SystemCleanupEngine(scope:scope).scan(category)
            XCTAssertTrue(report.selectableCandidates(includeUserData:false).isEmpty,"An owner UID cannot authorize data in a group-writable system domain")
            XCTAssertTrue(report.unconfirmedIssues.contains { $0.contains(root) })
            for path in files.keys { XCTAssertTrue(FileManager.default.fileExists(atPath:path)) }
        }
    }
    func testNestedSharedWritableSystemDataRetainsTheWholeDomain() async throws {
        for category in [SystemCleanupCategory.caches, .logs] {
            let (f,scope,files) = try prepared(); defer { try? f.clean() }
            let root = scope.libraryRoot + (category == .caches ? "/Caches/" : "/Logs/") + "\(identifier)"
            let nested = root + "/nested"
            try FileManager.default.createDirectory(atPath:nested,withIntermediateDirectories:true,attributes:[.posixPermissions:0o775])
            let path = nested + "/old.log"
            try Data("owned shared descendant".utf8).write(to:URL(fileURLWithPath:path))
            try FileManager.default.setAttributes([.modificationDate:Date().addingTimeInterval(-40*86400)],ofItemAtPath:path)
            let report = try await SystemCleanupEngine(scope:scope).scan(category)
            XCTAssertTrue(report.selectableCandidates(includeUserData:false).isEmpty,"A safe root cannot hide shared writable descendants")
            for path in files.keys { XCTAssertTrue(FileManager.default.fileExists(atPath:path)) }
            XCTAssertTrue(FileManager.default.fileExists(atPath:path))
        }
    }
    func testLogDomainACLWriteGrantCannotAuthorizeSystemData() async throws {
        let (f,scope,_) = try prepared(); defer { try? f.clean() }
        let root = scope.libraryRoot + "/Logs/\(identifier)", path = root + "/old.log"
        try FileManager.default.createDirectory(atPath:root,withIntermediateDirectories:true)
        try Data("owned old log".utf8).write(to:URL(fileURLWithPath:path))
        try FileManager.default.setAttributes([.modificationDate:Date().addingTimeInterval(-40*86400)],ofItemAtPath:path)
        _ = try BoundedProcess.run("/bin/chmod",arguments:["+a","everyone allow write",root],timeout:3)
        let report = try await SystemCleanupEngine(scope:scope).scan(.logs)
        XCTAssertTrue(report.selectableCandidates(includeUserData:false).isEmpty,"POSIX owner/mode without ACL verification cannot authorize system logs")
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:path)),Data("owned old log".utf8))
    }
    func testApplicationACLWriteGrantCannotAuthorizeSystemData() async throws {
        let (f,scope,files) = try prepared(); defer { try? f.clean() }
        _ = try BoundedProcess.run("/bin/chmod",arguments:["+a","everyone allow write",f.executable],timeout:3)
        XCTAssertTrue(AppInspector.signatureMatches(path:f.app,identifier:identifier),"ACL-only change must not be confused with a damaged fixture signature")
        let engine = try SystemCleanupEngine(scope:scope), report = try await engine.scan(.caches)
        XCTAssertTrue(report.selectableCandidates(includeUserData:false).isEmpty,"A valid signature and root-like POSIX bits do not establish that other users cannot rewrite the app")
        for path in files.keys { XCTAssertTrue(FileManager.default.fileExists(atPath:path)) }
    }
    func testSystemMutationHonorsOneGlobalLockAcrossRequesterNamespaces() async throws {
        let (f,scope,files) = try prepared(); defer { try? f.clean() }
        _ = try scope.openVault(create:true)
        let engine = try SystemCleanupEngine(scope:scope), report = try await engine.scan(.caches)
        let plan = try await engine.makePlan(reportID:report.id,selected:Set(report.selectableCandidates(includeUserData:false).map(\.id)))
        var lease: SafeDirectory? = try SafeDirectory(path:URL(fileURLWithPath:scope.vaultPath).deletingLastPathComponent().path)
        XCTAssertEqual(as_lock(try XCTUnwrap(lease).fd),0)
        do { _ = try await engine.execute(planID:plan.id); XCTFail("A global system-operation lock must stop mutation before any source move") } catch { }
        for path in files.keys { XCTAssertTrue(FileManager.default.fileExists(atPath:path)) }
        withExtendedLifetime(lease) { }; lease = nil
    }
    func testUnfinishedOtherRequesterOperationBlocksNewSystemCleanup() async throws {
        let (f,scope,files) = try prepared(); defer { try? f.clean() }
        let interrupted = try SystemCleanupEngine(scope:scope,failurePoint:.interruptAfterMove), report = try await interrupted.scan(.caches)
        let plan = try await interrupted.makePlan(reportID:report.id,selected:Set(report.selectableCandidates(includeUserData:false).map(\.id)))
        do { _ = try await interrupted.execute(planID:plan.id); XCTFail("Owned interruption must stop") } catch { }
        let batches = try await interrupted.recoveryBatches(), batch = try XCTUnwrap(batches.first)
        let from = scope.vaultPath + "/" + batch.id.uuidString
        let directory = try SafeDirectory(path:from), decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        var simulatedOtherRequester = try decoder.decode(RecoveryManifest.self,from:directory.read("manifest.json"))
        simulatedOtherRequester.requestingUserID = getuid() + 1
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        try directory.write(encoder.encode(simulatedOtherRequester),name:"manifest.json")
        let base = try SafeDirectory(path:URL(fileURLWithPath:scope.vaultPath).deletingLastPathComponent().path)
        let other = try base.privateChild(String(getuid() + 1))
        try SafeFilesystem.move(SafeFilesystem.snapshot(from),into:other,name:batch.id.uuidString)
        let remaining = files.keys.filter { FileManager.default.fileExists(atPath:$0) }
        XCTAssertEqual(remaining.count,1)
        let fresh = try SystemCleanupEngine(scope:scope)
        do {
            let scan = try await fresh.scan(.caches)
            let next = try await fresh.makePlan(reportID:scan.id,selected:Set(scan.selectableCandidates(includeUserData:false).map(\.id)))
            _ = try await fresh.execute(planID:next.id)
            XCTFail("A pending operation in another UID namespace must prevent splitting the shared system cache domain")
        } catch { }
        for path in remaining { XCTAssertTrue(FileManager.default.fileExists(atPath:path)) }
    }
    private func prepared() throws -> (NativeAcceptanceTests.NativeFixture,SystemCleanupScope,[String:Data]) {
        let f = try fixture(), library = f.home + "/MachineLibrary"
        let root = library + "/Caches/\(identifier)"
        try FileManager.default.createDirectory(atPath:root,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
        let files = [root + "/cache.db":Data("owned database".utf8),root + "/cache.db-wal":Data("owned journal".utf8)]
        for (path,bytes) in files { try bytes.write(to:URL(fileURLWithPath:path)) }
        return (f,try SystemCleanupScope.fixture(libraryRoot:library,applicationsRoot:f.home + "/Applications",userHome:f.home,requesterUID:getuid()),files)
    }
    func testRootSchemaAndRequesterBindingRejectUserRecoveryAndCrossUserCopies() async throws {
        let (f,scope,files) = try prepared(); defer { try? f.clean() }
        let engine = try SystemCleanupEngine(scope:scope), report = try await engine.scan(.caches)
        let plan = try await engine.makePlan(reportID:report.id,selected:Set(report.selectableCandidates(includeUserData:false).map(\.id)))
        let batch = try await engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated); XCTAssertEqual(batch.schemaVersion,4); XCTAssertEqual(batch.requestingUserID,getuid())
        guard batch.status == .isolated else { return }
        let user = SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[SystemDomainRule.cacheName]),vaultPath:scope.vaultPath,fixture:true)
        do { _ = try await user.restore(batchID:batch.id); XCTFail("User recovery must reject a system manifest") } catch { }
        let other = try SystemCleanupScope.fixture(libraryRoot:scope.libraryRoot,applicationsRoot:scope.applicationsRoot,userHome:f.home,requesterUID:getuid() + 1)
        let otherVault = try other.openVault(create:true)
        try FileManager.default.copyItem(atPath:scope.vaultPath + "/" + batch.id.uuidString,toPath:otherVault.path + "/" + batch.id.uuidString)
        let otherEngine = try SystemCleanupEngine(scope:other)
        do { _ = try await otherEngine.restore(batchID:batch.id); XCTFail("A batch copied into another UID namespace must remain unauthorized") } catch { }
        for path in files.keys { XCTAssertFalse(FileManager.default.fileExists(atPath:path)) }
        let restored = try await engine.restore(batchID:batch.id); XCTAssertEqual(restored.status,.restored)
    }
    func testSystemFailureRollsBackAndInterruptedMoveRestoresInNewEngine() async throws {
        for point in [FailurePoint.beforeSecondMove,.interruptAfterMove] {
            let (f,scope,files) = try prepared(); defer { try? f.clean() }
            let engine = try SystemCleanupEngine(scope:scope,failurePoint:point), report = try await engine.scan(.caches)
            let plan = try await engine.makePlan(reportID:report.id,selected:Set(report.selectableCandidates(includeUserData:false).map(\.id)))
            if point == .beforeSecondMove {
                let result = try await engine.execute(planID:plan.id); XCTAssertEqual(result.status,.rolledBack,result.issue ?? "")
            } else {
                do { _ = try await engine.execute(planID:plan.id); XCTFail("Owned interruption must stop execution") } catch { }
                let fresh = try SystemCleanupEngine(scope:scope), batches = try await fresh.recoveryBatches()
                XCTAssertEqual(batches.count,1)
                let batch = try XCTUnwrap(batches.first)
                XCTAssertTrue(batch.hasUnconfirmedObjects)
                let restored = try await fresh.restore(batchID:batch.id); XCTAssertEqual(restored.status,.restored)
            }
            for (path,bytes) in files { XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:path)),bytes) }
        }
    }
    func testSystemOldLogsAreIndependentOfCachesAndPreserveRecentAndOtherFiles() async throws {
        let (f,scope,files) = try prepared(); defer { try? f.clean() }
        let root = scope.libraryRoot + "/Logs/\(identifier)", fm = FileManager.default
        try fm.createDirectory(atPath:root,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
        let old = root + "/old.log", recent = root + "/recent.log", note = root + "/notes.txt"
        for path in [old,recent,note] { try Data("owned log fixture".utf8).write(to:URL(fileURLWithPath:path)) }
        try fm.setAttributes([.modificationDate:Date().addingTimeInterval(-31 * 86400)],ofItemAtPath:old)
        let engine = try SystemCleanupEngine(scope:scope), report = try await engine.scan(.logs)
        let selected = report.selectableCandidates(includeUserData:false).filter(\.selectedByDefault)
        XCTAssertEqual(selected.map(\.path),[old],report.unconfirmedIssues.joined(separator:"; "))
        let plan = try await engine.makePlan(reportID:report.id,selected:Set(selected.map(\.id)))
        let batch = try await engine.execute(planID:plan.id); XCTAssertEqual(batch.status,.isolated)
        XCTAssertTrue(fm.fileExists(atPath:recent)); XCTAssertTrue(fm.fileExists(atPath:note))
        for path in files.keys { XCTAssertTrue(fm.fileExists(atPath:path)) }
        let restored = try await engine.restore(batchID:batch.id); XCTAssertEqual(restored.status,.restored)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:old)),Data("owned log fixture".utf8))
    }
    func testProtectedNamespacesAndLinkedDomainDoNotEnterSystemPlan() async throws {
        let compiledRules = NativeAcceptance.systemRules(for:PlatformStamp.current)
        let (f,scope,_) = try prepared(); defer { try? f.clean() }
        for path in ["/private/var/folders/Cursor/cache","/System/Library/Caches/a",scope.libraryRoot + "/Caches/com.apple.finder/a",scope.libraryRoot + "/Caches/\(identifier)/../outside",scope.libraryRoot + "/Caches/\(identifier)/Keychains"] {
            XCTAssertNotNil(scope.pathDenial(path,category:.cache,rule:SystemDomainRule.cacheName),path)
        }
        let linked = scope.libraryRoot + "/Caches/\(identifier)/escape"
        try FileManager.default.createSymbolicLink(atPath:linked,withDestinationPath:f.home + "/Library/Application Support")
        let engine = try SystemCleanupEngine(scope:scope), report = try await engine.scan(.caches)
        XCTAssertFalse(report.complete); XCTAssertTrue(report.selectableCandidates(includeUserData:false).isEmpty)
        XCTAssertFalse(report.issues.isEmpty)
        XCTAssertThrowsError(try SystemCleanupScope.authenticated(.init(uid:getuid(),pid:getpid(),auditToken:Data(repeating:1,count:32))))
        XCTAssertEqual(NativeAcceptance.systemRules(for:PlatformStamp.current),compiledRules,"An ordinary fixture must not alter the compiled production root matrix")
    }
    func testSystemCachePlanUsesWholeDomainAndFreshEngineRestoresOnlyOwnedObjects() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let fm = FileManager.default, library = f.home + "/MachineLibrary"
        let root = library + "/Caches/\(identifier)"
        try fm.createDirectory(atPath: root, withIntermediateDirectories: true, attributes:[.posixPermissions:0o700])
        let files = [root + "/cache.db":Data("owned cache database".utf8), root + "/cache.db-wal":Data("owned cache journal".utf8)]
        for (path,data) in files { try data.write(to:URL(fileURLWithPath:path)) }
        let inode = try SafeDirectory(path:root).ownIdentity.inode
        let sentinel = f.home + "/Library/Application Support/personal-note"
        try Data("keep user data".utf8).write(to:URL(fileURLWithPath:sentinel))
        let scope = try SystemCleanupScope.fixture(libraryRoot:library,applicationsRoot:f.home + "/Applications",userHome:f.home,requesterUID:getuid())
        let engine = try SystemCleanupEngine(scope:scope), report = try await engine.scan(.caches)
        let items = report.selectableCandidates(includeUserData:false)
        XCTAssertEqual(Set(items.map(\.path)),Set(files.keys),report.unconfirmedIssues.joined(separator:"; "))
        guard items.count == 2 else { return }
        do { _ = try await engine.makePlan(reportID:report.id,selected:[items[0].id]); XCTFail("System cache database and journal must remain one selection") } catch { }
        let plan = try await engine.makePlan(reportID:report.id,selected:Set(items.map(\.id)))
        let batch = try await engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        guard batch.status == .isolated else { return }
        XCTAssertEqual(try SafeDirectory(path:root).ownIdentity.inode,inode)
        for path in files.keys { XCTAssertFalse(fm.fileExists(atPath:path)) }
        let fresh = try SystemCleanupEngine(scope:scope), restored = try await fresh.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:"; "))
        for (path,data) in files { XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:path)),data) }
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:sentinel)),Data("keep user data".utf8))
        XCTAssertEqual(try SafeDirectory(path:root).ownIdentity.inode,inode)
    }
}
#endif
