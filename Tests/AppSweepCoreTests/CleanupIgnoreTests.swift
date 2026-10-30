import Foundation
import XCTest
import CFSafety
@testable import AppSweepCore
#if os(macOS)
@testable import AppSweepApp
#endif

final class CleanupIgnoreTests: XCTestCase, @unchecked Sendable {
    func testLegacySupportCompatibilityDoesNotAdmitLinksSharedWritersOrPublicVaults() throws {
        for kind in ["link", "shared", "public-vault"] {
            let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
            let supportPath = f.home + "/Library/Application Support"
            try FileManager.default.createDirectory(atPath: supportPath, withIntermediateDirectories: true)
            let path = supportPath + "/App Sweep"
            if kind == "link" {
                try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: f.source)
            } else {
                try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: false)
                try FileManager.default.setAttributes([.posixPermissions: kind == "shared" ? 0o775 : 0o755], ofItemAtPath: path)
            }
            let support = try SafeDirectory(path: supportPath)
            if kind == "public-vault" {
                try FileManager.default.createDirectory(atPath: path + "/Recovery", withIntermediateDirectories: false, attributes: [.posixPermissions: 0o755])
                let root = try XCTUnwrap(support.appSweepSupport(create: true))
                XCTAssertThrowsError(try root.privateChild("Recovery"))
            } else {
                XCTAssertThrowsError(try support.appSweepSupport(create: false))
                XCTAssertThrowsError(try support.appSweepSupport(create: true))
            }
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.source + "/data")), Data("regenerable".utf8))
        }
    }
    func testUpgradeFromLegacySupportDirectoryPreservesBackupsAndAllowsPrivateSettings() async throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let parent = f.home + "/Library/Application Support/App Sweep"
        try FileManager.default.createDirectory(atPath: parent + "/backups", withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: parent)
        let backup = parent + "/backups/legacy.json", bytes = Data("legacy backup retained".utf8)
        try bytes.write(to: URL(fileURLWithPath: backup))
        let before = try SafeFilesystem.snapshot(backup), store = CleanupIgnoreStore(home: f.home, ownerUID: as_current_uid())
        let original = try store.read()
        XCTAssertTrue(original.paths.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: parent + "/Settings.noindex"))
        let saved = try store.update(path: f.source, adding: true, expectedRevision: original.revision)
        XCTAssertEqual(try store.read(), saved)
        XCTAssertEqual(try SafeDirectory(path: parent).ownIdentity.mode & 0o777, 0o755)
        XCTAssertEqual(try SafeDirectory(path: parent + "/Settings.noindex").ownIdentity.mode & 0o777, 0o700)
        try SafeFilesystem.verify(before)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: backup)), bytes)
        _ = try store.update(path: f.source, adding: false, expectedRevision: saved.revision)
        let engine = f.engine()
        let report = await engine.adoptFixture([f.candidate], snapshots: [f.candidate.id: f.snapshot])
        let plan = try await engine.makePlan(reportID: report.id, selected: [f.candidate.id], includeUserData: false)
        XCTAssertEqual(plan.items.map(\.path), [f.source])
    }
    func testLegacyParentWritableByOthersAndPublicSettingsStillFailClosed() throws {
        for (parentMode, settingsMode) in [(0o775, 0o700), (0o777, 0o700), (0o755, 0o755)] {
            let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
            try persist([], in: f.home)
            let parent = f.home + "/Library/Application Support/App Sweep"
            try FileManager.default.setAttributes([.posixPermissions: parentMode], ofItemAtPath: parent)
            try FileManager.default.setAttributes([.posixPermissions: settingsMode], ofItemAtPath: parent + "/Settings.noindex")
            let store = CleanupIgnoreStore(home: f.home, ownerUID: as_current_uid())
            XCTAssertThrowsError(try store.read())
            XCTAssertThrowsError(try store.update(path: f.source, adding: true, expectedRevision: CleanupIgnoreList.empty.revision))
        }
    }
    private func persist(_ paths: [String], in home: String, schema: Int = 1) throws {
        let directory = home + "/Library/Application Support/App Sweep/Settings.noindex"
        try FileManager.default.createDirectory(atPath:directory,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
        let data = try JSONSerialization.data(withJSONObject:["schemaVersion":schema,"revision":UUID().uuidString,"paths":paths])
        try SafeDirectory(path:directory).write(data,name:"cleanup-ignores.json")
    }
    func testIgnoredCandidateCannotBecomeSelectableFromForgedDerivedFields() throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        var json = try XCTUnwrap(JSONSerialization.jsonObject(with:JSONEncoder().encode(f.candidate)) as? [String:Any])
        json["ignoredReason"] = "用户忽略"
        json["selectedByDefault"] = true; json["allowedActions"] = ["report","reviewPlan","isolate"]
        json["executionAllowed"] = true
        let candidate = try JSONDecoder().decode(Candidate.self,from:JSONSerialization.data(withJSONObject:json))
        XCTAssertEqual(candidate.allowedActions,[.report])
        XCTAssertFalse(candidate.selectedByDefault)
    }
    func testPersistedIgnoreRejectsAnExistingRegisteredReport() async throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let engine = f.engine(), report = await engine.adoptFixture([f.candidate],snapshots:[f.candidate.id:f.snapshot])
        try persist([f.source],in:f.home)
        do { _ = try await engine.makePlan(reportID:report.id,selected:[f.candidate.id],includeUserData:false); XCTFail("A new ignore must invalidate the earlier scan") } catch { }
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:f.source + "/data")),Data("regenerable".utf8))
    }
    func testIgnoreAddedAfterReviewStopsExecutionBeforeMovingAnyFile() async throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let engine = f.engine(), report = await engine.adoptFixture([f.candidate],snapshots:[f.candidate.id:f.snapshot])
        let plan = try await engine.makePlan(reportID:report.id,selected:[f.candidate.id],includeUserData:false)
        try persist([f.source + "/data"],in:f.home)
        do { _ = try await engine.execute(planID:plan.id); XCTFail("Ignoring a child must also protect its enclosing candidate") } catch { XCTAssertTrue(error is ExecutionPreflightFailure,"A settings rejection is known to precede all source mutations") }
        XCTAssertTrue(FileManager.default.fileExists(atPath:f.source + "/data"))
        XCTAssertFalse(FileManager.default.fileExists(atPath:f.vault),"Refusal must precede creation of an execution journal")
    }
    func testMalformedIgnoreVersionIsNotAnEmptyAllowList() async throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let engine = f.engine(), report = await engine.adoptFixture([f.candidate],snapshots:[f.candidate.id:f.snapshot])
        try persist([],in:f.home,schema:999)
        do { _ = try await engine.makePlan(reportID:report.id,selected:[f.candidate.id],includeUserData:false); XCTFail("Unknown policy cannot be interpreted as no ignores") } catch { }
        XCTAssertTrue(FileManager.default.fileExists(atPath:f.source))
    }
    func testMissingIgnoreStorageKeepsPreviouslyValidatedFixtureFlow() async throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let engine = f.engine(), report = await engine.adoptFixture([f.candidate],snapshots:[f.candidate.id:f.snapshot])
        let plan = try await engine.makePlan(reportID:report.id,selected:[f.candidate.id],includeUserData:false)
        XCTAssertEqual(plan.items.map(\.id),[f.candidate.id])
        XCTAssertFalse(FileManager.default.fileExists(atPath:f.home + "/Library/Application Support/App Sweep/Settings.noindex"),"Read-only preview must not create settings")
    }
    func testAddingAndRemovingIgnorePersistsAcrossEnginesAndExpiresOldReports() async throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let first = f.engine(), original = try await first.cleanupIgnores()
        let saved = try await first.addCleanupIgnore(path:f.source,expectedRevision:original.revision)
        XCTAssertEqual(saved.paths,[f.source])
        let fresh = f.engine(), loaded = try await fresh.cleanupIgnores()
        XCTAssertEqual(loaded,saved)
        let ignored = await fresh.adoptFixture([f.candidate],snapshots:[f.candidate.id:f.snapshot])
        XCTAssertTrue(ignored.selectableCandidates(includeUserData:true).isEmpty)
        XCTAssertNotNil(ignored.candidates.first?.ignoredReason)
        do { _ = try await first.removeCleanupIgnore(path:f.source,expectedRevision:original.revision); XCTFail("Stale settings must not erase another instance's update") } catch { }
        let removed = try await fresh.removeCleanupIgnore(path:f.source,expectedRevision:saved.revision)
        XCTAssertTrue(removed.paths.isEmpty); XCTAssertNotEqual(removed.revision,original.revision)
        do { _ = try await fresh.makePlan(reportID:ignored.id,selected:[f.candidate.id],includeUserData:false); XCTFail("Unignore still requires a new scan") } catch { }
        let rescanned = await fresh.adoptFixture([f.candidate],snapshots:[f.candidate.id:f.snapshot])
        let plan = try await fresh.makePlan(reportID:rescanned.id,selected:[f.candidate.id],includeUserData:false)
        XCTAssertEqual(plan.items.map(\.id),[f.candidate.id])
    }
    func testIgnoreCannotBeEvadedByEnclosingCandidateCaseOrUnicode() {
        let list = CleanupIgnoreList(schemaVersion:1,revision:UUID(),paths:["/fixture/Café/keep"])
        for path in ["/fixture/cafe\u{301}/keep/file","/fixture/CAFÉ","/fixture/Café/keep"] {
            XCTAssertNotNil(list.reason(for:path),path)
        }
        XCTAssertNil(list.reason(for:"/fixture/Café/keeper"))
        XCTAssertNil(list.reason(for:"/fixture/Café-other"))
    }
    func testIgnoringOneCacheMemberProtectsTheCompleteGroup() throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let items = ["Cache.db","Cache.db-wal"].map { name in
            Candidate(id:UUID(),path:f.source + "/" + name,category:.cache,bundleIdentifier:f.candidate.bundleIdentifier,
                      evidence:f.candidate.evidence,rule:CacheDomainRule.name,identity:f.snapshot.identity,bytes:10,retentionReason:nil,executionAllowed:true)
        }
        let scan = ScanReport(schemaVersion:1,id:UUID(),createdAt:Date(),ruleVersion:SweepEngine.ruleVersion,applicationPath:nil,candidates:items,complete:true,issues:[],platformLimitation:nil)
        let filtered = CleanupIgnoreList(schemaVersion:1,revision:UUID(),paths:[f.source + "/Cache.db-wal"]).applying(to:scan)
        XCTAssertTrue(filtered.selectableCandidates(includeUserData:true).isEmpty)
        XCTAssertTrue(filtered.candidates.allSatisfy { $0.ignoredReason != nil })
        XCTAssertEqual(scan.selectableCandidates(includeUserData:true).count,2)
    }
    func testSameRevisionWithChangedContentInvalidatesPlanAndRecoveryRemainsAvailable() async throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let engine=f.engine(), empty=try await engine.cleanupIgnores()
        let saved=try await engine.addCleanupIgnore(path:f.home + "/unrelated",expectedRevision:empty.revision)
        let scan=await engine.adoptFixture([f.candidate],snapshots:[f.candidate.id:f.snapshot])
        let plan=try await engine.makePlan(reportID:scan.id,selected:[f.candidate.id],includeUserData:false)
        let dir=try SafeDirectory(path:f.home + "/Library/Application Support/App Sweep/Settings.noindex")
        try dir.write(JSONEncoder().encode(CleanupIgnoreList(schemaVersion:1,revision:saved.revision,paths:[f.source])),name:"cleanup-ignores.json")
        do { _ = try await engine.execute(planID:plan.id); XCTFail("Revision alone is not enough") } catch { }
        XCTAssertTrue(FileManager.default.fileExists(atPath:f.source))
        let current=try await engine.cleanupIgnores()
        _ = try await engine.removeCleanupIgnore(path:f.source,expectedRevision:current.revision)
        let refreshed=await engine.adoptFixture([f.candidate],snapshots:[f.candidate.id:f.snapshot])
        let reviewed=try await engine.makePlan(reportID:refreshed.id,selected:[f.candidate.id],includeUserData:false)
        let batch=try await engine.execute(planID:reviewed.id)
        let after=try await engine.cleanupIgnores()
        _ = try await engine.addCleanupIgnore(path:f.source,expectedRevision:after.revision)
        let restored=try await f.engine().restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:f.source + "/data")),Data("regenerable".utf8))
    }
    func testUnsafeIgnoreStorageIsNeverTreatedAsEmptyOrWrittenThrough() async throws {
        for kind in ["link","hardlink","mode","malformed"] {
            let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
            try persist([],in:f.home)
            let path=f.home + "/Library/Application Support/App Sweep/Settings.noindex/cleanup-ignores.json"
            let outside=f.home + "/keep.json", original=Data("retain this unrelated file".utf8)
            try original.write(to:URL(fileURLWithPath:outside))
            switch kind {
            case "link": try FileManager.default.removeItem(atPath:path); try FileManager.default.createSymbolicLink(atPath:path,withDestinationPath:outside)
            case "hardlink": try FileManager.default.removeItem(atPath:path); try FileManager.default.linkItem(atPath:outside,toPath:path)
            case "mode": try FileManager.default.setAttributes([.posixPermissions:0o666],ofItemAtPath:path)
            default: try Data("not JSON".utf8).write(to:URL(fileURLWithPath:path))
            }
            do { _ = try await f.engine().cleanupIgnores(); XCTFail(kind + " read accepted") } catch { }
            do { _ = try await f.engine().addCleanupIgnore(path:f.source,expectedRevision:CleanupIgnoreList.empty.revision); XCTFail(kind + " written through") } catch { }
            XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:outside)),original)
        }
    }
    func testSettingsDirectoryLinkCannotCreateOutsideFiles() async throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        try persist([],in:f.home)
        let parent=f.home + "/Library/Application Support/App Sweep", original=parent + "/Settings.noindex"
        try FileManager.default.moveItem(atPath:original,toPath:parent + "/retained-settings")
        try FileManager.default.createSymbolicLink(atPath:original,withDestinationPath:f.source)
        do { _ = try await f.engine().cleanupIgnores(); XCTFail("Linked settings accepted") } catch { }
        do { _ = try await f.engine().addCleanupIgnore(path:f.source,expectedRevision:CleanupIgnoreList.empty.revision); XCTFail("Settings written outside private directory") } catch { }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath:f.source),["data"])
    }
    func testInvalidAndOversizedPoliciesAreRejectedWithoutResettingExistingEntries() async throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let engine=f.engine(), original=try await engine.cleanupIgnores()
        let saved=try await engine.addCleanupIgnore(path:f.source,expectedRevision:original.revision)
        for path in ["/","relative","/fixture/../other","/fixture//item","/fixture/","/fixture/\0item","/" + String(repeating:"a",count:4096)] {
            do { _ = try await engine.addCleanupIgnore(path:path,expectedRevision:saved.revision); XCTFail("Invalid path accepted") } catch { }
        }
        let loaded=try await engine.cleanupIgnores(); XCTAssertEqual(loaded,saved)
        let oversized=CleanupIgnoreList(schemaVersion:1,revision:UUID(),paths:(0...1000).map { "/fixture/\($0)" })
        XCTAssertThrowsError(try oversized.validate())
        XCTAssertThrowsError(try CleanupIgnoreList(schemaVersion:1,revision:UUID(),paths:["/fixture/A","/fixture/a"]).validate())
    }
    func testSettingsWriterLeaseBlocksCleanupBeforeAnyMutation() async throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        try persist([],in:f.home)
        let engine=f.engine(), scan=await engine.adoptFixture([f.candidate],snapshots:[f.candidate.id:f.snapshot])
        let plan=try await engine.makePlan(reportID:scan.id,selected:[f.candidate.id],includeUserData:false)
        let writer=try SafeDirectory(path:f.home + "/Library/Application Support/App Sweep/Settings.noindex")
        XCTAssertEqual(as_lock(writer.fd),0)
        defer { withExtendedLifetime(writer) {} }
        do { _ = try await engine.execute(planID:plan.id); XCTFail("Cleanup raced a settings writer") } catch { }
        XCTAssertTrue(FileManager.default.fileExists(atPath:f.source + "/data"))
        XCTAssertFalse(FileManager.default.fileExists(atPath:f.vault))
    }
    func testExecutionLeaseBlocksFirstSettingsCreationAndReleasesAfterward() throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let store=CleanupIgnoreStore(home:f.home,ownerUID:as_current_uid()), original=try store.read()
        try withExtendedLifetime(store.executionLease(original)) {
            XCTAssertThrowsError(try store.update(path:f.source,adding:true,expectedRevision:original.revision))
            XCTAssertFalse(FileManager.default.fileExists(atPath:f.home + "/Library/Application Support/App Sweep/Settings.noindex"))
        }
        let saved=try store.update(path:f.source,adding:true,expectedRevision:original.revision)
        XCTAssertEqual(saved.paths,[f.source])
        try withExtendedLifetime(store.executionLease(saved)) {
            XCTAssertThrowsError(try store.update(path:f.source,adding:false,expectedRevision:saved.revision))
            XCTAssertEqual(try store.read(),saved)
        }
        XCTAssertTrue(try store.update(path:f.source,adding:false,expectedRevision:saved.revision).paths.isEmpty)
    }
    func testReplacingSettingsDirectoryInvalidatesHeldExecutionLease() throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        try persist([],in:f.home)
        let store=CleanupIgnoreStore(home:f.home,ownerUID:as_current_uid()), original=try store.read()
        let lease=try store.executionLease(original)
        defer { withExtendedLifetime(lease) {} }
        let path=f.home + "/Library/Application Support/App Sweep/Settings.noindex"
        try FileManager.default.moveItem(atPath:path,toPath:path + ".retained")
        try FileManager.default.createDirectory(atPath:path,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
        try SafeDirectory(path:path).write(JSONEncoder().encode(original),name:"cleanup-ignores.json")
        XCTAssertThrowsError(try store.verify(original,lease:lease))
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:f.source + "/data")),Data("regenerable".utf8))
    }
    #if os(macOS)
    func testCLIIgnoreHelpAndInvalidInputsUseTheSharedSettingsInterface() throws {
        let executable=Bundle(for:CleanupIgnoreTests.self).bundleURL.deletingLastPathComponent().appendingPathComponent("app-sweep").path
        guard FileManager.default.isExecutableFile(atPath:executable) else { throw XCTSkip("Native SwiftPM sibling CLI required") }
        let help=try BoundedProcess.capture(executable,arguments:["--help"],timeout:10,mergeStderr:true)
        XCTAssertEqual(help.status,0)
        for command in ["ignore-list","ignore-add","ignore-remove"] { XCTAssertTrue(help.text.contains(command),command) }
        for arguments in [["ignore-list","--path","/System"],["ignore-add"],["ignore-add","--path","relative"],["ignore-remove","--path","/System","--execute"],["ignore-add","--path","/a","--path","/b"]] {
            let result=try BoundedProcess.capture(executable,arguments:arguments,timeout:10,mergeStderr:true)
            XCTAssertNotEqual(result.status,0)
            XCTAssertTrue(result.text.contains("忽略"),result.text)
        }
    }
    @MainActor
    private func waitForUI(_ store: SweepStore) async throws {
        let deadline=ProcessInfo.processInfo.systemUptime + 15
        while store.busy && ProcessInfo.processInfo.systemUptime < deadline { try await Task.sleep(for:.milliseconds(25)) }
        XCTAssertFalse(store.busy,"Ignore settings UI operation exceeded bounded wait")
    }
    @MainActor
    func testGUIIgnorePersistsAndInvalidatesBothReviewWorkflows() async throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let engine=f.engine(), scan=await engine.adoptFixture([f.candidate],snapshots:[f.candidate.id:f.snapshot])
        let store=SweepStore(engine:engine)
        store.workspace = .uninstall; store.report=scan; store.selected=[f.candidate.id]
        store.overview = .init(id:UUID(),sections:[.init(source:.user,report:scan,issue:nil)])
        store.plan=try await engine.makePlan(reportID:scan.id,selected:[f.candidate.id],includeUserData:false)
        store.combinedReview = .init(id:UUID(),overviewID:store.overview!.id,items:[f.candidate],retainedIssues:[])
        store.ignore(f.candidate); try await waitForUI(store)
        XCTAssertFalse(store.error,store.message)
        let saved=try await f.engine().cleanupIgnores()
        XCTAssertEqual(saved.paths,[f.source])
        XCTAssertNil(store.plan); XCTAssertNil(store.combinedReview)
        XCTAssertNil(store.report); XCTAssertNil(store.overview); XCTAssertTrue(store.selected.isEmpty)
        XCTAssertTrue(FileManager.default.fileExists(atPath:f.source + "/data"))
        store.removeIgnore(path:f.source); try await waitForUI(store)
        XCTAssertFalse(store.error,store.message); XCTAssertEqual(store.ignoreList?.paths,[])
        XCTAssertNil(store.report,"Removing an ignore does not reuse old evidence")
    }
    @MainActor
    func testGUIIgnoreBusyAndUnknownCandidatesDoNotChangeRestrictions() async throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let engine=f.engine(), scan=await engine.adoptFixture([f.candidate],snapshots:[f.candidate.id:f.snapshot])
        let store=SweepStore(engine:engine); store.workspace = .uninstall; store.report=scan
        store.busy=true; store.ignore(f.candidate); store.loadIgnores(); store.removeIgnore(path:f.source)
        XCTAssertTrue(store.busy); XCTAssertEqual(store.report?.id,scan.id); XCTAssertNil(store.ignoreList)
        store.busy=false; store.report=nil; store.ignore(f.candidate); try await waitForUI(store)
        let list=try await engine.cleanupIgnores(); XCTAssertTrue(list.paths.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath:f.home + "/Library/Application Support/App Sweep/Settings.noindex"))
    }
    @MainActor
    func testGUIStaleRemovalShowsFailureAndKeepsNewerRestriction() async throws {
        let f=try RecoveryTests.Fixture(); defer { try? f.clean() }
        let engine=f.engine(), initial=try await engine.cleanupIgnores()
        let saved=try await engine.addCleanupIgnore(path:f.source,expectedRevision:initial.revision)
        let store=SweepStore(engine:engine); store.loadIgnores(); try await waitForUI(store)
        let newer=try await f.engine().addCleanupIgnore(path:f.home + "/keep",expectedRevision:saved.revision)
        store.removeIgnore(path:f.source); try await waitForUI(store)
        XCTAssertTrue(store.error); XCTAssertFalse(store.message.isEmpty)
        let list=try await engine.cleanupIgnores(); XCTAssertEqual(list,newer)
    }
    func testPublicScanRetainsIgnoredApplicationWithoutLosingOwnershipEvidence() async throws {
        let f=try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let support = f.home + "/Library/Application Support/App Sweep"
        try FileManager.default.createDirectory(atPath: support + "/backups", withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: support)
        // This test exercises ignores, not duplicate installation ownership.
        // Retained acceptance samples legitimately share the default fixture ID.
        let identifier="org.example.ignore." + UUID().uuidString.lowercased()
        let infoURL=URL(fileURLWithPath:f.app + "/Contents/Info.plist")
        var info=try XCTUnwrap(PropertyListSerialization.propertyList(from:Data(contentsOf:infoURL),format:nil) as? [String:Any])
        info["CFBundleIdentifier"]=identifier
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:infoURL)
        _ = try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-","--identifier",identifier,f.app],timeout:10)
        try await f.waitUntilUnused(f.app)
        let original=try await f.engine.scanApplication(f.app)
        let originalBody=try XCTUnwrap(original.candidates.first { $0.path == f.app })
        if !originalBody.allowed {
            let owners=try AppInspector.inventory(home:f.home,selectedApplication:f.app,ownershipIdentifier:identifier)
                .filter { $0.bundleIdentifier.isEmpty || $0.bundleIdentifier.lowercased() == identifier }
            print("IGNORE_FIXTURE_OWNERS",owners.count)
            for owner in owners.prefix(20) {
                print("IGNORE_FIXTURE_OWNER",owner.path,owner.bundleIdentifier,owner.protectedReason ?? "")
            }
        }
        XCTAssertTrue(originalBody.allowed,"Initial owned fixture was retained: \(originalBody.retentionReason ?? "no reason"); scan issues: \(original.issues)")
        let settings=try await f.engine.cleanupIgnores()
        _ = try await f.engine.addCleanupIgnore(path:f.app,expectedRevision:settings.revision)
        let ignored=try await f.engine.scanApplication(f.app), body=try XCTUnwrap(ignored.candidates.first { $0.path == f.app })
        XCTAssertFalse(body.allowed); XCTAssertNotNil(body.ignoredReason)
        XCTAssertTrue(body.evidence.contains(where: \.authorizes))
        do { _ = try await f.engine.makePlan(reportID:ignored.id,selected:[body.id],includeUserData:false); XCTFail("Ignored body planned") } catch { }
        let latest = try await f.engine.cleanupIgnores()
        _ = try await f.engine.removeCleanupIgnore(path: f.app, expectedRevision: latest.revision)
        let rescanned = try await f.engine.scanApplication(f.app)
        let restoredBody = try XCTUnwrap(rescanned.candidates.first { $0.path == f.app })
        let plan = try await f.engine.makePlan(reportID: rescanned.id, selected: [restoredBody.id], includeUserData: false)
        let batch = try await f.engine.execute(planID: plan.id)
        XCTAssertEqual(batch.status, .isolated, batch.issue ?? "")
        let recovered = try await f.restoreWhenUnused(batch)
        XCTAssertEqual(recovered.status, .restored)
        XCTAssertEqual(try SafeDirectory(path: support).ownIdentity.mode & 0o777, 0o755)
    }
    #endif
}
