#if os(macOS)
import Foundation
import Darwin
import XCTest
@testable import AppSweepCore
@testable import AppSweepApp

final class DeviceBackupRuleTests: XCTestCase, @unchecked Sendable {
    private struct Fixture {
        let home: String
        let path: String
        let identifier = "00008020-0011223344556677"
        let identity: FileIdentity
        init(encrypted: Bool = false, legacy: Bool = false, archived: Bool = false) throws {
            guard getuid() != 0, let base = ProcessInfo.processInfo.environment["APP_SWEEP_FIXTURES"],
                  base.hasPrefix(NSHomeDirectory() + "/AppSweepAcceptance") else { throw XCTSkip("Requires owned non-root isolated fixture root") }
            home = base + "/" + UUID().uuidString
            path = home + "/Library/Application Support/MobileSync/Backup/" + identifier + (archived ? "-20261001-123456" : "")
            try FileManager.default.createDirectory(atPath:path,withIntermediateDirectories:true)
            try FileManager.default.setAttributes([.posixPermissions:0o700],ofItemAtPath:home)
            identity = try SafeDirectory(path:home).ownIdentity
            try write(["Device Name":"Disposable iPhone","Unique Identifier":identifier,"Product Type":"iPhone15,2","Last Backup Date":Date(timeIntervalSince1970:1700000000)],name:"Info.plist")
            try write(["SnapshotState":"finished","Version":legacy ? "2.4" : "3.3","Date":Date(timeIntervalSince1970:1700000000),"BackupState":"new"],name:"Status.plist")
            try write(["IsEncrypted":encrypted,"Version":"9.1"],name:"Manifest.plist")
            let content = legacy ? Data([109,98,100,98,5,0]) : (encrypted ? Data(repeating:0x42,count:64) : Data("SQLite format 3\0".utf8) + Data(repeating:0,count:64))
            try content.write(to:URL(fileURLWithPath:path + (legacy ? "/Manifest.mbdb" : "/Manifest.db")),options:.withoutOverwriting)
        }
        func write(_ value: [String:Any], name: String) throws {
            try PropertyListSerialization.data(fromPropertyList:value,format:.binary,options:0).write(to:URL(fileURLWithPath:path + "/" + name))
        }
        func clean() throws {
            let current = try SafeDirectory(path:home).ownIdentity
            guard current.device == identity.device, current.inode == identity.inode, current.owner == getuid() else { throw SweepError.denied("Retain changed backup test root") }
            try FileManager.default.removeItem(atPath:home)
        }
    }
    func testModernEncryptedAndArchivedMetadataAreIdentifiedWithoutReadingDevicePayloads() throws {
        for encrypted in [false,true] {
            let f = try Fixture(encrypted:encrypted,archived:encrypted); defer { try? f.clean() }
            let info = try DeviceBackupRule.inspect(path:f.path,home:f.home)
            XCTAssertEqual(info.deviceName,"Disposable iPhone")
            XCTAssertEqual(info.date,Date(timeIntervalSince1970:1700000000))
            XCTAssertEqual(info.encrypted,encrypted)
            XCTAssertEqual(info.format,.database)
            XCTAssertTrue(DeviceBackupRule.matches(path:f.path,home:f.home))
            XCTAssertFalse(DeviceBackupRule.matches(path:URL(fileURLWithPath:f.path).deletingLastPathComponent().path,home:f.home))
        }
    }
    func testLegacyMetadataRequiresItsActualDatabaseHeader() throws {
        let f = try Fixture(legacy:true); defer { try? f.clean() }
        XCTAssertEqual(try DeviceBackupRule.inspect(path:f.path,home:f.home).format,.legacyDatabase)
        try Data("not an mbdb".utf8).write(to:URL(fileURLWithPath:f.path + "/Manifest.mbdb"))
        XCTAssertThrowsError(try DeviceBackupRule.inspect(path:f.path,home:f.home))
    }
    func testIncompleteMismatchedUnknownAndCorruptMetadataAreNotEligible() throws {
        let f = try Fixture(); defer { try? f.clean() }
        for status in ["uploading","removing",""] {
            try f.write(["SnapshotState":status,"Version":"3.3","Date":Date(timeIntervalSince1970:1700000000),"BackupState":"new"],name:"Status.plist")
            XCTAssertThrowsError(try DeviceBackupRule.inspect(path:f.path,home:f.home))
        }
        try f.write(["SnapshotState":"finished","Version":"999.0","Date":Date(timeIntervalSince1970:1700000000),"BackupState":"new"],name:"Status.plist")
        XCTAssertThrowsError(try DeviceBackupRule.inspect(path:f.path,home:f.home))
        try f.write(["SnapshotState":"finished","Version":"3.3","Date":Date(timeIntervalSince1970:1700000000),"BackupState":"new"],name:"Status.plist")
        try f.write(["Device Name":"Disposable iPhone","Unique Identifier":"other-device","Product Type":"iPhone15,2","Last Backup Date":Date(timeIntervalSince1970:1700000000)],name:"Info.plist")
        XCTAssertThrowsError(try DeviceBackupRule.inspect(path:f.path,home:f.home))
        try Data("broken plist".utf8).write(to:URL(fileURLWithPath:f.path + "/Info.plist"))
        XCTAssertThrowsError(try DeviceBackupRule.inspect(path:f.path,home:f.home))
    }
    func testLinksHardLinksOversizedPlistsAndPathAliasesAreRejected() throws {
        let f = try Fixture(); defer { try? f.clean() }
        let info = f.path + "/Info.plist", original = try Data(contentsOf:URL(fileURLWithPath:info))
        try FileManager.default.moveItem(atPath:info,toPath:f.home + "/metadata")
        try FileManager.default.createSymbolicLink(atPath:info,withDestinationPath:f.home + "/metadata")
        XCTAssertThrowsError(try DeviceBackupRule.inspect(path:f.path,home:f.home))
        try FileManager.default.removeItem(atPath:info)
        try FileManager.default.linkItem(atPath:f.home + "/metadata",toPath:info)
        XCTAssertThrowsError(try DeviceBackupRule.inspect(path:f.path,home:f.home))
        try FileManager.default.removeItem(atPath:info)
        try Data(repeating:32,count:8*1024*1024 + 1).write(to:URL(fileURLWithPath:info))
        XCTAssertThrowsError(try DeviceBackupRule.inspect(path:f.path,home:f.home))
        try original.write(to:URL(fileURLWithPath:info))
        XCTAssertThrowsError(try DeviceBackupRule.inspect(path:f.path + "/../" + f.identifier,home:f.home))
        XCTAssertThrowsError(try DeviceBackupRule.inspect(path:f.home,home:f.home))
        try FileManager.default.createSymbolicLink(atPath:f.home + "/alias",withDestinationPath:f.path)
        XCTAssertThrowsError(try DeviceBackupRule.inspect(path:f.home + "/alias",home:f.home))
    }
    private func engine(_ f: Fixture, failure: FailurePoint? = nil) -> SweepEngine {
        SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[DeviceBackupRule.name]),vaultPath:f.home + "/Library/Application Support/App Sweep/Recovery",failurePoint:failure,fixture:false)
    }
    func testCatalogSeparatesSameNameDevicesAndMarksLatestOnlyAmongConfirmedBackups() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let root = DeviceBackupRule.root(home:f.home)
        func add(_ leaf: String, identifier: String, date: Date, damaged: Bool = false) throws -> String {
            let path = root + "/" + leaf
            try FileManager.default.copyItem(atPath:f.path,toPath:path)
            let info = try PropertyListSerialization.data(fromPropertyList:["Device Name":"Disposable iPhone","Unique Identifier":identifier,"Last Backup Date":date],format:.binary,options:0)
            try (damaged ? Data("broken metadata".utf8) : info).write(to:URL(fileURLWithPath:path + "/Info.plist"))
            return path
        }
        let older = try add(f.identifier + "-20231001-000000",identifier:f.identifier,date:Date(timeIntervalSince1970:1600000000))
        let otherID = "00008020-8899001122334455"
        let other = try add(otherID,identifier:otherID,date:Date(timeIntervalSince1970:1750000000))
        let unknown = try add("00008020-FFEEDDCCBBAA9988",identifier:"00008020-FFEEDDCCBBAA9988",date:Date(),damaged:true)
        let report = try await engine(f).scanLegacyManagementFixture()
        let backups = report.candidates.filter { $0.category == .deviceBackup }
        XCTAssertEqual(backups.count,4)
        let original = try XCTUnwrap(backups.first { $0.path == f.path })
        let details = try XCTUnwrap(original.deviceBackupDetails)
        XCTAssertEqual(details.deviceName,"Disposable iPhone")
        XCTAssertEqual(details.date,Date(timeIntervalSince1970:1700000000))
        XCTAssertFalse(details.encrypted)
        XCTAssertEqual(details.groupKey.count,64)
        XCTAssertFalse(details.groupKey.contains(f.identifier))
        let groups = DeviceBackupCatalog.groups(in:report.candidates)
        XCTAssertEqual(groups.count,3,"Same display name must not merge two devices or unknown metadata")
        let first = try XCTUnwrap(groups.first { $0.items.contains(where:{ $0.path == f.path }) })
        XCTAssertEqual(Set(first.items.map(\.path)),[f.path,older])
        XCTAssertEqual(first.items.map(\.path),[f.path,older])
        XCTAssertEqual(first.latestCandidateIDs,[original.id])
        let second = try XCTUnwrap(groups.first { $0.items.contains(where:{ $0.path == other }) })
        XCTAssertEqual(second.items.count,1)
        XCTAssertNotEqual(first.id,second.id)
        let unconfirmed = try XCTUnwrap(groups.first { $0.items.contains(where:{ $0.path == unknown }) })
        XCTAssertNil(unconfirmed.deviceName)
        XCTAssertTrue(unconfirmed.latestCandidateIDs.isEmpty)
        XCTAssertTrue(backups.allSatisfy { $0.userData && !$0.selectedByDefault })
        XCTAssertFalse(report.selectableCandidates(includeUserData:false).contains { $0.category == .deviceBackup })
    }
    func testCatalogKeepsTiedLatestBackupsAndLegacyReportCompatibility() async throws {
        let f = try Fixture(encrypted:true); defer { try? f.clean() }
        let archived = f.path + "-20231114-221320"
        try FileManager.default.copyItem(atPath:f.path,toPath:archived)
        let report = try await engine(f).scanLegacyManagementFixture()
        let backups = report.candidates.filter { $0.category == .deviceBackup }
        let group = try XCTUnwrap(DeviceBackupCatalog.groups(in:backups).first)
        XCTAssertEqual(group.latestCandidateIDs,Set(backups.map(\.id)),"Tied dates must not invent one uniquely newest backup")
        let original = try XCTUnwrap(backups.first)
        XCTAssertEqual(original.deviceBackupDetails?.encrypted,true)
        let packet = try JSONEncoder().encode(original)
        XCTAssertEqual(try JSONDecoder().decode(Candidate.self,from:packet).deviceBackupDetails,original.deviceBackupDetails)
        var legacy = try XCTUnwrap(JSONSerialization.jsonObject(with:packet) as? [String:Any])
        legacy.removeValue(forKey:"deviceBackupDetails")
        let decoded = try JSONDecoder().decode(Candidate.self,from:JSONSerialization.data(withJSONObject:legacy))
        XCTAssertNil(decoded.deviceBackupDetails)
        XCTAssertFalse(decoded.selectedByDefault)
        let unknownGroup = try XCTUnwrap(DeviceBackupCatalog.groups(in:[decoded]).first)
        XCTAssertTrue(unknownGroup.latestCandidateIDs.isEmpty)
        XCTAssertNil(unknownGroup.deviceName)
    }
    func testWholeBackupRequiresExplicitDataSelectionAndFreshEngineRestoresItsBytes() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let before = try Data(contentsOf:URL(fileURLWithPath:f.path + "/Info.plist"))
        let e = engine(f), report = try await e.scanLegacyManagementFixture()
        let item = try XCTUnwrap(report.candidates.first { $0.category == .deviceBackup })
        XCTAssertTrue(item.userData)
        XCTAssertEqual(item.displayName,"Disposable iPhone")
        XCTAssertEqual(try JSONDecoder().decode(Candidate.self,from:JSONEncoder().encode(item)).displayName,"Disposable iPhone","Recovery and reviewed reports must retain the device label")
        XCTAssertFalse(item.selectedByDefault)
        XCTAssertNil(item.bundleIdentifier)
        XCTAssertNil(item.applicationPath)
        XCTAssertFalse(report.selectableCandidates(includeUserData:false).contains { $0.id == item.id })
        do { _ = try await e.makePlan(reportID:report.id,selected:[item.id],includeUserData:false); XCTFail("Backups must never enter default garbage selection") } catch { }
        let plan = try await e.makePlan(reportID:report.id,selected:[item.id],includeUserData:true)
        let moved = try await e.execute(planID:plan.id)
        XCTAssertEqual(moved.status,.isolated,moved.issue ?? "")
        XCTAssertFalse(FileManager.default.fileExists(atPath:f.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath:DeviceBackupRule.root(home:f.home)),"Never move the whole Backup root")
        let restored = try await engine(f).restore(batchID:moved.id)
        XCTAssertEqual(restored.status,.restored)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:f.path + "/Info.plist")),before)
    }
    func testBackupMetadataChangedAfterReviewIsRefusedBeforeAnyMove() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let e = engine(f), report = try await e.scanLegacyManagementFixture()
        let item = try XCTUnwrap(report.selectableCandidates(includeUserData:true).first { $0.category == .deviceBackup })
        let plan = try await e.makePlan(reportID:report.id,selected:[item.id],includeUserData:true)
        try f.write(["SnapshotState":"uploading","Version":"3.3","Date":Date(timeIntervalSince1970:1700000000),"BackupState":"new"],name:"Status.plist")
        do { _ = try await e.execute(planID:plan.id); XCTFail("A changed backup cannot use a stale plan") } catch { }
        XCTAssertTrue(FileManager.default.fileExists(atPath:f.path))
    }
    func testBackupRecoveryConflictDoesNotOverwriteRegeneratedPersonalData() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let e = engine(f), report = try await e.scanLegacyManagementFixture()
        let item = try XCTUnwrap(report.selectableCandidates(includeUserData:true).first { $0.category == .deviceBackup })
        let plan = try await e.makePlan(reportID:report.id,selected:[item.id],includeUserData:true)
        let moved = try await e.execute(planID:plan.id)
        XCTAssertEqual(moved.status,.isolated)
        try FileManager.default.createDirectory(atPath:f.path,withIntermediateDirectories:false)
        try Data("new Finder backup".utf8).write(to:URL(fileURLWithPath:f.path + "/regenerated"),options:.withoutOverwriting)
        let result = try await engine(f).restore(batchID:moved.id)
        XCTAssertEqual(result.status,.needsAttention)
        XCTAssertEqual(try String(contentsOfFile:f.path + "/regenerated",encoding:.utf8),"new Finder backup")
        XCTAssertFalse(FileManager.default.fileExists(atPath:f.path + "/Info.plist"))
    }
    func testUnrelatedDiscoveryFailureDoesNotHideIndependentlyIdentifiedBackup() throws {
        let f = try Fixture(); defer { try? f.clean() }
        let policy = SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[DeviceBackupRule.name])
        let output = try Scanner(policy:policy).legacyManagementFixture(indexLookup:{ _ in throw SweepError.denied("Fixture index unavailable") })
        XCTAssertFalse(output.report.complete)
        let item = try XCTUnwrap(output.report.selectableCandidates(includeUserData:true).first { $0.category == .deviceBackup })
        XCTAssertTrue(output.report.selectionIsComplete([item.id],includeUserData:true))
    }

    func testBackupWithSharedWritablePayloadIsRetainedBeforePlanning() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let payload = f.path + "/payload"
        try Data("personal backup payload".utf8).write(to:URL(fileURLWithPath:payload))
        try FileManager.default.setAttributes([.posixPermissions:0o666],ofItemAtPath:payload)
        let report = try await engine(f).scanLegacyManagementFixture()
        XCTAssertTrue(report.selectableCandidates(includeUserData:true).filter { $0.category == .deviceBackup }.isEmpty,"Other writers must not retain access while a backup is reviewed or moved")
    }
    func testLargeBackupRoundTripUsesCompleteTreeCommitmentWithoutApplicationAuthority() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let bucket = f.path + "/00"
        try FileManager.default.createDirectory(atPath:bucket,withIntermediateDirectories:false)
        let count = 20_010
        for index in 0..<count {
            try Data("owned".utf8).write(to:URL(fileURLWithPath:bucket + "/" + String(format:"%040x",index)))
        }
        let policy = SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[DeviceBackupRule.name,"local-device-backup-large-v1"])
        let e = SweepEngine(policy:policy,vaultPath:f.home + "/Library/Application Support/App Sweep/Recovery",fixture:false)
        let report = try await e.scanLegacyManagementFixture()
        let item = try XCTUnwrap(report.selectableCandidates(includeUserData:true).first { $0.category == .deviceBackup },report.issues.joined(separator:"; "))
        let plan = try await e.makePlan(reportID:report.id,selected:[item.id],includeUserData:true)
        let moved = try await e.execute(planID:plan.id)
        XCTAssertEqual(moved.status,.isolated,moved.issue ?? "")
        let entry = try XCTUnwrap(moved.entries.first)
        XCTAssertNotNil(entry.treeFingerprint)
        XCTAssertTrue(entry.contents.isEmpty,"Large backups cannot truncate or overflow an inline journal")
        let fresh = SweepEngine(policy:policy,vaultPath:f.home + "/Library/Application Support/App Sweep/Recovery",fixture:false)
        let restored = try await fresh.restore(batchID:moved.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath:bucket).count,count)
        XCTAssertEqual(try String(contentsOfFile:bucket + "/" + String(format:"%040x",count-1),encoding:.utf8),"owned")
    }

    @MainActor
    private func waitForUI(_ store: SweepStore) async throws {
        let deadline = ProcessInfo.processInfo.systemUptime + 120
        while store.busy && ProcessInfo.processInfo.systemUptime < deadline { try await Task.sleep(for:.milliseconds(50)) }
        XCTAssertFalse(store.busy,"Backup UI operation exceeded bounded wait")
    }
    @MainActor
    func testDefaultUIOmitsBackupsButCanRestoreAnExistingLegacyBatch() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let e = engine(f)
        let coordinator = try CleanupCoordinator.fixture(engine: e, systemFactory: { throw SweepError.denied("Fixture system component unavailable") })
        do {
            let legacy = try await e.scanLegacyManagementFixture()
            let item = try XCTUnwrap(legacy.selectableCandidates(includeUserData: true).first { $0.path == f.path })
            let plan = try await e.makePlan(reportID: legacy.id, selected: [item.id], includeUserData: true)
            let batch = try await e.execute(planID: plan.id)
            XCTAssertEqual(batch.status, .isolated)
            let store = SweepStore(engine: e, coordinator: coordinator)
            store.scan(); try await waitForUI(store)
            XCTAssertFalse(store.overview?.candidates.contains { $0.category == .deviceBackup } ?? true)
            store.switchWorkspace(.recovery); try await waitForUI(store)
            let row = try XCTUnwrap(store.recoveryRows.first { $0.summary.id == batch.id })
            store.selectRecovery(row.id); try await waitForUI(store)
            store.restore(); try await waitForUI(store)
            XCTAssertTrue(FileManager.default.fileExists(atPath: f.path + "/Info.plist"), store.message)
            await coordinator.close()
        } catch { await coordinator.close(); throw error }
    }

    func testFailedApplicationRootDoesNotEraseIndependentBackupScope() throws {
        let f = try Fixture(); defer { try? f.clean() }
        // A real untraversable application root invalidates ownership discovery.
        // It must not erase the independently checked personal-backup scope.
        try FileManager.default.createSymbolicLink(atPath:f.home + "/Applications",withDestinationPath:f.home + "/missing-app-root")
        let policy = SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[DeviceBackupRule.name])
        do {
            let output = try Scanner(policy:policy).legacyManagementFixture(indexLookup:{ _ in [] })
            XCTAssertFalse(output.report.complete)
            XCTAssertFalse(output.report.issues.isEmpty)
            let backup = try XCTUnwrap(output.report.selectableCandidates(includeUserData:true).first { $0.category == .deviceBackup })
            XCTAssertEqual(backup.path,f.path)
            XCTAssertTrue(output.report.selectionIsComplete([backup.id],includeUserData:true))
        } catch { XCTFail("Independent backup scope must survive failed app ownership discovery: \(error)") }
    }

    func testOpenBackupPayloadBlocksExecutionWithoutMovingOrClosingIt() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let payload = f.path + "/personal-data"
        try Data("original personal bytes".utf8).write(to:URL(fileURLWithPath:payload))
        let e = engine(f), report = try await e.scanLegacyManagementFixture()
        let item = try XCTUnwrap(report.selectableCandidates(includeUserData:true).first { $0.category == .deviceBackup })
        let plan = try await e.makePlan(reportID:report.id,selected:[item.id],includeUserData:true)
        let handle = try FileHandle(forReadingFrom:URL(fileURLWithPath:payload))
        defer { try? handle.close() }
        do { _ = try await e.execute(planID:plan.id); XCTFail("An open backup cannot move") } catch { }
        XCTAssertEqual(try handle.readToEnd(),Data("original personal bytes".utf8))
        XCTAssertTrue(FileManager.default.fileExists(atPath:f.path + "/Info.plist"))
    }

    func testKnownBackupWorkerPreventsWholeBackupMoveAndIsNeverTerminated() async throws {
        let f = try Fixture(), process = Process()
        defer { if !process.isRunning { try? f.clean() } }
        let e = engine(f), report = try await e.scanLegacyManagementFixture()
        let item = try XCTUnwrap(report.selectableCandidates(includeUserData:true).first { $0.category == .deviceBackup })
        let plan = try await e.makePlan(reportID:report.id,selected:[item.id],includeUserData:true)
        let executable = f.home + "/idevicebackup2"
        try FileManager.default.copyItem(atPath:"/bin/sleep",toPath:executable)
        // Relocated Apple platform executables need an independent local test
        // signature; a killed launch is not evidence of backup-worker handling.
        _ = try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-",executable],timeout:5)
        process.executableURL = URL(fileURLWithPath:executable); process.arguments = ["8"]
        let stopped = expectation(description:"Disposable named backup worker exits naturally")
        process.terminationHandler = { _ in stopped.fulfill() }
        try process.run()
        var bodyError: Error?
        do {
            try await Task.sleep(for:.milliseconds(200))
            guard process.isRunning else { throw SweepError.incomplete("Named backup worker failed to start") }
            let running = try BoundedProcess.run("/bin/ps",arguments:["-ww","-p",String(process.processIdentifier),"-o","command="],timeout:3)
            guard running.hasPrefix(executable + " ") else { throw SweepError.incomplete("Disposable backup worker command identity not established") }
            do { _ = try await e.execute(planID:plan.id); XCTFail("Known backup activity must block the transaction") } catch { }
            XCTAssertTrue(process.isRunning,"App Sweep cannot end another process")
            XCTAssertTrue(FileManager.default.fileExists(atPath:f.path + "/Info.plist"))
        } catch { bodyError = error }
        await fulfillment(of:[stopped],timeout:15)
        guard !process.isRunning else { throw SweepError.incomplete("Retain fixture with active worker: " + f.home) }
        XCTAssertEqual(process.terminationStatus,0)
        if let bodyError { throw bodyError }
    }

    func testInterruptedWholeBackupMoveIsRecoverableByFreshEngine() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let expected = try Data(contentsOf:URL(fileURLWithPath:f.path + "/Info.plist"))
        let e = engine(f,failure:.interruptAfterMove), report = try await e.scanLegacyManagementFixture()
        let item = try XCTUnwrap(report.selectableCandidates(includeUserData:true).first { $0.category == .deviceBackup })
        let plan = try await e.makePlan(reportID:report.id,selected:[item.id],includeUserData:true)
        do { _ = try await e.execute(planID:plan.id); XCTFail("Expected injected interruption") } catch { }
        XCTAssertFalse(FileManager.default.fileExists(atPath:f.path))
        let fresh = engine(f), batches = try await fresh.recoveryBatches()
        let interrupted = try XCTUnwrap(batches.first)
        XCTAssertTrue(interrupted.hasUnconfirmedObjects)
        let restored = try await fresh.restore(batchID:interrupted.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:f.path + "/Info.plist")),expected)
    }

    func testBackupPurgeRequiresExactConfirmationAndTouchesOnlyIsolatedTree() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let sentinel = f.home + "/keep"
        try Data("keep outside backup".utf8).write(to:URL(fileURLWithPath:sentinel))
        let e = engine(f), report = try await e.scanLegacyManagementFixture()
        let item = try XCTUnwrap(report.selectableCandidates(includeUserData:true).first { $0.category == .deviceBackup })
        let plan = try await e.makePlan(reportID:report.id,selected:[item.id],includeUserData:true)
        let moved = try await e.execute(planID:plan.id)
        XCTAssertEqual(moved.status,.isolated,moved.issue ?? "")
        let object = f.home + "/Library/Application Support/App Sweep/Recovery/" + moved.id.uuidString + "/objects.noindex/" + item.id.uuidString
        do { _ = try await engine(f).purge(batchID:moved.id,confirmation:"yes"); XCTFail("Backups require a batch-specific permanent-deletion confirmation") } catch { }
        XCTAssertTrue(FileManager.default.fileExists(atPath:object + "/Info.plist"))
        let purged = try await engine(f).purge(batchID:moved.id,confirmation:"永久清空 " + moved.id.uuidString)
        XCTAssertEqual(purged.status,.purged,purged.issue ?? "")
        XCTAssertFalse(FileManager.default.fileExists(atPath:object))
        XCTAssertEqual(try String(contentsOfFile:sentinel,encoding:.utf8),"keep outside backup")
        XCTAssertTrue(FileManager.default.fileExists(atPath:DeviceBackupRule.root(home:f.home)))
    }

    func testPayloadLinksAndWritableACLRetainTheEntireBackup() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let target = f.home + "/shared-original", payload = f.path + "/payload"
        try Data("unrelated original".utf8).write(to:URL(fileURLWithPath:target))
        try FileManager.default.createSymbolicLink(atPath:payload,withDestinationPath:target)
        let linked = try await engine(f).scanLegacyManagementFixture()
        XCTAssertFalse(linked.selectableCandidates(includeUserData:true).contains { $0.category == .deviceBackup })
        try FileManager.default.removeItem(atPath:payload)
        try FileManager.default.linkItem(atPath:target,toPath:payload)
        let hardlinked = try await engine(f).scanLegacyManagementFixture()
        XCTAssertFalse(hardlinked.selectableCandidates(includeUserData:true).contains { $0.category == .deviceBackup })
        try FileManager.default.removeItem(atPath:payload)
        try Data("private payload".utf8).write(to:URL(fileURLWithPath:payload))
        _ = try BoundedProcess.run("/bin/chmod",arguments:["+a","everyone allow write",payload],timeout:3)
        let shared = try await engine(f).scanLegacyManagementFixture()
        XCTAssertFalse(shared.selectableCandidates(includeUserData:true).contains { $0.category == .deviceBackup })
        XCTAssertEqual(try String(contentsOfFile:target,encoding:.utf8),"unrelated original")
    }

}
#endif
