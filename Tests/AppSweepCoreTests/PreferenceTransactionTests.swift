#if os(macOS)
import Foundation
import Darwin
import XCTest
@testable import AppSweepCore

/// The domain and bundle are new UUID-owned VM objects. A separate native
/// reader, outside the moved bundle, checks effective CFPreferences values.
final class PreferenceTransactionTests: XCTestCase, @unchecked Sendable {
    private static let rule = "cfpreferences-service-domain-v2"
    private func fixture() throws -> PreferenceDomainServiceTests.NativeDomainFixture {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_PREFERENCE_TRANSACTION_ACCEPTANCE"] == "AppSweep-General-20261016",
              getuid()==501, geteuid()==501, try SystemIdentity.home()=="/Users/localtest",
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).hasPrefix("VirtualMac") else {
            throw XCTSkip("Explicit disposable VM current-home transaction acceptance only")
        }
        let f=try PreferenceDomainServiceTests.NativeDomainFixture()
        // A transaction starts from settled, stopped-app state. Avoid the
        // independent CF consumer's delayed flush racing the reviewed snapshot.
        let seed=try BoundedProcess.capture("/usr/bin/defaults",arguments:["write",f.identifier,"acceptance-consumer","-string","original-owned-value"],timeout:10,mergeStderr:false)
        guard seed.status==0 else { throw SweepError.incomplete("Owned native transaction seed failed") }
        try FileManager.default.copyItem(atPath:f.executable,toPath:f.root.path + "/observer")
        return f
    }
    private func engine(_ f: PreferenceDomainServiceTests.NativeDomainFixture, failure: FailurePoint? = nil) -> SweepEngine {
        SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[SelectedApplicationRule.name,ChosenApplicationRule.name,ChosenApplicationRule.largeName,Self.rule,"cfpreferences-exact-domain-v1"]),vaultPath:f.root.path + "/Recovery",failurePoint:failure,fixture:false)
    }
    private func value(_ f: PreferenceDomainServiceTests.NativeDomainFixture) throws -> CapturedProcess {
        try BoundedProcess.capture(f.root.path + "/observer",arguments:["--observe-pref",f.identifier],timeout:3,mergeStderr:false)
    }
    private func waitUnused(_ path: String) async throws {
        var last: Error=SweepError.incomplete("Owned witness still occupied")
        for _ in 0..<40 {
            do { try BusyInspector.ensureUnused(SafeFilesystem.snapshot(path,allowInternalLinks:path.hasSuffix(".app"),purpose:path.hasSuffix(".app") ? .application : .ordinary));return }
            catch { last=error;try await Task.sleep(nanoseconds:250_000_000) }
        }
        throw last
    }
    private func plan(_ f: PreferenceDomainServiceTests.NativeDomainFixture, engine: SweepEngine) async throws -> CleanupPlan {
        let app=f.root.path + "/Preference Witness.app"
        try await waitUnused(app)
        let report=try await engine.scanApplication(app)
        let body=try XCTUnwrap(report.candidates.first { $0.category == .application && $0.path == app })
        let preference=try XCTUnwrap(report.candidates.first { $0.path == f.path })
        XCTAssertEqual(preference.rule,Self.rule,"Real-home settings must use the native service transaction")
        XCTAssertFalse(preference.selectedByDefault)
        guard preference.rule==Self.rule, preference.allowed,preference.executionAllowed else { throw SweepError.incomplete("Native preference transaction not available: " + (preference.retentionReason ?? "rule missing")) }
        return try await engine.makePlan(reportID:report.id,selected:[body.id,preference.id],includeUserData:true)
    }
    func testDefaultRetainsSettingsThenExplicitSelectionClearsAndFreshEngineRestoresActualValues() async throws {
        let f=try fixture(),first=engine(f),app=f.root.path + "/Preference Witness.app"
        let unrelated=try fixture()
        try await waitUnused(app)
        let report=try await first.scanApplication(app)
        let preference=try XCTUnwrap(report.candidates.first { $0.path == f.path })
        XCTAssertEqual(preference.rule,Self.rule)
        guard preference.rule == Self.rule else { throw SweepError.incomplete("Native transaction is not connected to scanning") }
        let body=try XCTUnwrap(report.candidates.first { $0.category == .application && $0.path == app })
        let legacy=Candidate(id:UUID(),path:f.path,category:.userData,bundleIdentifier:f.identifier,applicationPath:app,evidence:preference.evidence,rule:"cfpreferences-exact-domain-v1",identity:preference.identity,bytes:preference.bytes,retentionReason:nil,executionAllowed:true)
        let legacyReport=await first.adoptFixture([body,legacy],snapshots:[body.id:try SafeFilesystem.snapshot(app,allowInternalLinks:true,purpose:.application),legacy.id:try SafeFilesystem.snapshot(f.path)],applicationPath:app)
        do { _ = try await first.makePlan(reportID:legacyReport.id,selected:[body.id,legacy.id],includeUserData:true);XCTFail("Legacy recovery support must not authorize another real-home file-only preference plan") } catch { }
        let retained=try await first.makePlan(reportID:report.id,selected:[body.id],includeUserData:false)
        let bodyOnly=try await first.execute(planID:retained.id)
        XCTAssertEqual(bodyOnly.status,.isolated,bodyOnly.issue ?? "")
        XCTAssertEqual(try value(f).text.trimmingCharacters(in:.whitespacesAndNewlines),"original-owned-value")
        let back=try await engine(f).restore(batchID:bodyOnly.id)
        XCTAssertEqual(back.status,.restored,back.issue ?? back.entries.compactMap(\.message).joined(separator:";"))
        let next=engine(f),selected=try await plan(f,engine:next)
        let cleared=try await next.execute(planID:selected.id)
        XCTAssertEqual(cleared.status,.isolated,cleared.issue ?? "")
        guard cleared.status == .isolated else { return }
        XCTAssertEqual(cleared.schemaVersion,5)
        XCTAssertEqual(try value(f).status,6,"Moving a plist without clearing native values fails this assertion")
        XCTAssertEqual(try value(unrelated).text.trimmingCharacters(in:.whitespacesAndNewlines),"original-owned-value","A same-prefix independent domain must remain unchanged")
        let entry=try XCTUnwrap(cleared.entries.first { $0.original.path==f.path })
        XCTAssertNotNil(entry.backupDigest);XCTAssertNil(entry.isolatedIdentity,"Settings are backed up, not falsely counted as moved files")
        XCTAssertEqual(cleared.isolatedBytes,cleared.entries.filter { $0.original.category == .application }.reduce(0) { $0+$1.original.bytes })
        XCTAssertGreaterThan(cleared.independentBackupBytes,0)
        let restored=try await engine(f).restore(batchID:cleared.id)
        XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:";"))
        XCTAssertEqual(try value(f).text.trimmingCharacters(in:.whitespacesAndNewlines),"original-owned-value")
        XCTAssertTrue(try SafeFilesystem.presence(app))
        try f.finish()
        let purged=try await engine(f).purge(batchID:cleared.id,confirmation:"永久清空 " + cleared.id.uuidString)
        XCTAssertEqual(purged.status,.purged,purged.issue ?? "")
        XCTAssertEqual(try value(f).status,6,"Purging recovery backups must not restore or clear native values")
        XCTAssertTrue(try SafeFilesystem.presence(app),"Purging restored backup bytes must leave the restored app")
        XCTAssertEqual(try value(unrelated).text.trimmingCharacters(in:.whitespacesAndNewlines),"original-owned-value")
        try unrelated.finish()
        print("NATIVE_PREFERENCE_TRANSACTION complete root=\(f.root.path) batch=\(cleared.id) actualConsumer=true freshEngine=true")
    }
    func testMismatchedScanContentCommitmentBlocksBeforeMovingApplication() async throws {
        let f=try fixture(),e=engine(f),app=f.root.path + "/Preference Witness.app"
        try await waitUnused(app)
        let report=try await e.scanApplication(app)
        let body=try XCTUnwrap(report.candidates.first { $0.category == .application && $0.path==app })
        let preference=try XCTUnwrap(report.candidates.first { $0.path==f.path && $0.rule==Self.rule && $0.allowed })
        var evidence=try SafeFilesystem.snapshot(f.path)
        evidence.contentDigest=String(repeating:"0",count:64)
        let stale=await e.adoptFixture([body,preference],snapshots:[body.id:try SafeFilesystem.snapshot(app,allowInternalLinks:true,purpose:.application),preference.id:evidence],applicationPath:app)
        let selected=try await e.makePlan(reportID:stale.id,selected:[body.id,preference.id],includeUserData:true)
        do { _ = try await e.execute(planID:selected.id);XCTFail("A different content commitment must invalidate even an unchanged inode") } catch { }
        XCTAssertTrue(try SafeFilesystem.presence(app))
        XCTAssertEqual(try value(f).text.trimmingCharacters(in:.whitespacesAndNewlines),"original-owned-value")
        let batches=try await e.recoveryBatches();XCTAssertTrue(batches.isEmpty)
        try f.finish()
    }
    func testUnreadablePreferenceIsUnconfirmedWhileApplicationRemainsSelectable() async throws {
        let f=try fixture(),e=engine(f),app=f.root.path + "/Preference Witness.app"
        try await waitUnused(app)
        let mode=try SafeFilesystem.snapshot(f.path).identity.mode & 0o7777
        do {
            guard chmod(f.path,0)==0 else { throw SweepError.filesystem("Owned permission regression setup failed") }
            defer { _ = chmod(f.path,mode_t(mode)) }
            let report=try await e.scanApplication(app)
            let body=try XCTUnwrap(report.candidates.first { $0.category == .application && $0.path==app })
            XCTAssertFalse(report.complete,"A denied preference read must remain an unconfirmed scope")
            XCTAssertFalse(report.unconfirmedIssues.isEmpty)
            XCTAssertTrue(report.selectableCandidates(includeUserData:true).contains { $0.id==body.id },"The independent app body must stay selectable")
            XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains { $0.path==f.path })
        }
        try f.finish()
    }
    func testRecoveryKeepsNewSettingsAndDoesNotRestoreBodyPastConflict() async throws {
        let f=try fixture(),e=engine(f),p=try await plan(f,engine:e)
        let cleared=try await e.execute(planID:p.id)
        XCTAssertEqual(cleared.status,.isolated,cleared.issue ?? "");guard cleared.status == .isolated else { return }
        let body=try XCTUnwrap(cleared.entries.first { $0.original.category == .application })
        let seed=try BoundedProcess.capture("/usr/bin/defaults",arguments:["write",f.identifier,"acceptance-consumer","-string","new-owned-value"],timeout:5,mergeStderr:false)
        XCTAssertEqual(seed.status,0)
        let recovered=try await engine(f).restore(batchID:cleared.id)
        XCTAssertEqual(recovered.status,.needsAttention)
        XCTAssertEqual(try value(f).text.trimmingCharacters(in:.whitespacesAndNewlines),"new-owned-value")
        XCTAssertFalse(try SafeFilesystem.presence(body.original.path))
        print("NATIVE_PREFERENCE_TRANSACTION conflictRetained root=\(f.root.path) batch=\(cleared.id)")
    }
    func testBeforeBackupInterruptionRecoversWithoutEverClearingNativeValues() async throws {
        let f=try fixture(),e=engine(f,failure:.preferenceBeforeBackup),p=try await plan(f,engine:e)
        do { _ = try await e.execute(planID:p.id);XCTFail("Expected interruption after durable intent and before backup creation") } catch { }
        XCTAssertEqual(try value(f).text.trimmingCharacters(in:.whitespacesAndNewlines),"original-owned-value","Backup intent alone must not clear settings")
        let batches=try await engine(f).recoveryBatches()
        let batch=try XCTUnwrap(batches.first)
        let restored=try await engine(f).restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:";"))
        XCTAssertEqual(try value(f).text.trimmingCharacters(in:.whitespacesAndNewlines),"original-owned-value")
        try f.finish()
    }
    func testIsolatedPurgeRemovesOnlyStoredAppAndBackupAndPreservesNewNativeValues() async throws {
        let f=try fixture(),e=engine(f),p=try await plan(f,engine:e)
        let cleared=try await e.execute(planID:p.id)
        XCTAssertEqual(cleared.status,.isolated,cleared.issue ?? "");guard cleared.status == .isolated else { return }
        let seed=try BoundedProcess.capture("/usr/bin/defaults",arguments:["write",f.identifier,"acceptance-consumer","-string","new-owned-value"],timeout:5,mergeStderr:false)
        XCTAssertEqual(seed.status,0)
        let body=try XCTUnwrap(cleared.entries.first { $0.original.category == .application })
        let stored=f.root.path + "/Recovery/" + cleared.id.uuidString + "/" + cleared.objectsDirectory + "/" + body.id.uuidString
        try await waitUnused(stored)
        let purged=try await engine(f).purge(batchID:cleared.id,confirmation:"永久清空 " + cleared.id.uuidString)
        XCTAssertEqual(purged.status,.purged,purged.issue ?? "")
        XCTAssertEqual(try value(f).text.trimmingCharacters(in:.whitespacesAndNewlines),"new-owned-value","Purge must not issue a preferences clear or restore")
        XCTAssertFalse(try SafeFilesystem.presence(stored))
        XCTAssertFalse(try SafeFilesystem.presence(f.root.path + "/Preference Witness.app"))
        print("NATIVE_PREFERENCE_TRANSACTION isolatedPurgeKeepsNewValues root=\(f.root.path) batch=\(cleared.id)")
    }
    func testInterruptedBackupIntentClearAndRestoreCanBeExplicitlyRecovered() async throws {
        for point in [FailurePoint.preferenceAfterBackup,.preferenceBeforeClear,.preferenceAfterClear,.preferenceBeforeRestore,.preferenceAfterRestore] {
            let f=try fixture(),e=engine(f,failure:point),p=try await plan(f,engine:e)
            if point == .preferenceBeforeRestore || point == .preferenceAfterRestore {
                let cleared=try await e.execute(planID:p.id)
                XCTAssertEqual(cleared.status,.isolated,cleared.issue ?? "");guard cleared.status == .isolated else { continue }
                do { _ = try await e.restore(batchID:cleared.id);XCTFail("Expected durable preference interruption") } catch { }
            } else {
                do { _ = try await e.execute(planID:p.id);XCTFail("Expected durable preference interruption") } catch { }
            }
            let batches=try await engine(f).recoveryBatches()
            let batch=try XCTUnwrap(batches.first { $0.entries.contains { $0.original.path == f.path } })
            let result=try await engine(f).restore(batchID:batch.id)
            XCTAssertEqual(result.status,.restored,result.entries.compactMap(\.message).joined(separator:";"))
            XCTAssertEqual(try value(f).text.trimmingCharacters(in:.whitespacesAndNewlines),"original-owned-value")
            try f.finish()
            print("NATIVE_PREFERENCE_TRANSACTION interruptedPhaseRecovered=\(point) root=\(f.root.path)")
        }
    }
    func testForgedPreferenceDomainInManifestCannotImportBackupIntoOtherDomain() async throws {
        let f=try fixture(),e=engine(f),p=try await plan(f,engine:e)
        let cleared=try await e.execute(planID:p.id)
        XCTAssertEqual(cleared.status,.isolated,cleared.issue ?? "");guard cleared.status == .isolated else { return }
        let batch=try SafeDirectory(path:f.root.path + "/Recovery/" + cleared.id.uuidString)
        let saved=try batch.read("manifest.json")
        var document=try XCTUnwrap(try JSONSerialization.jsonObject(with:saved) as? [String:Any])
        var entries=try XCTUnwrap(document["entries"] as? [[String:Any]])
        let index=try XCTUnwrap(entries.firstIndex { ($0["original"] as? [String:Any])?["path"] as? String == f.path })
        var candidate=try XCTUnwrap(entries[index]["original"] as? [String:Any])
        candidate["bundleIdentifier"]="org.example.nativefixture.unrelated"
        candidate["path"]=f.home + "/Library/Preferences/org.example.nativefixture.unrelated.plist"
        entries[index]["original"]=candidate;document["entries"]=entries
        try batch.write(JSONSerialization.data(withJSONObject:document,options:[.sortedKeys]),name:"manifest.json")
        do { _ = try await engine(f).restore(batchID:cleared.id);XCTFail("Forged domain must be rejected before service access") } catch { }
        XCTAssertEqual(try value(f).status,6)
        try batch.write(saved,name:"manifest.json")
        let restored=try await engine(f).restore(batchID:cleared.id)
        XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:";"))
        let setting=try XCTUnwrap(restored.entries.first { $0.original.path==f.path })
        let archive=try batch.existingPrivateChild(restored.backupsDirectory).existingPrivateChild(setting.id.uuidString)
        try archive.write(Data("tampered receipt".utf8),name:"receipt.plist")
        do { _ = try await engine(f).purge(batchID:cleared.id,confirmation:"永久清空 " + cleared.id.uuidString);XCTFail("Changed independent receipt must block purge before any deletion") } catch { }
        XCTAssertEqual(try value(f).text.trimmingCharacters(in:.whitespacesAndNewlines),"original-owned-value")
        try f.finish()
    }
}
#endif
