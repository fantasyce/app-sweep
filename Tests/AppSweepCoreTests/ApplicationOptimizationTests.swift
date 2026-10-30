#if os(macOS)
import Foundation
import Darwin
import XCTest
import CFSafety
@testable import AppSweepCore

final class ApplicationOptimizationTests: XCTestCase, @unchecked Sendable {
    private func fixture() throws -> NativeAcceptanceTests.NativeFixture {
        let f = try NativeAcceptanceTests.NativeFixture()
        do {
            let code = f.home + "/optimization.c"
            try Data("int main(void) { return 0; }\n".utf8).write(to:URL(fileURLWithPath:code))
            let sdk = try XCTUnwrap(ProcessInfo.processInfo.environment["APP_SWEEP_SDK"])
            let clang = try XCTUnwrap(ProcessInfo.processInfo.environment["APP_SWEEP_CLANG"])
            for arch in ["arm64","x86_64"] {
                let result = try BoundedProcess.capture(clang,arguments:["-arch",arch,"-isysroot",sdk,"-mmacosx-version-min=12.0",code,"-o",f.home + "/" + arch],timeout:30,mergeStderr:true)
                guard result.status == 0 else { throw SweepError.incomplete(result.text) }
            }
            _ = try BoundedProcess.run("/usr/bin/lipo",arguments:["-create",f.home + "/arm64",f.home + "/x86_64","-output",f.executable],timeout:10)
            try signChangedFixture(f.app)
            return f
        } catch { try? f.clean(); throw error }
    }
    private func engine(_ f: NativeAcceptanceTests.NativeFixture, enabled: Bool = true) -> ApplicationOptimizationEngine {
        ApplicationOptimizationEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:enabled ? [ApplicationOptimizationEngine.rule] : []))
    }
    private func snapshot(_ path: String) throws -> FileSnapshot {
        try SafeFilesystem.snapshot(path,allowInternalLinks:true,purpose:.application,allowInternalHardLinks:true)
    }
    private func manifestPath(_ f: NativeAcceptanceTests.NativeFixture, _ id: UUID) -> String {
        f.home + "/Library/Application Support/App Sweep/Optimization.noindex/" + id.uuidString + "/optimization.json"
    }
    private func rewrite(_ f: NativeAcceptanceTests.NativeFixture, _ id: UUID, _ update: (inout [String:Any]) -> Void) throws {
        let path = manifestPath(f,id)
        var json = try XCTUnwrap(try JSONSerialization.jsonObject(with:Data(contentsOf:URL(fileURLWithPath:path)))as?[String:Any])
        update(&json)
        let batch = try SafeDirectory(path:URL(fileURLWithPath:path).deletingLastPathComponent().path)
        try batch.write(JSONSerialization.data(withJSONObject:json),name:"optimization.json")
    }
    private func signChangedFixture(_ path: String) throws {
        let result = try BoundedProcess.capture("/usr/bin/codesign",arguments:["--force","--sign","-",path],timeout:10,mergeStderr:true)
        guard result.status == 0 else { throw SweepError.incomplete("Changed fixture signing failed: " + result.text) }
    }
    private func coordinator(_ f: NativeAcceptanceTests.NativeFixture, rules: Set<String> = [ApplicationOptimizationEngine.rule]) throws -> ApplicationOptimizationCoordinator {
        try .fixture(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:rules))
    }
    private func purgeEngine(_ f: NativeAcceptanceTests.NativeFixture, enabled: Bool = true, failure: ApplicationOptimizationEngine.FailurePoint = .none) -> ApplicationOptimizationEngine {
        ApplicationOptimizationEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:enabled ? [ApplicationOptimizationEngine.rule,ApplicationOptimizationEngine.purgeRule] : [ApplicationOptimizationEngine.rule]),failurePoint:failure)
    }
    private func storedPath(_ f: NativeAcceptanceTests.NativeFixture, _ id: UUID) -> String {
        URL(fileURLWithPath:manifestPath(f,id)).deletingLastPathComponent().appendingPathComponent(id.uuidString).path
    }
    func testPurgePublishedPreservesInstalledBodyAndLatestData() async throws {
        let f = try fixture();defer { try? f.clean() }
        let e = purgeEngine(f), review = try await e.review(f.app)
        let batch = try await e.execute(reviewID:review.id), installed = try snapshot(f.app)
        let note = f.home + "/latest-note.txt", latest = Data("latest user document after publication".utf8)
        try latest.write(to:URL(fileURLWithPath:note))
        let purge = try await e.reviewPurge(batchID:batch.id)
        XCTAssertTrue(purge.removesOriginal);XCTAssertGreaterThan(purge.retainedBackupBytes,0)
        let result = try await e.purge(reviewID:purge.id,confirmation:"永久清空 " + batch.id.uuidString)
        XCTAssertEqual(result.status,.purged);XCTAssertEqual(result.schemaVersion,4)
        XCTAssertFalse(try SafeFilesystem.presence(storedPath(f,batch.id)))
        XCTAssertNoThrow(try SafeFilesystem.verify(installed))
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:note)),latest)
        let history = try await purgeEngine(f).history()
        XCTAssertEqual(history.map(\.status),[.purged])
        do { _ = try await e.undo(batchID:batch.id);XCTFail("Permanent removal was exposed as undoable") } catch { }
        XCTAssertNoThrow(try SafeFilesystem.verify(installed))
    }
    func testPurgeRestoredPreservesExactOriginal() async throws {
        let f = try fixture();defer { try? f.clean() }
        let original = try snapshot(f.app), e = purgeEngine(f), review = try await e.review(f.app)
        let batch = try await e.execute(reviewID:review.id)
        _ = try await e.undo(batchID:batch.id)
        let restored = try snapshot(f.app), purge = try await e.reviewPurge(batchID:batch.id)
        XCTAssertFalse(purge.removesOriginal)
        let result = try await e.purge(reviewID:purge.id,confirmation:"永久清空 " + batch.id.uuidString)
        XCTAssertEqual(result.status,.purged)
        XCTAssertFalse(try SafeFilesystem.presence(storedPath(f,batch.id)))
        XCTAssertTrue(restored.identity.sameObject(as:original.identity));XCTAssertEqual(restored.tree,original.tree)
        XCTAssertNoThrow(try SafeFilesystem.verify(restored))
    }
    func testPurgeRetainedPreservesUpdatedCurrentBody() async throws {
        let f = try fixture();defer { try? f.clean() }
        let e = purgeEngine(f), review = try await e.review(f.app), batch = try await e.execute(reviewID:review.id)
        try FileManager.default.createDirectory(atPath:f.app + "/Contents/Resources",withIntermediateDirectories:true)
        try Data("new signed version after optimization".utf8).write(to:URL(fileURLWithPath:f.app + "/Contents/Resources/update.txt"))
        try signChangedFixture(f.app)
        let updated = try snapshot(f.app)
        do { _ = try await e.undo(batchID:batch.id);XCTFail("Updated app overwritten") } catch { }
        let keep = try await e.reviewKeepingCurrent(batchID:batch.id)
        _ = try await e.keepCurrent(reviewID:keep.id)
        let purge = try await e.reviewPurge(batchID:batch.id)
        XCTAssertTrue(purge.removesOriginal)
        let result = try await e.purge(reviewID:purge.id,confirmation:"永久清空 " + batch.id.uuidString)
        XCTAssertEqual(result.status,.purged);XCTAssertEqual(result.purgeOrigin,.retained)
        XCTAssertFalse(try SafeFilesystem.presence(storedPath(f,batch.id)))
        XCTAssertNoThrow(try SafeFilesystem.verify(updated))
    }
    func testPurgeRequiresIndependentRuleAndSingleUseConfirmation() async throws {
        let f = try fixture();defer { try? f.clean() }
        let e = purgeEngine(f), review = try await e.review(f.app), batch = try await e.execute(reviewID:review.id)
        let installed = try snapshot(f.app), stored = try snapshot(storedPath(f,batch.id))
        let disabled = purgeEngine(f,enabled:false), denied = try await disabled.reviewPurge(batchID:batch.id)
        do { _ = try await disabled.purge(reviewID:denied.id,confirmation:"永久清空 " + batch.id.uuidString);XCTFail("Optimization rule authorized permanent removal") } catch { }
        let wrong = try await e.reviewPurge(batchID:batch.id)
        do { _ = try await e.purge(reviewID:wrong.id,confirmation:"永久清空 " + UUID().uuidString);XCTFail("Wrong batch confirmation accepted") } catch { }
        do { _ = try await e.purge(reviewID:wrong.id,confirmation:"永久清空 " + batch.id.uuidString);XCTFail("Rejected capability replayed") } catch { }
        XCTAssertNoThrow(try SafeFilesystem.verify(installed));XCTAssertNoThrow(try SafeFilesystem.verify(stored))
        let fresh = try await e.reviewPurge(batchID:batch.id)
        _ = try await e.purge(reviewID:fresh.id,confirmation:"永久清空 " + batch.id.uuidString)
        do { _ = try await e.purge(reviewID:fresh.id,confirmation:"永久清空 " + batch.id.uuidString);XCTFail("Consumed purge replayed") } catch { }
        XCTAssertNoThrow(try SafeFilesystem.verify(installed))
    }
    func testChangedPurgeTargetAndOutsideLinkCannotDeleteAnything() async throws {
        let f = try fixture();defer { try? f.clean() }
        let e = purgeEngine(f), review = try await e.review(f.app), batch = try await e.execute(reviewID:review.id)
        let installed = try snapshot(f.app), purge = try await e.reviewPurge(batchID:batch.id)
        let outside = f.home + "/outside-sentinel.txt", bytes = Data("outside must remain".utf8)
        try bytes.write(to:URL(fileURLWithPath:outside))
        try FileManager.default.createSymbolicLink(atPath:storedPath(f,batch.id) + "/unexpected-link",withDestinationPath:outside)
        let link = storedPath(f,batch.id) + "/unexpected-link"
        let originalExecutable = try Data(contentsOf:URL(fileURLWithPath:storedPath(f,batch.id) + "/Contents/MacOS/fixture"))
        do { _ = try await e.purge(reviewID:purge.id,confirmation:"永久清空 " + batch.id.uuidString);XCTFail("Changed retained object deleted") } catch { }
        XCTAssertNoThrow(try SafeFilesystem.verify(installed))
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath:link),outside)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:storedPath(f,batch.id) + "/Contents/MacOS/fixture")),originalExecutable)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:outside)),bytes)
    }
    func testPurgeInterruptionBeforeRemovalRequiresFreshChoice() async throws {
        let f = try fixture();defer { try? f.clean() }
        let e = purgeEngine(f,failure:.beforePurgeRemoval), review = try await e.review(f.app), batch = try await e.execute(reviewID:review.id)
        let installed = try snapshot(f.app), stored = try snapshot(storedPath(f,batch.id)), purge = try await e.reviewPurge(batchID:batch.id)
        do { _ = try await e.purge(reviewID:purge.id,confirmation:"永久清空 " + batch.id.uuidString);XCTFail("Interruption not observed") } catch { }
        let pending = try await e.history()
        XCTAssertEqual(pending.first?.status,.purging)
        let restarted = purgeEngine(f), reconciled = try await restarted.reconcile(batchID:batch.id)
        XCTAssertEqual(reconciled.status,.published);XCTAssertNil(reconciled.purgeOrigin)
        XCTAssertNoThrow(try SafeFilesystem.verify(installed));XCTAssertNoThrow(try SafeFilesystem.verify(stored))
        do { _ = try await restarted.purge(reviewID:purge.id,confirmation:"永久清空 " + batch.id.uuidString);XCTFail("Restart resumed old removal grant") } catch { }
    }
    func testPurgeInterruptionAfterRemovalOnlyFinalizesAbsentSlot() async throws {
        let f = try fixture();defer { try? f.clean() }
        let e = purgeEngine(f,failure:.afterPurgeRemoval), review = try await e.review(f.app), batch = try await e.execute(reviewID:review.id)
        let installed = try snapshot(f.app), purge = try await e.reviewPurge(batchID:batch.id)
        do { _ = try await e.purge(reviewID:purge.id,confirmation:"永久清空 " + batch.id.uuidString);XCTFail("Post-delete interruption not observed") } catch { }
        XCTAssertFalse(try SafeFilesystem.presence(storedPath(f,batch.id)))
        let restarted = purgeEngine(f), result = try await restarted.reconcile(batchID:batch.id)
        XCTAssertEqual(result.status,.purged)
        XCTAssertFalse(try SafeFilesystem.presence(storedPath(f,batch.id)))
        XCTAssertNoThrow(try SafeFilesystem.verify(installed))
    }
    func testPartialPurgeInspectionPreservesRemainingObjects() async throws {
        let f = try fixture();defer { try? f.clean() }
        let e = purgeEngine(f,failure:.beforePurgeRemoval), review = try await e.review(f.app), batch = try await e.execute(reviewID:review.id)
        let installed = try snapshot(f.app), purge = try await e.reviewPurge(batchID:batch.id)
        do { _ = try await e.purge(reviewID:purge.id,confirmation:"永久清空 " + batch.id.uuidString);XCTFail("Interruption not observed") } catch { }
        // Fault model: only this owned sample loses one leaf after durable intent.
        try FileManager.default.removeItem(atPath:storedPath(f,batch.id) + "/Contents/Info.plist")
        let partial = try snapshot(storedPath(f,batch.id)), restarted = purgeEngine(f)
        let result = try await restarted.reconcile(batchID:batch.id)
        XCTAssertEqual(result.status,.needsAttention);XCTAssertEqual(result.purgeOrigin,.published)
        do { _ = try await restarted.undo(batchID:batch.id);XCTFail("Partial permanent removal entered ordinary undo") } catch { }
        do { _ = try await restarted.reviewKeepingCurrent(batchID:batch.id);XCTFail("Partial permanent removal entered keep-current") } catch { }
        XCTAssertNoThrow(try SafeFilesystem.verify(installed));XCTAssertNoThrow(try SafeFilesystem.verify(partial))
    }
    func testPublicPurgeReviewIsClosedReplacedInstanceBoundAndConsumed() async throws {
        let f = try fixture();defer { try? f.clean() }
        let rules: Set<String> = [ApplicationOptimizationEngine.rule,ApplicationOptimizationEngine.purgeRule]
        let first = try coordinator(f,rules:rules), other = try coordinator(f,rules:rules)
        let review = try await first.review(applicationPath:f.app,kind:.architectures), batch = try await first.execute(reviewID:review.id)
        let installed = try snapshot(f.app), stored = try snapshot(storedPath(f,batch.id))
        let foreign = try await first.reviewPurge(batchID:batch.id)
        do { _ = try await other.purge(reviewID:foreign.id,confirmation:"永久清空 " + batch.id.uuidString);XCTFail("Foreign purge executed") } catch { }
        try await first.close()
        do { _ = try await first.purge(reviewID:foreign.id,confirmation:"永久清空 " + batch.id.uuidString);XCTFail("Closed purge executed") } catch { }
        let replaced = try await first.reviewPurge(batchID:batch.id), latest = try await first.reviewPurge(batchID:batch.id)
        do { _ = try await first.purge(reviewID:replaced.id,confirmation:"永久清空 " + batch.id.uuidString);XCTFail("Replaced purge executed") } catch { }
        XCTAssertNoThrow(try SafeFilesystem.verify(installed));XCTAssertNoThrow(try SafeFilesystem.verify(stored))
        let purged = try await first.purge(reviewID:latest.id,confirmation:"永久清空 " + batch.id.uuidString)
        XCTAssertEqual(purged.status,.purged);XCTAssertEqual(purged.storedBytes,0);XCTAssertFalse(purged.canRestore)
        do { _ = try await first.purge(reviewID:latest.id,confirmation:"永久清空 " + batch.id.uuidString);XCTFail("Public purge replayed") } catch { }
        XCTAssertNoThrow(try SafeFilesystem.verify(installed))
    }
    func testPublicPurgeWithoutIndependentAcceptanceIsPreviewOnly() async throws {
        let f = try fixture();defer { try? f.clean() }
        let c = try coordinator(f), review = try await c.review(applicationPath:f.app,kind:.architectures), batch = try await c.execute(reviewID:review.id)
        let installed = try snapshot(f.app), stored = try snapshot(storedPath(f,batch.id))
        let preview = try await c.reviewPurge(batchID:batch.id)
        XCTAssertFalse(preview.executionAvailable);XCTAssertNotNil(preview.limitation)
        do { _ = try await c.purge(reviewID:preview.id,confirmation:"永久清空 " + batch.id.uuidString);XCTFail("Readonly purge mutated objects") } catch { }
        XCTAssertNoThrow(try SafeFilesystem.verify(installed));XCTAssertNoThrow(try SafeFilesystem.verify(stored))
    }
    func testPendingPurgePublicInspectionNeedsItsIndependentAcceptance() async throws {
        let f = try fixture();defer { try? f.clean() }
        let e = purgeEngine(f,failure:.beforePurgeRemoval), r = try await e.review(f.app), b = try await e.execute(reviewID:r.id)
        let p = try await e.reviewPurge(batchID:b.id)
        do { _ = try await e.purge(reviewID:p.id,confirmation:"永久清空 " + b.id.uuidString);XCTFail("Expected durable interruption") } catch { }
        let installed = try snapshot(f.app), stored = try snapshot(storedPath(f,b.id)), c = try coordinator(f)
        let rows = try await c.history()
        let row = try XCTUnwrap(rows.first)
        XCTAssertFalse(row.canInspect);XCTAssertFalse(row.canRestore);XCTAssertFalse(row.canKeepCurrent)
        do { _ = try await c.inspect(batchID:b.id);XCTFail("Non-purge grant rewrote purge intent") } catch { }
        let pending = try await e.history();XCTAssertEqual(pending.first?.status,.purging)
        XCTAssertNoThrow(try SafeFilesystem.verify(installed));XCTAssertNoThrow(try SafeFilesystem.verify(stored))
    }
    func testPurgeRejectsLegacyAndForgedJournalStagesWithoutRemovingObjects() async throws {
        let f = try fixture();defer { try? f.clean() }
        let e = purgeEngine(f), r = try await e.review(f.app), b = try await e.execute(reviewID:r.id)
        let installed = try snapshot(f.app), stored = try snapshot(storedPath(f,b.id))
        for (schema,status,origin) in [(1,"published",""),(2,"purging","published"),(3,"purged","published"),(4,"purging",""),(4,"purging","prepared"),(4,"published","published")] {
            try rewrite(f,b.id) { $0["schemaVersion"] = schema; $0["status"] = status; if origin.isEmpty { $0.removeValue(forKey:"purgeOrigin") } else { $0["purgeOrigin"] = origin } }
            do { _ = try await e.reviewPurge(batchID:b.id);XCTFail("Legacy or inconsistent stage authorized removal") } catch { }
            XCTAssertNoThrow(try SafeFilesystem.verify(installed));XCTAssertNoThrow(try SafeFilesystem.verify(stored))
        }
    }
    func testPurgeOccupiedBackupAndChangedJournalPermissionsLeaveCompleteObjects() async throws {
        let f = try fixture();defer { try? f.clean() }
        let e = purgeEngine(f), r = try await e.review(f.app), b = try await e.execute(reviewID:r.id)
        let installed = try snapshot(f.app), stored = try snapshot(storedPath(f,b.id))
        let p = try await e.reviewPurge(batchID:b.id)
        let handle = try FileHandle(forReadingFrom:URL(fileURLWithPath:stored.path + "/Contents/MacOS/fixture"))
        do { _ = try await e.purge(reviewID:p.id,confirmation:"永久清空 " + b.id.uuidString);XCTFail("Occupied backup was removed") } catch { }
        try handle.close()
        let fresh = try await e.reviewPurge(batchID:b.id)
        let journal = manifestPath(f,b.id)
        XCTAssertEqual(chmod(journal,0o444),0)
        defer { _ = chmod(journal,0o600) }
        do { _ = try await e.purge(reviewID:fresh.id,confirmation:"永久清空 " + b.id.uuidString);XCTFail("Changed journal permissions authorized deletion") } catch { }
        XCTAssertNoThrow(try SafeFilesystem.verify(installed));XCTAssertNoThrow(try SafeFilesystem.verify(stored))
    }
    func testPurgeChangedRecordInstalledBodyAndExternalHardLinkCannotBeRemoved() async throws {
        for change in ["record","installed","hard-link","ancestor"] {
            let f = try fixture();defer { try? f.clean() }
            let e = purgeEngine(f), r = try await e.review(f.app), b = try await e.execute(reviewID:r.id)
            let p = try await e.reviewPurge(batchID:b.id), storage = storedPath(f,b.id)
            if change == "record" { try rewrite(f,b.id) { $0["issue"] = "changed after review" } }
            else if change == "installed" { try Data("updated current data".utf8).write(to:URL(fileURLWithPath:f.app + "/Contents/current-update")) }
            else if change == "hard-link" { XCTAssertEqual(link(storage + "/Contents/MacOS/fixture",f.home + "/outside-hard-link"),0) }
            else {
                let parent = URL(fileURLWithPath:storage).deletingLastPathComponent().path
                try FileManager.default.moveItem(atPath:parent,toPath:parent + "-retained")
                try FileManager.default.createDirectory(atPath:parent,withIntermediateDirectories:false)
                try FileManager.default.createSymbolicLink(atPath:parent + "/optimization.json",withDestinationPath:parent + "-retained/optimization.json")
            }
            let installed = try snapshot(f.app)
            do { _ = try await e.purge(reviewID:p.id,confirmation:"永久清空 " + b.id.uuidString);XCTFail("Changed " + change + " accepted") } catch { }
            XCTAssertNoThrow(try SafeFilesystem.verify(installed))
            let retained = change == "ancestor" ? URL(fileURLWithPath:storage).deletingLastPathComponent().path + "-retained/" + b.id.uuidString : storage
            XCTAssertTrue(FileManager.default.fileExists(atPath:retained + "/Contents/MacOS/fixture"))
            if change == "hard-link" { XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:f.home + "/outside-hard-link")),try Data(contentsOf:URL(fileURLWithPath:retained + "/Contents/MacOS/fixture"))) }
        }
    }
    func testPurgeActualIntentWriteDenialCannotRemoveBackup() async throws {
        let f = try fixture();defer { try? f.clean() }
        let e = purgeEngine(f), r = try await e.review(f.app), b = try await e.execute(reviewID:r.id)
        let installed = try snapshot(f.app), stored = try snapshot(storedPath(f,b.id))
        let p = try await e.reviewPurge(batchID:b.id)
        let path = manifestPath(f,b.id), before = try SafeFilesystem.readMetadata(path)
        let batchDirectory = URL(fileURLWithPath:path).deletingLastPathComponent().path
        XCTAssertEqual(chflags(batchDirectory,UInt32(UF_IMMUTABLE)),0)
        defer { _ = chflags(batchDirectory,0) }
        do { _ = try await e.purge(reviewID:p.id,confirmation:"永久清空 " + b.id.uuidString);XCTFail("Failed durable intent still allowed removal") }
        catch { XCTAssertTrue(error.localizedDescription.contains("无法持久化恢复日志"),"Expected actual journal write failure, got: " + error.localizedDescription) }
        XCTAssertEqual(chflags(batchDirectory,0),0)
        XCTAssertEqual(try SafeFilesystem.readMetadata(path),before)
        let rows = try await e.history();XCTAssertEqual(rows.first?.status,.published)
        XCTAssertNoThrow(try SafeFilesystem.verify(installed));XCTAssertNoThrow(try SafeFilesystem.verify(stored))
        do { _ = try await e.purge(reviewID:p.id,confirmation:"永久清空 " + b.id.uuidString);XCTFail("Failed write capability replayed") } catch { }
    }
    func testPurgeActualUnlinkDenialStopsAndInspectionPreservesRemainder() async throws {
        let f = try fixture();defer { try? f.clean() }
        let relative = "/Contents/Resources/immutable-sentinel.txt"
        try FileManager.default.createDirectory(atPath:f.app + "/Contents/Resources",withIntermediateDirectories:true)
        try Data("owned immutable filesystem failure sample".utf8).write(to:URL(fileURLWithPath:f.app + relative))
        XCTAssertEqual(chflags(f.app + relative,UInt32(UF_IMMUTABLE)),0)
        var backup: String?
        defer {
            // Only undo the immutable flag introduced above on these two owned
            // sample copies, so the existing fixture teardown can remove them.
            _ = chflags(f.app + relative,0)
            if let backup { _ = chflags(backup + relative,0) }
        }
        try signChangedFixture(f.app)
        let e = purgeEngine(f), r = try await e.review(f.app)
        let b: ApplicationOptimizationRecord
        do { b = try await e.execute(reviewID:r.id) }
        catch {
            // Preparation may have copied the flagged sample before failing.
            // This fresh fixture owns at most its one recorded batch.
            let pending = try await e.history()
            if pending.count == 1, let row = pending.first { backup = storedPath(f,row.id) }
            throw error
        }
        backup = storedPath(f,b.id)
        let installed = try snapshot(f.app), p = try await e.reviewPurge(batchID:b.id)
        do { _ = try await e.purge(reviewID:p.id,confirmation:"永久清空 " + b.id.uuidString);XCTFail("Immutable backup removal unexpectedly succeeded") }
        catch { XCTAssertTrue(error.localizedDescription.contains("副本清空或持久化未确认"),"Expected actual verified removal failure, got: " + error.localizedDescription) }
        let rows = try await e.history();XCTAssertEqual(rows.first?.status,.needsAttention);XCTAssertEqual(rows.first?.purgeOrigin,.published)
        XCTAssertTrue(FileManager.default.fileExists(atPath:storedPath(f,b.id) + relative))
        let remaining = try snapshot(storedPath(f,b.id))
        _ = try await e.reconcile(batchID:b.id)
        XCTAssertNoThrow(try SafeFilesystem.verify(installed));XCTAssertNoThrow(try SafeFilesystem.verify(remaining))
    }
    func testReadOnlyHistoryDoesNotDescribePurgedBackupAsRetained() async throws {
        let f = try fixture();defer { try? f.clean() }
        let e = purgeEngine(f), r = try await e.review(f.app), b = try await e.execute(reviewID:r.id)
        let p = try await e.reviewPurge(batchID:b.id)
        _ = try await e.purge(reviewID:p.id,confirmation:"永久清空 " + b.id.uuidString)
        let c = try coordinator(f,rules:[]), rows = try await c.history(), row = try XCTUnwrap(rows.first)
        XCTAssertEqual(row.status,.purged);XCTAssertEqual(row.storedBytes,0)
        XCTAssertFalse(row.canReviewPurge);XCTAssertFalse(row.canRestore);XCTAssertFalse(row.canKeepCurrent)
        XCTAssertNil(row.purgeLimitation,"An already removed backup must not be described as still retained")
    }
    func testPublicCoordinatorReviewCannotCrossInstancesBeReplayedOrSurviveClose() async throws {
        let f = try fixture();defer { try? f.clean() }
        let original = try snapshot(f.app), first = try coordinator(f), other = try coordinator(f)
        let review = try await first.review(applicationPath:f.app,kind:.architectures)
        do { _ = try await other.execute(reviewID:review.id);XCTFail("Foreign coordinator review executed") } catch { }
        try await first.close()
        do { _ = try await first.execute(reviewID:review.id);XCTFail("Closed review executed") } catch { }
        let replaced = try await first.review(applicationPath:f.app,kind:.architectures)
        let latest = try await first.review(applicationPath:f.app,kind:.architectures)
        do { _ = try await first.execute(reviewID:replaced.id);XCTFail("Replaced review executed") } catch { }
        XCTAssertNoThrow(try SafeFilesystem.verify(original))
        let published = try await first.execute(reviewID:latest.id)
        XCTAssertEqual(published.status,.published);XCTAssertEqual(published.kind,.architectures)
        do { _ = try await first.execute(reviewID:latest.id);XCTFail("Review replayed") } catch { }
        let restored = try await other.restore(batchID:published.id)
        XCTAssertEqual(restored.status,.restored)
        XCTAssertTrue(try snapshot(f.app).identity.sameObject(as:original.identity))
        XCTAssertEqual(try snapshot(f.app).tree,original.tree)
    }
    func testPublicCoordinatorPreservesOriginalThroughRestartRestore() async throws {
        let f = try fixture();defer { try? f.clean() }
        let original = try snapshot(f.app), c = try coordinator(f)
        let review = try await c.review(applicationPath:f.app,kind:.architectures)
        XCTAssertTrue(review.executionAvailable);XCTAssertNil(review.limitation)
        let batch = try await c.execute(reviewID:review.id)
        XCTAssertGreaterThan(try XCTUnwrap(batch.storedBytes),0)
        let document = f.home + "/latest-user-document.txt", latest = Data("new user content after optimization".utf8)
        try latest.write(to:URL(fileURLWithPath:document))
        let restarted = try coordinator(f), history = try await restarted.history()
        XCTAssertEqual(history.map(\.id),[batch.id]);XCTAssertTrue(history[0].canRestore)
        let restored = try await restarted.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored);XCTAssertFalse(restored.canRestore)
        XCTAssertTrue(try snapshot(f.app).identity.sameObject(as:original.identity))
        XCTAssertEqual(try snapshot(f.app).tree,original.tree)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:document)),latest)
    }
    func testPublicCoordinatorReadOnlyAndKindRulesRemainEnforced() async throws {
        let f = try fixture();defer { try? f.clean() }
        let infoPath = f.app + "/Contents/Info.plist"
        var info = try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:infoPath)),format:nil) as? [String:Any])
        info["CFBundleDevelopmentRegion"] = "de"
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:infoPath))
        for language in ["Base","de","en","zh-Hans","fr","es"] {
            let directory = f.app + "/Contents/Resources/" + language + ".lproj"
            try FileManager.default.createDirectory(atPath:directory,withIntermediateDirectories:true)
            try Data("\"message\" = \"\(language)\";\n".utf8).write(to:URL(fileURLWithPath:directory + "/Localizable.strings"))
        }
        try signChangedFixture(f.app)
        let original = try snapshot(f.app), disabled = try coordinator(f,rules:[])
        let readOnly = try await disabled.review(applicationPath:f.app,kind:.architectures)
        XCTAssertFalse(readOnly.executionAvailable);XCTAssertNotNil(readOnly.limitation)
        do { _ = try await disabled.execute(reviewID:readOnly.id);XCTFail("Read-only coordinator mutated app") } catch { }
        let architectureOnly = try coordinator(f)
        let language = try await architectureOnly.review(applicationPath:f.app,kind:.languages,retainingLanguages:["en","zh-Hans"])
        XCTAssertFalse(language.executionAvailable);XCTAssertNotNil(language.limitation)
        XCTAssertTrue(language.availableLanguages.contains("fr"))
        do { _ = try await architectureOnly.execute(reviewID:language.id);XCTFail("Architecture grant authorized language") } catch { }
        XCTAssertNoThrow(try SafeFilesystem.verify(original))
    }
    func testPublicCoordinatorUpdatedKeepChoicePreservesBothBodies() async throws {
        let f = try fixture();defer { try? f.clean() }
        let c = try coordinator(f), review = try await c.review(applicationPath:f.app,kind:.architectures)
        let published = try await c.execute(reviewID:review.id)
        let storedPath = f.home + "/Library/Application Support/App Sweep/Optimization.noindex/" + published.id.uuidString + "/" + published.id.uuidString
        let original = try snapshot(storedPath)
        try FileManager.default.createDirectory(atPath:f.app + "/Contents/Resources",withIntermediateDirectories:true)
        try Data("new independently signed fixture update".utf8).write(to:URL(fileURLWithPath:f.app + "/Contents/Resources/new-version.txt"))
        try signChangedFixture(f.app)
        let updated = try snapshot(f.app)
        do { _ = try await c.restore(batchID:published.id);XCTFail("Updated app overwritten") } catch { }
        let reviewKeep = try await c.reviewKeepingCurrent(batchID:published.id)
        XCTAssertGreaterThan(reviewKeep.retainedBackupBytes,0)
        let retained = try await c.keepCurrent(reviewID:reviewKeep.id)
        XCTAssertEqual(retained.status,.retained);XCTAssertFalse(retained.canRestore)
        do { _ = try await c.keepCurrent(reviewID:reviewKeep.id);XCTFail("Keep-current choice replayed") } catch { }
        XCTAssertNoThrow(try SafeFilesystem.verify(updated));XCTAssertNoThrow(try SafeFilesystem.verify(original))
    }
    func testPublicCoordinatorInspectsUnpublishedPreparationWithoutMovingApp() async throws {
        let f = try fixture();defer { try? f.clean() }
        let original = try snapshot(f.app), id = UUID(), architecture = try ApplicationArchitecturePreparation.nativeArchitecture().0
        let identifier = try XCTUnwrap(try AppInspector.metadata(f.app,component:false).0["CFBundleIdentifier"] as? String)
        let root = try SafeDirectory(path:f.home + "/Library/Application Support").privateChild("App Sweep")
        _ = try root.privateChild("Recovery")
        let batch = try root.privateChild("Optimization.noindex").privateChild(id.uuidString)
        let record = ApplicationOptimizationRecord(schemaVersion:2,id:id,ownerUID:getuid(),createdAt:Date(),rule:ApplicationOptimizationEngine.rule,applicationPath:f.app,identifier:identifier,architecture:architecture,nativeCodeHash:try ApplicationArchitecturePreparation.signature(f.app,identifier:identifier,architecture:architecture),originalAncestors:original.ancestors,original:try .init(original),prepared:nil,status:.preparing,issue:nil)
        let encoder = JSONEncoder();encoder.dateEncodingStrategy = .iso8601
        try batch.write(encoder.encode(record),name:"optimization.json")
        let c = try coordinator(f), history = try await c.history()
        XCTAssertEqual(history.map(\.id),[id]);XCTAssertTrue(history[0].canInspect);XCTAssertNil(history[0].storedBytes)
        let stopped = try await c.inspect(batchID:id)
        XCTAssertEqual(stopped.status,.stopped);XCTAssertFalse(stopped.canInspect)
        XCTAssertNoThrow(try SafeFilesystem.verify(original))
    }
    // Removing publish/undo or losing the original inode makes this workflow fail.
    func testPublishesAndRestoresOriginalAcrossEngineRestartWithoutResigning() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let support = f.home + "/Library/Application Support/App Sweep"
        try FileManager.default.createDirectory(atPath: support + "/backups", withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: support)
        let original = try snapshot(f.app), bytes = try SafeFilesystem.readMetadata(f.executable)
        let e = engine(f), review = try await e.review(f.app)
        XCTAssertGreaterThan(review.estimatedReductionBytes,0)
        let published = try await e.execute(reviewID:review.id)
        XCTAssertEqual(published.status,.published)
        let installed = try snapshot(f.app)
        XCTAssertNotEqual(installed.identity.inode,original.identity.inode)
        XCTAssertLessThan(installed.bytes,original.bytes)
        let retained = try snapshot(f.home + "/Library/Application Support/App Sweep/Optimization.noindex/" + published.id.uuidString + "/" + published.id.uuidString)
        XCTAssertTrue(retained.identity.sameObject(as:original.identity))
        XCTAssertEqual(retained.tree,original.tree)
        XCTAssertEqual(try BoundedProcess.capture(f.executable,arguments:[],timeout:5,mergeStderr:true).status,0)
        let restarted = engine(f), restored = try await restarted.undo(batchID:published.id)
        XCTAssertEqual(restored.status,.restored)
        XCTAssertTrue(try snapshot(f.app).identity.sameObject(as:original.identity))
        XCTAssertEqual(try snapshot(f.app).tree,original.tree)
        XCTAssertEqual(try SafeFilesystem.readMetadata(f.executable),bytes)
        let history = try await restarted.history()
        XCTAssertEqual(history.map(\.id),[published.id])
        XCTAssertEqual(history.first?.status,.restored)
    }
    // A reviewed snapshot cannot authorize a new version or be replayed.
    func testCompletedCurrentCleanupHistoryDoesNotBlockIndependentOptimization() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let cache = f.home + "/Library/Caches/org.example.history"
        try FileManager.default.createDirectory(atPath:cache,withIntermediateDirectories:true)
        try Data("retained cache contents".utf8).write(to:URL(fileURLWithPath:cache + "/data"))
        let before = try SafeFilesystem.snapshot(cache)
        _ = try SafeDirectory(path:f.home + "/Library/Application Support").privateChild("App Sweep")
        let item = Candidate(id:UUID(),path:cache,category:.cache,bundleIdentifier:"org.example.history",evidence:[.init(kind:.validatedRule,detail:"owned history fixture",verified:true)],rule:"fixture-v1",identity:before.identity,bytes:before.bytes,retentionReason:nil)
        let cleanup = SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true),vaultPath:f.home + "/Library/Application Support/App Sweep/Recovery")
        let scan = await cleanup.adoptFixture([item],snapshots:[item.id:before])
        let plan = try await cleanup.makePlan(reportID:scan.id,selected:[item.id],includeUserData:false)
        let batch = try await cleanup.execute(planID:plan.id)
        let restored = try await cleanup.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored)
        let e = engine(f), reviewed = try await e.review(f.app), published = try await e.execute(reviewID:reviewed.id)
        XCTAssertEqual(published.status,.published)
        let undone = try await e.undo(batchID:published.id); XCTAssertEqual(undone.status,.restored)
        XCTAssertEqual(try SafeFilesystem.readMetadata(cache + "/data"),Data("retained cache contents".utf8))
    }
    func testUnconfirmedBackupInOtherwiseRestoredHistoryStillBlocksOptimization() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let root = try SafeDirectory(path:f.home + "/Library/Application Support").privateChild("App Sweep").privateChild("Recovery")
        let id = UUID(), batch = try root.privateChild(id.uuidString)
        let item = Candidate(id:UUID(),path:f.home + "/Library/Caches/org.example.history/data",category:.cache,bundleIdentifier:"org.example.history",evidence:[],rule:"fixture-v1",identity:nil,bytes:0,retentionReason:nil)
        let entry = RecoveryEntry(id:item.id,original:item,state:.restored,message:nil)
        let record = RecoveryManifest(schemaVersion:5,id:id,createdAt:Date(),status:.restored,entries:[entry],issue:nil)
        let encoder = JSONEncoder();encoder.dateEncodingStrategy = .iso8601
        var json = try XCTUnwrap(try JSONSerialization.jsonObject(with:encoder.encode(record)) as? [String:Any])
        var entries = try XCTUnwrap(json["entries"] as? [[String:Any]]);entries[0]["backupPending"] = true;json["entries"] = entries
        try batch.write(JSONSerialization.data(withJSONObject:json),name:"manifest.json")
        let original = try snapshot(f.app), e = engine(f), reviewed = try await e.review(f.app)
        do { _ = try await e.execute(reviewID:reviewed.id);XCTFail("Unconfirmed backup treated as completed history") } catch { }
        XCTAssertNoThrow(try SafeFilesystem.verify(original))
        let history = try await e.history();XCTAssertTrue(history.isEmpty)
    }
    func testChangedSourceAndUsedReviewNeverPublish() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let e = engine(f), review = try await e.review(f.app)
        try Data("new version".utf8).write(to:URL(fileURLWithPath:f.app + "/Contents/new-data"))
        for _ in 0..<2 {
            do { _ = try await e.execute(reviewID:review.id); XCTFail("Stale/used review executed") } catch { }
        }
        XCTAssertEqual(try SafeFilesystem.readMetadata(f.app + "/Contents/new-data"),Data("new version".utf8))
        XCTAssertFalse(FileManager.default.fileExists(atPath:f.home + "/Library/Application Support/App Sweep/Optimization.noindex"))
    }
    // Undo must not overwrite an application updated after publication.
    func testChangedApplicationRootAttributeRefusesUndoAndPreservesBothObjects() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let e = engine(f), review = try await e.review(f.app)
        let published = try await e.execute(reviewID:review.id)
        let stored = f.home + "/Library/Application Support/App Sweep/Optimization.noindex/" + published.id.uuidString + "/" + published.id.uuidString
        _ = try BoundedProcess.run("/usr/bin/xattr",arguments:["-w","org.appsweep.root-conflict","new metadata must survive",f.app],timeout:3)
        let installedBefore = try snapshot(f.app), storedBefore = try snapshot(stored)
        do { _ = try await engine(f).undo(batchID:published.id); XCTFail("Changed root attribute was overwritten by undo") } catch { }
        XCTAssertNoThrow(try SafeFilesystem.verify(installedBefore))
        XCTAssertNoThrow(try SafeFilesystem.verify(storedBefore))
        XCTAssertEqual(try BoundedProcess.run("/usr/bin/xattr",arguments:["-p","org.appsweep.root-conflict",f.app],timeout:3),"new metadata must survive\n")
        let history = try await e.history()
        XCTAssertEqual(history.first?.status,.needsAttention)
    }

    func testUpdatedInstalledApplicationIsPreservedAndRecoveryReportsConflict() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let e = engine(f), review = try await e.review(f.app)
        let published = try await e.execute(reviewID:review.id)
        let updated = f.app + "/Contents/new-update"
        try Data("must survive".utf8).write(to:URL(fileURLWithPath:updated))
        do { _ = try await engine(f).undo(batchID:published.id); XCTFail("Updated app overwritten") } catch { }
        XCTAssertEqual(try SafeFilesystem.readMetadata(updated),Data("must survive".utf8))
        let history = try await engine(f).history()
        XCTAssertEqual(history.first?.status,.needsAttention)
        XCTAssertTrue(FileManager.default.fileExists(atPath:f.home + "/Library/Application Support/App Sweep/Optimization.noindex/" + published.id.uuidString + "/" + published.id.uuidString + "/Contents/MacOS/fixture"))
    }
    // Removing this metadata-only exit strands an updated application forever;
    // skipping either revalidation could acknowledge a different app or backup.
    func testReviewedKeepCurrentClosesConflictWithoutMovingOrDeletingEitherObject() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let e = engine(f), reviewed = try await e.review(f.app)
        let published = try await e.execute(reviewID:reviewed.id)
        try FileManager.default.createDirectory(atPath:f.app + "/Contents/Resources",withIntermediateDirectories:true)
        try Data("new version resource".utf8).write(to:URL(fileURLWithPath:f.app + "/Contents/Resources/version.txt"))
        try signChangedFixture(f.app)
        do { _ = try await e.undo(batchID:published.id); XCTFail("Updated version overwritten") } catch { }
        let installed = try snapshot(f.app), storedPath = URL(fileURLWithPath:manifestPath(f,published.id)).deletingLastPathComponent().path + "/" + published.slot
        let stored = try snapshot(storedPath)
        let choice = try await e.reviewKeepingCurrent(batchID:published.id)
        let kept = try await e.keepCurrent(reviewID:choice.id)
        XCTAssertEqual(kept.status.rawValue,"retained")
        XCTAssertFalse(kept.status.unfinished)
        XCTAssertNoThrow(try SafeFilesystem.verify(installed)); XCTAssertNoThrow(try SafeFilesystem.verify(stored))
        let restarted = engine(f), history = try await restarted.history()
        XCTAssertEqual(history.first?.status.rawValue,"retained")
        XCTAssertNoThrow(try ApplicationOptimizationEngine.ensureNoPending(policy:SafetyPolicy(home:f.home,acceptedPlatform:true),paths:[f.app],identifiers:["org.example.sweepfixture"]))
        do { _ = try await restarted.undo(batchID:published.id); XCTFail("Closed conflict allowed old undo") } catch { }
        do { _ = try await e.keepCurrent(reviewID:choice.id); XCTFail("Choice replayed") } catch { }
        XCTAssertNoThrow(try SafeFilesystem.verify(installed)); XCTAssertNoThrow(try SafeFilesystem.verify(stored))
    }
    func testKeepCurrentRefusesChangesToEitherReviewedObjectAndUnknownChoices() async throws {
        for changed in ["installed","stored"] {
            let f = try fixture(); defer { try? f.clean() }
            let e = engine(f), reviewed = try await e.review(f.app)
            let published = try await e.execute(reviewID:reviewed.id)
            try FileManager.default.createDirectory(atPath:f.app + "/Contents/Resources",withIntermediateDirectories:true)
        try Data("new version".utf8).write(to:URL(fileURLWithPath:f.app + "/Contents/Resources/version.txt"))
            try signChangedFixture(f.app)
            let choice = try await e.reviewKeepingCurrent(batchID:published.id)
            let storedPath = URL(fileURLWithPath:manifestPath(f,published.id)).deletingLastPathComponent().path + "/" + published.slot
            let target = changed == "installed" ? f.app : storedPath
            try Data("after review".utf8).write(to:URL(fileURLWithPath:target + "/Contents/after-review"))
            let installed = try snapshot(f.app), stored = try snapshot(storedPath)
            for id in [UUID(),choice.id] {
                do { _ = try await e.keepCurrent(reviewID:id); XCTFail("Changed or unknown choice accepted") } catch { }
            }
            let history = try await engine(f).history()
            XCTAssertNotEqual(history.first?.status.rawValue,"retained")
            XCTAssertNoThrow(try SafeFilesystem.verify(installed)); XCTAssertNoThrow(try SafeFilesystem.verify(stored))
        }
    }
    func testKeepCurrentCannotDismissAHealthyPublishedPairOrDamagedBackup() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let e = engine(f), reviewed = try await e.review(f.app)
        let published = try await e.execute(reviewID:reviewed.id)
        do { _ = try await e.reviewKeepingCurrent(batchID:published.id); XCTFail("No conflict to close") } catch { }
        try FileManager.default.createDirectory(atPath:f.app + "/Contents/Resources",withIntermediateDirectories:true)
        try Data("new version".utf8).write(to:URL(fileURLWithPath:f.app + "/Contents/Resources/version.txt"))
        try signChangedFixture(f.app)
        let storedPath = URL(fileURLWithPath:manifestPath(f,published.id)).deletingLastPathComponent().path + "/" + published.slot
        try Data("damaged retained original".utf8).write(to:URL(fileURLWithPath:storedPath + "/Contents/damage"))
        do { _ = try await e.reviewKeepingCurrent(batchID:published.id); XCTFail("Damaged original acknowledged") } catch { }
        let history = try await e.history(); XCTAssertEqual(history.first?.status,.published)
    }
    func testKeepingCurrentCannotAcknowledgeChangedJournalOrForgedTerminalRecord() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let e = engine(f), reviewed = try await e.review(f.app), published = try await e.execute(reviewID:reviewed.id)
        try FileManager.default.createDirectory(atPath:f.app + "/Contents/Resources",withIntermediateDirectories:true)
        try Data("valid current version".utf8).write(to:URL(fileURLWithPath:f.app + "/Contents/Resources/version.txt"))
        try signChangedFixture(f.app)
        let choice = try await e.reviewKeepingCurrent(batchID:published.id)
        try rewrite(f,published.id) { $0["issue"] = "changed after review" }
        do { _ = try await e.keepCurrent(reviewID:choice.id); XCTFail("Changed journal acknowledged") } catch { }
        for schema in [2,3] {
            try rewrite(f,published.id) { $0["schemaVersion"] = schema; $0["status"] = "retained" }
            do { _ = try await engine(f).history(); XCTFail("Missing confirmation proof accepted") } catch { }
            do { try ApplicationOptimizationEngine.ensureNoPending(policy:SafetyPolicy(home:f.home,acceptedPlatform:true),paths:[f.app],identifiers:["org.example.sweepfixture"]); XCTFail("Invalid terminal record ignored") } catch { }
        }
    }
    func testKeepingCurrentRefusesUnsignedChangedApplicationWithoutTouchingBackup() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let e = engine(f), reviewed = try await e.review(f.app), published = try await e.execute(reviewID:reviewed.id)
        try Data("unverified modification".utf8).write(to:URL(fileURLWithPath:f.app + "/Contents/new-update"))
        let before = try snapshot(f.app)
        let storedPath = URL(fileURLWithPath:manifestPath(f,published.id)).deletingLastPathComponent().path + "/" + published.slot
        let stored = try snapshot(storedPath)
        do { _ = try await e.reviewKeepingCurrent(batchID:published.id); XCTFail("Invalid current signature accepted") } catch { }
        XCTAssertNoThrow(try SafeFilesystem.verify(before)); XCTAssertNoThrow(try SafeFilesystem.verify(stored))
        let history = try await e.history(); XCTAssertEqual(history.first?.status,.published)
    }
    func testAnotherWriterOnAnyApplicationNodeRefusesReviewBeforePreparing() async throws {
        for exposure in ["file-mode","directory-mode","write-acl"] {
            let f = try fixture(); defer { try? f.clean() }
            let resources = f.app + "/Contents/Resources"
            try FileManager.default.createDirectory(atPath:resources,withIntermediateDirectories:true)
            let resource = resources + "/data.txt"
            try Data("sealed resource".utf8).write(to:URL(fileURLWithPath:resource))
            if exposure == "file-mode" { XCTAssertEqual(chmod(resource,0o666),0) }
            else if exposure == "directory-mode" { XCTAssertEqual(chmod(resources,0o777),0) }
            else { _ = try BoundedProcess.run("/bin/chmod",arguments:["+a","everyone allow write",resource],timeout:3) }
            try signChangedFixture(f.app)
            let original = try snapshot(f.app)
            do { _ = try await engine(f).review(f.app); XCTFail("Another writer on " + exposure + " was accepted") } catch { }
            XCTAssertNoThrow(try SafeFilesystem.verify(original))
            XCTAssertFalse(FileManager.default.fileExists(atPath:f.home + "/Library/Application Support/App Sweep/Optimization.noindex"))
        }
    }
    func testUnacceptedRuleAndUnknownReviewCannotCreatePreparation() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let e = engine(f,enabled:false), source = try snapshot(f.app)
        let review = try await e.review(f.app)
        for id in [review.id,UUID()] {
            do { _ = try await e.execute(reviewID:id); XCTFail("Unaccepted rule executed") } catch { }
        }
        XCTAssertNoThrow(try SafeFilesystem.verify(source))
        XCTAssertFalse(FileManager.default.fileExists(atPath:f.home + "/Library/Application Support/App Sweep/Optimization.noindex"))
    }
    // Simulate a persisted pre-swap intent surviving an already successful swap.
    func testExplicitReconciliationRecognizesPublishedObjectsWithoutRepeatingSwap() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let e = engine(f), review = try await e.review(f.app)
        let published = try await e.execute(reviewID:review.id), inode = try snapshot(f.app).identity.inode
        try rewrite(f,published.id) { $0["status"] = "publishing" }
        let restarted = engine(f), pending = try await restarted.history()
        XCTAssertEqual(pending.first?.status,.publishing)
        XCTAssertEqual(try snapshot(f.app).identity.inode,inode)
        let reconciled = try await restarted.reconcile(batchID:published.id)
        XCTAssertEqual(reconciled.status,.published)
        XCTAssertEqual(try snapshot(f.app).identity.inode,inode)
        let restored = try await restarted.undo(batchID:published.id)
        XCTAssertEqual(restored.status,.restored)
        try rewrite(f,published.id) { $0["status"] = "undoing" }
        let originalInode = try snapshot(f.app).identity.inode
        let second = try await engine(f).reconcile(batchID:published.id)
        XCTAssertEqual(second.status,.restored)
        XCTAssertEqual(try snapshot(f.app).identity.inode,originalInode)
    }
    func testForgedProtectedJournalCannotAuthorizeRestoration() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let e = engine(f), review = try await e.review(f.app)
        let published = try await e.execute(reviewID:review.id), installed = try snapshot(f.app)
        try rewrite(f,published.id) { $0["applicationPath"] = "/System/Applications/Protected.app" }
        do { _ = try await engine(f).undo(batchID:published.id); XCTFail("Protected forged path accepted") } catch { }
        XCTAssertNoThrow(try SafeFilesystem.verify(installed))
    }
    func testUnfinishedOptimizationBlocksOrdinaryCleanupAndPreparationIsNotResumed() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let e = engine(f), review = try await e.review(f.app)
        let published = try await e.execute(reviewID:review.id)
        try rewrite(f,published.id) { $0["status"] = "publishing" }
        let cache = f.home + "/Library/Caches/org.example.sweepfixture"
        try FileManager.default.createDirectory(atPath:cache,withIntermediateDirectories:true)
        try Data("must remain".utf8).write(to:URL(fileURLWithPath:cache + "/data"))
        let source = try SafeFilesystem.snapshot(cache)
        let candidate = Candidate(id:UUID(),path:cache,category:.cache,bundleIdentifier:"org.example.sweepfixture",evidence:[.init(kind:.validatedRule,detail:"own test data",verified:true)],rule:"fixture-v1",identity:source.identity,bytes:source.bytes,retentionReason:nil)
        let cleanup = SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true),vaultPath:f.home + "/Library/Application Support/App Sweep/Recovery")
        let report = await cleanup.adoptFixture([candidate],snapshots:[candidate.id:source])
        let plan = try await cleanup.makePlan(reportID:report.id,selected:[candidate.id],includeUserData:false)
        do { _ = try await cleanup.execute(planID:plan.id); XCTFail("Unconfirmed optimization allowed cleanup") } catch { }
        XCTAssertNoThrow(try SafeFilesystem.verify(source))
        _ = try await e.reconcile(batchID:published.id)
        _ = try await e.undo(batchID:published.id)
        let original = try snapshot(f.app)
        try rewrite(f,published.id) { $0["status"] = "preparing"; $0.removeValue(forKey:"prepared") }
        let stopped = try await engine(f).reconcile(batchID:published.id)
        XCTAssertEqual(stopped.status,.stopped)
        XCTAssertNoThrow(try SafeFilesystem.verify(original))
        XCTAssertTrue(FileManager.default.fileExists(atPath:f.home + "/Library/Application Support/App Sweep/Optimization.noindex/" + published.id.uuidString + "/" + published.id.uuidString))
    }
    func testKnownUnfinishedApplicationDoesNotBlockUnrelatedVerifiedCleanup() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let e = engine(f), review = try await e.review(f.app)
        let published = try await e.execute(reviewID:review.id), installed = try snapshot(f.app)
        try rewrite(f,published.id) { $0["status"] = "publishing" }
        let cache = f.home + "/Library/Caches/org.example.unrelated"
        try FileManager.default.createDirectory(atPath:cache,withIntermediateDirectories:true)
        try Data("independent regenerable sample".utf8).write(to:URL(fileURLWithPath:cache + "/data"))
        let source = try SafeFilesystem.snapshot(cache)
        let candidate = Candidate(id:UUID(),path:cache,category:.cache,bundleIdentifier:"org.example.unrelated",evidence:[.init(kind:.validatedRule,detail:"independent own test data",verified:true)],rule:"fixture-v1",identity:source.identity,bytes:source.bytes,retentionReason:nil)
        let cleanup = SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true),vaultPath:f.home + "/Library/Application Support/App Sweep/Recovery")
        let report = await cleanup.adoptFixture([candidate],snapshots:[candidate.id:source])
        let plan = try await cleanup.makePlan(reportID:report.id,selected:[candidate.id],includeUserData:false)
        let result = try await cleanup.execute(planID:plan.id)
        XCTAssertEqual(result.status,.isolated)
        XCTAssertFalse(FileManager.default.fileExists(atPath:cache))
        XCTAssertNoThrow(try SafeFilesystem.verify(installed))
        let restored = try await cleanup.restore(batchID:result.id)
        XCTAssertEqual(restored.status,.restored)
        XCTAssertEqual(try SafeFilesystem.readMetadata(cache + "/data"),Data("independent regenerable sample".utf8))
    }
    func testUnjournaledBatchAndSymlinkedJournalCannotBeIgnored() async throws {
        for alias in [false,true] {
            let f = try fixture(); defer { try? f.clean() }
            let e = engine(f), review = try await e.review(f.app), source = try snapshot(f.app)
            let root = try SafeDirectory(path:f.home + "/Library/Application Support").privateChild("App Sweep")
            if alias {
                let outside = try SafeDirectory(path:f.home).privateChild("unrelated")
                XCTAssertEqual(symlink(outside.path,root.path + "/Optimization.noindex"),0)
            } else {
                let journal = try root.privateChild("Optimization.noindex")
                _ = try journal.privateChild(UUID().uuidString)
            }
            do { _ = try await e.execute(reviewID:review.id); XCTFail("Unknown journal ignored") } catch { }
            XCTAssertNoThrow(try SafeFilesystem.verify(source))
        }
    }
    private struct InterruptedFixture: Codable {
        let home: String
        let homeIdentity: FileIdentity
        let original: FileIdentity
        let tree: TreeFingerprint
    }
    func testInterruptionChild() async throws {
        guard let phase = ProcessInfo.processInfo.environment["APP_SWEEP_OPTIMIZATION_PROBE_PHASE"] else { throw XCTSkip("Only the isolated interruption driver starts this child") }
        let f = try fixture(); defer { try? f.clean() } // Abrupt _exit bypasses teardown.
        XCTAssertEqual(chmod(f.home,0o700),0)
        let before = try snapshot(f.app)
        let receipt = InterruptedFixture(home:f.home,homeIdentity:try SafeDirectory(path:f.home).ownIdentity,original:before.identity,tree:try .capture(before.tree))
        try SafeDirectory(path:f.home).write(JSONEncoder().encode(receipt),name:"interruption-before.json")
        print("OPTIMIZATION_CHILD_HOME=" + f.home); fflush(nil)
        XCTAssertEqual(setenv("APP_SWEEP_OPTIMIZATION_PROBE_HOME",f.home,1),0)
        let e = engine(f), review = try await e.review(f.app)
        do {
            let published = try await e.execute(reviewID:review.id)
            if ["undoing","restored","root-settle"].contains(phase) { _ = try await e.undo(batchID:published.id) }
        } catch {
            if ["write-failure","swap-eio","sync-after-swap","root-settle","root-never-settles"].contains(phase) { fflush(nil); _exit(87) }
            throw error
        }
        if phase == "root-settle" { fflush(nil); _exit(92) }
        XCTFail("Interruption shim did not intercept its exact fixture checkpoint")
    }
    // These are real child exits and injected syscall failures, not merely
    // status edits. A blind second swap or lost original inode fails this test.
    func testAbruptExitsAndPersistenceFailuresRetainBothSidesWithoutAutomaticResumption() async throws {
        let owner = try fixture(); defer { try? owner.clean() }
        let source = try NativeAcceptanceTests.NativeFixture.resource("OptimizationInterruption",extension:"c")
        let sdk = try XCTUnwrap(ProcessInfo.processInfo.environment["APP_SWEEP_SDK"])
        let clang = try XCTUnwrap(ProcessInfo.processInfo.environment["APP_SWEEP_CLANG"])
        let library = owner.home + "/interruption.dylib"
        let compilation = try BoundedProcess.capture(clang,arguments:["-dynamiclib","-isysroot",sdk,"-mmacosx-version-min=12.0",source.path,"-o",library],timeout:20,mergeStderr:true)
        XCTAssertEqual(compilation.status,0,compilation.text)
        guard compilation.status == 0 else { return }
        let developer = try XCTUnwrap(ProcessInfo.processInfo.environment["DEVELOPER_DIR"])
        let cases: [(String,Int32,ApplicationOptimizationRecord.Status)] = [
            ("preparing",81,.stopped),("prepared",82,.stopped),("publishing",83,.stopped),
            ("published",84,.published),("undoing",85,.published),("restored",86,.restored),
            ("write-failure",87,.stopped),("swap-eio",87,.published),("sync-after-swap",87,.published),("descriptor-flags",89,.stopped),("ancestor-sync",91,.stopped),
            ("root-settle",92,.restored),("root-never-settles",87,.published)
        ]
        for (phase,exit,expected) in cases {
            let result = try BoundedProcess.capture("/usr/bin/env",arguments:["DYLD_INSERT_LIBRARIES="+library,"APP_SWEEP_OPTIMIZATION_PROBE_PHASE="+phase,developer+"/usr/bin/xctest","-XCTest","AppSweepCoreTests.ApplicationOptimizationTests/testInterruptionChild",Bundle(for:Self.self).bundlePath],timeout:30,mergeStderr:true)
            XCTAssertEqual(result.status,exit,phase + ": " + result.text)
            if phase == "root-settle" {
                XCTAssertTrue(result.text.contains("OPTIMIZATION_ROOT_CTIME_CHANGE=1"),result.text)
                XCTAssertTrue(result.text.contains("OPTIMIZATION_ROOT_CTIME_CHANGE=2"),result.text)
            }
            if phase == "root-never-settles" {
                XCTAssertTrue(result.text.contains("OPTIMIZATION_ROOT_CTIME_CHANGE=1"),result.text)
                XCTAssertFalse(result.text.contains("OPTIMIZATION_ROOT_CTIME_CHANGE=2"),"Unstable verification must not repeat the exchange")
                XCTAssertLessThan(result.text.components(separatedBy:"OPTIMIZATION_ROOT_CTIME_CHANGE=").count,12,"Read-only stabilization must stop at a finite bound")
            }
            guard let line = result.text.split(separator:"\n").first(where:{ $0.hasPrefix("OPTIMIZATION_CHILD_HOME=") }) else { XCTFail(result.text); continue }
            let home = String(line.dropFirst("OPTIMIZATION_CHILD_HOME=".count))
            let base = try XCTUnwrap(ProcessInfo.processInfo.environment["APP_SWEEP_FIXTURES"])
            guard URL(fileURLWithPath:home).deletingLastPathComponent().path == base,
                  UUID(uuidString:URL(fileURLWithPath:home).lastPathComponent) != nil, home != owner.home else { XCTFail("Unconfirmed child fixture"); continue }
            let receipt = try JSONDecoder().decode(InterruptedFixture.self,from:SafeFilesystem.readMetadata(home+"/interruption-before.json"))
            guard receipt.home == home, try SafeDirectory(path:home).ownIdentity.inode == receipt.homeIdentity.inode else { XCTFail("Child fixture replaced"); continue }
            defer {
                do {
                    let current = try SafeFilesystem.snapshot(home,allowInternalLinks:true,purpose:.managedData,allowInternalHardLinks:true)
                    XCTAssertEqual(current.identity.inode,receipt.homeIdentity.inode)
                    XCTAssertTrue(SafeFilesystem.removeVerified(in:try SafeDirectory(path:base),name:URL(fileURLWithPath:home).lastPathComponent,identity:current.identity,contents:current.tree,allowInternalHardLinks:true))
                    print("OPTIMIZATION_INTERRUPTION_FIXTURE_REMOVED=" + home)
                } catch { XCTFail("Exact interruption fixture retained: " + home) }
            }
            guard result.status == exit else { continue }
            let e = ApplicationOptimizationEngine(policy:SafetyPolicy(home:home,acceptedPlatform:true,validatedRules:[ApplicationOptimizationEngine.rule]))
            let history = try await e.history(), batch = try XCTUnwrap(history.first)
            XCTAssertEqual(history.count,1)
            let installedBefore = try snapshot(home+"/Applications/Disposable Fixture.app")
            let checked = try await e.reconcile(batchID:batch.id)
            XCTAssertEqual(checked.status,expected,phase)
            XCTAssertNoThrow(try SafeFilesystem.verify(installedBefore),"Reconciliation moved the installed application")
            let originalPath = expected == .published ? home+"/Library/Application Support/App Sweep/Optimization.noindex/"+batch.id.uuidString+"/"+batch.id.uuidString : home+"/Applications/Disposable Fixture.app"
            let original = try snapshot(originalPath)
            XCTAssertTrue(original.identity.sameObject(as:receipt.original),phase)
            XCTAssertTrue(try receipt.tree.matches(original.tree),phase)
            if expected == .published {
                let restored = try await e.undo(batchID:batch.id)
                XCTAssertEqual(restored.status,.restored)
                XCTAssertTrue(try snapshot(home+"/Applications/Disposable Fixture.app").identity.sameObject(as:receipt.original))
            }
        }
    }
    func testSharedRecoveryLeaseBlocksOptimizationBeforePreparation() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let e = engine(f), review = try await e.review(f.app), source = try snapshot(f.app)
        let root = try SafeDirectory(path:f.home + "/Library/Application Support").privateChild("App Sweep")
        let recovery = try root.privateChild("Recovery")
        XCTAssertEqual(as_lock(recovery.fd),0)
        do { _ = try await e.execute(reviewID:review.id); XCTFail("Concurrent cleanup lease ignored") } catch { }
        XCTAssertNoThrow(try SafeFilesystem.verify(source))
        XCTAssertFalse(FileManager.default.fileExists(atPath:root.path + "/Optimization.noindex"))
    }
}
#endif
