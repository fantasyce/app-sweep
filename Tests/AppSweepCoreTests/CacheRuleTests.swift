#if os(macOS)
import Foundation
import XCTest
import SQLite3
import Darwin
@testable import AppSweepCore

final class CacheRuleTests: XCTestCase, @unchecked Sendable {
    func testDeniedFirefoxScopeDoesNotBlockIndependentCacheRecovery() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let app = f.home + "/Applications/Firefox.app/Contents"
        let profile = f.home + "/Library/Application Support/Firefox"
        try FileManager.default.createDirectory(atPath: app, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: profile, withIntermediateDirectories: true)
        try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier":"org.mozilla.firefox"], format:.xml, options:0).write(to:URL(fileURLWithPath:app + "/Info.plist"))
        let original = Data("[Profile0]\nIsRelative=1\nPath=Profiles/owned-test\n".utf8)
        try original.write(to: URL(fileURLWithPath: profile + "/profiles.ini"))
        try FileManager.default.setAttributes([.posixPermissions:0], ofItemAtPath:profile)
        defer { try? FileManager.default.setAttributes([.posixPermissions:0o700], ofItemAtPath:profile) }
        let engine = f.engine(), report = try await engine.scanJunk()
        XCTAssertFalse(report.complete, "Permission failure must remain visible")
        XCTAssertFalse(report.issues.isEmpty)
        let item = try XCTUnwrap(report.selectableCandidates(includeUserData:false).first { $0.rule == CacheRule.name })
        let bytes = try Data(contentsOf:URL(fileURLWithPath:item.path))
        let plan = try await engine.makePlan(reportID:report.id, selected:[item.id], includeUserData:false)
        let batch = try await engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated)
        let restored = try await engine.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:item.path)),bytes)
        try FileManager.default.setAttributes([.posixPermissions:0o700], ofItemAtPath:profile)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:profile + "/profiles.ini")),original)
    }
    func testIncompleteDiagnosticScopeDoesNotHideVerifiedCache() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let logs = f.home + "/Library/Logs/DiagnosticReports"
        try FileManager.default.createDirectory(atPath:logs,withIntermediateDirectories:true)
        XCTAssertEqual(mkfifo(logs + "/owned.ips",0o600),0)
        try FileManager.default.setAttributes([.modificationDate:Date().addingTimeInterval(-31 * 86400)],ofItemAtPath:logs + "/owned.ips")
        let engine = f.engine(), report = try await engine.scanJunk()
        XCTAssertFalse(report.complete)
        XCTAssertTrue(report.issues.contains { $0.contains("不是普通文件") })
        let item = try XCTUnwrap(report.selectableCandidates(includeUserData:false).first { $0.rule == CacheRule.name })
        let plan = try await engine.makePlan(reportID:report.id,selected:[item.id],includeUserData:false)
        XCTAssertEqual(plan.items.map(\.id),[item.id])
        XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains { $0.path.hasPrefix(logs + "/") })
    }
    private func isolate(_ f: Fixture) async throws -> (SweepEngine, RecoveryManifest, Candidate) {
        let engine = f.engine(), report = try await engine.scanJunk()
        let item = try XCTUnwrap(report.candidates.first { $0.rule == CacheRule.name && $0.allowed })
        let plan = try await engine.makePlan(reportID: report.id, selected: [item.id], includeUserData: false)
        let batch = try await engine.execute(planID: plan.id)
        guard batch.status == .isolated else { throw SweepError.incomplete(batch.issue ?? "Owned sample was not isolated") }
        for entry in batch.entries {
            for folder in ["objects.noindex", "backups.noindex"] {
                let path = batchRoot(f, batch) + "/" + folder + "/" + entry.id.uuidString
                for attempt in 0..<40 {
                    do { try BusyInspector.ensureUnused(SafeFilesystem.snapshot(path)); break }
                    catch {
                        if let diagnostic = try? BoundedProcess.capture("/usr/sbin/lsof", arguments: ["-F0pcn", "--", path], timeout: 3, mergeStderr: true) { print(diagnostic.text.replacingOccurrences(of: "\0", with: " ")) }
                        if attempt == 39 { throw error }
                        try await Task.sleep(nanoseconds: 250_000_000)
                    }
                }
            }
        }
        return (engine, batch, item)
    }
    private func batchRoot(_ f: Fixture, _ batch: RecoveryManifest) -> String {
        f.home + "/Library/Application Support/App Sweep/Recovery/" + batch.id.uuidString
    }
    func testBackupWrittenBeforeRegistrationIsVisibleAndRecoverableAfterRestart() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let engine = f.engine(failurePoint:.interruptAfterBackup), report = try await engine.scanJunk()
        let item = try XCTUnwrap(report.candidates.first { $0.rule == CacheRule.name && $0.allowed })
        let plan = try await engine.makePlan(reportID:report.id,selected:[item.id],includeUserData:false)
        do { _ = try await engine.execute(planID:plan.id); XCTFail("Expected interruption after backup write before identity registration") } catch { }
        XCTAssertTrue(FileManager.default.fileExists(atPath:item.path), "The original must not move before the backup is registered")
        let restarted=f.engine(), batches=try await restarted.recoveryBatches()
        let batch=try XCTUnwrap(batches.first)
        XCTAssertEqual(batch.status,.inProgress)
        XCTAssertTrue(batch.hasIndependentBackups)
        let restored=try await restarted.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:"\n"))
        XCTAssertGreaterThan(restored.independentBackupBytes,0)
        XCTAssertTrue(restored.canPurge)
        let cleared=try await restarted.purge(batchID:batch.id,confirmation:"永久清空 " + batch.id.uuidString)
        XCTAssertEqual(cleared.status,.purged)
        XCTAssertFalse(FileManager.default.fileExists(atPath:batchRoot(f,batch) + "/backups.noindex/" + item.id.uuidString))
        XCTAssertTrue(FileManager.default.fileExists(atPath:item.path))
    }
    func testReconstructionSyncFailureCanBeVerifiedAndRetried() async throws {
        let f=try Fixture(); defer { try? f.clean() }
        let (_,batch,item)=try await isolate(f)
        try FileManager.default.removeItem(atPath:batchRoot(f,batch) + "/objects.noindex/" + item.id.uuidString)
        let failing=f.engine(failurePoint:.afterReconstruction)
        let first=try await failing.restore(batchID:batch.id)
        XCTAssertEqual(first.status,.needsAttention)
        let restarted=f.engine(), restored=try await restarted.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:"\n"))
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:item.path)),Data(repeating:0x41,count:524288))
    }
    func testPendingArchiveStillRequiresThePreviouslyJournaledDigest() async throws {
        let f=try Fixture(); defer { try? f.clean() }
        let engine=f.engine(failurePoint:.interruptAfterBackup), report=try await engine.scanJunk()
        let item=try XCTUnwrap(report.candidates.first { $0.rule == CacheRule.name && $0.allowed })
        let plan=try await engine.makePlan(reportID:report.id,selected:[item.id],includeUserData:false)
        do { _ = try await engine.execute(planID:plan.id); XCTFail("Expected interruption") } catch { }
        let batches=try await engine.recoveryBatches(), batch=try XCTUnwrap(batches.first)
        let archive=batchRoot(f,batch) + "/backups.noindex/" + item.id.uuidString
        var data=try Data(contentsOf:URL(fileURLWithPath:archive))
        let payload=try XCTUnwrap(data.range(of:Data(repeating:0x41,count:64))); data[payload.lowerBound+32] ^= 1
        try data.write(to:URL(fileURLWithPath:archive))
        let result=try await f.engine().restore(batchID:batch.id)
        XCTAssertEqual(result.status,.needsAttention)
        XCTAssertTrue(result.hasUnconfirmedBackups)
        XCTAssertFalse(result.canPurge)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:item.path)),Data(repeating:0x41,count:524288))
    }
    func testUnregisteredPartialArchiveRemainsVisibleAsUnconfirmed() async throws {
        let f=try Fixture(); defer { try? f.clean() }
        let engine=f.engine(failurePoint:.interruptAfterBackup), report=try await engine.scanJunk()
        let item=try XCTUnwrap(report.candidates.first { $0.rule == CacheRule.name && $0.allowed })
        let plan=try await engine.makePlan(reportID:report.id,selected:[item.id],includeUserData:false)
        do { _ = try await engine.execute(planID:plan.id); XCTFail("Expected interruption") } catch { }
        let batches=try await engine.recoveryBatches(), batch=try XCTUnwrap(batches.first)
        let partial=batchRoot(f,batch) + "/backups.noindex/.rebuild-partial"
        try Data("owned partial write".utf8).write(to:URL(fileURLWithPath:partial))
        let result=try await f.engine().restore(batchID:batch.id)
        XCTAssertEqual(result.status,.needsAttention)
        XCTAssertTrue(result.hasUnconfirmedBackups)
        XCTAssertFalse(result.canPurge)
        XCTAssertTrue(result.entries.compactMap(\.message).joined().contains("未登记"))
        XCTAssertTrue(FileManager.default.fileExists(atPath:partial))
        XCTAssertTrue(FileManager.default.fileExists(atPath:item.path))
    }
    func testBackupCapacityIsReservedBeforeAnySourceMoves() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let engine = f.engine(failurePoint: .insufficientBackupSpace)
        let report = try await engine.scanJunk()
        let item = try XCTUnwrap(report.candidates.first { $0.rule == CacheRule.name && $0.allowed })
        let bytes = try Data(contentsOf: URL(fileURLWithPath: item.path))
        let plan = try await engine.makePlan(reportID: report.id, selected: [item.id], includeUserData: false)
        do { _ = try await engine.execute(planID: plan.id); XCTFail("Independent backup storage must be reserved in addition to journal headroom") }
        catch { XCTAssertTrue(error.localizedDescription.contains("空间")) }
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: item.path)), bytes)
        let batches = try await engine.recoveryBatches()
        XCTAssertTrue(batches.isEmpty)
    }
    func testInterruptedBackedMoveCanRecoverInNewEngineAfterPrimaryDisappears() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let engine = f.engine(failurePoint: .interruptAfterMove)
        let report = try await engine.scanJunk()
        let item = try XCTUnwrap(report.candidates.first { $0.rule == CacheRule.name && $0.allowed })
        let original = try Data(contentsOf: URL(fileURLWithPath: item.path))
        let plan = try await engine.makePlan(reportID: report.id, selected: [item.id], includeUserData: false)
        do { _ = try await engine.execute(planID: plan.id); XCTFail("Expected injected interruption") }
        catch { XCTAssertTrue(error.localizedDescription.contains("中断")) }
        let restarted = f.engine()
        let batches = try await restarted.recoveryBatches()
        let batch = try XCTUnwrap(batches.first)
        XCTAssertEqual(batch.status, .inProgress)
        try FileManager.default.removeItem(atPath: batchRoot(f, batch) + "/objects.noindex/" + item.id.uuidString)
        let restored = try await restarted.restore(batchID: batch.id)
        XCTAssertEqual(restored.status, .restored, restored.entries.compactMap(\.message).joined(separator: "\n"))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: item.path)), original)
    }
    func testInterruptedBackedPurgePreservesRecoveryForNewEngine() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let (_, batch, item) = try await isolate(f)
        let engine = f.engine(failurePoint: .interruptDuringPurge)
        do { _ = try await engine.purge(batchID: batch.id, confirmation: "永久清空 " + batch.id.uuidString); XCTFail("Expected injected interruption") }
        catch { XCTAssertTrue(error.localizedDescription.contains("中断")) }
        let restarted = f.engine()
        let batches = try await restarted.recoveryBatches()
        XCTAssertEqual(batches.first?.status, .purging)
        let restored = try await restarted.restore(batchID: batch.id)
        XCTAssertEqual(restored.status, .restored, restored.entries.compactMap(\.message).joined(separator: "\n"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: item.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: batchRoot(f, batch) + "/backups.noindex/" + item.id.uuidString))
    }
    func testForgedBackupIdentityCannotBypassItsContentDigest() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let (engine, batch, item) = try await isolate(f)
        let root = batchRoot(f, batch), archive = root + "/backups.noindex/" + item.id.uuidString
        var bytes = try Data(contentsOf: URL(fileURLWithPath: archive))
        let payload = try XCTUnwrap(bytes.range(of: Data(repeating: 0x41, count: 64)))
        bytes[payload.lowerBound+32] ^= 1 // Keep the archive structurally valid.
        try bytes.write(to: URL(fileURLWithPath: archive))
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        var forged = try decoder.decode(RecoveryManifest.self, from: Data(contentsOf: URL(fileURLWithPath: root + "/manifest.json")))
        forged.entries[0].backupIdentity = try SafeFilesystem.snapshot(archive).identity
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        try SafeDirectory(path: root).write(encoder.encode(forged), name: "manifest.json")
        try FileManager.default.removeItem(atPath: root + "/objects.noindex/" + item.id.uuidString)
        let result = try await engine.restore(batchID: batch.id)
        XCTAssertEqual(result.status, .needsAttention)
        XCTAssertFalse(FileManager.default.fileExists(atPath: item.path))
    }
    func testRegeneratedResponseIsNotOverwrittenWhenMovedObjectWasReclaimed() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let (engine, batch, item) = try await isolate(f)
        let replacement = Data("new response must remain".utf8)
        try replacement.write(to: URL(fileURLWithPath: item.path))
        try FileManager.default.removeItem(atPath: batchRoot(f,batch) + "/objects.noindex/" + item.id.uuidString)
        let result = try await engine.restore(batchID: batch.id)
        XCTAssertEqual(result.status, .needsAttention)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: item.path)), replacement)
        XCTAssertTrue(FileManager.default.fileExists(atPath: batchRoot(f,batch) + "/backups.noindex/" + item.id.uuidString))
    }
    func testExplicitPurgeRemovesBothResponseAndIndependentArchive() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let (engine,batch,item) = try await isolate(f)
        let result: RecoveryManifest
        do { result = try await engine.purge(batchID:batch.id,confirmation:"永久清空 " + batch.id.uuidString) }
        catch {
            print("Owned cache purge diagnostics: \(error)")
            for folder in ["objects.noindex", "backups.noindex"] {
                let path = batchRoot(f, batch) + "/" + folder + "/" + item.id.uuidString
                if let diagnostic = try? BoundedProcess.capture("/usr/sbin/lsof", arguments:["-F0pcn","--",path], timeout:3,mergeStderr:true) { print(diagnostic.text.replacingOccurrences(of:"\0",with:" ")) }
            }
            print("Journal after refusal: \(try await engine.recoveryBatches())")
            throw error
        }
        XCTAssertEqual(result.status,.purged)
        XCTAssertFalse(FileManager.default.fileExists(atPath:batchRoot(f,batch) + "/objects.noindex/" + item.id.uuidString))
        XCTAssertFalse(FileManager.default.fileExists(atPath:batchRoot(f,batch) + "/backups.noindex/" + item.id.uuidString))
    }
    func testRestoredArchiveCanBeExplicitlyClearedWithoutTouchingRestoredResponse() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let (engine,batch,item) = try await isolate(f)
        let restored = try await engine.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored)
        let original = try Data(contentsOf:URL(fileURLWithPath:item.path))
        let result = try await engine.purge(batchID:batch.id,confirmation:"永久清空 " + batch.id.uuidString)
        XCTAssertEqual(result.status,.purged)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:item.path)),original)
        XCTAssertFalse(FileManager.default.fileExists(atPath:batchRoot(f,batch) + "/backups.noindex/" + item.id.uuidString))
    }
    func testVerifiedArchiveCanBeExplicitlyPurgedAfterPrimaryWasReclaimed() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let (engine,batch,item) = try await isolate(f)
        try FileManager.default.removeItem(atPath:batchRoot(f,batch) + "/objects.noindex/" + item.id.uuidString)
        let result = try await engine.purge(batchID:batch.id,confirmation:"永久清空 " + batch.id.uuidString)
        XCTAssertEqual(result.status,.purged)
        XCTAssertFalse(FileManager.default.fileExists(atPath:batchRoot(f,batch) + "/backups.noindex/" + item.id.uuidString))
        XCTAssertFalse(FileManager.default.fileExists(atPath:item.path))
    }
    func testDeletedIsolatedResponseCanRestoreFromIndependentBackup() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let source = f.path + "/" + (try XCTUnwrap(FileManager.default.contentsOfDirectory(atPath: f.path).first))
        _ = try BoundedProcess.run("/usr/bin/xattr", arguments: ["-w", "org.appsweep.acceptance", "preserve-response-metadata", source], timeout: 3)
        let original = try Data(contentsOf: URL(fileURLWithPath: source))
        let attributes = try FileManager.default.attributesOfItem(atPath: source)
        let engine = f.engine(); let report = try await engine.scanJunk()
        let item = try XCTUnwrap(report.candidates.first { $0.rule == CacheRule.name && $0.allowed })
        let plan = try await engine.makePlan(reportID: report.id, selected: [item.id], includeUserData: false)
        let moved = try await engine.execute(planID: plan.id)
        guard moved.status == .isolated else { XCTFail(moved.issue ?? "Isolation failed"); return }
        let object = f.home + "/Library/Application Support/App Sweep/Recovery/" + moved.id.uuidString + "/objects.noindex/" + item.id.uuidString
        // Simulate the independently observed native consumer reclaiming its
        // moved cache inode. Only this test's exact disposable object is removed.
        try FileManager.default.removeItem(atPath: object)
        let restored = try await engine.restore(batchID: moved.id)
        XCTAssertEqual(restored.status, .restored, restored.entries.compactMap(\.message).joined(separator: "\n"))
        guard FileManager.default.fileExists(atPath: source) else { XCTFail("Original response was not reconstructed"); return }
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: source)), original)
        let after = try FileManager.default.attributesOfItem(atPath: source)
        for key: FileAttributeKey in [.posixPermissions, .groupOwnerAccountID, .modificationDate] {
            XCTAssertEqual(String(describing: after[key]), String(describing: attributes[key]))
        }
        XCTAssertEqual(try BoundedProcess.run("/usr/bin/xattr", arguments: ["-p", "org.appsweep.acceptance", source], timeout: 3).trimmingCharacters(in: .whitespacesAndNewlines), "preserve-response-metadata")
    }
    func testIsolationRetainsPayloadDirectoryIdentity() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let directory = try SafeFilesystem.snapshot(f.path)
        let database = try Data(contentsOf: URL(fileURLWithPath: f.root + "/Cache.db"))
        let engine = f.engine()
        let report = try await engine.scanJunk()
        let item = try XCTUnwrap(report.candidates.first { $0.rule == CacheRule.name && $0.allowed })
        XCTAssertFalse(item.identity?.isDirectory ?? true, "Response files, not their live cache directory, must move")
        let plan = try await engine.makePlan(reportID: report.id, selected: [item.id], includeUserData: false)
        let moved = try await engine.execute(planID: plan.id)
        XCTAssertEqual(moved.status, .isolated, moved.issue ?? "")
        guard try SafeFilesystem.presence(f.path) else { XCTFail("Cache directory identity was removed"); return }
        XCTAssertEqual(try SafeFilesystem.snapshot(f.path).identity.inode, directory.identity.inode)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.root + "/Cache.db")), database)
        let restored = try await engine.restore(batchID: moved.id)
        XCTAssertEqual(restored.status, .restored)
        assertSamePayloads(try SafeFilesystem.snapshot(f.path).tree, directory.tree)
    }
    private func assertSamePayloads(_ actual: [TreeEntry], _ expected: [TreeEntry], file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(actual.map(\.relative), expected.map(\.relative), file: file, line: line)
        for (a, b) in zip(actual, expected) {
            // A file rename changes kernel-managed ctime; identity, permissions,
            // size and mtime must remain identical.
            XCTAssertTrue(a.identity.sameObject(as: b.identity), file: file, line: line)
        }
    }
    private func sessionMetadata(_ fixture: Fixture, method: String = "GET", body: Any? = nil, count: Int = 22) throws {
        var db: OpaquePointer?
        guard sqlite3_open((fixture.root + "/Cache.db"), &db) == SQLITE_OK, let db else { throw SweepError.invalid("Owned fixture unavailable") }
        defer { sqlite3_close(db) }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT request_object FROM cfurl_cache_blob_data LIMIT 1", -1, &statement, nil) == SQLITE_OK, let statement else { throw SweepError.invalid("Owned request unavailable") }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW, let bytes = sqlite3_column_blob(statement, 0) else { throw SweepError.invalid("Owned request empty") }
        let data = Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 0)))
        guard sqlite3_reset(statement) == SQLITE_OK else { throw SweepError.invalid("Owned request read could not finish") }
        var request = try XCTUnwrap(try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
        let original = try XCTUnwrap(request["Array"] as? [Any])
        let null = "__CFURLRequestNullTokenString__"
        var array = Array(original.prefix(16))
        array.append(contentsOf: [null, 2, method, ["Accept": "text/plain"], body ?? null, null] as [Any])
        request["Array"] = Array(array.prefix(count))
        let encoded = try PropertyListSerialization.data(fromPropertyList: request, format: .binary, options: 0)
        let hex = encoded.map { String(format: "%02x", $0) }.joined()
        try fixture.sql("UPDATE cfurl_cache_blob_data SET request_object=X'" + hex + "'")
    }
    func testSessionGETMetadataWithoutBodyCanBeConfirmed() throws {
        let fixture = try Fixture()
        defer { try? FileManager.default.removeItem(atPath: fixture.home) }
        try CacheRule.verify(path: fixture.path, home: fixture.home, identifier: fixture.identifier)
        try sessionMetadata(fixture)
        XCTAssertNoThrow(try CacheRule.verify(path: fixture.path, home: fixture.home, identifier: fixture.identifier))
    }
    func testSessionUnknownMethodBodyOrShapeIsRetained() throws {
        let fixture = try Fixture()
        defer { try? FileManager.default.removeItem(atPath: fixture.home) }
        try sessionMetadata(fixture, method: "POST")
        XCTAssertThrowsError(try CacheRule.verify(path: fixture.path, home: fixture.home, identifier: fixture.identifier))
        try sessionMetadata(fixture, body: Data("persistent request body".utf8))
        XCTAssertThrowsError(try CacheRule.verify(path: fixture.path, home: fixture.home, identifier: fixture.identifier))
        try sessionMetadata(fixture, body: ["stream": "unknown"])
        XCTAssertThrowsError(try CacheRule.verify(path: fixture.path, home: fixture.home, identifier: fixture.identifier))
        try sessionMetadata(fixture, count: 21)
        XCTAssertThrowsError(try CacheRule.verify(path: fixture.path, home: fixture.home, identifier: fixture.identifier))
    }
    struct Fixture {
        let home: String, app: String, executable: String, root: String, path: String, identifier: String
        init(identifier: String = "org.example.network." + UUID().uuidString.lowercased(), checkpoint: Bool = true) throws {
            guard let base = ProcessInfo.processInfo.environment["APP_SWEEP_FIXTURES"], base.hasPrefix(NSHomeDirectory() + "/AppSweepAcceptance") else { throw XCTSkip("Requires explicitly owned native fixtures") }
            self.identifier = identifier
            home = base + "/" + UUID().uuidString
            app = home + "/Applications/Network Fixture.app"
            executable = app + "/Contents/MacOS/consumer"
            root = home + "/Library/Caches/" + identifier
            path = root + "/fsCachedData"
            try FileManager.default.createDirectory(atPath: app + "/Contents/MacOS", withIntermediateDirectories: true)
            try FileManager.default.createDirectory(atPath: home + "/Library/Application Support", withIntermediateDirectories: true)
            let info = ["CFBundleIdentifier":identifier, "CFBundleName":"Network Fixture", "CFBundleExecutable":"consumer", "CFBundlePackageType":"APPL", "CFBundleVersion":"1"]
            try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: URL(fileURLWithPath: app + "/Contents/Info.plist"))
            let source = try NativeAcceptanceTests.NativeFixture.resource("NetworkCacheConsumer", extension: "m")
            let clang = ProcessInfo.processInfo.environment["APP_SWEEP_CLANG"] ?? "/usr/bin/clang"
            let sdk = try XCTUnwrap(ProcessInfo.processInfo.environment["APP_SWEEP_SDK"])
            let output = try BoundedProcess.capture(clang, arguments: ["-fobjc-arc", "-isysroot", sdk, "-framework", "Foundation", source.path, "-o", executable], timeout: 30, mergeStderr: true)
            guard output.status == 0 else { throw SweepError.incomplete(output.text) }
            _ = try BoundedProcess.run("/usr/bin/codesign", arguments: ["--force", "--sign", "-", app], timeout: 10)
            try generate(checkpoint: checkpoint)
        }
        func generate(checkpoint: Bool = true) throws {
            let output = try BoundedProcess.run(executable, arguments: ["--generate", root], timeout: 10)
            guard output.trimmingCharacters(in: .whitespacesAndNewlines) == "524288" else { throw SweepError.incomplete("Native cache generation did not persist the response") }
            // Only the test driver checkpoints its own generated fixture. The
            // production rule must never open a source database for writing.
            if checkpoint { try sql("PRAGMA wal_checkpoint(TRUNCATE)") }
        }
        func sql(_ text: String) throws {
            var db: OpaquePointer?
            guard sqlite3_open((root + "/Cache.db"), &db) == SQLITE_OK, let db else { throw SweepError.invalid("Owned fixture database unavailable") }
            defer { sqlite3_close(db) }
            guard sqlite3_exec(db, text, nil, nil, nil) == SQLITE_OK else { throw SweepError.invalid("Owned fixture SQL failed") }
        }
        func stageCommittedWAL(_ statement: String) throws {
            var database: Data!, wal: Data!
            var db: OpaquePointer?
            guard sqlite3_open(root + "/Cache.db", &db) == SQLITE_OK, let db else { throw SweepError.invalid("Owned fixture database unavailable") }
            do {
                defer { sqlite3_close(db) }
                guard sqlite3_exec(db, "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; " + statement, nil, nil, nil) == SQLITE_OK else { throw SweepError.invalid("Owned WAL generation failed") }
                database = try Data(contentsOf: URL(fileURLWithPath: root + "/Cache.db"))
                wal = try Data(contentsOf: URL(fileURLWithPath: root + "/Cache.db-wal"))
                guard wal.count > 32 else { throw SweepError.invalid("Owned SQLite transaction did not generate WAL frames") }
            }
            // Preserve genuine committed bytes before close checkpoints them,
            // then stage only these disposable files as an offline read fixture.
            try database.write(to: URL(fileURLWithPath: root + "/Cache.db"))
            try wal.write(to: URL(fileURLWithPath: root + "/Cache.db-wal"))
        }
        func engine(failurePoint: FailurePoint? = nil) -> SweepEngine {
            SweepEngine(policy: SafetyPolicy(home: home, acceptedPlatform: true, validatedRules: [CacheRule.name]), vaultPath: home + "/Library/Application Support/App Sweep/Recovery", failurePoint: failurePoint, fixture: false)
        }
        func clean() throws { try FileManager.default.removeItem(atPath: home) }
    }
    func testNativeCacheFormatWorksForUnlistedRandomIdentifiers() throws {
        for _ in 0..<2 {
            let f = try Fixture(); defer { try? f.clean() }
            XCTAssertNoThrow(try CacheRule.verify(path: f.path, home: f.home, identifier: f.identifier))
            XCTAssertThrowsError(try CacheRule.verify(path: f.path, home: f.home, identifier: f.identifier + ".other"))
        }
    }
    func testUnknownFileInsidePayloadDirectoryIsRetained() throws {
        let f = try Fixture(); defer { try? f.clean() }
        try Data("personal draft".utf8).write(to: URL(fileURLWithPath: f.path + "/notes.txt"))
        XCTAssertThrowsError(try CacheRule.verify(path: f.path, home: f.home, identifier: f.identifier))
    }
    func testCommittedNativeWALIsReadWithoutChangingSourceFiles() throws {
        let f = try Fixture(checkpoint: false); defer { try? f.clean() }
        try f.stageCommittedWAL("UPDATE cfurl_cache_response SET time_stamp = 'fixture-new-transaction'")
        let database = try Data(contentsOf: URL(fileURLWithPath: f.root + "/Cache.db"))
        let wal = try Data(contentsOf: URL(fileURLWithPath: f.root + "/Cache.db-wal"))
        XCTAssertGreaterThan(wal.count, 32)
        XCTAssertNoThrow(try CacheRule.verify(path: f.path, home: f.home, identifier: f.identifier))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.root + "/Cache.db")), database)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.root + "/Cache.db-wal")), wal)
        var corrupt = wal; corrupt[31] ^= 1
        try corrupt.write(to: URL(fileURLWithPath: f.root + "/Cache.db-wal"))
        XCTAssertThrowsError(try CacheRule.verify(path: f.path, home: f.home, identifier: f.identifier))
    }
    func testUserInfoCommittedOnlyInWALIsRetained() throws {
        let f = try Fixture(); defer { try? f.clean() }
        try f.stageCommittedWAL("UPDATE cfurl_cache_blob_data SET user_info = X'01'")
        XCTAssertThrowsError(try CacheRule.verify(path: f.path, home: f.home, identifier: f.identifier))
    }
    func testOccupiedMetadataCannotAuthorizePayloadMove() throws {
        let f = try Fixture(); defer { try? f.clean() }
        let handle = try FileHandle(forReadingFrom: URL(fileURLWithPath: f.root + "/Cache.db")); defer { try? handle.close() }
        XCTAssertThrowsError(try CacheRule.verify(path: f.path, home: f.home, identifier: f.identifier))
    }
    func testHardLinkedPayloadOrMetadataCannotAuthorizeMove() throws {
        let f = try Fixture(); defer { try? f.clean() }
        let payload = try XCTUnwrap(FileManager.default.contentsOfDirectory(atPath: f.path).first)
        let outside = f.home + "/shared-payload"
        try FileManager.default.linkItem(atPath: f.path + "/" + payload, toPath: outside)
        XCTAssertThrowsError(try CacheRule.verify(path: f.path, home: f.home, identifier: f.identifier))
        try FileManager.default.removeItem(atPath: outside)
        try FileManager.default.linkItem(atPath: f.root + "/Cache.db", toPath: f.home + "/shared-metadata")
        XCTAssertThrowsError(try CacheRule.verify(path: f.path, home: f.home, identifier: f.identifier))
    }
    func testRunningConsumerRetainsCacheAndIsNeverTerminated() async throws {
        let f = try Fixture(), process = Process()
        defer { if !process.isRunning { try? f.clean() } }
        let original = try SafeFilesystem.snapshot(f.path)
        let engine = f.engine()
        let report = try await engine.scanJunk()
        let item = try XCTUnwrap(report.candidates.first { $0.rule == CacheRule.name && $0.allowed })
        let plan = try await engine.makePlan(reportID: report.id, selected: [item.id], includeUserData: false)
        process.executableURL = URL(fileURLWithPath: f.executable); process.arguments = ["--wait", f.root]
        process.standardOutput = FileHandle.nullDevice
        let stopped = expectation(description: "Owned cache consumer exited")
        process.terminationHandler = { _ in stopped.fulfill() }
        try process.run()
        var bodyError: Error?
        do {
            for _ in 0..<100 where !FileManager.default.fileExists(atPath:f.root + "/wait-ready") { try await Task.sleep(nanoseconds:50_000_000) }
            guard FileManager.default.fileExists(atPath:f.root + "/wait-ready"), process.isRunning else { throw SweepError.incomplete("Disposable consumer failed to reach its running barrier") }
            do { _ = try await engine.execute(planID: plan.id); XCTFail("Running cache consumer must prevent the move") } catch { }
            XCTAssertTrue(process.isRunning)
            XCTAssertEqual(try SafeFilesystem.snapshot(f.path).tree, original.tree)
            let runningReport = try await engine.scanJunk()
            XCTAssertFalse(runningReport.candidates.contains { $0.rule == CacheRule.name && $0.allowed })
            XCTAssertTrue(process.isRunning)
        } catch { bodyError = error }
        try Data().write(to:URL(fileURLWithPath:f.root + "/release-wait"))
        await fulfillment(of:[stopped],timeout:10)
        guard !process.isRunning else { throw SweepError.incomplete("Owned cache consumer did not exit; retained at " + f.home) }
        XCTAssertEqual(process.terminationStatus,0)
        if let bodyError { throw bodyError }
    }
    func testChangedResponseMetadataAfterPlanningStopsBeforeMove() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let original = try SafeFilesystem.snapshot(f.path)
        let engine = f.engine()
        let report = try await engine.scanJunk()
        let item = try XCTUnwrap(report.candidates.first { $0.rule == CacheRule.name && $0.allowed })
        let plan = try await engine.makePlan(reportID: report.id, selected: [item.id], includeUserData: false)
        try f.sql("UPDATE cfurl_cache_blob_data SET user_info = X'01'; PRAGMA wal_checkpoint(TRUNCATE)")
        do { _ = try await engine.execute(planID: plan.id); XCTFail("Changed cache evidence must prevent the move") } catch { }
        XCTAssertEqual(try SafeFilesystem.snapshot(f.path).tree, original.tree)
    }
    func testUninstallMovesVerifiedCacheAfterAppAndRestoresBothWithoutUserData() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let notes = f.home + "/Library/Application Support/notes.txt"
        try Data("keep this personal fixture".utf8).write(to: URL(fileURLWithPath: notes))
        let engine = SweepEngine(policy: SafetyPolicy(home: f.home, acceptedPlatform: true, validatedRules: [CacheRule.name, "signed-application-v1"]), vaultPath: f.home + "/Library/Application Support/App Sweep/Recovery", fixture: false)
        let report = try await engine.scanApplication(f.app)
        XCTAssertTrue(report.complete, report.issues.joined(separator: "\n"))
        let selected = report.selectableCandidates(includeUserData: false).filter(\.selectedByDefault)
        XCTAssertEqual(Set(selected.map(\.path)), Set([f.app] + (try SafeFilesystem.snapshot(f.path)).tree.map { f.path + "/" + $0.relative }))
        let plan = try await engine.makePlan(reportID: report.id, selected: Set(selected.map(\.id)), includeUserData: false)
        XCTAssertEqual(plan.items.first?.path, f.app)
        let moved = try await engine.execute(planID: plan.id)
        XCTAssertEqual(moved.status, .isolated, moved.issue ?? "")
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.app))
        XCTAssertTrue(FileManager.default.fileExists(atPath: f.path))
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: f.path).isEmpty)
        XCTAssertEqual(try String(contentsOfFile: notes, encoding: .utf8), "keep this personal fixture")
        let restored = try await engine.restore(batchID: moved.id)
        XCTAssertEqual(restored.status, .restored, restored.entries.compactMap(\.message).joined(separator: "\n"))
        XCTAssertEqual(try BoundedProcess.run(f.executable, arguments: ["--read", f.root], timeout: 10).trimmingCharacters(in: .whitespacesAndNewlines), "524288")
        XCTAssertEqual(try String(contentsOfFile: notes, encoding: .utf8), "keep this personal fixture")
    }
    func testUnknownSchemaOrUserInfoCannotAuthorizePayloads() throws {
        let f = try Fixture(); defer { try? f.clean() }
        try f.sql("UPDATE cfurl_cache_blob_data SET user_info = X'01'; PRAGMA wal_checkpoint(TRUNCATE)")
        XCTAssertThrowsError(try CacheRule.verify(path: f.path, home: f.home, identifier: f.identifier))
        try f.sql("UPDATE cfurl_cache_blob_data SET user_info = NULL; CREATE TABLE personal_notes(body TEXT); PRAGMA wal_checkpoint(TRUNCATE)")
        XCTAssertThrowsError(try CacheRule.verify(path: f.path, home: f.home, identifier: f.identifier))
    }
    func testUnknownPayloadReferenceAndLinksAreRejected() throws {
        let f = try Fixture(); defer { try? f.clean() }
        try f.sql("UPDATE cfurl_cache_receiver_data SET receiver_data = X'2E2E2F736563726574'; PRAGMA wal_checkpoint(TRUNCATE)")
        XCTAssertThrowsError(try CacheRule.verify(path: f.path, home: f.home, identifier: f.identifier))
        try FileManager.default.createSymbolicLink(atPath: f.path + "/link", withDestinationPath: "/private/var/folders")
        XCTAssertThrowsError(try CacheRule.verify(path: f.path, home: f.home, identifier: f.identifier))
    }
    func testSharedInstallationCannotAuthorizeCache() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let copy = f.home + "/Applications/Archive"
        try FileManager.default.createDirectory(atPath: copy, withIntermediateDirectories: true)
        try FileManager.default.copyItem(atPath: f.app, toPath: copy + "/Copy.app")
        let report = try await f.engine().scanJunk()
        XCTAssertFalse(report.candidates.contains { $0.rule == CacheRule.name && $0.allowed })
    }
    func testPayloadIsolationRestoreAndRegenerationLeaveDatabaseAndUserData() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let sentinel = f.home + "/Library/Application Support/notes.txt"
        try Data("keep user data".utf8).write(to: URL(fileURLWithPath: sentinel))
        let original = try SafeFilesystem.snapshot(f.path)
        let database = try Data(contentsOf: URL(fileURLWithPath: f.root + "/Cache.db"))
        let engine = f.engine()
        let report = try await engine.scanJunk()
        let item = try XCTUnwrap(report.candidates.first { $0.rule == CacheRule.name && $0.allowed }, report.candidates.compactMap(\.retentionReason).joined(separator: "\n"))
        let plan = try await engine.makePlan(reportID: report.id, selected: [item.id], includeUserData: false)
        let moved = try await engine.execute(planID: plan.id)
        XCTAssertEqual(moved.status, .isolated, moved.issue ?? "")
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.root + "/Cache.db")), database)
        XCTAssertEqual(try String(contentsOfFile: sentinel, encoding: .utf8), "keep user data")
        let restored = try await engine.restore(batchID: moved.id)
        XCTAssertEqual(restored.status, .restored, restored.entries.compactMap(\.message).joined(separator: "\n"))
        assertSamePayloads(try SafeFilesystem.snapshot(f.path).tree, original.tree)
        XCTAssertEqual(try BoundedProcess.run(f.executable, arguments: ["--read", f.root], timeout: 10).trimmingCharacters(in: .whitespacesAndNewlines), "524288")
        try f.sql("PRAGMA wal_checkpoint(TRUNCATE)")
        let next = try await engine.scanJunk()
        let nextItem = try XCTUnwrap(next.candidates.first { $0.rule == CacheRule.name && $0.allowed })
        let nextPlan = try await engine.makePlan(reportID: next.id, selected: [nextItem.id], includeUserData: false)
        let second = try await engine.execute(planID: nextPlan.id)
        XCTAssertEqual(second.status, .isolated, second.issue ?? "")
        try f.generate()
        XCTAssertTrue(FileManager.default.fileExists(atPath: f.path))
        let conflict = try await engine.restore(batchID: second.id)
        XCTAssertEqual(conflict.status, .needsAttention)
        XCTAssertEqual(try String(contentsOfFile: sentinel, encoding: .utf8), "keep user data")
    }
}
#endif
