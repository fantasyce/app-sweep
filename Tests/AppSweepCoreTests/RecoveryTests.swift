import XCTest
@testable import AppSweepCore
#if os(macOS)
import Darwin
#else
import Glibc
#endif

final class RecoveryTests: XCTestCase, @unchecked Sendable {
    func testForgedMixedCaseAppleIdentityCannotAuthorizeRecoveryOrPurge() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let app = f.home + "/Applications/Case.app"
        try FileManager.default.createDirectory(atPath:app + "/Contents",withIntermediateDirectories:true)
        try Data("owned package fixture".utf8).write(to:URL(fileURLWithPath:app + "/Contents/data"))
        let snapshot = try SafeFilesystem.snapshot(app)
        let item = Candidate(id:UUID(),path:app,category:.application,bundleIdentifier:"org.example.fixture",evidence:[.init(kind:.validatedRule,detail:"owned package",verified:true)],rule:"signed-application-v1",identity:snapshot.identity,bytes:snapshot.bytes,retentionReason:nil)
        let engine=f.engine(), report=await engine.adoptFixture([item],snapshots:[item.id:snapshot],applicationPath:app)
        let plan=try await engine.makePlan(reportID:report.id,selected:[item.id],includeUserData:false)
        let batch=try await engine.execute(planID:plan.id)
        let root=f.vault + "/" + batch.id.uuidString
        var object=try XCTUnwrap(try JSONSerialization.jsonObject(with:Data(contentsOf:URL(fileURLWithPath:root + "/manifest.json"))) as? [String:Any])
        var entries=try XCTUnwrap(object["entries"] as? [[String:Any]])
        var original=try XCTUnwrap(entries[0]["original"] as? [String:Any])
        original["bundleIdentifier"]="Com.Apple.Fake"; entries[0]["original"]=original; object["entries"]=entries
        try SafeDirectory(path:root).write(JSONSerialization.data(withJSONObject:object),name:"manifest.json")
        let list=try await engine.recoveryBatches(),unconfirmed=try XCTUnwrap(list.first{$0.id == batch.id})
        XCTAssertEqual(unconfirmed.status,.needsAttention);XCTAssertTrue(unconfirmed.entries.isEmpty)
        do{_=try await engine.restore(batchID:batch.id);XCTFail("A forged case variant authorized recovery")}catch{}
        do{_=try await engine.purge(batchID:batch.id,confirmation:"永久清空 "+batch.id.uuidString);XCTFail("A forged case variant authorized purge")}catch{}
        XCTAssertTrue(FileManager.default.fileExists(atPath:root + "/objects.noindex/" + item.id.uuidString))
        XCTAssertFalse(FileManager.default.fileExists(atPath:app))
    }
    struct Fixture {
        let home: String
        let source: String
        let vault: String
        let candidate: Candidate
        let snapshot: FileSnapshot
        init() throws {
            let base = ProcessInfo.processInfo.environment["APP_SWEEP_FIXTURES"] ?? "/out/fixtures"
            home = base + "/" + UUID().uuidString
            source = home + "/Library/Caches/org.example.fixture"
            vault = home + "/vault"
            try FileManager.default.createDirectory(atPath: source, withIntermediateDirectories: true)
            try Data("regenerable".utf8).write(to: URL(fileURLWithPath: source + "/data"))
            snapshot = try SafeFilesystem.snapshot(source)
            candidate = Candidate(id: UUID(), path: source, category: .cache, bundleIdentifier: "org.example.fixture", evidence: [OwnershipEvidence(kind: .validatedRule, detail: "fixture rule", verified: true)], rule: "fixture-v1", identity: snapshot.identity, bytes: snapshot.bytes, retentionReason: nil)
        }
        func engine(failure: FailurePoint? = nil) -> SweepEngine {
            SweepEngine(policy: SafetyPolicy(home: home, acceptedPlatform: true), vaultPath: vault, failurePoint: failure)
        }
        func clean() throws { try FileManager.default.removeItem(atPath: home) }
    }
    func testNewBatchesAvoidIndexingAndLegacyLayoutsStillRestore() async throws {
        for version in [RecoveryManifest.currentSchemaVersion, 3, 1, 2] {
            let f = try Fixture(); defer { try? f.clean() }
            let engine = f.engine()
            let report = await engine.adoptFixture([f.candidate], snapshots: [f.candidate.id: f.snapshot])
            let plan = try await engine.makePlan(reportID: report.id, selected: [f.candidate.id], includeUserData: false)
            let moved = try await engine.execute(planID: plan.id)
            XCTAssertEqual(moved.schemaVersion, RecoveryManifest.currentSchemaVersion, "New recovery objects must not invite indexing of quarantined applications or private data")
            guard moved.schemaVersion == RecoveryManifest.currentSchemaVersion else { continue }
            let root = f.vault + "/" + moved.id.uuidString
            XCTAssertTrue(FileManager.default.fileExists(atPath: root + "/objects.noindex/" + f.candidate.id.uuidString))
            if version != RecoveryManifest.currentSchemaVersion {
                // Simulate a previously shipped layout only inside this owned fixture.
                if version < 3 {
                    try FileManager.default.moveItem(atPath: root + "/objects.noindex", toPath: root + "/objects")
                }
                var json = try XCTUnwrap(try JSONSerialization.jsonObject(with: SafeFilesystem.readMetadata(root + "/manifest.json")) as? [String: Any])
                json["schemaVersion"] = version
                try SafeDirectory(path: root).write(JSONSerialization.data(withJSONObject: json), name: "manifest.json")
            }
            let result = try await f.engine().restore(batchID: moved.id)
            XCTAssertEqual(result.status, .restored)
            XCTAssertEqual(try String(contentsOfFile: f.source + "/data", encoding: .utf8), "regenerable")
        }
    }
    func testSchemaDowngradeCannotFallbackToANewStorageDirectory() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let engine = f.engine(), report = await engine.adoptFixture([f.candidate], snapshots: [f.candidate.id: f.snapshot])
        let plan = try await engine.makePlan(reportID: report.id, selected: [f.candidate.id], includeUserData: false)
        let moved = try await engine.execute(planID: plan.id), root = f.vault + "/" + moved.id.uuidString
        var json = try XCTUnwrap(try JSONSerialization.jsonObject(with: SafeFilesystem.readMetadata(root + "/manifest.json")) as? [String: Any])
        json["schemaVersion"] = 2
        try SafeDirectory(path: root).write(JSONSerialization.data(withJSONObject: json), name: "manifest.json")
        do { _ = try await f.engine().restore(batchID: moved.id); XCTFail("A mismatched layout must remain for review") } catch { }
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.source))
        XCTAssertTrue(FileManager.default.fileExists(atPath: root + "/objects.noindex/" + f.candidate.id.uuidString + "/data"))
    }
    func testMoveIsRecoverableAndDoesNotClaimReleasedSpace() async throws {
        let f = try Fixture(); defer { try? f.clean() }; let engine = f.engine()
        let report = await engine.adoptFixture([f.candidate], snapshots: [f.candidate.id: f.snapshot])
        let plan = try await engine.makePlan(reportID: report.id, selected: [f.candidate.id], includeUserData: false)
        let result = try await engine.execute(planID: plan.id)
        XCTAssertEqual(result.status, .isolated); XCTAssertEqual(result.isolatedBytes, 11)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.source))
        let restored = try await engine.restore(batchID: result.id)
        XCTAssertEqual(restored.status, .restored)
        XCTAssertEqual(try String(contentsOfFile: f.source + "/data", encoding: .utf8), "regenerable")
    }
    func testFabricatedPlanIDCannotExecute() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        do { _ = try await f.engine().execute(planID: UUID()); XCTFail("Untrusted plan executed") } catch { }
        XCTAssertTrue(FileManager.default.fileExists(atPath: f.source))
    }
    func testPurgeChecksNestedUnicodePackageAndNeverFollowsItsLinks() async throws {
        let f = try Fixture(); defer { try? f.clean() }
        let app = f.home + "/Applications/Fixture.app"
        let nested = app + "/Contents/Resources/资料-Ω"
        try FileManager.default.createDirectory(atPath: nested + "/empty", withIntermediateDirectories: true)
        try Data("owned".utf8).write(to: URL(fileURLWithPath: nested + "/数据.txt"))
        try FileManager.default.createSymbolicLink(atPath: app + "/外部链接", withDestinationPath: f.source + "/data")
        let snapshot = try SafeFilesystem.snapshot(app, allowInternalLinks: true)
        let item = Candidate(id: UUID(), path: app, category: .application, bundleIdentifier: "org.example.fixture", evidence: [.init(kind: .validatedRule, detail: "Independent package fixture", verified: true)], rule: "signed-application-v1", identity: snapshot.identity, bytes: snapshot.bytes, retentionReason: nil)
        let engine = f.engine()
        let report = await engine.adoptFixture([item], snapshots: [item.id:snapshot], applicationPath: app)
        let plan = try await engine.makePlan(reportID: report.id, selected: [item.id], includeUserData: false)
        let moved = try await engine.execute(planID: plan.id)
        XCTAssertEqual(moved.status, .isolated, moved.issue ?? "")
        let purged = try await engine.purge(batchID: moved.id, confirmation: "永久清空 " + moved.id.uuidString)
        XCTAssertEqual(purged.status, .purged, purged.issue ?? "")
        XCTAssertEqual(try String(contentsOfFile: f.source + "/data", encoding: .utf8), "regenerable")
    }
    func testJournalFailureBeforeMoveLeavesSourceUntouched() async throws {
        let f = try Fixture(); defer { try? f.clean() }; let engine = f.engine(failure: .beforeJournal)
        let report = await engine.adoptFixture([f.candidate], snapshots: [f.candidate.id: f.snapshot])
        let plan = try await engine.makePlan(reportID: report.id, selected: [f.candidate.id], includeUserData: false)
        do { _ = try await engine.execute(planID: plan.id); XCTFail("Should fail") } catch { }
        XCTAssertTrue(FileManager.default.fileExists(atPath: f.source))
    }
    func testRestoreConflictDoesNotOverwriteAndCanBeRetried() async throws {
        let f = try Fixture(); defer { try? f.clean() }; let engine = f.engine()
        let report = await engine.adoptFixture([f.candidate], snapshots: [f.candidate.id: f.snapshot])
        let plan = try await engine.makePlan(reportID: report.id, selected: [f.candidate.id], includeUserData: false)
        let moved = try await engine.execute(planID: plan.id)
        try FileManager.default.createDirectory(atPath: f.source, withIntermediateDirectories: false)
        try Data("keep".utf8).write(to: URL(fileURLWithPath: f.source + "/new"))
        let result = try await engine.restore(batchID: moved.id)
        XCTAssertEqual(result.status, .needsAttention)
        XCTAssertEqual(try String(contentsOfFile: f.source + "/new", encoding: .utf8), "keep")
    }
    func testRestoreRejectsAReplacedOriginalAncestor() async throws {
        let f = try Fixture(); defer { try? f.clean() }; let engine = f.engine()
        let report = await engine.adoptFixture([f.candidate], snapshots: [f.candidate.id:f.snapshot])
        let plan = try await engine.makePlan(reportID: report.id, selected: [f.candidate.id], includeUserData: false)
        let moved = try await engine.execute(planID: plan.id)
        XCTAssertEqual(moved.status, .isolated)
        let parent = f.home + "/Library/Caches"
        try FileManager.default.moveItem(atPath: parent, toPath: parent + "-original")
        try FileManager.default.createDirectory(atPath: parent, withIntermediateDirectories: false)
        let result = try await engine.restore(batchID: moved.id)
        XCTAssertEqual(result.status, .needsAttention)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.source))
        XCTAssertTrue(FileManager.default.fileExists(atPath: f.vault + "/" + moved.id.uuidString + "/objects.noindex/" + f.candidate.id.uuidString + "/data"))
    }
    func testInterruptedMoveIsOfferedForRecoveryAndNeverContinued() async throws {
        let f = try Fixture(); defer { try? f.clean() }; let engine = f.engine(failure: .interruptAfterMove)
        let report = await engine.adoptFixture([f.candidate], snapshots: [f.candidate.id: f.snapshot])
        let plan = try await engine.makePlan(reportID: report.id, selected: [f.candidate.id], includeUserData: false)
        do { _ = try await engine.execute(planID: plan.id); XCTFail("Injected interruption") } catch { }
        let reopened = f.engine()
        let batches = try await reopened.recoveryBatches()
        XCTAssertEqual(batches.count, 1); XCTAssertEqual(batches[0].status, .inProgress)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.source))
        let restored = try await reopened.restore(batchID: batches[0].id)
        XCTAssertEqual(restored.status, .restored)
        XCTAssertTrue(FileManager.default.fileExists(atPath: f.source))
    }
    func testSecondMoveFailureRollsBackFirstAndLeavesLaterItemsUntouched() async throws {
        for _ in 0..<20 {
        let f = try Fixture(); defer { try? f.clean() }
        let secondPath = f.home + "/Library/Caches/org.example.second"
        try FileManager.default.createDirectory(atPath: secondPath, withIntermediateDirectories: false)
        try Data("second".utf8).write(to: URL(fileURLWithPath: secondPath + "/data"))
        let secondSnapshot = try SafeFilesystem.snapshot(secondPath)
        let second = Candidate(id: UUID(), path: secondPath, category: .cache, bundleIdentifier: "org.example.second", evidence: f.candidate.evidence, rule: "fixture-v1", identity: secondSnapshot.identity, bytes: secondSnapshot.bytes, retentionReason: nil)
        let engine = f.engine(failure: .beforeSecondMove)
        let report = await engine.adoptFixture([f.candidate, second], snapshots: [f.candidate.id:f.snapshot, second.id:secondSnapshot])
        let plan = try await engine.makePlan(reportID: report.id, selected: [f.candidate.id, second.id], includeUserData: false)
        let result = try await engine.execute(planID: plan.id)
        XCTAssertEqual(result.status, .rolledBack, ([result.issue ?? ""] + result.entries.compactMap(\.message)).joined(separator: "\n"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: f.source + "/data"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: secondPath + "/data"))
        }
    }
    func testForgedRecoveryManifestCannotMoveIntoProtectedPath() async throws {
        let f = try Fixture(); defer { try? f.clean() }; let engine = f.engine()
        let report = await engine.adoptFixture([f.candidate], snapshots: [f.candidate.id:f.snapshot])
        let plan = try await engine.makePlan(reportID: report.id, selected: [f.candidate.id], includeUserData: false)
        let moved = try await engine.execute(planID: plan.id)
        let path = f.vault + "/" + moved.id.uuidString + "/manifest.json"
        var json = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: path))) as! [String:Any]
        var entries = json["entries"] as! [[String:Any]]; var original = entries[0]["original"] as! [String:Any]
        original["path"] = "/private/var/folders/protected"; entries[0]["original"] = original; json["entries"] = entries
        try JSONSerialization.data(withJSONObject: json).write(to: URL(fileURLWithPath: path))
        do { _ = try await engine.restore(batchID: moved.id); XCTFail("Forged manifest accepted") } catch { }
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.source))
    }
    func testPurgeRequiresSeparateExactConfirmation() async throws {
        let f = try Fixture(); defer { try? f.clean() }; let engine = f.engine()
        let report = await engine.adoptFixture([f.candidate], snapshots: [f.candidate.id:f.snapshot])
        let plan = try await engine.makePlan(reportID: report.id, selected: [f.candidate.id], includeUserData: false)
        let moved = try await engine.execute(planID: plan.id)
        do { _ = try await engine.purge(batchID: moved.id, confirmation: "yes"); XCTFail("Unconfirmed purge") } catch { }
        let batches = try await engine.recoveryBatches()
        XCTAssertEqual(batches[0].status, .isolated)
        let purged = try await engine.purge(batchID: moved.id, confirmation: "永久清空 " + moved.id.uuidString)
        XCTAssertEqual(purged.status, .purged)
        XCTAssertEqual(purged.isolatedBytes, 0)
    }
    func testLowSpaceNeverMovesSource() async throws {
        let f = try Fixture(); defer { try? f.clean() }; let engine = f.engine(failure: .lowSpace)
        let report = await engine.adoptFixture([f.candidate], snapshots: [f.candidate.id:f.snapshot])
        let plan = try await engine.makePlan(reportID: report.id, selected: [f.candidate.id], includeUserData: false)
        do { _ = try await engine.execute(planID: plan.id); XCTFail("Low-space execution") } catch { }
        XCTAssertTrue(FileManager.default.fileExists(atPath: f.source))
    }

    func testPurgeInterruptionIsNeverReportedAsCompleted() async throws {
        let f = try Fixture(); defer { try? f.clean() }; let engine = f.engine(failure: .interruptDuringPurge)
        let report = await engine.adoptFixture([f.candidate], snapshots: [f.candidate.id:f.snapshot])
        let plan = try await engine.makePlan(reportID: report.id, selected: [f.candidate.id], includeUserData: false)
        let moved = try await engine.execute(planID: plan.id)
        do { _ = try await engine.purge(batchID: moved.id, confirmation: "永久清空 " + moved.id.uuidString); XCTFail("Expected interrupted purge") } catch { }
        let batches = try await f.engine().recoveryBatches()
        XCTAssertEqual(batches[0].status, .purging)
        XCTAssertTrue(batches[0].hasUnconfirmedObjects)
        let restored = try await f.engine().restore(batchID: moved.id)
        XCTAssertEqual(restored.status, .restored)
    }

    func testForgedUnregisteredRuleCannotAuthorizeRecovery() async throws {
        let f = try Fixture(); defer { try? f.clean() }; let engine = f.engine()
        let report = await engine.adoptFixture([f.candidate], snapshots: [f.candidate.id:f.snapshot])
        let plan = try await engine.makePlan(reportID: report.id, selected: [f.candidate.id], includeUserData: false)
        let moved = try await engine.execute(planID: plan.id)
        let path = f.vault + "/" + moved.id.uuidString + "/manifest.json"
        var json = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: path))) as! [String:Any]
        var entries = json["entries"] as! [[String:Any]]; var original = entries[0]["original"] as! [String:Any]
        original["rule"] = "support-discovery-only-v1"; entries[0]["original"] = original; json["entries"] = entries
        try JSONSerialization.data(withJSONObject: json).write(to: URL(fileURLWithPath: path))
        do { _ = try await engine.restore(batchID: moved.id); XCTFail("Unknown recovery rule accepted") } catch { }
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.source))
    }

    func testForgedApplicationRuleCannotRestoreInsideAnotherApplication() async throws {
        let f = try Fixture(); defer { try? f.clean() }; let engine = f.engine()
        let report = await engine.adoptFixture([f.candidate], snapshots: [f.candidate.id:f.snapshot])
        let plan = try await engine.makePlan(reportID: report.id, selected: [f.candidate.id], includeUserData: false)
        let moved = try await engine.execute(planID: plan.id)
        let parent = f.home + "/Applications/Other.app/Contents/Helpers"
        try FileManager.default.createDirectory(atPath: parent, withIntermediateDirectories: true)
        let target = parent + "/Forged.app"
        let path = f.vault + "/" + moved.id.uuidString + "/manifest.json"
        var json = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: path))) as! [String:Any]
        var entries = json["entries"] as! [[String:Any]]; var original = entries[0]["original"] as! [String:Any]
        original["path"] = target; original["category"] = "application"; original["rule"] = "signed-application-v1"
        entries[0]["original"] = original; json["entries"] = entries
        try JSONSerialization.data(withJSONObject: json).write(to: URL(fileURLWithPath: path))
        do { _ = try await engine.restore(batchID: moved.id); XCTFail("Nested application restore accepted") } catch { }
        XCTAssertFalse(FileManager.default.fileExists(atPath: target))
    }

    func testChangedIsolatedRootMetadataRequiresManualRecovery() async throws {
        let f = try Fixture(); defer { try? f.clean() }; let engine = f.engine()
        let report = await engine.adoptFixture([f.candidate], snapshots: [f.candidate.id:f.snapshot])
        let plan = try await engine.makePlan(reportID: report.id, selected: [f.candidate.id], includeUserData: false)
        let moved = try await engine.execute(planID: plan.id)
        let object = f.vault + "/" + moved.id.uuidString + "/objects.noindex/" + f.candidate.id.uuidString
        // chmod records a metadata change even when the permissions remain the same.
        XCTAssertEqual(chmod(object, mode_t(f.snapshot.identity.mode & 0o777)), 0)
        let result = try await engine.restore(batchID: moved.id)
        XCTAssertEqual(result.status, .needsAttention)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.source))
    }

}
