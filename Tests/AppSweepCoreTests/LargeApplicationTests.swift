#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

final class LargeApplicationTests: XCTestCase, @unchecked Sendable {
    private let count = 20_010
    private func fixture() throws -> NativeAcceptanceTests.NativeFixture {
        let f = try NativeAcceptanceTests.NativeFixture(additionalRules: [ChosenApplicationRule.name, ChosenApplicationRule.largeName])
        do {
            // A runnable unsigned bundle avoids timing-dependent signing of twenty
            // thousand resources. It exercises the same selected-body rule.
            _ = try BoundedProcess.run("/usr/bin/codesign", arguments: ["--remove-signature", f.app], timeout: 10)
            _ = try BoundedProcess.run("/usr/bin/codesign", arguments: ["--force", "--sign", "-", "--identifier", "org.example.large-executable", f.executable], timeout: 10)
            let resources = f.app + "/Contents/Resources/Many"
            try FileManager.default.createDirectory(atPath: resources, withIntermediateDirectories: true)
            for index in 0..<count { try Data().write(to: URL(fileURLWithPath: resources + "/" + String(index))) }
            return f
        } catch { try? f.clean(); throw error }
    }
    private func engine(_ f: NativeAcceptanceTests.NativeFixture) -> SweepEngine {
        SweepEngine(policy: SafetyPolicy(home: f.home, acceptedPlatform: true, validatedRules: [ChosenApplicationRule.name, ChosenApplicationRule.largeName]), vaultPath: f.home + "/Library/Application Support/App Sweep/Recovery", fixture: false)
    }
    private func isolate(_ f: NativeAcceptanceTests.NativeFixture, engine: SweepEngine) async throws -> RecoveryManifest {
        do { _ = try SafeFilesystem.snapshot(f.app); XCTFail("Ordinary-directory limits must not expand with application support") }
        catch SweepError.incomplete { }
        let report = try await engine.scanApplication(f.app)
        let body = try XCTUnwrap(report.candidates.first { $0.category == .application })
        XCTAssertTrue(body.allowed, body.retentionReason ?? "")
        let plan = try await engine.makePlan(reportID: report.id, selected: [body.id], includeUserData: false)
        let moved = try await engine.execute(planID: plan.id)
        guard moved.status == .isolated else { throw SweepError.incomplete(moved.issue ?? "Large body was not isolated") }
        XCTAssertLessThan(try JSONEncoder().encode(moved).count, 64 * 1024, "Recovery intent must stay bounded instead of embedding every application resource")
        return moved
    }
    func testPublicEngineHandlesAnOwnedLargeApplication() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_PUBLIC_LARGE_ACCEPTANCE"] == "1" else { throw XCTSkip("Explicit public-engine acceptance in a registered environment only") }
        let model = try BoundedProcess.run("/usr/sbin/sysctl", arguments: ["-n", "hw.model"], timeout: 3).trimmingCharacters(in: .whitespacesAndNewlines)
        let home = try SystemIdentity.home()
        guard (model.hasPrefix("VirtualMac") && home == "/Users/localtest") || (model == "MacBookPro14,3" && home == "/Users/acceptance") else { throw XCTSkip("Not a registered acceptance environment") }
        let f = try fixture(); defer { try? f.clean() }
        let before = try SafeFilesystem.snapshot(f.app, allowInternalLinks: true, purpose: .application)
        let engine = SweepEngine(), report = try await engine.scanApplication(f.app)
        let body = try XCTUnwrap(report.selectableCandidates(includeUserData: false).first { $0.path == f.app }, report.candidates.compactMap(\.retentionReason).joined(separator: "; "))
        XCTAssertEqual(body.rule, SelectedApplicationRule.name)
        let plan = try await engine.makePlan(reportID: report.id, selected: [body.id], includeUserData: false)
        let moved = try await engine.execute(planID: plan.id)
        guard moved.status == .isolated else { throw SweepError.incomplete(moved.issue ?? "Public large-body isolation failed") }
        let restored = try await SweepEngine().restore(batchID: moved.id)
        XCTAssertEqual(restored.status, .restored, restored.entries.compactMap(\.message).joined(separator: "; "))
        let after = try SafeFilesystem.snapshot(f.app, allowInternalLinks: true, purpose: .application)
        XCTAssertTrue(after.identity.sameObject(as: before.identity))
        XCTAssertEqual(after.tree, before.tree)
        print("Public default engine: owned large bundle isolated/restored with exact identities, no policy injection")
    }
    func testUnacceptedLargeRuleCannotIssuePlan() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let readonly = SweepEngine(policy: SafetyPolicy(home: f.home, acceptedPlatform: true, validatedRules: [ChosenApplicationRule.name]), vaultPath: f.home + "/Library/Application Support/App Sweep/Recovery", fixture: false)
        let report = try await readonly.scanApplication(f.app)
        let body = try XCTUnwrap(report.candidates.first { $0.category == .application })
        XCTAssertEqual(body.rule, ChosenApplicationRule.largeName)
        XCTAssertFalse(body.allowed)
        do { _ = try await readonly.makePlan(reportID: report.id, selected: [body.id], includeUserData: false); XCTFail("Unaccepted capacity cannot be enabled through the small-body rule") } catch { }
        XCTAssertTrue(FileManager.default.fileExists(atPath: f.app))
    }
    func testSelectedLargeBodyOutsideInstallFoldersRestoresThroughItsOwnRule() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let directory = f.home + "/Downloads"
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        let target = directory + "/Portable.app"
        try FileManager.default.moveItem(atPath: f.app, toPath: target)
        let policy = SafetyPolicy(home: f.home, acceptedPlatform: true, validatedRules: ["selected-application-v2", ChosenApplicationRule.largeName])
        let vault = f.home + "/Library/Application Support/App Sweep/Recovery"
        let selected = SweepEngine(policy: policy, vaultPath: vault, fixture: false)
        let report = try await selected.scanApplication(target)
        let body = try XCTUnwrap(report.selectableCandidates(includeUserData: false).first { $0.category == .application })
        XCTAssertEqual(body.rule, "selected-application-v2")
        let plan = try await selected.makePlan(reportID: report.id, selected: [body.id], includeUserData: false)
        let moved = try await selected.execute(planID: plan.id)
        XCTAssertEqual(moved.status, .isolated, moved.issue ?? "")
        let fresh = SweepEngine(policy: policy, vaultPath: vault, fixture: false)
        let restored = try await fresh.restore(batchID: moved.id)
        XCTAssertEqual(restored.status, .restored, restored.entries.compactMap(\.message).joined(separator: "; "))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: target + "/Contents/Resources/Many").count, count)
    }
    func testLargeBodyRestoresInFreshEngineAndCanBePurged() async throws {
        let f = try fixture(); defer { try? f.clean() }
        // The unsigned large-tree fixture is still useful for structural
        // rejection cases. A launch/restore test needs a runnable control:
        // seal the independently built complete bundle before either launch.
        _ = try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-",f.app],timeout:30)
        print("LARGE_BODY_CONTROL original launch begins")
        try f.generate(timeout:30)
        print("LARGE_BODY_CONTROL original launch passed")
        let moved = try await isolate(f, engine: engine(f))
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.app))
        // The previous schema2 compact-tree layout remains restorable. This
        // simulated legacy record and rename affect only the owned test batch.
        XCTAssertEqual(moved.schemaVersion, RecoveryManifest.currentSchemaVersion)
        let root = f.home + "/Library/Application Support/App Sweep/Recovery/" + moved.id.uuidString
        try FileManager.default.moveItem(atPath: root + "/objects.noindex", toPath: root + "/objects")
        var json = try XCTUnwrap(try JSONSerialization.jsonObject(with: SafeFilesystem.readMetadata(root + "/manifest.json")) as? [String: Any])
        json["schemaVersion"] = 2
        try SafeDirectory(path: root).write(JSONSerialization.data(withJSONObject: json), name: "manifest.json")
        let fresh = engine(f)
        let restored = try await fresh.restore(batchID: moved.id)
        XCTAssertEqual(restored.status, .restored, restored.entries.compactMap(\.message).joined(separator: "; "))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.app + "/Contents/Resources/Many").count, count)
        print("LARGE_BODY_CONTROL restored launch begins")
        try f.generate(timeout:30)
        print("LARGE_BODY_CONTROL restored launch passed")
        let second = try await isolate(f, engine: fresh)
        let purged = try await fresh.purge(batchID: second.id, confirmation: "永久清空 " + second.id.uuidString)
        XCTAssertEqual(purged.status, .purged, purged.issue ?? "")
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.app))
    }
    func testChangedLargeBodyCannotRestoreOrPurgeExternalAlias() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let moved = try await isolate(f, engine: engine(f))
        let item = try XCTUnwrap(moved.entries.first)
        let root = f.home + "/Library/Application Support/App Sweep/Recovery/" + moved.id.uuidString + "/objects.noindex/" + item.id.uuidString
        let outside = f.home + "/retained.txt"
        try Data("retain".utf8).write(to: URL(fileURLWithPath: outside))
        try Data("changed".utf8).write(to: URL(fileURLWithPath: root + "/Contents/Resources/Many/0"))
        let alias = root + "/Contents/Resources/Many/1"
        try FileManager.default.removeItem(atPath: alias)
        try FileManager.default.createSymbolicLink(atPath: alias, withDestinationPath: outside)
        let fresh = engine(f)
        let restored = try await fresh.restore(batchID: moved.id)
        XCTAssertEqual(restored.status, .needsAttention)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.app))
        do { _ = try await fresh.purge(batchID: moved.id, confirmation: "永久清空 " + moved.id.uuidString); XCTFail("Changed recovery object must remain for manual resolution") } catch { }
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: outside)), Data("retain".utf8))
        XCTAssertTrue(FileManager.default.fileExists(atPath: root))
    }
    func testUnknownFingerprintAndManifestDowngradeAreRejected() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let moved = try await isolate(f, engine: engine(f))
        let batch = try SafeDirectory(path: f.home + "/Library/Application Support/App Sweep/Recovery/" + moved.id.uuidString)
        let original = try batch.read("manifest.json")
        let encoded = try XCTUnwrap(JSONSerialization.jsonObject(with: original) as? [String: Any])
        for mutation in 0..<3 {
            var changed = encoded
            var entries = try XCTUnwrap(changed["entries"] as? [[String: Any]])
            var fingerprint = try XCTUnwrap(entries[0]["treeFingerprint"] as? [String: Any])
            if mutation == 0 { changed["schemaVersion"] = 1 }
            if mutation == 1 { fingerprint["algorithm"] = "unknown" }
            if mutation == 2 { fingerprint["count"] = 1_000_001 }
            entries[0]["treeFingerprint"] = fingerprint; changed["entries"] = entries
            try batch.write(JSONSerialization.data(withJSONObject: changed), name: "manifest.json")
            let listed=try await engine(f).recoveryBatches()
            let retained=try XCTUnwrap(listed.first{$0.id == moved.id})
            XCTAssertTrue(retained.hasUnconfirmedObjects);XCTAssertFalse(retained.canPurge)
            do { _ = try await engine(f).restore(batchID:moved.id); XCTFail("Invalid recovery representation executed") } catch { }
            do { _ = try await engine(f).purge(batchID:moved.id,confirmation:"永久清空 "+moved.id.uuidString); XCTFail("Invalid recovery representation purged") } catch { }
            XCTAssertFalse(FileManager.default.fileExists(atPath: f.app))
        }
        try batch.write(original, name: "manifest.json")
        let restored = try await engine(f).restore(batchID: moved.id)
        XCTAssertEqual(restored.status, .restored)
    }
}
#endif
