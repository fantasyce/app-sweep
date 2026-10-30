#if os(macOS)
import CryptoKit
import CFSafety
import Foundation
import XCTest
@testable import AppSweepCore

/// Explicit opt-in only: these are task-installed official apps and test data in
/// the disposable VM, never an arbitrary developer machine or the Intel account.
final class RealApplicationUninstallTests: XCTestCase, @unchecked Sendable {
    private func missingPreference(_ output: CapturedProcess, domain: String, key: String) -> Bool {
        let messages = ["The domain/default pair of (" + domain + ", " + key + ") does not exist",
                        "Could not find key '" + key + "' in domain '" + domain + "'",
                        "Could not find domain '" + domain + "'", "Domain '" + domain + "' not found."]
        return output.status == 1 && messages.contains(where: output.text.contains)
    }
    func testPreferenceProbeSeparatesMissingValuesFromPermissionAndOtherErrors() {
        let domain = "com.colliderli.iina", key = "AppSweepAcceptanceMarker"
        for text in ["The domain/default pair of (com.colliderli.iina, AppSweepAcceptanceMarker) does not exist", "Error: Could not find key 'AppSweepAcceptanceMarker' in domain 'com.colliderli.iina'.", "Error: Domain 'com.colliderli.iina' not found."] {
            XCTAssertTrue(missingPreference(CapturedProcess(status: 1, text: text), domain: domain, key: key))
        }
        for output in [CapturedProcess(status: 1, text: "Permission denied"), CapturedProcess(status: 1, text: "Error: Domain 'different.domain' not found."), CapturedProcess(status: 0, text: "Error: Domain 'com.colliderli.iina' not found.")] {
            XCTAssertFalse(missingPreference(output, domain: domain, key: key))
        }
    }
    func testIINAOwnershipReadOnlyDiagnostic() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_REAL_SUPPORT_ACCEPTANCE"] == "1",
              try SystemIdentity.home() == "/Users/localtest",
              try BoundedProcess.run("/usr/sbin/sysctl", arguments: ["-n", "hw.model"], timeout: 3).hasPrefix("VirtualMac") else { throw XCTSkip("Disposable VM diagnostic only") }
        let path = "/Users/localtest/Applications/IINA.app"
        let inspected = try AppInspector.inspect(path)
        print("IINA_DIRECT_SIGNATURE", inspected.signed, inspected.protectedReason ?? "none")
        for url in try ApplicationRegistry.systemLocations(inspected.bundleIdentifier) {
            print("IINA_REGISTERED_URL", url.absoluteString, "STANDARD", url.standardizedFileURL.path)
        }
        let inventory = try AppInspector.inventorySnapshot(home: "/Users/localtest", selectedApplication: path)
        for app in inventory.applications where app.bundleIdentifier == "com.colliderli.iina" || app.bundleIdentifier.isEmpty {
            print("IINA_OWNER_OR_UNRESOLVED", app.path, app.bundleIdentifier, app.signed, app.protectedReason ?? "none")
        }
        for issue in inventory.issues { print("IINA_INVENTORY_ISSUE", issue) }
        print("IINA_UNIQUE", AppInspector.uniqueOwner(identifier: inspected.bundleIdentifier, path: path, inventory: inventory.applications))
        let report = try await SweepEngine().scanApplication(path)
        for candidate in report.candidates {
            print("IINA_SCAN_CANDIDATE", candidate.path, candidate.retentionReason ?? "selectable")
        }
        for issue in report.issues { print("IINA_SCAN_ISSUE", issue) }
    }
    func testOfficialIINAUserDataChoiceAndFullRestoration() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_REAL_SUPPORT_ACCEPTANCE"] == "1",
              try BoundedProcess.run("/usr/sbin/sysctl", arguments: ["-n", "hw.model"], timeout: 3).hasPrefix("VirtualMac"),
              try SystemIdentity.home() == "/Users/localtest" else { throw XCTSkip("Prepared disposable IINA VM only") }
        let home = try SystemIdentity.home(), identifier = "com.colliderli.iina"
        let app = home + "/Applications/IINA.app", root = SupportDomainRule.path(home: home, identifier: identifier)
        guard AppInspector.signatureMatches(path: app, identifier: identifier), AppInspector.signedByTeam(path: app, team: "67CQ77V27R") else { throw SweepError.denied("Official task-created IINA identity not confirmed") }
        try ActivityInspector.ensureStopped(bundleID: identifier, applicationPath: app)
        guard try SafeFilesystem.presence(root), !(try SafeFilesystem.snapshot(root).tree.isEmpty) else { throw SweepError.incomplete("IINA must first create its own real support data") }
        let media = home + "/AppSweepAcceptanceGeneral-20261016/media-fixture.noindex/fixture.png"
        let persistent = [root, home + "/Library/Preferences/" + identifier + ".plist", media]
        let probePreferences = ProcessInfo.processInfo.environment["APP_SWEEP_CFPREFS_PROBE"] == "1"
        let markerKey = "AppSweepAcceptanceMarker-" + UUID().uuidString, markerValue = UUID().uuidString
        var probeReceipt: SafeDirectory?
        if probePreferences {
            let task = try SafeDirectory(path:home + "/AppSweepAcceptanceGeneral-20261016")
            let receipt = try task.privateChild("preference-probes.noindex").privateChild(UUID().uuidString)
            try receipt.write(JSONSerialization.data(withJSONObject:["domain":identifier,"key":markerKey,"value":markerValue,"state":"prepared; remove only this exact matching value after restoration"],options:[.sortedKeys]),name:"ownership.json")
            probeReceipt = receipt
            print("Owned native preference probe receipt: " + receipt.path)
            let old = try BoundedProcess.capture("/usr/bin/defaults", arguments: ["read", identifier, markerKey], timeout: 3, mergeStderr: true)
            guard missingPreference(old, domain: identifier, key: markerKey) else { throw SweepError.incomplete("The unique test preference key is not confirmed absent: " + old.text) }
            _ = try BoundedProcess.run("/usr/bin/defaults", arguments: ["write", identifier, markerKey, "-string", markerValue], timeout: 3)
            XCTAssertEqual(try BoundedProcess.run("/usr/bin/defaults", arguments: ["read", identifier, markerKey], timeout: 3).trimmingCharacters(in: .whitespacesAndNewlines), markerValue)
        }
        let rules = NativeAcceptance.rules(for: PlatformStamp.current).union([SupportDomainRule.name])
        let engine = ProcessInfo.processInfo.environment["APP_SWEEP_PUBLIC_SUPPORT_ACCEPTANCE"] == "1" ? SweepEngine() : SweepEngine(policy: SafetyPolicy(home: home, acceptedPlatform: true, validatedRules: rules), vaultPath: home + "/Library/Application Support/App Sweep/Recovery", fixture: false)
        for includeData in [false, true] {
            let bytes = try fingerprints(persistent), original = try SafeFilesystem.snapshot(app, allowInternalLinks: true, purpose: .application)
            var report = try await engine.scanApplication(app)
            // Restoring to Applications may start normal OS extension/index
            // discovery. The test may wait and request a new scan, never bypass it.
            for attempt in 0..<20 {
                if report.selectableCandidates(includeUserData: false).contains(where: { $0.path == app }) { break }
                let reason = report.candidates.first { $0.path == app }?.retentionReason ?? "No confirmed body"
                guard reason.contains("仍被进程使用") || reason.contains("文件占用状态未确认") else { throw SweepError.incomplete(reason) }
                print("IINA body scan safely deferred, attempt \(attempt + 1): " + reason)
                try await Task.sleep(nanoseconds: 500_000_000)
                report = try await engine.scanApplication(app)
            }
            guard report.selectableCandidates(includeUserData: false).contains(where: { $0.path == app }) else { throw SweepError.incomplete("IINA body remains occupied; no plan was issued") }
            let support = try XCTUnwrap(report.selectableCandidates(includeUserData: true).first { $0.path == root }, report.issues.joined(separator: "; ") + report.candidates.compactMap(\.retentionReason).joined(separator: "; "))
            XCTAssertEqual(support.rule, SupportDomainRule.name)
            XCTAssertFalse(support.selectedByDefault)
            let selected = Set(report.selectableCandidates(includeUserData: includeData).map(\.id))
            let plan = try await engine.makePlan(reportID: report.id, selected: selected, includeUserData: includeData)
            XCTAssertEqual(plan.items.contains { $0.id == support.id }, includeData)
            let moved = try await engine.execute(planID: plan.id)
            guard moved.status == .isolated else { throw SweepError.incomplete(moved.issue ?? "IINA isolation incomplete") }
            print("Real IINA batch \(moved.id), includeUserData=\(includeData)")
            do {
                if includeData {
                    XCTAssertFalse(FileManager.default.fileExists(atPath: root))
                    if probePreferences {
                        let cleared = try BoundedProcess.capture("/usr/bin/defaults", arguments: ["read", identifier, markerKey], timeout: 3, mergeStderr: true)
                        XCTAssertEqual(cleared.status, 1, "A fresh native preferences client must not see removed settings")
                        XCTAssertTrue(missingPreference(cleared, domain: identifier, key: markerKey), "Permission and other errors are not proof that settings were cleared: " + cleared.text)
                    }
                }
                else { XCTAssertEqual(try fingerprints(persistent), bytes) }
                let restored = try await restoreWhenUnused(moved, engine: engine, home: home)
                guard restored.status == .restored else { throw SweepError.incomplete("IINA recovery retained: " + moved.id.uuidString + " " + restored.entries.compactMap(\.message).joined(separator: "; ")) }
                let after = try SafeFilesystem.snapshot(app, allowInternalLinks: true, purpose: .application)
                XCTAssertTrue(after.identity.sameObject(as: original.identity)); XCTAssertEqual(after.tree, original.tree)
                XCTAssertTrue(AppInspector.signatureMatches(path: app, identifier: identifier))
                XCTAssertEqual(try fingerprints(persistent), bytes)
                if probePreferences { XCTAssertEqual(try BoundedProcess.run("/usr/bin/defaults", arguments: ["read", identifier, markerKey], timeout: 3).trimmingCharacters(in: .whitespacesAndNewlines), markerValue) }
            } catch { _ = try? await restoreWhenUnused(moved, engine: engine, home: home); throw error }
            print("Official IINA full restoration passed; \(bytes.count) persistent file digests, support/plugin data, media and app identities retained; no purge")
        }
        if probePreferences {
            let current = try BoundedProcess.run("/usr/bin/defaults",arguments:["read",identifier,markerKey],timeout:3).trimmingCharacters(in:.whitespacesAndNewlines)
            guard current == markerValue else { throw SweepError.incomplete("Owned preference probe changed; retain it with its receipt") }
            _ = try BoundedProcess.run("/usr/bin/defaults", arguments: ["delete", identifier, markerKey], timeout: 3)
            if let probeReceipt { try probeReceipt.write(JSONSerialization.data(withJSONObject:["domain":identifier,"key":markerKey,"value":markerValue,"state":"removed after successful restoration"],options:[.sortedKeys]),name:"ownership.json") }
            print("Only the exact task-created test preference marker removed after successful restoration")
        }
    }
    func testOfficialFirefoxAndViennaBodyIsolationAndRestoration() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_REAL_UNINSTALL_ACCEPTANCE"] == "1",
              try BoundedProcess.run("/usr/sbin/sysctl", arguments: ["-n", "hw.model"], timeout: 3).hasPrefix("VirtualMac"),
              try SystemIdentity.home() == "/Users/localtest" else { throw XCTSkip("Requires the explicitly prepared disposable consumer VM") }
        let home = try SystemIdentity.home()
        let engine = SweepEngine()
        for (name, identifier, support) in [("Firefox", "org.mozilla.firefox", "Firefox"), ("Vienna", "uk.co.opencommunity.vienna2", "Vienna")] {
            let path = home + "/Applications/" + name + ".app"
            let app = try AppInspector.inspect(path)
            guard app.signed, app.bundleIdentifier == identifier else { throw SweepError.denied("Official consumer identity not confirmed: " + name) }
            try ActivityInspector.ensureStopped(bundleID: identifier, applicationPath: path)
            let original = try SafeFilesystem.snapshot(path, allowInternalLinks: true)
            let persistent = [home + "/Library/Application Support/" + support, home + "/Library/Preferences/" + identifier + ".plist"]
            let before = try fingerprints(persistent)
            let report = try await engine.scanApplication(path)
            let body = try XCTUnwrap(report.selectableCandidates(includeUserData: false).first { $0.category == .application && $0.path == path }, report.issues.joined(separator: "; ") + report.candidates.compactMap(\.retentionReason).joined(separator: "; "))
            XCTAssertEqual(body.rule, SelectedApplicationRule.name)
            let plan = try await engine.makePlan(reportID: report.id, selected: [body.id], includeUserData: false)
            XCTAssertFalse(plan.items.contains { $0.userData })
            let moved = try await engine.execute(planID: plan.id)
            guard moved.status == .isolated else { throw SweepError.incomplete("Body isolation incomplete: " + (moved.issue ?? moved.status.rawValue)) }
            do {
                XCTAssertFalse(FileManager.default.fileExists(atPath: path))
                XCTAssertEqual(try fingerprints(persistent), before)
                let restored = try await restoreWhenUnused(moved, engine: engine, home: home)
                guard restored.status == .restored else { throw SweepError.incomplete("Consumer recovery requires attention: " + moved.id.uuidString + " " + restored.entries.compactMap(\.message).joined(separator: "; ")) }
            } catch {
                // Attempt normal recovery before surfacing an acceptance failure.
                // No direct move, journal rewrite, conflict overwrite or purge.
                _ = try? await restoreWhenUnused(moved, engine: engine, home: home)
                throw error
            }
            let restored = try SafeFilesystem.snapshot(path, allowInternalLinks: true)
            XCTAssertTrue(restored.identity.sameObject(as: original.identity))
            XCTAssertEqual(restored.tree, original.tree)
            XCTAssertTrue(AppInspector.signatureMatches(path: path, identifier: identifier))
            XCTAssertEqual(try fingerprints(persistent), before)
            print("Official \(name): full bundle \(original.tree.count) entries isolated/restored through Core; signature, file identities and \(before.count) persistent digests unchanged; no purge.")
        }
    }
    private func fingerprints(_ roots: [String]) throws -> [String: String] {
        var result: [String: String] = [:]
        for root in roots where try SafeFilesystem.presence(root) {
            let snapshot = try SafeFilesystem.snapshot(root, allowInternalLinks: true)
            let files: [(String, FileIdentity)] = snapshot.identity.isDirectory ? snapshot.tree.filter { !$0.identity.isDirectory && !$0.identity.isLink }.map { (root + "/" + $0.relative, $0.identity) } : [(root, snapshot.identity)]
            for (file, identity) in files {
                // Test data databases can exceed the product metadata reader's16MiB
                // cap. Use the existing verified no-follow C reader for this read-only
                // acceptance digest; the product's metadata limit is unchanged.
                guard identity.size >= 0, identity.size <= 64 * 1024 * 1024 else { throw SweepError.incomplete("Acceptance digest exceeds64MiB: " + file) }
                let url = URL(fileURLWithPath: file), parent = try SafeDirectory(path: url.deletingLastPathComponent().path)
                var expected = identity.native, count = 0
                var bytes = [UInt8](repeating: 0, count: max(1, Int(identity.size)))
                guard as_read_verified_file(parent.fd, url.lastPathComponent, &expected, &bytes, bytes.count, &count) == 0 else { throw SweepError.stale("Acceptance data changed or is unreadable: " + file) }
                result[file] = SHA256.hash(data: Data(bytes.prefix(count))).map { String(format: "%02x", $0) }.joined()
            }
            do { try SafeFilesystem.verify(snapshot) }
            catch {
                print("Acceptance fingerprint changed: " + root)
                if let current = try? SafeFilesystem.snapshot(root,allowInternalLinks:true) {
                    print("Fingerprint root expected=\(snapshot.identity), current=\(current.identity), ancestorsChanged=\(snapshot.ancestors != current.ancestors)")
                    let old = Dictionary(uniqueKeysWithValues:snapshot.tree.map { ($0.relative,$0.identity) })
                    let next = Dictionary(uniqueKeysWithValues:current.tree.map { ($0.relative,$0.identity) })
                    for name in Set(old.keys).union(next.keys).sorted().filter({ old[$0] != next[$0] }).prefix(10) {
                        print("Fingerprint entry changed: \(name), expected=\(String(describing:old[name])), current=\(String(describing:next[name]))")
                    }
                }
                throw error
            }
        }
        return result
    }
    private func restoreWhenUnused(_ batch: RecoveryManifest, engine: SweepEngine, home: String) async throws -> RecoveryManifest {
        var current = batch
        for attempt in 0..<8 {
            // Preferences are restored by CFPreferences from their independent backup;
            // they have no ordinary object at objects/<entry-id>.
            for entry in current.entries where entry.preference == nil && (entry.state == .moved || entry.state == .conflict) {
                let object = home + "/Library/Application Support/App Sweep/Recovery/" + batch.id.uuidString + "/" + batch.objectsDirectory + "/" + entry.id.uuidString
                var ready = false
                for _ in 0..<40 {
                    do { try BusyInspector.ensureUnused(SafeFilesystem.snapshot(object, allowInternalLinks: true, purpose: .application)); ready = true; break }
                    catch {
                        let reason = error.localizedDescription
                        guard reason.contains("文件仍被进程使用") || reason.contains("文件占用状态未确认") else { throw error }
                        if !ready { print("Consumer recovery waiting: " + entry.original.path + " — " + reason) }
                        try await Task.sleep(nanoseconds: 250_000_000)
                    }
                }
                guard ready else { throw SweepError.incomplete("Consumer recovery object is still busy; batch " + batch.id.uuidString) }
            }
            current = try await engine.restore(batchID: batch.id)
            if current.status == .restored { return current }
            guard current.entries.compactMap(\.message).contains(where: { $0.contains("文件占用状态未确认") || $0.contains("文件仍被进程使用") }) else { return current }
            print("Consumer restore deferred for observed indexer activity, attempt \(attempt + 1)")
            try await Task.sleep(nanoseconds: 250_000_000)
        }
        return current
    }
}
#endif
