#if os(macOS)
import Foundation
import CryptoKit
import XCTest
@testable import AppSweepCore

/// Opt-in acceptance of an unmodified official consumer inside the disposable VM.
/// The driver never terminates the consumer or changes its persistent records.
final class FoundationConsumerTests: XCTestCase, @unchecked Sendable {
    private struct Checkpoint: Codable {
        let batch: UUID
        let rule: String
        let identity: FileIdentity
        let tree: [TreeEntry]
        let payloadDigests: [String: String]
        let persistent: [String: String]
    }
    func testOfficialConsumerPayloadWorkflow() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard environment["APP_SWEEP_FOUNDATION_ACCEPTANCE"] == "1",
              try BoundedProcess.run("/usr/sbin/sysctl", arguments: ["-n", "hw.model"], timeout: 3).hasPrefix("VirtualMac"),
              NSHomeDirectory() == "/Users/localtest" else { throw XCTSkip("Requires the prepared disposable third-party consumer VM") }
        let home = try SystemIdentity.home()
        let task = home + "/AppSweepAcceptanceGeneral-20261016"
        let app = home + "/Applications/Vienna.app"
        let identifier = "uk.co.opencommunity.vienna2"
        let inspected = try AppInspector.inspect(app)
        XCTAssertEqual(inspected.bundleIdentifier, identifier)
        XCTAssertTrue(inspected.signed)
        let info = try XCTUnwrap(try PropertyListSerialization.propertyList(from: SafeFilesystem.readMetadata(app + "/Contents/Info.plist"), format: nil) as? [String: Any])
        let rawVersion = try XCTUnwrap(info["CFBundleShortVersionString"] as? String)
        let version = try XCTUnwrap(rawVersion.split(whereSeparator: \.isWhitespace).first).description
        XCTAssertEqual(version, environment["APP_SWEEP_CONSUMER_VERSION"])
        guard !version.isEmpty, version.utf8.allSatisfy({ (48...57).contains($0) || $0 == 46 }) else { throw SweepError.invalid("Consumer version is not a checkpoint filename") }
        let checkpointURL = URL(fileURLWithPath: task + "/vienna-regeneration-" + version + ".json")
        let path = CacheRule.path(home: home, identifier: identifier)
        let persistentPaths = [home + "/Library/Application Support/Vienna/messages.db", home + "/Library/Preferences/" + identifier + ".plist"]
        let engine = SweepEngine(policy: SafetyPolicy(home: home, acceptedPlatform: true, validatedRules: [CacheRule.name]), vaultPath: home + "/Library/Application Support/App Sweep/Recovery", fixture: false)
        let stage = environment["APP_SWEEP_CONSUMER_STAGE"] ?? "roundTrip"
        if stage != "finishRegeneration" {
            for batch in try await engine.recoveryBatches() where batch.status == .needsAttention && batch.entries.allSatisfy({ $0.original.rule == CacheRule.name && CacheRule.matches(path: $0.original.path, home: home, identifier: identifier) }) {
                _ = try await restoreWhenUnused(batch, engine: engine, home: home)
            }
        }
        if stage == "finishRegeneration" {
            let currentPersistent = try fingerprints(persistentPaths)
            let checkpoint = try JSONDecoder().decode(Checkpoint.self, from: SafeFilesystem.readMetadata(checkpointURL.path))
            guard checkpoint.rule == CacheRule.name else { throw SweepError.invalid("Checkpoint belongs to another cache operation") }
            let batches = try await engine.recoveryBatches()
            let batch = try XCTUnwrap(batches.first { $0.id == checkpoint.batch })
            guard !batch.entries.isEmpty, batch.entries.allSatisfy({ CacheRule.matches(path: $0.original.path, home: home, identifier: identifier) }) else { throw SweepError.invalid("Unexpected consumer recovery batch") }
            try CacheRule.verify(path: path, home: home, identifier: identifier)
            let regenerated = try SafeFilesystem.snapshot(path)
            guard regenerated.identity.inode == checkpoint.identity.inode, !regenerated.tree.isEmpty else { throw SweepError.incomplete("Consumer did not regenerate payloads in its original directory") }
            let currentMetadata = try fingerprints(try metadataPaths(home: home, identifier: identifier))
            var conflict = try await engine.restore(batchID: batch.id)
            for _ in 0..<8 where conflict.entries.compactMap(\.message).contains(where: { $0.contains("文件占用状态未确认") || $0.contains("文件仍被进程使用") }) {
                try await Task.sleep(nanoseconds: 500_000_000)
                conflict = try await engine.restore(batchID: batch.id)
            }
            guard conflict.status == .needsAttention, conflict.entries.contains(where: { $0.state == .conflict && $0.message?.contains("原路径已存在，不覆盖") == true }) else { throw SweepError.incomplete("Expected response-file conflict was not confirmed: " + conflict.entries.compactMap(\.message).joined(separator: "; ")) }
            // Normal restoration may already restore non-conflicting originals.
            // Every newly generated response must keep its exact identity.
            let preserved = try SafeDirectory(path: task + "/fixtures").privateChild("vienna-regenerated")
            for entry in regenerated.tree {
                let file = try SafeFilesystem.snapshot(path + "/" + entry.relative)
                guard file.identity.sameObject(as: entry.identity) else { throw SweepError.stale("Regenerated response changed during conflict handling") }
                try BusyInspector.ensureUnused(file)
                try SafeFilesystem.move(file, into: preserved, name: UUID().uuidString)
            }
            _ = try await restoreWhenUnused(conflict, engine: engine, home: home)
            assertSamePayloads(try SafeFilesystem.snapshot(path).tree, checkpoint.tree, allowReconstruction: true)
            XCTAssertEqual(try fingerprints(checkpoint.tree.map { path + "/" + $0.relative }), checkpoint.payloadDigests)
            XCTAssertEqual(try SafeFilesystem.snapshot(path).identity.inode, checkpoint.identity.inode)
            XCTAssertEqual(try fingerprints(persistentPaths), currentPersistent)
            XCTAssertEqual(try fingerprints(try metadataPaths(home: home, identifier: identifier)), currentMetadata)
            print("Official Foundation consumer \(version): regenerated response files, refused conflict overwrite, restored originals; directory and databases preserved.")
            return
        }
        guard ["roundTrip", "prepareRegeneration"].contains(stage) else { throw SweepError.invalid("Unknown consumer acceptance stage") }
        let report = try await engine.scanJunk()
        XCTAssertTrue(report.complete, report.issues.joined(separator: "\n"))
        let candidates = report.candidates.filter { $0.rule == CacheRule.name && CacheRule.matches(path: $0.path, home: home, identifier: identifier) && $0.allowed }
        guard !candidates.isEmpty else { throw SweepError.incomplete(report.candidates.filter { $0.bundleIdentifier == identifier }.map { $0.path + ": " + ($0.retentionReason ?? "eligible") }.joined(separator: "\n")) }
        let original = try SafeFilesystem.snapshot(path)
        let originalPayloads = try fingerprints(original.tree.map { path + "/" + $0.relative })
        let before = try fingerprints(persistentPaths)
        let metadata = try metadataPaths(home: home, identifier: identifier)
        let databaseBefore = try fingerprints(metadata)
        if stage == "prepareRegeneration", FileManager.default.fileExists(atPath: checkpointURL.path) { throw SweepError.invalid("Existing acceptance checkpoint must be reviewed before any move") }
        let plan = try await engine.makePlan(reportID: report.id, selected: Set(candidates.map(\.id)), includeUserData: false)
        let moved = try await engine.execute(planID: plan.id)
        guard moved.status == .isolated else { throw SweepError.incomplete(moved.issue ?? "Consumer payload was not isolated") }
        XCTAssertTrue(try SafeFilesystem.snapshot(path).tree.isEmpty)
        XCTAssertEqual(try SafeFilesystem.snapshot(path).identity.inode, original.identity.inode)
        XCTAssertEqual(try fingerprints(persistentPaths), before)
        XCTAssertEqual(try fingerprints(metadata), databaseBefore)
        if stage == "prepareRegeneration" {
            try JSONEncoder().encode(Checkpoint(batch: moved.id, rule: CacheRule.name, identity: original.identity, tree: original.tree, payloadDigests: originalPayloads, persistent: before)).write(to: checkpointURL, options: .withoutOverwriting)
            print("Official Foundation consumer \(version): isolated payload; awaiting normal application refresh in the VM.")
        } else {
            _ = try await restoreWhenUnused(moved, engine: engine, home: home)
            assertSamePayloads(try SafeFilesystem.snapshot(path).tree, original.tree)
            XCTAssertEqual(try fingerprints(original.tree.map { path + "/" + $0.relative }), originalPayloads)
            XCTAssertEqual(try fingerprints(persistentPaths), before)
            XCTAssertEqual(try fingerprints(metadata), databaseBefore)
            print("Official Foundation consumer \(version): completed isolation/restore and database/persistent-file digest assertions.")
        }
    }
    private func assertSamePayloads(_ actual: [TreeEntry], _ expected: [TreeEntry], allowReconstruction: Bool = false) {
        XCTAssertEqual(actual.map(\.relative), expected.map(\.relative))
        for (a, b) in zip(actual, expected) {
            if allowReconstruction {
                XCTAssertEqual(a.identity.mode, b.identity.mode); XCTAssertEqual(a.identity.owner, b.identity.owner)
                XCTAssertEqual(a.identity.links, b.identity.links); XCTAssertEqual(a.identity.size, b.identity.size)
                XCTAssertEqual(a.identity.modifiedSeconds, b.identity.modifiedSeconds)
                XCTAssertEqual(a.identity.modifiedNanoseconds, b.identity.modifiedNanoseconds)
            } else { XCTAssertTrue(a.identity.sameObject(as: b.identity)) }
        }
    }
    private func restoreWhenUnused(_ batch: RecoveryManifest, engine: SweepEngine, home: String) async throws -> RecoveryManifest {
        var result = batch
        for attempt in 0..<8 {
            for entry in result.entries where entry.state != .restored {
                let object = home + "/Library/Application Support/App Sweep/Recovery/" + batch.id.uuidString + "/" + batch.objectsDirectory + "/" + entry.id.uuidString
                if try SafeFilesystem.presence(object) { try BusyInspector.ensureUnused(SafeFilesystem.snapshot(object)) }
                else if entry.backupDigest != nil {
                    let backup = home + "/Library/Application Support/App Sweep/Recovery/" + batch.id.uuidString + "/" + batch.backupsDirectory + "/" + entry.id.uuidString
                    try BusyInspector.ensureUnused(SafeFilesystem.snapshot(backup))
                } else { throw SweepError.incomplete("Both isolated response and independent backup are unconfirmed") }
            }
            result = try await engine.restore(batchID: batch.id)
            if result.status == .restored { return result }
            let reasons = result.entries.compactMap(\.message)
            guard attempt < 7, reasons.contains(where: { $0.contains("文件占用状态未确认") || $0.contains("文件仍被进程使用") }) else { throw SweepError.incomplete(reasons.joined(separator: "\n")) }
            try await Task.sleep(nanoseconds: 500_000_000)
        }
        throw SweepError.incomplete("Consumer restore remains unconfirmed")
    }
    private func metadataPaths(home: String, identifier: String) throws -> [String] {
        try ["", "-wal", "-shm"].map { home + "/Library/Caches/" + identifier + "/Cache.db" + $0 }.filter { try SafeFilesystem.presence($0) }
    }
    private func fingerprints(_ paths: [String]) throws -> [String: String] {
        var result = [String: String]()
        for path in paths {
            let snapshot = try SafeFilesystem.snapshot(path)
            let data = try SafeFilesystem.readMetadata(path, maximumBytes: 16 * 1024 * 1024)
            try SafeFilesystem.verify(snapshot)
            result[path] = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        }
        return result
    }
}
#endif
