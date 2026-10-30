#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

/// Only the official application and data already installed by this VM task.
final class RealCacheDomainTests: XCTestCase, @unchecked Sendable {
    struct Receipt: Codable {
        let schemaVersion: Int
        let id: UUID
        let batch: UUID
        let rootInode: UInt64
        let cacheDigests: [String: String]
        let persistentDigests: [String: String]
    }
    struct PreservedObject: Codable {
        let source: String
        let name: UUID
        let identity: FileIdentity
        let contents: [TreeEntry]
        var moved: Bool
    }
    struct Preservation: Codable {
        let id: UUID
        let regeneratedDigests: [String: String]
        var objects: [PreservedObject]
    }
    private func context() throws -> (String, String, String, String) {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_REAL_DOMAIN_ACCEPTANCE"] == "1",
              try BoundedProcess.run("/usr/sbin/sysctl", arguments: ["-n", "hw.model"], timeout: 3).hasPrefix("VirtualMac"),
              try SystemIdentity.home() == "/Users/localtest" else { throw XCTSkip("Explicit task-installed consumer VM only") }
        let home = try SystemIdentity.home(), app = home + "/Applications/Vienna.app", identifier = "uk.co.opencommunity.vienna2"
        _ = try BoundedProcess.run("/usr/bin/codesign", arguments: ["--verify", "--deep", "--strict", "--test-requirement", "=anchor apple generic and identifier \"" + identifier + "\"", app], timeout: 30)
        try ActivityInspector.ensureStopped(bundleID: identifier, applicationPath: app)
        return (home, app, identifier, home + "/AppSweepAcceptanceGeneral-20261016")
    }
    private func fingerprints(_ roots: [String], cache: Bool = false) throws -> [String: String] {
        var result: [String: String] = [:]
        for root in roots {
            guard try SafeFilesystem.presence(root) else { result[root] = "absent"; continue }
            let snapshot = try SafeFilesystem.snapshot(root, allowInternalHardLinks: cache)
            let files = snapshot.identity.isDirectory ? snapshot.tree.filter { !$0.identity.isDirectory }.map { root + "/" + $0.relative } : [root]
            for path in files { result[path] = try VerifiedFileStream.digest(SafeFilesystem.fileSnapshot(path, in: snapshot)) }
            try SafeFilesystem.verify(snapshot)
        }
        return result
    }
    private func engine(home: String) -> SweepEngine {
        SweepEngine()
    }
    private func restore(_ batch: UUID, engine: SweepEngine) async throws -> RecoveryManifest {
        var result = try await engine.restore(batchID: batch)
        for _ in 0..<12 {
            if result.status == .restored { return result }
            guard result.entries.compactMap(\.message).contains(where: { $0.contains("文件仍被进程使用") || $0.contains("文件占用状态未确认") }) else { return result }
            try await Task.sleep(nanoseconds: 500_000_000)
            result = try await engine.restore(batchID: batch)
        }
        return result
    }
    func testOfficialViennaRoundtripAndPrepareRegeneration() async throws {
        let (home, app, identifier, task) = try context(), fm = FileManager.default
        let marker = task + "/cache-domain-pending.json"
        guard !fm.fileExists(atPath: marker) else { throw SweepError.incomplete("Finish the recorded consumer regeneration/recovery before creating another trial") }
        let root = CacheDomainRule.root(home: home, identifier: identifier)
        let original = try SafeFilesystem.snapshot(root, allowInternalHardLinks: true)
        guard !original.tree.isEmpty else { throw SweepError.incomplete("Official consumer must create real cache contents first") }
        let persistent = [home + "/Library/Application Support/Vienna", home + "/Library/Preferences/" + identifier + ".plist"]
        let before = try fingerprints(persistent), core = self.engine(home: home)
        let rounds = ProcessInfo.processInfo.environment["APP_SWEEP_DOMAIN_ROUNDTRIP_ONLY"] == "1" ? 1 : 2
        for round in 0..<rounds {
            let cacheBytes = try fingerprints([root], cache: true), report = try await core.scanJunk()
            let items = report.selectableCandidates(includeUserData: false).filter { $0.rule == CacheDomainRule.name && URL(fileURLWithPath: $0.path).deletingLastPathComponent().path == root }
            let members = try CacheDomainRule.members(home: home, identifier: identifier)
            XCTAssertFalse(items.isEmpty, report.candidates.filter { $0.path.hasPrefix(root) }.compactMap(\.retentionReason).joined(separator: "; ") + report.unconfirmedIssues.joined(separator: "; "))
            guard !items.isEmpty else { return }
            XCTAssertEqual(Set(items.map(\.path)), members)
            let plan = try await core.makePlan(reportID: report.id, selected: Set(items.map(\.id)), includeUserData: false)
            let batch = try await core.execute(planID: plan.id)
            guard batch.status == .isolated else { throw SweepError.incomplete(batch.issue ?? "Official cache isolation incomplete") }
            XCTAssertTrue(batch.hasIndependentBackups)
            XCTAssertEqual(try SafeDirectory(path: root).ownIdentity.inode, original.identity.inode)
            XCTAssertEqual(try fingerprints(persistent), before)
            XCTAssertTrue(try CacheDomainRule.members(home: home, identifier: identifier).isEmpty)
            if round == 0 {
                let restored = try await restore(batch.id, engine: core)
                guard restored.status == .restored else { throw SweepError.incomplete(restored.entries.compactMap(\.message).joined(separator: "; ")) }
                XCTAssertEqual(try fingerprints([root], cache: true), cacheBytes)
                XCTAssertEqual(try fingerprints(persistent), before)
                XCTAssertTrue(AppInspector.signatureMatches(path: app, identifier: identifier))
                print("Official Vienna complete cache namespace isolated/restored, independent bytes registered, persistent data and publisher signature unchanged")
            } else {
                let receipt = Receipt(schemaVersion: 1, id: UUID(), batch: batch.id, rootInode: original.identity.inode, cacheDigests: cacheBytes, persistentDigests: before)
                try JSONEncoder().encode(receipt).write(to: URL(fileURLWithPath: marker), options: .withoutOverwriting)
                print("Official cache regeneration pending; batch=" + batch.id.uuidString + "; marker=" + marker)
            }
        }
    }
    func testOfficialViennaRegenerationAndConflictRecovery() async throws {
        let (home, app, identifier, task) = try context(), fm = FileManager.default
        let marker = task + "/cache-domain-pending.json", root = CacheDomainRule.root(home: home, identifier: identifier)
        let receipt = try JSONDecoder().decode(Receipt.self, from: SafeFilesystem.readMetadata(marker))
        guard receipt.schemaVersion == 1, receipt.cacheDigests.keys.allSatisfy({ SafetyPolicy.contains(root, $0) }),
              try SafeDirectory(path: root).ownIdentity.inode == receipt.rootInode else { throw SweepError.denied("Official consumer receipt or cache parent identity mismatch") }
        let core = self.engine(home: home)
        let batches = try await core.recoveryBatches(), batch = try XCTUnwrap(batches.first { $0.id == receipt.batch })
        guard batch.entries.allSatisfy({ $0.original.rule == CacheDomainRule.name && $0.original.bundleIdentifier == identifier && URL(fileURLWithPath: $0.original.path).deletingLastPathComponent().path == root }) else { throw SweepError.denied("Only this task's exact cache group can be recovered") }
        let parent = try SafeDirectory(path: task).privateChild("cache-domain-regenerated.noindex")
        let preserved = try parent.privateChild(receipt.id.uuidString)
        let journal = preserved.path + "/ownership.json"
        var preservation: Preservation
        if try SafeFilesystem.presence(journal) {
            preservation = try JSONDecoder().decode(Preservation.self, from: preserved.read("ownership.json"))
            guard preservation.id == receipt.id else { throw SweepError.denied("Regenerated data receipt identity mismatch") }
        } else {
            let snapshot = try CacheDomainRule.verifyDomain(home: home, identifier: identifier)
            guard !snapshot.tree.isEmpty, try SafeFilesystem.presence(root + "/Cache.db") else { throw SweepError.incomplete("Official application has not regenerated its real cache database") }
            let generated = try fingerprints([root], cache: true)
            XCTAssertNotEqual(generated, receipt.cacheDigests)
            let conflict = try await core.restore(batchID: receipt.batch)
            XCTAssertEqual(conflict.status, .needsAttention)
            XCTAssertEqual(try fingerprints([root], cache: true), generated, "Recovery must not overwrite fresh consumer data")
            guard conflict.status == .needsAttention else { return }
            let objects = try snapshot.tree.filter { !$0.relative.contains("/") }.map { entry -> PreservedObject in
                let child = try SafeFilesystem.snapshot(root + "/" + entry.relative, allowInternalHardLinks: true)
                return PreservedObject(source: child.path, name: UUID(), identity: child.identity, contents: child.tree, moved: false)
            }
            preservation = Preservation(id: receipt.id, regeneratedDigests: generated, objects: objects)
            try preserved.write(JSONEncoder().encode(preservation), name: "ownership.json")
        }
        if batch.status != .restored {
            for index in preservation.objects.indices {
                let object = preservation.objects[index]
                guard CacheDomainRule.matches(path: object.source, home: home, identifier: identifier) else { throw SweepError.denied("Regenerated fixture path is outside the exact domain") }
                let destination = preserved.path + "/" + object.name.uuidString
                if try SafeFilesystem.presence(destination) {
                    let current = try SafeFilesystem.snapshot(destination, allowInternalHardLinks: true)
                    guard current.identity.sameObject(as: object.identity), current.tree == object.contents else { throw SweepError.stale("Preserved regenerated fixture changed") }
                } else {
                    let current = try SafeFilesystem.snapshot(object.source, allowInternalHardLinks: true)
                    guard current.identity == object.identity, current.tree == object.contents else { throw SweepError.stale("Regenerated source changed before fixture transfer") }
                    var idle = false
                    for _ in 0..<40 {
                        do { try BusyInspector.ensureUnused(current); idle = true; break }
                        catch { try await Task.sleep(nanoseconds: 250_000_000) }
                    }
                    guard idle else { throw SweepError.incomplete("Regenerated fixture is still occupied; no process is terminated") }
                    try SafeFilesystem.move(current, into: preserved, name: object.name.uuidString)
                }
                preservation.objects[index].moved = true
                try preserved.write(JSONEncoder().encode(preservation), name: "ownership.json")
            }
            let alreadyRestored = Set(batch.entries.filter { $0.state == .restored }.map { $0.original.path })
            guard try CacheDomainRule.members(home: home, identifier: identifier) == alreadyRestored else { throw SweepError.stale("Unconfirmed files remain after fixture preservation; retained for review") }
            let restored = try await restore(receipt.batch, engine: core)
            guard restored.status == .restored else { throw SweepError.incomplete(restored.entries.compactMap(\.message).joined(separator: "; ")) }
        }
        XCTAssertEqual(try fingerprints([root], cache: true), receipt.cacheDigests)
        XCTAssertEqual(try SafeDirectory(path: root).ownIdentity.inode, receipt.rootInode)
        for (path, digest) in receipt.persistentDigests where digest != "absent" { XCTAssertTrue(fm.fileExists(atPath: path), "Persistent file retained: " + path) }
        XCTAssertTrue(AppInspector.signatureMatches(path: app, identifier: identifier))
        let completed = task + "/cache-domain-completed-" + receipt.id.uuidString + ".json"
        guard !fm.fileExists(atPath: completed) else { throw SweepError.denied("Completion receipt already exists") }
        try fm.moveItem(atPath: marker, toPath: completed)
        print("Official Vienna regenerated real cache after whole-domain cleanup; original cache restored byte-for-byte after conflict refusal. Regenerated fixture retained at " + preserved.path + "; completed receipt=" + completed)
    }
}
#endif
