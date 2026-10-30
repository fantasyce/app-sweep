#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

/// Opt-in acceptance of the original vendor-signed application and its own
/// disposable VM profile. No synthetic cache bytes stand in for the consumer.
final class RealChromiumCacheTests: XCTestCase, @unchecked Sendable {
    private var google: Bool { ProcessInfo.processInfo.environment["APP_SWEEP_CHROMIUM_CONSUMER"] == "google" }
    private var identifier: String { google ? "com.google.Chrome" : "com.brave.Browser" }
    private var namespace: String { google ? "Google/Chrome" : "BraveSoftware/Brave-Browser" }
    struct Receipt: Codable {
        let id: UUID
        let batch: UUID
        let root: String
        let rootInode: UInt64
        let cache: [String:String]
        let persistent: [String:String]
    }
    private func context() throws -> (String,String,String) {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_REAL_CHROMIUM_ACCEPTANCE"] == "1",
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).hasPrefix("VirtualMac2,1"),
              try SystemIdentity.home() == "/Users/localtest" else { throw XCTSkip("Explicit disposable VM consumer acceptance only") }
        let home = try SystemIdentity.home(), app = home + "/Applications/" + (google ? "Google Chrome.app" : "Brave Browser.app")
        let stage = home + "/AppSweepAcceptanceGeneral-20261016/" + (google ? "chrome-default.noindex" : "brave-consumer.noindex")
        let raw = try JSONSerialization.jsonObject(with:SafeFilesystem.readMetadata(stage + "/default-consumer-ownership.json")) as? [String:Any]
        guard raw?["identifier"] as? String == identifier, raw?["namespace"] as? String == namespace,
              let inode = raw?["sourceInode"] as? UInt64,
              try SafeDirectory(path:app).ownIdentity.inode == inode,
              AppInspector.signatureMatches(path:app,identifier:identifier),
              AppInspector.signedByTeam(path:app,team:google ? "EQHXZ8M8AV" : "KL8N8XSYF4") else { throw SweepError.denied("Original task-owned publisher-signed consumer required") }
        try ActivityInspector.ensureStopped(bundleID:identifier,applicationPath:app)
        return (home,app,stage)
    }
    private func engine(_ home: String) -> SweepEngine {
        // Real workflow acceptance must use the shipped policy and its live
        // platform context, never a private union of enabled rules.
        SweepEngine()
    }
    private func fingerprints(_ path: String) throws -> [String:String] {
        let snapshot = try SafeFilesystem.snapshot(path,allowInternalHardLinks:true)
        var result:[String:String] = [:]
        for entry in snapshot.tree where !entry.identity.isDirectory {
            result[entry.relative] = try VerifiedFileStream.digest(SafeFilesystem.fileSnapshot(path + "/" + entry.relative,in:snapshot))
        }
        try SafeFilesystem.verify(snapshot)
        return result
    }
    private func members(_ root: String) throws -> [String] {
        try SafeFilesystem.snapshot(root,allowInternalHardLinks:true).tree.filter { !$0.relative.contains("/") }.map(\.relative).sorted()
    }
    private func restore(_ batch: UUID, home: String) async throws -> RecoveryManifest {
        var result = try await engine(home).restore(batchID:batch)
        for _ in 0..<12 {
            if result.status == .restored { return result }
            guard result.entries.compactMap(\.message).contains(where:{ $0.contains("文件仍被进程使用") || $0.contains("文件占用状态未确认") }) else { return result }
            try await Task.sleep(nanoseconds:500_000_000)
            result = try await engine(home).restore(batchID:batch)
        }
        return result
    }
    func testOfficialDefaultProfileRoundtripAndPrepareRegeneration() async throws {
        let (home,app,stage) = try context(), root = home + "/Library/Caches/" + namespace + "/Default"
        let support = home + "/Library/Application Support/" + namespace
        let marker = stage + "/cache-pending.json"
        guard !FileManager.default.fileExists(atPath:marker) else { throw SweepError.incomplete("Finish the recorded consumer recovery first") }
        let persistent = try fingerprints(support), cache = try fingerprints(root)
        XCTAssertFalse(cache.isEmpty,"Official consumer must create actual cache first")
        guard !cache.isEmpty else { return }
        let inode = try SafeDirectory(path:root).ownIdentity.inode
        let rounds=ProcessInfo.processInfo.environment["APP_SWEEP_CHROMIUM_ROUNDTRIP_ONLY"] == "1" ? 1 : 2
        for round in 0..<rounds {
            let core = engine(home), report = try await core.scanJunk()
            let candidates = report.selectableCandidates(includeUserData:false).filter { $0.rule == ChromiumCacheRule.name && URL(fileURLWithPath:$0.path).deletingLastPathComponent().path == root }
            XCTAssertFalse(candidates.isEmpty,report.candidates.filter { $0.path.hasPrefix(root) }.compactMap(\.retentionReason).joined(separator:"; ") + report.unconfirmedIssues.joined(separator:"; "))
            guard !candidates.isEmpty else { return }
            XCTAssertEqual(Set(candidates.map(\.path)),Set(try members(root).map { root + "/" + $0 }))
            let plan = try await core.makePlan(reportID:report.id,selected:Set(candidates.map(\.id)),includeUserData:false)
            let isolated = try await core.execute(planID:plan.id)
            XCTAssertEqual(isolated.status,.isolated,isolated.issue ?? "")
            guard isolated.status == .isolated else { return }
            XCTAssertTrue(isolated.hasIndependentBackups)
            XCTAssertTrue(try members(root).isEmpty)
            XCTAssertEqual(try SafeDirectory(path:root).ownIdentity.inode,inode)
            XCTAssertEqual(try fingerprints(support),persistent,"Persistent profile bytes must not be cleaned")
            if round == 0 {
                let recovered = try await restore(isolated.id,home:home)
                XCTAssertEqual(recovered.status,.restored,recovered.entries.compactMap(\.message).joined(separator:"; "))
                guard recovered.status == .restored else { return }
                XCTAssertEqual(try fingerprints(root),cache)
                XCTAssertEqual(try fingerprints(support),persistent)
                XCTAssertTrue(AppInspector.signatureMatches(path:app,identifier:identifier))
            } else {
                let receipt = Receipt(id:UUID(),batch:isolated.id,root:root,rootInode:inode,cache:cache,persistent:persistent)
                try JSONEncoder().encode(receipt).write(to:URL(fileURLWithPath:marker),options:.withoutOverwriting)
                print("Original vendor-signed consumer: real default cache isolated, fresh-engine restored byte-for-byte, persistent profile unchanged; second batch awaiting real regeneration: " + isolated.id.uuidString)
            }
        }
    }
    func testOfficialRegenerationRefusesOverwriteAndRestoresOriginalCache() async throws {
        let (home,app,stage) = try context(), marker = stage + "/cache-pending.json"
        let receipt = try JSONDecoder().decode(Receipt.self,from:SafeFilesystem.readMetadata(marker))
        let root = home + "/Library/Caches/" + namespace + "/Default", support = home + "/Library/Application Support/" + namespace
        guard receipt.root == root, try SafeDirectory(path:root).ownIdentity.inode == receipt.rootInode else { throw SweepError.stale("Recorded consumer root changed") }
        let core = engine(home), history = try await core.recoveryBatches()
        let batch = try XCTUnwrap(history.first { $0.id == receipt.batch })
        guard batch.entries.allSatisfy({ $0.original.rule == ChromiumCacheRule.name && $0.original.bundleIdentifier == identifier && URL(fileURLWithPath:$0.original.path).deletingLastPathComponent().path == root }) else { throw SweepError.denied("Recovery batch is not the exact recorded consumer group") }
        let generated = try fingerprints(root), currentPersistent = try fingerprints(support)
        XCTAssertFalse(generated.isEmpty,"Consumer must regenerate its real cache")
        guard !generated.isEmpty else { return }
        let conflict = try await core.restore(batchID:receipt.batch)
        XCTAssertEqual(conflict.status,.needsAttention)
        XCTAssertEqual(try fingerprints(root),generated,"Restore must not overwrite newly regenerated data")
        guard conflict.status == .needsAttention else { return }
        let parent = try SafeDirectory(path:stage).privateChild("regenerated-cache.noindex")
        let preservation = try parent.privateChild(receipt.id.uuidString)
        struct Object: Codable { let source: String; let name: String; let identity: FileIdentity; let tree: [TreeEntry] }
        let objects = try members(root).map { name -> Object in
            let snapshot = try SafeFilesystem.snapshot(root + "/" + name,allowInternalHardLinks:true)
            return Object(source:snapshot.path,name:UUID().uuidString,identity:snapshot.identity,tree:snapshot.tree)
        }
        // Preserve regenerated bytes instead of deleting them to manufacture a
        // successful undo; journal precedes every fixture-only relocation.
        try preservation.write(JSONEncoder().encode(objects),name:"ownership.json")
        for object in objects {
            let snapshot = try SafeFilesystem.snapshot(object.source,allowInternalHardLinks:true)
            guard snapshot.identity == object.identity, snapshot.tree == object.tree else { throw SweepError.stale("Regenerated fixture changed") }
            try BusyInspector.ensureUnused(snapshot)
            try SafeFilesystem.move(snapshot,into:preservation,name:object.name)
        }
        let recovered = try await restore(receipt.batch,home:home)
        XCTAssertEqual(recovered.status,.restored,recovered.entries.compactMap(\.message).joined(separator:"; "))
        guard recovered.status == .restored else { return }
        XCTAssertEqual(try fingerprints(root),receipt.cache)
        XCTAssertEqual(try fingerprints(support),currentPersistent)
        XCTAssertEqual(try SafeDirectory(path:root).ownIdentity.inode,receipt.rootInode)
        XCTAssertTrue(AppInspector.signatureMatches(path:app,identifier:identifier))
        try FileManager.default.moveItem(atPath:marker,toPath:stage + "/cache-completed-" + receipt.id.uuidString + ".json")
        print("Official consumer regenerated real cache; conflict refused overwrite; original cache restored exactly and current persistent profile unchanged. Regenerated bytes retained at " + preservation.path)
    }
    func testOfficialBodyCacheAndProfileChoiceWithFreshRestoration() async throws {
        try await verifyOriginalConsumerChoices([false,true])
    }
    func testOfficialBodyCacheAndOptInProfileWithFreshRestoration() async throws {
        try await verifyOriginalConsumerChoices([true])
    }
    private func verifyOriginalConsumerChoices(_ choices: [Bool]) async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_REAL_CHROMIUM_PROFILE_ACCEPTANCE"] == "1" else { throw XCTSkip("Explicit whole-profile disposable VM acceptance") }
        let (home,app,stage) = try context(), support = home + "/Library/Application Support/" + namespace
        let cacheRoot = home + "/Library/Caches/" + namespace
        func core() -> SweepEngine { SweepEngine() }
        func recover(_ id: UUID) async throws -> RecoveryManifest {
            for attempt in 0..<12 {
                let result = try await core().restore(batchID:id)
                if result.status == .restored { return result }
                guard attempt < 11, result.entries.compactMap(\.message).contains(where: { $0.contains("文件仍被进程使用") || $0.contains("文件占用状态未确认") }) else { return result }
                try await Task.sleep(nanoseconds:500_000_000)
            }
            throw SweepError.incomplete("Consumer recovery observation exhausted")
        }
        let trials = try SafeDirectory(path:stage).privateChild("profile-choice.noindex")
        for includeData in choices {
            let operation = try trials.privateChild(UUID().uuidString)
            var receipt: [String:Any] = ["purpose":"actual original signed browser body/cache/profile choice only; no preference reset, root operation or purge","application":app,"profile":support,"cache":cacheRoot,"includeUserData":includeData,"state":"recorded intent; no move yet"]
            func save() throws { try operation.write(JSONSerialization.data(withJSONObject:receipt,options:[.sortedKeys]),name:"ownership.json") }
            try save()
            let engine = core(), before = try fingerprints(support), caches = try fingerprints(cacheRoot)
            let original = try SafeFilesystem.snapshot(app,allowInternalLinks:true,purpose:.application)
            // A completed restore legitimately wakes Spotlight. Wait only for a
            // fresh read-only occupancy proof; never retry an execute operation.
            let idleDeadline = ProcessInfo.processInfo.systemUptime + 60
            while true {
                do { try BusyInspector.ensureUnused(original,allowReadOnlyLocalization:true); break }
                catch is CancellationError { throw CancellationError() }
                catch {
                    guard ProcessInfo.processInfo.systemUptime < idleDeadline,
                          error.localizedDescription.contains("文件仍被进程使用") || error.localizedDescription.contains("文件占用状态未确认") else { throw error }
                    try await Task.sleep(nanoseconds:500_000_000)
                }
            }
            let report = try await engine.scanApplication(app)
            let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601; encoder.outputFormatting = [.prettyPrinted,.sortedKeys]
            try operation.write(encoder.encode(report),name:"scan.json")
            let profile = try XCTUnwrap(report.selectableCandidates(includeUserData:true).first { $0.path == support && $0.rule == ChromiumProfileRule.name },report.unconfirmedIssues.joined(separator:"; ") + report.candidates.compactMap(\.retentionReason).joined(separator:"; "))
            XCTAssertFalse(profile.selectedByDefault)
            let items = report.selectableCandidates(includeUserData:includeData).filter { $0.path == app || $0.rule == ChromiumCacheRule.name || $0.rule == ChromiumProfileRule.name }
            guard items.contains(where: { $0.path == app }), items.contains(where: { $0.rule == ChromiumCacheRule.name }), items.allSatisfy({ $0.applicationPath == app }) else {
                print("Original consumer scan evidence: " + operation.path + "/scan.json")
                throw SweepError.incomplete("Original consumer body/cache selection was not confirmed: " + report.candidates.map { $0.path + ": " + ($0.retentionReason ?? $0.allowedActions.map(\.rawValue).joined(separator:",")) }.joined(separator:"; ") + report.unconfirmedIssues.joined(separator:"; "))
            }
            let plan = try await engine.makePlan(reportID:report.id,selected:Set(items.map(\.id)),includeUserData:includeData)
            XCTAssertEqual(plan.items.contains(where: { $0.id == profile.id }),includeData)
            receipt["paths"] = plan.items.map(\.path); receipt["state"] = "reviewed exact original consumer scope; execution intent"; try save()
            let batch = try await engine.execute(planID:plan.id)
            receipt["batch"] = batch.id.uuidString; receipt["state"] = batch.status.rawValue; try save()
            guard batch.status == .isolated else { throw SweepError.incomplete("Consumer isolation retained: " + batch.id.uuidString + "; " + (batch.issue ?? "")) }
            do {
                if includeData { XCTAssertFalse(FileManager.default.fileExists(atPath:support)) }
                else { XCTAssertEqual(try fingerprints(support),before) }
                let restored = try await recover(batch.id)
                receipt["state"] = restored.status.rawValue; try save()
                guard restored.status == .restored else { throw SweepError.incomplete("Consumer undo retained: " + restored.entries.compactMap(\.message).joined(separator:"; ")) }
                let current = try SafeFilesystem.snapshot(app,allowInternalLinks:true,purpose:.application)
                XCTAssertTrue(current.identity.sameObject(as:original.identity)); XCTAssertEqual(current.tree,original.tree)
                XCTAssertEqual(try fingerprints(support),before); XCTAssertEqual(try fingerprints(cacheRoot),caches)
                XCTAssertTrue(AppInspector.signatureMatches(path:app,identifier:identifier))
            } catch {
                let restored = try? await recover(batch.id)
                receipt["state"] = restored?.status.rawValue ?? "recovery-unconfirmed"; try? save()
                throw error
            }
            guard testRun?.failureCount == 0 else { throw SweepError.incomplete("Native consumer assertions failed; no accepted choice receipt") }
            print("Original consumer body/cache/profile choice and fresh-instance exact restoration passed; includeUserData=" + String(includeData) + "; receipt=" + operation.path)
        }
    }
}
#endif
