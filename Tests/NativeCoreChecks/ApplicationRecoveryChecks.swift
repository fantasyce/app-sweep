import Foundation
import Darwin
@testable import AppSweepCore

@MainActor func applicationRecoveryChecks() async throws {
    let f = try OwnedFixture(), engine = try f.engine(), outside = f.home + "/outside-binary"
    try fm.linkItem(atPath: f.binary, toPath: outside)
    let report = try await settledApplication(engine, app: f.app), body = try selectedBody(report, app: f.app)
    let plan = try await engine.makePlan(reportID: report.id, selected: [body.id], includeUserData: false)
    let batch = try await engine.execute(planID: plan.id)
    try check(batch.status == .isolated, "Recovery boundary sample did not isolate")
    guard let entry = batch.entries.first, let proof = entry.applicationLinks else { throw CheckFailure("Original application link commitments absent") }
    let stored = f.home + "/Library/Application Support/App Sweep/Recovery/" + batch.id.uuidString + "/" + batch.objectsDirectory + "/" + body.id.uuidString
    try fm.removeItem(atPath: outside)
    let current = try SafeFilesystem.snapshot(stored, allowInternalLinks: true, purpose: .application, allowApplicationHardLinks: true)
    try check(entry.matchesRestorationContents(current), "Original commitment did not permit alias count change")
    try check(!entry.matchesContents(current), "Ordinary execution/purge matching must remain strict")
    var legacy = entry; legacy.applicationLinks = nil
    try check(!legacy.matchesRestorationContents(current), "Legacy journal invented missing content proof")
    let forged = ApplicationLinkRecovery(version: 1, members: proof.members.map { .init(relative: $0.relative, identity: $0.identity, digest: String(repeating: "0", count: 64)) })
    try check(!forged.matches(current, entry: entry), "Forged content commitment accepted")
    let escaped = ApplicationLinkRecovery(version: 1, members: [.init(relative: "../outside", identity: proof.members[0].identity, digest: proof.members[0].digest)])
    try reject("escaping proof member cannot authorize recovery") { try escaped.validate(for: entry) }
    var wrongType = entry
    wrongType = RecoveryEntry(id: entry.id, original: Candidate(id: entry.id, path: f.home + "/Library/Caches/foreign", category: .cache, bundleIdentifier: f.identifier, evidence: [], rule: CacheDomainRule.name, identity: current.identity, bytes: current.bytes, retentionReason: nil), state: .moved, message: nil)
    try reject("application recovery proof cannot authorize a cache") { try proof.validate(for: wrongType) }
    var compact = entry; compact.contents = []; compact.treeFingerprint = try TreeFingerprint.capture(entry.contents)
    try check(proof.matches(current, entry: compact), "Compact tree commitment did not normalize only proven members")
    print("PASS original commitment, legacy refusal, forged/escaping/type guards and compact metadata comparison")
    do {
        _ = try await engine.purge(batchID: batch.id, confirmation: "永久清空 " + batch.id.uuidString)
        throw CheckFailure("Alias churn improperly relaxed permanent purge")
    } catch let error as CheckFailure { throw error } catch { }
    try check(fm.fileExists(atPath: stored), "Refused purge lost recovery object")
    try fm.createDirectory(atPath: f.app, withIntermediateDirectories: false)
    try Data("conflict".utf8).write(to: URL(fileURLWithPath: f.app + "/keep"))
    let conflict = try await engine.restore(batchID: batch.id)
    try check(conflict.status == .needsAttention && String(contentsOfFile: f.app + "/keep", encoding: .utf8) == "conflict", "Recovery overwrote existing path")
    try fm.removeItem(atPath: f.app) // Exact owned conflict fixture only.
    let fresh = try f.engine()
    let restored = try await fresh.restore(batchID: batch.id)
    try check(restored.status == .restored, "Fresh engine could not recover preserved batch")
    print("PASS strict purge, existing-path preservation and restart/retry recovery")
    try f.finish()

    let g = try OwnedFixture(), other = g.home + "/outside-resource", gEngine = try g.engine()
    try fm.linkItem(atPath: g.app + "/Contents/Resources/asset", toPath: other)
    let gReport = try await settledApplication(gEngine, app: g.app), gBody = try selectedBody(gReport, app: g.app)
    let gPlan = try await gEngine.makePlan(reportID: gReport.id, selected: [gBody.id], includeUserData: false)
    let gBatch = try await gEngine.execute(planID: gPlan.id)
    try check(gBatch.status == .isolated, "Metadata sample did not isolate")
    let value: [UInt8] = [1, 2, 3]
    try check(setxattr(other, "org.example.appsweep.acceptance", value, value.count, 0, 0) == 0, "Owned xattr setup failed")
    let altered = try await gEngine.restore(batchID: gBatch.id)
    try check(altered.status == .needsAttention && !fm.fileExists(atPath: g.app), "Changed linked xattrs accepted at restore")
    try check(removexattr(other, "org.example.appsweep.acceptance", 0) == 0, "Owned xattr reset failed")
    let recovered = try await gEngine.restore(batchID: gBatch.id)
    try check(recovered.status == .restored, "Identical metadata after reverting owned xattr did not recover")
    print("PASS linked extended-attribute changes block restoration without losing objects")
    let nextReport = try await settledApplication(gEngine, app: g.app), nextBody = try selectedBody(nextReport, app: g.app)
    let nextPlan = try await gEngine.makePlan(reportID: nextReport.id, selected: [nextBody.id], includeUserData: false)
    let next = try await gEngine.execute(planID: nextPlan.id)
    try check(next.status == .isolated, "Content sample did not isolate")
    let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: other))
    try handle.write(contentsOf: Data("alteredresource".utf8)); try handle.close()
    let rejected = try await gEngine.restore(batchID: next.id)
    try check(rejected.status == .needsAttention && !fm.fileExists(atPath: g.app), "Changed linked bytes accepted at restore")
    print("PASS changed linked bytes remain a preserved recovery conflict")
    try g.finish()
}
