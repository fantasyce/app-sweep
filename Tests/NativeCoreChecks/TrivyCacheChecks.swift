import Foundation
import Darwin
@testable import AppSweepCore

@MainActor func trivyCacheChecks() async throws {
    let f = try OwnedFixture(), root = f.home + "/Library/Caches/trivy", path = root + "/db"
    try fm.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    // Public Bolt meta-page format, independent fixed four-page fixture.
    let pages = ["AAAAAAAAAAAEAAAAAAAAAO3aDO0CAAAAABAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAAEAAAAAAAAAAAAAAAAAAAALq7y+5/NRX8=", "AQAAAAAAAAAEAAAAAAAAAO3aDO0CAAAAABAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAAEAAAAAAAAAAEAAAAAAAAAT/jhBqmUQJ4="]
    var database = Data(repeating: 0, count: 16384)
    for (i, page) in pages.enumerated() { database.replaceSubrange(i*4096..<i*4096+80, with: Data(base64Encoded: page)!) }
    try database.write(to: URL(fileURLWithPath: path + "/trivy.db"))
    let metadata = Data(#"{"Version":2,"UpdatedAt":"2026-01-01T00:00:00Z","NextUpdate":"2026-01-02T00:00:00Z","DownloadedAt":"2026-01-01T12:00:00Z"}"#.utf8)
    try metadata.write(to: URL(fileURLWithPath: path + "/metadata.json"))
    try fm.createDirectory(atPath: root + "/fanal", withIntermediateDirectories: false)
    try Data("unvalidated scan database".utf8).write(to: URL(fileURLWithPath: root + "/fanal/fanal.db"))
    let rule = "development-trivy-database-v1", engine = try f.engine(rules: [rule]), report = try await engine.scanJunk()
    let items = report.selectableCandidates(includeUserData: false).filter { $0.rule == rule }
    try check(items.map(\.path) == [path], "Trivy downloadable database is missing from actionable results")
    try check(report.candidates.contains { $0.path == root + "/fanal" && !$0.executionAllowed }, "Unvalidated sibling hidden or enabled")
    let before = try SafeFilesystem.snapshot(path), plan = try await engine.makePlan(reportID: report.id, selected: [items[0].id], includeUserData: false)
    let batch = try await engine.execute(planID: plan.id)
    try check(batch.status == .isolated, "Trivy database quarantine failed")
    let result = try await f.engine(rules: [rule]).restore(batchID: batch.id)
    try check(result.status == .restored && SafeFilesystem.snapshot(path).identity.inode == before.identity.inode, "Trivy database did not restore original object")
    print("PASS Trivy database pair is one recoverable item; unvalidated scan cache retained")
    try Data("personal file".utf8).write(to: URL(fileURLWithPath: path + "/notes.txt"))
    try reject("Trivy mixed user files rejected") { _ = try ToolCacheRule.verify(path,home:f.home) }
    try fm.removeItem(atPath: path + "/notes.txt")
    try Data(#"{"Version":3}"#.utf8).write(to: URL(fileURLWithPath: path + "/metadata.json"))
    try reject("Unknown Trivy schema retained") { _ = try ToolCacheRule.verify(path,home:f.home) }
    try metadata.write(to: URL(fileURLWithPath: path + "/metadata.json"))
    database[16] = 0; try database.write(to: URL(fileURLWithPath: path + "/trivy.db"))
    try reject("Corrupt Bolt metadata retained") { _ = try ToolCacheRule.verify(path,home:f.home) }
    try f.finish()
}
