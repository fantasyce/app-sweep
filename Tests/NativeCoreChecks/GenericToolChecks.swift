import Foundation
import Darwin
@testable import AppSweepCore

@MainActor func genericToolChecks() async throws {
    let f = try OwnedFixture()
    let npmRule = "development-npm-cache-v1", pnpmRule = "development-pnpm-metadata-v1"
    let content = f.home + "/.npm/_cacache/content-v2", index = f.home + "/.npm/_cacache/index-v5"
    let log = f.home + "/.npm/_logs/2026-10-28T00_00_00_000Z-debug-0.log"
    let meta = f.home + "/Library/Caches/pnpm/v11/metadata/registry.npmjs.org"
    let legacy = f.home + "/Library/Caches/pnpm/metadata-v1.3/registry.npmjs.org"
    let body = "{\"name\":\"independent-fixture\",\"versions\":{\"1.0.0\":{\"name\":\"independent-fixture\",\"version\":\"1.0.0\"}},\"dist-tags\":{\"latest\":\"1.0.0\"}}"
    let contentFile = content + "/sha512/ab/cd/" + String(repeating: "a", count: 124)
    let indexFile = index + "/ab/cd/" + String(repeating: "b", count: 60)
    for path in [contentFile, indexFile, log, meta + "/independent-fixture.jsonl", legacy + "/independent-fixture.json"] {
        try fm.createDirectory(atPath: URL(fileURLWithPath: path).deletingLastPathComponent().path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let text = path.hasSuffix(".jsonl") ? "{}\n" + body : (path.hasSuffix(".json") ? body : "owned regenerable fixture")
        try Data(text.utf8).write(to: URL(fileURLWithPath: path))
    }
    // Real registries contain valid metadata larger than 8 MiB (for example
    // long-lived TypeScript/@types packages), without a different cache format.
    let largeMetadata = String(body.dropLast()) + ",\"readme\":\"" + String(repeating: "x", count: 9 * 1024 * 1024) + "\"}"
    try Data(largeMetadata.utf8).write(to: URL(fileURLWithPath: legacy + "/independent-fixture.json"))
    _ = try ToolCacheRule.verify(legacy, home: f.home)
    print("PASS bounded metadata larger than 8 MiB remains recognizable")
    let retained = [f.home + "/Library/pnpm/store", f.home + "/.cache/uv", f.home + "/.cargo/registry/cache",
                    f.home + "/go/pkg/mod/cache", f.home + "/Library/Caches/electron-builder",
                    f.home + "/.npm/_cacache/tmp", f.home + "/Library/Caches/pnpm/v99",
                    f.home + "/Library/Caches/pnpm/v11/tool-environment"]
    for path in retained {
        try fm.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try Data("retained fixture".utf8).write(to: URL(fileURLWithPath: path + "/record"))
    }
    let expected = [content, index, log, meta, legacy], rules: Set<String> = [npmRule, pnpmRule]
    let engine = try f.engine(rules: rules), report = try await engine.scanJunk()
    let items = report.selectableCandidates(includeUserData: false).filter { rules.contains($0.rule) }
    try check(Set(items.map(\.path)) == Set(expected), "npm/pnpm generic caches missing or overbroad: " + report.candidates.compactMap(\.retentionReason).joined(separator: "; "))
    for path in retained {
        try check(report.candidates.contains { $0.path == path && !$0.executionAllowed && $0.retentionReason != nil }, "Tool catalog lost retained location: " + path)
    }
    try check(!report.candidates.contains { item in
        item.rule == ToolCacheCatalog.rule && expected.contains { SafetyPolicy.contains(item.path, $0) }
    }, "Retained catalog parent double-counted recognized descendants")
    print("PASS recognized caches and retained unknown siblings both appear without overlapping roots")
    print("PASS npm and pnpm standard formats discovered; shared stores, uv and runtime downloads are retained")
    let unaccepted = try await f.engine(rules: [ToolCacheRule.name]).scanJunk()
    try check(!unaccepted.selectableCandidates(includeUserData: true).contains { expected.contains($0.path) }, "Old tool acceptance authorized new producer rules")
    let before = try expected.map { try SafeFilesystem.snapshot($0) }
    let plan = try await engine.makePlan(reportID: report.id, selected: Set(items.map(\.id)), includeUserData: false)
    let batch = try await engine.execute(planID: plan.id)
    try check(batch.status == .isolated, "Tool isolation failed: " + (batch.issue ?? ""))
    let restored = try await f.engine(rules: rules).restore(batchID: batch.id)
    try check(restored.status == .restored, "Tool restore failed: " + (restored.issue ?? ""))
    for (offset, path) in expected.enumerated() {
        let after = try SafeFilesystem.snapshot(path)
        try check(after.identity.inode == before[offset].identity.inode && after.tree == before[offset].tree, "Tool recovery changed original object")
    }
    for path in retained { try check(String(contentsOfFile: path + "/record", encoding: .utf8) == "retained fixture", "Unselected tool data changed") }
    print("PASS new tool rules need separate acceptance; native isolation and fresh-engine recovery preserve exact data")
    do {
        let fd = open(contentFile, O_RDONLY | O_CLOEXEC)
        try check(fd >= 0, "Cannot open owned busy-cache fixture")
        defer { _ = close(fd) }
        let busyEngine = try f.engine(rules: rules), busyReport = try await busyEngine.scanJunk()
        guard let candidate = busyReport.selectableCandidates(includeUserData: false).first(where: { $0.path == content }) else {
            throw CheckFailure("Discovery still performs a recursive occupancy subprocess for each tool item")
        }
        let busyPlan = try await busyEngine.makePlan(reportID: busyReport.id, selected: [candidate.id], includeUserData: false)
        do {
            _ = try await busyEngine.execute(planID: busyPlan.id)
            throw CheckFailure("Open tool cache passed execution preflight")
        } catch let failure as CheckFailure { throw failure }
        catch { }
        try check(fm.fileExists(atPath: contentFile), "Open cache was moved before refusal")
    }
    print("PASS tool discovery defers occupancy subprocesses; open files still block execution before any move")
    for (label, change, undo) in [
        ("unexpected-file", { try Data("document".utf8).write(to: URL(fileURLWithPath: content + "/notes.txt")) }, { try fm.removeItem(atPath: content + "/notes.txt") }),
        ("symbolic-link", { try fm.createSymbolicLink(atPath: content + "/escape", withDestinationPath: f.home + "/.cache/uv") }, { try fm.removeItem(atPath: content + "/escape") }),
        ("shared-ancestor", { try check(chmod(f.home + "/.npm", 0o777) == 0, "chmod failed") }, { try check(chmod(f.home + "/.npm", 0o700) == 0, "chmod restore failed") })
    ] {
        try change()
        try reject("npm rejects " + label) { _ = try ToolCacheRule.verify(content, home: f.home) }
        try undo()
    }
    try Data("{\"name\":\"unrelated\",\"versions\":{}}".utf8).write(to: URL(fileURLWithPath: meta + "/independent-fixture.jsonl"))
    try reject("pnpm malformed/mismatched package metadata retained") { _ = try ToolCacheRule.verify(meta, home: f.home) }
    let policy = SafetyPolicy(home: f.home, acceptedPlatform: true, validatedRules: rules)
    for path in [f.home + "/.npm", f.home + "/.npmrc", f.home + "/.npm/_cacache/tmp",
                 f.home + "/Library/pnpm/store", f.home + "/Library/Caches/pnpm/v99/metadata/registry.npmjs.org",
                 f.home + "/.codex/packages", "/private/var/folders/cache"] {
        try check(policy.denial(path: path, category: .development, rule: npmRule) != nil, "npm forged path accepted: " + path)
        try check(policy.denial(path: path, category: .development, rule: pnpmRule) != nil, "pnpm forged path accepted: " + path)
    }
    print("PASS new producer rules reject forged paths, future versions and unrelated data")
    for command in ["/usr/local/bin/npm install", "node /tmp/npm-cli.js ci", "node /tmp/npx-cli.js test", "npx tool"] {
        try check(ToolCacheRule.isProducer(command: command, producer: .npm), "Missed npm alias: " + command)
    }
    for command in ["/usr/local/bin/pnpm install", "node /tmp/pnpm.cjs add", "node /tmp/pnpm.mjs install", "pnpx tool"] {
        try check(ToolCacheRule.isProducer(command: command, producer: .pnpm), "Missed pnpm alias: " + command)
    }
    for producer in [ToolCacheRule.Producer.npm, .pnpm] {
        try check(!ToolCacheRule.isProducer(command: "/usr/bin/other-npm-tool --pnpm-cache", producer: producer), "Substring-only process association")
    }
    let beforeActivity = try await engine.scanJunk()
    guard let activeItem = beforeActivity.selectableCandidates(includeUserData: false).first(where: { $0.path == content }) else {
        throw CheckFailure("Missing activity fixture")
    }
    let activePlan = try await engine.makePlan(reportID: beforeActivity.id, selected: [activeItem.id], includeUserData: false)
    let toolBinary = f.home + "/npm"
    try fm.copyItem(atPath: "/bin/sleep", toPath: toolBinary)
    let process = Process()
    process.executableURL = URL(fileURLWithPath: toolBinary); process.arguments = ["20"]
    try process.run()
    do {
        do {
            _ = try await engine.execute(planID: activePlan.id)
            throw CheckFailure("Producer started after plan but execution proceeded")
        } catch let failure as CheckFailure { throw failure }
        catch { }
        try check(fm.fileExists(atPath: contentFile), "Activity refusal moved a cache")
    } catch {
        if process.isRunning { process.terminate() }
        throw error
    }
    if process.isRunning { process.terminate() }
    let deadline = Date().addingTimeInterval(5)
    while process.isRunning && Date() < deadline { try await Task.sleep(nanoseconds: 50_000_000) }
    try check(!process.isRunning, "Owned producer process did not exit")
    print("PASS producer aliases detected; a producer starting after review blocks the whole plan")
    let oversized = String(body.dropLast()) + ",\"readme\":\"" + String(repeating: "x", count: 16 * 1024 * 1024) + "\"}"
    try Data(oversized.utf8).write(to: URL(fileURLWithPath: legacy + "/independent-fixture.json"))
    try reject("metadata above the bounded reader ceiling retained") { _ = try ToolCacheRule.verify(legacy, home: f.home) }
    try f.finish()
}
