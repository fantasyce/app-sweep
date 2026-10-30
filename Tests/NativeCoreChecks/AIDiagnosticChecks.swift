import Foundation
import Darwin
@testable import AppSweepCore

/// Missing discovery must fail before the diagnostics rule is introduced.
/// The current host may be running Codex, so discovery must expose either the
/// manual candidate or a clear retained entry, without touching real logs.
@MainActor func aiDiagnosticDiscoveryChecks() async throws {
    let f = try OwnedFixture()
    let root = f.home + "/.codex/log"
    try fm.createDirectory(atPath: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    let path = root + "/codex-tui.log"
    let bytes = Data("2026-10-30T00:00:00Z INFO codex_tui: owned diagnostic fixture\n".utf8)
    try bytes.write(to: URL(fileURLWithPath: path))
    try aiDiagnosticRuleGuards(f: f, path: path, bytes: bytes)
    let engine = try f.engine(rules: ["fixed-ai-producer-diagnostic-v1"])
    let report = try await engine.scanJunk()
    guard let item = report.candidates.first(where: { $0.path == path && $0.rule == "fixed-ai-producer-diagnostic-v1" }) else {
        throw CheckFailure("Default Codex CLI diagnostic log is missing from discovery")
    }
    try check(item.category == .log && !item.selectedByDefault && item.recommendation == .manual, "CLI diagnostics must be classified as logs requiring manual selection")
    try check(try Data(contentsOf: URL(fileURLWithPath: path)) == bytes, "Discovery changed the owned diagnostic log")
    print("PASS default CLI diagnostic log is discovered and never selected by default")
    guard let actionable = report.selectableCandidates(includeUserData: false).first(where: { $0.id == item.id }) else {
        throw CheckFailure("Owned diagnostic fixture must be actionable after producer scoping: " + (item.retentionReason ?? ""))
    }
    let original = try AIDiagnosticRule.verify(path: path, home: f.home)
    let plan = try await engine.makePlan(reportID: report.id, selected: [actionable.id], includeUserData: false)
    let batch = try await engine.execute(planID: plan.id)
    try check(batch.status == .isolated && !fm.fileExists(atPath: path), "Explicit diagnostic selection did not isolate: " + (batch.issue ?? "") + batch.entries.compactMap(\.message).joined(separator: "; "))
    try check(AIDiagnosticRule.matches(path: path, home: f.home), "Recovery authorization incorrectly requires the isolated source to exist")
    let restored = try await f.engine(rules: [AIDiagnosticRule.name]).restore(batchID: batch.id)
    try check(restored.status == .restored, "Fresh-engine diagnostic recovery failed: " + (restored.issue ?? "") + restored.entries.compactMap(\.message).joined(separator: "; "))
    let after = try AIDiagnosticRule.verify(path: path, home: f.home)
    try check(after.identity.sameObject(as: original.identity) && Data(contentsOf: URL(fileURLWithPath: path)) == bytes, "Recovered diagnostic bytes or identity changed")
    print("PASS manual diagnostic isolation and fresh-engine identity/byte recovery")

    let conflictEngine = try f.engine(rules: [AIDiagnosticRule.name]), conflictReport = try await conflictEngine.scanJunk()
    guard let conflictItem = conflictReport.selectableCandidates(includeUserData: false).first(where: { $0.path == path }) else { throw CheckFailure("Diagnostic fixture missing after recovery") }
    let conflictPlan = try await conflictEngine.makePlan(reportID: conflictReport.id, selected: [conflictItem.id], includeUserData: false)
    let conflictBatch = try await conflictEngine.execute(planID: conflictPlan.id)
    try check(conflictBatch.status == .isolated, "Diagnostic conflict sample did not isolate")
    try AIDiagnosticRule.verifyRestoreDestination(path: path, home: f.home)
    let originalMode = try SafeDirectory(path: root).ownIdentity.mode
    let writeGrant = "everyone allow write,append,delete_child"
    _ = try BoundedProcess.run("/bin/chmod", arguments: ["+a", writeGrant, root], timeout: 3)
    try check(SafeDirectory(path: root).ownIdentity.mode == originalMode, "Diagnostic ACL sample unexpectedly changed POSIX mode")
    try reject("Diagnostic destination ACL-only sharing is retained with absent source") { try AIDiagnosticRule.verifyRestoreDestination(path: path, home: f.home) }
    let sharedDestination = try await f.engine(rules: [AIDiagnosticRule.name]).restore(batchID: conflictBatch.id)
    try check(sharedDestination.status != .restored && !fm.fileExists(atPath: path), "Recovery restored a diagnostic into an ACL-shared directory")
    _ = try BoundedProcess.run("/bin/chmod", arguments: ["-a", writeGrant, root], timeout: 3)
    try check(SafeDirectory(path: root).ownIdentity.mode == originalMode, "Removing diagnostic test ACL changed POSIX mode")
    try AIDiagnosticRule.verifyRestoreDestination(path: path, home: f.home)
    let newer = Data("New independently recreated log\n".utf8)
    try newer.write(to: URL(fileURLWithPath: path))
    let conflict = try await f.engine(rules: [AIDiagnosticRule.name]).restore(batchID: conflictBatch.id)
    try check(conflict.status != .restored && Data(contentsOf: URL(fileURLWithPath: path)) == newer, "Diagnostic recovery overwrote the newly created log")
    try fm.moveItem(atPath: path, toPath: f.home + "/newer-diagnostic-held")
    let resolved = try await f.engine(rules: [AIDiagnosticRule.name]).restore(batchID: conflictBatch.id)
    try check(resolved.status == .restored && Data(contentsOf: URL(fileURLWithPath: path)) == bytes, "Diagnostic conflict recovery did not preserve the original")
    print("PASS diagnostic recovery retains a newer destination and restores after conflict is moved")

    let busyEngine = try f.engine(rules: [AIDiagnosticRule.name]), busyReport = try await busyEngine.scanJunk()
    guard let busyItem = busyReport.selectableCandidates(includeUserData: false).first(where: { $0.path == path }) else { throw CheckFailure("Diagnostic fixture missing before producer check") }
    let busyPlan = try await busyEngine.makePlan(reportID: busyReport.id, selected: [busyItem.id], includeUserData: false)
    let executable = f.home + "/codex"
    try fm.copyItem(atPath: "/bin/sleep", toPath: executable)
    let producer = Process(); producer.executableURL = URL(fileURLWithPath: executable); producer.arguments = ["30"]
    producer.currentDirectoryURL = URL(fileURLWithPath: f.home)
    try producer.run()
    do {
        defer { if producer.isRunning { producer.terminate() }; producer.waitUntilExit() }
        let processes = try ActivityInspector.processes(BoundedProcess.run("/bin/ps", arguments: ["-ww", "-axo", "pid=,command="], timeout: 3), ownPID: ProcessInfo.processInfo.processIdentifier)
        try check(processes.contains { $0.pid == producer.processIdentifier && AIDiagnosticRule.isProducer($0.command) }, "Actual fixture producer was not identified")
        try reject("Real fixture Codex producer blocks diagnostics") { try AIDiagnosticRule.ensureStopped(path: path, home: f.home) }
        do { _ = try await busyEngine.execute(planID: busyPlan.id); throw CheckFailure("Producer started after review but diagnostic log was moved") }
        catch let error as CheckFailure { throw error } catch { }
        try check(Data(contentsOf: URL(fileURLWithPath: path)) == bytes, "Busy producer check changed diagnostic bytes")
    }
    let staleEngine = try f.engine(rules: [AIDiagnosticRule.name]), staleReport = try await staleEngine.scanJunk()
    guard let staleItem = staleReport.selectableCandidates(includeUserData: false).first(where: { $0.path == path }) else { throw CheckFailure("Diagnostic fixture missing before stale-plan check") }
    let stalePlan = try await staleEngine.makePlan(reportID: staleReport.id, selected: [staleItem.id], includeUserData: false)
    try newer.write(to: URL(fileURLWithPath: path))
    do { _ = try await staleEngine.execute(planID: stalePlan.id); throw CheckFailure("Changed diagnostic file moved under an old plan") }
    catch let error as CheckFailure { throw error } catch { }
    try check(Data(contentsOf: URL(fileURLWithPath: path)) == newer, "Stale diagnostic plan changed new bytes")
    print("PASS a producer started after review and changed diagnostic content both veto execution")
    try f.finish()
}

/// Each sample represents a concrete unsafe widening of the fixed diagnostic
/// rule. The external sentinel proves that link rejection never follows it.
@MainActor private func aiDiagnosticRuleGuards(f: OwnedFixture, path: String, bytes: Data) throws {
    let root = f.home + "/.codex/log", outside = f.home + "/outside-diagnostic-sentinel"
    try Data("Private external data\n".utf8).write(to: URL(fileURLWithPath: outside))
    let outsideIdentity = try SafeDirectory(path: f.home).identity("outside-diagnostic-sentinel")
    let outsideBytes = try Data(contentsOf: URL(fileURLWithPath: outside))
    _ = try AIDiagnosticRule.verify(path: path, home: f.home)
    for excluded in [root, path + ".1", path + ".gz", root + "/other.log", path + "/child", root + "/nested/codex-tui.log", root + "/../codex-tui.log", f.home + "/.codex//log/codex-tui.log", f.home + "/.codex/auth.json", f.home + "/.codex/history.jsonl", f.home + "/.codex/state_5.sqlite", f.home + "/.codex/sessions/codex-tui.log", f.home + "/.codex/config.toml", f.home + "/.codex/plugins/codex-tui.log", f.home + "/.gemini/tmp/codex-tui.log"] {
        try check(!AIDiagnosticRule.matches(path: excluded, home: f.home), "Diagnostic matching widened to undocumented logs, rotations or personal state: " + excluded)
    }
    try check(!AIDiagnosticRule.matches(path: path, home: "/") && !AIDiagnosticRule.matches(path: path, home: f.home + "/"), "Diagnostic root accepted a noncanonical home")
    try fm.moveItem(atPath: path, toPath: f.home + "/held-diagnostic")
    try check(AIDiagnosticRule.matches(path: path, home: f.home), "Matching requires a live source, breaking recovery")
    try fm.createSymbolicLink(atPath: path, withDestinationPath: outside)
    try reject("Diagnostic symlink is retained") { _ = try AIDiagnosticRule.verify(path: path, home: f.home) }
    try fm.removeItem(atPath: path)
    try fm.createDirectory(atPath: path, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    try reject("Directory named codex-tui.log is retained") { _ = try AIDiagnosticRule.verify(path: path, home: f.home) }
    try fm.removeItem(atPath: path); try fm.moveItem(atPath: f.home + "/held-diagnostic", toPath: path)
    try fm.linkItem(atPath: path, toPath: f.home + "/diagnostic-hardlink")
    try reject("Diagnostic hardlink is retained") { _ = try AIDiagnosticRule.verify(path: path, home: f.home) }
    try fm.removeItem(atPath: f.home + "/diagnostic-hardlink")
    for shared in [path, root, f.home + "/.codex"] {
        let originalMode = try fm.attributesOfItem(atPath: shared)[.posixPermissions] as! NSNumber
        try check(chmod(shared, 0o777) == 0, "Cannot prepare shared diagnostic fixture")
        try reject("Shared diagnostic object or ancestor is retained") { _ = try AIDiagnosticRule.verify(path: path, home: f.home) }
        try check(chmod(shared, mode_t(originalMode.uint32Value)) == 0, "Cannot restore diagnostic fixture permissions")
    }
    for disguised in [Data("SQLite format 3\0private data".utf8), Data([0x37,0x7f,0x06,0x82,0,0,0,0]), Data([0x37,0x7f,0x06,0x83,0,0,0,0])] {
        try disguised.write(to: URL(fileURLWithPath: path))
        try reject("Database or WAL disguised as diagnostics is retained") { _ = try AIDiagnosticRule.verify(path: path, home: f.home) }
    }
    try bytes.write(to: URL(fileURLWithPath: path))
    let held = open(path, O_RDONLY | O_CLOEXEC)
    try check(held >= 0, "Cannot open owned diagnostic occupancy sample")
    do {
        defer { _ = close(held) }
        try reject("Actually opened diagnostic log is retained") { _ = try AIDiagnosticRule.verify(path: path, home: f.home) }
    }
    for command in ["/opt/homebrew/bin/codex", "/usr/local/bin/codex app-server", "/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex app-server", "/Applications/Developer Tools/Codex.app/Contents/MacOS/Codex", "/usr/local/bin/node /opt/lib/node_modules/@openai/codex/bin/codex.js"] {
        try check(AIDiagnosticRule.isProducer(command), "Explicit diagnostic producer was missed")
    }
    for command in ["/usr/bin/python3 unrelated-service.py", "/usr/local/bin/node unrelated-server.js", "/usr/bin/python3 codex_report.py", "/usr/bin/printf codex", "/opt/homebrew/bin/codex-helper"] {
        try check(!AIDiagnosticRule.isProducer(command), "Unrelated interpreter or incidental producer name blocks diagnostics")
    }
    try assertExternal(outside, identity: outsideIdentity, bytes: outsideBytes)
    print("PASS diagnostic path, type, topology, payload, permissions, open-file and producer boundaries")
}

/// Read-only real-home check, separate from synthetic transaction acceptance.
/// This checks activity only; it neither opens nor changes the user's log.
func aiDiagnosticHostChecks() throws {
    let home = try SystemIdentity.home()
    try reject("Running host Codex retains real-home diagnostics without reading the log") {
        try AIDiagnosticRule.ensureStopped(path: home + "/.codex/log/codex-tui.log", home: home)
    }
}
