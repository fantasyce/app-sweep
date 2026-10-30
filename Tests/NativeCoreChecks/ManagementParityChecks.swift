import Foundation
import Darwin
@testable import AppSweepCore

/// All inputs are manufactured inside this run's registered UUID home. These
/// exercise the production scan/plan/execute/recovery path, never legacy scan.
@MainActor func managementParityChecks() async throws {
    let f = try OwnedFixture()
    let rules: Set<String> = ["document-history-versions-v1", "corrupt-preference-file-v1", "local-device-backup-v1", "stale-user-launch-agent-v1", "xcode-archive-management-v1", "xcode-device-symbols-v1"]
    func directory(_ path: String) throws {
        try fm.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }
    func plist(_ value: [String: Any], _ path: String) throws {
        try PropertyListSerialization.data(fromPropertyList: value, format: .binary, options: 0).write(to: URL(fileURLWithPath: path))
    }
    let backupID = "00008020-0011223344556677"
    let backup = f.home + "/Library/Application Support/MobileSync/Backup/" + backupID
    let archive = f.home + "/Library/Developer/Xcode/Archives/2026-10-30/Owned.xcarchive"
    let symbolVersion = f.home + "/Library/Developer/Xcode/iOS DeviceSupport/17.2 (21C62)"
    let symbols = symbolVersion + "/Symbols"
    let preferences = f.home + "/Library/Preferences/" + f.identifier + ".plist"
    let agentLabel = "org.example.nativeparity.stale." + UUID().uuidString.lowercased()
    let agent = f.home + "/Library/LaunchAgents/" + agentLabel + ".plist"
    let document = URL(fileURLWithPath: f.home + "/Documents/Owned History.txt")
    for path in [backup, archive + "/Products", symbols + "/usr/lib", f.home + "/Library/Preferences", f.home + "/Library/LaunchAgents", f.home + "/Documents"] { try directory(path) }
    try plist(["Device Name": "Owned iPhone", "Unique Identifier": backupID, "Product Type": "iPhone15,2", "Last Backup Date": Date(timeIntervalSince1970: 1700000000)], backup + "/Info.plist")
    try plist(["SnapshotState": "finished", "Version": "3.3", "Date": Date(timeIntervalSince1970: 1700000000), "BackupState": "new"], backup + "/Status.plist")
    try plist(["IsEncrypted": false, "Version": "9.1"], backup + "/Manifest.plist")
    try (Data("SQLite format 3\0".utf8) + Data(repeating: 0, count: 64)).write(to: URL(fileURLWithPath: backup + "/Manifest.db"))
    try plist(["ArchiveVersion": 2, "CreationDate": Date(), "Name": "Owned", "SchemeName": "Owned"], archive + "/Info.plist")
    try Data("independent archived product".utf8).write(to: URL(fileURLWithPath: archive + "/Products/data"))
    // Use a native Mach-O already present in this owned fixture; no compiler or
    // actual installed Xcode/device producer is invoked by this check.
    try fm.copyItem(atPath: f.binary, toPath: symbols + "/usr/lib/libOwned.dylib")
    let imageBytes = Data("developer image must remain".utf8)
    try imageBytes.write(to: URL(fileURLWithPath: symbolVersion + "/DeveloperDiskImage.dmg"))
    let damagedBytes = Data("<?xml version=\"1.0\"?><plist><dict><key>broken</key>".utf8)
    try damagedBytes.write(to: URL(fileURLWithPath: preferences))
    try plist(["Label": agentLabel, "ProgramArguments": [f.home + "/Applications/Missing.app/Contents/MacOS/owned"], "RunAtLoad": false], agent)
    let currentBytes = Data("current document remains".utf8), historyBytes = Data("old document history".utf8)
    let historical = URL(fileURLWithPath: f.home + "/owned-history-payload.txt")
    try currentBytes.write(to: document); try historyBytes.write(to: historical)
    _ = try NSFileVersion.addOfItem(at: document, withContentsOf: historical, options: [])
    defer { try? NSFileVersion.removeOtherVersionsOfItem(at: document) }
    let expected = [backup: "local-device-backup-v1", archive: "xcode-archive-management-v1", symbols: "xcode-device-symbols-v1", preferences: "corrupt-preference-file-v1", agent: "stale-user-launch-agent-v1", document.path: "document-history-versions-v1"]
    let engine = try f.engine(rules: rules)
    let report = try await engine.scanJunk()
    for (path, rule) in expected {
        guard let candidate = report.candidates.first(where: { $0.path == path && $0.rule == rule }) else {
            throw CheckFailure("Production scan omitted manual management: " + rule + "; " + report.issues.joined(separator: "; "))
        }
        try check(candidate.userData && !candidate.selectedByDefault, "Personal management became default garbage: " + rule)
        try check(report.selectableCandidates(includeUserData: true).contains(where: { $0.id == candidate.id }), "Verified manual management not selectable: " + rule + ": " + (candidate.retentionReason ?? "unconfirmed scope"))
    }
    let items = report.candidates.filter { expected[$0.path] == $0.rule }
    let ids = Set(items.map(\.id))
    try check(items.count == 6 && Set(items.map(\.path)).count == 6, "Management candidates duplicate or overlap")
    try check(report.selectableCandidates(includeUserData: false).allSatisfy { !ids.contains($0.id) }, "Default selection contains personal management")
    do {
        _ = try await engine.makePlan(reportID: report.id, selected: ids, includeUserData: false)
        throw CheckFailure("Personal-management opt-in bypassed")
    } catch let error as CheckFailure { throw error } catch { }
    print("PASS production scan exposes all six manual management rules; default selection and plan exclude personal data")

    let original = try Dictionary(uniqueKeysWithValues: [backup, archive, symbols, preferences, agent, document.path].map { ($0, try SafeFilesystem.snapshot($0).identity) })
    let plan = try await engine.makePlan(reportID: report.id, selected: ids, includeUserData: true)
    let isolated = try await engine.execute(planID: plan.id)
    try check(isolated.status == .isolated, "Manual management isolation failed: " + (isolated.issue ?? "") + isolated.entries.compactMap(\.message).joined(separator: "; "))
    for path in [backup, archive, symbols, preferences, agent] { try check(!fm.fileExists(atPath: path), "Selected management object not isolated") }
    try check(Data(contentsOf: document) == currentBytes && NSFileVersion.otherVersionsOfItem(at: document)?.isEmpty == true, "History management changed current document or retained selected history")
    try check(Data(contentsOf: URL(fileURLWithPath: symbolVersion + "/DeveloperDiskImage.dmg")) == imageBytes && fm.fileExists(atPath: f.app), "Management moved an unrelated image/application")
    try directory(backup)
    let regenerated = Data("regenerated backup must survive recovery".utf8)
    try regenerated.write(to: URL(fileURLWithPath: backup + "/regenerated.txt"))
    let conflict = try await f.engine(rules: rules).restore(batchID: isolated.id)
    try check(conflict.status == .needsAttention && Data(contentsOf: URL(fileURLWithPath: backup + "/regenerated.txt")) == regenerated, "Management recovery overwrote a regenerated backup")
    try fm.moveItem(atPath: backup, toPath: f.home + "/regenerated-backup")
    let restored = try await f.engine(rules: rules).restore(batchID: isolated.id)
    try check(restored.status == .restored, "Fresh-engine management restore failed: " + (restored.issue ?? "") + restored.entries.compactMap(\.message).joined(separator: "; "))
    for path in [backup, archive, symbols, preferences, agent, document.path] {
        try check(SafeFilesystem.snapshot(path).identity.inode == original[path]?.inode, "Management recovery changed original identity: " + path)
    }
    try check(Data(contentsOf: URL(fileURLWithPath: preferences)) == damagedBytes, "Corrupt-preference recovery changed original bytes")
    try check(Data(contentsOf: document) == currentBytes, "History recovery changed current document")
    let histories = NSFileVersion.otherVersionsOfItem(at: document) ?? []
    try check(histories.count == 1, "History recovery did not restore one version")
    var coordination: NSError?, historicalBytes: Data?, historicalError: Error?
    NSFileCoordinator(filePresenter: nil).coordinate(readingItemAt: histories[0].url, options: [], error: &coordination) { url in
        do { historicalBytes = try Data(contentsOf: url) } catch { historicalError = error }
    }
    if let coordination { throw coordination }; if let historicalError { throw historicalError }
    try check(historicalBytes == historyBytes, "History recovery changed original version bytes")
    print("PASS all six manual rules complete production plan/isolation/fresh recovery; backup conflict, current document, application and device image survive")

    let second = try await engine.scanJunk()
    guard let backupItem = second.selectableCandidates(includeUserData: true).first(where: { $0.path == backup }) else { throw CheckFailure("Restored backup missing from production scan") }
    let changedPlan = try await engine.makePlan(reportID: second.id, selected: [backupItem.id], includeUserData: true)
    try plist(["SnapshotState": "uploading", "Version": "3.3"], backup + "/Status.plist")
    do {
        _ = try await engine.execute(planID: changedPlan.id)
        throw CheckFailure("Changed backup metadata used stale production plan")
    } catch let error as CheckFailure { throw error } catch { }
    try check(fm.fileExists(atPath: backup), "Changed backup moved before execution recheck")
    let blocked = try await engine.scanJunk()
    try check(!blocked.selectableCandidates(includeUserData: true).contains { $0.path == backup }, "Incomplete backup became selectable")
    try check(Data(contentsOf: document) == currentBytes, "Negative checks changed unrelated document")
    print("PASS changed/incomplete backup remains in place after production plan recheck")
    try NSFileVersion.removeOtherVersionsOfItem(at: document)
    try f.finish()
}
