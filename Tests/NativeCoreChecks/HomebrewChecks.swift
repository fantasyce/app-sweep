import Foundation
import CryptoKit
import Darwin
@testable import AppSweepCore

/// Explicit native producer acceptance; never uses the caller's Homebrew cache.
@MainActor func homebrewChecks() async throws {
    let environment = ProcessInfo.processInfo.environment
    let userHome = try SystemIdentity.home()
    guard let brew = environment["APP_SWEEP_HOMEBREW_EXECUTABLE"],
          XcodeRule.canonical(brew), fm.isExecutableFile(atPath: brew),
          let workRoot = environment["APP_SWEEP_TEST_WORK_ROOT"],
          XcodeRule.canonical(workRoot), workRoot != "/", workRoot != userHome else {
        throw CheckFailure("Explicit existing Homebrew executable and owned work directory required")
    }
    _ = try SafeDirectory(path: workRoot)
    let f = try OwnedFixture(), producer = f.home + "/producer"
    let cache = f.home + "/Library/Caches/Homebrew", downloads = cache + "/downloads"
    let evidence = workRoot + "/evidence-" + URL(fileURLWithPath: f.home).lastPathComponent
    let prefix = producer + "/prefix", wrapper = prefix + "/bin/brew"
    for path in [downloads, prefix + "/bin", producer + "/tmp", producer + "/logs", producer + "/config", evidence] {
        try fm.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }
    try fm.createSymbolicLink(atPath: wrapper, withDestinationPath: brew)
    // Homebrew derives its locks from the invocation prefix, while following the
    // executable link to the existing repository and portable Ruby. The seatbelt
    // profile also prevents unexpected writes anywhere outside this owned home.
    let profile = producer + "/homebrew.sb"
    let quotedHome = String(data: try JSONSerialization.data(withJSONObject: f.home, options: [.fragmentsAllowed]), encoding: .utf8)!
    try Data(("(version 1)\n(allow default)\n(deny file-write*)\n(allow file-write* (subpath " + quotedHome + ") (literal \"/dev/null\") (literal \"/dev/tty\"))\n").utf8).write(to: URL(fileURLWithPath: profile))
    let revision = "3e3da86e4eaccd23f4ce43df9b0a31b16c707347"
    let url = "https://raw.githubusercontent.com/Homebrew/brew/" + revision + "/Library/Homebrew/test/support/fixtures/tarballs/testball-0.1.tbz"
    let expectedDigest = "91e3f7930c98d7ccfb288e115ed52d06b0e5bc16fec7dce8bdda86530027067b"
    let formula = producer + "/appsweep-closeout-cache.rb"
    try Data("""
    class AppsweepCloseoutCache < Formula
      desc "Task-owned native cache acceptance; fetch only"
      homepage "https://github.com/Homebrew/brew"
      url "\(url)"
      version "0.1"
      sha256 "\(expectedDigest)"
      def install
        odie "This acceptance formula must never be installed"
      end
    end
    """.utf8).write(to: URL(fileURLWithPath: formula))
    let producerEnvironment = ["-i", "HOME=" + userHome, "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
        "TMPDIR=" + producer + "/tmp", "XDG_CONFIG_HOME=" + producer + "/config",
        "HOMEBREW_CACHE=" + cache, "HOMEBREW_TEMP=" + producer + "/tmp", "HOMEBREW_LOGS=" + producer + "/logs",
        "HOMEBREW_NO_AUTO_UPDATE=1", "HOMEBREW_NO_INSTALL_FROM_API=1", "HOMEBREW_AUTOMATICALLY_SET_NO_INSTALL_FROM_API=1",
        "HOMEBREW_NO_ANALYTICS=1",
        "HOMEBREW_NO_BOOTSNAP=1", "HOMEBREW_NO_ENV_HINTS=1", "HOMEBREW_DEVELOPER=1", "HOMEBREW_CURL_RETRIES=0"]
    func produce(_ pass: Int) throws {
        let result = try BoundedProcess.capture("/usr/bin/env", arguments: producerEnvironment +
            ["/usr/bin/sandbox-exec", "-f", profile, wrapper, "fetch", "--formula", "--build-from-source", formula],
            timeout: 30, mergeStderr: true)
        try Data(result.text.utf8).write(to: URL(fileURLWithPath: evidence + "/fetch-" + String(pass) + ".log"))
        try check(result.status == 0, "Homebrew fetch failed: " + String(result.text.prefix(4096)))
    }
    func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    try Data(("fixture=" + f.home + "\nproducer=" + brew + "\nurl=" + url + "\nsha256=" + expectedDigest + "\n").utf8)
        .write(to: URL(fileURLWithPath: evidence + "/source.txt"))
    try produce(1)
    let children = try XcodeArchiveRule.children(downloads)
    try check(children.count == 1, "Expected one small completed Homebrew download")
    let path = downloads + "/" + children[0], bytes = try Data(contentsOf: URL(fileURLWithPath: path))
    try check(bytes.count == 1318 && digest(bytes) == expectedDigest, "Homebrew did not fetch the pinned archive")
    let original = try ToolCacheRule.verify(path, home: f.home)
    try check(original.identity.links == 1 && !original.identity.isDirectory, "Native download is not a private regular file")
    print("PASS real Homebrew fetch produced " + children[0] + " bytes=" + String(bytes.count))

    let controlBase = downloads + "/" + String(repeating: "b", count: 64) + "--retained.tbz"
    let incomplete = controlBase + ".incomplete", lock = controlBase + ".lock", temporary = controlBase + ".tmp", unrelated = downloads + "/notes.txt"
    for held in [incomplete, lock, temporary, unrelated] { try Data("owned retained control".utf8).write(to: URL(fileURLWithPath: held)) }
    let general = try await f.engine(rules: [ToolCacheRule.name]).scanJunk()
    try check(!general.selectableCandidates(includeUserData: true).contains { $0.path == path }, "Generic tool rule borrowed Homebrew authority")
    let engine = try f.engine(rules: [ToolCacheRule.homebrewName]), report = try await engine.scanJunk()
    guard let item = report.selectableCandidates(includeUserData: false).first(where: { $0.path == path }) else {
        throw CheckFailure("Native Homebrew download not selectable: " + report.candidates.compactMap(\.retentionReason).joined(separator: "; "))
    }
    try check(item.rule == ToolCacheRule.homebrewName && item.applicationPath == nil && item.bundleIdentifier == nil, "Homebrew provenance or rule changed")
    try check(!report.selectableCandidates(includeUserData: true).contains { [incomplete, lock, temporary, unrelated].contains($0.path) }, "Incomplete or unrelated cache became selectable")
    let plan = try await engine.makePlan(reportID: report.id, selected: [item.id], includeUserData: false)
    let batch = try await engine.execute(planID: plan.id)
    try check(batch.status == .isolated && !fm.fileExists(atPath: path), "Native Homebrew isolation failed: " + (batch.issue ?? ""))
    for held in [incomplete, lock, temporary, unrelated] {
        try check(try Data(contentsOf: URL(fileURLWithPath: held)) == Data("owned retained control".utf8), "Unselected control changed")
    }
    try check(AppInspector.signatureMatches(path: f.app, identifier: f.identifier), "Unselected application changed")
    print("PASS exact Homebrew rule isolates completed file; generic authority and incomplete/control files remain excluded")

    try produce(2)
    let regenerated = try ToolCacheRule.verify(path, home: f.home)
    try check(regenerated.identity.inode != original.identity.inode && Data(contentsOf: URL(fileURLWithPath: path)) == bytes, "Homebrew did not independently regenerate isolated download")
    let conflict = try await f.engine(rules: [ToolCacheRule.homebrewName]).restore(batchID: batch.id)
    try check(conflict.status == .needsAttention, "Recovery overwrote producer-regenerated path")
    try check(SafeFilesystem.snapshot(path).identity.inode == regenerated.identity.inode && Data(contentsOf: URL(fileURLWithPath: path)) == bytes, "Regenerated download changed during recovery conflict")
    let movedRegenerated = producer + "/regenerated-cache.tbz"
    try fm.moveItem(atPath: path, toPath: movedRegenerated)
    let restored = try await f.engine(rules: [ToolCacheRule.homebrewName]).restore(batchID: batch.id)
    try check(restored.status == .restored, "Homebrew recovery failed after owned conflict moved aside: " + (restored.issue ?? ""))
    let actual = try ToolCacheRule.verify(path, home: f.home)
    try check(actual.identity.inode == original.identity.inode && actual.identity.device == original.identity.device &&
        actual.identity.mode == original.identity.mode && actual.identity.links == original.identity.links &&
        Data(contentsOf: URL(fileURLWithPath: path)) == bytes, "Restored Homebrew download lost original identity, permissions, or bytes")
    try produce(3)
    try check(SafeFilesystem.snapshot(path).identity.inode == original.identity.inode && Data(contentsOf: URL(fileURLWithPath: path)) == bytes, "Homebrew failed to reuse the restored download")
    try fm.copyItem(atPath: path, toPath: evidence + "/restored-cache.tbz")
    try fm.copyItem(atPath: movedRegenerated, toPath: evidence + "/regenerated-cache.tbz")
    try fm.copyItem(atPath: formula, toPath: evidence + "/appsweep-closeout-cache.rb")
    let receipt: [String: Any] = ["producer": brew, "sourceURL": url, "sha256": expectedDigest, "bytes": bytes.count,
        "cacheBasename": children[0], "originalInode": original.identity.inode, "regeneratedInode": regenerated.identity.inode,
        "restoredInode": actual.identity.inode, "batchID": batch.id.uuidString, "rule": ToolCacheRule.homebrewName,
        "checks": ["real-fetch", "isolated", "producer-regenerated", "conflict-preserved", "fresh-engine-restored", "producer-reused-restored"]]
    try JSONSerialization.data(withJSONObject: receipt, options: [.prettyPrinted, .sortedKeys]).write(to: URL(fileURLWithPath: evidence + "/acceptance.json"))
    print("PASS Homebrew isolation, producer regeneration, recovery conflict, original-object restore and producer reuse")
    print("Homebrew evidence " + evidence)
    try f.finish()
}
