import Foundation
import CryptoKit
import Darwin
@testable import AppSweepCore

/// Runs existing producers with empty configuration, fixed public package input,
/// and OS-enforced writes confined to the fresh fixture. Never installs an app.
@MainActor func genericProducerChecks() async throws {
    let env = ProcessInfo.processInfo.environment
    guard let node = env["APP_SWEEP_NODE_EXECUTABLE"], fm.isExecutableFile(atPath: node),
          let npm = env["APP_SWEEP_NPM_CLI"], fm.fileExists(atPath: npm),
          let pnpm = env["APP_SWEEP_PNPM_CLI"], fm.fileExists(atPath: pnpm),
          let work = env["APP_SWEEP_TEST_WORK_ROOT"], XcodeRule.canonical(work) else {
        throw CheckFailure("Explicit existing npm/pnpm/node and owned evidence root required")
    }
    for tool in ["npm", "pnpm"] {
        let f = try OwnedFixture(), producer = f.home + "/producer"
        let evidence = work + "/producer-evidence-" + tool + "-" + URL(fileURLWithPath: f.home).lastPathComponent
        for path in [producer + "/project", producer + "/tmp", producer + "/config", producer + "/store", producer + "/state", evidence] {
            try fm.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
        let project = producer + "/project"
        try Data("{\"name\":\"appsweep-owned-producer-check\",\"version\":\"1.0.0\",\"private\":true}".utf8).write(to: URL(fileURLWithPath: project + "/package.json"))
        for config in ["user.npmrc", "global.npmrc"] {
            try Data("registry=https://registry.npmjs.org/\nupdate-notifier=false\n".utf8).write(to: URL(fileURLWithPath: producer + "/" + config))
        }
        let quoted = String(data: try JSONSerialization.data(withJSONObject: f.home, options: [.fragmentsAllowed]), encoding: .utf8)!
        let profile = producer + "/producer.sb"
        try Data(("(version 1)\n(allow default)\n(deny file-write*)\n(allow file-write* (subpath " + quoted + ") (literal \"/dev/null\") (literal \"/dev/tty\"))\n").utf8).write(to: URL(fileURLWithPath: profile))
        let wrapper = producer + "/run.sh"
        let quotedProject = "'" + project.replacingOccurrences(of: "'", with: "'\\''") + "'"
        try Data(("#!/bin/sh\nset -eu\ncd " + quotedProject + "\nexec \"$@\"\n").utf8).write(to: URL(fileURLWithPath: wrapper))
        let cache = tool == "npm" ? f.home + "/.npm" : f.home + "/Library/Caches/pnpm"
        let packages = tool == "npm" ? ["is-number@7.0.0"] : ["is-number@7.0.0", "typescript@5.9.3"]
        let environment = ["-i", "PATH=/opt/homebrew/bin:/usr/bin:/bin", "CI=true",
            "TMPDIR=" + producer + "/tmp", "XDG_CONFIG_HOME=" + producer + "/config",
            "XDG_DATA_HOME=" + producer + "/state", "XDG_CACHE_HOME=" + producer + "/temporary-cache",
            "npm_config_userconfig=" + producer + "/user.npmrc", "npm_config_globalconfig=" + producer + "/global.npmrc",
            "npm_config_update_notifier=false", "npm_config_ignore_scripts=true", "NO_UPDATE_NOTIFIER=1", "NODE_DISABLE_COMPILE_CACHE=1"]
        func produce(_ pass: Int, offline: Bool) throws {
            let lock = project + "/pnpm-lock.yaml"
            if tool == "pnpm", fm.fileExists(atPath: lock) { try fm.removeItem(atPath: lock) }
            let arguments: [String]
            if tool == "npm" {
                arguments = [node, npm, "--cache", cache, "--ignore-scripts", "--no-audit", "--no-fund",
                    offline ? "--offline" : "--prefer-online", "cache", "add"] + packages
            } else {
                arguments = [node, pnpm, "add", "--dir", project, "--cache-dir", cache, "--store-dir", producer + "/store",
                    "--config.state-dir=" + producer + "/state",
                    "--ignore-workspace", "--reporter=append-only", "--lockfile-only", "--ignore-scripts"]
                    + (offline ? ["--offline"] : []) + packages
            }
            let output = try BoundedProcess.capture("/usr/bin/env",
                arguments: environment + ["/usr/bin/sandbox-exec", "-f", profile, "/bin/sh", wrapper] + arguments,
                timeout: 30, mergeStderr: true)
            try Data(output.text.utf8).write(to: URL(fileURLWithPath: evidence + "/producer-" + String(pass) + ".log"))
            try check(output.status == 0, tool + " producer failed: " + String(output.text.prefix(3000)))
        }
        try produce(1, offline: false)
        let rule = tool == "npm" ? "development-npm-cache-v1" : "development-pnpm-metadata-v1"
        let engine = try f.engine(rules: [rule]), report = try await engine.scanJunk()
        let items = report.selectableCandidates(includeUserData: false).filter {
            $0.rule == rule && (tool != "npm" || $0.path.hasPrefix(cache + "/_cacache/"))
        }
        try check(!items.isEmpty && (tool != "npm" || items.count == 2), "Real producer caches missing: " + report.candidates.compactMap(\.retentionReason).joined(separator: "; "))
        let originals = try items.map { try SafeFilesystem.snapshot($0.path) }
        let digests = try items.map { item in
            try SafeFilesystem.snapshot(item.path).tree.filter { !$0.identity.isDirectory }.map { entry in
                let bytes = try Data(contentsOf: URL(fileURLWithPath: item.path + "/" + entry.relative))
                return entry.relative + ":" + SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
            }.sorted()
        }
        let plan = try await engine.makePlan(reportID: report.id, selected: Set(items.map(\.id)), includeUserData: false)
        let batch = try await engine.execute(planID: plan.id)
        try check(batch.status == .isolated, tool + " isolation failed: " + (batch.issue ?? ""))
        try produce(2, offline: false)
        for (i, item) in items.enumerated() {
            try check(SafeFilesystem.snapshot(item.path).identity.inode != originals[i].identity.inode, "Producer did not regenerate isolated cache")
        }
        let conflict = try await f.engine(rules: [rule]).restore(batchID: batch.id)
        try check(conflict.status == .needsAttention, tool + " recovery overwrote regenerated cache")
        for (i, item) in items.enumerated() {
            try fm.moveItem(atPath: item.path, toPath: producer + "/regenerated-" + String(i))
        }
        let restored = try await f.engine(rules: [rule]).restore(batchID: batch.id)
        try check(restored.status == .restored, tool + " fresh-engine restore failed: " + (restored.issue ?? ""))
        for (i, item) in items.enumerated() {
            let now = try SafeFilesystem.snapshot(item.path)
            try check(now.identity.inode == originals[i].identity.inode && now.tree == originals[i].tree, "Producer recovery changed original identity/contents")
            let currentDigests = try now.tree.filter { !$0.identity.isDirectory }.map { entry in
                let bytes = try Data(contentsOf: URL(fileURLWithPath: item.path + "/" + entry.relative))
                return entry.relative + ":" + SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
            }.sorted()
            try check(currentDigests == digests[i], "Producer restore changed original bytes")
        }
        try produce(3, offline: true)
        let receipt: [String:Any] = ["producer": tool, "cli": tool == "npm" ? npm : pnpm,
            "packages": packages, "rule": rule, "candidateCount": items.count,
            "relativePaths": items.map { String($0.path.dropFirst(f.home.count)) },
            "originalSHA256": digests,
            "checks": ["generated", "isolated", "regenerated", "conflict-preserved", "fresh-engine-restored", "offline-reused"],
            "writeBoundary": "OS sandbox: fixture home only"]
        try JSONSerialization.data(withJSONObject: receipt, options: [.prettyPrinted, .sortedKeys]).write(to: URL(fileURLWithPath: evidence + "/acceptance.json"))
        print("PASS real " + tool + " generation, native isolation, regeneration, conflict-safe restore and offline reuse")
        print("Producer evidence " + evidence)
        try f.finish()
    }
}
