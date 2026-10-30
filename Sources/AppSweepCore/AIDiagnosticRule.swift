import Foundation
import CFSafety
import AppKit
import Darwin

/// Fixed documented diagnostic producers, not a rule for an AI application's
/// whole state directory. New producers require their own path/format evidence.
enum AIDiagnosticRule {
    static let name = "fixed-ai-producer-diagnostic-v1"
    static let provenance = "官方固定位置的 CLI 诊断日志；需手动选择并正常退出生产工具，不包含会话、配置或数据库"

    private struct Producer: Sendable {
        let directory: String
        let filenames: Set<String>
        let bundleIdentifiers: Set<String>
    }
    private static let producers = [Producer(directory: "/.codex/log", filenames: ["codex-tui.log"],
                                            bundleIdentifiers: ["com.openai.codex", "com.openai.codex.cli"])]
    static func roots(home: String) -> [String] {
        guard XcodeRule.canonical(home), home != "/" else { return [] }
        return producers.map { home + $0.directory }
    }
    private static func producer(path: String, home: String) -> Producer? {
        guard XcodeRule.canonical(home), home != "/", XcodeRule.canonical(path) else { return nil }
        let url = URL(fileURLWithPath: path)
        return producers.first { home + $0.directory == url.deletingLastPathComponent().path && $0.filenames.contains(url.lastPathComponent) }
    }
    /// Deliberately independent of source existence: recovery validates this
    /// original location after the source has moved into the recovery vault.
    static func matches(path: String, home: String) -> Bool { producer(path: path, home: home) != nil }

    /// The source is absent while isolated. Check the current destination
    /// ancestry without inspecting or following any new occupant at its leaf.
    static func verifyRestoreDestination(path: String, home: String) throws {
        guard matches(path: path, home: home), as_current_uid() != 0 else { throw SweepError.denied("诊断日志恢复目标未确认") }
        let volume = try SafeDirectory(path: home).ownIdentity
        let parent = URL(fileURLWithPath: path).deletingLastPathComponent().path
        let before = try SafeFilesystem.ancestors(of: parent)
        for ancestor in before where SafetyPolicy.contains(home, ancestor.path) {
            let directory = try SafeDirectory(path: ancestor.path), identity = try directory.ownIdentity
            guard identity.owner == as_current_uid(), identity.sameVolume(as: volume),
                  as_unshared_node_descriptor(directory.fd, as_current_uid()) == 1 else {
                throw SweepError.denied("诊断日志恢复目标目录的卷、所有者或共享权限已改变")
            }
        }
        guard try SafeFilesystem.ancestors(of: parent) == before else { throw SweepError.stale("诊断日志恢复目标目录在核验期间改变") }
    }

    static func verify(path: String, home: String) throws -> FileSnapshot {
        guard matches(path: path, home: home), as_current_uid() != 0 else { throw SweepError.denied("不是已登记生产者的固定诊断日志") }
        let url = URL(fileURLWithPath: path), parent = try SafeDirectory(path: url.deletingLastPathComponent().path)
        let identity = try parent.identity(url.lastPathComponent)
        guard identity.mode & 0o170000 == 0o100000, identity.owner == as_current_uid(), identity.links == 1 else {
            throw SweepError.denied("诊断日志不是当前账户独占的普通文件")
        }
        let snapshot = try SafeFilesystem.snapshot(path)
        guard snapshot.identity == identity else { throw SweepError.stale("诊断日志在核验期间改变") }
        try ContainerDataRule.verifyPrivateTree(snapshot, home: home)
        _ = try CacheNodeMetadata.read(snapshot)
        try ApplicationLogRule.verifyLogPayload(snapshot)
        try SafeFilesystem.verify(snapshot)
        try BusyInspector.ensureUnused(snapshot)
        return snapshot
    }

    /// These are conservative activity vetoes, never file deletion authority.
    /// The first executable or exact npm entry must identify the producer; a
    /// generic interpreter or an incidental mention of "codex" is insufficient.
    static func isProducer(_ command: String) -> Bool {
        let patterns = [
            #"^(?:[^\s]+/)?codex(?:\s|$)"#,
            #"^/[^\r\n]*\.app/Contents/(?:MacOS/(?:Codex|codex)|Resources/codex)(?:\s|$)"#,
            #"^(?:[^\s]+/)?node(?:js)?\s+(?:[^\s]+/)?node_modules/@openai/codex/bin/codex\.js(?:\s|$)"#
        ]
        return patterns.contains { command.range(of: $0, options: .regularExpression) != nil }
    }
    static func ensureStopped(path: String, home: String) throws {
        guard let producer = producer(path: path, home: home) else { throw SweepError.denied("诊断日志活动检查超出已知范围") }
        let ownPID = ProcessInfo.processInfo.processIdentifier
        let output = try BoundedProcess.run("/bin/ps", arguments: ["-ww", "-axo", "pid=,command="], timeout: 3)
        for process in try ActivityInspector.processes(output, ownPID: ownPID) where process.pid != ownPID {
            try Task.checkCancellation()
            let bundle = NSRunningApplication(processIdentifier: process.pid)?.bundleIdentifier
            let related = isProducer(process.command) || bundle.map(producer.bundleIdentifiers.contains) == true || process.command.contains(home + producer.directory)
            guard related else { continue }
            #if DEBUG
            // Existing native acceptance fixture convention only. This branch
            // cannot scope the real home or a release transaction. The helper
            // checks birth-bound argv/cwd; it does not inspect arbitrary env.
            let fixture = URL(fileURLWithPath: home), base = fixture.deletingLastPathComponent()
            if base.deletingLastPathComponent().path == (try SystemIdentity.home()),
               base.lastPathComponent == "AppSweepAcceptance" || base.lastPathComponent.hasPrefix("AppSweepAcceptance-"),
               UUID(uuidString: fixture.lastPathComponent) != nil,
               !process.command.contains(home), !DownloadCacheActivity.referencesFixture(pid: process.pid, home: home) { continue }
            #endif
            throw SweepError.denied("Codex CLI 或桌面生产工具仍在运行，请正常退出后重新核对诊断日志；App Sweep 不会结束进程")
        }
    }
}
