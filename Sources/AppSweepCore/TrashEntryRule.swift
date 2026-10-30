import Foundation
import CFSafety

/// A whole direct entry already placed in the user's Trash. This is personal
/// data management, not authority to empty a volume or follow an alias.
enum TrashEntryRule {
    static let name = "current-user-trash-entry-v1"
    static let provenance = "当前用户废纸篓中的完整条目；需主动选择，移入恢复区后仍可恢复"
    static func root(home: String) -> String { home + "/.Trash" }
    static func matches(path: String, home: String) -> Bool {
        guard XcodeRule.canonical(home), XcodeRule.canonical(path), home != "/",
              URL(fileURLWithPath: path).deletingLastPathComponent().path == root(home: home) else { return false }
        let leaf = URL(fileURLWithPath: path).lastPathComponent
        return ![".DS_Store", ".localized"].contains(leaf)
    }
    static func verify(path: String, home: String) throws -> FileSnapshot {
        guard matches(path: path, home: home) else { throw SweepError.denied("不是当前用户废纸篓的直接条目") }
        let snapshot = try SafeFilesystem.snapshot(path, purpose: .managedData)
        try verifyContents(snapshot, home: home)
        return snapshot
    }
    /// For an authenticated recovery object. Never authorizes its path itself.
    static func verifyContents(_ snapshot: FileSnapshot, home: String) throws {
        guard as_current_uid() != 0, !snapshot.allowInternalLinks,
              !snapshot.allowInternalHardLinks, !snapshot.allowApplicationHardLinks,
              !snapshot.identity.isLink, !snapshot.tree.contains(where: { $0.identity.isLink }) else {
            throw SweepError.denied("废纸篓条目含链接或未确认的快照能力，整项保留")
        }
        try ContainerDataRule.verifyPrivateTree(snapshot, home: home)
    }
    static func ensureStopped(path: String, home: String) throws {
        guard matches(path: path, home: home) else { throw SweepError.denied("废纸篓活动检查超出当前用户范围") }
        // Trash has no single producer to stop. The shared transaction's
        // BusyInspector checks the selected object immediately before moving,
        // restoring or purging it. This path-only check also works after move.
    }
}
