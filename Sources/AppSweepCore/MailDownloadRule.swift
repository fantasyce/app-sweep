import Foundation
import CFSafety

/// Mail's opened/downloaded attachment copies may contain user edits. Never
/// inspect, remove or claim regenerability for the live mailbox attachment store.
enum MailDownloadRule {
    static let name = "mail-download-copy-v1"
    static let provenance = "Mail Downloads 中的附件副本；可能含个人编辑，不保证可重新下载，需主动选择"
    static func roots(home: String) -> [String] {
        [home + "/Library/Mail Downloads", home + "/Library/Containers/com.apple.mail/Data/Library/Mail Downloads"]
    }
    static func matches(path: String, home: String) -> Bool {
        XcodeRule.canonical(home) && XcodeRule.canonical(path) && home != "/" &&
        roots(home: home).contains(URL(fileURLWithPath: path).deletingLastPathComponent().path) &&
        UUID(uuidString: URL(fileURLWithPath: path).lastPathComponent) != nil
    }
    static func verify(path: String, home: String) throws -> FileSnapshot {
        try verifyDestination(path: path, home: home)
        let snapshot = try SafeFilesystem.snapshot(path, purpose: .managedData)
        try verifyContents(snapshot, home: home)
        try verifyDestination(path: path, home: home)
        return snapshot
    }
    /// Original destination proof remains required after the selected copy has
    /// moved away. It does not enumerate any other download or live mailbox.
    static func verifyDestination(path: String, home: String) throws {
        guard matches(path: path, home: home) else { throw SweepError.denied("不是已确认位置中的单组邮件下载副本") }
        let device = try SafeDirectory(path: home).ownIdentity.device
        let ancestors = try SafeFilesystem.ancestors(of: URL(fileURLWithPath: path).deletingLastPathComponent().path)
        for ancestor in ancestors where SafetyPolicy.contains(home, ancestor.path) {
            let directory = try SafeDirectory(path: ancestor.path)
            guard ancestor.owner == as_current_uid(), ancestor.device == device,
                  as_unshared_node_descriptor(directory.fd, as_current_uid()) == 1 else {
                throw SweepError.denied("邮件下载目标的所有者、卷或独占权限未确认")
            }
        }
        if path.hasPrefix(home + "/Library/Containers/") {
            let metadata = try SafeFilesystem.snapshot(home + "/Library/Containers/com.apple.mail/.com.apple.containermanagerd.metadata.plist")
            try ContainerDataRule.verifyPrivateTree(metadata, home: home)
            guard let info = try PropertyListSerialization.propertyList(from: SafeFilesystem.readMetadata(metadata.path), format: nil) as? [String: Any],
                  info["MCMMetadataIdentifier"] as? String == "com.apple.mail",
                  info["MCMMetadataContentClass"] as? Int == 2,
                  let user = info["MCMMetadataUserIdentity"] as? [String: Any], user["posixUID"] as? UInt32 == as_current_uid() else {
                throw SweepError.denied("邮件容器的标识或当前用户所有权未确认")
            }
            if let ownership = info["MCMMetadataOwnership"] {
                guard let owner = ownership as? [String: Any], owner["uid"] as? UInt32 == as_current_uid() else {
                    throw SweepError.denied("邮件容器的附加所有权不一致或格式未确认")
                }
            }
            if let associated = info["AssociatedBundleIdentifiers"] {
                guard let ids = associated as? [String], Set(ids) == ["com.apple.mail"] else {
                    throw SweepError.denied("邮件下载位置具有未确认的共享归属")
                }
            }
            try SafeFilesystem.verify(metadata)
        }
        guard try SafeFilesystem.ancestors(of: URL(fileURLWithPath: path).deletingLastPathComponent().path) == ancestors else {
            throw SweepError.stale("邮件下载目标祖先在核验期间改变")
        }
    }
    /// Only validates a previously authenticated recovery object, not location.
    static func verifyContents(_ snapshot: FileSnapshot, home: String) throws {
        guard as_current_uid() != 0, snapshot.identity.isDirectory, !snapshot.tree.isEmpty,
              !snapshot.allowInternalLinks, !snapshot.allowInternalHardLinks, !snapshot.allowApplicationHardLinks,
              !snapshot.tree.contains(where: { $0.identity.isLink }) else {
            throw SweepError.denied("邮件下载组为空、不是目录或包含链接，整组保留")
        }
        try ContainerDataRule.verifyPrivateTree(snapshot, home: home)
    }
    static func ensureStopped(path: String, home: String) throws {
        guard matches(path: path, home: home) else { throw SweepError.denied("邮件活动检查超出下载副本范围") }
        try ActivityInspector.ensureStopped(bundleID: "com.apple.mail", applicationPath: "/System/Applications/Mail.app")
    }
}
