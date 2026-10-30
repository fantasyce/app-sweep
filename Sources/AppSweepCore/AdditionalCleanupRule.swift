import Foundation
import CFSafety

/// A single dispatch point keeps newly managed personal-data categories on the
/// same scan, execution and recovery rules. A display category grants no access.
enum AdditionalCleanupRule {
    static var names: Set<String> { [TrashEntryRule.name, MailDownloadRule.name, AIStorageRule.name] }
    static func matches(_ item: Candidate, home: String) -> Bool {
        guard item.category == .userData, item.bundleIdentifier == nil,
              item.applicationPath == nil, item.component == nil,
              item.identity?.owner == as_current_uid() else { return false }
        return matches(path: item.path, rule: item.rule, home: home)
    }
    static func matches(path: String, rule: String, home: String) -> Bool {
        switch rule {
        case TrashEntryRule.name: return TrashEntryRule.matches(path: path, home: home)
        case MailDownloadRule.name: return MailDownloadRule.matches(path: path, home: home)
        case AIStorageRule.name: return AIStorageRule.matches(path: path, home: home)
        default: return false
        }
    }
    static func verify(_ item: Candidate, home: String) throws {
        guard matches(item, home: home) else { throw SweepError.denied("资料管理对象的范围或类型未确认") }
        switch item.rule {
        case TrashEntryRule.name: _ = try TrashEntryRule.verify(path: item.path, home: home)
        case MailDownloadRule.name: _ = try MailDownloadRule.verify(path: item.path, home: home)
        case AIStorageRule.name: _ = try AIStorageRule.verify(path: item.path, home: home)
        default: throw SweepError.denied("未登记的资料管理规则")
        }
    }
    static func verifyContents(_ snapshot: FileSnapshot, original: Candidate, home: String) throws {
        guard matches(original, home: home) else { throw SweepError.denied("资料恢复范围未确认") }
        switch original.rule {
        case TrashEntryRule.name: try TrashEntryRule.verifyContents(snapshot, home: home)
        case MailDownloadRule.name: try MailDownloadRule.verifyContents(snapshot, home: home)
        case AIStorageRule.name: try AIStorageRule.verifyContents(snapshot, home: home)
        default: throw SweepError.denied("未登记的资料恢复规则")
        }
    }
    static func ensureStopped(_ item: Candidate, home: String) throws {
        guard matches(item, home: home) else { throw SweepError.denied("资料活动范围未确认") }
        switch item.rule {
        case TrashEntryRule.name: try TrashEntryRule.ensureStopped(path: item.path, home: home)
        case MailDownloadRule.name: try MailDownloadRule.ensureStopped(path: item.path, home: home)
        case AIStorageRule.name: try AIStorageRule.ensureStopped(path: item.path, home: home)
        default: throw SweepError.denied("资料使用状态未确认")
        }
    }
    /// The original object may be absent while isolated, but its destination
    /// must still be private and retain the same semantic owner at restore time.
    static func verifyRestoreDestination(_ item: Candidate, home: String) throws {
        guard matches(item, home: home), let original = item.identity else {
            throw SweepError.denied("资料恢复目标未确认")
        }
        let volume = try SafeDirectory(path: home).ownIdentity
        guard original.sameVolume(as: volume) else { throw SweepError.denied("资料恢复目标跨卷") }
        let parent = URL(fileURLWithPath: item.path).deletingLastPathComponent().path
        for ancestor in try SafeFilesystem.ancestors(of: parent) where SafetyPolicy.contains(home, ancestor.path) {
            let directory = try SafeDirectory(path: ancestor.path), identity = try directory.ownIdentity
            guard identity.owner == as_current_uid(), identity.sameVolume(as: volume),
                  as_unshared_node_descriptor(directory.fd, as_current_uid()) == 1 else {
                throw SweepError.denied("资料恢复目标目录的所有者或共享权限已改变")
            }
        }
        if item.rule == MailDownloadRule.name { try MailDownloadRule.verifyDestination(path: item.path, home: home) }
    }
}
