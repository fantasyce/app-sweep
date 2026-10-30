import Foundation
import CFSafety
#if os(macOS)
import Darwin
#else
import Glibc
#endif

/// Exact per-application web storage. These are opt-in user data (including
/// website state and login cookies), never a regenerable-cache designation.
enum ApplicationStorageRule {
    static let name = "application-web-data-v1"
    static func paths(home: String, identifier: String) -> [String] {
        guard AppInspector.validIdentifier(identifier), !identifier.lowercased().hasPrefix("com.apple.") else { return [] }
        return [home + "/Library/HTTPStorages/" + identifier,
                home + "/Library/HTTPStorages/" + identifier + ".binarycookies",
                home + "/Library/WebKit/" + identifier]
    }
    static func matches(path: String, home: String, identifier: String) -> Bool {
        XcodeRule.canonical(path) && paths(home: home, identifier: identifier).contains(path)
            && SafetyPolicy(home: home, acceptedPlatform: false).protectedDenial(path) == nil
    }
    static func kindMatches(_ identity: FileIdentity, path: String) -> Bool {
        path.hasSuffix(".binarycookies")
            ? identity.mode & 0o170000 == 0o100000 && identity.links == 1
            : identity.isDirectory
    }
    static func verify(path: String, home: String, identifier: String) throws {
        guard matches(path: path, home: home, identifier: identifier) else {
            throw SweepError.denied("不是精确应用标识的网页资料目录")
        }
        let snapshot = try SafeFilesystem.snapshot(path)
        guard kindMatches(snapshot.identity, path: path),
              snapshot.identity.owner == as_current_uid(),
              snapshot.tree.allSatisfy({ $0.identity.owner == as_current_uid() }),
              !SupportDomainRule.containsProtectedContent(snapshot.tree) else {
            throw SweepError.denied("网页资料的类型、独占所有者或内容未确认")
        }
        let device = try SafeDirectory(path: home).ownIdentity.device
        for ancestor in snapshot.ancestors where SafetyPolicy.contains(home, ancestor.path) {
            let directory = try SafeDirectory(path: ancestor.path), identity = try directory.ownIdentity
            guard identity.owner == as_current_uid(), identity.device == device,
                  as_unshared_node_descriptor(directory.fd, as_current_uid()) == 1 else {
                throw SweepError.denied("网页资料祖先的所有者、卷或独占写入权限未确认")
            }
        }
        guard snapshot.identity.device == device else { throw SweepError.denied("网页资料跨卷，保留") }
        let deadline = ProcessInfo.processInfo.systemUptime + 20
        for node in [TreeEntry(relative: "", identity: snapshot.identity)] + snapshot.tree {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw SweepError.incomplete("网页资料独占权限核对超时") }
            let target = node.relative.isEmpty ? path : path + "/" + node.relative
            let url = URL(fileURLWithPath: target), parent = try SafeDirectory(path: url.deletingLastPathComponent().path)
            let fd = url.lastPathComponent.withCString { openat(parent.fd, $0, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC) }
            guard fd >= 0 else { throw SweepError.incomplete("网页资料独占权限无法核验") }
            defer { as_close(fd) }
            var identity = ASIdentity()
            guard as_identity_fd(fd, &identity) == 0, FileIdentity(identity) == node.identity,
                  as_unshared_node_descriptor(fd, as_current_uid()) == 1 else {
                throw SweepError.denied("网页资料的身份或独占写入权限未确认")
            }
        }
        try SafeFilesystem.verify(snapshot)
        try BusyInspector.ensureUnused(snapshot)
    }
}
