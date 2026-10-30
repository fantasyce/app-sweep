import Foundation
import CFSafety
#if os(macOS)
import Darwin
#else
import Glibc
#endif

/// Personal profile data, offered only by an explicit application-uninstall scan.
/// Runtime metadata and current installation ownership, never a display name,
/// establish the logical target. Stored sources remain engine-internal evidence.
enum ChromiumProfileRule {
    static let name = "chromium-registered-profile-data-v1"
    static func verify(path: String, home: String, identifier: String, applicationPath: String,
                       signaturePath: String?, inventory supplied: [ApplicationIdentity]? = nil,
                       storedSource: String? = nil) throws -> FileSnapshot {
        let value = try ChromiumCacheRule.verifiedNamespace(home:home,identifier:identifier,applicationPath:applicationPath,signaturePath:signaturePath)
        let expected = home + "/Library/Application Support/" + value
        guard path == expected, SafetyPolicy(home:home,acceptedPlatform:false).lexicalDenial(path) == nil else { throw SweepError.denied("资料路径与签名浏览器命名空间不一致") }
        let inventory = try supplied ?? AppInspector.inventory(home:home,selectedApplication:signaturePath == nil ? applicationPath : nil)
        if signaturePath == nil {
            guard AppInspector.uniqueOwner(identifier:identifier,path:applicationPath,inventory:inventory) else { throw SweepError.denied("浏览器资料没有唯一安装主体") }
        } else {
            guard !inventory.contains(where: { $0.bundleIdentifier.isEmpty || $0.bundleIdentifier.lowercased() == identifier.lowercased() }) else { throw SweepError.denied("隔离后存在同标识或未确认安装，资料保留") }
        }
        try ChromiumCacheRule.exclusive(value,app:applicationPath,inventory:inventory)
        let physical = storedSource ?? path, snapshot = try SafeFilesystem.snapshot(physical)
        guard snapshot.identity.isDirectory, snapshot.identity.owner == as_current_uid(),
              snapshot.identity.device == (try SafeDirectory(path:home).ownIdentity).device,
              snapshot.tree.allSatisfy({ $0.identity.owner == as_current_uid() && !$0.identity.isLink }),
              !SupportDomainRule.containsProtectedContent(snapshot.tree) else { throw SweepError.denied("浏览器资料包含共享、链接或安全状态，整项保留") }
        for ancestor in snapshot.ancestors {
            let directory = try SafeDirectory(path:ancestor.path)
            guard as_unshared_node_descriptor(directory.fd,ancestor.owner) == 1 else { throw SweepError.denied("浏览器资料祖先目录存在共享改写权限") }
        }
        for entry in [TreeEntry(relative:"",identity:snapshot.identity)] + snapshot.tree {
            try Task.checkCancellation()
            let path = entry.relative.isEmpty ? physical : physical + "/" + entry.relative
            let url = URL(fileURLWithPath:path), parent = try SafeDirectory(path:url.deletingLastPathComponent().path)
            let fd = url.lastPathComponent.withCString { openat(parent.fd,$0,O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC) }
            guard fd >= 0 else { throw SweepError.denied("浏览器资料文件无法安全核验") }
            defer { as_close(fd) }
            var current = ASIdentity()
            guard as_identity_fd(fd,&current) == 0, FileIdentity(current) == entry.identity,
                  as_unshared_node_descriptor(fd,as_current_uid()) == 1 else { throw SweepError.denied("浏览器资料包含共享权限或未确认身份，整项保留") }
        }
        guard let profiles = ChromiumCacheRule.profiles(data:try ChromiumCacheRule.profileMetadata(physical + "/Local State")) else { throw SweepError.denied("浏览器资料缺少完整配置档注册证据") }
        for profile in profiles {
            let bytes = try ChromiumCacheRule.profileMetadata(physical + "/" + profile + "/Preferences")
            guard let info = try? JSONSerialization.jsonObject(with:bytes) as? [String:Any], info["profile"] is [String:Any] else { throw SweepError.denied("浏览器配置档资料未确认") }
        }
        try SafeFilesystem.verify(snapshot)
        return snapshot
    }
    static func structuralMatch(path: String, home: String) -> Bool {
        let prefix = home + "/Library/Application Support/"
        guard path.hasPrefix(prefix), path == URL(fileURLWithPath:path).standardizedFileURL.path else { return false }
        return ChromiumCacheRule.namespace(info:["CrProductDirName":String(path.dropFirst(prefix.count))]) != nil
    }
    /// Constructed from actual controlled objects, never decoded from a path
    /// override. Also validates already-restored profile dependencies and stops
    /// new-profile conflicts before any dependent cache member can move.
    static func recoverySources(_ manifest: RecoveryManifest, objects: SafeDirectory, home: String) throws -> [String:String] {
        var result: [String:String] = [:]
        for entry in manifest.entries where entry.original.rule == name && entry.state != .purged {
            guard let app = entry.original.applicationPath, let identifier = entry.original.bundleIdentifier,
                  result[app] == nil, let originalIdentity = entry.original.identity else { throw SweepError.denied("浏览器资料恢复依赖重复或缺少身份") }
            let dependentCachePending = manifest.entries.contains { item in
                CacheArchive.supports(item.original.rule) && item.original.applicationPath == app && item.state != .restored && item.state != .purged
            }
            if entry.state == .restored && !dependentCachePending { continue }
            let stored = objects.path + "/" + entry.id.uuidString
            let hasStored = try SafeFilesystem.presence(stored), hasOriginal = try SafeFilesystem.presence(entry.original.path)
            guard hasStored != hasOriginal else { throw SweepError.denied("原资料路径冲突或恢复对象缺失，关联缓存与资料整组保留") }
            let physical = hasStored ? stored : entry.original.path
            let current = try SafeFilesystem.snapshot(physical)
            let identityMatches = hasStored ? (entry.isolatedIdentity.map { current.identity == $0 } ?? current.identity.sameObject(as:originalIdentity)) : current.identity.sameObject(as:entry.isolatedIdentity ?? originalIdentity)
            guard identityMatches, try entry.matchesContents(current) else { throw SweepError.stale("浏览器资料恢复证据的身份或完整内容已改变") }
            var signature: String?
            if let body = manifest.entries.first(where: { $0.original.category == .application && $0.original.path == app && $0.state != .restored && $0.state != .purged }) {
                let path = objects.path + "/" + body.id.uuidString
                if try SafeFilesystem.presence(path) {
                    let snapshot = try SafeFilesystem.snapshot(path,allowInternalLinks:true,purpose:.application,allowApplicationHardLinks:true)
                    guard let expected = body.isolatedIdentity ?? body.original.identity,
                          snapshot.identity.sameObject(as:expected), try body.matchesRestorationContents(snapshot) else { throw SweepError.stale("浏览器隔离主体已改变，不能提供资料归属") }
                    signature = path
                }
            }
            _ = try verify(path:entry.original.path,home:home,identifier:identifier,applicationPath:app,signaturePath:signature,storedSource:physical)
            try SafeFilesystem.verify(current)
            result[app] = physical
        }
        return result
    }
}
