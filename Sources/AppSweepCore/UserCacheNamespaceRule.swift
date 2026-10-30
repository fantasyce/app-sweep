import Foundation
import CFSafety

/// A current user's standard cache namespace. No application identity is
/// invented: the cache-directory contract, whole-tree checks and stricter
/// activity gate are independent of an application's name or installation.
enum UserCacheNamespaceRule {
    static let name = "cache-user-namespace-v1"
    static func namespace(path: String, home: String) -> String? {
        let prefix = home + "/Library/Caches/"
        guard path.hasPrefix(prefix), path == URL(fileURLWithPath:path).standardizedFileURL.path,
              !path.contains("\0"), !path.hasSuffix("/"), !path.contains("//") else { return nil }
        let parts = path.dropFirst(prefix.count).split(separator:"/",omittingEmptySubsequences:false)
        guard parts.count == 2, parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }),
              SafetyPolicy(home:home,acceptedPlatform:false).lexicalDenial(path) == nil else { return nil }
        let leaf = parts[0].lowercased()
        guard leaf != "keychains", !leaf.hasSuffix(".keychain"), !leaf.hasSuffix(".keychain-db"),
              !leaf.contains("appsweep"), !leaf.contains("app-sweep"), !leaf.contains("app sweep") else { return nil }
        return prefix + parts[0]
    }
    static func verifyNamespace(_ path: String, home: String, memberLimit: Int = 1000) throws -> FileSnapshot {
        guard namespace(path:path + "/member",home:home) == path else { throw SweepError.denied("不是当前用户标准缓存目录中的独立命名空间") }
        let cacheRoot = try SafeDirectory(path:home + "/Library/Caches")
        guard try cacheRoot.ownIdentity.owner == as_current_uid(), as_unshared_node_descriptor(cacheRoot.fd,as_current_uid()) == 1 else {
            throw SweepError.denied("缓存根目录的所有者或共享写入权限未确认")
        }
        let snapshot = try CacheDomainRule.verifyPrivateDomain(root:path,memberLimit:memberLimit)
        guard snapshot.identity.device == (try cacheRoot.ownIdentity).device else {
            throw SweepError.denied("缓存命名空间不是同卷普通目录")
        }
        return snapshot
    }
    /// Independent producer declaration defined by the Cache Directory Tagging
    /// Specification. A cache location or application-like name is insufficient.
    static func verifyProducerTag(root: String, home: String) throws {
        guard namespace(path: root + "/CACHEDIR.TAG", home: home) == root,
              !URL(fileURLWithPath: root).lastPathComponent.lowercased().hasPrefix("com.apple.") else {
            throw SweepError.denied("缓存标记不能授权受保护命名空间")
        }
        let path = root + "/CACHEDIR.TAG", snapshot = try SafeFilesystem.snapshot(path)
        guard snapshot.identity.mode & 0o170000 == 0o100000, snapshot.identity.links == 1,
              snapshot.identity.owner == as_current_uid(), snapshot.identity.size >= 43,
              snapshot.identity.size <= 65536 else { throw SweepError.denied("缓存标记不是独立、受限大小的普通文件") }
        let bytes = try SafeFilesystem.readMetadata(path, maximumBytes: 65536)
        guard bytes.starts(with: Data("Signature: 8a477f597d28d172789f06886806bc55".utf8)),
              String(data: bytes, encoding: .utf8) != nil else { throw SweepError.denied("生产者缓存标记未确认") }
        try SafeFilesystem.verify(snapshot)
    }
    static func verify(path: String, home: String) throws {
        guard let root=namespace(path:path,home:home) else { throw SweepError.denied("不是已登记缓存命名空间的直接子对象") }
        _ = try verifyNamespace(root,home:home)
        try CacheDomainRule.verifyMember(path:path,root:root,home:home)
    }
}
