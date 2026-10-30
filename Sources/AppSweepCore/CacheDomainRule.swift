import Foundation
import CFSafety

/// Apple's regenerable per-application cache namespace. The scanner must also
/// establish a unique signed owner and a complete safe domain before offering it.
enum CacheDomainRule {
    static let name = "cache-exact-domain-v1"
    static func root(home: String, identifier: String) -> String { home + "/Library/Caches/" + identifier }
    static func members(home: String, identifier: String) throws -> Set<String> {
        guard AppInspector.validIdentifier(identifier) else { throw SweepError.denied("缓存域标识无效") }
        return try members(root:root(home:home,identifier:identifier))
    }
    static func members(root path: String) throws -> Set<String> {
        let directory = try SafeDirectory(path: path)
        guard try directory.ownIdentity.owner == as_current_uid() else { throw SweepError.denied("缓存域所有者已改变") }
        var buffer = [UInt8](repeating: 0, count: 2 * 1024 * 1024), count = 0
        guard as_directory_entries(directory.fd, &buffer, buffer.count, 20_000, &count) == 0,
              let text = String(bytes: buffer.prefix(count), encoding: .utf8) else { throw SweepError.incomplete("缓存域成员枚举失败或截断") }
        return Set(text.split(separator: "\0").map { path + "/" + $0 })
    }
    static func matches(path: String, home: String, identifier: String) -> Bool {
        AppInspector.validIdentifier(identifier) && path == URL(fileURLWithPath: path).standardizedFileURL.path &&
        URL(fileURLWithPath: path).deletingLastPathComponent().path == root(home: home, identifier: identifier)
    }
    static func verifyDomain(home: String, identifier: String) throws -> FileSnapshot {
        try verifyDomain(root:root(home:home,identifier:identifier))
    }
    static func verifyPrivateDomain(root path: String, memberLimit: Int = 1000) throws -> FileSnapshot {
        let snapshot=try SafeFilesystem.snapshot(path)
        guard snapshot.identity.isDirectory,snapshot.tree.filter({!$0.relative.contains("/")}).count <= memberLimit else { throw SweepError.denied("缓存不是完整目录或超过核验容量，整组保留") }
        let nodes=[TreeEntry(relative:"",identity:snapshot.identity)] + snapshot.tree
        guard !SupportDomainRule.containsProtectedContent(nodes) else { throw SweepError.denied("缓存包含安全状态，整项保留") }
        let deadline=ProcessInfo.processInfo.systemUptime + 20
        for node in nodes {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw SweepError.incomplete("缓存元数据核验超时") }
            guard node.identity.owner == as_current_uid(),node.identity.mode & 0o022 == 0,
                  node.identity.isDirectory || node.identity.links == 1 else { throw SweepError.denied("缓存含其他所有者、共享写入或硬链接，整项保留") }
            _=try CacheNodeMetadata.read(path:node.relative.isEmpty ? path : path + "/" + node.relative,identity:node.identity)
        }
        try SafeFilesystem.verify(snapshot)
        return snapshot
    }
    static func verifyDomain(root: String) throws -> FileSnapshot {
        let snapshot = try SafeFilesystem.snapshot(root, allowInternalHardLinks: true)
        guard snapshot.identity.isDirectory, snapshot.identity.owner == as_current_uid(),
              snapshot.tree.allSatisfy({ $0.identity.owner == as_current_uid() }),
              !SupportDomainRule.containsProtectedContent(snapshot.tree) else { throw SweepError.denied("缓存域包含其他所有者或安全状态，整项保留") }
        let deadline = ProcessInfo.processInfo.systemUptime + 20
        for entry in snapshot.tree {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw SweepError.incomplete("缓存权限及元数据扫描超时") }
            _ = try CacheNodeMetadata.read(path: snapshot.path + "/" + entry.relative, identity: entry.identity)
        }
        try SafeFilesystem.verify(snapshot)
        return snapshot
    }
    static func verify(path: String, home: String, identifier: String) throws {
        guard matches(path: path, home: home, identifier: identifier), SafetyPolicy(home: home, acceptedPlatform: false).lexicalDenial(path) == nil else { throw SweepError.denied("不是精确应用缓存域的直接子对象") }
        try verifyMember(path:path,root:root(home:home,identifier:identifier),home:home)
    }
    static func verifyMember(path: String, root directory: String, home: String) throws {
        guard path == URL(fileURLWithPath:path).standardizedFileURL.path,
              URL(fileURLWithPath:path).deletingLastPathComponent().path == directory,
              SafetyPolicy.contains(home + "/Library/Caches",directory),
              SafetyPolicy(home:home,acceptedPlatform:false).lexicalDenial(path) == nil else { throw SweepError.denied("不是已核验缓存域的直接子对象") }
        let root = try SafeDirectory(path: directory).ownIdentity
        let snapshot = try SafeFilesystem.snapshot(path, allowInternalHardLinks: true)
        let entries = [TreeEntry(relative: URL(fileURLWithPath: path).lastPathComponent, identity: snapshot.identity)] + snapshot.tree
        guard root.owner == as_current_uid(), root.device == snapshot.identity.device,
              entries.allSatisfy({ $0.identity.owner == as_current_uid() }),
              !SupportDomainRule.containsProtectedContent(entries) else { throw SweepError.denied("缓存对象所有者、卷或安全内容未确认") }
        try SafeFilesystem.verify(snapshot)
    }
}
