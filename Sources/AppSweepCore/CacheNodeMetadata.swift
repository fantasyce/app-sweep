import Foundation
import CFSafety
#if os(macOS)
import Darwin
#else
import Glibc
#endif

struct CacheNodeMetadata: Codable, Sendable, Equatable {
    let group: UInt32
    let attributes: Data
    // Missing in older receipts; nil and zero have the same original semantics.
    let flags: UInt32?
    static func read(_ snapshot: FileSnapshot) throws -> Self {
        let result = try read(path: snapshot.path, identity: snapshot.identity)
        try SafeFilesystem.verify(snapshot)
        return result
    }
    static func read(path: String, identity: FileIdentity) throws -> Self {
        let url = URL(fileURLWithPath: path), parent = try SafeDirectory(path: url.deletingLastPathComponent().path)
        var expected = identity.native, group: UInt32 = 0, flags: UInt32 = 0, count = 0
        var attributes = [UInt8](repeating: 0, count: 65_536)
        guard as_cache_node_metadata_with_flags(parent.fd, url.lastPathComponent, &expected, &group, &flags, &attributes, attributes.count, &count) == 0 else { throw SweepError.denied("缓存权限、ACL、标志或扩展属性不能保真备份，整项保留") }
        guard try parent.identity(url.lastPathComponent) == identity else { throw SweepError.stale("读取元数据时缓存对象已改变") }
        return Self(group: group, attributes: Data(attributes.prefix(count)), flags: flags == 0 ? nil : flags)
    }
    func apply(to snapshot: FileSnapshot, original: FileIdentity) throws {
        let url = URL(fileURLWithPath: snapshot.path), parent = try SafeDirectory(path: url.deletingLastPathComponent().path)
        let fd = url.lastPathComponent.withCString { openat(parent.fd, $0, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC) }
        guard fd >= 0 else { throw SweepError.filesystem("无法打开已创建的私有恢复对象") }
        defer { as_close(fd) }
        var expected = snapshot.identity.native, metadata = original.native
        let status = attributes.withUnsafeBytes { as_apply_private_node_metadata_with_flags(fd, &expected, &metadata, group, flags ?? 0, $0.baseAddress, $0.count) }
        guard status == 0, fsync(parent.fd) == 0 else { throw SweepError.filesystem("恢复对象元数据未能保真写入") }
    }
    func apply(toPrivatePath path: String, original: FileIdentity) throws {
        let url = URL(fileURLWithPath: path), parent = try SafeDirectory(path: url.deletingLastPathComponent().path)
        let identity = try parent.identity(url.lastPathComponent)
        // Metadata restoration must not mistake one nested directory for the
        // complete hard-link scope. The C writer accepts only our newly created
        // private node, checks its exact identity and never follows a link.
        try apply(to: FileSnapshot(path: path, identity: identity, ancestors: [], tree: [], bytes: 0, allowInternalLinks: false), original: original)
    }
}
