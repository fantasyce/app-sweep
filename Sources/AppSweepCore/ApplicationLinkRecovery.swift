import Foundation
import CFSafety
#if os(macOS)
import Darwin
import CryptoKit
#endif

/// Original read-only commitments for linked members of a whole application.
/// These permit recovery after alias churn, never execution or permanent purge.
struct ApplicationLinkRecovery: Codable, Sendable {
    struct Member: Codable, Sendable {
        let relative: String
        let identity: FileIdentity
        let digest: String
    }
    let version: Int
    let members: [Member]
    static let maximumMembers = 4096

    static func capture(_ snapshot: FileSnapshot) throws -> Self? {
        guard snapshot.allowApplicationHardLinks else { return nil }
        let linked = snapshot.tree.filter { $0.identity.mode & 0o170000 == 0o100000 && $0.identity.links > 1 }
        guard !linked.isEmpty else { return nil }
        guard linked.count <= maximumMembers else { throw SweepError.incomplete("应用硬链接恢复记录超过容量，整项保留") }
        var digests: [String: String] = [:], members: [Member] = []
        for node in linked {
            let key = ContainedHardLinks.key(node.identity)
            let digest = try digests[key] ?? memberDigest(root: snapshot.path, node: node)
            digests[key] = digest
            members.append(Member(relative: node.relative, identity: node.identity, digest: digest))
        }
        try SafeFilesystem.verify(snapshot)
        return Self(version: 1, members: members)
    }

    func validate(for entry: RecoveryEntry) throws {
        guard version == 1, !members.isEmpty, members.count <= Self.maximumMembers,
              entry.original.category == .application, entry.original.identity?.isDirectory == true,
              [SelectedApplicationRule.name, ChosenApplicationRule.name, ChosenApplicationRule.largeName, "signed-application-v1"].contains(entry.original.rule),
              entry.backupDigest == nil, entry.reconstructedContents == nil,
              Set(members.map(\.relative)).count == members.count else { throw SweepError.denied("应用硬链接恢复证据无效") }
        for member in members {
            let parts = member.relative.split(separator: "/", omittingEmptySubsequences: false)
            guard !member.relative.isEmpty, member.relative.utf8.count < 4096, !member.relative.contains("\0"),
                  parts.count <= 128, parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }),
                  member.identity.mode & 0o170000 == 0o100000, member.identity.links > 1,
                  member.identity.size >= 0, member.identity.sameVolume(as: entry.original.identity!),
                  member.digest.utf8.count == 64, member.digest.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw SweepError.denied("应用硬链接恢复成员无效") }
        }
        if entry.treeFingerprint == nil {
            let linked = entry.contents.filter { $0.identity.mode & 0o170000 == 0o100000 && $0.identity.links > 1 }
            guard linked == members.map({ TreeEntry(relative: $0.relative, identity: $0.identity) }) else { throw SweepError.denied("应用硬链接证据与原目录不一致") }
        }
    }

    func matches(_ snapshot: FileSnapshot, entry: RecoveryEntry) throws -> Bool {
        try validate(for: entry)
        guard snapshot.allowApplicationHardLinks, snapshot.identity.isDirectory else { return false }
        let byPath = Dictionary(uniqueKeysWithValues: members.map { ($0.relative, $0) })
        var normalized: [TreeEntry] = [], seen = Set<String>(), digests: [String: String] = [:]
        for node in snapshot.tree {
            guard let original = byPath[node.relative] else { normalized.append(node); continue }
            let a = node.identity, b = original.identity
            // Only nlink and ctime may differ; all other identity fields remain exact.
            guard a.links >= 1, a.sameVolume(as: b), a.inode == b.inode, a.mode == b.mode,
                  a.owner == b.owner, a.size == b.size, a.modifiedSeconds == b.modifiedSeconds,
                  a.modifiedNanoseconds == b.modifiedNanoseconds else { return false }
            let key = ContainedHardLinks.key(a)
            let digest = try digests[key] ?? Self.memberDigest(root: snapshot.path, node: node)
            digests[key] = digest
            guard digest == original.digest else { return false }
            seen.insert(node.relative)
            normalized.append(TreeEntry(relative: node.relative, identity: b))
        }
        guard seen.count == members.count else { return false }
        let matches = try entry.treeFingerprint?.matches(normalized) ?? (normalized == entry.contents)
        if matches { try SafeFilesystem.verify(snapshot) }
        return matches
    }

    private static func memberDigest(root: String, node: TreeEntry) throws -> String {
        #if os(macOS)
        let url = URL(fileURLWithPath: root + "/" + node.relative)
        let parent = try SafeDirectory(path: url.deletingLastPathComponent().path)
        let fd = url.lastPathComponent.withCString { openat(parent.fd, $0, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC) }
        guard fd >= 0 else { throw SweepError.filesystem("无法读取应用硬链接恢复证据") }
        defer { as_close(fd) }
        func verify() throws {
            var raw = ASIdentity()
            guard as_identity_fd(fd, &raw) == 0, FileIdentity(raw) == node.identity,
                  try parent.identity(url.lastPathComponent) == node.identity else { throw SweepError.stale("应用硬链接读取期间已改变") }
        }
        try verify()
        let metadata = try descriptorMetadata(fd)
        var hash = SHA256()
        hash.update(data: Data("AppSweep application linked member v1\0".utf8))
        hash.update(data: metadata)
        let input = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        var remaining = node.identity.size
        let deadline = ProcessInfo.processInfo.systemUptime + 300
        while remaining > 0 {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw SweepError.incomplete("应用硬链接恢复摘要超时") }
            let chunk = try input.read(upToCount: Int(min(remaining, 256 * 1024))) ?? Data()
            guard !chunk.isEmpty else { throw SweepError.stale("应用硬链接内容被截断") }
            hash.update(data: chunk); remaining -= Int64(chunk.count)
        }
        guard (try input.read(upToCount: 1) ?? Data()).isEmpty,
              try descriptorMetadata(fd) == metadata else { throw SweepError.stale("应用硬链接内容或权限已改变") }
        try verify()
        return hash.finalize().map { String(format: "%02x", $0) }.joined()
        #else
        throw SweepError.denied("当前平台未验收应用硬链接恢复摘要")
        #endif
    }

    #if os(macOS)
    /// Hash permissions not represented by FileIdentity too: group, flags, ACL
    /// and the complete sorted extended-attribute set. Never write through fd.
    private static func descriptorMetadata(_ fd: Int32) throws -> Data {
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw SweepError.filesystem("应用文件权限读取失败") }
        var output = Data()
        func append(_ data: Data) {
            var size = UInt64(data.count).littleEndian
            withUnsafeBytes(of: &size) { output.append(contentsOf: $0) }; output.append(data)
        }
        append(Data("\(info.st_gid):\(info.st_flags)".utf8))
        errno = 0
        if let acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED) {
            defer { acl_free(UnsafeMutableRawPointer(acl)) }
            var length = 0
            guard let text = acl_to_text(acl, &length) else { throw SweepError.denied("应用 ACL 未确认") }
            defer { acl_free(text) }
            guard length >= 0, length <= 65536 else { throw SweepError.denied("应用 ACL 超过容量") }
            append(Data(bytes: text, count: length))
        } else {
            guard errno == ENOENT else { throw SweepError.denied("应用 ACL 读取失败") }
            append(Data())
        }
        var names = [CChar](repeating: 0, count: 65536)
        let length = flistxattr(fd, &names, names.count, 0)
        guard length >= 0 else { throw SweepError.denied("应用扩展属性读取失败") }
        let raw = names.prefix(length).map { UInt8(bitPattern: $0) }
        let keys = raw.split(separator: 0).map { Array($0) }.sorted { $0.lexicographicallyPrecedes($1) }
        guard keys.reduce(0, { $0 + $1.count + 1 }) == length else { throw SweepError.denied("应用扩展属性名称无效") }
        for key in keys {
            let name = key.map { CChar(bitPattern: $0) } + [0]
            let size = name.withUnsafeBufferPointer { fgetxattr(fd, $0.baseAddress!, nil, 0, 0, 0) }
            guard size >= 0, size <= 65536, output.count + size + key.count <= 1_048_576 else { throw SweepError.denied("应用扩展属性超过恢复容量") }
            var value = [UInt8](repeating: 0, count: max(1, size))
            let read = name.withUnsafeBufferPointer { fgetxattr(fd, $0.baseAddress!, &value, size, 0, 0) }
            guard read == size else { throw SweepError.stale("应用扩展属性读取期间已改变") }
            append(Data(key)); append(Data(value.prefix(size)))
        }
        return output
    }
    #endif
}
