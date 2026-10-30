import Foundation
import CFSafety
#if canImport(CryptoKit)
import CryptoKit
#endif
#if os(macOS)
import Darwin
#else
import Glibc
#endif

struct StreamedCopy: Sendable {
    let identity: FileIdentity
    let digest: String
}

/// Streaming primitive for independent cache archives, not an execution rule.
enum VerifiedFileStream {
    static func copy(_ source: FileSnapshot, into directory: SafeDirectory, name: String) throws -> StreamedCopy {
        guard UUID(uuidString: name)?.uuidString == name, as_private_descriptor(directory.fd) == 1,
              try directory.ownIdentity.device == source.identity.device else { throw SweepError.denied("独立副本必须在同卷私有目录内独占创建") }
        try validate(source)
        try SafeFilesystem.verify(source)
        guard directory.availableBytes > UInt64(source.identity.size) + CacheBackup.freeSpaceReserve else { throw SweepError.denied("独立副本空间不足，未创建输出") }
        let fd = name.withCString { openat(directory.fd, $0, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600) }
        guard fd >= 0 else { throw SweepError.filesystem("独立副本目标已存在或无法安全创建") }
        let output = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        defer { as_close(fd) }
        // Failed or interrupted writes remain attributable to the caller's
        // durable intent. Never remove an uncertain object automatically.
        let digest = try consume(source) { try output.write(contentsOf: $0) }
        try output.synchronize()
        #if os(macOS)
        guard fcntl(fd, F_FULLFSYNC) == 0 else { throw SweepError.filesystem("独立副本未能完整同步") }
        #endif
        var raw = ASIdentity()
        guard as_identity_fd(fd, &raw) == 0, raw.size == source.identity.size,
              raw.owner == as_current_uid(), raw.links == 1, raw.mode & 0o7777 == 0o600,
              fsync(directory.fd) == 0 else { throw SweepError.stale("独立副本身份或目录同步失败") }
        let identity = FileIdentity(raw)
        guard try directory.identity(name) == identity else { throw SweepError.stale("独立副本路径已被替换") }
        return StreamedCopy(identity: identity, digest: digest)
    }
    static func digest(_ source: FileSnapshot) throws -> String {
        try consume(source) { _ in }
    }
    /// Read-only comparison of a file whose owner was independently bound by
    /// the caller. This does not grant copying or any mutation across owners.
    static func digest(_ source: FileSnapshot, ownedBy owner: UInt32) throws -> String {
        try consume(source, owner: owner) { _ in }
    }
    private static func validate(_ source: FileSnapshot, owner: UInt32 = as_current_uid()) throws {
        guard source.identity.mode & 0o170000 == 0o100000, source.identity.owner == owner,
              (source.identity.links == 1 || source.hardLinkContext != nil), source.identity.size >= 0, source.tree.isEmpty else { throw SweepError.denied("流式来源必须是当前用户的独立普通文件或已确认闭合的缓存引用") }
    }
    private static func consume(_ source: FileSnapshot, owner: UInt32 = as_current_uid(), body: (Data) throws -> Void) throws -> String {
        #if canImport(CryptoKit)
        try validate(source, owner: owner)
        try SafeFilesystem.verify(source)
        let url = URL(fileURLWithPath: source.path), parent = try SafeDirectory(path: url.deletingLastPathComponent().path)
        let fd = url.lastPathComponent.withCString { openat(parent.fd, $0, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC) }
        guard fd >= 0 else { throw SweepError.filesystem("无法安全打开流式来源") }
        defer { as_close(fd) }
        var raw = ASIdentity()
        guard as_identity_fd(fd, &raw) == 0, FileIdentity(raw) == source.identity else { throw SweepError.stale("流式来源身份已改变") }
        let input = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        var remaining = source.identity.size, hash = SHA256()
        let deadline = ProcessInfo.processInfo.systemUptime + 300
        while remaining > 0 {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw SweepError.incomplete("流式副本超时，原对象保留") }
            let chunk = try input.read(upToCount: Int(min(remaining, 256 * 1024))) ?? Data()
            guard !chunk.isEmpty else { throw SweepError.stale("流式来源被截断") }
            hash.update(data: chunk)
            try body(chunk)
            remaining -= Int64(chunk.count)
        }
        guard (try input.read(upToCount: 1) ?? Data()).isEmpty,
              as_identity_fd(fd, &raw) == 0, FileIdentity(raw) == source.identity,
              try parent.identity(url.lastPathComponent) == source.identity else { throw SweepError.stale("流式读取过程中来源已改变") }
        try SafeFilesystem.verify(source)
        return hash.finalize().map { String(format: "%02x", $0) }.joined()
        #else
        throw SweepError.denied("当前平台未验收流式摘要")
        #endif
    }
}
