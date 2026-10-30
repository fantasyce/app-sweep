import Foundation
import CFSafety
#if os(macOS)
import Darwin
#else
import Glibc
#endif

/// Independent user-log rule. The exact application domain is a prerequisite,
/// never a vendor-prefix or display-name match.
enum ApplicationLogRule {
    static let name = "third-party-namespace-log-30d-v1"
    static let currentName = "third-party-user-log-v2"
    static func root(home: String, identifier: String) -> String { home + "/Library/Logs/" + identifier }
    static func matches(path: String, home: String, identifier: String) -> Bool {
        let root = Self.root(home: home, identifier: identifier)
        guard AppInspector.validIdentifier(identifier), SafetyPolicy.contains(root, path), path != root,
              path == URL(fileURLWithPath: path).standardizedFileURL.path,
              path.dropFirst(root.count + 1).split(separator: "/").count <= 64 else { return false }
        return recognizableName(URL(fileURLWithPath: path).lastPathComponent)
    }
    static func recognizableName(_ name: String) -> Bool {
        return name.range(of: #"^.+\.(?:moz_)?log(?:\.[0-9]+)?(?:\.(?:gz|bz2|xz|zip))?$"#, options: .regularExpression) != nil
    }
    static func verify(path: String, home: String, identifier: String, now: Date = Date()) throws {
        guard matches(path: path, home: home, identifier: identifier) else { throw SweepError.denied("不是已确认的应用日志路径") }
        let snapshot = try SafeFilesystem.snapshot(path)
        guard snapshot.identity.mode & 0o170000 == 0o100000, snapshot.identity.owner == as_current_uid(),
              Attribution.oldLog(modified: Date(timeIntervalSince1970: Double(snapshot.identity.modifiedSeconds)), now: now) else { throw SweepError.denied("日志所有者或超过30天的时限未确认，已保留") }
        try SafeFilesystem.verify(snapshot)
    }
    static func currentMatches(path: String, home: String, identifier: String) -> Bool {
        guard AppInspector.validIdentifier(identifier), path == URL(fileURLWithPath:path).standardizedFileURL.path else { return false }
        if matches(path:path,home:home,identifier:identifier) { return true }
        guard URL(fileURLWithPath:path).deletingLastPathComponent().path == home + "/Library/Logs" else { return false }
        let leaf=URL(fileURLWithPath:path).lastPathComponent
        guard leaf.hasPrefix(identifier) else { return false }
        return String(leaf.dropFirst(identifier.count)).range(of:#"^\.log(?:\.[0-9]+)?(?:\.(?:gz|bz2|xz|zip))?$"#,options:.regularExpression) != nil
    }
    static func loosePaths(home: String, identifier: String) throws -> [String] {
        let root=home + "/Library/Logs"
        guard try SafeFilesystem.presence(root) else { return [] }
        let directory=try SafeDirectory(path:root),before=try directory.ownIdentity
        guard before.owner == as_current_uid() else { throw SweepError.denied("日志根目录所有者未确认") }
        var buffer=[UInt8](repeating:0,count:2*1024*1024),count=0
        guard as_directory_entries(directory.fd,&buffer,buffer.count,4096,&count) == 0,
              let text=String(bytes:buffer.prefix(count),encoding:.utf8) else { throw SweepError.incomplete("松散日志枚举失败或截断") }
        guard try directory.ownIdentity == before, try SafeDirectory(path:root).ownIdentity == before else { throw SweepError.stale("日志根目录在枚举期间改变") }
        return text.split(separator:"\0").map { root + "/" + $0 }.filter { currentMatches(path:$0,home:home,identifier:identifier) }.sorted()
    }
    static func verifyCurrent(path: String, home: String, identifier: String) throws {
        guard currentMatches(path:path,home:home,identifier:identifier) else { throw SweepError.denied("不是精确应用标识的日志路径") }
        let snapshot=try SafeFilesystem.snapshot(path)
        guard snapshot.identity.mode & 0o170000 == 0o100000, snapshot.identity.owner == as_current_uid(), snapshot.identity.links == 1 else { throw SweepError.denied("日志类型或独占所有者未确认") }
        _=try CacheNodeMetadata.read(snapshot)
        for ancestor in snapshot.ancestors where SafetyPolicy.contains(home + "/Library/Logs",ancestor.path) {
            let directory=try SafeDirectory(path:ancestor.path)
            guard as_unshared_node_descriptor(directory.fd,as_current_uid()) == 1 else { throw SweepError.denied("日志目录存在共享改写权限，已保留") }
        }
        try verifyLogPayload(snapshot)
        try SafeFilesystem.verify(snapshot)
        try BusyInspector.ensureUnused(snapshot)
    }
    static func verifyLogPayload(_ snapshot:FileSnapshot) throws {
        let path=snapshot.path,prefix:Data
        do {
            let url=URL(fileURLWithPath:path),directory=try SafeDirectory(path:url.deletingLastPathComponent().path)
            let fd=url.lastPathComponent.withCString { openat(directory.fd,$0,O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC) }
            guard fd >= 0 else { throw SweepError.incomplete("日志读取权限未确认") }
            defer { as_close(fd) }
            var raw=ASIdentity()
            guard as_identity_fd(fd,&raw) == 0,FileIdentity(raw) == snapshot.identity else { throw SweepError.stale("日志打开时身份改变") }
            prefix=try FileHandle(fileDescriptor:fd,closeOnDealloc:false).read(upToCount:16) ?? Data()
            guard as_identity_fd(fd,&raw) == 0,FileIdentity(raw) == snapshot.identity,try directory.identity(url.lastPathComponent) == snapshot.identity else { throw SweepError.stale("日志读取时身份改变") }
        }
        let wal=Array(prefix.prefix(4))
        guard prefix != Data("SQLite format 3\0".utf8),wal != [0x37,0x7f,0x06,0x82],wal != [0x37,0x7f,0x06,0x83] else { throw SweepError.denied("日志扩展名对应数据库或日志页，整项保留") }
        try SafeFilesystem.verify(snapshot)
    }
}
