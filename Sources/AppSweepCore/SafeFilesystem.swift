import Foundation
import CFSafety
#if os(macOS)
import Darwin
#else
import Glibc
#endif

extension FileIdentity {
    init(_ s: ASIdentity) {
        let volume=withUnsafeBytes(of:s.volume_uuid){String(bytes:$0.prefix{$0 != 0},encoding:.utf8)}
        self.init(device: s.device, inode: s.inode, mode: s.mode, owner: s.owner, links: s.links, size: s.size, modifiedSeconds: s.modified_seconds, modifiedNanoseconds: s.modified_nanoseconds, changedSeconds: s.changed_seconds, changedNanoseconds: s.changed_nanoseconds,volumeUUID:volume.flatMap{UUID(uuidString:$0)?.uuidString})
    }
    var native: ASIdentity {
        var value=ASIdentity();value.device=device;value.inode=inode;value.links=links;value.mode=mode;value.owner=owner;value.size=size;value.modified_seconds=modifiedSeconds;value.modified_nanoseconds=modifiedNanoseconds;value.changed_seconds=changedSeconds;value.changed_nanoseconds=changedNanoseconds
        if let volumeUUID,let uuid=UUID(uuidString:volumeUUID)?.uuidString{withUnsafeMutableBytes(of:&value.volume_uuid){$0.copyBytes(from:Array(uuid.utf8)+[0])}}
        return value
    }
    func sameObject(as other: FileIdentity) -> Bool { sameVolume(as:other) && inode == other.inode && mode == other.mode && owner == other.owner && links == other.links && size == other.size && modifiedSeconds == other.modifiedSeconds && modifiedNanoseconds == other.modifiedNanoseconds }
    var isDirectory: Bool { var s = native; return as_is_directory(&s) != 0 }
    var isLink: Bool { var s = native; return as_is_link(&s) != 0 }
}
struct TreeEntry: Codable, Sendable, Equatable { let relative: String; let identity: FileIdentity }
struct AncestorIdentity: Codable, Sendable, Equatable {
    let path:String;let device:UInt64;let inode:UInt64;let mode:UInt32;let owner:UInt32
    var volumeUUID:String? = nil
    static func ==(lhs:Self,rhs:Self)->Bool {
        let sameVolume:Bool
        if let a=lhs.volumeUUID,let b=rhs.volumeUUID{sameVolume=UUID(uuidString:a)?.uuidString == a && UUID(uuidString:b)?.uuidString == b && a == b}
        else{sameVolume=lhs.device == rhs.device}
        return sameVolume && lhs.path == rhs.path && lhs.inode == rhs.inode && lhs.mode == rhs.mode && lhs.owner == rhs.owner
    }
}
enum SnapshotPurpose: Sendable {
    case ordinary, application, managedData
    var maximumEntries: Int { self == .ordinary ? 20_000 : TreeFingerprint.maximumEntries }
    var timeout: TimeInterval { self == .ordinary ? 20 : 300 }
}
struct FileSnapshot: Sendable {
    let path: String
    let identity: FileIdentity
    let ancestors: [AncestorIdentity]
    let tree: [TreeEntry]
    let bytes: Int64
    let allowInternalLinks: Bool
    var purpose: SnapshotPurpose = .ordinary
    var allowInternalHardLinks: Bool = false
    // Whole signed bundles are renamed/unlinked, never edited through an alias.
    // This capability is in-process only; decoded reports cannot request it.
    var allowApplicationHardLinks: Bool = false
    var hardLinkContext: HardLinkContext? = nil
    /// In-process scan commitment for service-managed files. It is never
    /// accepted from a decoded report and does not relax ordinary file moves.
    var contentDigest: String? = nil
}
/// Only an unchanged root object with a changed ctime qualifies. Callers still
/// need an independent metadata commitment before repeating any read.
struct SnapshotRootChange: Error, LocalizedError, Sendable {
    let path: String
    let before: FileIdentity
    let after: FileIdentity
    var errorDescription: String? { "应用根目录元数据仍在变化，两份对象均保留" }
}
final class SafeDirectory {
    let fd: Int32
    let path: String
    init(path: String) throws {
        fd = as_open_directory(path); self.path = path
        guard fd >= 0 else { throw SweepError.filesystem("不能安全打开目录：\(path)") }
        ScanReadActivity.completed()
    }
    private init(fd: Int32, path: String) { self.fd = fd; self.path = path }
    deinit { as_close(fd) }
    /// Borrow the already held directory for a synchronous journal callback.
    /// No path is reopened, and the duplicate has an independent lifetime.
    static func duplicating(_ descriptor:Int32,path:String,expected:FileIdentity)throws->SafeDirectory {
        let copy=fcntl(descriptor,F_DUPFD_CLOEXEC,3)
        guard copy>=0 else{throw SweepError.filesystem("不能复制已核对的日志目录句柄")}
        var identity=ASIdentity()
        guard as_identity_fd(copy,&identity) == 0,identity.device == expected.device,identity.inode == expected.inode,identity.owner == expected.owner,identity.mode == expected.mode,as_private_descriptor(copy) == 1 else{as_close(copy);throw SweepError.stale("日志目录句柄的身份或私有权限改变")}
        return SafeDirectory(fd:copy,path:path)
    }
    func identity(_ name: String) throws -> FileIdentity {
        var s = ASIdentity(); guard as_identity_at(fd, name, &s) == 0 else { throw SweepError.filesystem("对象缺失或无法确认：\(name)") }; ScanReadActivity.completed(); return FileIdentity(s)
    }
    var ownIdentity: FileIdentity { get throws { var s = ASIdentity(); guard as_identity_fd(fd, &s) == 0 else { throw SweepError.filesystem("目录身份读取失败") }; ScanReadActivity.completed(); return FileIdentity(s) } }
    /// Legacy releases used 0755 for this shared parent of backups and settings.
    /// The caller still creates each recovery/settings leaf with privateChild.
    /// Never chmod the legacy parent or traverse a link to migrate it.
    func appSweepSupport(create: Bool) throws -> SafeDirectory? {
        let parent = try ownIdentity, owner = as_current_uid()
        guard owner != 0, path.hasSuffix("/Library/Application Support"),
              parent.owner == owner, as_unshared_node_descriptor(fd, owner) == 1 else {
            throw SweepError.denied("应用资料目录的归属或写入权限未确认")
        }
        let childFD = openat(fd, "App Sweep", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        if childFD < 0, errno == ENOENT { return create ? try privateChild("App Sweep") : nil }
        guard childFD >= 0 else { throw SweepError.denied("不能安全打开 App Sweep 资料目录") }
        let child = SafeDirectory(fd: childFD, path: path + "/App Sweep")
        let actual = try child.ownIdentity, expected = try identity("App Sweep")
        guard actual.device == parent.device, actual.sameObject(as: expected),
              as_unshared_node_descriptor(child.fd, owner) == 1 else {
            throw SweepError.denied("App Sweep 资料目录可被其他账户改写或身份已改变")
        }
        return child
    }
    func privateChild(_ name: String) throws -> SafeDirectory {
        let child = as_private_directory(fd, name)
        guard child >= 0 else { throw SweepError.denied("恢复目录必须属于当前用户且仅当前用户可访问：\(name)") }
        return SafeDirectory(fd: child, path: path + "/" + name)
    }
    func existingPrivateChild(_ name: String) throws -> SafeDirectory {
        guard !name.contains("/"), name != ".", name != ".." else { throw SweepError.denied("目录名无效") }
        let expected = try identity(name)
        let child = try SafeDirectory(path: path + "/" + name)
        let actual = try child.ownIdentity
        guard actual.device == expected.device, actual.inode == expected.inode, as_private_descriptor(child.fd) == 1 else { throw SweepError.denied("恢复目录身份、权限或 ACL 未确认") }
        return child
    }
    func write(_ data: Data, name: String) throws {
        let result = data.withUnsafeBytes { as_write_atomic(fd, name, $0.baseAddress, $0.count) }
        guard result == 0 else { throw SweepError.filesystem("无法持久化恢复日志，停止操作") }
    }
    func read(_ name: String) throws -> Data {
        var buffer = [UInt8](repeating: 0, count: 16 * 1024 * 1024); var count = 0
        guard as_read_file(fd, name, &buffer, buffer.count, &count) == 0 else { throw SweepError.denied("恢复日志无效、过大或权限不安全") }
        return Data(buffer.prefix(count))
    }
    var availableBytes: UInt64 { as_available_bytes(fd) }
}

enum SafeFilesystem {
    private static func canonicalPOSIXSpelling(_ path: String) -> Bool {
        // Foundation may rewrite an existing physical /private/tmp path to
        // /tmp. Validate spelling without resolving filesystem aliases; the
        // descriptor walk still rejects links, replacements and mount escapes.
        path.hasPrefix("/") && path.count > 1 && !path.contains("\0") &&
        !path.contains("//") && !path.hasSuffix("/") &&
        !path.split(separator:"/").contains(where:{ $0 == "." || $0 == ".." })
    }
    static func readMetadata(_ path: String, maximumBytes: Int = 2 * 1024 * 1024) throws -> Data {
        guard maximumBytes > 0, maximumBytes <= 16 * 1024 * 1024, canonicalPOSIXSpelling(path) else { throw SweepError.invalid("元数据路径或读取上限无效") }
        let url = URL(fileURLWithPath: path)
        let parent = try SafeDirectory(path: url.deletingLastPathComponent().path)
        let identity = try parent.identity(url.lastPathComponent)
        guard identity.mode & 0o170000 == 0o100000, identity.links == 1, identity.size >= 0,
              identity.size <= maximumBytes else { throw SweepError.denied("元数据不是有界普通文件") }
        var buffer = [UInt8](repeating: 0, count: max(1, Int(identity.size))); var count = 0
        var expected = identity.native
        guard as_read_verified_file(parent.fd, url.lastPathComponent, &expected, &buffer, buffer.count, &count) == 0 else { throw SweepError.stale("元数据类型、身份或内容未确认") }
        ScanReadActivity.completed()
        return Data(buffer.prefix(count))
    }
    static func ancestors(of parentPath: String) throws -> [AncestorIdentity] {
        var result: [AncestorIdentity] = []; var component = "/"
        for part in parentPath.split(separator: "/") {
            component = component == "/" ? component + part : component + "/" + part
            let s = try SafeDirectory(path: component).ownIdentity
            result.append(AncestorIdentity(path: component, device: s.device, inode: s.inode, mode: s.mode, owner: s.owner,volumeUUID:s.volumeUUID))
        }
        return result
    }
    static func presence(_ path: String) throws -> Bool {
        let url = URL(fileURLWithPath: path)
        let fd = as_open_directory(url.deletingLastPathComponent().path)
        if fd < 0 { if errno == ENOENT { return false }; throw SweepError.filesystem("路径存在性未确认：" + path) }
        defer { as_close(fd) }
        var identity = ASIdentity()
        if as_identity_at(fd, url.lastPathComponent, &identity) == 0 { ScanReadActivity.completed(); return true }
        if errno == ENOENT { return false }
        throw SweepError.filesystem("文件存在性未确认：" + path)
    }
    static func snapshot(_ path: String, allowInternalLinks: Bool = false, purpose: SnapshotPurpose = .ordinary, allowInternalHardLinks: Bool = false, reportRootChanges: Bool = false, allowApplicationHardLinks: Bool = false) throws -> FileSnapshot {
        guard canonicalPOSIXSpelling(path) else { throw SweepError.denied("非规范路径") }
        let url = URL(fileURLWithPath: path)
        let parentPath = url.deletingLastPathComponent().path
        let parent = try SafeDirectory(path: parentPath)
        let identity = try parent.identity(url.lastPathComponent)
        guard !identity.isLink, identity.isDirectory || (identity.mode & 0o170000 == 0o100000 && identity.links == 1) else { throw SweepError.denied("符号链接、特殊文件或异常硬链接") }
        guard !allowApplicationHardLinks || (identity.isDirectory && purpose == .application && !allowInternalHardLinks) else { throw SweepError.denied("应用硬链接仅用于完整包移动") }
        let ancestors = try ancestors(of: parentPath)
        var tree: [TreeEntry] = []
        var bytes = identity.isDirectory ? Int64(0) : max(0, identity.size)
        var measured = Set<String>()
        let deadline = Date().addingTimeInterval(purpose.timeout)
        if identity.isDirectory {
            var buffer = [UInt8](repeating: 0, count: purpose == .application ? 16 * 1024 * 1024 : 2 * 1024 * 1024)
            var pending = [path]
            while let directory = pending.popLast() {
                try ScanCancellation.check()
                guard Date() < deadline, tree.count < purpose.maximumEntries else { throw SweepError.incomplete("扫描截断，不能执行") }
                let handle = try SafeDirectory(path: directory)
                var count = 0
                guard as_directory_entries(handle.fd, &buffer, buffer.count, min(100_000, purpose.maximumEntries - tree.count), &count) == 0,
                      let text = String(bytes: buffer.prefix(count), encoding: .utf8) else { throw SweepError.incomplete("目录枚举失败或超过有限容量，不能执行") }
                let children = text.split(separator: "\0").map(String.init).sorted()
                for name in children {
                    try ScanCancellation.check()
                    guard Date() < deadline else { throw SweepError.incomplete("扫描超时，不能执行") }
                    let child = try handle.identity(name)
                    guard child.sameVolume(as:identity) else { throw SweepError.denied("跨卷或挂载点") }
                    guard child.isDirectory || child.isLink || (child.mode & 0o170000 == 0o100000 && (child.links == 1 || allowInternalHardLinks || allowApplicationHardLinks)) else { throw SweepError.denied("特殊文件或异常硬链接") }
                    guard !child.isLink || allowInternalLinks else { throw SweepError.denied("目录内含符号链接") }
                    let full = directory + "/" + name
                    tree.append(TreeEntry(relative: String(full.dropFirst(path.count + 1)), identity: child))
                    if child.isDirectory { pending.append(full) }
                    else if !child.isLink, !(allowInternalHardLinks || allowApplicationHardLinks) || measured.insert(ContainedHardLinks.key(child)).inserted { bytes += max(0, child.size) }
                    guard tree.count <= purpose.maximumEntries else { throw SweepError.incomplete("扫描截断，不能执行") }
                }
            }
        }
        if allowApplicationHardLinks, tree.contains(where: { $0.identity.mode & 0o170000 == 0o100000 && $0.identity.links > 1 }) {
            let (info, _) = try AppInspector.metadata(path, component: false)
            guard info["CFBundlePackageType"] as? String == "APPL", let identifier = info["CFBundleIdentifier"] as? String,
                  AppInspector.signatureMatches(path: path, identifier: identifier) else { throw SweepError.denied("硬链接应用的完整签名未确认") }
            for group in ContainedHardLinks.groups(tree).values {
                guard let first = group.first, first.identity.links >= UInt64(group.count), group.allSatisfy({ $0.identity == first.identity }) else {
                    throw SweepError.stale("应用硬链接身份或引用数量不一致")
                }
            }
        }
        let final = try parent.identity(url.lastPathComponent)
        if reportRootChanges, final != identity, identity.sameObject(as:final) {
            throw SnapshotRootChange(path:path,before:identity,after:final)
        }
        guard final == identity else { throw SweepError.stale("扫描过程中目标已改变") }
        if allowInternalHardLinks { try ContainedHardLinks.validate(tree) }
        return FileSnapshot(path: path, identity: identity, ancestors: ancestors, tree: tree.sorted { $0.relative < $1.relative }, bytes: bytes, allowInternalLinks: allowInternalLinks, purpose: purpose, allowInternalHardLinks: allowInternalHardLinks && identity.isDirectory, allowApplicationHardLinks: allowApplicationHardLinks)
    }
    static func fileSnapshot(_ path: String, in directory: FileSnapshot) throws -> FileSnapshot {
        if path == directory.path, !directory.identity.isDirectory { return try snapshot(path) }
        guard SafetyPolicy.contains(directory.path, path), path != directory.path,
              let entry = directory.tree.first(where: { directory.path + "/" + $0.relative == path }),
              entry.identity.mode & 0o170000 == 0o100000 else { throw SweepError.denied("归档文件不在已确认的完整目录中") }
        if entry.identity.links == 1 { return try snapshot(path) }
        guard directory.allowInternalHardLinks else { throw SweepError.denied("此规则不允许硬链接") }
        let aliases = directory.tree.filter { $0.identity.device == entry.identity.device && $0.identity.inode == entry.identity.inode }.map { directory.path + "/" + $0.relative }
        let context = HardLinkContext(root: directory.path, rootIdentity: directory.identity, aliases: aliases)
        try context.verify(entry.identity)
        let parent = URL(fileURLWithPath: path).deletingLastPathComponent().path
        return FileSnapshot(path: path, identity: entry.identity, ancestors: try ancestors(of: parent), tree: [], bytes: entry.identity.size, allowInternalLinks: false, hardLinkContext: context)
    }
    static func verify(_ expected: FileSnapshot, reportRootChanges: Bool = false) throws {
        if let context = expected.hardLinkContext {
            try context.verify(expected.identity)
            guard expected.tree.isEmpty, context.aliases.contains(expected.path), try ancestors(of: URL(fileURLWithPath: expected.path).deletingLastPathComponent().path) == expected.ancestors else { throw SweepError.stale("硬链接归档来源或祖先已改变") }
            return
        }
        let current = try snapshot(expected.path, allowInternalLinks: expected.allowInternalLinks, purpose: expected.purpose, allowInternalHardLinks: expected.allowInternalHardLinks, reportRootChanges:reportRootChanges, allowApplicationHardLinks: expected.allowApplicationHardLinks)
        if reportRootChanges, current.identity != expected.identity, current.identity.sameObject(as:expected.identity),
           current.ancestors == expected.ancestors, current.tree == expected.tree {
            throw SnapshotRootChange(path:expected.path,before:expected.identity,after:current.identity)
        }
        guard current.identity == expected.identity, current.ancestors == expected.ancestors, current.tree == expected.tree else { throw SweepError.stale("目标或祖先目录已改变，请重新扫描") }
    }
    static func move(_ snapshot: FileSnapshot, into target: SafeDirectory, name: String, targetAncestors: [AncestorIdentity]? = nil) throws {
        try verify(snapshot)
        let url = URL(fileURLWithPath: snapshot.path)
        let source = try SafeDirectory(path: url.deletingLastPathComponent().path)
        let sourceIdentity = try source.ownIdentity
        guard let expectedParent = snapshot.ancestors.last, sourceIdentity.device == expectedParent.device,
              sourceIdentity.inode == expectedParent.inode, sourceIdentity.mode == expectedParent.mode,
              sourceIdentity.owner == expectedParent.owner else { throw SweepError.stale("移动前原目录身份已改变") }
        if let targetAncestors {
            let targetIdentity = try target.ownIdentity
            guard try ancestors(of: target.path) == targetAncestors, let expected = targetAncestors.last,
                  AncestorIdentity(path:target.path,device:targetIdentity.device,inode:targetIdentity.inode,mode:targetIdentity.mode,owner:targetIdentity.owner,volumeUUID:targetIdentity.volumeUUID) == expected, targetIdentity.inode == expected.inode,
                  targetIdentity.mode == expected.mode, targetIdentity.owner == expected.owner else { throw SweepError.stale("恢复目标或祖先目录已改变") }
        }
        var native = snapshot.identity.native
        let result = as_move_exclusive(source.fd, url.lastPathComponent, target.fd, name, &native)
        guard result == 0 else { throw SweepError.filesystem(result == -2 ? "移动已发生，但持久化状态未确认，需要恢复" : "移动失败、身份改变或目标冲突") }
        let moved = try Self.snapshot(target.path + "/" + name, allowInternalLinks: snapshot.allowInternalLinks, purpose: snapshot.purpose, allowInternalHardLinks: snapshot.allowInternalHardLinks, allowApplicationHardLinks: snapshot.allowApplicationHardLinks)
        guard moved.identity.sameObject(as: snapshot.identity), moved.tree == snapshot.tree else { throw SweepError.stale("移动后对象或内容核对失败") }
    }
    static func removeVerified(in directory: SafeDirectory, name: String, identity: FileIdentity, contents: [TreeEntry], allowInternalHardLinks: Bool = false, allowApplicationHardLinks: Bool = false) -> Bool {
        if allowApplicationHardLinks {
            guard !allowInternalHardLinks, let verified = try? snapshot(directory.path + "/" + name, allowInternalLinks: true, purpose: .application, allowApplicationHardLinks: true),
                  verified.identity == identity, verified.tree == contents else { return false }
        }
        let names = contents.map { strdup($0.relative) }
        defer { names.forEach { free($0) } }
        guard names.allSatisfy({ $0 != nil }) else { return false }
        let entries = contents.indices.map { ASVerifiedEntry(relative: UnsafePointer(names[$0]), identity: contents[$0].identity.native) }
        var expected = identity.native
        return entries.withUnsafeBufferPointer {
            if allowApplicationHardLinks { return as_remove_verified_application_links(directory.fd, name, &expected, $0.baseAddress, $0.count) == 0 }
            if allowInternalHardLinks { return as_remove_verified_contained_links(directory.fd, name, &expected, $0.baseAddress, $0.count) == 0 }
            return as_remove_verified(directory.fd, name, &expected, $0.baseAddress, $0.count) == 0
        }
    }
}
