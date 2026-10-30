#if os(macOS)
import Foundation
import Darwin
import CFSafety

/// Prepares a complete independent bundle. It never modifies the installed
/// object, publishes a replacement, or grants authority to clean a path.
/// The caller must persist a preparation intent before invoking this method;
/// every failure retains the new partial directory for reconciliation.
enum ApplicationTreeCopy {
    private static let maximumBytes: UInt64 = 1 << 40
    private static let reserve: UInt64 = 2 * 1024 * 1024 * 1024
    private static let nodeAllowance: UInt64 = 64 * 1024 * 1024

    static func prepare(_ source: FileSnapshot, in parent: SafeDirectory, name: String, architecturePlan: ApplicationArchitecturePreparation.Plan? = nil, languagePlan: ApplicationLanguagePreparation.Plan? = nil) throws -> FileSnapshot {
        try Task.checkCancellation()
        guard architecturePlan == nil || languagePlan == nil else { throw SweepError.denied("一次准备只能核对一种应用变更") }
        guard getuid() != 0, getuid() == geteuid(), source.purpose == .application,
              source.identity.isDirectory, source.hardLinkContext == nil,
              URL(fileURLWithPath:source.path).pathExtension.lowercased() == "app",
              UUID(uuidString:name)?.uuidString == name,
              !SafetyPolicy.contains(source.path,parent.path), source.bytes >= 0,
              UInt64(source.bytes) <= maximumBytes else { throw SweepError.denied("应用副本的来源、准备区或容量未确认") }
        guard as_private_descriptor(parent.fd) == 1 else { throw SweepError.denied("应用准备区必须私有") }
        let parentIdentity = try parent.ownIdentity
        guard parentIdentity.isDirectory, parentIdentity.owner == getuid(), parentIdentity.device == source.identity.device else { throw SweepError.denied("应用副本要求同卷准备区及足够空间") }
        let all = [TreeEntry(relative:"",identity:source.identity)] + source.tree
        guard all.allSatisfy({ $0.identity.owner == getuid() && $0.identity.device == source.identity.device &&
            $0.identity.mode & 0o7000 == 0 && ($0.identity.isDirectory || $0.identity.isLink || $0.identity.mode & 0o170000 == 0o100000) }) else {
            throw SweepError.denied("应用包中存在其他所有者、特殊权限或未知节点")
        }
        try ContainedHardLinks.validate(source.tree)
        try SafeFilesystem.verify(source)
        try architecturePlan?.verify(source)
        try languagePlan?.verify(source)
        let changes = Dictionary(uniqueKeysWithValues:(architecturePlan?.changes ?? []).map { ($0.relative,$0) })
        var savings: Int64 = 0
        let omitted = Dictionary(uniqueKeysWithValues:(languagePlan?.omitted ?? []).map { ($0.relative,$0.identity) })
        var omittedCount = 0
        for entry in source.tree {
            guard let expected = omitted[entry.relative] else { continue }
            guard entry.identity == expected,
                  entry.identity.isDirectory || (entry.identity.mode & 0o170000 == 0o100000 && entry.identity.links == 1) else {
                throw SweepError.denied("语言准备节点与原应用不一致")
            }
            if !entry.identity.isDirectory {
                guard entry.identity.size >= 0, entry.identity.size <= source.bytes-savings else { throw SweepError.denied("语言资源容量未确认") }
                savings += entry.identity.size
            }
            omittedCount += 1
        }
        guard omittedCount == omitted.count else { throw SweepError.denied("语言分析包含不存在的节点") }
        let expectedTree = source.tree.filter { omitted[$0.relative] == nil }
        let copiedNodes = [TreeEntry(relative:"",identity:source.identity)] + expectedTree
        var matched = 0
        for entry in source.tree where !changes.isEmpty {
            try Task.checkCancellation()
            guard let change = changes[entry.relative] else { continue }
            guard entry.identity == change.originalIdentity,
                  entry.identity.mode & 0o170000 == 0o100000, entry.identity.links == 1,
                  change.slice.offset <= UInt64(entry.identity.size), change.slice.size > 0,
                  change.slice.size <= UInt64(entry.identity.size)-change.slice.offset,
                  change.slice.size < UInt64(entry.identity.size),
                  entry.identity.size-Int64(change.slice.size) <= source.bytes-savings else {
                throw SweepError.denied("精简分析的独立节点或节省容量未确认")
            }
            savings += entry.identity.size-Int64(change.slice.size)
            matched += 1
        }
        guard matched == changes.count else { throw SweepError.denied("精简分析包含来源中不存在的节点") }
        var required: UInt64 = 0
        for group in ContainedHardLinks.groups(source.tree).values {
            guard let first = group.first, first.identity.size >= 0,
                  UInt64(first.identity.size) <= maximumBytes-required else { throw SweepError.denied("应用内容容量超出准备上限") }
            required += UInt64(first.identity.size)
        }
        guard required == UInt64(source.bytes), parent.availableBytes >= required + reserve + nodeAllowance else {
            throw SweepError.denied("应用容量记录不一致或没有足够的安全余量")
        }
        var existing = ASIdentity()
        guard as_identity_at(parent.fd,name,&existing) != 0, errno == ENOENT else { throw SweepError.denied("应用准备对象已存在或状态未知") }
        let deadline = ProcessInfo.processInfo.systemUptime + 300
        let parentAncestors = try SafeFilesystem.ancestors(of:parent.path)
        guard mkdirat(parent.fd,name,0o700) == 0 else { throw SweepError.filesystem("无法建立独占应用副本目录") }
        // Nothing below removes this directory. Partial preparation belongs to
        // the caller's already-persisted operation and remains recoverable.
        let destination = parent.path + "/" + name
        let root = try parent.existingPrivateChild(name)
        var directories: [String:FileIdentity] = ["":try root.ownIdentity]
        let sourceDirectories = Dictionary(uniqueKeysWithValues:all.filter { $0.identity.isDirectory }.map { ($0.relative,$0.identity) })
        func remaining() throws -> Int32 {
            try Task.checkCancellation()
            let seconds = deadline-ProcessInfo.processInfo.systemUptime
            guard seconds > 0 else { throw SweepError.incomplete("应用副本准备超时，部分准备对象已保留") }
            guard parent.availableBytes >= reserve + nodeAllowance else { throw SweepError.denied("准备卷空间余量不足，部分副本已保留") }
            return Int32(max(1,min(300_000,ceil(seconds*1000))))
        }
        func boundDirectory(_ base: String,_ relative: String,_ expected: FileIdentity) throws -> SafeDirectory {
            _ = try remaining()
            let handle = try SafeDirectory(path:relative.isEmpty ? base : base + "/" + relative)
            let actual = try handle.ownIdentity
            guard actual.isDirectory, actual.device == expected.device, actual.inode == expected.inode,
                  actual.owner == expected.owner, actual.mode == expected.mode else { throw SweepError.stale("应用副本的目录身份或权限已变化") }
            return handle
        }
        func split(_ relative: String) -> (String,String) {
            let parts = relative.split(separator:"/").map(String.init)
            return (parts.dropLast().joined(separator:"/"),parts.last ?? "")
        }
        func sourceParent(_ relative: String) throws -> (SafeDirectory,String) {
            if relative.isEmpty {
                let url = URL(fileURLWithPath:source.path), path = url.deletingLastPathComponent().path
                let handle = try SafeDirectory(path:path), actual = try handle.ownIdentity
                guard let expected = source.ancestors.last, expected.path == path,
                      actual.device == expected.device, actual.inode == expected.inode,
                      actual.owner == expected.owner, actual.mode == expected.mode else { throw SweepError.stale("应用来源父目录已变化") }
                return (handle,url.lastPathComponent)
            }
            let (path,name) = split(relative)
            guard let expected = sourceDirectories[path] else { throw SweepError.invalid("应用来源目录缺少完整快照") }
            return (try boundDirectory(source.path,path,expected),name)
        }
        func targetParent(_ relative: String) throws -> (SafeDirectory,String) {
            if relative.isEmpty { return (parent,name) }
            let (path,name) = split(relative)
            guard let expected = directories[path] else { throw SweepError.invalid("应用准备目录尚未建立") }
            return (try boundDirectory(destination,path,expected),name)
        }
        let nestedDirectories = expectedTree.filter { $0.identity.isDirectory }.sorted {
            let a = $0.relative.split(separator:"/").count, b = $1.relative.split(separator:"/").count
            return a == b ? $0.relative < $1.relative : a < b
        }
        for entry in nestedDirectories {
            let (handle,child) = try targetParent(entry.relative)
            guard mkdirat(handle.fd,child,0o700) == 0 else { throw SweepError.filesystem("应用准备子目录建立失败；部分副本已保留") }
            let created = try handle.existingPrivateChild(child)
            directories[entry.relative] = try created.ownIdentity
        }
        var firstHardLink: [String:String] = [:]
        var changedNodes: [String:(identity:FileIdentity,digest:[UInt8])] = [:]
        for entry in expectedTree where !entry.identity.isDirectory {
            let (target,child) = try targetParent(entry.relative)
            let isRegular = entry.identity.mode & 0o170000 == 0o100000
            let key = ContainedHardLinks.key(entry.identity)
            if isRegular, entry.identity.links > 1, let first = firstHardLink[key] {
                let (from,firstName) = try targetParent(first)
                var expected = try from.identity(firstName).native
                guard as_link_private_regular(from.fd,firstName,target.fd,child,&expected) == 0 else {
                    throw SweepError.incomplete("应用副本硬链接重建未确认；部分副本已保留")
                }
            } else {
                let (input,inputName) = try sourceParent(entry.relative)
                let dataBytes = isRegular ? UInt64(entry.identity.size) : 0
                guard parent.availableBytes >= reserve + nodeAllowance + dataBytes else { throw SweepError.denied("单个应用节点缺少写入空间，部分副本已保留") }
                var expected = entry.identity.native, created = ASIdentity()
                let result: Int32
                if let change = changes[entry.relative] {
                    result = as_copy_owned_regular_range(input.fd,inputName,&expected,target.fd,child,change.slice.offset,change.slice.size,maximumBytes,try remaining(),&created)
                } else {
                    result = as_copy_owned_node(input.fd,inputName,&expected,target.fd,child,maximumBytes,try remaining(),&created)
                }
                guard result == 0 else {
                    throw SweepError.incomplete("应用节点复制或元数据核对未完成（错误 \(errno)）；部分副本已保留")
                }
                if changes[entry.relative] != nil {
                    var commitment = [UInt8](repeating:0,count:32)
                    guard as_owned_node_digest(target.fd,child,&created,maximumBytes,try remaining(),&commitment) == 0 else {
                        throw SweepError.stale("准备的架构节点已变化；部分副本保留")
                    }
                    changedNodes[entry.relative] = (FileIdentity(created),commitment)
                }
                if isRegular, entry.identity.links > 1 { firstHardLink[key] = entry.relative }
            }
        }
        // Apply directory metadata only after every descendant/link is present.
        // Each parent is still private while its children receive final modes.
        for entry in Array(nestedDirectories.reversed()) + [TreeEntry(relative:"",identity:source.identity)] {
            let (input,inputName) = try sourceParent(entry.relative), (target,child) = try targetParent(entry.relative)
            var expected = entry.identity.native, created = ASIdentity()
            let result = entry.relative.isEmpty ?
                as_copy_owned_application_root(input.fd,inputName,&expected,target.fd,child,try remaining(),&created) :
                as_copy_owned_node(input.fd,inputName,&expected,target.fd,child,maximumBytes,try remaining(),&created)
            guard result == 0 else {
                let location = entry.relative.isEmpty ? "应用根目录" : entry.relative
                throw SweepError.incomplete("应用目录元数据核对未完成：\(location)（错误 \(errno)）；部分副本已保留")
            }
            directories[entry.relative] = FileIdentity(created)
        }
        let copied = try SafeFilesystem.snapshot(destination,allowInternalLinks:source.allowInternalLinks,purpose:.application,allowInternalHardLinks:source.allowInternalHardLinks)
        guard copied.identity.device == source.identity.device,
              copied.identity.inode == (try root.ownIdentity.inode),
              copied.bytes == source.bytes-savings,
              copied.tree.map(\.relative) == expectedTree.map(\.relative) else { throw SweepError.stale("应用副本的完整路径或对象已变化") }
        let targetEntries = Dictionary(uniqueKeysWithValues:([TreeEntry(relative:"",identity:copied.identity)] + copied.tree).map { ($0.relative,$0.identity) })
        // Inodes differ by design. Compare independent node commitments and the
        // complete regular-file alias groups, never the old inode tree digest.
        for entry in copiedNodes {
            guard let identity = targetEntries[entry.relative] else { throw SweepError.stale("应用副本缺少节点") }
            let (input,inputName) = try sourceParent(entry.relative), (output,outputName) = try targetParent(entry.relative)
            var original = entry.identity.native, actual = identity.native
            var before = [UInt8](repeating:0,count:32), after = before
            if let changed = changedNodes[entry.relative] {
                guard identity == changed.identity,
                      as_owned_node_digest(output.fd,outputName,&actual,maximumBytes,try remaining(),&after) == 0,
                      changed.digest == after else { throw SweepError.stale("架构准备节点的身份、内容或元数据已变化") }
            } else if entry.relative.isEmpty {
                guard as_owned_application_root_digest(input.fd,inputName,&original,try remaining(),&before) == 0,
                      as_owned_application_root_digest(output.fd,outputName,&actual,try remaining(),&after) == 0,
                      before == after else { throw SweepError.stale("应用副本根目录的权限或普通元数据不一致") }
            } else {
                guard as_owned_node_digest(input.fd,inputName,&original,maximumBytes,try remaining(),&before) == 0,
                  as_owned_node_digest(output.fd,outputName,&actual,maximumBytes,try remaining(),&after) == 0,
                  before == after else { throw SweepError.stale("应用副本内容或元数据不一致") }
            }
        }
        func topology(_ tree: [TreeEntry]) -> Set<Set<String>> {
            Set(ContainedHardLinks.groups(tree).values.map { Set($0.map(\.relative)) })
        }
        guard topology(expectedTree) == topology(copied.tree) else { throw SweepError.stale("应用副本硬链接拓扑不一致") }
        try SafeFilesystem.verify(source)
        try SafeFilesystem.verify(copied)
        let parentNow = try parent.ownIdentity
        guard parentNow.device == parentIdentity.device, parentNow.inode == parentIdentity.inode,
              parentNow.mode == parentIdentity.mode, parentNow.owner == parentIdentity.owner,
              as_private_descriptor(parent.fd) == 1,
              try SafeFilesystem.ancestors(of:parent.path) == parentAncestors else { throw SweepError.stale("应用准备区或祖先目录已变化") }
        _ = try remaining()
        return copied
    }
}
#endif
