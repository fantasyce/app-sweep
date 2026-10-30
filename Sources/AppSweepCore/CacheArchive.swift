import Foundation
import CFSafety
#if canImport(CryptoKit)
import CryptoKit
#endif

/// Independent, non-purgeable bytes for a complete cache object. Integration is
/// blocked until metadata, interrupted creation and reconstruction are verified.
enum CacheArchive {
    static let format = "cache-tree-v1"
    static let rules = [GodotCacheRule.name, CacheDomainRule.name, SystemDomainRule.cacheName, ChromiumCacheRule.name, UserCacheNamespaceRule.name, DarwinCacheRule.name, WebKitCacheRule.name, WebKitTemporaryRule.name, NamedApplicationRule.cacheName] + ApplicationCacheRule.rules
    static func supports(_ rule: String) -> Bool { rules.contains(rule) }
    fileprivate struct Node: Codable, Sendable {
        let relative: String
        let identity: FileIdentity
        let metadata: CacheNodeMetadata
        let blob: String?
        let digest: String?
    }
    fileprivate struct Receipt: Codable, Sendable {
        let schemaVersion: Int
        let id: UUID
        let sourcePath: String
        let rule: String
        let nodes: [Node]
    }
    struct Prepared: Sendable {
        let digest: String
        let requiredBytes: UInt64
        fileprivate let receipt: Receipt
        fileprivate let packet: Data
    }
    static func prepare(_ snapshot: FileSnapshot, candidate: Candidate) throws -> Prepared {
        guard supports(candidate.rule), candidate.category == .cache,
              candidate.path == snapshot.path, candidate.identity == snapshot.identity,
              !snapshot.allowInternalLinks, snapshot.tree.count <= 20_000 else { throw SweepError.denied("归档来源与登记缓存对象不一致") }
        try SafeFilesystem.verify(snapshot)
        let entries = [TreeEntry(relative: "", identity: snapshot.identity)] + snapshot.tree
        var nodes: [Node] = [], attributesBytes = 0
        let deadline = ProcessInfo.processInfo.systemUptime + 300
        for entry in entries {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw SweepError.incomplete("归档准备超时，原对象保留") }
            let path = entry.relative.isEmpty ? snapshot.path : snapshot.path + "/" + entry.relative
            let metadata = try CacheNodeMetadata.read(path: path, identity: entry.identity)
            attributesBytes += metadata.attributes.count
            guard attributesBytes <= 8 * 1024 * 1024 else { throw SweepError.denied("缓存扩展属性超出可核验的恢复清单容量") }
            let digest = entry.identity.isDirectory ? nil : try VerifiedFileStream.digest(SafeFilesystem.fileSnapshot(path, in: snapshot))
            nodes.append(Node(relative: entry.relative, identity: entry.identity, metadata: metadata,
                              blob: entry.identity.isDirectory ? nil : UUID().uuidString, digest: digest))
        }
        try SafeFilesystem.verify(snapshot)
        let receipt = Receipt(schemaVersion: 1, id: candidate.id, sourcePath: candidate.path, rule: candidate.rule, nodes: nodes)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let packet = try encoder.encode(receipt)
        guard packet.count <= 16 * 1024 * 1024 else { throw SweepError.denied("缓存恢复清单超出容量") }
        return Prepared(digest: try hash(packet), requiredBytes: nodes.filter { !$0.identity.isDirectory }.reduce(UInt64(0)) { $0 + UInt64($1.identity.size) } + UInt64(packet.count) + UInt64(nodes.count + 1) * 4096,
                        receipt: receipt, packet: packet)
    }
    static func create(_ prepared: Prepared, snapshot: FileSnapshot, candidate: Candidate, in directory: SafeDirectory) throws -> FileSnapshot {
        guard prepared.receipt.id == candidate.id, prepared.receipt.sourcePath == snapshot.path,
              prepared.receipt.nodes.first?.identity == snapshot.identity,
              try directory.ownIdentity.device == snapshot.identity.device,
              directory.availableBytes > prepared.requiredBytes + CacheBackup.freeSpaceReserve,
              try !SafeFilesystem.presence(directory.path + "/" + candidate.id.uuidString) else { throw SweepError.denied("独立归档目标存在、卷不一致或空间不足") }
        try SafeFilesystem.verify(snapshot)
        let archive = try directory.privateChild(candidate.id.uuidString)
        let deadline = ProcessInfo.processInfo.systemUptime + 300
        for node in prepared.receipt.nodes {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw SweepError.incomplete("独立归档写入超时，原对象保留") }
            guard let blob = node.blob, let digest = node.digest else { continue }
            let path = node.relative.isEmpty ? snapshot.path : snapshot.path + "/" + node.relative
            let input = try SafeFilesystem.fileSnapshot(path, in: snapshot)
            guard input.identity == node.identity else { throw SweepError.stale("归档写入前缓存身份已改变") }
            let copy = try VerifiedFileStream.copy(input, into: archive, name: blob)
            guard copy.digest == digest, try VerifiedFileStream.digest(SafeFilesystem.snapshot(archive.path + "/" + blob)) == digest else { throw SweepError.stale("独立归档字节摘要不一致") }
        }
        try SafeFilesystem.verify(snapshot)
        try archive.write(prepared.packet, name: "receipt.json")
        return try SafeFilesystem.snapshot(archive.path, purpose: .application)
    }
    static func materialize(_ entry: RecoveryEntry, from directory: SafeDirectory, into objects: SafeDirectory) throws -> FileSnapshot {
        let (receipt, _) = try read(entry, in: directory)
        let deadline = ProcessInfo.processInfo.systemUptime + 300
        let required = receipt.nodes.filter { !$0.identity.isDirectory }.reduce(UInt64(0)) { $0 + UInt64(max(0, $1.identity.size)) } + UInt64(receipt.nodes.count + 1) * 4096
        guard objects.availableBytes > required + CacheBackup.freeSpaceReserve else { throw SweepError.denied("独立副本重建空间不足，未创建目标") }
        let name = entry.id.uuidString, target = objects.path + "/" + name
        guard try !SafeFilesystem.presence(target), let root = receipt.nodes.first else { throw SweepError.denied("重建目标存在，不覆盖") }
        let archive = try directory.existingPrivateChild(name)
        if !root.identity.isDirectory {
            guard let blob = root.blob else { throw SweepError.invalid("独立归档缺少根文件") }
            _ = try VerifiedFileStream.copy(SafeFilesystem.snapshot(archive.path + "/" + blob), into: objects, name: name)
            try root.metadata.apply(to: SafeFilesystem.snapshot(target), original: root.identity)
        } else {
            let rebuilt = try objects.privateChild(name)
            let directories = receipt.nodes.dropFirst().filter { $0.identity.isDirectory }.sorted { $0.relative.split(separator: "/").count < $1.relative.split(separator: "/").count }
            for node in directories {
                try check(deadline)
                let url = URL(fileURLWithPath: rebuilt.path + "/" + node.relative)
                _ = try SafeDirectory(path: url.deletingLastPathComponent().path).privateChild(url.lastPathComponent)
            }
            var anchors: [String: (path: String, count: UInt64)] = [:]
            for node in receipt.nodes.dropFirst() where !node.identity.isDirectory {
                try check(deadline)
                guard let blob = node.blob else { throw SweepError.invalid("独立归档缺少文件数据") }
                let url = URL(fileURLWithPath: rebuilt.path + "/" + node.relative), parent = try SafeDirectory(path: url.deletingLastPathComponent().path)
                let key = ContainedHardLinks.key(node.identity)
                if let anchor = anchors[key] {
                    let first = URL(fileURLWithPath: anchor.path), source = try SafeDirectory(path: first.deletingLastPathComponent().path)
                    let identity = try source.identity(first.lastPathComponent)
                    guard identity.links == anchor.count, identity.owner == node.identity.owner else { throw SweepError.stale("私有重建引用已改变") }
                    var expected = identity.native
                    guard as_link_private_regular(source.fd, first.lastPathComponent, parent.fd, url.lastPathComponent, &expected) == 0 else { throw SweepError.filesystem("无法完整重建缓存引用；保留未完成对象") }
                    anchors[key] = (anchor.path, anchor.count + 1)
                    continue
                }
                let temporary = UUID().uuidString
                _ = try VerifiedFileStream.copy(SafeFilesystem.snapshot(archive.path + "/" + blob), into: parent, name: temporary)
                var initial = node.identity.native; initial.links = 1
                try node.metadata.apply(to: SafeFilesystem.snapshot(parent.path + "/" + temporary), original: FileIdentity(initial))
                try SafeFilesystem.move(SafeFilesystem.snapshot(parent.path + "/" + temporary), into: parent, name: url.lastPathComponent)
                anchors[key] = (url.path, 1)
            }
            for node in (directories.reversed() + [root]) {
                try check(deadline)
                let path = node.relative.isEmpty ? rebuilt.path : rebuilt.path + "/" + node.relative
                try node.metadata.apply(toPrivatePath: path, original: node.identity)
            }
        }
        let result = try SafeFilesystem.snapshot(target, allowInternalHardLinks: true)
        guard try matches(result, receipt: receipt) else { throw SweepError.stale("重建对象的结构、字节或元数据不一致") }
        return result
    }
    static func verifiedSnapshot(_ entry: RecoveryEntry, in directory: SafeDirectory) throws -> FileSnapshot {
        try read(entry, in: directory).1
    }
    static func validatesReconstruction(_ snapshot: FileSnapshot, entry: RecoveryEntry, in directory: SafeDirectory) throws -> Bool {
        try matches(snapshot, receipt: read(entry, in: directory).0)
    }
    private static func read(_ entry: RecoveryEntry, in directory: SafeDirectory) throws -> (Receipt, FileSnapshot) {
        let deadline = ProcessInfo.processInfo.systemUptime + 300
        guard supports(entry.original.rule), entry.backupFormat == format, let digest = entry.backupDigest else { throw SweepError.denied("不是已登记的通用缓存独立归档") }
        let archive = try directory.existingPrivateChild(entry.id.uuidString)
        let snapshot = try SafeFilesystem.snapshot(archive.path, purpose: .application)
        guard entry.backupIdentity.map({ $0 == snapshot.identity }) ?? (entry.backupPending == true) else { throw SweepError.stale("独立归档目录身份已改变") }
        let packet = try archive.read("receipt.json")
        guard try hash(packet) == digest else { throw SweepError.stale("独立归档恢复清单摘要不一致") }
        let receipt = try JSONDecoder().decode(Receipt.self, from: packet)
        guard receipt.schemaVersion == 1, receipt.id == entry.id, receipt.sourcePath == entry.original.path,
              receipt.rule == entry.original.rule, receipt.nodes.first?.relative == "", receipt.nodes.count <= 20_001,
              receipt.nodes.first?.identity == entry.original.identity, receipt.nodes.count == entry.contents.count + 1,
              receipt.nodes.dropFirst().map({ TreeEntry(relative: $0.relative, identity: $0.identity) }) == entry.contents else { throw SweepError.denied("独立归档与原始扫描记录不一致") }
        try ContainedHardLinks.validate(entry.contents)
        let files = receipt.nodes.filter { !$0.identity.isDirectory }
        guard files.allSatisfy({ $0.blob.flatMap(UUID.init(uuidString:))?.uuidString == $0.blob && $0.digest?.count == 64 }),
              Set(files.compactMap(\.blob)).count == files.count,
              Set(snapshot.tree.map(\.relative)) == Set(files.compactMap(\.blob) + ["receipt.json"]) else { throw SweepError.denied("独立归档包含未知或重复对象") }
        for node in receipt.nodes {
            try check(deadline)
            guard node.identity.owner == entry.original.identity?.owner, node.identity.isDirectory || (node.identity.mode & 0o170000 == 0o100000 && node.identity.links >= 1 && node.identity.size >= 0),
                  !node.identity.isDirectory || (node.blob == nil && node.digest == nil), node.metadata.attributes.count <= 65_536,
                  node.relative.isEmpty || (!node.relative.hasPrefix("/") && !node.relative.hasSuffix("/") && !node.relative.contains("//") && !node.relative.contains("\0") && !node.relative.split(separator: "/").contains(where: { $0 == "." || $0 == ".." })) else { throw SweepError.denied("独立归档路径或元数据无效") }
        }
        for file in files {
            try check(deadline)
            let path = archive.path + "/" + (file.blob ?? "")
            let input = try SafeFilesystem.snapshot(path)
            guard input.identity.size == file.identity.size, try VerifiedFileStream.digest(input) == file.digest else { throw SweepError.stale("独立归档文件内容已改变") }
        }
        try SafeFilesystem.verify(snapshot)
        return (receipt, snapshot)
    }
    private static func matches(_ snapshot: FileSnapshot, receipt: Receipt) throws -> Bool {
        let deadline = ProcessInfo.processInfo.systemUptime + 300
        let nodes = [TreeEntry(relative: "", identity: snapshot.identity)] + snapshot.tree
        guard nodes.map(\.relative) == receipt.nodes.map(\.relative) else { return false }
        var topology: [String: String] = [:], seen = Set<String>()
        for (node, expected) in zip(nodes, receipt.nodes) {
            try check(deadline)
            let a = node.identity, b = expected.identity
            guard a.mode == b.mode, a.owner == b.owner, a.isDirectory == b.isDirectory,
                  a.modifiedSeconds == b.modifiedSeconds, a.modifiedNanoseconds == b.modifiedNanoseconds,
                  a.isDirectory || (a.size == b.size && a.links == b.links) else { return false }
            if !a.isDirectory {
                let oldKey = ContainedHardLinks.key(b), newKey = ContainedHardLinks.key(a)
                if let known = topology[oldKey] { guard known == newKey else { return false } }
                else { guard seen.insert(newKey).inserted else { return false }; topology[oldKey] = newKey }
            }
            let path = node.relative.isEmpty ? snapshot.path : snapshot.path + "/" + node.relative
            guard try CacheNodeMetadata.read(path: path, identity: a) == expected.metadata else { return false }
            if !a.isDirectory, try VerifiedFileStream.digest(SafeFilesystem.fileSnapshot(path, in: snapshot)) != expected.digest { return false }
        }
        try SafeFilesystem.verify(snapshot)
        return true
    }
    private static func check(_ deadline: TimeInterval) throws {
        try Task.checkCancellation()
        guard ProcessInfo.processInfo.systemUptime < deadline else { throw SweepError.incomplete("独立归档核验或重建超时，停止并保留恢复资料") }
    }
    private static func hash(_ data: Data) throws -> String {
        #if canImport(CryptoKit)
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        #else
        throw SweepError.denied("当前平台未验证归档摘要")
        #endif
    }
}
