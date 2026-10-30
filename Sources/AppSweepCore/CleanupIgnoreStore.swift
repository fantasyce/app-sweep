import Foundation
import CFSafety
#if os(macOS)
import Darwin
#else
import Glibc
#endif

/// User restrictions only. Neither a decoded list nor a path in it authorizes
/// discovery, access, execution or restoration of that path.
public struct CleanupIgnoreList: Codable, Sendable, Equatable {
    public let schemaVersion: Int
    public let revision: UUID
    public let paths: [String]
    public let categories: [CandidateCategory]
    public static let supportedCategories: [CandidateCategory] = [.cache,.log,.development,.userData,.deviceBackup]
    init(schemaVersion: Int, revision: UUID, paths: [String], categories: [CandidateCategory] = []) {
        self.schemaVersion = schemaVersion; self.revision = revision; self.paths = paths; self.categories = categories
    }
    private enum CodingKeys: String, CodingKey { case schemaVersion, revision, paths, categories }
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy:CodingKeys.self)
        schemaVersion = try values.decode(Int.self,forKey:.schemaVersion)
        revision = try values.decode(UUID.self,forKey:.revision)
        paths = try values.decode([String].self,forKey:.paths)
        // Schema 2 must explicitly carry restrictions, including an empty set.
        // Schema 1 remains readable only when it has no category restrictions.
        categories = schemaVersion == 2 ? try values.decode([CandidateCategory].self,forKey:.categories) :
            try values.decodeIfPresent([CandidateCategory].self,forKey:.categories) ?? []
    }
    static let empty = Self(schemaVersion:1,revision:UUID(uuid:(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)),paths:[])
    static func key(_ path: String) -> String { path.precomposedStringWithCanonicalMapping.lowercased() }
    static func validPath(_ path: String) -> Bool {
        path.hasPrefix("/") && path.count > 1 && path.utf8.count <= 4096 && !path.contains("\0") &&
        !path.hasSuffix("/") && !path.contains("//") && !path.split(separator:"/").contains(where:{ $0 == "." || $0 == ".." })
    }
    func validate() throws {
        guard [1,2].contains(schemaVersion), schemaVersion == 2 || categories.isEmpty,
              revision != Self.empty.revision, paths.count <= 1000,
              categories.count <= Self.supportedCategories.count,
              Set(categories).count == categories.count, categories.allSatisfy(Self.supportedCategories.contains),
              paths.allSatisfy(Self.validPath), Set(paths.map(Self.key)).count == paths.count else {
            throw SweepError.denied("忽略列表版本或内容未确认，请先核对设置")
        }
    }
    func reason(for item: Candidate) -> String? {
        categories.contains(item.category) ? "用户已保留此分类：" + item.category.title : reason(for:item.path)
    }
    func reason(for path: String) -> String? {
        let candidate = Self.key(path)
        return paths.contains { ignored in
            let key = Self.key(ignored)
            return SafetyPolicy.contains(key,candidate) || SafetyPolicy.contains(candidate,key)
        } ? "用户已忽略此项目或其中的内容" : nil
    }
    func applying(to report: ScanReport) -> ScanReport {
        var items = report.candidates.map { original in
            var item = original
            if let reason = reason(for:item) { item.ignoredReason = reason }
            return item
        }
        let groups = Set(items.filter { $0.ignoredReason != nil }.compactMap(\.selectionGroupID))
        for index in items.indices where items[index].selectionGroupID.map({ groups.contains($0) }) == true {
            if items[index].ignoredReason == nil { items[index].ignoredReason = "关联缓存包含忽略项目，整组保留" }
        }
        return ScanReport(schemaVersion:report.schemaVersion,id:report.id,createdAt:report.createdAt,ruleVersion:report.ruleVersion,
                          applicationPath:report.applicationPath,candidates:items,complete:report.complete,issues:report.issues,
                          platformLimitation:report.platformLimitation,scopes:report.scopes,ignoreRevision:revision)
    }
}

final class CleanupIgnoreLease: Sendable {
    // Immutable, private duplicate descriptors retain the locks until the last
    // lease reference dies. No descriptor escapes or mutable SafeDirectory is
    // transferred between isolation domains.
    private let descriptors: [Int32]
    let ancestors: [AncestorIdentity]
    init(directories: [SafeDirectory], ancestors: [AncestorIdentity]) throws {
        var descriptors: [Int32] = []
        do {
            for directory in directories {
                let fd = fcntl(directory.fd,F_DUPFD_CLOEXEC,0)
                guard fd >= 0 else { throw SweepError.denied("不能保留忽略设置的操作锁") }
                descriptors.append(fd)
            }
        } catch { for fd in descriptors { as_close(fd) }; throw error }
        self.descriptors = descriptors; self.ancestors = ancestors
    }
    deinit { for fd in descriptors { as_close(fd) } }
    func keepAlive() { withExtendedLifetime(self) {} }
    func verify() throws {
        guard let last = ancestors.last, try SafeFilesystem.ancestors(of:last.path) == ancestors else {
            throw SweepError.stale("忽略设置目录已改变，请重新扫描")
        }
    }
}

/// The location and owner come from the engine's authenticated context, never
/// from JSON or a request. Root may read this restriction but never write it.
struct CleanupIgnoreStore {
    let home: String
    let ownerUID: UInt32
    private let filename = "cleanup-ignores.json"
    private let maximumBytes = 1024 * 1024

    private func directory(create: Bool) throws -> SafeDirectory? {
        guard ownerUID >= 500, CleanupIgnoreList.validPath(home), !create || (as_current_uid() == ownerUID && ownerUID != 0) else {
            throw SweepError.denied("忽略设置账户未确认")
        }
        for ancestor in try SafeFilesystem.ancestors(of:home) {
            let node = try SafeDirectory(path:ancestor.path)
            guard [0,ownerUID].contains(ancestor.owner), as_unshared_node_descriptor(node.fd,ancestor.owner) == 1 else {
                throw SweepError.denied("忽略设置祖先权限未确认")
            }
        }
        var current = try SafeDirectory(path:home)
        let identity = try current.ownIdentity
        guard identity.owner == ownerUID else { throw SweepError.denied("忽略设置主目录不属于当前账户") }
        for name in ["Library","Application Support","App Sweep","Settings.noindex"] {
            let path = current.path + "/" + name
            if try !SafeFilesystem.presence(path) {
                guard create else { return nil }
                current = try current.privateChild(name)
            } else { current = try SafeDirectory(path:path) }
            let node = try current.ownIdentity
            // The legacy app created a normal 0755 support directory for backups.
            // Only the settings leaf must be private; every ancestor still must
            // belong to this user and reject other writers and granting ACLs.
            let privateRequired = name == "Settings.noindex"
            guard node.owner == ownerUID, node.device == identity.device,
                  as_unshared_node_descriptor(current.fd,ownerUID) == 1,
                  !privateRequired || node.mode & 0o77 == 0 else { throw SweepError.denied("忽略设置目录身份或权限未确认") }
        }
        return current
    }
    func read() throws -> CleanupIgnoreList {
        guard let directory = try directory(create:false) else { return .empty }
        return try read(in:directory)
    }
    private func read(in directory: SafeDirectory) throws -> CleanupIgnoreList {
        let path = directory.path + "/" + filename
        guard try SafeFilesystem.presence(path) else { return .empty }
        let snapshot = try SafeFilesystem.snapshot(path)
        guard snapshot.identity.owner == ownerUID, snapshot.identity.mode & 0o77 == 0,
              !snapshot.identity.isDirectory, snapshot.identity.size <= maximumBytes else { throw SweepError.denied("忽略列表文件权限或容量未确认") }
        let fd = openat(directory.fd,filename,O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw SweepError.denied("无法读取忽略列表") }
        defer { as_close(fd) }
        guard as_unshared_node_descriptor(fd,ownerUID) == 1 else { throw SweepError.denied("忽略列表包含未确认访问权限") }
        let list = try JSONDecoder().decode(CleanupIgnoreList.self,from:SafeFilesystem.readMetadata(path,maximumBytes:maximumBytes))
        try list.validate(); try SafeFilesystem.verify(snapshot)
        return list
    }
    private func lockedHome() throws -> SafeDirectory {
        // This existing directory also serializes first-time settings creation.
        // The privileged reader never creates files in the user's home.
        _ = try directory(create:false)
        let root = try SafeDirectory(path:home)
        guard try root.ownIdentity.owner == ownerUID, as_unshared_node_descriptor(root.fd,ownerUID) == 1,
              as_lock(root.fd) == 0 else { throw SweepError.denied("忽略设置正在被其他操作使用") }
        return root
    }
    func executionLease(_ expected: CleanupIgnoreList) throws -> CleanupIgnoreLease {
        let root = try lockedHome()
        var directories = [root]
        if let directory = try directory(create:false) {
            guard as_lock(directory.fd) == 0 else { throw SweepError.denied("忽略设置正在被其他操作使用") }
            directories.append(directory)
        }
        let lease = try CleanupIgnoreLease(directories:directories,ancestors:SafeFilesystem.ancestors(of:directories.last!.path))
        for directory in directories {
            let identity = try directory.ownIdentity
            guard lease.ancestors.contains(where:{ $0.path == directory.path && $0.inode == identity.inode && $0.device == identity.device }) else {
                throw SweepError.stale("忽略设置目录身份已改变")
            }
        }
        try verify(expected,lease:lease)
        return lease
    }
    func verify(_ expected: CleanupIgnoreList, lease: CleanupIgnoreLease? = nil) throws {
        try lease?.verify()
        guard try read() == expected else { throw SweepError.stale("忽略设置已改变，请重新扫描并核对计划") }
        try lease?.verify()
    }
    func update(path: String, adding: Bool, expectedRevision: UUID) throws -> CleanupIgnoreList {
        guard CleanupIgnoreList.validPath(path) else { throw SweepError.invalid("忽略路径必须是明确的绝对路径，不能使用别名") }
        return try update(expectedRevision:expectedRevision) { old in
            let key = CleanupIgnoreList.key(path), exists = old.paths.contains { CleanupIgnoreList.key($0) == key }
            guard exists != adding else { return nil }
            let paths = adding ? old.paths + [path] : old.paths.filter { CleanupIgnoreList.key($0) != key }
            return CleanupIgnoreList(schemaVersion:2,revision:UUID(),paths:paths.sorted(),categories:old.categories)
        }
    }
    func update(category: CandidateCategory, ignored: Bool, expectedRevision: UUID) throws -> CleanupIgnoreList {
        guard CleanupIgnoreList.supportedCategories.contains(category) else { throw SweepError.invalid("此分类不支持忽略设置") }
        return try update(expectedRevision:expectedRevision) { old in
            guard old.categories.contains(category) != ignored else { return nil }
            let categories = ignored ? old.categories + [category] : old.categories.filter { $0 != category }
            return CleanupIgnoreList(schemaVersion:2,revision:UUID(),paths:old.paths,categories:categories.sorted { $0.rawValue < $1.rawValue })
        }
    }
    private func update(expectedRevision: UUID, changed: (CleanupIgnoreList) -> CleanupIgnoreList?) throws -> CleanupIgnoreList {
        let root = try lockedHome()
        defer { withExtendedLifetime(root) {} }
        guard let directory = try directory(create:true), as_lock(directory.fd) == 0 else { throw SweepError.denied("忽略设置正在被其他操作使用") }
        defer { withExtendedLifetime(directory) {} }
        let ancestors = try SafeFilesystem.ancestors(of:directory.path)
        let old = try read(in:directory)
        guard old.revision == expectedRevision else { throw SweepError.stale("忽略列表已被修改，请重新读取后操作") }
        guard let next = changed(old) else { return old }
        try next.validate()
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys,.withoutEscapingSlashes]
        let data = try encoder.encode(next)
        guard data.count <= maximumBytes, try SafeFilesystem.ancestors(of:directory.path) == ancestors else { throw SweepError.denied("忽略设置容量或目录身份已改变") }
        try directory.write(data,name:filename)
        guard try SafeFilesystem.ancestors(of:directory.path) == ancestors, try read() == next else { throw SweepError.stale("忽略设置保存结果未确认，请重新读取") }
        return next
    }
}
