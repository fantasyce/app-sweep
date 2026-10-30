#if os(macOS)
import Foundation
import CFSafety
import Darwin

/// Group state is recovery evidence only. No stored plan, path or receipt can
/// authorize cleanup; execution still consumes the live engines' own plans.
public struct CleanupRunReceipt: Codable, Sendable, Identifiable {
    public enum Status: String, Codable, Sendable { case prepared, running, isolated, rollingBack, rolledBack, needsAttention }
    public struct Entry: Codable, Sendable {
        public enum State: String, Codable, Sendable { case pending, submitted, isolated, restoring, restored, rolledBack, needsAttention }
        public let source: CleanupSource
        public let planID: UUID
        public var batchID: UUID?
        public var state: State
    }
    public let schemaVersion: Int
    public let id: UUID
    public let ownerUID: UInt32
    public let createdAt: Date
    public var status: Status
    public var entries: [Entry]
    public var issue: String?
}

final class CleanupCoordinationJournal {
    private let directory: SafeDirectory
    private let ancestors: [AncestorIdentity]
    private init(directory: SafeDirectory) throws {
        self.directory = directory
        ancestors = try SafeFilesystem.ancestors(of:directory.path)
        try verify()
    }
    static func open(path: String, create: Bool) throws -> CleanupCoordinationJournal? {
        guard as_current_uid() != 0, path.hasSuffix("/Library/Application Support/App Sweep/Coordination.noindex"),
              path == URL(fileURLWithPath:path).standardizedFileURL.path else { throw SweepError.denied("组合清理日志范围未确认") }
        let supportPath = URL(fileURLWithPath:path).deletingLastPathComponent().deletingLastPathComponent().path
        for ancestor in try SafeFilesystem.ancestors(of:supportPath) {
            let parent = try SafeDirectory(path:ancestor.path)
            guard as_unshared_node_descriptor(parent.fd,ancestor.owner) == 1 else { throw SweepError.denied("组合日志祖先可被其他用户改写") }
        }
        let support = try SafeDirectory(path:supportPath)
        guard try support.ownIdentity.owner == as_current_uid() else { throw SweepError.denied("组合日志不属于当前账户") }
        if !create {
            guard try SafeFilesystem.presence(path) else { return nil }
            guard let root = try support.appSweepSupport(create: false) else { throw SweepError.denied("组合日志父目录不存在") }
            return try Self(directory:root.existingPrivateChild("Coordination.noindex"))
        }
        guard let root = try support.appSweepSupport(create: true) else { throw SweepError.denied("组合日志父目录不存在") }
        return try Self(directory:root.privateChild("Coordination.noindex"))
    }
    private func verify() throws {
        guard try SafeFilesystem.ancestors(of:directory.path) == ancestors,
              as_private_descriptor(directory.fd) == 1 else { throw SweepError.stale("组合日志目录身份或权限已改变") }
        for ancestor in ancestors {
            let current = try SafeDirectory(path:ancestor.path)
            guard as_unshared_node_descriptor(current.fd,ancestor.owner) == 1 else { throw SweepError.stale("组合日志祖先权限已改变") }
        }
    }
    func create(_ receipt: CleanupRunReceipt) throws {
        try verify()
        guard try FileManager.default.contentsOfDirectory(atPath:directory.path).count < 1000 else { throw SweepError.incomplete("组合操作记录过多，请先核对保留记录") }
        guard mkdirat(directory.fd,receipt.id.uuidString,0o700) == 0 else { throw SweepError.denied("组合操作记录已存在，不能覆盖") }
        try persist(receipt)
    }
    func persist(_ receipt: CleanupRunReceipt) throws {
        try verify(); try validate(receipt,id:receipt.id)
        let batch = try directory.existingPrivateChild(receipt.id.uuidString)
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601; encoder.outputFormatting = [.sortedKeys,.withoutEscapingSlashes]
        let data = try encoder.encode(receipt)
        guard data.count <= 64*1024 else { throw SweepError.incomplete("组合日志超过容量") }
        try batch.write(data,name:"coordination.json")
        try verify()
    }
    func pending() throws -> [CleanupRunReceipt] {
        try verify()
        let names = try FileManager.default.contentsOfDirectory(atPath:directory.path)
        guard names.count <= 1000 else { throw SweepError.incomplete("组合操作记录过多，不能当作没有记录") }
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        var result: [CleanupRunReceipt] = []
        for name in names.sorted() {
            guard let id = UUID(uuidString:name), id.uuidString == name else { throw SweepError.denied("组合日志中存在未登记名称") }
            let batch = try directory.existingPrivateChild(name), path = batch.path + "/coordination.json"
            guard try SafeFilesystem.presence(path) else { throw SweepError.incomplete("组合操作日志未写完，需要核对") }
            let snapshot = try SafeFilesystem.snapshot(path)
            guard snapshot.identity.owner == as_current_uid(), snapshot.identity.mode & 0o77 == 0,
                  snapshot.identity.size <= 64*1024 else { throw SweepError.denied("组合日志文件权限或容量未确认") }
            let receipt = try decoder.decode(CleanupRunReceipt.self,from:SafeFilesystem.readMetadata(path,maximumBytes:64*1024))
            try SafeFilesystem.verify(snapshot); try validate(receipt,id:id)
            if ![.isolated,.rolledBack].contains(receipt.status) { result.append(receipt) }
        }
        try verify()
        return result.sorted { $0.createdAt > $1.createdAt }
    }
    private func validate(_ receipt: CleanupRunReceipt,id: UUID) throws {
        guard receipt.schemaVersion == 1, receipt.id == id, receipt.ownerUID == as_current_uid(),
              !receipt.entries.isEmpty, receipt.entries.count <= CleanupSource.allCases.count,
              Set(receipt.entries.map(\.source)).count == receipt.entries.count,
              Set(receipt.entries.map(\.planID)).count == receipt.entries.count,
              (receipt.issue?.utf8.count ?? 0) <= 16*1024 else { throw SweepError.denied("组合日志版本、账户或来源未确认") }
    }
}
#endif
