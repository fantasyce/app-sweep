#if os(macOS)
import Foundation
import Darwin
import CFSafety

/// History is evidence for recovery, never an executable reviewed plan.
struct ApplicationOptimizationRecord: Codable, Sendable, Identifiable {
    enum Status: String, Codable, Sendable {
        case preparing, prepared, publishing, published, undoing, restored, stopped, needsAttention, retained, purging, purged
        var unfinished: Bool { ![.published,.restored,.stopped,.retained,.purged].contains(self) }
    }
    struct Object: Codable, Sendable {
        let identity: FileIdentity
        let tree: TreeFingerprint
        let bytes: Int64
        let rootMetadata: String?
        init(_ snapshot: FileSnapshot) throws {
            identity = snapshot.identity; tree = try .capture(snapshot.tree); bytes = snapshot.bytes
            rootMetadata = try Self.rootDigest(snapshot)
        }
        /// Preparation already compared this root with the original's independent
        /// metadata commitment. A root-only ctime transition permits a bounded
        /// complete re-read, never a copy, exchange, or acceptance of new values.
        static func capturePrepared(_ expected: FileSnapshot, matchingRootMetadata committed: String) throws -> Self {
            guard case .application = expected.purpose else { throw SweepError.denied("准备对象必须是完整应用快照") }
            let deadline = ProcessInfo.processInfo.systemUptime + 2
            for attempt in 0..<3 {
                do {
                    if attempt > 0, ProcessInfo.processInfo.systemUptime >= deadline { throw SweepError.stale("准备包读取重试窗口已结束，两份对象均保留") }
                    try Task.checkCancellation()
                    let current = attempt == 0 ? expected : try SafeFilesystem.snapshot(expected.path,allowInternalLinks:true,purpose:.application,allowInternalHardLinks:true,reportRootChanges:true)
                    guard current.identity.sameObject(as:expected.identity), current.tree == expected.tree,
                          current.ancestors == expected.ancestors, current.bytes == expected.bytes else {
                        throw SweepError.stale("准备包身份、内容或祖先已改变，原包与副本均保留")
                    }
                    let object = try Self(current)
                    guard object.rootMetadata == committed else { throw SweepError.stale("准备包根目录权限或元数据不符合原包承诺") }
                    try SafeFilesystem.verify(current,reportRootChanges:true)
                    return object
                } catch let change as SnapshotRootChange {
                    guard change.path == expected.path, expected.identity.sameObject(as:change.before),
                          expected.identity.sameObject(as:change.after), attempt < 2,
                          ProcessInfo.processInfo.systemUptime < deadline else { throw change }
                    try Task.checkCancellation()
                    usleep(20_000)
                }
            }
            throw SweepError.stale("准备包根目录状态仍未稳定，两份对象均保留")
        }
        func matches(_ snapshot: FileSnapshot) throws -> Bool {
            try identity.sameObject(as:snapshot.identity) && bytes == snapshot.bytes && tree.matches(snapshot.tree) &&
                (rootMetadata == nil || rootMetadata == Self.rootDigest(snapshot))
        }
        private static func rootDigest(_ snapshot: FileSnapshot) throws -> String {
            let url = URL(fileURLWithPath:snapshot.path)
            let parent = try SafeDirectory(path:url.deletingLastPathComponent().path)
            var expected = snapshot.identity.native, digest = [UInt8](repeating:0,count:32)
            guard as_owned_application_root_digest(parent.fd,url.lastPathComponent,&expected,5000,&digest) == 0 else {
                if let now = try? parent.identity(url.lastPathComponent), now != snapshot.identity, now.sameObject(as:snapshot.identity) {
                    throw SnapshotRootChange(path:snapshot.path,before:snapshot.identity,after:now)
                }
                throw SweepError.stale("应用根目录的权限或元数据未确认，两份对象均保留")
            }
            return digest.map { String(format:"%02x",$0) }.joined()
        }
    }
    var schemaVersion: Int
    let id: UUID
    let ownerUID: UInt32
    let createdAt: Date
    let rule: String
    let applicationPath: String
    let identifier: String
    let architecture: String
    let nativeCodeHash: String
    let originalAncestors: [AncestorIdentity]
    let original: Object
    var prepared: Object?
    var status: Status
    var issue: String?
    var retainedCurrent: Object? = nil
    var retainedCurrentNativeHash: String? = nil
    var purgeOrigin: Status? = nil
    // The sole storage slot is derived from this batch, never a decoded path.
    var slot: String { id.uuidString }
}

/// Complete-bundle optimization, with a retained original and no in-place edits.
/// Only the actor's live single-use reviews can begin execution.
actor ApplicationOptimizationEngine {
    static let rule = "application-architecture-transaction-v1"
    static let purgeRule = "application-optimization-purge-v1"
    static let languageRule = "application-language-transaction-v1"
    struct Review: Sendable, Identifiable {
        let id: UUID
        let applicationPath: String
        let architecture: String
        let estimatedReductionBytes: Int64
        let retainedReasons: [String]
        let availableLanguages: [String]
    }
    struct KeepCurrentReview: Sendable, Identifiable {
        let id: UUID
        let batchID: UUID
        let applicationPath: String
        let retainedBackupBytes: Int64
    }
    struct PurgeReview: Sendable, Identifiable {
        let id: UUID
        let batchID: UUID
        let applicationPath: String
        let retainedBackupBytes: Int64
        let removesOriginal: Bool
    }
    private struct LiveKeepCurrentReview {
        let record: Data
        let batchID: UUID
        let installed: FileSnapshot
        let stored: FileSnapshot
        let nativeHash: String
        let issuedAt: TimeInterval
    }
    private enum Preparation: Sendable {
        case architecture(ApplicationArchitecturePreparation.Plan)
        case language(ApplicationLanguagePreparation.Plan)
        var source: FileSnapshot { switch self { case .architecture(let p):p.source;case .language(let p):p.source } }
        var identifier: String { switch self { case .architecture(let p):p.identifier;case .language(let p):p.identifier } }
        var architecture: String { switch self { case .architecture(let p):p.architecture;case .language(let p):p.architecture } }
        var nativeCodeHash: String { switch self { case .architecture(let p):p.nativeCodeHash;case .language(let p):p.nativeCodeHash } }
        var rule: String { switch self { case .architecture:ApplicationOptimizationEngine.rule;case .language:ApplicationOptimizationEngine.languageRule } }
        var estimatedReductionBytes: Int64 {
            switch self {
            case .architecture(let p):p.changes.reduce(Int64(0)) { $0 + $1.originalIdentity.size - Int64($1.slice.size) }
            case .language(let p):p.omitted.filter { $0.identity.mode & 0o170000 == 0o100000 }.reduce(Int64(0)) { $0 + $1.identity.size }
            }
        }
        var retainedReasons: [String] { switch self { case .architecture(let p):p.retained.map(\.reason);case .language(let p):p.retained } }
        var availableLanguages: [String] { switch self { case .architecture: [];case .language(let p):p.availableLanguages } }
        func verify(_ current: FileSnapshot) throws {
            switch self { case .architecture(let p):try p.verify(current);case .language(let p):try p.verify(current) }
        }
        func prepare(in batch: SafeDirectory, name: String) throws -> FileSnapshot {
            switch self {
            case .architecture(let p):try ApplicationArchitecturePreparation.prepare(p,in:batch,name:name).snapshot
            case .language(let p):try ApplicationLanguagePreparation.prepare(p,in:batch,name:name).snapshot
            }
        }
    }
    private struct LiveReview {
        let plan: Preparation
        let issuedAt: TimeInterval
    }
    private let policy: SafetyPolicy
    private var reviews: [UUID:LiveReview] = [:]
    private var keepReviews: [UUID:LiveKeepCurrentReview] = [:]
    private var purgeReviews: [UUID:LiveKeepCurrentReview] = [:]
    #if DEBUG
    enum FailurePoint { case none, beforePurgeRemoval, afterPurgeRemoval }
    private let failurePoint: FailurePoint
    #endif
    init() {
        policy = .current
        #if DEBUG
        failurePoint = .none
        #endif
    }
    #if DEBUG
    init(policy: SafetyPolicy, failurePoint: FailurePoint = .none) { self.policy = policy; self.failurePoint = failurePoint }
    #endif

    func review(_ path: String) throws -> Review {
        try createReview(path) { .architecture(try ApplicationArchitecturePreparation.analyze($0)) }
    }
    func reviewLanguages(_ path: String, retaining languages: [String]) throws -> Review {
        try createReview(path) { .language(try ApplicationLanguagePreparation.analyze($0,retaining:languages)) }
    }
    private func createReview(_ path: String, prepare: (FileSnapshot) throws -> Preparation) throws -> Review {
        try checkPath(path)
        let source = try snapshot(path)
        try ownedParent(source)
        try exclusiveNodes(source)
        let plan = try prepare(source)
        if reviews.count >= 4 { reviews.removeAll() }
        let id = UUID()
        reviews[id] = LiveReview(plan:plan,issuedAt:ProcessInfo.processInfo.systemUptime)
        return Review(id:id,applicationPath:path,architecture:plan.architecture,estimatedReductionBytes:plan.estimatedReductionBytes,retainedReasons:plan.retainedReasons,availableLanguages:plan.availableLanguages)
    }

    func execute(reviewID: UUID) throws -> ApplicationOptimizationRecord {
        guard policy.executionEnabled else { throw SweepError.denied("此平台的应用精简事务尚未验收，不能执行") }
        guard let reviewed = reviews.removeValue(forKey:reviewID),
              ProcessInfo.processInfo.systemUptime - reviewed.issuedAt < 300 else { throw SweepError.stale("精简核对未知、已使用或过期，请重新核对") }
        let plan = reviewed.plan
        guard policy.ruleIsValidated(plan.rule) else { throw SweepError.denied("此类应用精简事务尚未验收，不能执行") }
        try checkPath(plan.source.path); try plan.verify(plan.source)
        try ownedParent(plan.source)
        try inactive(plan.source,identifier:plan.identifier)
        let lease = try OptimizationJournal.lease(policy:policy,create:true)
        defer { as_close(lease) }
        try OptimizationJournal.ensureNoUnfinishedCleanup(policy:policy)
        try Self.ensureNoPending(policy:policy,paths:[plan.source.path],identifiers:[plan.identifier])
        let journal = try OptimizationJournal.open(policy:policy,create:true)!
        var record = ApplicationOptimizationRecord(schemaVersion:2,id:UUID(),ownerUID:getuid(),createdAt:Date(),rule:plan.rule,applicationPath:plan.source.path,identifier:plan.identifier,architecture:plan.architecture,nativeCodeHash:plan.nativeCodeHash,originalAncestors:plan.source.ancestors,original:try .init(plan.source),prepared:nil,status:.preparing,issue:nil)
        let batch = try journal.create(record)
        // Intent exists durably before copying even the first byte.
        let prepared = try plan.prepare(in:batch,name:record.slot)
        guard let rootMetadata = record.original.rootMetadata else { throw SweepError.denied("原包缺少独立根目录元数据承诺") }
        record.prepared = try .capturePrepared(prepared,matchingRootMetadata:rootMetadata); record.status = .prepared
        try journal.persist(record)
        try plan.verify(plan.source)
        let (installed,stored) = try pair(record,batch:batch,published:false)
        try inactive(installed,identifier:record.identifier)
        try BusyInspector.ensureUnused(stored)
        record.status = .publishing; try journal.persist(record)
        try exchange(installed,stored,batch:batch,name:record.slot)
        // Never retry an indeterminate exchange. The persisted intent remains.
        try verifyAfterExchange(record,batch:batch,published:true)
        record.status = .published; try journal.persist(record)
        return record
    }

    func history() throws -> [ApplicationOptimizationRecord] {
        guard let journal = try OptimizationJournal.open(policy:policy,create:false) else { return [] }
        let lease = try OptimizationJournal.lease(policy:policy,create:false)
        defer { as_close(lease) }
        return try journal.records()
    }

    func undo(batchID: UUID) throws -> ApplicationOptimizationRecord {
        guard policy.executionEnabled else { throw SweepError.denied("当前平台未验收应用精简恢复") }
        let lease = try OptimizationJournal.lease(policy:policy,create:false)
        defer { as_close(lease) }
        guard let journal = try OptimizationJournal.open(policy:policy,create:false) else { throw SweepError.denied("没有应用精简记录") }
        var record = try journal.read(batchID)
        guard record.purgeOrigin == nil, [.published,.needsAttention].contains(record.status), record.prepared != nil else { throw SweepError.denied("此记录需要先核对中断状态，或已经恢复") }
        let batch = try journal.batch(batchID)
        do {
            let (installed,stored) = try pair(record,batch:batch,published:true)
            try inactive(installed,identifier:record.identifier)
            try BusyInspector.ensureUnused(stored)
            record.status = .undoing; record.issue = nil; try journal.persist(record)
            try exchange(installed,stored,batch:batch,name:record.slot)
            try verifyAfterExchange(record,batch:batch,published:false)
            record.status = .restored; try journal.persist(record)
            return record
        } catch {
            // Keep the pre-exchange intent if a swap might have occurred. An
            // explicit reconciliation inspects both objects before any retry.
            if record.status != .undoing {
                record.status = .needsAttention
                record.issue = "安装包已更新、被占用或恢复对象未确认；两份对象均保留，未覆盖任何文件。"
                try journal.persist(record)
            }
            throw error
        }
    }

    /// A live reviewed choice only closes an obsolete restore transaction. It
    /// never exchanges, exports or deletes either application. A valid retained
    /// original remains necessary even when the current version is kept.
    func reviewKeepingCurrent(batchID: UUID) throws -> KeepCurrentReview {
        guard policy.executionEnabled else { throw SweepError.denied("当前平台未验收应用精简恢复") }
        let lease = try OptimizationJournal.lease(policy:policy,create:false)
        defer { as_close(lease) }
        guard let journal = try OptimizationJournal.open(policy:policy,create:false) else { throw SweepError.denied("没有应用精简记录") }
        let record = try journal.read(batchID), batch = try journal.batch(batchID)
        let (installed,stored,hash) = try keepCurrentPair(record,batch:batch)
        if keepReviews.count >= 4 { keepReviews.removeAll() }
        let id = UUID()
        keepReviews[id] = LiveKeepCurrentReview(record:try encoded(record),batchID:batchID,installed:installed,stored:stored,nativeHash:hash,issuedAt:ProcessInfo.processInfo.systemUptime)
        return KeepCurrentReview(id:id,batchID:batchID,applicationPath:record.applicationPath,retainedBackupBytes:stored.bytes)
    }
    func keepCurrent(reviewID: UUID) throws -> ApplicationOptimizationRecord {
        guard policy.executionEnabled else { throw SweepError.denied("当前平台未验收应用精简恢复") }
        guard let choice = keepReviews.removeValue(forKey:reviewID),
              ProcessInfo.processInfo.systemUptime - choice.issuedAt < 300 else { throw SweepError.stale("保留核对未知、已使用或过期，请重新核对") }
        let lease = try OptimizationJournal.lease(policy:policy,create:false)
        defer { as_close(lease) }
        guard let journal = try OptimizationJournal.open(policy:policy,create:false) else { throw SweepError.denied("没有应用精简记录") }
        var record = try journal.read(choice.batchID)
        guard try encoded(record) == choice.record else { throw SweepError.stale("恢复记录已改变，请重新核对") }
        try SafeFilesystem.verify(choice.installed); try SafeFilesystem.verify(choice.stored)
        let (installed,stored,hash) = try keepCurrentPair(record,batch:journal.batch(choice.batchID))
        guard installed.identity == choice.installed.identity, installed.tree == choice.installed.tree,
              installed.ancestors == choice.installed.ancestors, installed.bytes == choice.installed.bytes,
              stored.identity == choice.stored.identity, stored.tree == choice.stored.tree,
              stored.ancestors == choice.stored.ancestors, stored.bytes == choice.stored.bytes,
              hash == choice.nativeHash else { throw SweepError.stale("核对后应用或恢复对象已改变，两份对象保留") }
        record.retainedCurrent = try .init(installed)
        record.retainedCurrentNativeHash = hash
        try SafeFilesystem.verify(installed); try SafeFilesystem.verify(stored)
        record.schemaVersion = max(record.schemaVersion,3); record.status = .retained
        record.issue = "已明确保留核对时的当前应用，结束旧版本恢复事务；旧原包仍保留，未覆盖、删除或释放空间。"
        try journal.persist(record)
        return record
    }
    /// A permanent-removal capability is independent of the optimization grant.
    /// It binds a complete private backup and the unchanged installed app.
    func reviewPurge(batchID: UUID) throws -> PurgeReview {
        purgeReviews.removeAll()
        let lease = try OptimizationJournal.lease(policy:policy,create:false)
        defer { as_close(lease) }
        guard let journal = try OptimizationJournal.open(policy:policy,create:false) else { throw SweepError.denied("没有应用精简记录") }
        let record = try journal.read(batchID), batch = try journal.batch(batchID)
        guard record.schemaVersion >= 2, record.purgeOrigin == nil,
              [.published,.restored,.retained].contains(record.status) else { throw SweepError.denied("此副本缺少完整对象承诺，或需要先核对中断状态；继续保留") }
        let (installed,stored,hash) = try purgePair(record,batch:batch,origin:record.status)
        let id = UUID()
        purgeReviews[id] = LiveKeepCurrentReview(record:try encoded(record),batchID:batchID,installed:installed,stored:stored,nativeHash:hash,issuedAt:ProcessInfo.processInfo.systemUptime)
        return .init(id:id,batchID:batchID,applicationPath:record.applicationPath,retainedBackupBytes:stored.bytes,removesOriginal:record.status != .restored)
    }
    func purge(reviewID: UUID, confirmation: String) throws -> ApplicationOptimizationRecord {
        guard let choice = purgeReviews.removeValue(forKey:reviewID),
              ProcessInfo.processInfo.systemUptime - choice.issuedAt < 300 else { throw SweepError.stale("清空核对未知、已使用或过期，请重新核对") }
        guard confirmation == "永久清空 " + choice.batchID.uuidString else { throw SweepError.denied("永久清空确认不匹配此批次") }
        guard policy.executionEnabled, policy.ruleIsValidated(Self.purgeRule) else { throw SweepError.denied("此平台的恢复副本永久清空尚未独立验收") }
        let lease = try OptimizationJournal.lease(policy:policy,create:false)
        defer { as_close(lease) }
        try OptimizationJournal.ensureNoUnfinishedCleanup(policy:policy)
        guard let journal = try OptimizationJournal.open(policy:policy,create:false) else { throw SweepError.denied("没有应用精简记录") }
        var record = try journal.read(choice.batchID)
        guard policy.ruleIsValidated(record.rule), try encoded(record) == choice.record else { throw SweepError.stale("清空记录或规则已改变，请重新核对") }
        let batch = try journal.batch(choice.batchID)
        try SafeFilesystem.verify(choice.installed); try SafeFilesystem.verify(choice.stored)
        let (installed,stored,hash) = try purgePair(record,batch:batch,origin:record.status)
        guard installed.identity == choice.installed.identity, installed.tree == choice.installed.tree,
              installed.ancestors == choice.installed.ancestors, installed.bytes == choice.installed.bytes,
              stored.identity == choice.stored.identity, stored.tree == choice.stored.tree,
              stored.ancestors == choice.stored.ancestors, stored.bytes == choice.stored.bytes,
              hash == choice.nativeHash else { throw SweepError.stale("核对后当前应用或恢复副本已改变，继续保留") }
        try Task.checkCancellation()
        record.schemaVersion = 4; record.purgeOrigin = record.status; record.status = .purging; record.issue = nil
        try journal.persist(record) // Durable intent before any object removal.
        #if DEBUG
        if failurePoint == .beforePurgeRemoval { throw SweepError.incomplete("测试中断：清空意图已持久化，尚未删除") }
        #endif
        do {
            try Task.checkCancellation()
            try SafeFilesystem.verify(installed); try SafeFilesystem.verify(stored)
            try inactive(installed,identifier:record.identifier); try BusyInspector.ensureUnused(stored)
            guard SafeFilesystem.removeVerified(in:batch,name:record.slot,identity:stored.identity,contents:stored.tree,allowInternalHardLinks:true),
                  try !SafeFilesystem.presence(batch.path + "/" + record.slot), fsync(batch.fd) == 0 else { throw SweepError.filesystem("副本清空或持久化未确认；停止，不自动重试") }
            try SafeFilesystem.verify(installed)
        } catch {
            record.status = .needsAttention; record.issue = "永久清空未确认；不再处理剩余对象，请核对当前应用和副本状态。"
            try journal.persist(record)
            throw error
        }
        #if DEBUG
        if failurePoint == .afterPurgeRemoval { throw SweepError.incomplete("测试中断：副本已移除，完成记录尚未持久化") }
        #endif
        record.status = .purged; record.issue = "经核对的恢复副本已永久清空；当前应用与用户资料未作回退。"
        try journal.persist(record)
        return record
    }
    private func purgeInstalled(_ record: ApplicationOptimizationRecord, origin: ApplicationOptimizationRecord.Status) throws -> (FileSnapshot,String) {
        guard record.schemaVersion >= 2, let prepared = record.prepared,
              [.published,.restored,.retained].contains(origin) else { throw SweepError.denied("副本来源未确认") }
        let installed = try snapshot(record.applicationPath)
        let hash: String
        if origin == .retained {
            guard let current = record.retainedCurrent, let committedHash = record.retainedCurrentNativeHash,
                  installed.ancestors == record.originalAncestors, try current.matches(installed) else { throw SweepError.stale("已保留的当前应用已改变，副本继续保留") }
            try checkPath(installed.path); try ownedParent(installed); try exclusiveNodes(installed)
            hash = try ApplicationArchitecturePreparation.signature(installed.path,identifier:record.identifier,architecture:record.architecture)
            guard hash == committedHash else { throw SweepError.stale("当前应用签名已改变") }
        } else {
            try verify(installed,object:origin == .published ? prepared : record.original,record:record,originalLocation:true)
            hash = record.nativeCodeHash
        }
        try inactive(installed,identifier:record.identifier)
        try SafeFilesystem.verify(installed)
        return (installed,hash)
    }
    private func purgePair(_ record: ApplicationOptimizationRecord, batch: SafeDirectory, origin: ApplicationOptimizationRecord.Status) throws -> (FileSnapshot,FileSnapshot,String) {
        let (installed,hash) = try purgeInstalled(record,origin:origin)
        guard let prepared = record.prepared else { throw SweepError.denied("副本身份未确认") }
        let stored = try snapshot(batch.path + "/" + record.slot)
        try verify(stored,object:origin == .restored ? prepared : record.original,record:record,originalLocation:false)
        guard installed.identity.device == stored.identity.device else { throw SweepError.denied("恢复副本不在同一卷") }
        try exclusiveNodes(stored); try BusyInspector.ensureUnused(stored)
        try SafeFilesystem.verify(installed); try SafeFilesystem.verify(stored)
        return (installed,stored,hash)
    }
    private func reconcilePurge(_ original: ApplicationOptimizationRecord, journal: OptimizationJournal, batch: SafeDirectory) throws -> ApplicationOptimizationRecord {
        var record = original
        guard let origin = record.purgeOrigin else { throw SweepError.denied("永久清空来源未确认") }
        do {
            _ = try purgeInstalled(record,origin:origin)
            if try !SafeFilesystem.presence(batch.path + "/" + record.slot) {
                record.status = .purged; record.issue = "经核对副本已不存在，当前应用符合承诺；已结束清空记录。"
            } else {
                _ = try purgePair(record,batch:batch,origin:origin)
                record.status = origin; record.purgeOrigin = nil
                record.issue = "完整副本仍保留；中断清空已停止，如需永久清空必须重新核对确认。"
            }
        } catch {
            record.status = .needsAttention
            record.issue = "当前应用或副本不完整、变化或访问未确认；保留剩余对象，不自动继续清空或恢复。"
        }
        try journal.persist(record)
        return record
    }
    private func encoded(_ record: ApplicationOptimizationRecord) throws -> Data {
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601; encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(record)
    }
    private func keepCurrentPair(_ record: ApplicationOptimizationRecord, batch: SafeDirectory) throws -> (FileSnapshot,FileSnapshot,String) {
        guard [2,4].contains(record.schemaVersion), record.purgeOrigin == nil, [.published,.needsAttention].contains(record.status),
              let prepared = record.prepared, record.original.rootMetadata != nil else { throw SweepError.denied("此批次缺少可核对的已发布对象，不能结束恢复") }
        try checkPath(record.applicationPath)
        let installed = try snapshot(record.applicationPath), stored = try snapshot(batch.path + "/" + record.slot)
        guard installed.ancestors == record.originalAncestors,
              installed.identity.device == stored.identity.device,
              installed.identity.inode != record.original.identity.inode,
              try !prepared.matches(installed) else { throw SweepError.denied("当前包仍是原精简对象，应使用正常撤销") }
        try ownedParent(installed); try exclusiveNodes(installed)
        try verify(stored,object:record.original,record:record,originalLocation:false)
        try inactive(installed,identifier:record.identifier); try BusyInspector.ensureUnused(stored)
        let hash = try ApplicationArchitecturePreparation.signature(installed.path,identifier:record.identifier,architecture:record.architecture)
        try SafeFilesystem.verify(installed); try SafeFilesystem.verify(stored)
        return (installed,stored,hash)
    }

    /// Inspect, do not resume. Even a successful reconciliation makes no app move.
    func reconcile(batchID: UUID) throws -> ApplicationOptimizationRecord {
        let lease = try OptimizationJournal.lease(policy:policy,create:false)
        defer { as_close(lease) }
        guard let journal = try OptimizationJournal.open(policy:policy,create:false) else { throw SweepError.denied("没有应用精简记录") }
        var record = try journal.read(batchID)
        guard record.status.unfinished else { return record }
        let batch = try journal.batch(batchID)
        if record.purgeOrigin != nil {
            guard policy.executionEnabled, policy.ruleIsValidated(Self.purgeRule), policy.ruleIsValidated(record.rule) else { throw SweepError.denied("此平台未验收副本永久清空状态核对，记录和对象继续保留") }
            return try reconcilePurge(record,journal:journal,batch:batch)
        }
        do {
            if record.prepared == nil {
                let installed = try snapshot(record.applicationPath)
                try verify(installed,object:record.original,record:record,originalLocation:true)
                record.status = .stopped
                record.issue = "准备中断，原安装包完整保留；不自动继续，已有部分副本保留待核对。"
            } else if (try? pair(record,batch:batch,published:true)) != nil {
                record.status = .published; record.issue = nil
            } else {
                _ = try pair(record,batch:batch,published:false)
                let wasUndo = record.status == .undoing
                record.status = wasUndo ? .restored : .stopped
                record.issue = wasUndo ? nil : "原包仍在安装位置，已停止；不会自动发布准备包。"
            }
        } catch {
            record.status = .needsAttention
            record.issue = "两处对象或原安装位置已改变，无法确认中断状态；保留对象并等待人工核对。"
        }
        try journal.persist(record)
        return record
    }

    static func ensureNoPending(policy: SafetyPolicy, paths: [String], identifiers: Set<String>) throws {
        guard !paths.isEmpty, paths.count <= 2000 else { throw SweepError.denied("缺少有效的事务影响范围") }
        guard let journal = try OptimizationJournal.open(policy:policy,create:false) else { return }
        let owners = Set(identifiers.map { $0.lowercased() })
        for record in try journal.records() where record.status.unfinished {
            if owners.contains(record.identifier.lowercased()) || paths.contains(where: {
                SafetyPolicy.contains($0,record.applicationPath) || SafetyPolicy.contains(record.applicationPath,$0)
            }) { throw SweepError.denied("请先核对此应用未完成的精简或恢复记录") }
        }
    }
    private func checkPath(_ path: String) throws {
        guard getuid() != 0, geteuid() == getuid(), policy.systemScope == nil,
              SelectedApplicationRule.matches(path:path,policy:policy) else { throw SweepError.denied("精简应用位置受保护、属于其他用户或包内组件") }
    }
    private func snapshot(_ path: String, reportRootChanges: Bool = false) throws -> FileSnapshot {
        try SafeFilesystem.snapshot(path,allowInternalLinks:true,purpose:.application,allowInternalHardLinks:true,reportRootChanges:reportRootChanges)
    }
    private func ownedParent(_ snapshot: FileSnapshot) throws {
        let path = URL(fileURLWithPath:snapshot.path).deletingLastPathComponent().path
        let parent = try SafeDirectory(path:path), value = try parent.ownIdentity
        guard value.owner == getuid(), value.device == snapshot.identity.device,
              as_unshared_node_descriptor(parent.fd,getuid()) == 1 else { throw SweepError.denied("此安装目录需要独立的管理员精简事务，普通入口不能处理") }
        for expected in snapshot.ancestors {
            let directory = try SafeDirectory(path:expected.path)
            guard as_unshared_node_descriptor(directory.fd,expected.owner) == 1 else { throw SweepError.denied("应用祖先目录存在其他写入者") }
        }
    }
    /// A private destination cannot revoke another user's existing authority
    /// over a shared source node. Validate every physical node before issuing
    /// a review; later complete snapshots bind modes and ACL-changing ctimes.
    private func exclusiveNodes(_ source: FileSnapshot) throws {
        let deadline = ProcessInfo.processInfo.systemUptime + 300
        func check(_ path: String, _ expected: FileIdentity) throws {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw SweepError.incomplete("应用节点授权检查超时，原包保留") }
            if expected.isLink { return } // Links are closed bundle contents, not followed.
            let url = URL(fileURLWithPath:path), parent = try SafeDirectory(path:url.deletingLastPathComponent().path)
            let fd = openat(parent.fd,url.lastPathComponent,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)
            guard fd >= 0 else { throw SweepError.denied("应用节点访问权限未确认，原包保留") }
            defer { as_close(fd) }
            var before = ASIdentity(), after = ASIdentity()
            guard as_identity_fd(fd,&before) == 0, FileIdentity(before) == expected,
                  as_unshared_node_descriptor(fd,getuid()) == 1,
                  as_identity_fd(fd,&after) == 0, FileIdentity(after) == expected,
                  try parent.identity(url.lastPathComponent) == expected else {
                throw SweepError.denied("应用包节点存在共享写入权限、额外授权或身份变化，原包保留")
            }
        }
        try check(source.path,source.identity)
        for entry in source.tree { try check(source.path + "/" + entry.relative,entry.identity) }
        try SafeFilesystem.verify(source)
    }
    private func inactive(_ source: FileSnapshot, identifier: String) throws {
        try ChosenApplicationRule.verifyStored(path:source.path,identifier:identifier,requireNoInstalledHelpers:true)
        let labels = try ChosenApplicationRule.dependencyLabels(path:source.path)
        try ActivityInspector.ensureSystemServicesStopped(identifiers:[identifier]+labels,applicationPath:source.path)
        try ActivityInspector.ensureStopped(bundleID:identifier,applicationPath:source.path,additionalIdentifiers:labels)
        try BusyInspector.ensureUnused(source,allowReadOnlyLocalization:policy.ruleIsValidated(LocalizedResourceReader.name))
        try SafeFilesystem.verify(source)
    }
    private func verify(_ current: FileSnapshot, object: ApplicationOptimizationRecord.Object, record: ApplicationOptimizationRecord, originalLocation: Bool, reportRootChanges: Bool = false) throws {
        if originalLocation {
            try checkPath(current.path)
            guard current.ancestors == record.originalAncestors else { throw SweepError.stale("原安装位置的祖先已改变") }
            try ownedParent(current)
        }
        guard current.identity.owner == getuid(), current.tree.allSatisfy({ $0.identity.owner == getuid() && $0.identity.device == current.identity.device }),
              try object.matches(current),
              try ApplicationArchitecturePreparation.signature(current.path,identifier:record.identifier,architecture:record.architecture) == record.nativeCodeHash else {
            throw SweepError.stale("应用已更新、替换或内容改变；不会覆盖当前版本")
        }
        try SafeFilesystem.verify(current,reportRootChanges:reportRootChanges)
    }
    private func pair(_ record: ApplicationOptimizationRecord, batch: SafeDirectory, published: Bool, reportRootChanges: Bool = false) throws -> (FileSnapshot,FileSnapshot) {
        guard let prepared = record.prepared else { throw SweepError.denied("准备对象未完成") }
        let installed = try snapshot(record.applicationPath,reportRootChanges:reportRootChanges), stored = try snapshot(batch.path + "/" + record.slot,reportRootChanges:reportRootChanges)
        try verify(installed,object:published ? prepared : record.original,record:record,originalLocation:true,reportRootChanges:reportRootChanges)
        try verify(stored,object:published ? record.original : prepared,record:record,originalLocation:false,reportRootChanges:reportRootChanges)
        guard installed.identity.device == stored.identity.device else { throw SweepError.denied("精简恢复对象不在同一卷") }
        return (installed,stored)
    }
    /// A successful swap is never repeated. Only re-read the entire pair after
    /// a root-only ctime transition, with durable non-macl metadata commitments.
    /// Content, ACL, signature, identity and ancestor failures still stop at once.
    private func verifyAfterExchange(_ record: ApplicationOptimizationRecord, batch: SafeDirectory, published: Bool) throws {
        guard record.schemaVersion >= 2 else { _ = try pair(record,batch:batch,published:published); return }
        let deadline = ProcessInfo.processInfo.systemUptime + 2
        for attempt in 0..<3 {
            do { _ = try pair(record,batch:batch,published:published,reportRootChanges:true); return }
            catch let change as SnapshotRootChange {
                guard [record.applicationPath,batch.path + "/" + record.slot].contains(change.path),
                      change.before.sameObject(as:change.after), attempt < 2,
                      ProcessInfo.processInfo.systemUptime < deadline else { throw change }
                try Task.checkCancellation()
                usleep(20_000)
            }
        }
    }
    private func exchange(_ installed: FileSnapshot, _ stored: FileSnapshot, batch: SafeDirectory, name: String) throws {
        try SafeFilesystem.verify(installed); try SafeFilesystem.verify(stored)
        let parent = try SafeDirectory(path:URL(fileURLWithPath:installed.path).deletingLastPathComponent().path)
        var a = installed.identity.native, b = stored.identity.native
        var ap = try parent.ownIdentity.native, bp = try batch.ownIdentity.native
        let result = as_exchange_owned_directories(parent.fd,URL(fileURLWithPath:installed.path).lastPathComponent,&a,&ap,batch.fd,name,&b,&bp)
        guard result == 0 else { throw SweepError.filesystem(result == -2 ? "交换或持久化结果未确认，必须核对两处对象；不会自动重试" : "交换未完成或身份改变；原包与准备包均保留") }
    }
}

private final class OptimizationJournal {
    private let directory: SafeDirectory
    private let ancestors: [AncestorIdentity]
    private let policy: SafetyPolicy
    private init(_ directory: SafeDirectory, policy: SafetyPolicy) throws {
        self.directory = directory; self.policy = policy
        ancestors = try SafeFilesystem.ancestors(of:directory.path)
        try verify()
    }
    private static func root(policy: SafetyPolicy, create: Bool) throws -> SafeDirectory? {
        guard getuid() != 0, geteuid() == getuid(), policy.systemScope == nil,
              policy.home.hasPrefix("/"), !policy.home.contains("\0"), policy.home == URL(fileURLWithPath:policy.home).standardizedFileURL.path else { throw SweepError.denied("应用精简账户范围未确认") }
        let supportPath = policy.home + "/Library/Application Support"
        for ancestor in try SafeFilesystem.ancestors(of:supportPath) {
            let parent = try SafeDirectory(path:ancestor.path)
            guard as_unshared_node_descriptor(parent.fd,ancestor.owner) == 1 else { throw SweepError.denied("应用精简记录祖先可被其他用户改写") }
        }
        let support = try SafeDirectory(path:supportPath)
        guard try support.ownIdentity.owner == getuid() else { throw SweepError.denied("应用精简记录不属于当前账户") }
        if create {
            guard let root = try support.appSweepSupport(create: true) else { throw SweepError.denied("应用精简记录父目录不存在") }
            guard fsync(support.fd) == 0 else { throw SweepError.filesystem("无法持久化精简记录的父目录") }
            return root
        }
        return try support.appSweepSupport(create: false)
    }
    static func open(policy: SafetyPolicy, create: Bool) throws -> OptimizationJournal? {
        guard let root = try root(policy:policy,create:create) else { return nil }
        if create {
            let directory = try root.privateChild("Optimization.noindex")
            guard fsync(root.fd) == 0 else { throw SweepError.filesystem("无法持久化新建精简记录目录") }
            return try .init(directory,policy:policy)
        }
        guard try SafeFilesystem.presence(root.path + "/Optimization.noindex") else { return nil }
        return try .init(root.existingPrivateChild("Optimization.noindex"),policy:policy)
    }
    static func lease(policy: SafetyPolicy, create: Bool) throws -> Int32 {
        guard let root = try root(policy:policy,create:create) else { throw SweepError.denied("应用恢复区不存在") }
        let recovery = try create ? root.privateChild("Recovery") : root.existingPrivateChild("Recovery")
        if create, fsync(root.fd) != 0 { throw SweepError.filesystem("无法持久化恢复操作锁目录") }
        let descriptor = fcntl(recovery.fd,F_DUPFD_CLOEXEC,3)
        guard descriptor >= 0 else { throw SweepError.filesystem("无法持有恢复操作锁") }
        guard as_lock(descriptor) == 0 else { as_close(descriptor); throw SweepError.denied("另一清理或恢复操作正在执行") }
        return descriptor
    }
    static func ensureNoUnfinishedCleanup(policy: SafetyPolicy) throws {
        guard let root = try root(policy:policy,create:false) else { throw SweepError.denied("恢复目录不存在") }
        let recovery = try root.existingPrivateChild("Recovery")
        let names = try FileManager.default.contentsOfDirectory(atPath:recovery.path)
        guard names.count <= 1000 else { throw SweepError.incomplete("恢复记录超过核对容量") }
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        for name in names {
            guard let id = UUID(uuidString:name), id.uuidString == name else { throw SweepError.denied("存在未确认的恢复记录") }
            let batch = try recovery.existingPrivateChild(name)
            let record = try decoder.decode(RecoveryManifest.self,from:batch.read("manifest.json"))
            guard RecoveryManifest.userSchemaVersions.contains(record.schemaVersion), record.id == id, record.requestingUserID == nil,
                  !record.hasUnconfirmedObjects, ![.inProgress,.purging,.needsAttention].contains(record.status) else { throw SweepError.denied("请先核对未完成的清理恢复记录") }
        }
    }
    private func verify() throws {
        guard try SafeFilesystem.ancestors(of:directory.path) == ancestors, as_private_descriptor(directory.fd) == 1 else { throw SweepError.stale("应用精简记录目录已变化") }
        for ancestor in ancestors {
            let parent = try SafeDirectory(path:ancestor.path)
            guard as_unshared_node_descriptor(parent.fd,ancestor.owner) == 1 else { throw SweepError.stale("应用精简记录祖先权限已变化") }
        }
    }
    func batch(_ id: UUID) throws -> SafeDirectory { try verify(); return try directory.existingPrivateChild(id.uuidString) }
    func create(_ record: ApplicationOptimizationRecord) throws -> SafeDirectory {
        try verify(); try validate(record,id:record.id)
        guard try FileManager.default.contentsOfDirectory(atPath:directory.path).count < 1000,
              mkdirat(directory.fd,record.id.uuidString,0o700) == 0,
              fsync(directory.fd) == 0 else { throw SweepError.filesystem("无法独占建立并持久化精简批次") }
        try persist(record); return try batch(record.id)
    }
    func persist(_ record: ApplicationOptimizationRecord) throws {
        try verify(); try validate(record,id:record.id)
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601; encoder.outputFormatting = [.sortedKeys,.withoutEscapingSlashes]
        let bytes = try encoder.encode(record)
        guard bytes.count <= 128*1024 else { throw SweepError.incomplete("应用精简记录超出容量") }
        try batch(record.id).write(bytes,name:"optimization.json")
        try verify()
    }
    func read(_ id: UUID) throws -> ApplicationOptimizationRecord {
        let batch = try batch(id), path = batch.path + "/optimization.json"
        let expected = try SafeFilesystem.snapshot(path)
        guard expected.identity.owner == getuid(), expected.identity.mode & 0o7077 == 0,
              expected.identity.links == 1, expected.identity.size <= 128*1024 else { throw SweepError.denied("应用精简记录权限、类型或容量未确认") }
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        let record = try decoder.decode(ApplicationOptimizationRecord.self,from:SafeFilesystem.readMetadata(path,maximumBytes:128*1024))
        try SafeFilesystem.verify(expected); try validate(record,id:id); try verify()
        if record.status == .purged, try SafeFilesystem.presence(batch.path + "/" + record.slot) { throw SweepError.denied("已清空记录仍有未知存储对象，必须人工核对") }
        return record
    }
    func records() throws -> [ApplicationOptimizationRecord] {
        try verify()
        let names = try FileManager.default.contentsOfDirectory(atPath:directory.path)
        guard names.count <= 1000 else { throw SweepError.incomplete("应用精简记录超过核对容量，不能当作没有记录") }
        let result = try names.sorted().map { name -> ApplicationOptimizationRecord in
            guard let id = UUID(uuidString:name), id.uuidString == name else { throw SweepError.denied("存在未确认的应用精简目录") }
            return try read(id)
        }
        return result.sorted { $0.createdAt > $1.createdAt }
    }
    private func validate(_ r: ApplicationOptimizationRecord, id: UUID) throws {
        guard [1,2,3,4].contains(r.schemaVersion), r.id == id, r.ownerUID == getuid(),
              (r.rule == ApplicationOptimizationEngine.rule || (r.schemaVersion >= 2 && r.rule == ApplicationOptimizationEngine.languageRule)),
              SelectedApplicationRule.matches(path:r.applicationPath,policy:policy),
              AppInspector.validIdentifier(r.identifier), !r.identifier.lowercased().hasPrefix("com.apple."),
              !["org.appsweep.app","org.appsweep.cli"].contains(r.identifier.lowercased()),
              r.architecture == PlatformStamp.current?.architecture,
              r.nativeCodeHash.count == 40, r.nativeCodeHash.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              !r.originalAncestors.isEmpty, r.originalAncestors.count <= 128,
              r.originalAncestors.last?.path == URL(fileURLWithPath:r.applicationPath).deletingLastPathComponent().path,
              (r.issue?.utf8.count ?? 0) <= 16*1024 else { throw SweepError.denied("应用精简记录的范围、版本或身份无效") }
        for object in [r.original,r.prepared,r.retainedCurrent].compactMap({ $0 }) {
            guard object.identity.isDirectory, object.identity.owner == getuid(), object.identity.mode & 0o7022 == 0,
                  object.bytes >= 0, object.tree.validCacheTree || object.tree.validLargeTree else { throw SweepError.denied("应用精简对象身份或树承诺无效") }
            if let digest = object.rootMetadata {
                guard digest.utf8.count == 64, digest.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw SweepError.denied("应用根目录元数据承诺无效") }
            } else if r.schemaVersion >= 2 { throw SweepError.denied("应用精简记录缺少根目录元数据承诺") }
        }
        if r.status != .preparing && r.status != .stopped && r.status != .needsAttention && r.prepared == nil {
            throw SweepError.denied("应用精简阶段缺少准备对象身份")
        }
        if let origin = r.purgeOrigin {
            guard r.schemaVersion == 4, [.published,.restored,.retained].contains(origin),
                  [.purging,.purged,.needsAttention].contains(r.status), r.prepared != nil else { throw SweepError.denied("永久清空来源与阶段不一致") }
        } else if [.purging,.purged].contains(r.status) {
            throw SweepError.denied("永久清空记录缺少原阶段")
        }
        if r.status == .retained || r.purgeOrigin == .retained {
            guard [3,4].contains(r.schemaVersion), let current = r.retainedCurrent, let hash = r.retainedCurrentNativeHash,
                  r.prepared != nil, current.identity.device == r.original.identity.device,
                  current.identity.inode != r.original.identity.inode,
                  hash.utf8.count == 40, hash.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw SweepError.denied("保留当前版本的确认记录缺少独立对象承诺") }
        } else if r.schemaVersion == 3 || r.retainedCurrent != nil || r.retainedCurrentNativeHash != nil {
            throw SweepError.denied("保留确认记录与事务阶段不一致")
        }
        if let prepared = r.prepared {
            guard prepared.identity.device == r.original.identity.device, prepared.identity.inode != r.original.identity.inode,
                  prepared.bytes < r.original.bytes else { throw SweepError.denied("应用精简两份对象或缩减量未确认") }
        }
    }
}
#endif
