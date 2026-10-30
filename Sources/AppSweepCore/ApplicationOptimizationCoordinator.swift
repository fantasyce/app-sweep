#if os(macOS)
import Foundation
import CFSafety

public enum ApplicationOptimizationKind: String, CaseIterable, Sendable {
    case architectures, languages
    public var title: String { switch self { case .architectures: "架构精简";case .languages: "语言精简" } }
    fileprivate var rule: String { switch self { case .architectures:ApplicationOptimizationEngine.rule;case .languages:ApplicationOptimizationEngine.languageRule } }
}
public struct ApplicationOptimizationReview: Identifiable, Sendable {
    public let id: UUID
    public let kind: ApplicationOptimizationKind
    public let applicationPath: String
    public let estimatedReductionBytes: Int64
    public let retainedReasons: [String]
    public let availableLanguages: [String]
    public let executionAvailable: Bool
    public let limitation: String?
}
public struct ApplicationOptimizationBatch: Identifiable, Sendable {
    public enum Status: String, Sendable {
        case preparing, prepared, publishing, published, undoing, restored, stopped, needsAttention, retained, purging, purged
    }
    public let id: UUID
    public let kind: ApplicationOptimizationKind
    public let applicationPath: String
    public let status: Status
    public let createdAt: Date
    /// Recorded retained-object size. Unknown/interrupted orientation is nil.
    /// This is never an amount of released disk space.
    public let storedBytes: Int64?
    public let issue: String?
    public let limitation: String?
    /// These allow requesting a fresh verification, not bypassing that check.
    public let canRestore: Bool
    public let canInspect: Bool
    public let canKeepCurrent: Bool
    public let canReviewPurge: Bool
    public let purgeLimitation: String?
}
public struct ApplicationOptimizationKeepReview: Identifiable, Sendable {
    public let id: UUID
    public let batchID: UUID
    public let applicationPath: String
    public let retainedBackupBytes: Int64
}

public struct ApplicationOptimizationPurgeReview: Identifiable, Sendable {
    public let id: UUID
    public let batchID: UUID
    public let applicationPath: String
    public let retainedBackupBytes: Int64
    public let removesOriginal: Bool
    public let executionAvailable: Bool
    public let limitation: String?
}

/// Normal clients receive live review IDs and display values only. No public
/// policy, journal path, decoded-record executor or filesystem override exists.
public actor ApplicationOptimizationCoordinator {
    private let engine: ApplicationOptimizationEngine
    private let policy: SafetyPolicy
    private var latestReview: (id:UUID,kind:ApplicationOptimizationKind)?
    private var latestKeep: (id:UUID,batch:UUID)?
    private var latestPurge: (id:UUID,batch:UUID)?
    private var inFlight = false
    private var mutating = false
    private var epoch: UInt64 = 0
    public init() { policy = .current; engine = ApplicationOptimizationEngine() }
    #if DEBUG
    private init(policy: SafetyPolicy) { self.policy = policy; engine = ApplicationOptimizationEngine(policy:policy) }
    static func fixture(policy: SafetyPolicy) throws -> ApplicationOptimizationCoordinator {
        guard as_current_uid() != 0, policy.systemScope == nil else { throw SweepError.denied("精简协调器夹具仅允许普通用户范围") }
        return .init(policy:policy)
    }
    #endif
    private func begin(mutation: Bool) throws -> UInt64 {
        try Task.checkCancellation()
        guard !inFlight else { throw SweepError.denied("另一精简或恢复操作正在进行") }
        inFlight = true; mutating = mutation
        return epoch
    }
    private func finish() { inFlight = false; mutating = false }
    private func check(_ token: UInt64) throws {
        try Task.checkCancellation()
        guard epoch == token else { throw CancellationError() }
    }
    public func close() throws {
        guard !mutating else { throw SweepError.denied("精简或恢复正在核对执行，请等待本次结果") }
        epoch &+= 1; latestReview = nil; latestKeep = nil; latestPurge = nil
    }
    private func available(_ kind: ApplicationOptimizationKind) -> Bool {
        as_current_uid() != 0 && policy.systemScope == nil && policy.executionEnabled && policy.ruleIsValidated(kind.rule)
    }
    private func limitation(_ kind: ApplicationOptimizationKind) -> String? {
        guard !available(kind) else { return nil }
        return policy.limitation ?? "当前系统上的\(kind.title)执行尚未验收；可核对方案，应用继续保留。"
    }
    private func authorize(_ kind: ApplicationOptimizationKind) throws {
        try Task.checkCancellation()
        guard available(kind) else { throw SweepError.denied(limitation(kind) ?? "此类精简或恢复尚未验收") }
    }
    private func kind(_ rule: String) throws -> ApplicationOptimizationKind {
        switch rule {
        case ApplicationOptimizationEngine.rule:return .architectures
        case ApplicationOptimizationEngine.languageRule:return .languages
        default:throw SweepError.denied("未知的应用精简类别，记录保留待核对")
        }
    }
    private func presentation(_ record: ApplicationOptimizationRecord) throws -> ApplicationOptimizationBatch {
        let kind = try kind(record.rule)
        guard let status = ApplicationOptimizationBatch.Status(rawValue:record.status.rawValue) else { throw SweepError.incomplete("应用精简记录状态未确认") }
        let stored: Int64?
        switch record.status {
        case .published,.retained:stored = record.original.bytes
        case .prepared,.restored,.stopped:stored = record.prepared?.bytes
        case .purged:stored = 0
        case .preparing,.publishing,.undoing,.needsAttention,.purging:stored = nil
        }
        let allowed = available(kind)
        return .init(id:record.id,kind:kind,applicationPath:record.applicationPath,status:status,createdAt:record.createdAt,storedBytes:stored,issue:record.issue,limitation:limitation(kind),
                     canRestore:allowed && record.purgeOrigin == nil && [.published,.needsAttention].contains(record.status) && record.prepared != nil,
                     canInspect:allowed && record.status.unfinished && (record.purgeOrigin == nil || policy.ruleIsValidated(ApplicationOptimizationEngine.purgeRule)),
                     canKeepCurrent:allowed && record.purgeOrigin == nil && record.status == .needsAttention && record.prepared != nil,
                     canReviewPurge:record.schemaVersion >= 2 && record.purgeOrigin == nil && [.published,.restored,.retained].contains(record.status),
                     purgeLimitation:record.status == .purged ? nil : record.schemaVersion < 2 ? "旧记录缺少完整元数据承诺，副本保留，不能永久清空。" : purgeLimitation(kind))
    }
    private func authorizedRecord(_ id: UUID) async throws -> ApplicationOptimizationRecord {
        let rows = try await engine.history()
        guard let record = rows.first(where:{ $0.id == id }) else { throw SweepError.denied("未找到此应用精简批次") }
        try authorize(kind(record.rule))
        return record
    }
    public func review(applicationPath: String, kind: ApplicationOptimizationKind, retainingLanguages: [String] = []) async throws -> ApplicationOptimizationReview {
        let token = try begin(mutation:false); defer { finish() }
        latestReview = nil; latestKeep = nil; latestPurge = nil
        let raw: ApplicationOptimizationEngine.Review
        switch kind {
        case .architectures:raw = try await engine.review(applicationPath)
        case .languages:
            let preferred = Locale.preferredLanguages
            guard retainingLanguages.count <= 64, preferred.count <= 64 else { throw SweepError.denied("保留语言数量超出核对范围") }
            let languages = Array(Set(preferred + retainingLanguages)).sorted()
            guard !languages.isEmpty, languages.count <= 64 else { throw SweepError.denied("系统首选与额外保留语言未确认或数量过多") }
            raw = try await engine.reviewLanguages(applicationPath,retaining:languages)
        }
        try check(token)
        latestReview = (raw.id,kind)
        return .init(id:raw.id,kind:kind,applicationPath:raw.applicationPath,estimatedReductionBytes:raw.estimatedReductionBytes,retainedReasons:raw.retainedReasons,availableLanguages:raw.availableLanguages,executionAvailable:available(kind),limitation:limitation(kind))
    }
    public func execute(reviewID: UUID) async throws -> ApplicationOptimizationBatch {
        _ = try begin(mutation:true); defer { finish() }
        guard let choice = latestReview, choice.id == reviewID else { throw SweepError.stale("精简方案未知、已取消、已替换或已使用，请重新核对") }
        latestReview = nil; latestKeep = nil; latestPurge = nil
        try authorize(choice.kind)
        // A completed mutation receipt is not discarded through an epoch check.
        return try presentation(await engine.execute(reviewID:reviewID))
    }
    public func history() async throws -> [ApplicationOptimizationBatch] {
        let token = try begin(mutation:false); defer { finish() }
        let rows = try await engine.history(); try check(token)
        return try rows.map(presentation)
    }
    public func restore(batchID: UUID) async throws -> ApplicationOptimizationBatch {
        _ = try begin(mutation:true); defer { finish() }
        latestReview = nil; latestKeep = nil; latestPurge = nil
        let record = try await authorizedRecord(batchID)
        guard record.purgeOrigin == nil, [.published,.needsAttention].contains(record.status), record.prepared != nil else { throw SweepError.denied("此批次需要先核对中断状态，或已经结束恢复") }
        return try presentation(await engine.undo(batchID:batchID))
    }
    public func inspect(batchID: UUID) async throws -> ApplicationOptimizationBatch {
        _ = try begin(mutation:true); defer { finish() }
        latestReview = nil; latestKeep = nil; latestPurge = nil
        let record = try await authorizedRecord(batchID)
        if record.purgeOrigin != nil, let reason = purgeLimitation(try kind(record.rule)) { throw SweepError.denied(reason) }
        return try presentation(await engine.reconcile(batchID:batchID))
    }
    private func purgeLimitation(_ kind: ApplicationOptimizationKind) -> String? {
        guard available(kind), policy.ruleIsValidated(ApplicationOptimizationEngine.purgeRule) else { return "此平台的恢复副本永久清空尚未独立验收；可核对对象，副本继续保留。" }
        return nil
    }
    public func reviewPurge(batchID: UUID) async throws -> ApplicationOptimizationPurgeReview {
        let token = try begin(mutation:false); defer { finish() }
        latestReview = nil; latestKeep = nil; latestPurge = nil
        let rows = try await engine.history()
        guard let record = rows.first(where:{ $0.id == batchID }) else { throw SweepError.denied("未找到此恢复批次") }
        let kind = try kind(record.rule), raw = try await engine.reviewPurge(batchID:batchID)
        try check(token); latestPurge = (raw.id,raw.batchID)
        let reason = purgeLimitation(kind)
        return .init(id:raw.id,batchID:raw.batchID,applicationPath:raw.applicationPath,retainedBackupBytes:raw.retainedBackupBytes,removesOriginal:raw.removesOriginal,executionAvailable:reason == nil,limitation:reason)
    }
    public func purge(reviewID: UUID, confirmation: String) async throws -> ApplicationOptimizationBatch {
        _ = try begin(mutation:true); defer { finish() }
        guard let choice = latestPurge, choice.id == reviewID else { throw SweepError.stale("清空核对已取消、替换或使用，请重新核对") }
        latestReview = nil; latestKeep = nil; latestPurge = nil
        let record = try await authorizedRecord(choice.batch)
        if let reason = purgeLimitation(try kind(record.rule)) { throw SweepError.denied(reason) }
        return try presentation(await engine.purge(reviewID:reviewID,confirmation:confirmation))
    }
    public func reviewKeepingCurrent(batchID: UUID) async throws -> ApplicationOptimizationKeepReview {
        let token = try begin(mutation:false); defer { finish() }
        latestReview = nil; latestKeep = nil; latestPurge = nil
        _ = try await authorizedRecord(batchID)
        let raw = try await engine.reviewKeepingCurrent(batchID:batchID)
        try check(token); latestKeep = (raw.id,raw.batchID)
        return .init(id:raw.id,batchID:raw.batchID,applicationPath:raw.applicationPath,retainedBackupBytes:raw.retainedBackupBytes)
    }
    public func keepCurrent(reviewID: UUID) async throws -> ApplicationOptimizationBatch {
        _ = try begin(mutation:true); defer { finish() }
        guard let choice = latestKeep, choice.id == reviewID else { throw SweepError.stale("保留当前版本的核对已取消、替换或使用") }
        latestKeep = nil; latestReview = nil; latestPurge = nil
        _ = try await authorizedRecord(choice.batch)
        return try presentation(await engine.keepCurrent(reviewID:reviewID))
    }
}
#endif
