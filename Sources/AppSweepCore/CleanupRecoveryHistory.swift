#if os(macOS)
import Foundation

public enum CleanupRecoveryOrigin: String, Codable, CaseIterable, Sendable {
    case user, system
    public var title: String { self == .user ? "当前用户恢复区" : "系统恢复区" }
}
public struct CleanupRecoveryRow: Sendable, Identifiable {
    public let origin: CleanupRecoveryOrigin
    public let summary: RecoveryBatchSummary
    public var id: String { origin.rawValue + "/" + summary.id.uuidString }
    public init(origin: CleanupRecoveryOrigin, manifest: RecoveryManifest) {
        self.origin = origin; summary = RecoveryBatchSummary(manifest)
    }
    init(origin: CleanupRecoveryOrigin, summary: RecoveryBatchSummary) {
        self.origin = origin; self.summary = summary
    }
}
public struct CleanupHistoryFailure: Sendable {
    public let origin: CleanupRecoveryOrigin
    public let message: String
}
public struct CleanupHistoryPage: Sendable {
    public let rows: [CleanupRecoveryRow]
    public let nextUserCursor: UUID?
    public let nextSystemCursor: UUID?
    public let queriedOrigins: [CleanupRecoveryOrigin]
    public let failures: [CleanupHistoryFailure]
    public let executionEnabledOrigins: Set<CleanupRecoveryOrigin>
    public var issues: [String] { failures.map { $0.origin.title + "：" + $0.message } }
}
#endif
