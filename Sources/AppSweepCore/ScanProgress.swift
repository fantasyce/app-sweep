import Foundation

/// Read-only discovery feedback. Counts include retained findings and never
/// authorize selection, plan review, or execution before a scan has finished.
public struct ScanProgress: Sendable, Equatable {
    public let stage: String
    public let detail: String?
    public let discoveredCount: Int
    /// Display-only snapshots, keyed by the existing cleanup source names.
    /// A snapshot alone cannot authorize a plan; callers must finish discovery
    /// and use the coordinator's registered final overview for review.
    public let completedReports: [String:ScanReport]
    public init(stage: String, detail: String? = nil, discoveredCount: Int, completedReports: [String:ScanReport] = [:]) {
        self.stage = stage; self.detail = detail; self.discoveredCount = discoveredCount
        self.completedReports=completedReports
    }
    public static func == (lhs:Self,rhs:Self) -> Bool {
        lhs.stage == rhs.stage && lhs.detail == rhs.detail && lhs.discoveredCount == rhs.discoveredCount &&
        lhs.completedReports.mapValues(\.id) == rhs.completedReports.mapValues(\.id)
    }
}
