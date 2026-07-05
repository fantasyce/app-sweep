import Foundation

enum Confidence: String, Codable, CaseIterable, Sendable {
    case high
    case medium
    case reportOnly
    case blocked
}

enum CandidateAction: String, Codable, Sendable {
    case trash
    case reportOnly
    case blocked
}

enum CandidateStatus: String, Codable, Sendable {
    case exists
    case missing
    case trashed
    case backedUp
    case backupFailed
    case trashFailed
    case skipped
}

struct AppIdentity: Codable, Sendable {
    let appPath: String
    let bundleIdentifier: String
    let bundleName: String
    let displayName: String
    let executableName: String
    let normalizedNames: [String]
    let teamIdentifier: String?
}

struct Candidate: Codable, Identifiable, Sendable {
    var id: String { path }

    let path: String
    let reason: String
    let confidence: Confidence
    let action: CandidateAction
    let risk: String
    let exists: Bool
    let isDirectory: Bool
    let isSymlink: Bool
    let sizeBytes: UInt64
    let status: CandidateStatus
    let detail: String?
}

struct Summary: Codable, Sendable {
    let totalCandidates: Int
    let existingCandidates: Int
    let trashEligibleExisting: Int
    let reportOnlyExisting: Int
    let blockedExisting: Int
    let totalExistingBytes: UInt64
}

struct Report: Codable, Sendable {
    let generatedAt: String
    let command: String
    let toolVersion: String
    let app: AppIdentity
    let summary: Summary
    let candidates: [Candidate]
}

struct AuditReport: Codable, Sendable {
    let generatedAt: String
    let command: String
    let toolVersion: String
    let app: AppIdentity
    let strongPatterns: [String]
    let strongPathMatches: [String]
    let genericNameMatches: [String]
    let registrations: [AuditSection]
    let unreadableErrors: [String]
    let summary: AuditSummary
}

struct AuditSection: Codable, Identifiable, Sendable {
    var id: String { name }

    let name: String
    let command: String
    let matches: [String]
}

struct AuditSummary: Codable, Sendable {
    let strongPathMatchCount: Int
    let genericNameMatchCount: Int
    let registrationMatchCount: Int
    let unreadableErrorCount: Int
}

struct RestoreReport: Codable, Sendable {
    let generatedAt: String
    let command: String
    let toolVersion: String
    let sourceReportPath: String
    let items: [RestoreItem]
    let summary: RestoreSummary
}

struct RestoreItem: Codable, Identifiable, Sendable {
    var id: String { originalPath }

    let originalPath: String
    let backupPath: String?
    let status: String
    let detail: String?
}

struct RestoreSummary: Codable, Sendable {
    let restored: Int
    let skippedExisting: Int
    let missingBackup: Int
    let failed: Int
}
