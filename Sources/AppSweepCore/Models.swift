import Foundation

public enum CandidateCategory: String, Codable, Sendable, CaseIterable {
    case application, backgroundComponent, cache, log, development, userData, deviceBackup, protected
    public var title: String {
        switch self { case .application: "应用主体"; case .backgroundComponent: "后台组件"; case .cache: "应用缓存"; case .log: "日志与崩溃报告"; case .development: "开发中间文件"; case .userData: "用户数据"; case .deviceBackup: "本地设备备份（个人资料）"; case .protected: "保留项目" }
    }
}
public struct FileIdentity: Codable, Sendable, Equatable {
    public let device: UInt64
    public let inode: UInt64
    public let mode: UInt32
    public let owner: UInt32
    public let links: UInt64
    public let size: Int64
    public let modifiedSeconds: Int64
    public let modifiedNanoseconds: Int64
    public let changedSeconds: Int64
    public let changedNanoseconds: Int64
    public var volumeUUID:String? = nil
    func sameVolume(as other:FileIdentity)->Bool {
        if let volumeUUID,let otherUUID=other.volumeUUID {
            return UUID(uuidString:volumeUUID)?.uuidString == volumeUUID && UUID(uuidString:otherUUID)?.uuidString == otherUUID && volumeUUID == otherUUID
        }
        return device == other.device
    }
    public static func ==(lhs:Self,rhs:Self)->Bool {
        lhs.sameVolume(as:rhs) && lhs.inode == rhs.inode && lhs.mode == rhs.mode && lhs.owner == rhs.owner && lhs.links == rhs.links && lhs.size == rhs.size && lhs.modifiedSeconds == rhs.modifiedSeconds && lhs.modifiedNanoseconds == rhs.modifiedNanoseconds && lhs.changedSeconds == rhs.changedSeconds && lhs.changedNanoseconds == rhs.changedNanoseconds
    }
}
public enum CandidateAction: String, Codable, Sendable { case report, reviewPlan, isolate }
/// Recommendation changes the initial selection, never the permitted actions.
public enum CandidateRecommendation: String, Codable, Sendable { case recommended, manual }
public struct Candidate: Sendable, Identifiable, Equatable {
    public let id: UUID
    public let path: String
    public let category: CandidateCategory
    public let bundleIdentifier: String?
    public var applicationPath: String? = nil
    public var scanScopeID: String? = nil
    public let evidence: [OwnershipEvidence]
    public let rule: String
    public let identity: FileIdentity?
    public let bytes: Int64
    public let retentionReason: String?
    public var allowsPlanReview: Bool = true
    public var executionAllowed: Bool = false
    /// Presentation only; never used to establish ownership or a target path.
    public var displayName: String? = nil
    public var deviceBackupDetails: DeviceBackupDetails? = nil
    public var simulatorDevice: SimulatorDeviceReference? = nil
    public var recommendation: CandidateRecommendation? = nil
    public var ignoredReason: String? = nil
    public var systemHelper: InstalledSystemHelperReference? = nil
    public var component: ApplicationComponentReference? = nil
    public var ownerIdentifier: String? { component?.ownerIdentifier ?? bundleIdentifier }
    public var userData: Bool { category == .userData || category == .deviceBackup }
    public var selectionGroupID: String? {
        if rule == InstalledSystemHelperRule.name,let systemHelper,let applicationPath{return "system-helper:"+applicationPath+":"+systemHelper.label}
        if category == .application{return "uninstall-body:" + path}
        if rule == ApplicationAgentRule.name,let applicationPath{return "uninstall-body:" + applicationPath}
        if rule == GodotCacheRule.name { return GodotCacheRule.thumbnailKey(path).map { "godot-preview:" + $0 } }
        return CacheArchive.supports(rule) ? "cache-domain:" + URL(fileURLWithPath: path).deletingLastPathComponent().path : nil
    }
    public var allowed: Bool { ignoredReason == nil && retentionReason == nil && identity != nil && evidence.contains(where: \.authorizes) }
    public var selectedByDefault: Bool {
        allowed && allowsPlanReview && executionAllowed && !userData && category != .protected && recommendation != .manual
    }
    public var defaultSelectionReason: String {
        if let ignoredReason { return ignoredReason }
        if !allowed || !allowsPlanReview || category == .protected { return retentionReason ?? "未确认，保持保留" }
        if !executionAllowed { return "仅可预览，默认不选" }
        if userData { return "个人资料，需主动选择" }
        return recommendation == .manual ? "需手动选择，默认不选" : "建议选择"
    }
    public var allowedActions: [CandidateAction] {
        guard allowed && allowsPlanReview else { return [.report] }
        return executionAllowed ? [.report, .reviewPlan, .isolate] : [.report, .reviewPlan]
    }
    static func fixture(path: String, userData: Bool) -> Candidate {
        Candidate(id: UUID(), path: path, category: userData ? .userData : .cache, bundleIdentifier: "org.example.app", evidence: [], rule: "fixture", identity: nil, bytes: 0, retentionReason: nil)
    }
}
extension Candidate: Codable {
    private enum CodingKeys: String, CodingKey {
        case id, path, category, bundleIdentifier, applicationPath, scanScopeID, evidence, rule, identity, bytes, retentionReason
        case allowsPlanReview, executionAllowed, displayName, deviceBackupDetails, simulatorDevice, recommendation, ignoredReason, systemHelper, component, userData, selectedByDefault, allowedActions
    }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(id: try c.decode(UUID.self, forKey: .id), path: try c.decode(String.self, forKey: .path),
                  category: try c.decode(CandidateCategory.self, forKey: .category),
                  bundleIdentifier: try c.decodeIfPresent(String.self, forKey: .bundleIdentifier),
                  applicationPath: try c.decodeIfPresent(String.self, forKey: .applicationPath),
                  scanScopeID: try c.decodeIfPresent(String.self, forKey: .scanScopeID),
                  evidence: try c.decode([OwnershipEvidence].self, forKey: .evidence), rule: try c.decode(String.self, forKey: .rule),
                  identity: try c.decodeIfPresent(FileIdentity.self, forKey: .identity), bytes: try c.decode(Int64.self, forKey: .bytes),
                  retentionReason: try c.decodeIfPresent(String.self, forKey: .retentionReason),
                  allowsPlanReview: try c.decodeIfPresent(Bool.self, forKey: .allowsPlanReview) ?? true,
                  executionAllowed: try c.decodeIfPresent(Bool.self, forKey: .executionAllowed) ?? false,
                  displayName: try c.decodeIfPresent(String.self, forKey: .displayName),
                  deviceBackupDetails: try c.decodeIfPresent(DeviceBackupDetails.self, forKey: .deviceBackupDetails),
                  recommendation: try c.decodeIfPresent(CandidateRecommendation.self, forKey: .recommendation),
                  ignoredReason: try c.decodeIfPresent(String.self, forKey: .ignoredReason))
        simulatorDevice=try c.decodeIfPresent(SimulatorDeviceReference.self,forKey:.simulatorDevice)
        systemHelper=try c.decodeIfPresent(InstalledSystemHelperReference.self,forKey:.systemHelper)
        component=try c.decodeIfPresent(ApplicationComponentReference.self,forKey:.component)
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id); try c.encode(path, forKey: .path); try c.encode(category, forKey: .category)
        try c.encodeIfPresent(bundleIdentifier, forKey: .bundleIdentifier); try c.encodeIfPresent(applicationPath, forKey: .applicationPath)
        try c.encodeIfPresent(scanScopeID, forKey: .scanScopeID)
        try c.encode(evidence, forKey: .evidence); try c.encode(rule, forKey: .rule); try c.encodeIfPresent(identity, forKey: .identity)
        try c.encode(bytes, forKey: .bytes); try c.encodeIfPresent(retentionReason, forKey: .retentionReason)
        try c.encode(allowsPlanReview, forKey: .allowsPlanReview); try c.encode(executionAllowed, forKey: .executionAllowed)
        try c.encodeIfPresent(displayName, forKey: .displayName)
        try c.encodeIfPresent(deviceBackupDetails, forKey: .deviceBackupDetails)
        try c.encodeIfPresent(simulatorDevice,forKey:.simulatorDevice)
        try c.encodeIfPresent(systemHelper,forKey:.systemHelper)
        try c.encodeIfPresent(component,forKey:.component)
        try c.encodeIfPresent(recommendation, forKey: .recommendation)
        try c.encodeIfPresent(ignoredReason, forKey: .ignoredReason)
        try c.encode(userData, forKey: .userData); try c.encode(selectedByDefault, forKey: .selectedByDefault)
        try c.encode(allowedActions, forKey: .allowedActions)
    }
}
public struct ScanScope: Codable, Sendable, Identifiable {
    public let id: String
    public let root: String
    public let complete: Bool
    public let candidateIDs: [UUID]
    public let issues: [String]
}
public struct ScanReport: Codable, Sendable {
    public let schemaVersion: Int
    public let id: UUID
    public let createdAt: Date
    public let ruleVersion: String
    public let applicationPath: String?
    public let candidates: [Candidate]
    public let complete: Bool
    public let issues: [String]
    public let platformLimitation: String?
    public var scopes: [ScanScope]? = nil
    public var ignoreRevision: UUID? = nil
    var unconfirmedIssues: [String] {
        let scopedIssues = (scopes ?? []).filter { !$0.complete || !$0.issues.isEmpty }.flatMap { scope in
            scope.issues.isEmpty ? ["未确认范围：" + scope.root] : scope.issues
        }
        return Array(Set(issues + scopedIssues)).sorted()
    }
    /// A display projection preserves scan identity; the engine still revalidates
    /// its original registered snapshots before executing another selection.
    public func excluding(_ ids: Set<UUID>) -> ScanReport {
        var result = ScanReport(schemaVersion:schemaVersion,id:id,createdAt:createdAt,ruleVersion:ruleVersion,
                                applicationPath:applicationPath,candidates:candidates.filter { !ids.contains($0.id) },
                                complete:complete,issues:issues,platformLimitation:platformLimitation)
        result.scopes = scopes?.map { ScanScope(id:$0.id,root:$0.root,complete:$0.complete,
                                               candidateIDs:$0.candidateIDs.filter { !ids.contains($0) },issues:$0.issues) }
        result.ignoreRevision = ignoreRevision
        return result
    }
    public func requiringRecheck(afterRecoveryOf originals: [Candidate]) -> ScanReport {
        let scan = self
        let items = scan.candidates.map { item -> Candidate in
            let affected = originals.contains { original in
                item.path == original.path || item.path.hasPrefix(original.path + "/") ||
                original.path.hasPrefix(item.path + "/") ||
                (original.category == .application && item.applicationPath == original.path) ||
                (item.applicationPath != nil && item.applicationPath == original.applicationPath)
            }
            guard affected else { return item }
            var pending = item
            pending.allowsPlanReview = false; pending.executionAllowed = false
            pending.ignoredReason = "恢复操作涉及此项目，请重新核对后再选择"
            return pending
        }
        var updated = ScanReport(schemaVersion: scan.schemaVersion, id: scan.id, createdAt: scan.createdAt,
            ruleVersion: scan.ruleVersion, applicationPath: scan.applicationPath, candidates: items,
            complete: scan.complete, issues: scan.issues, platformLimitation: scan.platformLimitation)
        updated.scopes = scan.scopes; updated.ignoreRevision = scan.ignoreRevision
        return updated
    }
    /// Only meaningful for a report registered with this engine; decoded JSON is not authority.
    /// Build membership and failed-path indexes once, rather than once per response file.
    func validatedSelectionIDs() -> Set<UUID> {
        guard [1, 2].contains(schemaVersion) else { return [] }
        var counts: [UUID: Int] = [:]
        for item in candidates { counts[item.id, default: 0] += 1 }
        let unique = Set(counts.compactMap { $0.value == 1 ? $0.key : nil })
        guard let scopes else { return complete ? unique : [] }
        guard schemaVersion == 2 else { return [] }
        var scopeCounts: [String: Int] = [:], memberships: [UUID: Int] = [:]
        var validScopes: Set<String> = [], failedRoots: Set<String> = [], failedAncestors: Set<String> = []
        for scope in scopes {
            scopeCounts[scope.id, default: 0] += 1
            for id in scope.candidateIDs { memberships[id, default: 0] += 1 }
            if scope.complete && scope.issues.isEmpty && Set(scope.candidateIDs).count == scope.candidateIDs.count && scope.candidateIDs.allSatisfy({ unique.contains($0) }) {
                validScopes.insert(scope.id)
            } else if !scope.complete || !scope.issues.isEmpty {
                failedRoots.insert(scope.root)
                failedAncestors.formUnion(Self.pathAncestors(scope.root))
            }
        }
        var membersByScope: [String: Set<UUID>] = [:]
        for scope in scopes where scopeCounts[scope.id] == 1 && validScopes.contains(scope.id) {
            membersByScope[scope.id] = Set(scope.candidateIDs)
        }
        return Set(candidates.compactMap { item in
            guard unique.contains(item.id), let scope = item.scanScopeID, memberships[item.id] == 1,
                  membersByScope[scope]?.contains(item.id) == true,
                  !failedAncestors.contains(item.path),
                  !Self.pathAncestors(item.path).contains(where: { failedRoots.contains($0) }) else { return nil }
            return item.id
        })
    }
    private static func pathAncestors(_ path: String) -> [String] {
        var result = [path], current = path
        while let slash = current.lastIndex(of: "/"), slash != current.startIndex {
            current = String(current[..<slash]); result.append(current)
        }
        if path.hasPrefix("/") { result.append("/") }
        return result
    }
    /// Presentation capability only. Plans still require the engine's registered scan.
    public func selectableCandidates(includeUserData: Bool) -> [Candidate] {
        let validated = validatedSelectionIDs()
        let available = candidates.filter { validated.contains($0.id) && $0.allowedActions.contains(.reviewPlan) && (!$0.userData || includeUserData) }
        let availableIDs = Set(available.map(\.id))
        let blocked = Set(candidates.filter { !availableIDs.contains($0.id) }.compactMap(\.selectionGroupID))
        return available.filter { $0.selectionGroupID.map { !blocked.contains($0) } ?? true }
    }
    public func recommendedSelectionIDs() -> Set<UUID> {
        let available = selectableCandidates(includeUserData: false)
        let manualGroups = Set(available.filter { !$0.selectedByDefault }.compactMap(\.selectionGroupID))
        return Set(available.filter { item in
            item.selectedByDefault && (item.selectionGroupID.map { !manualGroups.contains($0) } ?? true)
        }.map(\.id))
    }
    public func selectionIDs(for candidateID: UUID, includeUserData: Bool) -> Set<UUID> {
        let available = selectableCandidates(includeUserData: includeUserData)
        guard let item = available.first(where: { $0.id == candidateID }) else { return [] }
        guard let group = item.selectionGroupID else { return [candidateID] }
        return Set(available.filter { $0.selectionGroupID == group }.map(\.id))
    }
    public func selectionIsComplete(_ selected: Set<UUID>, includeUserData: Bool) -> Bool {
        let available = selectableCandidates(includeUserData: includeUserData)
        guard selected.isSubset(of: Set(available.map(\.id))) else { return false }
        let groups = Set(available.filter { selected.contains($0.id) }.compactMap(\.selectionGroupID))
        return available.allSatisfy { item in
            guard let group = item.selectionGroupID, groups.contains(group) else { return true }
            return selected.contains(item.id)
        }
    }

}
public struct CleanupPlan: Codable, Sendable, Identifiable {
    public let schemaVersion: Int
    public let id: UUID
    public let reportID: UUID
    public let createdAt: Date
    public let ruleVersion: String
    public let items: [Candidate]
    public let includeUserData: Bool
    public var retainedIssues: [String]? = nil
    public var ignoreRevision: UUID? = nil
    public var bytes: Int64 { items.reduce(0) { $0 + $1.bytes } }
    public var documentHistoryCount:Int{items.filter{$0.rule == DocumentHistoryRecord.rule}.count}
    public var preferenceCount: Int { items.filter { $0.rule == PreferenceRecoveryRecord.rule }.count }
}
public struct RecoveryEntry: Codable, Sendable, Identifiable {
    public let id: UUID
    public let original: Candidate
    public var state: State
    public var message: String?
    var isolatedIdentity: FileIdentity? = nil
    var contents: [TreeEntry] = []
    var treeFingerprint: TreeFingerprint? = nil
    var applicationLinks: ApplicationLinkRecovery? = nil
    var originalAncestors: [AncestorIdentity]? = nil
    var backupDigest: String? = nil
    var backupIdentity: FileIdentity? = nil
    var backupFormat: String? = nil
    var backupBytes: Int64? = nil
    var reconstructedContents: [TreeEntry]? = nil
    var backupPending: Bool? = nil
    var reconstructionPending: Bool? = nil
    var preference: PreferenceRecoveryRecord? = nil
    var userAgent:UserAgentRecoveryRecord? = nil
    var systemHelper:UserAgentRecoveryRecord? = nil
    var history:DocumentHistoryRecord? = nil
    public enum State: String, Codable, Sendable { case prepared, moved, restorePrepared, purgePrepared, restored, conflict, purged }
    func matchesContents(_ snapshot: FileSnapshot) throws -> Bool {
        if let reconstructedContents { return snapshot.tree == reconstructedContents }
        if let treeFingerprint { return try treeFingerprint.matches(snapshot.tree) }
        return snapshot.tree == contents
    }
    func matchesRestorationContents(_ snapshot: FileSnapshot) throws -> Bool {
        if try matchesContents(snapshot) { return true }
        return try applicationLinks?.matches(snapshot, entry: self) ?? false
    }
}
struct PreferenceRecoveryRecord: Codable, Sendable {
    static let rule = "cfpreferences-service-domain-v2"
    enum Phase: String, Codable, Sendable { case prepared, clearing, cleared, restoring, restored }
    var phase: Phase
    let originalValuesDigest: String
    var originalRawDigest: String? = nil
    var emptyIdentity: FileIdentity? = nil
    var restoredIdentity: FileIdentity? = nil
}
struct CacheRecoveryMember: Codable, Sendable {
    let original: Candidate
    let fingerprint: TreeFingerprint
}
public struct RecoveryManifest: Codable, Sendable, Identifiable {
    static let currentSchemaVersion = 5
    static let userSchemaVersions = [1,2,3,5]
    static let systemSchemaVersion = 4
    // Layout is derived only from the validated schema, never from whichever
    // directory exists. Older batches retain their original storage locations.
    var objectsDirectory: String { [3,4,5].contains(schemaVersion) ? "objects.noindex" : "objects" }
    var backupsDirectory: String { [3,4,5].contains(schemaVersion) ? "backups.noindex" : "backups" }
    public let schemaVersion: Int
    public let id: UUID
    public let createdAt: Date
    public var status: Status
    public var entries: [RecoveryEntry]
    public var issue: String?
    public var retainedIssues: [String]? = nil
    public var previewOnlyReason:String? = nil
    var requestingUserID: UInt32? = nil
    var cacheSelection: [CacheRecoveryMember]? = nil
    public enum Status: String, Codable, Sendable { case inProgress, isolated, purging, rolledBack, needsAttention, restored, partiallyRestored, purged }
    public var hasUnconfirmedObjects: Bool {
        previewOnlyReason != nil || status == .needsAttention || status == .inProgress || status == .purging ||
        (status == .isolated && entries.contains { $0.state != .moved }) ||
        entries.contains { $0.state == .prepared || $0.state == .restorePrepared || $0.state == .purgePrepared || $0.state == .conflict || $0.backupPending == true || $0.reconstructionPending == true || $0.preference?.phase == .clearing || $0.preference?.phase == .restoring || $0.userAgent?.phase == .unregistering || $0.userAgent?.phase == .restoring || $0.systemHelper?.phase == .unregistering || $0.systemHelper?.phase == .restoring }
    }
    public var isolatedBytes: Int64 { entries.filter { $0.preference == nil && $0.history == nil && ($0.state == .moved || $0.state == .conflict) }.reduce(0) { $0 + $1.original.bytes } }
    public var backedUpPreferenceCount: Int { entries.filter { $0.preference != nil && $0.backupDigest != nil }.count }
    public var independentBackupBytes: Int64 { entries.filter { $0.backupDigest != nil }.reduce(0) { $0 + ($1.backupBytes ?? $1.backupIdentity?.size ?? 0) } }
    public var hasIndependentBackups: Bool { entries.contains { $0.backupDigest != nil } }
    public var hasUnconfirmedBackups: Bool { entries.contains { $0.backupPending == true } }
    public var canPurge: Bool { !hasUnconfirmedObjects && (status == .isolated || (hasIndependentBackups && [.restored, .rolledBack, .partiallyRestored].contains(status))) }
}
/// A bounded history index carries no paths or file trees. Full records are read
/// separately by UUID, within the authenticated user's recovery namespace.
public struct RecoveryBatchSummary: Codable, Sendable, Identifiable {
    public let id: UUID
    public let createdAt: Date
    public let status: RecoveryManifest.Status
    public let entryCount: Int
    public let isolatedBytes: Int64
    public let hasIndependentBackups: Bool
    public let hasUnconfirmedObjects: Bool
    public var issue:String? = nil
    init(_ manifest: RecoveryManifest) {
        id = manifest.id; createdAt = manifest.createdAt; status = manifest.status
        entryCount = manifest.entries.count; isolatedBytes = manifest.isolatedBytes
        hasIndependentBackups = manifest.hasIndependentBackups
        hasUnconfirmedObjects = manifest.hasUnconfirmedObjects
        issue=manifest.previewOnlyReason ?? manifest.issue
    }
}
public struct RecoveryBatchPage: Codable, Sendable {
    static let pageSize = 16
    public let items: [RecoveryBatchSummary]
    public let nextCursor: UUID?
    func validate() throws {
        guard items.count <= Self.pageSize, Set(items.map(\.id)).count == items.count,
              items.allSatisfy({ $0.entryCount >= 0 && $0.entryCount <= 1000 && $0.isolatedBytes >= 0 && ($0.issue?.utf8.count ?? 0) <= 2048 }),
              nextCursor == nil || nextCursor == items.last?.id else { throw SweepError.denied("恢复分页结构或容量无效") }
    }
}
public struct ApplicationCatalog: Sendable {
    public let applications: [ApplicationIdentity]
    public let unconfirmedIssues: [String]
}
public struct ApplicationIdentity: Sendable, Identifiable, Equatable {
    public var id: String { path }
    public let path: String
    public let name: String
    public let bundleIdentifier: String
    public let signed: Bool
    public let protectedReason: String?
    // In-process discovery evidence only; never serialized or used to authorize
    // a move. Unusual installation nodes retain their physical metadata owner.
    var attributionMetadataPath: String? = nil
    // Preserve the observed raw spelling for malformed conflict-only hints.
    var attributionRawIdentifier: String? = nil
}
public enum SweepError: Error, LocalizedError, Sendable {
    case denied(String), stale(String), invalid(String), filesystem(String), incomplete(String)
    public var errorDescription: String? { switch self { case .denied(let s), .stale(let s), .invalid(let s), .filesystem(let s), .incomplete(let s): s } }
}

/// Only thrown before source mutation and before a recovery batch is created.
/// Transport failures must never be converted into this local proof.
struct ExecutionPreflightFailure: Error, LocalizedError, Sendable {
    let message: String
    var errorDescription: String? { message }
}
