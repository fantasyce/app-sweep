import Foundation

/// Per authenticated connection; never decodes reports or plans supplied by clients.
struct PrivilegedPlanRegistry {
    private let owner: AuthenticatedLocalPeer
    private let sessionNonce: Data
    private var reports: [UUID: (ScanReport, TimeInterval)] = [:]
    private var plans: [UUID: (CleanupPlan, TimeInterval)] = [:]
    private var lastUptime: TimeInterval = 0
    init(peer: AuthenticatedLocalPeer, nonce: Data) throws {
        guard peer.uid != 0, peer.pid > 0, peer.auditToken.count == 32, nonce.count == 32 else { throw SweepError.denied("系统计划会话无效") }
        owner = peer; sessionNonce = nonce
    }
    private mutating func validate(peer: AuthenticatedLocalPeer, nonce: Data, uptime: TimeInterval) throws {
        guard peer.uid == owner.uid, peer.pid == owner.pid, peer.auditToken == owner.auditToken,
              nonce == sessionNonce, uptime.isFinite, uptime >= lastUptime else { throw SweepError.denied("系统计划不属于此连接，或计时状态已改变") }
        lastUptime = uptime
        reports = reports.filter { uptime - $0.value.1 < 300 }
        plans = plans.filter { uptime - $0.value.1 < 300 }
    }
    mutating func register(_ report: ScanReport, peer: AuthenticatedLocalPeer, nonce: Data, uptime: TimeInterval) throws {
        try validate(peer: peer, nonce: nonce, uptime: uptime)
        guard reports.count < 4, reports[report.id] == nil, report.ruleVersion == SweepEngine.ruleVersion,
              report.applicationPath == nil, report.candidates.count <= 10000,
              Set(report.candidates.map(\.id)).count == report.candidates.count else { throw SweepError.denied("系统扫描未知、重复或超过会话容量") }
        reports[report.id] = (report, uptime)
    }
    mutating func review(scanID: UUID, selected: [UUID], peer: AuthenticatedLocalPeer, nonce: Data, uptime: TimeInterval) throws -> CleanupPlan {
        try verifyReview(scanID:scanID,selected:selected,peer:peer,nonce:nonce,uptime:uptime)
        guard let (report, _) = reports[scanID] else { throw SweepError.denied("系统扫描已过期") }
        let chosen = Set(selected), items = report.candidates.filter { chosen.contains($0.id) }
        let plan = CleanupPlan(schemaVersion: 1, id: UUID(), reportID: report.id, createdAt: Date(),
                               ruleVersion: report.ruleVersion, items: items, includeUserData: items.contains{$0.userData},
                               retainedIssues: report.unconfirmedIssues.isEmpty ? nil : report.unconfirmedIssues)
        try registerReviewed(plan,peer:peer,nonce:nonce,uptime:uptime)
        return plan
    }
    mutating func verifyReview(scanID: UUID, selected: [UUID], peer: AuthenticatedLocalPeer, nonce: Data, uptime: TimeInterval) throws {
        try validate(peer: peer, nonce: nonce, uptime: uptime)
        guard let (report, _) = reports[scanID], plans.count < 8, !selected.isEmpty, selected.count <= 1000,
              Set(selected).count == selected.count,
              report.selectionIsComplete(Set(selected), includeUserData: true) else { throw SweepError.denied("系统选择未知、未确认、重复或超过会话容量") }
        let chosen = Set(selected), items = report.candidates.filter { chosen.contains($0.id) }
        guard items.count == selected.count, items.allSatisfy({ $0.executionAllowed && ([.cache, .log].contains($0.category) || ($0.category == .userData && $0.rule == DeletedUserArchiveRule.name && !$0.selectedByDefault) || ($0.category == .backgroundComponent && $0.rule == InstalledSystemHelperRule.name && !$0.selectedByDefault && $0.systemHelper != nil)) }) else { throw SweepError.denied("系统选择包含尚未开放的类别或动作") }
    }
    /// Accepts only the server engine's reviewed plan, never a client payload.
    mutating func registerReviewed(_ plan: CleanupPlan, peer: AuthenticatedLocalPeer, nonce: Data, uptime: TimeInterval) throws {
        try verifyReview(scanID:plan.reportID,selected:plan.items.map(\.id),peer:peer,nonce:nonce,uptime:uptime)
        guard let (report, _) = reports[plan.reportID], plan.schemaVersion == 1,
              plan.ruleVersion == report.ruleVersion, plan.includeUserData == plan.items.contains(where:{$0.userData}), plans[plan.id] == nil,
              plan.retainedIssues == (report.unconfirmedIssues.isEmpty ? nil : report.unconfirmedIssues),
              plan.items.allSatisfy({ item in report.candidates.contains(item) }) else { throw SweepError.denied("系统计划与已登记扫描不一致") }
        plans[plan.id] = (plan, uptime)
    }
    mutating func consume(planID: UUID, peer: AuthenticatedLocalPeer, nonce: Data, uptime: TimeInterval) throws -> CleanupPlan {
        try validate(peer: peer, nonce: nonce, uptime: uptime)
        guard let (plan, _) = plans.removeValue(forKey: planID), plan.ruleVersion == SweepEngine.ruleVersion else { throw SweepError.denied("系统计划未知、已使用或过期，请重新扫描") }
        // Removal precedes execution/revalidation: failures require a new review.
        return plan
    }
}
