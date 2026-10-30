#if os(macOS)
import Foundation
import CFSafety

public enum CleanupSource: String, Codable, CaseIterable, Sendable {
    case user, systemCaches, systemLogs, deletedUserArchives, applicationHelpers
    public var title: String {
        switch self { case .user: "当前用户与开发文件"; case .systemCaches: "系统级缓存"; case .systemLogs: "系统级日志"; case .deletedUserArchives: "已删除账户归档（个人资料）";case .applicationHelpers:"系统辅助组件（手动管理）" }
    }
}
public struct CleanupSection: Sendable {
    public let source: CleanupSource
    public let report: ScanReport?
    public let issue: String?
    public init(source:CleanupSource,report:ScanReport?,issue:String?) {
        self.source=source;self.report=report;self.issue=issue
    }
}
public struct CleanupOverview: Sendable, Identifiable {
    public let id: UUID
    public let sections: [CleanupSection]
    public init(id:UUID,sections:[CleanupSection]) { self.id=id;self.sections=sections }
    public var candidates: [Candidate] { sections.flatMap { $0.report?.candidates ?? [] } }
    public var unconfirmedIssues: [String] {
        sections.flatMap { section in
            ([section.issue,section.report?.platformLimitation].compactMap { $0 } + (section.report?.unconfirmedIssues ?? [])).map { section.source.title + "：" + $0 }
        }
    }
    public var complete: Bool {
        sections.allSatisfy { $0.issue == nil && $0.report?.complete == true && $0.report?.platformLimitation == nil }
    }
    public func selectableCandidates(includeUserData: Bool) -> [Candidate] {
        sections.flatMap { $0.report?.selectableCandidates(includeUserData:includeUserData) ?? [] }
    }
    public func excluding(_ ids: Set<UUID>) -> CleanupOverview {
        CleanupOverview(id:id,sections:sections.map { .init(source:$0.source,report:$0.report?.excluding(ids),issue:$0.issue) })
    }
    public func recommendedSelectionIDs() -> Set<UUID> {
        sections.reduce(into: Set<UUID>()) { $0.formUnion($1.report?.recommendedSelectionIDs() ?? []) }
    }
    public func selectionIDs(for id: UUID,includeUserData: Bool) -> Set<UUID> {
        sections.reduce(into:Set<UUID>()) { $0.formUnion($1.report?.selectionIDs(for:id,includeUserData:includeUserData) ?? []) }
    }
    public func selectionIsComplete(_ selected: Set<UUID>,includeUserData: Bool) -> Bool {
        guard !selected.isEmpty, selected.isSubset(of:Set(selectableCandidates(includeUserData:includeUserData).map(\.id))) else { return false }
        return sections.allSatisfy { section in
            guard let report = section.report else { return true }
            return report.selectionIsComplete(selected.intersection(Set(report.candidates.map(\.id))),includeUserData:includeUserData)
        }
    }
}
public struct CleanupReview: Sendable, Identifiable {
    public let id: UUID
    public let overviewID: UUID
    public let items: [Candidate]
    public let retainedIssues: [String]
    public var applicationPrerequisite: String? = nil
}
public struct CleanupBatchRecord: Sendable {
    public let source: CleanupSource
    public let manifest: RecoveryManifest
}
public struct CleanupRunResult: Sendable, Identifiable {
    public enum Status: String, Sendable { case isolated, rolledBack, needsAttention }
    public let id: UUID
    public let status: Status
    public let batches: [CleanupBatchRecord]
    public let uncertainSources: [CleanupSource]
    public let retainedIssues: [String]
    public let issue: String?
}

/// Coordinates trusted existing capabilities, never recreates their authority.
/// A public constructor has no endpoint, path, credential or executor override.
public actor CleanupCoordinator {
    private struct SourcePlan: Sendable { let source: CleanupSource; let plan: CleanupPlan }
    private struct Reviewed: Sendable { let presentation: CleanupReview; let plans: [SourcePlan]; let deadline: TimeInterval }
    private let engine: SweepEngine
    private let systemFactory: @Sendable () async throws -> SystemServiceClient
    private var system: SystemServiceClient?
    private var overview: CleanupOverview?
    private var reviewed: Reviewed?
    private var inFlight = false
    private var epoch: UInt64 = 0
    public init() { engine = SweepEngine(); systemFactory = { try await SystemServiceClient.connect() } }
    private init(engine: SweepEngine,systemFactory: @escaping @Sendable () async throws -> SystemServiceClient) {
        self.engine = engine; self.systemFactory = systemFactory
    }
    #if DEBUG
    static func fixture(engine: SweepEngine,systemFactory: @escaping @Sendable () async throws -> SystemServiceClient) throws -> CleanupCoordinator {
        guard as_current_uid() != 0 else { throw SweepError.denied("协调器夹具只允许普通测试账户") }
        return Self(engine:engine,systemFactory:systemFactory)
    }
    #endif
    /// Recovery browsing uses its own transport so it cannot revoke scan plans.
    public nonisolated func recoverySession() -> CleanupCoordinator {
        Self(engine:engine,systemFactory:systemFactory)
    }
    public func discardReview() { reviewed = nil }
    public func close() async {
        epoch &+= 1; overview = nil; reviewed = nil
        await closeSystem()
    }
    private func closeSystem() async {
        let previous = system; system = nil
        await previous?.close()
    }
    private func check(_ expected: UInt64) throws {
        try Task.checkCancellation()
        guard epoch == expected else { throw CancellationError() }
    }
    private func connect(_ expected: UInt64) async throws -> SystemServiceClient {
        let client = try await systemFactory()
        do { try check(expected) } catch { await client.close(); throw error }
        system = client
        return client
    }
    private static func scanUser(engine:SweepEngine,deadline:TimeInterval,progress:(@Sendable (ScanProgress) -> Void)?) async -> CleanupSection {
        do {
            let remaining=deadline-ProcessInfo.processInfo.systemUptime
            guard remaining > 0 else { throw SweepError.incomplete("用户范围尚未开始，已保留") }
            let report=try await engine.scanJunk(maximumDuration:min(120,remaining),progress:progress)
            progress?(.init(stage:"用户范围已扫描",discoveredCount:report.candidates.count,completedReports:[CleanupSource.user.rawValue:report]))
            return .init(source:.user,report:report,issue:nil)
        } catch { return .init(source:.user,report:nil,issue:error.localizedDescription) }
    }
    public func scanJunk(maximumDuration:TimeInterval=120,progress: (@Sendable (ScanProgress) -> Void)? = nil) async throws -> CleanupOverview {
        guard !inFlight else { throw SweepError.denied("另一清理操作正在进行") }
        guard maximumDuration > 0,maximumDuration <= 120,maximumDuration.isFinite else { throw SweepError.invalid("扫描等待期限无效") }
        let deadline=ProcessInfo.processInfo.systemUptime + maximumDuration
        inFlight = true; defer { inFlight = false }
        overview = nil; reviewed = nil
        let token = epoch
        await closeSystem(); try check(token)
        var sections: [CleanupSection] = []
        progress?(.init(stage:"准备扫描",discoveredCount:0))
        try check(token)
        // The two independent discovery sources share one deadline, but neither
        // may consume the other's entire budget before it has even started.
        async let userSection=Self.scanUser(engine:engine,deadline:deadline,progress:progress)
        do {
            progress?(.init(stage:"连接系统清理服务",discoveredCount:sections.reduce(0) { $0 + ($1.report?.candidates.count ?? 0) }))
            try check(token)
            // Connection has a fixed 5s connect + 10s greeting bound. Do not
            // start it when that could consume the remaining discovery budget.
            guard deadline-ProcessInfo.processInfo.systemUptime > 15 else { throw SweepError.incomplete("本次扫描已到等待期限，系统范围未确认并保留") }
            let client = try await connect(token)
            let statusDuration=min(10,deadline-ProcessInfo.processInfo.systemUptime)
            guard statusDuration > 0 else { throw SweepError.incomplete("系统状态尚未确认，已保留") }
            let status = try await client.status(maximumDuration:statusDuration); try check(token)
            for (source,category) in [(CleanupSource.systemCaches,SystemCleanupCategory.caches),(.systemLogs,.logs)] {
                try check(token)
                progress?(.init(stage:"检查" + source.title,discoveredCount:sections.reduce(0) { $0 + ($1.report?.candidates.count ?? 0) }))
                try check(token)
                do {
                    let remaining=deadline-ProcessInfo.processInfo.systemUptime
                    // A native ownership inventory can take 30s. Starting a
                    // final category with only a few seconds left would close
                    // the transport and revoke earlier completed scan handles.
                    guard remaining >= SystemCleanupEngine.maximumDiscoveryDuration + 5 else { throw SweepError.incomplete("剩余扫描时间不足，此范围未开始并保留") }
                    let report = try await client.scan(category,maximumDuration:remaining); try check(token)
                    sections.append(.init(source:source,report:report,issue:status.executionEnabled ? nil : status.limitation))
                    let completed=Dictionary(uniqueKeysWithValues:sections.compactMap{ section in section.report.map{(section.source.rawValue,$0)} })
                    progress?(.init(stage:source.title + "已扫描",discoveredCount:sections.reduce(0){$0 + ($1.report?.candidates.count ?? 0)},completedReports:completed))
                } catch {
                    try check(token)
                    guard await client.hasActiveConnection else { throw error }
                    sections.append(.init(source:source,report:nil,issue:error.localizedDescription))
                }
            }
        } catch {
            try check(token)
            let reason="系统扫描连接已失效，请重新扫描；本次系统项目保留：" + error.localizedDescription
            sections=sections.map { section in
                guard let report=section.report else { return section }
                let items=report.candidates.map { original in
                    var item=original
                    item.allowsPlanReview=false;item.executionAllowed=false
                    item.ignoredReason=item.ignoredReason ?? reason
                    return item
                }
                var retained=ScanReport(schemaVersion:report.schemaVersion,id:report.id,createdAt:report.createdAt,ruleVersion:report.ruleVersion,applicationPath:report.applicationPath,candidates:items,complete:false,issues:report.issues+[reason],platformLimitation:report.platformLimitation)
                retained.scopes=report.scopes;retained.ignoreRevision=report.ignoreRevision
                return .init(source:section.source,report:retained,issue:reason)
            }
            for source in [CleanupSource.systemCaches,.systemLogs] where !sections.contains(where: { $0.source == source }) {
                sections.append(.init(source:source,report:nil,issue:error.localizedDescription))
            }
            await closeSystem()
        }
        let completedUser=await userSection
        try check(token)
        sections.insert(completedUser,at:0)
        let result = CleanupOverview(id:UUID(),sections:sections)
        guard Set(result.candidates.map(\.id)).count == result.candidates.count,
              Set(sections.compactMap { $0.report?.id }).count == sections.compactMap({ $0.report }).count else {
            await closeSystem(); throw SweepError.denied("不同扫描范围返回重复编号，不能建立选择")
        }
        overview = result
        progress?(.init(stage:"准备扫描结果",discoveredCount:result.candidates.count))
        try check(token)
        return result
    }
    /// Explicit prerequisite stage of uninstall. The body and user data remain
    /// untouched, and require a fresh separate review after this stage succeeds.
    public func reviewApplicationPrerequisites(applicationPath: String) async throws -> CleanupReview {
        guard !inFlight, XcodeRule.canonical(applicationPath), applicationPath.hasSuffix(".app") else { throw SweepError.denied("待核对应用位置无效或另一操作正在进行") }
        inFlight = true; defer { inFlight = false }
        reviewed = nil; overview = nil
        let token = epoch
        await closeSystem(); try check(token)
        let client = try await connect(token)
        let report = try await client.scan(.applicationHelpers)
        try check(token)
        let related = report.candidates.filter { $0.applicationPath == applicationPath && $0.rule == InstalledSystemHelperRule.name }
        let selected = Set(related.map(\.id))
        guard !selected.isEmpty, report.selectionIsComplete(selected, includeUserData: false) else {
            throw SweepError.denied("无法独占处理该应用的系统组件，请使用应用官方卸载器。" + related.compactMap(\.retentionReason).prefix(3).joined(separator: "；"))
        }
        let plan = try await client.review(scanID: report.id, candidateIDs: selected.sorted { $0.uuidString < $1.uuidString })
        try check(token)
        guard Set(plan.items.map(\.id)) == selected,
              plan.items.allSatisfy({ $0.applicationPath == applicationPath && $0.rule == InstalledSystemHelperRule.name }) else { throw SweepError.denied("组件计划与选中应用不一致") }
        var presentation = CleanupReview(id: UUID(), overviewID: report.id, items: plan.items, retainedIssues: report.unconfirmedIssues)
        presentation.applicationPrerequisite = applicationPath
        reviewed = .init(presentation: presentation, plans: [.init(source: .applicationHelpers, plan: plan)], deadline: ProcessInfo.processInfo.systemUptime + 300)
        return presentation
    }
    public func review(overviewID: UUID,selected: Set<UUID>,includeUserData: Bool) async throws -> CleanupReview {
        guard !inFlight else { throw SweepError.denied("另一清理操作正在进行") }
        inFlight = true; defer { inFlight = false }
        reviewed = nil
        guard let overview, overview.id == overviewID, selected.count <= 1000,
              overview.selectionIsComplete(selected,includeUserData:includeUserData) else { throw SweepError.denied("总览已过期、选择未确认或超过1000项") }
        let token = epoch, deadline = ProcessInfo.processInfo.systemUptime + 300
        var plans: [SourcePlan] = []
        do {
            for section in overview.sections {
                guard let report = section.report else { continue }
                let ids = selected.intersection(Set(report.candidates.map(\.id)))
                if ids.isEmpty { continue }
                let plan: CleanupPlan
                if section.source == .user { plan = try await engine.makePlan(reportID:report.id,selected:ids,includeUserData:includeUserData) }
                else {
                    guard let system else { throw SweepError.denied("系统扫描连接已失效，请重新扫描") }
                    plan = try await system.review(scanID:report.id,candidateIDs:ids.sorted { $0.uuidString < $1.uuidString })
                }
                try check(token)
                plans.append(.init(source:section.source,plan:plan))
            }
            guard Set(plans.flatMap { $0.plan.items.map(\.id) }) == selected else { throw SweepError.denied("各执行者的计划与本次选择不一致") }
            let presentation = CleanupReview(id:UUID(),overviewID:overview.id,items:plans.flatMap { $0.plan.items },retainedIssues:overview.unconfirmedIssues)
            reviewed = .init(presentation:presentation,plans:plans,deadline:deadline)
            return presentation
        } catch { reviewed = nil; throw error }
    }
    public func pendingRuns() async throws -> [CleanupRunReceipt] {
        guard !inFlight else { throw SweepError.denied("另一清理操作正在进行") }
        inFlight = true; defer { inFlight = false }
        let path = try await engine.coordinationStoragePath()
        return try CleanupCoordinationJournal.open(path:path,create:false)?.pending() ?? []
    }
    public func execute(reviewID: UUID) async throws -> CleanupRunResult {
        guard !inFlight else { throw SweepError.denied("另一清理操作正在进行") }
        inFlight = true; defer { inFlight = false }
        guard let review = reviewed, review.presentation.id == reviewID,
              ProcessInfo.processInfo.systemUptime < review.deadline else { throw SweepError.denied("组合计划不存在、已经使用或已过期") }
        let token = epoch
        let scannedOverview = overview
        reviewed = nil; overview = nil
        try check(token)
        let path = try await engine.coordinationStoragePath(); try check(token)
        guard let journal = try CleanupCoordinationJournal.open(path:path,create:true) else { throw SweepError.denied("组合日志不可用") }
        var receipt = CleanupRunReceipt(schemaVersion:1,id:reviewID,ownerUID:as_current_uid(),createdAt:Date(),status:.prepared,
                                       entries:review.plans.map { .init(source:$0.source,planID:$0.plan.id,batchID:nil,state:.pending) },issue:nil)
        try journal.create(receipt)
        var records: [CleanupBatchRecord] = [], uncertain: [CleanupSource] = []
        var issue: String?, persistenceFailed = false
        for (index,item) in review.plans.enumerated() {
            var submitted = false, received = false
            do {
                try check(token)
                receipt.status = .running; receipt.entries[index].state = .submitted
                try journal.persist(receipt)
                submitted = true
                let batch: RecoveryManifest
                if item.source == .user { batch = try await engine.execute(planID:item.plan.id) }
                else {
                    guard let system else { throw SweepError.denied("系统计划连接已失效，不能自动重建执行请求") }
                    batch = try await system.execute(planID:item.plan.id)
                }
                received = true
                records.append(.init(source:item.source,manifest:batch))
                receipt.entries[index].batchID = batch.id
                receipt.entries[index].state = batch.status == .isolated ? .isolated : (batch.status == .rolledBack ? .rolledBack : .needsAttention)
                try journal.persist(receipt)
                guard batch.status == .isolated else { issue = batch.issue ?? "本批次没有完成隔离"; break }
                try check(token)
            } catch {
                if item.source == .user && error is ExecutionPreflightFailure {
                    receipt.entries[index].state = .rolledBack
                } else if submitted && !received { uncertain.append(item.source) }
                issue = item.source.title + "：" + error.localizedDescription
                break
            }
        }
        if issue == nil {
            do {
                receipt.status = .isolated; try journal.persist(receipt)
                overview = scannedOverview?.excluding(Set(review.presentation.items.map(\.id)))
                return .init(id:reviewID,status:.isolated,batches:records,uncertainSources:[],retainedIssues:review.presentation.retainedIssues,issue:nil)
            } catch { issue = "组合完成状态未能持久化：" + error.localizedDescription; persistenceFailed = true }
        }
        receipt.status = .rollingBack; receipt.issue = String((issue ?? "操作未完成").prefix(4096))
        do { try journal.persist(receipt) } catch { persistenceFailed = true }
        // Never repeat an execute. Each engine durably records its own restore;
        // an unavailable group journal cannot justify hiding a known batch.
        for index in records.indices.reversed() {
            let record = records[index]
            if [.restored,.rolledBack].contains(record.manifest.status) { continue }
            if let entry = receipt.entries.firstIndex(where: { $0.source == record.source }) {
                receipt.entries[entry].state = .restoring
                do { try journal.persist(receipt) } catch { persistenceFailed = true }
            }
            do {
                let restored = try await restoreBatch(source:record.source,batchID:record.manifest.id)
                records[index] = .init(source:record.source,manifest:restored)
                if let entry = receipt.entries.firstIndex(where: { $0.source == record.source }) {
                    receipt.entries[entry].state = restored.status == .restored ? .restored : .needsAttention
                }
            } catch { issue = String(((issue ?? "") + "；恢复未完成：" + error.localizedDescription).prefix(4096)) }
            do { try journal.persist(receipt) } catch { persistenceFailed = true }
        }
        let restored = uncertain.isEmpty && !persistenceFailed && records.allSatisfy { [.restored,.rolledBack].contains($0.manifest.status) }
        receipt.status = restored ? .rolledBack : .needsAttention; receipt.issue = String((issue ?? "操作需要核对").prefix(4096))
        do { try journal.persist(receipt) } catch { persistenceFailed = true }
        if restored && !persistenceFailed && records.isEmpty { overview = scannedOverview }
        return .init(id:reviewID,status:restored && !persistenceFailed ? .rolledBack : .needsAttention,batches:records,uncertainSources:uncertain,retainedIssues:review.presentation.retainedIssues,issue:issue)
    }
    /// Read bounded summaries in separate authorised namespaces. A failed
    /// origin remains explicitly unknown and cannot erase another origin's rows.
    public func historyPage(afterUser: UUID? = nil,afterSystem: UUID? = nil) async throws -> CleanupHistoryPage {
        guard !inFlight else { throw SweepError.denied("另一清理操作正在进行") }
        guard afterUser == nil || afterSystem == nil else { throw SweepError.invalid("一次只继续一个恢复区的分页") }
        inFlight = true; defer { inFlight = false }
        overview = nil; reviewed = nil
        let token = epoch
        await closeSystem(); try check(token)
        let origins: [CleanupRecoveryOrigin] = afterUser != nil ? [.user] : (afterSystem != nil ? [.system] : [.user,.system])
        var rows: [CleanupRecoveryRow] = [], failures: [CleanupHistoryFailure] = []
        var userCursor: UUID?, systemCursor: UUID?
        var executionOrigins: Set<CleanupRecoveryOrigin> = []
        for origin in origins {
            do {
                let page: RecoveryBatchPage
                if origin == .user {
                    let policy = await engine.recoveryExecutionPolicy()
                    page = try await engine.recoveryPage(after:afterUser)
                    if policy.executionEnabled { executionOrigins.insert(.user) }
                    else { failures.append(.init(origin:.user,message:policy.limitation ?? "当前范围仅允许读取")) }
                } else {
                    let client = try await connect(token), status = try await client.status()
                    try check(token)
                    page = try await client.recoveryPage(after:afterSystem)
                    if status.executionEnabled { executionOrigins.insert(.system) }
                    else { failures.append(.init(origin:.system,message:status.limitation ?? "系统恢复区当前仅允许读取")) }
                }
                try check(token)
                rows += page.items.map { .init(origin:origin,summary:$0) }
                if origin == .user { userCursor = page.nextCursor } else { systemCursor = page.nextCursor }
            } catch {
                try check(token)
                failures.append(.init(origin:origin,message:error.localizedDescription))
                if origin == .system { await closeSystem() }
            }
        }
        return .init(rows:rows,nextUserCursor:userCursor,nextSystemCursor:systemCursor,queriedOrigins:origins,failures:failures,executionEnabledOrigins:executionOrigins)
    }
    public func recoveryDetail(origin: CleanupRecoveryOrigin,batchID: UUID) async throws -> RecoveryManifest {
        guard !inFlight else { throw SweepError.denied("另一清理操作正在进行") }
        inFlight = true; defer { inFlight = false }
        overview = nil; reviewed = nil
        let token = epoch
        await closeSystem(); try check(token)
        do {
            let batch: RecoveryManifest
            if origin == .user { batch = try await engine.recoveryBatch(id:batchID) }
            else { batch = try await connect(token).recoveryBatch(id:batchID) }
            try check(token)
            return batch
        } catch { await closeSystem(); throw error }
    }
    public func restoreRecovery(origin: CleanupRecoveryOrigin,batchID: UUID) async throws -> RecoveryManifest {
        guard !inFlight else { throw SweepError.denied("另一清理操作正在进行") }
        inFlight = true; defer { inFlight = false }
        overview = nil; reviewed = nil
        let token = epoch
        return try await restoreBatch(source:origin == .user ? .user : .systemCaches,batchID:batchID,expectedEpoch:token)
    }
    public func purgeRecovery(origin: CleanupRecoveryOrigin,batchID: UUID,confirmation: String) async throws -> RecoveryManifest {
        guard !inFlight else { throw SweepError.denied("另一清理操作正在进行") }
        guard confirmation == "永久清空 " + batchID.uuidString else { throw SweepError.denied("需要单独明确确认永久清空的批次") }
        inFlight = true; defer { inFlight = false }
        overview = nil; reviewed = nil
        let token = epoch
        await closeSystem(); try check(token)
        do {
            let batch: RecoveryManifest
            if origin == .user { batch = try await engine.purge(batchID:batchID,confirmation:confirmation) }
            else { batch = try await connect(token).purge(batchID:batchID,confirmation:confirmation) }
            try check(token)
            return batch
        } catch { await closeSystem(); throw error }
    }
    public func restore(source: CleanupSource,batchID: UUID) async throws -> RecoveryManifest {
        guard !inFlight else { throw SweepError.denied("另一清理操作正在进行") }
        inFlight = true; defer { inFlight = false }
        overview = nil; reviewed = nil
        return try await restoreBatch(source:source,batchID:batchID)
    }
    private func restoreBatch(source: CleanupSource,batchID: UUID,expectedEpoch: UInt64? = nil) async throws -> RecoveryManifest {
        let token = expectedEpoch ?? epoch
        await closeSystem(); try check(token)
        let result: RecoveryManifest
        if source == .user { result = try await engine.restore(batchID:batchID) }
        else { result = try await connect(token).restore(batchID:batchID) }
        try check(token)
        return result
    }
}
#endif
