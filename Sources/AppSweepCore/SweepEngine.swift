import Foundation
import CFSafety

/// Native filesystem and signature APIs can synchronously wait for dispatch
/// work. Keep that blocking work outside Swift's cooperative worker pool.
@available(macOS 14.0, *)
final class FilesystemExecutor: SerialExecutor, @unchecked Sendable {
    private let queue = DispatchQueue(label: "org.appsweep.filesystem", qos: .utility)
    func enqueue(_ job: UnownedJob) {
        queue.async { [self] in
            job.runSynchronously(on: asUnownedSerialExecutor())
        }
    }
}

/// Retain the existing default-actor scheduling on older Swift runtimes.
actor LegacyFilesystemExecutor { }

enum FailurePoint: Sendable { case beforeJournal, beforeMove, interruptAfterMove, beforeSecondMove, interruptDuringPurge, occupySecondPurge, lowSpace, insufficientBackupSpace, interruptAfterBackup, afterReconstruction
    case agentAfterUnregister, agentAfterRestore
    case preferenceBeforeBackup, preferenceAfterBackup, preferenceBeforeClear, preferenceAfterClear, preferenceBeforeRestore, preferenceAfterRestore
}

/// Only reports produced in this process can issue executable plans. Decoded JSON is never authority.
public actor SweepEngine {
    private nonisolated let legacyFilesystemExecutor = LegacyFilesystemExecutor()
    private nonisolated let filesystemExecutor: (any SerialExecutor)? = {
        if #available(macOS 14.0, *) { return FilesystemExecutor() }
        return nil
    }()
    public nonisolated var unownedExecutor: UnownedSerialExecutor {
        if #available(macOS 14.0, *), let filesystemExecutor { return filesystemExecutor.asUnownedSerialExecutor() }
        return legacyFilesystemExecutor.unownedExecutor
    }
    public static let ruleVersion = "2.1.0-parity-54"
    public static func previewLegacyReport(_ path: String) throws -> Data {
        let json = try JSONSerialization.jsonObject(with: SafeFilesystem.readMetadata(path, maximumBytes: 16 * 1024 * 1024))
        return try JSONSerialization.data(withJSONObject: json, options: [.prettyPrinted, .sortedKeys])
    }
    private let policy: SafetyPolicy
    private let vaultPath: String
    private let failurePoint: FailurePoint?
    private let fixture: Bool
    private var permitsLocalizedResourceReaders: Bool { policy.systemScope == nil && policy.ruleIsValidated(LocalizedResourceReader.name) }
    private var reports: [UUID: ScanReport] = [:]
    private var snapshots: [UUID: FileSnapshot] = [:]
    private var plans: [UUID: CleanupPlan] = [:]
    private var reportIgnores: [UUID: CleanupIgnoreList] = [:]
    private var planIgnores: [UUID: CleanupIgnoreList] = [:]
    private var ignoreStore: CleanupIgnoreStore { .init(home:policy.home,ownerUID:policy.systemScope?.requesterUID ?? as_current_uid()) }
    public init() {
        policy = .current
        vaultPath = policy.home + "/Library/Application Support/App Sweep/Recovery"
        failurePoint = nil; fixture = false
    }
    init(systemScope: SystemCleanupScope, failurePoint: FailurePoint? = nil) {
        policy = SafetyPolicy(systemScope:systemScope); vaultPath = systemScope.vaultPath
        self.failurePoint = failurePoint; fixture = false
    }
    #if DEBUG
    init(policy: SafetyPolicy, vaultPath: String, failurePoint: FailurePoint? = nil, fixture: Bool = true) {
        self.policy = policy; self.vaultPath = vaultPath; self.failurePoint = failurePoint; self.fixture = fixture
    }
    func adoptFixture(_ items: [Candidate], snapshots: [UUID: FileSnapshot], complete: Bool = true, applicationPath: String? = nil) -> ScanReport {
        let report = ScanReport(schemaVersion: 1, id: UUID(), createdAt: Date(), ruleVersion: Self.ruleVersion, applicationPath: applicationPath, candidates: items, complete: complete, issues: [], platformLimitation: policy.limitation)
        let ignores = try? ignoreStore.read()
        let filtered = ignores?.applying(to:report) ?? report
        register(filtered, snapshots: snapshots, ignores:ignores); return filtered
    }
    #endif
    func register(_ report: ScanReport, snapshots found: [UUID: FileSnapshot], ignores: CleanupIgnoreList? = nil) {
        // Bound in-memory scan history. Existing plans become invalid when their source report expires.
        if reports.count >= 4 { reports.removeAll(); snapshots.removeAll(); plans.removeAll(); reportIgnores.removeAll(); planIgnores.removeAll() }
        reports[report.id] = report; snapshots.merge(found) { _, new in new }
        reportIgnores[report.id] = ignores ?? .empty
    }
    public func cleanupIgnores() throws -> CleanupIgnoreList { try ignoreStore.read() }
    public func addCleanupIgnore(path: String, expectedRevision: UUID) throws -> CleanupIgnoreList {
        try updateIgnore(path:path,adding:true,expectedRevision:expectedRevision)
    }
    public func removeCleanupIgnore(path: String, expectedRevision: UUID) throws -> CleanupIgnoreList {
        try updateIgnore(path:path,adding:false,expectedRevision:expectedRevision)
    }
    public func setCleanupCategoryIgnored(_ category: CandidateCategory, ignored: Bool, expectedRevision: UUID) throws -> CleanupIgnoreList {
        guard policy.systemScope == nil else { throw SweepError.denied("系统执行者不能改写用户忽略设置") }
        let result = try ignoreStore.update(category:category,ignored:ignored,expectedRevision:expectedRevision)
        invalidateIgnoreEvidence()
        return result
    }
    private func updateIgnore(path: String, adding: Bool, expectedRevision: UUID) throws -> CleanupIgnoreList {
        guard policy.systemScope == nil else { throw SweepError.denied("系统执行者不能改写用户忽略设置") }
        let result = try ignoreStore.update(path:path,adding:adding,expectedRevision:expectedRevision)
        invalidateIgnoreEvidence()
        return result
    }
    private func invalidateIgnoreEvidence() {
        reports.removeAll(); plans.removeAll(); snapshots.removeAll(); reportIgnores.removeAll(); planIgnores.removeAll()
    }
    public func makePlan(reportID: UUID, selected: Set<UUID>, includeUserData: Bool) throws -> CleanupPlan {
        try policy.systemScope?.verify()
        guard let report = reports[reportID], report.ruleVersion == Self.ruleVersion else { throw SweepError.denied("扫描未完成或已过期，请重新扫描") }
        guard let ignores = reportIgnores[reportID] else { throw SweepError.denied("扫描缺少忽略设置记录") }
        try ignoreStore.verify(ignores)
        let known = Set(report.candidates.map(\.id))
        guard selected.isSubset(of: known) else { throw SweepError.invalid("选择包含未知项目") }
        let items = report.candidates.filter { selected.contains($0.id) }
        guard items.count <= 1000 else { throw SweepError.denied("单批项目超出恢复记录容量，请分批选择不超过 1000 项") }
        let validated = report.validatedSelectionIDs()
        guard !items.isEmpty, items.allSatisfy({ validated.contains($0.id) && $0.allowedActions.contains(.reviewPlan) && (!$0.userData || includeUserData) }) else { throw SweepError.denied("包含未确认范围、保留项目，或尚未选择同时清理用户数据") }
        guard report.selectionIsComplete(selected, includeUserData: includeUserData) else { throw SweepError.denied("应用主体与已确认后台组件、关联缓存必须按组处理") }
        if let app = report.applicationPath, !items.contains(where: { $0.path == app && $0.category == .application }) { throw SweepError.denied("应用主体必须先处理，不能单独处理其资料") }
        for item in items {
            guard ignores.reason(for:item) == nil else { throw SweepError.denied("选择包含用户忽略的项目") }
            if let reason = policy.denial(item) { throw SweepError.denied(reason) }
            guard registeredRecoveryRule(item), !legacyRealPreference(item), fixture || policy.ruleIsValidated(item.rule) else { throw SweepError.denied("规则未登记或旧偏好文件入口已退役，不能生成执行计划") }
            guard snapshots[item.id] != nil else { throw SweepError.invalid("缺少可信扫描身份") }
            for other in items where other.id != item.id {
                if SafetyPolicy.contains(item.path, other.path) { throw SweepError.invalid("计划包含重叠路径，请保留父项") }
            }
        }
        if !fixture {
            var checked = Set<String>()
            for item in items {
                let key = item.rule + ":" + (item.applicationPath ?? item.bundleIdentifier ?? URL(fileURLWithPath:item.path).deletingLastPathComponent().path)
                if checked.insert(key).inserted { try ensureStopped(item,applicationPath:item.applicationPath ?? report.applicationPath) }
            }
        }
        func order(_ item: Candidate) -> Int {
            if item.rule == InstalledSystemHelperRule.name,let scope=policy.systemScope{return InstalledSystemHelperRule.isBinary(item,scope:scope) ? -3 : -2}
            return item.rule == ApplicationAgentRule.name ? -1 : (item.category == .application ? 0 : (item.rule == ChromiumProfileRule.name ? 2 : 1))
        }
        let ordered = items.sorted { order($0) < order($1) }
        let warnings = report.unconfirmedIssues
        let plan = CleanupPlan(schemaVersion: 1, id: UUID(), reportID: reportID, createdAt: Date(), ruleVersion: Self.ruleVersion, items: ordered, includeUserData: includeUserData, retainedIssues: warnings.isEmpty ? nil : warnings,ignoreRevision:ignores.revision)
        plans[plan.id] = plan; planIgnores[plan.id] = ignores; return plan
    }
    func verifyOwner(_ item: Candidate, isolatedApplication: String? = nil, godotProofs: [String:GodotCacheRule.OwnerProof] = [:]) throws {
        guard !fixture else { return }
        if let scope = policy.systemScope {
            if item.rule == InstalledSystemHelperRule.name{guard isolatedApplication == nil,scope.denial(item) == nil else{throw SweepError.denied("辅助组件不能借用其他主体")};try InstalledSystemHelperRule.verify(item,scope:scope);return}
            if item.rule == SystemDiagnosticRule.name {
                guard isolatedApplication == nil, scope.denial(item) == nil,
                      try SystemDiagnosticRule.inspect(item.path, scope: scope).identifier == item.bundleIdentifier else { throw SweepError.denied("系统诊断报告归属已改变") }
                return
            }
            if item.rule == DeletedUserArchiveRule.name {guard isolatedApplication == nil,scope.denial(item) == nil else{throw SweepError.denied("账户归档不能借用应用归属")};try DeletedUserArchiveRule.verify(item.path,scope:scope);return}
            guard isolatedApplication == nil, let identifier = item.bundleIdentifier, let appPath = item.applicationPath else { throw SweepError.denied("系统应用归属未确认") }
            let currentInventory = try scope.applicationInventory()
            guard currentInventory.issues.isEmpty else { throw SweepError.incomplete("系统对象执行前归属复查未完成") }
            let inventory = currentInventory.applications
            guard let app = inventory.first(where: {$0.path == appPath && $0.bundleIdentifier == identifier}) else { throw SweepError.denied("系统应用主体已改变") }
            try scope.verifyApplication(app,inventory:inventory)
            try SystemDomainRule.verify(item,scope:scope)
            return
        }
        if item.rule == AIDiagnosticRule.name {
            guard isolatedApplication == nil, item.category == .log, item.bundleIdentifier == nil,
                  item.applicationPath == nil, item.component == nil else { throw SweepError.denied("诊断日志不能借用应用卸载归属") }
            _ = try AIDiagnosticRule.verify(path:item.path,home:policy.home)
            return
        }
        if AdditionalCleanupRule.names.contains(item.rule) {
            guard isolatedApplication == nil else { throw SweepError.denied("个人资料不能借用卸载主体归属") }
            try AdditionalCleanupRule.verify(item, home: policy.home)
            return
        }
        #if os(macOS)
        if item.rule == DocumentVersionRule.name {
            let current=try DocumentHistoryTransaction.inspect(item.path,home:policy.home)
            guard item.category == .userData,item.bundleIdentifier == nil,item.applicationPath == nil,snapshots[item.id]?.contentDigest == current.digest else{throw SweepError.stale("原生历史版本选择已改变")};return
        }
        #endif
        if item.rule == ApplicationAgentRule.name {
            guard item.category == .backgroundComponent,isolatedApplication == nil else{throw SweepError.denied("后台组件类型或执行顺序未确认")}
            _=try applicationAgentDeclaration(item);return
        }
        if item.rule == StaleUserAgentRule.name {
            guard item.category == .userData,item.bundleIdentifier == nil,item.applicationPath == nil,isolatedApplication == nil else{throw SweepError.denied("后台项不能借用应用归属")}
            let declaration=try StaleUserAgentRule.inspect(item.path,home:policy.home);_=try StaleUserAgentRule.registered(declaration);return
        }
        if item.rule == DeviceBackupRule.name {
            guard item.category == .deviceBackup, item.bundleIdentifier == nil, item.applicationPath == nil,
                  let snapshot = snapshots[item.id], snapshot.identity.owner == as_current_uid(),
                  snapshot.tree.allSatisfy({ $0.identity.owner == as_current_uid() && !$0.identity.isLink && ($0.identity.isDirectory || $0.identity.links == 1) }) else { throw SweepError.denied("设备备份完整归属未确认") }
            _ = try DeviceBackupRule.inspect(path:item.path,home:policy.home)
            try DeviceBackupRule.verifyTree(snapshot)
            return
        }
        if item.rule == XcodeDeviceSupportRule.name {
            guard item.category == .userData,item.bundleIdentifier == nil,item.applicationPath == nil,isolatedApplication == nil else{throw SweepError.denied("设备符号不能借用应用归属")}
            try XcodeDeviceSupportRule.verify(item.path,home:policy.home)
            return
        }
        if item.rule == XcodeArchiveRule.name {
            guard item.category == .userData,item.bundleIdentifier == nil,item.applicationPath == nil else{throw SweepError.denied("归档不能借用应用归属")}
            _=try XcodeArchiveRule.inspect(item.path,home:policy.home)
            return
        }
        if item.rule == GodotCacheRule.name {
            if let isolatedApplication {
                guard let app=item.applicationPath,let proof=godotProofs[app],proof.snapshot.path == isolatedApplication else { throw SweepError.denied("Godot 缓存缺少同批隔离主体凭据") }
            }
            try GodotCacheRule.verify(item,home:policy.home,ownerProof:item.applicationPath.flatMap { godotProofs[$0] }); return
        }
        if item.rule == UserCacheNamespaceRule.name {
            guard item.category == .cache, item.bundleIdentifier == nil, item.applicationPath == nil, isolatedApplication == nil else { throw SweepError.denied("通用缓存不能借用或伪造应用归属") }
            try UserCacheNamespaceRule.verify(path:item.path,home:policy.home)
            return
        }
        if ToolCacheRule.rules.contains(item.rule) {
            guard item.category == .development,item.bundleIdentifier == nil,item.applicationPath == nil,isolatedApplication == nil else{throw SweepError.denied("工具缓存不能借用应用归属")}
            guard ToolCacheRule.location(item.path,home:policy.home)?.producer.rule == item.rule else{throw SweepError.denied("工具缓存规则与路径不匹配")}
            _=try ToolCacheRule.verify(item.path,home:policy.home);return
        }
        if ApplicationCacheRule.rules.contains(item.rule) {
            guard isolatedApplication == nil else { throw SweepError.denied("应用缓存不能借用隔离主体的归属") }
            try ApplicationCacheRule.verify(item,home:policy.home)
            return
        }
        if item.rule == SimulatorCacheRule.name {try SimulatorCacheRule.verify(item,home:policy.home);return}
        if item.rule == XcodeGeneratedRule.name,item.category == .development {
            try XcodeGeneratedRule.verify(item.path,home:policy.home)
            return
        }
        if item.rule == XcodeRule.name, item.category == .development {
            try XcodeRule.verify(item.path, home: policy.home)
            guard let snapshot = snapshots[item.id], snapshot.identity.owner == as_current_uid(), snapshot.tree.allSatisfy({ $0.identity.owner == as_current_uid() }) else { throw SweepError.denied("开发中间目录包含其他所有者") }
            return
        }
        if [ChosenApplicationRule.name, ChosenApplicationRule.largeName, SelectedApplicationRule.name].contains(item.rule), item.category == .application {
            guard let identifier = item.bundleIdentifier, item.applicationPath == item.path else { throw SweepError.denied("应用主体选择未确认") }
            if item.rule == SelectedApplicationRule.name {
                if let isolatedApplication { try SelectedApplicationRule.verifyStored(path: isolatedApplication, identifier: identifier, requireNoInstalledHelpers: true) }
                else { try SelectedApplicationRule.verify(path: item.path, policy: policy, identifier: identifier) }
            } else if let isolatedApplication { try ChosenApplicationRule.verifyStored(path: isolatedApplication, identifier: identifier, requireNoInstalledHelpers: true) }
            else { try ChosenApplicationRule.verify(path: item.path, home: policy.home, identifier: identifier) }
            return
        }
        guard let identifier = item.bundleIdentifier, AppInspector.validIdentifier(identifier), let originalApp = item.applicationPath else { throw SweepError.denied("应用归属未确认") }
        let ownerInventory: [ApplicationIdentity]
        if let component=item.component {
            guard ApplicationComponentRule.supportedRules.contains(item.rule) else{throw SweepError.denied("此规则不能借用内嵌组件归属")}
            ownerInventory=try ApplicationComponentRule.verifyOwner(component,application:originalApp,identifier:identifier,home:policy.home,signaturePath:isolatedApplication)
        } else if let isolatedApplication {
            ownerInventory=try AppInspector.verifyIsolatedDataOwner(original:originalApp,stored:isolatedApplication,identifier:identifier,home:policy.home)
        } else {
            let app = try AppInspector.inspect(originalApp)
            var protectionCleared = app.protectedReason == nil || item.rule == FirefoxRule.name || item.rule == FirefoxFormatRule.name
            if !protectionCleared {
                _ = try AppInspector.verifiedDataOwner(path: originalApp, identifier: identifier, home: policy.home)
                protectionCleared = true
            }
            guard app.signed, app.bundleIdentifier == identifier, protectionCleared else { throw SweepError.denied("应用签名或归属已改变") }
            let inventory = try AppInspector.inventory(home: policy.home, selectedApplication: originalApp)
            guard AppInspector.uniqueOwner(identifier: identifier, path: originalApp, inventory: inventory) else { throw SweepError.denied("应用归属不唯一或安装位置未确认") }
            ownerInventory = inventory
        }
        if item.category != .application, let snapshot = snapshots[item.id] {
            guard snapshot.identity.owner == as_current_uid(), snapshot.tree.allSatisfy({ $0.identity.owner == as_current_uid() }) else { throw SweepError.denied("资料包含其他所有者，归属未确认") }
        }
        if item.rule == "ips-third-party-30d-v1" || item.rule == LegacyCrashRule.name {
            let snapshot = try SafeFilesystem.snapshot(item.path)
            guard snapshot.identity.size <= 2 * 1024 * 1024,
                  Attribution.oldLog(modified: Date(timeIntervalSince1970: Double(snapshot.identity.modifiedSeconds)), now: Date()),
                  (item.rule == LegacyCrashRule.name ? LegacyCrashRule.owns(try SafeFilesystem.readMetadata(item.path), identifier: identifier, applicationPath: originalApp) : DiagnosticRule.owns(try SafeFilesystem.readMetadata(item.path), identifier: identifier, applicationPath: originalApp)) else { throw SweepError.denied("诊断报告年龄或归属已改变") }
            try SafeFilesystem.verify(snapshot)
        }
        if item.rule == FirefoxRule.name || item.rule == FirefoxFormatRule.name {
            let peers = FirefoxRule.externalFamilyOwners(applicationPath:originalApp,inventory:try AppInspector.inventory(home:policy.home))
            guard peers.isEmpty else { throw SweepError.denied("存在其他 Mozilla 应用，缓存归属未确认") }
            if item.rule == FirefoxFormatRule.name { try FirefoxFormatRule.verify(item.path, home: policy.home, applicationPath: originalApp, signaturePath: isolatedApplication) }
            else { try FirefoxRule.verify(item.path, home: policy.home, applicationPath: originalApp, signaturePath: isolatedApplication) }
        }
        if item.rule == CacheRule.name {
            try CacheRule.verify(path: item.path, home: policy.home, identifier: identifier)
        }
        if item.rule == ApplicationLogRule.name {
            try ApplicationLogRule.verify(path: item.path, home: policy.home, identifier: identifier)
        }
        if item.rule == ApplicationLogRule.currentName {
            try ApplicationLogRule.verifyCurrent(path:item.path,home:policy.home,identifier:identifier)
        }
        if item.rule == CacheDomainRule.name {
            try ChromiumCacheRule.verifyNoRuntimeOverlap(identifier:identifier,inventory:ownerInventory)
            try CacheDomainRule.verify(path: item.path, home: policy.home, identifier: identifier)
        }
        if item.rule == DarwinCacheRule.name {
            guard let scope=policy.darwinScope,scope.home == policy.home else{throw SweepError.denied("Darwin 缓存账户范围未确认")}
            try DarwinCacheRule.verify(path:item.path,identifier:identifier,scope:scope)
        }
        if item.rule == WebKitCacheRule.name {
            guard let scope = policy.darwinScope, scope.home == policy.home, item.component == nil else { throw SweepError.denied("WebKit 缓存账户或归属范围未确认") }
            try WebKitCacheRule.verify(path: item.path, identifier: identifier, scope: scope)
        }
        if item.rule == WebKitTemporaryRule.name {
            guard let scope = policy.darwinTemporaryScope, scope.home == policy.home, item.component == nil else { throw SweepError.denied("WebKit 临时目录账户或归属范围未确认") }
            try WebKitTemporaryRule.verify(path: item.path, identifier: identifier, scope: scope)
        }
        if item.rule == ChromiumCacheRule.name {
            let root = try ChromiumCacheRule.verifiedRoot(path:item.path,home:policy.home,identifier:identifier,applicationPath:originalApp,signaturePath:isolatedApplication)
            try CacheDomainRule.verifyMember(path:item.path,root:root,home:policy.home)
        }
        if item.rule == SupportDomainRule.name {
            try ChromiumCacheRule.verifyNoRuntimeOverlap(identifier:identifier,inventory:ownerInventory)
            try SupportDomainRule.verify(path: item.path, home: policy.home, identifier: identifier)
        }
        if item.rule == ApplicationStorageRule.name {
            guard item.category == .userData, item.component == nil else { throw SweepError.denied("网页资料不能借用其他规则归属") }
            try ApplicationStorageRule.verify(path: item.path, home: policy.home, identifier: identifier)
        }
        if item.rule == NamedApplicationRule.cacheName || item.rule == NamedApplicationRule.dataName {
            try NamedApplicationRule.verifyOwner(application:originalApp,identifier:identifier,home:policy.home,signaturePath:isolatedApplication,inventory:ownerInventory)
            try NamedApplicationRule.verify(item.path,home:policy.home,identifier:identifier,cache:item.rule == NamedApplicationRule.cacheName)
        }
        if item.rule == ApplicationGroupRule.name {
            try ApplicationGroupRule.verify(path:item.path,home:policy.home,signaturePath:isolatedApplication ?? originalApp,originalApplicationPath:originalApp,identifier:identifier,inventory:ownerInventory)
        }
        if item.rule == ApplicationScriptsRule.name {
            guard AppInspector.signatureMatches(path:isolatedApplication ?? originalApp,identifier:identifier) else{throw SweepError.denied("应用脚本代码签名标识不匹配")}
            try ApplicationScriptsRule.verify(item.path,home:policy.home,identifier:identifier)
        }
        if item.rule == CorruptPreferenceRule.name {
            let current=try CorruptPreferenceRule.inspect(path:item.path,home:policy.home,identifier:identifier)
            guard snapshots[item.id]?.contentDigest == current.digest else{throw SweepError.stale("损坏偏好文件内容已改变")}
        }
        if item.rule == ContainerDataRule.name {
            try ContainerDataRule.verifySandbox(path:isolatedApplication ?? originalApp,identifier:identifier)
            _=try ContainerDataRule.verify(path:item.path,home:policy.home,identifier:identifier)
        }
        if item.rule == ChromiumProfileRule.name {
            _ = try ChromiumProfileRule.verify(path:item.path,home:policy.home,identifier:identifier,applicationPath:originalApp,signaturePath:isolatedApplication,inventory:ownerInventory)
        }
    }
    private func legacyRealPreference(_ item: Candidate) -> Bool {
        item.rule == "cfpreferences-exact-domain-v1" && policy.home == (try? SystemIdentity.home())
    }
    public func execute(planID: UUID) async throws -> RecoveryManifest {
        try policy.systemScope?.verify()
        let systemLease = try policy.systemScope?.operationLock()
        defer { if let systemLease { as_close(systemLease) } }
        try policy.systemScope?.ensureNoUnfinishedOperations()
        guard policy.executionEnabled else { throw SweepError.denied(policy.limitation ?? "只读模式") }
        guard let plan = plans.removeValue(forKey: planID), reports[plan.reportID] != nil, plan.ruleVersion == Self.ruleVersion, Date().timeIntervalSince(plan.createdAt) < 300 else { throw SweepError.invalid("计划未知、已使用或过期") }
        guard let ignores = planIgnores.removeValue(forKey:planID) else { throw SweepError.invalid("计划缺少忽略设置记录") }
        let ignoreLease: CleanupIgnoreLease
        do { ignoreLease = try ignoreStore.executionLease(ignores) }
        catch { throw ExecutionPreflightFailure(message:error.localizedDescription) }
        defer { ignoreLease.keepAlive() }
        var godotProofs: [String:GodotCacheRule.OwnerProof] = [:]
        do {
        #if os(macOS)
        if plan.items.contains(where:{needsApplicationTransfer($0)}) { try await ApplicationTransferClient.preflight() }
        #endif
        for app in Set(plan.items.filter { $0.rule == GodotCacheRule.name }.compactMap(\.applicationPath)) {
            godotProofs[app]=try GodotCacheRule.ownerProof(application:app,home:policy.home)
        }
        for item in plan.items {
            guard let snapshot = snapshots[item.id], policy.denial(item) == nil, registeredRecoveryRule(item), !legacyRealPreference(item), fixture || policy.ruleIsValidated(item.rule) else { throw SweepError.denied("计划重新验证失败") }
            if item.rule != PreferenceRecoveryRecord.rule { try SafeFilesystem.verify(snapshot) }
            try verifyOwner(item,godotProofs:godotProofs)
            if !fixture { try BusyInspector.ensureUnused(snapshot,allowReadOnlyLocalization:permitsLocalizedResourceReaders) }
            if !fixture { try ensureStopped(item, applicationPath: item.applicationPath ?? reports[plan.reportID]?.applicationPath) }
        }
        try verifyCacheGroups(plan, removed: [],godotProofs:godotProofs)
        try ignoreStore.verify(ignores,lease:ignoreLease)
        } catch { throw ExecutionPreflightFailure(message:error.localizedDescription) }
        if failurePoint == .beforeJournal { throw SweepError.filesystem("注入：日志写入失败") }
        let vault = try openVault(create: true)
        guard as_lock(vault.fd) == 0 else { throw SweepError.denied("另一操作正在使用恢复区") }
        #if os(macOS)
        if policy.systemScope == nil, vaultPath == policy.home + "/Library/Application Support/App Sweep/Recovery" { try ApplicationOptimizationEngine.ensureNoPending(policy:policy,paths:plan.items.flatMap { [$0.path] + ($0.applicationPath.map { [$0] } ?? []) },identifiers:Set(plan.items.compactMap(\.bundleIdentifier))) }
        #endif
        for id in try batchIDs(vault) {
            let previous = try readManifest(vault.existingPrivateChild(id.uuidString),id:id)
            guard ![.inProgress,.purging,.needsAttention].contains(previous.status) else { throw SweepError.denied("请先处理未完成的恢复批次") }
        }
        var backupBytes: UInt64 = 0
        #if os(macOS)
        var historyPreparations:[UUID:DocumentHistoryTransaction.Prepared]=[:]
        var historyParts=0
        for item in plan.items where item.rule == DocumentVersionRule.name {
            guard let snapshot=snapshots[item.id] else{throw SweepError.denied("缺少文稿审查身份")}
            let prepared=try DocumentHistoryTransaction.prepare(item,snapshot:snapshot,home:policy.home)
            historyParts+=prepared.selection.record.parts.count;guard historyParts<=200 else{throw SweepError.denied("单批历史版本超出恢复容量，请分批选择")}
            historyPreparations[item.id]=prepared;backupBytes+=prepared.requiredBytes
        }
        var preferencePreparations: [UUID:PreferenceTransaction.Prepared] = [:]
        for item in plan.items where item.rule == PreferenceRecoveryRecord.rule {
            guard let snapshot=snapshots[item.id] else { throw SweepError.invalid("缺少偏好扫描身份") }
            let prepared=try PreferenceTransaction.prepare(snapshot,candidate:item,home:policy.home)
            preferencePreparations[item.id]=prepared;backupBytes += prepared.requiredBytes
        }
        #endif
        var archivePreparations: [UUID: CacheArchive.Prepared] = [:]
        for item in plan.items where [CacheRule.name,CorruptPreferenceRule.name].contains(item.rule) {
            guard let snapshot = snapshots[item.id] else { throw SweepError.invalid("缺少独立备份的扫描身份") }
            backupBytes += try CacheBackup.requiredBytes(snapshot)
        }
        for item in plan.items where CacheArchive.supports(item.rule) {
            guard let snapshot = snapshots[item.id] else { throw SweepError.invalid("缺少通用缓存的可信扫描身份") }
            let prepared = try CacheArchive.prepare(snapshot, candidate: item)
            archivePreparations[item.id] = prepared
            backupBytes += prepared.requiredBytes
        }
        let available = failurePoint == .insufficientBackupSpace ? CacheBackup.freeSpaceReserve + 1 : vault.availableBytes
        guard failurePoint != .lowSpace, available > CacheBackup.freeSpaceReserve + backupBytes else { throw SweepError.denied("可用空间不足，不能可靠保存整批恢复副本及操作记录") }
        let id = UUID(); let batch = try vault.privateChild(id.uuidString)
        var manifest = RecoveryManifest(schemaVersion: policy.systemScope == nil ? RecoveryManifest.currentSchemaVersion : RecoveryManifest.systemSchemaVersion, id: id, createdAt: Date(), status: .inProgress, entries: [], issue: nil, retainedIssues: plan.retainedIssues)
        manifest.requestingUserID = policy.systemScope?.requesterUID
        let cacheItems = plan.items.filter { CacheArchive.supports($0.rule) }
        if !cacheItems.isEmpty {
            manifest.cacheSelection = try cacheItems.map { item in
                guard let snapshot = snapshots[item.id] else { throw SweepError.invalid("缺少缓存组的完整扫描记录") }
                return CacheRecoveryMember(original: item, fingerprint: try TreeFingerprint.capture(snapshot.tree))
            }
        }
        let objects = try batch.privateChild(manifest.objectsDirectory)
        try persist(manifest, in: batch)
        do {
            for (index, item) in plan.items.enumerated() {
                try ignoreStore.verify(ignores,lease:ignoreLease)
                guard let snapshot = snapshots[item.id] else { throw SweepError.invalid("扫描身份丢失") }
                if failurePoint == .beforeMove || (failurePoint == .beforeSecondMove && index == 1) { throw SweepError.filesystem("注入：移动失败") }
                #if os(macOS)
                if item.rule == PreferenceRecoveryRecord.rule {
                    guard let prepared=preferencePreparations[item.id] else { throw SweepError.invalid("缺少可信偏好扫描内容") }
                    try PreferenceDomainService.verify(prepared.original)
                } else { try SafeFilesystem.verify(snapshot) }
                #else
                try SafeFilesystem.verify(snapshot)
                #endif
                let isolatedApp = manifest.entries.first { $0.original.category == .application && $0.original.path == item.applicationPath && $0.state == .moved }.map { objects.path + "/" + $0.id.uuidString }
                try verifyOwner(item, isolatedApplication: isolatedApp,godotProofs:godotProofs)
                if !fixture { try BusyInspector.ensureUnused(snapshot,allowReadOnlyLocalization:permitsLocalizedResourceReaders) }
                if !fixture { try ensureStopped(item, applicationPath: isolatedApp ?? item.applicationPath ?? reports[plan.reportID]?.applicationPath) }
                guard snapshot.identity.device == (try objects.ownIdentity).device else { throw SweepError.denied("首版不处理其他卷") }
                let large = snapshot.tree.count > TreeFingerprint.inlineLimit
                let fingerprint = large ? try TreeFingerprint.capture(snapshot.tree) : nil
                manifest.entries.append(RecoveryEntry(id: item.id, original: item, state: .prepared, message: nil, contents: large ? [] : snapshot.tree, treeFingerprint: fingerprint, originalAncestors: snapshot.ancestors))
                if item.category == .application {
                    manifest.entries[manifest.entries.count - 1].applicationLinks = try ApplicationLinkRecovery.capture(snapshot)
                }
                if item.rule == InstalledSystemHelperRule.name,let scope=policy.systemScope{
                    if InstalledSystemHelperRule.isBinary(item,scope:scope){
                        manifest.entries[manifest.entries.count-1].systemHelper = .init(wasRegistered:try InstalledSystemHelperRule.registered(item,scope:scope),phase:.prepared)
                        try persist(manifest,in:batch)
                    }else{
                        guard let reference=item.systemHelper,let binaryIndex=manifest.entries.firstIndex(where:{$0.original.rule == InstalledSystemHelperRule.name && $0.original.systemHelper == reference && InstalledSystemHelperRule.isBinary($0.original,scope:scope) && $0.state == .moved}),manifest.entries[binaryIndex].systemHelper != nil else{throw SweepError.denied("辅助程序尚未同批隔离，不能注销服务")}
                        manifest.entries[binaryIndex].systemHelper?.phase = .unregistering;try persist(manifest,in:batch)
                        try InstalledSystemHelperRule.unregister(item,scope:scope)
                        if failurePoint == .agentAfterUnregister{throw Interruption.injected}
                        manifest.entries[binaryIndex].systemHelper?.phase = .unregistered;try persist(manifest,in:batch)
                    }
                }
                #if os(macOS)
                if item.rule == DocumentVersionRule.name {
                    guard let prepared=historyPreparations[item.id] else{throw SweepError.invalid("缺少已核对的文稿历史")}
                    let last=manifest.entries.count-1
                    manifest.entries[last].history=prepared.selection.record
                    manifest.entries[last].backupDigest=prepared.digest;manifest.entries[last].backupFormat=DocumentHistoryTransaction.format;manifest.entries[last].backupPending=true
                    try persist(manifest,in:batch)
                    let saved=try DocumentHistoryTransaction.create(prepared,item:item,in:batch.privateChild(manifest.backupsDirectory))
                    manifest.entries[last].backupIdentity=saved.identity;manifest.entries[last].backupBytes=saved.bytes;manifest.entries[last].backupPending=false;try persist(manifest,in:batch)
                    var entry=manifest.entries[last]
                    let journalFD=batch.fd,journalPath=batch.path,journalIdentity=try batch.ownIdentity
                    let interruptedRemoval = failurePoint == .interruptAfterMove
                    try DocumentHistoryTransaction.remove(&entry,home:policy.home,isolation:self,afterNativeRemoval:{if interruptedRemoval{throw Interruption.injected}}){changed in
                        manifest.entries[last]=changed
                        let journal=try SafeDirectory.duplicating(journalFD,path:journalPath,expected:journalIdentity)
                        try persist(manifest,in:journal)
                    }
                    entry.state = .moved;entry.message="历史版本已独立备份并经 macOS 移除；当前文稿保留"
                    manifest.entries[last]=entry;try persist(manifest,in:batch);continue
                }
                if item.rule == PreferenceRecoveryRecord.rule {
                    guard let prepared=preferencePreparations[item.id] else { throw SweepError.invalid("缺少已核对的偏好服务状态") }
                    let last=manifest.entries.count-1
                    manifest.entries[last].preference = .init(phase:.prepared,originalValuesDigest:prepared.original.valuesDigest)
                    manifest.entries[last].preference?.originalRawDigest=prepared.original.inspection.digest
                    manifest.entries[last].backupDigest=prepared.digest
                    manifest.entries[last].backupFormat=PreferenceTransaction.format
                    manifest.entries[last].backupPending=true
                    try persist(manifest,in:batch)
                    if failurePoint == .preferenceBeforeBackup { throw Interruption.injected }
                    let saved=try PreferenceTransaction.create(prepared,candidate:item,in:batch.privateChild(manifest.backupsDirectory))
                    if failurePoint == .preferenceAfterBackup { throw Interruption.injected }
                    manifest.entries[last].backupIdentity=saved.identity
                    manifest.entries[last].backupBytes=saved.bytes
                    manifest.entries[last].backupPending=false
                    try persist(manifest,in:batch)
                    manifest.entries[last].preference?.phase = .clearing
                    try persist(manifest,in:batch)
                    if failurePoint == .preferenceBeforeClear { throw Interruption.injected }
                    try verifyOwner(item,isolatedApplication:isolatedApp,godotProofs:godotProofs)
                    if !fixture { try ensureStopped(item,applicationPath:isolatedApp ?? item.applicationPath) }
                    try ignoreStore.verify(ignores,lease:ignoreLease)
                    let empty=try PreferenceDomainService.clear(prepared.original)
                    if failurePoint == .preferenceAfterClear { throw Interruption.injected }
                    manifest.entries[last].preference?.emptyIdentity=empty.inspection.snapshot.identity
                    manifest.entries[last].preference?.phase = .cleared
                    manifest.entries[last].state = .moved
                    manifest.entries[last].message="设置已独立备份并通过 macOS 偏好服务清除"
                    try persist(manifest,in:batch)
                    continue
                }
                #endif
                if [StaleUserAgentRule.name,ApplicationAgentRule.name].contains(item.rule) {
                    let declaration=try applicationAgentDeclaration(item),last=manifest.entries.count-1
                    manifest.entries[last].userAgent = .init(wasRegistered:try StaleUserAgentRule.registered(declaration),phase:.prepared)
                    if item.rule == ApplicationAgentRule.name {
                        guard let body=plan.items.first(where:{$0.category == .application && $0.path == item.applicationPath && $0.bundleIdentifier == item.bundleIdentifier}),let identity=snapshots[body.id]?.identity,let identifier=item.bundleIdentifier else{throw SweepError.denied("后台组件缺少已核对的同批主体")}
                        manifest.entries[last].userAgent?.applicationIdentity=identity
                        manifest.entries[last].userAgent?.applicationCodeHash=try ApplicationAgentRule.codeHash(application:body.path,identifier:identifier)
                    }
                    try persist(manifest,in:batch)
                    manifest.entries[last].userAgent?.phase = .unregistering;try persist(manifest,in:batch)
                    try StaleUserAgentRule.unregister(declaration)
                    if failurePoint == .agentAfterUnregister{throw Interruption.injected}
                    manifest.entries[last].userAgent?.phase = .unregistered;try persist(manifest,in:batch)
                    try SafeFilesystem.verify(snapshot)
                }
                try persist(manifest, in: batch) // Durable intent precedes every mutation.
                if [CacheRule.name,CorruptPreferenceRule.name].contains(item.rule) {
                    let prepared = try CacheBackup.prepare(snapshot, candidate: item)
                    manifest.entries[manifest.entries.count - 1].backupDigest = prepared.digest
                    manifest.entries[manifest.entries.count - 1].backupPending = true
                    try persist(manifest, in: batch) // Digest and destination intent precede archive creation.
                    let identity = try CacheBackup.create(prepared, snapshot: snapshot, candidate: item, in: batch.privateChild(manifest.backupsDirectory))
                    if failurePoint == .interruptAfterBackup { throw Interruption.injected }
                    manifest.entries[manifest.entries.count - 1].backupIdentity = identity
                    manifest.entries[manifest.entries.count - 1].backupPending = false
                    try persist(manifest, in: batch) // Independent bytes are durable before the original inode moves.
                }
                if CacheArchive.supports(item.rule) {
                    guard let prepared = archivePreparations[item.id] else { throw SweepError.invalid("缺少已复核的独立缓存归档") }
                    let last = manifest.entries.count - 1
                    manifest.entries[last].backupDigest = prepared.digest
                    manifest.entries[last].backupFormat = CacheArchive.format
                    manifest.entries[last].backupPending = true
                    try persist(manifest, in: batch)
                    let archive = try CacheArchive.create(prepared, snapshot: snapshot, candidate: item, in: batch.privateChild(manifest.backupsDirectory))
                    if failurePoint == .interruptAfterBackup { throw Interruption.injected }
                    manifest.entries[last].backupIdentity = archive.identity
                    manifest.entries[last].backupBytes = archive.bytes
                    manifest.entries[last].backupPending = false
                    try persist(manifest, in: batch)
                }
                if CacheArchive.supports(item.rule) {
                    let originals = manifest.entries.filter { $0.original.category == .application && $0.state == .moved }
                    let paths = Dictionary(uniqueKeysWithValues:originals.map { ($0.original.path,objects.path + "/" + $0.id.uuidString) })
                    try verifyCacheGroups(plan,removed:Set(manifest.entries.filter { $0.state == .moved }.map(\.id)),signaturePaths:paths,godotProofs:godotProofs)
                }
                try ignoreStore.verify(ignores,lease:ignoreLease)
                #if os(macOS)
                if needsApplicationTransfer(item) {
                    try await ApplicationTransferClient.isolate(batchID:id,itemID:item.id,snapshot:snapshot)
                    let moved=try SafeFilesystem.snapshot(objects.path + "/" + item.id.uuidString,allowInternalLinks:true,purpose:.application,allowApplicationHardLinks:true)
                    guard try !SafeFilesystem.presence(snapshot.path),moved.identity.sameObject(as:snapshot.identity),moved.tree == snapshot.tree else { throw SweepError.stale("管理员移动后的应用身份未确认") }
                } else { try SafeFilesystem.move(snapshot, into: objects, name: item.id.uuidString) }
                #else
                try SafeFilesystem.move(snapshot, into: objects, name: item.id.uuidString)
                #endif
                if failurePoint == .interruptAfterMove { throw Interruption.injected }
                manifest.entries[manifest.entries.count - 1].isolatedIdentity = try objects.identity(item.id.uuidString)
                manifest.entries[manifest.entries.count - 1].state = .moved
                try persist(manifest, in: batch)
                if item.category == .application,godotProofs[item.path] != nil {
                    godotProofs[item.path]=try GodotCacheRule.ownerProof(application:item.path,home:policy.home,signaturePath:objects.path + "/" + item.id.uuidString)
                }
            }
            let isolatedBodies = manifest.entries.filter { $0.original.category == .application && $0.state == .moved }
            let isolatedPaths = Dictionary(uniqueKeysWithValues:isolatedBodies.map { ($0.original.path,objects.path + "/" + $0.id.uuidString) })
            let profileSources = try ChromiumProfileRule.recoverySources(manifest,objects:objects,home:policy.home)
            try verifyCacheGroups(plan,removed:Set(manifest.entries.filter { $0.state == .moved }.map(\.id)),signaturePaths:isolatedPaths,profileSources:profileSources,godotProofs:godotProofs)
            manifest.status = .isolated; try persist(manifest, in: batch); return manifest
        } catch Interruption.injected { throw SweepError.filesystem("注入：进程中断，保留待恢复日志") }
        catch {
            manifest.issue = error.localizedDescription
            do { manifest = try await restoreEntries(manifest, batch: batch, objects: objects, rollback: true) }
            catch { manifest.status = .needsAttention; manifest.issue = "操作失败且恢复未确认：" + error.localizedDescription; try? persist(manifest, in: batch) }
            return manifest
        }
    }
    public func recoveryBatches() throws -> [RecoveryManifest] {
        guard try SafeFilesystem.presence(vaultPath) else { return [] }
        let vault = try openVault(create: false)
        guard as_lock(vault.fd) == 0 else { throw SweepError.denied("恢复区正在使用") }
        return try readBatches(vault)
    }
    func recoveryPage(after cursor: UUID?) throws -> RecoveryBatchPage {
        try Task.checkCancellation()
        try policy.systemScope?.verify()
        guard try SafeFilesystem.presence(vaultPath) else {
            guard cursor == nil else { throw SweepError.stale("恢复分页位置已不存在，请刷新列表") }
            return RecoveryBatchPage(items:[],nextCursor:nil)
        }
        let vault = try openVault(create:false)
        guard as_lock(vault.fd) == 0 else { throw SweepError.denied("恢复区正在使用") }
        // Keep only bounded summaries in memory. Read and discard each complete
        // record so creation dates, rather than random UUIDs, determine history.
        var summaries: [RecoveryBatchSummary] = []
        for id in try batchIDs(vault) {
            try Task.checkCancellation()
            summaries.append(RecoveryBatchSummary(try historyManifest(vault,id:id)))
        }
        summaries.sort {
            $0.createdAt == $1.createdAt ? $0.id.uuidString < $1.id.uuidString : $0.createdAt > $1.createdAt
        }
        let start: Int
        if let cursor {
            guard let position = summaries.firstIndex(where:{ $0.id == cursor }) else { throw SweepError.stale("恢复分页位置已不存在，请刷新列表") }
            start = position + 1
        } else { start = 0 }
        let end = min(start + RecoveryBatchPage.pageSize,summaries.count)
        try Task.checkCancellation()
        return RecoveryBatchPage(items:Array(summaries[start..<end]),nextCursor:end < summaries.count ? summaries[end - 1].id : nil)
    }
    func recoveryBatch(id: UUID) throws -> RecoveryManifest {
        try policy.systemScope?.verify()
        let vault = try openVault(create:false)
        guard as_lock(vault.fd) == 0 else { throw SweepError.denied("恢复区正在使用") }
        return try readManifest(vault.existingPrivateChild(id.uuidString),id:id)
    }
    public func restore(batchID: UUID) async throws -> RecoveryManifest {
        let systemLease = try policy.systemScope?.operationLock()
        defer { if let systemLease { as_close(systemLease) } }
        guard policy.executionEnabled else { throw SweepError.denied(policy.limitation ?? "只读模式") }
        let vault = try openVault(create: false)
        guard as_lock(vault.fd) == 0 else { throw SweepError.denied("恢复区正在使用") }
        let batch = try vault.existingPrivateChild(batchID.uuidString)
        let manifest = try readManifest(batch, id: batchID)
        if let reason=manifest.previewOnlyReason{throw SweepError.denied(reason)}
        guard manifest.entries.allSatisfy({ fixture || (policy.ruleIsValidated($0.original.rule) && ($0.treeFingerprint == nil || policy.ruleIsValidated($0.original.rule == DeviceBackupRule.name ? DeviceBackupRule.largeName : ChosenApplicationRule.largeName))) }) else { throw SweepError.denied("该恢复规则尚未通过当前平台验收，仅允许预览") }
        let objects = try batch.existingPrivateChild(manifest.objectsDirectory)
        return try await restoreEntries(manifest, batch: batch, objects: objects, rollback: false)
    }
    public func purge(batchID: UUID, confirmation: String) async throws -> RecoveryManifest {
        let systemLease = try policy.systemScope?.operationLock()
        defer { if let systemLease { as_close(systemLease) } }
        guard policy.executionEnabled, confirmation == "永久清空 " + batchID.uuidString else { throw SweepError.denied("需要单独明确确认永久清空的批次") }
        let vault = try openVault(create: false)
        guard as_lock(vault.fd) == 0 else { throw SweepError.denied("恢复区正在使用") }
        let batch = try vault.existingPrivateChild(batchID.uuidString)
        var manifest = try readManifest(batch, id: batchID)
        if let reason=manifest.previewOnlyReason{throw SweepError.denied(reason)}
        guard manifest.entries.allSatisfy({ fixture || (policy.ruleIsValidated($0.original.rule) && ($0.treeFingerprint == nil || policy.ruleIsValidated($0.original.rule == DeviceBackupRule.name ? DeviceBackupRule.largeName : ChosenApplicationRule.largeName))) }) else { throw SweepError.denied("该清空规则尚未通过当前平台验收，仅允许预览") }
        guard manifest.canPurge else { throw SweepError.denied("未完成或存在冲突的批次不能永久清空") }
        let restoredBatch = manifest.status != .isolated
        let objects = try batch.existingPrivateChild(manifest.objectsDirectory)
        let backups = manifest.hasIndependentBackups ? try batch.existingPrivateChild(manifest.backupsDirectory) : nil
        var targets = [[(SafeDirectory, FileSnapshot)]]()
        // Check every original object and archive before deleting the first one.
        for entry in manifest.entries {
            var entryTargets = [(SafeDirectory, FileSnapshot)]()
            if !restoredBatch && entry.preference == nil && entry.history == nil {
                guard entry.state == .moved, let expected = entry.isolatedIdentity else { throw SweepError.denied("恢复对象状态未确认") }
                let path = objects.path + "/" + entry.id.uuidString
                if try SafeFilesystem.presence(path) {
                    let snapshot = try SafeFilesystem.snapshot(path, allowInternalLinks: entry.original.category == .application || [ContainerDataRule.name,ApplicationScriptsRule.name,ApplicationGroupRule.name,DownloadCacheRule.builderName,AIStorageRule.name].contains(entry.original.rule), purpose: entry.original.category == .application ? .application : ([DeviceBackupRule.name,ContainerDataRule.name,ApplicationScriptsRule.name,ApplicationGroupRule.name,TrashEntryRule.name,MailDownloadRule.name,AIStorageRule.name].contains(entry.original.rule) ? .managedData : .ordinary), allowInternalHardLinks: CacheArchive.supports(entry.original.rule), allowApplicationHardLinks: entry.original.category == .application)
                    guard snapshot.identity == expected, try entry.matchesContents(snapshot) else { throw SweepError.stale("恢复对象已改变，不能永久清空") }
                    if AdditionalCleanupRule.names.contains(entry.original.rule) { try AdditionalCleanupRule.verifyContents(snapshot, original: entry.original, home: policy.home) }
                    if entry.original.rule == DeviceBackupRule.name { try DeviceBackupRule.verifyTree(snapshot) }
                    if entry.original.rule == DeletedUserArchiveRule.name,let scope=policy.systemScope{try DeletedUserArchiveRule.verify(entry.original.path,scope:scope,storedPath:snapshot.path)}
                    entryTargets.append((objects, snapshot))
                } else if entry.backupDigest == nil { throw SweepError.stale("恢复对象缺失，不能确认永久清空范围") }
            } else if restoredBatch {
                guard entry.state == .restored || entry.state == .purged else { throw SweepError.denied("恢复对象状态未确认") }
            }
            if let backups, entry.backupDigest != nil {
                entryTargets.append((backups, try IndependentBackup.verifiedSnapshot(entry, in: backups)))
            }
            for (_, snapshot) in entryTargets where !fixture { try BusyInspector.ensureUnused(snapshot,allowReadOnlyLocalization:permitsLocalizedResourceReaders) }
            if !restoredBatch && entry.original.rule == ApplicationAgentRule.name {
                try verifyApplicationAgentPurgeOwner(entry,manifest:manifest,objects:objects)
            }
            targets.append(entryTargets)
        }
        manifest.status = .purging
        try persist(manifest, in: batch)
        for index in manifest.entries.indices {
            let previousState = manifest.entries[index].state
            if targets[index].isEmpty { continue }
            #if DEBUG
            let occupied = failurePoint == .occupySecondPurge && index == 1 ? try FileHandle(forReadingFrom: URL(fileURLWithPath: targets[index][0].1.path)) : nil
            defer { try? occupied?.close() }
            #endif
            do {
                let entry = manifest.entries[index]
                if !restoredBatch && entry.original.rule == ApplicationAgentRule.name {
                    try verifyApplicationAgentPurgeOwner(entry,manifest:manifest,objects:objects)
                }
                for (directory, expected) in targets[index] {
                    let current = try SafeFilesystem.snapshot(expected.path, allowInternalLinks: entry.original.category == .application || [ContainerDataRule.name,ApplicationScriptsRule.name,ApplicationGroupRule.name,DownloadCacheRule.builderName,AIStorageRule.name].contains(entry.original.rule), purpose: entry.original.category == .application ? .application : ([DeviceBackupRule.name,ContainerDataRule.name,ApplicationScriptsRule.name,ApplicationGroupRule.name,TrashEntryRule.name,MailDownloadRule.name,AIStorageRule.name].contains(entry.original.rule) ? .managedData : .ordinary), allowInternalHardLinks: CacheArchive.supports(entry.original.rule), allowApplicationHardLinks: entry.original.category == .application)
                    if AdditionalCleanupRule.names.contains(entry.original.rule) { try AdditionalCleanupRule.verifyContents(current, original: entry.original, home: policy.home) }
                    if entry.original.rule == DeviceBackupRule.name { try DeviceBackupRule.verifyTree(current) }
                    guard current.identity == expected.identity, current.tree == expected.tree else { throw SweepError.stale("清空前对象或内容已改变") }
                    if directory.path == backups?.path { _ = try IndependentBackup.verifiedSnapshot(entry, in: directory) }
                    if !fixture { try BusyInspector.ensureUnused(current,allowReadOnlyLocalization:permitsLocalizedResourceReaders) }
                }
                if !fixture { try ensureStopped(entry.original, applicationPath: entry.original.category == .application ? targets[index][0].1.path : entry.original.applicationPath,metadataPath:targets[index][0].1.path,purging:true) }
            } catch {
                manifest.status = .needsAttention; manifest.issue = "清空前复查失败，停止后续项目：" + error.localizedDescription
                try persist(manifest, in: batch); return manifest
            }
            manifest.entries[index].state = .purgePrepared
            try persist(manifest, in: batch)
            if failurePoint == .interruptDuringPurge { throw SweepError.filesystem("注入：永久清空中断，状态未确认") }
            for (directory, expected) in targets[index] {
                if !fixture { try BusyInspector.ensureUnused(expected,allowReadOnlyLocalization:permitsLocalizedResourceReaders) }
                #if os(macOS)
                if needsApplicationTransfer(manifest.entries[index].original,sourcePath:expected.path),directory.path == objects.path {
                    do { try await ApplicationTransferClient.purge(batchID:batchID,itemID:manifest.entries[index].id,confirmation:confirmation) }
                    catch { manifest.status = .needsAttention;manifest.issue=error.localizedDescription;try persist(manifest,in:batch);return manifest }
                    guard try !SafeFilesystem.presence(expected.path) else { throw SweepError.stale("管理员清空结果未确认") }
                    continue
                }
                #endif
                guard SafeFilesystem.removeVerified(in: directory, name: manifest.entries[index].id.uuidString, identity: expected.identity, contents: expected.tree, allowInternalHardLinks: expected.allowInternalHardLinks, allowApplicationHardLinks: expected.allowApplicationHardLinks) else {
                    manifest.status = .needsAttention; manifest.issue = "永久清空未完成，停止后续处理"; try persist(manifest, in: batch); return manifest
                }
            }
            manifest.entries[index].backupDigest = nil; manifest.entries[index].backupIdentity = nil
            manifest.entries[index].backupFormat = nil; manifest.entries[index].backupBytes = nil; manifest.entries[index].reconstructedContents = nil
            manifest.entries[index].state = restoredBatch ? previousState : .purged
            try persist(manifest, in: batch)
        }
        manifest.status = .purged; try persist(manifest, in: batch); return manifest
    }
    private enum Interruption: Error { case injected }
    func recoveryExecutionPolicy() -> SafetyPolicy { policy }
    /// Internal fixed storage for the coordinator; never derived from a report
    /// or supplied to a privileged endpoint. DEBUG engines keep their own home.
    func coordinationStoragePath() throws -> String {
        guard policy.systemScope == nil, as_current_uid() != 0 else { throw SweepError.denied("组合日志仅属于当前普通用户") }
        return policy.home + "/Library/Application Support/App Sweep/Coordination.noindex"
    }
    private func openVault(create: Bool) throws -> SafeDirectory {
        if let systemScope = policy.systemScope { return try systemScope.openVault(create:create) }
        if !create { return try checkedVault() }
        let url = URL(fileURLWithPath: vaultPath)
        if fixture { return try SafeDirectory(path: url.deletingLastPathComponent().path).privateChild(url.lastPathComponent) }
        #if DEBUG
        // Only the internal DEBUG initializer supplies a different vault. Native
        // current-home tests retain real ownership/activity checks in their own
        // private task directory, rather than touching existing recovery batches.
        if vaultPath != policy.home + "/Library/Application Support/App Sweep/Recovery" {
            let parent=try SafeDirectory(path:url.deletingLastPathComponent().path)
            guard as_private_descriptor(parent.fd) == 1, SafetyPolicy.contains(policy.home,vaultPath) else { throw SweepError.denied("原生验收恢复区必须位于当前用户私有任务目录") }
            return try parent.privateChild(url.lastPathComponent)
        }
        #endif
        let support = try SafeDirectory(path: policy.home + "/Library/Application Support")
        guard let root = try support.appSweepSupport(create: true) else { throw SweepError.denied("恢复区父目录不存在") }
        return try root.privateChild("Recovery")
    }
    private func checkedVault() throws -> SafeDirectory {
        let vault = try SafeDirectory(path: vaultPath); let identity = try vault.ownIdentity
        guard identity.owner == as_current_uid(), as_private_descriptor(vault.fd) == 1 else { throw SweepError.denied("恢复区权限或 ACL 未确认") }; return vault
    }
    private func persist(_ manifest: RecoveryManifest, in batch: SafeDirectory) throws {
        try policy.systemScope?.verify()
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601; encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(manifest)
        guard data.count <= 16 * 1024 * 1024 else { throw SweepError.denied("恢复清单过大，停止操作") }
        try batch.write(data, name: "manifest.json")
    }
    private func registeredRecoveryRule(_ item: Candidate) -> Bool {
        if let component=item.component {
            guard policy.systemScope == nil,ApplicationComponentRule.valid(component),ApplicationComponentRule.supportedRules.contains(item.rule),item.applicationPath != nil,item.bundleIdentifier != component.ownerIdentifier else{return false}
        }
        if let systemScope = policy.systemScope {
            return systemScope.denial(item,requireCurrentVolume:false) == nil && [SystemDiagnosticRule.name,SystemDomainRule.cacheName,SystemDomainRule.logName,SystemDomainRule.currentLogName,DeletedUserArchiveRule.name,InstalledSystemHelperRule.name].contains(item.rule)
        }
        if item.rule == AIDiagnosticRule.name {
            return item.category == .log && item.bundleIdentifier == nil && item.applicationPath == nil && item.component == nil &&
                item.identity?.owner == as_current_uid() && item.identity?.links == 1 &&
                ((item.identity?.mode ?? 0) & 0o170000) == 0o100000 && AIDiagnosticRule.matches(path:item.path,home:policy.home)
        }
        if AdditionalCleanupRule.names.contains(item.rule) {
            return AdditionalCleanupRule.matches(item, home: policy.home) && policy.denial(item) == nil
        }
        if item.rule == DocumentVersionRule.name {
            #if os(macOS)
            return item.category == .userData && item.bundleIdentifier == nil && item.applicationPath == nil && item.identity?.owner == as_current_uid() && ((item.identity?.mode ?? 0) & 0o170000) == 0o100000 && DocumentVersionRule.matches(item.path,home:policy.home)
            #else
            return false
            #endif
        }
        if item.rule == ApplicationAgentRule.name {
            return item.category == .backgroundComponent && item.bundleIdentifier.map(SystemCleanupScope.validIdentifier) == true && item.applicationPath.map{SelectedApplicationRule.matches(path:$0,policy:policy)} == true && item.identity?.owner == as_current_uid() && item.identity?.links == 1 && ((item.identity?.mode ?? 0) & 0o170000) == 0o100000 && StaleUserAgentRule.label(path:item.path,home:policy.home) != nil
        }
        if item.rule == StaleUserAgentRule.name {
            return item.category == .userData && item.bundleIdentifier == nil && item.applicationPath == nil && item.identity?.owner == as_current_uid() && ((item.identity?.mode ?? 0) & 0o170000) == 0o100000 && StaleUserAgentRule.label(path:item.path,home:policy.home) != nil
        }
        if item.rule == DeviceBackupRule.name {
            return item.category == .deviceBackup && item.bundleIdentifier == nil && item.applicationPath == nil &&
                item.identity?.isDirectory == true && item.identity?.owner == as_current_uid() && DeviceBackupRule.matches(path:item.path,home:policy.home)
        }
        if item.rule == XcodeDeviceSupportRule.name {
            return item.category == .userData && item.bundleIdentifier == nil && item.applicationPath == nil && item.identity?.isDirectory == true && item.identity?.owner == as_current_uid() && XcodeDeviceSupportRule.matches(item.path,home:policy.home)
        }
        if item.rule == XcodeArchiveRule.name {
            return item.category == .userData && item.bundleIdentifier == nil && item.applicationPath == nil && item.identity?.isDirectory == true && item.identity?.owner == as_current_uid() && XcodeArchiveRule.matches(item.path,home:policy.home)
        }
        if item.rule == GodotCacheRule.name {
            return item.category == .cache && item.bundleIdentifier == GodotCacheRule.identifier && item.applicationPath != nil && item.identity?.owner == as_current_uid() && item.identity?.links == 1 && ((item.identity?.mode ?? 0) & 0o170000) == 0o100000 && GodotCacheRule.matches(item.path,home:policy.home)
        }
        if item.rule == UserCacheNamespaceRule.name {
            return item.category == .cache && item.bundleIdentifier == nil && item.applicationPath == nil &&
                item.identity?.owner == as_current_uid() && UserCacheNamespaceRule.namespace(path:item.path,home:policy.home) != nil
        }
        if ToolCacheRule.rules.contains(item.rule) {
            guard let location=ToolCacheRule.location(item.path,home:policy.home),let identity=item.identity,
                  location.producer.rule == item.rule else{return false}
            let kindMatches = ToolCacheRule.kindMatches(identity, path: item.path, home: policy.home)
            return item.category == .development && item.bundleIdentifier == nil && item.applicationPath == nil && kindMatches && identity.owner == as_current_uid()
        }
        if ApplicationCacheRule.rules.contains(item.rule) {
            return item.category == .cache && item.identity?.owner == as_current_uid() && item.applicationPath != nil &&
                item.bundleIdentifier != nil && ApplicationCacheRule.identifier(path:item.path,home:policy.home,rule:item.rule) == item.bundleIdentifier
        }
        if item.rule == DarwinCacheRule.name {
            guard let scope=policy.darwinScope,scope.home == policy.home,let id=item.bundleIdentifier else{return false}
            return item.category == .cache && item.applicationPath != nil && item.identity?.owner == scope.ownerUID && scope.identifier(path:item.path) == id
        }
        if item.rule == WebKitCacheRule.name {
            guard let scope = policy.darwinScope, scope.home == policy.home, let id = item.bundleIdentifier else { return false }
            return item.category == .cache && item.applicationPath != nil && item.component == nil && item.identity?.owner == scope.ownerUID && WebKitCacheRule.root(path: item.path, identifier: id, scope: scope) != nil
        }
        if item.rule == WebKitTemporaryRule.name {
            guard let scope = policy.darwinTemporaryScope, scope.home == policy.home, let id = item.bundleIdentifier else { return false }
            return item.category == .cache && item.applicationPath != nil && item.component == nil && item.identity?.isDirectory == true && item.identity?.owner == scope.ownerUID && WebKitTemporaryRule.root(path: item.path, identifier: id, scope: scope) != nil
        }
        if item.rule == SimulatorCacheRule.name {
            return item.category == .development && item.bundleIdentifier == nil && item.applicationPath == nil && item.identity?.isDirectory == true && item.identity?.owner == as_current_uid() && SimulatorCacheRule.deviceID(item.path,home:policy.home) == item.simulatorDevice?.id && item.simulatorDevice != nil
        }
        if item.rule == XcodeGeneratedRule.name,item.category == .development {
            return item.bundleIdentifier == "com.apple.dt.Xcode" && item.applicationPath == nil && item.identity?.isDirectory == true && item.identity?.owner == as_current_uid() && XcodeGeneratedRule.matches(item.path,home:policy.home)
        }
        if item.rule == XcodeRule.name, item.category == .development {
            return item.bundleIdentifier == "com.apple.dt.Xcode" && item.identity?.isDirectory == true && XcodeRule.derivedDirectory(item.path, home: policy.home) != nil
        }
        guard let identifier = item.bundleIdentifier, AppInspector.validIdentifier(identifier), (!identifier.lowercased().hasPrefix("com.apple.") || (item.category == .application && item.rule == SelectedApplicationRule.name)), !identifier.lowercased().contains("appsweep"), !identifier.lowercased().contains("app-sweep") else { return false }
        switch (item.rule, item.category) {
        case (SelectedApplicationRule.name, .application):
            return item.identity?.isDirectory == true && item.applicationPath == item.path && SelectedApplicationRule.matches(path: item.path, policy: policy)
        case (ChosenApplicationRule.name, .application), (ChosenApplicationRule.largeName, .application):
            return item.identity?.isDirectory == true && item.applicationPath == item.path && ChosenApplicationRule.matches(path: item.path, home: policy.home)
        case ("signed-application-v1", .application):
            let parent = URL(fileURLWithPath: item.path).deletingLastPathComponent().path
            return item.identity?.isDirectory == true && item.path.hasSuffix(".app") && ["/Applications", policy.home + "/Applications"].contains(parent)
        case ("cfpreferences-exact-domain-v1", .userData):
            return ((item.identity?.mode ?? 0) & 0o170000) == 0o100000 && item.path == policy.home + "/Library/Preferences/" + identifier + ".plist"
        case (CorruptPreferenceRule.name,.userData):
            return item.applicationPath != nil && item.identity?.owner == as_current_uid() && ((item.identity?.mode ?? 0) & 0o170000) == 0o100000 && CorruptPreferenceRule.matches(path:item.path,home:policy.home,identifier:identifier)
        case (PreferenceRecoveryRecord.rule, .userData):
            return ((item.identity?.mode ?? 0) & 0o170000) == 0o100000 && item.identity?.owner == as_current_uid() && item.identity?.links == 1 && item.path == policy.home + "/Library/Preferences/" + identifier + ".plist" && item.applicationPath != nil
        case (SupportDomainRule.name, .userData):
            return item.identity?.isDirectory == true && item.identity?.owner == as_current_uid() && SupportDomainRule.matches(path: item.path, home: policy.home, identifier: identifier)
        case (ApplicationStorageRule.name, .userData):
            return item.applicationPath != nil && item.component == nil && item.identity?.owner == as_current_uid()
                && item.identity.map { ApplicationStorageRule.kindMatches($0, path: item.path) } == true
                && ApplicationStorageRule.matches(path: item.path, home: policy.home, identifier: identifier)
        case (NamedApplicationRule.cacheName,.cache),(NamedApplicationRule.dataName,.userData):
            return item.applicationPath != nil && item.identity?.owner == as_current_uid() && NamedApplicationRule.matches(item.path,home:policy.home,identifier:identifier,cache:item.rule == NamedApplicationRule.cacheName)
        case (ChromiumProfileRule.name, .userData):
            return item.identity?.isDirectory == true && item.identity?.owner == as_current_uid() && item.applicationPath != nil && ChromiumProfileRule.structuralMatch(path:item.path,home:policy.home)
        case ("exclusive-container-v1", .userData):
            return item.identity?.isDirectory == true && item.path == policy.home + "/Library/Containers/" + identifier
        case (ApplicationGroupRule.name,.userData):
            return item.identity?.isDirectory == true && item.identity?.owner == as_current_uid() && ApplicationGroupRule.matches(item.path,home:policy.home) && item.applicationPath != nil
        case (ApplicationScriptsRule.name,.userData):
            return item.identity?.isDirectory == true && item.identity?.owner == as_current_uid() && ApplicationScriptsRule.matches(item.path,home:policy.home,identifier:identifier) && item.applicationPath != nil
        case (ContainerDataRule.name,.userData):
            return item.identity?.isDirectory == true && item.identity?.owner == as_current_uid() && ContainerDataRule.matches(item.path,home:policy.home,identifier:identifier) && item.applicationPath != nil
        case (ApplicationLogRule.name, .log):
            return ((item.identity?.mode ?? 0) & 0o170000) == 0o100000 && item.identity?.owner == as_current_uid() && ApplicationLogRule.matches(path: item.path, home: policy.home, identifier: identifier)
        case (ApplicationLogRule.currentName, .log):
            return ((item.identity?.mode ?? 0) & 0o170000) == 0o100000 && item.identity?.owner == as_current_uid() && item.applicationPath != nil && ApplicationLogRule.currentMatches(path:item.path,home:policy.home,identifier:identifier)
        case ("ips-third-party-30d-v1", .log):
            return ((item.identity?.mode ?? 0) & 0o170000) == 0o100000 && item.path.hasSuffix(".ips") && URL(fileURLWithPath: item.path).deletingLastPathComponent().path == policy.home + "/Library/Logs/DiagnosticReports"
        case (LegacyCrashRule.name, .log):
            return ((item.identity?.mode ?? 0) & 0o170000) == 0o100000 && item.identity?.owner == as_current_uid() && item.path.hasSuffix(".crash") && URL(fileURLWithPath: item.path).deletingLastPathComponent().path == policy.home + "/Library/Logs/DiagnosticReports"
        case (FirefoxRule.name, .cache):
            return identifier == "org.mozilla.firefox" && item.identity?.isDirectory == true && FirefoxRule.cacheLeaf(item.path, home: policy.home) != nil
        case (FirefoxFormatRule.name, .cache):
            return identifier == "org.mozilla.firefox" && item.identity?.isDirectory == true && FirefoxRule.cacheLeaf(item.path, home: policy.home) != nil
        case (CacheRule.name, .cache):
            return item.identity?.isDirectory == false && CacheRule.matches(path: item.path, home: policy.home, identifier: identifier)
        case (CacheDomainRule.name, .cache):
            return item.identity?.owner == as_current_uid() && CacheDomainRule.matches(path: item.path, home: policy.home, identifier: identifier)
        case (ChromiumCacheRule.name, .cache):
            return item.identity?.owner == as_current_uid() && item.applicationPath != nil && ChromiumCacheRule.structuralMatch(path:item.path,home:policy.home)
        case (CacheRule.legacyName, .cache):
            return item.identity?.isDirectory == true && item.path == CacheRule.path(home: policy.home, identifier: identifier)
        case ("fixture-v1", .cache):
            return fixture && item.path == policy.home + "/Library/Caches/" + identifier
        default: return false
        }
    }
    private func recoveryPathDenial(_ item:Candidate)->String? {
        if let scope=policy.systemScope{return scope.denial(item,requireCurrentVolume:false)}
        return policy.denial(item)
    }
    private func readManifest(_ batch: SafeDirectory, id: UUID) throws -> RecoveryManifest {
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        var result = try decoder.decode(RecoveryManifest.self, from: batch.read("manifest.json"))
        result.previewOnlyReason=nil // Derived from validated contents, never caller authority.
        let versions = policy.systemScope == nil ? RecoveryManifest.userSchemaVersions : [RecoveryManifest.systemSchemaVersion]
        guard versions.contains(result.schemaVersion), result.requestingUserID == policy.systemScope?.requesterUID,
              result.id == id, result.entries.count <= 1000, Set(result.entries.map(\.id)).count == result.entries.count else { throw SweepError.denied("恢复清单结构或请求用户绑定无效") }
        for entry in result.entries {
            if let links = entry.applicationLinks {
                guard result.schemaVersion == 5, policy.systemScope == nil else { throw SweepError.denied("应用硬链接恢复证据版本无效") }
                try links.validate(for: entry)
            }
            let helperBinary=policy.systemScope.map{entry.original.rule == InstalledSystemHelperRule.name && InstalledSystemHelperRule.isBinary(entry.original,scope:$0)} ?? false
            guard helperBinary == (entry.systemHelper != nil),entry.systemHelper == nil || (result.schemaVersion == RecoveryManifest.systemSchemaVersion && entry.preference == nil && entry.userAgent == nil && entry.history == nil && entry.backupDigest == nil),
                  (entry.original.rule == InstalledSystemHelperRule.name) == (entry.original.systemHelper != nil) else{throw SweepError.denied("系统辅助组件恢复记录与类型不一致")}
            guard (entry.original.rule == DocumentVersionRule.name) == (entry.history != nil),entry.history == nil || (result.schemaVersion == 5 && policy.systemScope == nil && entry.preference == nil && entry.userAgent == nil && entry.isolatedIdentity == nil && entry.contents.isEmpty && entry.treeFingerprint == nil && entry.history!.parts.count<=100) else{throw SweepError.denied("文稿历史阶段与类型不一致")}
            guard [StaleUserAgentRule.name,ApplicationAgentRule.name].contains(entry.original.rule) == (entry.userAgent != nil),entry.userAgent == nil || (result.schemaVersion == 5 && policy.systemScope == nil && entry.preference == nil && entry.backupDigest == nil) else{throw SweepError.denied("后台项恢复阶段与规则不一致")}
            guard (entry.original.rule == PreferenceRecoveryRecord.rule) == (entry.preference != nil) else { throw SweepError.denied("偏好阶段与规则不一致") }
            if let digest = entry.backupDigest {
                guard ([CacheRule.name,CorruptPreferenceRule.name,PreferenceRecoveryRecord.rule,DocumentVersionRule.name] + CacheArchive.rules).contains(entry.original.rule), entry.backupIdentity != nil || entry.backupPending == true, digest.count == 64, digest.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw SweepError.denied("独立备份记录无效") }
            } else if entry.backupIdentity != nil { throw SweepError.denied("独立备份缺少摘要") }
            if entry.backupPending == true || entry.reconstructionPending == true {
                guard ([CacheRule.name,CorruptPreferenceRule.name,PreferenceRecoveryRecord.rule,DocumentVersionRule.name] + CacheArchive.rules).contains(entry.original.rule), entry.backupDigest != nil else { throw SweepError.denied("备份阶段缺少已登记摘要") }
            }
            if CacheArchive.supports(entry.original.rule), entry.backupDigest != nil {
                guard entry.backupFormat == CacheArchive.format, entry.backupBytes.map({ $0 >= 0 }) ?? (entry.backupPending == true) else { throw SweepError.denied("通用缓存归档格式或容量未登记") }
            } else if entry.original.rule == DocumentVersionRule.name {
                if entry.state == .purged || (entry.state == .restored && entry.backupDigest == nil){
                    guard entry.backupDigest == nil,entry.backupIdentity == nil,entry.backupFormat == nil,entry.backupBytes == nil,entry.backupPending != true else{throw SweepError.denied("已清空的历史记录仍含副本授权")}
                }else{
                    guard entry.backupDigest != nil,entry.backupFormat == "native-document-history-backup-v1",entry.backupBytes.map({$0>=0}) ?? (entry.backupPending == true) else{throw SweepError.denied("历史版本独立副本未登记")}
                }
            } else if entry.original.rule == PreferenceRecoveryRecord.rule {
                #if os(macOS)
                guard result.schemaVersion == 5, policy.systemScope == nil,
                      result.entries.contains(where:{ $0.original.category == .application && $0.original.path == entry.original.applicationPath && $0.original.bundleIdentifier == entry.original.ownerIdentifier }) else { throw SweepError.denied("偏好恢复记录缺少同批应用主体") }
                try PreferenceTransaction.validateRecord(entry,home:policy.home)
                #else
                throw SweepError.denied("当前平台不能执行原生偏好事务")
                #endif
            } else if entry.backupFormat != nil || entry.backupBytes != nil || entry.reconstructedContents != nil || entry.preference != nil { throw SweepError.denied("恢复记录的独立归档类型无效") }
            if let contents = entry.reconstructedContents {
                guard contents.count == entry.contents.count, contents.map(\.relative) == entry.contents.map(\.relative), contents.allSatisfy({ $0.identity.owner == as_current_uid() && !$0.identity.isLink }), !SupportDomainRule.containsProtectedContent(contents) else { throw SweepError.denied("重建结构与原始对象不一致") }
            }
            guard entry.id == entry.original.id, entry.original.allowed, recoveryPathDenial(entry.original) == nil, entry.original.identity != nil, registeredRecoveryRule(entry.original) else { throw SweepError.denied("恢复清单包含越界或未知对象") }
            if entry.original.component != nil {
                guard result.entries.contains(where:{$0.original.category == .application && $0.original.path == entry.original.applicationPath && $0.original.bundleIdentifier == entry.original.ownerIdentifier}) else{throw SweepError.denied("组件恢复记录缺少同批外层应用")}
            }
            if entry.original.rule == ApplicationAgentRule.name {
                guard let identity=entry.userAgent?.applicationIdentity,let hash=entry.userAgent?.applicationCodeHash,[20,32].contains(hash.count),identity.isDirectory else{throw SweepError.denied("后台组件恢复记录缺少原主体身份与代码摘要")}
                if let body=result.entries.first(where:{$0.original.category == .application && $0.original.path == entry.original.applicationPath && $0.original.bundleIdentifier == entry.original.bundleIdentifier}){
                    guard body.original.identity == identity else{throw SweepError.denied("后台组件与同批主体身份不一致")}
                }
            }
            if entry.original.rule == DeviceBackupRule.name {
                guard entry.contents.allSatisfy({ $0.identity.owner == as_current_uid() && !$0.identity.isLink && ($0.identity.isDirectory || $0.identity.links == 1) }) else { throw SweepError.denied("设备备份恢复清单包含链接或其他所有者") }
            }
            if [ContainerDataRule.name,ApplicationScriptsRule.name,ApplicationGroupRule.name].contains(entry.original.rule) {
                guard result.entries.contains(where:{$0.original.category == .application && $0.original.path == entry.original.applicationPath && $0.original.bundleIdentifier == entry.original.bundleIdentifier}),
                      entry.contents.allSatisfy({$0.identity.owner == as_current_uid()}),!SupportDomainRule.containsProtectedContent(entry.contents.filter{!$0.identity.isLink}) else{throw SweepError.denied("容器恢复缺少同批主体或包含其他所有者/安全状态")}
            }
            if ([SupportDomainRule.name,ChromiumProfileRule.name,NamedApplicationRule.dataName,ApplicationStorageRule.name] + CacheArchive.rules).contains(entry.original.rule) {
                guard entry.contents.allSatisfy({ $0.identity.owner == as_current_uid() }), !SupportDomainRule.containsProtectedContent(entry.contents) else { throw SweepError.denied("应用资料恢复清单包含其他所有者或安全状态") }
            }
            if let fingerprint = entry.treeFingerprint {
                guard [2, 3, 5].contains(result.schemaVersion),
                      ((entry.original.category == .application && [ChosenApplicationRule.largeName, SelectedApplicationRule.name].contains(entry.original.rule)) || (entry.original.category == .deviceBackup && entry.original.rule == DeviceBackupRule.name) || (entry.original.category == .userData && [ContainerDataRule.name,ApplicationScriptsRule.name,ApplicationGroupRule.name,TrashEntryRule.name,MailDownloadRule.name,AIStorageRule.name].contains(entry.original.rule))),
                      entry.original.identity?.isDirectory == true, entry.contents.isEmpty,
                      fingerprint.validLargeTree else { throw SweepError.denied("大型恢复对象摘要结构或版本无效") }
            }
            guard entry.contents.count <= 20_000, entry.contents.allSatisfy({ !$0.relative.isEmpty && !$0.relative.hasPrefix("/") && !$0.relative.split(separator: "/").contains("..") && !$0.relative.split(separator: "/").contains(".") }), Set(entry.contents.map(\.relative)).count == entry.contents.count else { throw SweepError.denied("恢复清单包含无效的对象路径") }
        }
        if let members = result.cacheSelection {
            guard !members.isEmpty, members.count <= 1000, Set(members.map { $0.original.id }).count == members.count,
                  Set(members.map { $0.original.path }).count == members.count else { throw SweepError.denied("缓存组恢复记录重复或超出容量") }
            let byID = Dictionary(uniqueKeysWithValues: members.map { ($0.original.id, $0) })
            for member in members {
                guard CacheArchive.supports(member.original.rule), member.original.category == .cache,
                      member.original.allowed, registeredRecoveryRule(member.original), recoveryPathDenial(member.original) == nil,
                      member.fingerprint.validCacheTree, member.original.identity?.isDirectory == true || member.fingerprint.count == 0 else { throw SweepError.denied("缓存组含越界或未确认成员") }
            }
            for entry in result.entries where CacheArchive.supports(entry.original.rule) {
                guard byID[entry.id]?.original == entry.original else { throw SweepError.denied("缓存组与逐项操作记录不一致") }
            }
        }
        #if os(macOS)
        if result.entries.contains(where:{$0.original.identity?.volumeUUID == nil || $0.originalAncestors?.contains(where:{$0.volumeUUID == nil}) == true}){
            result.previewOnlyReason="旧恢复记录缺少稳定的磁盘卷身份，只可预览；原文件与副本均保留，不会猜测或改写原记录。"
        }
        #endif
        return result
    }
    /// Display uncertainty per batch. This placeholder is never persisted or
    /// passed to execution: restore and purge always call strict readManifest.
    private func historyManifest(_ vault:SafeDirectory,id:UUID)throws->RecoveryManifest {
        let directory=try vault.existingPrivateChild(id.uuidString)
        do{return try readManifest(directory,id:id)}
        catch{
            let detail=String(error.localizedDescription.unicodeScalars.filter{!CharacterSet.controlCharacters.contains($0)}.prefix(160))
            let message="恢复记录未能校验，原文件与副本均保留："+detail
            return RecoveryManifest(schemaVersion:RecoveryManifest.currentSchemaVersion,id:id,createdAt:Date(timeIntervalSince1970:Double(try directory.ownIdentity.modifiedSeconds)),status:.needsAttention,entries:[],issue:message,previewOnlyReason:message,requestingUserID:policy.systemScope?.requesterUID)
        }
    }
    private func batchIDs(_ vault: SafeDirectory) throws -> [UUID] {
        let names = try FileManager.default.contentsOfDirectory(atPath:vault.path)
        guard names.count <= 1000 else { throw SweepError.denied("恢复批次过多，需要人工检查") }
        return try names.sorted().map { name in
            guard let id = UUID(uuidString:name), id.uuidString == name else { throw SweepError.denied("恢复区存在未登记对象，需要人工检查") }
            return id
        }
    }
    private func readBatches(_ vault: SafeDirectory) throws -> [RecoveryManifest] {
        try batchIDs(vault).map { id in
            try historyManifest(vault,id:id)
        }.sorted { $0.createdAt > $1.createdAt }
    }
    private func restoreEntries(_ initial: RecoveryManifest, batch: SafeDirectory, objects: SafeDirectory, rollback: Bool) async throws -> RecoveryManifest {
        var manifest = initial; var conflict = false
        let godotProofs: [String:GodotCacheRule.OwnerProof]
        do { godotProofs = try preflightCacheRecovery(manifest, objects: objects) }
        catch {
            if let index = manifest.entries.firstIndex(where: { (CacheArchive.supports($0.original.rule) || $0.original.rule == ChromiumProfileRule.name) && $0.state != .restored && $0.state != .purged }) {
                manifest.entries[index].state = .conflict
                manifest.entries[index].message = "关联缓存整组恢复暂停：" + error.localizedDescription
            }
            manifest.status = .needsAttention; try persist(manifest, in: batch); return manifest
        }
        // Reverse execution order, but never overwrite a newly created original path.
        for index in manifest.entries.indices.reversed() {
            var entry = manifest.entries[index]
            if entry.state == .restored || entry.state == .purged { continue }
            do {
                let name = entry.id.uuidString
                let original = entry.original.path
                guard policy.denial(entry.original) == nil else { throw SweepError.denied("恢复目标受保护") }
                if entry.original.rule == ApplicationAgentRule.name {
                    guard let app=entry.original.applicationPath,let identifier=entry.original.bundleIdentifier,
                          let identity=entry.userAgent?.applicationIdentity,try SafeDirectory(path:app).ownIdentity.sameObject(as:identity),
                          try ApplicationAgentRule.codeHash(application:app,identifier:identifier) == entry.userAgent?.applicationCodeHash else{throw SweepError.stale("原后台组件的应用主体尚未恢复或已被替换，保留且不注册")}
                }
                if entry.original.rule == CorruptPreferenceRule.name {
                    guard let id=entry.original.bundleIdentifier,let app=entry.original.applicationPath else{throw SweepError.denied("损坏偏好恢复归属缺失")}
                    _=try AppInspector.verifiedDataOwner(path:app,identifier:id,home:policy.home)
                    guard try AppInspector.uniqueOwner(identifier:id,path:app,inventory:AppInspector.inventory(home:policy.home,selectedApplication:app)) else{throw SweepError.denied("损坏偏好恢复的应用归属不唯一")}
                    if !fixture{try ensureStopped(entry.original,applicationPath:app)}
                }
                if [ContainerDataRule.name,ApplicationScriptsRule.name,ApplicationGroupRule.name,ApplicationStorageRule.name].contains(entry.original.rule) || (entry.original.component != nil && entry.original.rule == SupportDomainRule.name) {try verifyApplicationDataRecoveryOwner(entry,manifest:manifest,objects:objects)}
                #if os(macOS)
                if entry.original.rule == DocumentVersionRule.name {
                    let last=index
                    guard entry.history != nil,try SafeFilesystem.presence(batch.path + "/" + manifest.backupsDirectory) else{throw SweepError.incomplete("历史副本未完成；原生历史保留，请核对后恢复")}
                    let backups=try batch.existingPrivateChild(manifest.backupsDirectory)
                    let saved=try DocumentHistoryTransaction.backup(entry,in:backups,home:policy.home)
                    entry.backupIdentity=saved.identity;entry.backupBytes=saved.bytes;entry.backupPending=false;entry.state = .restorePrepared
                    manifest.entries[index]=entry;try persist(manifest,in:batch)
                    let journalFD=batch.fd,journalPath=batch.path,journalIdentity=try batch.ownIdentity
                    let interruptedRestore = failurePoint == .afterReconstruction
                    try DocumentHistoryTransaction.restore(&entry,backups:backups,home:policy.home,isolation:self,afterNativeRestore:{if interruptedRestore{throw Interruption.injected}}){changed in
                        manifest.entries[last]=changed
                        let journal=try SafeDirectory.duplicating(journalFD,path:journalPath,expected:journalIdentity)
                        try persist(manifest,in:journal)
                    }
                    entry.state = .restored;entry.message="内容已添加为新的历史版本；当前文稿保留，恢复副本仍可查看"
                    manifest.entries[index]=entry;try persist(manifest,in:batch);continue
                }
                if entry.original.rule == PreferenceRecoveryRecord.rule {
                    try verifyPreferenceRecoveryOwner(entry,manifest:manifest,objects:objects)
                    let backupRoot=batch.path + "/" + manifest.backupsDirectory
                    let target=backupRoot + "/" + name
                    if entry.backupPending == true, try !SafeFilesystem.presence(target) {
                        guard entry.preference?.phase == .prepared, let identifier=entry.original.bundleIdentifier else { throw SweepError.denied("偏好备份缺失，不能推断服务状态") }
                        let current=try PreferenceDomainService.inspect(path:original,home:policy.home,identifier:identifier)
                        guard let originalIdentity=entry.original.identity,
                              current.inspection.snapshot.identity.sameObject(as:originalIdentity),
                              current.inspection.snapshot.ancestors == entry.originalAncestors,
                              current.inspection.digest == entry.preference?.originalRawDigest,
                              current.valuesDigest == entry.preference?.originalValuesDigest else { throw SweepError.stale("偏好备份未完成且原设置已改变") }
                        entry.backupDigest=nil;entry.backupIdentity=nil;entry.backupFormat=nil;entry.backupBytes=nil;entry.backupPending=false
                        entry.preference?.phase = .restored;entry.preference?.restoredIdentity=current.inspection.snapshot.identity
                        entry.state = .restored;entry.message="备份开始前中断，原设置未改动"
                        manifest.entries[index]=entry;try persist(manifest,in:batch);continue
                    }
                    let backups=try batch.existingPrivateChild(manifest.backupsDirectory)
                    let backup=try PreferenceTransaction.verifiedSnapshot(entry,in:backups,home:policy.home)
                    if entry.backupPending == true {
                        entry.backupIdentity=backup.identity;entry.backupBytes=backup.bytes;entry.backupPending=false
                        manifest.entries[index]=entry;try persist(manifest,in:batch)
                    }
                    let input=try PreferenceTransaction.recoveryInput(entry,in:backups,home:policy.home)
                    if !input.alreadyRestored {
                        entry.preference?.emptyIdentity=input.current.inspection.snapshot.identity
                        entry.preference?.phase = .restoring;entry.state = .restorePrepared
                        manifest.entries[index]=entry;try persist(manifest,in:batch)
                        if failurePoint == .preferenceBeforeRestore { throw Interruption.injected }
                        _ = try PreferenceDomainService.restore(original:input.original,expectedEmpty:input.current,backupPath:input.backupPath)
                        if failurePoint == .preferenceAfterRestore { throw Interruption.injected }
                    }
                    let final=try PreferenceDomainService.inspect(path:original,home:policy.home,identifier:input.original.identifier)
                    guard final.valuesDigest == input.original.valuesDigest else { throw SweepError.stale("偏好恢复后的原生值未确认") }
                    entry.preference?.restoredIdentity=final.inspection.snapshot.identity
                    entry.preference?.phase = .restored;entry.state = .restored;entry.message=nil
                    manifest.entries[index]=entry;try persist(manifest,in:batch);continue
                }
                #endif
                if entry.backupPending == true {
                    if try SafeFilesystem.presence(batch.path + "/" + manifest.backupsDirectory) {
                        let backups = try batch.existingPrivateChild(manifest.backupsDirectory)
                        let names = try FileManager.default.contentsOfDirectory(atPath: backups.path)
                        let known = Set(manifest.entries.filter { $0.backupDigest != nil }.map { $0.id.uuidString })
                        guard names.count <= 1000, Set(names).isSubset(of: known) else { throw SweepError.denied("备份写入中断，存在未登记的临时对象；保留并等待人工核对") }
                        if try SafeFilesystem.presence(backups.path + "/" + name) {
                            let verified = try IndependentBackup.verifiedSnapshot(entry, in: backups)
                            entry.backupIdentity = verified.identity
                            if CacheArchive.supports(entry.original.rule) { entry.backupBytes = verified.bytes }
                        } else { entry.backupDigest = nil; entry.backupIdentity = nil }
                    } else { entry.backupDigest = nil; entry.backupIdentity = nil }
                    if entry.backupDigest == nil { entry.backupFormat = nil; entry.backupBytes = nil; entry.reconstructedContents = nil }
                    entry.backupPending = false
                    manifest.entries[index] = entry
                    try persist(manifest, in: batch)
                }
                var stored = try? objects.identity(name)
                if stored == nil, entry.backupDigest != nil, try !SafeFilesystem.presence(original) {
                    manifest.entries[index].state = .restorePrepared
                    manifest.entries[index].reconstructionPending = true
                    try persist(manifest, in: batch)
                    let rebuilt = try IndependentBackup.materialize(entry, from: batch.existingPrivateChild(manifest.backupsDirectory), into: objects)
                    if failurePoint == .afterReconstruction { throw SweepError.filesystem("注入：重建重命名后目录同步失败") }
                    manifest.entries[index].isolatedIdentity = rebuilt.identity
                    if CacheArchive.supports(entry.original.rule) { manifest.entries[index].reconstructedContents = rebuilt.tree }
                    manifest.entries[index].reconstructionPending = false
                    try persist(manifest, in: batch)
                    entry = manifest.entries[index]; stored = rebuilt.identity
                }
                if let stored {
                    guard let identity = entry.original.identity else { throw SweepError.stale("恢复对象缺少原始身份") }
                    // A completed isolation has a post-rename identity, including ctime.
                    // Only an interrupted move lacks that record and must allow rename's ctime change.
                    var unchanged = entry.isolatedIdentity.map { stored == $0 } ?? stored.sameObject(as: identity)
                    if !unchanged, (entry.state == .restorePrepared || entry.reconstructionPending == true), entry.backupDigest != nil {
                        unchanged = try IndependentBackup.validatesReconstruction(SafeFilesystem.snapshot(objects.path + "/" + name, allowInternalHardLinks: CacheArchive.supports(entry.original.rule)), entry: entry, in: batch.existingPrivateChild(manifest.backupsDirectory))
                        if unchanged {
                            manifest.entries[index].isolatedIdentity = stored
                            if CacheArchive.supports(entry.original.rule) { manifest.entries[index].reconstructedContents = try SafeFilesystem.snapshot(objects.path + "/" + name, allowInternalHardLinks: CacheArchive.supports(entry.original.rule)).tree }
                            manifest.entries[index].reconstructionPending = false; try persist(manifest, in: batch)
                            entry = manifest.entries[index]
                        }
                    }
                    guard unchanged else { throw SweepError.stale("恢复对象身份或元数据已改变") }
                    let snapshot = try SafeFilesystem.snapshot(objects.path + "/" + name, allowInternalLinks: entry.original.category == .application || [ContainerDataRule.name,ApplicationScriptsRule.name,ApplicationGroupRule.name,DownloadCacheRule.builderName,AIStorageRule.name].contains(entry.original.rule), purpose: entry.original.category == .application ? .application : ([DeviceBackupRule.name,ContainerDataRule.name,ApplicationScriptsRule.name,ApplicationGroupRule.name,TrashEntryRule.name,MailDownloadRule.name,AIStorageRule.name].contains(entry.original.rule) ? .managedData : .ordinary), allowInternalHardLinks: CacheArchive.supports(entry.original.rule), allowApplicationHardLinks: entry.original.category == .application)
                    if entry.original.rule == ContainerDataRule.name,let id=entry.original.bundleIdentifier{try ContainerDataRule.verifyContents(snapshot,home:policy.home,identifier:id)}
                    if entry.reconstructedContents != nil {
                        guard try IndependentBackup.validatesReconstruction(snapshot, entry: entry, in: batch.existingPrivateChild(manifest.backupsDirectory)) else { throw SweepError.stale("重建字节与已登记独立归档不一致") }
                    }
                    guard try entry.matchesRestorationContents(snapshot) else { throw SweepError.stale("恢复对象内容已改变") }
                    if AdditionalCleanupRule.names.contains(entry.original.rule) { try AdditionalCleanupRule.verifyContents(snapshot, original: entry.original, home: policy.home) }
                    if entry.original.rule == DeviceBackupRule.name { try DeviceBackupRule.verifyTree(snapshot) }
                    if entry.original.rule == DeletedUserArchiveRule.name,let scope=policy.systemScope{try DeletedUserArchiveRule.verify(entry.original.path,scope:scope,storedPath:snapshot.path)}
                    if !fixture && entry.original.category == .application {
                        guard let identifier = entry.original.bundleIdentifier else { throw SweepError.denied("恢复应用标识未确认") }
                        if entry.original.rule == SelectedApplicationRule.name {
                            try SelectedApplicationRule.verifyStored(path: snapshot.path, identifier: identifier)
                        } else if [ChosenApplicationRule.name, ChosenApplicationRule.largeName].contains(entry.original.rule) {
                            try ChosenApplicationRule.verifyStored(path: snapshot.path, identifier: identifier)
                        } else if !AppInspector.signatureMatches(path: snapshot.path, identifier: identifier) { throw SweepError.denied("恢复应用签名未确认") }
                    }
                    if !fixture { try BusyInspector.ensureUnused(snapshot,allowReadOnlyLocalization:permitsLocalizedResourceReaders) }
                    let url = URL(fileURLWithPath: original)
                    guard let ancestors = entry.originalAncestors,
                          try SafeFilesystem.ancestors(of: url.deletingLastPathComponent().path) == ancestors else { throw SweepError.stale("恢复目标祖先已改变，或旧记录缺少目录身份；仅供预览") }
                    let parent = try SafeDirectory(path: url.deletingLastPathComponent().path)
                    if (try? parent.identity(url.lastPathComponent)) != nil { throw SweepError.denied("原路径已存在，不覆盖；请先手动处理冲突") }
                    if AdditionalCleanupRule.names.contains(entry.original.rule) { try AdditionalCleanupRule.verifyRestoreDestination(entry.original, home: policy.home) }
                    if entry.original.rule == AIDiagnosticRule.name { try AIDiagnosticRule.verifyRestoreDestination(path:entry.original.path,home:policy.home) }
                    if !fixture { try ensureStopped(entry.original, applicationPath: entry.original.category == .application ? original : nil, metadataPath: snapshot.path) }
                    manifest.entries[index].state = .restorePrepared
                    try persist(manifest, in: batch)
                    if entry.original.rule == GodotCacheRule.name {
                        guard let app=entry.original.applicationPath,let proof=godotProofs[app] else { throw SweepError.denied("Godot 缓存恢复归属未确认") }
                        try GodotCacheRule.verify(proof,home:policy.home)
                    }
                    #if os(macOS)
                    if needsApplicationTransfer(entry.original,sourcePath:snapshot.path,restoring:true) {
                        try await ApplicationTransferClient.restore(batchID:manifest.id,itemID:entry.id)
                        let restored=try SafeFilesystem.snapshot(original,allowInternalLinks:true,purpose:.application,allowApplicationHardLinks:true)
                        guard try !SafeFilesystem.presence(snapshot.path),restored.identity.sameObject(as:snapshot.identity),try entry.matchesRestorationContents(restored) else { throw SweepError.stale("管理员恢复后的应用身份未确认") }
                    } else { try SafeFilesystem.move(snapshot, into: parent, name: url.lastPathComponent, targetAncestors: ancestors) }
                    #else
                    try SafeFilesystem.move(snapshot, into: parent, name: url.lastPathComponent, targetAncestors: ancestors)
                    #endif
                } else {
                    // Interrupted before isolation, or after restoration: only exact original identity can resolve it.
                    let current = try SafeFilesystem.snapshot(original, allowInternalLinks: entry.original.category == .application || [ContainerDataRule.name,ApplicationScriptsRule.name,ApplicationGroupRule.name,DownloadCacheRule.builderName,AIStorageRule.name].contains(entry.original.rule), purpose: entry.original.category == .application ? .application : ([DeviceBackupRule.name,ContainerDataRule.name,ApplicationScriptsRule.name,ApplicationGroupRule.name,TrashEntryRule.name,MailDownloadRule.name,AIStorageRule.name].contains(entry.original.rule) ? .managedData : .ordinary), allowInternalHardLinks: CacheArchive.supports(entry.original.rule), allowApplicationHardLinks: entry.original.category == .application)
                    guard let expected = entry.isolatedIdentity ?? entry.original.identity, current.identity.sameObject(as: expected), try entry.matchesRestorationContents(current) else {
                        if entry.backupDigest != nil { throw SweepError.denied("原路径已存在，不覆盖；独立备份仍保留") }
                        throw SweepError.stale("两端身份未确认，需要人工处理")
                    }
                }
                if [StaleUserAgentRule.name,ApplicationAgentRule.name].contains(entry.original.rule) {
                    guard let agent=entry.userAgent else{throw SweepError.denied("缺少原后台项注册记录")}
                    manifest.entries[index].userAgent?.phase = .restoring;try persist(manifest,in:batch)
                    let declaration=try applicationAgentDeclaration(entry.original)
                    try StaleUserAgentRule.restore(declaration,wasRegistered:agent.wasRegistered)
                    if failurePoint == .agentAfterRestore{throw Interruption.injected}
                    manifest.entries[index].userAgent?.phase = .restored
                }
                manifest.entries[index].state = .restored
                manifest.entries[index].message = entry.original.rule == "cfpreferences-exact-domain-v1" ? "旧记录仅恢复偏好文件；macOS 偏好服务状态未验证" : nil
                manifest.entries[index].reconstructionPending = false
                try persist(manifest, in: batch)
            } catch Interruption.injected { throw Interruption.injected }
            catch {
                conflict = true; manifest.entries[index].state = .conflict; manifest.entries[index].message = error.localizedDescription
                manifest.status = .needsAttention; try persist(manifest, in: batch)
                break // A failure stops this batch, including recovery.
            }
        }
        if !conflict,let scope=policy.systemScope{
            for index in manifest.entries.indices where manifest.entries[index].systemHelper != nil && manifest.entries[index].systemHelper?.phase != .restored{
                do{
                    let item=manifest.entries[index].original,wasRegistered=manifest.entries[index].systemHelper!.wasRegistered
                    manifest.entries[index].systemHelper?.phase = .restoring;try persist(manifest,in:batch)
                    try InstalledSystemHelperRule.restoreRegistration(item,wasRegistered:wasRegistered,scope:scope)
                    if failurePoint == .agentAfterRestore{throw Interruption.injected}
                    manifest.entries[index].systemHelper?.phase = .restored;try persist(manifest,in:batch)
                }catch Interruption.injected{throw Interruption.injected}
                catch{conflict=true;manifest.entries[index].state = .conflict;manifest.entries[index].message=error.localizedDescription;break}
            }
        }
        manifest.status = conflict ? .needsAttention : (manifest.entries.contains { $0.state == .purged } ? .partiallyRestored : (rollback ? .rolledBack : .restored))
        try persist(manifest, in: batch); return manifest
    }
    private func applicationAgentDeclaration(_ item:Candidate,storedPath:String?=nil)throws->StaleUserAgentRule.Declaration {
        if item.rule == StaleUserAgentRule.name{return try StaleUserAgentRule.inspect(item.path,home:policy.home,storedPath:storedPath)}
        guard item.rule == ApplicationAgentRule.name,let app=item.applicationPath,let identifier=item.bundleIdentifier else{throw SweepError.denied("应用后台组件缺少精确主体")}
        return try ApplicationAgentRule.inspect(item.path,home:policy.home,application:app,identifier:identifier,storedPath:storedPath)
    }
    private func needsApplicationTransfer(_ item:Candidate,sourcePath:String?=nil,restoring:Bool=false) -> Bool {
        #if os(macOS)
        !fixture && policy.systemScope == nil && ApplicationTransferClient.required(for:item,sourcePath:sourcePath,restoring:restoring)
        #else
        false
        #endif
    }
    private func verifyApplicationAgentPurgeOwner(_ entry:RecoveryEntry,manifest:RecoveryManifest,objects:SafeDirectory)throws {
        guard let original=entry.original.applicationPath,let identifier=entry.original.bundleIdentifier,
              let agent=entry.userAgent,agent.phase == .unregistered,
              let body=manifest.entries.first(where:{$0.original.category == .application && $0.original.path == original && $0.original.bundleIdentifier == identifier}),
              body.state == .moved,let expected=body.isolatedIdentity,
              body.original.identity == agent.applicationIdentity,
              try !SafeFilesystem.presence(original) else{throw SweepError.denied("后台项清空缺少同批隔离主体或出现新的应用安装，保留")}
        let path=objects.path+"/"+body.id.uuidString,current=try SafeFilesystem.snapshot(path,allowInternalLinks:true,purpose:.application,allowApplicationHardLinks:true)
        guard current.identity == expected,try body.matchesContents(current),
              try ApplicationAgentRule.codeHash(application:path,identifier:identifier) == agent.applicationCodeHash else{throw SweepError.stale("后台项清空的隔离主体或签名已改变")}
        let inventory=try AppInspector.inventory(home:policy.home,ownershipIdentifier:identifier)
        guard !inventory.contains(where:{$0.bundleIdentifier.isEmpty || $0.bundleIdentifier.lowercased() == identifier.lowercased()}) else{throw SweepError.denied("后台项原应用之外出现相同标识或未确认安装，保留")}
        if !fixture{try ensureStopped(entry.original,applicationPath:original,metadataPath:objects.path+"/"+entry.id.uuidString,purging:true)}
    }
    private func verifyApplicationDataRecoveryOwner(_ entry:RecoveryEntry,manifest:RecoveryManifest,objects:SafeDirectory) throws {
        guard let identifier=entry.original.ownerIdentifier,let originalPath=entry.original.applicationPath,
              let body=manifest.entries.first(where:{$0.original.category == .application && $0.original.path == originalPath && $0.original.bundleIdentifier == identifier}) else{throw SweepError.denied("容器恢复缺少同批应用主体")}
        let saved=objects.path + "/" + body.id.uuidString,stored=try SafeFilesystem.presence(saved),path=stored ? saved : originalPath
        let current=try SafeFilesystem.snapshot(path,allowInternalLinks:true,purpose:.application,allowApplicationHardLinks:true)
        guard let expected=stored ? (body.isolatedIdentity ?? body.original.identity) : body.original.identity,
              current.identity.sameObject(as:expected),try body.matchesRestorationContents(current) else{throw SweepError.stale("容器恢复的原应用主体已改变")}
        guard AppInspector.signatureMatches(path:path,identifier:identifier) else{throw SweepError.stale("应用资料恢复的原代码签名标识已改变")}
        if let component=entry.original.component,let childID=entry.original.bundleIdentifier {
            _=try ApplicationComponentRule.verifyOwner(component,application:originalPath,identifier:childID,home:policy.home,signaturePath:stored ? path : nil)
        }
        if entry.original.rule == ContainerDataRule.name{try ContainerDataRule.verifySandbox(path:path,identifier:identifier)}
        let inventory=try AppInspector.inventory(home:policy.home,selectedApplication:stored ? nil : originalPath,ownershipIdentifier:identifier)
        if stored {
            try AppInspector.verifyIsolatedDataOwner(original:originalPath,stored:path,identifier:identifier,home:policy.home)
        }else{
            guard AppInspector.uniqueOwner(identifier:identifier,path:originalPath,inventory:inventory) else{throw SweepError.denied("容器恢复归属不唯一")}
            _=try AppInspector.verifiedDataOwner(path:originalPath,identifier:identifier,home:policy.home)
        }
        if entry.original.rule == ApplicationGroupRule.name {
            let group=URL(fileURLWithPath:entry.original.path).lastPathComponent
            let creators=try ApplicationGroupRule.membership(group:group,signaturePath:path,originalApplicationPath:originalPath,identifier:identifier,inventory:inventory)
            let savedData=objects.path + "/" + entry.id.uuidString,dataPath=try SafeFilesystem.presence(savedData) ? savedData : entry.original.path
            try ApplicationGroupRule.verifyContents(SafeFilesystem.snapshot(dataPath,allowInternalLinks:true,purpose:.managedData),home:policy.home,group:group,creators:creators)
        }
        if !fixture{try ensureStopped(body.original,applicationPath:path,metadataPath:path);try ensureStopped(entry.original,applicationPath:path)}
    }
    #if os(macOS)
    private func verifyPreferenceRecoveryOwner(_ entry: RecoveryEntry, manifest: RecoveryManifest, objects: SafeDirectory) throws {
        guard let identifier=entry.original.ownerIdentifier,
              let body=manifest.entries.first(where:{ $0.original.category == .application && $0.original.path == entry.original.applicationPath && $0.original.bundleIdentifier == identifier }) else { throw SweepError.denied("偏好恢复缺少同批应用主体") }
        let storedPath=objects.path + "/" + body.id.uuidString
        let stored=try SafeFilesystem.presence(storedPath)
        let path=stored ? storedPath : body.original.path
        let current=try SafeFilesystem.snapshot(path,allowInternalLinks:true,purpose:.application,allowApplicationHardLinks:true)
        guard let expected=stored ? (body.isolatedIdentity ?? body.original.identity) : body.original.identity,
              current.identity.sameObject(as:expected), try body.matchesRestorationContents(current),
              AppInspector.signatureMatches(path:path,identifier:identifier) else { throw SweepError.stale("偏好恢复的原应用主体或签名已改变") }
        try verifyOwner(entry.original,isolatedApplication:stored ? path : nil)
        if !fixture {
            try ensureStopped(body.original,applicationPath:path,metadataPath:path)
            try ensureStopped(entry.original,applicationPath:path)
        }
    }
    #endif
    private func ensureStopped(_ item: Candidate, applicationPath: String?, metadataPath: String? = nil,purging:Bool=false) throws {
        if let scope = policy.systemScope {
            try scope.verify()
            if item.rule == InstalledSystemHelperRule.name{
                let privatePurge=purging && metadataPath.map{SafetyPolicy.contains(vaultPath,$0)} == true
                try InstalledSystemHelperRule.ensureStopped(item,scope:scope,requireApplication:!privatePurge);return
            }
            if item.rule == DeletedUserArchiveRule.name {
                try DeletedUserArchiveRule.ensureInactive(item.path,scope:scope)
                if let metadataPath,SafetyPolicy.contains(vaultPath,metadataPath){try DeletedUserArchiveRule.ensureUnmounted(metadataPath);return}
                if try SafeFilesystem.presence(item.path){try DeletedUserArchiveRule.ensureUnmounted(item.path)}
                return
            }
            guard let identifier = item.bundleIdentifier else { throw SweepError.denied("系统运行状态未确认") }
            try ActivityInspector.ensureSystemServicesStopped(identifiers:[identifier],applicationPath:item.applicationPath)
            try ActivityInspector.ensureStopped(bundleID:identifier,applicationPath:applicationPath ?? item.applicationPath,userID:scope.requesterUID)
            return
        }
        if [StaleUserAgentRule.name,ApplicationAgentRule.name].contains(item.rule) {
            if purging,item.rule == ApplicationAgentRule.name,let stored=metadataPath,SafetyPolicy.contains(vaultPath,stored),let app=item.applicationPath,let identifier=item.bundleIdentifier {
                let declaration=try StaleUserAgentRule.inspect(item.path,home:policy.home,storedPath:stored,installedApplication:app)
                guard try !StaleUserAgentRule.registered(declaration) else{throw SweepError.denied("隔离的后台项出现新注册，保留")}
                try ActivityInspector.ensureStopped(bundleID:identifier,applicationPath:app,additionalIdentifiers:[declaration.label],userHome:policy.home)
                return
            }
            let path=(try SafeFilesystem.presence(item.path)) ? item.path : metadataPath
            guard let path else{throw SweepError.denied("后台项声明缺失，活动未确认")}
            let declaration=try applicationAgentDeclaration(item,storedPath:path);_=try StaleUserAgentRule.registered(declaration);return
        }
        if item.rule == DocumentVersionRule.name {
            if let metadataPath,SafetyPolicy.contains(vaultPath,metadataPath){return}
            try BusyInspector.ensureUnused(SafeFilesystem.snapshot(item.path));return
        }
        if AdditionalCleanupRule.names.contains(item.rule) { try AdditionalCleanupRule.ensureStopped(item, home: policy.home); return }
        if item.rule == AIDiagnosticRule.name { try AIDiagnosticRule.ensureStopped(path:item.path,home:policy.home); return }
        if item.rule == DeviceBackupRule.name { try ActivityInspector.ensureDeviceBackupsStopped(); return }
        if item.rule == XcodeArchiveRule.name {try XcodeArchiveRule.ensureStopped();return}
        if item.rule == SimulatorCacheRule.name {try SimulatorCacheRule.ensureStopped(item,home:policy.home);return}
        if item.rule == XcodeDeviceSupportRule.name {try XcodeDeviceSupportRule.ensureStopped();return}
        if item.rule == GodotCacheRule.name {
            guard let app=item.applicationPath else { throw SweepError.denied("Godot 缓存使用者未确认") }
            try GodotCacheRule.ensureStopped(application:app); return
        }
        if item.rule == UserCacheNamespaceRule.name {
            guard let root=UserCacheNamespaceRule.namespace(path:item.path,home:policy.home) else { throw SweepError.denied("通用缓存活动范围未确认") }
            try ActivityInspector.ensureUnattributedCacheStopped(namespace:root)
            return
        }
        if ToolCacheRule.rules.contains(item.rule) {
            guard let location=ToolCacheRule.location(item.path,home:policy.home) else{throw SweepError.denied("工具缓存活动范围未确认")}
            try ToolCacheRule.ensureStopped(location.producer,home:policy.home);return
        }
        if [ContainerDataRule.name,ApplicationScriptsRule.name,ApplicationGroupRule.name].contains(item.rule) {
            guard let id=item.bundleIdentifier else{throw SweepError.denied("容器活动归属未确认")}
            let path=applicationPath ?? item.applicationPath
            try ActivityInspector.ensureSystemServicesStopped(identifiers:[id],applicationPath:path)
            try ActivityInspector.ensureStopped(bundleID:id,applicationPath:path,additionalIdentifiers:[id + "."])
            return
        }
        if ApplicationCacheRule.rules.contains(item.rule) {
            guard let identifier=item.bundleIdentifier,let app=item.applicationPath else { throw SweepError.denied("应用缓存的活动归属未确认") }
            try ActivityInspector.ensureSystemServicesStopped(identifiers:[identifier],applicationPath:app)
            try ActivityInspector.ensureStopped(bundleID:identifier,applicationPath:app,additionalIdentifiers:[identifier + "."])
            return
        }
        if item.category == .development { try ActivityInspector.ensureBuildToolsStopped() }
        var relatedIdentifiers: [String] = item.component.map{[$0.ownerIdentifier]} ?? []
        if [DarwinCacheRule.name, WebKitCacheRule.name, WebKitTemporaryRule.name].contains(item.rule) {
            guard let id=item.bundleIdentifier,let scope = item.rule == WebKitTemporaryRule.name ? policy.darwinTemporaryScope : policy.darwinScope else{throw SweepError.denied("Darwin 活动范围未确认")}
            try scope.verify();relatedIdentifiers.append(id + ".")
            if [WebKitCacheRule.name, WebKitTemporaryRule.name].contains(item.rule) { relatedIdentifiers += WebKitCacheRule.namespaces(identifier: id) }
            try ActivityInspector.ensureSystemServicesStopped(identifiers:[id],applicationPath:applicationPath)
        }
        if [ChosenApplicationRule.name, ChosenApplicationRule.largeName, SelectedApplicationRule.name].contains(item.rule) {
            guard let identifier = item.bundleIdentifier else { throw SweepError.denied("系统后台依赖未确认") }
            let labels = try ChosenApplicationRule.dependencyLabels(path: metadataPath ?? applicationPath ?? item.path)
            relatedIdentifiers = labels
            try ActivityInspector.ensureSystemServicesStopped(identifiers: [identifier] + labels, applicationPath: applicationPath)
        }
        if item.rule == FirefoxRule.name || item.rule == FirefoxFormatRule.name { try ActivityInspector.ensureStopped(bundleID: "org.mozilla.", applicationPath: applicationPath) }
        try ActivityInspector.ensureStopped(bundleID: item.bundleIdentifier, applicationPath: applicationPath, additionalIdentifiers: relatedIdentifiers,userHome:policy.ruleIsValidated(ApplicationAgentRule.name) ? policy.home : nil)
    }
    private func verifyCacheGroups(_ plan: CleanupPlan, removed: Set<UUID>, signaturePaths: [String:String] = [:], profileSources: [String:String] = [:], godotProofs: [String:GodotCacheRule.OwnerProof] = [:]) throws {
        let groups = Dictionary(grouping: plan.items.filter { CacheArchive.supports($0.rule) }) { $0.selectionGroupID ?? $0.id.uuidString }
        // Fresh for this verification boundary only. Moving a member starts a
        // new boundary; never reuse namespace evidence across mutations.
        var godotMembers: [String:[String:Set<String>]] = [:]
        for items in groups.values {
            try Task.checkCancellation()
            guard let first = items.first else { throw SweepError.denied("关联缓存域未确认") }
            let expected = Set(items.filter { !removed.contains($0.id) }.map(\.path))
            let actual: Set<String>
            if first.rule == GodotCacheRule.name {
                guard let app=first.applicationPath,profileSources[app] == nil else { throw SweepError.denied("Godot 缓存组归属未确认") }
                if let isolated=signaturePaths[app],godotProofs[app]?.snapshot.path != isolated { throw SweepError.denied("Godot 缓存组与同批隔离主体不一致") }
                if godotMembers[app] == nil {
                    if let proof=godotProofs[app] { try GodotCacheRule.verify(proof,home:policy.home) }
                    else { try GodotCacheRule.verifyOwner(application:app,home:policy.home) }
                    _=try GodotCacheRule.verifyNamespace(home:policy.home)
                    let members=try CacheDomainRule.members(root:policy.home + "/Library/Caches/Godot")
                    godotMembers[app]=Dictionary(grouping:members) { GodotCacheRule.thumbnailKey($0) ?? $0 }.mapValues { Set($0) }
                }
                guard GodotCacheRule.matches(first.path,home:policy.home) else { throw SweepError.denied("Godot 缓存路径未确认") }
                actual=godotMembers[app]?[GodotCacheRule.thumbnailKey(first.path) ?? first.path] ?? []
            } else {
                actual=try cacheMembers(first,signaturePath:first.applicationPath.flatMap { signaturePaths[$0] },profileSource:first.applicationPath.flatMap { profileSources[$0] })
            }
            guard actual == expected else { throw SweepError.stale("缓存域成员已改变，停止处理并保留新增文件；请重新扫描") }
        }
    }
    private func preflightCacheRecovery(_ manifest: RecoveryManifest, objects: SafeDirectory) throws -> [String:GodotCacheRule.OwnerProof] {
        let profileSources = try ChromiumProfileRule.recoverySources(manifest,objects:objects,home:policy.home)
        let cacheEntries = manifest.entries.filter { CacheArchive.supports($0.original.rule) }
        guard cacheEntries.contains(where: { $0.state != .restored && $0.state != .purged }) else { return [:] }
        // Older development batches have no group header. Their recorded entries
        // remain recoverable, but no unrecorded neighbour can be assumed original.
        let members = try manifest.cacheSelection ?? cacheEntries.map { CacheRecoveryMember(original: $0.original, fingerprint: try TreeFingerprint.capture($0.contents)) }
        let entries = Dictionary(uniqueKeysWithValues: cacheEntries.map { ($0.id, $0) })
        let groups = Dictionary(grouping: members) { $0.original.selectionGroupID ?? $0.original.id.uuidString }
        var godotProofs: [String:GodotCacheRule.OwnerProof] = [:]
        for group in groups.values {
            guard group.contains(where: { member in entries[member.original.id].map { $0.state != .restored && $0.state != .purged } ?? false }) else { continue }
            guard let first = group.first?.original else { throw SweepError.denied("缓存恢复组标识未确认") }
            var existing = Set<String>()
            for member in group {
                try Task.checkCancellation()
                let item = member.original
                let present = try SafeFilesystem.presence(item.path)
                if let entry = entries[item.id] {
                    let stored = try SafeFilesystem.presence(objects.path + "/" + entry.id.uuidString)
                    if present {
                        guard entry.state != .purged, !stored else { throw SweepError.denied("应用已生成新的关联缓存，整组保留且不覆盖") }
                        let current = try SafeFilesystem.snapshot(item.path, allowInternalHardLinks: true)
                        let expected = entry.isolatedIdentity ?? item.identity
                        let same = expected.map { entry.isolatedIdentity != nil || entry.state == .restorePrepared || entry.state == .restored ? current.identity.sameObject(as: $0) : current.identity == $0 } ?? false
                        guard same, try entry.matchesContents(current) else { throw SweepError.stale("已恢复或尚未移动的缓存成员已改变") }
                        existing.insert(item.path)
                    } else if entry.state == .restored { throw SweepError.stale("先前已恢复的缓存成员已改变，不能混合恢复") }
                } else {
                    guard present else { throw SweepError.stale("尚未处理的原缓存成员已消失") }
                    let current = try SafeFilesystem.snapshot(item.path, allowInternalHardLinks: true)
                    guard current.identity == item.identity, try member.fingerprint.matches(current.tree) else { throw SweepError.stale("尚未处理的原缓存成员已改变") }
                    existing.insert(item.path)
                }
            }
            let isolated = manifest.entries.first { entry in
                entry.original.category == .application && entry.original.path == first.applicationPath &&
                    entry.state != .restored && entry.state != .purged &&
                    ((try? SafeFilesystem.presence(objects.path + "/" + entry.id.uuidString)) == true)
            }.map { objects.path + "/" + $0.id.uuidString }
            if first.rule == GodotCacheRule.name,let app=first.applicationPath,godotProofs[app] == nil {
                godotProofs[app]=try GodotCacheRule.ownerProof(application:app,home:policy.home,signaturePath:isolated)
            }
            guard try cacheMembers(first,signaturePath:isolated,profileSource:first.applicationPath.flatMap { profileSources[$0] },godotProof:first.applicationPath.flatMap { godotProofs[$0] }) == existing else { throw SweepError.denied("缓存域出现未确认的新成员，整组保留且不覆盖") }
        }
        return godotProofs
    }
    private func cacheMembers(_ item: Candidate, signaturePath: String? = nil, profileSource: String? = nil, godotProof:GodotCacheRule.OwnerProof? = nil) throws -> Set<String> {
        if ApplicationCacheRule.rules.contains(item.rule) {
            guard signaturePath == nil,profileSource == nil,let id=item.bundleIdentifier,let app=item.applicationPath,
                  ApplicationCacheRule.identifier(path:item.path,home:policy.home,rule:item.rule) == id else { throw SweepError.denied("应用缓存组归属未确认") }
            _=try ApplicationCacheRule.verifyRoot(home:policy.home,identifier:id,applicationPath:app,rule:item.rule)
            return try CacheDomainRule.members(root:ApplicationCacheRule.root(home:policy.home,identifier:id,rule:item.rule))
        }
        if item.rule == GodotCacheRule.name {
            guard profileSource == nil,let app=item.applicationPath else { throw SweepError.denied("Godot 缓存恢复归属未确认") }
            if let godotProof {
                guard godotProof.application == app,godotProof.snapshot.path == (signaturePath ?? app) else { throw SweepError.denied("Godot 恢复主体凭据不匹配") }
                try GodotCacheRule.verify(godotProof,home:policy.home)
            } else { try GodotCacheRule.verifyOwner(application:app,home:policy.home) }
            _=try GodotCacheRule.verifyNamespace(home:policy.home)
            return try GodotCacheRule.members(item.path,home:policy.home)
        }
        if item.rule == UserCacheNamespaceRule.name {
            guard item.bundleIdentifier == nil, item.applicationPath == nil, signaturePath == nil, profileSource == nil,
                  let root=UserCacheNamespaceRule.namespace(path:item.path,home:policy.home) else { throw SweepError.denied("通用缓存组不能携带应用归属") }
            _ = try UserCacheNamespaceRule.verifyNamespace(root,home:policy.home)
            return try CacheDomainRule.members(root:root)
        }
        guard let identifier = item.bundleIdentifier else { throw SweepError.denied("缓存域应用标识未确认") }
        if let scope = policy.systemScope { return try SystemDomainRule.members(scope,identifier:identifier) }
        if let component=item.component {
            guard let app=item.applicationPath,ApplicationComponentRule.supportedRules.contains(item.rule) else{throw SweepError.denied("组件缓存恢复关系未确认")}
            _=try ApplicationComponentRule.verifyOwner(component,application:app,identifier:identifier,home:policy.home,signaturePath:signaturePath)
        }
        if [DarwinCacheRule.name, WebKitCacheRule.name, WebKitTemporaryRule.name].contains(item.rule) {
            guard let scope = item.rule == WebKitTemporaryRule.name ? policy.darwinTemporaryScope : policy.darwinScope,scope.home == policy.home,let app=item.applicationPath,profileSource == nil else{throw SweepError.denied("Darwin 缓存恢复范围未确认")}
            try scope.verify()
            if let component=item.component {
                _=try ApplicationComponentRule.verifyOwner(component,application:app,identifier:identifier,home:scope.home,signaturePath:signaturePath)
            } else if let signaturePath {
                try AppInspector.verifyIsolatedDataOwner(original:app,stored:signaturePath,identifier:identifier,home:scope.home)
            } else {
                _=try AppInspector.verifiedDataOwner(path:app,identifier:identifier,home:scope.home)
                let inventory=try AppInspector.inventory(home:scope.home,selectedApplication:app,ownershipIdentifier:identifier)
                guard AppInspector.uniqueOwner(identifier:identifier,path:app,inventory:inventory) else{throw SweepError.denied("Darwin 缓存当前应用归属不唯一，保留隔离对象")}
            }
            if item.rule == WebKitCacheRule.name {
                guard item.component == nil, let root = WebKitCacheRule.root(path: item.path, identifier: identifier, scope: scope) else { throw SweepError.denied("WebKit 恢复缓存域未确认") }
                _ = try WebKitCacheRule.verifyRoot(root, identifier: identifier, scope: scope)
                return try CacheDomainRule.members(root: root)
            }
            if item.rule == WebKitTemporaryRule.name {
                guard item.component == nil, let root = WebKitTemporaryRule.root(path: item.path, identifier: identifier, scope: scope) else { throw SweepError.denied("WebKit 临时恢复范围未确认") }
                _ = try WebKitTemporaryRule.verifyNamespace(identifier: identifier, scope: scope)
                return try CacheDomainRule.members(root: root).filter { WebKitTemporaryRule.root(path: $0, identifier: identifier, scope: scope) != nil }
            }
            _=try DarwinCacheRule.verifyRoot(identifier:identifier,scope:scope)
            return try CacheDomainRule.members(root:scope.root + "/" + identifier)
        }
        if item.rule == ChromiumCacheRule.name {
            guard let app = item.applicationPath else { throw SweepError.denied("浏览器缓存缺少应用主体证据") }
            let root = try ChromiumCacheRule.verifiedRoot(path:item.path,home:policy.home,identifier:identifier,applicationPath:app,signaturePath:signaturePath,profileSource:profileSource)
            return try CacheDomainRule.members(root:root)
        }
        if item.rule == NamedApplicationRule.cacheName {
            guard let app=item.applicationPath,profileSource == nil,
                  let root=NamedApplicationRule.root(home:policy.home,identifier:identifier,cache:true),NamedApplicationRule.matches(item.path,home:policy.home,identifier:identifier,cache:true) else{throw SweepError.denied("名称缓存范围未确认")}
            try NamedApplicationRule.verifyOwner(application:app,identifier:identifier,home:policy.home,signaturePath:signaturePath)
            _=try CacheDomainRule.verifyPrivateDomain(root:root)
            return try CacheDomainRule.members(root:root)
        }
        guard item.rule == CacheDomainRule.name else { throw SweepError.denied("缓存域规则未确认") }
        try ChromiumCacheRule.verifyNoRuntimeOverlap(identifier:identifier,inventory:AppInspector.inventory(home:policy.home))
        return try CacheDomainRule.members(home:policy.home,identifier:identifier)
    }
}


extension SweepEngine {
    private func finishScan(_ output: ScanOutput, ignores: CleanupIgnoreList) throws -> ScanReport {
        try Task.checkCancellation(); try ignoreStore.verify(ignores)
        let report = ignores.applying(to:output.report)
        register(report,snapshots:output.snapshots,ignores:ignores)
        return report
    }
    func makeSystemPlan(reportID:UUID,selected:Set<UUID>)throws->CleanupPlan{
        guard policy.systemScope != nil,let report=reports[reportID] else{throw SweepError.denied("系统扫描已过期")}
        let personal=report.candidates.contains{selected.contains($0.id) && $0.rule == DeletedUserArchiveRule.name && $0.userData}
        return try makePlan(reportID:reportID,selected:selected,includeUserData:personal)
    }
    func scanSystem(_ category: SystemCleanupCategory) throws -> ScanReport {
        guard let scope = policy.systemScope else { throw SweepError.denied("普通清理入口不能扫描系统事务") }
        let ignores = try ignoreStore.read()
        let policy=policy
        var builder=Scanner.Builder(policy:policy)
        let duration=SystemCleanupEngine.maximumDiscoveryDuration
        try Scanner(policy:policy).boundedStage("系统范围只读扫描",builder:&builder,progress:nil,timeout:duration,maximumDuration:duration) { part,_ in
            try SystemScanner(scope:scope,policy:policy).scan(category,into:&part)
        }
        return try finishScan(builder.finish(applicationPath:nil),ignores:ignores)
    }
    public func applicationCatalog() throws -> ApplicationCatalog {
        try applicationCatalog(indexLookup: ApplicationIndex.systemPaths)
    }
    func applicationCatalog(indexLookup: @escaping ApplicationIndex.Lookup) throws -> ApplicationCatalog {
        let home = policy.home
        let inventory = try ReadOnlyScanPool.shared.run(stage:"应用列表") { _ in
            try AppInspector.inventorySnapshot(home:home,indexLookup:indexLookup)
        }
        return ApplicationCatalog(applications: inventory.applications.filter { !$0.path.isEmpty }, unconfirmedIssues: inventory.issues)
    }
    public func applications() throws -> [ApplicationIdentity] { try applicationCatalog().applications }
    public func scanApplication(_ path: String) throws -> ScanReport {
        guard policy.systemScope == nil else { throw SweepError.denied("系统执行者不接受应用路径参数") }
        let ignores = try ignoreStore.read()
        let scanner = Scanner(policy:policy)
        let output = try ReadOnlyScanPool.shared.run(stage:"应用卸载明细") { _ in try scanner.application(path) }
        return try finishScan(output,ignores:ignores)
    }
    public func scanKnown(bundleIdentifier: String, displayName: String) throws -> ScanReport {
        guard policy.systemScope == nil else { throw SweepError.denied("系统执行者不接受外部应用归属声明") }
        let ignores = try ignoreStore.read()
        let scanner = Scanner(policy:policy)
        let output = try ReadOnlyScanPool.shared.run(stage:"应用残留明细") { _ in try scanner.known(identifier:bundleIdentifier,name:displayName) }
        return try finishScan(output,ignores:ignores)
    }
    public func scanJunk(maximumDuration:TimeInterval=120,progress: (@Sendable (ScanProgress) -> Void)? = nil) throws -> ScanReport {
        guard policy.systemScope == nil else { throw SweepError.denied("系统执行者必须指定已登记类别") }
        let ignores = try ignoreStore.read()
        let output = try Scanner(policy: policy).junk(maximumDuration:maximumDuration,progress:progress)
        return try finishScan(output,ignores:ignores)
    }
    #if DEBUG
    func scanLegacyManagementFixture() throws -> ScanReport {
        guard policy.systemScope == nil else { throw SweepError.denied("旧记录夹具不接受系统范围") }
        let ignores = try ignoreStore.read()
        return try finishScan(Scanner(policy: policy).legacyManagementFixture(), ignores: ignores)
    }
    #endif
}
