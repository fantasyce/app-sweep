import SwiftUI
import AppKit
import AppSweepCore
import UniformTypeIdentifiers

@MainActor
final class SweepStore: ObservableObject {
    enum Workspace: String, CaseIterable { case junk = "系统清理", uninstall = "应用卸载", recovery = "恢复区" }
    struct OptimizationSelection: Identifiable {
        let id = UUID()
        let applicationPath: String
    }
    struct RecentRecovery: Identifiable, Equatable {
        let origin: CleanupRecoveryOrigin
        let batchID: UUID
        var id: String { origin.rawValue + "/" + batchID.uuidString }
    }
    @Published var workspace: Workspace = .junk
    @Published var apps: [ApplicationIdentity] = [] {
        didSet {
            // Explicitly chosen bundles outside the catalog remain visible in
            // their own selection row. A disappeared catalog row cannot linger.
            if let selectedApp, oldValue.contains(where: { $0.path == selectedApp }) { reconcileApplicationSelection() }
        }
    }
    @Published var executionAvailable = SafetyPolicy.current.executionEnabled
    @Published var readOnlyReason = SafetyPolicy.current.limitation
    @Published var query = "" { didSet { if query != oldValue { reconcileApplicationSelection() } } }
    @Published var showRetainedApps = false { didSet { if showRetainedApps != oldValue { reconcileApplicationSelection() } } }
    @Published var selectedApp: String?
    var applicationPickerRoot: URL?
    @Published var report: ScanReport?
    @Published var overview: CleanupOverview?
    @Published private(set) var scanPreview: CleanupOverview?
    @Published var combinedReview: CleanupReview?
    private var dependencyReview: (id: UUID, coordinator: CleanupCoordinator)?
    @Published var retainedItems: [Candidate] = []
    @Published var retainedIssues: [String] = []
    @Published var selected = Set<UUID>()
    @Published var includeUserData = false
    @Published var plan: CleanupPlan?
    @Published var recoveryRows: [CleanupRecoveryRow] = []
    @Published private(set) var recentRecovery: [RecentRecovery] = []
    @Published var selectedBatch: String?
    @Published private(set) var currentBatch: RecoveryManifest?
    @Published var recoveryIssues: [String] = []
    @Published var recoveryExecutionOrigins: Set<CleanupRecoveryOrigin> = []
    @Published var pendingRuns: [CleanupRunReceipt] = []
    @Published var nextUserCursor: UUID?
    @Published var nextSystemCursor: UUID?
    private var purgeOrigin: CleanupRecoveryOrigin?
    @Published var busy = false
    @Published var canCancel = false
    @Published private(set) var scanProgress: ScanProgress?
    @Published private(set) var scanStartedAt: Date?
    private var operationID = UUID()
    @Published var completionNotice: String?
    @Published var message = ""
    @Published var error = false
    @Published var purgeBatch: RecoveryManifest?
    @Published var purgeConfirmation = ""
    @Published var accessMessage = ""
    @Published var preparationRequired = false
    @Published private(set) var checkingAccess = false
    @Published private(set) var accessReadiness = AccessReadinessEvaluator.evaluate(.init(userSubject: "", systemSubject: "", evidence: []), now: Date())
    private let accessSubject = UUID().uuidString
    private var accessCheck: Task<Void, Never>?
    @Published private(set) var ignoreList: CleanupIgnoreList?
    @Published var applicationDiscoveryIssues: [String] = []
    @Published var optimizationSelection: OptimizationSelection?
    @Published private(set) var optimizationReview: ApplicationOptimizationReview?
    @Published private(set) var optimizationResult: ApplicationOptimizationBatch?
    @Published private(set) var optimizationHistory: [ApplicationOptimizationBatch] = []
    @Published private(set) var optimizationIssues: [String] = []
    @Published var optimizationKeepReview: ApplicationOptimizationKeepReview?
    @Published var optimizationPurgeReview: ApplicationOptimizationPurgeReview?
    private var purgeInteractionID: UUID?
    private var optimizationInteractionID: UUID?
    private var keepInteractionID: UUID?
    private var folderAccess: [URL] = []
    private let engine: SweepEngine
    private let coordinator: CleanupCoordinator
    private let optimization: ApplicationOptimizationCoordinator
    private var retiringOperation: Task<Void,Never>?
    private var operation: Task<Void, Never>?
    init(engine: SweepEngine = SweepEngine(), coordinator: CleanupCoordinator = CleanupCoordinator(), optimization: ApplicationOptimizationCoordinator = ApplicationOptimizationCoordinator()) { self.engine = engine; self.coordinator = coordinator; self.optimization = optimization }
    deinit { for url in folderAccess { url.stopAccessingSecurityScopedResource() } }
    func chooseApplication() {
        guard !busy else { return }
        let panel = NSOpenPanel()
        panel.canChooseFiles = true; panel.canChooseDirectories = false
        panel.treatsFilePackagesAsDirectories = false; panel.allowedContentTypes = [.applicationBundle]
        panel.allowsMultipleSelection = false; panel.canCreateDirectories = false
        panel.directoryURL = applicationPickerRoot ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications")
        panel.message = "选择要核对的应用本体。系统与受保护位置不会进入清理计划。"
        panel.prompt = "选择应用"
        panel.begin { [weak self] response in
            guard response == .OK, let url = panel.url else { return }
            Task { @MainActor in
                guard let self, !self.busy else { return }
                if !self.folderAccess.contains(url), url.startAccessingSecurityScopedResource() { self.folderAccess.append(url) }
                self.selectedApp = url.path; self.report = nil; self.plan = nil
                self.selected.removeAll(); self.includeUserData = false
                self.retainedItems = []; self.retainedIssues = []
                self.message = "已选择 \(url.deletingPathExtension().lastPathComponent)。查看卸载明细后再核对本次计划。"
                self.error = false
            }
        }
    }
    func chooseAccessFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true; panel.canChooseFiles = false
        panel.allowsMultipleSelection = false; panel.canCreateDirectories = false
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library")
        panel.message = "选择允许 App Sweep 核对资料的文件夹；不会立即清理文件。"
        panel.prompt = "允许访问"
        panel.begin { [weak self] response in
            guard response == .OK, let url = panel.url else { return }
            Task { @MainActor in
                guard let self else { return }
                if !self.folderAccess.contains(url), url.startAccessingSecurityScopedResource() { self.folderAccess.append(url) }
                self.accessMessage = "已选择 \(url.lastPathComponent)。重新扫描后会核对实际访问结果；未确认的资料继续保留。"
            }
        }
    }
    func chooseServiceInstaller() {
        guard !checkingAccess, !busy else { return }
        let panel = NSOpenPanel()
        panel.title = "选择当前版本配套的系统服务安装包"
        panel.message = "选择同一份交付中的 App-Sweep-System-Service-2.1.0.pkg。管理员认证由 macOS 安装器完成。"
        panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [UTType(filenameExtension: "pkg") ?? .package]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        guard url.lastPathComponent == "App-Sweep-System-Service-2.1.0.pkg" else {
            accessMessage = "请选择本次交付中配套的 App Sweep 系统服务安装包。"; return
        }
        // User-selected installer document only. No shell command, credential
        // collection or privileged installation occurs inside the application.
        accessMessage = NSWorkspace.shared.open(url)
            ? "已打开系统安装器。完成安装后，返回点击“核对访问”。"
            : "无法打开安装器，请在 Finder 中打开配套安装包。"
    }
    func openPrivacySettings() {
        guard let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"), NSWorkspace.shared.open(url) else {
            accessMessage = "请在系统设置的“隐私与安全性 → 完全磁盘访问权限”中查看 App Sweep。"; return
        }
        accessMessage = "开启后按系统提示重新打开，再核对访问。"
    }
    func checkPreparation() {
        guard !checkingAccess else { return }
        checkingAccess = true
        let subject = accessSubject
        accessCheck = Task { [weak self] in
            let userResult = await Task.detached { AccessPreparationProbe.user() }.value
            var evidence: [AccessReadiness.Evidence] = [.init(scope: .user, result: userResult, subject: subject, checkedAt: Date())]
            var systemSubject = "unavailable"
            do {
                let client = try await SystemServiceClient.connect()
                do {
                    let status = try await client.status(maximumDuration: 5)
                    systemSubject = status.accessSubject ?? "unconfirmed"
                    evidence.append(.init(scope: .system, result: status.accessProbe ?? .unknown, subject: systemSubject, checkedAt: Date()))
                } catch {
                    evidence.append(.init(scope: .system, result: .unavailable, subject: systemSubject, checkedAt: Date()))
                }
                await client.close()
            } catch {
                evidence.append(.init(scope: .system, result: .unavailable, subject: systemSubject, checkedAt: Date()))
            }
            guard let self else { return }
            self.accessReadiness = AccessReadinessEvaluator.evaluate(.init(userSubject: subject, systemSubject: systemSubject, evidence: evidence), now: Date())
            self.checkingAccess = false
        }
    }
    func finishPreparation() {
        preparationRequired = false
        // An onboarding preference records navigation only, never permission.
        UserDefaults.standard.set(1, forKey: "accessPreparationVersion")
        message = accessReadiness.state == .ready ? "" : "当前为受限访问；未确认的范围会保留。"
    }
    var filteredApps: [ApplicationIdentity] {
        apps.filter { app in
            (showRetainedApps || app.protectedReason == nil) &&
            (query.isEmpty || app.name.localizedCaseInsensitiveContains(query) || app.bundleIdentifier.localizedCaseInsensitiveContains(query))
        }
    }
    private func reconcileApplicationSelection() {
        guard let selectedApp, !filteredApps.contains(where: { $0.path == selectedApp }) else { return }
        self.selectedApp = nil
        report = nil; plan = nil; selected.removeAll(); includeUserData = false
    }
    var canReview: Bool {
        guard !busy, !selected.isEmpty else { return false }
        if workspace == .junk { return overview?.selectionIsComplete(selected,includeUserData:includeUserData) == true }
        guard let report else { return false }
        if let path = report.applicationPath,
           !report.candidates.contains(where: { $0.path == path && $0.category == .application && selected.contains($0.id) }) { return false }
        return report.selectionIsComplete(selected, includeUserData: includeUserData)
    }
    var selectedRecoveryRow: CleanupRecoveryRow? { recoveryRows.first { $0.id == selectedBatch } }
    var recoveryExecutionAvailable: Bool { selectedRecoveryRow.map { recoveryExecutionOrigins.contains($0.origin) } ?? false }
    var hasScan: Bool { workspace == .junk ? overview != nil : report != nil }
    func switchWorkspace(_ next: Workspace) {
        guard !preparationRequired else { return }
        guard !busy || canCancel else { return }
        if busy { cancel() }
        let previous = retiringOperation, coordinator = coordinator
        retiringOperation = Task { await previous?.value; await coordinator.discardReview() }
        closeUnusedDependencyReview()
        NSApp?.keyWindow?.makeFirstResponder(nil)
        workspace = next; combinedReview = nil; retainedItems = []; retainedIssues = []
        selected.removeAll(); plan = nil; includeUserData = false; message = ""; completionNotice = nil
        optimizationSelection = nil; optimizationInteractionID = nil
        if next == .recovery { loadRecovery() }
        if next == .uninstall && apps.isEmpty { loadApps() }
    }
    func cancel() {
        guard !busy || canCancel else { return }
        closeUnusedDependencyReview()
        operationID = UUID()
        if busy { operation?.cancel(); message = "已取消；扫描结果未确认。" }
        let previous = operation ?? retiringOperation
        let coordinator = coordinator
        let optimization = optimization
        retiringOperation = Task { await previous?.value; await coordinator.close(); try? await optimization.close() }
        operation = nil; busy = false; canCancel = false
        scanProgress = nil; scanStartedAt = nil; scanPreview = nil
        plan = nil; combinedReview = nil
        optimizationReview = nil; optimizationKeepReview = nil; keepInteractionID = nil
        optimizationPurgeReview = nil; purgeInteractionID = nil
    }
    private func start(cancellable: Bool = true, _ action: @escaping @MainActor () async throws -> Void) {
        guard !busy, !preparationRequired else { return }
        busy = true; canCancel = cancellable; error = false; message = ""; completionNotice = nil
        let id = UUID(); operationID = id
        let retiring = retiringOperation; retiringOperation = nil
        operation = Task {
            await retiring?.value
            do { try Task.checkCancellation(); try await action(); try Task.checkCancellation() }
            catch is CancellationError { if operationID != id { return }; message = "已取消；扫描结果未确认。" }
            catch { if operationID != id { return }; self.error = true; message = error.localizedDescription }
            guard operationID == id else { return }
            busy = false; canCancel = false
            scanProgress = nil; scanStartedAt = nil; scanPreview = nil
        }
    }
    func loadApps() { start {
        let catalog = try await self.engine.applicationCatalog()
        try Task.checkCancellation()
        self.apps = catalog.applications; self.applicationDiscoveryIssues = catalog.unconfirmedIssues
        if !catalog.unconfirmedIssues.isEmpty {
            self.message = "已读取可确认的应用。部分发现范围未确认，你仍可手动选择应用。"; self.error = true
        }
    } }
    func loadIgnores() { start(cancellable:false) {
        self.ignoreList = nil
        self.ignoreList = try await self.engine.cleanupIgnores()
    } }
    func ignore(_ candidate: Candidate) {
        guard !busy, workspace != .recovery else { return }
        let current = workspace == .junk ? overview?.candidates : report?.candidates
        guard current?.contains(candidate) == true else { return }
        start(cancellable:false) {
            let current = try await self.engine.cleanupIgnores()
            self.ignoreList = try await self.engine.addCleanupIgnore(path:candidate.path,expectedRevision:current.revision)
            await self.ignoreSettingsChanged()
        }
    }
    func removeIgnore(path: String) {
        guard !busy, let current = ignoreList, current.paths.contains(path) else { return }
        start(cancellable:false) {
            self.ignoreList = try await self.engine.removeCleanupIgnore(path:path,expectedRevision:current.revision)
            await self.ignoreSettingsChanged()
        }
    }
    func setCategoryIgnored(_ category: CandidateCategory, ignored: Bool) {
        guard !busy, let current = ignoreList, CleanupIgnoreList.supportedCategories.contains(category),
              current.categories.contains(category) != ignored else { return }
        start(cancellable:false) {
            self.ignoreList = try await self.engine.setCleanupCategoryIgnored(category,ignored:ignored,expectedRevision:current.revision)
            await self.ignoreSettingsChanged()
        }
    }
    private func ignoreSettingsChanged() async {
        await coordinator.close()
        report = nil; overview = nil; plan = nil; combinedReview = nil
        selected.removeAll(); retainedItems = []; retainedIssues = []; includeUserData = false
        message = "保留列表已更新。请重新扫描后核对新的计划；已有恢复记录仍可使用。"
    }
    func scan() {
        guard !busy, !preparationRequired else { return }
        if workspace == .junk { overview = nil; scanPreview = nil } else { report = nil }
        plan = nil; combinedReview = nil
        retainedItems = []; retainedIssues = []; selected.removeAll(); includeUserData = false
        let space = workspace, path = selectedApp
        if space == .junk {
            scanStartedAt = Date(); scanProgress = .init(stage:"准备扫描",discoveredCount:0)
        }
        start {
            if space == .uninstall {
                guard let path else { throw SweepError.invalid("请先选择一个应用") }
                let output = try await self.engine.scanApplication(path)
                try Task.checkCancellation()
                self.report = output
                self.selected = output.recommendedSelectionIDs()
                self.error = !output.complete
                // CandidateList presents incomplete discovery once, beside its results.
            } else if space == .junk {
                let id = self.operationID
                let previewProgress=ScanPreviewProgress()
                let (updates, continuation) = AsyncStream<ScanProgress>.makeStream(bufferingPolicy:.bufferingNewest(1))
                let display = Task { @MainActor in
                    for await update in updates {
                        guard !Task.isCancelled, self.operationID == id, self.busy else { return }
                        self.scanProgress = update
                        if !update.completedReports.isEmpty {
                            var sections=self.scanPreview?.sections ?? []
                            for source in CleanupSource.allCases {
                                guard let report=update.completedReports[source.rawValue] else{continue}
                                sections.removeAll{$0.source == source}
                                sections.append(.init(source:source,report:report,issue:nil))
                            }
                            self.scanPreview=CleanupOverview(id:self.scanPreview?.id ?? UUID(),sections:sections)
                        }
                    }
                }
                defer { continuation.finish(); display.cancel() }
                let output = try await self.coordinator.scanJunk(progress:{ continuation.yield(previewProgress.merging($0)) })
                continuation.finish()
                await display.value
                try Task.checkCancellation()
                let recommendations = await Task.detached { output.recommendedSelectionIDs() }.value
                try Task.checkCancellation()
                self.selected = recommendations
                self.overview = output
                self.error = !output.complete
            }
        }
    }
    func toggleData(_ enabled: Bool) {
        guard !busy else { return }
        includeUserData = enabled
        plan = nil; combinedReview = nil
        if workspace == .junk {
            let selectable = overview?.selectableCandidates(includeUserData:enabled) ?? []
            selected.formIntersection(Set(selectable.map(\.id)))
            // Personal backups require individual choice even after enabling
            // management; cache selections keep their normal behaviour.
        } else if let report {
            let selectable = report.selectableCandidates(includeUserData:enabled)
            selected.formIntersection(Set(selectable.map(\.id)))
            if enabled { selected.formUnion(selectable.filter(\.userData).map(\.id)) }
        }
    }
    func select(_ candidate: Candidate, enabled: Bool) {
        guard !busy else { return }
        let ids: Set<UUID>
        if workspace == .junk { ids = overview?.selectionIDs(for:candidate.id,includeUserData:includeUserData) ?? [] }
        else { ids = report?.selectionIDs(for:candidate.id,includeUserData:includeUserData) ?? [] }
        if enabled { selected.formUnion(ids) } else { selected.subtract(ids) }
        plan = nil; combinedReview = nil
    }
    func selectRecommended() {
        guard !busy, workspace != .recovery else { return }
        selected = workspace == .junk ? (overview?.recommendedSelectionIDs() ?? []) : (report?.recommendedSelectionIDs() ?? [])
        plan = nil; combinedReview = nil
        if selected.isEmpty { message = "这些项目需要手动选择；请先核对应用和缓存内容。"; error = false }
    }
    func clearSelection() {
        guard !busy, workspace != .recovery else { return }
        selected.removeAll()
        plan = nil; combinedReview = nil
    }
    var hasSystemUninstallPrerequisites: Bool {
        report?.candidates.contains { $0.category == .application && $0.ignoredReason == nil && ($0.retentionReason?.contains("安装了系统辅助组件") ?? false) } == true
    }
    func closeUnusedDependencyReview() {
        if let pending = dependencyReview {
            dependencyReview = nil
            Task { await pending.coordinator.close() }
        }
    }
    func reviewUninstallPrerequisites() {
        guard let path = report?.applicationPath, !busy else { return }
        closeUnusedDependencyReview()
        start {
            let dependency = self.coordinator.recoverySession()
            do {
                let review = try await dependency.reviewApplicationPrerequisites(applicationPath: path)
                try Task.checkCancellation()
                self.dependencyReview = (review.id, dependency)
                self.combinedReview = review
            } catch { await dependency.close(); throw error }
        }
    }
    func review() { start {
        if self.workspace == .junk, let overview = self.overview {
            self.combinedReview = try await self.coordinator.review(overviewID:overview.id,selected:self.selected,includeUserData:self.includeUserData)
        } else if let report = self.report {
            self.plan = try await self.engine.makePlan(reportID:report.id,selected:self.selected,includeUserData:self.includeUserData)
        }
    } }
    func execute() {
        if let review = combinedReview {
            let dependency = dependencyReview?.id == review.id ? dependencyReview?.coordinator : nil
            dependencyReview = nil; combinedReview = nil
            start(cancellable:false) {
                defer { if let dependency { Task { await dependency.close() } } }
                let result = try await (dependency ?? self.coordinator).execute(reviewID:review.id)
                self.rememberRecovery(result.batches.map { RecentRecovery(origin:$0.source == .user ? .user : .system,batchID:$0.manifest.id) })
                if result.status == .isolated {
                    self.selected.removeAll()
                    self.overview = self.overview?.excluding(Set(review.items.map(\.id)))
                    self.retainedItems = []; self.retainedIssues = []
                    self.completionNotice = review.applicationPrerequisite == nil ? "已将 \(review.items.count) 项移入恢复区，可撤销" : "系统组件已移入恢复区，应用主体仍保留"
                    if review.applicationPrerequisite != nil {
                        self.retainResultsAfterRecoveryChange(review.items)
                        self.message = "请重新核对该应用，再选择卸载；尚未完成应用卸载。撤销全部操作时，先恢复应用主体，再恢复组件。"
                    } else { self.message = "" }
                    self.error = false
                } else {
                    let unchanged = result.status == .rolledBack && result.batches.isEmpty && result.uncertainSources.isEmpty
                    if !unchanged {
                        if dependency != nil { self.retainResultsAfterRecoveryChange(review.items) }
                        else { self.overview = nil; self.selected.removeAll() }
                    }
                    self.retainedIssues = result.retainedIssues
                    self.message = "操作未完成：" + (result.issue ?? "请核对恢复区")
                    self.error = true
                }
                // Recovery history is loaded when requested; it must not delay
                // the result or invalidate the remaining scan's transport.

            }
            return
        }
        guard let plan else { return }; self.plan = nil
        start(cancellable: false) {
            let result = try await self.engine.execute(planID: plan.id)
            self.rememberRecovery([RecentRecovery(origin:.user,batchID:result.id)])
            self.retainedIssues = result.retainedIssues ?? []
            if result.status == .isolated {
                let moved = Set(plan.items.map(\.id))
                self.retainedItems = self.report?.candidates.filter { !moved.contains($0.id) } ?? []
                if let app = plan.items.first(where: { $0.category == .application }) {
                    self.apps.removeAll { $0.path == app.path || $0.path.hasPrefix(app.path + "/") }; self.selectedApp = nil
                }
            }
            self.message = result.status == .isolated ? "文件已移入恢复区 \(byteText(result.isolatedBytes))。" + (result.backedUpPreferenceCount > 0 ? "另有 \(result.backedUpPreferenceCount) 项设置已独立备份并清除，支持撤销；备份仍占用磁盘空间。" : "尚未释放磁盘空间。") + (self.retainedIssues.isEmpty ? "另有 \(self.retainedItems.count) 项保留，可查看原因。" : "仍有未确认范围未处理，请查看保留说明。") : "操作未完成：\(result.issue ?? "请在恢复区查看处理状态")"
            self.error = result.status != .isolated
            if result.status == .isolated {
                self.report = self.report?.excluding(Set(plan.items.map(\.id)))
                self.retainedItems = []; self.retainedIssues = []
                self.completionNotice = "已将 \(plan.items.count) 项移入恢复区，可撤销"
                self.message = ""; self.error = false
            } else { self.report = nil }
            self.selected.removeAll()
        }
    }
    private func rememberRecovery(_ references: [RecentRecovery]) {
        var seen = Set<String>()
        recentRecovery = Array((references + recentRecovery).filter { seen.insert($0.id).inserted }.prefix(8))
    }
    private func refreshHistory(afterUser: UUID? = nil, afterSystem: UUID? = nil) async throws {
        let reader = coordinator.recoverySession()
        defer { Task { await reader.close() } }
        let page = try await reader.historyPage(afterUser:afterUser,afterSystem:afterSystem)
        try Task.checkCancellation()
        if afterUser == nil && afterSystem == nil {
            recoveryRows = page.rows; recoveryIssues = page.issues
            recoveryExecutionOrigins = page.executionEnabledOrigins
            nextUserCursor = page.nextUserCursor; nextSystemCursor = page.nextSystemCursor
        } else {
            let existing = Set(recoveryRows.map(\.id))
            recoveryRows += page.rows.filter { !existing.contains($0.id) }
            recoveryIssues += page.issues
            recoveryExecutionOrigins.subtract(page.queriedOrigins)
            recoveryExecutionOrigins.formUnion(page.executionEnabledOrigins)
            if page.queriedOrigins.contains(.user) { nextUserCursor = page.nextUserCursor }
            if page.queriedOrigins.contains(.system) { nextSystemCursor = page.nextSystemCursor }
        }
        // These are display references from actual execution results, never
        // execution authority. Re-read each bounded record through its origin.
        var recentRows: [CleanupRecoveryRow] = []
        for reference in recentRecovery {
            recoveryRows.removeAll { $0.id == reference.id }
            do {
                let manifest = try await reader.recoveryDetail(origin:reference.origin,batchID:reference.batchID)
                try Task.checkCancellation()
                recentRows.append(CleanupRecoveryRow(origin:reference.origin,manifest:manifest))
            } catch {
                try Task.checkCancellation()
                recoveryIssues.append(reference.origin.title + "的本次操作未确认：" + error.localizedDescription)
            }
        }
        recoveryRows = (recentRows + recoveryRows).sorted {
            $0.summary.createdAt == $1.summary.createdAt ? $0.id < $1.id : $0.summary.createdAt > $1.summary.createdAt
        }
        if !recoveryIssues.isEmpty { error = true }
        if afterUser == nil && afterSystem == nil { try await refreshOptimizationHistory() }
    }
    func loadRecovery() { start {
        self.plan = nil; self.combinedReview = nil
        self.selectedBatch = nil; self.currentBatch = nil
        try await self.refreshHistory()
        do { self.pendingRuns = try await self.coordinator.pendingRuns() }
        catch { self.recoveryIssues.append("组合操作记录：" + error.localizedDescription); self.error = true }
        if !self.pendingRuns.isEmpty || self.recoveryRows.contains(where: { [.inProgress,.purging,.needsAttention].contains($0.summary.status) }) || self.optimizationHistory.contains(where:{ [.preparing,.prepared,.publishing,.undoing,.needsAttention,.purging].contains($0.status) }) {
            self.workspace = .recovery
            self.message = "发现未完成操作，请核对恢复记录。程序不会自动继续清理。"; self.error = true
        }
    } }
    func loadMoreRecovery(_ origin: CleanupRecoveryOrigin) {
        let cursor = origin == .user ? nextUserCursor : nextSystemCursor
        guard let cursor else { return }
        start { try await self.refreshHistory(afterUser:origin == .user ? cursor : nil,afterSystem:origin == .system ? cursor : nil) }
    }
    func selectRecovery(_ id: String?) {
        guard !busy else { return }
        selectedBatch = id; currentBatch = nil
        guard let row = selectedRecoveryRow else { return }
        start {
            let reader = self.coordinator.recoverySession()
            defer { Task { await reader.close() } }
            let batch = try await reader.recoveryDetail(origin:row.origin,batchID:row.summary.id)
            try Task.checkCancellation()
            guard self.selectedBatch == row.id else { return }
            self.currentBatch = batch
        }
    }
    func retainResultsAfterRecoveryChange(_ originals: [Candidate]) {
        // Presentation only: unchanged report identities stay registered with
        // their existing engines. Every future plan still revalidates on review.
        func project(_ scan: ScanReport) -> ScanReport {
            let updated = scan.requiringRecheck(afterRecoveryOf: originals)
            selected.subtract(updated.candidates.filter { !$0.allowsPlanReview }.map(\.id))
            return updated
        }
        if let report { self.report = project(report) }
        if let overview {
            self.overview = CleanupOverview(id: overview.id, sections: overview.sections.map {
                CleanupSection(source: $0.source, report: $0.report.map(project), issue: $0.issue)
            })
        }
        plan = nil; combinedReview = nil
    }
    func restore() {
        guard let row = selectedRecoveryRow, currentBatch?.id == row.summary.id,currentBatch?.previewOnlyReason == nil else { return }
        let originals = currentBatch?.entries.map(\.original) ?? []
        start(cancellable:false) {
            self.retainResultsAfterRecoveryChange(originals)
            let recovery = self.coordinator.recoverySession()
            defer { Task { await recovery.close() } }
            let result = try await recovery.restoreRecovery(origin:row.origin,batchID:row.summary.id)
            if result.entries.contains(where: { $0.original.category == .application && $0.state == .restored }) {
                self.apps = [] // Rediscover lazily when the uninstall workspace is entered again.
            }
            try await self.refreshHistory()
            self.currentBatch = result
            self.message = result.status == .restored ? (result.hasIndependentBackups ? "已恢复；独立恢复备份仍保留，可单独确认清空。" : "已恢复；原路径中的已有文件未被覆盖。") : "恢复未完成，请处理显示的冲突后重试。"
            self.error = result.status != .restored || !self.recoveryIssues.isEmpty
        }
    }
    func requestPurge() {
        guard !busy, let row = selectedRecoveryRow, let batch = currentBatch, batch.id == row.summary.id else { return }
        purgeOrigin = row.origin; purgeConfirmation = ""; purgeBatch = batch
    }
    func purge() {
        guard let batch = purgeBatch, let origin = purgeOrigin else { return }
        let confirmation = purgeConfirmation; purgeBatch = nil; purgeOrigin = nil; purgeConfirmation = ""
        start(cancellable:false) {
            let recovery = self.coordinator.recoverySession()
            defer { Task { await recovery.close() } }
            let result = try await recovery.purgeRecovery(origin:origin,batchID:batch.id,confirmation:confirmation)
            try await self.refreshHistory()
            self.currentBatch = result
            self.message = result.status == .purged ? "已清空本批次恢复区内容；实际可用空间由文件系统决定。" : "永久清空未完成，后续项目已停止。"
            self.error = result.status != .purged || !self.recoveryIssues.isEmpty
        }
    }

    func openOptimization() {
        guard !busy, let path = selectedApp else { return }
        cancel()
        let selection = OptimizationSelection(applicationPath:path)
        optimizationSelection = selection; optimizationInteractionID = selection.id
        optimizationReview = nil; optimizationResult = nil; message = ""; error = false
    }
    func closeOptimization() {
        guard !busy || canCancel else { return }
        optimizationInteractionID = nil; optimizationSelection = nil
        cancel()
    }
    func optimizationSheetDisappeared(_ id: UUID) {
        guard optimizationInteractionID == id else { return }
        closeOptimization()
    }
    func invalidateOptimizationReview() {
        guard !busy || canCancel else { return }
        cancel(); optimizationResult = nil; message = ""; error = false
    }
    func reviewOptimization(kind: ApplicationOptimizationKind, retainingLanguages: [String]) {
        guard !busy, let selection = optimizationSelection else { return }
        optimizationReview = nil; optimizationResult = nil
        start {
            let value = try await self.optimization.review(applicationPath:selection.applicationPath,kind:kind,retainingLanguages:retainingLanguages)
            try Task.checkCancellation()
            guard self.optimizationSelection?.id == selection.id else { throw CancellationError() }
            self.optimizationReview = value
        }
    }
    func executeOptimization() {
        guard !busy, let review = optimizationReview, review.executionAvailable,
              optimizationSelection?.applicationPath == review.applicationPath else { return }
        let actor = optimization
        applyOptimizationMutation { try await actor.execute(reviewID:review.id) }
    }
    private func refreshOptimizationHistory() async throws {
        do {
            let rows = try await optimization.history(); try Task.checkCancellation()
            optimizationHistory = rows; optimizationIssues = []
        } catch is CancellationError { throw CancellationError() }
        catch { optimizationHistory = []; optimizationIssues = [error.localizedDescription]; self.error = true }
    }
    private func applyOptimizationMutation(_ action: @escaping @Sendable () async throws -> ApplicationOptimizationBatch) {
        start(cancellable:false) {
            do {
                let result = try await action()
                self.purgeInteractionID = nil; self.optimizationPurgeReview = nil
                self.optimizationResult = result; self.optimizationReview = nil
                self.plan = nil; self.combinedReview = nil; self.report = nil; self.overview = nil; self.selected.removeAll()
                switch result.status {
                case .published:self.message = "应用副本已精简，原包保留；备份仍占用磁盘空间。"
                case .restored:self.message = "原安装包已恢复；用户资料未作回退，精简副本仍保留。"
                case .stopped:self.message = "准备操作已停止，原安装包保留；已有准备对象仍保留待核对。"
                case .purged:self.message = "经核对的恢复副本已永久清空，无法撤销。当前应用保留，用户资料未作回退。"
                case .retained:self.message = "已记录为保留当前版本，当前应用与原包备份均保留。没有释放磁盘空间。"
                default:self.message = result.issue ?? "操作结果尚未确认，请核对恢复记录。"
                }
                self.error = ![.published,.restored,.stopped,.retained,.purged].contains(result.status)
                try await self.refreshOptimizationHistory()
                if !self.optimizationIssues.isEmpty { self.message += "恢复记录列表未确认，请刷新。" }
            } catch {
                self.purgeInteractionID = nil; self.optimizationPurgeReview = nil
                self.optimizationReview = nil
                try await self.refreshOptimizationHistory()
                throw error
            }
        }
    }
    func restoreOptimization(_ batchID: UUID) {
        guard !busy, optimizationHistory.contains(where:{ $0.id == batchID && $0.canRestore }) else { return }
        let actor = optimization
        applyOptimizationMutation { try await actor.restore(batchID:batchID) }
    }
    func inspectOptimization(_ batchID: UUID) {
        guard !busy, optimizationHistory.contains(where:{ $0.id == batchID && $0.canInspect }) else { return }
        let actor = optimization
        applyOptimizationMutation { try await actor.inspect(batchID:batchID) }
    }
    func requestOptimizationPurge(_ batchID: UUID) {
        guard !busy, optimizationHistory.contains(where:{ $0.id == batchID && $0.canReviewPurge }) else { return }
        start {
            let value = try await self.optimization.reviewPurge(batchID:batchID)
            try Task.checkCancellation()
            guard self.workspace == .recovery else { throw CancellationError() }
            self.purgeInteractionID = value.id; self.optimizationPurgeReview = value
        }
    }
    func confirmOptimizationPurge(confirmation: String) {
        guard !busy, let review = optimizationPurgeReview, review.executionAvailable,
              confirmation == "永久清空 " + review.batchID.uuidString else { return }
        let actor = optimization
        applyOptimizationMutation { try await actor.purge(reviewID:review.id,confirmation:confirmation) }
    }
    func cancelOptimizationPurge() {
        guard !busy || canCancel else { return }
        purgeInteractionID = nil; optimizationPurgeReview = nil; cancel()
    }
    func optimizationPurgeSheetDisappeared(_ id: UUID) {
        guard purgeInteractionID == id else { return }
        cancelOptimizationPurge()
    }
    func reviewKeepingCurrentOptimization(_ batchID: UUID) {
        guard !busy, optimizationHistory.contains(where:{ $0.id == batchID && $0.canKeepCurrent }) else { return }
        start {
            let value = try await self.optimization.reviewKeepingCurrent(batchID:batchID)
            try Task.checkCancellation()
            guard self.workspace == .recovery else { throw CancellationError() }
            self.keepInteractionID = value.id; self.optimizationKeepReview = value
        }
    }
    func confirmKeepingCurrentOptimization() {
        guard !busy, let review = optimizationKeepReview else { return }
        keepInteractionID = nil; optimizationKeepReview = nil
        let actor = optimization
        applyOptimizationMutation { try await actor.keepCurrent(reviewID:review.id) }
    }
    func cancelKeepingCurrentOptimization() {
        guard !busy || canCancel else { return }
        keepInteractionID = nil; optimizationKeepReview = nil; cancel()
    }
    func keepCurrentSheetDisappeared(_ id: UUID) {
        guard keepInteractionID == id else { return }
        cancelKeepingCurrentOptimization()
    }

}
extension RecoveryManifest.Status {
    var title: String {
        switch self { case .inProgress: "操作中断，等待恢复"; case .isolated: "已移入恢复区"; case .purging: "永久清空中断，等待核对"; case .rolledBack: "操作失败，已撤销"; case .needsAttention: "需要处理冲突"; case .restored: "已恢复"; case .partiallyRestored: "可恢复项目已恢复，部分已永久清空"; case .purged: "已永久清空" }
    }
}
extension RecoveryEntry.State {
    var title: String { switch self { case .prepared: "移动状态未确认"; case .moved: "在恢复区"; case .restorePrepared: "恢复状态未确认"; case .purgePrepared: "永久清空状态未确认"; case .restored: "已恢复"; case .conflict: "需要人工处理"; case .purged: "已永久清空" } }
}
