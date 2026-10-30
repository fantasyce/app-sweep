import SwiftUI
import AppSweepCore

@MainActor
struct SweepWindow: View {
    @EnvironmentObject private var store: SweepStore
    @Environment(\.colorScheme) private var scheme
    @AppStorage("appearance") private var appearance = "system"
    @State private var showAccess = false
    @State private var showIgnores = false
    @State private var showStatusDetails = false
    @State private var showScanScope = false
    @State private var applicationSearch = ""
    @State private var showRetainedApplications = false
    private var palette: PaperPalette { PaperPalette(scheme: scheme) }
    var body: some View {
        Group {
            if store.preparationRequired {
                AccessOnboardingView { }.environmentObject(store)
            } else { workspaceBody }
        }
    }
    private var workspaceBody: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 12) {
                Text("App Sweep").font(SketchFont.body(18)).fontWeight(.semibold).foregroundColor(palette.ink).padding(.vertical, 16)
                workspaceButton(.junk)
                workspaceButton(.uninstall)
                Spacer()
                workspaceButton(.recovery)
                Text(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "开发版")
                    .font(.system(size: 11, design: .monospaced)).foregroundColor(palette.secondary).padding(.horizontal, 10)
            }.padding(16).frame(width: 180).background(PaperBackground(sidebar: true))
            Rectangle().fill(palette.line).frame(width: 1)
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .firstTextBaseline) {
                    Text(store.workspace.rawValue).font(SketchFont.body(24)).fontWeight(.semibold)
                    Spacer()
                    SketchMenu(title: "设置", symbol: .settings, items:
                        [SketchMenuItem(id: "ignores", title: "保留列表…") { store.loadIgnores(); showIgnores = true }] +
                        (store.workspace == .recovery ? [] : [SketchMenuItem(id: "access", title: "扫描访问…") { showAccess = true }]) +
                        [SketchMenuItem(id: "appearance-light", title: "浅色外观", selected: appearance == "light") { appearance = "light" },
                         SketchMenuItem(id: "appearance-dark", title: "深色外观", selected: appearance == "dark") { appearance = "dark" },
                         SketchMenuItem(id: "appearance-system", title: "外观跟随系统", selected: appearance == "system") { appearance = "system" }]
                    ).fixedSize().disabled(store.busy)
                }
                if store.workspace == .recovery {
                    Text("移入恢复区的文件仍占用空间，可随时撤销。").font(SketchFont.body(14)).foregroundColor(palette.secondary)
                }
                if let reason = store.readOnlyReason { Text(reason).font(SketchFont.body(13)).foregroundColor(palette.secondary) }
                operationStatus
                // Keep result views mounted across navigation, including their
                // search, disclosures and native scroll position.
                ZStack {
                    scanWorkspace.opacity(store.workspace == .junk ? 1 : 0)
                        .disabled(store.workspace != .junk)
                        .allowsHitTesting(store.workspace == .junk).accessibilityHidden(store.workspace != .junk)
                    uninstallWorkspace.opacity(store.workspace == .uninstall ? 1 : 0)
                        .disabled(store.workspace != .uninstall)
                        .allowsHitTesting(store.workspace == .uninstall).accessibilityHidden(store.workspace != .uninstall)
                    recoveryWorkspace.opacity(store.workspace == .recovery ? 1 : 0)
                        .disabled(store.workspace != .recovery)
                        .allowsHitTesting(store.workspace == .recovery).accessibilityHidden(store.workspace != .recovery)
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
            }.padding(24).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading).background(PaperBackground())
        }
        .overlay(alignment: .topTrailing) {
            if let notice = store.completionNotice {
                CompletionNotice(text: notice).padding(.top, 68).padding(.trailing, 20).allowsHitTesting(false)
            }
        }
        .foregroundColor(palette.ink).accentColor(palette.accent)
        .sheet(item: $store.combinedReview, onDismiss: { store.closeUnusedDependencyReview() }) { review in CombinedPlanSheet(review: review).environmentObject(store) }
        .sheet(item: $store.plan) { plan in PlanSheet(plan: plan).environmentObject(store) }
        .sheet(item: $store.purgeBatch) { batch in PurgeSheet(batch: batch).environmentObject(store) }
        .sheet(isPresented: $showAccess) { AccessSheet { showAccess = false }.environmentObject(store) }
        .sheet(isPresented: $showIgnores) { CleanupIgnoreSheet { showIgnores = false }.environmentObject(store) }
        .sheet(item: $store.optimizationSelection) { selection in ApplicationOptimizationSheet(selection: selection).environmentObject(store) }
        .sheet(item: $store.optimizationPurgeReview) { review in OptimizationPurgeSheet(review: review).environmentObject(store) }
        .sheet(item: $store.optimizationKeepReview) { review in OptimizationKeepCurrentSheet(review: review).environmentObject(store) }
    }

    private func workspaceButton(_ workspace: SweepStore.Workspace) -> some View {
        Button { store.switchWorkspace(workspace) } label: {
            HStack(spacing: 8) {
                SketchIcon(symbol: workspaceSymbol(workspace))
                Text(workspace.rawValue).font(SketchFont.body(14)).fontWeight(.medium)
                Spacer(minLength: 0)
            }.padding(10).frame(maxWidth: .infinity)
        }.disabled(store.busy && !store.canCancel).buttonStyle(.plain)
            .background(store.workspace == workspace ? palette.sage : Color.clear)
            .clipShape(RoundedRectangle(cornerRadius: 8))
            .foregroundColor(store.workspace == workspace ? palette.accent : palette.ink)
            .accessibilityAddTraits(store.workspace == workspace ? .isSelected : [])
    }
    private func workspaceSymbol(_ workspace: SweepStore.Workspace) -> SketchSymbol {
        switch workspace { case .junk: .clean; case .uninstall: .applications; case .recovery: .recovery }
    }
    @ViewBuilder private var operationStatus: some View {
        if store.busy {
            HStack(spacing: 9) {
                ProgressView().controlSize(.small)
                Text(store.scanProgress?.stage ?? "正在核对…").font(SketchFont.body(14)).lineLimit(1)
                    .help(store.scanProgress?.detail ?? "")
                Spacer(minLength: 6)
                if let progress = store.scanProgress, let started = store.scanStartedAt {
                    TimelineView(.periodic(from: started, by: 1)) { context in
                        Text("\(progress.discoveredCount) 项 · \(Int(max(0, context.date.timeIntervalSince(started)))) 秒")
                            .font(.system(size: 11, design: .monospaced)).foregroundColor(palette.secondary)
                    }
                }
                if store.canCancel { Button("取消") { store.cancel() }.keyboardShortcut(.cancelAction).buttonStyle(.link) }
            }.padding(.vertical, 4)
        } else if !store.message.isEmpty || !store.retainedItems.isEmpty || !store.retainedIssues.isEmpty {
            HStack(alignment: .center, spacing: 10) {
                Text(store.message.isEmpty ? "本次有保留或未处理的项目。" : store.message)
                    .font(SketchFont.body(13)).lineLimit(2).frame(maxWidth: .infinity, alignment: .leading)
                    .accessibilityLabel((store.error ? "未完成。" : "状态。") + store.message)
                Button("查看说明") { showStatusDetails = true }.buttonStyle(.link).font(SketchFont.body(13)).fixedSize()
                    .popover(isPresented: $showStatusDetails) { statusDetails }
                if store.workspace != .recovery && !store.recentRecovery.isEmpty {
                    Button("恢复记录") { store.switchWorkspace(.recovery) }.buttonStyle(.link).font(SketchFont.body(13)).fixedSize()
                }
            }.padding(9).background(store.error ? palette.coral : palette.sage)
                .clipShape(RoundedRectangle(cornerRadius: 8))
        }
    }
    private var statusDetails: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                if !store.message.isEmpty { Text(store.message).font(SketchFont.body(14)).textSelection(.enabled) }
                if !store.retainedItems.isEmpty {
                    Text("保留的 \(store.retainedItems.count) 项").font(SketchFont.body(17))
                    ForEach(store.retainedItems) { item in
                        VStack(alignment: .leading, spacing: 3) {
                            Text(URL(fileURLWithPath: item.path).lastPathComponent).font(SketchFont.body(14))
                            Text(item.ignoredReason ?? item.retentionReason ?? (item.userData ? "按选择保留用户数据" : "本次未选择"))
                                .font(SketchFont.body(13)).foregroundColor(palette.secondary)
                            Text(item.path).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                        }
                    }
                }
                if !store.retainedIssues.isEmpty {
                    Text("未处理范围").font(SketchFont.body(17))
                    ForEach(Array(store.retainedIssues.enumerated()), id: \.offset) { _, issue in
                        Text(issue).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                    }
                }
            }.frame(maxWidth: .infinity, alignment: .leading).padding(18)
        }.frame(width: 430, height: 300).background(PaperBackground())
    }
    private var scanWorkspace: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let overview = store.overview ?? store.scanPreview {
                HStack {
                    Text(store.scanPreview == nil ? "按分类核对本次扫描结果" : "扫描结果陆续显示，完成后可核对")
                        .font(SketchFont.body(13)).foregroundColor(palette.secondary)
                    Spacer()
                    Button("扫描范围 · \(overview.sections.count) 项") { showScanScope = true }
                        .buttonStyle(.link).font(SketchFont.body(13))
                        .popover(isPresented: $showScanScope) {
                            VStack(alignment: .leading, spacing: 10) {
                                Text("扫描范围").font(SketchFont.body(18))
                                ForEach(overview.sections, id: \.source) { section in
                                    Text(section.source.title + (section.report == nil ? " · 未确认" : " · 已扫描"))
                                        .font(SketchFont.body(14))
                                }
                            }.padding(18).frame(width: 300, alignment: .leading).background(PaperBackground())
                        }
                }
                CandidateList(report: overview).environmentObject(store)
            } else {
                VStack(spacing: 12) {
                    Spacer()
                    SketchIcon(symbol: .clean).scaleEffect(1.9).frame(width: 44, height: 44).foregroundColor(palette.accent)
                    Text(store.busy ? "正在核对扫描范围" : "整理缓存与旧日志").font(SketchFont.body(24)).fontWeight(.semibold)
                    Text(store.busy ? "已确认的结果会陆续出现在这里。" : "先扫描，再按分类选择。个人资料默认保留。")
                        .font(SketchFont.body(14)).foregroundColor(palette.secondary)
                    Spacer()
                }.frame(maxWidth: .infinity)
            }
            scanFooter(for: .junk)
        }
    }

    private var visibleApplications: [ApplicationIdentity] {
        store.apps.filter { app in
            (showRetainedApplications || app.protectedReason == nil) &&
            (applicationSearch.isEmpty || app.name.localizedCaseInsensitiveContains(applicationSearch) ||
             app.bundleIdentifier.localizedCaseInsensitiveContains(applicationSearch) || app.path.localizedCaseInsensitiveContains(applicationSearch))
        }
    }
    private var uninstallWorkspace: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top, spacing: 14) {
                applicationList.frame(width: 218)
                Rectangle().fill(palette.line.opacity(0.3)).frame(width: 1)
                uninstallDetail.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            }.frame(maxWidth: .infinity, maxHeight: .infinity)
            scanFooter(for: .uninstall)
        }
    }
    private var applicationList: some View {
        VStack(alignment: .leading, spacing: 9) {
            TextField("搜索应用", text: $applicationSearch).textFieldStyle(.roundedBorder)
                .accessibilityLabel("搜索应用").disabled(store.busy)
            HStack {
                Text("\(visibleApplications.count) 个应用").font(SketchFont.body(13)).foregroundColor(palette.secondary)
                Spacer(minLength: 0)
                SketchMenu(title: "更多", items: [
                    SketchMenuItem(id: "refresh", title: "刷新应用列表") { store.loadApps() },
                    SketchMenuItem(id: "choose", title: "选择其它位置的应用…") { store.chooseApplication() },
                    SketchMenuItem(id: "retained", title: "显示受保护及待核对的应用", selected: showRetainedApplications) { showRetainedApplications.toggle() }
                ]).fixedSize().disabled(store.busy)
            }
            if !store.applicationDiscoveryIssues.isEmpty {
                SketchDisclosure("部分发现范围未确认") {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(store.applicationDiscoveryIssues, id: \.self) { Text($0).font(SketchFont.body(12)).textSelection(.enabled) }
                        }
                    }.frame(maxHeight: 90)
                }.font(SketchFont.body(13)).foregroundColor(palette.secondary)
            }
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 3) {
                    ForEach(visibleApplications) { app in
                        Button { selectApplication(app.path) } label: {
                            HStack(spacing: 9) {
                                ApplicationIcon(path: app.path, size: 30)
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(app.name).font(SketchFont.body(13)).fontWeight(.medium).lineLimit(1).truncationMode(.middle)
                                    if app.protectedReason != nil {
                                        Text("已保留 · 查看原因").font(SketchFont.body(12)).foregroundColor(palette.secondary)
                                    }
                                }
                                Spacer(minLength: 0)
                            }.padding(9).frame(maxWidth: .infinity, alignment: .leading).contentShape(Rectangle())
                                .background(store.selectedApp == app.path ? palette.sage : .clear)
                                .clipShape(RoundedRectangle(cornerRadius: 8))
                        }.buttonStyle(.plain).disabled(store.busy)
                            .accessibilityLabel(app.name + (app.protectedReason == nil ? "" : "，已保留"))
                            .accessibilityAddTraits(store.selectedApp == app.path ? .isSelected : [])
                            .help(app.path)
                    }
                    if visibleApplications.isEmpty && !store.busy {
                        Text(store.apps.isEmpty ? "应用列表尚未加载。" : "没有匹配项。可修改搜索，或在“更多”中显示保留项目。")
                            .font(SketchFont.body(13)).foregroundColor(palette.secondary).padding(.vertical, 20)
                        if store.apps.isEmpty { Button("读取应用列表") { store.loadApps() }.buttonStyle(.link) }
                    }
                }.padding(.trailing, 3)
            }
            if let path = store.selectedApp, !visibleApplications.contains(where: { $0.path == path }) {
                Text("当前选择：" + URL(fileURLWithPath: path).deletingPathExtension().lastPathComponent)
                    .font(SketchFont.body(12)).foregroundColor(palette.accent).lineLimit(2)
            }
        }.frame(maxHeight: .infinity, alignment: .topLeading)
    }
    @ViewBuilder private var uninstallDetail: some View {
        if let path = store.selectedApp {
            VStack(alignment: .leading, spacing: 10) {
                applicationContext(path)
                if let report = store.report, report.applicationPath == path {
                    if store.hasSystemUninstallPrerequisites {
                        Button("先核对独占系统组件…") { store.reviewUninstallPrerequisites() }
                            .buttonStyle(.link).font(SketchFont.body(13)).disabled(store.busy)
                    }
                    Toggle("同时清理用户数据", isOn: Binding(get: { store.includeUserData }, set: store.toggleData))
                        .toggleStyle(SketchCheckbox()).font(SketchFont.body(13)).disabled(store.busy)
                        .help("仅包含归属已确认且符合规则的资料、设置和容器。钥匙串及共享资源始终保留。")
                    CandidateList(report: report, showsCategorySidebar: false).environmentObject(store)
                } else {
                    Spacer()
                    Text(store.busy ? "正在核对所选应用…" : "查看卸载明细，核对应用主体与关联文件。")
                        .font(SketchFont.body(15)).foregroundColor(palette.secondary).frame(maxWidth: .infinity)
                    Text("运行中、共享或归属不明的项目会保留。")
                        .font(SketchFont.body(13)).foregroundColor(palette.secondary).frame(maxWidth: .infinity)
                    Spacer()
                }
            }
        } else {
            VStack(spacing: 12) {
                Spacer()
                SketchIcon(symbol: .applications).scaleEffect(1.7).frame(width: 40, height: 40).foregroundColor(palette.accent)
                Text("从左侧选择一个应用").font(SketchFont.body(22)).fontWeight(.semibold)
                Text("这里会显示安装位置、保留原因和卸载明细。")
                    .font(SketchFont.body(14)).foregroundColor(palette.secondary)
                Spacer()
            }.frame(maxWidth: .infinity)
        }
    }
    private func applicationContext(_ path: String) -> some View {
        let app = store.apps.first { $0.path == path }
        return HStack(alignment: .top, spacing: 10) {
            ApplicationIcon(path: path, size: 40)
            VStack(alignment: .leading, spacing: 4) {
                Text(app?.name ?? URL(fileURLWithPath: path).deletingPathExtension().lastPathComponent)
                    .font(SketchFont.body(18)).fontWeight(.semibold).lineLimit(1).truncationMode(.middle)
                Text(path).font(.system(size: 10, design: .monospaced)).lineLimit(1).truncationMode(.middle).textSelection(.enabled).help(path)
                if let identifier = app?.bundleIdentifier, !identifier.isEmpty {
                    Text(identifier).font(.system(size: 10, design: .monospaced)).lineLimit(1).truncationMode(.middle).textSelection(.enabled).help(identifier)
                }
                if let reason = app?.protectedReason { Text(reason).font(SketchFont.body(12)).foregroundColor(palette.secondary).fixedSize(horizontal: false, vertical: true) }
            }.frame(maxWidth: .infinity, alignment: .leading)
        }.padding(13).background(palette.surface).clipShape(RoundedRectangle(cornerRadius: 10))
    }
    private func selectApplication(_ path: String) {
        guard !store.busy, !store.preparationRequired, store.workspace == .uninstall,
              store.selectedApp != path else { return }
        // A newly chosen app must never inherit another app's registered plan.
        store.closeUnusedDependencyReview()
        store.selectedApp = path; store.report = nil; store.plan = nil; store.combinedReview = nil
        store.selected.removeAll(); store.includeUserData = false
        store.retainedItems = []; store.retainedIssues = []; store.message = ""; store.error = false; store.completionNotice = nil
        store.scan()
    }
    private func scanFooter(for workspace: SweepStore.Workspace) -> some View {
        let candidates = workspace == .junk ? (store.overview?.candidates ?? []) : (store.report?.candidates ?? [])
        let selected = candidates.filter { store.selected.contains($0.id) }
        let bytes = selected.filter { $0.identity != nil }.reduce(Int64(0)) { $0 + $1.bytes }
        let unknown = selected.filter { $0.identity == nil }.count
        let hasScan = workspace == .junk ? store.overview != nil : store.report?.applicationPath == store.selectedApp && store.report != nil
        return VStack(spacing: 10) {
            Rectangle().fill(palette.line).frame(height: 1)
            HStack(spacing: 12) {
                if hasScan {
                    Button("重新扫描") { store.scan() }.buttonStyle(.link).font(SketchFont.body(13)).disabled(store.busy)
                    Spacer(minLength: 4)
                    VStack(alignment: .trailing, spacing: 3) {
                        Text("已选 \(selected.count) 项 · " + (unknown == selected.count && unknown > 0 ? "体积未确认" : byteText(bytes) + (unknown > 0 ? " + 未确认" : "")))
                            .font(SketchFont.body(13)).fontWeight(.medium).monospacedDigit()
                        Text("先移入恢复区，仍占用空间").font(SketchFont.body(11)).foregroundColor(palette.secondary)
                    }
                    Button(workspace == .uninstall ? "核对卸载计划" : "核对清理计划") { store.review() }
                        .buttonStyle(PaperButton()).disabled(!store.canReview || store.workspace != workspace)
                        .keyboardShortcut(.defaultAction)
                } else {
                    Text(workspace == .uninstall ? "选择应用后先查看明细" : "扫描不会移动或删除文件")
                        .font(SketchFont.body(13)).foregroundColor(palette.secondary)
                    Spacer(minLength: 4)
                    Button(workspace == .uninstall ? "查看卸载明细" : "扫描系统垃圾") { store.scan() }
                        .buttonStyle(PaperButton()).disabled(store.busy || store.workspace != workspace || (workspace == .uninstall && store.selectedApp == nil))
                        .keyboardShortcut(.defaultAction)
                }
            }
        }
    }
    private var recoveryWorkspace: some View {
        VStack(alignment: .leading, spacing: 12) {
            OptimizationRecoverySection().environmentObject(store)
            if store.recoveryRows.isEmpty && store.optimizationHistory.isEmpty { Spacer(); Text(store.busy ? "正在读取恢复记录…" : "恢复区暂无已登记批次。").foregroundColor(palette.secondary).frame(maxWidth: .infinity); Spacer() }
            else if !store.recoveryRows.isEmpty {
                List(selection: Binding(get:{ store.selectedBatch },set:store.selectRecovery)) {
                    ForEach(store.recoveryRows) { row in
                        let batch = row.summary
                        VStack(alignment: .leading, spacing: 5) {
                            if store.recentRecovery.contains(where: { $0.id == row.id }) { Text("最近操作").font(SketchFont.body(14)) }
                            Text(row.origin.title).font(SketchFont.body(13)).foregroundColor(store.selectedBatch == row.id ? Color(nsColor:.alternateSelectedControlTextColor) : palette.ink)
                            HStack { Text(batch.createdAt, style: .date); Text(batch.createdAt, style: .time); Spacer(); Text(batch.status.title) }.foregroundColor(store.selectedBatch == row.id ? Color(nsColor: .alternateSelectedControlTextColor) : palette.ink)
                            if let issue=batch.issue{Text(issue).font(SketchFont.body(13)).foregroundColor(store.selectedBatch == row.id ? Color(nsColor:.alternateSelectedControlTextColor) : palette.secondary)}
                            Text(batch.hasUnconfirmedObjects ? "隔离文件体积尚未确认" : "隔离文件 \(byteText(batch.isolatedBytes))").foregroundColor(store.selectedBatch == row.id ? Color(nsColor: .alternateSelectedControlTextColor) : palette.secondary)
                            if batch.hasIndependentBackups { Text("独立恢复备份仍保留；选中批次查看详情。").foregroundColor(store.selectedBatch == row.id ? Color(nsColor:.alternateSelectedControlTextColor) : palette.secondary) }
                        }.padding(.vertical, 8).tag(row.id)
                    }
                }.listStyle(.plain)
                if let batch = store.currentBatch {
                    if batch.hasIndependentBackups {
                        Text("独立备份共 \(byteText(batch.independentBackupBytes))" + (batch.backedUpPreferenceCount > 0 ? "，其中 \(batch.backedUpPreferenceCount) 项为应用设置恢复副本。" : "。"))
                            .font(SketchFont.body(13)).foregroundColor(palette.secondary)
                    }
                    ScrollView { VStack(alignment: .leading, spacing: 12) { ForEach(batch.entries) { entry in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(entry.original.path).font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                            Text(entry.message ?? entry.state.title).foregroundColor(palette.secondary)
                        }
                    } }.frame(maxWidth: .infinity, alignment: .leading) }.frame(maxHeight: 160)
                }
            }
            if !store.recoveryIssues.isEmpty {
                SketchDisclosure("未确认的恢复范围") { ForEach(Array(store.recoveryIssues.enumerated()),id:\.offset) { _,issue in Text(issue).font(SketchFont.body(13)).textSelection(.enabled) } }
            }
            if !store.pendingRuns.isEmpty {
                SketchDisclosure("未完成的组合操作") {
                    ForEach(store.pendingRuns) { run in
                        VStack(alignment:.leading,spacing:5) {
                            Text(run.id.uuidString).font(.system(size:11,design:.monospaced))
                            Text(run.issue ?? "上次操作未结束，请核对各来源批次。不会自动继续清理。")
                            ForEach(Array(run.entries.enumerated()),id:\.offset) { _,entry in
                                Text(entry.source.title + " · " + (entry.batchID?.uuidString ?? "批次结果未确认"))
                                    .font(.system(size:11,design:.monospaced)).textSelection(.enabled)
                            }
                        }
                    }
                }
            }
            HStack {
                if store.nextUserCursor != nil { Button("更多用户批次") { store.loadMoreRecovery(.user) }.disabled(store.busy) }
                if store.nextSystemCursor != nil { Button("更多系统批次") { store.loadMoreRecovery(.system) }.disabled(store.busy) }
            }
            HStack {
                Button("刷新记录") { store.loadRecovery() }.buttonStyle(.link).disabled(store.busy)
                Spacer()
                if let batch = store.currentBatch {
                    if batch.canPurge { Button(batch.status == .isolated ? "永久清空…" : "清空恢复副本…") { store.requestPurge() }.buttonStyle(.link).disabled(store.busy || !store.recoveryExecutionAvailable) }
                    if batch.status != .restored && batch.status != .purged && batch.status != .rolledBack && batch.status != .partiallyRestored { Button("撤销此批次") { store.restore() }.buttonStyle(PaperButton()).disabled(store.busy || !store.recoveryExecutionAvailable || batch.previewOnlyReason != nil) }
                }
            }
        }
    }
}

/// Success feedback does not move the list or change workspaces. Errors remain
/// in the persistent status area until the user addresses them.
private struct CompletionNotice: View {
    let text: String
    @Environment(\.colorScheme) private var scheme
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var visible = false
    var body: some View {
        let palette = PaperPalette(scheme:scheme)
        Text(text).font(SketchFont.body(15)).foregroundColor(palette.ink)
            .padding(.horizontal,18).padding(.vertical,12)
            .background(palette.sage).clipShape(RoundedRectangle(cornerRadius: 10))
            .opacity(visible ? 1 : 0)
            .accessibilityHidden(!visible)
            .task(id:text) {
                withAnimation(reduceMotion ? nil : .easeInOut(duration:0.6)) { visible = true }
                do { try await Task.sleep(nanoseconds:5_000_000_000) } catch { return }
                withAnimation(reduceMotion ? nil : .easeInOut(duration:0.8)) { visible = false }
            }
    }
}
