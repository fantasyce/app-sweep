import SwiftUI
import AppSweepCore

protocol CandidatePresentation {
    var candidates: [Candidate] { get }
    var complete: Bool { get }
    var issues: [String] { get }
    func selectableCandidates(includeUserData: Bool) -> [Candidate]
}
extension ScanReport: CandidatePresentation { }
extension CleanupOverview: CandidatePresentation {
    var issues: [String] { unconfirmedIssues }
}

@MainActor
struct CandidateList<Report: CandidatePresentation>: View {
    let report: Report
    var showsCategorySidebar = true
    @State private var search = ""
    @State private var showRetained = false
    @State private var selectedCategory: CandidateDisplaySection?
    @State private var largestFirst = true
    @EnvironmentObject private var store: SweepStore
    @Environment(\.colorScheme) private var scheme
    private var palette: PaperPalette { PaperPalette(scheme: scheme) }

    var body: some View {
        let selectableIDs = Set(report.selectableCandidates(includeUserData: store.includeUserData).map(\.id))
        let dataSelectableIDs = Set(report.selectableCandidates(includeUserData: true).filter(\.executionAllowed).map(\.id))
        let projection = CandidateListProjection(candidates: report.candidates, selectableIDs: selectableIDs)
        let latestBackupIDs = Set(DeviceBackupCatalog.groups(in: report.candidates).flatMap(\.latestCandidateIDs))
        let category = selectedCategory.flatMap { projection.sections.contains($0) ? $0 : nil }
        let rows = visibleRows(projection.rows, category: category)
        let activeRows = rows.filter { $0.actionable || requiresDataOptIn($0, dataSelectableIDs: dataSelectableIDs) }
        let retainedRows = rows.filter { !$0.actionable && !requiresDataOptIn($0, dataSelectableIDs: dataSelectableIDs) }
        return HStack(alignment: .top, spacing: 18) {
            if showsCategorySidebar {
                categorySidebar(projection, selected: category, dataSelectableIDs: dataSelectableIDs)
                    .frame(width: 180)
                Rectangle().fill(palette.line).frame(width: 1)
            }
            ScrollViewReader { proxy in
                VStack(alignment: .leading, spacing: 12) {
                    toolbar(projection, selected: category, proxy: proxy)
                    if store.workspace == .junk && report.candidates.contains(where: \.userData) {
                        Toggle("允许选择个人资料", isOn: Binding(get: { store.includeUserData }, set: { store.toggleData($0) }))
                            .toggleStyle(SketchCheckbox()).font(SketchFont.body(13)).disabled(store.busy)
                            .help("开启后仍需逐项选择。备份、文稿历史和模型等个人资料不会自动勾选。")
                    }
                    if !report.complete {
                        SketchDisclosure(report.candidates.isEmpty ? "扫描未完成 · 查看原因" : "部分范围未确认 · 查看原因") {
                            ScrollView {
                                VStack(alignment: .leading, spacing: 8) {
                                    ForEach(Array(report.issues.enumerated()), id: \.offset) { _, issue in
                                        Text(issue).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                                    }
                                }.frame(maxWidth: .infinity, alignment: .leading)
                            }.frame(maxHeight: 100)
                        }.font(SketchFont.body(12)).padding(10).background(palette.coral)
                            .clipShape(RoundedRectangle(cornerRadius: 8))
                    }
                    HStack(spacing: 12) {
                        Text(category?.title ?? "全部项目").font(SketchFont.body(17)).fontWeight(.semibold)
                        Spacer(minLength: 0)
                        Button("建议选择") { store.selectRecommended() }
                            .help("按完整项目组选择已确认的建议项目；个人资料与需手选项目继续保留。")
                        Button("取消选择") { store.clearSelection() }
                    }.buttonStyle(.link).font(SketchFont.body(12)).disabled(store.busy)
                    if activeRows.contains(where: { $0.candidate.userData }) {
                        Text(store.includeUserData
                            ? (store.workspace == .uninstall ? "已包含符合规则的用户资料，可逐项调整。" : "个人资料需逐项选择；移入恢复区后仍占用空间。")
                            : "个人资料默认保留，开启上方选项后可逐项选择。")
                            .font(SketchFont.body(12)).foregroundColor(palette.secondary)
                    }
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 0) {
                            ForEach(activeRows) { row in
                                candidateRow(row, selectableIDs: selectableIDs,
                                    requiresOptIn: requiresDataOptIn(row, dataSelectableIDs: dataSelectableIDs), latestBackupIDs: latestBackupIDs)
                            }
                            if !retainedRows.isEmpty {
                                if activeRows.isEmpty {
                                    Text("保留项目 · \(retainedRows.reduce(0) { $0 + $1.members.count }) 项")
                                        .font(SketchFont.body(14)).foregroundColor(palette.secondary).padding(.vertical, 9)
                                } else {
                                    SketchDisclosure("保留项目 · \(retainedRows.reduce(0) { $0 + $1.members.count }) 项", isExpanded: $showRetained) { EmptyView() }
                                        .font(SketchFont.body(14)).foregroundColor(palette.secondary).padding(.top, 9)
                                }
                                if showRetained || activeRows.isEmpty {
                                    ForEach(retainedRows) { row in
                                        candidateRow(row, selectableIDs: selectableIDs, requiresOptIn: false, latestBackupIDs: latestBackupIDs)
                                    }
                                }
                            }
                            if rows.isEmpty {
                                Text(search.isEmpty ? "此分类暂无项目。" : "没有匹配项。可清空搜索，或选择其他分类。")
                                    .font(SketchFont.body(14)).foregroundColor(palette.secondary)
                                    .frame(maxWidth: .infinity, alignment: .center).padding(.vertical, 36)
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(.trailing, 6)
                    }
                }.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            }
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func categorySidebar(_ projection: CandidateListProjection, selected: CandidateDisplaySection?, dataSelectableIDs: Set<UUID>) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("分类 · 已统计容量").font(SketchFont.body(12)).fontWeight(.medium).foregroundColor(palette.secondary).padding(.horizontal, 8)
            ScrollView {
                VStack(alignment: .leading, spacing: 4) {
                    categoryButton(title: "全部项目", category: nil, rows: projection.rows, selected: selected, dataSelectableIDs: dataSelectableIDs)
                    ForEach(projection.sections) { section in
                        categoryButton(title: section.title, category: section,
                            rows: projection.rows.filter { $0.section == section }, selected: selected, dataSelectableIDs: dataSelectableIDs)
                    }
                }.padding(.trailing, 3)
            }
            Text("容量含保留项目；未确认的体积另行标注。")
                .font(SketchFont.body(12)).foregroundColor(palette.secondary).padding(.horizontal, 8)
        }
    }

    private func categoryButton(title: String, category: CandidateDisplaySection?, rows: [CandidateDisplayRow], selected: CandidateDisplaySection?, dataSelectableIDs: Set<UUID>) -> some View {
        let count = rows.reduce(0) { $0 + $1.members.count }
        let retained = rows.filter { !$0.actionable && !requiresDataOptIn($0, dataSelectableIDs: dataSelectableIDs) }.reduce(0) { $0 + $1.members.count }
        let unknown = rows.reduce(0) { $0 + $1.unknownCount }
        let bytes = rows.reduce(Int64(0)) { $0 + $1.knownBytes }
        return Button { selectedCategory = category } label: {
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(SketchFont.body(14)).fontWeight(.medium).foregroundColor(selected == category ? palette.accent : palette.ink)
                HStack(alignment: .firstTextBaseline, spacing: 4) {
                    Text(unknown == count && count > 0 ? "未统计" : byteText(bytes)).font(.system(size: 12, design: .monospaced))
                    Spacer(minLength: 0)
                    Text("\(count) 项").font(SketchFont.body(12))
                }.foregroundColor(palette.secondary)
                if retained > 0 || (unknown > 0 && unknown < count) {
                    Text([retained > 0 ? "保留 \(retained) 项" : nil,
                          unknown > 0 && unknown < count ? "\(unknown) 项未统计" : nil].compactMap { $0 }.joined(separator: " · "))
                        .font(SketchFont.body(11)).foregroundColor(palette.secondary)
                }
            }.padding(10).frame(maxWidth: .infinity, alignment: .leading)
                .background(selected == category ? palette.sage : Color.clear)
                .clipShape(RoundedRectangle(cornerRadius: 8))
                .contentShape(Rectangle())
        }.buttonStyle(.plain).accessibilityAddTraits(selected == category ? .isSelected : [])
            .accessibilityLabel(title + "，\(count) 项，" + (unknown == count && count > 0 ? "体积未统计" : "已统计 " + byteText(bytes)) + "，保留 \(retained) 项")
    }

    private func toolbar(_ projection: CandidateListProjection, selected: CandidateDisplaySection?, proxy: ScrollViewProxy) -> some View {
        let applicationPaths = Array(Set(report.candidates.compactMap(\.applicationPath))).sorted()
        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                TextField("搜索名称或路径", text: $search).textFieldStyle(.roundedBorder)
                    .accessibilityLabel("筛选扫描结果")
                SketchMenu(title: largestFirst ? "按大小" : "按名称", items: [
                    SketchMenuItem(id: "size", title: "按大小", selected: largestFirst) { largestFirst = true },
                    SketchMenuItem(id: "name", title: "按名称", selected: !largestFirst) { largestFirst = false }
                ]).fixedSize()
            }
            if !showsCategorySidebar || applicationPaths.count > 1 {
                HStack(spacing: 8) {
                    if !showsCategorySidebar {
                        SketchMenu(title: selected?.title ?? "全部类别", items:
                            [SketchMenuItem(id: "all", title: "全部类别", selected: selected == nil) { selectedCategory = nil }] +
                            projection.sections.map { section in
                                SketchMenuItem(id: section.id, title: section.title, selected: selected == section) { selectedCategory = section }
                            })
                    }
                    if applicationPaths.count > 1 {
                        SketchMenu(title: "按应用定位", items: applicationPaths.map { path in
                            SketchMenuItem(id: path, title: applicationNavigationTitle(path, paths: applicationPaths)) {
                                if let row = projection.rows.first(where: { $0.members.contains { $0.applicationPath == path } }) {
                                    search = ""; selectedCategory = nil
                                    if !row.actionable { showRetained = true }
                                    Task { @MainActor in
                                        await Task.yield()
                                        proxy.scrollTo(row.id, anchor: .center)
                                    }
                                }
                            }
                        }).accessibilityHint("跳转到关联项目后，请在明细中核对归属。")
                    }
                    Spacer(minLength: 0)
                }
            }
        }.disabled(store.busy)
    }

    private func candidateRow(_ row: CandidateDisplayRow, selectableIDs: Set<UUID>, requiresOptIn: Bool, latestBackupIDs: Set<UUID>) -> some View {
        let candidate = row.candidate
        let grouped = row.members.count > 1
        return VStack(alignment: .leading, spacing: 3) {
            if row.actionable || requiresOptIn {
                Toggle(isOn: Binding(get: { store.selected.contains(candidate.id) }, set: { store.select(candidate, enabled: $0) })) {
                    candidateLabel(row)
                }.toggleStyle(SketchCheckbox()).disabled(store.busy || requiresOptIn)
                    .accessibilityLabel("\(candidateTitle(candidate))，\(grouped ? "关联缓存组，共 \(row.members.count) 项" : "单项")，\(requiresOptIn ? "个人资料默认保留" : "可选择清理")")
                    .accessibilityHint(candidate.selectionGroupID == nil ? "" : "应用主体及后台组件、关联缓存会按组选择和处理")
            } else {
                HStack(spacing: 8) {
                    Text("保留").font(SketchFont.body(12)).foregroundColor(palette.secondary)
                    candidateLabel(row)
                }
            }
            HStack(spacing: 6) {
                Text(row.section.title)
                if grouped { Text("· \(row.members.count) 项一起处理") }
                else if !candidate.selectedByDefault && row.actionable { Text("· 主动选择") }
                if requiresOptIn { Text("· 个人资料") }
            }.font(SketchFont.body(12)).foregroundColor(palette.secondary).padding(.leading, 22)
            if candidate.category == .deviceBackup, let details = candidate.deviceBackupDetails {
                HStack(spacing: 6) {
                    Text(details.deviceName).lineLimit(1)
                    Text(details.date, style: .date)
                    Text(details.encrypted ? "标记为加密" : "标记为未加密")
                    if latestBackupIDs.contains(candidate.id) {
                        Text("最新 · 默认保留").foregroundColor(palette.accent)
                    }
                }.font(SketchFont.body(12)).foregroundColor(palette.secondary).padding(.leading, 22)
            }
            SketchDisclosure(grouped ? "查看组内 \(row.members.count) 项" : (row.actionable || requiresOptIn ? "查看详情" : "查看保留原因")) {
                VStack(alignment: .leading, spacing: 6) {
                    if !row.actionable { Text(requiresOptIn ? "个人资料默认保留；开启“允许选择个人资料”后再逐项选择。" : retentionText(candidate, selectableIDs: selectableIDs)).font(SketchFont.body(13)) }
                    else if !candidate.selectedByDefault { Text(candidate.defaultSelectionReason).font(SketchFont.body(13)) }
                    if grouped {
                        ForEach(row.members) { member in
                            HStack(alignment: .top) {
                                Text(URL(fileURLWithPath: member.path).lastPathComponent)
                                Spacer(minLength: 4)
                                Text(member.identity == nil ? "未统计" : byteText(member.bytes))
                            }.font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                        }
                    }
                    Text(grouped ? URL(fileURLWithPath: candidate.path).deletingLastPathComponent().path : candidate.path)
                        .font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                    ForEach(Array(candidate.evidence.enumerated()), id: \.offset) { _, evidence in
                        Text((evidence.verified ? "已核对：" : "线索：") + evidence.detail).font(SketchFont.body(12))
                    }
                    Text("规则：" + candidate.rule).font(.system(size: 10, design: .monospaced))
                    if candidate.ignoredReason == nil {
                        Button(grouped ? "以后保留此缓存组" : "以后保留此项") { store.ignore(candidate) }
                            .buttonStyle(.link).disabled(store.busy).accessibilityLabel("以后保留：" + candidateTitle(candidate))
                            .help("加入保留列表，后续扫描不再选择此项目；已有计划需要重新核对。")
                    }
                }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 4)
            }.font(SketchFont.body(12)).padding(.leading, 18)
        }.padding(.vertical, 11).id(row.id)
            .overlay(alignment: .bottom) { Rectangle().fill(palette.line).frame(height: 1) }
    }

    private func candidateLabel(_ row: CandidateDisplayRow) -> some View {
        let candidate = row.candidate
        let owner = candidate.applicationPath.map { URL(fileURLWithPath: $0).deletingPathExtension().lastPathComponent }
            ?? URL(fileURLWithPath: candidate.path).deletingLastPathComponent().lastPathComponent
        return HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(row.members.count > 1 ? owner + " · 缓存组" : candidateTitle(candidate))
                .font(SketchFont.body(14)).fontWeight(.medium).lineLimit(1).truncationMode(.middle)
                .help(row.members.count > 1 ? owner + " · 缓存组" : candidateTitle(candidate))
            Spacer(minLength: 4)
            Text(row.unknownCount == row.members.count ? "未统计" : byteText(row.knownBytes) + (row.unknownCount > 0 ? " + 未统计" : ""))
                .font(.system(size: 12, design: .monospaced)).foregroundColor(palette.secondary).fixedSize()
        }
    }
    private func requiresDataOptIn(_ row: CandidateDisplayRow, dataSelectableIDs: Set<UUID>) -> Bool {
        store.workspace == .junk && !store.includeUserData && row.candidate.userData && row.members.allSatisfy { dataSelectableIDs.contains($0.id) }
    }
    private func visibleRows(_ rows: [CandidateDisplayRow], category: CandidateDisplaySection?) -> [CandidateDisplayRow] {
        rows.filter { row in
            (category == nil || row.section == category) && row.members.contains { matchesSearch($0) }
        }.sorted { left, right in
            if largestFirst && left.knownBytes != right.knownBytes { return left.knownBytes > right.knownBytes }
            return candidateTitle(left.candidate).localizedStandardCompare(candidateTitle(right.candidate)) == .orderedAscending
        }
    }
    private func matchesSearch(_ item: Candidate) -> Bool {
        search.isEmpty || item.path.localizedCaseInsensitiveContains(search) ||
        (item.applicationPath?.localizedCaseInsensitiveContains(search) ?? false) ||
        (item.displayName?.localizedCaseInsensitiveContains(search) ?? false) ||
        CandidateDisplaySection.section(for: item).title.localizedCaseInsensitiveContains(search)
    }
    private func applicationNavigationTitle(_ path: String, paths: [String]) -> String {
        let url = URL(fileURLWithPath: path), name = url.deletingPathExtension().lastPathComponent
        let duplicates = paths.filter { URL(fileURLWithPath: $0).deletingPathExtension().lastPathComponent == name }.count
        return duplicates > 1 ? name + " · " + url.deletingLastPathComponent().path : name
    }
    private func retentionText(_ item: Candidate, selectableIDs: Set<UUID>) -> String {
        if let reason = item.ignoredReason { return reason }
        if let reason = item.retentionReason { return reason }
        if !item.executionAllowed { return "当前平台或规则仅支持预览，此项目保留。" }
        if item.selectionGroupID != nil && !selectableIDs.contains(item.id) { return "关联对象尚未全部确认，整组保留。" }
        if item.userData && !store.includeUserData { return store.workspace == .junk ? "个人资料默认保留；开启“允许选择个人资料”后可逐项选择。" : "默认保留用户数据；需主动开启“同时清理用户数据”。" }
        if !report.complete { return "此项目依赖的扫描范围尚未确认，不能选择。" }
        return "缺少可供计划核对的归属或文件身份依据。"
    }
    private func candidateTitle(_ item: Candidate) -> String {
        switch item.path {
        case "/System/Library/Caches": return "macOS 系统缓存"
        case "/Library/Caches": return "系统公共缓存"
        case "/private/var/folders": return "系统临时状态"
        default:
            if item.category == .deviceBackup { return item.displayName ?? URL(fileURLWithPath: item.path).lastPathComponent }
            if item.userData, let displayName = item.displayName { return displayName }
            if item.category == .development { return item.displayName ?? "Xcode 构建中间文件" }
            if item.category == .cache, ["foundation-http-payload-v1", "foundation-http-response-v1"].contains(item.rule), let application = item.applicationPath {
                return URL(fileURLWithPath: application).deletingPathExtension().lastPathComponent + " · 网络响应缓存"
            }
            if item.category == .backgroundComponent { return item.displayName ?? "应用后台组件" }
            if (item.category == .cache || item.category == .log), let application = item.applicationPath {
                return URL(fileURLWithPath: application).deletingPathExtension().lastPathComponent + " · " + URL(fileURLWithPath: item.path).lastPathComponent
            }
            return item.displayName ?? URL(fileURLWithPath: item.path).lastPathComponent
        }
    }
}
@MainActor
struct CleanupIgnoreSheet: View {
    let dismiss: () -> Void
    @EnvironmentObject private var store: SweepStore
    @Environment(\.colorScheme) private var scheme
    var body: some View {
        VStack(alignment:.leading,spacing:18) {
            Text("保留列表").font(SketchFont.body(22)).fontWeight(.semibold)
            Text("勾选分类即可在后续扫描中持续保留，也可从候选明细保留单个项目。取消保留后仍需重新扫描，已有恢复操作不受影响。")
                .font(SketchFont.body(14))
            if store.busy { ProgressView("正在核对保留设置…") }
            if !store.message.isEmpty {
                Text(store.message).font(SketchFont.body(14)).padding(10)
                    .background(store.error ? PaperPalette(scheme:scheme).coral : PaperPalette(scheme:scheme).sage)
                    .accessibilityLabel((store.error ? "未完成。" : "状态。") + store.message)
            }
            if let list = store.ignoreList {
                ScrollView {
                    LazyVStack(alignment:.leading,spacing:14) {
                        Text("持续保留分类").font(SketchFont.body(16)).fontWeight(.semibold)
                        ForEach(CleanupIgnoreList.supportedCategories,id:\.self) { category in
                            Toggle(category.title,isOn:Binding(get:{ list.categories.contains(category) },set:{ store.setCategoryIgnored(category,ignored:$0) }))
                                .toggleStyle(SketchCheckbox()).disabled(store.busy)
                                .accessibilityLabel("持续保留分类：" + category.title)
                                .accessibilityHint("此设置也适用于应用卸载。取消保留不会自动选择或清理。")
                        }
                        Text("这些设置也适用于应用卸载。个人资料仍默认保留；取消分类保留不会扩大清理权限。")
                            .font(SketchFont.body(13)).foregroundColor(PaperPalette(scheme:scheme).secondary)
                        Text("单独保留的项目").font(SketchFont.body(16)).fontWeight(.semibold).padding(.top,6)
                        if list.paths.isEmpty { Text("尚未单独保留项目。").foregroundColor(PaperPalette(scheme:scheme).secondary) }
                        ForEach(list.paths,id:\.self) { path in
                            HStack(alignment:.top,spacing:16) {
                                Text(path).font(.system(size:11,design:.monospaced)).textSelection(.enabled)
                                    .frame(maxWidth:.infinity,alignment:.leading)
                                Button("移出列表") { store.removeIgnore(path:path) }
                                    .buttonStyle(.link).disabled(store.busy)
                                    .accessibilityLabel("移出保留列表：" + path)
                            }
                        }
                    }.padding(.trailing,8)
                }
            } else if !store.busy {
                Text("保留设置未能读取。请先核对原因；未确认时不会继续清理。")
            }
            Spacer(minLength:0)
            HStack {
                Button("重新读取") { store.loadIgnores() }.disabled(store.busy)
                Spacer()
                Button("完成") { dismiss() }.buttonStyle(PaperButton()).keyboardShortcut(.cancelAction).disabled(store.busy)
            }
        }.padding(28).frame(width:620,height:460).font(SketchFont.body())
            .foregroundColor(PaperPalette(scheme:scheme).ink).background(PaperBackground()).accentColor(PaperPalette(scheme:scheme).accent)
    }
}
@MainActor
struct PlanSheet: View {
    let plan: CleanupPlan
    @EnvironmentObject private var store: SweepStore
    @Environment(\.presentationMode) private var presentation
    @Environment(\.colorScheme) private var scheme
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("核对本次计划").font(SketchFont.body(22)).fontWeight(.semibold)
            Text("\(plan.items.count) 项 · \(byteText(plan.bytes))\n" + (plan.documentHistoryCount > 0 ? "文稿历史会独立备份后经 macOS 移除，当前文稿保留。撤销会添加为新的历史版本。\n" : "") + (plan.preferenceCount > 0 ? "文件会移入恢复区；另有 \(plan.preferenceCount) 项应用设置会独立备份后通过 macOS 清除。均可在恢复区撤销，不自动永久删除备份。" : "所选内容会保留可恢复副本，不会自动永久删除。空间暂不释放。"))
            if let issues = plan.retainedIssues, !issues.isEmpty {
                Text("还有未确认范围，本次不会处理；不能视为已全部清理。").font(SketchFont.body(14)).foregroundColor(PaperPalette(scheme:scheme).secondary)
            }
            ScrollView { VStack(alignment: .leading, spacing: 14) { ForEach(plan.items) { item in VStack(alignment: .leading, spacing: 4) { Text(item.category.title); Text(item.path).font(.system(size: 11, design: .monospaced)).textSelection(.enabled) } } }.frame(maxWidth: .infinity, alignment: .leading) }
            Text("执行前会重新检查身份、归属及运行状态；任一项未确认时停止。未验收的平台仅允许扫描。")
                .foregroundColor(PaperPalette(scheme: scheme).secondary)
            HStack { Button("返回修改") { store.plan = nil }.keyboardShortcut(.cancelAction); Spacer(); Button(plan.preferenceCount > 0 || plan.documentHistoryCount > 0 ? "确认处理并保留恢复副本" : "移入恢复区") { store.execute() }.buttonStyle(PaperButton()).disabled(!store.executionAvailable).keyboardShortcut(.defaultAction) }
        }.padding(28).frame(width: 620, height: 460).font(SketchFont.body()).foregroundColor(PaperPalette(scheme: scheme).ink).background(PaperBackground()).accentColor(PaperPalette(scheme: scheme).accent)
    }
}
@MainActor
struct CombinedPlanSheet: View {
    let review: CleanupReview
    @EnvironmentObject private var store: SweepStore
    @Environment(\.colorScheme) private var scheme
    var body: some View {
        VStack(alignment:.leading,spacing:18) {
            Text("核对本次计划").font(SketchFont.body(22)).fontWeight(.semibold)
            Text("\(review.items.count) 项。将保留可恢复副本，尚不释放磁盘空间。")
            if review.items.contains(where: { $0.rule == "document-history-versions-v1" }) {
                Text("文稿历史会独立备份后经 macOS 移除，当前文稿保留。撤销会添加为新的历史版本。")
                    .font(SketchFont.body(14)).foregroundColor(PaperPalette(scheme:scheme).secondary)
            }
            if review.applicationPrerequisite != nil {
                Text("本步仅处理已确认的独占系统组件，应用主体和资料仍保留。完成后需重新核对并确认卸载应用；这一步不表示应用已经卸载。")
                    .font(SketchFont.body(14)).padding(10).background(PaperPalette(scheme:scheme).coral)
            }
            if review.items.contains(where:{ $0.category == .deviceBackup }) {
                Text("本地设备备份包含个人资料。移入恢复区期间，Finder无法使用它恢复设备。请先结束备份/同步并断开设备；本程序未验证备份的设备恢复有效性。")
                    .font(SketchFont.body(14)).padding(10).background(PaperPalette(scheme:scheme).coral)
            }
            Text("任一批次失败即停止，尝试撤销已经完成的批次；状态不明或恢复冲突会保留记录，需要核对。")
                .foregroundColor(PaperPalette(scheme:scheme).secondary)
            if !review.retainedIssues.isEmpty { Text("部分扫描范围尚未确认，本次不会处理。不能视为已全部清理。").foregroundColor(PaperPalette(scheme:scheme).secondary) }
            ScrollView { VStack(alignment:.leading,spacing:14) {
                if review.items.contains(where: { ["mail-download-copy-v1", "ai-huggingface-local-repository-v1"].contains($0.rule) }) {
                    Text("邮件下载副本可能包含个人编辑；本地模型不保证可再次下载。请确认这些是你不再需要的资料。")
                        .font(SketchFont.body(14)).foregroundColor(PaperPalette(scheme:scheme).secondary)
                }
                ForEach(review.items) { item in
                    VStack(alignment:.leading,spacing:4) {
                        Text(item.category.title)
                        Text(item.path).font(.system(size:11,design:.monospaced)).textSelection(.enabled)
                    }
                }
            }.frame(maxWidth:.infinity,alignment:.leading) }
            HStack {
                Button("返回修改") { store.combinedReview = nil }.keyboardShortcut(.cancelAction)
                Spacer()
                Button(review.items.contains(where: { $0.rule == "document-history-versions-v1" }) ? "确认处理并保留恢复副本" : "移入恢复区") { store.execute() }.buttonStyle(PaperButton())
                    .disabled(!review.items.allSatisfy(\.executionAllowed)).keyboardShortcut(.defaultAction)
            }
        }.padding(28).frame(width:620,height:460).font(SketchFont.body())
            .foregroundColor(PaperPalette(scheme:scheme).ink).background(PaperBackground()).accentColor(PaperPalette(scheme:scheme).accent)
    }
}
@MainActor
struct PurgeSheet: View {
    let batch: RecoveryManifest
    @EnvironmentObject private var store: SweepStore
    @Environment(\.colorScheme) private var scheme
    private var phrase: String { "永久清空 " + batch.id.uuidString }
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text(batch.status == .isolated ? "永久清空此批次" : "永久清空恢复副本").font(SketchFont.body(22)).fontWeight(.semibold)
            Text(batch.status == .isolated ? "此操作不能撤销。仅处理本批次登记且身份核对通过的恢复区对象。" : "清空仍保存在恢复区的独立备份，已恢复到原位置的文件保留。此操作不能撤销。")
            Text("请输入以下完整内容：")
            Text(phrase).font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
            TextField("确认内容", text: $store.purgeConfirmation).textFieldStyle(.roundedBorder)
            HStack { Button("保留文件") { store.purgeBatch = nil }.keyboardShortcut(.cancelAction); Spacer(); Button("永久清空") { store.purge() }.buttonStyle(PaperButton(caution: true)).disabled(store.purgeConfirmation != phrase) }
        }.padding(28).frame(width: 620).font(SketchFont.body()).foregroundColor(PaperPalette(scheme: scheme).ink).background(PaperBackground()).accentColor(PaperPalette(scheme: scheme).accent)
    }
}
