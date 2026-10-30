import SwiftUI
import AppSweepCore

@MainActor
struct ApplicationOptimizationSheet: View {
    let selection: SweepStore.OptimizationSelection
    @EnvironmentObject private var store: SweepStore
    @Environment(\.colorScheme) private var scheme
    @State private var kind: ApplicationOptimizationKind = .languages
    @State private var retained = Set<String>()
    @State private var languageOptions: [String] = []
    private var palette: PaperPalette { PaperPalette(scheme:scheme) }
    private var name: String { URL(fileURLWithPath:selection.applicationPath).deletingPathExtension().lastPathComponent }
    var body: some View {
        VStack(alignment:.leading,spacing:16) {
            HStack(spacing:12) {
                ApplicationIcon(path:selection.applicationPath,size:36)
                Text("精简 " + name).font(SketchFont.body(21))
                Spacer()
            }.fixedSize(horizontal:false,vertical:true)
            ScrollView {
            VStack(alignment:.leading,spacing:16) {
            Text("先核对可省略的语言或架构，再确认本次变化。完整原包保留在恢复区，支持撤销。")
                .foregroundColor(palette.secondary).fixedSize(horizontal:false,vertical:true)
            if let result = store.optimizationResult {
                Text(result.status.title).font(SketchFont.body(17))
                Text(store.message).fixedSize(horizontal:false,vertical:true)
                if let issue = result.issue { Text(issue).foregroundColor(palette.secondary) }
            } else {
                Picker("精简内容",selection:$kind) {
                    ForEach(ApplicationOptimizationKind.allCases,id:\.self) { Text($0.title).tag($0) }
                }.pickerStyle(.segmented).disabled(store.busy)
                if kind == .languages {
                    Text("始终保留系统首选语言、英文、Base 与开发者默认语言。额外保留的选择只会减少本次精简范围。")
                        .font(SketchFont.body(14)).foregroundColor(palette.secondary).fixedSize(horizontal:false,vertical:true)
                    if !languageOptions.isEmpty {
                        SketchDisclosure("额外保留的语言") {
                            ScrollView {
                                LazyVGrid(columns:[GridItem(.flexible(),alignment:.leading),GridItem(.flexible(),alignment:.leading)],alignment:.leading,spacing:9) {
                                    ForEach(languageOptions,id:\.self) { language in
                                        Toggle(Locale.current.localizedString(forLanguageCode:language) ?? language,isOn:Binding(get:{ retained.contains(language) },set:{ value in
                                            if value { retained.insert(language) } else { retained.remove(language) }
                                        })).toggleStyle(SketchCheckbox()).disabled(store.busy)
                                    }
                                }.padding(.top,8)
                            }.frame(maxHeight:130)
                        }.font(SketchFont.body(14))
                    }
                }
                if let review = store.optimizationReview {
                    Text("应用包预计减少 " + byteText(review.estimatedReductionBytes)).font(SketchFont.body(17))
                    Text("原包备份继续占用空间；应用包体积减少不等于已释放空间。")
                        .font(SketchFont.body(14)).foregroundColor(palette.secondary)
                    if let limitation = review.limitation { Text(limitation).foregroundColor(palette.secondary).fixedSize(horizontal:false,vertical:true) }
                    if !review.retainedReasons.isEmpty {
                        SketchDisclosure("保留项目与原因") {
                            ScrollView { VStack(alignment:.leading,spacing:8) {
                                ForEach(Array(review.retainedReasons.enumerated()),id:\.offset) { _,reason in Text(reason).font(SketchFont.body(13)).textSelection(.enabled) }
                            }.frame(maxWidth:.infinity,alignment:.leading) }.frame(maxHeight:120)
                        }
                    }
                } else {
                    Text("核对后，在这里查看本次变化和保留原因。").foregroundColor(palette.secondary)
                }
            }
            if store.busy {
                HStack { ProgressView().controlSize(.small);Text(store.canCancel ? "正在核对…" : "正在处理，请等待本次结果…") }
            }
            if store.error && store.optimizationResult == nil && !store.message.isEmpty {
                Text(store.message).padding(10).frame(maxWidth:.infinity,alignment:.leading).background(palette.coral)
                    .accessibilityLabel("未完成。" + store.message)
                if !store.optimizationHistory.isEmpty {
                    Button("查看恢复记录") { openRecovery() }.buttonStyle(.link).disabled(store.busy)
                }
            }
            }.frame(maxWidth:.infinity,alignment:.leading)
            }.frame(minHeight:200,maxHeight:400)
            HStack {
                Button(store.optimizationResult == nil ? "取消" : "关闭") { store.closeOptimization() }
                    .keyboardShortcut(.cancelAction).disabled(store.busy && !store.canCancel)
                Spacer()
                if store.optimizationResult != nil {
                    Button("查看恢复记录") { openRecovery() }.buttonStyle(PaperButton()).disabled(store.busy)
                } else if let review = store.optimizationReview {
                    Button("重新核对") { reviewAgain() }.buttonStyle(.link).disabled(store.busy)
                    Button("保留原包并精简") { store.executeOptimization() }.buttonStyle(PaperButton())
                        .keyboardShortcut(.defaultAction).disabled(store.busy || !review.executionAvailable)
                } else {
                    Button("核对方案") { reviewAgain() }.buttonStyle(PaperButton()).keyboardShortcut(.defaultAction).disabled(store.busy)
                }
            }.fixedSize(horizontal:false,vertical:true)
        }
        .font(SketchFont.body()).foregroundColor(palette.ink).padding(24)
        .frame(minWidth:520,idealWidth:600,maxWidth:680,minHeight:390,idealHeight:540,maxHeight:600)
        .background(PaperBackground())
        .interactiveDismissDisabled(store.busy && !store.canCancel)
        .onChange(of:kind) { _ in store.invalidateOptimizationReview() }
        .onChange(of:retained) { _ in store.invalidateOptimizationReview() }
        .onChange(of:store.optimizationReview?.id) { _ in
            if let review = store.optimizationReview, review.kind == .languages { languageOptions = review.availableLanguages }
        }
        .onDisappear { store.optimizationSheetDisappeared(selection.id) }
    }
    private func reviewAgain() { store.reviewOptimization(kind:kind,retainingLanguages:retained.sorted()) }
    private func openRecovery() { store.closeOptimization();store.switchWorkspace(.recovery) }
}

@MainActor
struct OptimizationKeepCurrentSheet: View {
    let review: ApplicationOptimizationKeepReview
    @EnvironmentObject private var store: SweepStore
    @Environment(\.colorScheme) private var scheme
    private var palette: PaperPalette { PaperPalette(scheme:scheme) }
    var body: some View {
        VStack(alignment:.leading,spacing:16) {
            Text("保留当前版本").font(SketchFont.body(21))
            Text(URL(fileURLWithPath:review.applicationPath).deletingPathExtension().lastPathComponent).font(SketchFont.body(18))
            Text("确认后，将本批次记录为保留当前版本。当前应用与原包备份都会保留；不会释放磁盘空间。")
                .fixedSize(horizontal:false,vertical:true)
            Text("保留的原包备份：" + byteText(review.retainedBackupBytes)).foregroundColor(palette.secondary)
            Text(review.applicationPath).font(.system(size:11,design:.monospaced)).textSelection(.enabled)
            HStack {
                Button("取消") { store.cancelKeepingCurrentOptimization() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button("确认保留当前版本") { store.confirmKeepingCurrentOptimization() }.buttonStyle(PaperButton()).keyboardShortcut(.defaultAction)
            }.disabled(store.busy)
        }.font(SketchFont.body()).foregroundColor(palette.ink).padding(24).frame(width:540).background(PaperBackground())
            .interactiveDismissDisabled(store.busy).onDisappear { store.keepCurrentSheetDisappeared(review.id) }
    }
}

@MainActor
struct OptimizationPurgeSheet: View {
    let review: ApplicationOptimizationPurgeReview
    @EnvironmentObject private var store: SweepStore
    @Environment(\.colorScheme) private var scheme
    @State private var confirmation = ""
    private var palette: PaperPalette { PaperPalette(scheme:scheme) }
    private var phrase: String { "永久清空 " + review.batchID.uuidString }
    var body: some View {
        VStack(alignment:.leading,spacing:16) {
            Text("永久清空恢复副本").font(SketchFont.body(21))
            ScrollView {
                VStack(alignment:.leading,spacing:14) {
                    Text(URL(fileURLWithPath:review.applicationPath).deletingPathExtension().lastPathComponent).font(SketchFont.body(18))
                    Text(review.removesOriginal ? "将永久删除本批次保留的原包，之后无法再从此批次恢复原包。" : "将永久删除本批次保留的精简副本。已恢复的原安装包继续保留。")
                        .fixedSize(horizontal:false,vertical:true)
                    Text("仅处理刚核对的恢复副本。当前安装位置与用户资料继续保留；此操作无法撤销。")
                        .fixedSize(horizontal:false,vertical:true)
                    Text("副本大小：" + byteText(review.retainedBackupBytes)).foregroundColor(palette.secondary)
                    Text("文件体积与实际可用空间变化可能不同，完成后不按此数值宣称已释放空间。")
                        .font(SketchFont.body(13)).foregroundColor(palette.secondary).fixedSize(horizontal:false,vertical:true)
                    SketchDisclosure("当前应用与批次") {
                        Text(review.applicationPath).textSelection(.enabled)
                        Text(review.batchID.uuidString).textSelection(.enabled)
                    }.font(.system(size:11,design:.monospaced))
                    if let limitation = review.limitation {
                        Text(limitation).foregroundColor(palette.secondary).fixedSize(horizontal:false,vertical:true)
                    } else {
                        Text("输入下方完整确认文字：").font(SketchFont.body(14))
                        Text(phrase).font(.system(size:12,design:.monospaced)).textSelection(.enabled)
                        TextField("永久清空与批次编号",text:$confirmation)
                            .textFieldStyle(.roundedBorder).font(.system(size:12,design:.monospaced))
                            .accessibilityLabel("永久清空确认文字").disabled(store.busy)
                    }
                    if store.busy { HStack { ProgressView().controlSize(.small);Text("正在核对并处理，请等待本次结果…") } }
                }.frame(maxWidth:.infinity,alignment:.leading)
            }.frame(minHeight:180,maxHeight:380)
            HStack {
                Button("取消") { store.cancelOptimizationPurge() }.keyboardShortcut(.cancelAction).disabled(store.busy)
                Spacer()
                Button("永久清空此副本") { store.confirmOptimizationPurge(confirmation:confirmation) }
                    .buttonStyle(PaperButton(caution:true)).keyboardShortcut(.defaultAction)
                    .disabled(store.busy || !review.executionAvailable || confirmation != phrase)
            }.fixedSize(horizontal:false,vertical:true)
        }.font(SketchFont.body()).foregroundColor(palette.ink).padding(24)
            .frame(minWidth:520,idealWidth:600,maxWidth:680,minHeight:380,idealHeight:530,maxHeight:600)
            .background(PaperBackground()).interactiveDismissDisabled(store.busy)
            .onDisappear { store.optimizationPurgeSheetDisappeared(review.id) }
    }
}
