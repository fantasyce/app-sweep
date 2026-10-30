import SwiftUI
import AppSweepCore

@MainActor
struct OptimizationRecoverySection: View {
    @EnvironmentObject private var store: SweepStore
    @Environment(\.colorScheme) private var scheme
    @State private var expanded = true
    private var palette: PaperPalette { PaperPalette(scheme:scheme) }
    var body: some View {
        if !store.optimizationHistory.isEmpty {
            SketchDisclosure("应用精简记录 · \(store.optimizationHistory.count)",isExpanded:$expanded) {
                ScrollView {
                    LazyVStack(alignment:.leading,spacing:16) {
                        ForEach(store.optimizationHistory) { row in
                            let name = URL(fileURLWithPath:row.applicationPath).deletingPathExtension().lastPathComponent
                            VStack(alignment:.leading,spacing:7) {
                                HStack(spacing:9) {
                                    ApplicationIcon(path:row.applicationPath,size:26)
                                    Text(name).font(SketchFont.body(16));Spacer()
                                    Text(row.kind.title).foregroundColor(palette.secondary)
                                }
                                HStack { Text(row.createdAt,style:.date);Text(row.createdAt,style:.time);Spacer();Text(row.status.title) }
                                    .font(SketchFont.body(13))
                                Text(row.storedBytes.map { "记录的保留对象：" + byteText($0) } ?? "保留对象大小未确认")
                                    .font(SketchFont.body(13)).foregroundColor(palette.secondary)
                                if let issue = row.issue { Text(issue).font(SketchFont.body(13)).fixedSize(horizontal:false,vertical:true) }
                                if let limitation = row.limitation { Text(limitation).font(SketchFont.body(13)).foregroundColor(palette.secondary) }
                                if let limitation = row.purgeLimitation { Text(limitation).font(SketchFont.body(13)).foregroundColor(palette.secondary) }
                                SketchDisclosure("路径与记录") {
                                    Text(row.applicationPath).textSelection(.enabled)
                                    Text(row.id.uuidString).textSelection(.enabled)
                                }.font(.system(size:11,design:.monospaced)).foregroundColor(palette.secondary)
                                HStack(spacing:15) {
                                    if row.canInspect { Button("核对中断状态") { store.inspectOptimization(row.id) }.accessibilityLabel("核对" + name + "的中断状态") }
                                    if row.canRestore { Button("核对并恢复原包") { store.restoreOptimization(row.id) }.accessibilityLabel("核对并恢复" + name + "的原包") }
                                    if row.canReviewPurge { Button("永久清空恢复副本…") { store.requestOptimizationPurge(row.id) }.accessibilityLabel("核对并永久清空" + name + "的恢复副本") }
                                    if row.canKeepCurrent { Button("保留当前版本…") { store.reviewKeepingCurrentOptimization(row.id) }.accessibilityLabel("核对是否保留" + name + "的当前版本") }
                                }.buttonStyle(.link).disabled(store.busy)
                                Rectangle().fill(palette.line.opacity(0.25)).frame(height:1)
                            }
                        }
                    }.padding(.top,10).frame(maxWidth:.infinity,alignment:.leading)
                }.frame(minHeight:80,maxHeight:store.recoveryRows.isEmpty ? .infinity : 160)
            }.font(SketchFont.body(15))
        }
        if !store.optimizationIssues.isEmpty {
            SketchDisclosure("未确认的应用精简记录") {
                ForEach(Array(store.optimizationIssues.enumerated()),id:\.offset) { _,issue in Text(issue).font(SketchFont.body(13)).textSelection(.enabled) }
            }
        }
    }
}
extension ApplicationOptimizationBatch.Status {
    var title: String {
        switch self {
        case .preparing:"准备未完成"
        case .prepared:"副本已准备"
        case .publishing:"交换结果待核对"
        case .published:"已精简，原包保留"
        case .undoing:"恢复结果待核对"
        case .restored:"已恢复，副本保留"
        case .stopped:"已停止，请核对保留对象"
        case .needsAttention:"需要核对"
        case .retained:"当前版本与备份均保留"
        case .purging:"副本清空结果待核对"
        case .purged:"恢复副本已永久清空"
        }
    }
}
