import SwiftUI
import AppSweepCore

@MainActor
struct AccessOnboardingView: View {
    let continueToWorkspace: () -> Void
    @EnvironmentObject private var store: SweepStore
    @Environment(\.colorScheme) private var scheme
    @AppStorage("accessSettingsRequested") private var settingsRequested = false
    private var palette: PaperPalette { PaperPalette(scheme: scheme) }

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            Text("App Sweep").font(SketchFont.body(18)).fontWeight(.semibold).foregroundColor(palette.accent)
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    Text("先准备好扫描访问").font(SketchFont.body(24)).fontWeight(.semibold)
                    Text("允许读取应用缓存和残留，扫描后由你决定处理哪些内容。")
                        .foregroundColor(palette.secondary)
                    VStack(alignment: .leading, spacing: 18) {
                        status("应用资料访问", scope: .user)
                        status("系统清理服务", scope: .system)
                    }.padding(20).frame(maxWidth: .infinity, alignment: .leading)
                        .background(palette.surface).clipShape(RoundedRectangle(cornerRadius: 10))
                    Button("打开完全磁盘访问设置") {
                        settingsRequested = true
                        store.openPrivacySettings()
                    }.buttonStyle(PaperButton()).disabled(store.checkingAccess)
                    Text(settingsRequested ? "为 App Sweep 开启后，按系统提示退出并重新打开，再核对访问。" : "在系统设置中授权。系统服务安装如需管理员认证，会另行说明。")
                        .font(SketchFont.body(14)).foregroundColor(palette.secondary)
                    SketchDisclosure("安装或修复系统清理服务") {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("打开与当前应用同一份下载中的 App-Sweep-System-Service-2.1.0.pkg，按安装器提示完成认证，然后返回核对访问。安装包会校验配套应用与服务，不匹配时不会启用。")
                                .fixedSize(horizontal: false, vertical: true)
                            Button("选择配套服务安装包…") { store.chooseServiceInstaller() }
                                .buttonStyle(PaperButton()).disabled(store.checkingAccess)
                            if !store.accessMessage.isEmpty { Text(store.accessMessage) }
                        }.font(SketchFont.body(14)).foregroundColor(palette.secondary)
                    }
                    SketchDisclosure("访问范围与说明") {
                        VStack(alignment: .leading, spacing: 10) {
                            Text("完全磁盘访问允许读取邮件、信息等受保护资料，可随时在系统设置撤销。访问检查是只读探测，不读取探测数据库内容，也不代表任意文件都能处理。")
                            Text("系统服务的连接与读取权限分别核对。扫描和执行仍检查实际归属、运行状态与保护规则。")
                            Text(Bundle.main.bundleURL.path).font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                            Text("设置列表中没有 App Sweep 时，点击“+”选择上述应用。")
                        }.font(SketchFont.body(14)).foregroundColor(palette.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 12)
            }
            HStack {
                Button("稍后设置，使用受限范围") { finish() }.buttonStyle(.link).disabled(store.checkingAccess)
                Spacer()
                if store.checkingAccess { ProgressView().controlSize(.small); Text("正在核对访问…").font(SketchFont.body(14)) }
                else if store.accessReadiness.state == .ready {
                    Button("开始使用") { finish() }.buttonStyle(PaperButton())
                } else {
                    Button("核对访问") { store.checkPreparation() }.buttonStyle(PaperButton())
                }
            }
        }.padding(40).frame(maxWidth: 760, maxHeight: .infinity, alignment: .leading)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .font(SketchFont.body(15)).foregroundColor(palette.ink)
            .background(PaperBackground()).accentColor(palette.accent)
    }
    private func finish() {
        settingsRequested = false
        store.finishPreparation()
        continueToWorkspace()
    }
    private func status(_ title: String, scope: AccessReadiness.Scope) -> some View {
        let result = store.accessReadiness.evidence.first { $0.scope == scope }?.result
        let text: String
        switch result {
        case .readable: text = "读取检查通过"
        case .denied: text = "读取受限 · 请检查授权或重新打开"
        case .unavailable: text = "未连接 · 检查服务安装"
        case .missing, .unknown: text = "尚未确认 · 扫描时保留未知范围"
        case nil: text = "尚未核对"
        }
        return HStack {
            Text(title)
            Spacer()
            Text(text).font(SketchFont.body(14)).foregroundColor(palette.secondary)
        }.accessibilityElement(children: .combine)
    }
}
