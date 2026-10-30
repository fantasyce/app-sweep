import Foundation
import AppSweepCore
#if os(Linux)
import Glibc
#else
import Darwin
#endif

@main
struct AppSweepCommand {
    static func main() async {
        do { try await run(Array(CommandLine.arguments.dropFirst())) }
        catch let error as SystemCLIUsageError { FileHandle.standardError.write(Data(("未完成：" + error.localizedDescription + "\n").utf8)); exit(64) }
        catch { FileHandle.standardError.write(Data(("未完成：" + error.localizedDescription + "\n").utf8)); exit(1) }
    }
    static func emit<T: Encodable>(_ value: T) throws {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]; encoder.dateEncodingStrategy = .iso8601
        FileHandle.standardOutput.write(try encoder.encode(value)); print("")
    }
    static func option(_ name: String, in args: [String]) -> String? {
        guard let i = args.firstIndex(of: name), i + 1 < args.count else { return nil }; return args[i + 1]
    }
    static func run(_ args: [String]) async throws {
        let engine = SweepEngine()
        let command = args.first ?? "help"
        switch command {
        #if os(macOS)
        case "_native-preference-export":
            guard args.count == 2 else { throw SweepError.invalid("原生偏好读取只接受一个精确应用域") }
            print(try NativePreferenceExport.encodedDomain(args[1]))
        #endif
        case "--version", "version": print("App Sweep 2.1.0")
        case "help", "--help":
            print("""
            App Sweep 2.1.0
              scan --app /Applications/Example.app       只读卸载预览
              scan-junk                                  只读垃圾扫描
              scan-known --bundle-id org.example.app      孤立残留预览
              apply --app PATH [--include-user-data]      核对计划后明确确认
              recovery                                   恢复批次列表
              restore --batch UUID                       撤销已登记批次
              purge --batch UUID                         单独确认永久清空
              preview-report --report PATH               旧报告只读预览
              ignore-list                                查看持续保留列表
              ignore-add --path PATH                      加入保留列表；不清理文件
              ignore-remove --path PATH                   移出保留列表；需重新扫描
              ignore-add --category CATEGORY             持续保留分类；不清理文件
              ignore-remove --category CATEGORY          取消分类保留；需重新扫描
                CATEGORY: cache | log | development | userData | deviceBackup
              system-status                              已安装系统服务状态
              system-scan --category caches|logs          系统范围只读扫描
              system-apply --category caches|logs         同一连接审查并确认系统计划
              system-recovery [--after UUID]              系统恢复批次摘要分页
              system-batch --batch UUID                   系统恢复批次详情
              system-restore --batch UUID                 撤销系统批次
              system-purge --batch UUID                   单独确认清空系统恢复副本
            未验收的系统与架构只读；旧 uninstall 为预览，trash-path 已停用。
            """)
        case let name where name.hasPrefix("system-"): try await runSystem(args)
        case "ignore-list":
            guard args.count == 1 else { throw SweepError.invalid("忽略设置用法：ignore-list") }
            try await emit(engine.cleanupIgnores())
        case "ignore-add", "ignore-remove":
            guard args.count == 3, ["--path","--category"].contains(args[1]) else { throw SweepError.invalid("忽略设置用法：\(command) --path PATH 或 --category CATEGORY") }
            let category = args[1] == "--category" ? CandidateCategory(rawValue:args[2]) : nil
            if args[1] == "--category" {
                guard let category, CleanupIgnoreList.supportedCategories.contains(category) else { throw SweepError.invalid("忽略分类必须为 cache、log、development、userData 或 deviceBackup") }
            }
            let current = try await engine.cleanupIgnores()
            if let category { try await emit(engine.setCleanupCategoryIgnored(category,ignored:command == "ignore-add",expectedRevision:current.revision)) }
            else if command == "ignore-add" { try await emit(engine.addCleanupIgnore(path:args[2],expectedRevision:current.revision)) }
            else { try await emit(engine.removeCleanupIgnore(path:args[2],expectedRevision:current.revision)) }
        case "scan-junk": try await emit(engine.scanJunk())
        case "scan", "uninstall", "backup", "audit-full":
            let positional = args.count > 1 && !args[1].hasPrefix("--") ? args[1] : nil
            guard let path = option("--app", in: args) ?? positional else { throw SweepError.invalid("缺少 --app") }
            if command != "scan" { FileHandle.standardError.write(Data("旧入口仅提供范围受限的只读预览，执行参数和输出路径参数不会执行。\n".utf8)) }
            try await emit(engine.scanApplication(path))
        case "scan-known", "uninstall-known", "audit-full-known":
            let positional = args.count > 1 && !args[1].hasPrefix("--") ? args[1] : nil
            guard let identifier = option("--bundle-id", in: args) ?? positional else { throw SweepError.invalid("缺少 --bundle-id") }
            try await emit(engine.scanKnown(bundleIdentifier: identifier, displayName: option("--name", in: args) ?? identifier))
        case "apply":
            guard let path = option("--app", in: args) else { throw SweepError.invalid("缺少 --app") }
            let report = try await engine.scanApplication(path)
            let includeData = args.contains("--include-user-data")
            let ids = Set(report.selectableCandidates(includeUserData:includeData).filter(\.executionAllowed).map(\.id))
            let plan = try await engine.makePlan(reportID: report.id, selected: ids, includeUserData: includeData)
            try emit(plan)
            if let limitation = report.platformLimitation { throw SweepError.denied(limitation) }
            let confirmation=plan.preferenceCount > 0 ? "确认处理" : "移入恢复区"
            print(plan.preferenceCount > 0 ? "文件将移入恢复区；选中的设置域会独立备份后通过 macOS 清除，可在恢复区撤销。输入“确认处理”继续：" : "这些文件将移入专用恢复区，尚未释放空间。输入“移入恢复区”继续：")
            guard readLine() == confirmation else { throw SweepError.denied("已取消") }
            try await emit(engine.execute(planID: plan.id))
        case "recovery": try await emit(engine.recoveryBatches())
        case "restore":
            guard let raw = option("--batch", in: args), let id = UUID(uuidString: raw) else { throw SweepError.denied("旧报告恢复已停用；只能恢复已登记的 --batch UUID") }
            try await emit(engine.restore(batchID: id))
        case "purge":
            guard let raw = option("--batch", in: args), let id = UUID(uuidString: raw) else { throw SweepError.invalid("缺少有效 --batch UUID") }
            print("永久清空后不能撤销。输入“永久清空 \(id.uuidString)”确认：")
            try await emit(engine.purge(batchID: id, confirmation: readLine() ?? ""))
        case "preview-report":
            guard let path = option("--report", in: args) else { throw SweepError.invalid("缺少 --report") }
            let data = try SweepEngine.previewLegacyReport(path)
            FileHandle.standardOutput.write(data); print("\n只读预览：报告中的路径和自由文本不具有执行权限。")
        case "trash-path": throw SweepError.denied("trash-path 已停用，不能直接提交路径删除")
        default: throw SweepError.invalid("未知命令；使用 --help 查看安全接口")
        }
    }
}
