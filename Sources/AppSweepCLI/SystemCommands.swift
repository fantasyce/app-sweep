import Foundation
import AppSweepCore

struct SystemCLIUsageError: Error, LocalizedError {
    let message: String
    var errorDescription: String? { "系统参数无效：" + message }
}

extension AppSweepCommand {
    static func runSystem(_ args: [String]) async throws {
        #if os(macOS)
        let command = args.first ?? ""
        let options: Set<String>
        let required: Set<String>
        switch command {
        case "system-status": options = []; required = []
        case "system-scan", "system-apply": options = ["--category"]; required = options
        case "system-recovery": options = ["--after"]; required = []
        case "system-batch", "system-restore", "system-purge": options = ["--batch"]; required = options
        default: throw SystemCLIUsageError(message:"未知系统命令")
        }
        var values: [String:String] = [:], index = 1
        while index < args.count {
            let option = args[index]
            guard options.contains(option), values[option] == nil, index + 1 < args.count,
                  !args[index + 1].hasPrefix("--") else { throw SystemCLIUsageError(message:"存在不支持、重复或缺值的参数") }
            values[option] = args[index + 1]; index += 2
        }
        guard required.isSubset(of:Set(values.keys)) else { throw SystemCLIUsageError(message:"缺少必填参数") }
        let category: SystemCleanupCategory?
        if let raw = values["--category"] {
            guard let parsed = SystemCleanupCategory(rawValue:raw) else { throw SystemCLIUsageError(message:"--category 只接受 caches、logs、deletedUserArchives 或 applicationHelpers") }
            category = parsed
        } else { category = nil }
        let batchID: UUID?
        if let raw = values["--batch"] ?? values["--after"] {
            guard let parsed = UUID(uuidString:raw) else { throw SystemCLIUsageError(message:"批次与分页位置必须是有效 UUID") }
            batchID = parsed
        } else { batchID = nil }
        // Validate the complete command before connecting. No option contains a
        // filesystem path, a user ID, a serialized plan, or an approval bypass.
        let client = try await SystemServiceClient.connect()
        do {
            switch command {
            case "system-status": try await emit(client.status())
            case "system-scan":
                guard let category else { throw SystemCLIUsageError(message:"缺少类别") }
                try await emit(client.scan(category))
            case "system-apply":
                guard let category else { throw SystemCLIUsageError(message:"缺少类别") }
                guard ![.deletedUserArchives,.applicationHelpers].contains(category) else{throw SweepError.denied("个人归档及系统辅助组件需在应用中逐项选择并核对计划；命令行不自动选择") }
                let status = try await client.status()
                guard status.executionEnabled else { throw SweepError.denied(status.limitation ?? "当前系统清理尚未通过验收") }
                let report = try await client.scan(category)
                let ids = report.selectableCandidates(includeUserData:false).map(\.id)
                let plan = try await client.review(scanID:report.id,candidateIDs:ids)
                try emit(plan)
                print("核对以上系统清理计划。输入“移入恢复区”继续；不会自动重试：")
                guard readLine() == "移入恢复区" else { throw SweepError.denied("已取消") }
                try await emit(client.execute(planID:plan.id))
            case "system-recovery": try await emit(client.recoveryPage(after:batchID))
            case "system-batch":
                guard let batchID else { throw SystemCLIUsageError(message:"缺少批次") }
                try await emit(client.recoveryBatch(id:batchID))
            case "system-restore":
                guard let batchID else { throw SystemCLIUsageError(message:"缺少批次") }
                try await emit(client.restore(batchID:batchID))
            case "system-purge":
                guard let batchID else { throw SystemCLIUsageError(message:"缺少批次") }
                print("永久清空后不能撤销。输入“永久清空 \(batchID.uuidString)”确认：")
                let confirmation = readLine() ?? ""
                try await emit(client.purge(batchID:batchID,confirmation:confirmation))
            default: throw SystemCLIUsageError(message:"未知系统命令")
            }
            await client.close()
        } catch {
            await client.close()
            throw error
        }
        #else
        throw SweepError.denied("当前平台不支持 macOS 系统服务")
        #endif
    }
}
