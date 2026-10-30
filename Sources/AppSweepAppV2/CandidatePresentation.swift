import Foundation
import AppSweepCore

/// Display sections do not change the engine's categories or grant selection authority.
enum CandidateDisplaySection: String, CaseIterable, Identifiable {
    case application, backgroundComponent, cache, log, development
    case documentHistory, corruptPreferences, staleAgents, deviceBackup
    case developmentArchives, deviceSymbols, deletedUserArchives
    case trash, mailDownloads, aiModels, userData, protected

    var id: String { rawValue }
    var title: String {
        switch self {
        case .application: "应用主体"
        case .backgroundComponent: "后台组件"
        case .cache: "应用缓存"
        case .log: "日志与崩溃报告"
        case .development: "开发中间文件"
        case .documentHistory: "文稿历史版本"
        case .corruptPreferences: "损坏的偏好设置"
        case .staleAgents: "失效登录项"
        case .deviceBackup: "本地设备备份"
        case .developmentArchives: "开发归档"
        case .deviceSymbols: "设备调试符号"
        case .deletedUserArchives: "已删除账户归档"
        case .trash: "废纸篓"
        case .mailDownloads: "邮件下载副本"
        case .aiModels: "本地 AI 模型"
        case .userData: "应用资料与设置"
        case .protected: "其他保留项目"
        }
    }

    static func section(for candidate: Candidate) -> Self {
        // These exact rule names only label existing results; unknown rules keep
        // their underlying category and cannot become selectable through the UI.
        switch candidate.rule {
        case "document-history-versions-v1": return .documentHistory
        case "corrupt-preference-file-v1": return .corruptPreferences
        case "stale-user-launch-agent-v1": return .staleAgents
        case "xcode-archive-management-v1": return .developmentArchives
        case "xcode-device-symbols-v1": return .deviceSymbols
        case "deleted-user-archive-v1": return .deletedUserArchives
        case "current-user-trash-entry-v1": return .trash
        case "mail-download-copy-v1": return .mailDownloads
        case "ai-huggingface-local-repository-v1": return .aiModels
        default: break
        }
        switch candidate.category {
        case .application: return .application
        case .backgroundComponent: return .backgroundComponent
        case .cache: return .cache
        case .log: return .log
        case .development: return .development
        case .deviceBackup: return .deviceBackup
        case .userData: return .userData
        case .protected: return .protected
        }
    }
}

struct CandidateDisplayRow: Identifiable {
    let candidate: Candidate
    let members: [Candidate]
    let actionable: Bool
    var id: UUID { candidate.id }
    var section: CandidateDisplaySection { .section(for: candidate) }
    var knownBytes: Int64 { members.filter { $0.identity != nil }.reduce(0) { $0 + $1.bytes } }
    var unknownCount: Int { members.filter { $0.identity == nil }.count }
}

struct CandidateListProjection {
    let rows: [CandidateDisplayRow]
    var sections: [CandidateDisplaySection] {
        CandidateDisplaySection.allCases.filter { section in rows.contains { $0.section == section } }
    }
    init(candidates: [Candidate], selectableIDs: Set<UUID>) {
        var seen = Set<UUID>()
        let uniqueCandidates = candidates.filter { seen.insert($0.id).inserted }
        let cacheGroups = Dictionary(grouping: uniqueCandidates.filter { $0.category == .cache && $0.selectionGroupID != nil }) { $0.selectionGroupID! }
        var emitted = Set<UUID>()
        rows = uniqueCandidates.compactMap { candidate in
            guard emitted.insert(candidate.id).inserted else { return nil }
            let members = candidate.category == .cache
                ? candidate.selectionGroupID.flatMap { cacheGroups[$0] } ?? [candidate]
                : [candidate]
            emitted.formUnion(members.map(\.id))
            return CandidateDisplayRow(candidate: candidate, members: members,
                actionable: members.allSatisfy { selectableIDs.contains($0.id) && $0.executionAllowed })
        }
    }
}
