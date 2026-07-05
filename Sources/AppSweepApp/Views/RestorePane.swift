import SwiftUI

struct RestorePane: View {
    let report: RestoreReport?
    let onChooseRestore: () -> Void

    var body: some View {
        if let report {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 10), count: 4), spacing: 10) {
                        RestoreMetric(title: "Restored", value: "\(report.summary.restored)", color: DesignTokens.success)
                        RestoreMetric(title: "Skipped", value: "\(report.summary.skippedExisting)", color: DesignTokens.warning)
                        RestoreMetric(title: "Missing", value: "\(report.summary.missingBackup)", color: DesignTokens.danger)
                        RestoreMetric(title: "Failed", value: "\(report.summary.failed)", color: DesignTokens.danger)
                    }

                    Text("Source: \(AppFormatters.shortPath(report.sourceReportPath))")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .textSelection(.enabled)

                    LazyVStack(spacing: 8) {
                        ForEach(report.items) { item in
                            VStack(alignment: .leading, spacing: 5) {
                                StatusBadge(text: item.status, color: color(for: item.status))
                                Text(AppFormatters.shortPath(item.originalPath))
                                    .font(.system(.body, design: .monospaced))
                                    .textSelection(.enabled)
                                if let backupPath = item.backupPath {
                                    Text(AppFormatters.shortPath(backupPath))
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                        .textSelection(.enabled)
                                }
                                if let detail = item.detail {
                                    Text(detail)
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(10)
                            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: DesignTokens.rowCorner))
                        }
                    }
                }
                .padding(18)
            }
        } else {
            VStack(spacing: 16) {
                EmptyReportView(
                    systemImage: "arrow.uturn.backward.circle",
                    title: "No restore report yet",
                    message: "Choose a previous backup JSON to restore backed-up items. Existing paths are never overwritten."
                )
                Button {
                    onChooseRestore()
                } label: {
                    Label("Choose Backup Report", systemImage: "doc.badge.clock")
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func color(for status: String) -> Color {
        switch status {
        case "restored": return DesignTokens.success
        case "skippedExisting": return DesignTokens.warning
        case "failed", "missingBackup", "missingBackupPath": return DesignTokens.danger
        default: return .secondary
        }
    }
}

private struct RestoreMetric: View {
    let title: String
    let value: String
    let color: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
            Text(value)
                .font(.system(size: 18, weight: .semibold))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: DesignTokens.panelCorner))
        .overlay(alignment: .top) {
            Rectangle()
                .fill(color)
                .frame(height: 3)
                .clipShape(RoundedRectangle(cornerRadius: 2))
        }
    }
}
