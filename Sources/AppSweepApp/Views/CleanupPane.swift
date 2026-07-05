import SwiftUI

struct CleanupPane: View {
    let report: Report?

    var body: some View {
        VStack(spacing: 0) {
            if let report {
                ScrollView {
                    VStack(alignment: .leading, spacing: 14) {
                        SummaryGrid(summary: report.summary)
                        CandidateListView(candidates: report.candidates)
                    }
                    .padding(18)
                }
            } else {
                EmptyReportView(
                    systemImage: "magnifyingglass",
                    title: "No scan yet",
                    message: "Run Scan to see app bundle, user caches, preferences, containers, and cleanup candidates."
                )
            }
        }
    }
}

private struct SummaryGrid: View {
    let summary: Summary

    var body: some View {
        LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 10), count: 5), spacing: 10) {
            MetricCard(title: "Existing", value: "\(summary.existingCandidates)", color: DesignTokens.safetyBlue)
            MetricCard(title: "Trash Eligible", value: "\(summary.trashEligibleExisting)", color: DesignTokens.success)
            MetricCard(title: "Report Only", value: "\(summary.reportOnlyExisting)", color: DesignTokens.warning)
            MetricCard(title: "Blocked", value: "\(summary.blockedExisting)", color: DesignTokens.danger)
            MetricCard(title: "Size", value: AppFormatters.bytes(summary.totalExistingBytes), color: .secondary)
        }
    }
}

private struct MetricCard: View {
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
                .lineLimit(1)
                .minimumScaleFactor(0.75)
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

struct CandidateListView: View {
    let candidates: [Candidate]

    private var visibleCandidates: [Candidate] {
        candidates.filter { $0.exists || $0.status != .missing }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Candidates")
                    .font(.headline)
                Spacer()
                Text("\(visibleCandidates.count) visible")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            if visibleCandidates.isEmpty {
                EmptyReportView(
                    systemImage: "checkmark.seal",
                    title: "No existing candidates",
                    message: "The current scan did not find app-specific files in the configured cleanup surfaces."
                )
                .frame(minHeight: 220)
            } else {
                LazyVStack(spacing: 8) {
                    ForEach(visibleCandidates) { candidate in
                        CandidateRowView(candidate: candidate)
                    }
                }
            }
        }
    }
}

private struct CandidateRowView: View {
    let candidate: Candidate

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 8) {
                StatusBadge(text: candidate.confidence.rawValue, color: color(for: candidate.confidence))
                StatusBadge(text: candidate.action.rawValue, color: actionColor(candidate.action))
                StatusBadge(text: candidate.status.rawValue, color: statusColor(candidate.status))
                Spacer()
                Text(AppFormatters.bytes(candidate.sizeBytes))
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Text(AppFormatters.shortPath(candidate.path))
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
                .lineLimit(2)

            Text(candidate.reason)
                .font(.caption)
                .foregroundColor(.secondary)

            if let detail = candidate.detail {
                Text(detail)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .textSelection(.enabled)
                    .lineLimit(3)
            }
        }
        .padding(10)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: DesignTokens.rowCorner))
    }

    private func color(for confidence: Confidence) -> Color {
        switch confidence {
        case .high: return DesignTokens.success
        case .medium: return DesignTokens.safetyBlue
        case .reportOnly: return DesignTokens.warning
        case .blocked: return DesignTokens.danger
        }
    }

    private func actionColor(_ action: CandidateAction) -> Color {
        switch action {
        case .trash: return DesignTokens.success
        case .reportOnly: return DesignTokens.warning
        case .blocked: return DesignTokens.danger
        }
    }

    private func statusColor(_ status: CandidateStatus) -> Color {
        switch status {
        case .exists, .backedUp: return DesignTokens.safetyBlue
        case .trashed: return DesignTokens.success
        case .backupFailed, .trashFailed: return DesignTokens.danger
        case .skipped: return DesignTokens.warning
        case .missing: return .secondary
        }
    }
}
