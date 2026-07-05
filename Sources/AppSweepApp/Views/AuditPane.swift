import SwiftUI

struct AuditPane: View {
    let report: AuditReport?

    var body: some View {
        if let report {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 10), count: 4), spacing: 10) {
                        AuditMetric(title: "Strong", value: "\(report.summary.strongPathMatchCount)", color: DesignTokens.danger)
                        AuditMetric(title: "Weak", value: "\(report.summary.genericNameMatchCount)", color: DesignTokens.warning)
                        AuditMetric(title: "Registrations", value: "\(report.summary.registrationMatchCount)", color: DesignTokens.safetyBlue)
                        AuditMetric(title: "Unreadable", value: "\(report.summary.unreadableErrorCount)", color: .secondary)
                    }

                    PathSection(title: "Strong Path Matches", subtitle: "Exact bundle-id or high-confidence identifiers.", paths: report.strongPathMatches)

                    ForEach(report.registrations.filter { !$0.matches.isEmpty }) { section in
                        PathSection(title: section.name, subtitle: "System registration evidence.", paths: section.matches)
                    }

                    PathSection(title: "Weak Name Matches", subtitle: "Evidence only. These are not deletion candidates by themselves.", paths: report.genericNameMatches)
                    PathSection(title: "Unreadable or Timed Out", subtitle: "Permission or timeout notes from segmented full-machine scan.", paths: report.unreadableErrors)
                }
                .padding(18)
            }
        } else {
            EmptyReportView(
                systemImage: "scope",
                title: "No full audit yet",
                message: "Run Full Audit to search root-level locations, /System, /Library, /private, and user Library without deleting anything."
            )
        }
    }
}

private struct AuditMetric: View {
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

private struct PathSection: View {
    let title: String
    let subtitle: String
    let paths: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.headline)
                    Text(subtitle)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                Spacer()
                Text("\(paths.count)")
                    .font(.caption.weight(.semibold))
                    .foregroundColor(.secondary)
            }

            if paths.isEmpty {
                Text("No entries")
                    .font(.callout)
                    .foregroundColor(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
                    .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: DesignTokens.rowCorner))
            } else {
                LazyVStack(spacing: 6) {
                    ForEach(paths, id: \.self) { path in
                        Text(AppFormatters.shortPath(path))
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                            .lineLimit(2)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(8)
                            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: DesignTokens.rowCorner))
                    }
                }
            }
        }
    }
}
