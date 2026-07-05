import AppKit
import SwiftUI

enum DetailSection: String, CaseIterable, Identifiable {
    case cleanup = "Cleanup"
    case audit = "Full Audit"
    case backups = "Backups"
    case restore = "Restore"
    case logs = "Logs"

    var id: String { rawValue }
}

struct DetailView: View {
    @ObservedObject var store: UninstallerStore
    @Binding var showingUninstallConfirmation: Bool
    @State private var section: DetailSection = .cleanup

    var body: some View {
        VStack(spacing: 0) {
            if let app = store.selectedApp {
                AppHeaderView(app: app)
                    .padding(18)

                ActionBarView(
                    store: store,
                    showingUninstallConfirmation: $showingUninstallConfirmation
                )
                .padding(.horizontal, 18)
                .padding(.bottom, 14)

                if let error = store.errorMessage {
                    ErrorBanner(message: error)
                        .padding(.horizontal, 18)
                        .padding(.bottom, 12)
                }

                Picker("Section", selection: $section) {
                    ForEach(DetailSection.allCases) { section in
                        Text(section.rawValue).tag(section)
                    }
                }
                .pickerStyle(.segmented)
                .padding(.horizontal, 18)
                .padding(.bottom, 12)

                Divider()

                Group {
                    switch section {
                    case .cleanup:
                        CleanupPane(report: store.scanReport)
                    case .audit:
                        AuditPane(report: store.auditReport)
                    case .backups:
                        BackupPane(store: store)
                    case .restore:
                        RestorePane(report: store.restoreReport, onChooseRestore: store.chooseAndRestoreBackupReport)
                    case .logs:
                        LogPane(lines: store.logLines)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                EmptySelectionView(onChooseApp: store.chooseApplication)
            }
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

private struct AppHeaderView: View {
    let app: InstalledApp

    var body: some View {
        HStack(spacing: 14) {
            Image(nsImage: NSWorkspace.shared.icon(forFile: app.path))
                .resizable()
                .frame(width: 54, height: 54)
                .cornerRadius(10)

            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 8) {
                    Text(app.name)
                        .font(.system(size: 22, weight: .semibold))
                        .lineLimit(1)

                    if app.isAppleProtected {
                        StatusBadge(text: "Protected", color: .secondary)
                    }
                }

                Text(AppFormatters.shortPath(app.path))
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)

                Text(app.bundleIdentifier.isEmpty ? "No bundle identifier found" : app.bundleIdentifier)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .textSelection(.enabled)
            }

            Spacer()
        }
    }
}

private struct ActionBarView: View {
    @ObservedObject var store: UninstallerStore
    @Binding var showingUninstallConfirmation: Bool

    var body: some View {
        HStack(spacing: 8) {
            Button {
                store.runScan()
            } label: {
                Label("Scan", systemImage: "magnifyingglass")
            }
            .disabled(!store.canRunAction)

            Button {
                store.runFullAudit()
            } label: {
                Label("Full Audit", systemImage: "scope")
            }
            .disabled(!store.canRunAction)

            Button {
                store.runBackup()
            } label: {
                Label("Backup", systemImage: "archivebox")
            }
            .disabled(!store.canRunAction || store.selectedApp?.isAppleProtected == true)

            Spacer()

            Button {
                store.chooseAndRestoreBackupReport()
            } label: {
                Label("Restore Report", systemImage: "arrow.uturn.backward.circle")
            }
            .disabled(store.isRunning)

            Button {
                showingUninstallConfirmation = true
            } label: {
                Label("Uninstall", systemImage: "trash")
            }
            .buttonStyle(.borderedProminent)
            .tint(DesignTokens.danger)
            .disabled(!store.canRunAction || store.selectedApp?.isAppleProtected == true)
        }
    }
}

private struct EmptySelectionView: View {
    let onChooseApp: () -> Void

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 54, weight: .regular))
                .foregroundColor(DesignTokens.safetyBlue)

            VStack(spacing: 6) {
                Text("Choose an app to inspect")
                    .font(.title2.weight(.semibold))
                Text("Start with read-only scan or full audit. Nothing is moved until you confirm uninstall.")
                    .font(.body)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 520)
            }

            Button {
                onChooseApp()
            } label: {
                Label("Choose Application", systemImage: "plus.app")
            }
            .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(32)
    }
}

private struct ErrorBanner: View {
    let message: String

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundColor(DesignTokens.danger)
            Text(message)
                .font(.callout)
                .textSelection(.enabled)
                .lineLimit(4)
            Spacer()
        }
        .padding(10)
        .background(DesignTokens.danger.opacity(0.10), in: RoundedRectangle(cornerRadius: DesignTokens.panelCorner))
        .overlay(
            RoundedRectangle(cornerRadius: DesignTokens.panelCorner)
                .stroke(DesignTokens.danger.opacity(0.25))
        )
    }
}
