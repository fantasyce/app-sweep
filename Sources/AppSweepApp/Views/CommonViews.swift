import SwiftUI

struct StatusBadge: View {
    let text: String
    let color: Color

    var body: some View {
        Text(text)
            .font(.system(size: 11, weight: .semibold))
            .lineLimit(1)
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(color.opacity(0.14), in: Capsule())
            .foregroundColor(color)
    }
}

struct EmptyReportView: View {
    let systemImage: String
    let title: String
    let message: String

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: systemImage)
                .font(.system(size: 36, weight: .regular))
                .foregroundColor(DesignTokens.safetyBlue)
            Text(title)
                .font(.headline)
            Text(message)
                .font(.callout)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 520)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(28)
    }
}

struct StatusBarView: View {
    @ObservedObject var store: UninstallerStore

    var body: some View {
        HStack(spacing: 10) {
            if store.isRunning {
                ProgressView()
                    .controlSize(.small)
            } else {
                Circle()
                    .fill(store.errorMessage == nil ? DesignTokens.success : DesignTokens.danger)
                    .frame(width: 8, height: 8)
            }

            Text(store.statusMessage)
                .font(.caption)
                .foregroundColor(.secondary)
                .lineLimit(1)

            Spacer()

            if let lastBackupDirectory = store.lastBackupDirectory {
                Text("Backup: \(AppFormatters.shortPath(lastBackupDirectory.path))")
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                    .textSelection(.enabled)
            } else if let lastReportURL = store.lastReportURL {
                Text(AppFormatters.shortPath(lastReportURL.path))
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                    .textSelection(.enabled)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 7)
        .background(.bar)
    }
}

struct UninstallConfirmationView: View {
    let appName: String
    @Binding var backupFirst: Bool
    let isRunning: Bool
    let onCancel: () -> Void
    let onConfirm: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                Image(systemName: "trash")
                    .font(.system(size: 28, weight: .semibold))
                    .foregroundColor(DesignTokens.danger)

                VStack(alignment: .leading, spacing: 4) {
                    Text("Uninstall \(appName)?")
                        .font(.title3.weight(.semibold))
                    Text("Items are moved to Trash. The CLI will skip leftovers if the main app cannot be moved.")
                        .font(.callout)
                        .foregroundColor(.secondary)
                }
            }

            Toggle("Create a backup before uninstalling", isOn: $backupFirst)
                .toggleStyle(.checkbox)

            Text("This action requires explicit confirmation and does not use sudo. Root-owned files are reported or skipped.")
                .font(.caption)
                .foregroundColor(.secondary)

            HStack {
                Spacer()
                Button("Cancel", action: onCancel)
                    .keyboardShortcut(.cancelAction)
                Button("Move to Trash") {
                    onConfirm()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .tint(DesignTokens.danger)
                .disabled(isRunning)
            }
        }
        .padding(22)
        .frame(width: 460)
    }
}
