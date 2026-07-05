import SwiftUI

struct BackupPane: View {
    @ObservedObject var store: UninstallerStore
    @State private var pendingDelete: BackupItem?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                BackupRootView(store: store)

                if let lastBackupDirectory = store.lastBackupDirectory {
                    LastBackupView(url: lastBackupDirectory) {
                        AppKitPanels.revealInFinder(lastBackupDirectory)
                    }
                }

                HStack {
                    Text("Backups")
                        .font(.headline)
                    Spacer()
                    Text("\(store.backupItems.count) folders")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }

                if store.backupItems.isEmpty {
                    EmptyReportView(
                        systemImage: "archivebox",
                        title: "No backups found",
                        message: "Backup folders will appear here after a backup or backup-first uninstall."
                    )
                    .frame(minHeight: 260)
                } else {
                    LazyVStack(spacing: 8) {
                        ForEach(store.backupItems) { item in
                            BackupRowView(
                                item: item,
                                onReveal: { store.revealBackup(item) },
                                onDelete: { pendingDelete = item }
                            )
                        }
                    }
                }
            }
            .padding(18)
        }
        .alert("Delete Backup?", isPresented: deleteBinding, presenting: pendingDelete) { item in
            Button("Cancel", role: .cancel) {
                pendingDelete = nil
            }
            Button("Delete", role: .destructive) {
                store.deleteBackup(item)
                pendingDelete = nil
            }
        } message: { item in
            Text("This permanently removes \(item.name) from \(AppFormatters.shortPath(item.url.path)).")
        }
    }

    private var deleteBinding: Binding<Bool> {
        Binding(
            get: { pendingDelete != nil },
            set: { isPresented in
                if !isPresented {
                    pendingDelete = nil
                }
            }
        )
    }
}

private struct BackupRootView: View {
    @ObservedObject var store: UninstallerStore

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Backup Location")
                        .font(.headline)
                    Text(AppFormatters.shortPath(store.backupRootURL.path))
                        .font(.system(.callout, design: .monospaced))
                        .foregroundColor(.secondary)
                        .textSelection(.enabled)
                        .lineLimit(2)
                }

                Spacer()

                Button {
                    store.refreshBackups()
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .disabled(store.isRunning)

                Button {
                    store.revealBackupRoot()
                } label: {
                    Label("Reveal", systemImage: "folder")
                }
            }
        }
        .padding(12)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: DesignTokens.panelCorner))
    }
}

private struct LastBackupView: View {
    let url: URL
    let onReveal: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "checkmark.seal.fill")
                .foregroundColor(DesignTokens.success)
            VStack(alignment: .leading, spacing: 3) {
                Text("Latest operation backup")
                    .font(.subheadline.weight(.semibold))
                Text(AppFormatters.shortPath(url.path))
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(.secondary)
                    .textSelection(.enabled)
                    .lineLimit(2)
            }
            Spacer()
            Button {
                onReveal()
            } label: {
                Label("Reveal", systemImage: "folder")
            }
        }
        .padding(12)
        .background(DesignTokens.success.opacity(0.10), in: RoundedRectangle(cornerRadius: DesignTokens.panelCorner))
        .overlay(
            RoundedRectangle(cornerRadius: DesignTokens.panelCorner)
                .stroke(DesignTokens.success.opacity(0.25))
        )
    }
}

private struct BackupRowView: View {
    let item: BackupItem
    let onReveal: () -> Void
    let onDelete: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "archivebox")
                .font(.system(size: 22, weight: .regular))
                .foregroundColor(DesignTokens.safetyBlue)
                .frame(width: 28)

            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 8) {
                    Text(item.appName)
                        .font(.body.weight(.semibold))
                        .lineLimit(1)
                    StatusBadge(text: AppFormatters.bytes(item.sizeBytes), color: .secondary)
                    StatusBadge(text: "\(item.fileCount) files", color: .secondary)
                }

                Text(item.name)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)

                Text(AppFormatters.shortPath(item.url.path))
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(.secondary)
                    .textSelection(.enabled)
                    .lineLimit(2)
            }

            Spacer()

            Text(item.modifiedAt.formatted(date: .abbreviated, time: .shortened))
                .font(.caption)
                .foregroundColor(.secondary)
                .frame(width: 126, alignment: .trailing)

            Button {
                onReveal()
            } label: {
                Label("Reveal", systemImage: "folder")
            }

            Button(role: .destructive) {
                onDelete()
            } label: {
                Label("Delete", systemImage: "trash")
            }
        }
        .padding(10)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: DesignTokens.rowCorner))
    }
}
