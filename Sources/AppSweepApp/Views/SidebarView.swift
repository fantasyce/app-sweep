import AppKit
import SwiftUI

struct SidebarView: View {
    @ObservedObject var store: UninstallerStore
    @State private var query = ""

    private var filteredApps: [InstalledApp] {
        guard !query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return store.apps
        }
        let needle = query.lowercased()
        return store.apps.filter {
            $0.name.lowercased().contains(needle)
                || $0.bundleIdentifier.lowercased().contains(needle)
                || $0.path.lowercased().contains(needle)
        }
    }

    var body: some View {
        VStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 6) {
                Text("App Sweep")
                    .font(.headline)
                Text("Safe app removal with backup-first cleanup")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 14)
            .padding(.top, 14)

            HStack(spacing: 8) {
                Button {
                    store.refreshApps()
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .labelStyle(.iconOnly)
                .help("Refresh applications")

                Button {
                    store.chooseApplication()
                } label: {
                    Label("Choose App", systemImage: "plus.app")
                }
                .help("Choose an app bundle manually")
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 14)

            TextField("Search apps", text: $query)
                .textFieldStyle(.roundedBorder)
                .padding(.horizontal, 14)

            List(filteredApps) { app in
                AppRowView(app: app, isSelected: store.selectedApp == app)
                    .contentShape(Rectangle())
                    .onTapGesture {
                        store.select(app)
                    }
                    .contextMenu {
                        Button("Scan") {
                            store.select(app)
                            store.runScan()
                        }
                        Button("Full Audit") {
                            store.select(app)
                            store.runFullAudit()
                        }
                    }
            }
            .listStyle(.sidebar)
        }
    }
}

private struct AppRowView: View {
    let app: InstalledApp
    let isSelected: Bool

    var body: some View {
        HStack(spacing: 10) {
            Image(nsImage: NSWorkspace.shared.icon(forFile: app.path))
                .resizable()
                .frame(width: 30, height: 30)
                .cornerRadius(6)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(app.name)
                        .font(.system(size: 13, weight: .medium))
                        .lineLimit(1)
                    if app.isAppleProtected {
                        Text("Apple")
                            .font(.system(size: 10, weight: .semibold))
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1)
                            .background(Color.secondary.opacity(0.14), in: Capsule())
                    }
                }
                Text(app.subtitle)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(app.name), \(app.bundleIdentifier)")
    }
}
