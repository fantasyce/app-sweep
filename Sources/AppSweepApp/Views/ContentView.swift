import SwiftUI

struct ContentView: View {
    @StateObject private var store = UninstallerStore()
    @State private var showingUninstallConfirmation = false
    @State private var backupBeforeUninstall = true

    var body: some View {
        VStack(spacing: 0) {
            HSplitView {
                SidebarView(store: store)
                    .frame(minWidth: 260, idealWidth: 300, maxWidth: 360)

                DetailView(
                    store: store,
                    showingUninstallConfirmation: $showingUninstallConfirmation
                )
                .frame(minWidth: 720)
            }

            StatusBarView(store: store)
        }
        .sheet(isPresented: $showingUninstallConfirmation) {
            UninstallConfirmationView(
                appName: store.selectedApp?.name ?? "Selected App",
                backupFirst: $backupBeforeUninstall,
                isRunning: store.isRunning,
                onCancel: { showingUninstallConfirmation = false },
                onConfirm: {
                    showingUninstallConfirmation = false
                    store.runUninstall(backupFirst: backupBeforeUninstall)
                }
            )
        }
        .onReceive(NotificationCenter.default.publisher(for: .refreshApplicationsRequested)) { _ in
            store.refreshApps()
        }
    }
}
