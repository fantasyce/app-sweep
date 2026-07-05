import AppKit
import Foundation
import UniformTypeIdentifiers

enum AppKitPanels {
    @MainActor
    static func chooseApplication() -> URL? {
        let panel = NSOpenPanel()
        panel.title = "Choose an application"
        panel.prompt = "Choose"
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.directoryURL = URL(fileURLWithPath: "/Applications")

        guard panel.runModal() == .OK, let url = panel.url else { return nil }
        return url.pathExtension == "app" ? url : nil
    }

    @MainActor
    static func chooseBackupReport() -> URL? {
        let panel = NSOpenPanel()
        panel.title = "Choose a backup report"
        panel.prompt = "Restore"
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.json]
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("App Sweep/reports")

        guard panel.runModal() == .OK else { return nil }
        return panel.url
    }

    @MainActor
    static func revealInFinder(_ url: URL) {
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }
}
