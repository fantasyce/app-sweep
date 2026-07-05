import AppKit
import SwiftUI

@main
struct AppSweepApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup {
            ContentView()
                .frame(minWidth: 1040, minHeight: 680)
        }
        .commands {
            CommandGroup(after: .newItem) {
                Button("Refresh Applications") {
                    NotificationCenter.default.post(name: .refreshApplicationsRequested, object: nil)
                }
                .keyboardShortcut("r", modifiers: [.command])
            }
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var isRunningQA = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        isRunningQA = AppQARunner.maybeRunFromArguments()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        !isRunningQA
    }
}

extension Notification.Name {
    static let refreshApplicationsRequested = Notification.Name("refreshApplicationsRequested")
}
