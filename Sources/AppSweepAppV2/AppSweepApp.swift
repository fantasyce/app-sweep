import AppKit
import SwiftUI

@main
@MainActor
struct AppSweepApp: App {
    @NSApplicationDelegateAdaptor(SweepDelegate.self) private var delegate
    @StateObject private var store: SweepStore
    @AppStorage("appearance") private var appearance = "system"
    init() {
        SketchFont.register()
        let model = SweepStore()
        model.preparationRequired = UserDefaults.standard.integer(forKey: "accessPreparationVersion") < 1 || UserDefaults.standard.bool(forKey: "accessSettingsRequested")
        _store = StateObject(wrappedValue: model)
    }
    var body: some Scene {
        WindowGroup {
            SweepWindow().environmentObject(store)
                .font(SketchFont.body())
                .preferredColorScheme(appearance == "system" ? nil : (appearance == "dark" ? .dark : .light))
                .frame(minWidth: 960, idealWidth: 1100, minHeight: 640, idealHeight: 740)
                .background(InitialPaperWindow())
        }
        .commands {
            CommandGroup(replacing: .newItem) { }
            CommandMenu("外观") {
                Picker("外观", selection: $appearance) { Text("跟随系统").tag("system"); Text("浅色").tag("light"); Text("深色").tag("dark") }
            }
            CommandMenu("工作区") {
                ForEach(Array(SweepStore.Workspace.allCases.enumerated()), id: \.element) { index, space in
                    Button(space.rawValue) { store.switchWorkspace(space) }.keyboardShortcut(KeyEquivalent(Character(String(index + 1))), modifiers: .command)
                }
            }
        }
    }
}
@MainActor
final class SweepDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) { NSApp.setActivationPolicy(.regular); NSApp.activate(ignoringOtherApps: true) }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}
