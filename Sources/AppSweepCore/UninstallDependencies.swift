import Foundation

enum UninstallDependencies {
    /// A declaration is not an installed service. Present or unreadable resources
    /// still block a body-only uninstall until their lifecycle can be handled.
    static func ensureNoInstalledPrivilegedHelpers(info: [String: Any], libraryRoot: String = "/Library") throws {
        for label in try declaredLabels(info: info) {
            for path in [libraryRoot + "/PrivilegedHelperTools/" + label, libraryRoot + "/LaunchDaemons/" + label + ".plist"] {
                if try SafeFilesystem.presence(path) { throw SweepError.denied("此应用安装了系统辅助组件，可先核对独占组件；无法确认时请使用应用的官方卸载器。不能只移走主体而留下组件。当前整份保留：" + label) }
            }
        }
    }
    static func declaredLabels(info: [String: Any]) throws -> [String] {
        guard let raw = info["SMPrivilegedExecutables"] else { return [] }
        // App discovery accepts real single-component bundle IDs. Privileged
        // helper declarations retain their separately validated dotted labels.
        guard let declarations = raw as? [String: String], declarations.count <= 32,
              declarations.allSatisfy({ AppInspector.validIdentifier($0.key) && $0.key.contains(".") && !$0.value.isEmpty && $0.value.utf8.count <= 65536 }) else { throw SweepError.denied("特权辅助组件声明未确认") }
        return declarations.keys.sorted()
    }
}
