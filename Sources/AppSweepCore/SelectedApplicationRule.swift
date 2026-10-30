import Foundation

/// Explicit whole-bundle intent; this rule never authorizes associated Apple data.
enum SelectedApplicationRule {
    static let name = "selected-application-v2"
    static func matches(path: String, policy: SafetyPolicy) -> Bool {
        guard policy.protectedDenial(path) == nil, path == URL(fileURLWithPath: path).standardizedFileURL.path,
              path.hasSuffix(".app") else { return false }
        guard let root = ["/Applications", policy.home].first(where: { $0 != path && SafetyPolicy.contains($0, path) }) else { return false }
        let packages = ["app", "framework", "bundle", "xpc", "appex", "plugin", "kext", "prefpane", "component", "vst", "vst3"]
        return !path.dropFirst(root.count + 1).split(separator: "/").dropLast().contains { part in
            packages.contains { part.lowercased().hasSuffix("." + $0) }
        }
    }
    static func verify(path: String, policy: SafetyPolicy, identifier: String) throws {
        guard matches(path: path, policy: policy) else { throw SweepError.denied("应用位于受保护、其它用户或包内组件位置，已保留") }
        try verifyStored(path: path, identifier: identifier, requireNoInstalledHelpers: true)
    }
    static func verifyStored(path: String, identifier: String, requireNoInstalledHelpers: Bool = false) throws {
        try ChosenApplicationRule.verifyStored(path: path, identifier: identifier, requireNoInstalledHelpers: requireNoInstalledHelpers, allowOptionalApple: true)
    }
}
