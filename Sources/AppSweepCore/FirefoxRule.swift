import Foundation
import CFSafety

/// Independently written conservative mapping of Firefox's registered profiles.
/// This never treats the persistent profile directory itself as disposable.
enum FirefoxRule {
    static func externalFamilyOwners(applicationPath: String, inventory: [ApplicationIdentity]) -> [ApplicationIdentity] {
        inventory.filter { $0.bundleIdentifier.lowercased().hasPrefix("org.mozilla.") && !SafetyPolicy.contains(applicationPath,$0.path) }
    }
    static let name = "firefox-158-cache2-v1"
    static let version = "158.0_20261007201254/20261007201254"
    static let helperIdentifiers = ["org.mozilla.updater", "org.mozilla.dmgInstallHelper"]
    static func cacheOnlyHelpersAllowed(_ info: [String: Any], installed: Bool, systemExtensions: Bool) -> Bool {
        guard !installed, !systemExtensions, let helpers = info["SMPrivilegedExecutables"] as? [String: String] else { return false }
        return Set(helpers.keys) == Set(helperIdentifiers) && helpers.values.allSatisfy { !$0.isEmpty && $0.count <= 4096 }
    }
    static func cacheLeaf(_ path: String, home: String) -> String? {
        let prefix = home + "/Library/Caches/Firefox/Profiles/"
        guard path.hasPrefix(prefix) else { return nil }
        let parts = path.dropFirst(prefix.count).split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, validLeaf(String(parts[0])), parts[1] == "cache2" else { return nil }
        return String(parts[0])
    }
    static func compatible(_ data: Data, applicationPath: String, architecture: String) -> Bool {
        guard architecture == "arm64", let values = ini(data)?["Compatibility"] else { return false }
        return values["LastVersion"] == version && values["LastOSABI"] == "Darwin_aarch64-gcc3" &&
            values["LastPlatformDir"] == applicationPath + "/Contents/Resources" &&
            values["LastAppDir"] == applicationPath + "/Contents/Resources/browser"
    }
    static func cacheLayout(_ contents: [(String, Bool)]) -> Bool {
        guard contents.contains(where: { $0.0 == "entries" && $0.1 }) else { return false }
        return contents.allSatisfy { path, directory in
            if path == "entries" || path == "doomed" { return directory }
            if ["index", "index.log", "index.tmp"].contains(path) { return !directory }
            let parts = path.split(separator: "/", omittingEmptySubsequences: false)
            return !directory && parts.count == 2 && parts[0] == "entries" && parts[1].utf8.count == 40 &&
                parts[1].utf8.allSatisfy { (48...57).contains($0) || (65...70).contains($0) }
        }
    }
    static func verify(_ path: String, home: String, applicationPath: String, signaturePath: String? = nil) throws {
        guard let leaf = cacheLeaf(path, home: home), PlatformStamp.current?.architecture == "arm64" else { throw SweepError.denied("不是已验收的 Firefox 缓存范围或架构") }
        let signedPath = signaturePath ?? applicationPath
        guard AppInspector.signatureMatches(path: signedPath, identifier: "org.mozilla.firefox"),
              AppInspector.signedByTeam(path: signedPath, team: "43AQ936H96") else { throw SweepError.denied("Firefox 官方签名未确认") }
        let info = try metadata(signedPath + "/Contents/Info.plist", requireOwner: false)
        guard let plist = try PropertyListSerialization.propertyList(from: info, format: nil) as? [String: Any],
              plist["CFBundleShortVersionString"] as? String == "158.0", plist["CFBundleVersion"] as? String == "15826.10.7" else { throw SweepError.denied("Firefox 版本尚未独立验收") }
        var installed = false
        for helper in helperIdentifiers {
            if try SafeFilesystem.presence("/Library/PrivilegedHelperTools/" + helper) { installed = true }
            if try SafeFilesystem.presence("/Library/LaunchDaemons/" + helper + ".plist") { installed = true }
        }
        guard try cacheOnlyHelpersAllowed(plist, installed: installed, systemExtensions: SafeFilesystem.presence(signedPath + "/Contents/Library/SystemExtensions")) else { throw SweepError.denied("Firefox 辅助组件已安装或未确认，仅报告缓存") }
        let profiles = home + "/Library/Application Support/Firefox"
        guard let leaves = profileLeaves(try metadata(profiles + "/profiles.ini")), leaves.contains(leaf),
              compatible(try metadata(profiles + "/Profiles/" + leaf + "/compatibility.ini"), applicationPath: applicationPath, architecture: "arm64") else { throw SweepError.denied("Firefox 注册配置档、版本或应用归属未确认") }
        let snapshot = try SafeFilesystem.snapshot(path)
        guard snapshot.identity.isDirectory, snapshot.identity.owner == as_current_uid(),
              snapshot.tree.allSatisfy({ $0.identity.owner == as_current_uid() }),
              cacheLayout(snapshot.tree.map { ($0.relative, $0.identity.isDirectory) }) else { throw SweepError.denied("Firefox 缓存含未知内容，保留") }
        try SafeFilesystem.verify(snapshot)
    }
    static func registeredLeaves(home: String) throws -> [String] {
        guard let leaves = profileLeaves(try metadata(home + "/Library/Application Support/Firefox/profiles.ini")) else { throw SweepError.denied("Firefox 配置档未确认") }
        return leaves
    }
    static func metadata(_ path: String, requireOwner: Bool = true) throws -> Data {
        let snapshot = try SafeFilesystem.snapshot(path)
        guard !snapshot.identity.isDirectory, snapshot.identity.size <= 2 * 1024 * 1024,
              !requireOwner || snapshot.identity.owner == as_current_uid() else { throw SweepError.denied("Firefox 元数据权限或类型未确认") }
        let data = try SafeFilesystem.readMetadata(path)
        try SafeFilesystem.verify(snapshot)
        return data
    }
    private static func validLeaf(_ leaf: String) -> Bool {
        !leaf.isEmpty && leaf != "." && leaf != ".." && leaf.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [45,46,95].contains($0) }
    }
    static func profileLeaves(_ data: Data) -> [String]? {
        guard let sections = ini(data) else { return nil }
        var result = Set<String>()
        for (section, values) in sections where section.range(of: #"^Profile[0-9]+$"#, options: .regularExpression) != nil {
            guard values["IsRelative"] == "1", let path = values["Path"] else { return nil }
            let parts = path.split(separator: "/", omittingEmptySubsequences: false)
            guard parts.count == 2, parts[0] == "Profiles", validLeaf(String(parts[1])),
                  result.insert(String(parts[1])).inserted else { return nil }
        }
        return result.sorted()
    }
    static func ini(_ data: Data) -> [String: [String: String]]? {
        guard data.count <= 2 * 1024 * 1024, let text = String(data: data, encoding: .utf8), !text.contains("\0") else { return nil }
        var sections: [String: [String: String]] = [:]
        var current: String?
        for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty || line.hasPrefix(";") || line.hasPrefix("#") { continue }
            if line.hasPrefix("[") {
                guard line.hasSuffix("]"), line.count > 2, line.count < 128 else { return nil }
                let name = String(line.dropFirst().dropLast())
                guard sections[name] == nil, !name.contains("[") && !name.contains("]") else { return nil }
                sections[name] = [:]; current = name
            } else {
                guard let current, let separator = line.firstIndex(of: "=") else { return nil }
                let key = line[..<separator].trimmingCharacters(in: .whitespaces)
                let value = line[line.index(after: separator)...].trimmingCharacters(in: .whitespaces)
                guard !key.isEmpty, key.count < 128, value.count <= 4096, sections[current]?[key] == nil else { return nil }
                sections[current]?[key] = value
            }
        }
        return sections
    }
}
