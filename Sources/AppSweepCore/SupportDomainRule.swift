import Foundation
import CFSafety

/// Apple's exact per-application support domain, independently combined with
/// signing, exclusive installation and explicit user-data intent by the scanner.
enum SupportDomainRule {
    static let name = "support-exact-domain-v1"
    static func path(home: String, identifier: String) -> String {
        home + "/Library/Application Support/" + identifier
    }
    static func matches(path: String, home: String, identifier: String) -> Bool {
        AppInspector.validIdentifier(identifier) && path == Self.path(home: home, identifier: identifier)
    }
    static func containsProtectedContent(_ entries: [TreeEntry]) -> Bool {
        entries.contains { entry in
            entry.relative.split(separator: "/").contains { component in
                let name = component.lowercased()
                return name == "keychains" || name.hasSuffix(".keychain") || name.hasSuffix(".keychain-db") || name == "com.apple.tcc"
            }
        }
    }
    static func verify(path: String, home: String, identifier: String) throws {
        guard matches(path: path, home: home, identifier: identifier), SafetyPolicy(home: home, acceptedPlatform: false).lexicalDenial(path) == nil else { throw SweepError.denied("不是精确应用域资料目录") }
        let snapshot = try SafeFilesystem.snapshot(path)
        guard snapshot.identity.isDirectory, snapshot.identity.owner == as_current_uid(),
              snapshot.tree.allSatisfy({ $0.identity.owner == as_current_uid() }) else { throw SweepError.denied("应用资料目录类型或所有者未确认，已保留") }
        guard !containsProtectedContent(snapshot.tree) else { throw SweepError.denied("应用资料包含钥匙串或安全状态，整项保留") }
        try SafeFilesystem.verify(snapshot)
    }
}
