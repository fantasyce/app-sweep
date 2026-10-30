import Foundation

/// Current-user WebKit auxiliary caches, scoped by the complete client bundle
/// identifier. This does not authorize the sibling T directory or shared WebKit
/// domains. The scanner/executor separately prove the unique signed, stopped app.
enum WebKitCacheRule {
    static let name = "cache-webkit-derived-v1"
    static func namespaces(identifier: String) -> [String] {
        guard SystemCleanupScope.validIdentifier(identifier) else { return [] }
        return ["GPU", "Networking", "WebContent"].map { "com.apple.WebKit." + $0 + "+" + identifier }
    }
    static func root(path: String, identifier: String, scope: DarwinCacheScope) -> String? {
        guard scope.kind == .cache, XcodeRule.canonical(path), path.hasPrefix(scope.root + "/") else { return nil }
        let parts = path.dropFirst(scope.root.count + 1).split(separator: "/")
        guard parts.count == 2, namespaces(identifier: identifier).contains(String(parts[0])) else { return nil }
        let leaf = parts[1].lowercased()
        let exactFramework = String(parts[1]) == String(parts[0]).split(separator:"+").first.map(String.init)
        guard (!leaf.hasPrefix("com.apple.") || exactFramework), leaf != "keychains", !leaf.hasSuffix(".keychain"), !leaf.hasSuffix(".keychain-db"),
              !leaf.contains("appsweep"), !leaf.contains("app-sweep") else { return nil }
        return scope.root + "/" + parts[0]
    }
    static func verifyRoot(_ root: String, identifier: String, scope: DarwinCacheScope) throws -> FileSnapshot {
        try scope.verify()
        guard self.root(path: root + "/member", identifier: identifier, scope: scope) == root else { throw SweepError.denied("不是当前账户的精确 WebKit 派生缓存") }
        let snapshot = try CacheDomainRule.verifyPrivateDomain(root: root)
        guard snapshot.identity.device == scope.device else { throw SweepError.denied("WebKit 缓存跨卷，保留") }
        return snapshot
    }
    static func verify(path: String, identifier: String, scope: DarwinCacheScope) throws {
        guard let root = root(path: path, identifier: identifier, scope: scope) else { throw SweepError.denied("WebKit 缓存路径未登记") }
        let snapshot = try verifyRoot(root, identifier: identifier, scope: scope)
        guard snapshot.tree.contains(where: { !$0.relative.contains("/") && root + "/" + $0.relative == path }) else { throw SweepError.stale("WebKit 缓存直接子项已改变") }
    }
}
