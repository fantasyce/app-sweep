import Foundation
import CFSafety

/// WebKit's nonpersistent mapped-blob working directory, not its durable website
/// data and not arbitrary DARWIN_USER_TEMP_DIR contents. Owner/process proof is
/// shared with application caches; this rule has its own native acceptance.
enum WebKitTemporaryRule {
    static let name = "cache-webkit-temporary-blob-v1"
    static func namespace(_ identifier: String) -> String? {
        SystemCleanupScope.validIdentifier(identifier) ? "com.apple.WebKit.Networking+" + identifier : nil
    }
    static func root(path: String, identifier: String, scope: DarwinCacheScope) -> String? {
        guard scope.kind == .temporary, XcodeRule.canonical(path), let namespace = namespace(identifier) else { return nil }
        let root = scope.root + "/" + namespace
        guard URL(fileURLWithPath: path).deletingLastPathComponent().path == root,
              URL(fileURLWithPath: path).lastPathComponent.range(of: #"^BlobRegistryFiles-[A-Za-z0-9]{6,32}$"#, options: .regularExpression) != nil else { return nil }
        return root
    }
    static func verifyNamespace(identifier: String, scope: DarwinCacheScope) throws -> FileSnapshot {
        try scope.verify()
        guard scope.kind == .temporary, let name = namespace(identifier) else { throw SweepError.denied("WebKit 临时目录的账户或归属未确认") }
        let path = scope.root + "/" + name, directory = try SafeDirectory(path: path)
        let snapshot = try SafeFilesystem.snapshot(path)
        // macOS marks this enclosing namespace rootless/SF_NOUNLINK. It is an
        // ancestor, never a cleanup or backup target. Check private ownership
        // and stable identity here; the movable Blob child receives the full
        // metadata/backup validation below. Never remove/change the namespace.
        guard snapshot.identity.isDirectory, snapshot.identity.owner == scope.ownerUID,
              snapshot.identity.device == scope.device, as_private_descriptor(directory.fd) == 1,
              try directory.ownIdentity == snapshot.identity else { throw SweepError.denied("WebKit 临时命名空间账户、私有权限或卷未确认") }
        try SafeFilesystem.verify(snapshot)
        return snapshot
    }
    static func verify(path: String, identifier: String, scope: DarwinCacheScope) throws {
        guard root(path: path, identifier: identifier, scope: scope) != nil else { throw SweepError.denied("不是精确 WebKit 临时 Blob 目录") }
        _ = try verifyNamespace(identifier: identifier, scope: scope)
        let snapshot = try CacheDomainRule.verifyPrivateDomain(root: path)
        guard snapshot.tree.allSatisfy({ node in
            node.identity.mode & 0o170000 == 0o100000 && node.relative.range(of: #"^mapping-file-[1-9][0-9]*\.blob$"#, options: .regularExpression) != nil
        }) else { throw SweepError.denied("WebKit 临时 Blob 目录含其他资料，保留") }
        try SafeFilesystem.verify(snapshot)
    }
}
