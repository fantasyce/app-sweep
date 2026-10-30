import Foundation
import CFSafety

/// Independently written rule for Godot's documented editor cache namespace.
/// Project-local .godot data, settings and arbitrary neighbours are never members.
enum GodotCacheRule {
    static let name = "cache-godot-generated-v1"
    static let identifier = "org.godotengine.godot"
    struct OwnerProof { let application: String; let snapshot: FileSnapshot }
    static func ownerProof(application: String, home: String, signaturePath: String? = nil) throws -> OwnerProof {
        if let signaturePath { try AppInspector.verifyIsolatedDataOwner(original:application,stored:signaturePath,identifier:identifier,home:home) }
        else { try verifyOwner(application:application,home:home) }
        return OwnerProof(application:application,snapshot:try SafeFilesystem.snapshot(signaturePath ?? application,allowInternalLinks:true,purpose:.application,allowApplicationHardLinks:true))
    }
    static func verify(_ proof: OwnerProof, home: String, registryLookup: ApplicationRegistry.Lookup = ApplicationRegistry.systemLocations) throws {
        try SafeFilesystem.verify(proof.snapshot)
        if proof.snapshot.path == proof.application {
            _=try AppInspector.verifiedDataOwner(path:proof.application,identifier:identifier,home:home)
        } else {
            guard try !SafeFilesystem.presence(proof.application),AppInspector.signatureMatches(path:proof.snapshot.path,identifier:identifier) else {
                throw SweepError.stale("Godot 原安装位置或隔离签名已改变")
            }
            try ChosenApplicationRule.verifyStored(path:proof.snapshot.path,identifier:identifier,requireNoInstalledHelpers:true)
        }
        for location in try ApplicationRegistry.locations(identifiers:[identifier],lookup:registryLookup) {
            guard try SafeFilesystem.presence(location.path) else { continue }
            let identity=try SafeDirectory(path:location.path).ownIdentity
            guard identity.sameObject(as:proof.snapshot.identity) else { throw SweepError.stale("Godot 安装归属已改变，请重新扫描") }
        }
        try SafeFilesystem.verify(proof.snapshot)
    }
    static func matches(_ path: String, home: String) -> Bool {
        guard UserCacheNamespaceRule.namespace(path:path,home:home) == home + "/Library/Caches/Godot" else { return false }
        let leaf = URL(fileURLWithPath:path).lastPathComponent
        return leaf.range(of:#"^editor_doc_cache-[0-9]+\.[0-9]+\.res$"#,options:.regularExpression) != nil || thumbnailKey(path) != nil
    }
    static func thumbnailKey(_ path: String) -> String? {
        let url=URL(fileURLWithPath:path),leaf=url.lastPathComponent
        guard leaf.range(of:#"^resthumb-[0-9a-f]{32}(?:_small\.png|\.png|\.txt)$"#,options:.regularExpression) != nil else { return nil }
        return url.deletingLastPathComponent().path + "/" + String(leaf.prefix(41))
    }
    static func verifyNamespace(home: String) throws -> FileSnapshot {
        // Independent preview groups can be selected in smaller batches. This
        // bounded discovery limit does not change the 1000-item plan limit.
        try UserCacheNamespaceRule.verifyNamespace(home + "/Library/Caches/Godot",home:home,memberLimit:20_000)
    }
    static func members(_ path: String, home: String) throws -> Set<String> {
        guard matches(path,home:home) else { throw SweepError.denied("不是已登记的 Godot 可再生成缓存") }
        if let key=thumbnailKey(path) {
            return try CacheDomainRule.members(root:home + "/Library/Caches/Godot").filter { thumbnailKey($0) == key }
        }
        return try SafeFilesystem.presence(path) ? [path] : []
    }
    static func verifyOwner(application: String, home: String, inventory: [ApplicationIdentity]? = nil) throws {
        _=try AppInspector.verifiedDataOwner(path:application,identifier:identifier,home:home)
        let apps=try inventory ?? AppInspector.inventory(home:home,selectedApplication:application,ownershipIdentifier:identifier)
        guard AppInspector.uniqueOwner(identifier:identifier,path:application,inventory:apps) else { throw SweepError.denied("Godot 安装归属不唯一，缓存保留") }
    }
    static func verify(_ item: Candidate, home: String, ownerProof: OwnerProof? = nil) throws {
        guard item.rule == name,item.category == .cache,item.bundleIdentifier == identifier,let app=item.applicationPath,matches(item.path,home:home) else { throw SweepError.denied("Godot 缓存归属或位置未确认") }
        if let ownerProof {
            guard ownerProof.application == app else { throw SweepError.denied("Godot 主体凭据不匹配") }
            try verify(ownerProof,home:home)
        } else { try verifyOwner(application:app,home:home) }
        _=try verifyNamespace(home:home)
        let snapshot=try SafeFilesystem.snapshot(item.path)
        guard !snapshot.identity.isDirectory,snapshot.identity.links == 1,snapshot.identity.owner == as_current_uid() else { throw SweepError.denied("Godot 缓存不是独立普通文件") }
    }
    static func ensureStopped(application: String) throws {
        try ActivityInspector.ensureStopped(bundleID:identifier,applicationPath:application,additionalIdentifiers:[identifier + "."])
        try ActivityInspector.ensureSystemServicesStopped(identifiers:[identifier],applicationPath:application)
    }
}
