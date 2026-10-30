import Foundation
import CFSafety
#if os(macOS)
import Security
#endif

/// Public producer conventions, not a match on a display name. Each entry is
/// bound to an anchored publisher and an independently documented namespace.
enum NamedApplicationRule {
    static let cacheName = "named-publisher-cache-v1"
    static let dataName = "named-publisher-data-v1"
    struct Domain: Sendable {
        let identifier: String
        let team: String
        let directory: String
    }
    static let domains: [Domain] = [
        .init(identifier:"com.sublimetext.4",team:"Z6D26JE4Y4",directory:"Sublime Text"),
        .init(identifier:GodotCacheRule.identifier,team:"6K46PWY5DM",directory:"Godot"),
        .init(identifier:"com.docker.docker",team:"9BNSXJN65R",directory:"Docker Desktop")
    ]
    static func domain(_ identifier: String) -> Domain? { domains.first{$0.identifier == identifier} }
    static func root(home: String, identifier: String, cache: Bool) -> String? {
        guard let domain=domain(identifier),!cache || identifier != GodotCacheRule.identifier else{return nil}
        return home + (cache ? "/Library/Caches/" : "/Library/Application Support/") + domain.directory
    }
    static func matches(_ path: String, home: String, identifier: String, cache: Bool) -> Bool {
        guard XcodeRule.canonical(path),let root=root(home:home,identifier:identifier,cache:cache) else{return false}
        if cache { return URL(fileURLWithPath:path).deletingLastPathComponent().path == root }
        if identifier != GodotCacheRule.identifier { return path == root }
        guard URL(fileURLWithPath:path).deletingLastPathComponent().path == root else{return false}
        let leaf=URL(fileURLWithPath:path).lastPathComponent
        // app_userdata is shared with exported games and must never be swept
        // into editor removal. Unknown/new children remain visible but retained.
        return ["projects.cfg","export_templates","feature_profiles","script_templates","text_editor_themes","shader_cache"].contains(leaf)
            || leaf.range(of:#"^editor_settings-[0-9]+\.[0-9]+\.tres$"#,options:.regularExpression) != nil
    }
    static func verifyPublisher(application: String, identifier: String) throws {
        guard let domain=domain(identifier) else{throw SweepError.denied("未登记名称目录的发布者")}
        #if os(macOS)
        var code:SecStaticCode?,requirement:SecRequirement?
        let text="anchor apple generic and identifier \"" + identifier + "\" and certificate leaf[subject.OU] = \"" + domain.team + "\""
        guard SecRequirementCreateWithString(text as CFString,[],&requirement) == errSecSuccess,
              SecStaticCodeCreateWithPath(URL(fileURLWithPath:application) as CFURL,[],&code) == errSecSuccess,let code,
              SecStaticCodeCheckValidity(code,SecCSFlags(rawValue:kSecCSStrictValidate | kSecCSCheckNestedCode | kSecCSCheckAllArchitectures),requirement) == errSecSuccess else {
            throw SweepError.denied("名称目录的原始发布者与完整签名未确认")
        }
        #else
        throw SweepError.denied("当前平台不能核对名称目录的发布者")
        #endif
    }
    static func verifyOwner(application: String, identifier: String, home: String, signaturePath: String? = nil, inventory: [ApplicationIdentity]? = nil) throws {
        let source=signaturePath ?? application
        try verifyPublisher(application:source,identifier:identifier)
        let apps:[ApplicationIdentity]
        if let signaturePath {
            let current=try AppInspector.verifyIsolatedDataOwner(original:application,stored:signaturePath,identifier:identifier,home:home)
            apps=inventory ?? current
        }
        else {
            apps=try inventory ?? AppInspector.inventory(home:home,ownershipIdentifier:identifier)
            _=try AppInspector.verifiedDataOwner(path:application,identifier:identifier,home:home)
            guard AppInspector.uniqueOwner(identifier:identifier,path:application,inventory:apps) else{throw SweepError.denied("名称目录的安装归属不唯一")}
        }
        try verifyNamespace(identifier:identifier,source:source,inventory:apps)
    }
    static func verifyNamespace(identifier:String,source:String,inventory:[ApplicationIdentity]) throws {
        guard let domain=domain(identifier),!inventory.contains(where:{ app in
            app.path != source && !SafetyPolicy.contains(source,app.path) &&
                (app.bundleIdentifier.isEmpty || app.name.caseInsensitiveCompare(domain.directory) == .orderedSame)
        }) else{throw SweepError.denied("其他应用可能使用相同名称目录，保留")}
        // A different display name does not exclude an explicit runtime claim
        // on this directory or any parent/child namespace.
        try ChromiumCacheRule.exclusive(domain.directory,app:source,inventory:inventory)
    }
    static func verify(_ path: String, home: String, identifier: String, cache: Bool) throws {
        guard matches(path,home:home,identifier:identifier,cache:cache),SafetyPolicy(home:home,acceptedPlatform:false).lexicalDenial(path) == nil else{throw SweepError.denied("不是发布者约定的独占名称目录")}
        if cache {
            guard identifier == "com.sublimetext.4" else{throw SweepError.denied("此名称缓存尚缺少独立执行验收，保留")}
            let root=root(home:home,identifier:identifier,cache:true)!
            _=try CacheDomainRule.verifyPrivateDomain(root:root)
            try CacheDomainRule.verifyMember(path:path,root:root,home:home)
        } else {
            let snapshot=try SafeFilesystem.snapshot(path)
            guard snapshot.identity.owner == as_current_uid(),snapshot.identity.mode & 0o022 == 0,
                  snapshot.tree.allSatisfy({$0.identity.owner == as_current_uid() && $0.identity.mode & 0o022 == 0}),
                  !SupportDomainRule.containsProtectedContent(snapshot.tree) else{throw SweepError.denied("名称资料包含其他所有者或安全状态，保留")}
            let parent=try SafeDirectory(path:URL(fileURLWithPath:path).deletingLastPathComponent().path)
            guard as_unshared_node_descriptor(parent.fd,as_current_uid()) == 1 else{throw SweepError.denied("名称资料的祖先存在共享写入权限，保留")}
            guard identifier == GodotCacheRule.identifier || snapshot.identity.isDirectory else{throw SweepError.denied("名称资料不是目录")}
            try SafeFilesystem.verify(snapshot)
        }
    }
}
