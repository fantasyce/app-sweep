import Foundation
import CFSafety

/// Captured current-user authority, never decoded from a plan or manifest.
struct DarwinCacheScope: Sendable {
    enum Kind: String, Sendable { case cache = "C", temporary = "T" }
    let kind: Kind
    let home: String
    let root: String
    let ownerUID: UInt32
    let device: UInt64
    private let ancestors: [AncestorIdentity]
    private let fixture: Bool
    private init(home: String, root: String, fixture: Bool, kind: Kind = .cache) throws {
        self.home=home;self.root=root;self.fixture=fixture;self.kind=kind;ownerUID=as_current_uid()
        let directory=try SafeDirectory(path:root)
        device=try directory.ownIdentity.device
        ancestors=try SafeFilesystem.ancestors(of:root)
        try verify()
    }
    static func canonicalRoot(_ raw: String, kind: Kind = .cache) -> String? {
        var path=raw.trimmingCharacters(in:.whitespacesAndNewlines)
        if path.hasSuffix("/"){path.removeLast()}
        if path.hasPrefix("/var/folders/"){path="/private" + path}
        let prefix="/private/var/folders/"
        guard XcodeRule.canonical(path),path.hasPrefix(prefix) else{return nil}
        let parts=path.dropFirst(prefix.count).split(separator:"/")
        func component(_ s: Substring) -> Bool {s.utf8.allSatisfy{(48...57).contains($0)||(65...90).contains($0)||(97...122).contains($0)||$0 == 95||$0 == 45}}
        guard parts.count == 3,parts[0].utf8.count == 2,(20...64).contains(parts[1].utf8.count),parts[2] == Substring(kind.rawValue),component(parts[0]),component(parts[1]) else{return nil}
        return path
    }
    static func current(kind: Kind = .cache) throws -> Self {
        #if os(macOS)
        guard as_current_uid() >= 500 else{throw SweepError.denied("Darwin 缓存只属于当前普通用户会话")}
        let home=try SystemIdentity.home(),raw=try BoundedProcess.run("/usr/bin/getconf",arguments:[kind == .cache ? "DARWIN_USER_CACHE_DIR" : "DARWIN_USER_TEMP_DIR"],timeout:3)
        guard let root=canonicalRoot(raw,kind:kind) else{throw SweepError.incomplete("系统返回的 Darwin 用户目录位置未确认")}
        return try Self(home:home,root:root,fixture:false,kind:kind)
        #else
        throw SweepError.denied("当前平台未验收 Darwin 用户缓存位置")
        #endif
    }
    #if DEBUG
    static func fixture(home: String, kind: Kind = .cache) throws -> Self {
        guard as_current_uid() != 0,home.hasPrefix(try SystemIdentity.home() + "/AppSweepAcceptance"),XcodeRule.canonical(home) else{throw SweepError.denied("Darwin 夹具必须位于本任务私有测试目录")}
        return try Self(home:home,root:home + (kind == .cache ? "/DarwinCache" : "/DarwinTemporary"),fixture:true,kind:kind)
    }
    #endif
    func verify() throws {
        if !fixture {guard try SystemIdentity.home() == home else{throw SweepError.denied("Darwin 缓存当前账户已改变")}}
        guard as_current_uid() == ownerUID,ownerUID >= 500,
              try SafeFilesystem.ancestors(of:root) == ancestors else{throw SweepError.stale("Darwin 缓存账户或祖先身份已改变")}
        let directory=try SafeDirectory(path:root),identity=try directory.ownIdentity
        guard identity.owner == ownerUID,identity.device == device,try SafeDirectory(path:home).ownIdentity.device == device,
              as_private_descriptor(directory.fd) == 1,
              ancestors.allSatisfy({$0.owner == 0 || ($0.owner == ownerUID && $0.mode & 0o022 == 0)}) else{throw SweepError.denied("Darwin 缓存根目录的用户、卷或私有权限未确认")}
    }
    func identifier(path: String) -> String? {
        guard kind == .cache,XcodeRule.canonical(path),path.hasPrefix(root + "/") else{return nil}
        let parts=path.dropFirst(root.count + 1).split(separator:"/")
        guard parts.count == 2,SystemCleanupScope.validIdentifier(String(parts[0])),
              !String(parts[0]).lowercased().hasPrefix("com.apple."),
              !parts.contains(where:{let s=$0.lowercased();return s == "keychains"||s.hasSuffix(".keychain")||s.hasSuffix(".keychain-db")||s.contains("appsweep")||s.contains("app-sweep")}) else{return nil}
        // These framework-generated leaves belong to the enclosing third-party
        // cache owner. This never authorizes an Apple application namespace.
        let leaf=String(parts[1])
        if leaf.lowercased().hasPrefix("com.apple."),!["com.apple.metal","com.apple.metalfe","com.apple.gpuarchiver"].contains(leaf){return nil}
        return String(parts[0])
    }
}

enum DarwinCacheRule {
    static let name="cache-darwin-application-v1"
    static func verifyRoot(identifier: String, scope: DarwinCacheScope) throws -> FileSnapshot {
        try scope.verify()
        let root=scope.root + "/" + identifier
        guard scope.identifier(path:root + "/member") == identifier else{throw SweepError.denied("不是当前用户的精确第三方 Darwin 缓存域")}
        let snapshot=try CacheDomainRule.verifyPrivateDomain(root:root)
        guard snapshot.identity.device == scope.device else{throw SweepError.denied("Darwin 应用缓存跨卷，保留")}
        return snapshot
    }
    static func verify(path: String, identifier: String, scope: DarwinCacheScope) throws {
        guard scope.identifier(path:path) == identifier else{throw SweepError.denied("Darwin 缓存对象不在登记域的直接子项中")}
        let snapshot=try verifyRoot(identifier:identifier,scope:scope)
        guard snapshot.tree.contains(where:{scope.root + "/" + identifier + "/" + $0.relative == path && !$0.relative.contains("/")}) else{throw SweepError.stale("Darwin 缓存成员已改变")}
    }
}
