import Foundation
import CFSafety

public struct SafetyPolicy: Sendable {
    let home: String
    let acceptedPlatform: Bool
    let validatedRules: Set<String>
    let systemScope: SystemCleanupScope?
    let darwinScope: DarwinCacheScope?
    let darwinScopeIssue: String?
    let darwinTemporaryScope: DarwinCacheScope?
    let darwinTemporaryIssue: String?
    init(home: String, acceptedPlatform: Bool, validatedRules: Set<String> = [], darwinScope: DarwinCacheScope? = nil, darwinScopeIssue: String? = nil, darwinTemporaryScope: DarwinCacheScope? = nil, darwinTemporaryIssue: String? = nil) { self.home = home; self.acceptedPlatform = acceptedPlatform; self.validatedRules = validatedRules; systemScope = nil;self.darwinScope=darwinScope;self.darwinScopeIssue=darwinScopeIssue;self.darwinTemporaryScope=darwinTemporaryScope;self.darwinTemporaryIssue=darwinTemporaryIssue }
    init(systemScope: SystemCleanupScope) {
        self.systemScope = systemScope; home = systemScope.userHome;darwinScope=nil;darwinScopeIssue=nil;darwinTemporaryScope=nil;darwinTemporaryIssue=nil
        // Root execution has an independent matrix. User-space acceptance is not authority.
        let rules = systemScope.fixture ? Set([SystemDiagnosticRule.name,SystemDomainRule.cacheName,SystemDomainRule.logName,SystemDomainRule.currentLogName,DeletedUserArchiveRule.name,InstalledSystemHelperRule.name]) : NativeAcceptance.systemRules(for:PlatformStamp.current)
        validatedRules = rules; acceptedPlatform = !rules.isEmpty
    }
    func ruleIsValidated(_ rule: String) -> Bool { validatedRules.contains(rule) }
    // Acceptance is an embedded release property, never an environment variable or CLI flag.
    public static var current: SafetyPolicy {
        let home = (try? SystemIdentity.home()) ?? ""
        let stamp = PlatformStamp.current
        let enabled = !home.isEmpty && as_current_uid() != 0 && stamp.map { NativeAcceptance.matches($0, accepted: NativeAcceptance.platforms) } == true
        var darwin:DarwinCacheScope?,darwinIssue:String?
        do{darwin=try DarwinCacheScope.current()}catch{darwinIssue=error.localizedDescription}
        var temporary: DarwinCacheScope?, temporaryIssue: String?
        do { temporary = try DarwinCacheScope.current(kind: .temporary) } catch { temporaryIssue = error.localizedDescription }
        return SafetyPolicy(home: home, acceptedPlatform: enabled, validatedRules: NativeAcceptance.rules(for: stamp),darwinScope:darwin,darwinScopeIssue:darwinIssue,darwinTemporaryScope:temporary,darwinTemporaryIssue:temporaryIssue)
    }
    public var executionEnabled: Bool { acceptedPlatform }
    public var limitation: String? { executionEnabled ? nil : "当前系统与架构尚未完成验收，仅允许只读扫描。" }
    public func lexicalDenial(_ path: String) -> String? {
        if let protected = protectedDenial(path) { return protected }
        let roots = ["/Applications", home + "/Applications", home + "/Library/Caches", home + "/Library/Logs", home + "/Library/Preferences", home + "/Library/Application Support", home + "/Library/Containers", home + "/Library/Developer/Xcode/DerivedData"]
        guard roots.contains(where: { Self.contains($0, path) && $0 != path }) else { return "不在已验证的清理范围内" }
        return nil
    }
    func denial(_ item: Candidate) -> String? {
        if let systemScope { return systemScope.denial(item) }
        return denial(path: item.path, category: item.category, rule: item.rule)
    }
    func denial(path: String, category: CandidateCategory, rule: String) -> String? {
        if let systemScope { return systemScope.pathDenial(path,category:category,rule:rule) }
        if rule == AIDiagnosticRule.name {
            guard category == .log, AIDiagnosticRule.matches(path: path, home: home) else {
                return "不是已登记生产者的固定诊断日志"
            }
            return protectedDenial(path)
        }
        if AdditionalCleanupRule.names.contains(rule) {
            guard category == .userData, AdditionalCleanupRule.matches(path: path, rule: rule, home: home) else {
                return "不是已登记的个人资料管理范围"
            }
            // Only the exact Mail Downloads copy location is an exception to
            // the Apple namespace guard; mailbox databases remain protected.
            let mailNamespace = rule == MailDownloadRule.name ? home + "/Library/Containers/com.apple.mail" : nil
            return protectedDenial(path, appleCacheNamespace: mailNamespace)
        }
        if ToolCacheRule.rules.contains(rule) {
            if let protected = protectedDenial(path) { return protected }
            return category == .development && ToolCacheRule.location(path, home: home)?.producer.rule == rule
                ? nil : "工具规则与精确缓存格式不匹配"
        }
        if rule == ToolCacheCatalog.rule {
            if let protected = protectedDenial(path) { return protected }
            return category == .development && ToolCacheCatalog.entries(home: home).contains { Self.contains($0.path, path) }
                ? nil : "不是已登记的只读工具发现位置"
        }
        if rule == ApplicationStorageRule.name {
            let leaf = URL(fileURLWithPath: path).lastPathComponent
            let identifier = leaf.hasSuffix(".binarycookies") ? String(leaf.dropLast(".binarycookies".count)) : leaf
            return category == .userData && ApplicationStorageRule.matches(path: path, home: home, identifier: identifier)
                ? nil : "不是已登记的独立应用网页资料"
        }
        if rule == SimulatorCacheRule.name {
            guard category == .development,SimulatorCacheRule.deviceID(path,home:home) != nil else{return "不是已登记模拟器中的独立缓存子项"}
            return protectedDenial(path,appleCacheNamespace:path)
        }
        if rule == DocumentVersionRule.name {
            if let protected=protectedDenial(path){return protected}
            return category == .userData && DocumentVersionRule.matches(path,home:home) ? nil : "不是本地文稿历史范围"
        }
        if rule == StaleUserAgentRule.name || rule == ApplicationAgentRule.name {
            guard category == (rule == StaleUserAgentRule.name ? .userData : .backgroundComponent),StaleUserAgentRule.label(path:path,home:home) != nil else{return "不是已登记的当前用户后台项"}
            return protectedDenial(path,appleCacheNamespace:nil,userAgentPath:path)
        }
        if rule == ApplicationGroupRule.name {
            if let protected=protectedDenial(path){return protected}
            return category == .userData && ApplicationGroupRule.matches(path,home:home) ? nil : "不是已登记的应用组资料目录"
        }
        if rule == ApplicationScriptsRule.name {
            if let protected=protectedDenial(path){return protected}
            let identifier=URL(fileURLWithPath:path).lastPathComponent
            return category == .userData && ApplicationScriptsRule.matches(path,home:home,identifier:identifier) ? nil : "不是代码签名标识对应的应用脚本目录"
        }
        if rule == ContainerDataRule.name {
            if let protected=protectedDenial(path){return protected}
            let identifier=URL(fileURLWithPath:path).lastPathComponent
            return category == .userData && ContainerDataRule.matches(path,home:home,identifier:identifier) ? nil : "不是已登记的独占应用容器"
        }
        if rule == DarwinCacheRule.name {
            guard category == .cache,let darwinScope,darwinScope.home == home,darwinScope.identifier(path:path) != nil else{return "Darwin 缓存子项类型尚未验收或所属范围未确认，保留"}
            return nil
        }
        if rule == WebKitCacheRule.name {
            guard category == .cache, let scope = darwinScope, scope.home == home,
                  let namespace = path.dropFirst(scope.root.count + 1).split(separator: "/").first,
                  let separator = namespace.firstIndex(of: "+"),
                  WebKitCacheRule.root(path: path, identifier: String(namespace[namespace.index(after: separator)...]), scope: scope) != nil else {
                return "不是当前账户已登记的 WebKit 缓存子项"
            }
            return nil
        }
        if rule == WebKitTemporaryRule.name {
            guard category == .cache, let scope = darwinTemporaryScope, scope.home == home,
                  path.hasPrefix(scope.root + "/"), let namespace = path.dropFirst(scope.root.count + 1).split(separator: "/").first,
                  namespace.hasPrefix("com.apple.WebKit.Networking+"),
                  WebKitTemporaryRule.root(path: path, identifier: String(namespace.dropFirst("com.apple.WebKit.Networking+".count)), scope: scope) != nil else { return "不是当前账户已验证的 WebKit 临时 Blob 子目录" }
            return nil
        }
        if rule == XcodeDeviceSupportRule.name {
            if let protected=protectedDenial(path){return protected}
            return category == .userData && XcodeDeviceSupportRule.matches(path,home:home) ? nil : "不是已登记的整份设备符号目录"
        }
        if rule == XcodeArchiveRule.name {
            if let protected=protectedDenial(path){return protected}
            return category == .userData && XcodeArchiveRule.matches(path,home:home) ? nil : "不是已登记位置中的整份 Xcode 归档"
        }
        if ApplicationCacheRule.rules.contains(rule) {
            guard category == .cache,let namespace=ApplicationCacheRule.ownerNamespace(path:path,home:home,rule:rule) else { return "不是已登记的应用缓存子对象" }
            return protectedDenial(path,appleCacheNamespace:namespace)
        }
        if rule == DeviceBackupRule.name {
            if let protected = protectedDenial(path) { return protected }
            return category == .deviceBackup && DeviceBackupRule.matches(path:path,home:home) ? nil : "不是已登记的整份本地设备备份"
        }
        if category == .application && rule == SelectedApplicationRule.name {
            if let protected = protectedDenial(path) { return protected }
            return SelectedApplicationRule.matches(path: path, policy: self) ? nil : "此应用位置尚未完成验证，已保留"
        }
        return lexicalDenial(path)
    }
    func protectedDenial(_ path: String) -> String? {
        protectedDenial(path,appleCacheNamespace:nil)
    }
    private func protectedDenial(_ path: String, appleCacheNamespace: String?, userAgentPath:String?=nil) -> String? {
        guard path.hasPrefix("/"), !path.contains("\0") else { return "路径无效" }
        let parts = path.split(separator: "/", omittingEmptySubsequences: false)
        guard !parts.contains(".."), !parts.contains("."), !path.contains("//"), !path.hasSuffix("/") else { return "拒绝路径别名" }
        for root in ["/System", "/Library", "/private", "/var", "/tmp", "/dev", "/Volumes"] {
            if Self.contains(root.lowercased(), path.lowercased()) { return "系统或其他卷受保护" }
        }
        for root in [home + "/Library/Keychains", home + "/Library/Application Support/com.apple.TCC", home + "/Library/Application Support/App Sweep", home + "/Library/Saved Application State", home + "/Library/LaunchAgents"] {
            if path == userAgentPath,root == home + "/Library/LaunchAgents"{continue}
            if Self.contains(root.lowercased(), path.lowercased()) { return "安全、运行或恢复状态受保护" }
        }
        var prefix=""
        for part in path.split(separator:"/") {
            prefix += "/" + part
            let name=part.lowercased()
            if (name.hasPrefix("com.apple.") && prefix != appleCacheNamespace) || name == "app sweep.app" || name == "appsweep.app" { return "Apple 或本应用受保护" }
        }
        return nil
    }
    static func contains(_ root: String, _ path: String) -> Bool { path == root || path.hasPrefix(root + "/") }
}

public struct OwnershipEvidence: Codable, Sendable, Equatable {
    public enum Kind: String, Codable, Sendable { case nameHint, vendorHint, bundleIdentifier, signature, containerMetadata, validatedRule }
    public let kind: Kind
    public let detail: String
    public let verified: Bool
    public var authorizes: Bool { verified && kind != .nameHint && kind != .vendorHint }
}
