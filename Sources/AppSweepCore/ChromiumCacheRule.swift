import Foundation
import CFSafety
#if os(macOS)
import Security
#endif

/// Runtime-declared profile caches. Display names and vendor prefixes are never
/// sufficient authority, and persistent profile directories are never moved.
enum ChromiumCacheRule {
    static let name = "chromium-registered-profile-cache-v1"
    private static func leaf(_ value: String) -> Bool {
        let lower = value.lowercased()
        return !value.isEmpty && value.utf8.count <= 255 && value != "." && value != ".." &&
            !value.contains("/") && value == value.trimmingCharacters(in:.whitespacesAndNewlines) &&
            !value.unicodeScalars.contains(where:{ CharacterSet.controlCharacters.contains($0) }) &&
            !lower.hasPrefix("com.apple.") && lower != "keychains" && !lower.hasSuffix(".keychain") &&
            !lower.hasSuffix(".keychain-db") && !["app sweep","app sweep.app","appsweep","appsweep.app"].contains(lower)
    }
    static func namespace(info: [String:Any]) -> String? {
        guard let value = info["CrProductDirName"] as? String, value.utf8.count <= 1024 else { return nil }
        let parts = value.split(separator:"/",omittingEmptySubsequences:false).map(String.init)
        guard (1...4).contains(parts.count), parts.allSatisfy(leaf) else { return nil }
        return value
    }
    /// Display-only hint. Callers must retain it; execution uses runtimeNamespace
    /// and complete publisher/ownership verification instead.
    static func discoveryNamespace(info: [String: Any], identifier: String) -> String? {
        if info["CrProductDirName"] != nil { return namespace(info: info) }
        return identifier == "com.google.Chrome" ? "Google/Chrome" : nil
    }
    private static func securedInfo(path: String, identifier: String, googlePublisher: Bool = false) throws -> [String:Any] {
        #if os(macOS)
        let infoPath = path + "/Contents/Info.plist"
        let snapshot = try SafeFilesystem.snapshot(infoPath)
        guard snapshot.identity.mode & 0o170000 == 0o100000,
              let disk = try PropertyListSerialization.propertyList(from:SafeFilesystem.readMetadata(infoPath),format:nil) as? [String:Any] else {
            throw SweepError.denied("浏览器应用元数据不是完整普通文件")
        }
        var code: SecStaticCode?, requirement: SecRequirement?
        if googlePublisher {
            guard identifier == "com.google.Chrome",
                  SecRequirementCreateWithString("anchor apple generic and identifier \"com.google.Chrome\" and certificate leaf[subject.OU] = \"EQHXZ8M8AV\"" as CFString,[],&requirement) == errSecSuccess else {
                throw SweepError.denied("浏览器缺省品牌的发布者要求未确认")
            }
        }
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath:path) as CFURL,[],&code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code,SecCSFlags(rawValue:kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode),requirement) == errSecSuccess else {
            throw SweepError.denied("浏览器签名或缺省品牌发布者未确认")
        }
        var raw: CFDictionary?
        guard SecCodeCopySigningInformation(code,SecCSFlags(rawValue:kSecCSSigningInformation),&raw) == errSecSuccess,
              let signing = raw as? [String:Any], signing[kSecCodeInfoIdentifier as String] as? String == identifier,
              let sealed = signing[kSecCodeInfoPList as String] as? [String:Any], sealed["CFBundleIdentifier"] as? String == identifier,
              NSDictionary(dictionary:sealed).isEqual(to:disk) else {
            throw SweepError.denied("当前浏览器元数据与签名保护的内容不一致")
        }
        try SafeFilesystem.verify(snapshot)
        return sealed
        #else
        throw SweepError.denied("当前平台未验收浏览器签名元数据")
        #endif
    }
    /// Signed runtime declarations are general. The documented missing-field
    /// branding default additionally requires the original anchored publisher;
    /// a display name, bundle ID or self-signed branding field cannot grant it.
    static func runtimeNamespace(path: String, identifier: String) throws -> String {
        let info = try securedInfo(path:path,identifier:identifier)
        if info["CrProductDirName"] != nil {
            guard let value = namespace(info:info) else { throw SweepError.denied("浏览器签名目录声明无效") }
            return value
        }
        guard identifier == "com.google.Chrome" else { throw SweepError.denied("浏览器没有可核验的目录声明或缺省品牌") }
        let anchored = try securedInfo(path:path,identifier:identifier,googlePublisher:true)
        guard NSDictionary(dictionary:anchored).isEqual(to:info),
              anchored["KSProductID"] == nil || anchored["KSProductID"] as? String == identifier else {
            throw SweepError.stale("浏览器品牌元数据已改变或不一致")
        }
        return "Google/Chrome"
    }
    static func profiles(data: Data) -> [String]? {
        guard data.count <= 2*1024*1024,
              let raw = try? JSONSerialization.jsonObject(with:data) as? [String:Any],
              let profile = raw["profile"] as? [String:Any],
              let entries = profile["info_cache"] as? [String:Any], !entries.isEmpty, entries.count <= 200,
              entries.allSatisfy({ leaf($0.key) && $0.value is [String:Any] }) else { return nil }
        return entries.keys.sorted()
    }
    static func profileMetadata(_ path: String) throws -> Data {
        let snapshot = try SafeFilesystem.snapshot(path)
        guard snapshot.identity.mode & 0o170000 == 0o100000, snapshot.identity.links == 1,
              snapshot.identity.owner == as_current_uid(), snapshot.identity.size <= 2*1024*1024 else {
            throw SweepError.denied("浏览器配置档元数据的所有者、类型或容量未确认")
        }
        let data = try SafeFilesystem.readMetadata(path)
        try SafeFilesystem.verify(snapshot)
        return data
    }
    static func verifiedNamespace(home: String, identifier: String, applicationPath: String, signaturePath: String?) throws -> String {
        let source = signaturePath ?? applicationPath
        if signaturePath != nil {
            try ChosenApplicationRule.verifyStored(path:source,identifier:identifier,requireNoInstalledHelpers:true)
            guard AppInspector.signatureMatches(path:source,identifier:identifier) else { throw SweepError.denied("隔离应用的浏览器签名未确认") }
        } else { _ = try AppInspector.verifiedDataOwner(path:source,identifier:identifier,home:home) }
        let value = try runtimeNamespace(path:source,identifier:identifier)
        guard SafetyPolicy(home:home,acceptedPlatform:false).protectedDenial(home + "/Library/Caches/" + value) == nil else {
            throw SweepError.denied("签名应用没有声明可核验的浏览器资料命名空间")
        }
        // A runtime declaration cannot take authority over another cache
        // format's reserved root, even when that application's body is absent.
        guard !SafetyPolicy.contains("firefox",value.lowercased()),
              !SafetyPolicy.contains(value.lowercased(),"firefox") else {
            throw SweepError.denied("浏览器声明与 Firefox 配置档缓存重叠，已保留")
        }
        return value
    }
    static func exclusive(_ value: String, app: String, inventory: [ApplicationIdentity]) throws {
        let wanted = value.lowercased()
        for peer in inventory where peer.path != app && !SafetyPolicy.contains(app,peer.path) {
            try Task.checkCancellation()
            guard !peer.path.isEmpty, !peer.bundleIdentifier.isEmpty else { throw SweepError.denied("存在未确认安装，浏览器共享命名空间归属未确认") }
            // Exact-ID caches of another app must not overlap this runtime root.
            let domains = [peer.bundleIdentifier] + (try peerNamespace(peer).map { [$0] } ?? [])
            guard !domains.contains(where:{ SafetyPolicy.contains($0.lowercased(),wanted) || SafetyPolicy.contains(wanted,$0.lowercased()) }) else {
                throw SweepError.denied("其他已安装应用使用相同或重叠的缓存命名空间，已保留")
            }
        }
    }
    private static func peerNamespace(_ peer: ApplicationIdentity) throws -> String? {
        // The inventory's signed Apple alias is independently anchored to the
        // OS. It supplies no third-party runtime namespace and is never followed.
        if peer.signed && peer.bundleIdentifier.hasPrefix("com.apple."),
           let identity = try? SafeDirectory(path:URL(fileURLWithPath:peer.path).deletingLastPathComponent().path).identity(URL(fileURLWithPath:peer.path).lastPathComponent), identity.isLink { return nil }
        // Embedded iOS/simulator .app bundles use Info.plist at their root.
        // Use the inventory's component layout reader for both flat and macOS
        // bundles; missing metadata still blocks ownership rather than guessing.
        let (info,_) = try AppInspector.metadata(peer.attributionMetadataPath ?? peer.path,component:true)
        // Quoted IDs remain non-authorizing conflict clues. Compare their exact
        // observed spelling rather than mistaking normalization for a change.
        let expectedIdentifier = peer.attributionRawIdentifier ?? peer.bundleIdentifier
        guard info["CFBundleIdentifier"] as? String == expectedIdentifier else { throw SweepError.stale("安装归属元数据的标识已改变") }
        guard info["CrProductDirName"] != nil else {
            // Chrome's public runtime contract has an implicit branding default.
            // An identifier hint may block a competing claim, never authorize
            // that peer's cache. Owner resolution still requires signed proof.
            return peer.bundleIdentifier.lowercased() == "com.google.chrome" ? "Google/Chrome" : nil
        }
        guard let value = namespace(info:info) else { throw SweepError.denied("另一应用的浏览器命名空间声明未确认") }
        return value
    }
    /// Exact bundle-ID cache/support conventions cannot override an installed
    /// runtime namespace, including the owner's own parent/child namespace.
    static func verifyNoRuntimeOverlap(identifier: String, inventory: [ApplicationIdentity]) throws {
        let domain = identifier.lowercased(), deadline = ProcessInfo.processInfo.systemUptime + 20
        for peer in inventory {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline, !peer.path.isEmpty, !peer.bundleIdentifier.isEmpty else {
                throw SweepError.incomplete("应用域的运行时共享归属未确认")
            }
            if let value = try peerNamespace(peer)?.lowercased(),
               SafetyPolicy.contains(value,domain) || SafetyPolicy.contains(domain,value) {
                throw SweepError.denied("应用域与已安装浏览器的命名空间重叠，须按配置档核验；整域保留")
            }
        }
    }
    private static func registered(home: String, namespace: String) throws -> [String] {
        let root = home + "/Library/Application Support/" + namespace
        guard let leaves = profiles(data:try profileMetadata(root + "/Local State")) else { throw SweepError.denied("浏览器配置档注册清单未确认") }
        return leaves
    }
    static func roots(home: String, app: ApplicationIdentity, inventory: [ApplicationIdentity]) throws -> [String] {
        guard AppInspector.uniqueOwner(identifier:app.bundleIdentifier,path:app.path,inventory:inventory) else { throw SweepError.denied("浏览器应用缺少唯一安装主体") }
        let value = try verifiedNamespace(home:home,identifier:app.bundleIdentifier,applicationPath:app.path,signaturePath:nil)
        try exclusive(value,app:app.path,inventory:inventory)
        let hasProfile = try SafeFilesystem.presence(home + "/Library/Application Support/" + value)
        let hasCache = try SafeFilesystem.presence(home + "/Library/Caches/" + value)
        if !hasProfile && !hasCache { return [] }
        return try registered(home:home,namespace:value).map { home + "/Library/Caches/" + value + "/" + $0 }
    }
    static func verifiedRoot(path: String, home: String, identifier: String, applicationPath: String, signaturePath: String?, inventory supplied: [ApplicationIdentity]? = nil, profileSource: String? = nil) throws -> String {
        let value = try verifiedNamespace(home:home,identifier:identifier,applicationPath:applicationPath,signaturePath:signaturePath)
        let inventory = try supplied ?? AppInspector.inventory(home:home,selectedApplication:signaturePath == nil ? applicationPath : nil)
        if signaturePath == nil {
            guard AppInspector.uniqueOwner(identifier:identifier,path:applicationPath,inventory:inventory) else { throw SweepError.denied("浏览器安装归属已改变") }
        } else {
            guard !inventory.contains(where:{ $0.bundleIdentifier.isEmpty || $0.bundleIdentifier.lowercased() == identifier.lowercased() }) else { throw SweepError.denied("隔离后仍存在同标识或未确认安装，浏览器缓存保留") }
        }
        try exclusive(value,app:applicationPath,inventory:inventory)
        let prefix = home + "/Library/Caches/" + value + "/"
        guard path == URL(fileURLWithPath:path).standardizedFileURL.path, path.hasPrefix(prefix) else { throw SweepError.denied("不是签名浏览器的缓存范围") }
        let parts = path.dropFirst(prefix.count).split(separator:"/",omittingEmptySubsequences:false).map(String.init)
        let source = profileSource ?? home + "/Library/Application Support/" + value
        guard parts.count == 2, parts.allSatisfy(leaf),
              let registered = profiles(data:try profileMetadata(source + "/Local State")),
              registered.contains(parts[0]) else { throw SweepError.denied("缓存不属于已注册的浏览器配置档") }
        let profile = source + "/" + parts[0]
        let preferences = try profileMetadata(profile + "/Preferences")
        guard let raw = try? JSONSerialization.jsonObject(with:preferences) as? [String:Any], raw["profile"] is [String:Any] else { throw SweepError.denied("浏览器配置档资料未确认，已保留") }
        let root = prefix + parts[0], directory = try SafeDirectory(path:root), profileDirectory = try SafeDirectory(path:profile)
        guard try directory.ownIdentity.owner == as_current_uid(),
              try profileDirectory.ownIdentity.owner == as_current_uid(),
              try directory.ownIdentity.device == profileDirectory.ownIdentity.device else { throw SweepError.denied("浏览器缓存的所有者或卷未确认") }
        return root
    }
    static func structuralMatch(path: String, home: String) -> Bool {
        let prefix = home + "/Library/Caches/"
        guard path.hasPrefix(prefix), path == URL(fileURLWithPath:path).standardizedFileURL.path else { return false }
        let parts = path.dropFirst(prefix.count).split(separator:"/",omittingEmptySubsequences:false).map(String.init)
        return (3...6).contains(parts.count) && parts.allSatisfy(leaf)
    }
}
