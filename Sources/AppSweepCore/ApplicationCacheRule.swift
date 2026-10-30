import Foundation
import CFSafety
#if os(macOS)
import Security
#endif

/// Typed exceptions for an application's regenerable cache. Neither rule grants
/// authority over an Apple application, a container root or other container data.
enum ApplicationCacheRule {
    static let appleName = "cache-apple-application-v1"
    static let containerName = "cache-application-container-v1"
    static let rules = [appleName,containerName]
    static func root(home: String, identifier: String, rule: String) -> String {
        rule == containerName ? home + "/Library/Containers/" + identifier + "/Data/Library/Caches" : CacheDomainRule.root(home:home,identifier:identifier)
    }
    static func identifier(path: String, home: String, rule: String) -> String? {
        guard rules.contains(rule), path == URL(fileURLWithPath:path).standardizedFileURL.path,
              !path.contains("\0"), !path.contains("//"), !path.hasSuffix("/") else { return nil }
        let prefix=home + (rule == containerName ? "/Library/Containers/" : "/Library/Caches/")
        guard path.hasPrefix(prefix) else { return nil }
        let parts=path.dropFirst(prefix.count).split(separator:"/",omittingEmptySubsequences:false)
        guard parts.count == (rule == containerName ? 5 : 2),
              parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }),
              AppInspector.validIdentifier(String(parts[0])),
              rule != appleName || parts[0].hasPrefix("com.apple."),
              rule != containerName || Array(parts[1...3]) == ["Data","Library","Caches"] else { return nil }
        let id=String(parts[0])
        guard !id.lowercased().contains("appsweep"),!id.lowercased().contains("app-sweep") else { return nil }
        return id
    }
    static func ownerNamespace(path: String, home: String, rule: String) -> String? {
        guard let id=identifier(path:path,home:home,rule:rule) else { return nil }
        return home + (rule == containerName ? "/Library/Containers/" : "/Library/Caches/") + id
    }
    static func systemApplications() throws -> [ApplicationIdentity] {
        var apps:[ApplicationIdentity]=[]
        for root in ["/System/Applications","/System/Applications/Utilities"] {
            guard try SafeFilesystem.presence(root) else { continue }
            let directory=try SafeDirectory(path:root),before=try directory.ownIdentity
            var bytes=[UInt8](repeating:0,count:512*1024),count=0
            guard as_directory_entries(directory.fd,&bytes,bytes.count,256,&count) == 0,
                  let names=String(bytes:bytes.prefix(count),encoding:.utf8) else { throw SweepError.incomplete("Apple 应用发现截断，相关缓存保留") }
            for name in names.split(separator:"\0").map(String.init).sorted() where name.hasSuffix(".app") {
                try Task.checkCancellation()
                // Discovery only; the actual rule checks the Apple anchor.
                if let app=try? AppInspector.inspect(root + "/" + name,verifySignature:false) { apps.append(app) }
            }
            guard try directory.ownIdentity == before else { throw SweepError.stale("Apple 应用目录在发现期间改变") }
        }
        return apps
    }
    static func verifyOwner(path: String, identifier: String, home: String, rule: String) throws {
        if identifier.hasPrefix("com.apple.") {
            let parent=URL(fileURLWithPath:path).deletingLastPathComponent().path
            guard ["/System/Applications","/System/Applications/Utilities"].contains(parent),path.hasSuffix(".app") else { throw SweepError.denied("不是已核验的 Apple 用户应用主体") }
            let (info,_)=try AppInspector.metadata(path,component:false)
            guard info["CFBundleIdentifier"] as? String == identifier,info["CFBundlePackageType"] as? String == "APPL",
                  info["LSUIElement"] as? Bool != true,info["LSBackgroundOnly"] as? Bool != true,
                  try SafeDirectory(path:path).ownIdentity.owner == 0 else { throw SweepError.denied("Apple 后台或系统状态应用不在用户缓存规则范围") }
            #if os(macOS)
            var code:SecStaticCode?,requirement:SecRequirement?,raw:CFDictionary?
            guard SecStaticCodeCreateWithPath(URL(fileURLWithPath:path) as CFURL,[],&code) == errSecSuccess,let code,
                  SecRequirementCreateWithString("anchor apple" as CFString,[],&requirement) == errSecSuccess,let requirement,
                  SecStaticCodeCheckValidity(code,SecCSFlags(rawValue:kSecCSStrictValidate | kSecCSCheckAllArchitectures),requirement) == errSecSuccess,
                  SecCodeCopySigningInformation(code,SecCSFlags(rawValue:kSecCSSigningInformation),&raw) == errSecSuccess,
                  let signing=raw as? [String:Any],signing[kSecCodeInfoIdentifier as String] as? String == identifier else { throw SweepError.denied("Apple 签名锚点及标识未确认") }
            #else
            throw SweepError.denied("当前平台未核验 Apple 缓存签名")
            #endif
        } else {
            guard rule == containerName else { throw SweepError.denied("Apple 缓存不能借用第三方归属") }
            _=try AppInspector.verifiedDataOwner(path:path,identifier:identifier,home:home)
            let inventory=try AppInspector.inventory(home:home,selectedApplication:path)
            guard AppInspector.uniqueOwner(identifier:identifier,path:path,inventory:inventory) else { throw SweepError.denied("容器缓存的应用归属不唯一") }
        }
        if rule == containerName {
            #if os(macOS)
            var code:SecStaticCode?,raw:CFDictionary?
            guard SecStaticCodeCreateWithPath(URL(fileURLWithPath:path) as CFURL,[],&code) == errSecSuccess,let code,
                  SecCodeCopySigningInformation(code,SecCSFlags(rawValue:kSecCSSigningInformation),&raw) == errSecSuccess,
                  let signing=raw as? [String:Any],let entitlements=signing[kSecCodeInfoEntitlementsDict as String] as? [String:Any],
                  entitlements["com.apple.security.app-sandbox"] as? Bool == true else { throw SweepError.denied("签名未声明独立应用沙箱，容器缓存保留") }
            #else
            throw SweepError.denied("当前平台未核验容器签名声明")
            #endif
        }
    }
    static func verifyRoot(home: String, identifier: String, applicationPath: String, rule: String) throws -> FileSnapshot {
        let root=Self.root(home:home,identifier:identifier,rule:rule),probe=root + "/member"
        guard Self.identifier(path:probe,home:home,rule:rule) == identifier,
              SafetyPolicy(home:home,acceptedPlatform:false).denial(path:probe,category:.cache,rule:rule) == nil else { throw SweepError.denied("缓存规则路径越界") }
        try verifyOwner(path:applicationPath,identifier:identifier,home:home,rule:rule)
        let device=try SafeDirectory(path:home).ownIdentity.device
        var ancestor=root
        while SafetyPolicy.contains(home + "/Library",ancestor),ancestor != home + "/Library" {
            let directory=try SafeDirectory(path:ancestor),identity=try directory.ownIdentity
            guard identity.owner == as_current_uid(),identity.device == device,as_unshared_node_descriptor(directory.fd,as_current_uid()) == 1 else { throw SweepError.denied("缓存祖先的所有者、卷或共享权限未确认") }
            ancestor=URL(fileURLWithPath:ancestor).deletingLastPathComponent().path
        }
        if rule == containerName {
            let metadata=home + "/Library/Containers/" + identifier + "/.com.apple.containermanagerd.metadata.plist"
            let snapshot=try SafeFilesystem.snapshot(metadata)
            guard !snapshot.identity.isDirectory,snapshot.identity.owner == as_current_uid(),snapshot.identity.links == 1,snapshot.identity.mode & 0o022 == 0,
                  let info=try PropertyListSerialization.propertyList(from:SafeFilesystem.readMetadata(metadata,maximumBytes:2*1024*1024),format:nil) as? [String:Any],
                  info["MCMMetadataIdentifier"] as? String == identifier,info["MCMMetadataContentClass"] as? Int == 2,
                  let user=info["MCMMetadataUserIdentity"] as? [String:Any],user["posixUID"] as? UInt32 == as_current_uid() else { throw SweepError.denied("容器元数据标识、类别或用户归属未确认") }
            // Native containers can omit this supplemental dictionary. The
            // filesystem owner, private ancestors, native user identity and
            // signed sandbox declaration above remain mandatory.
            if let ownership=info["MCMMetadataOwnership"] {
                guard let owner=ownership as? [String:Any],owner["uid"] as? UInt32 == as_current_uid() else {
                    throw SweepError.denied("容器附加所有权与当前用户不一致或格式未确认")
                }
            }
            if let associated=info["AssociatedBundleIdentifiers"] {
                guard let ids=associated as? [String],!ids.isEmpty,Set(ids) == [identifier] else { throw SweepError.denied("容器关联了其他应用或归属未确认") }
            }
            try SafeFilesystem.verify(snapshot)
        }
        return try CacheDomainRule.verifyPrivateDomain(root:root)
    }
    static func verify(_ item: Candidate, home: String) throws {
        guard item.category == .cache,let id=item.bundleIdentifier,let app=item.applicationPath,
              identifier(path:item.path,home:home,rule:item.rule) == id else { throw SweepError.denied("缓存对象与登记归属不一致") }
        let snapshot=try verifyRoot(home:home,identifier:id,applicationPath:app,rule:item.rule)
        guard snapshot.tree.contains(where:{root(home:home,identifier:id,rule:item.rule) + "/" + $0.relative == item.path && !$0.relative.contains("/")}) else { throw SweepError.stale("缓存成员已改变") }
    }
}
