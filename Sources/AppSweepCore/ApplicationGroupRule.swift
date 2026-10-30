import Foundation
import CFSafety
#if os(macOS)
import Security
import AppKit
#endif

/// An entitlement is a membership claim. Creator metadata and other installed
/// users are checked separately before it can authorise whole group data.
enum ApplicationGroupRule {
    static let name="exclusive-declared-app-group-v1"
    static func validGroup(_ id:String) -> Bool {
        guard AppInspector.validIdentifier(id),id.utf8.count <= 255,
              !id.lowercased().contains("com.apple."),!id.lowercased().contains("appsweep"),!id.lowercased().contains("app-sweep") else{return false}
        return id.hasPrefix("group.") || id.split(separator:".").first?.range(of:#"^[A-Z0-9]{10}$"#,options:.regularExpression) != nil
    }
    static func matches(_ path:String,home:String) -> Bool {
        let prefix=home + "/Library/Group Containers/"
        guard XcodeRule.canonical(path),path.hasPrefix(prefix) else{return false}
        let leaf=String(path.dropFirst(prefix.count));return !leaf.contains("/") && validGroup(leaf)
    }
    private static func code(_ path:String) throws -> (identifier:String,groups:Set<String>)? {
        #if os(macOS)
        var code:SecStaticCode?,raw:CFDictionary?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath:path)as CFURL,[],&code) == errSecSuccess,let code else{throw SweepError.incomplete("应用组件签名声明无法读取")}
        let status=SecCodeCopySigningInformation(code,SecCSFlags(rawValue:kSecCSSigningInformation),&raw)
        if status == errSecCSUnsigned{return nil}
        guard status == errSecSuccess,let info=raw as? [String:Any] else{throw SweepError.incomplete("应用组件签名声明未确认")}
        guard let id=info[kSecCodeInfoIdentifier as String]as? String else {
            if info[kSecCodeInfoEntitlementsDict as String] == nil{return nil}
            throw SweepError.incomplete("应用组声明缺少代码标识")
        }
        let entitlements=info[kSecCodeInfoEntitlementsDict as String]as? [String:Any] ?? [:]
        guard let value=entitlements["com.apple.security.application-groups"] else{return(id,[])}
        // Other applications can legitimately declare protected Apple groups.
        // They are read-only reference inputs; the cleanup namespace restriction
        // applies to the selected group, not every unrelated declaration.
        guard let groups=value as? [String],groups.count <= 128,groups.allSatisfy({!$0.isEmpty && $0.utf8.count <= 255 && !$0.contains("\0") && !$0.contains("\n") && !$0.contains("\r")}) else{throw SweepError.incomplete("应用组声明格式未确认")}
        return(id,Set(groups))
        #else
        throw SweepError.denied("当前平台未验证原生应用组声明")
        #endif
    }
    static func declarations(applicationPath:String,identifier:String) throws -> [String:Set<String>] {
        guard SystemCleanupScope.validIdentifier(identifier),AppInspector.signatureMatches(path:applicationPath,identifier:identifier) else{throw SweepError.denied("应用组缺少原主体的有效签名")}
        let snapshot=try SafeFilesystem.snapshot(applicationPath,allowInternalLinks:true,purpose:.application,allowApplicationHardLinks:true)
        var paths=[applicationPath]
        paths += snapshot.tree.filter{$0.identity.isDirectory && ["app","xpc","appex"].contains(URL(fileURLWithPath:$0.relative).pathExtension)}.map{applicationPath + "/" + $0.relative}
        guard paths.count <= 128 else{throw SweepError.incomplete("应用组组件数量超过核对容量")}
        var result:[String:Set<String>]=[:]
        for path in paths {
            try Task.checkCancellation()
            guard let signed=try code(path) else{continue}
            for group in signed.groups where validGroup(group){result[group,default:[]].insert(signed.identifier)}
        }
        try SafeFilesystem.verify(snapshot);return result
    }
    static func membership(group:String,signaturePath:String,originalApplicationPath:String,identifier:String,inventory:[ApplicationIdentity]) throws -> Set<String> {
        guard validGroup(group),let creators=try declarations(applicationPath:signaturePath,identifier:identifier)[group],!creators.isEmpty else{throw SweepError.denied("所选应用及内嵌组件没有声明此应用组")}
        try ActivityInspector.ensureStopped(bundleID:identifier,applicationPath:signaturePath,additionalIdentifiers:Array(creators))
        try ActivityInspector.ensureSystemServicesStopped(identifiers:[identifier]+creators.sorted(),applicationPath:signaturePath)
        let deadline=ProcessInfo.processInfo.systemUptime + 20
        for app in inventory where !SafetyPolicy.contains(originalApplicationPath,app.path) {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else{throw SweepError.incomplete("其他应用的共享组引用核对超时")}
            guard !app.path.isEmpty,!app.bundleIdentifier.isEmpty else{throw SweepError.incomplete("存在无法确认的安装或组件，应用组保留")}
            if try code(app.path)?.groups.contains(group) == true{throw SweepError.denied("其他已安装应用或组件也声明此应用组，整份保留：" + app.name)}
        }
        #if os(macOS)
        for app in NSWorkspace.shared.runningApplications {
            guard let path=app.bundleURL?.path,!SafetyPolicy.contains(originalApplicationPath,path),!SafetyPolicy.contains(signaturePath,path) else{continue}
            if try code(path)?.groups.contains(group) == true{throw SweepError.denied("其他运行中的应用声明此应用组，保留")}
        }
        #endif
        return creators
    }
    static func verifyContents(_ snapshot:FileSnapshot,home:String,group:String,creators:Set<String>) throws {
        let metadata=try SafeFilesystem.snapshot(snapshot.path + "/.com.apple.containermanagerd.metadata.plist")
        guard validGroup(group),let info=try PropertyListSerialization.propertyList(from:SafeFilesystem.readMetadata(metadata.path,maximumBytes:2*1024*1024),format:nil)as? [String:Any],
              info["MCMMetadataIdentifier"]as? String == group,info["MCMMetadataContentClass"]as? Int == 7,
              let creator=info["MCMMetadataCreator"]as? String,creators.contains(creator),SystemCleanupScope.validIdentifier(creator),
              let user=info["MCMMetadataUserIdentity"]as? [String:Any],user["posixUID"]as? UInt32 == as_current_uid(),
              let owner=info["MCMMetadataOwnership"]as? [String:Any],owner["uid"]as? UInt32 == as_current_uid() else{throw SweepError.denied("应用组原生标识、创建者、类别或账户归属不一致，保留")}
        if let value=info["AssociatedBundleIdentifiers"] {
            guard let ids=value as? [String],!ids.isEmpty,Set(ids).isSubset(of:creators) else{throw SweepError.denied("应用组还关联其他标识，保留")}
        }
        try ContainerDataRule.verifyPrivateTree(snapshot,home:home);try SafeFilesystem.verify(metadata)
    }
    static func verify(path:String,home:String,signaturePath:String,originalApplicationPath:String,identifier:String,inventory:[ApplicationIdentity]) throws {
        guard matches(path,home:home),SafetyPolicy(home:home,acceptedPlatform:false).protectedDenial(path) == nil else{throw SweepError.denied("不是已登记的应用组目录")}
        let group=URL(fileURLWithPath:path).lastPathComponent,creators=try membership(group:group,signaturePath:signaturePath,originalApplicationPath:originalApplicationPath,identifier:identifier,inventory:inventory)
        try verifyContents(SafeFilesystem.snapshot(path,allowInternalLinks:true,purpose:.managedData),home:home,group:group,creators:creators)
    }
}
