import Foundation
import CFSafety
#if os(macOS)
import Darwin
import Security
#else
import Glibc
#endif

/// Whole private application data, never a group container or cache rule.
enum ContainerDataRule {
    static let name="exclusive-application-container-v2"
    static func matches(_ path:String,home:String,identifier:String) -> Bool {
        SystemCleanupScope.validIdentifier(identifier) && XcodeRule.canonical(path) && path == home + "/Library/Containers/" + identifier
    }
    static func verifySandbox(path:String,identifier:String) throws {
        #if os(macOS)
        var code:SecStaticCode?,raw:CFDictionary?
        guard AppInspector.signatureMatches(path:path,identifier:identifier),
              SecStaticCodeCreateWithPath(URL(fileURLWithPath:path)as CFURL,[],&code) == errSecSuccess,let code,
              SecCodeCopySigningInformation(code,SecCSFlags(rawValue:kSecCSSigningInformation),&raw) == errSecSuccess,
              let signing=raw as? [String:Any],let entitlements=signing[kSecCodeInfoEntitlementsDict as String]as? [String:Any],
              entitlements["com.apple.security.app-sandbox"]as? Bool == true else{throw SweepError.denied("应用签名未声明独立沙箱，容器资料保留")}
        #else
        throw SweepError.denied("当前平台未验证原生容器归属")
        #endif
    }
    static func verify(path:String,home:String,identifier:String) throws -> FileSnapshot {
        guard matches(path,home:home,identifier:identifier),SafetyPolicy(home:home,acceptedPlatform:false).protectedDenial(path) == nil else{throw SweepError.denied("不是当前应用的标准独占容器")}
        let snapshot=try SafeFilesystem.snapshot(path,allowInternalLinks:true,purpose:.managedData)
        try verifyContents(snapshot,home:home,identifier:identifier)
        return snapshot
    }
    /// Read-only validation also used for an already identity-bound vault object.
    /// It supplies no destination or filesystem mutation authority.
    static func verifyContents(_ snapshot:FileSnapshot,home:String,identifier:String) throws {
        let path=snapshot.path,metadata=path + "/.com.apple.containermanagerd.metadata.plist"
        let meta=try SafeFilesystem.snapshot(metadata)
        guard SystemCleanupScope.validIdentifier(identifier),snapshot.identity.isDirectory,
              let info=try PropertyListSerialization.propertyList(from:SafeFilesystem.readMetadata(metadata,maximumBytes:2*1024*1024),format:nil)as? [String:Any],
              info["MCMMetadataIdentifier"]as? String == identifier,info["MCMMetadataContentClass"]as? Int == 2,
              let user=info["MCMMetadataUserIdentity"]as? [String:Any],user["posixUID"]as? UInt32 == as_current_uid(),
              let owner=info["MCMMetadataOwnership"]as? [String:Any],owner["uid"]as? UInt32 == as_current_uid() else{throw SweepError.denied("容器标识、类别或账户所有权未确认")}
        if let associated=info["AssociatedBundleIdentifiers"] {
            guard let ids=associated as? [String],!ids.isEmpty,Set(ids) == [identifier] else{throw SweepError.denied("容器关联了其他应用，整份保留")}
        }
        try verifyPrivateTree(snapshot,home:home);try SafeFilesystem.verify(meta)
    }
    static func verifyPrivateTree(_ snapshot:FileSnapshot,home:String) throws {
        let path=snapshot.path
        let device=try SafeDirectory(path:home).ownIdentity.device
        for ancestor in snapshot.ancestors where SafetyPolicy.contains(home,ancestor.path) {
            let directory=try SafeDirectory(path:ancestor.path)
            guard ancestor.device == device,ancestor.owner == as_current_uid(),as_unshared_node_descriptor(directory.fd,as_current_uid()) == 1 else{throw SweepError.denied("容器祖先的卷、所有者或共享权限未确认")}
        }
        let nodes=[TreeEntry(relative:"",identity:snapshot.identity)]+snapshot.tree
        guard !SupportDomainRule.containsProtectedContent(nodes.filter{!$0.identity.isLink}),!nodes.contains(where:{$0.relative.split(separator:"/").contains(where:{["app sweep.app","appsweep.app"].contains($0.lowercased())})}) else{throw SweepError.denied("容器包含安全或本应用状态，整份保留")}
        let deadline=ProcessInfo.processInfo.systemUptime + 300
        for node in nodes {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else{throw SweepError.incomplete("容器独占权限核验超时")}
            guard node.identity.owner == as_current_uid(),node.identity.device == device,
                  node.identity.isDirectory || node.identity.isLink || node.identity.links == 1 else{throw SweepError.denied("容器包含其他所有者、卷或异常硬链接")}
            // macOS installs links to Documents/Downloads and other user roots.
            // Snapshot/move/restore/purge treat them as opaque directory entries.
            if node.identity.isLink{continue}
            let target=node.relative.isEmpty ? path : path + "/" + node.relative,url=URL(fileURLWithPath:target),parent=try SafeDirectory(path:url.deletingLastPathComponent().path)
            let fd=url.lastPathComponent.withCString{openat(parent.fd,$0,O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)}
            guard fd >= 0 else{throw SweepError.incomplete("容器对象的独占权限无法核验")};defer{as_close(fd)}
            var identity=ASIdentity()
            guard as_identity_fd(fd,&identity) == 0,FileIdentity(identity) == node.identity,as_unshared_node_descriptor(fd,as_current_uid()) == 1 else{throw SweepError.denied("容器对象的身份、ACL或共享权限已改变")}
        }
        try SafeFilesystem.verify(snapshot)
    }
}
