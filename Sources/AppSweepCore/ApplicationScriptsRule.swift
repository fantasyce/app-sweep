import Foundation
import CFSafety
#if os(macOS)
import Darwin
#else
import Glibc
#endif

/// NSApplicationScriptsDirectory is associated with the code-signing identifier.
/// Reading the directory never executes or resolves its scripts and links.
enum ApplicationScriptsRule {
    static let name="signed-application-scripts-v1"
    static func matches(_ path:String,home:String,identifier:String) -> Bool {
        SystemCleanupScope.validIdentifier(identifier) && XcodeRule.canonical(path) && path == home + "/Library/Application Scripts/" + identifier
    }
    static func verify(_ path:String,home:String,identifier:String) throws {
        guard matches(path,home:home,identifier:identifier),SafetyPolicy(home:home,acceptedPlatform:false).protectedDenial(path) == nil else{throw SweepError.denied("不是代码签名标识对应的应用脚本目录")}
        let snapshot=try SafeFilesystem.snapshot(path,allowInternalLinks:true,purpose:.managedData),device=try SafeDirectory(path:home).ownIdentity.device
        let nodes=[TreeEntry(relative:"",identity:snapshot.identity)]+snapshot.tree
        guard snapshot.identity.isDirectory,!SupportDomainRule.containsProtectedContent(nodes.filter{!$0.identity.isLink}),
              !nodes.contains(where:{$0.relative.split(separator:"/").contains(where:{["app sweep.app","appsweep.app"].contains($0.lowercased())})}) else{throw SweepError.denied("应用脚本目录包含安全或本应用状态，保留")}
        for ancestor in snapshot.ancestors where SafetyPolicy.contains(home,ancestor.path) {
            let directory=try SafeDirectory(path:ancestor.path)
            guard ancestor.owner == as_current_uid(),ancestor.device == device,as_unshared_node_descriptor(directory.fd,as_current_uid()) == 1 else{throw SweepError.denied("应用脚本祖先的所有者、卷或共享权限未确认")}
        }
        let deadline=ProcessInfo.processInfo.systemUptime + 300
        for node in nodes {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else{throw SweepError.incomplete("应用脚本核对超时")}
            guard node.identity.owner == as_current_uid(),node.identity.device == device,
                  node.identity.isDirectory || node.identity.isLink || node.identity.links == 1 else{throw SweepError.denied("应用脚本包含其他所有者、卷或异常硬链接")}
            if node.identity.isLink{continue}
            let target=node.relative.isEmpty ? path : path + "/" + node.relative,url=URL(fileURLWithPath:target),parent=try SafeDirectory(path:url.deletingLastPathComponent().path)
            let fd=url.lastPathComponent.withCString{openat(parent.fd,$0,O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)}
            guard fd >= 0 else{throw SweepError.incomplete("应用脚本独占权限无法核验")};defer{as_close(fd)}
            var identity=ASIdentity()
            guard as_identity_fd(fd,&identity) == 0,FileIdentity(identity) == node.identity,as_unshared_node_descriptor(fd,as_current_uid()) == 1 else{throw SweepError.denied("应用脚本的身份或共享权限改变")}
        }
        try SafeFilesystem.verify(snapshot)
    }
}
