import Foundation
import CFSafety
#if os(macOS)
import Darwin
#else
import Glibc
#endif

enum XcodeGeneratedRule {
    static let name="xcode-generated-data-v1"
    static func projectDirectory(_ path: String, home: String) -> String? {
        let prefix=home + "/Library/Developer/Xcode/DerivedData/"
        guard XcodeRule.canonical(path),path.hasPrefix(prefix) else{return nil}
        let parts=path.dropFirst(prefix.count).split(separator:"/")
        guard (parts.count == 2 && parts[1] == "Index.noindex") ||
              (parts.count == 3 && parts[1] == "Build" && parts[2] == "Products") else{return nil}
        return prefix + parts[0]
    }
    static func matches(_ path: String, home: String) -> Bool {
        path == home + "/Library/Developer/Xcode/DerivedData/ModuleCache.noindex" || projectDirectory(path,home:home) != nil
    }
    static func title(_ path: String) -> String {
        if path.hasSuffix("/ModuleCache.noindex"){return "Xcode 编译模块缓存"}
        if path.hasSuffix("/Index.noindex"){return "Xcode 项目索引"}
        return "Xcode 构建产物（需要时重新编译）"
    }
    static func verify(_ path: String, home: String) throws {
        guard matches(path,home:home),SafetyPolicy(home:home,acceptedPlatform:false).lexicalDenial(path) == nil else{throw SweepError.denied("不是已登记的 Xcode 派生产物")}
        if let project=projectDirectory(path,home:home){try XcodeRule.verifyWorkspace(project)}
        _=try verifyPrivateTree(path,home:home)
    }
    static func verifyPrivateTree(_ path: String, home: String) throws -> FileSnapshot {
        let base=home + "/Library/Developer/Xcode"
        guard XcodeRule.canonical(path),SafetyPolicy.contains(base,path),path != base else{throw SweepError.denied("开发文件位置未确认")}
        let device=try SafeDirectory(path:home).ownIdentity.device
        var ancestor=path
        while SafetyPolicy.contains(home + "/Library",ancestor),ancestor != home + "/Library" {
            let directory=try SafeDirectory(path:ancestor),identity=try directory.ownIdentity
            guard identity.owner == as_current_uid(),identity.device == device,as_unshared_node_descriptor(directory.fd,as_current_uid()) == 1 else{throw SweepError.denied("开发产物目录的所有者、卷或共享权限未确认")}
            ancestor=URL(fileURLWithPath:ancestor).deletingLastPathComponent().path
        }
        // Complete private objects only. Project sources, SourcePackages and
        // custom build locations are never authorized by a similarly named path.
        let snapshot=try SafeFilesystem.snapshot(path)
        let nodes=[TreeEntry(relative:"",identity:snapshot.identity)] + snapshot.tree
        guard snapshot.identity.isDirectory,!SupportDomainRule.containsProtectedContent(nodes),
              !nodes.contains(where:{$0.relative.split(separator:"/").contains(where:{["app sweep.app","appsweep.app"].contains($0.lowercased())})}) else{throw SweepError.denied("派生产物包含安全或本应用状态，整项保留")}
        let deadline=ProcessInfo.processInfo.systemUptime + 20
        for node in nodes {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else{throw SweepError.incomplete("派生产物权限核验超时")}
            guard node.identity.owner == as_current_uid(),node.identity.mode & 0o7022 == 0,
                  node.identity.isDirectory || node.identity.links == 1 else{throw SweepError.denied("派生产物包含共享、特殊权限或硬链接，保留")}
            let target=node.relative.isEmpty ? path : path + "/" + node.relative,url=URL(fileURLWithPath:target),parent=try SafeDirectory(path:url.deletingLastPathComponent().path)
            let fd=url.lastPathComponent.withCString{openat(parent.fd,$0,O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)}
            guard fd >= 0 else{throw SweepError.denied("派生产物的权限无法核验")}
            defer{as_close(fd)}
            var identity=ASIdentity()
            guard as_identity_fd(fd,&identity) == 0,FileIdentity(identity) == node.identity,as_unshared_node_descriptor(fd,as_current_uid()) == 1 else{throw SweepError.denied("派生产物的身份或 ACL 不再独占")}
        }
        // This is an inode-preserving whole-object move. Executable outputs
        // retain their original mode; the cache archive's non-executable byte
        // reconstruction rules remain unchanged.
        try SafeFilesystem.verify(snapshot)
        return snapshot
    }
}
