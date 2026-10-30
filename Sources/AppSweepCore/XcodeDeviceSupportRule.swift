import Foundation
import CFSafety
#if os(macOS)
import Darwin
#else
import Glibc
#endif

/// Device symbols retain debugging history. Developer images and SDKs are separate.
enum XcodeDeviceSupportRule {
    static let name="xcode-device-symbols-v1"
    static let families=["iOS","watchOS","tvOS","visionOS"]
    static func roots(home:String) -> [String] {families.map{home + "/Library/Developer/Xcode/" + $0 + " DeviceSupport"}}
    static func matches(_ path:String,home:String) -> Bool {
        guard XcodeRule.canonical(path),let root=roots(home:home).first(where:{path.hasPrefix($0 + "/")}) else{return false}
        let parts=path.dropFirst(root.count + 1).split(separator:"/").map(String.init)
        guard (parts.count == 2 && parts[1] == "Symbols") || (parts.count == 3 && ["arm64","arm64e"].contains(parts[1]) && parts[2] == "Symbols") else{return false}
        return parts[0].range(of:#"^(?:[A-Za-z0-9]+,[0-9]+ )?[0-9]{1,2}\.[0-9]{1,2}(?:\.[0-9]{1,2})? \([0-9]{2,3}[A-Z][A-Za-z0-9]{1,12}\)(?: arm64e?)?$"#,options:.regularExpression) != nil
    }
    static func title(_ path:String) -> String {
        let parts=path.components(separatedBy:"/")
        guard let index=parts.firstIndex(where:{$0.hasSuffix(" DeviceSupport")}),parts.count > index + 1 else{return "Xcode 设备符号（调试资料）"}
        return "Xcode 设备符号（调试资料） · " + parts[index].replacingOccurrences(of:" DeviceSupport",with:"") + " " + parts[index + 1]
    }
    static func verify(_ path:String,home:String) throws {
        guard matches(path,home:home),SafetyPolicy(home:home,acceptedPlatform:false).protectedDenial(path) == nil else{throw SweepError.denied("不是已确认版本的整份设备符号目录")}
        let snapshot=try XcodeGeneratedRule.verifyPrivateTree(path,home:home)
        var recognized=false
        for node in snapshot.tree where !node.identity.isDirectory {
            try Task.checkCancellation()
            let leaf=URL(fileURLWithPath:node.relative).lastPathComponent
            guard leaf.hasSuffix(".dylib") || leaf.hasPrefix("dyld_shared_cache_") || node.relative.contains(".dSYM/Contents/Resources/DWARF/") else{continue}
            let url=URL(fileURLWithPath:path + "/" + node.relative),parent=try SafeDirectory(path:url.deletingLastPathComponent().path)
            let fd=url.lastPathComponent.withCString{openat(parent.fd,$0,O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)}
            guard fd >= 0 else{throw SweepError.incomplete("设备符号文件无法读取")}
            defer{as_close(fd)}
            var identity=ASIdentity()
            guard as_identity_fd(fd,&identity) == 0,FileIdentity(identity) == node.identity else{throw SweepError.stale("设备符号文件身份改变")}
            let header=try FileHandle(fileDescriptor:fd,closeOnDealloc:false).read(upToCount:16) ?? Data()
            guard as_identity_fd(fd,&identity) == 0,FileIdentity(identity) == node.identity,try parent.identity(url.lastPathComponent) == node.identity else{throw SweepError.stale("设备符号读取期间改变")}
            let magic=Array(header.prefix(4))
            if [[0xcf,0xfa,0xed,0xfe],[0xce,0xfa,0xed,0xfe],[0xca,0xfe,0xba,0xbe],[0xbe,0xba,0xfe,0xca]].contains(magic) || header.starts(with:Data("dyld_v1".utf8)){recognized=true;break}
        }
        guard recognized else{throw SweepError.denied("未发现可确认的原生符号内容，整份保留")}
        try SafeFilesystem.verify(snapshot)
    }
    static func ensureStopped() throws {
        try XcodeArchiveRule.ensureStopped()
        let own=ProcessInfo.processInfo.processIdentifier
        let output=try BoundedProcess.run("/bin/ps",arguments:["-ww","-axo","pid=,command="],timeout:3)
        let pattern=#"(?:^|/)(?:lldb|lldb-server|debugserver|dsymutil|symbolicatecrash|atos|DTServiceHub)(?:\s|$)"#
        guard try !ActivityInspector.processes(output,ownPID:own).contains(where:{$0.pid != own && $0.command.range(of:pattern,options:.regularExpression) != nil}) else{throw SweepError.denied("调试或符号工具正在运行，保留设备支持资料")}
    }
}
