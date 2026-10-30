import Foundation
import CFSafety

/// Archives contain personal build/symbol history, not disposable cache data.
enum XcodeArchiveRule {
    static let name="xcode-archive-management-v1"
    static func children(_ path: String) throws -> [String] {
        let directory=try SafeDirectory(path:path),before=try directory.ownIdentity
        var buffer=[UInt8](repeating:0,count:2*1024*1024),count=0
        guard as_directory_entries(directory.fd,&buffer,buffer.count,1000,&count) == 0,
              let text=String(bytes:buffer.prefix(count),encoding:.utf8) else{throw SweepError.incomplete("归档目录枚举失败或截断")}
        guard try directory.ownIdentity == before,try SafeDirectory(path:path).ownIdentity == before else{throw SweepError.stale("归档目录在发现期间改变")}
        return text.split(separator:"\0").map(String.init).sorted()
    }
    static func matches(_ path: String, home: String) -> Bool {
        let prefix=home + "/Library/Developer/Xcode/Archives/"
        guard XcodeRule.canonical(path),path.hasPrefix(prefix) else{return false}
        let parts=path.dropFirst(prefix.count).split(separator:"/")
        return parts.count == 2 && parts[0].range(of:#"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"#,options:.regularExpression) != nil && parts[1].hasSuffix(".xcarchive") && parts[1].count > 10
    }
    static func inspect(_ path: String, home: String) throws -> String {
        guard matches(path,home:home),SafetyPolicy(home:home,acceptedPlatform:false).protectedDenial(path) == nil else{throw SweepError.denied("不是已登记位置中的整份 Xcode 归档")}
        let metadata=try SafeFilesystem.snapshot(path + "/Info.plist")
        guard !metadata.identity.isDirectory,metadata.identity.links == 1,metadata.identity.owner == as_current_uid(),
              let info=try PropertyListSerialization.propertyList(from:SafeFilesystem.readMetadata(metadata.path,maximumBytes:2*1024*1024),format:nil)as? [String:Any],
              info["ArchiveVersion"]as? Int == 2,info["CreationDate"]is Date,
              let name=info["Name"]as? String,!name.isEmpty,name.utf8.count <= 1024,
              let scheme=info["SchemeName"]as? String,!scheme.isEmpty,scheme.utf8.count <= 1024 else{throw SweepError.denied("Xcode 归档元数据不完整，整份保留")}
        _=try SafeDirectory(path:path + "/Products")
        _=try XcodeGeneratedRule.verifyPrivateTree(path,home:home)
        try SafeFilesystem.verify(metadata)
        let label=String(name.unicodeScalars.filter{!CharacterSet.controlCharacters.contains($0)}.prefix(100))
        return "Xcode 归档（个人资料） · " + label
    }
    static func ensureStopped() throws {
        try ActivityInspector.ensureBuildToolsStopped()
        try ActivityInspector.ensureStopped(bundleID:"com.apple.dt.Xcode",applicationPath:nil)
    }
}
