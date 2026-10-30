import Foundation
import CFSafety
#if os(macOS)
import Darwin
#else
import Glibc
#endif

public struct SimulatorDeviceReference:Codable,Sendable,Equatable {
    let id:String
    let runtime:String
    let deviceType:String
    let dataIdentity:FileIdentity
}

/// Only independent cache children of a native registered, stopped device.
/// Device data, runtimes, SDKs and the native device registry are never moved.
enum SimulatorCacheRule {
    static let name="registered-simulator-cache-v1"
    static let tool="/Library/Developer/PrivateFrameworks/CoreSimulator.framework/Versions/A/Resources/bin/simctl"
    struct Device:Sendable {
        let id:String, runtime:String, deviceType:String, dataPath:String, title:String, state:String
        let available:Bool
    }
    static func sameDataDirectory(_ current:FileIdentity,_ original:FileIdentity)->Bool{
        // Booting changes a device directory's contents and modification time.
        // Bind its physical directory and permissions, not mutable child metadata.
        current.isDirectory && original.isDirectory && current.sameVolume(as:original) && current.inode == original.inode && current.owner == original.owner && current.mode == original.mode
    }
    static func deviceID(_ path:String,home:String)->String?{
        let prefix=home+"/Library/Developer/CoreSimulator/Devices/"
        guard XcodeRule.canonical(path),path.hasPrefix(prefix) else{return nil}
        let parts=path.dropFirst(prefix.count).split(separator:"/").map(String.init)
        guard parts.count == 5,UUID(uuidString:parts[0])?.uuidString == parts[0],
              Array(parts[1...3]) == ["data","Library","Caches"],!parts[4].isEmpty else{return nil}
        return parts[0]
    }
    static func parse(_ data:Data,home:String)throws->[Device]{
        guard data.count <= 2*1024*1024,let object=try JSONSerialization.jsonObject(with:data)as? [String:Any],
              let runtimes=object["devices"]as? [String:[[String:Any]]],runtimes.count <= 100 else{throw SweepError.incomplete("模拟器注册列表无法确认")}
        var result:[Device]=[],seen=Set<String>()
        for (runtime,rows) in runtimes {
            guard runtime.hasPrefix("com.apple.CoreSimulator.SimRuntime."),AppInspector.validIdentifier(runtime) else{throw SweepError.incomplete("模拟器运行时标识未知")}
            for row in rows {
                guard result.count < 1000,let id=row["udid"]as? String,UUID(uuidString:id)?.uuidString == id,seen.insert(id).inserted,
                      let dataPath=row["dataPath"]as? String,dataPath == home+"/Library/Developer/CoreSimulator/Devices/"+id+"/data",
                      let type=row["deviceTypeIdentifier"]as? String,type.hasPrefix("com.apple.CoreSimulator.SimDeviceType."),AppInspector.validIdentifier(type),
                      let state=row["state"]as? String,!state.isEmpty,state.utf8.count <= 128,
                      let available=row["isAvailable"]as? Bool,let title=row["name"]as? String,title.utf8.count <= 1024 else{throw SweepError.incomplete("模拟器设备身份、位置或状态未确认")}
                result.append(.init(id:id,runtime:runtime,deviceType:type,dataPath:dataPath,title:String(title.unicodeScalars.filter{!CharacterSet.controlCharacters.contains($0)}.prefix(100)),state:state,available:available))
            }
        }
        return result.sorted{$0.id < $1.id}
    }
    static func devices(home:String)throws->[Device]{
        #if os(macOS)
        let binary=try SafeFilesystem.snapshot(tool)
        guard binary.identity.owner == 0,binary.identity.links == 1,!binary.identity.isDirectory,
              binary.identity.mode & 0o7022 == 0,binary.identity.mode & 0o111 != 0,
              try BoundedProcess.capture("/usr/bin/codesign",arguments:["--verify","--strict","-R","=anchor apple",tool],timeout:10,mergeStderr:true).status == 0 else{throw SweepError.denied("原生模拟器工具签名未确认")}
        try SafeFilesystem.verify(binary)
        let text=try BoundedProcess.run(tool,arguments:["list","devices","--json"],timeout:15)
        try SafeFilesystem.verify(binary)
        return try parse(Data(text.utf8),home:home)
        #else
        throw SweepError.denied("当前平台未验证原生模拟器管理")
        #endif
    }
    static func reference(_ path:String,home:String,devices:[Device]?=nil,expected:SimulatorDeviceReference?=nil)throws->(SimulatorDeviceReference,String){
        guard let id=deviceID(path,home:home),let device=try (devices ?? self.devices(home:home)).first(where:{$0.id == id}),device.available,device.state == "Shutdown" else{throw SweepError.denied("模拟器未注册、运行时不可用或未完全停止，保留缓存")}
        let root=URL(fileURLWithPath:device.dataPath).deletingLastPathComponent().path,meta=try SafeFilesystem.snapshot(root+"/device.plist")
        guard meta.identity.owner == as_current_uid(),!meta.identity.isDirectory,meta.identity.links == 1,
              let info=try PropertyListSerialization.propertyList(from:SafeFilesystem.readMetadata(meta.path),format:nil)as? [String:Any],
              info["UDID"]as? String == id,info["runtime"]as? String == device.runtime,info["deviceType"]as? String == device.deviceType,
              info["state"]as? Int == 1,info["isDeleted"]as? Bool == false,info["isEphemeral"]as? Bool == false else{throw SweepError.denied("模拟器原生元数据与注册状态不一致")}
        let data=try SafeDirectory(path:device.dataPath).ownIdentity,homeIdentity=try SafeDirectory(path:home).ownIdentity
        guard data.owner == as_current_uid(),data.sameVolume(as:homeIdentity) else{throw SweepError.denied("模拟器资料的卷或所有者未确认")}
        if let expected {
            guard expected.id == id,expected.runtime == device.runtime,expected.deviceType == device.deviceType,sameDataDirectory(data,expected.dataIdentity) else{throw SweepError.stale("模拟器设备、运行时或资料目录已改变，保留恢复对象")}
        }
        try SafeFilesystem.verify(meta)
        return (.init(id:id,runtime:device.runtime,deviceType:device.deviceType,dataIdentity:data),device.title)
    }
    static func verify(_ item:Candidate,home:String)throws{
        guard item.category == .development,item.bundleIdentifier == nil,item.applicationPath == nil,let expected=item.simulatorDevice else{throw SweepError.denied("模拟器缓存缺少原生归属记录")}
        _=try reference(item.path,home:home,expected:expected)
        let snapshot=try SafeFilesystem.snapshot(item.path)
        guard snapshot.identity.isDirectory else{throw SweepError.denied("仅管理独立模拟器缓存目录，松散锁和特殊文件保留")}
        try verifyPrivateTree(snapshot,home:home)
    }
    static func verifyPrivateTree(_ snapshot:FileSnapshot,home:String)throws{
        guard let id=deviceID(snapshot.path,home:home),snapshot.identity.isDirectory else{throw SweepError.denied("不是模拟器独立缓存目录")}
        let barrier=try SafeDirectory(path:home+"/Library"),barrierIdentity=try barrier.ownIdentity
        // Native simulator data/Library are 0775. The enclosing host Library
        // must remain non-traversable to every other account, without ACL grants.
        guard barrierIdentity.owner == as_current_uid(),barrierIdentity.mode & 0o7077 == 0,
              as_no_grant_acl_descriptor(barrier.fd) == 1 else{throw SweepError.denied("当前用户 Library 不再是私有访问边界，模拟器缓存保留")}
        let data=home+"/Library/Developer/CoreSimulator/Devices/"+id+"/data"
        for ancestor in snapshot.ancestors where SafetyPolicy.contains(home,ancestor.path){
            let directory=try SafeDirectory(path:ancestor.path),identity=try directory.ownIdentity
            let nativeMode=(ancestor.path == data || ancestor.path == data+"/Library") && identity.mode & 0o7777 == 0o775
            guard identity.owner == as_current_uid(),identity.sameVolume(as:barrierIdentity),
                  as_unshared_node_descriptor(directory.fd,as_current_uid()) == 1 || (nativeMode && as_no_grant_acl_descriptor(directory.fd) == 1) else{throw SweepError.denied("模拟器缓存祖先的权限或卷未确认")}
        }
        let nodes=[TreeEntry(relative:"",identity:snapshot.identity)]+snapshot.tree
        guard !SupportDomainRule.containsProtectedContent(nodes) else{throw SweepError.denied("缓存包含钥匙串或安全状态，整项保留")}
        let deadline=ProcessInfo.processInfo.systemUptime+20
        for node in nodes{
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else{throw SweepError.incomplete("模拟器缓存权限核验超时")}
            guard node.identity.owner == as_current_uid(),node.identity.mode & 0o7022 == 0,
                  node.identity.isDirectory || node.identity.links == 1 else{throw SweepError.denied("缓存共享、特殊权限或硬链接未确认")}
            let path=node.relative.isEmpty ? snapshot.path : snapshot.path+"/"+node.relative,url=URL(fileURLWithPath:path),parent=try SafeDirectory(path:url.deletingLastPathComponent().path)
            let fd=url.lastPathComponent.withCString{openat(parent.fd,$0,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)}
            guard fd >= 0 else{throw SweepError.incomplete("模拟器缓存权限不可读")};defer{as_close(fd)}
            var identity=ASIdentity()
            guard as_identity_fd(fd,&identity) == 0,FileIdentity(identity) == node.identity,as_unshared_node_descriptor(fd,as_current_uid()) == 1 else{throw SweepError.denied("缓存身份或 ACL 不再独占")}
        }
        try SafeFilesystem.verify(snapshot)
        guard try barrier.ownIdentity == barrierIdentity else{throw SweepError.stale("私有访问边界已改变")}
    }
    static func ensureStopped(_ item:Candidate,home:String)throws{
        guard let expected=item.simulatorDevice else{throw SweepError.denied("模拟器恢复归属缺失")}
        _=try reference(item.path,home:home,expected:expected)
        try ActivityInspector.ensureBuildToolsStopped()
    }
}
