import Foundation
import CFSafety

struct DocumentHistoryRecord:Codable,Sendable {
    static let rule="document-history-versions-v1"
    struct Part:Codable,Sendable {
        enum Phase:String,Codable,Sendable{case prepared,removing,removed,restoring,restored}
        let id:UUID
        let originalID:Data
        let digest:String
        let bytes:Int64
        var phase:Phase = .prepared
        var restoredID:Data? = nil
        var restoreBaseline:[Data]? = nil
    }
    let documentDigest:String
    var parts:[Part]
}
enum DocumentVersionRule {
    static let name=DocumentHistoryRecord.rule
    static func matches(_ path:String,home:String)->Bool {
        XcodeRule.canonical(path) && [home + "/Documents",home + "/Desktop"].contains{path != $0 && SafetyPolicy.contains($0,path)} &&
        ![".keychain",".keychain-db",".sqlite",".db"].contains(where:path.lowercased().hasSuffix)
    }
}
#if os(macOS)
import CryptoKit
import Darwin

/// The coordinator is confined to one operation; Apple permits cancel from any
/// thread. Cancellation never implies the operation did not happen: journaled
/// per-version phases are reconciled through the native API after interruption.
private final class HistoryCoordinator:@unchecked Sendable {
    let value=NSFileCoordinator(filePresenter:nil)
}
/// Read-only native version capability. The public coordinator grants access
/// to a version file even when its system-owned parent cannot be listed. Never
/// relax the ordinary directory walker or accept a decoded source URL here.
private struct NativeHistoryPayload {
    let descriptor:Int32
    let identity:FileIdentity
    private func consume(_ body:(Data)throws->Void)throws->String {
        var before=ASIdentity()
        guard as_identity_fd(descriptor,&before) == 0,FileIdentity(before) == identity,lseek(descriptor,0,SEEK_SET) == 0 else{throw SweepError.stale("原生历史读取句柄已改变")}
        let input=FileHandle(fileDescriptor:descriptor,closeOnDealloc:false),deadline=ProcessInfo.processInfo.systemUptime+30
        var remaining=identity.size,hash=SHA256()
        while remaining>0{
            try Task.checkCancellation();guard ProcessInfo.processInfo.systemUptime<deadline else{throw SweepError.incomplete("历史内容读取超时")}
            let bytes=try input.read(upToCount:Int(min(remaining,256*1024))) ?? Data()
            guard !bytes.isEmpty else{throw SweepError.stale("历史内容被截断")}
            hash.update(data:bytes);try body(bytes);remaining-=Int64(bytes.count)
        }
        var after=ASIdentity()
        guard (try input.read(upToCount:1) ?? Data()).isEmpty,as_identity_fd(descriptor,&after) == 0,FileIdentity(after) == identity else{throw SweepError.stale("原生历史内容在读取期间改变")}
        return hash.finalize().map{String(format:"%02x",$0)}.joined()
    }
    func digest()throws->String{try consume{_ in}}
    func copy(into directory:SafeDirectory,name:String)throws->StreamedCopy {
        guard UUID(uuidString:name)?.uuidString == name,as_private_descriptor(directory.fd) == 1,try directory.ownIdentity.device == identity.device,directory.availableBytes>UInt64(identity.size)+CacheBackup.freeSpaceReserve else{throw SweepError.denied("历史副本必须在同卷私有目录中独占创建并保留恢复空间")}
        let output=name.withCString{openat(directory.fd,$0,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0o600)}
        guard output>=0 else{throw SweepError.filesystem("历史副本目标已存在或无法创建")};defer{as_close(output)}
        let file=FileHandle(fileDescriptor:output,closeOnDealloc:false),digest=try consume{try file.write(contentsOf:$0)}
        try file.synchronize();var raw=ASIdentity()
        guard fcntl(output,F_FULLFSYNC) == 0,fsync(directory.fd) == 0,as_identity_fd(output,&raw) == 0,raw.owner == as_current_uid(),raw.links == 1,raw.mode & 0o7777 == 0o600,raw.size == identity.size,try directory.identity(name) == FileIdentity(raw) else{throw SweepError.filesystem("历史副本身份或持久保存未确认")}
        return StreamedCopy(identity:FileIdentity(raw),digest:digest)
    }
}
enum DocumentHistoryTransaction {
    static let format="native-document-history-backup-v1"
    struct Selection {
        let document:FileSnapshot
        let record:DocumentHistoryRecord
        let digest:String
        var bytes:Int64{record.parts.reduce(0){$0+$1.bytes}}
    }
    struct Prepared {
        let selection:Selection
        let receipt:Data
        var digest:String{hash(receipt)}
        var requiredBytes:UInt64{UInt64(selection.bytes)*2 + UInt64(receipt.count) + 128*1024}
    }
    private struct Receipt:Codable {
        let schemaVersion:Int
        let candidateID:UUID
        let document:String
        let identity:FileIdentity
        let ancestors:[AncestorIdentity]
        let history:DocumentHistoryRecord
    }
    private struct Commitment:Codable {let identifier:Data;let digest:String;let bytes:Int64}
    static func hash(_ data:Data)->String{SHA256.hash(data:data).map{String(format:"%02x",$0)}.joined()}
    private static func access<T>(_ url:URL,writing:Bool=false,_ operation:(URL)throws->T)throws->T {
        try Task.checkCancellation()
        return try withoutActuallyEscaping(operation){action in
        let holder=HistoryCoordinator(),deadline=ProcessInfo.processInfo.systemUptime+30
        let timer=DispatchWorkItem{holder.value.cancel()};DispatchQueue.global().asyncAfter(deadline:.now()+30,execute:timer);defer{timer.cancel()}
        var failure:NSError?,result:Result<T,Error>?
        let body:(URL)->Void={ coordinated in
            result=Result{guard ProcessInfo.processInfo.systemUptime<deadline else{throw SweepError.incomplete("文稿协调超时，操作未确认")};return try action(coordinated)}
        }
        if writing{holder.value.coordinate(writingItemAt:url,options:[],error:&failure,byAccessor:body)}
        else{holder.value.coordinate(readingItemAt:url,options:[],error:&failure,byAccessor:body)}
        if let failure{throw SweepError.incomplete("文稿协调未确认：" + failure.localizedDescription)}
        guard let result else{throw SweepError.incomplete("原生文稿操作未执行，不能判断为空")}
        return try result.get()
        }
    }
    private static func identifier(_ version:NSFileVersion)throws->Data {
        let data=try NSKeyedArchiver.archivedData(withRootObject:version.persistentIdentifier,requiringSecureCoding:true)
        guard !data.isEmpty,data.count<=8192 else{throw SweepError.incomplete("原生版本标识超出容量")};return data
    }
    private static func validateIdentifier(_ data:Data)throws {
        guard !data.isEmpty,data.count<=8192 else{throw SweepError.denied("原生版本标识超出安全容量")}
    }
    private static func decoded(_ data:Data,nativeIdentifiers:[Any])throws->Any {
        try validateIdentifier(data)
        // An opaque native identifier may contain system coding classes. Derive
        // the allowlist from live public API objects, never archive class names.
        var classes:[AnyClass]=[NSArray.self,NSDictionary.self,NSString.self,NSNumber.self,NSData.self,NSDate.self,NSUUID.self,NSURL.self]
        var visited=Set<ObjectIdentifier>()
        func collect(_ value:Any,depth:Int)throws {
            let object=value as AnyObject,key=ObjectIdentifier(object)
            if visited.contains(key){return};visited.insert(key)
            guard depth<=8,visited.count<=2048,let native=object as? NSObject,object is NSSecureCoding else{throw SweepError.incomplete("原生标识类型未确认")}
            classes.append(type(of:object));classes.append(native.classForCoder)
            if let array=object as? NSArray{for child in array{try collect(child,depth:depth+1)}}
            else if let dictionary=object as? NSDictionary{for (key,value) in dictionary{try collect(key,depth:depth+1);try collect(value,depth:depth+1)}}
        }
        for value in nativeIdentifiers{try collect(value,depth:0)}
        guard let result=try NSKeyedUnarchiver.unarchivedObject(ofClasses:classes,from:data) else{throw SweepError.denied("原生标识安全解码失败")}
        return result
    }
    private static func versions(_ document:String)throws->[NSFileVersion] {
        guard let values=NSFileVersion.otherVersionsOfItem(at:URL(fileURLWithPath:document)),values.count<=100,
              values.allSatisfy({$0.hasLocalContents && !$0.isConflict}) else{throw SweepError.incomplete("历史版本列表、数量、本地内容或冲突状态未确认，整组保留")}
        return values
    }
    private static func find(_ id:Data,document:String)throws->NSFileVersion? {
        let all=try versions(document)
        guard !all.isEmpty else{return nil}
        let value=try decoded(id,nativeIdentifiers:all.map{$0.persistentIdentifier})
        return all.first{($0.persistentIdentifier as? NSObject)?.isEqual(value) == true}
    }
    private static func payload<T>(_ version:NSFileVersion,document:FileSnapshot,_ operation:(NativeHistoryPayload)throws->T)throws->T {
        guard version.hasLocalContents,!version.isConflict,version.url.isFileURL else{throw SweepError.denied("只处理已确认的本地普通历史版本")}
        return try access(version.url){url in
            let fd=url.path.withCString{open($0,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)}
            guard fd>=0 else{throw SweepError.incomplete("原生历史读取权限未确认")};defer{as_close(fd)}
            var raw=ASIdentity()
            guard as_identity_fd(fd,&raw) == 0,raw.mode & 0o170000 == 0o100000,[as_current_uid(),0].contains(raw.owner),raw.device == document.identity.device,raw.size>=0,raw.size<=256*1024*1024 else{throw SweepError.denied("历史内容的类型、归属、卷或容量未确认")}
            return try operation(NativeHistoryPayload(descriptor:fd,identity:FileIdentity(raw)))
        }
    }
    static func document(_ path:String,home:String)throws->FileSnapshot {
        guard DocumentVersionRule.matches(path,home:home),SafetyPolicy(home:home,acceptedPlatform:false).protectedDenial(path) == nil else{throw SweepError.denied("不是当前用户本地文稿范围")}
        var snapshot=try SafeFilesystem.snapshot(path)
        guard snapshot.identity.owner == as_current_uid(),snapshot.identity.mode & 0o170000 == 0o100000,snapshot.identity.links == 1,snapshot.identity.device == (try SafeDirectory(path:home).ownIdentity.device) else{throw SweepError.denied("当前文稿类型、所有者或卷未确认")}
        let values=try URL(fileURLWithPath:path).resourceValues(forKeys:[.isUbiquitousItemKey,.isPackageKey])
        guard values.isUbiquitousItem != true,values.isPackage != true else{throw SweepError.denied("云端或包文稿整组保留")}
        try ContainerDataRule.verifyPrivateTree(snapshot,home:home)
        snapshot.contentDigest=try VerifiedFileStream.digest(snapshot);return snapshot
    }
    static func inspect(_ path:String,home:String)throws->Selection {
        let current=try document(path,home:home),all=try versions(path);var parts:[DocumentHistoryRecord.Part]=[]
        let deadline=ProcessInfo.processInfo.systemUptime+30
        for version in all{
            try Task.checkCancellation();guard ProcessInfo.processInfo.systemUptime<deadline else{throw SweepError.incomplete("历史版本扫描超时，整组保留")}
            let id=try identifier(version);_=try decoded(id,nativeIdentifiers:[version.persistentIdentifier])
            let value=try payload(version,document:current){source in (source.identity.size,try source.digest())}
            parts.append(.init(id:UUID(),originalID:id,digest:value.1,bytes:value.0))
            guard parts.reduce(Int64(0),{$0+$1.bytes})<=1024*1024*1024 else{throw SweepError.incomplete("文稿历史超出单组容量，保留")}
        }
        parts.sort{$0.originalID.lexicographicallyPrecedes($1.originalID)}
        guard Set(parts.map(\.originalID)).count == parts.count else{throw SweepError.incomplete("原生版本标识重复，保留")}
        try SafeFilesystem.verify(current)
        let encoder=PropertyListEncoder();encoder.outputFormat = .binary
        let commitment=try encoder.encode(parts.map{Commitment(identifier:$0.originalID,digest:$0.digest,bytes:$0.bytes)})
        return Selection(document:current,record:.init(documentDigest:current.contentDigest!,parts:parts),digest:hash(commitment))
    }
    static func prepare(_ item:Candidate,snapshot:FileSnapshot,home:String)throws->Prepared {
        let selection=try inspect(item.path,home:home)
        guard item.rule == DocumentVersionRule.name,item.category == .userData,item.bundleIdentifier == nil,item.applicationPath == nil,!selection.record.parts.isEmpty,selection.digest == snapshot.contentDigest,selection.document.identity == snapshot.identity,selection.document.ancestors == snapshot.ancestors else{throw SweepError.stale("历史版本或当前文稿在审查后改变")}
        let receipt=Receipt(schemaVersion:1,candidateID:item.id,document:item.path,identity:snapshot.identity,ancestors:snapshot.ancestors,history:selection.record),encoder=PropertyListEncoder();encoder.outputFormat = .binary
        return Prepared(selection:selection,receipt:try encoder.encode(receipt))
    }
    static func create(_ prepared:Prepared,item:Candidate,in backups:SafeDirectory)throws->FileSnapshot {
        let root=try backups.privateChild(item.id.uuidString)
        guard try FileManager.default.contentsOfDirectory(atPath:root.path).isEmpty else{throw SweepError.stale("历史副本目录不是独占空目录")}
        try root.write(prepared.receipt,name:"receipt.plist")
        for part in prepared.selection.record.parts{
            guard let version=try find(part.originalID,document:item.path) else{throw SweepError.stale("待备份历史版本已消失")}
            let copied=try payload(version,document:prepared.selection.document){source in try source.copy(into:root,name:part.id.uuidString)}
            guard copied.digest == part.digest,copied.identity.size == part.bytes else{throw SweepError.stale("历史副本字节改变")}
        }
        return try SafeFilesystem.snapshot(root.path)
    }
    static func verifyDocument(_ entry:RecoveryEntry,home:String)throws->FileSnapshot {
        let current=try document(entry.original.path,home:home)
        guard let original=entry.original.identity,let record=entry.history,
              current.identity.sameVolume(as:original),current.identity.inode == original.inode,current.identity.owner == original.owner,current.identity.mode == original.mode,current.identity.links == original.links,current.ancestors == entry.originalAncestors,current.contentDigest == record.documentDigest else{throw SweepError.stale("当前文稿已改变或替换，历史恢复保留且不覆盖")}
        return current
    }
    static func backup(_ entry:RecoveryEntry,in backups:SafeDirectory,home:String)throws->FileSnapshot {
        guard entry.original.rule == DocumentVersionRule.name,let history=entry.history,!history.parts.isEmpty,history.parts.count<=100,Set(history.parts.map(\.id)).count == history.parts.count,entry.preference == nil,entry.userAgent == nil,entry.isolatedIdentity == nil,entry.backupFormat == format else{throw SweepError.denied("文稿历史恢复记录结构无效")}
        let root=try backups.existingPrivateChild(entry.id.uuidString),snapshot=try SafeFilesystem.snapshot(root.path),data=try root.read("receipt.plist")
        guard entry.backupDigest == hash(data),entry.backupIdentity.map({$0 == snapshot.identity}) ?? (entry.backupPending == true) else{throw SweepError.stale("历史副本身份或独立回执已改变")}
        let receipt=try PropertyListDecoder().decode(Receipt.self,from:data)
        guard receipt.schemaVersion == 1,receipt.candidateID == entry.id,receipt.document == entry.original.path,receipt.identity == entry.original.identity,receipt.ancestors == entry.originalAncestors,receipt.history.documentDigest == history.documentDigest,receipt.history.parts.count == history.parts.count,Set(snapshot.tree.map(\.relative)) == Set(history.parts.map{$0.id.uuidString}+["receipt.plist"]) else{throw SweepError.denied("历史回执与文稿或副本结构不一致")}
        for (part,bound) in zip(history.parts,receipt.history.parts){
            guard part.id == bound.id,part.originalID == bound.originalID,part.digest == bound.digest,part.bytes == bound.bytes,part.bytes>=0,part.bytes<=256*1024*1024,(part.restoreBaseline?.count ?? 0)<=200 else{throw SweepError.denied("历史版本绑定不一致")}
            try validateIdentifier(part.originalID);if let restored=part.restoredID{try validateIdentifier(restored)}
            for id in part.restoreBaseline ?? []{try validateIdentifier(id)}
            let payload=try SafeFilesystem.snapshot(root.path + "/" + part.id.uuidString)
            guard payload.identity.owner == as_current_uid(),payload.identity.mode & 0o177777 == 0o100600,payload.identity.links == 1,payload.identity.size == part.bytes,try VerifiedFileStream.digest(payload) == part.digest else{throw SweepError.stale("历史内容副本不一致")}
        }
        try SafeFilesystem.verify(snapshot);return snapshot
    }
    static func remove(_ entry:inout RecoveryEntry,home:String,isolation:isolated(any Actor)?,afterNativeRemoval:()throws->Void = {},persist:(RecoveryEntry)throws->Void)throws {
        for index in entry.history!.parts.indices{
            let part=entry.history!.parts[index]
            entry.history!.parts[index].phase = .removing;try persist(entry)
            try access(URL(fileURLWithPath:entry.original.path),writing:true){_ in
                let doc=try verifyDocument(entry,home:home)
                let remaining=entry.history!.parts.filter{$0.phase != .removed}.map(\.originalID)
                guard Set(try versions(entry.original.path).map(identifier)) == Set(remaining) else{throw SweepError.stale("文稿历史出现新版本或改变，停止本批次")}
                guard let version=try find(part.originalID,document:entry.original.path),try payload(version,document:doc,{try $0.digest()}) == part.digest else{throw SweepError.stale("原历史版本改变，停止处理")}
                try version.remove()
                try afterNativeRemoval()
                guard try find(part.originalID,document:entry.original.path) == nil else{throw SweepError.incomplete("原生历史版本移除未确认")}
                _=try verifyDocument(entry,home:home)
            }
            entry.history!.parts[index].phase = .removed;try persist(entry)
        }
    }
    static func restore(_ entry:inout RecoveryEntry,backups:SafeDirectory,home:String,isolation:isolated(any Actor)?,afterNativeRestore:()throws->Void = {},persist:(RecoveryEntry)throws->Void)throws {
        _=try backup(entry,in:backups,home:home)
        let root=try backups.existingPrivateChild(entry.id.uuidString)
        for index in entry.history!.parts.indices{
            let part=entry.history!.parts[index]
            let existing=try [part.restoredID,part.originalID].compactMap{$0}.compactMap{try find($0,document:entry.original.path)}.first
            if let existing{
                let doc=try verifyDocument(entry,home:home)
                guard try payload(existing,document:doc,{try $0.digest()}) == part.digest else{throw SweepError.stale("已有历史版本与原内容不一致")}
                entry.history!.parts[index].restoredID=try identifier(existing);entry.history!.parts[index].phase = .restored;try persist(entry);continue
            }
            if part.phase == .restoring,let baseline=part.restoreBaseline{
                let candidates=try versions(entry.original.path).filter{version in
                    try !baseline.contains{raw in (try decoded(raw,nativeIdentifiers:[version.persistentIdentifier]) as? NSObject)?.isEqual(version.persistentIdentifier) == true}
                }
                let doc=try verifyDocument(entry,home:home),matches=try candidates.filter{try payload($0,document:doc,{try $0.digest()}) == part.digest}
                guard matches.count<=1 else{throw SweepError.stale("中断后出现多个相同新历史版本，需人工核对")}
                if let match=matches.first{entry.history!.parts[index].restoredID=try identifier(match);entry.history!.parts[index].phase = .restored;try persist(entry);continue}
            }
            entry.history!.parts[index].restoreBaseline=try versions(entry.original.path).map(identifier)
            entry.history!.parts[index].phase = .restoring;try persist(entry)
            let restored=try access(URL(fileURLWithPath:entry.original.path),writing:true){url in
                _=try verifyDocument(entry,home:home)
                let payload=root.path + "/" + part.id.uuidString
                let made=try NSFileVersion.addOfItem(at:url,withContentsOf:URL(fileURLWithPath:payload),options:[])
                let doc=try verifyDocument(entry,home:home)
                guard try self.payload(made,document:doc,{try $0.digest()}) == part.digest else{throw SweepError.stale("恢复后的原生历史内容未确认")}
                try afterNativeRestore()
                return try identifier(made)
            }
            entry.history!.parts[index].restoredID=restored;entry.history!.parts[index].phase = .restored;try persist(entry)
        }
    }
}
#endif
