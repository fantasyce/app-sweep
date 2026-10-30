import Foundation
import CFSafety

/// Whole personal archives in macOS's dedicated deleted-user location only.
/// No account, home directory, image contents or account database is modified.
enum DeletedUserArchiveRule {
    static let name="deleted-user-archive-v1"
    static func root(_ scope:SystemCleanupScope)->String{scope.fixture ? scope.libraryRoot + "/Deleted Users" : "/Users/Deleted Users"}
    static func account(_ path:String,scope:SystemCleanupScope)->String?{
        guard XcodeRule.canonical(path),URL(fileURLWithPath:path).deletingLastPathComponent().path == root(scope),path.hasSuffix(".dmg") else{return nil}
        let value=String(URL(fileURLWithPath:path).lastPathComponent.dropLast(4))
        return value.range(of:#"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}$"#,options:.regularExpression) != nil ? value : nil
    }
    private static func plist(_ executable:String,_ arguments:[String],timeout:TimeInterval=10)throws->Any{
        let text=try BoundedProcess.run(executable,arguments:arguments,timeout:timeout)
        return try PropertyListSerialization.propertyList(from:Data(text.utf8),format:nil)
    }
    static func ensureInactive(_ path:String,scope:SystemCleanupScope)throws{
        guard let name=account(path,scope:scope) else{throw SweepError.denied("不是专用位置中的独立账户归档")}
        let wanted=name.lowercased()
        guard let users=try plist("/usr/bin/dscl",["-plist","/Search","-readall","/Users","RecordName","NFSHomeDirectory","UniqueID"])as? [[String:Any]],!users.isEmpty,users.count<=4096 else{throw SweepError.incomplete("现存账户查询未确认，归档保留")}
        for user in users{
            guard let names=user["dsAttrTypeStandard:RecordName"]as? [String],!names.isEmpty,
                  let homes=user["dsAttrTypeStandard:NFSHomeDirectory"]as? [String],
                  let ids=user["dsAttrTypeStandard:UniqueID"]as? [String],ids.count == 1,Int32(ids[0]) != nil else{throw SweepError.incomplete("账户名、位置或身份未确认，归档保留")}
            if names.contains(where:{$0.lowercased() == wanted}) || homes.contains(where:{URL(fileURLWithPath:$0).lastPathComponent.lowercased() == wanted}){throw SweepError.denied("归档名称对应现存账户，保留个人资料")}
        }
        let active=try BoundedProcess.run("/bin/ps",arguments:["-axo","user="],timeout:5)
        guard !active.isEmpty else{throw SweepError.incomplete("活动账户状态未确认")}
        guard !active.split(separator:"\n").contains(where:{$0.trimmingCharacters(in:.whitespaces).lowercased() == wanted}) else{throw SweepError.denied("账户仍有活动进程，归档保留")}
    }
    static func ensureUnmounted(_ path:String)throws{
        guard let info=try plist("/usr/bin/hdiutil",["info","-plist"])as? [String:Any],let images=info["images"]as? [[String:Any]],images.count<=1000 else{throw SweepError.incomplete("磁盘映像使用状态未确认")}
        for image in images{
            guard let source=image["image-path"]as? String,XcodeRule.canonical(source) else{throw SweepError.incomplete("已挂载映像位置未确认，归档保留")}
            guard source != path else{throw SweepError.denied("账户归档正在挂载，保留")}
        }
    }
    static func verify(_ path:String,scope:SystemCleanupScope,storedPath:String?=nil)throws{
        try scope.verify()
        guard as_administrator_member(scope.requesterUID) == 1 else{throw SweepError.denied("仅已确认的管理员可管理已删除账户的个人归档")}
        try ensureInactive(path,scope:scope)
        let root=try SafeDirectory(path:root(scope)),rootIdentity=try root.ownIdentity
        guard rootIdentity.owner == scope.ownerUID else{throw SweepError.denied("账户归档根目录所有者未确认")}
        try scope.verifyUnsharedNode(path:root.path,identity:rootIdentity)
        let actual=storedPath ?? path,snapshot=try SafeFilesystem.snapshot(actual)
        guard snapshot.identity.owner == scope.ownerUID,snapshot.identity.mode & 0o170000 == 0o100000,snapshot.identity.links == 1,snapshot.identity.device == rootIdentity.device else{throw SweepError.denied("归档不是同卷独占普通文件，保留")}
        try scope.verifyUnsharedNode(path:actual,identity:snapshot.identity)
        try ensureUnmounted(actual);try BusyInspector.ensureUnused(snapshot)
        guard let info=try plist("/usr/bin/hdiutil",["imageinfo","-plist",actual],timeout:15)as? [String:Any],
              let format=info["Format"]as? String,["UDZO","UDRO","UDRW","UDBZ","ULFO","ULZO"].contains(format),
              let properties=info["Properties"]as? [String:Any],properties["Encrypted"]as? Bool == false else{throw SweepError.denied("磁盘映像格式或加密状态未确认，保留")}
        try SafeFilesystem.verify(snapshot)
        guard try root.ownIdentity == rootIdentity else{throw SweepError.stale("账户归档目录在核对后改变")}
    }
    static func scan(scope:SystemCleanupScope,builder:inout Scanner.Builder)throws{
        let base=root(scope)
        try builder.scoped(root:base){part in
            guard try SafeFilesystem.presence(base) else{return}
            for file in try XcodeArchiveRule.children(base) where file.hasSuffix(".dmg"){
                let path=base + "/" + file;var reason:String?
                do{try verify(path,scope:scope)}catch is CancellationError{throw CancellationError()}catch{reason=error.localizedDescription}
                try part.add(path,category:.userData,bundleID:nil,rule:name,evidence:[.init(kind:.validatedRule,detail:"macOS专用账户归档位置、非现存/活动账户及未挂载完整磁盘映像；仅整份移入恢复区，不恢复或修改账户",verified:reason == nil)],reason:reason,applicationPath:nil,displayName:file + "（已删除账户归档 · 个人资料）")
            }
        }
    }
}
