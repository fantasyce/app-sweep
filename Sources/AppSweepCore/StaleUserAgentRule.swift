import Foundation
import CFSafety

/// Only an exact current-user declaration whose whole application is absent.
/// Registration is inspected and restored through launchd, never its database.
enum StaleUserAgentRule {
    static let name="stale-user-launch-agent-v1"
    struct Declaration {
        let path:String
        let label:String
        let program:String
        let snapshot:FileSnapshot
        var domain:String{"gui/" + String(as_current_uid())}
        var target:String{domain + "/" + label}
    }
    static func label(path:String,home:String)->String? {
        guard XcodeRule.canonical(path),URL(fileURLWithPath:path).deletingLastPathComponent().path == home + "/Library/LaunchAgents",path.hasSuffix(".plist") else{return nil}
        let value=String(URL(fileURLWithPath:path).lastPathComponent.dropLast(6))
        return SystemCleanupScope.validIdentifier(value) ? value : nil
    }
    static func inspect(_ path:String,home:String,storedPath:String?=nil,installedApplication:String?=nil)throws->Declaration {
        guard let label=label(path:path,home:home) else{throw SweepError.denied("不是当前用户的独立第三方后台项")}
        let actual=storedPath ?? path,snapshot=try SafeFilesystem.snapshot(actual)
        guard snapshot.identity.owner == as_current_uid(),snapshot.identity.mode & 0o170000 == 0o100000,snapshot.identity.links == 1,snapshot.identity.size <= 1024*1024 else{throw SweepError.denied("后台项类型、所有者或容量未确认")}
        try ContainerDataRule.verifyPrivateTree(snapshot,home:home)
        guard let info=try PropertyListSerialization.propertyList(from:SafeFilesystem.readMetadata(actual,maximumBytes:1024*1024),format:nil)as? [String:Any],info["Label"]as? String == label else{throw SweepError.denied("后台项标识与精确文件名不一致")}
        let allowed:Set<String>=["Label","Program","ProgramArguments","RunAtLoad","KeepAlive","Disabled","ProcessType","LimitLoadToSessionType"]
        guard Set(info.keys).isSubset(of:allowed),info["KeepAlive"] == nil || (info["KeepAlive"]as? NSNumber)?.boolValue == false else{throw SweepError.denied("后台项含定时、共享、持续重启或未验证副作用，保留")}
        if let raw=info["RunAtLoad"] {guard let value=raw as? NSNumber,!value.boolValue else{throw SweepError.denied("后台项会在恢复注册时自动启动或启动条件未确认，保留")}}
        if let raw=info["Disabled"] {guard raw is NSNumber else{throw SweepError.denied("后台项启用状态未确认")}}
        var arguments:[String]=[]
        if let raw=info["ProgramArguments"] {guard let values=raw as? [String],!values.isEmpty,values.count<=128,values.allSatisfy({!$0.contains("\0") && $0.utf8.count<=4096}) else{throw SweepError.denied("后台项程序参数未确认")};arguments=values}
        guard let program=info["Program"]as? String ?? arguments.first,XcodeRule.canonical(program),
              program.hasPrefix(home + (installedApplication == nil ? "/Applications/" : "/")) || program.hasPrefix("/Applications/"),
              let range=program.range(of:".app/Contents/MacOS/"),range.upperBound < program.endIndex else{throw SweepError.denied("后台项不指向独立应用包中的程序，保留")}
        let app=String(program[..<range.lowerBound])+".app"
        guard SelectedApplicationRule.matches(path:app,policy:SafetyPolicy(home:home,acceptedPlatform:false)) else{throw SweepError.denied("后台项应用位置未确认")}
        if let installedApplication {
            guard app == installedApplication else{throw SweepError.denied("后台项程序未精确指向所选应用")}
        }else{
            guard try !SafeFilesystem.presence(app) else{throw SweepError.denied("后台项所属应用仍存在，保留")}
        }
        // All existing ancestors must be physical; presence failures never mean absent.
        _=try SafeFilesystem.ancestors(of:URL(fileURLWithPath:app).deletingLastPathComponent().path)
        try SafeFilesystem.verify(snapshot)
        return Declaration(path:path,label:label,program:program,snapshot:snapshot)
    }
    static func registered(_ declaration:Declaration)throws->Bool {
        #if os(macOS)
        let result=try BoundedProcess.capture("/bin/launchctl",arguments:["print",declaration.target],timeout:5,mergeStderr:true)
        if result.status == 113 {
            _=try BoundedProcess.run("/bin/launchctl",arguments:["print",declaration.domain],timeout:5)
            return false
        }
        guard result.status == 0 else{throw SweepError.incomplete("后台项注册状态未确认")}
        let lines=Set(result.text.split(separator:"\n").map{$0.trimmingCharacters(in:.whitespaces)})
        guard lines.contains("path = " + declaration.path),lines.contains("program = " + declaration.program),lines.contains("state = not running"),!lines.contains(where:{$0.hasPrefix("pid = ")}) else{throw SweepError.denied("后台项正在运行、注册来源不同或状态未确认，保留")}
        return true
        #else
        throw SweepError.denied("当前平台不支持后台项管理")
        #endif
    }
    static func unregister(_ declaration:Declaration)throws {
        #if os(macOS)
        if try registered(declaration){_=try BoundedProcess.run("/bin/launchctl",arguments:["bootout",declaration.target],timeout:5)}
        guard try !registered(declaration) else{throw SweepError.incomplete("后台项尚未注销")}
        #else
        throw SweepError.denied("当前平台不支持后台项管理")
        #endif
    }
    static func restore(_ declaration:Declaration,wasRegistered:Bool)throws {
        #if os(macOS)
        let current=try registered(declaration)
        if wasRegistered && !current {
            try SafeFilesystem.verify(declaration.snapshot)
            _=try BoundedProcess.run("/bin/launchctl",arguments:["bootstrap",declaration.domain,declaration.path],timeout:5)
            guard try registered(declaration) else{throw SweepError.incomplete("原后台项注册尚未恢复")}
        } else if !wasRegistered && current {throw SweepError.denied("原未注册的后台项出现新注册，需人工核对")}
        #else
        throw SweepError.denied("当前平台不支持后台项管理")
        #endif
    }
}
struct UserAgentRecoveryRecord:Codable,Sendable {
    enum Phase:String,Codable,Sendable{case prepared,unregistering,unregistered,restoring,restored}
    let wasRegistered:Bool
    var phase:Phase
    var applicationIdentity:FileIdentity? = nil
    var applicationCodeHash:Data? = nil
}
