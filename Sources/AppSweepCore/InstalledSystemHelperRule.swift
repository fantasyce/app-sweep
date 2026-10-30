import Foundation
import CFSafety
#if os(macOS)
import Security
#endif

public struct InstalledSystemHelperReference:Codable,Sendable,Equatable{
    let label:String
    let applicationIdentity:FileIdentity
    let applicationCodeHash:Data
    let helperCodeHash:Data
    var embeddedCodeHash:Data? = nil
    let plistIdentity:FileIdentity
    let plistDigest:String
}

/// Explicit management of exclusive SMJobBless components. The application is
/// retained until this separate dependency stage completes; no process is killed.
enum InstalledSystemHelperRule{
    static let name="exclusive-installed-system-helper-v1"
    static func binary(_ label:String,_ scope:SystemCleanupScope)->String{scope.libraryRoot+"/PrivilegedHelperTools/"+label}
    static func plist(_ label:String,_ scope:SystemCleanupScope)->String{scope.libraryRoot+"/LaunchDaemons/"+label+".plist"}
    static func label(_ path:String,scope:SystemCleanupScope)->String?{
        guard XcodeRule.canonical(path) else{return nil}
        let url=URL(fileURLWithPath:path),parent=url.deletingLastPathComponent().path
        let value:String
        if parent == scope.libraryRoot+"/PrivilegedHelperTools"{value=url.lastPathComponent}
        else if parent == scope.libraryRoot+"/LaunchDaemons",url.lastPathComponent.hasSuffix(".plist"){value=String(url.lastPathComponent.dropLast(6))}
        else{return nil}
        return SystemCleanupScope.validIdentifier(value) ? value : nil
    }
    static func isBinary(_ item:Candidate,scope:SystemCleanupScope)->Bool{item.systemHelper.map{item.path == binary($0.label,scope)} ?? false}
    static func domain(_ scope:SystemCleanupScope)->String{scope.fixture ? "gui/"+String(scope.requesterUID) : "system"}
    private static func checkAdministrator(_ scope:SystemCleanupScope)throws{
        guard scope.fixture || as_administrator_member(scope.requesterUID) == 1 else{throw SweepError.denied("仅已确认的管理员可管理系统辅助组件")}
    }
    static func hasOtherAccounts(_ data:Data,requesterUID:UInt32)throws->Bool{
        guard let rows=try PropertyListSerialization.propertyList(from:data,format:nil)as? [[String:Any]],!rows.isEmpty,rows.count<=4096 else{throw SweepError.incomplete("系统组件的账户共享范围未确认")}
        var requester=false,other=false
        for row in rows{
            guard let values=row["dsAttrTypeStandard:UniqueID"]as? [String],values.count == 1,let id=Int32(values[0]) else{throw SweepError.incomplete("账户身份查询不完整，系统组件保留")}
            if id>=500 && id != 65534{if UInt32(id) == requesterUID{requester=true}else{other=true}}
        }
        guard requester else{throw SweepError.incomplete("认证用户未包含在原生账户查询中")}
        return other
    }
    #if os(macOS)
    private static func signing(_ path:String)throws->(SecStaticCode,[String:Any]){
        var code:SecStaticCode?,raw:CFDictionary?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath:path)as CFURL,[],&code) == errSecSuccess,let code,
              SecStaticCodeCheckValidity(code,SecCSFlags(rawValue:kSecCSStrictValidate|kSecCSCheckAllArchitectures|kSecCSCheckNestedCode),nil) == errSecSuccess,
              SecCodeCopySigningInformation(code,SecCSFlags(rawValue:kSecCSSigningInformation),&raw) == errSecSuccess,let info=raw as? [String:Any] else{throw SweepError.denied("辅助组件代码签名未确认")}
        return(code,info)
    }
    private static func satisfies(_ code:SecStaticCode,_ text:String,basicOnly:Bool=false)throws->Bool{
        var requirement:SecRequirement?
        guard !text.isEmpty,text.utf8.count<=65536,SecRequirementCreateWithString(text as CFString,[],&requirement) == errSecSuccess,let requirement else{throw SweepError.denied("辅助组件原生签名要求无法解析")}
        let flags = basicOnly ? kSecCSBasicValidateOnly|kSecCSCheckAllArchitectures : kSecCSStrictValidate|kSecCSCheckAllArchitectures
        return SecStaticCodeCheckValidity(code,SecCSFlags(rawValue:flags),requirement) == errSecSuccess
    }
    private static func clientIdentityMayMatch(_ path:String,requirement:String)throws->Bool{
        var code:SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath:path)as CFURL,[],&code) == errSecSuccess,let code else{return false}
        // Reject unrelated identities before walking their complete resources.
        // A possible match still undergoes the original strict validation below.
        return try satisfies(code,requirement,basicOnly:true)
    }
    #endif
    private static func referenceMetadata(_ app:ApplicationIdentity)throws->[String:Any]{
        if let physical = app.attributionMetadataPath {
            let info = try AppInspector.metadata(physical, component: true).0
            guard info["CFBundleIdentifier"] as? String == (app.attributionRawIdentifier ?? app.bundleIdentifier) else { throw SweepError.stale("组件共享线索的实际标识已改变") }
            return info // Discovery-only metadata; never a new executable target.
        }
        // Bystanders also include flattened iOS bundles. This reads declarations
        // for sharing vetoes only; inspect still requires the chosen macOS bundle.
        if let metadata=try? AppInspector.metadata(app.path,component:true).0{return metadata}
        #if os(macOS)
        // Read-only bystanders include native Apple aliases (for example Safari).
        // Signed metadata can add shared-ownership conflicts, never a write target.
        if let signed=try? signing(app.path),let info=signed.1[kSecCodeInfoPList as String]as? [String:Any]{return info}
        #endif
        do { return try AppInspector.metadata(app.path,component:true).0 }
        catch { throw SweepError.incomplete("辅助组件共享检查未确认：" + app.path + "；" + error.localizedDescription) }
    }
    /// Runs in the user client, with its own file access. Unknown or shared
    /// clients never produce an exclusive proof; the service rechecks the exact
    /// embedded helper hash before using the result as a sharing veto check.
    static func userSideSharingChecks(inventory: [ApplicationIdentity]) throws -> [UserOwnershipInventory.HelperCheck] {
        #if os(macOS)
        let userApps = inventory.filter { !SafetyPolicy.contains("/Applications", $0.path) }
        var checks: [String: UserOwnershipInventory.HelperCheck] = [:]
        for owner in inventory where SafetyPolicy.contains("/Applications", owner.path) {
            try Task.checkCancellation()
            guard let info = try? referenceMetadata(owner), let labels = try? UninstallDependencies.declaredLabels(info: info) else { continue }
            for label in labels {
                guard checks.count < 128 else { throw SweepError.incomplete("组件归属检查超限") }
                let embedded = owner.path + "/Contents/Library/LaunchServices/" + label
                guard let (_, signed) = try? signing(embedded), let metadata = signed[kSecCodeInfoPList as String] as? [String: Any],
                      let clients = metadata["SMAuthorizedClients"] as? [String], clients.count == 1,
                      let hash = try? ApplicationAgentRule.codeHash(application: embedded, identifier: label) else { continue }
                var exclusive = checks[label] == nil
                for app in userApps {
                    try Task.checkCancellation()
                    do {
                        let metadata = try referenceMetadata(app)
                        if try UninstallDependencies.declaredLabels(info: metadata).contains(label) { exclusive = false }
                        if try clientIdentityMayMatch(app.attributionMetadataPath ?? app.path, requirement: clients[0]) { exclusive = false }
                    } catch is CancellationError { throw CancellationError() }
                    catch { exclusive = false }
                }
                checks[label] = .init(label: label, codeHash: hash, inspectedPaths: Array(Set(userApps.map(\.path))).sorted(), exclusive: exclusive)
            }
        }
        return checks.values.sorted { $0.label < $1.label }
        #else
        throw SweepError.denied("当前平台未验证组件归属读取")
        #endif
    }
    static func application(_ item:Candidate,scope:SystemCleanupScope)throws{
        try scope.verify();try checkAdministrator(scope)
        if !scope.fixture{
            let users=try BoundedProcess.run("/usr/bin/dscl",arguments:["-plist","/Search","-readall","/Users","UniqueID"],timeout:5)
            guard try !hasOtherAccounts(Data(users.utf8),requesterUID:scope.requesterUID) else{throw SweepError.denied("存在其他用户账户，系统辅助组件的跨账户共享未确认，保留")}
        }
        guard let ref=item.systemHelper,let path=item.applicationPath,let id=item.bundleIdentifier,
              SystemCleanupScope.validIdentifier(id),label(item.path,scope:scope) == ref.label,
              SafetyPolicy.contains(scope.applicationsRoot,path),path != scope.applicationsRoot else{throw SweepError.denied("辅助组件缺少精确应用归属")}
        try ChosenApplicationRule.verifyStored(path:path,identifier:id)
        let body=try SafeDirectory(path:path).ownIdentity
        guard body.sameObject(as:ref.applicationIdentity),[scope.ownerUID,scope.requesterUID].contains(body.owner),
              try ApplicationAgentRule.codeHash(application:path,identifier:id) == ref.applicationCodeHash else{throw SweepError.stale("辅助组件原应用尚未恢复、已替换或已更新，保留组件")}
        let inventory=try scope.applicationInventory()
        guard inventory.issues.isEmpty,AppInspector.uniqueOwner(identifier:id,path:path,inventory:inventory.applications) else{throw SweepError.incomplete("辅助组件的安装归属不完整或共享")}
        #if os(macOS)
        let embedded=path+"/Contents/Library/LaunchServices/"+ref.label,embeddedInfo=try signing(embedded).1
        guard try ApplicationAgentRule.codeHash(application:embedded,identifier:ref.label) == (ref.embeddedCodeHash ?? ref.helperCodeHash),
              let metadata=embeddedInfo[kSecCodeInfoPList as String]as? [String:Any],let clients=metadata["SMAuthorizedClients"]as? [String],clients.count == 1 else{throw SweepError.denied("原辅助组件的授权客户端声明未确认")}
        #endif
        for app in inventory.applications where app.path != path{
            if !scope.fixture && !SafetyPolicy.contains(scope.applicationsRoot, app.path) {
                guard try scope.userInventory.current().provesExclusiveHelper(label: ref.label, codeHash: ref.embeddedCodeHash ?? ref.helperCodeHash, applicationsRoot: scope.applicationsRoot) else {
                    throw SweepError.denied("用户侧安装可能共享此系统组件，组件保留")
                }
                continue // User files were inspected by the authenticated client.
            }
            let info=try referenceMetadata(app)
            guard !(try UninstallDependencies.declaredLabels(info:info)).contains(ref.label) else{throw SweepError.denied("辅助组件仍由其他应用声明，整组保留")}
            #if os(macOS)
            let physical = app.attributionMetadataPath ?? app.path
            if try clientIdentityMayMatch(physical,requirement:clients[0]),let code=try? signing(physical).0,try satisfies(code,clients[0]){throw SweepError.denied("组件允许其他已安装客户端，保留共享资源")}
            #endif
        }
    }
    static func inspect(application path:String,identifier:String,label:String,scope:SystemCleanupScope)throws->InstalledSystemHelperReference{
        #if os(macOS)
        try checkAdministrator(scope)
        guard SystemCleanupScope.validIdentifier(label) else{throw SweepError.denied("系统组件标识受保护")}
        let app=try SafeDirectory(path:path).ownIdentity,appHash=try ApplicationAgentRule.codeHash(application:path,identifier:identifier)
        let source=try SafeFilesystem.snapshot(plist(label,scope)),helper=try SafeFilesystem.snapshot(binary(label,scope))
        for snapshot in [source,helper]{
            guard snapshot.identity.owner == scope.ownerUID,!snapshot.identity.isDirectory,snapshot.identity.links == 1 else{throw SweepError.denied("辅助组件不是原所有者的独立普通文件")}
            try scope.verifyUnsharedNode(path:snapshot.path,identity:snapshot.identity)
            let parent=try SafeDirectory(path:URL(fileURLWithPath:snapshot.path).deletingLastPathComponent().path)
            guard as_unshared_node_descriptor(parent.fd,scope.ownerUID) == 1 else{throw SweepError.denied("辅助组件安装目录可被共享改写")}
        }
        let relationship = try signedRelationship(application: path, identifier: identifier, label: label, installed: helper.path)
        var ref=InstalledSystemHelperReference(label:label,applicationIdentity:app,applicationCodeHash:appHash,helperCodeHash:relationship.installed,plistIdentity:source.identity,plistDigest:try VerifiedFileStream.digest(source))
        ref.embeddedCodeHash = relationship.embedded
        let item=Candidate(id:UUID(),path:source.path,category:.backgroundComponent,bundleIdentifier:identifier,applicationPath:path,evidence:[],rule:name,identity:source.identity,bytes:source.bytes,retentionReason:nil,systemHelper:ref)
        try self.application(item,scope:scope)
        let embedded=path+"/Contents/Library/LaunchServices/"+label
        let embeddedSource=try SafeFilesystem.snapshot(embedded)
        guard embeddedSource.identity.owner == app.owner else{throw SweepError.denied("包内辅助程序与已确认的应用所有者不一致")}
        try SafeFilesystem.verify(embeddedSource)
        _=try declaration(item,scope:scope)
        try SafeFilesystem.verify(source);try SafeFilesystem.verify(helper)
        return ref
        #else
        throw SweepError.denied("当前平台未验证系统辅助组件")
        #endif
    }
    /// Read-only relationship proof. It does not authorize lifecycle or a path;
    /// callers must also bind installation identity, exclusivity and stopped state.
    static func signedRelationship(application path: String, identifier: String, label: String, installed: String) throws -> (installed: Data, embedded: Data) {
        #if os(macOS)
        let appInfo = try AppInspector.metadata(path, component: false).0
        guard appInfo["CFBundleIdentifier"] as? String == identifier,
              let requirement = (appInfo["SMPrivilegedExecutables"] as? [String:String])?[label] else { throw SweepError.denied("应用未声明此辅助组件") }
        let embedded = path + "/Contents/Library/LaunchServices/" + label
        let installedHash = try ApplicationAgentRule.codeHash(application: installed, identifier: label)
        let embeddedHash = try ApplicationAgentRule.codeHash(application: embedded, identifier: label)
        let (code, info) = try signing(installed)
        let (embeddedCode, embeddedInfo) = try signing(embedded), (appCode, appSigning) = try signing(path)
        let source = try SafeFilesystem.snapshot(installed), bundled = try SafeFilesystem.snapshot(embedded)
        guard try satisfies(code, requirement), try satisfies(embeddedCode, requirement),
              let clients = (info[kSecCodeInfoPList as String] as? [String:Any])?["SMAuthorizedClients"] as? [String], clients.count == 1,
              let embeddedClients = (embeddedInfo[kSecCodeInfoPList as String] as? [String:Any])?["SMAuthorizedClients"] as? [String], clients == embeddedClients,
              try satisfies(appCode, clients[0]) else { throw SweepError.denied("已安装组件与包内副本的双向签名或客户端范围不一致") }
        if installedHash == embeddedHash {
            guard try VerifiedFileStream.digest(source, ownedBy: source.identity.owner) == VerifiedFileStream.digest(bundled, ownedBy: bundled.identity.owner) else { throw SweepError.denied("同签名辅助组件的字节不一致") }
        } else {
            // A normal application update can carry a newer helper. Only native
            // Apple-anchored signatures of the same publisher can bridge this
            // version difference; ad-hoc names or a vendor prefix cannot.
            guard let team = appSigning[kSecCodeInfoTeamIdentifier as String] as? String,
                  team.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil,
                  info[kSecCodeInfoTeamIdentifier as String] as? String == team,
                  embeddedInfo[kSecCodeInfoTeamIdentifier as String] as? String == team else { throw SweepError.denied("不同版本的辅助组件缺少同一可信发布者") }
            let anchor = "anchor apple generic and certificate leaf[subject.OU] = \"" + team + "\""
            guard try satisfies(appCode, anchor), try satisfies(code, anchor), try satisfies(embeddedCode, anchor) else { throw SweepError.denied("不同版本辅助组件的原生信任链未确认") }
        }
        try SafeFilesystem.verify(source); try SafeFilesystem.verify(bundled)
        return (installedHash, embeddedHash)
        #else
        throw SweepError.denied("当前平台未验证系统辅助组件")
        #endif
    }
    static func verify(_ item:Candidate,scope:SystemCleanupScope)throws{
        try application(item,scope:scope)
        guard let ref=item.systemHelper else{throw SweepError.denied("辅助组件引用缺失")}
        let snapshot=try SafeFilesystem.snapshot(item.path)
        try scope.verifyUnsharedNode(path:item.path,identity:snapshot.identity)
        if isBinary(item,scope:scope){
            guard snapshot.identity.mode & 0o111 != 0,try ApplicationAgentRule.codeHash(application:item.path,identifier:ref.label) == ref.helperCodeHash else{throw SweepError.stale("辅助程序身份或代码改变")}
        }else{_=try declaration(item,scope:scope)}
    }
    static func scan(scope:SystemCleanupScope,builder:inout Scanner.Builder)throws{
        try checkAdministrator(scope)
        let inventory=try scope.applicationInventory()
        guard inventory.issues.isEmpty else{builder.issues += inventory.issues;return}
        var count=0
        for app in inventory.applications where SystemCleanupScope.validIdentifier(app.bundleIdentifier) && SafetyPolicy.contains(scope.applicationsRoot,app.path){
            let info=try referenceMetadata(app)
            for label in try UninstallDependencies.declaredLabels(info:info){
                try Task.checkCancellation();count += 1
                guard count<=1000 else{throw SweepError.incomplete("辅助组件发现超过有界容量")}
                let paths=[binary(label,scope),plist(label,scope)]
                guard try paths.contains(where:{try SafeFilesystem.presence($0)}) else{continue}
                var reference:InstalledSystemHelperReference?,reason:String?
                if builder.policy.ruleIsValidated(name){
                    do{
                        reference=try inspect(application:app.path,identifier:app.bundleIdentifier,label:label,scope:scope)
                        guard let reference else{throw SweepError.denied("辅助组件归属缺失")}
                        var item=Candidate(id:UUID(),path:paths[0],category:.backgroundComponent,bundleIdentifier:app.bundleIdentifier,applicationPath:app.path,evidence:[],rule:name,identity:nil,bytes:0,retentionReason:nil)
                        item.systemHelper=reference
                        try ensureStopped(item,scope:scope)
                        for path in paths{try BusyInspector.ensureUnused(SafeFilesystem.snapshot(path))}
                    }catch is CancellationError{throw CancellationError()}
                    catch{reason=error.localizedDescription;if case SweepError.incomplete = error{builder.issues.append(app.path+"："+error.localizedDescription)}}
                }else{reason="系统辅助组件管理尚未通过当前平台验收，仅报告"}
                for path in paths{
                    try builder.scoped(root:path){part in
                        try part.add(path,category:.backgroundComponent,bundleID:app.bundleIdentifier,rule:name,
                            evidence:[.init(kind:.validatedRule,detail:"独占 SMJobBless 双向原生签名、已固定的安装与包内版本、精确停止状态；成组手动处理，应用主体和资料保留",verified:reason == nil)],reason:reason,applicationPath:app.path,displayName:"系统辅助组件 · "+app.name+" · "+URL(fileURLWithPath:path).lastPathComponent)
                        if let index=part.items.indices.last{part.items[index].systemHelper=reference;part.items[index].recommendation = .manual}
                    }
                }
            }
        }
    }
    static func declaration(_ item:Candidate,scope:SystemCleanupScope)throws->String{
        guard let ref=item.systemHelper else{throw SweepError.denied("缺少辅助组件声明")}
        let path=plist(ref.label,scope),snapshot=try SafeFilesystem.snapshot(path)
        guard snapshot.identity.sameObject(as:ref.plistIdentity),try VerifiedFileStream.digest(snapshot) == ref.plistDigest,
              let info=try PropertyListSerialization.propertyList(from:SafeFilesystem.readMetadata(path,maximumBytes:1024*1024),format:nil)as? [String:Any],
              Set(info.keys).isSubset(of:["Label","Program","ProgramArguments","MachServices","RunAtLoad","KeepAlive","Disabled","ProcessType","Version","AssociatedBundleIdentifiers","Sockets"]),
              info["Label"]as? String == ref.label,info["Program"] == nil || info["Program"]as? String == binary(ref.label,scope),
              info["ProgramArguments"]as? [String] == [binary(ref.label,scope)],
              info["KeepAlive"] == nil || info["KeepAlive"]as? Bool == false,
              info["ProcessType"] == nil || ["Background","Interactive","Adaptive","Standard"].contains(info["ProcessType"] as? String ?? ""),
              info["Version"] == nil || (info["Version"] as? String)?.range(of: "^[A-Za-z0-9._-]{1,64}$", options: .regularExpression) != nil,
              info["AssociatedBundleIdentifiers"] == nil || info["AssociatedBundleIdentifiers"] as? [String] == item.bundleIdentifier.map({[$0]}) else{throw SweepError.denied("辅助服务含共享、持续重启或未知副作用，保留")}
        for flag in ["RunAtLoad","KeepAlive","Disabled"] {
            if let value = info[flag] { guard CFGetTypeID(value as CFTypeRef) == CFBooleanGetTypeID() else { throw SweepError.denied("辅助服务开关不是明确的布尔声明") } }
        }
        if let sockets = info["Sockets"] {
            let socketRoot = scope.fixture ? scope.libraryRoot + "/Run" : "/var/run"
            guard info["MachServices"] == nil, let entries = sockets as? [String:[String:Any]], Set(entries.keys) == ["Listener"], let listener = entries["Listener"],
                  Set(listener.keys) == ["SockPathName","SockPathMode"],
                  listener["SockPathName"] as? String == socketRoot + "/" + ref.label + ".sock",
                  let mode = listener["SockPathMode"] as? Int, [0o600,0o666].contains(mode) else { throw SweepError.denied("辅助服务 Socket 不是精确独立端点，保留") }
        } else {
            guard info["MachServices"] as? [String:Bool] == [ref.label:true] else { throw SweepError.denied("辅助服务 Mach 端点不是精确独占声明") }
        }
        return path
    }
    private static func permitsDormantRegistration(_ item: Candidate, scope: SystemCleanupScope) throws -> Bool {
        let path = try declaration(item, scope: scope)
        guard let info = try PropertyListSerialization.propertyList(from: SafeFilesystem.readMetadata(path, maximumBytes: 1024*1024), format: nil) as? [String:Any] else { throw SweepError.denied("辅助服务声明未确认") }
        return info["Sockets"] == nil && info["RunAtLoad"] as? Bool != true
    }
    static func registered(_ item:Candidate,scope:SystemCleanupScope)throws->Bool{
        guard let ref=item.systemHelper else{throw SweepError.denied("缺少辅助组件登记")}
        let domain=domain(scope),output=try BoundedProcess.capture("/bin/launchctl",arguments:["print",domain+"/"+ref.label],timeout:5,mergeStderr:true)
        if output.status == 113{_=try BoundedProcess.run("/bin/launchctl",arguments:["print",domain],timeout:5);return false}
        let lines=Set(output.text.split(separator:"\n").map{$0.trimmingCharacters(in:.whitespaces)})
        guard output.status == 0,lines.contains("path = "+plist(ref.label,scope)),lines.contains("program = "+binary(ref.label,scope)),
              lines.contains("state = not running"),!lines.contains(where:{$0.hasPrefix("pid = ")}) else{throw SweepError.denied("辅助服务正在运行、来源改变或状态未知；App Sweep 不会结束它")}
        return true
    }
    static func ensureStopped(_ item:Candidate,scope:SystemCleanupScope,requireApplication:Bool=true)throws{
        if requireApplication{try application(item,scope:scope)}else{try scope.verify();try checkAdministrator(scope)}
        let knownRegistered=try registered(item,scope:scope)
        guard requireApplication || !knownRegistered else{throw SweepError.denied("组件已重新注册，保留隔离副本并先核对新注册")}
        if knownRegistered, try !permitsDormantRegistration(item, scope: scope) { throw SweepError.denied("自动启动或 Socket 服务仍已注册；请先自行停用，再核对卸载") }
        guard let id=item.bundleIdentifier,let app=item.applicationPath,let ref=item.systemHelper else{throw SweepError.denied("辅助服务活动归属未确认")}
        let own=ProcessInfo.processInfo.processIdentifier,processes=try ActivityInspector.processes(BoundedProcess.run("/bin/ps",arguments:["-ww","-axo","pid=,command="],timeout:3),ownPID:own)
        guard !processes.contains(where:{$0.pid != own && ($0.command.contains(app) || $0.command.contains(id) || $0.command.contains(ref.label))}) else{throw SweepError.denied("应用或辅助程序仍在运行，保留组件")}
        for domain in Set([self.domain(scope),"gui/"+String(scope.requesterUID)]){
            let output=try BoundedProcess.run("/bin/launchctl",arguments:["print",domain],timeout:5)
            let remaining=unresolvedRegistry(output,verifiedLabel:knownRegistered && domain == self.domain(scope) ? ref.label : nil)
            guard !remaining.contains(app),!remaining.contains(id),!remaining.contains(ref.label) else{throw SweepError.denied("存在其他关联注册，辅助组件保留")}
        }
    }
    static func unresolvedRegistry(_ output:String,verifiedLabel:String?)->String{
        output.split(separator:"\n").filter{line in
            guard let label=verifiedLabel else{return true}
            let fields=line.split(whereSeparator:{$0 == " " || $0 == "\t"})
            let service=fields.count == 3 && fields[0] == "0" && (fields[1] == "-" || Int(fields[1]) != nil) && fields[2] == Substring(label)
            // Native dormant declared Mach endpoint; active ports and other
            // domains/jobs stay uncertain even when their names look related.
            let endpoint=fields.count == 4 && fields[0] == "0" && fields[1] == "M" && fields[2] == "D" && fields[3] == Substring(label)
            return !service && !endpoint
        }.joined(separator:"\n")
    }
    static func unregister(_ item:Candidate,scope:SystemCleanupScope)throws{
        try ensureStopped(item,scope:scope)
        guard let ref=item.systemHelper else{throw SweepError.denied("缺少辅助组件登记")}
        // The executable has already been moved by the verified transaction.
        guard try !SafeFilesystem.presence(binary(ref.label,scope)) else{throw SweepError.denied("先隔离已核验的程序，再注销停止状态的服务")}
        if try registered(item,scope:scope){_=try BoundedProcess.run("/bin/launchctl",arguments:["bootout",domain(scope)+"/"+ref.label],timeout:5)}
        guard try !registered(item,scope:scope) else{throw SweepError.incomplete("系统辅助组件注销未确认")}
    }
    static func restoreRegistration(_ item:Candidate,wasRegistered:Bool,scope:SystemCleanupScope)throws{
        try application(item,scope:scope)
        guard let ref=item.systemHelper,let id=item.bundleIdentifier,let app=item.applicationPath else{throw SweepError.denied("缺少辅助组件恢复归属")}
        let current=try inspect(application:app,identifier:id,label:ref.label,scope:scope)
        guard current.helperCodeHash == ref.helperCodeHash,(current.embeddedCodeHash ?? current.helperCodeHash) == (ref.embeddedCodeHash ?? ref.helperCodeHash),current.plistDigest == ref.plistDigest,current.plistIdentity.sameObject(as:ref.plistIdentity) else{throw SweepError.stale("原辅助组件文件尚未完整恢复")}
        try ensureStopped(item,scope:scope)
        let registered=try registered(item,scope:scope)
        if wasRegistered && !registered{
            guard try permitsDormantRegistration(item, scope: scope) else { throw SweepError.denied("恢复不会自动启动服务；文件已保留，需要人工核对登记状态") }
            _=try BoundedProcess.run("/bin/launchctl",arguments:["bootstrap",domain(scope),plist(ref.label,scope)],timeout:5)
            guard try self.registered(item,scope:scope) else{throw SweepError.incomplete("原辅助组件注册尚未恢复")}
        }else if !wasRegistered && registered{throw SweepError.denied("原未注册的组件出现新注册，保留且不覆盖")}
    }
}
