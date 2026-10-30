import Foundation
import CFSafety
#if os(macOS)
import Darwin
#else
import Glibc
#endif

/// Service-owned authority, never decoded from requests. Production roots are fixed.
struct SystemCleanupScope: Sendable {
    let libraryRoot: String
    let applicationsRoot: String
    let userHome: String
    let requesterUID: UInt32
    let ownerUID: UInt32
    private let device: UInt64
    private let roots: [String: [AncestorIdentity]]
    private let configuration: LoadedRootServicePins?
    private let user: AuthenticatedUserContext?
    private let vaultBase: String
    let fixture: Bool
    let userInventory = UserOwnershipInventoryStore()
    var vaultPath: String { vaultBase + "/" + String(requesterUID) }

    private init(libraryRoot: String, applicationsRoot: String, userHome: String, requesterUID: UInt32,
                 configuration: LoadedRootServicePins?, user: AuthenticatedUserContext?, fixture: Bool) throws {
        self.libraryRoot = libraryRoot; self.applicationsRoot = applicationsRoot; self.userHome = userHome
        self.requesterUID = requesterUID; ownerUID = as_current_uid()
        device = try SafeDirectory(path:libraryRoot).ownIdentity.device
        self.configuration = configuration; self.user = user; self.fixture = fixture
        vaultBase = fixture ? libraryRoot + "/Recovery.noindex" : "/Library/Application Support/App Sweep/Recovery.noindex"
        guard requesterUID >= 500, requesterUID < UInt32(Int32.max) else { throw SweepError.denied("系统恢复用户未确认") }
        roots = try Dictionary(uniqueKeysWithValues: [libraryRoot, applicationsRoot].map { ($0, try SafeFilesystem.ancestors(of: $0)) })
        try verify()
    }
    static func authenticated(_ peer: AuthenticatedLocalPeer) throws -> Self {
        guard as_current_uid() == 0, getuid() == 0 else { throw SweepError.denied("系统执行者必须由系统安装并以root运行") }
        let user = try AuthenticatedUserContext.resolve(peer), config = try RootServiceConfiguration.load()
        return try Self(libraryRoot:"/Library",applicationsRoot:"/Applications",userHome:user.home,requesterUID:user.uid,configuration:config,user:user,fixture:false)
    }
    #if DEBUG
    static func fixture(libraryRoot: String, applicationsRoot: String, userHome: String, requesterUID: UInt32) throws -> Self {
        let accountHome = try SystemIdentity.home()
        guard as_current_uid() != 0, userHome.hasPrefix(accountHome + "/AppSweepAcceptance"),
              libraryRoot == userHome + "/MachineLibrary", applicationsRoot == userHome + "/Applications" else { throw SweepError.denied("仅允许现有隔离任务的私有系统夹具") }
        _ = try SafeDirectory(path:libraryRoot).privateChild("Recovery.noindex")
        return try Self(libraryRoot:libraryRoot,applicationsRoot:applicationsRoot,userHome:userHome,requesterUID:requesterUID,configuration:nil,user:nil,fixture:true)
    }
    #endif
    func verify() throws {
        guard as_current_uid() == ownerUID, fixture || ownerUID == 0 else { throw SweepError.denied("系统执行者身份已改变") }
        try configuration?.verifyUnchanged(); try user?.verifyUnchanged()
        for (path, expected) in roots {
            guard try SafeFilesystem.ancestors(of:path) == expected,
                  try SafeDirectory(path:path).ownIdentity.owner == ownerUID else { throw SweepError.stale("系统范围目录或祖先身份已改变") }
        }
    }
    func applicationInventory() throws -> ApplicationInventory {
        try verify()
        if !fixture {
            let userEvidence = try userInventory.current()
            let machine = try AppInspector.inventorySnapshot(home: userHome, machineOnly: true)
            let result = try userEvidence.combining(machine: machine, applicationsRoot: applicationsRoot)
            try verify()
            return result
        }
        let result = try AppInspector.inventorySnapshot(home:userHome,indexLookup: { home in
            guard home == userHome else { throw SweepError.denied("系统索引范围与认证账户不一致") }
            if let user { return try ApplicationIndex.systemPaths(for:user) }
            return try ApplicationIndex.systemPaths(home:home)
        })
        try verify()
        return result
    }
    func openVault(create: Bool) throws -> SafeDirectory {
        try verify()
        if !create { return try SafeDirectory(path:vaultBase).existingPrivateChild(String(requesterUID)) }
        let parentPath = URL(fileURLWithPath:vaultBase).deletingLastPathComponent().path
        let parent = try SafeDirectory(path:parentPath)
        if !fixture {
            // The fixed installation/configuration chain must remain root-only writable.
            _ = try RootServiceConfiguration.load()
        }
        return try parent.privateChild("Recovery.noindex").privateChild(String(requesterUID))
    }
    func operationLock() throws -> Int32 {
        try verify()
        let fd = as_open_directory(vaultBase)
        guard fd >= 0 else { throw SweepError.denied("系统恢复基础目录未完整安装") }
        guard as_private_descriptor(fd) == 1, as_lock(fd) == 0 else { as_close(fd); throw SweepError.denied("另一系统操作正在使用恢复区，请稍后重试") }
        return fd
    }
    /// Called with the global lock held. Never exposes another user's paths.
    func ensureNoUnfinishedOperations() throws {
        let base = try SafeDirectory(path:vaultBase), names = try FileManager.default.contentsOfDirectory(atPath:base.path)
        guard names.count <= 1000 else { throw SweepError.denied("系统恢复用户目录过多，需要核对") }
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        for name in names {
            guard let uid = UInt32(name), uid >= 500, uid < UInt32(Int32.max), String(uid) == name else { throw SweepError.denied("系统恢复区存在未登记对象，需要核对") }
            let vault = try base.existingPrivateChild(name), batches = try FileManager.default.contentsOfDirectory(atPath:vault.path)
            guard batches.count <= 1000 else { throw SweepError.denied("系统恢复批次过多，需要核对") }
            for batchName in batches {
                guard let id = UUID(uuidString:batchName), id.uuidString == batchName else { throw SweepError.denied("系统恢复批次名称未确认") }
                let batch = try vault.existingPrivateChild(batchName)
                let manifest = try decoder.decode(RecoveryManifest.self,from:batch.read("manifest.json"))
                guard manifest.schemaVersion == RecoveryManifest.systemSchemaVersion, manifest.id == id, manifest.requestingUserID == uid else { throw SweepError.denied("系统恢复记录与请求用户不一致，需要核对") }
                guard !manifest.hasUnconfirmedObjects, ![.inProgress,.purging,.needsAttention].contains(manifest.status) else { throw SweepError.denied("存在未完成的系统清理操作，请先完成恢复；其他系统清理已暂停") }
            }
        }
    }
    func denial(_ item: Candidate,requireCurrentVolume:Bool=true) -> String? {
        guard let volume=try? SafeDirectory(path:libraryRoot).ownIdentity else{return "系统卷身份未确认"}
        if let reason = pathDenial(item.path,category:item.category,rule:item.rule) { return reason }
        if item.rule == InstalledSystemHelperRule.name{
            guard item.category == .backgroundComponent,let ref=item.systemHelper,InstalledSystemHelperRule.label(item.path,scope:self) == ref.label,
                  item.bundleIdentifier.map(Self.validIdentifier) == true,let app=item.applicationPath,XcodeRule.canonical(app),SelectedApplicationRule.matches(path:app,policy:SafetyPolicy(home:userHome,acceptedPlatform:false)),SafetyPolicy.contains(applicationsRoot,app),app != applicationsRoot,
                  item.identity?.owner == ownerUID,item.identity?.links == 1,(item.identity?.mode ?? 0) & 0o170000 == 0o100000,
                  !requireCurrentVolume || item.identity?.sameVolume(as:volume) == true,
                  ref.applicationIdentity.isDirectory,[ownerUID,requesterUID].contains(ref.applicationIdentity.owner),[20,32].contains(ref.applicationCodeHash.count),[20,32].contains(ref.helperCodeHash.count),ref.plistIdentity.owner == ownerUID,ref.plistIdentity.links == 1,ref.plistIdentity.mode & 0o170000 == 0o100000,ref.plistIdentity.size>0,ref.plistIdentity.size<=1024*1024,ref.plistDigest.count == 64,ref.plistDigest.utf8.allSatisfy({(48...57).contains($0)||(97...102).contains($0)}) else{return "系统辅助组件的归属、身份或动作未确认"}
            return nil
        }
        if item.rule == SystemDiagnosticRule.name {
            return item.category == .log && item.applicationPath == nil && item.bundleIdentifier.map({ AppInspector.validIdentifier($0) && $0.hasPrefix("com.apple.") }) == true && item.identity?.owner == ownerUID && item.identity?.links == 1 && (item.identity?.mode ?? 0) & 0o170000 == 0o100000 && (item.identity?.mode ?? 0) & 0o022 == 0 && (!requireCurrentVolume || item.identity?.sameVolume(as: volume) == true) ? nil : "系统诊断报告身份或归属未确认"
        }
        if item.rule == DeletedUserArchiveRule.name {
            return item.category == .userData && item.bundleIdentifier == nil && item.applicationPath == nil && item.identity?.owner == ownerUID && (!requireCurrentVolume || item.identity?.sameVolume(as:volume) == true) && item.identity?.links == 1 && (item.identity?.mode ?? 0) & 0o170000 == 0o100000 ? nil : "账户归档身份或类别未确认"
        }
        guard item.identity?.owner == ownerUID, !requireCurrentVolume || item.identity?.sameVolume(as:volume) == true, let id = item.bundleIdentifier, Self.validIdentifier(id),
              let app = item.applicationPath, app.hasSuffix(".app"), canonical(app),
              SafetyPolicy.contains(applicationsRoot,app), app != applicationsRoot else { return "系统对象归属或应用位置未确认" }
        if item.rule == SystemDomainRule.cacheName, item.category == .cache,
           URL(fileURLWithPath:item.path).deletingLastPathComponent().path == SystemDomainRule.cacheRoot(self,id) { return canonical(item.path) ? nil : "系统路径别名受保护" }
        if item.rule == SystemDomainRule.logName, item.category == .log,
           SystemDomainRule.logMatches(item.path,scope:self,identifier:id), (item.identity?.mode ?? 0) & 0o170000 == 0o100000 { return nil }
        if item.rule == SystemDomainRule.currentLogName,item.category == .log,
           SystemDomainRule.currentLogMatches(item.path,scope:self,identifier:id),(item.identity?.mode ?? 0) & 0o170000 == 0o100000{return nil}
        return "不在已登记的系统规则范围内"
    }
    func pathDenial(_ path: String,category: CandidateCategory,rule: String) -> String? {
        guard canonical(path) else { return "系统路径别名受保护" }
        if rule == InstalledSystemHelperRule.name{return category == .backgroundComponent && InstalledSystemHelperRule.label(path,scope:self) != nil ? nil : "不是已登记的系统辅助组件位置"}
        if rule == SystemDiagnosticRule.name { return category == .log && SystemDiagnosticRule.matches(path, libraryRoot: libraryRoot) ? nil : "不是已登记的独立系统诊断报告" }
        if rule == DeletedUserArchiveRule.name {
            return category == .userData && DeletedUserArchiveRule.account(path,scope:self) != nil ? nil : "不是专用位置中的整份账户归档"
        }
        let base: String
        if category == .cache && rule == SystemDomainRule.cacheName { base = libraryRoot + "/Caches" }
        else if category == .log && [SystemDomainRule.logName,SystemDomainRule.currentLogName].contains(rule) { base = libraryRoot + "/Logs" }
        else { return "系统执行者不接受此类别或规则" }
        guard SafetyPolicy.contains(base,path), path != base else { return "不在已登记的系统范围内" }
        let parts = path.dropFirst(base.count + 1).split(separator:"/").map(String.init)
        guard (parts.count >= 2 || (category == .log && rule == SystemDomainRule.currentLogName && parts.count == 1)), Self.validIdentifier(parts[0]),
              category != .cache || parts.count == 2,
              !parts.contains(where: { let name = $0.lowercased(); return name == "keychains" || name.hasSuffix(".keychain") || name.hasSuffix(".keychain-db") || name == "com.apple.tcc" }) else { return "系统命名空间或安全内容受保护" }
        return nil
    }
    static func validIdentifier(_ id: String) -> Bool {
        AppInspector.validIdentifier(id) && !id.lowercased().hasPrefix("com.apple.") && !id.lowercased().contains("appsweep") && !id.lowercased().contains("app-sweep")
    }
    func verifyApplication(_ app: ApplicationIdentity, inventory: [ApplicationIdentity], inspectionProcess:(@Sendable (Int32) throws -> Bool)? = nil) throws {
        try verify()
        guard Self.validIdentifier(app.bundleIdentifier), canonical(app.path), app.path.hasSuffix(".app"),
              SafetyPolicy.contains(applicationsRoot,app.path), app.path != applicationsRoot,
              SelectedApplicationRule.matches(path:app.path,policy:SafetyPolicy(home:userHome,acceptedPlatform:false)),
              AppInspector.uniqueOwner(identifier:app.bundleIdentifier,path:app.path,inventory:inventory) else { throw SweepError.denied("系统缓存缺少唯一的第三方安装主体") }
        try ChosenApplicationRule.verifyStored(path:app.path,identifier:app.bundleIdentifier,requireNoInstalledHelpers:true)
        guard AppInspector.signatureMatches(path:app.path,identifier:app.bundleIdentifier) else { throw SweepError.denied("系统数据应用签名未确认") }
        let body = try SafeFilesystem.snapshot(app.path,allowInternalLinks:true,purpose:.application,allowApplicationHardLinks:true)
        guard body.identity.device == device, body.identity.owner == ownerUID, body.identity.mode & 0o022 == 0,
              body.tree.allSatisfy({ $0.identity.owner == ownerUID && ($0.identity.isLink || $0.identity.mode & 0o022 == 0) }) else { throw SweepError.denied("系统数据主体可被其他用户改写，已保留") }
        for node in [TreeEntry(relative:"",identity:body.identity)] + body.tree where !node.identity.isLink {
            try Task.checkCancellation()
            let path = node.relative.isEmpty ? body.path : body.path + "/" + node.relative
            try verifyUnsharedNode(path:path,identity:node.identity)
        }
        try ActivityInspector.ensureSystemServicesStopped(identifiers:[app.bundleIdentifier],applicationPath:app.path)
        try ActivityInspector.ensureStopped(bundleID:app.bundleIdentifier,applicationPath:app.path,userID:requesterUID,inspectionProcess:inspectionProcess)
        try BusyInspector.ensureUnused(body)
        try SafeFilesystem.verify(body)
    }
    func verifyUnsharedNode(path: String,identity: FileIdentity) throws {
        let url = URL(fileURLWithPath:path), parent = try SafeDirectory(path:url.deletingLastPathComponent().path)
        let fd = url.lastPathComponent.withCString { openat(parent.fd,$0,O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC) }
        guard fd >= 0 else { throw SweepError.denied("系统对象无法安全核验") }
        defer { as_close(fd) }
        var native = ASIdentity()
        guard as_identity_fd(fd,&native) == 0, FileIdentity(native) == identity,
              as_unshared_node_descriptor(fd,ownerUID) == 1 else { throw SweepError.denied("系统对象的所有者、ACL或改写权限未确认，已保留") }
    }
    private func canonical(_ path: String) -> Bool {
        path.hasPrefix("/") && !path.hasSuffix("/") && !path.contains("\0") && !path.contains("//") && path == URL(fileURLWithPath:path).standardizedFileURL.path
    }
}

struct SystemScanner {
    let scope: SystemCleanupScope
    let policy: SafetyPolicy
    func scan(_ category: SystemCleanupCategory) throws -> ScanOutput {
        var builder=Scanner.Builder(policy:policy)
        try scan(category,into:&builder)
        return builder.finish(applicationPath:nil)
    }
    func scan(_ category: SystemCleanupCategory, into builder: inout Scanner.Builder) throws {
        try scope.verify()
        let lease = try scope.operationLock()
        defer { as_close(lease) }
        try scope.ensureNoUnfinishedOperations()
        if category == .deletedUserArchives {
            try DeletedUserArchiveRule.scan(scope:scope,builder:&builder)
            try scope.verify();return
        }
        if category == .applicationHelpers{
            try InstalledSystemHelperRule.scan(scope:scope,builder:&builder)
            try scope.verify();return
        }
        if category == .logs { try SystemDiagnosticRule.scan(scope: scope, builder: &builder) }
        let inventory = try scope.applicationInventory(), apps = inventory.applications
        builder.issues += inventory.issues
        for app in apps where SystemCleanupScope.validIdentifier(app.bundleIdentifier) && SafetyPolicy.contains(scope.applicationsRoot,app.path) {
            try Task.checkCancellation()
            let root = category == .caches ? SystemDomainRule.cacheRoot(scope,app.bundleIdentifier) : SystemDomainRule.logRoot(scope,app.bundleIdentifier)
            try builder.scoped(root:root) { part in
                guard try SafeFilesystem.presence(root) else { return }
                try scope.verifyApplication(app,inventory:apps)
                let snapshot: FileSnapshot
                if category == .caches { snapshot = try SystemDomainRule.verifyDomain(scope,identifier:app.bundleIdentifier) }
                else {
                    snapshot = try SystemDomainRule.verifyLogDomain(scope,identifier:app.bundleIdentifier)
                }
                let currentLogs=policy.ruleIsValidated(SystemDomainRule.currentLogName)
                let paths = category == .caches ? try SystemDomainRule.members(scope,identifier:app.bundleIdentifier).sorted() : snapshot.tree.filter { !$0.identity.isDirectory }.map { root + "/" + $0.relative }
                for path in paths {
                    if category == .logs {
                        guard SystemDomainRule.logMatches(path,scope:scope,identifier:app.bundleIdentifier),
                              let entry = snapshot.tree.first(where: { root + "/" + $0.relative == path }),
                              (currentLogs || Attribution.oldLog(modified:Date(timeIntervalSince1970:Double(entry.identity.modifiedSeconds)),now:Date())) else { continue }
                        if currentLogs {
                            var reason:String?
                            do{try SystemDomainRule.verifyCurrentLog(path,scope:scope,identifier:app.bundleIdentifier)}
                            catch is CancellationError{throw CancellationError()}
                            catch{reason=error.localizedDescription;switch error{case SweepError.denied:break;default:part.issues.append(path + "：" + error.localizedDescription)}}
                            try part.add(path,category:.log,bundleID:app.bundleIdentifier,rule:SystemDomainRule.currentLogName,
                                evidence:[.init(kind:.signature,detail:"系统安装主体签名及唯一归属已核验",verified:true),.init(kind:.validatedRule,detail:"独占且未占用的普通系统应用日志；近期日志需手动选择",verified:reason == nil)],reason:reason,applicationPath:app.path)
                            continue
                        }
                    }
                    try part.add(path,category:category == .caches ? .cache : .log,bundleID:app.bundleIdentifier,
                                 rule:category == .caches ? SystemDomainRule.cacheName : SystemDomainRule.logName,
                                 evidence:[.init(kind:.signature,detail:"系统安装主体签名、唯一归属及不可由其他用户改写的结构已核验",verified:true),
                                           .init(kind:.validatedRule,detail:"精确第三方系统域；所有者、卷及停止状态已核验",verified:true)],reason:nil,applicationPath:app.path)
                }
                try SafeFilesystem.verify(snapshot)
            }
            if category == .logs,policy.ruleIsValidated(SystemDomainRule.currentLogName) {
                do {
                    for path in try SystemDomainRule.looseLogs(scope,identifier:app.bundleIdentifier) {
                        try builder.scoped(root:path){part in
                            try scope.verifyApplication(app,inventory:apps)
                            var reason:String?
                            do{try SystemDomainRule.verifyCurrentLog(path,scope:scope,identifier:app.bundleIdentifier)}
                            catch is CancellationError{throw CancellationError()}
                            catch{reason=error.localizedDescription;switch error{case SweepError.denied:break;default:part.issues.append(path + "：" + error.localizedDescription)}}
                            try part.add(path,category:.log,bundleID:app.bundleIdentifier,rule:SystemDomainRule.currentLogName,
                                evidence:[.init(kind:.signature,detail:"精确应用标识、系统安装主体签名与唯一归属一致",verified:true),.init(kind:.validatedRule,detail:"精确标识的松散系统日志及数字轮转；近期日志需手动选择",verified:reason == nil)],reason:reason,applicationPath:app.path)
                        }
                    }
                }catch is CancellationError{throw CancellationError()}
                catch{builder.issues.append("松散系统日志发现未确认：" + error.localizedDescription)}
            }
        }
        try scope.verify()
    }
}

enum SystemDomainRule {
    static let cacheName = "system-cache-exact-domain-v1"
    static let logName = "system-third-party-log-30d-v1"
    static let currentLogName = "system-third-party-log-v2"
    static func cacheRoot(_ scope: SystemCleanupScope,_ id: String) -> String { scope.libraryRoot + "/Caches/" + id }
    static func logRoot(_ scope: SystemCleanupScope,_ id: String) -> String { scope.libraryRoot + "/Logs/" + id }
    static func members(_ scope: SystemCleanupScope,identifier: String) throws -> Set<String> {
        let path = cacheRoot(scope,identifier), directory = try SafeDirectory(path:path)
        guard try directory.ownIdentity.owner == scope.ownerUID else { throw SweepError.denied("系统缓存域所有者已改变") }
        var buffer = [UInt8](repeating:0,count:2 * 1024 * 1024), count = 0
        guard as_directory_entries(directory.fd,&buffer,buffer.count,20000,&count) == 0,
              let text = String(bytes:buffer.prefix(count),encoding:.utf8) else { throw SweepError.incomplete("系统缓存成员枚举失败或截断") }
        return Set(text.split(separator:"\0").map { path + "/" + $0 })
    }
    static func verifyDomain(_ scope: SystemCleanupScope,identifier: String) throws -> FileSnapshot {
        guard SystemCleanupScope.validIdentifier(identifier) else { throw SweepError.denied("受保护的系统标识") }
        let snapshot = try SafeFilesystem.snapshot(cacheRoot(scope,identifier),allowInternalHardLinks:true)
        guard snapshot.identity.isDirectory, snapshot.identity.owner == scope.ownerUID,
              snapshot.tree.allSatisfy({ $0.identity.owner == scope.ownerUID }),
              !SupportDomainRule.containsProtectedContent(snapshot.tree) else { throw SweepError.denied("系统缓存包含其他用户、共享或安全对象，整域保留") }
        for entry in [TreeEntry(relative:"",identity:snapshot.identity)] + snapshot.tree {
            try Task.checkCancellation()
            let path = entry.relative.isEmpty ? snapshot.path : snapshot.path + "/" + entry.relative
            try scope.verifyUnsharedNode(path:path,identity:entry.identity)
            _ = try CacheNodeMetadata.read(path:path,identity:entry.identity)
        }
        try SafeFilesystem.verify(snapshot); return snapshot
    }
    static func logMatches(_ path: String,scope: SystemCleanupScope,identifier: String) -> Bool {
        let root = logRoot(scope,identifier)
        return SystemCleanupScope.validIdentifier(identifier) && path != root && SafetyPolicy.contains(root,path) &&
            path == URL(fileURLWithPath:path).standardizedFileURL.path && path.dropFirst(root.count + 1).split(separator:"/").count <= 64 &&
            ApplicationLogRule.recognizableName(URL(fileURLWithPath:path).lastPathComponent)
    }
    static func currentLogMatches(_ path:String,scope:SystemCleanupScope,identifier:String) -> Bool {
        guard SystemCleanupScope.validIdentifier(identifier),XcodeRule.canonical(path) else{return false}
        if logMatches(path,scope:scope,identifier:identifier){return true}
        let url=URL(fileURLWithPath:path),name=url.lastPathComponent
        return url.deletingLastPathComponent().path == scope.libraryRoot + "/Logs" && name.hasPrefix(identifier) &&
            String(name.dropFirst(identifier.count)).range(of:#"^\.log(?:\.[0-9]+)?(?:\.(?:gz|bz2|xz|zip))?$"#,options:.regularExpression) != nil
    }
    static func looseLogs(_ scope:SystemCleanupScope,identifier:String) throws -> [String] {
        let root=scope.libraryRoot + "/Logs"
        guard try SafeFilesystem.presence(root) else{return []}
        let directory=try SafeDirectory(path:root),before=try directory.ownIdentity
        guard before.owner == scope.ownerUID else{throw SweepError.denied("系统日志根目录所有者未确认")}
        try scope.verifyUnsharedNode(path:root,identity:before)
        var buffer=[UInt8](repeating:0,count:2*1024*1024),count=0
        guard as_directory_entries(directory.fd,&buffer,buffer.count,4096,&count) == 0,let text=String(bytes:buffer.prefix(count),encoding:.utf8) else{throw SweepError.incomplete("松散系统日志枚举失败或截断")}
        guard try directory.ownIdentity == before,try SafeDirectory(path:root).ownIdentity == before else{throw SweepError.stale("系统日志根目录枚举期间改变")}
        return text.split(separator:"\0").map{root + "/" + $0}.filter{currentLogMatches($0,scope:scope,identifier:identifier)}.sorted()
    }
    static func verifyCurrentLog(_ path:String,scope:SystemCleanupScope,identifier:String) throws {
        guard currentLogMatches(path,scope:scope,identifier:identifier) else{throw SweepError.denied("不是精确应用的系统日志")}
        var domain:FileSnapshot?
        if logMatches(path,scope:scope,identifier:identifier){domain=try verifyLogDomain(scope,identifier:identifier)}
        else {
            let root=scope.libraryRoot + "/Logs",identity=try SafeDirectory(path:root).ownIdentity
            guard identity.owner == scope.ownerUID else{throw SweepError.denied("系统日志根目录所有者未确认")}
            try scope.verifyUnsharedNode(path:root,identity:identity)
        }
        let snapshot=try SafeFilesystem.snapshot(path)
        guard snapshot.identity.owner == scope.ownerUID,snapshot.identity.mode & 0o170000 == 0o100000,snapshot.identity.links == 1 else{throw SweepError.denied("系统日志类型或独占所有者未确认")}
        try scope.verifyUnsharedNode(path:path,identity:snapshot.identity)
        _=try CacheNodeMetadata.read(snapshot)
        try ApplicationLogRule.verifyLogPayload(snapshot)
        try BusyInspector.ensureUnused(snapshot)
        try SafeFilesystem.verify(snapshot)
        if let domain{try SafeFilesystem.verify(domain)}
    }
    static func verifyLogDomain(_ scope: SystemCleanupScope,identifier: String) throws -> FileSnapshot {
        guard SystemCleanupScope.validIdentifier(identifier) else { throw SweepError.denied("受保护的系统标识") }
        let snapshot = try SafeFilesystem.snapshot(logRoot(scope,identifier))
        guard snapshot.identity.isDirectory, snapshot.identity.owner == scope.ownerUID,
              snapshot.tree.allSatisfy({$0.identity.owner == scope.ownerUID}) else { throw SweepError.denied("系统日志包含其他用户资料，整域保留") }
        for entry in [TreeEntry(relative:"",identity:snapshot.identity)] + snapshot.tree {
            try Task.checkCancellation()
            try scope.verifyUnsharedNode(path:entry.relative.isEmpty ? snapshot.path : snapshot.path + "/" + entry.relative,identity:entry.identity)
        }
        try SafeFilesystem.verify(snapshot)
        return snapshot
    }
    static func verify(_ item: Candidate,scope: SystemCleanupScope) throws {
        try scope.verify()
        guard scope.denial(item) == nil, let id = item.bundleIdentifier else { throw SweepError.denied("系统对象规则未确认") }
        if item.rule == cacheName {
            let domain = try verifyDomain(scope,identifier:id)
            guard try members(scope,identifier:id).contains(item.path), domain.tree.contains(where: { domain.path + "/" + $0.relative == item.path }) else { throw SweepError.denied("系统缓存不是完整域中的直接成员") }
        } else if item.rule == currentLogName {
            try verifyCurrentLog(item.path,scope:scope,identifier:id)
        } else {
            let domain = try verifyLogDomain(scope,identifier:id)
            let snapshot = try SafeFilesystem.snapshot(item.path)
            guard snapshot.identity.owner == scope.ownerUID, snapshot.identity.mode & 0o170000 == 0o100000,
                  Attribution.oldLog(modified:Date(timeIntervalSince1970:Double(snapshot.identity.modifiedSeconds)),now:Date()) else { throw SweepError.denied("系统日志归属或年龄已改变") }
            try SafeFilesystem.verify(snapshot)
            try SafeFilesystem.verify(domain)
        }
    }
}

actor SystemCleanupEngine {
    // Must finish before the coordinator's admission budget, including transfer.
    static let maximumDiscoveryDuration:TimeInterval = 40
    private let engine: SweepEngine
    init(scope: SystemCleanupScope, failurePoint: FailurePoint? = nil) throws {
        try scope.verify()
        engine = SweepEngine(systemScope:scope,failurePoint:failurePoint)
    }
    func scan(_ category: SystemCleanupCategory) async throws -> ScanReport { try await engine.scanSystem(category) }
    func makePlan(reportID: UUID, selected: Set<UUID>) async throws -> CleanupPlan { try await engine.makeSystemPlan(reportID:reportID,selected:selected) }
    func execute(planID: UUID) async throws -> RecoveryManifest { try await engine.execute(planID:planID) }
    func restore(batchID: UUID) async throws -> RecoveryManifest { try await engine.restore(batchID:batchID) }
    func purge(batchID: UUID, confirmation: String) async throws -> RecoveryManifest { try await engine.purge(batchID:batchID,confirmation:confirmation) }
    func recoveryPage(after cursor: UUID?) async throws -> RecoveryBatchPage { try await engine.recoveryPage(after:cursor) }
    func recoveryBatch(id: UUID) async throws -> RecoveryManifest { try await engine.recoveryBatch(id:id) }
    func recoveryBatches() async throws -> [RecoveryManifest] { try await engine.recoveryBatches() }
}
