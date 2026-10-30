#if os(macOS)
import Foundation
import CryptoKit
import Darwin
import Security
import CFSafety

protocol ServiceDeploymentLifecycle: Sendable {
    func stop() async throws
    func start() async throws
}
enum ServiceDeploymentFailurePoint: Sendable { case interruptAfterBatchCreation, interruptAfterStagingProgram, interruptAfterProgramPublication, interruptAfterProgramRemoval }
public struct ServiceDeploymentResult: Codable, Sendable {
    public enum Status: String, Codable, Sendable { case installed, removed, rolledBack, needsAttention }
    public let status: Status
    public let journalPath: String
    public let issue: String?
}

/// Called by the separately authenticated Installer executable. No normal user
/// cleanup command, socket request or GUI-provided plan gains this authority.
public enum SystemServiceInstallation {
    public static func install(packageRoot: String) async throws -> ServiceDeploymentResult {
        let payload = try ServiceDeploymentPayload.loadRootPackage(packageRoot)
        return try await ServiceDeployment.production().install(payload,lifecycle:LaunchdServiceLifecycle())
    }
    public static func remove() async throws -> ServiceDeploymentResult {
        try await ServiceDeployment.production().remove(lifecycle:LaunchdServiceLifecycle())
    }
    public static func restoreRemoval(_ id: UUID) async throws -> ServiceDeploymentResult {
        try await ServiceDeployment.production().restoreRemoval(id,lifecycle:LaunchdServiceLifecycle())
    }
    public static func recover() async throws -> ServiceDeploymentResult {
        try await ServiceDeployment.production().recover(lifecycle:LaunchdServiceLifecycle())
    }
}

/// Installation is not an action on the cleanup socket. The package entry point
/// must already be root; the only non-root constructor is a bounded DEBUG fixture.
struct ServiceDeploymentPayload: Sendable {
    fileprivate let program: Data
    fileprivate let configuration: Data
    fileprivate let declaration: Data
    fileprivate let fixture: Bool
    private init(program: Data, configuration: Data, declaration: Data, fixture: Bool) throws {
        guard !program.isEmpty, program.count <= 16 * 1024 * 1024 else { throw SweepError.denied("组件程序为空或超过安装容量") }
        _ = try RootServicePins.decode(configuration)
        try ServiceDeclaration.validate(declaration)
        self.program = program; self.configuration = configuration; self.declaration = declaration; self.fixture = fixture
    }
    static func loadRootPackage(_ path: String) throws -> Self {
        guard getuid() == 0, geteuid() == 0 else { throw SweepError.denied("系统组件只能从已认证的管理员安装流程读取") }
        // The package script directory must not be replaceable by a normal user.
        for ancestor in try SafeFilesystem.ancestors(of:path) {
            let directory = try SafeDirectory(path:ancestor.path)
            let stickyTemporary = ["/private/tmp","/private/var/tmp"].contains(ancestor.path) && ancestor.mode & 0o1000 != 0
            guard ancestor.owner == 0, as_no_grant_acl_descriptor(directory.fd) == 1,
                  stickyTemporary || as_unshared_node_descriptor(directory.fd,0) == 1 else { throw SweepError.denied("安装来源祖先可被其他用户改写") }
        }
        let contentsSeal = try verifyContentsDirectories(path,owner:0)
        let base = path + "/Library/Application Support/App Sweep/Service"
        let paths = [base + "/AppSweepSystemService",base + "/config.json",path + "/Library/LaunchDaemons/org.appsweep.system-service.plist"]
        let snapshots = try paths.map { try SafeFilesystem.snapshot($0) }
        for snapshot in snapshots { try ServiceDeploymentFile.verifyUnshared(snapshot,owner:0) }
        let bytes = try paths.map { try SafeFilesystem.readMetadata($0,maximumBytes:16 * 1024 * 1024) }
        let pins = try RootServicePins.decode(bytes[1])
        try verifyProgram(paths[0],pins:pins)
        for snapshot in snapshots { try SafeFilesystem.verify(snapshot) }
        guard try verifyContentsDirectories(path,owner:0) == contentsSeal else { throw SweepError.stale("安装包内部目录在读取期间改变") }
        return try Self(program:bytes[0],configuration:bytes[1],declaration:bytes[2],fixture:false)
    }
    /// Read-only helper shared with native owner/ACL fixtures. Production always
    /// calls it with owner zero, after validating the package root's ancestors.
    static func verifyContentsDirectories(_ path: String, owner: UInt32) throws -> [AncestorIdentity] {
        let root = try SafeDirectory(path:path), device = try root.ownIdentity.device
        let parents = [path,path + "/Library",path + "/Library/Application Support",path + "/Library/Application Support/App Sweep",path + "/Library/Application Support/App Sweep/Service",path + "/Library/LaunchDaemons"]
        var seal: [AncestorIdentity] = []
        for parent in parents {
            let directory = try SafeDirectory(path:parent), identity = try directory.ownIdentity
            guard identity.device == device, as_unshared_node_descriptor(directory.fd,owner) == 1 else { throw SweepError.denied("安装包内部目录所有者、ACL、卷或权限不安全") }
            seal.append(AncestorIdentity(path:parent,device:identity.device,inode:identity.inode,mode:identity.mode,owner:identity.owner))
        }
        return seal
    }
    fileprivate static func verifyProgram(_ path: String, pins: RootServicePins) throws {
        var code: SecStaticCode?, requirement: SecRequirement?, info: CFDictionary?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath:path) as CFURL,[],&code) == errSecSuccess, let code,
              SecRequirementCreateWithString(try pins.requirement(for:.service) as CFString,[],&requirement) == errSecSuccess, let requirement,
              SecStaticCodeCheckValidity(code,SecCSFlags(rawValue:kSecCSStrictValidate | kSecCSCheckAllArchitectures),requirement) == errSecSuccess,
              SecCodeCopySigningInformation(code,SecCSFlags(rawValue:kSecCSSigningInformation),&info) == errSecSuccess,
              let dictionary = info as? [String:Any], let flags = dictionary[kSecCodeInfoFlags as String] as? NSNumber,
              flags.uint32Value & SecCodeSignatureFlags.runtime.rawValue != 0 else { throw SweepError.denied("组件代码摘要、签名或运行时保护未确认") }
        let entitlements: [String:Any]
        if let raw = dictionary[kSecCodeInfoEntitlementsDict as String] {
            guard let value = raw as? [String:Any] else { throw SweepError.denied("组件签名权限格式无效") }
            entitlements = value
        } else { entitlements = [:] }
        for key in ["com.apple.security.get-task-allow","get-task-allow","com.apple.security.cs.disable-library-validation","com.apple.security.cs.allow-dyld-environment-variables","com.apple.security.cs.allow-unsigned-executable-memory","com.apple.security.cs.disable-executable-page-protection","com.apple.security.cs.allow-jit"] {
            if let value = entitlements[key] { guard let flag = value as? Bool, !flag else { throw SweepError.denied("组件包含不允许的运行时例外") } }
        }
    }
    #if DEBUG
    static func fixture(program: Data, configuration: Data) throws -> Self {
        guard getuid() != 0, getuid() == geteuid() else { throw SweepError.denied("安装夹具只能由普通测试用户创建") }
        return try Self(program:program,configuration:configuration,declaration:ServiceDeclaration.data(),fixture:true)
    }
    #endif
}

// On-demand UI requests have bounded occupancy checks. A Background job can
// throttle their APFS metadata reads past that bound during concurrent scanning.
// Standard scheduling retains normal resource limits without background clamps.
private enum ServiceDeclaration {
    static var dictionary: [String:Any] { [
        "Label":"org.appsweep.system-service",
        "ProgramArguments":["/Library/Application Support/App Sweep/Service/AppSweepSystemService"],
        "UserName":"root", "GroupName":"wheel", "ProcessType":"Standard", "ThrottleInterval":5,
        "Sockets":["Control":["SockPathName":"/Library/Application Support/App Sweep/Service/control.sock","SockPathOwner":0,"SockPathGroup":0,"SockPathMode":438,"SockType":"stream","SockPassive":true]]
    ] }
    static func data() throws -> Data { try PropertyListSerialization.data(fromPropertyList:dictionary,format:.xml,options:0) }
    static func validate(_ data: Data, allowLegacy: Bool = false) throws {
        guard !data.isEmpty, data.count <= 64 * 1024,
              let value = try PropertyListSerialization.propertyList(from:data,options:[],format:nil) as? [String:Any] else { throw SweepError.denied("系统组件启动声明与固定程序不一致") }
        // Only installed legacy declarations may retain the old scheduler.
        // Paths, socket ownership and every other field remain exact matches.
        var legacy = dictionary; legacy["ProcessType"] = "Background"
        guard NSDictionary(dictionary:value).isEqual(to:dictionary) ||
              (allowLegacy && NSDictionary(dictionary:value).isEqual(to:legacy)) else { throw SweepError.denied("系统组件启动声明与固定程序不一致") }
    }
}

private struct ServiceDeploymentFile: Codable, Sendable {
    let identity: FileIdentity
    let digest: String
    static func read(_ path: String, owner: UInt32) throws -> Self {
        let snapshot = try SafeFilesystem.snapshot(path)
        try verifyUnshared(snapshot,owner:owner)
        let data = try SafeFilesystem.readMetadata(path,maximumBytes:16 * 1024 * 1024)
        try SafeFilesystem.verify(snapshot)
        return Self(identity:snapshot.identity,digest:hash(data))
    }
    static func hash(_ data: Data) -> String { SHA256.hash(data:data).map { String(format:"%02x",$0) }.joined() }
    static func verifyUnshared(_ snapshot: FileSnapshot,owner: UInt32) throws {
        guard snapshot.tree.isEmpty, snapshot.identity.owner == owner, snapshot.identity.links == 1,
              snapshot.identity.mode & 0o170000 == 0o100000, snapshot.identity.size > 0, snapshot.identity.size <= 16 * 1024 * 1024 else { throw SweepError.denied("组件必须是当前安装者拥有的有界普通文件") }
        let url = URL(fileURLWithPath:snapshot.path), parent = try SafeDirectory(path:url.deletingLastPathComponent().path)
        let fd = openat(parent.fd,url.lastPathComponent,O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw SweepError.denied("组件文件不能安全打开") }
        defer { as_close(fd) }
        var current = ASIdentity()
        guard as_identity_fd(fd,&current) == 0, FileIdentity(current) == snapshot.identity,
              as_unshared_node_descriptor(fd,owner) == 1 else { throw SweepError.denied("组件身份、ACL或改写权限不安全") }
    }
    func matches(_ path: String, owner: UInt32) throws -> Bool {
        let value = try Self.read(path,owner:owner)
        return value.identity.sameObject(as:identity) && value.digest == digest
    }
}

actor ServiceDeployment {
    private enum Role: String, Codable, Sendable, CaseIterable { case program, configuration, declaration }
    private struct Item: Codable, Sendable {
        let role: Role
        let old: ServiceDeploymentFile?
        var next: ServiceDeploymentFile?
        var oldName: String { "previous-" + role.rawValue }
        var nextName: String { "next-" + role.rawValue }
        var retiredName: String { "reverted-" + role.rawValue }
    }
    private struct Journal: Codable, Sendable {
        enum State: String, Codable { case preparing, stopping, replacing, starting, installed, removing, removed, rollingBack, rolledBack, needsAttention }
        let schemaVersion: Int
        let id: UUID
        let owner: UInt32
        let createdAt: Date
        let seal: [AncestorIdentity]
        var state: State
        var items: [Item]
        var issue: String?
        // Missing in schema-1 installation journals written before removal existed.
        var operation: Operation? = nil
        enum Operation: String, Codable { case removal }
    }
    private struct Scope: Sendable {
        let library: String
        let fixture: Bool
        let owner: UInt32
        let ancestors: [AncestorIdentity]
        func verify() throws {
            guard as_current_uid() == owner, fixture || (getuid() == 0 && geteuid() == 0),
                  try SafeFilesystem.ancestors(of:library) == ancestors else { throw SweepError.stale("安装范围或安装者身份已改变") }
            for ancestor in ancestors {
                let directory = try SafeDirectory(path:ancestor.path)
                guard as_unshared_node_descriptor(directory.fd,ancestor.owner) == 1 else { throw SweepError.denied("安装范围祖先存在未确认的ACL或改写权限") }
            }
        }
    }
    private struct Layout {
        let service: SafeDirectory
        let launch: SafeDirectory
        let vault: SafeDirectory
        let recovery: SafeDirectory
        let seal: [AncestorIdentity]
        func path(_ role: Role) -> String {
            switch role {
            case .program: return service.path + "/AppSweepSystemService"
            case .configuration: return service.path + "/config.json"
            case .declaration: return launch.path + "/org.appsweep.system-service.plist"
            }
        }
        func parent(_ role: Role) -> SafeDirectory { role == .declaration ? launch : service }
        func verify() throws {
            let current = try [service.path,launch.path,vault.path,recovery.path].flatMap { try SafeFilesystem.ancestors(of:$0) }
            guard current == seal else { throw SweepError.stale("组件目录或恢复目录已被替换") }
            // ACL grants can change without changing POSIX mode or inode.
            // Recheck every ancestor, not only the fixed leaf directories.
            var checked: Set<String> = []
            for ancestor in seal where checked.insert(ancestor.path).inserted {
                let directory = try SafeDirectory(path:ancestor.path)
                guard as_unshared_node_descriptor(directory.fd,ancestor.owner) == 1 else { throw SweepError.stale("组件祖先的ACL或改写权限已改变") }
            }
            guard as_private_descriptor(vault.fd) == 1, as_private_descriptor(recovery.fd) == 1 else { throw SweepError.stale("组件或数据恢复目录不再私有") }
        }
        func locks() throws -> [Int32] {
            var descriptors: [Int32] = []
            do {
                for path in [vault.path,recovery.path] {
                    let fd = as_open_directory(path)
                    guard fd >= 0 else { throw SweepError.denied("安装锁目录未确认") }
                    descriptors.append(fd)
                    guard as_lock(fd) == 0 else { throw SweepError.denied("另一安装或系统清理操作正在使用组件") }
                }
                return descriptors
            } catch { descriptors.forEach { as_close($0) }; throw error }
        }
    }
    private let scope: Scope
    private let failurePoint: ServiceDeploymentFailurePoint?
    private var inFlight = false
    private init(scope: Scope, failurePoint: ServiceDeploymentFailurePoint? = nil) { self.scope = scope; self.failurePoint = failurePoint }
    static func production() throws -> ServiceDeployment {
        guard getuid() == 0, geteuid() == 0 else { throw SweepError.denied("组件部署要求独立的管理员安装认证") }
        let root = "/Library"
        return Self(scope:Scope(library:root,fixture:false,owner:0,ancestors:try SafeFilesystem.ancestors(of:root)))
    }
    #if DEBUG
    static func fixture(libraryRoot: String, failurePoint: ServiceDeploymentFailurePoint? = nil) throws -> ServiceDeployment {
        let home = try SystemIdentity.home(), suffix = "/MachineLibrary"
        guard getuid() != 0, geteuid() == getuid(), libraryRoot.hasPrefix(home + "/AppSweepAcceptance"), libraryRoot.hasSuffix(suffix), libraryRoot == URL(fileURLWithPath:libraryRoot).standardizedFileURL.path, !libraryRoot.contains("//"),
              try SafeDirectory(path:libraryRoot).ownIdentity.owner == getuid() else { throw SweepError.denied("安装夹具必须位于现有测试任务的私有目录") }
        return Self(scope:Scope(library:libraryRoot,fixture:true,owner:getuid(),ancestors:try SafeFilesystem.ancestors(of:libraryRoot)),failurePoint:failurePoint)
    }
    #endif
    private func publicChild(_ parent: SafeDirectory, _ name: String) throws -> SafeDirectory {
        if mkdirat(parent.fd,name,0o755) != 0 && errno != EEXIST { throw SweepError.filesystem("不能创建固定组件目录") }
        let child = try SafeDirectory(path:parent.path + "/" + name)
        let identity = try child.ownIdentity
        guard identity.owner == scope.owner, as_unshared_node_descriptor(child.fd,scope.owner) == 1,
              scope.fixture || identity.mode & 0o7777 == 0o755 else { throw SweepError.denied("组件目录所有者、ACL或权限不安全") }
        return child
    }
    private func layout() throws -> Layout {
        try scope.verify()
        let library = try SafeDirectory(path:scope.library)
        let support = try publicChild(try publicChild(library,"Application Support"),"App Sweep")
        let service = try publicChild(support,"Service"), launch = try publicChild(library,"LaunchDaemons")
        let vault = try support.privateChild("Installation.noindex"), recovery = try support.privateChild("Recovery.noindex")
        let seal = try [service.path,launch.path,vault.path,recovery.path].flatMap { try SafeFilesystem.ancestors(of:$0) }
        guard try [service,launch,vault,recovery].allSatisfy({ try $0.ownIdentity.device == library.ownIdentity.device }) else { throw SweepError.denied("组件与恢复目录必须在同一卷") }
        let layout = Layout(service:service,launch:launch,vault:vault,recovery:recovery,seal:seal)
        try layout.verify()
        return layout
    }
    private func persist(_ journal: Journal, batch: SafeDirectory) throws {
        // A retained descriptor is not permission to write into a directory
        // that has since been detached or replaced at its recorded path.
        let current = try SafeDirectory(path:batch.path), expected = try batch.ownIdentity, actual = try current.ownIdentity
        guard expected.device == actual.device, expected.inode == actual.inode,
              expected.owner == actual.owner, expected.mode == actual.mode,
              as_private_descriptor(current.fd) == 1 else { throw SweepError.stale("安装日志目录已被替换") }
        for ancestor in journal.seal where batch.path.hasPrefix(ancestor.path + "/") {
            let identity = try SafeDirectory(path:ancestor.path).ownIdentity
            let current=AncestorIdentity(path:ancestor.path,device:identity.device,inode:identity.inode,mode:identity.mode,owner:identity.owner,volumeUUID:identity.volumeUUID)
            guard current == ancestor else { throw SweepError.stale("安装日志祖先已被替换") }
        }
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601; encoder.outputFormatting = [.sortedKeys,.withoutEscapingSlashes]
        try batch.write(encoder.encode(journal),name:"installation.json")
    }
    private func load(_ id: UUID, layout: Layout, forHistory:Bool=false) throws -> Journal {
        let batch = try layout.vault.existingPrivateChild(id.uuidString)
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        let journal = try decoder.decode(Journal.self,from:batch.read("installation.json"))
        // Completed pre-volume-UUID records are immutable history, never move
        // authority. A fresh install reads the live component set independently.
        // Pending recovery and explicit removal restoration keep the strict seal.
        let completedLegacyHistory=forHistory && [.installed,.removed,.rolledBack].contains(journal.state) &&
            journal.seal.count == layout.seal.count && zip(journal.seal,layout.seal).allSatisfy { old,current in
                old.volumeUUID == nil && old.path == current.path && old.inode == current.inode && old.owner == current.owner && old.mode == current.mode
            }
        guard journal.schemaVersion == 1, journal.id == id, journal.owner == scope.owner, (journal.seal == layout.seal || completedLegacyHistory),
              journal.items.map(\.role) == Role.allCases else { throw SweepError.denied("组件安装记录的范围、版本或角色无效") }
        if journal.operation == .removal {
            guard journal.items.allSatisfy({ $0.old != nil && $0.next == nil }),
                  [.preparing,.stopping,.removing,.removed,.rollingBack,.rolledBack,.needsAttention].contains(journal.state) else { throw SweepError.denied("组件移除记录的角色或状态不完整") }
        } else if journal.items.contains(where: { $0.next == nil }) {
            guard [.preparing,.rollingBack,.rolledBack,.needsAttention].contains(journal.state) else { throw SweepError.denied("未完成暂存的记录不能授权发布组件") }
        }
        for item in journal.items {
            for file in [item.old,item.next].compactMap({ $0 }) {
                guard file.identity.owner == scope.owner, file.identity.links == 1, file.identity.mode & 0o170000 == 0o100000,
                      file.identity.size > 0, file.identity.size <= 16 * 1024 * 1024, file.digest.utf8.count == 64,
                      file.digest.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw SweepError.denied("组件安装记录含有无效身份") }
            }
        }
        return journal
    }
    private func journals(_ layout: Layout) throws -> [Journal] {
        let names = try FileManager.default.contentsOfDirectory(atPath:layout.vault.path)
        guard names.count <= 64 else { throw SweepError.denied("组件安装记录过多，请先核对旧版本") }
        return try names.map { name in
            guard let id = UUID(uuidString:name), id.uuidString == name else { throw SweepError.denied("安装恢复区存在未登记对象") }
            return try load(id,layout:layout,forHistory:true)
        }.sorted { $0.createdAt > $1.createdAt }
    }
    private func stage(_ data: Data, name: String, mode: mode_t, batch: SafeDirectory) throws -> ServiceDeploymentFile {
        try batch.write(data,name:name)
        let identity = try batch.identity(name), fd = openat(batch.fd,name,O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw SweepError.denied("不能打开新组件暂存文件") }
        defer { as_close(fd) }
        var actual = ASIdentity()
        guard as_identity_fd(fd,&actual) == 0, FileIdentity(actual) == identity, as_private_descriptor(fd) == 1,
              fchmod(fd,mode) == 0, fsync(fd) == 0, fsync(batch.fd) == 0 else { throw SweepError.filesystem("组件暂存权限或持久化失败") }
        return try ServiceDeploymentFile.read(batch.path + "/" + name,owner:scope.owner)
    }
    func install(_ payload: ServiceDeploymentPayload, lifecycle: any ServiceDeploymentLifecycle) async throws -> ServiceDeploymentResult {
        guard !inFlight, scope.fixture == payload.fixture else { throw SweepError.denied("安装正在进行或来源与权限范围不一致") }
        inFlight = true; defer { inFlight = false }
        let layout = try layout(), descriptors = try layout.locks()
        defer { descriptors.forEach { as_close($0) } }
        guard try journals(layout).allSatisfy({ [.installed,.removed,.rolledBack].contains($0.state) }) else { throw SweepError.denied("请先恢复上次未完成的组件安装") }
        var previous: [Role:ServiceDeploymentFile] = [:]
        for role in Role.allCases where try SafeFilesystem.presence(layout.path(role)) { previous[role] = try ServiceDeploymentFile.read(layout.path(role),owner:scope.owner) }
        guard previous.isEmpty || previous.count == Role.allCases.count else { throw SweepError.denied("现有组件不完整，不能猜测覆盖") }
        if !previous.isEmpty {
            let pins = try RootServicePins.decode(SafeFilesystem.readMetadata(layout.path(.configuration),maximumBytes:64 * 1024))
            try ServiceDeclaration.validate(SafeFilesystem.readMetadata(layout.path(.declaration),maximumBytes:64 * 1024),allowLegacy:true)
            if !scope.fixture { try ServiceDeploymentPayload.verifyProgram(layout.path(.program),pins:pins) }
        }
        guard layout.vault.availableBytes > 512 * 1024 * 1024 + UInt64(payload.program.count) else { throw SweepError.denied("空间不足，不能保留组件回退副本") }
        let id = UUID(), batch = try layout.vault.privateChild(id.uuidString)
        if failurePoint == .interruptAfterBatchCreation { throw SweepError.filesystem("注入的创建安装批次中断") }
        var journal = Journal(schemaVersion:1,id:id,owner:scope.owner,createdAt:Date(),seal:layout.seal,state:.preparing,
                              items:Role.allCases.map { Item(role:$0,old:previous[$0],next:nil) },issue:nil)
        // Persist before the first staged component, so interruption cannot
        // strand an unrecorded half-package that blocks all later upgrades.
        try persist(journal,batch:batch)
        let inputs: [Data] = [payload.program,payload.configuration,payload.declaration]
        for (index,role) in Role.allCases.enumerated() {
            journal.items[index].next = try stage(inputs[index],name:"next-" + role.rawValue,mode:role == .program ? 0o755 : 0o644,batch:batch)
            try persist(journal,batch:batch)
            if role == .program && failurePoint == .interruptAfterStagingProgram { throw SweepError.filesystem("注入的组件暂存中断") }
        }
        if !scope.fixture {
            try ServiceDeploymentPayload.verifyProgram(batch.path + "/next-program",pins:RootServicePins.decode(payload.configuration))
            guard let staged = journal.items.first?.next, try staged.matches(batch.path + "/next-program",owner:scope.owner) else { throw SweepError.stale("实际暂存组件与验签对象不一致") }
        }
        do {
            journal.state = .stopping; try persist(journal,batch:batch)
            if !previous.isEmpty { try await lifecycle.stop() }
            try layout.verify()
            for item in journal.items {
                try scope.verify(); try layout.verify()
                journal.state = .replacing; try persist(journal,batch:batch)
                if let old = item.old {
                    guard try old.matches(layout.path(item.role),owner:scope.owner) else { throw SweepError.stale("旧组件在替换前改变") }
                    try SafeFilesystem.move(SafeFilesystem.snapshot(layout.path(item.role)),into:batch,name:item.oldName)
                }
                guard let next = item.next, try next.matches(batch.path + "/" + item.nextName,owner:scope.owner) else { throw SweepError.stale("新组件暂存对象已改变") }
                try SafeFilesystem.move(SafeFilesystem.snapshot(batch.path + "/" + item.nextName),into:layout.parent(item.role),name:URL(fileURLWithPath:layout.path(item.role)).lastPathComponent,targetAncestors:try SafeFilesystem.ancestors(of:layout.parent(item.role).path))
                if item.role == .program && failurePoint == .interruptAfterProgramPublication { throw DeploymentInterruption.injected }
            }
            journal.state = .starting; try persist(journal,batch:batch)
            try await lifecycle.start()
            try layout.verify()
            for item in journal.items {
                guard let next = item.next, try next.matches(layout.path(item.role),owner:scope.owner) else { throw SweepError.stale("组件在启动检查期间改变") }
            }
            journal.state = .installed; try persist(journal,batch:batch)
            return result(journal,batch:batch)
        } catch DeploymentInterruption.injected { throw SweepError.filesystem("注入的安装中断；记录保留，必须显式恢复") }
        catch {
            journal.issue = error.localizedDescription
            // A startup can partially succeed before reporting failure. Never
            // replace files underneath a possibly running new service.
            do { try await lifecycle.stop() }
            catch {
                journal.state = .needsAttention; journal.issue = (journal.issue ?? "") + "；不能确认组件已停止：" + error.localizedDescription
                try persist(journal,batch:batch); return result(journal,batch:batch)
            }
            return try await rollback(journal,batch:batch,layout:layout,lifecycle:lifecycle)
        }
    }
    /// Remove only this service's fixed, complete verified component set. All
    /// bytes remain in the installation vault; user recovery data is untouched.
    func remove(lifecycle: any ServiceDeploymentLifecycle) async throws -> ServiceDeploymentResult {
        guard !inFlight else { throw SweepError.denied("另一组件操作正在进行") }
        inFlight = true; defer { inFlight = false }
        let layout = try layout(), descriptors = try layout.locks()
        defer { descriptors.forEach { as_close($0) } }
        guard try journals(layout).allSatisfy({ [.installed,.removed,.rolledBack].contains($0.state) }) else { throw SweepError.denied("请先恢复上次未完成的组件操作") }
        var previous: [ServiceDeploymentFile] = []
        for role in Role.allCases { previous.append(try ServiceDeploymentFile.read(layout.path(role),owner:scope.owner)) }
        let pins = try RootServicePins.decode(SafeFilesystem.readMetadata(layout.path(.configuration),maximumBytes:64 * 1024))
        try ServiceDeclaration.validate(SafeFilesystem.readMetadata(layout.path(.declaration),maximumBytes:64 * 1024),allowLegacy:true)
        if !scope.fixture { try ServiceDeploymentPayload.verifyProgram(layout.path(.program),pins:pins) }
        let id = UUID(), batch = try layout.vault.privateChild(id.uuidString)
        var journal = Journal(schemaVersion:1,id:id,owner:scope.owner,createdAt:Date(),seal:layout.seal,state:.preparing,
                              items:zip(Role.allCases,previous).map { Item(role:$0.0,old:$0.1,next:nil) },issue:nil,operation:.removal)
        try persist(journal,batch:batch)
        var stopped = false
        do {
            journal.state = .stopping; try persist(journal,batch:batch)
            try await lifecycle.stop(); stopped = true
            try scope.verify(); try layout.verify()
            // Check the complete removal set after stopping and before any move.
            for item in journal.items {
                guard let old = item.old, try old.matches(layout.path(item.role),owner:scope.owner) else { throw SweepError.stale("组件在停止期间改变") }
            }
            for item in journal.items {
                try scope.verify(); try layout.verify()
                journal.state = .removing; try persist(journal,batch:batch)
                guard let old = item.old, try old.matches(layout.path(item.role),owner:scope.owner) else { throw SweepError.stale("组件在移除前改变") }
                try SafeFilesystem.move(SafeFilesystem.snapshot(layout.path(item.role)),into:batch,name:item.oldName)
                if item.role == .program && failurePoint == .interruptAfterProgramRemoval { throw DeploymentInterruption.injected }
            }
            try scope.verify(); try layout.verify()
            for item in journal.items {
                guard try !SafeFilesystem.presence(layout.path(item.role)), let old = item.old,
                      try old.matches(batch.path + "/" + item.oldName,owner:scope.owner) else { throw SweepError.stale("不能确认组件已进入恢复区") }
            }
            journal.state = .removed; try persist(journal,batch:batch)
            return result(journal,batch:batch)
        } catch DeploymentInterruption.injected { throw SweepError.filesystem("注入的移除中断；必须显式恢复") }
        catch {
            journal.issue = error.localizedDescription
            guard stopped else {
                journal.state = .needsAttention; try persist(journal,batch:batch)
                return result(journal,batch:batch)
            }
            return try await rollback(journal,batch:batch,layout:layout,lifecycle:lifecycle)
        }
    }
    func restoreRemoval(_ id: UUID,lifecycle: any ServiceDeploymentLifecycle) async throws -> ServiceDeploymentResult {
        guard !inFlight else { throw SweepError.denied("另一组件操作正在进行") }
        inFlight = true; defer { inFlight = false }
        let layout = try layout(), descriptors = try layout.locks()
        defer { descriptors.forEach { as_close($0) } }
        guard try journals(layout).allSatisfy({ [.installed,.removed,.rolledBack].contains($0.state) }) else { throw SweepError.denied("请先恢复未完成的组件操作") }
        let journal = try load(id,layout:layout)
        guard journal.operation == .removal, journal.state == .removed else { throw SweepError.denied("指定批次不是可撤销的组件移除") }
        let batch = try layout.vault.existingPrivateChild(id.uuidString)
        // A later install or unknown target must not be stopped or overwritten.
        for item in journal.items {
            guard try !SafeFilesystem.presence(layout.path(item.role)), let old = item.old,
                  try old.matches(batch.path + "/" + item.oldName,owner:scope.owner) else { throw SweepError.denied("组件恢复遇到新安装、冲突或缺失副本；保留现状") }
        }
        try await lifecycle.stop()
        return try await rollback(journal,batch:batch,layout:layout,lifecycle:lifecycle)
    }
    func recover(lifecycle: any ServiceDeploymentLifecycle) async throws -> ServiceDeploymentResult {
        guard !inFlight else { throw SweepError.denied("另一组件安装正在进行") }
        inFlight = true; defer { inFlight = false }
        let layout = try layout(), descriptors = try layout.locks()
        defer { descriptors.forEach { as_close($0) } }
        if let unrecorded = try recoverUnrecordedBatch(layout) { return unrecorded }
        let pending = try journals(layout).filter { ![.installed,.removed,.rolledBack].contains($0.state) }
        guard pending.count == 1, let journal = pending.first else { throw SweepError.denied("没有唯一可恢复的组件安装记录") }
        let batch = try layout.vault.existingPrivateChild(journal.id.uuidString)
        try await lifecycle.stop()
        return try await rollback(journal,batch:batch,layout:layout,lifecycle:lifecycle)
    }
    private func recoverUnrecordedBatch(_ layout: Layout) throws -> ServiceDeploymentResult? {
        let names = try FileManager.default.contentsOfDirectory(atPath:layout.vault.path)
        guard names.count <= 64 else { throw SweepError.denied("组件安装记录过多") }
        var orphan: (UUID,SafeDirectory)?
        for name in names {
            guard let id = UUID(uuidString:name), id.uuidString == name else { throw SweepError.denied("安装恢复区存在未登记名称") }
            let batch = try layout.vault.existingPrivateChild(name)
            if try SafeFilesystem.presence(batch.path + "/installation.json") {
                let journal = try load(id,layout:layout,forHistory:true)
                guard [.installed,.removed,.rolledBack].contains(journal.state) else { return nil }
                continue
            }
            guard orphan == nil else { throw SweepError.denied("多个未登记安装目录需要人工核对") }
            let contents = try FileManager.default.contentsOfDirectory(atPath:batch.path)
            guard contents.count <= 4 else { throw SweepError.denied("未登记安装目录包含未知内容") }
            // Before the first atomic journal commit only a bounded private
            // partial journal may exist. Preserve it; it grants no move rights.
            for entry in contents {
                guard entry.range(of:#"^\.journal-[0-9]{1,12}-[0-9]{1,20}$"#,options:.regularExpression) != nil else { throw SweepError.denied("未登记安装目录包含未知对象") }
                let identity = try batch.identity(entry)
                let fd = openat(batch.fd,entry,O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
                guard fd >= 0 else { throw SweepError.denied("不能核对未完成日志") }
                defer { as_close(fd) }
                guard as_private_descriptor(fd) == 1, identity.owner == scope.owner, identity.links == 1,
                      identity.mode & 0o170000 == 0o100000, identity.size >= 0, identity.size <= 16 * 1024 * 1024 else { throw SweepError.denied("未完成日志身份不安全") }
            }
            orphan = (id,batch)
        }
        guard let (id,batch) = orphan else { return nil }
        try scope.verify(); try layout.verify()
        let journal = Journal(schemaVersion:1,id:id,owner:scope.owner,createdAt:Date(),seal:layout.seal,state:.rolledBack,
                              items:Role.allCases.map { Item(role:$0,old:nil,next:nil) },issue:"未登记的暂存目录已记录并保留；没有执行组件移动")
        try persist(journal,batch:batch)
        return result(journal,batch:batch)
    }
    private enum DeploymentInterruption: Error { case injected }
    private func result(_ journal: Journal,batch: SafeDirectory) -> ServiceDeploymentResult {
        .init(status:journal.state == .installed ? .installed : (journal.state == .removed ? .removed : (journal.state == .rolledBack ? .rolledBack : .needsAttention)),journalPath:batch.path + "/installation.json",issue:journal.issue)
    }
    private func rollback(_ initial: Journal,batch: SafeDirectory,layout: Layout,lifecycle: any ServiceDeploymentLifecycle) async throws -> ServiceDeploymentResult {
        var journal = initial
        do {
            // Validate the entire inverse plan before moving any component.
            try scope.verify(); try layout.verify()
            for item in journal.items {
                let target = layout.path(item.role)
                if try SafeFilesystem.presence(target) {
                    guard try (item.next.map { try $0.matches(target,owner:scope.owner) } ?? false) || (item.old.map { try $0.matches(target,owner:scope.owner) } ?? false) else { throw SweepError.stale("组件恢复遇到未知目标，不能覆盖") }
                }
                if let old = item.old {
                    let backup = batch.path + "/" + item.oldName
                    guard try (SafeFilesystem.presence(backup) ? old.matches(backup,owner:scope.owner) : old.matches(target,owner:scope.owner)) else { throw SweepError.stale("上一版本组件缺失或改变") }
                }
            }
            journal.state = .rollingBack; try persist(journal,batch:batch)
            for item in journal.items.reversed() {
                try scope.verify(); try layout.verify()
                let target = layout.path(item.role)
                if let next = item.next, try SafeFilesystem.presence(target), try next.matches(target,owner:scope.owner) {
                    try SafeFilesystem.move(SafeFilesystem.snapshot(target),into:batch,name:item.retiredName)
                }
                if let old = item.old, try SafeFilesystem.presence(batch.path + "/" + item.oldName) {
                    guard try old.matches(batch.path + "/" + item.oldName,owner:scope.owner) else { throw SweepError.stale("上一版本组件改变") }
                    try SafeFilesystem.move(SafeFilesystem.snapshot(batch.path + "/" + item.oldName),into:layout.parent(item.role),name:URL(fileURLWithPath:target).lastPathComponent,targetAncestors:try SafeFilesystem.ancestors(of:layout.parent(item.role).path))
                }
            }
            if journal.items.allSatisfy({ $0.old != nil }) { try await lifecycle.start() }
            try scope.verify(); try layout.verify()
            for item in journal.items {
                if let old = item.old {
                    guard try old.matches(layout.path(item.role),owner:scope.owner) else { throw SweepError.stale("旧组件在恢复启动期间改变") }
                } else {
                    guard try !SafeFilesystem.presence(layout.path(item.role)) else { throw SweepError.stale("恢复期间出现未知组件目标") }
                }
            }
            journal.state = .rolledBack; try persist(journal,batch:batch)
        } catch {
            journal.state = .needsAttention; journal.issue = (journal.issue.map { $0 + "；" } ?? "") + error.localizedDescription
            try persist(journal,batch:batch)
        }
        return result(journal,batch:batch)
    }
}
#endif
