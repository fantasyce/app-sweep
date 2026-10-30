import Foundation
import CFSafety
#if os(macOS)
import Security
#endif

enum Attribution {
    static func canAuthorize(hints: [OwnershipEvidence]) -> Bool { hints.contains(where: \.authorizes) }
    static func exclusiveContainer(identifier: String, target: String, associated: [String]) -> Bool {
        identifier == target && !associated.isEmpty && Set(associated) == [target]
    }
    static func oldLog(modified: Date, now: Date) -> Bool { modified < now.addingTimeInterval(-30 * 86400) }
}
enum AppInspector {
    private static func installationEntries(_ directory: SafeDirectory, buffer: inout [UInt8]) throws -> ([String], Int) {
        var count=0, visited=0
        guard as_installation_entries(directory.fd,&buffer,buffer.count,&count,&visited) == 0,
              let text=String(bytes:buffer.prefix(count),encoding:.utf8) else { throw SweepError.incomplete("安装目录或包内组件枚举失败、截断，归属未确认") }
        return (text.split(separator:"\0").map(String.init).sorted(),visited)
    }
    static func metadata(_ path: String, component: Bool) throws -> ([String: Any], String) {
        _ = try SafeDirectory(path: path)
        let metadataRoot: String
        if component, try !SafeFilesystem.presence(path + "/Contents") { metadataRoot = path }
        else { metadataRoot = path + "/Contents" }
        let directory = try SafeDirectory(path: metadataRoot), identity = try directory.identity("Info.plist")
        guard !identity.isLink, identity.links == 1, identity.size < 2 * 1024 * 1024 else { throw SweepError.denied("应用元数据无法确认") }
        guard let info = try PropertyListSerialization.propertyList(from: SafeFilesystem.readMetadata(metadataRoot + "/Info.plist"), format: nil) as? [String: Any] else { throw SweepError.invalid("应用元数据无效") }
        return (info, metadataRoot)
    }
    private static func unbuiltTemplate(_ path: String) throws -> String? {
        let (info, root) = try metadata(path, component: true)
        guard info["CFBundlePackageType"] as? String == "APPL", let identifier = info["CFBundleIdentifier"] as? String, (!validIdentifier(identifier) || identifier == "WRAPPEDPRODUCTBUNDLEIDENTIFIER"),
              let executable = info["CFBundleExecutable"] as? String, !executable.isEmpty, executable != ".", executable != "..", !executable.contains("/"), !executable.contains("\0") else { return nil }
        let binary = root + (root == path ? "/" : "/MacOS/") + executable
        // A development template with neither a usable identifier nor its
        // declared executable is not an installed owner. Still inspect its
        // physical contents for actual embedded applications.
        return try SafeFilesystem.presence(binary) ? nil : root
    }
    private static func quotedIdentifierHint(_ path: String) throws -> (ApplicationIdentity, String)? {
        let (info, body) = try metadata(path, component: true)
        guard let raw = info["CFBundleIdentifier"] as? String, raw.hasPrefix("\""), raw.hasSuffix("\""), raw.count > 2 else { return nil }
        let identifier = String(raw.dropFirst().dropLast())
        guard validIdentifier(identifier) else { return nil }
        // A malformed quoted identifier can only add an ownership conflict,
        // never authorize this bundle or its data for cleanup.
        var hint = ApplicationIdentity(path:path,name:URL(fileURLWithPath:path).lastPathComponent,bundleIdentifier:identifier,signed:false,protectedReason:"标识含额外引号，仅作归属冲突线索；保留")
        hint.attributionRawIdentifier = raw
        return (hint, body)
    }
    private static func wrappedApplicationHint(_ path: String, buffer: inout [UInt8]) throws -> (ApplicationIdentity, String)? {
        _ = try SafeDirectory(path: path)
        guard try !SafeFilesystem.presence(path + "/Contents"),
              try !SafeFilesystem.presence(path + "/Info.plist") else { return nil }
        let wrapper = try SafeDirectory(path: path + "/Wrapper")
        let (names, _) = try installationEntries(wrapper, buffer: &buffer)
        let bundles = names.filter { $0.hasSuffix(".app") }
        guard bundles.count == 1, let name = bundles.first else { return nil }
        let identity = try wrapper.identity(name)
        guard identity.isDirectory, !identity.isLink, identity.device == (try wrapper.ownIdentity).device else { return nil }
        let (info, body) = try metadata(wrapper.path + "/" + name, component: true)
        guard body == wrapper.path + "/" + name, info["CFBundlePackageType"] as? String == "APPL",
              let identifier = info["CFBundleIdentifier"] as? String, validIdentifier(identifier) else { return nil }
        // This is a conflict clue only. Neither the wrapper nor an external
        // WrappedBundle alias acquires cleanup authority from this metadata.
        var hint = ApplicationIdentity(path:path,name:URL(fileURLWithPath:path).deletingPathExtension().lastPathComponent,bundleIdentifier:identifier,signed:false,protectedReason:"移动应用包装，仅作归属核对；保留")
        hint.attributionMetadataPath = body
        return (hint, path)
    }
    private static func declaredExecutableAlias(_ path: String, package: String) throws -> ApplicationIdentity? {
        let (info, body) = try metadata(package, component: true)
        guard let identifier = info["CFBundleIdentifier"] as? String, validIdentifier(identifier),
              let executable = info["CFBundleExecutable"] as? String, !executable.isEmpty,
              executable != ".", executable != "..", !executable.contains("/"), !executable.contains("\0"),
              path == body + (body == package ? "/" : "/MacOS/") + executable else { return nil }
        // Do not resolve or read the destination. Keep the dependency as an
        // unresolved owner of this ID, blocking its data but not unrelated IDs.
        var hint = ApplicationIdentity(path:path,name:executable,bundleIdentifier:identifier,signed:false,protectedReason:"声明的可执行文件指向包外，关联资料保留")
        hint.attributionMetadataPath = package
        return hint
    }
    static func inspect(_ path: String, verifySignature: Bool = true, component: Bool = false) throws -> ApplicationIdentity {
        guard path.hasSuffix(".app") || (component && (path.hasSuffix(".xpc") || path.hasSuffix(".appex"))) else { throw SweepError.invalid("请选择应用包") }
        let (info, _) = try metadata(path, component: component)
        guard let identifier = info["CFBundleIdentifier"] as? String, validIdentifier(identifier),
              identifier != "WRAPPEDPRODUCTBUNDLEIDENTIFIER" else { throw SweepError.invalid("应用标识无效") }
        let name = info["CFBundleDisplayName"] as? String ?? info["CFBundleName"] as? String ?? URL(fileURLWithPath: path).deletingPathExtension().lastPathComponent
        let signed = verifySignature && signatureMatches(path: path, identifier: identifier)
        return ApplicationIdentity(path: path, name: name, bundleIdentifier: identifier, signed: signed, protectedReason: protection(identifier: identifier, info: info, path: path))
    }
    static func protection(identifier: String, info: [String: Any], path: String, considerPrivilegedDeclaration: Bool = true, protectAppleIdentity: Bool = true) -> String? {
        if protectAppleIdentity && identifier.lowercased().hasPrefix("com.apple.") { return "Apple 应用始终保留" }
        if identifier == "org.appsweep.app" || identifier == "com.fantasyce.appsweep" || identifier.lowercased().contains("app-sweep") || identifier.lowercased().contains("appsweep") { return "App Sweep 自身始终保留" }
        if (considerPrivilegedDeclaration && info["SMPrivilegedExecutables"] != nil) || FileManager.default.fileExists(atPath: path + "/Contents/Library/SystemExtensions") { return "声明了辅助组件或包含系统扩展，需在卸载明细中核对依赖" }
        return nil
    }
    static func signatureMatches(path: String, identifier: String) -> Bool {
        #if os(macOS)
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode), nil) == errSecSuccess else { return false }
        var raw: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &raw) == errSecSuccess,
              let signing = raw as? [String: Any] else { return false }
        return signing[kSecCodeInfoIdentifier as String] as? String == identifier
        #else
        return false
        #endif
    }
    static func validIdentifier(_ value: String) -> Bool { !value.isEmpty && value.count < 256 && value.unicodeScalars.contains(where: { CharacterSet.alphanumerics.contains($0) }) && value.unicodeScalars.allSatisfy { CharacterSet.alphanumerics.contains($0) || ".-_".unicodeScalars.contains($0) } }
    static func verifiedDataOwner(path: String, identifier: String, home: String) throws -> ApplicationIdentity {
        // A declaration alone is not a live dependency. This checks actual helper
        // locations, structural safety and protected identities without granting
        // a service-removal capability.
        guard !identifier.lowercased().hasPrefix("com.apple.") else { throw SweepError.denied("Apple 应用资料始终受保护") }
        try SelectedApplicationRule.verify(path: path, policy: SafetyPolicy(home: home, acceptedPlatform: false), identifier: identifier)
        let app = try inspect(path)
        guard app.signed, app.bundleIdentifier == identifier else { throw SweepError.denied("应用资料缺少一致的有效签名主体") }
        return app
    }
    /// Only the executor supplies an isolated path from its own journal. The
    /// original install must remain absent and no other installed owner may exist.
    @discardableResult
    static func verifyIsolatedDataOwner(original: String, stored: String, identifier: String, home: String) throws -> [ApplicationIdentity] {
        guard SelectedApplicationRule.matches(path:original,policy:SafetyPolicy(home:home,acceptedPlatform:false)),
              !identifier.lowercased().hasPrefix("com.apple."),
              try !SafeFilesystem.presence(original),signatureMatches(path:stored,identifier:identifier) else {
            throw SweepError.denied("隔离应用的原位置或签名未确认")
        }
        try ChosenApplicationRule.verifyStored(path:stored,identifier:identifier,requireNoInstalledHelpers:true)
        let inventory=try self.inventory(home:home,ownershipIdentifier:identifier)
        let storedIdentity=try SafeDirectory(path:stored).ownIdentity
        let conflicts=inventory.filter { candidate in
            guard candidate.bundleIdentifier.isEmpty || candidate.bundleIdentifier.lowercased() == identifier.lowercased() else{return false}
            // Launch Services can update its URL after our move. That exact
            // recorded object is the isolated owner, not a second installation.
            if candidate.path == stored,let current=try? SafeDirectory(path:candidate.path).ownIdentity,current.sameObject(as:storedIdentity){return false}
            return true
        }
        guard conflicts.isEmpty else {
            throw SweepError.denied("存在其他安装或未确认的应用归属，保留关联资料：" + conflicts.prefix(2).map{$0.path.isEmpty ? $0.bundleIdentifier + "（" + ($0.protectedReason ?? "未确认") + "）" : $0.path}.joined(separator:"；"))
        }
        return inventory.filter{$0.path != stored}
    }
    static func signedByTeam(path: String, team: String) -> Bool {
        #if os(macOS)
        var code: SecStaticCode?; var raw: CFDictionary?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &raw) == errSecSuccess,
              let info = raw as? [String: Any] else { return false }
        return info[kSecCodeInfoTeamIdentifier as String] as? String == team
        #else
        return false
        #endif
    }
    private static func protectedAppleAlias(_ path: String) -> ApplicationIdentity? {
        #if os(macOS)
        guard let destination = try? FileManager.default.destinationOfSymbolicLink(atPath: path), destination.utf8.count <= 4096 else { return nil }
        let target = (destination.hasPrefix("/") ? URL(fileURLWithPath: destination) : URL(fileURLWithPath: path).deletingLastPathComponent().appendingPathComponent(destination)).standardizedFileURL.path
        guard target.hasPrefix("/System/Applications/") || target.hasPrefix("/System/Cryptexes/App/System/Applications/") || target.hasPrefix("/System/Volumes/Preboot/Cryptexes/App/System/Applications/") else { return nil }
        var requirement: SecRequirement?; var code: SecStaticCode?; var raw: CFDictionary?
        guard SecRequirementCreateWithString("anchor apple" as CFString, [], &requirement) == errSecSuccess, let requirement,
              SecStaticCodeCreateWithPath(URL(fileURLWithPath: target) as CFURL, [], &code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSBasicValidateOnly | kSecCSCheckAllArchitectures), requirement) == errSecSuccess,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &raw) == errSecSuccess,
              let info = raw as? [String: Any], let identifier = info[kSecCodeInfoIdentifier as String] as? String,
              identifier.hasPrefix("com.apple."), validIdentifier(identifier) else { return nil }
        // Read-only identification of an OS-owned Apple alias avoids treating Safari
        // as an unknown third-party installation. Mutation still rejects every alias.
        return ApplicationIdentity(path: path, name: URL(fileURLWithPath: path).deletingPathExtension().lastPathComponent, bundleIdentifier: identifier, signed: true, protectedReason: "Apple 系统应用的链接，始终保留")
        #else
        return nil
        #endif
    }
    static func inventory(home: String, selectedApplication: String? = nil, ownershipIdentifier: String? = nil, registryLookup: ApplicationRegistry.Lookup = ApplicationRegistry.systemLocations, indexLookup: ApplicationIndex.Lookup = ApplicationIndex.systemPaths) throws -> [ApplicationIdentity] {
        try inventorySnapshot(home: home, selectedApplication: selectedApplication, ownershipIdentifier: ownershipIdentifier, registryLookup: registryLookup, indexLookup: indexLookup).applications
    }
    private static func applicationNamespaceStorage(_ path: String, home: String) throws -> Bool {
        let url = URL(fileURLWithPath: path)
        guard [home + "/Library/Application Scripts", home + "/Library/HTTPStorages"].contains(url.deletingLastPathComponent().path),
              validIdentifier(url.lastPathComponent) else { return false }
        _ = try SafeDirectory(path: path)
        // Native script and HTTP namespaces are named after identifiers, including ones
        // ending in .app. Spotlight can mistake these data directories for apps.
        // Actual bundle metadata and unknown/link access still require inspection.
        return try !SafeFilesystem.presence(path + "/Contents") && !SafeFilesystem.presence(path + "/Info.plist")
    }
    #if DEBUG
    // Test-only installation scope. Release builds always inspect /Applications.
    static func fixtureMachineApplicationsRoot(home: String) throws -> String? {
        let environment = ProcessInfo.processInfo.environment
        guard let base = environment["APP_SWEEP_FIXTURES"],
              let path = environment["APP_SWEEP_TEST_MACHINE_APPLICATIONS"],
              base != "/", base != (try SystemIdentity.home()),
              SafetyPolicy.contains(base, home), path == base + "/MachineApplications" else { return nil }
        let directory = try SafeDirectory(path: path)
        guard try directory.ownIdentity.owner == as_current_uid() else {
            throw SweepError.denied("Installation test scope is not owned by the test user")
        }
        return path
    }
    #endif
    static func inventorySnapshot(home: String, selectedApplication: String? = nil, ownershipIdentifier: String? = nil, registryLookup: ApplicationRegistry.Lookup = ApplicationRegistry.systemLocations, indexLookup: ApplicationIndex.Lookup = ApplicationIndex.systemPaths, machineOnly: Bool = false, retainedApplication: String? = nil) throws -> ApplicationInventory {
        var result: [ApplicationIdentity] = [], issues: [String] = []
        let deadline = Date().addingTimeInterval(30)
        var visited = 0
        var entryBuffer = [UInt8](repeating:0,count:2*1024*1024)
        var machineApplications = "/Applications"
        #if DEBUG
        machineApplications = try fixtureMachineApplicationsRoot(home: home) ?? machineApplications
        #endif
        var roots: [(String, String?)] = machineOnly ? [(machineApplications, nil)] : [(machineApplications, nil), (home + "/Applications", nil)]
        // This bounded subtree is for retained component hints only. It is not
        // an exclusive-owner inventory and must never authorize data cleanup.
        if let retainedApplication {
            guard !machineOnly, selectedApplication == nil, ownershipIdentifier == nil else { throw SweepError.invalid("保留提示不能兼作完整归属扫描") }
            result = [try inspect(retainedApplication, verifySignature: false)]
            roots = [(try metadata(retainedApplication, component: false).1, retainedApplication)]
        }
        var indexed: [String] = []
        do { indexed = machineOnly || retainedApplication != nil ? [] : try indexLookup(home) }
        catch is CancellationError { throw CancellationError() }
        catch { issues.append("非标准位置的索引发现未确认：" + error.localizedDescription) }
        for path in Set(indexed + (machineOnly ? [] : [selectedApplication].compactMap { $0 })).sorted() {
            try ScanCancellation.check()
            guard !roots.contains(where: { $0.1 == nil && SafetyPolicy.contains($0.0, path) }),
                  SelectedApplicationRule.matches(path: path, policy: SafetyPolicy(home: home, acceptedPlatform: false)) else { continue }
            do {
                guard try SafeFilesystem.presence(path) else { continue }
                if path != selectedApplication, try applicationNamespaceStorage(path, home: home) { continue }
                let app = try inspect(path, verifySignature: false)
                result.append(app)
                roots.append((try metadata(path, component: false).1, path))
            } catch is CancellationError { throw CancellationError() }
            catch {
                if path == selectedApplication { throw error }
                issues.append("索引中的应用位置未确认，已保留：" + path + "；" + error.localizedDescription)
            }
        }
        func walk(_ root: String, _ outerPackage: String?) throws {
            if try !SafeFilesystem.presence(root) { return }
            let device = try SafeDirectory(path: root).ownIdentity.device
            var pending: [(String, Int, String?)] = [(root, 0, outerPackage)]
            while let (directory, depth, package) = pending.popLast() {
                try ScanCancellation.check()
                guard Date() < deadline else { throw SweepError.incomplete("应用归属扫描超时，结果未确认") }
                let handle = try SafeDirectory(path: directory)
                guard try handle.ownIdentity.device == device else { throw SweepError.incomplete("安装目录出现挂载点，归属未确认") }
                let (names, count) = try installationEntries(handle, buffer:&entryBuffer)
                visited += count
                guard visited <= 500_000 else { throw SweepError.incomplete("应用及包内组件归属扫描截断，结果未确认") }
                for name in names {
                    try ScanCancellation.check()
                    let path = directory + "/" + name
                    let identity = try handle.identity(name)
                    if identity.isLink, let package, let target = try? FileManager.default.destinationOfSymbolicLink(atPath:path) {
                        let resolved = (target.hasPrefix("/") ? URL(fileURLWithPath:target) : URL(fileURLWithPath:directory).appendingPathComponent(target)).standardizedFileURL.path
                        // Internal aliases, including .app aliases, never create
                        // another installed owner. Their physical target is scanned.
                        if SafetyPolicy.contains(package,resolved) { continue }
                    }
                    if name.hasSuffix(".app") || (package != nil && (name.hasSuffix(".xpc") || name.hasSuffix(".appex"))) {
                        if identity.isLink, let apple = protectedAppleAlias(path) { result.append(apple); continue }
                        do {
                            if package != nil, let body = try? unbuiltTemplate(path) { pending.append((body, depth + 1, package)); continue }
                            let app = try inspect(path, verifySignature: false, component: package != nil)
                            result.append(ApplicationIdentity(path: app.path, name: app.name, bundleIdentifier: app.bundleIdentifier, signed: app.signed, protectedReason: app.protectedReason ?? (package != nil ? "包内组件与外层应用一起处理，不能单独卸载" : nil)))
                            guard depth < 64 else { throw SweepError.incomplete("包内组件扫描深度超限，归属未确认") }
                            let body = try metadata(path, component: package != nil).1
                            pending.append((body, depth + 1, package ?? path))
                        } catch {
                            if package != nil, let (hint, body) = try? quotedIdentifierHint(path) { result.append(hint); pending.append((body, depth + 1, package)); continue }
                            if !identity.isLink, depth < 64, let (hint, body) = try? wrappedApplicationHint(path, buffer: &entryBuffer) { result.append(hint); pending.append((body, depth + 1, package ?? path)); continue }
                            result.append(ApplicationIdentity(path: path, name: String(name.dropLast(4)), bundleIdentifier: "", signed: false, protectedReason: "元数据未确认：" + error.localizedDescription))
                        }
                    } else if identity.isLink {
                        if let package, let hint = try? declaredExecutableAlias(path, package: package) { result.append(hint) }
                        else { result.append(ApplicationIdentity(path: path, name: name, bundleIdentifier: "", signed: false, protectedReason: "链接安装位置未确认，归属仅供核对")) }
                    } else if identity.isDirectory {
                        guard depth < (package == nil ? 8 : 64), identity.device == device else { throw SweepError.incomplete("嵌套安装范围或挂载点未确认") }
                        pending.append((path, depth + 1, package))
                    }
                }
            }
        }
        for (root, package) in roots { try walk(root, package) }
        if machineOnly || retainedApplication != nil { return .init(applications: result, issues: issues) }
        var queried = Set<String>()
        while true {
            let identifiers = Set(result.map(\.bundleIdentifier) + [ownershipIdentifier].compactMap { $0 })
                .filter { AppInspector.validIdentifier($0) && !$0.lowercased().hasPrefix("com.apple.") }
                .subtracting(queried)
            if identifiers.isEmpty { break }
            queried.formUnion(identifiers)
            guard queried.count <= 10_000, Date() < deadline else { throw SweepError.incomplete("应用注册归属查询超限或超时") }
            for identifier in identifiers.sorted() {
                let locations: [ApplicationRegistry.Location]
                do { locations = try ApplicationRegistry.locations(identifiers: [identifier], lookup: registryLookup) }
                catch is CancellationError { throw CancellationError() }
                catch {
                    // The empty path is an explicit unresolved query, never a
                    // fictional installation. It blocks this ID's data only.
                    issues.append(identifier + " 的注册查询未确认：" + error.localizedDescription)
                    result.append(ApplicationIdentity(path: "", name: identifier + "（注册状态未确认）", bundleIdentifier: identifier,
                        signed: false, protectedReason: "应用注册查询未确认：" + error.localizedDescription))
                    continue
                }
                for location in locations {
                    try ScanCancellation.check()
                    guard Date() < deadline else { throw SweepError.incomplete("应用归属扫描超时") }
                    if result.contains(where: { $0.path == location.path }) { continue }
                    do {
                        guard try SafeFilesystem.presence(location.path) else { continue }
                        guard SelectedApplicationRule.matches(path: location.path, policy: SafetyPolicy(home: home, acceptedPlatform: false)) else {
                            // Registrations outside the verified current-user scope
                            // remain conflicts, never a licence to inspect or mutate them.
                            throw SweepError.denied("注册位置属于受保护、其它用户或尚未验证范围")
                        }
                        let identity = try SafeDirectory(path: location.path).ownIdentity
                        if result.contains(where: { existing in
                            guard let prior = try? SafeDirectory(path: existing.path).ownIdentity else { return false }
                            return identity.sameObject(as: prior)
                        }) { continue }
                        let app = try inspect(location.path, verifySignature: false)
                        result.append(app)
                        try walk(try metadata(location.path, component: false).1, location.path)
                    } catch is CancellationError { throw CancellationError() }
                    catch {
                        result.append(ApplicationIdentity(path: location.path, name: URL(fileURLWithPath: location.path).deletingPathExtension().lastPathComponent,
                            bundleIdentifier: location.identifier, signed: false, protectedReason: "已注册的同标识安装未确认：" + error.localizedDescription))
                    }
                }
            }
        }
        return ApplicationInventory(applications: result.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }, issues: Array(Set(issues)).sorted())
    }
    static func uniqueOwner(identifier: String, path: String, inventory: [ApplicationIdentity]) -> Bool {
        guard !inventory.contains(where: { $0.bundleIdentifier.isEmpty }) else { return false }
        let owners = inventory.filter { $0.bundleIdentifier.lowercased() == identifier.lowercased() }
        return owners.count == 1 && owners[0].path == path
    }
}
struct ScanOutput: Sendable { let report: ScanReport; let snapshots: [UUID: FileSnapshot] }
/// Keeps only fully closed outer scopes. The native worker may outlive its
/// waiter, so closing this checkpoint also revokes every subsequent update.
fileprivate final class ScanStageCheckpoint: @unchecked Sendable {
    private let lock=NSLock()
    private var committed: Scanner.Builder
    private var activeRoot: String?
    private var closed=false
    private var preview: ScanReport?
    init(_ builder: Scanner.Builder) { committed=builder }
    func begin(_ root: String) {
        ScanReadActivity.commit {
            self.lock.lock();defer{self.lock.unlock()}
            if !self.closed { self.activeRoot=root }
        }
    }
    func accept(_ builder: Scanner.Builder) {
        var detached=builder;detached.scopeCheckpoint=nil;detached.scopeProgress=nil
        let value=detached
        ScanReadActivity.commit {
            self.lock.lock();defer{self.lock.unlock()}
            if !self.closed {
                if self.committed.items.count != value.items.count || self.committed.issues != value.issues { self.preview=nil }
                self.committed=value;self.activeRoot=nil
            }
        }
    }
    func finish() -> (Scanner.Builder,String?) {
        lock.lock();defer{lock.unlock()}
        closed=true;return(committed,activeRoot)
    }
    func display() -> ScanReport {
        lock.lock();defer{lock.unlock()}
        if let preview{return preview}
        let report=committed.finish(applicationPath:nil).report
        preview=report;return report
    }
}
struct Scanner: Sendable {
    let policy: SafetyPolicy
    private var scanDeadline: TimeInterval? = nil
    init(policy: SafetyPolicy) { self.policy=policy }
    func application(_ path: String) throws -> ScanOutput {
        if let protected = policy.protectedDenial(path) { throw SweepError.denied(protected) }
        guard policy.lexicalDenial(path) == nil || SelectedApplicationRule.matches(path: path, policy: policy) else { throw SweepError.denied("此应用位置尚未完成验证，已保留") }
        let hint = try AppInspector.inspect(path, verifySignature: false)
        let chosenRule = policy.ruleIsValidated(SelectedApplicationRule.name) || !ChosenApplicationRule.matches(path: path, home: policy.home) || hint.bundleIdentifier.lowercased().hasPrefix("com.apple.") ? SelectedApplicationRule.name : ChosenApplicationRule.name
        // A busy app cannot form an uninstall plan. Resolve that cheap refusal
        // before signature, recursive body and unrelated installation walks.
        do { try ActivityInspector.ensureStopped(bundleID: hint.bundleIdentifier, applicationPath: path, userHome: policy.home) }
        catch is CancellationError { throw CancellationError() }
        catch { return try chosenApplication(path, app: hint, rule: chosenRule, earlyRetention: error.localizedDescription) }
        let app = try AppInspector.inspect(path)
        if policy.ruleIsValidated(SelectedApplicationRule.name) || !ChosenApplicationRule.matches(path: path, home: policy.home) || app.bundleIdentifier.lowercased().hasPrefix("com.apple.") {
            return try chosenApplication(path, app: app, rule: SelectedApplicationRule.name)
        }
        if policy.ruleIsValidated(ChosenApplicationRule.name) { return try chosenApplication(path, app: app) }
        let inventory = try AppInspector.inventory(home: policy.home, selectedApplication: path)
        let unique = AppInspector.uniqueOwner(identifier: app.bundleIdentifier, path: path, inventory: inventory)
        var builder = Builder(policy: policy)
        let parent = URL(fileURLWithPath: path).deletingLastPathComponent().path
        let direct = ["/Applications", policy.home + "/Applications"].contains(parent)
        let reason = app.protectedReason ?? (!direct ? "嵌套安装仅用于归属核对，首版保留" : (!app.signed ? "签名未确认，不能处理" : (!unique ? "存在相同应用标识或未确认安装，不能证明独占归属" : nil)))
        let evidence = [OwnershipEvidence(kind: .bundleIdentifier, detail: app.bundleIdentifier, verified: true), OwnershipEvidence(kind: .signature, detail: "应用签名与标识一致", verified: app.signed)]
        try builder.scoped(root: path) { scope in
            try scope.add(path, category: .application, bundleID: app.bundleIdentifier, rule: "signed-application-v1", evidence: evidence, reason: reason, applicationPath: path)
        }
        try addResidue(app:app,trusted:reason == nil,inventory:inventory,builder:&builder)
        try addChromiumCaches(app:app,trusted:reason == nil,inventory:inventory,builder:&builder)
        try addChromiumProfile(app:app,trusted:reason == nil,inventory:inventory,builder:&builder)
        try ScanCancellation.check()
        return builder.finish(applicationPath: path)
    }
    private func chosenApplication(_ path: String, app: ApplicationIdentity, rule: String = ChosenApplicationRule.name, earlyRetention: String? = nil) throws -> ScanOutput {
        var builder = Builder(policy: policy)
        var reason = earlyRetention
        do {
            if reason == nil {
                if rule == SelectedApplicationRule.name { try SelectedApplicationRule.verify(path: path, policy: policy, identifier: app.bundleIdentifier) }
                else { try ChosenApplicationRule.verify(path: path, home: policy.home, identifier: app.bundleIdentifier) }
            }
        }
        catch is CancellationError { throw CancellationError() }
        catch { reason = error.localizedDescription }
        try builder.scoped(root: path) { scope in
            try scope.add(path, category: .application, bundleID: app.bundleIdentifier, rule: rule,
                          evidence: [.init(kind: .validatedRule, detail: "用户选择的完整应用主体；结构与可执行文件已核对，不据此授权关联资料", verified: reason == nil)],
                          reason: reason, applicationPath: path)
        }
        // An uninstall plan requires this body. A busy/retained body still gets
        // presence-only residue hints, but cannot justify expensive data reads.
        let bodyAllowed = builder.items.first(where: { $0.path == path && $0.category == .application })?.allowed == true
        var dataInventory: [ApplicationIdentity]? = bodyAllowed ? nil : [app], dataTrusted = false
        try builder.scoped(root: policy.home + "/Library") { scope in
            let inventory: [ApplicationIdentity]
            if bodyAllowed { inventory = try AppInspector.inventory(home: policy.home, selectedApplication: path) }
            else {
                let hints = try AppInspector.inventorySnapshot(home: policy.home, retainedApplication: path)
                inventory = hints.applications; scope.issues.append(contentsOf: hints.issues)
            }
            let trusted = reason == nil && bodyAllowed && app.signed && !app.bundleIdentifier.lowercased().hasPrefix("com.apple.") && AppInspector.uniqueOwner(identifier: app.bundleIdentifier, path: path, inventory: inventory)
            dataInventory = inventory; dataTrusted = trusted
        }
        if let dataInventory {
            try addResidue(app:app,trusted:dataTrusted,inventory:dataInventory,builder:&builder)
            try addChromiumCaches(app:app,trusted:dataTrusted,inventory:dataInventory,builder:&builder)
            try addChromiumProfile(app:app,trusted:dataTrusted,inventory:dataInventory,builder:&builder)
            try addComponentResidue(app:app,trusted:dataTrusted,inventory:dataInventory,builder:&builder)
        }
        // Lifecycle references remain visible even when body execution is blocked.
        var references=UninstallRelatedReferences.Inspection()
        try builder.scoped(root:app.path) { scope in
            references=try UninstallRelatedReferences.locations(app:app,home:policy.home,darwin:policy.darwinScope)
        }
        for issue in references.issues {
            try builder.scoped(root:issue.path) { _ in throw SweepError.incomplete(issue.message) }
        }
        for reference in references.references {
            try builder.scoped(root:reference.path) { scope in
                guard try SafeFilesystem.presence(reference.path),!scope.items.contains(where:{$0.path == reference.path || ($0.rule == WebKitCacheRule.name && URL(fileURLWithPath:$0.path).deletingLastPathComponent().path == reference.path)}) else{return}
                var item=Candidate(id:UUID(),path:reference.path,category:reference.category,bundleIdentifier:app.bundleIdentifier,evidence:[],rule:"uninstall-related-reference-v1",identity:nil,bytes:0,retentionReason:reference.reason)
                item.applicationPath=app.path;item.displayName=reference.title
                scope.items.append(item)
            }
        }
        try ScanCancellation.check()
        return builder.finish(applicationPath: path)
    }
    func known(identifier: String, name: String) throws -> ScanOutput {
        guard AppInspector.validIdentifier(identifier) else { throw SweepError.invalid("应用标识无效") }
        var builder = Builder(policy: policy)
        // A missing application cannot supply signature or a fictional /Applications path.
        let app = ApplicationIdentity(path: "", name: name, bundleIdentifier: identifier, signed: false, protectedReason: "应用主体不存在，归属仅供人工核对")
        try addResidue(app:app,trusted:false,inventory:[],builder:&builder)
        try ScanCancellation.check()
        return builder.finish(applicationPath: nil)
    }
    func junk(maximumDuration: TimeInterval = 120,indexLookup: @escaping ApplicationIndex.Lookup = ApplicationIndex.systemPaths, progress: (@Sendable (ScanProgress) -> Void)? = nil) throws -> ScanOutput {
        guard maximumDuration > 0,maximumDuration <= 120,maximumDuration.isFinite else { throw SweepError.invalid("扫描等待期限无效") }
        var scanner=self
        scanner.scanDeadline=ProcessInfo.processInfo.systemUptime + maximumDuration
        return try scanner.junkWithinDeadline(indexLookup:indexLookup,progress:progress)
    }
    #if DEBUG
    /// Compatibility entry point for earlier isolated recovery fixtures.
    /// Product callers discover these manual data scopes through junk().
    func legacyManagementFixture(indexLookup: @escaping ApplicationIndex.Lookup = ApplicationIndex.systemPaths) throws -> ScanOutput {
        let account = try SystemIdentity.home()
        let privateFixture = policy.home.hasPrefix(account + "/AppSweepAcceptance") && policy.home != account
        let legacyFlags = ["APP_SWEEP_DOCUMENT_HISTORY_ACCEPTANCE", "APP_SWEEP_XCODE_ARCHIVE_ACCEPTANCE", "APP_SWEEP_DEVICE_SYMBOL_ACCEPTANCE"]
        let registeredNativeFixture = policy.home == account && account == "/Users/localtest" &&
            as_current_uid() == 501 && legacyFlags.contains { ProcessInfo.processInfo.environment[$0] == "AppSweep-General-20261016" }
        if !privateFixture {
            guard registeredNativeFixture,
                  try BoundedProcess.run("/usr/sbin/sysctl", arguments: ["-n", "hw.model"], timeout: 3)
                    .trimmingCharacters(in: .whitespacesAndNewlines) == "VirtualMac2,1" else {
                throw SweepError.denied("旧原生恢复夹具仅允许明确启用的既有测试虚拟机")
            }
        }
        guard privateFixture || registeredNativeFixture,
              try SafeDirectory(path: policy.home).ownIdentity.owner == as_current_uid() else {
            throw SweepError.denied("旧恢复兼容夹具必须位于登记测试目录")
        }
        let inventory: ApplicationInventory
        do { inventory = try AppInspector.inventorySnapshot(home: policy.home, indexLookup: indexLookup) }
        catch is CancellationError { throw CancellationError() }
        catch { inventory = .init(applications: [], issues: ["旧记录夹具的应用归属未确认：" + error.localizedDescription]) }
        var builder = Builder(policy: policy)
        builder.issues += inventory.issues
        try addDocumentHistory(builder: &builder)
        try addCorruptPreferences(apps: inventory.applications, builder: &builder)
        try addDeviceBackups(builder: &builder)
        try addStaleUserAgents(builder: &builder)
        try addXcodeArchives(builder: &builder)
        try addXcodeDeviceSymbols(builder: &builder)
        return builder.finish(applicationPath: nil)
    }
    #endif
    private func junkWithinDeadline(indexLookup: @escaping ApplicationIndex.Lookup,progress: (@Sendable (ScanProgress) -> Void)?) throws -> ScanOutput {
        try scanProgress(progress,stage:"核对已安装应用",count:0)
        let inventory: ApplicationInventory
        do {
            let remaining=max(0.001,(scanDeadline ?? .infinity)-ProcessInfo.processInfo.systemUptime)
            inventory = try ReadOnlyScanPool.shared.run(stage:"应用归属发现",timeout:min(30,remaining),maximumDuration:remaining) { _ in try AppInspector.inventorySnapshot(home:policy.home,indexLookup:indexLookup) }
        }
        catch is CancellationError { throw CancellationError() }
        catch {
            // An incomplete installation tree cannot authorise app-owned data.
            // Independent cache/development scopes still get their own checks.
            inventory = ApplicationInventory(applications:[],issues:["应用安装归属扫描未确认，相关应用资料保留：" + error.localizedDescription])
        }
        let apps = inventory.applications
        var builder = Builder(policy: policy)
        if !inventory.issues.isEmpty {
            builder.issues += inventory.issues
        }
        try scanProgress(progress,stage:"检查应用缓存与日志",count:builder.items.count)
        try boundedStage("检查应用缓存与日志",builder:&builder,progress:progress) { [self] builder, progress in
            for app in apps where !app.bundleIdentifier.isEmpty {
                try scanProgress(progress,stage:"检查应用缓存与日志",detail:app.name,count:builder.items.count)
                try addNamedApplication(app:app,trusted:AppInspector.uniqueOwner(identifier:app.bundleIdentifier,path:app.path,inventory:apps),inventory:apps,includeData:false,builder:&builder)
                if app.bundleIdentifier == "org.mozilla.firefox" {
                    try builder.scoped(root: policy.home + "/Library/Application Support/Firefox") { scope in
                        try addFirefox(app: app, apps: apps, builder: &scope)
                    }
                }
                if app.protectedReason != nil {
                    do { _ = try AppInspector.verifiedDataOwner(path: app.path, identifier: app.bundleIdentifier, home: policy.home) }
                    catch is CancellationError { throw CancellationError() }
                    catch { continue }
                }
                let unique = AppInspector.uniqueOwner(identifier: app.bundleIdentifier, path: app.path, inventory: apps)
                try builder.scoped(root: policy.home + "/Library/Caches/" + app.bundleIdentifier) { scope in
                    try addCache(app: app, trusted: unique, inventory:apps, builder: &scope)
                }
                try addChromiumCaches(app:app,trusted:unique,inventory:apps,builder:&builder)
                try addApplicationLogs(app: app, trusted: unique, builder: &builder)
            }
        }
        try scanProgress(progress,stage:"检查应用与容器缓存",count:builder.items.count)
        try boundedStage("检查应用与容器缓存",builder:&builder,progress:progress) { [self] builder, progress in
            try addApplicationCaches(apps:apps,builder:&builder,progress:progress)
        }
        try scanProgress(progress,stage:"检查当前账户临时缓存",count:builder.items.count)
        try boundedStage("检查当前账户临时缓存",builder:&builder,progress:progress) { [self] builder, progress in
            try addDarwinCaches(apps:apps,builder:&builder,progress:progress)
            try addWebKitCaches(apps:apps,builder:&builder,progress:progress)
        }
        try boundedStage("检查已知编辑器缓存",builder:&builder,progress:progress) { [self] builder, progress in
            try addGodotCaches(apps:apps,builder:&builder)
        }
        try boundedStage("检查开发工具缓存",builder:&builder,progress:progress) { [self] builder, progress in
            try addToolCaches(builder:&builder,progress:progress)
        }
        try scanProgress(progress,stage:"检查其他缓存位置",count:builder.items.count)
        try boundedStage("检查其他缓存位置",builder:&builder,progress:progress) { [self] builder, progress in
            try addUncoveredCacheNamespaces(builder: &builder,progress:progress)
        }
        try scanProgress(progress,stage:"检查开发构建产物",count:builder.items.count)
        try boundedStage("检查开发构建产物",builder:&builder,progress:progress) { [self] builder, progress in
            try addXcodeGenerated(builder:&builder)
        }
        try scanProgress(progress,stage:"检查模拟器缓存",count:builder.items.count)
        try boundedStage("检查模拟器缓存",builder:&builder,progress:progress) { [self] builder, progress in
            try addSimulatorCaches(builder:&builder)
        }
        try scanProgress(progress,stage:"检查构建中间文件",count:builder.items.count)
        try boundedStage("检查构建中间文件",builder:&builder,progress:progress) { [self] builder, progress in
            let derived = policy.home + "/Library/Developer/Xcode/DerivedData"
            try builder.scoped(root: derived) { scope in
              if try SafeFilesystem.presence(derived) {
                _ = try SafeDirectory(path: derived)
                let names = try FileManager.default.contentsOfDirectory(atPath: derived)
                guard names.count <= 1000 else { throw SweepError.denied("开发目录扫描截断") }
                for name in names {
                    try ScanCancellation.check()
                    let item = derived + "/" + name + "/Build/Intermediates.noindex"
                    guard try SafeFilesystem.presence(item) else { continue }
                    var reason: String?
                    if !policy.ruleIsValidated(XcodeRule.name) { reason = "Xcode 中间目录可能包含未知内容，首版仅报告" }
                    else {
                        do { try XcodeRule.verify(item, home: policy.home) }
                        catch { reason = "Xcode 工作区及中间目录未确认：" + error.localizedDescription }
                    }
                    try scope.add(item, category: .development, bundleID: "com.apple.dt.Xcode", rule: XcodeRule.name, evidence: [.init(kind: .validatedRule, detail: "精确 Intermediates.noindex 目录及当前用户的工作区元数据", verified: reason == nil)], reason: reason, applicationPath: nil)
                }
            }
              }
        }
        try scanProgress(progress,stage:"检查崩溃报告",count:builder.items.count)
        try boundedStage("检查崩溃报告",builder:&builder,progress:progress) { [self] builder, progress in
            try builder.scoped(root: policy.home + "/Library/Logs/DiagnosticReports") { scope in
                try addCrashReports(apps: apps, builder: &scope)
            }
        }
        try boundedStage("检查工具诊断日志",builder:&builder,progress:progress) { [self] builder, _ in
            for root in AIDiagnosticRule.roots(home:policy.home) {
                try builder.scoped(root:root) { scope in
                    guard try SafeFilesystem.presence(root) else{return}
                    for name in try XcodeArchiveRule.children(root) {
                        try ScanCancellation.check()
                        let path=root + "/" + name
                        guard AIDiagnosticRule.matches(path:path,home:policy.home) else{continue}
                        var reason:String?
                        if policy.ruleIsValidated(AIDiagnosticRule.name) {
                            do {
                                try AIDiagnosticRule.ensureStopped(path:path,home:policy.home)
                                _=try AIDiagnosticRule.verify(path:path,home:policy.home)
                            } catch is CancellationError { throw CancellationError() }
                            catch {
                                reason=error.localizedDescription
                                switch error { case SweepError.denied: break; default: scope.issues.append(path + "：" + error.localizedDescription) }
                            }
                        } else { reason="该诊断日志规则尚未通过当前平台验收，保留" }
                        try scope.add(path,category:.log,bundleID:nil,rule:AIDiagnosticRule.name,
                            evidence:[.init(kind:.validatedRule,detail:AIDiagnosticRule.provenance,verified:reason == nil)],
                            reason:reason,applicationPath:nil,displayName:"Codex CLI 诊断日志")
                    }
                }
            }
        }
        // Personal management follows cache/log discovery and never enters the
        // recommended selection. Each rule keeps its platform, ownership,
        // activity and recovery checks; a discovery stage grants no new path.
        try boundedStage("检查设备备份",builder:&builder,progress:progress) { [self] builder, _ in
            try addDeviceBackups(builder:&builder)
        }
        try boundedStage("检查应用偏好文件",builder:&builder,progress:progress) { [self] builder, _ in
            try addCorruptPreferences(apps:apps,builder:&builder)
        }
        try boundedStage("检查失效后台项目",builder:&builder,progress:progress) { [self] builder, _ in
            try addStaleUserAgents(builder:&builder)
        }
        try boundedStage("检查项目归档",builder:&builder,progress:progress) { [self] builder, _ in
            try addXcodeArchives(builder:&builder)
        }
        try boundedStage("检查设备调试符号",builder:&builder,progress:progress) { [self] builder, _ in
            try addXcodeDeviceSymbols(builder:&builder)
        }
        try boundedStage("检查当前账户废纸篓",builder:&builder,progress:progress) { [self] builder, _ in
            try addManualData(root:TrashEntryRule.root(home:policy.home),rule:TrashEntryRule.name,provenance:TrashEntryRule.provenance,
                matches:{TrashEntryRule.matches(path:$0,home:policy.home)},verify:{ path in
                    let snapshot=try TrashEntryRule.verify(path:path,home:policy.home)
                    try TrashEntryRule.ensureStopped(path:path,home:policy.home);return snapshot
                },builder:&builder)
        }
        try boundedStage("检查邮件下载副本",builder:&builder,progress:progress) { [self] builder, _ in
            for root in MailDownloadRule.roots(home:policy.home) {
                try addManualData(root:root,rule:MailDownloadRule.name,provenance:MailDownloadRule.provenance,
                    matches:{MailDownloadRule.matches(path:$0,home:policy.home)},verify:{ path in
                        let snapshot=try MailDownloadRule.verify(path:path,home:policy.home)
                        try MailDownloadRule.ensureStopped(path:path,home:policy.home);return snapshot
                    },builder:&builder)
            }
        }
        try boundedStage("检查独立本地模型",builder:&builder,progress:progress) { [self] builder, _ in
            try addManualData(root:AIStorageRule.root(home:policy.home),rule:AIStorageRule.name,provenance:AIStorageRule.provenance,
                matches:{AIStorageRule.matches(path:$0,home:policy.home)},verify:{ path in
                    let snapshot=try AIStorageRule.verify(path:path,home:policy.home)
                    try AIStorageRule.ensureStopped(path:path,home:policy.home);return snapshot
                },builder:&builder)
        }
        try boundedStage("检查文稿历史版本",builder:&builder,progress:progress,maximumDuration:30) { [self] builder, _ in
            try addDocumentHistory(builder:&builder)
        }
        for path in ["/System/Library/Caches", "/Library/Caches", "/private/var/folders"] {
            builder.reportProtected(path, reason: "目录整体受保护；仅独立系统规则核验的子项目可处理，关键系统状态保留")
        }
        try scanProgress(progress,stage:"完成用户范围扫描",count:builder.items.count)
        return builder.finish(applicationPath: nil)
    }
    func boundedStage(_ name: String, builder: inout Builder, progress: (@Sendable (ScanProgress) -> Void)?,
                              timeout: TimeInterval = 30, maximumDuration: TimeInterval = 300,
                              operation: @escaping @Sendable (inout Builder, (@Sendable (ScanProgress) -> Void)?) throws -> Void) throws {
        try ScanCancellation.check()
        let remaining=(scanDeadline ?? .infinity)-ProcessInfo.processInfo.systemUptime
        guard remaining > 0 else {
            let issue="本次扫描已到等待期限，未开始的范围保留；已完成范围可继续核对"
            if !builder.issues.contains(issue) { builder.issues.append(issue) }
            return
        }
        let initial = builder
        let checkpoint=ScanStageCheckpoint(initial)
        do {
            builder = try ReadOnlyScanPool.shared.run(stage:name,timeout:min(timeout,remaining),maximumDuration:min(maximumDuration,remaining),progress:{ value in
                let completed=checkpoint.display()
                progress?(.init(stage:value.stage,detail:value.detail,discoveredCount:completed.candidates.count,completedReports:["user":completed]))
            }) { feedback in
                var staged = initial
                staged.scopeCheckpoint=checkpoint
                staged.scopeProgress={ count in feedback(.init(stage:name,discoveredCount:count)) }
                try operation(&staged,feedback)
                try ScanCancellation.check()
                staged.scopeCheckpoint=nil
                staged.scopeProgress=nil
                return staged
            }
            _=checkpoint.finish()
        } catch is CancellationError { _=checkpoint.finish();throw CancellationError() }
        catch {
            let (completed,activeRoot)=checkpoint.finish()
            builder=completed
            builder.issues.append(error.localizedDescription)
            if let activeRoot {
                builder.scopes.append(.init(id:UUID().uuidString,root:activeRoot,complete:false,candidateIDs:[],issues:[error.localizedDescription]))
            }
        }
        try ScanCancellation.check()
        progress?(.init(stage:name,discoveredCount:builder.items.count,completedReports:["user":builder.finish(applicationPath:nil).report]))
        try ScanCancellation.check()
    }
    private func scanProgress(_ progress: (@Sendable (ScanProgress) -> Void)?, stage: String, detail: String? = nil, count: Int) throws {
        try ScanCancellation.check()
        progress?(.init(stage:stage,detail:detail,discoveredCount:count))
        try ScanCancellation.check()
    }
    private func addDarwinCaches(apps: [ApplicationIdentity], applicationPath: String? = nil, builder: inout Builder, progress: (@Sendable (ScanProgress) -> Void)? = nil, retainedReason: String? = nil) throws {
        guard policy.ruleIsValidated(DarwinCacheRule.name) else{return}
        guard let darwin=policy.darwinScope,darwin.home == policy.home else {
            builder.issues.append("Darwin 用户缓存范围未确认：" + (policy.darwinScopeIssue ?? "缺少当前账户范围"))
            return
        }
        do{try darwin.verify()}
        catch is CancellationError{throw CancellationError()}
        catch{builder.issues.append("Darwin 用户缓存范围未确认：" + error.localizedDescription);return}
        for app in apps where SystemCleanupScope.validIdentifier(app.bundleIdentifier) && (applicationPath == nil || app.path == applicationPath) {
            try scanProgress(progress,stage:"检查当前账户临时缓存",detail:app.name,count:builder.items.count)
            let root=darwin.root + "/" + app.bundleIdentifier
            try builder.scoped(root:root){scope in
                guard try SafeFilesystem.presence(root) else{return}
                if let retainedReason {
                    try scope.add(root, category: .cache, bundleID: app.bundleIdentifier, rule: DarwinCacheRule.name, evidence: [], reason: retainedReason, applicationPath: app.path)
                    return
                }
                do {
                    guard AppInspector.uniqueOwner(identifier:app.bundleIdentifier,path:app.path,inventory:apps) else{throw SweepError.denied("Darwin 缓存应用归属不唯一")}
                    _=try AppInspector.verifiedDataOwner(path:app.path,identifier:app.bundleIdentifier,home:policy.home)
                    try ActivityInspector.ensureStopped(bundleID:app.bundleIdentifier,applicationPath:app.path,additionalIdentifiers:[app.bundleIdentifier + "."])
                    try ActivityInspector.ensureSystemServicesStopped(identifiers:[app.bundleIdentifier],applicationPath:app.path)
                    let snapshot=try DarwinCacheRule.verifyRoot(identifier:app.bundleIdentifier,scope:darwin)
                    try BusyInspector.ensureUnused(snapshot)
                    for member in try CacheDomainRule.members(root:root).sorted() {
                        try scope.add(member,category:.cache,bundleID:app.bundleIdentifier,rule:DarwinCacheRule.name,
                            evidence:[.init(kind:.signature,detail:"第三方应用标识、签名及唯一安装一致",verified:true),
                                      .init(kind:.validatedRule,detail:"系统确认的当前账户 Darwin C-cache 内精确应用缓存域；完整私有对象及停止状态已核对；根目录保留，需手动选择",verified:true)],
                            reason:nil,applicationPath:app.path)
                    }
                    try SafeFilesystem.verify(snapshot);try darwin.verify()
                }catch is CancellationError{throw CancellationError()}
                catch {
                    if case SweepError.incomplete = error{scope.issues.append(root + "：" + error.localizedDescription)}
                    var item=Candidate(id:UUID(),path:root,category:.cache,bundleIdentifier:app.bundleIdentifier,evidence:[],rule:DarwinCacheRule.name,identity:nil,bytes:0,retentionReason:error.localizedDescription)
                    item.applicationPath=app.path;scope.items.append(item)
                }
            }
        }
    }
    private func addWebKitCaches(apps: [ApplicationIdentity], applicationPath: String? = nil, builder: inout Builder, progress: (@Sendable (ScanProgress) -> Void)? = nil, retainedReason: String? = nil) throws {
        try addWebKitTemporary(apps: apps, applicationPath: applicationPath, builder: &builder, retainedReason: retainedReason)
        guard policy.ruleIsValidated(WebKitCacheRule.name) else { return }
        guard let darwin = policy.darwinScope, darwin.home == policy.home else {
            builder.issues.append("WebKit 派生缓存范围未确认：" + (policy.darwinScopeIssue ?? "缺少当前账户范围")); return
        }
        for app in apps where applicationPath == nil || app.path == applicationPath {
            for namespace in WebKitCacheRule.namespaces(identifier: app.bundleIdentifier) {
                let root = darwin.root + "/" + namespace
                try builder.scoped(root: root) { scope in
                    guard try SafeFilesystem.presence(root) else { return }
                    if let retainedReason {
                        try scope.add(root, category: .cache, bundleID: app.bundleIdentifier, rule: WebKitCacheRule.name, evidence: [], reason: retainedReason, applicationPath: app.path)
                        return
                    }
                    try scanProgress(progress, stage: "检查 WebKit 派生缓存", detail: app.name, count: scope.items.count)
                    do {
                        guard AppInspector.uniqueOwner(identifier: app.bundleIdentifier, path: app.path, inventory: apps) else { throw SweepError.denied("WebKit 缓存应用归属不唯一") }
                        _ = try AppInspector.verifiedDataOwner(path: app.path, identifier: app.bundleIdentifier, home: policy.home)
                        try ActivityInspector.ensureStopped(bundleID: app.bundleIdentifier, applicationPath: app.path, additionalIdentifiers: WebKitCacheRule.namespaces(identifier: app.bundleIdentifier))
                        try ActivityInspector.ensureSystemServicesStopped(identifiers: [app.bundleIdentifier], applicationPath: app.path)
                        let snapshot = try WebKitCacheRule.verifyRoot(root, identifier: app.bundleIdentifier, scope: darwin)
                        try BusyInspector.ensureUnused(snapshot)
                        for member in try CacheDomainRule.members(root: root).sorted() {
                            try scope.add(member, category: .cache, bundleID: app.bundleIdentifier, rule: WebKitCacheRule.name,
                                evidence: [.init(kind: .signature, detail: "唯一第三方应用的完整签名与客户端标识一致", verified: true),
                                           .init(kind: .validatedRule, detail: "当前账户 C-cache 的精确 WebKit 派生域；仅处理子项，保留域目录", verified: true)],
                                reason: nil, applicationPath: app.path, displayName: "WebKit · " + app.name)
                        }
                        try SafeFilesystem.verify(snapshot); try darwin.verify()
                    } catch is CancellationError { throw CancellationError() }
                    catch {
                        if case SweepError.incomplete = error { scope.issues.append(root + "：" + error.localizedDescription) }
                        var item = Candidate(id: UUID(), path: root, category: .cache, bundleIdentifier: app.bundleIdentifier, evidence: [], rule: WebKitCacheRule.name, identity: nil, bytes: 0, retentionReason: error.localizedDescription)
                        item.applicationPath = app.path; item.displayName = "WebKit · " + app.name; scope.items.append(item)
                    }
                }
            }
        }
    }
    private func addWebKitTemporary(apps: [ApplicationIdentity], applicationPath: String?, builder: inout Builder, retainedReason: String?) throws {
        guard policy.ruleIsValidated(WebKitTemporaryRule.name) else { return }
        guard let temporary = policy.darwinTemporaryScope, temporary.home == policy.home else {
            builder.issues.append("WebKit 临时目录未确认：" + (policy.darwinTemporaryIssue ?? "缺少当前账户范围")); return
        }
        for app in apps where applicationPath == nil || app.path == applicationPath {
            guard let namespace = WebKitTemporaryRule.namespace(app.bundleIdentifier) else { continue }
            let root = temporary.root + "/" + namespace
            try builder.scoped(root: root) { part in
                guard try SafeFilesystem.presence(root) else { return }
                for path in try CacheDomainRule.members(root: root).sorted() where WebKitTemporaryRule.root(path: path, identifier: app.bundleIdentifier, scope: temporary) != nil {
                    try ScanCancellation.check()
                    var reason = retainedReason
                    if reason == nil {
                        do {
                            guard AppInspector.uniqueOwner(identifier: app.bundleIdentifier, path: app.path, inventory: apps) else { throw SweepError.denied("WebKit 临时目录归属不唯一") }
                            _ = try AppInspector.verifiedDataOwner(path: app.path, identifier: app.bundleIdentifier, home: policy.home)
                            try ActivityInspector.ensureStopped(bundleID: app.bundleIdentifier, applicationPath: app.path, additionalIdentifiers: WebKitCacheRule.namespaces(identifier: app.bundleIdentifier))
                            try ActivityInspector.ensureSystemServicesStopped(identifiers: [app.bundleIdentifier], applicationPath: app.path)
                            try WebKitTemporaryRule.verify(path: path, identifier: app.bundleIdentifier, scope: temporary)
                            try BusyInspector.ensureUnused(SafeFilesystem.snapshot(path))
                        } catch is CancellationError { throw CancellationError() }
                        catch { reason = error.localizedDescription; if case SweepError.incomplete = error { part.issues.append(root + "：" + error.localizedDescription) } }
                    }
                    try part.add(path, category: .cache, bundleID: app.bundleIdentifier, rule: WebKitTemporaryRule.name,
                        evidence: [.init(kind: .validatedRule, detail: "当前账户精确 WebKit 网络进程域的临时 Blob；唯一签名应用已退出", verified: reason == nil)],
                        reason: reason, applicationPath: app.path, displayName: "WebKit 临时文件 · " + app.name)
                }
            }
        }
    }
    private func addSimulatorCaches(builder:inout Builder)throws{
        let root=policy.home+"/Library/Developer/CoreSimulator/Devices"
        do{
            guard try SafeFilesystem.presence(root) else{return}
            let devices=try SimulatorCacheRule.devices(home:policy.home)
            for device in devices {
                let caches=device.dataPath+"/Library/Caches"
                guard try SafeFilesystem.presence(caches) else{continue}
                for leaf in try XcodeArchiveRule.children(caches){
                    let path=caches+"/"+leaf
                    try builder.scoped(root:path){scope in
                        var reason:String?,reference:SimulatorDeviceReference?,title=device.title
                        if policy.ruleIsValidated(SimulatorCacheRule.name){
                            do{
                                (reference,title)=try SimulatorCacheRule.reference(path,home:policy.home,devices:devices)
                                let snapshot=try SafeFilesystem.snapshot(path)
                                guard snapshot.identity.isDirectory else{throw SweepError.denied("松散锁文件和特殊对象保留")}
                                try SimulatorCacheRule.verifyPrivateTree(snapshot,home:policy.home)
                                try BusyInspector.ensureUnused(snapshot)
                                try ActivityInspector.ensureBuildToolsStopped()
                            }catch is CancellationError{throw CancellationError()}
                            catch{reason=error.localizedDescription;if case SweepError.incomplete = error{scope.issues.append(path+"："+error.localizedDescription)}}
                        }else{reason="模拟器缓存尚未通过当前平台验收，仅报告"}
                        try scope.add(path,category:.development,bundleID:nil,rule:SimulatorCacheRule.name,
                            evidence:[.init(kind:.validatedRule,detail:"原生注册、已停止且运行时可用的模拟器；仅独立可再生成缓存子项，运行时、设备资料及共享对象保留",verified:reason == nil)],
                            reason:reason,applicationPath:nil,displayName:"模拟器缓存 · "+title+" · "+leaf)
                        if let index=scope.items.indices.last{scope.items[index].simulatorDevice=reference;scope.items[index].recommendation = .manual}
                    }
                }
            }
        }catch is CancellationError{throw CancellationError()}
        catch{builder.issues.append("模拟器缓存发现未确认："+error.localizedDescription)}
    }
    private func addXcodeDeviceSymbols(builder: inout Builder) throws {
        for root in XcodeDeviceSupportRule.roots(home:policy.home) {
            do {
                guard try SafeFilesystem.presence(root) else{continue}
                for version in try XcodeArchiveRule.children(root) {
                    for suffix in ["Symbols","arm64/Symbols","arm64e/Symbols"] {
                        let path=root + "/" + version + "/" + suffix
                        try builder.scoped(root:path){scope in
                            guard try SafeFilesystem.presence(path) else{return}
                            var reason:String?
                            if policy.ruleIsValidated(XcodeDeviceSupportRule.name) {
                                do{try XcodeDeviceSupportRule.verify(path,home:policy.home);try XcodeDeviceSupportRule.ensureStopped();try BusyInspector.ensureUnused(SafeFilesystem.snapshot(path))}
                                catch is CancellationError{throw CancellationError()}
                                catch{reason=error.localizedDescription;switch error{case SweepError.denied:break;default:scope.issues.append(path + "：" + error.localizedDescription)}}
                            }else{reason="设备符号管理尚未通过当前平台验收，保留调试资料"}
                            try scope.add(path,category:.userData,bundleID:nil,rule:XcodeDeviceSupportRule.name,
                                evidence:[.init(kind:.validatedRule,detail:"标准设备支持位置、原生符号、完整私有对象；调试资料默认保留，需逐份主动选择",verified:reason == nil)],
                                reason:reason,applicationPath:nil,displayName:XcodeDeviceSupportRule.title(path))
                        }
                    }
                }
            }catch is CancellationError{throw CancellationError()}
            catch{builder.issues.append("设备符号发现未确认：" + error.localizedDescription)}
        }
    }
    private func addXcodeArchives(builder: inout Builder) throws {
        let root=policy.home + "/Library/Developer/Xcode/Archives"
        do {
            guard try SafeFilesystem.presence(root) else{return}
            let days=try XcodeArchiveRule.children(root)
            var count=0
            for day in days {
                let names:[String]
                do{names=try XcodeArchiveRule.children(root + "/" + day)}
                catch is CancellationError{throw CancellationError()}
                catch{builder.issues.append("归档日期目录发现未确认：" + error.localizedDescription);continue}
                count += names.count;guard count <= 1000 else{throw SweepError.incomplete("归档数量超过有界扫描容量")}
                for name in names where name.hasSuffix(".xcarchive") {
                    let path=root + "/" + day + "/" + name
                    try builder.scoped(root:path){scope in
                        var reason:String?,title="Xcode 归档（个人资料）"
                        if policy.ruleIsValidated(XcodeArchiveRule.name) {
                            do{title=try XcodeArchiveRule.inspect(path,home:policy.home);try XcodeArchiveRule.ensureStopped();try BusyInspector.ensureUnused(SafeFilesystem.snapshot(path))}
                            catch is CancellationError{throw CancellationError()}
                            catch{
                                reason=error.localizedDescription
                                switch error{case SweepError.denied:break;default:scope.issues.append(path + "：" + error.localizedDescription)}
                            }
                        }else{reason="归档管理尚未通过当前平台验收，保留个人资料"}
                        try scope.add(path,category:.userData,bundleID:nil,rule:XcodeArchiveRule.name,
                            evidence:[.init(kind:.validatedRule,detail:"整份原生 Xcode 归档及当前用户所有权；包含产品和调试历史，默认保留，需逐份主动选择",verified:reason == nil)],
                            reason:reason,applicationPath:nil,displayName:title)
                    }
                }
            }
        }catch is CancellationError{throw CancellationError()}
        catch{builder.issues.append("Xcode 归档发现未确认：" + error.localizedDescription)}
    }
    private func addXcodeGenerated(builder: inout Builder) throws {
        let root=policy.home + "/Library/Developer/Xcode/DerivedData"
        let names:[String]
        do {
            guard try SafeFilesystem.presence(root) else{return}
            _=try SafeDirectory(path:root)
            names=try FileManager.default.contentsOfDirectory(atPath:root)
            guard names.count <= 1000 else{throw SweepError.incomplete("Xcode 派生目录枚举截断")}
        }catch is CancellationError{throw CancellationError()}
        catch {
            builder.issues.append("Xcode 派生目录发现未确认：" + error.localizedDescription)
            builder.reportProtected(root,reason:error.localizedDescription)
            return
        }
        var paths=[root + "/ModuleCache.noindex"]
        for name in names.sorted() where name != "ModuleCache.noindex" {
            paths += [root + "/" + name + "/Build/Products",root + "/" + name + "/Index.noindex"]
        }
        for path in paths {
            try builder.scoped(root:path){scope in
                guard try SafeFilesystem.presence(path) else{return}
                var reason:String?
                if policy.ruleIsValidated(XcodeGeneratedRule.name) {
                    do{try XcodeGeneratedRule.verify(path,home:policy.home);try ActivityInspector.ensureBuildToolsStopped();try BusyInspector.ensureUnused(SafeFilesystem.snapshot(path))}
                    catch is CancellationError{throw CancellationError()}
                    catch{reason=error.localizedDescription}
                }else{reason="此开发产物规则尚未通过当前平台验收，保留"}
                try scope.add(path,category:.development,bundleID:"com.apple.dt.Xcode",rule:XcodeGeneratedRule.name,
                    evidence:[.init(kind:.validatedRule,detail:"标准派生目录；项目产物核对真实工作区；仅完整私有对象，需主动选择，清理后可能需要重新编译",verified:reason == nil)],
                    reason:reason,applicationPath:nil,displayName:XcodeGeneratedRule.title(path))
            }
        }
    }
    private func addApplicationCaches(apps: [ApplicationIdentity], builder: inout Builder, progress: (@Sendable (ScanProgress) -> Void)? = nil) throws {
        guard ApplicationCacheRule.rules.contains(where:policy.ruleIsValidated) else { return }
        var owners=apps.filter{!$0.bundleIdentifier.isEmpty && !$0.bundleIdentifier.hasPrefix("com.apple.")}
        do { owners += try ApplicationCacheRule.systemApplications() }
        catch is CancellationError { throw CancellationError() }
        catch { builder.issues.append("Apple 应用缓存发现未确认：" + error.localizedDescription) }
        for app in owners {
            for rule in ApplicationCacheRule.rules where policy.ruleIsValidated(rule) {
                guard rule != ApplicationCacheRule.appleName || app.bundleIdentifier.hasPrefix("com.apple.") else { continue }
                try scanProgress(progress,stage:"检查应用与容器缓存",detail:app.name,count:builder.items.count)
                let root=ApplicationCacheRule.root(home:policy.home,identifier:app.bundleIdentifier,rule:rule)
                try builder.scoped(root:root) { scope in
                    guard try SafeFilesystem.presence(root) else { return }
                    do {
                        let snapshot=try ApplicationCacheRule.verifyRoot(home:policy.home,identifier:app.bundleIdentifier,applicationPath:app.path,rule:rule)
                        try ActivityInspector.ensureStopped(bundleID:app.bundleIdentifier,applicationPath:app.path,additionalIdentifiers:[app.bundleIdentifier + "."])
                        try ActivityInspector.ensureSystemServicesStopped(identifiers:[app.bundleIdentifier],applicationPath:app.path)
                        try BusyInspector.ensureUnused(snapshot)
                        for member in try CacheDomainRule.members(root:root).sorted() {
                            try scope.add(member,category:.cache,bundleID:app.bundleIdentifier,rule:rule,
                                evidence:[.init(kind:.signature,detail:"应用签名、标识及缓存位置一致；Apple 应用另核验 Apple 签名锚点",verified:true),
                                          .init(kind:.validatedRule,detail:"仅可再生成缓存；容器元数据与沙箱声明一致；原目录及其他用户资料保留，需手动选择",verified:true)],
                                reason:nil,applicationPath:app.path)
                        }
                        try SafeFilesystem.verify(snapshot)
                    } catch is CancellationError { throw CancellationError() }
                    catch {
                        if case SweepError.incomplete = error { scope.issues.append(root + "：" + error.localizedDescription) }
                        // This is a retained discovery root, not an executable
                        // member. Keep the real refusal reason instead of the
                        // member-only path guard obscuring it.
                        var retained=Candidate(id:UUID(),path:root,category:.cache,bundleIdentifier:app.bundleIdentifier,evidence:[],rule:rule,identity:nil,bytes:0,retentionReason:error.localizedDescription)
                        retained.applicationPath=app.path
                        scope.items.append(retained)
                    }
                }
            }
        }
    }
    private func addGodotCaches(apps: [ApplicationIdentity], builder: inout Builder) throws {
        guard policy.ruleIsValidated(GodotCacheRule.name) else { return }
        let root=policy.home + "/Library/Caches/Godot"
        try builder.scoped(root:root) { scope in
            guard try SafeFilesystem.presence(root) else { return }
            do {
                guard let app=apps.first(where:{$0.bundleIdentifier == GodotCacheRule.identifier}) else { throw SweepError.denied("Godot 安装归属未确认，缓存保留") }
                try GodotCacheRule.verifyOwner(application:app.path,home:policy.home,inventory:apps)
                try GodotCacheRule.ensureStopped(application:app.path)
                let snapshot=try GodotCacheRule.verifyNamespace(home:policy.home)
                try BusyInspector.ensureUnused(snapshot)
                for path in try CacheDomainRule.members(root:root).sorted() {
                    let ordinary=snapshot.tree.first(where:{root + "/" + $0.relative == path}).map{!$0.identity.isDirectory} == true
                    let known=ordinary && GodotCacheRule.matches(path,home:policy.home)
                    try scope.add(path,category:.cache,bundleID:app.bundleIdentifier,rule:GodotCacheRule.name,
                        evidence:[.init(kind:.signature,detail:"有效 Godot 签名主体与唯一安装已核对",verified:true),
                                  .init(kind:.validatedRule,detail:"仅编辑器文档缓存和资源预览；预览图及其索引作为同一组；项目与设置保留",verified:known)],
                        reason:known ? nil : "不是已验证的 Godot 缓存文件，保留",applicationPath:app.path)
                }
                try SafeFilesystem.verify(snapshot)
            } catch is CancellationError { throw CancellationError() }
            catch {
                try scope.add(root,category:.cache,bundleID:GodotCacheRule.identifier,rule:GodotCacheRule.name,evidence:[],reason:error.localizedDescription,applicationPath:nil)
            }
        }
    }
    private func addToolCaches(builder:inout Builder,progress:(@Sendable (ScanProgress)->Void)?) throws {
        for (root,producer) in ToolCacheRule.roots(home:policy.home) {
            do {
                guard try SafeFilesystem.presence(root) else{continue}
                let names=try XcodeArchiveRule.children(root)
                var activityIssue:String?
                do{try ToolCacheRule.ensureStopped(producer,home:policy.home)}
                catch is CancellationError{throw CancellationError()}
                catch{activityIssue=error.localizedDescription}
                for name in names {
                    try ScanCancellation.check()
                    let path=root + "/" + name
                    guard ToolCacheRule.location(path,home:policy.home) != nil else{continue}
                    try scanProgress(progress,stage:"检查开发工具缓存",detail:producer.title,count:builder.items.count)
                    try builder.scoped(root:path){scope in
                        if let directory=try? SafeDirectory(path:path),try directory.ownIdentity.isDirectory,
                           try XcodeArchiveRule.children(path).isEmpty {return}
                        var reason=activityIssue
                        if reason == nil {
                            // The producer gate covers discovery. A recursive lsof
                            // for every bucket can consume the entire scan budget;
                            // execute rechecks occupancy before the batch and move.
                            do{_ = try ToolCacheRule.verify(path,home:policy.home)}
                            catch is CancellationError{throw CancellationError()}
                            catch{reason=error.localizedDescription}
                        }
                        try scope.add(path,category:.development,bundleID:nil,rule:producer.rule,evidence:[.init(kind:.validatedRule,detail:"工具公开缓存位置、生成格式、当前用户独占目录；需要时重新构建或下载",verified:reason == nil)],reason:reason,applicationPath:nil,displayName:producer.title + " · " + name)
                    }
                }
            } catch is CancellationError{throw CancellationError()}
            catch{builder.issues.append(root + "：" + error.localizedDescription)}
        }
        for entry in ToolCacheCatalog.entries(home: policy.home) {
            try ScanCancellation.check()
            let represented = builder.items.map(\.path)
            var pending = [entry.path]
            // Descend only along already represented branches. Unknown siblings
            // retain their own explanation, without double-counting known data.
            while let path = pending.popLast() {
                try ScanCancellation.check()
                guard !represented.contains(where: { SafetyPolicy.contains($0, path) }) else { continue }
                if represented.contains(where: { SafetyPolicy.contains(path, $0) }) {
                    do { pending += try XcodeArchiveRule.children(path).map { path + "/" + $0 } }
                    catch is CancellationError { throw CancellationError() }
                    catch { builder.issues.append(path + "：" + error.localizedDescription) }
                } else {
                    try builder.scoped(root: path) { scope in
                        try scope.add(path, category: .development, bundleID: nil, rule: ToolCacheCatalog.rule,
                            evidence: [], reason: entry.reason, applicationPath: nil, displayName: entry.title)
                    }
                }
            }
        }
    }
    private func addUncoveredCacheNamespaces(builder: inout Builder, progress: (@Sendable (ScanProgress) -> Void)? = nil) throws {
        let root = policy.home + "/Library/Caches"
        do {
            guard try SafeFilesystem.presence(root) else { return }
            let directory = try SafeDirectory(path: root), before = try directory.ownIdentity
            let homeDevice = try SafeDirectory(path: policy.home).ownIdentity.device
            guard before.owner == as_current_uid(), before.device == homeDevice else {
                throw SweepError.incomplete("用户缓存目录所有者或卷未确认")
            }
            var buffer = [UInt8](repeating: 0, count: 2 * 1024 * 1024), count = 0
            guard as_directory_entries(directory.fd, &buffer, buffer.count, 4096, &count) == 0,
                  let text = String(bytes: buffer.prefix(count), encoding: .utf8) else {
                throw SweepError.incomplete("用户缓存目录枚举失败或截断，范围未确认")
            }
            try ScanCancellation.check()
            guard try directory.ownIdentity == before, try SafeDirectory(path: root).ownIdentity == before else {
                throw SweepError.incomplete("用户缓存目录在发现期间改变，请重新扫描")
            }
            // Dedicated rules may describe nested browser profiles. Their top
            // namespace is already represented, even when the rule retains it.
            let coveredNamespaces = Set(builder.items.compactMap { item -> String? in
                guard item.path.hasPrefix(root + "/"),
                      let name = item.path.dropFirst(root.count + 1).split(separator:"/").first else { return nil }
                return root + "/" + name
            })
            for name in text.split(separator: "\0").map(String.init).sorted() {
                try ScanCancellation.check()
                let path = root + "/" + name
                guard !coveredNamespaces.contains(path) else { continue }
                try scanProgress(progress,stage:"检查其他缓存位置",detail:name,count:builder.items.count)
                if let child=try? SafeDirectory(path:path),try child.ownIdentity.isDirectory,
                   try XcodeArchiveRule.children(path).isEmpty {continue}
                var retainedReason = "缓存使用者未确认，保留；需要明确归属后才能检查应用是否已关闭"
                // A real producer tag supplies independent cache semantics. Do
                // not infer an owner or a fictional application path from it.
                if (try? SafeFilesystem.presence(path + "/CACHEDIR.TAG")) == true {
                    do {
                        try UserCacheNamespaceRule.verifyProducerTag(root: path, home: policy.home)
                        let snapshot = try UserCacheNamespaceRule.verifyNamespace(path, home: policy.home)
                        try ActivityInspector.ensureUnattributedCacheStopped(namespace: path)
                        try BusyInspector.ensureUnused(snapshot)
                        let members = try CacheDomainRule.members(root: path)
                        if members == [path + "/CACHEDIR.TAG"] { continue }
                        try builder.scoped(root: path) { scope in
                            for member in members.sorted() {
                                try scope.add(member, category: .cache, bundleID: nil, rule: UserCacheNamespaceRule.name,
                                    evidence: [.init(kind: .validatedRule, detail: "生产者 CACHEDIR.TAG 声明、当前用户独占缓存目录、完整文件组与活动检查", verified: true)],
                                    reason: nil, applicationPath: nil, displayName: name + " · 未关联安装的缓存")
                            }
                            try SafeFilesystem.verify(snapshot)
                        }
                        continue
                    } catch is CancellationError { throw CancellationError() }
                    catch { retainedReason = error.localizedDescription }
                }
                // Location and a filename are discovery evidence only. Do not
                // recurse into unknown data, invent an owner, or issue a plan.
                try builder.scoped(root: path) { scope in
                    try scope.add(path, category: .cache, bundleID: nil, rule: "cache-discovery-only-v1",
                              evidence: [.init(kind: .nameHint, detail: "标准用户缓存位置中的项目；名称仅是线索，尚未证明应用归属或可再生成性", verified: false)],
                              reason: retainedReason, applicationPath: nil)
                }
            }
            guard try directory.ownIdentity == before, try SafeDirectory(path: root).ownIdentity == before else {
                throw SweepError.incomplete("用户缓存目录在发现期间改变，结果未确认")
            }
        } catch is CancellationError { throw CancellationError() }
        catch {
            // The namespace inventory supplies no mutation evidence. Its failure
            // is visible, but cannot invalidate a separately verified app domain.
            builder.issues.append(root + "：" + error.localizedDescription)
        }
    }
    /// Discovery is bounded to direct children; each complete object owns its
    /// own scope, so an unknown sibling never authorizes or invalidates it.
    private func addManualData(root:String,rule:String,provenance:String,matches:(String)->Bool,
                               verify:(String)throws->FileSnapshot,builder:inout Builder)throws {
        var names:[String]=[]
        try builder.scoped(root:root) { _ in
            guard try SafeFilesystem.presence(root) else{return}
            names=try XcodeArchiveRule.children(root)
        }
        for name in names {
            try ScanCancellation.check()
            let path=root + "/" + name
            guard matches(path) else{continue}
            try builder.scoped(root:path) { scope in
                var reason:String?
                if policy.ruleIsValidated(rule) {
                    do{try BusyInspector.ensureUnused(verify(path))}
                    catch is CancellationError{throw CancellationError()}
                    catch{
                        reason=error.localizedDescription
                        switch error{case SweepError.denied:break;default:scope.issues.append(path + "：" + error.localizedDescription)}
                    }
                }else{reason="该资料管理规则尚未通过当前平台验收，保留"}
                try scope.add(path,category:.userData,bundleID:nil,rule:rule,
                    evidence:[.init(kind:.validatedRule,detail:provenance,verified:reason == nil)],reason:reason,
                    applicationPath:nil,displayName:name)
            }
        }
    }
    private func addDocumentHistory(builder:inout Builder)throws {
        #if os(macOS)
        let device=try SafeDirectory(path:policy.home).ownIdentity.device
        // Both roots share one bounded budget within the overall scan deadline.
        // Closed document scopes survive timeout; no later native read may add
        // authority after the scan pool has abandoned this stage.
        let deadline=min(scanDeadline ?? .infinity,ProcessInfo.processInfo.systemUptime+30)
        for root in [policy.home + "/Documents",policy.home + "/Desktop"]{
            try ScanCancellation.check()
            guard ProcessInfo.processInfo.systemUptime<deadline else{throw SweepError.incomplete("文稿历史发现已到等待期限，剩余范围保留")}
            var discovered:[String]=[]
            // Discovery supplies no cleanup authority. A document receives its
            // own complete native-version scope below; an unreadable sibling
            // must remain visible without invalidating that independent scope.
            do{
                guard try SafeFilesystem.presence(root) else{continue}
                let base=try SafeDirectory(path:root)
                guard try base.ownIdentity.device == device else{throw SweepError.denied("其他卷的文稿保留")}
                var pending:[(String,Int)]=[(root,0)],visited=0
                while let (directory,depth)=pending.popLast(){
                    try ScanCancellation.check()
                    guard ProcessInfo.processInfo.systemUptime<deadline,depth<=16 else{throw SweepError.incomplete("文稿历史发现超时或截断，范围未确认")}
                    let handle=try SafeDirectory(path:directory),names=try XcodeArchiveRule.children(directory)
                    for name in names{
                        try ScanCancellation.check()
                        guard ProcessInfo.processInfo.systemUptime<deadline else{throw SweepError.incomplete("文稿历史发现已到等待期限，剩余范围保留")}
                        visited+=1;guard visited<=10000 else{throw SweepError.incomplete("文稿数量超出发现容量，范围未确认")}
                        let path=directory + "/" + name,id=try handle.identity(name)
                        guard !id.isLink,id.owner == as_current_uid(),id.device == device,DocumentVersionRule.matches(path,home:policy.home) else{continue}
                        let values=try URL(fileURLWithPath:path).resourceValues(forKeys:[.isPackageKey,.isUbiquitousItemKey])
                        if values.isPackage == true || values.isUbiquitousItem == true{continue}
                        if id.isDirectory{pending.append((path,depth+1))}
                        else if id.mode & 0o170000 == 0o100000{discovered.append(path)}
                    }
                }
            }
            catch is CancellationError{throw CancellationError()}
            catch{builder.issues.append(root + "：" + error.localizedDescription)}
            for path in discovered{
                try ScanCancellation.check()
                guard ProcessInfo.processInfo.systemUptime<deadline else{throw SweepError.incomplete("文稿历史核对已到等待期限，剩余范围保留")}
                try builder.scoped(root:path){scope in
                    guard let versions=NSFileVersion.otherVersionsOfItem(at:URL(fileURLWithPath:path)) else{throw SweepError.incomplete("文稿版本查询未确认")}
                    ScanReadActivity.completed()
                    if versions.isEmpty{return}
                    try scope.add(path,category:.userData,bundleID:nil,rule:DocumentVersionRule.name,evidence:[.init(kind:.validatedRule,detail:"原生本地文稿历史；仅备份并移除历史版本，当前文稿保留；撤销会添加为新的历史版本",verified:true)],reason:nil,applicationPath:nil,displayName:URL(fileURLWithPath:path).lastPathComponent + "（历史版本）")
                }
            }
        }
        #endif
    }
    private func addCorruptPreferences(apps:[ApplicationIdentity],builder:inout Builder)throws {
        for app in apps where SystemCleanupScope.validIdentifier(app.bundleIdentifier) {
            let path=policy.home + "/Library/Preferences/" + app.bundleIdentifier + ".plist"
            try builder.scoped(root:path){ scope in
                guard try SafeFilesystem.presence(path) else{return}
                let inspected=try PreferenceFileInspector.inspect(path:path,home:policy.home,identifier:app.bundleIdentifier)
                guard inspected.status == .malformed else{return}
                var reason:String?
                do{
                    _=try AppInspector.verifiedDataOwner(path:app.path,identifier:app.bundleIdentifier,home:policy.home)
                    guard AppInspector.uniqueOwner(identifier:app.bundleIdentifier,path:app.path,inventory:apps) else{throw SweepError.denied("损坏偏好归属不唯一")}
                    _=try CorruptPreferenceRule.inspect(path:path,home:policy.home,identifier:app.bundleIdentifier)
                    try ActivityInspector.ensureStopped(bundleID:app.bundleIdentifier,applicationPath:app.path)
                }catch is CancellationError{throw CancellationError()}catch{reason=error.localizedDescription}
                try scope.add(path,category:.userData,bundleID:app.bundleIdentifier,rule:CorruptPreferenceRule.name,evidence:[.init(kind:.validatedRule,detail:"已确认格式损坏；独立备份后隔离损坏文件，不清除有效设置。撤销恢复原文件，macOS可能再次丢弃损坏内容，独立副本继续保留",verified:reason == nil)],reason:reason,applicationPath:app.path,displayName:app.name + "（损坏偏好文件）")
            }
        }
    }
    private func addStaleUserAgents(builder:inout Builder)throws {
        let root=policy.home + "/Library/LaunchAgents"
        try builder.scoped(root:root){ scope in
            guard try SafeFilesystem.presence(root) else{return}
            let names=try XcodeArchiveRule.children(root)
            guard names.count<=1000 else{throw SweepError.incomplete("后台项扫描截断，保留")}
            for name in names where name.hasSuffix(".plist") {
                let path=root + "/" + name
                guard StaleUserAgentRule.label(path:path,home:policy.home) != nil else{continue}
                var reason:String?
                do{let declaration=try StaleUserAgentRule.inspect(path,home:policy.home);_=try StaleUserAgentRule.registered(declaration)}
                catch is CancellationError{throw CancellationError()}
                catch{reason=error.localizedDescription}
                try scope.add(path,category:.userData,bundleID:nil,rule:StaleUserAgentRule.name,evidence:[.init(kind:.validatedRule,detail:"精确后台项声明、缺失的整份应用与当前账户注册状态",verified:reason == nil)],reason:reason,applicationPath:nil,displayName:name + "（失效后台项）")
            }
        }
    }
    private func addDeviceBackups(builder: inout Builder) throws {
        let root = DeviceBackupRule.root(home:policy.home)
        var names: [String] = []
        try builder.scoped(root:root) { _ in
            guard try SafeFilesystem.presence(root) else { return }
            _ = try SafeDirectory(path:root)
            names = try FileManager.default.contentsOfDirectory(atPath:root)
            guard names.count <= 1000 else { names = []; throw SweepError.incomplete("设备备份列表超过核对容量") }
        }
        for name in names.sorted() {
            try ScanCancellation.check()
            let path = root + "/" + name
            try builder.scoped(root:path) { scope in
                var reason: String?, displayName: String?, backupDetails: DeviceBackupDetails?, evidence: [OwnershipEvidence] = []
                do {
                    let metadata = try DeviceBackupRule.inspect(path:path,home:policy.home)
                    displayName = metadata.deviceName
                    backupDetails = metadata.details
                    evidence = [.init(kind:.validatedRule,detail:"整份本地设备备份：" + metadata.deviceName + "；记录日期 " + ISO8601DateFormatter().string(from:metadata.date) + "；" + (metadata.encrypted ? "元数据标记为加密" : "元数据标记为未加密") + "。未验证设备恢复有效性。",verified:true)]
                } catch is CancellationError { throw CancellationError() }
                catch { reason = "本地设备备份未确认，已保留：" + error.localizedDescription }
                try scope.add(path,category:.deviceBackup,bundleID:nil,rule:DeviceBackupRule.name,evidence:evidence,reason:reason,applicationPath:nil,displayName:displayName,deviceBackupDetails:backupDetails)
            }
        }
    }
    private func addResidue(app: ApplicationIdentity, trusted: Bool, inventory: [ApplicationIdentity], builder: inout Builder) throws {
        let identifier = app.bundleIdentifier
        let signature = OwnershipEvidence(kind: .signature, detail: "已验证应用：" + app.path, verified: trusted)
        try addApplicationAgents(app:app,trusted:trusted,builder:&builder)
        try addNamedApplication(app:app,trusted:trusted,inventory:inventory,includeData:true,builder:&builder)
        for path in ApplicationStorageRule.paths(home: policy.home, identifier: identifier) {
            try builder.scoped(root: path) { scope in
                guard try SafeFilesystem.presence(path) else { return }
                var reason: String? = trusted ? nil : "应用主体当前不可处理，关联网页资料保留"
                if reason == nil {
                    do { try ApplicationStorageRule.verify(path: path, home: policy.home, identifier: identifier) }
                    catch is CancellationError { throw CancellationError() }
                    catch { reason = error.localizedDescription }
                }
                try scope.add(path, category: .userData, bundleID: identifier, rule: ApplicationStorageRule.name,
                    evidence: [signature, .init(kind: .validatedRule,
                        detail: "精确应用标识的 HTTP/WebKit 资料；签名、唯一安装和独占目录已核对，含网站与登录数据，默认保留",
                        verified: reason == nil)], reason: reason, applicationPath: app.path)
            }
        }
        // Keep the complete inventory for exclusive-owner checks, while limiting
        // uninstall discovery to the selected app rather than every installed app.
        try addDarwinCaches(apps:inventory,applicationPath:app.path,builder:&builder,retainedReason:trusted ? nil : "应用主体当前不可处理，缓存保留；退出后重新核对")
        try addWebKitCaches(apps:inventory,applicationPath:app.path,builder:&builder,retainedReason:trusted ? nil : "应用主体当前不可处理，缓存保留；退出后重新核对")
        if trusted && identifier == GodotCacheRule.identifier {
            // Reuse the same bounded cache rule as junk discovery. A selected
            // application does not authorize the entire named cache directory.
            try addGodotCaches(apps:inventory,builder:&builder)
        }
        if trusted && identifier == "org.mozilla.firefox" {
            try builder.scoped(root:policy.home + "/Library/Application Support/Firefox") { scope in
                try addFirefox(app:app,apps:AppInspector.inventory(home:policy.home),builder:&scope)
            }
        }
        try builder.scoped(root:CacheDomainRule.root(home:policy.home,identifier:identifier)) { scope in
            try addCache(app:app,trusted:trusted,inventory:inventory,builder:&scope)
        }
        try addApplicationLogs(app:app,trusted:trusted,builder:&builder)
        let pref = policy.home + "/Library/Preferences/" + identifier + ".plist"
        try builder.scoped(root:pref) { scope in
            let native = policy.home == (try SystemIdentity.home())
            var reason: String? = trusted ? nil : "缺少唯一已验证的应用主体"
            #if os(macOS)
            if native, reason == nil, try SafeFilesystem.presence(pref) {
                do { _ = try PreferenceDomainService.inspect(path:pref,home:policy.home,identifier:identifier) }
                catch is CancellationError { throw CancellationError() }
                catch { reason = "偏好服务状态未确认，已保留：" + error.localizedDescription;scope.issues.append(pref + "：" + error.localizedDescription) }
            }
            #endif
            // Synthetic-home legacy tests exercise file semantics only. Real
            // users never receive another v1 file-only preference plan.
            try scope.add(pref, category: .userData, bundleID: identifier, rule: native ? PreferenceRecoveryRecord.rule : "cfpreferences-exact-domain-v1", evidence: [signature, .init(kind: .validatedRule, detail: native ? "精确应用偏好服务域；独立备份后清除，默认保留资料，恢复遇到新设置不覆盖" : "旧合成目录文件语义，不代表原生偏好清除", verified: trusted && reason == nil)], reason: reason, applicationPath: app.path)
        }
        let support = SupportDomainRule.path(home: policy.home, identifier: identifier)
        try builder.scoped(root:support) { scope in
            guard try SafeFilesystem.presence(support) else { return }
            var reason: String? = trusted ? nil : "缺少唯一已验证的应用主体，不能授权资料目录"
            if reason == nil {
                do {
                    try ChromiumCacheRule.verifyNoRuntimeOverlap(identifier:identifier,inventory:inventory)
                    try SupportDomainRule.verify(path: support, home: policy.home, identifier: identifier)
                }
                catch is CancellationError { throw CancellationError() }
                catch {
                    reason = error.localizedDescription
                    switch error { case SweepError.incomplete, SweepError.filesystem: scope.issues.append(support + "：" + error.localizedDescription); default: break }
                }
            }
            try scope.add(support, category: .userData, bundleID: identifier, rule: SupportDomainRule.name,
                            evidence: [signature, .init(kind: .validatedRule, detail: "Apple 精确应用域资料约定；签名、唯一安装、所有者及完整目录已核对，需要主动选择用户数据", verified: reason == nil)],
                            reason: reason, applicationPath: app.path)
        }
        let container=policy.home + "/Library/Containers/" + identifier
        try builder.scoped(root:container){scope in
            guard try SafeFilesystem.presence(container) else{return}
            var reason:String?=trusted ? nil : "容器缺少唯一签名主体"
            if reason == nil {
                do {
                    try ContainerDataRule.verifySandbox(path:app.path,identifier:identifier)
                    _=try ContainerDataRule.verify(path:container,home:policy.home,identifier:identifier)
                    try ActivityInspector.ensureStopped(bundleID:identifier,applicationPath:app.path,additionalIdentifiers:[identifier + "."])
                    try ActivityInspector.ensureSystemServicesStopped(identifiers:[identifier],applicationPath:app.path)
                }catch is CancellationError{throw CancellationError()}
                catch{reason=error.localizedDescription;switch error{case SweepError.denied:break;default:scope.issues.append(container + "：" + error.localizedDescription)}}
            }
            try scope.add(container,category:.userData,bundleID:identifier,rule:ContainerDataRule.name,
                evidence:[signature,.init(kind:.containerMetadata,detail:"独立沙箱签名、class2容器标识及当前账户所有权；其他关联应用保留，目录链接不跟随",verified:trusted && reason == nil)],
                reason:reason,applicationPath:app.path,displayName:"应用容器资料（默认保留）")
        }
        let scripts=policy.home + "/Library/Application Scripts/" + identifier
        try builder.scoped(root:scripts){scope in
            guard try SafeFilesystem.presence(scripts) else{return}
            var reason:String?=trusted && AppInspector.signatureMatches(path:app.path,identifier:identifier) ? nil : "应用脚本缺少唯一匹配的代码签名标识"
            if reason == nil {
                do {
                    try ApplicationScriptsRule.verify(scripts,home:policy.home,identifier:identifier)
                    try ActivityInspector.ensureStopped(bundleID:identifier,applicationPath:app.path,additionalIdentifiers:[identifier + "."])
                    try ActivityInspector.ensureSystemServicesStopped(identifiers:[identifier],applicationPath:app.path)
                    try BusyInspector.ensureUnused(SafeFilesystem.snapshot(scripts,allowInternalLinks:true,purpose:.managedData))
                }catch is CancellationError{throw CancellationError()}
                catch{reason=error.localizedDescription;switch error{case SweepError.denied:break;default:scope.issues.append(scripts + "：" + error.localizedDescription)}}
            }
            try scope.add(scripts,category:.userData,bundleID:identifier,rule:ApplicationScriptsRule.name,
                evidence:[signature,.init(kind:.validatedRule,detail:"Apple应用脚本目录API按代码签名标识关联；完整私有对象、不执行脚本，默认保留资料",verified:reason == nil)],
                reason:reason,applicationPath:app.path,displayName:"应用专用脚本（默认保留）")
        }
        var declaredGroupPaths=Set<String>()
        if trusted {
            do {
                let declarations=try ApplicationGroupRule.declarations(applicationPath:app.path,identifier:identifier)
                for group in declarations.keys.sorted() {
                    let path=policy.home + "/Library/Group Containers/" + group
                    declaredGroupPaths.insert(path)
                    try builder.scoped(root:path){scope in
                        guard try SafeFilesystem.presence(path) else{return}
                        var reason:String?
                        do {
                            try ApplicationGroupRule.verify(path:path,home:policy.home,signaturePath:app.path,originalApplicationPath:app.path,identifier:identifier,inventory:inventory)
                            try BusyInspector.ensureUnused(SafeFilesystem.snapshot(path,allowInternalLinks:true,purpose:.managedData))
                        }catch is CancellationError{throw CancellationError()}
                        catch{reason=error.localizedDescription;switch error{case SweepError.denied:break;default:scope.issues.append(path + "：" + error.localizedDescription)}}
                        try scope.add(path,category:.userData,bundleID:identifier,rule:ApplicationGroupRule.name,
                            evidence:[signature,.init(kind:.containerMetadata,detail:"签名组声明、原生class7创建者、当前UID及其他安装/组件的组引用均已核对；共享或未知保留",verified:reason == nil)],
                            reason:reason,applicationPath:app.path,displayName:"应用组资料（仅当前应用使用时可选）")
                    }
                }
            }catch is CancellationError{throw CancellationError()}
            catch{builder.issues.append("应用组声明未确认：" + error.localizedDescription)}
        }
        // Vendor/name hints never authorise shared resources or launch state.
        for root in [policy.home + "/Library/Group Containers", policy.home + "/Library/LaunchAgents"] {
            try builder.scoped(root:root) { scope in
                guard try SafeFilesystem.presence(root) else { return }
                _ = try SafeDirectory(path: root)
                for name in try FileManager.default.contentsOfDirectory(atPath: root) where name.contains(identifier) {
                    if declaredGroupPaths.contains(root + "/" + name){continue}
                    try scope.add(root + "/" + name, category: .protected, bundleID: identifier, rule: "shared-discovery-only-v1", evidence: [.init(kind: .nameHint, detail: "仅用于发现", verified: false)], reason: "共享资源或后台状态，首版保留", applicationPath: app.path)
                }
            }
        }
    }
    private func addCache(app: ApplicationIdentity, trusted: Bool, inventory: [ApplicationIdentity], builder: inout Builder) throws {
        if policy.ruleIsValidated(CacheDomainRule.name) {
            try addCacheDomain(app: app, trusted: trusted, inventory:inventory, builder: &builder)
            return
        }
        let root = policy.home + "/Library/Caches/" + app.bundleIdentifier
        guard try SafeFilesystem.presence(root) else { return }
        let payload = CacheRule.path(home: policy.home, identifier: app.bundleIdentifier)
        var reason = "未识别出可独立确认的缓存格式，当前保留"
        do {
            guard trusted, !app.path.isEmpty else { throw SweepError.denied("缺少唯一已验证的应用主体，缓存归属未确认") }
            let signed = try AppInspector.inspect(app.path)
            guard signed.signed, signed.protectedReason == nil, signed.bundleIdentifier == app.bundleIdentifier else { throw SweepError.denied("应用签名或受保护状态未确认") }
            guard try SafeFilesystem.presence(payload) else { throw SweepError.denied(reason) }
            try ActivityInspector.ensureStopped(bundleID: app.bundleIdentifier, applicationPath: app.path)
            try CacheRule.verify(path: payload, home: policy.home, identifier: app.bundleIdentifier)
            for entry in try SafeFilesystem.snapshot(payload).tree {
                try ScanCancellation.check()
                try builder.add(payload + "/" + entry.relative, category: .cache, bundleID: app.bundleIdentifier, rule: CacheRule.name,
                            evidence: [.init(kind: .signature, detail: "签名与唯一应用标识一致", verified: true), .init(kind: .validatedRule, detail: "Foundation HTTP 元数据确认的响应文件；保留缓存目录身份与数据库", verified: true)], reason: nil, applicationPath: app.path)
            }
            reason = "其他内容保留；仅已确认的网络缓存载荷提供选择"
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            reason = error.localizedDescription
            switch error {
            case SweepError.incomplete, SweepError.filesystem: builder.issues.append(root + "：" + reason)
            default: break
            }
        }
        try builder.add(root, category: .cache, bundleID: app.bundleIdentifier, rule: "cache-unvalidated-v1", evidence: [.init(kind: .bundleIdentifier, detail: app.bundleIdentifier, verified: false)], reason: reason, applicationPath: app.path)
    }
    private func addChromiumProfile(app: ApplicationIdentity, trusted: Bool, inventory: [ApplicationIdentity], builder: inout Builder) throws {
        guard !app.path.isEmpty else { return }
        let info = try AppInspector.metadata(app.path,component:!app.path.hasSuffix(".app")).0
        guard info["CrProductDirName"] != nil || app.bundleIdentifier == "com.google.Chrome" else { return }
        let value: String
        do {
            if trusted { value = try ChromiumCacheRule.runtimeNamespace(path:app.path,identifier:app.bundleIdentifier) }
            else {
                guard let hint = ChromiumCacheRule.discoveryNamespace(info: info, identifier: app.bundleIdentifier) else { throw SweepError.denied("浏览器资料命名空间未确认") }
                value = hint
            }
        }
        catch is CancellationError { throw CancellationError() }
        catch { builder.issues.append(app.path + "：浏览器用户资料目录未确认：" + error.localizedDescription); return }
        let root = policy.home + "/Library/Application Support/" + value
        try builder.scoped(root:root) { scope in
            guard try SafeFilesystem.presence(root) else { return }
            var reason: String? = trusted ? nil : "浏览器资料缺少唯一已验证的应用主体"
            if reason == nil {
                do {
                    try ActivityInspector.ensureStopped(bundleID:app.bundleIdentifier,applicationPath:app.path)
                    _ = try ChromiumProfileRule.verify(path:root,home:policy.home,identifier:app.bundleIdentifier,applicationPath:app.path,signaturePath:nil,inventory:inventory)
                } catch is CancellationError { throw CancellationError() }
                catch { reason = error.localizedDescription }
            }
            try scope.add(root,category:.userData,bundleID:app.bundleIdentifier,rule:ChromiumProfileRule.name,
                          evidence:[.init(kind:.validatedRule,detail:"签名运行时目录、唯一安装与完整配置档已核对；包含书签、历史和设置等个人资料，默认保留",verified:reason == nil)],reason:reason,applicationPath:app.path)
        }
    }
    private func addComponentResidue(app: ApplicationIdentity, trusted: Bool, inventory: [ApplicationIdentity], builder: inout Builder) throws {
        var seen=Set<String>()
        for child in inventory.sorted(by:{$0.path < $1.path}) where child.path.hasPrefix(app.path + "/Contents/") && AppInspector.validIdentifier(child.bundleIdentifier) && child.bundleIdentifier != app.bundleIdentifier {
            guard seen.insert(child.bundleIdentifier).inserted else{continue}
            let reference=ApplicationComponentReference(ownerIdentifier:app.bundleIdentifier,relativePath:String(child.path.dropFirst(app.path.count+1)))
            guard ApplicationComponentRule.valid(reference) else{continue}
            let identifier=child.bundleIdentifier
            var ownerReason:String?
            do {
                guard trusted else{throw SweepError.denied("外层应用尚不能处理，关联组件资料保留")}
                _=try ApplicationComponentRule.verifyOwner(reference,application:app.path,identifier:identifier,home:policy.home,inventory:inventory)
                try ActivityInspector.ensureStopped(bundleID:identifier,applicationPath:app.path,additionalIdentifiers:[app.bundleIdentifier,identifier + "."])
            } catch is CancellationError {throw CancellationError()}
            catch {ownerReason=error.localizedDescription}
            var locations:[(String,CandidateCategory,String)]=[
                (CacheDomainRule.root(home:policy.home,identifier:identifier),.cache,CacheDomainRule.name),
                (SupportDomainRule.path(home:policy.home,identifier:identifier),.userData,SupportDomainRule.name),
                (policy.home + "/Library/Preferences/" + identifier + ".plist",.userData,PreferenceRecoveryRecord.rule)]
            if let darwin=policy.darwinScope {locations.append((darwin.root + "/" + identifier,.cache,DarwinCacheRule.name))}
            for (root,category,rule) in locations {
                try builder.scoped(root:root) { scope in
                    guard try SafeFilesystem.presence(root) else{return}
                    func add(_ path:String,reason:String?) throws {
                        try scope.add(path,category:category,bundleID:identifier,rule:rule,
                            evidence:[.init(kind:.signature,detail:"外层应用签名保护的内嵌组件：" + reference.relativePath,verified:reason == nil)],
                            reason:reason,applicationPath:app.path)
                        if let index=scope.items.indices.last {scope.items[index].component=reference}
                    }
                    if let ownerReason {try add(root,reason:ownerReason);return}
                    do {
                        if category == .cache {
                            if rule == DarwinCacheRule.name {
                                guard let darwin=policy.darwinScope else{throw SweepError.denied("组件缓存账户范围未确认")}
                                _=try DarwinCacheRule.verifyRoot(identifier:identifier,scope:darwin)
                            } else {_=try CacheDomainRule.verifyDomain(root:root)}
                            for member in try CacheDomainRule.members(root:root).sorted() {try add(member,reason:nil)}
                        } else if rule == SupportDomainRule.name {
                            try SupportDomainRule.verify(path:root,home:policy.home,identifier:identifier)
                            try add(root,reason:nil)
                        } else {
                            guard policy.home == (try SystemIdentity.home()) else{throw SweepError.denied("此测试范围不使用当前账户偏好服务")}
                            #if os(macOS)
                            _=try PreferenceDomainService.inspect(path:root,home:policy.home,identifier:identifier)
                            #endif
                            try add(root,reason:nil)
                        }
                    } catch is CancellationError {throw CancellationError()}
                    catch {try add(root,reason:error.localizedDescription)}
                }
            }
            if child.path.contains("/Contents/Library/LoginItems/") {
                try builder.scoped(root:child.path) { scope in
                    try scope.add(child.path,category:.backgroundComponent,bundleID:identifier,rule:"embedded-login-reference-v1",evidence:[],reason:"内嵌登录组件包含在完整应用主体内，将随主体一起处理，无需重复选择",applicationPath:app.path)
                }
            }
        }
    }
    private func addNamedApplication(app: ApplicationIdentity, trusted: Bool, inventory: [ApplicationIdentity], includeData: Bool, builder: inout Builder) throws {
        guard NamedApplicationRule.domain(app.bundleIdentifier) != nil else{return}
        let identifier=app.bundleIdentifier
        var ownerReason:String?
        do {
            guard trusted else{throw SweepError.denied("缺少唯一可处理的应用主体，名称关联项保留")}
            try NamedApplicationRule.verifyOwner(application:app.path,identifier:identifier,home:policy.home,inventory:inventory)
            try ActivityInspector.ensureStopped(bundleID:identifier,applicationPath:app.path,additionalIdentifiers:[identifier + "."])
            try ActivityInspector.ensureSystemServicesStopped(identifiers:[identifier],applicationPath:app.path)
        } catch is CancellationError {throw CancellationError()}
        catch {ownerReason=error.localizedDescription}
        for cache in includeData ? [true,false] : [true] {
            guard let root=NamedApplicationRule.root(home:policy.home,identifier:identifier,cache:cache) else{continue}
            try builder.scoped(root:root) { scope in
                guard try SafeFilesystem.presence(root) else{return}
                let rule=cache ? NamedApplicationRule.cacheName : NamedApplicationRule.dataName
                let category:CandidateCategory=cache ? .cache : .userData
                if let ownerReason {
                    try scope.add(root,category:category,bundleID:identifier,rule:rule,evidence:[],reason:ownerReason,applicationPath:app.path)
                    return
                }
                let members = cache || identifier == GodotCacheRule.identifier ? try CacheDomainRule.members(root:root).sorted() : [root]
                for path in members {
                    var reason:String?
                    do {try NamedApplicationRule.verify(path,home:policy.home,identifier:identifier,cache:cache)}
                    catch is CancellationError {throw CancellationError()}
                    catch {reason = identifier == GodotCacheRule.identifier && URL(fileURLWithPath:path).lastPathComponent == "app_userdata" ? "游戏和项目存档可能被其他应用使用，卸载编辑器时保留" : error.localizedDescription}
                    try scope.add(path,category:category,bundleID:identifier,rule:rule,
                        evidence:[.init(kind:.signature,detail:"原始发布者、完整签名及唯一安装已核对",verified:true),
                                  .init(kind:.validatedRule,detail:cache ? "生产者公开约定的可再生成缓存；完整独立副本支持恢复" : "生产者公开约定的用户资料；主动选择后处理，保留共享内容",verified:reason == nil)],
                        reason:reason,applicationPath:app.path)
                }
            }
        }
    }
    private func addChromiumCaches(app: ApplicationIdentity, trusted: Bool, inventory: [ApplicationIdentity], builder: inout Builder) throws {
        guard !app.path.isEmpty else { return }
        let info: [String:Any]
        do { info = try AppInspector.metadata(app.path,component:!app.path.hasSuffix(".app")).0 }
        catch is CancellationError { throw CancellationError() }
        catch { builder.issues.append(app.path + "：浏览器命名空间未确认：" + error.localizedDescription); return }
        guard info["CrProductDirName"] != nil || app.bundleIdentifier == "com.google.Chrome" else { return }
        let roots: [String]
        do {
            guard trusted else { throw SweepError.denied("浏览器缓存缺少唯一已验证的应用主体") }
            roots = try ChromiumCacheRule.roots(home:policy.home,app:app,inventory:inventory)
        } catch is CancellationError { throw CancellationError() }
        catch {
            let reason = error.localizedDescription
            // Presence-only hints retain the refusal and require no repeated
            // full signature checks. They never grant a selectable action.
            if let value = ChromiumCacheRule.discoveryNamespace(info: info, identifier: app.bundleIdentifier) {
                let root = policy.home + "/Library/Caches/" + value
                try builder.scoped(root:root) { scope in
                    try scope.add(root,category:.cache,bundleID:app.bundleIdentifier,rule:ChromiumCacheRule.name,evidence:[],reason:reason,applicationPath:app.path)
                }
            } else { builder.issues.append(app.path + "：" + reason) }
            return
        }
        for root in roots {
            try builder.scoped(root:root) { scope in
                guard try SafeFilesystem.presence(root) else { return }
                try ActivityInspector.ensureStopped(bundleID:app.bundleIdentifier,applicationPath:app.path)
                let snapshot = try CacheDomainRule.verifyDomain(root:root)
                let direct = snapshot.tree.filter { !$0.relative.contains("/") }
                guard let first = direct.first else { return }
                guard try ChromiumCacheRule.verifiedRoot(path:root + "/" + first.relative,home:policy.home,identifier:app.bundleIdentifier,applicationPath:app.path,signaturePath:nil,inventory:inventory) == root else { throw SweepError.denied("浏览器缓存域已变化") }
                for entry in direct {
                    let path = root + "/" + entry.relative
                    try CacheDomainRule.verifyMember(path:path,root:root,home:policy.home)
                    try scope.add(path,category:.cache,bundleID:app.bundleIdentifier,rule:ChromiumCacheRule.name,
                                  evidence:[.init(kind:.signature,detail:"唯一签名应用声明的浏览器命名空间；已核对同域及重叠安装",verified:true),
                                            .init(kind:.validatedRule,detail:"注册配置档与用户资料分离的缓存域；整组独立备份，保留根目录身份",verified:true)],
                                  reason:nil,applicationPath:app.path)
                }
                try SafeFilesystem.verify(snapshot)
            }
        }
    }
    private func addCacheDomain(app: ApplicationIdentity, trusted: Bool, inventory: [ApplicationIdentity], builder: inout Builder) throws {
        let root = CacheDomainRule.root(home: policy.home, identifier: app.bundleIdentifier)
        guard try SafeFilesystem.presence(root) else { return }
        do {
            guard trusted, !app.path.isEmpty else { throw SweepError.denied("缓存缺少唯一已验证的应用主体") }
            try ChromiumCacheRule.verifyNoRuntimeOverlap(identifier:app.bundleIdentifier,inventory:inventory)
            _ = try AppInspector.verifiedDataOwner(path: app.path, identifier: app.bundleIdentifier, home: policy.home)
            try ActivityInspector.ensureStopped(bundleID: app.bundleIdentifier, applicationPath: app.path)
            let snapshot = try CacheDomainRule.verifyDomain(home: policy.home, identifier: app.bundleIdentifier)
            for entry in snapshot.tree where !entry.relative.contains("/") {
                try ScanCancellation.check()
                let path = root + "/" + entry.relative
                try CacheDomainRule.verify(path: path, home: policy.home, identifier: app.bundleIdentifier)
                try builder.add(path, category: .cache, bundleID: app.bundleIdentifier, rule: CacheDomainRule.name,
                                evidence: [.init(kind: .signature, detail: "精确应用标识、唯一安装及签名一致", verified: true),
                                           .init(kind: .validatedRule, detail: "Apple可再生成缓存目录约定；完整域无链接且当前用户独占，保留根目录身份", verified: true)],
                                reason: nil, applicationPath: app.path)
            }
            try SafeFilesystem.verify(snapshot)
        } catch is CancellationError { throw CancellationError() }
        catch {
            switch error {
            case SweepError.denied: break
            default: builder.issues.append(root + "：" + error.localizedDescription)
            }
            try builder.add(root, category: .cache, bundleID: app.bundleIdentifier, rule: "cache-unvalidated-v1", evidence: [], reason: error.localizedDescription, applicationPath: app.path)
        }
    }
    private func addFirefox(app: ApplicationIdentity, apps: [ApplicationIdentity], builder: inout Builder) throws {
        let root = policy.home + "/Library/Application Support/Firefox/profiles.ini"
        guard try SafeFilesystem.presence(root) else { return }
        do {
            let leaves = try FirefoxRule.registeredLeaves(home: policy.home)
            let unique = AppInspector.uniqueOwner(identifier: app.bundleIdentifier, path: app.path, inventory: apps) && FirefoxRule.externalFamilyOwners(applicationPath:app.path,inventory:apps).isEmpty
            let formatRule = policy.ruleIsValidated(FirefoxFormatRule.name)
            for leaf in leaves {
                let path = policy.home + "/Library/Caches/Firefox/Profiles/" + leaf + "/cache2"
                guard try SafeFilesystem.presence(path) else { continue }
                var reason: String?
                do {
                    guard unique else { throw SweepError.denied("存在其他 Mozilla 应用，独占归属未确认") }
                    if formatRule { try FirefoxFormatRule.verify(path, home: policy.home, applicationPath: app.path) }
                    else { try FirefoxRule.verify(path, home: policy.home, applicationPath: app.path) }
                } catch is CancellationError { throw CancellationError() }
                catch {
                    reason = error.localizedDescription
                    switch error { case SweepError.incomplete, SweepError.filesystem: builder.issues.append(path + "：" + error.localizedDescription); default: break }
                }
                try builder.add(path, category: .cache, bundleID: app.bundleIdentifier, rule: formatRule ? FirefoxFormatRule.name : FirefoxRule.name,
                            evidence: [.init(kind: .validatedRule, detail: formatRule ? "Firefox 官方签名、注册配置档、当前构建匹配及已识别的明文 HTTP 缓存格式" : "Firefox 158.0 官方签名、注册配置档与精确 cache2 结构", verified: reason == nil)], reason: reason, applicationPath: app.path)
            }
        } catch is CancellationError { throw CancellationError() }
        catch { builder.issues.append("Firefox 缓存归属未确认：" + error.localizedDescription) }
    }
    private func addApplicationLogs(app: ApplicationIdentity, trusted: Bool, builder: inout Builder) throws {
        let root=ApplicationLogRule.root(home:policy.home,identifier:app.bundleIdentifier)
        let current=policy.ruleIsValidated(ApplicationLogRule.currentName)
        let rule=current ? ApplicationLogRule.currentName : ApplicationLogRule.name
        var owner: (authorized:Bool,reason:String?)?
        func ownership() throws -> (authorized:Bool,reason:String?) {
            if let owner { return owner }
            let signed=try? AppInspector.verifiedDataOwner(path:app.path,identifier:app.bundleIdentifier,home:policy.home)
            let authorized=trusted && signed != nil
            var reason:String?=authorized ? nil : "应用日志缺少唯一已验证的签名主体"
            if reason == nil {
                do { try ActivityInspector.ensureStopped(bundleID:app.bundleIdentifier,applicationPath:app.path) }
                catch is CancellationError { throw CancellationError() }
                catch { reason=error.localizedDescription }
            }
            owner=(authorized,reason);return (authorized,reason)
        }
        func add(_ path: String, to scope: inout Builder) throws {
            let state=try ownership();var reason=state.reason
            if reason == nil {
                do {
                    if current { try ApplicationLogRule.verifyCurrent(path:path,home:policy.home,identifier:app.bundleIdentifier) }
                    else { try ApplicationLogRule.verify(path:path,home:policy.home,identifier:app.bundleIdentifier) }
                } catch is CancellationError { throw CancellationError() }
                catch { reason=error.localizedDescription }
            }
            try scope.add(path,category:.log,bundleID:app.bundleIdentifier,rule:rule,
                evidence:[.init(kind:.signature,detail:"精确应用标识、唯一安装及签名一致",verified:state.authorized),
                          .init(kind:.validatedRule,detail:current ? "独占普通应用日志；较新日志需手动选择，旧日志保留推荐" : "当前用户独占日志域内超过30天的普通日志及数字轮转文件",verified:reason == nil)],
                reason:reason,applicationPath:app.path)
        }
        try builder.scoped(root:root) { scope in
            guard try SafeFilesystem.presence(root) else { return }
            let snapshot=try SafeFilesystem.snapshot(root)
            guard snapshot.identity.isDirectory else { throw SweepError.denied("应用日志命名空间不是目录") }
            for entry in snapshot.tree where !entry.identity.isDirectory {
                try ScanCancellation.check()
                let path=root + "/" + entry.relative
                guard ApplicationLogRule.matches(path:path,home:policy.home,identifier:app.bundleIdentifier) else { continue }
                try add(path,to:&scope)
            }
            try SafeFilesystem.verify(snapshot)
        }
        if current {
            do {
                for path in try ApplicationLogRule.loosePaths(home:policy.home,identifier:app.bundleIdentifier) {
                    try builder.scoped(root:path) { scope in try add(path,to:&scope) }
                }
            } catch is CancellationError { throw CancellationError() }
            catch { builder.issues.append(policy.home + "/Library/Logs：松散日志发现未确认，独立已核验范围继续保留：" + error.localizedDescription) }
        }
    }
    private func addCrashReports(apps: [ApplicationIdentity], builder: inout Builder) throws {
        let root = policy.home + "/Library/Logs/DiagnosticReports"
        guard try SafeFilesystem.presence(root) else { return }
        let handle = try SafeDirectory(path: root)
        let names = try FileManager.default.contentsOfDirectory(atPath: root)
        guard names.count < 5000 else { throw SweepError.denied("崩溃报告扫描截断") }
        // One scan may contain many reports from one app. Reuse ownership and
        // activity findings only within this scan; execute revalidates every plan.
        var ownership: [String: (path: String?, verified: Bool, reason: String?)] = [:]
        for name in names where name.hasSuffix(".ips") || name.hasSuffix(".crash") {
            try ScanCancellation.check()
            let identity = try handle.identity(name)
            guard !identity.isLink, identity.links == 1, identity.size < 2 * 1024 * 1024, Attribution.oldLog(modified: Date(timeIntervalSince1970: Double(identity.modifiedSeconds)), now: Date()) else { continue }
            guard identity.mode & 0o170000 == 0o100000 else { builder.issues.append("诊断报告不是普通文件，未确认：" + name); continue }
            let data = try SafeFilesystem.readMetadata(root + "/" + name)
            let legacy = name.hasSuffix(".crash")
            guard let identifier = legacy ? LegacyCrashRule.headerIdentifier(data) : DiagnosticRule.headerIdentifier(data) else { continue }
            if ownership[identifier] == nil {
                let owners = apps.filter { $0.bundleIdentifier == identifier }
                let path = owners.count == 1 ? owners[0].path : nil
                var verified = false, reason: String? = "诊断报告归属或应用签名未确认"
                if let path, AppInspector.uniqueOwner(identifier: identifier, path: path, inventory: apps) {
                    do {
                        // Declarations alone are not installed dependencies.
                        _ = try AppInspector.verifiedDataOwner(path: path, identifier: identifier, home: policy.home)
                        verified = true
                        try ActivityInspector.ensureStopped(bundleID: identifier, applicationPath: path)
                        reason = nil
                    } catch is CancellationError { throw CancellationError() }
                    catch { reason = error.localizedDescription }
                }
                ownership[identifier] = (path, verified, reason)
            }
            guard let owner = ownership[identifier] else { throw SweepError.incomplete("诊断归属核验未完成") }
            let path = owner.path
            let trusted = owner.verified && path.map {
                (legacy ? LegacyCrashRule.owns(data, identifier: identifier, applicationPath: $0) : DiagnosticRule.owns(data, identifier: identifier, applicationPath: $0))
            } == true
            try builder.add(root + "/" + name, category: .log, bundleID: identifier, rule: legacy ? LegacyCrashRule.name : "ips-third-party-30d-v1", evidence: [.init(kind: .signature, detail: "唯一应用签名与诊断报告标识一致", verified: trusted), .init(kind: .validatedRule, detail: legacy ? "超过 30 天；文字报告头标识及可执行路径精确匹配" : "超过 30 天；报告头、正文应用标识及可执行路径精确匹配", verified: trusted)], reason: trusted ? owner.reason : "诊断报告归属或应用签名未确认", applicationPath: path)
        }
    }
    private func addApplicationAgents(app:ApplicationIdentity,trusted:Bool,builder:inout Builder)throws {
        guard !app.path.isEmpty else{return}
        let root=policy.home+"/Library/LaunchAgents"
        // An unreadable reference directory blocks this app's body scope; it
        // cannot be treated as a successful empty dependency inventory.
        try builder.scoped(root:app.path){scope in
            guard try SafeFilesystem.presence(root) else{return}
            let names=try XcodeArchiveRule.children(root)
            for name in names where name.hasSuffix(".plist"){
                let path=root+"/"+name
                guard try ApplicationAgentRule.references(path,application:app.path) else{continue}
                var reason:String?=trusted ? nil : "后台项缺少唯一签名主体"
                if reason == nil{
                    do{_=try ApplicationAgentRule.inspect(path,home:policy.home,application:app.path,identifier:app.bundleIdentifier)}
                    catch is CancellationError{throw CancellationError()}
                    catch{reason=error.localizedDescription}
                }
                try scope.add(path,category:.backgroundComponent,bundleID:app.bundleIdentifier,rule:ApplicationAgentRule.name,
                    evidence:[.init(kind:.signature,detail:"唯一签名主体及精确包内程序引用；后台项停止后先注销，再处理主体",verified:reason == nil)],reason:reason,applicationPath:app.path,displayName:"应用后台组件 · "+name)
            }
        }
    }
    struct Builder: Sendable {
        let policy: SafetyPolicy
        var items: [Candidate] = []; var snapshots: [UUID: FileSnapshot] = [:]; var issues: [String] = []
        var scopes: [ScanScope] = []
        fileprivate var scopeCheckpoint: ScanStageCheckpoint?
        fileprivate var scopeProgress: (@Sendable (Int) -> Void)?
        private var scopeDepth=0
        init(policy: SafetyPolicy) { self.policy=policy }
        mutating func scoped(root: String, _ operation: (inout Builder) throws -> Void) throws {
            try ScanCancellation.check()
            let outermost=scopeDepth == 0
            if outermost { scopeCheckpoint?.begin(root) }
            scopeDepth += 1
            let start = items.count, issueStart = issues.count
            do { try operation(&self) }
            catch is CancellationError { scopeDepth -= 1;throw CancellationError() }
            catch { issues.append(root + "：" + error.localizedDescription) }
            let failures = Array(issues.dropFirst(issueStart)), id = UUID().uuidString
            for index in start..<items.count { items[index].scanScopeID = id }
            scopes.append(ScanScope(id: id, root: root, complete: failures.isEmpty,
                                    candidateIDs: items[start...].map(\.id), issues: failures))
            scopeDepth -= 1
            if outermost { scopeCheckpoint?.accept(self);scopeProgress?(items.count) }
        }
        mutating func add(_ path: String, category: CandidateCategory, bundleID: String?, rule: String, evidence: [OwnershipEvidence], reason: String?, applicationPath: String?, displayName: String? = nil, deviceBackupDetails: DeviceBackupDetails? = nil) throws {
            try ScanCancellation.check()
            do { guard try SafeFilesystem.presence(path) else { return } }
            catch {
                issues.append(path + "：" + error.localizedDescription)
                items.append(Candidate(id: UUID(), path: path, category: category, bundleIdentifier: bundleID, evidence: evidence, rule: rule, identity: nil, bytes: 0, retentionReason: "存在性未确认：" + error.localizedDescription))
                return
            }
            let id = UUID(); var historyBytes:Int64?; var snapshot: FileSnapshot?; var effectiveRule = rule; var retention = policy.denial(path: path, category: category, rule: rule) ?? reason
            if retention == nil && !policy.ruleIsValidated(rule) { retention = "该规则尚未独立通过原生验收，仅报告" }
            // A retained discovery hint is not recursively scanned or measured.
            if retention == nil {
                do { snapshot = try SafeFilesystem.snapshot(path, allowInternalLinks: category == .application || [ContainerDataRule.name,ApplicationScriptsRule.name,ApplicationGroupRule.name,DownloadCacheRule.builderName,AIStorageRule.name].contains(rule), purpose: category == .application ? .application : ([DeviceBackupRule.name,ContainerDataRule.name,ApplicationScriptsRule.name,ApplicationGroupRule.name,TrashEntryRule.name,MailDownloadRule.name,AIStorageRule.name].contains(rule) ? .managedData : .ordinary), allowInternalHardLinks: CacheArchive.supports(rule), allowApplicationHardLinks: category == .application) }
                catch is CancellationError { throw CancellationError() }
                catch SweepError.denied(let reason) { retention = reason }
                catch { retention = "文件身份未确认：" + error.localizedDescription; issues.append(path + "：" + error.localizedDescription) }
            }
            #if os(macOS)
            if rule == DocumentVersionRule.name,retention == nil{
                do{let selection=try DocumentHistoryTransaction.inspect(path,home:policy.home);snapshot=selection.document;snapshot?.contentDigest=selection.digest;historyBytes=selection.bytes}
                catch is CancellationError{throw CancellationError()}
                catch{retention="历史版本未确认：" + error.localizedDescription;issues.append(path + "：" + error.localizedDescription)}
            }
            #endif
            if rule == DeviceBackupRule.name, retention == nil, let snapshot {
                do {
                    try DeviceBackupRule.verifyTree(snapshot)
                    if snapshot.tree.count > TreeFingerprint.inlineLimit && !policy.ruleIsValidated(DeviceBackupRule.largeName) { retention = "大型设备备份尚未独立完成平台验收，整份保留" }
                } catch is CancellationError { throw CancellationError() }
                catch { retention = error.localizedDescription; issues.append(path + "：" + error.localizedDescription) }
            }
            if category == .application, let snapshot, snapshot.tree.count > TreeFingerprint.inlineLimit {
                if rule != SelectedApplicationRule.name { effectiveRule = ChosenApplicationRule.largeName }
                if !policy.ruleIsValidated(ChosenApplicationRule.largeName) { retention = "当前平台的大型应用规则尚未独立完成验收，仅报告" }
            }
            #if os(macOS)
            if retention == nil, category == .application, let snapshot {
                do { try BusyInspector.ensureUnused(snapshot,allowReadOnlyLocalization:policy.systemScope == nil && policy.ruleIsValidated(LocalizedResourceReader.name)) }
                catch is CancellationError { throw CancellationError() }
                catch { retention = error.localizedDescription }
            }
            #endif
            if rule == "cfpreferences-exact-domain-v1", let snapshot, snapshot.identity.isDirectory { retention = "偏好域对象不是普通文件，归属未确认" }
            if [PreferenceRecoveryRecord.rule,CorruptPreferenceRule.name].contains(rule), retention == nil, let original=snapshot {
                do { snapshot?.contentDigest = try VerifiedFileStream.digest(original) }
                catch is CancellationError { throw CancellationError() }
                catch { retention = "偏好内容摘要未确认：" + error.localizedDescription;issues.append(path + "：" + error.localizedDescription) }
            }
            if retention == nil && !Attribution.canAuthorize(hints: evidence) { retention = "缺少可执行的归属证据" }
            var candidate = Candidate(id: id, path: path, category: category, bundleIdentifier: bundleID, evidence: evidence, rule: effectiveRule, identity: snapshot?.identity, bytes: historyBytes ?? snapshot?.bytes ?? 0, retentionReason: retention)
            candidate.applicationPath = applicationPath
            candidate.displayName = displayName
            candidate.deviceBackupDetails = deviceBackupDetails
            if [TrashEntryRule.name,MailDownloadRule.name,AIStorageRule.name].contains(rule) { candidate.recommendation = .manual }
            if rule == AIDiagnosticRule.name { candidate.recommendation = .manual }
            if rule == UserCacheNamespaceRule.name || rule == GodotCacheRule.name { candidate.recommendation = .manual }
            if ApplicationCacheRule.rules.contains(rule) { candidate.recommendation = .manual }
            if rule == XcodeGeneratedRule.name { candidate.recommendation = .manual }
            if rule == DarwinCacheRule.name || rule == WebKitCacheRule.name { candidate.recommendation = .manual }
            if [ApplicationLogRule.currentName,SystemDomainRule.currentLogName].contains(rule), let snapshot {
                candidate.recommendation = Attribution.oldLog(modified:Date(timeIntervalSince1970:Double(snapshot.identity.modifiedSeconds)),now:Date()) ? .recommended : .manual
            }
            items.append(candidate); if let snapshot { snapshots[id] = snapshot }
        }
        mutating func reportProtected(_ path: String, reason: String) { items.append(Candidate(id: UUID(), path: path, category: .protected, bundleIdentifier: nil, evidence: [], rule: "protected-v1", identity: nil, bytes: 0, retentionReason: reason)) }
        func finish(applicationPath: String?) -> ScanOutput {
            let confirmed = Set(scopes.filter { $0.complete && $0.issues.isEmpty }.map(\.id))
            let candidates = items.map { item in
                var item = item
                item.allowsPlanReview = item.scanScopeID.map { confirmed.contains($0) } == true && item.allowed
                item.executionAllowed = item.allowsPlanReview && policy.executionEnabled
                return item
            }
            return ScanOutput(report: ScanReport(schemaVersion: 2, id: UUID(), createdAt: Date(), ruleVersion: SweepEngine.ruleVersion, applicationPath: applicationPath, candidates: candidates, complete: issues.isEmpty, issues: issues, platformLimitation: policy.limitation, scopes: scopes), snapshots: snapshots)
        }
    }
}
