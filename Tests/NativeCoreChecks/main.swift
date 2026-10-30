import Foundation
import Darwin
@testable import AppSweepCore

struct CheckFailure: Error, CustomStringConvertible {
    let description: String
    init(_ message: String) { description = message }
}
func check(_ condition: @autoclosure () throws -> Bool, _ message: String) throws {
    guard try condition() else { throw CheckFailure(message) }
}
func reject(_ message: String, _ operation: () throws -> Void) throws {
    do { try operation() } catch { print("PASS " + message); return }
    throw CheckFailure(message)
}
let fm = FileManager.default
@MainActor struct OwnedFixture {
    let home: String
    let app: String
    let identifier: String
    let binary: String
    init(resuming path: String) throws {
        guard let root = ProcessInfo.processInfo.environment["APP_SWEEP_FIXTURES"],
              root.hasPrefix(try SystemIdentity.home() + "/AppSweepAcceptance"),
              URL(fileURLWithPath:path).deletingLastPathComponent().path == root,
              UUID(uuidString:URL(fileURLWithPath:path).lastPathComponent) != nil else {throw CheckFailure("Only an owned UUID fixture may resume")}
        _ = try SafeDirectory(path:path)
        home=path;app=path + "/Applications/Owned Fixture.app";binary=app + "/Contents/MacOS/fixture"
        identifier=try AppInspector.inspect(app).bundleIdentifier
        try check(identifier.hasPrefix("org.example.nativeparity."),"Unexpected fixture identity")
    }
    init() throws {
        let userHome = try SystemIdentity.home()
        guard let root = ProcessInfo.processInfo.environment["APP_SWEEP_FIXTURES"],
              root.hasPrefix(userHome + "/AppSweepAcceptance"), XcodeRule.canonical(root), getuid() != 0 else {
            throw CheckFailure("Explicit task-owned fixture directory required")
        }
        _ = try SafeDirectory(path: root)
        home = root + "/" + UUID().uuidString
        app = home + "/Applications/Owned Fixture.app"
        binary = app + "/Contents/MacOS/fixture"
        identifier = "org.example.nativeparity." + UUID().uuidString.lowercased()
        for path in [app + "/Contents/MacOS", app + "/Contents/Resources", home + "/Library/Application Support", home + "/DarwinCache", home + "/DarwinTemporary"] {
            try fm.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
        let info: [String: Any] = ["CFBundleIdentifier": identifier, "CFBundlePackageType": "APPL", "CFBundleName": "Owned Fixture", "CFBundleExecutable": "fixture"]
        try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: URL(fileURLWithPath: app + "/Contents/Info.plist"))
        try fm.copyItem(atPath: "/bin/sleep", toPath: binary)
        try Data("sealed resource".utf8).write(to: URL(fileURLWithPath: app + "/Contents/Resources/asset"))
        try fm.linkItem(atPath: app + "/Contents/Resources/asset", toPath: app + "/Contents/Resources/alias")
        _ = try BoundedProcess.run("/usr/bin/codesign", arguments: ["--force", "--sign", "-", "--identifier", identifier, app], timeout: 10)
        print("Fixture " + home)
    }
    func engine(rules: Set<String> = []) throws -> SweepEngine {
        SweepEngine(policy: SafetyPolicy(home: home, acceptedPlatform: true, validatedRules: rules.union([SelectedApplicationRule.name]), darwinScope: try DarwinCacheScope.fixture(home: home), darwinTemporaryScope: try DarwinCacheScope.fixture(home: home, kind: .temporary)), vaultPath: home + "/Library/Application Support/App Sweep/Recovery", fixture: false)
    }
    func finish() throws {
        // Only this invocation's UUID directory, never the fixture/workspace root.
        try fm.removeItem(atPath: home)
    }
}
func selectedBody(_ report: ScanReport, app: String) throws -> Candidate {
    guard let body = report.selectableCandidates(includeUserData: false).first(where: { $0.path == app }) else {
        throw CheckFailure("Whole signed application should be selectable: " + report.candidates.compactMap(\.retentionReason).joined(separator: "; "))
    }
    return body
}
func settledApplication(_ engine: SweepEngine, app: String) async throws -> ScanReport {
    let deadline = Date().addingTimeInterval(10)
    while true {
        let report = try await engine.scanApplication(app)
        let reason = report.candidates.first(where: { $0.path == app })?.retentionReason ?? ""
        // Newly created test bundles may briefly be read by Spotlight. Wait only
        // for that explicit system-reader result; never ignore a product refusal.
        if !reason.contains("系统组件仍在读取") || Date() >= deadline { return report }
        try await Task.sleep(nanoseconds: 250_000_000)
    }
}
func assertExternal(_ path: String, identity: FileIdentity, bytes: Data) throws {
    let url = URL(fileURLWithPath: path), current = try SafeDirectory(path: url.deletingLastPathComponent().path).identity(url.lastPathComponent)
    try check(current.inode == identity.inode && current.device == identity.device && current.mode == identity.mode, "External reference identity/permissions changed")
    try check(Data(contentsOf: url) == bytes, "External reference contents changed")
}
@MainActor func hardLinkChecks() async throws {
    let f = try OwnedFixture(), engine = try f.engine()
    let external = f.home + "/external-executable", externalResource = f.home + "/external-resource"
    try fm.linkItem(atPath: f.binary, toPath: external)
    try fm.linkItem(atPath: f.app + "/Contents/Resources/asset", toPath: externalResource)
    let identity = try SafeDirectory(path: f.home).identity("external-executable"), bytes = try Data(contentsOf: URL(fileURLWithPath: external))
    let resourceIdentity = try SafeDirectory(path: f.home).identity("external-resource"), resourceBytes = try Data(contentsOf: URL(fileURLWithPath: externalResource))
    var report = try await settledApplication(engine, app: f.app)
    var body = try selectedBody(report, app: f.app)
    print("PASS signed application with linked executable/resources is selectable")
    var plan = try await engine.makePlan(reportID: report.id, selected: [body.id], includeUserData: false)
    let extra = f.home + "/late-alias"
    try fm.linkItem(atPath: f.binary, toPath: extra)
    do { _ = try await engine.execute(planID: plan.id); throw CheckFailure("Changed alias count accepted") }
    catch let error as CheckFailure { throw error }
    catch { try check(fm.fileExists(atPath: f.app), "Stale plan moved body"); print("PASS changed hard-link count rejects old plan") }
    try fm.removeItem(atPath: extra)
    report = try await settledApplication(engine, app: f.app); body = try selectedBody(report, app: f.app)
    plan = try await engine.makePlan(reportID: report.id, selected: [body.id], includeUserData: false)
    // Starting through the outside alias must not evade inode occupancy checks.
    let process = Process(); process.executableURL = URL(fileURLWithPath: external); process.arguments = ["30"]
    try process.run()
    do { _ = try await engine.execute(planID: plan.id); if process.isRunning { process.terminate() }; throw CheckFailure("Running application accepted") }
    catch let error as CheckFailure { throw error }
    catch { print("PASS application running through outside alias blocks execution") }
    // This is our own short-lived fixture, never an installed app or service.
    if process.isRunning { process.terminate() }
    let deadline = Date().addingTimeInterval(5)
    while process.isRunning && Date() < deadline { try await Task.sleep(nanoseconds: 50_000_000) }
    try check(!process.isRunning, "Owned fixture failed to exit")
    report = try await settledApplication(engine, app: f.app); body = try selectedBody(report, app: f.app)
    plan = try await engine.makePlan(reportID: report.id, selected: [body.id], includeUserData: false)
    let batch = try await engine.execute(planID: plan.id)
    try check(batch.status == .isolated, "Isolation failed: " + (batch.issue ?? ""))
    try check(!fm.fileExists(atPath: f.app), "Application not moved")
    try assertExternal(external, identity: identity, bytes: bytes)
    let restored = try await engine.restore(batchID: batch.id)
    try check(restored.status == .restored, "Restore failed: " + restored.entries.compactMap(\.message).joined(separator: "; "))
    try check(AppInspector.signatureMatches(path: f.app, identifier: f.identifier), "Restored signature invalid")
    try assertExternal(external, identity: identity, bytes: bytes)
    print("PASS full native isolation and restoration preserve external hard link")
    report = try await settledApplication(engine, app: f.app); body = try selectedBody(report, app: f.app)
    plan = try await engine.makePlan(reportID: report.id, selected: [body.id], includeUserData: false)
    let purgeBatch = try await engine.execute(planID: plan.id)
    try check(purgeBatch.status == .isolated, "Second isolation failed")
    let purged = try await engine.purge(batchID: purgeBatch.id, confirmation: "永久清空 " + purgeBatch.id.uuidString)
    try check(purged.status == .purged, "Purge failed: " + (purged.issue ?? ""))
    try assertExternal(external, identity: identity, bytes: bytes)
    try assertExternal(externalResource, identity: resourceIdentity, bytes: resourceBytes)
    try check(SafeDirectory(path: f.home).identity("external-executable").links == 1, "Wrong remaining executable links")
    try check(SafeDirectory(path: f.home).identity("external-resource").links == 1, "Wrong remaining resource links")
    print("PASS purge unlinks only reviewed package names; outside aliases survive")
    let cache = f.home + "/ordinary-cache"
    try fm.createDirectory(atPath: cache, withIntermediateDirectories: false)
    try fm.linkItem(atPath: external, toPath: cache + "/borrowed")
    try reject("ordinary cache still rejects external hard links") { _ = try SafeFilesystem.snapshot(cache, allowInternalHardLinks: true) }
    try f.finish()
}

@MainActor func webKitChecks() async throws {
    let f = try OwnedFixture(), rule = "cache-webkit-derived-v1", engine = try f.engine(rules: [rule])
    var members: [String] = []
    for component in ["GPU", "Networking", "WebContent"] {
        let root = f.home + "/DarwinCache/com.apple.WebKit." + component + "+" + f.identifier
        try fm.createDirectory(atPath: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let path = root + "/cache.bin"
        try Data(("owned " + component).utf8).write(to: URL(fileURLWithPath: path))
        members.append(path)
    }
    let bytes = try members.map { try Data(contentsOf: URL(fileURLWithPath: $0)) }
    let scope = try DarwinCacheScope.fixture(home: f.home)
    let namespace = "com.apple.WebKit.Networking+" + f.identifier
    for path in [scope.root + "/" + namespace, scope.root + "/" + namespace + "/deep/leaf",
                 f.home + "/T/" + namespace + "/cache", scope.root + "/com.apple.WebKit.Networking/cache",
                 scope.root + "/" + namespace + ".other/cache", scope.root + "/" + namespace + "/../cache",
                 scope.root + "/" + namespace + "/keychains", scope.root + "/" + namespace + "/com.apple.TCC"] {
        try check(WebKitCacheRule.root(path: path, identifier: f.identifier, scope: scope) == nil, "Escaping/shared/unsafe WebKit path accepted: " + path)
    }
    try check(WebKitCacheRule.namespaces(identifier: "com.apple.Safari").isEmpty, "Apple data owner authorized")
    let policy = SafetyPolicy(home: f.home, acceptedPlatform: true, validatedRules: [rule, SelectedApplicationRule.name], darwinScope: scope)
    let junk = try Scanner(policy: policy).junk(indexLookup: { _ in [] }).report
    try check(Set(junk.selectableCandidates(includeUserData: false).filter { $0.rule == rule }.map(\.path)) == Set(members), "Junk and uninstall paths must agree")
    print("PASS junk/uninstall share WebKit discovery; T, shared, sibling and protected paths rejected")
    let report = try await engine.scanApplication(f.app)
    let caches = report.selectableCandidates(includeUserData: false).filter { members.contains($0.path) }
    try check(caches.count == 3, "Three exact WebKit C-cache members must be selectable: " + report.candidates.compactMap(\.retentionReason).joined(separator: "; "))
    let body = try selectedBody(report, app: f.app)
    let plan = try await engine.makePlan(reportID: report.id, selected: Set(caches.map(\.id) + [body.id]), includeUserData: false)
    let batch = try await engine.execute(planID: plan.id)
    try check(batch.status == .isolated, "WebKit body/cache isolation failed: " + (batch.issue ?? ""))
    for member in members { try check(!fm.fileExists(atPath: member), "Selected cache not isolated") }
    let restored = try await engine.restore(batchID: batch.id)
    try check(restored.status == .restored, "WebKit restore failed: " + restored.entries.compactMap(\.message).joined(separator: "; "))
    for (index, member) in members.enumerated() { try check(Data(contentsOf: URL(fileURLWithPath: member)) == bytes[index], "Cache restoration changed contents") }
    print("PASS WebKit exact C-cache discovery, plan, native isolation and restore")
    let duplicate = f.home + "/Applications/Duplicate.app"
    try fm.copyItem(atPath: f.app, toPath: duplicate)
    let shared = try await engine.scanApplication(f.app)
    try check(!shared.selectableCandidates(includeUserData: false).contains(where: { $0.rule == rule }), "Duplicate owner was authorized")
    try fm.removeItem(atPath: duplicate)
    let root = URL(fileURLWithPath: members[0]).deletingLastPathComponent().path
    let secret = f.home + "/outside-secret"
    try Data("untouched".utf8).write(to: URL(fileURLWithPath: secret))
    try fm.createSymbolicLink(atPath: root + "/escape", withDestinationPath: secret)
    let unsafe = try await engine.scanApplication(f.app)
    try check(!unsafe.selectableCandidates(includeUserData: false).contains(where: { $0.path.hasPrefix(root + "/") }), "Linked cache authorized")
    try check(String(contentsOfFile: secret, encoding: .utf8) == "untouched", "External cache target changed")
    print("PASS duplicate ownership and cache symlink escape stay blocked")
    try f.finish()
}

@MainActor func boundaryChecks() throws {
    let f = try OwnedFixture(), external = f.home + "/outside-resource"
    try fm.linkItem(atPath: f.app + "/Contents/Resources/asset", toPath: external)
    let snapshot = try SafeFilesystem.snapshot(f.app, allowInternalLinks: true, purpose: .application, allowApplicationHardLinks: true)
    try Data("changed through independent alias".utf8).write(to: URL(fileURLWithPath: external))
    try reject("external content change invalidates reviewed application") { try SafeFilesystem.verify(snapshot) }
    try reject("invalid bundle seal cannot authorize linked files") { _ = try SafeFilesystem.snapshot(f.app, allowInternalLinks: true, purpose: .application, allowApplicationHardLinks: true) }
    let alias = f.home + "/Alias.app"
    try fm.createSymbolicLink(atPath: alias, withDestinationPath: f.app)
    try reject("application root alias stays forbidden") { _ = try SafeFilesystem.snapshot(alias, allowInternalLinks: true, purpose: .application, allowApplicationHardLinks: true) }
    try reject("ordinary snapshots cannot borrow application link capability") { _ = try SafeFilesystem.snapshot(f.app, allowApplicationHardLinks: true) }
    let label = "org.example.owned.helper", registry = "0 - " + label + "\n42 - " + label + "\n0 M D " + label + "\n0x123 M A " + label + "\n0 - " + label + ".other"
    let remaining = InstalledSystemHelperRule.unresolvedRegistry(registry, verifiedLabel: label).components(separatedBy: "\n")
    try check(!remaining.contains("0 - " + label) && !remaining.contains("0 M D " + label), "Verified dormant registration incorrectly treated as running")
    try check(remaining.contains("42 - " + label) && remaining.contains("0x123 M A " + label) && remaining.contains("0 - " + label + ".other"), "Running or unrelated service registration ignored")
    print("PASS running/unknown service blocks retained; exact proven dormant service recognized")
    try f.finish()
}

@MainActor func linkedProfileChecks() async throws {
    let f = try OwnedFixture(), namespace = "Owned Chromium"
    let infoPath = f.app + "/Contents/Info.plist"
    var info = try PropertyListSerialization.propertyList(from: Data(contentsOf: URL(fileURLWithPath: infoPath)), format: nil) as! [String: Any]
    info["CrProductDirName"] = namespace
    try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: URL(fileURLWithPath: infoPath))
    _ = try BoundedProcess.run("/usr/bin/codesign", arguments: ["--force", "--sign", "-", "--identifier", f.identifier, f.app], timeout: 10)
    try fm.linkItem(atPath: f.binary, toPath: f.home + "/outside-binary")
    let support = f.home + "/Library/Application Support/" + namespace
    try fm.createDirectory(atPath: support + "/Default", withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    try JSONSerialization.data(withJSONObject: ["profile": ["info_cache": ["Default": ["name": "Owned"]]]]).write(to: URL(fileURLWithPath: support + "/Local State"))
    try JSONSerialization.data(withJSONObject: ["profile": ["name": "Owned"]]).write(to: URL(fileURLWithPath: support + "/Default/Preferences"))
    let engine = try f.engine(rules: [ChromiumProfileRule.name])
    let report = try await settledApplication(engine, app: f.app), body = try selectedBody(report, app: f.app)
    guard let profile = report.selectableCandidates(includeUserData: true).first(where: { $0.path == support }) else { throw CheckFailure("Linked browser profile not discoverable") }
    try check(!profile.selectedByDefault, "Personal browser data selected by default")
    do { _ = try await engine.makePlan(reportID: report.id, selected: [body.id, profile.id], includeUserData: false); throw CheckFailure("Personal data opt-in bypassed") }
    catch let error as CheckFailure { throw error } catch { }
    let plan = try await engine.makePlan(reportID: report.id, selected: [body.id, profile.id], includeUserData: true)
    let batch = try await engine.execute(planID: plan.id)
    try check(batch.status == .isolated, "Linked browser plus profile isolation failed: " + (batch.issue ?? "") + batch.entries.compactMap(\.message).joined(separator: "; "))
    try fm.removeItem(atPath: f.home + "/outside-binary")
    let restored = try await engine.restore(batchID: batch.id)
    try check(restored.status == .restored, "Linked browser plus profile recovery failed")
    try check(fm.fileExists(atPath: support + "/Default/Preferences") && AppInspector.signatureMatches(path: f.app, identifier: f.identifier), "Restored browser/profile missing")
    try check(ApplicationGroupRule.declarations(applicationPath: f.app, identifier: f.identifier).isEmpty, "Unexpected application groups")
    let library = f.home + "/MachineLibrary"
    try fm.createDirectory(atPath: library, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    let systemScope = try SystemCleanupScope.fixture(libraryRoot: library, applicationsRoot: f.home + "/Applications", userHome: f.home, requesterUID: getuid())
    let application = try AppInspector.inspect(f.app)
    try systemScope.verifyApplication(application, inventory: [application])
    print("PASS linked browser with opt-in personal profile isolates/restores; group declarations work")
    try f.finish()
}

@MainActor func restoreOwnedFixture(_ home: String) async throws {
    guard let root = ProcessInfo.processInfo.environment["APP_SWEEP_FIXTURES"],
          URL(fileURLWithPath: home).deletingLastPathComponent().path == root,
          UUID(uuidString: URL(fileURLWithPath: home).lastPathComponent) != nil else { throw CheckFailure("Not a registered UUID fixture") }
    let policy = SafetyPolicy(home: home, acceptedPlatform: true, validatedRules: [SelectedApplicationRule.name, ChromiumProfileRule.name], darwinScope: try DarwinCacheScope.fixture(home: home))
    let engine = SweepEngine(policy: policy, vaultPath: home + "/Library/Application Support/App Sweep/Recovery", fixture: false)
    let batches = try await engine.recoveryBatches()
    try check(!batches.isEmpty, "No recovery journal to verify")
    for batch in batches {
        let restored = try await engine.restore(batchID: batch.id)
        try check(restored.status == .restored, "Previously failed transaction not recovered")
    }
    print("PASS prior failed linked-profile journal recovered through real engine")
}

@MainActor func aliasConflictChecks() async throws {
    let f = try OwnedFixture(), engine = try f.engine(), alias = f.home + "/outside-binary"
    try fm.linkItem(atPath: f.binary, toPath: alias)
    let bytes = try Data(contentsOf: URL(fileURLWithPath: alias))
    let report = try await settledApplication(engine, app: f.app), body = try selectedBody(report, app: f.app)
    let plan = try await engine.makePlan(reportID: report.id, selected: [body.id], includeUserData: false)
    let batch = try await engine.execute(planID: plan.id)
    try check(batch.status == .isolated, "Conflict sample did not isolate")
    try fm.removeItem(atPath: alias)
    let restored = try await engine.restore(batchID: batch.id)
    try check(restored.status == .restored, "Alias-count-only change should restore when original bytes and metadata are proven: " + restored.entries.compactMap(\.message).joined(separator: "; "))
    try check(Data(contentsOf: URL(fileURLWithPath: f.binary)) == bytes, "Recovery changed the application")
    print("PASS external alias removal restores with original byte and metadata proof")
    try f.finish()
}

do {
    if CommandLine.arguments.contains("--management-parity") {try await managementParityChecks()}
    else if CommandLine.arguments.contains("--additional-categories") {try await additionalCategoryDiscoveryChecks()}
    else if CommandLine.arguments.contains("--ai-diagnostics") {try await aiDiagnosticDiscoveryChecks()}
    else if CommandLine.arguments.contains("--ai-diagnostics-host") {try aiDiagnosticHostChecks()}
    else if CommandLine.arguments.contains("--application-transfer") {try await applicationTransferChecks()}
    else if CommandLine.arguments.contains("--download-policy") {try await downloadPolicyChecks()}
    else if CommandLine.arguments.contains("--download-named-policy") {try await namedDownloadPolicyChecks()}
    else if CommandLine.arguments.contains("--download-explicit-path-policy") {try await explicitDownloadPathPolicyChecks()}
    else if CommandLine.arguments.contains("--runtime-exports") {try await runtimePackageChecks(undeclaredProducer:true,exportsEntry:true)}
    else if CommandLine.arguments.contains("--runtime-unadvertised-api") {try await runtimePackageChecks(undeclaredProducer:true)}
    else if CommandLine.arguments.contains("--runtime-package") {try await runtimePackageChecks()}
    else if CommandLine.arguments.contains("--hidden-cache-metadata") {try await hiddenCacheMetadataChecks()}
    else if CommandLine.arguments.contains("--framework-transaction") {try await frameworkTransactionChecks()}
    else if CommandLine.arguments.contains("--framework-namespace") {try await frameworkNamespaceChecks()}
    else if CommandLine.arguments.contains("--runtime-diagnostic") {try runtimeDiagnosticChecks()}
    else if CommandLine.arguments.contains("--runtime-review") {try await runtimeReviewChecks()}
    else if CommandLine.arguments.contains("--trivy-producer") {try await trivyProducerChecks()}
    else if CommandLine.arguments.contains("--trivy-cache") {try await trivyCacheChecks()}
    else if CommandLine.arguments.contains("--runtime-activity") {try await runtimeActivityChecks()}
    else if CommandLine.arguments.contains("--download-host-readonly") {try await downloadHostChecks()}
    else if CommandLine.arguments.contains("--download-mixed-guard") {try downloadMixedGuardChecks()}
    else if CommandLine.arguments.contains("--download-node-guard") {try await downloadNodeGuardChecks()}
    else if CommandLine.arguments.contains("--download-caches") { try await downloadCacheChecks() }
    else if CommandLine.arguments.contains("--webkit-producer") { try await webKitProducerChecks() }
    else if CommandLine.arguments.contains("--webkit-temp") { try await webKitTemporaryChecks() }
    else if CommandLine.arguments.contains("--helper-versions") { try helperVersionProofChecks() }
    else if CommandLine.arguments.contains("--helper-lifecycle") { try await helperLifecycleChecks() }
    else if CommandLine.arguments.contains("--helper-guards") { try await helperGuardChecks() }
    else if CommandLine.arguments.contains("--download-producers") { try await downloadProducerChecks() }
    else if CommandLine.arguments.contains("--generic-storage") { try await genericStorageChecks() }
    else if CommandLine.arguments.contains("--generic-tools") { try await genericToolChecks() }
    else if CommandLine.arguments.contains("--generic-producers") { try await genericProducerChecks() }
    else if CommandLine.arguments.contains("--hardlinks") { try await hardLinkChecks() }
    else if CommandLine.arguments.contains("--webkit") { try await webKitChecks() }
    else if CommandLine.arguments.contains("--boundaries") { try boundaryChecks() }
    else if CommandLine.arguments.contains("--linked-profile") { try await linkedProfileChecks() }
    else if CommandLine.arguments.contains("--alias-conflict") { try await aliasConflictChecks() }
    else if CommandLine.arguments.contains("--homebrew") { try await homebrewChecks() }
    else if CommandLine.arguments.contains("--system-helper-declarations") { try systemHelperDeclarationChecks() }
    else if CommandLine.arguments.contains("--running-scan") { try await runningScanChecks() }
    else if CommandLine.arguments.contains("--application-recovery") { try await applicationRecoveryChecks() }
    else if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--restore-fixture" { try await restoreOwnedFixture(CommandLine.arguments[2]) }
    else if CommandLine.arguments.contains("--all") { try await hardLinkChecks(); try await webKitChecks(); try boundaryChecks(); try await linkedProfileChecks(); try await aliasConflictChecks(); try await applicationRecoveryChecks(); try await runningScanChecks(); try systemHelperDeclarationChecks(); try await genericStorageChecks(); try await genericToolChecks(); try await downloadCacheChecks(); try downloadMixedGuardChecks(); try await webKitTemporaryChecks(); try await helperLifecycleChecks(); try await helperGuardChecks() }
    else { throw CheckFailure("Choose a documented check group") }
} catch {
    print("FAIL \(error)")
    exit(1)
}
