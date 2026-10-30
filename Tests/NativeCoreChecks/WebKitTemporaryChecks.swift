import Foundation
import Darwin
@testable import AppSweepCore

@MainActor func webKitTemporaryChecks() async throws {
    let f = try OwnedFixture(), rule = "cache-webkit-temporary-blob-v1"
    let temp = f.home + "/DarwinTemporary", namespace = "com.apple.WebKit.Networking+" + f.identifier
    let root = temp + "/" + namespace, blob = root + "/BlobRegistryFiles-aB12cD34"
    try fm.createDirectory(atPath: blob, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    let file = blob + "/mapping-file-1.blob", bytes = Data("independent temporary blob".utf8)
    try bytes.write(to: URL(fileURLWithPath: file))
    try Data("unrelated state".utf8).write(to: URL(fileURLWithPath: root + "/user-document"))
    let engine = try f.engine(rules: [rule]), report = try await settledApplication(engine, app: f.app)
    let items = report.selectableCandidates(includeUserData: false).filter { $0.rule == rule }
    try check(items.map(\.path) == [blob], "Exact stopped WebKit temporary blob not discoverable")
    let original = try SafeFilesystem.snapshot(blob), body = try selectedBody(report, app: f.app)
    let temporary = try DarwinCacheScope.fixture(home: f.home, kind: .temporary)
    let cache = try DarwinCacheScope.fixture(home: f.home)
    try check(WebKitTemporaryRule.root(path: blob, identifier: f.identifier, scope: cache) == nil, "C scope borrowed for T cleanup")
    for path in [temp, root, root + "/user-document", blob + "/mapping-file-1.blob", temp + "/other/BlobRegistryFiles-aB12cD34", blob + "/../BlobRegistryFiles-aB12cD34"] {
        try reject("unrelated/forged temporary target retained") { try WebKitTemporaryRule.verify(path: path, identifier: f.identifier, scope: temporary) }
    }
    try check(WebKitTemporaryRule.namespace("com.apple.Safari") == nil, "Apple temporary namespace authorized")
    try check(WebKitCacheRule.root(path: blob, identifier: f.identifier, scope: temporary) == nil, "T scope borrowed for C cleanup")
    let plan = try await engine.makePlan(reportID: report.id, selected: [body.id, items[0].id], includeUserData: false)
    let batch = try await engine.execute(planID: plan.id)
    try check(batch.status == .isolated, "Temporary blob isolation failed: " + (batch.issue ?? ""))
    try check(!fm.fileExists(atPath: blob) && fm.fileExists(atPath: root + "/user-document"), "Temporary scope moved unrelated files")
    try fm.createDirectory(atPath: blob, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    try Data("regenerated".utf8).write(to: URL(fileURLWithPath: file))
    let conflict = try await f.engine(rules: [rule]).restore(batchID: batch.id)
    try check(conflict.status == .needsAttention && Data(contentsOf: URL(fileURLWithPath: file)) == Data("regenerated".utf8), "Temporary recovery overwrote regenerated content")
    try fm.moveItem(atPath: blob, toPath: f.home + "/regenerated-blob")
    let restored = try await f.engine(rules: [rule]).restore(batchID: batch.id)
    try check(restored.status == .restored, "Temporary blob/application restore failed: " + (restored.issue ?? ""))
    try check(SafeFilesystem.snapshot(blob).identity.inode == original.identity.inode && Data(contentsOf: URL(fileURLWithPath: file)) == bytes, "Temporary recovery did not preserve original")
    print("PASS exact WebKit temporary blob supports full application transaction and fresh-engine recovery")
    let junk = try await engine.scanJunk()
    try check(junk.selectableCandidates(includeUserData: false).filter { $0.rule == rule }.map(\.path) == [blob], "Temporary junk/uninstall discovery differs")
    for (label, change, undo) in [
        ("unknown blob member", { try Data("persistent".utf8).write(to: URL(fileURLWithPath: blob + "/document")) }, { try fm.removeItem(atPath: blob + "/document") }),
        ("blob link", { try fm.createSymbolicLink(atPath: blob + "/mapping-file-2.blob", withDestinationPath: f.home + "/outside") }, { try fm.removeItem(atPath: blob + "/mapping-file-2.blob") }),
        ("shared namespace", { try check(chmod(root, 0o777) == 0, "chmod failed") }, { try check(chmod(root, 0o700) == 0, "chmod failed") }),
        ("duplicate owner", { try fm.copyItem(atPath: f.app, toPath: f.home + "/Applications/Second.app") }, { try fm.removeItem(atPath: f.home + "/Applications/Second.app") })
    ] {
        try change()
        let bad = try await engine.scanJunk()
        try check(!bad.selectableCandidates(includeUserData: true).contains { $0.rule == rule }, "Accepted " + label)
        try undo()
    }
    let active = Process(); active.executableURL = URL(fileURLWithPath: f.binary); active.arguments = ["15"]; try active.run()
    do {
        let busy = try await engine.scanApplication(f.app)
        try check(!busy.selectableCandidates(includeUserData: false).contains { $0.rule == rule }, "Running WebKit owner accepted")
    } catch { if active.isRunning { active.terminate() }; throw error }
    if active.isRunning { active.terminate() }
    let deadline = Date().addingTimeInterval(5)
    while active.isRunning && Date() < deadline { try await Task.sleep(nanoseconds: 50_000_000) }
    try check(!active.isRunning, "Owned test application failed to exit")
    print("PASS unknown temporary content, symlinks, shared namespace, duplicate and running owner remain blocked")
    try f.finish()
}

/// Actual macOS WebKit producer. All external roots are unique, absent before
/// launch and recorded before creation; no installed application is involved.
@MainActor func webKitProducerChecks() async throws {
    let env = ProcessInfo.processInfo.environment
    guard let source = env["APP_SWEEP_WEBKIT_PRODUCER_SOURCE"], let sdk = env["APP_SWEEP_SDK"], let work = env["APP_SWEEP_TEST_WORK_ROOT"] else { throw CheckFailure("Owned WebKit producer source, SDK and evidence root required") }
    let f = try env["APP_SWEEP_WEBKIT_RESUME"].map { try OwnedFixture(resuming: $0) } ?? OwnedFixture(), home = try SystemIdentity.home(), temporary = try DarwinCacheScope.current(kind: .temporary), cache = try DarwinCacheScope.current()
    let evidence = work + "/webkit-producer"
    try fm.createDirectory(atPath: evidence, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    let namespace = WebKitTemporaryRule.namespace(f.identifier)!, root = temporary.root + "/" + namespace
    let roots = [home + "/Library/WebKit/" + f.identifier, home + "/Library/Caches/" + f.identifier,
        home + "/Library/HTTPStorages/" + f.identifier, home + "/Library/Preferences/" + f.identifier + ".plist",
        home + "/Library/Saved Application State/" + f.identifier + ".savedState"]
        + WebKitCacheRule.namespaces(identifier: f.identifier).flatMap { [cache.root + "/" + $0, temporary.root + "/" + $0] }
    if env["APP_SWEEP_WEBKIT_RESUME"] != nil {
        let prior = try JSONSerialization.jsonObject(with:Data(contentsOf:URL(fileURLWithPath:evidence + "/ownership.json"))) as? [String:Any]
        try check(prior?["identifier"] as? String == f.identifier && prior?["rootsAbsentBefore"] as? [String] == roots,"Missing original producer ownership receipt")
    } else {
        for path in roots { try check(!SafeFilesystem.presence(path), "Native producer root existed before test") }
        try JSONSerialization.data(withJSONObject: ["identifier":f.identifier,"fixture":f.home,"rootsAbsentBefore":roots], options: [.prettyPrinted,.sortedKeys]).write(to: URL(fileURLWithPath: evidence + "/ownership.json"))
    }
    _ = try BoundedProcess.run("/usr/bin/clang", arguments: ["-isysroot",sdk,"-fobjc-arc","-framework","Cocoa","-framework","WebKit",source,"-o",f.binary],timeout:30)
    _ = try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-","--identifier",f.identifier,f.app],timeout:10)
    func produce(_ pass: Int) async throws {
        let log = evidence + "/pass-" + String(pass) + ".log"
        try Data().write(to: URL(fileURLWithPath: log))
        let out = try FileHandle(forWritingTo: URL(fileURLWithPath: log)); defer { try? out.close() }
        let process = Process(); process.executableURL = URL(fileURLWithPath:f.binary); process.standardOutput=out;process.standardError=out;try process.run()
        let deadline=Date().addingTimeInterval(20)
        while process.isRunning && Date()<deadline {try await Task.sleep(nanoseconds:100_000_000)}
        if process.isRunning {process.terminate();throw CheckFailure("Owned WebKit producer timeout")}
        try check(process.terminationStatus==0,"Native WebKit producer failed; see owned log")
        let stopped = Date().addingTimeInterval(12)
        while true {
            do { try ActivityInspector.ensureStopped(bundleID:f.identifier,applicationPath:f.app,additionalIdentifiers:WebKitCacheRule.namespaces(identifier:f.identifier)); break }
            catch { if Date()>=stopped {throw error};try await Task.sleep(nanoseconds:250_000_000) }
        }
    }
    try await produce(1)
    let members = try CacheDomainRule.members(root:root).filter {WebKitTemporaryRule.root(path:$0,identifier:f.identifier,scope:temporary) != nil}
    try check(!members.isEmpty,"Native WebKit did not leave a BlobRegistryFiles directory; this producer shape remains unverified")
    for path in members {try WebKitTemporaryRule.verify(path:path,identifier:f.identifier,scope:temporary);try BusyInspector.ensureUnused(SafeFilesystem.snapshot(path))}
    // Native producer disappearance/recreation complements the separate full
    // backend transaction test; these are all this test's own unique directories.
    let moved = f.home + "/native-blobs";try fm.createDirectory(atPath:moved,withIntermediateDirectories:false)
    for path in members {try fm.moveItem(atPath:path,toPath:moved + "/" + URL(fileURLWithPath:path).lastPathComponent)}
    try await produce(2)
    let regenerated = try CacheDomainRule.members(root:root).filter {WebKitTemporaryRule.root(path:$0,identifier:f.identifier,scope:temporary) != nil}
    try check(!regenerated.isEmpty,"Native WebKit did not regenerate temporary storage")
    for path in regenerated {try WebKitTemporaryRule.verify(path:path,identifier:f.identifier,scope:temporary)}
    try JSONSerialization.data(withJSONObject:["identifier":f.identifier,"originalMembers":members.map {URL(fileURLWithPath:$0).lastPathComponent},"regeneratedMembers":regenerated.map {URL(fileURLWithPath:$0).lastPathComponent},"blobRoundtripBytes":2097152,"transactionEvidence":"Separate native --webkit-temp checks","passed":true],options:[.prettyPrinted,.sortedKeys]).write(to:URL(fileURLWithPath:evidence + "/receipt.json"))
    var retained: [String] = []
    for path in roots where try SafeFilesystem.presence(path) {
        let snapshot = try SafeFilesystem.snapshot(path)
        try check(snapshot.identity.owner == getuid(),"Native producer root owner changed")
        try BusyInspector.ensureUnused(snapshot)
        try SafeFilesystem.verify(snapshot)
        var info = stat()
        try check(lstat(path,&info) == 0,"Owned producer stat failed")
        if info.st_flags & UInt32(SF_NOUNLINK) != 0 {
            try check(path.hasPrefix(temporary.root + "/com.apple.WebKit."),"Unexpected protected fixture root")
            for member in try CacheDomainRule.members(root:path) {
                try BusyInspector.ensureUnused(SafeFilesystem.snapshot(member));try fm.removeItem(atPath:member)
            }
            retained.append(path) // OS-protected empty namespace; never bypass protection.
        } else {try fm.removeItem(atPath:path)}
    }
    try JSONSerialization.data(withJSONObject:["removedOwnedContents":true,"retainedEmptyOSNamespaces":retained],options:[.prettyPrinted,.sortedKeys]).write(to:URL(fileURLWithPath:evidence + "/cleanup.json"))
    try f.finish()
    print("PASS real WebKit blob roundtrip, exact native T layout, removal and regeneration; owned contents removed; protected empty OS namespaces retained")
}
