import Foundation
import Darwin
@testable import AppSweepCore

/// Catches missing discovery, broad directory matching, and unsafe execution of
/// reviewed downloads that a producer starts using after scanning.
@MainActor func downloadCacheChecks() async throws {
    try check(DownloadCacheRule.isProducer("/task/node_modules/app-builder-bin/mac/app-builder_arm64 download-artifact"), "Native arm64 builder producer was missed")
    try check(DownloadCacheRule.isProducer("/task/node_modules/app-builder-bin/mac/app-builder_amd64 download-artifact"), "Native amd64 builder producer was missed")
    let f = try OwnedFixture()
    let electron = f.home + "/Library/Caches/electron"
    let builder = f.home + "/Library/Caches/electron-builder"
    let bucket = electron + "/" + String(repeating: "a", count: 64)
    let flat = electron + "/electron-v33.4.11-darwin-arm64.zip"
    let nsis = builder + "/nsis/nsis-3.0.4.1-nsis-3.0.4.1"
    let resources = builder + "/nsis/nsis-resources-3.4.1-nsis-resources-3.4.1"
    let signing = builder + "/winCodeSign/winCodeSign-2.6.0"
    let modern = builder + "/nsis@3.0.4.1"
    for path in [bucket, nsis + "/mac", resources + "/plugins/x86-unicode", signing + "/darwin/10.12/lib", modern, f.home + "/zip-input"] {
        try fm.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }
    try Data("Owned downloadable bytes".utf8).write(to: URL(fileURLWithPath: f.home + "/zip-input/payload"))
    _ = try BoundedProcess.run("/usr/bin/ditto", arguments: ["-c", "-k", f.home + "/zip-input", flat], timeout: 10)
    try fm.copyItem(atPath: flat, toPath: bucket + "/electron-v34.0.0-darwin-x64.zip")
    try fm.copyItem(atPath: "/usr/bin/true", toPath: nsis + "/mac/makensis")
    try Data([0x4d, 0x5a] + Array(repeating: 0, count: 62)).write(to: URL(fileURLWithPath: resources + "/plugins/x86-unicode/StdUtils.dll"))
    try Data([0,0,0,1,0x42,0x75,0x64,0x31]).write(to: URL(fileURLWithPath: resources + "/plugins/.DS_Store"))
    try Data([0x4d, 0x5a] + Array(repeating: 0, count: 62)).write(to: URL(fileURLWithPath: signing + "/rcedit-x64.exe"))
    try fm.copyItem(atPath: "/usr/bin/true", toPath: signing + "/darwin/osslsigncode")
    try fm.copyItem(atPath: "/usr/bin/true", toPath: signing + "/darwin/10.12/lib/libssl.1.0.0.dylib")
    try fm.createSymbolicLink(atPath: signing + "/darwin/10.12/lib/libssl.dylib", withDestinationPath: "libssl.1.0.0.dylib")
    // Independent small 7z signature/header, not an upstream implementation.
    try Data([0x37,0x7a,0xbc,0xaf,0x27,0x1c,0,4] + Array(repeating: 0, count: 24)).write(to: URL(fileURLWithPath: modern + "/nsis-3.0.4.1.7z"))
    let retained = [electron + "/personal-notes", builder + "/nsis/unfinished", builder + "/wine/wine-4.0.1-mac", builder + "/custom-tool"]
    for path in retained {
        try fm.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try Data("must remain".utf8).write(to: URL(fileURLWithPath: path + "/record"))
    }
    let expected = [bucket, flat, nsis, resources, signing, modern]
    let rules: Set<String> = ["development-electron-download-v1", "development-builder-toolset-v1"]
    let engine = try f.engine(rules: rules), report = try await engine.scanJunk()
    let items = report.selectableCandidates(includeUserData: false).filter { rules.contains($0.rule) }
    try check(Set(items.map(\.path)) == Set(expected), "Documented downloadable caches missing or overbroad: " + report.candidates.compactMap(\.retentionReason).joined(separator: "; "))
    for path in retained { try check(report.candidates.contains { SafetyPolicy.contains($0.path, path) && !$0.executionAllowed }, "Unknown cache sibling hidden: " + path) }
    print("PASS archive downloads and independent toolsets discovered; unknown and mutable Wine state retained")
    let originals = try items.map { try SafeFilesystem.snapshot($0.path, allowInternalLinks: $0.path == signing) }
    let plan = try await engine.makePlan(reportID: report.id, selected: Set(items.map(\.id)), includeUserData: false)
    let batch = try await engine.execute(planID: plan.id)
    try check(batch.status == .isolated, "Download isolation failed: " + (batch.issue ?? "") + batch.entries.compactMap(\.message).joined(separator: "; "))
    let restored = try await f.engine(rules: rules).restore(batchID: batch.id)
    try check(restored.status == .restored, "Download recovery failed: " + (restored.issue ?? ""))
    for (i, item) in items.enumerated() {
        let after = try SafeFilesystem.snapshot(item.path, allowInternalLinks: item.path == signing)
        try check(after.identity.inode == originals[i].identity.inode && after.tree == originals[i].tree, "Restored download changed")
    }
    try check(fm.destinationOfSymbolicLink(atPath: signing + "/darwin/10.12/lib/libssl.dylib") == "libssl.1.0.0.dylib", "Internal tool link changed")
    print("PASS independent download quarantine and fresh-engine restore retain identities and internal links")
    for (label, change, undo) in [
        ("unexpected personal file", { try Data("personal".utf8).write(to: URL(fileURLWithPath: bucket + "/notes.txt")) }, { try fm.removeItem(atPath: bucket + "/notes.txt") }),
        ("escaping tool link", { try fm.createSymbolicLink(atPath: signing + "/escape", withDestinationPath: "../../../../outside") }, { try fm.removeItem(atPath: signing + "/escape") }),
        ("shared cache parent", { try check(chmod(electron, 0o777) == 0, "chmod failed") }, { try check(chmod(electron, 0o700) == 0, "chmod failed") })
    ] {
        try change()
        let invalid = try await f.engine(rules: rules).scanJunk()
        let target = label == "escaping tool link" ? signing : bucket
        try check(!invalid.selectableCandidates(includeUserData: true).contains { $0.path == target }, "Accepted " + label)
        try undo()
    }
    let policy = SafetyPolicy(home: f.home, acceptedPlatform: true, validatedRules: rules)
    for path in [electron, builder, builder + "/nsis", f.home + "/Downloads/electron-v33.4.11-darwin-arm64.zip", "/private/var/folders/electron"] {
        for rule in rules { try check(policy.denial(path: path, category: .development, rule: rule) != nil, "Forged download scope accepted") }
    }
    let held = open(flat, O_RDONLY | O_CLOEXEC)
    try check(held >= 0, "Cannot hold download fixture")
    let busyEngine = try f.engine(rules: rules), busy = try await busyEngine.scanJunk()
    guard let item = busy.selectableCandidates(includeUserData: false).first(where: { $0.path == flat }) else { throw CheckFailure("Held download not discovered") }
    let busyPlan = try await busyEngine.makePlan(reportID: busy.id, selected: [item.id], includeUserData: false)
    do { _ = try await busyEngine.execute(planID: busyPlan.id); _ = close(held); throw CheckFailure("Open download moved") }
    catch let error as CheckFailure { throw error } catch { _ = close(held) }
    print("PASS mixed content, escaping links, shared ancestors, forged paths and open downloads block execution")
    try f.finish()
}

@MainActor func downloadMixedGuardChecks() throws {
    let f = try OwnedFixture(), path = f.home + "/Library/Caches/electron-builder/nsis/nsis-3.0.4"
    try fm.createDirectory(atPath:path + "/mac",withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
    try fm.copyItem(atPath:"/usr/bin/true",toPath:path + "/mac/makensis")
    try fm.createDirectory(atPath:path + "/Contrib/Language files",withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
    try Data("Independent source-build manifest fixture".utf8).write(to:URL(fileURLWithPath:path + "/Contrib/Language files/SConscript"))
    _=try ToolCacheRule.verify(path,home:f.home)
    for leaf in ["notes.txt","mac/customer-records.txt","unknown/state.bin"] {
        let target=path + "/" + leaf
        try fm.createDirectory(atPath:URL(fileURLWithPath:target).deletingLastPathComponent().path,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
        try Data("user-owned record".utf8).write(to:URL(fileURLWithPath:target))
        try reject("builder mixed content retained: " + leaf) {_ = try ToolCacheRule.verify(path,home:f.home)}
        try fm.removeItem(atPath:target)
    }
    try f.finish()
}
@MainActor func downloadNodeGuardChecks() async throws {
    guard let node=ProcessInfo.processInfo.environment["APP_SWEEP_NODE_EXECUTABLE"],let deps=ProcessInfo.processInfo.environment["APP_SWEEP_DOWNLOAD_DEPS"] else {throw CheckFailure("Pinned Node/API test tools required")}
    let f=try OwnedFixture(), script=f.home + "/download.cjs", ready=f.home + "/ready"
    let cache=f.home + "/Library/Caches/electron/electron-v33.4.11-darwin-arm64.zip", input=f.home + "/zip-input"
    try fm.createDirectory(atPath:URL(fileURLWithPath:cache).deletingLastPathComponent().path,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
    try fm.createDirectory(atPath:input,withIntermediateDirectories:false)
    try Data("owned download input".utf8).write(to:URL(fileURLWithPath:input + "/payload"))
    _=try BoundedProcess.run("/usr/bin/ditto",arguments:["-c","-k",input,cache],timeout:10)
    let engine=try f.engine(rules:[DownloadCacheRule.electronName]), report=try await engine.scanJunk()
    guard let item=report.selectableCandidates(includeUserData:false).first(where:{$0.path == cache}) else {throw CheckFailure("Owned inactive download was not selectable")}
    let original=try SafeFilesystem.snapshot(cache), plan=try await engine.makePlan(reportID:report.id,selected:[item.id],includeUserData:false)
    let source="require(process.argv[2]+'/@electron/get'); require('fs').writeFileSync(process.argv[3],'ready'); setTimeout(()=>{},60000);"
    try Data(source.utf8).write(to:URL(fileURLWithPath:script))
    let p=Process();p.executableURL=URL(fileURLWithPath:node);p.arguments=[script,deps,ready];try p.run()
    var failure:Error?
    do {
        let deadline=Date().addingTimeInterval(8)
        while !fm.fileExists(atPath:ready) && p.isRunning && Date()<deadline {try await Task.sleep(nanoseconds:50_000_000)}
        try check(fm.fileExists(atPath:ready) && p.isRunning,"Owned direct API caller did not pause")
        try reject("direct upstream API caller between file opens blocks cleanup") {try ToolCacheRule.ensureStopped(.electron)}
        try reject("direct API caller is still recognized in the owned cache scope") {try ToolCacheRule.ensureStopped(.electron,home:f.home)}
        do {_=try await engine.execute(planID:plan.id);throw CheckFailure("Direct API caller starting after review was not blocked")}
        catch let error as CheckFailure {throw error} catch { }
        try check(SafeFilesystem.snapshot(cache).identity == original.identity,"Active caller's cache moved")
        try check(DownloadCacheRule.isProducer("/opt/node /project/node_modules/electron/install.js"),"Direct Electron installer activity missed")
        try check(!DownloadCacheRule.isProducer("/opt/node /project/download.cjs"),"Generic Node process mislabeled as confirmed downloader")
    } catch {failure=error}
    if p.isRunning {p.terminate()}
    let end=Date().addingTimeInterval(5)
    while p.isRunning && Date()<end {try await Task.sleep(nanoseconds:50_000_000)}
    try check(!p.isRunning,"Owned API caller did not terminate")
    try f.finish()
    if let failure {throw failure}
}
