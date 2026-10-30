import Foundation
import Darwin
@testable import AppSweepCore

/// The approved relaxation is confined to completed download formats. A live
/// generic script with no concrete association is not proof of a cache user.
@MainActor func downloadPolicyChecks() async throws {
    guard let node=ProcessInfo.processInfo.environment["APP_SWEEP_NODE_EXECUTABLE"] else {throw CheckFailure("Node required")}
    let f=try OwnedFixture(),ready=f.home + "/ready",cache=f.home + "/Library/Caches/electron/electron-v33.4.11-darwin-arm64.zip"
    try fm.createDirectory(atPath:f.home + "/input",withIntermediateDirectories:true)
    try fm.createDirectory(atPath:URL(fileURLWithPath:cache).deletingLastPathComponent().path,withIntermediateDirectories:true)
    try Data("owned independent archive".utf8).write(to:URL(fileURLWithPath:f.home + "/input/payload"))
    _ = try BoundedProcess.run("/usr/bin/ditto",arguments:["-c","-k",f.home + "/input",cache],timeout:10)
    let p=Process();p.executableURL=URL(fileURLWithPath:node)
    p.arguments=["--input-type=commonjs","--eval","require('fs').writeFileSync(process.argv[1],'ready');setTimeout(()=>{},60000);",ready]
    p.currentDirectoryURL=URL(fileURLWithPath:f.home)
    try p.run();var failure:Error?
    do {
        let until=Date().addingTimeInterval(8)
        while p.isRunning && !fm.fileExists(atPath:ready) && Date()<until {try await Task.sleep(nanoseconds:50_000_000)}
        try check(p.isRunning && fm.fileExists(atPath:ready),"Opaque owned script failed to start")
        try check(DownloadCacheActivity.relation(pid:p.processIdentifier,home:f.home) == .unknown,"Fixture must exercise inconclusive runtime inspection")
        try ToolCacheRule.ensureStopped(.electron,home:f.home)
        try ToolCacheRule.ensureStopped(.electronBuilder,home:f.home)
        try check(!DownloadCacheRule.isProducer(node + " /project/server.cjs"),"Generic runtime is still called a confirmed producer")
        print("PASS live opaque generic script alone does not veto either download family")
        let engine=try f.engine(rules:[DownloadCacheRule.electronName]),report=try await engine.scanJunk()
        guard let candidate=report.selectableCandidates(includeUserData:false).first(where:{$0.path == cache}) else {throw CheckFailure("Download not selectable with opaque service")}
        let plan=try await engine.makePlan(reportID:report.id,selected:[candidate.id],includeUserData:false)
        let before=try SafeFilesystem.snapshot(cache),held=open(cache,O_RDONLY | O_CLOEXEC)
        try check(held >= 0,"Owned occupancy setup failed")
        do {
            do {_ = try await engine.execute(planID:plan.id);throw CheckFailure("Open archive moved")}
            catch let error as CheckFailure {throw error} catch { }
            try check(SafeFilesystem.snapshot(cache).identity == before.identity,"Occupied target changed")
        } catch {_ = close(held);throw error}
        _ = close(held)
        print("PASS open target still blocks execution despite unassociated runtime policy")
        let next=try f.engine(rules:[DownloadCacheRule.electronName]),newReport=try await next.scanJunk()
        guard let fresh=newReport.selectableCandidates(includeUserData:false).first(where:{$0.path == cache}) else {throw CheckFailure("Closed archive not selectable")}
        let newPlan=try await next.makePlan(reportID:newReport.id,selected:[fresh.id],includeUserData:false)
        let batch=try await next.execute(planID:newPlan.id)
        try check(batch.status == .isolated,"Owned download isolation failed")
        let restored=try await f.engine(rules:[DownloadCacheRule.electronName]).restore(batchID:batch.id)
        try check(restored.status == .restored && SafeFilesystem.snapshot(cache).identity.inode == before.identity.inode,"Owned archive recovery failed")
        try check(p.isRunning,"Product stopped the opaque service")
        print("PASS owned archive plan, isolation and fresh-engine recovery while unrelated service keeps running")
    } catch {failure=error}
    if p.isRunning {p.terminate()};let end=Date().addingTimeInterval(5)
    while p.isRunning && Date()<end {try await Task.sleep(nanoseconds:50_000_000)}
    try check(!p.isRunning,"Owned policy fixture did not stop")
    try f.finish();if let failure {throw failure}
}

@MainActor func namedDownloadPolicyChecks() async throws {
    guard let node=ProcessInfo.processInfo.environment["APP_SWEEP_NODE_EXECUTABLE"] else {throw CheckFailure("Node required")}
    let f=try OwnedFixture(),entry=f.home + "/node_modules/electron/install.js",ready=f.home + "/ready"
    try fm.createDirectory(atPath:URL(fileURLWithPath:entry).deletingLastPathComponent().path,withIntermediateDirectories:true)
    try Data("require('fs').writeFileSync(process.argv[2],'ready');setTimeout(()=>{},60000);".utf8).write(to:URL(fileURLWithPath:entry))
    let p=Process();p.executableURL=URL(fileURLWithPath:node);p.arguments=[entry,ready];p.currentDirectoryURL=URL(fileURLWithPath:f.home)
    try p.run();var failure:Error?
    do {
        let until=Date().addingTimeInterval(8)
        while p.isRunning && !fm.fileExists(atPath:ready) && Date()<until {try await Task.sleep(nanoseconds:50_000_000)}
        try check(p.isRunning && fm.fileExists(atPath:ready),"Named owned installer did not start")
        try reject("explicit Electron installer cannot be overridden by generic runtime inspection") {try ToolCacheRule.ensureStopped(.electron,home:f.home)}
        try reject("explicit installer also blocks shared builder downloads") {try ToolCacheRule.ensureStopped(.electronBuilder,home:f.home)}
    } catch {failure=error}
    if p.isRunning {p.terminate()};let end=Date().addingTimeInterval(5)
    while p.isRunning && Date()<end {try await Task.sleep(nanoseconds:50_000_000)}
    try check(!p.isRunning,"Owned named installer did not stop")
    try f.finish();if let failure {throw failure}
}

@MainActor func explicitDownloadPathPolicyChecks() async throws {
    guard let node=ProcessInfo.processInfo.environment["APP_SWEEP_NODE_EXECUTABLE"] else {throw CheckFailure("Node required")}
    let f=try OwnedFixture(),ready=f.home + "/ready",cache=f.home + "/Library/Caches/electron"
    let p=Process();p.executableURL=URL(fileURLWithPath:node)
    p.arguments=["--eval","require('fs').writeFileSync(process.argv[1],'ready');setTimeout(()=>{},60000);",ready,cache]
    p.currentDirectoryURL=URL(fileURLWithPath:f.home)
    var env=ProcessInfo.processInfo.environment;env["NODE_OPTIONS"]="--no-warnings";p.environment=env
    try p.run();var failure:Error?
    do {
        let until=Date().addingTimeInterval(8)
        while p.isRunning && !fm.fileExists(atPath:ready) && Date()<until {try await Task.sleep(nanoseconds:50_000_000)}
        try check(p.isRunning && fm.fileExists(atPath:ready),"Explicit path fixture did not start")
        try check(DownloadCacheActivity.relation(pid:p.processIdentifier,home:f.home) == .related,"Explicit cache path was hidden by opaque script/options")
        try reject("explicit cache path blocks even with inline code and runtime options") {try ToolCacheRule.ensureStopped(.electron,home:f.home)}
    } catch {failure=error}
    if p.isRunning {p.terminate()};let end=Date().addingTimeInterval(5)
    while p.isRunning && Date()<end {try await Task.sleep(nanoseconds:50_000_000)}
    try check(!p.isRunning,"Owned explicit path process did not stop")
    try f.finish();if let failure {throw failure}
}
