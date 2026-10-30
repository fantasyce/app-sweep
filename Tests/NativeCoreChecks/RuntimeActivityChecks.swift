import Foundation
import Darwin
@testable import AppSweepCore

/// A live unrelated Node service is not an Electron cache producer.
@MainActor func runtimeActivityChecks() async throws {
    guard let node = ProcessInfo.processInfo.environment["APP_SWEEP_NODE_EXECUTABLE"] else { throw CheckFailure("Node test runtime required") }
    let f = try OwnedFixture(), service = f.home + "/ordinary service"
    try fm.createDirectory(atPath: service, withIntermediateDirectories: true)
    try Data(#"{"name":"independent-fixture-service","version":"1.0.0","dependencies":{}}"#.utf8).write(to: URL(fileURLWithPath: service + "/package.json"))
    let script = service + "/main.cjs", ready = service + "/ready"
    try Data("require('fs').writeFileSync(process.argv[2],'ready');setTimeout(()=>{},60000);".utf8).write(to: URL(fileURLWithPath: script))
    let p = Process(); p.executableURL = URL(fileURLWithPath: node); p.arguments = [script, ready]; p.currentDirectoryURL = URL(fileURLWithPath: service)
    try p.run()
    var failure: Error?
    do {
        let deadline = Date().addingTimeInterval(8)
        while !fm.fileExists(atPath: ready) && p.isRunning && Date() < deadline { try await Task.sleep(nanoseconds: 50_000_000) }
        try check(p.isRunning && fm.fileExists(atPath: ready), "Owned Node service failed to start")
        do { try ToolCacheRule.ensureStopped(.electron, home: f.home) }
        catch { throw CheckFailure("Unrelated Node service blocks download cache: " + error.localizedDescription) }
        print("PASS ordinary live Node service does not block unrelated download caches")
        try Data("setTimeout(()=>{},60000);".utf8).write(to:URL(fileURLWithPath:script))
        try fm.setAttributes([.modificationDate:Date(timeIntervalSince1970:1)],ofItemAtPath:script)
        try check(DownloadCacheActivity.relation(pid:p.processIdentifier,home:f.home) == .unknown,"Changed script was incorrectly proved unrelated")
        try ToolCacheRule.ensureStopped(.electron,home:f.home)
        print("PASS changed generic script remains inconclusive without a blanket cache veto")
    } catch { failure = error }
    if p.isRunning { p.terminate() }
    let end = Date().addingTimeInterval(5)
    while p.isRunning && Date() < end { try await Task.sleep(nanoseconds: 50_000_000) }
    try check(!p.isRunning, "Owned Node fixture did not stop")
    try f.finish()
    if let failure { throw failure }
    guard let deps = ProcessInfo.processInfo.environment["APP_SWEEP_DOWNLOAD_DEPS"] else { throw CheckFailure("Real upstream API dependency required") }
    let nested = try OwnedFixture(), project = nested.home + "/project"
    try fm.createDirectory(atPath: project, withIntermediateDirectories: true)
    try Data(#"{"name":"independent-nested-service","version":"1.0.0","dependencies":{}}"#.utf8).write(to: URL(fileURLWithPath: project + "/package.json"))
    let helper = project + "/helper.cjs", entry = project + "/main.cjs", signal = project + "/ready"
    let quoted = String(data: try JSONSerialization.data(withJSONObject: deps + "/@electron/get", options: [.fragmentsAllowed]), encoding: .utf8)!
    try Data(("module.exports=require(" + quoted + ");").utf8).write(to: URL(fileURLWithPath: helper))
    try Data("require('./helper.cjs');require('fs').writeFileSync(process.argv[2],'ready');setTimeout(()=>{},60000);".utf8).write(to: URL(fileURLWithPath: entry))
    let q = Process(); q.executableURL = URL(fileURLWithPath: node); q.arguments = [entry, signal]; q.currentDirectoryURL = URL(fileURLWithPath: project)
    try q.run(); failure = nil
    do {
        let deadline = Date().addingTimeInterval(8)
        while !fm.fileExists(atPath: signal) && q.isRunning && Date() < deadline { try await Task.sleep(nanoseconds: 50_000_000) }
        try check(q.isRunning && fm.fileExists(atPath: signal), "Nested real API fixture failed to start")
        try reject("relative module loading a real download API remains blocked between opens") { try ToolCacheRule.ensureStopped(.electron, home: nested.home) }
    } catch { failure = error }
    if q.isRunning { q.terminate() }
    let stopped = Date().addingTimeInterval(5)
    while q.isRunning && Date() < stopped { try await Task.sleep(nanoseconds: 50_000_000) }
    try check(!q.isRunning, "Nested owned producer did not stop")
    try nested.finish()
    if let failure { throw failure }
    let preloadFixture = try OwnedFixture(), base = preloadFixture.home + "/service"
    try fm.createDirectory(atPath: base, withIntermediateDirectories: true)
    try Data(#"{"name":"independent-preload-service","version":"1.0.0","dependencies":{}}"#.utf8).write(to: URL(fileURLWithPath: base + "/package.json"))
    try Data(("require(" + quoted + ");").utf8).write(to: URL(fileURLWithPath: base + "/preload.cjs"))
    try Data("require('fs').writeFileSync(process.argv[2],'ready');setTimeout(()=>{},60000);".utf8).write(to: URL(fileURLWithPath: base + "/main.cjs"))
    let preload = Process(); preload.executableURL = URL(fileURLWithPath: node); preload.arguments = [base + "/main.cjs",base + "/ready"]; preload.currentDirectoryURL = URL(fileURLWithPath: base)
    var environment = ProcessInfo.processInfo.environment; environment["NODE_OPTIONS"] = "--require " + base + "/preload.cjs"; preload.environment = environment
    try preload.run(); failure = nil
    do {
        let deadline = Date().addingTimeInterval(8)
        while !fm.fileExists(atPath: base + "/ready") && preload.isRunning && Date() < deadline { try await Task.sleep(nanoseconds: 50_000_000) }
        try check(preload.isRunning && fm.fileExists(atPath: base + "/ready"), "Real preload fixture failed to start")
        try check(DownloadCacheActivity.relation(pid:preload.processIdentifier,home:preloadFixture.home) == .unknown,"Opaque preload was incorrectly proved unrelated")
        try ToolCacheRule.ensureStopped(.electron,home:preloadFixture.home)
        print("PASS opaque preload is inconclusive; no claim that every hidden API is detectable")
    } catch { failure = error }
    if preload.isRunning { preload.terminate() }
    let preloadEnd = Date().addingTimeInterval(5)
    while preload.isRunning && Date() < preloadEnd { try await Task.sleep(nanoseconds: 50_000_000) }
    try check(!preload.isRunning,"Owned preload fixture did not stop")
    try preloadFixture.finish()
    if let failure { throw failure }
    let titled = try OwnedFixture(), titledScript = titled.home + "/main.cjs", titledReady = titled.home + "/ready"
    try Data(("require(" + quoted + ");process.title='independent background worker';require('fs').writeFileSync(process.argv[2],'ready');setTimeout(()=>{},60000);").utf8).write(to:URL(fileURLWithPath:titledScript))
    let renamed=Process();renamed.executableURL=URL(fileURLWithPath:node);renamed.arguments=[titledScript,titledReady];renamed.currentDirectoryURL=URL(fileURLWithPath:titled.home)
    try renamed.run();failure=nil
    do {
        let deadline=Date().addingTimeInterval(8)
        while !fm.fileExists(atPath:titledReady) && renamed.isRunning && Date()<deadline {try await Task.sleep(nanoseconds:50_000_000)}
        try check(renamed.isRunning && fm.fileExists(atPath:titledReady),"Renamed API process failed to start")
        try check(DownloadCacheActivity.relation(pid:renamed.processIdentifier,home:titled.home) == .unknown,"Renamed opaque runtime was incorrectly proved unrelated")
        try ToolCacheRule.ensureStopped(.electron,home:titled.home)
        print("PASS renamed opaque runtime has no global veto or false negative-proof claim")
    } catch {failure=error}
    if renamed.isRunning {renamed.terminate()}
    let renamedEnd=Date().addingTimeInterval(5)
    while renamed.isRunning && Date()<renamedEnd {try await Task.sleep(nanoseconds:50_000_000)}
    try check(!renamed.isRunning,"Renamed owned runtime did not stop")
    try titled.finish()
    if let failure {throw failure}
}
