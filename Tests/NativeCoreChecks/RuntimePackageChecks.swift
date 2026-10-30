import Foundation
@testable import AppSweepCore

@MainActor func runtimePackageChecks(undeclaredProducer:Bool = false, exportsEntry:Bool = false) async throws {
    guard let node=ProcessInfo.processInfo.environment["APP_SWEEP_NODE_EXECUTABLE"] else{throw CheckFailure("Node required")}
    let f=try OwnedFixture(),root=f.home + "/ordinary-service",pkg=root + "/node_modules/local-helper"
    try fm.createDirectory(atPath:pkg,withIntermediateDirectories:true)
    try Data(#"{"name":"ordinary-service","dependencies":{"local-helper":"1.0.0"}}"#.utf8).write(to:URL(fileURLWithPath:root + "/package.json"))
    try Data(#"{"name":"local-helper","version":"1.0.0","main":"index.cjs","dependencies":{}}"#.utf8).write(to:URL(fileURLWithPath:pkg + "/package.json"))
    if exportsEntry {
        try Data(#"{"name":"local-helper","version":"1.0.0","exports":"./index.cjs","dependencies":{}}"#.utf8).write(to:URL(fileURLWithPath:pkg + "/package.json"))
    }
    var helper="module.exports=()=>42;"
    if undeclaredProducer {
        guard let deps=ProcessInfo.processInfo.environment["APP_SWEEP_DOWNLOAD_DEPS"] else{throw CheckFailure("Real API dependency required")}
        let path=String(data:try JSONSerialization.data(withJSONObject:deps + "/@electron/get",options:[.fragmentsAllowed]),encoding:.utf8)!
        helper="require(" + path + ");module.exports=()=>42;"
    }
    try Data(helper.utf8).write(to:URL(fileURLWithPath:pkg + "/index.cjs"))
    try Data("require('local-helper')();require('fs').writeFileSync(process.argv[2],'ready');setTimeout(()=>{},60000);".utf8).write(to:URL(fileURLWithPath:root + "/main.cjs"))
    let process=Process();process.executableURL=URL(fileURLWithPath:node);process.arguments=[root + "/main.cjs",root + "/ready"];process.currentDirectoryURL=URL(fileURLWithPath:root)
    try process.run();var failure:Error?
    do {
        let until=Date().addingTimeInterval(8)
        while process.isRunning && !fm.fileExists(atPath:root + "/ready") && Date()<until{try await Task.sleep(nanoseconds:50_000_000)}
        try check(process.isRunning && fm.fileExists(atPath:root + "/ready"),"Owned package service failed to start")
        if undeclaredProducer {print("DIRECT_RUNTIME " + DownloadCacheActivity.diagnostic(pid:process.processIdentifier,home:f.home));try reject("imported implementation with undeclared real API is retained") {try ToolCacheRule.ensureStopped(.electron,home:f.home)}}
        else {try ToolCacheRule.ensureStopped(.electron,home:f.home);print("PASS ordinary package-using Node service does not block unrelated downloads")}
    } catch {failure=error}
    if process.isRunning{process.terminate()}
    let until=Date().addingTimeInterval(5)
    while process.isRunning && Date()<until {try await Task.sleep(nanoseconds:50_000_000)}
    try check(!process.isRunning,"Owned service did not stop")
    try f.finish();if let failure{throw failure}
}
