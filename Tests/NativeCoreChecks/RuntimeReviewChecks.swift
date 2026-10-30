import Foundation
import Darwin
@testable import AppSweepCore

@MainActor func runtimeReviewChecks() async throws {
    guard let node=ProcessInfo.processInfo.environment["APP_SWEEP_NODE_EXECUTABLE"],let deps=ProcessInfo.processInfo.environment["APP_SWEEP_DOWNLOAD_DEPS"] else{throw CheckFailure("Pinned upstream API dependency required")}
    var failed:[String]=[]
    for variant in ["alias","comment-import","peer-wrapper","retargeted-link"] {
        let f=try OwnedFixture(),root=f.home + "/project",ready=root + "/ready"
        try fm.createDirectory(atPath:root,withIntermediateDirectories:true)
        try Data(#"{"name":"independent-review-fixture","version":"1.0.0","dependencies":{}}"#.utf8).write(to:URL(fileURLWithPath:root + "/package.json"))
        let api=deps + "/@electron/get", quoted=String(data:try JSONSerialization.data(withJSONObject:api,options:[.fragmentsAllowed]),encoding:.utf8)!
        let wait="require('fs').writeFileSync(process.argv[2],'ready');setTimeout(()=>{},60000);"
        var source:String, entry=root + "/main.cjs"
        if variant == "alias" {source="const load=require;load(process.env.APP_SWEEP_TEST_API);" + wait}
        else if variant == "comment-import" {source="(async()=>{await import /* loader */ (process.env.APP_SWEEP_TEST_API + '/dist/cjs/index.js');" + wait + "})();"}
        else if variant == "peer-wrapper" {
            let wrapper=root + "/node_modules/independent-wrapper"
            try fm.createDirectory(atPath:wrapper,withIntermediateDirectories:true)
            try Data(#"{"name":"independent-wrapper","version":"1.0.0","main":"index.cjs","peerDependencies":{"@electron/get":"3.1.0"}}"#.utf8).write(to:URL(fileURLWithPath:wrapper + "/package.json"))
            try Data("module.exports=require('@electron/get');".utf8).write(to:URL(fileURLWithPath:wrapper + "/index.cjs"))
            try fm.createDirectory(atPath:root + "/node_modules/@electron",withIntermediateDirectories:true)
            try fm.createSymbolicLink(atPath:root + "/node_modules/@electron/get",withDestinationPath:api)
            source="require('independent-wrapper');" + wait
        } else {
            try Data(wait.utf8).write(to:URL(fileURLWithPath:root + "/benign.cjs"))
            source="require(" + quoted + ");" + wait
        }
        try Data(source.utf8).write(to:URL(fileURLWithPath:entry))
        if variant == "retargeted-link" {try fm.createSymbolicLink(atPath:root + "/entry.cjs",withDestinationPath:"main.cjs");entry=root + "/entry.cjs"}
        let p=Process();p.executableURL=URL(fileURLWithPath:node);p.arguments=[entry,ready];p.currentDirectoryURL=URL(fileURLWithPath:root)
        var env=ProcessInfo.processInfo.environment
        if ["alias","comment-import"].contains(variant){env["APP_SWEEP_TEST_API"]=api}
        else{env.removeValue(forKey:"APP_SWEEP_TEST_API")}
        p.environment=env
        try p.run()
        var failure:Error?
        do {
            let deadline=Date().addingTimeInterval(8)
            while !fm.fileExists(atPath:ready) && p.isRunning && Date()<deadline {try await Task.sleep(nanoseconds:50_000_000)}
            try check(p.isRunning && fm.fileExists(atPath:ready),"Real API fixture did not start: " + variant)
            if variant == "retargeted-link" {try fm.removeItem(atPath:entry);try fm.createSymbolicLink(atPath:entry,withDestinationPath:"benign.cjs")}
            if variant == "retargeted-link" {
                try check(DownloadCacheActivity.relation(pid:p.processIdentifier,home:f.home) == .unknown,"Retargeted script was incorrectly proved unrelated")
                try ToolCacheRule.ensureStopped(.electron,home:f.home)
                print("PASS retargeted generic script remains inconclusive under the approved policy")
            } else {try reject("review runtime retained: " + variant) {try ToolCacheRule.ensureStopped(.electron,home:f.home)}}
        } catch {failure=error}
        if p.isRunning {p.terminate()};let end=Date().addingTimeInterval(5)
        while p.isRunning && Date()<end {try await Task.sleep(nanoseconds:50_000_000)}
        try check(!p.isRunning,"Owned review process did not stop")
        try f.finish()
        if let failure {failed.append(variant + ": " + String(describing:failure));print("REGRESSION " + failed.last!)}
    }
    try check(failed.isEmpty,failed.joined(separator:"; "))
}
