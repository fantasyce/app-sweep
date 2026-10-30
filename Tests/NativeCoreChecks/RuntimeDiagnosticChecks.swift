import Foundation
import CFSafety
@testable import AppSweepCore

/// Only counts and fixed diagnostic categories leave this read-only probe.
func runtimeDiagnosticChecks() throws {
    let text = try BoundedProcess.run("/bin/ps", arguments:["-ww","-axo","pid=,command="],timeout:3)
    var counts:[String:Int]=[:]
    for process in try ActivityInspector.processes(text,ownPID:ProcessInfo.processInfo.processIdentifier) where as_javascript_runtime(process.pid) == 1 {
        var birth=ASProcessBirth(),args=[CChar](repeating:0,count:262144),cwd=[CChar](repeating:0,count:4096),count=0
        let born=as_process_birth(process.pid,&birth)
        let code=born == 0 ? as_process_arguments(process.pid,&birth,&args,args.count,&count,&cwd,cwd.count) : -3
        let argv=Data(bytes:args,count:count).split(separator:0).compactMap{String(data:$0,encoding:.utf8)}
        var key=code != 0 ? "native-status-\(code)" : "argv-\(argv.count)-" + (argv.count > 1 ? (argv[1].hasPrefix("-") ? "option" : "entry") : "missing")
        if code == 0,argv.count > 1,!argv[1].hasPrefix("-") {
            let work=String(decoding:cwd.prefix{ $0 != 0 }.map{UInt8(bitPattern:$0)},as:UTF8.self)
            let path=argv[1].hasPrefix("/") ? argv[1] : work + "/" + argv[1]
            do {
                let url=URL(fileURLWithPath:path).standardizedFileURL,parent=try SafeDirectory(path:url.deletingLastPathComponent().path)
                let identity=try parent.identity(url.lastPathComponent)
                let content=try SafeFilesystem.readMetadata(url.path,maximumBytes:4*1024*1024)
                key += "-readable-" + (identity.changedSeconds <= Int64(birth.started_seconds) ? "unchanged" : "changed")
                let text=String(data:content,encoding:.utf8) ?? ""
                if text.contains("require(") || text.contains("import ") {key += "-imports"}
                if path.contains("/node_modules/") {key += "-package-entry"}
            } catch {key += "-" + error.localizedDescription}
            key += "-" + DownloadCacheActivity.diagnostic(pid:process.pid,home:try SystemIdentity.home())
        }
        counts[key,default:0]+=1
        if key.contains("-related") || key.contains("达到上限") || key.hasSuffix("-option") {
            print("RUNTIME_RETAINED pid=\(process.pid) entry=" + (argv.count > 1 ? URL(fileURLWithPath:argv[1]).lastPathComponent : "missing") + " " + DownloadCacheActivity.diagnostic(pid:process.pid,home:try SystemIdentity.home()))
        }
    }
    print("RUNTIME_DIAGNOSTIC " + String(data:try JSONSerialization.data(withJSONObject:counts,options:[.sortedKeys]),encoding:.utf8)!)
}
