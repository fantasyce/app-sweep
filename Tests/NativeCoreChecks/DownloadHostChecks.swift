import Foundation
import CFSafety
@testable import AppSweepCore

/// Read-only current-home comparison, through the public scan/plan boundary.
/// A plan is held in memory only; this check never calls execute or restore.
@MainActor func downloadHostChecks() async throws {
    guard let work=ProcessInfo.processInfo.environment["APP_SWEEP_TEST_WORK_ROOT"] else {throw CheckFailure("Task output required")}
    let home=try SystemIdentity.home()
    var rows:[[String:Any]]=[]
    let output=try BoundedProcess.run("/bin/ps",arguments:["-ww","-axo","pid=,command="],timeout:3)
    var runtimeCounts:[String:Int]=[:]
    for process in try ActivityInspector.processes(output,ownPID:ProcessInfo.processInfo.processIdentifier) where as_javascript_runtime(process.pid) == 1 {
        let relation=String(describing:DownloadCacheActivity.relation(pid:process.pid,home:home))
        runtimeCounts[relation,default:0] += 1
    }
    print("READONLY runtime relationship counts " + String(describing:runtimeCounts))
    for (root,producer) in ToolCacheRule.roots(home:home) where producer == .electron || producer == .electronBuilder {
        guard try SafeFilesystem.presence(root) else {continue}
        for path in try CacheDomainRule.members(root:root).sorted() {
            guard let location=ToolCacheRule.location(path,home:home),location.producer == producer else {continue}
            var row:[String:Any]=["path":path,"producer":producer.rawValue,"formatRecognized":false,"action":"read-only"]
            do {
                let snapshot=try ToolCacheRule.verify(path,home:home)
                row["formatRecognized"]=true;row["bytes"]=snapshot.bytes
                do {
                    try ToolCacheRule.ensureStopped(producer,home:home)
                    row["producerGatePassed"]=true
                    try BusyInspector.ensureUnused(snapshot)
                    row["occupancyCheckPassed"]=true
                    try SafeFilesystem.verify(snapshot)
                    row["identityRechecked"]=true
                } catch {row["retentionReason"]=error.localizedDescription}
            } catch {row["retentionReason"]=error.localizedDescription}
            rows.append(row)
        }
    }
    let accepted=NativeAcceptance.rules(for:PlatformStamp.current)
    try check(SafetyPolicy.current.executionEnabled && [DownloadCacheRule.electronName,DownloadCacheRule.builderName].allSatisfy(accepted.contains),"Current platform does not expose accepted backend rules")
    let engine=SweepEngine(),report=try await engine.scanJunk()
    let paths=Set(rows.compactMap{$0["path"] as? String})
    let selected=report.selectableCandidates(includeUserData:false).filter{paths.contains($0.path)}
    var planPaths:[String]=[],planIssue:String?
    do {
        let plan=try await engine.makePlan(reportID:report.id,selected:Set(selected.map(\.id)),includeUserData:false)
        planPaths=plan.items.map(\.path).sorted()
    } catch {planIssue=error.localizedDescription}
    for index in rows.indices {
        let path=rows[index]["path"] as! String
        rows[index]["selectable"]=selected.contains{$0.path == path}
        rows[index]["inReviewedPlan"]=planPaths.contains(path)
        if let candidate=report.candidates.first(where:{$0.path == path}),let reason=candidate.retentionReason {rows[index]["scanRetentionReason"]=reason}
    }
    var receipt:[String:Any]=["ruleVersion":SweepEngine.ruleVersion,"readOnly":true,"executionAttempted":false,"rows":rows,"runtimeCounts":runtimeCounts,"scanComplete":report.complete,"scanIssues":report.unconfirmedIssues,"planPaths":planPaths,"policyLimitation":"Inconclusive generic scripts are not proof of a downloader; known producers and actual file occupancy still block."]
    if let planIssue {receipt["planIssue"]=planIssue}
    let data=try JSONSerialization.data(withJSONObject:receipt,options:[.prettyPrinted,.sortedKeys])
    try data.write(to:URL(fileURLWithPath:work + "/download-host-readonly.json"))
    for row in rows {print("READONLY " + (row["path"] as! String) + ": " + String(describing:row["inReviewedPlan"]!) + " " + (row["retentionReason"] as? String ?? "producer gate and occupancy checked"))}
    try check(!rows.isEmpty && rows.allSatisfy{$0["identityRechecked"] as? Bool == true && $0["inReviewedPlan"] as? Bool == true},"Some observed download groups did not pass the read-only plan check; see receipt")
    print("PASS current-home download groups reach reviewed plan with no execution")
}
