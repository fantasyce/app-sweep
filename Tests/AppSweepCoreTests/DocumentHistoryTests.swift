#if os(macOS)
import Foundation
import XCTest
import Darwin
@testable import AppSweepCore

final class DocumentHistoryTests:XCTestCase,@unchecked Sendable {
    private func contents(_ document:URL)throws->[String]{
        let versions=try XCTUnwrap(NSFileVersion.otherVersionsOfItem(at:document));var result:[String]=[]
        for version in versions{
            var coordination:NSError?,failure:Error?,payload:Data?
            NSFileCoordinator(filePresenter:nil).coordinate(readingItemAt:version.url,options:[],error:&coordination){url in do{payload=try Data(contentsOf:url)}catch{failure=error}}
            if let coordination{throw coordination};if let failure{throw failure};result.append(try XCTUnwrap(payload).base64EncodedString())
        }
        return result.sorted()
    }
    func testNativeHistoryUsesExplicitPlanIndependentBackupsAndFreshRestoreWithoutTouchingCurrentDocument()async throws{
        guard ProcessInfo.processInfo.environment["APP_SWEEP_DOCUMENT_HISTORY_ACCEPTANCE"] == "AppSweep-General-20261016",getuid() == 501,try SystemIdentity.home() == "/Users/localtest",try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).hasPrefix("VirtualMac") else{throw XCTSkip("Single registered native document history fixture only")}
        let task="/Users/localtest/AppSweepAcceptanceGeneral-20261016",id="fca942ac-9b87-4109-8a57-f1f4d7efa8b3",owned=task + "/native-document-versions-" + id + ".noindex",path="/Users/localtest/Documents/AppSweep Version " + id + ".txt",rule="document-history-versions-v1"
        guard try SafeDirectory(path:owned).ownIdentity.inode == 10947435,try SafeFilesystem.snapshot(path).identity.inode == 10947441,try !SafeFilesystem.presence(owned + "/result.json") else{throw SweepError.denied("Registered document fixture changed or already completed")}
        let url=URL(fileURLWithPath:path),before=try Data(contentsOf:url),history=try contents(url)
        XCTAssertEqual(history.count,2)
        let policy=SafetyPolicy(home:"/Users/localtest",acceptedPlatform:true,validatedRules:[rule]),vault=owned + "/Recovery",engine=SweepEngine(policy:policy,vaultPath:vault,fixture:false),report=try await engine.scanLegacyManagementFixture()
        guard let item=report.selectableCandidates(includeUserData:true).first(where:{$0.path == path && $0.rule == rule})else{XCTFail("Document history has no native managed plan: " + report.candidates.filter{$0.path == path}.compactMap(\.retentionReason).joined(separator:"; ") + report.issues.filter{$0.contains(path)}.joined(separator:"; "));return}
        XCTAssertTrue(item.userData);XCTAssertFalse(item.selectedByDefault)
        XCTAssertFalse(report.selectableCandidates(includeUserData:false).contains{$0.id == item.id})
        let plan=try await engine.makePlan(reportID:report.id,selected:[item.id],includeUserData:true),batch=try await engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? batch.entries.compactMap(\.message).joined(separator:"; "))
        guard batch.status == .isolated else{return}
        XCTAssertEqual(try Data(contentsOf:url),before);XCTAssertEqual(try contents(url),[])
        XCTAssertEqual(batch.isolatedBytes,0,"Current document must never be moved or counted as isolated")
        XCTAssertGreaterThan(batch.independentBackupBytes,0)
        let fresh=SweepEngine(policy:policy,vaultPath:vault,fixture:false),restored=try await fresh.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:"; "))
        XCTAssertEqual(try Data(contentsOf:url),before);XCTAssertEqual(try SafeFilesystem.snapshot(path).identity.inode,10947441)
        XCTAssertEqual(try contents(url),history,"Native history lookup must see all original bytes; restored history uses new native identities")
        let result:[String:Any]=["document":path,"documentInode":10947441,"versions":history.count,"batch":batch.id.uuidString,"state":"native history plan, independent backup, per-version API removal and fresh native-history restoration; current document unchanged; ordinary UI pending"]
        try JSONSerialization.data(withJSONObject:result,options:[.sortedKeys]).write(to:URL(fileURLWithPath:owned + "/result.json"),options:.withoutOverwriting)
        print("NATIVE_DOCUMENT_HISTORY_ACCEPTED " + String(data:try JSONSerialization.data(withJSONObject:result),encoding:.utf8)!)
    }
    private func boundaryContext()throws->(String,String,SafetyPolicy){
        guard ProcessInfo.processInfo.environment["APP_SWEEP_DOCUMENT_HISTORY_ACCEPTANCE"] == "AppSweep-General-20261016",getuid() == 501,try SystemIdentity.home() == "/Users/localtest",try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).hasPrefix("VirtualMac") else{throw XCTSkip("Registered VM history boundary checks only")}
        let owned="/Users/localtest/AppSweepAcceptanceGeneral-20261016/native-document-versions-fca942ac-9b87-4109-8a57-f1f4d7efa8b3.noindex",path="/Users/localtest/Documents/AppSweep Version fca942ac-9b87-4109-8a57-f1f4d7efa8b3.txt"
        guard try SafeDirectory(path:owned).ownIdentity.inode == 10947435,try SafeFilesystem.snapshot(path).identity.inode == 10947441,try SafeFilesystem.presence(owned + "/result.json") else{throw XCTSkip("Complete basic registered history recovery before boundary checks")}
        return(owned,path,SafetyPolicy(home:"/Users/localtest",acceptedPlatform:true,validatedRules:["document-history-versions-v1"]))
    }
    private func historyPlan(_ engine:SweepEngine,path:String)async throws->CleanupPlan{
        let report=try await engine.scanLegacyManagementFixture(),item=try XCTUnwrap(report.selectableCandidates(includeUserData:true).first{$0.path == path && $0.rule == "document-history-versions-v1"},report.unconfirmedIssues.joined(separator:"; "))
        return try await engine.makePlan(reportID:report.id,selected:[item.id],includeUserData:true)
    }
    func testNativeInterruptionReconcilesRemovalAndAddedHistoryWithoutDuplicates()async throws{
        let(owned,path,policy)=try boundaryContext(),vault=owned + "/Recovery",url=URL(fileURLWithPath:path),current=try Data(contentsOf:url),original=try contents(url)
        XCTAssertEqual(original.count,2)
        let first=SweepEngine(policy:policy,vaultPath:vault,failurePoint:.interruptAfterMove,fixture:false),plan=try await historyPlan(first,path:path)
        var unexpected:RecoveryManifest?
        do{unexpected=try await first.execute(planID:plan.id);XCTFail("Native history removal needs its durable interruption boundary")}catch{print("HISTORY_REMOVAL_STOP " + String(describing:error))}
        let fresh=SweepEngine(policy:policy,vaultPath:vault,fixture:false)
        if let unexpected{_=try await fresh.restore(batchID:unexpected.id);return}
        XCTAssertEqual(try contents(url).count,1);XCTAssertEqual(try Data(contentsOf:url),current)
        let batches=try await fresh.recoveryBatches(),pending=try XCTUnwrap(batches.first{$0.hasUnconfirmedObjects})
        let recovered=try await fresh.restore(batchID:pending.id);XCTAssertEqual(recovered.status,.restored,recovered.entries.compactMap(\.message).joined(separator:"; "))
        XCTAssertEqual(try contents(url),original)
        let next=SweepEngine(policy:policy,vaultPath:vault,fixture:false),nextPlan=try await historyPlan(next,path:path),isolated=try await next.execute(planID:nextPlan.id)
        XCTAssertEqual(isolated.status,.isolated,isolated.issue ?? "")
        let interruptedRestore=SweepEngine(policy:policy,vaultPath:vault,failurePoint:.afterReconstruction,fixture:false)
        var unexpectedlyRestored=false
        do{_=try await interruptedRestore.restore(batchID:isolated.id);unexpectedlyRestored=true;XCTFail("Native history recreation needs its durable interruption boundary")}catch{}
        if unexpectedlyRestored{return}
        XCTAssertEqual(try contents(url).count,1)
        let final=try await SweepEngine(policy:policy,vaultPath:vault,fixture:false).restore(batchID:isolated.id)
        XCTAssertEqual(final.status,.restored,final.entries.compactMap(\.message).joined(separator:"; "))
        XCTAssertEqual(try contents(url),original);XCTAssertEqual(try Data(contentsOf:url),current)
        print("NATIVE_HISTORY_INTERRUPTION_ACCEPTED removal=" + pending.id.uuidString + " restoration=" + isolated.id.uuidString)
    }
    func testChangedCurrentDocumentBlocksHistoryRestorationWithoutOverwrite()async throws{
        let(owned,path,policy)=try boundaryContext(),vault=owned + "/Recovery",url=URL(fileURLWithPath:path),before=try Data(contentsOf:url),original=try contents(url)
        let engine=SweepEngine(policy:policy,vaultPath:vault,fixture:false),plan=try await historyPlan(engine,path:path),batch=try await engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        guard batch.status == .isolated else{return}
        let changed=Data("registered current document edited after history cleanup\n".utf8)
        try changed.write(to:url)
        let blocked=try await SweepEngine(policy:policy,vaultPath:vault,fixture:false).restore(batchID:batch.id)
        XCTAssertEqual(blocked.status,.needsAttention);XCTAssertEqual(try Data(contentsOf:url),changed);XCTAssertEqual(try contents(url),[])
        // Restore only this registered fixture's unchanged current bytes, then
        // use the public product recovery to return its original histories.
        try before.write(to:url)
        let restored=try await SweepEngine(policy:policy,vaultPath:vault,fixture:false).restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:"; "))
        XCTAssertEqual(try contents(url),original);XCTAssertEqual(try Data(contentsOf:url),before)
        print("NATIVE_HISTORY_CURRENT_CONFLICT_ACCEPTED " + batch.id.uuidString)
    }
    func testNativePurgeOfRestoredBackupKeepsCurrentAndNativeHistoryReadable()async throws{
        let(owned,path,policy)=try boundaryContext(),vault=owned + "/Recovery",url=URL(fileURLWithPath:path),before=try Data(contentsOf:url),versions=try contents(url)
        let result=try XCTUnwrap(try JSONSerialization.jsonObject(with:SafeFilesystem.readMetadata(owned + "/result.json"))as? [String:Any]),id=try XCTUnwrap(UUID(uuidString:try XCTUnwrap(result["batch"]as? String)))
        let engine=SweepEngine(policy:policy,vaultPath:vault,fixture:false),all=try await engine.recoveryBatches(),batch=try XCTUnwrap(all.first{$0.id == id})
        if batch.status != .purged{let purged=try await engine.purge(batchID:id,confirmation:"永久清空 " + id.uuidString);XCTAssertEqual(purged.status,.purged,purged.issue ?? "")}
        let readable=try await SweepEngine(policy:policy,vaultPath:vault,fixture:false).recoveryBatches()
        XCTAssertEqual(readable.first{$0.id == id}?.status,.purged)
        XCTAssertEqual(try Data(contentsOf:url),before);XCTAssertEqual(try contents(url),versions)
        print("NATIVE_HISTORY_PURGE_ACCEPTED " + id.uuidString)
    }
    func testUnconfirmedDirectoryDoesNotDisableIndependentOwnedHistory()async throws{
        let(owned,path,policy)=try boundaryContext(),parent=try SafeDirectory(path:"/Users/localtest/Documents"),name="AppSweep Blocked Scope " + UUID().uuidString
        try SafeDirectory(path:owned).write(JSONSerialization.data(withJSONObject:["directory":parent.path + "/" + name,"purpose":"one empty owned unreadable discovery scope; remove only through original held parent descriptor"]),name:"scope-intent-" + UUID().uuidString + ".json")
        XCTAssertEqual(name.withCString{mkdirat(parent.fd,$0,0o700)},0)
        let blocked=try SafeDirectory(path:parent.path + "/" + name),identity=try blocked.ownIdentity
        defer{_=fchmod(blocked.fd,0o700);if (try? parent.identity(name))?.inode == identity.inode{_=name.withCString{unlinkat(parent.fd,$0,AT_REMOVEDIR)}}}
        XCTAssertEqual(fchmod(blocked.fd,0),0)
        let report=try await SweepEngine(policy:policy,vaultPath:owned + "/Recovery",fixture:false).scanLegacyManagementFixture()
        XCTAssertFalse(report.unconfirmedIssues.isEmpty)
        for item in report.candidates where item.path == path {print("HISTORY_SELECTION",item.retentionReason ?? "none",item.allowed,item.allowsPlanReview)}
        print("HISTORY_DISCOVERY_ISSUES",report.issues)
        XCTAssertTrue(report.selectableCandidates(includeUserData:true).contains{$0.path == path},"An unrelated inaccessible directory cannot disable a separately confirmed native history group")
    }

}
#endif
