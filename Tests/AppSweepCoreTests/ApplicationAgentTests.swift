#if os(macOS)
import Foundation
import XCTest
import Darwin
@testable import AppSweepCore

final class ApplicationAgentTests:XCTestCase,@unchecked Sendable {
    private let rule="signed-app-user-launch-agent-v1"
    private func fixture()throws->(NativeAcceptanceTests.NativeFixture,String,String){
        let f=try NativeAcceptanceTests.NativeFixture(additionalRules:[rule]),label="org.example.disposable.agent."+UUID().uuidString.lowercased()
        let infoPath=f.app+"/Contents/Info.plist"
        var info=try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:infoPath)),format:nil)as? [String:Any])
        info["CFBundleIdentifier"]=label
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:infoPath))
        _=try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-",f.app],timeout:10)
        let root=f.home+"/Library/LaunchAgents",path=root+"/"+label+".plist"
        try FileManager.default.createDirectory(atPath:root,withIntermediateDirectories:true)
        let values:[String:Any]=["Label":label,"ProgramArguments":[f.executable],"RunAtLoad":false,"KeepAlive":false]
        try PropertyListSerialization.data(fromPropertyList:values,format:.xml,options:0).write(to:URL(fileURLWithPath:path))
        return(f,path,label)
    }
    private func target(_ label:String)->String{"gui/"+String(getuid())+"/"+label}
    func testSuccessfulAgentUninstallCanPermanentlyClearItsIsolatedBatch()async throws{
        let(f,path,label)=try fixture();defer{_=try? BoundedProcess.capture("/bin/launchctl",arguments:["bootout",target(label)],timeout:5,mergeStderr:true);try? f.clean()}
        _=try BoundedProcess.run("/bin/launchctl",arguments:["bootstrap","gui/"+String(getuid()),path],timeout:5)
        try await f.waitUntilUnused(f.app)
        let report=try await f.engine.scanApplication(f.app),selected=Set(report.selectableCandidates(includeUserData:false).filter{$0.category == .application || $0.rule == rule}.map(\.id))
        XCTAssertEqual(selected.count,2)
        let plan=try await f.engine.makePlan(reportID:report.id,selected:selected,includeUserData:false),batch=try await f.engine.execute(planID:plan.id)
        guard batch.status == .isolated else{XCTFail(batch.issue ?? "Uninstall failed");return}
        try await f.waitForIsolatedObjects(batch)
        let fresh=SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[rule,"signed-application-v1"]),vaultPath:f.home+"/Library/Application Support/App Sweep/Recovery",fixture:false)
        let purged=try await fresh.purge(batchID:batch.id,confirmation:"永久清空 "+batch.id.uuidString)
        XCTAssertEqual(purged.status,.purged,purged.issue ?? "")
        XCTAssertTrue(purged.entries.allSatisfy{$0.state == .purged})
        XCTAssertFalse(FileManager.default.fileExists(atPath:f.app));XCTAssertFalse(FileManager.default.fileExists(atPath:path))
    }
    func testReinstalledApplicationPreventsAgentBatchPurgeBeforeAnyDeletion()async throws{
        let(f,path,_)=try fixture();defer{try? f.clean()};try await f.waitUntilUnused(f.app)
        let report=try await f.engine.scanApplication(f.app),selected=Set(report.selectableCandidates(includeUserData:false).filter{$0.category == .application || $0.rule == rule}.map(\.id))
        let plan=try await f.engine.makePlan(reportID:report.id,selected:selected,includeUserData:false),batch=try await f.engine.execute(planID:plan.id)
        guard batch.status == .isolated else{XCTFail(batch.issue ?? "Uninstall failed");return}
        let body=try XCTUnwrap(batch.entries.first{$0.original.category == .application}),stored=f.home+"/Library/Application Support/App Sweep/Recovery/"+batch.id.uuidString+"/"+batch.objectsDirectory+"/"+body.id.uuidString
        try FileManager.default.copyItem(atPath:stored,toPath:f.app)
        do{let result=try await f.engine.purge(batchID:batch.id,confirmation:"永久清空 "+batch.id.uuidString);XCTAssertNotEqual(result.status,.purged);XCTAssertFalse(result.entries.contains{$0.state == .purged})}catch{}
        XCTAssertTrue(FileManager.default.fileExists(atPath:stored));XCTAssertTrue(FileManager.default.fileExists(atPath:f.app));XCTAssertFalse(FileManager.default.fileExists(atPath:path))
    }
    func testAutoStartingInstalledAgentIsRetainedBeforeUninstall()async throws{
        let(f,path,_)=try fixture();defer{try? f.clean()}
        var info=try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:path)),format:nil)as? [String:Any]);info["RunAtLoad"]=true
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:path))
        XCTAssertThrowsError(try StaleUserAgentRule.inspect(path,home:f.home,installedApplication:f.app))
        let report=try await f.engine.scanApplication(f.app)
        XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains{$0.category == .application || $0.path == path})
        XCTAssertTrue(FileManager.default.fileExists(atPath:f.app));XCTAssertTrue(FileManager.default.fileExists(atPath:path))
    }
    func testDefaultUninstallIncludesExclusiveDormantAgentAndFreshRestoreRestoresItsRegistration()async throws{
        let(f,path,label)=try fixture();defer{_=try? BoundedProcess.capture("/bin/launchctl",arguments:["bootout",target(label)],timeout:5,mergeStderr:true);try? f.clean()}
        _=try BoundedProcess.run("/bin/launchctl",arguments:["bootstrap","gui/"+String(getuid()),path],timeout:5)
        try await f.waitUntilUnused(f.app)
        let before=try SafeFilesystem.snapshot(path),report=try await f.engine.scanApplication(f.app)
        guard let agent=report.candidates.first(where:{$0.path == path && $0.rule == rule})else{XCTFail("Installed exact app agent is missing from uninstall lifecycle");return}
        XCTAssertFalse(agent.userData);XCTAssertTrue(agent.selectedByDefault,agent.retentionReason ?? "")
        let selected=Set(report.candidates.filter{$0.category == .application || $0.id == agent.id}.map(\.id))
        let plan=try await f.engine.makePlan(reportID:report.id,selected:selected,includeUserData:false)
        let batch=try await f.engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        XCTAssertFalse(FileManager.default.fileExists(atPath:f.app));XCTAssertFalse(FileManager.default.fileExists(atPath:path))
        XCTAssertEqual(try BoundedProcess.capture("/bin/launchctl",arguments:["print",target(label)],timeout:5,mergeStderr:true).status,113)
        let fresh=SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[rule,"signed-application-v1"]),vaultPath:f.home+"/Library/Application Support/App Sweep/Recovery",fixture:false)
        let restored=try await fresh.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:"; "))
        XCTAssertEqual(try SafeFilesystem.snapshot(path).identity.inode,before.identity.inode)
        XCTAssertEqual(try BoundedProcess.capture("/bin/launchctl",arguments:["print",target(label)],timeout:5,mergeStderr:true).status,0)
        XCTAssertTrue(try AppInspector.inspect(f.app).signed)
    }
    func testBodyOnlyPlanCannotLeaveAnExactInstalledAgentBehind()async throws{
        let(f,_,_)=try fixture();defer{try? f.clean()};try await f.waitUntilUnused(f.app)
        let report=try await f.engine.scanApplication(f.app),body=try XCTUnwrap(report.candidates.first{$0.category == .application})
        XCTAssertTrue(body.allowed,body.retentionReason ?? "")
        do{_=try await f.engine.makePlan(reportID:report.id,selected:[body.id],includeUserData:false);XCTFail("Body-only uninstall left an installed exact agent behind")}catch{}
    }
    func testUnregisterInterruptionRestoresAgentWithoutRequiringAnAlreadyMovedBody()async throws{
        let(f,path,label)=try fixture();defer{_=try? BoundedProcess.capture("/bin/launchctl",arguments:["bootout",target(label)],timeout:5,mergeStderr:true);try? f.clean()}
        _=try BoundedProcess.run("/bin/launchctl",arguments:["bootstrap","gui/"+String(getuid()),path],timeout:5)
        let policy=SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[rule,"signed-application-v1"]),vault=f.home+"/Library/Application Support/App Sweep/Recovery"
        let engine=SweepEngine(policy:policy,vaultPath:vault,failurePoint:.agentAfterUnregister,fixture:false)
        let report=try await engine.scanApplication(f.app),selected=Set(report.selectableCandidates(includeUserData:false).filter{$0.category == .application || $0.rule == rule}.map(\.id))
        XCTAssertEqual(selected.count,2)
        let plan=try await engine.makePlan(reportID:report.id,selected:selected,includeUserData:false)
        do{_=try await engine.execute(planID:plan.id);XCTFail("Expected interruption after durable unregister")}catch{}
        XCTAssertTrue(FileManager.default.fileExists(atPath:f.app));XCTAssertTrue(FileManager.default.fileExists(atPath:path))
        XCTAssertEqual(try BoundedProcess.capture("/bin/launchctl",arguments:["print",target(label)],timeout:5,mergeStderr:true).status,113)
        let fresh=SweepEngine(policy:policy,vaultPath:vault,fixture:false),batches=try await fresh.recoveryBatches(),batch=try XCTUnwrap(batches.first)
        let restored=try await fresh.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        XCTAssertEqual(try BoundedProcess.capture("/bin/launchctl",arguments:["print",target(label)],timeout:5,mergeStderr:true).status,0)
    }
    func testBodyMoveFailureRollsBackAgentAndOriginalRegistration()async throws{
        let(f,path,label)=try fixture();defer{_=try? BoundedProcess.capture("/bin/launchctl",arguments:["bootout",target(label)],timeout:5,mergeStderr:true);try? f.clean()}
        _=try BoundedProcess.run("/bin/launchctl",arguments:["bootstrap","gui/"+String(getuid()),path],timeout:5)
        let policy=SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[rule,"signed-application-v1"]),vault=f.home+"/Library/Application Support/App Sweep/Recovery"
        let engine=SweepEngine(policy:policy,vaultPath:vault,failurePoint:.beforeSecondMove,fixture:false)
        let report=try await engine.scanApplication(f.app),selected=Set(report.selectableCandidates(includeUserData:false).filter{$0.category == .application || $0.rule == rule}.map(\.id))
        XCTAssertEqual(selected.count,2)
        let plan=try await engine.makePlan(reportID:report.id,selected:selected,includeUserData:false),batch=try await engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.rolledBack,batch.issue ?? "")
        XCTAssertTrue(FileManager.default.fileExists(atPath:f.app));XCTAssertTrue(FileManager.default.fileExists(atPath:path))
        XCTAssertEqual(try BoundedProcess.capture("/bin/launchctl",arguments:["print",target(label)],timeout:5,mergeStderr:true).status,0)
    }
    func testUnknownRelatedRegistrationAndUnsafeDeclarationKeepTheWholeUninstall()async throws{
        for kind in ["unknown-related-job","keep-alive"]{
            let(f,path,label)=try fixture();var foreign:String?
            defer{if let foreign{_=try? BoundedProcess.capture("/bin/launchctl",arguments:["bootout",target(foreign)],timeout:5,mergeStderr:true)};try? f.clean()}
            if kind == "keep-alive"{
                var info=try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:path)),format:nil)as? [String:Any]);info["KeepAlive"]=true
                try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:path))
            }else{
                let other=label+".foreign",otherPath=f.home+"/Library/LaunchAgents/"+other+".plist"
                let info:[String:Any]=["Label":other,"ProgramArguments":["/usr/bin/true"],"RunAtLoad":false]
                try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:otherPath));foreign=other
                _=try BoundedProcess.run("/bin/launchctl",arguments:["bootstrap","gui/"+String(getuid()),otherPath],timeout:5)
            }
            let report=try await f.engine.scanApplication(f.app)
            XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains{$0.category == .application},kind)
            XCTAssertTrue(FileManager.default.fileExists(atPath:f.app));XCTAssertTrue(FileManager.default.fileExists(atPath:path))
        }
    }
}
#endif
