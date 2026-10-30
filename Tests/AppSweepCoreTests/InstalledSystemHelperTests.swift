#if os(macOS)
import Foundation
import XCTest
import Darwin
@testable import AppSweepCore

final class InstalledSystemHelperTests:XCTestCase,@unchecked Sendable{
    func testOtherAccountOrUnknownAccountTableCannotAuthorizeGlobalComponentManagement()throws{
        func packet(_ ids:[String])throws->Data{try PropertyListSerialization.data(fromPropertyList:ids.map{["dsAttrTypeStandard:UniqueID":[$0]]},format:.xml,options:0)}
        XCTAssertFalse(try InstalledSystemHelperRule.hasOtherAccounts(packet(["0","-2","501"]),requesterUID:501))
        XCTAssertTrue(try InstalledSystemHelperRule.hasOtherAccounts(packet(["0","501","502"]),requesterUID:501))
        XCTAssertTrue(try InstalledSystemHelperRule.hasOtherAccounts(packet(["501","100001"]),requesterUID:501))
        XCTAssertThrowsError(try InstalledSystemHelperRule.hasOtherAccounts(packet(["0","-2"]),requesterUID:501))
        XCTAssertThrowsError(try InstalledSystemHelperRule.hasOtherAccounts(packet(["501","unknown"]),requesterUID:501))
    }
    func testOnlyVerifiedZeroPIDJobAndDormantMachEndpointCanBeExcluded(){
        let label="org.example.helper",text="0 - \(label)\n0 M D \(label)\n0x123 M A \(label)\n0 - \(label).other\n"
        let remaining=InstalledSystemHelperRule.unresolvedRegistry(text,verifiedLabel:label)
        XCTAssertFalse(remaining.components(separatedBy:"\n").contains("0 - "+label))
        XCTAssertFalse(remaining.components(separatedBy:"\n").contains("0 M D "+label))
        XCTAssertTrue(remaining.contains("0x123 M A "+label));XCTAssertTrue(remaining.contains(label+".other"))
        XCTAssertEqual(InstalledSystemHelperRule.unresolvedRegistry(text,verifiedLabel:nil),text.trimmingCharacters(in:.newlines))
    }
    private func category()->SystemCleanupCategory?{
        let value=SystemCleanupCategory(rawValue:"applicationHelpers")
        XCTAssertNotNil(value,"Installed privileged application components need an explicit product scope")
        return value
    }
    private func prepared(sleeping:Bool=false,authorizedOtherID:String?=nil)throws->(NativeAcceptanceTests.NativeFixture,SystemCleanupScope,String,String,String){
        let f=try NativeAcceptanceTests.NativeFixture(),nonce=UUID().uuidString.lowercased(),appID="org.example.helperapp."+nonce,label="org.example.helper."+nonce
        let library=f.home+"/MachineLibrary",tools=library+"/PrivilegedHelperTools",agents=library+"/LaunchDaemons",embedded=f.app+"/Contents/Library/LaunchServices/"+label
        for path in [tools,agents,URL(fileURLWithPath:embedded).deletingLastPathComponent().path]{try FileManager.default.createDirectory(atPath:path,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])}
        let appInfo=f.app+"/Contents/Info.plist"
        var info=try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:appInfo)),format:nil)as? [String:Any])
        info["CFBundleIdentifier"]=appID;info["SMPrivilegedExecutables"]=[label:"identifier \""+label+"\""]
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:appInfo))
        let metadata=f.home+"/helper-info.plist",source=f.home+"/helper.c"
        let client="identifier \""+appID+"\""+(authorizedOtherID.map{" or identifier \""+$0+"\""} ?? "")
        try PropertyListSerialization.data(fromPropertyList:["CFBundleIdentifier":label,"CFBundleVersion":"1","SMAuthorizedClients":[client]],format:.xml,options:0).write(to:URL(fileURLWithPath:metadata))
        try Data((sleeping ? "#include <unistd.h>\nint main(void){sleep(60);return 0;}\n" : "int main(void){return 0;}\n").utf8).write(to:URL(fileURLWithPath:source))
        let clang=try XCTUnwrap(ProcessInfo.processInfo.environment["APP_SWEEP_CLANG"]),sdk=try XCTUnwrap(ProcessInfo.processInfo.environment["APP_SWEEP_SDK"])
        _=try BoundedProcess.run(clang,arguments:["-isysroot",sdk,"-mmacosx-version-min=12.0",source,"-Wl,-sectcreate,__TEXT,__info_plist,"+metadata,"-o",embedded],timeout:15)
        _=try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-","--identifier",label,embedded],timeout:10)
        _=try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-",f.app],timeout:10)
        let binary=tools+"/"+label,plist=agents+"/"+label+".plist"
        try FileManager.default.copyItem(atPath:embedded,toPath:binary)
        try PropertyListSerialization.data(fromPropertyList:["Label":label,"ProgramArguments":[binary],"MachServices":[label:true]],format:.xml,options:0).write(to:URL(fileURLWithPath:plist))
        let scope=try SystemCleanupScope.fixture(libraryRoot:library,applicationsRoot:f.home+"/Applications",userHome:f.home,requesterUID:UInt32(getuid()))
        return(f,scope,label,plist,binary)
    }
    func testUninstallPrerequisiteReviewSelectsOnlyTargetAndKeepsBody() async throws {
        let (f, scope, _, plist, binary) = try prepared(); defer { try? f.clean() }
        let hub = CoordinatorServiceFixture(scope: scope)
        let coordinator = try CleanupCoordinator.fixture(engine: f.engine, systemFactory: { try await hub.connect() })
        do {
            let review = try await coordinator.reviewApplicationPrerequisites(applicationPath: f.app)
            XCTAssertEqual(review.applicationPrerequisite, f.app)
            XCTAssertEqual(Set(review.items.map(\.path)), [plist, binary])
            let result = try await coordinator.execute(reviewID: review.id)
            XCTAssertEqual(result.status, .isolated, result.issue ?? "")
            XCTAssertTrue(FileManager.default.fileExists(atPath: f.app), "Prerequisite stage cannot remove the body")
            for record in result.batches {
                let restored = try await coordinator.restore(source: record.source, batchID: record.manifest.id)
                XCTAssertEqual(restored.status, .restored)
            }
            await coordinator.close(); await hub.finish()
        } catch { await coordinator.close(); await hub.finish(); throw error }
    }
    func testExactDormantComponentPairCanBeIsolatedAndNativeRegistrationRestored()async throws{
        guard let category=category() else{return}
        let(f,scope,label,plist,binary)=try prepared();defer{try? f.clean()}
        let domain="gui/"+String(getuid()),target=domain+"/"+label
        _=try BoundedProcess.run("/bin/launchctl",arguments:["bootstrap",domain,plist],timeout:5)
        defer{_=try? BoundedProcess.capture("/bin/launchctl",arguments:["bootout",target],timeout:5,mergeStderr:true)}
        let original=try SafeFilesystem.snapshot(binary),engine=try SystemCleanupEngine(scope:scope),report=try await engine.scan(category)
        let pair=report.selectableCandidates(includeUserData:false).filter{[plist,binary].contains($0.path)}
        XCTAssertEqual(Set(pair.map(\.path)),[plist,binary],report.candidates.compactMap(\.retentionReason).joined(separator:"; "))
        XCTAssertTrue(pair.allSatisfy{!$0.selectedByDefault && $0.category == .backgroundComponent})
        guard pair.count == 2 else{
            let full=try BoundedProcess.run("/bin/launchctl",arguments:["print",domain],timeout:5),lines=full.components(separatedBy:"\n")
            var indexes=Set<Int>()
            for (i,line)in lines.enumerated() where line.contains(label){for j in max(0,i-2)...min(lines.count-1,i+8){indexes.insert(j)}}
            print("EXACT_OWN_HELPER_REGISTRY_CONTEXT\n"+indexes.sorted().map{lines[$0]}.joined(separator:"\n"))
            return
        }
        XCTAssertEqual(report.selectionIDs(for:pair[0].id,includeUserData:false),Set(pair.map(\.id)))
        do{_=try await engine.makePlan(reportID:report.id,selected:[pair[0].id]);XCTFail("Component pair cannot be split")}catch{}
        let plan=try await engine.makePlan(reportID:report.id,selected:Set(pair.map(\.id))),batch=try await engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        XCTAssertFalse(FileManager.default.fileExists(atPath:plist));XCTAssertFalse(FileManager.default.fileExists(atPath:binary))
        XCTAssertEqual(try BoundedProcess.capture("/bin/launchctl",arguments:["print",target],timeout:5,mergeStderr:true).status,113)
        let user=SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[SelectedApplicationRule.name]),vaultPath:f.home+"/Library/Application Support/App Sweep/Recovery",fixture:false)
        let body=try await user.scanApplication(f.app)
        XCTAssertTrue(body.selectableCandidates(includeUserData:false).contains{$0.path == f.app},"Removing confirmed system dependencies must unblock normal application uninstall")
        let fresh=try SystemCleanupEngine(scope:scope),restored=try await fresh.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        XCTAssertEqual(try SafeFilesystem.snapshot(binary).identity.inode,original.identity.inode)
        XCTAssertEqual(try BoundedProcess.capture("/bin/launchctl",arguments:["print",target],timeout:5,mergeStderr:true).status,0)
    }
    func testEarlyUnregisterInterruptionCanRestoreTheWholePair()async throws{
        guard let category=category() else{return}
        let(f,scope,label,plist,binary)=try prepared();defer{try? f.clean()}
        let domain="gui/"+String(getuid()),target=domain+"/"+label
        _=try BoundedProcess.run("/bin/launchctl",arguments:["bootstrap",domain,plist],timeout:5)
        defer{_=try? BoundedProcess.capture("/bin/launchctl",arguments:["bootout",target],timeout:5,mergeStderr:true)}
        let engine=try SystemCleanupEngine(scope:scope,failurePoint:.agentAfterUnregister),report=try await engine.scan(category)
        let pair=report.selectableCandidates(includeUserData:false).filter{[plist,binary].contains($0.path)}
        guard pair.count == 2 else{XCTFail("Native helper pair was retained");return}
        let plan=try await engine.makePlan(reportID:report.id,selected:Set(pair.map(\.id)))
        do{_=try await engine.execute(planID:plan.id);XCTFail("Injected interruption must stop execution")}catch{}
        let page=try await engine.recoveryPage(after:nil),batch=try XCTUnwrap(page.items.first)
        let restored=try await SystemCleanupEngine(scope:scope).restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        XCTAssertEqual(try BoundedProcess.capture("/bin/launchctl",arguments:["print",target],timeout:5,mergeStderr:true).status,0)
    }
    func testSharedDeclarationAndKeepAliveRemainUntouched()async throws{
        guard let category=category() else{return}
        for mode in ["shared","KeepAlive"]{
            let(f,scope,_,plist,binary)=try prepared();defer{try? f.clean()}
            if mode == "shared"{
                let other=f.home+"/Applications/Other.app"
                try FileManager.default.copyItem(atPath:f.app,toPath:other)
                var info=try AppInspector.metadata(other,component:false).0
                info["CFBundleIdentifier"]="org.example.other."+UUID().uuidString.lowercased()
                try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:other+"/Contents/Info.plist"))
                _=try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-",other],timeout:10)
            }else{
                var info=try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:plist)),format:nil)as? [String:Any]);info["KeepAlive"]=true
                try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:plist))
            }
            let original=try Data(contentsOf:URL(fileURLWithPath:binary)),report=try await SystemCleanupEngine(scope:scope).scan(category)
            XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains{[plist,binary].contains($0.path)},mode)
            XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:binary)),original)
            XCTAssertTrue(FileManager.default.fileExists(atPath:plist))
        }
    }
    func testRunningHelperIsRetainedWithoutEndingItsProcess()async throws{
        guard let category=category() else{return}
        let(f,scope,label,plist,binary)=try prepared(sleeping:true);defer{try? f.clean()}
        let domain="gui/"+String(getuid()),target=domain+"/"+label
        _=try BoundedProcess.run("/bin/launchctl",arguments:["bootstrap",domain,plist],timeout:5)
        defer{_=try? BoundedProcess.capture("/bin/launchctl",arguments:["bootout",target],timeout:5,mergeStderr:true)}
        _=try BoundedProcess.run("/bin/launchctl",arguments:["kickstart",target],timeout:5)
        let text=try BoundedProcess.run("/bin/launchctl",arguments:["print",target],timeout:5)
        let pid=try XCTUnwrap(text.components(separatedBy:"\n").map{$0.trimmingCharacters(in:.whitespaces)}.first{$0.hasPrefix("pid = ")})
        let report=try await SystemCleanupEngine(scope:scope).scan(category)
        XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains{[plist,binary].contains($0.path)})
        XCTAssertTrue(try BoundedProcess.run("/bin/launchctl",arguments:["print",target],timeout:5).contains(pid),"Product must leave the running process alone")
        XCTAssertTrue(FileManager.default.fileExists(atPath:plist));XCTAssertTrue(FileManager.default.fileExists(atPath:binary))
    }
    func testRecreatedHelperBlocksRestorationAndRegistration()async throws{
        guard let category=category() else{return}
        let(f,scope,label,plist,binary)=try prepared();defer{try? f.clean()}
        let domain="gui/"+String(getuid()),target=domain+"/"+label
        _=try BoundedProcess.run("/bin/launchctl",arguments:["bootstrap",domain,plist],timeout:5)
        defer{_=try? BoundedProcess.capture("/bin/launchctl",arguments:["bootout",target],timeout:5,mergeStderr:true)}
        let engine=try SystemCleanupEngine(scope:scope),report=try await engine.scan(category),pair=report.selectableCandidates(includeUserData:false).filter{[plist,binary].contains($0.path)}
        guard pair.count == 2 else{XCTFail("Expected original component pair");return}
        let plan=try await engine.makePlan(reportID:report.id,selected:Set(pair.map(\.id))),batch=try await engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated)
        let newer=Data("new independent helper file".utf8);try newer.write(to:URL(fileURLWithPath:binary),options:.withoutOverwriting)
        let restored=try await SystemCleanupEngine(scope:scope).restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.needsAttention)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:binary)),newer)
        XCTAssertEqual(try BoundedProcess.capture("/bin/launchctl",arguments:["print",target],timeout:5,mergeStderr:true).status,113)
    }
    func testIsolatedHelperCanBePurgedAfterApplicationWasUninstalled()async throws{
        guard let category=category() else{return}
        let(f,scope,_,plist,binary)=try prepared();defer{try? f.clean()}
        let engine=try SystemCleanupEngine(scope:scope),report=try await engine.scan(category),pair=report.selectableCandidates(includeUserData:false).filter{[plist,binary].contains($0.path)}
        guard pair.count == 2 else{XCTFail("Expected unregistered component pair");return}
        let plan=try await engine.makePlan(reportID:report.id,selected:Set(pair.map(\.id))),batch=try await engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated)
        try FileManager.default.moveItem(atPath:f.app,toPath:f.home+"/Held.app")
        let purged=try await SystemCleanupEngine(scope:scope).purge(batchID:batch.id,confirmation:"永久清空 "+batch.id.uuidString)
        XCTAssertEqual(purged.status,.purged)
        XCTAssertFalse(FileManager.default.fileExists(atPath:plist));XCTAssertFalse(FileManager.default.fileExists(atPath:binary))
        XCTAssertTrue(FileManager.default.fileExists(atPath:f.home+"/Held.app"))
    }
    func testNewAuthorizedClientAfterReviewBlocksExecution()async throws{
        guard let category=category() else{return}
        let otherID="org.example.newclient."+UUID().uuidString.lowercased(),(f,scope,_,plist,binary)=try prepared(authorizedOtherID:otherID);defer{try? f.clean()}
        let engine=try SystemCleanupEngine(scope:scope),report=try await engine.scan(category),pair=report.selectableCandidates(includeUserData:false).filter{[plist,binary].contains($0.path)}
        guard pair.count == 2 else{XCTFail("Expected initially exclusive helper");return}
        let plan=try await engine.makePlan(reportID:report.id,selected:Set(pair.map(\.id)))
        let other=f.home+"/Applications/Other.app";try FileManager.default.copyItem(atPath:f.app,toPath:other)
        var info=try AppInspector.metadata(other,component:false).0
        info["CFBundleIdentifier"]=otherID;info.removeValue(forKey:"SMPrivilegedExecutables")
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:other+"/Contents/Info.plist"))
        _=try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-",other],timeout:10)
        do{_=try await engine.execute(planID:plan.id);XCTFail("A new natively authorized shared client must invalidate the old plan")}catch{}
        XCTAssertTrue(FileManager.default.fileExists(atPath:plist));XCTAssertTrue(FileManager.default.fileExists(atPath:binary))
    }
}
#endif
