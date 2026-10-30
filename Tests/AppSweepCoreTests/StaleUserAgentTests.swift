#if os(macOS)
import Foundation
import XCTest
import Darwin
@testable import AppSweepCore

final class StaleUserAgentTests: XCTestCase, @unchecked Sendable {
    private let rule="stale-user-launch-agent-v1"
    private func fixture() throws -> (NativeAcceptanceTests.NativeFixture,String,String) {
        let f=try NativeAcceptanceTests.NativeFixture(additionalRules:[rule]),label="org.example.disposable.stale." + UUID().uuidString.lowercased()
        let directory=f.home + "/Library/LaunchAgents",path=directory + "/" + label + ".plist"
        try FileManager.default.createDirectory(atPath:directory,withIntermediateDirectories:true)
        let values:[String:Any]=["Label":label,"ProgramArguments":[f.home + "/Applications/Missing.app/Contents/MacOS/missing"],"RunAtLoad":false,"KeepAlive":false]
        try PropertyListSerialization.data(fromPropertyList:values,format:.xml,options:0).write(to:URL(fileURLWithPath:path))
        return(f,path,label)
    }
    private func target(_ label:String)->String{"gui/" + String(getuid()) + "/" + label}
    func testRegisteredDormantMissingAppAgentIsIsolatedAndFreshRestorationRegistersOriginal() async throws {
        let(f,path,label)=try fixture();defer{_ = try? BoundedProcess.capture("/bin/launchctl",arguments:["bootout",target(label)],timeout:5,mergeStderr:true);try? f.clean()}
        _=try BoundedProcess.run("/bin/launchctl",arguments:["bootstrap","gui/" + String(getuid()),path],timeout:5)
        let original=try SafeFilesystem.snapshot(path),report=try await f.engine.scanLegacyManagementFixture()
        guard let item=report.candidates.first(where:{$0.path == path && $0.rule == rule}) else{XCTFail("Missing application agent has no explicit lifecycle cleanup");return}
        XCTAssertTrue(item.userData);XCTAssertFalse(item.selectedByDefault)
        XCTAssertTrue(report.selectableCandidates(includeUserData:true).contains{$0.id == item.id},item.retentionReason ?? "")
        let plan=try await f.engine.makePlan(reportID:report.id,selected:[item.id],includeUserData:true),batch=try await f.engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        XCTAssertFalse(FileManager.default.fileExists(atPath:path))
        XCTAssertEqual(try BoundedProcess.capture("/bin/launchctl",arguments:["print",target(label)],timeout:5,mergeStderr:true).status,113)
        let fresh=SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[rule]),vaultPath:f.home + "/Library/Application Support/App Sweep/Recovery",fixture:false)
        let restored=try await fresh.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:"; "))
        XCTAssertEqual(try SafeFilesystem.snapshot(path).identity.inode,original.identity.inode)
        XCTAssertEqual(try BoundedProcess.capture("/bin/launchctl",arguments:["print",target(label)],timeout:5,mergeStderr:true).status,0)
    }
    func testExistingAppAndAliasTargetsDoNotCountAsStale() async throws {
        let(f,path,_)=try fixture();defer{try? f.clean()}
        let program=f.home + "/Applications/Missing.app/Contents/MacOS/missing"
        try FileManager.default.createDirectory(atPath:URL(fileURLWithPath:program).deletingLastPathComponent().path,withIntermediateDirectories:true)
        let report=try await f.engine.scanLegacyManagementFixture()
        XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains{$0.path == path})
        try FileManager.default.removeItem(atPath:f.home + "/Applications/Missing.app")
        try FileManager.default.createSymbolicLink(atPath:f.home + "/Applications/Missing.app",withDestinationPath:"/System/Applications")
        let alias=try await f.engine.scanLegacyManagementFixture()
        XCTAssertFalse(alias.selectableCandidates(includeUserData:true).contains{$0.path == path})
    }
    func testFreshRestoreDoesNotOverwriteReplacementAgent() async throws {
        let(f,path,_)=try fixture();defer{try? f.clean()}
        let report=try await f.engine.scanLegacyManagementFixture()
        guard let item=report.selectableCandidates(includeUserData:true).first(where:{$0.path == path}) else{XCTFail("No stale agent candidate");return}
        let plan=try await f.engine.makePlan(reportID:report.id,selected:[item.id],includeUserData:true),batch=try await f.engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        let replacement=Data("replacement must survive".utf8);try replacement.write(to:URL(fileURLWithPath:path))
        let restored=try await f.engine.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.needsAttention)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:path)),replacement)
    }
    func testInterruptionAfterUnregisterRestoresTheOriginalFileAndRegistration() async throws {
        let(f,path,label)=try fixture();defer{_=try? BoundedProcess.capture("/bin/launchctl",arguments:["bootout",target(label)],timeout:5,mergeStderr:true);try? f.clean()}
        _=try BoundedProcess.run("/bin/launchctl",arguments:["bootstrap","gui/" + String(getuid()),path],timeout:5)
        let policy=SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[rule]),vault=f.home + "/Library/Application Support/App Sweep/Recovery"
        let engine=SweepEngine(policy:policy,vaultPath:vault,failurePoint:.agentAfterUnregister,fixture:false)
        let report=try await engine.scanLegacyManagementFixture(),item=try XCTUnwrap(report.selectableCandidates(includeUserData:true).first{$0.path == path})
        let plan=try await engine.makePlan(reportID:report.id,selected:[item.id],includeUserData:true)
        do{_=try await engine.execute(planID:plan.id);XCTFail("Expected interrupted durable lifecycle")}catch{}
        XCTAssertTrue(FileManager.default.fileExists(atPath:path))
        XCTAssertEqual(try BoundedProcess.capture("/bin/launchctl",arguments:["print",target(label)],timeout:5,mergeStderr:true).status,113)
        let fresh=SweepEngine(policy:policy,vaultPath:vault,fixture:false),batches=try await fresh.recoveryBatches(),batch=try XCTUnwrap(batches.first)
        XCTAssertTrue(batch.hasUnconfirmedObjects)
        let restored=try await fresh.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:"; "))
        XCTAssertEqual(try BoundedProcess.capture("/bin/launchctl",arguments:["print",target(label)],timeout:5,mergeStderr:true).status,0)
    }
    func testReinstalledMissingApplicationPreventsRegistrationRestoration() async throws {
        let(f,path,label)=try fixture();defer{_=try? BoundedProcess.capture("/bin/launchctl",arguments:["bootout",target(label)],timeout:5,mergeStderr:true);try? f.clean()}
        _=try BoundedProcess.run("/bin/launchctl",arguments:["bootstrap","gui/" + String(getuid()),path],timeout:5)
        let report=try await f.engine.scanLegacyManagementFixture(),item=try XCTUnwrap(report.selectableCandidates(includeUserData:true).first{$0.path == path})
        let plan=try await f.engine.makePlan(reportID:report.id,selected:[item.id],includeUserData:true),batch=try await f.engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        let app=f.home + "/Applications/Missing.app";try FileManager.default.createDirectory(atPath:app,withIntermediateDirectories:false)
        let result=try await f.engine.restore(batchID:batch.id)
        XCTAssertEqual(result.status,.needsAttention)
        XCTAssertFalse(FileManager.default.fileExists(atPath:path))
        XCTAssertEqual(try BoundedProcess.capture("/bin/launchctl",arguments:["print",target(label)],timeout:5,mergeStderr:true).status,113)
    }

}
#endif
