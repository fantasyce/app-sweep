#if os(macOS)
import Foundation
import XCTest
import Darwin
@testable import AppSweepCore

final class ApplicationScriptsTests: XCTestCase, @unchecked Sendable {
    private let rule="signed-application-scripts-v1"
    private let identifier="org.example.appscripts." + UUID().uuidString.lowercased()
    private var rules:Set<String>{[rule,ChosenApplicationRule.name,ChosenApplicationRule.largeName]}
    private func fixture() throws -> (NativeAcceptanceTests.NativeFixture,String) {
        let f=try NativeAcceptanceTests.NativeFixture(additionalRules:rules),path=f.app + "/Contents/Info.plist"
        var info=try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:path)),format:nil)as? [String:Any]);info["CFBundleIdentifier"]=identifier
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:path))
        _=try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-",f.app],timeout:10)
        let root=f.home + "/Library/Application Scripts/" + identifier
        try FileManager.default.createDirectory(atPath:root,withIntermediateDirectories:true)
        try Data("return 42\n".utf8).write(to:URL(fileURLWithPath:root + "/disposable.applescript"))
        return(f,root)
    }
    func testExactSignedScriptNamespaceIsExplicitPersonalDataAndRestoresWithItsBody() async throws {
        let(f,root)=try fixture();defer{try? f.clean()}
        let original=try SafeFilesystem.snapshot(root),report=try await f.engine.scanApplication(f.app)
        guard let item=report.candidates.first(where:{$0.path == root && $0.rule == rule}) else{XCTFail("App-specific user scripts remain unhandled outside its main container");return}
        XCTAssertFalse(item.selectedByDefault);XCTAssertTrue(item.userData)
        XCTAssertFalse(report.selectableCandidates(includeUserData:false).contains{$0.id == item.id})
        XCTAssertTrue(report.selectableCandidates(includeUserData:true).contains{$0.id == item.id},item.retentionReason ?? "")
        let body=try XCTUnwrap(report.selectableCandidates(includeUserData:true).first{$0.category == .application})
        let plan=try await f.engine.makePlan(reportID:report.id,selected:[body.id,item.id],includeUserData:true),batch=try await f.engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        let fresh=SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:rules),vaultPath:f.home + "/Library/Application Support/App Sweep/Recovery",fixture:false)
        let restored=try await fresh.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:"; "))
        XCTAssertEqual(try SafeFilesystem.snapshot(root).identity.inode,original.identity.inode)
        XCTAssertEqual(try String(contentsOfFile:root + "/disposable.applescript",encoding:.utf8),"return 42\n")
    }
    func testSimilarNamesSharedPermissionsAndProtectedContentNeverBecomeScriptAuthority() async throws {
        let(f,root)=try fixture();defer{try? f.clean()}
        let neighbor=root + ".helper";try FileManager.default.copyItem(atPath:root,toPath:neighbor)
        XCTAssertEqual(chmod(root,0o777),0)
        let shared=try await f.engine.scanApplication(f.app)
        XCTAssertFalse(shared.selectableCandidates(includeUserData:true).contains{$0.path == root || $0.path == neighbor})
        XCTAssertEqual(chmod(root,0o755),0)
        try Data("protected".utf8).write(to:URL(fileURLWithPath:root + "/private.keychain-db"))
        let protected=try await f.engine.scanApplication(f.app)
        XCTAssertFalse(protected.selectableCandidates(includeUserData:true).contains{$0.path == root})
        XCTAssertTrue(FileManager.default.fileExists(atPath:neighbor + "/disposable.applescript"))
    }
    func testNativeScriptDirectoryUsesDefaultDataChoiceAndRestoredAppReadsItsScript() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_SCRIPT_DATA_ACCEPTANCE"] == "AppSweep-General-20261016" else{throw XCTSkip("Registered native app-specific scripts only")}
        guard getuid() == 501,try SystemIdentity.home() == "/Users/localtest",try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).trimmingCharacters(in:.whitespacesAndNewlines) == "VirtualMac2,1" else{throw SweepError.denied("Requires registered disposable VM")}
        let task="/Users/localtest/AppSweepAcceptanceGeneral-20261016"
        let info=try XCTUnwrap(try JSONSerialization.jsonObject(with:SafeFilesystem.readMetadata(task + "/application-scripts-default-current.json"))as? [String:Any])
        let id=try XCTUnwrap(info["id"]as? String),owned=try XCTUnwrap(info["owned"]as? String),app=try XCTUnwrap(info["application"]as? String),root=try XCTUnwrap(info["scripts"]as? String),bundle=try XCTUnwrap(info["identifier"]as? String)
        guard UUID(uuidString:id) != nil,owned == task + "/native-app-scripts-" + id + ".noindex",app == "/Users/localtest/Applications/Disposable Script Data " + id + ".app",bundle == "org.example.disposable.scripts." + id,root == "/Users/localtest/Library/Application Scripts/" + bundle,!FileManager.default.fileExists(atPath:owned + "/result.json") else{throw SweepError.denied("Native script fixture registration changed")}
        let before=try SafeFilesystem.snapshot(root),file=root + "/disposable.applescript",digest=try VerifiedFileStream.digest(SafeFilesystem.snapshot(file)),inode=try SafeFilesystem.snapshot(file).identity.inode
        let e=SweepEngine(),report=try await e.scanApplication(app)
        guard let item=report.candidates.first(where:{$0.path == root && $0.rule == rule}),report.selectableCandidates(includeUserData:true).contains(where:{$0.id == item.id}) else{XCTFail(report.candidates.filter{$0.path == root}.compactMap(\.retentionReason).joined(separator:"; "));return}
        XCTAssertTrue(item.userData);XCTAssertFalse(item.selectedByDefault)
        XCTAssertFalse(report.selectableCandidates(includeUserData:false).contains{$0.id == item.id})
        let selected=report.selectableCandidates(includeUserData:true).filter{$0.category == .application || [rule,ContainerDataRule.name].contains($0.rule)}
        XCTAssertEqual(selected.count,3,"Body and both independently owned data roots should be available")
        let plan=try await e.makePlan(reportID:report.id,selected:Set(selected.map(\.id)),includeUserData:true),batch=try await e.execute(planID:plan.id)
        guard batch.status == .isolated else{XCTFail(batch.issue ?? "Native script data isolate failed");return}
        XCTAssertFalse(FileManager.default.fileExists(atPath:root))
        let restored=try await SweepEngine().restore(batchID:batch.id)
        guard restored.status == .restored else{XCTFail(restored.entries.compactMap(\.message).joined(separator:"; "));return}
        XCTAssertEqual(try SafeFilesystem.snapshot(root).identity.inode,before.identity.inode)
        XCTAssertEqual(try VerifiedFileStream.digest(SafeFilesystem.snapshot(file)),digest)
        XCTAssertEqual(try SafeFilesystem.snapshot(file).identity.inode,inode)
        let native=try BoundedProcess.capture(app + "/Contents/MacOS/script-data",arguments:["--read"],timeout:15,mergeStderr:false)
        XCTAssertEqual(native.status,0);let consumed=try XCTUnwrap(try JSONSerialization.jsonObject(with:try XCTUnwrap(native.text.data(using:.utf8)))as? [String:Any])
        XCTAssertEqual(consumed["canonical"]as? String,root);XCTAssertEqual(consumed["bytes"]as? Int,10)
        let result:[String:Any]=["application":app,"scripts":root,"scriptsInode":before.identity.inode,"scriptInode":inode,"scriptSHA256":digest,"batch":batch.id.uuidString,"state":"native NSApplicationScriptsDirectory; default product explicit data choice isolated body+container+scripts, fresh engine restored; original app read unchanged text without execution; ordinary GUI pending"]
        try JSONSerialization.data(withJSONObject:result,options:[.prettyPrinted,.sortedKeys]).write(to:URL(fileURLWithPath:owned + "/result.json"),options:.withoutOverwriting)
        print("DEFAULT_APPLICATION_SCRIPTS_ACCEPTED " + String(data:try JSONSerialization.data(withJSONObject:result),encoding:.utf8)!)
    }
}
#endif
