#if os(macOS)
import Foundation
import XCTest
import Darwin
@testable import AppSweepCore

final class CorruptPreferenceTests:XCTestCase,@unchecked Sendable {
    private func privateFixture()throws->(NativeAcceptanceTests.NativeFixture,String,String){
        let f=try NativeAcceptanceTests.NativeFixture(additionalRules:["corrupt-preference-file-v1"]),identifier="org.example.corrupt." + UUID().uuidString.lowercased(),infoPath=f.app + "/Contents/Info.plist"
        var info=try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:infoPath)),format:nil)as? [String:Any]);info["CFBundleIdentifier"]=identifier
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:infoPath))
        _=try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-",f.app],timeout:10)
        let directory=f.home + "/Library/Preferences";try FileManager.default.createDirectory(atPath:directory,withIntermediateDirectories:true)
        return(f,directory + "/" + identifier + ".plist",identifier)
    }
    func testValidUnknownNonDictionaryAndLinkedFilesAreNeverMalformedCleanupAuthority()async throws{
        let(f,path,_)=try privateFixture();defer{try? f.clean()}
        for bytes in [try PropertyListSerialization.data(fromPropertyList:["valid":"keep"],format:.binary,options:0),try PropertyListSerialization.data(fromPropertyList:["array"],format:.binary,options:0),Data("bplist01unknown format".utf8)]{
            try bytes.write(to:URL(fileURLWithPath:path))
            let report=try await f.engine.scanLegacyManagementFixture()
            XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains{$0.path == path})
        }
        try FileManager.default.removeItem(atPath:path)
        let sentinel=f.home + "/sentinel";try Data("keep".utf8).write(to:URL(fileURLWithPath:sentinel));try FileManager.default.createSymbolicLink(atPath:path,withDestinationPath:sentinel)
        let linked=try await f.engine.scanLegacyManagementFixture();XCTAssertFalse(linked.selectableCandidates(includeUserData:true).contains{$0.path == path})
        XCTAssertEqual(try String(contentsOfFile:sentinel,encoding:.utf8),"keep")
    }
    func testNewValidSettingsConflictKeepsTheIndependentOriginalMalformedBytes()async throws{
        let(f,path,_)=try privateFixture();defer{try? f.clean()}
        try Data("<?xml broken plist".utf8).write(to:URL(fileURLWithPath:path))
        let report=try await f.engine.scanLegacyManagementFixture()
        guard let item=report.selectableCandidates(includeUserData:true).first(where:{$0.path == path})else{XCTFail("Malformed-file handling is missing");return}
        let plan=try await f.engine.makePlan(reportID:report.id,selected:[item.id],includeUserData:true),batch=try await f.engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        let new=try PropertyListSerialization.data(fromPropertyList:["valid":"new"],format:.binary,options:0);try new.write(to:URL(fileURLWithPath:path))
        let recovered=try await f.engine.restore(batchID:batch.id)
        XCTAssertEqual(recovered.status,.needsAttention)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:path)),new)
        let entry=try XCTUnwrap(recovered.entries.first),backup=try SafeDirectory(path:f.home + "/Library/Application Support/App Sweep/Recovery/" + batch.id.uuidString + "/backups.noindex")
        _=try CacheBackup.verifiedSnapshot(entry,in:backup)
    }
    func testColdMalformedFileIsExplicitlyIsolatedRestoredAndRetainedIndependently() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_CORRUPT_PREFERENCE_ACCEPTANCE"] == "AppSweep-General-20261016",getuid() == 501,try SystemIdentity.home() == "/Users/localtest",try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).hasPrefix("VirtualMac") else{throw XCTSkip("Registered disposable VM current-user preference test only")}
        let rule="corrupt-preference-file-v1",f=try PreferenceDomainServiceTests.NativeDomainFixture()
        let app=f.home + "/Applications/Disposable Damaged Preferences " + UUID().uuidString + ".app"
        guard try !SafeFilesystem.presence(app) else{throw SweepError.denied("New fixture target already exists")}
        try f.root.write(JSONSerialization.data(withJSONObject:["application":app,"identifier":f.identifier,"purpose":"new independently signed disposable corruption consumer; retain on failure"]),name:"installed-app-intent.json")
        try FileManager.default.copyItem(atPath:f.root.path + "/Preference Witness.app",toPath:app)
        let appIdentity=try SafeFilesystem.snapshot(app,allowInternalLinks:true,purpose:.application).identity
        try f.root.write(JSONSerialization.data(withJSONObject:["application":app,"inode":appIdentity.inode,"device":appIdentity.device,"identifier":f.identifier]),name:"installed-app.json")
        let malformed=Data("<?xml version=\"1.0\"?><plist><dict><key>broken</key>".utf8)
        try malformed.write(to:URL(fileURLWithPath:f.path))
        let inspected=try PreferenceFileInspector.inspect(path:f.path,home:f.home,identifier:f.identifier)
        XCTAssertEqual(inspected.status,.malformed)
        let policy=SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[rule]),vault=f.root.path + "/Recovery",e=SweepEngine(policy:policy,vaultPath:vault,fixture:false)
        let report=try await e.scanLegacyManagementFixture()
        guard let item=report.candidates.first(where:{$0.path == f.path && $0.rule == rule})else{XCTFail("Malformed preferences have no explicit file-isolation transaction");return}
        XCTAssertTrue(item.userData);XCTAssertFalse(item.selectedByDefault)
        XCTAssertFalse(report.selectableCandidates(includeUserData:false).contains{$0.id == item.id})
        guard report.selectableCandidates(includeUserData:true).contains(where:{$0.id == item.id})else{XCTFail(item.retentionReason ?? "Unavailable corrupt preference");return}
        let plan=try await e.makePlan(reportID:report.id,selected:[item.id],includeUserData:true),batch=try await e.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? batch.entries.compactMap(\.message).joined(separator:"; "))
        guard batch.status == .isolated else{return}
        XCTAssertTrue(FileManager.default.fileExists(atPath:app),"Reset must leave the app installed")
        let saved=try XCTUnwrap(batch.entries.first),backup=try SafeDirectory(path:vault + "/" + batch.id.uuidString + "/backups.noindex")
        XCTAssertNotNil(saved.backupDigest)
        _=try CacheBackup.verifiedSnapshot(saved,in:backup)
        let restored=try await SweepEngine(policy:policy,vaultPath:vault,fixture:false).restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:"; "))
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:f.path)),malformed,"Undo restores the original malformed file without forcing the native service to parse it")
        XCTAssertEqual(try f.read().status,6,"Original malformed settings contain no usable native value; macOS may discard the damaged file itself")
        _=try CacheBackup.verifiedSnapshot(saved,in:backup)
        let result:[String:Any]=["application":app,"applicationInode":appIdentity.inode,"preference":f.path,"rawDigest":inspected.digest,"batch":batch.id.uuidString,"state":"cold malformed file isolated and exact bytes restored; native reader discarded malformed file and independent raw backup remains; normal UI pending"]
        try f.root.write(JSONSerialization.data(withJSONObject:result,options:[.sortedKeys]),name:"corrupt-result.json")
        print("CORRUPT_PREFERENCE_ACCEPTED " + String(data:try JSONSerialization.data(withJSONObject:result),encoding:.utf8)!)
    }
}
#endif
