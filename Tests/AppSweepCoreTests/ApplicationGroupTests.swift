#if os(macOS)
import Foundation
import XCTest
import Darwin
@testable import AppSweepCore

final class ApplicationGroupTests:XCTestCase,@unchecked Sendable {
    private let rule="exclusive-declared-app-group-v1"
    private let identifier="org.example.groupowner." + UUID().uuidString.lowercased()
    private var group:String{"group." + identifier}
    private var rules:Set<String>{[rule,ChosenApplicationRule.name,ChosenApplicationRule.largeName]}
    private func sign(_ app:String,identifier:String,home:String,groups:[String]?=nil) throws {
        let file=app + "/Contents/Info.plist"
        var info=try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:file)),format:nil)as? [String:Any]);info["CFBundleIdentifier"]=identifier
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:file))
        let entitlement=home + "/groups.plist"
        try PropertyListSerialization.data(fromPropertyList:["com.apple.security.app-sandbox":true,"com.apple.security.application-groups":groups ?? [group]],format:.xml,options:0).write(to:URL(fileURLWithPath:entitlement))
        _=try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-","--entitlements",entitlement,app],timeout:10)
    }
    private func fixture() throws -> (NativeAcceptanceTests.NativeFixture,String) {
        let f=try NativeAcceptanceTests.NativeFixture(additionalRules:rules);try sign(f.app,identifier:identifier,home:f.home)
        let root=f.home + "/Library/Group Containers/" + group
        try FileManager.default.createDirectory(atPath:root,withIntermediateDirectories:true)
        try Data("independent original group data".utf8).write(to:URL(fileURLWithPath:root + "/sample.txt"))
        let info:[String:Any]=["MCMMetadataIdentifier":group,"MCMMetadataContentClass":7,"MCMMetadataCreator":identifier,"MCMMetadataUserIdentity":["posixUID":getuid()],"MCMMetadataOwnership":["uid":getuid()]]
        try PropertyListSerialization.data(fromPropertyList:info,format:.binary,options:0).write(to:URL(fileURLWithPath:root + "/.com.apple.containermanagerd.metadata.plist"))
        return(f,root)
    }
    func testExclusiveDeclaredCreatedGroupIsExplicitDataAndRestoresWithOriginalBody() async throws {
        let(f,root)=try fixture();defer{try? f.clean()};let before=try SafeFilesystem.snapshot(root),report=try await f.engine.scanApplication(f.app)
        guard let item=report.candidates.first(where:{$0.path == root && $0.rule == rule}) else{XCTFail("Owned declared group has no product path");return}
        XCTAssertTrue(item.userData);XCTAssertFalse(item.selectedByDefault)
        XCTAssertFalse(report.selectableCandidates(includeUserData:false).contains{$0.id == item.id})
        XCTAssertTrue(report.selectableCandidates(includeUserData:true).contains{$0.id == item.id},item.retentionReason ?? "")
        let body=try XCTUnwrap(report.selectableCandidates(includeUserData:true).first{$0.category == .application})
        let plan=try await f.engine.makePlan(reportID:report.id,selected:[body.id,item.id],includeUserData:true),batch=try await f.engine.execute(planID:plan.id);XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        let fresh=SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:rules),vaultPath:f.home + "/Library/Application Support/App Sweep/Recovery",fixture:false),restored=try await fresh.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:"; "))
        XCTAssertEqual(try SafeFilesystem.snapshot(root).identity.inode,before.identity.inode)
        XCTAssertEqual(try String(contentsOfFile:root + "/sample.txt",encoding:.utf8),"independent original group data")
    }
    func testAnotherInstalledDeclarerOrDifferentCreatorRetainsTheGroup() async throws {
        for variant in ["peer","creator"] {
            let(f,root)=try fixture();defer{try? f.clean()}
            if variant == "peer" {
                let peer=f.home + "/Applications/Another Group User.app";try FileManager.default.copyItem(atPath:f.app,toPath:peer);try sign(peer,identifier:identifier + ".peer",home:f.home)
            }else{
                let file=root + "/.com.apple.containermanagerd.metadata.plist";var info=try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:file)),format:nil)as? [String:Any]);info["MCMMetadataCreator"]=identifier + ".other"
                try PropertyListSerialization.data(fromPropertyList:info,format:.binary,options:0).write(to:URL(fileURLWithPath:file))
            }
            let report=try await f.engine.scanApplication(f.app)
            XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains{$0.path == root},variant)
            XCTAssertEqual(try String(contentsOfFile:root + "/sample.txt",encoding:.utf8),"independent original group data")
        }
    }
    func testUnrelatedLegacyAndProtectedGroupDeclarationsDoNotBlockASeparateOwnedGroup() async throws {
        let(f,root)=try fixture();defer{try? f.clean()}
        let peer=f.home + "/Applications/Unrelated Declared Group.app";try FileManager.default.copyItem(atPath:f.app,toPath:peer)
        // This bundle is only a signed metadata input. It is never launched and
        // never requests or accesses the protected group it names.
        try sign(peer,identifier:identifier + ".unrelated",home:f.home,groups:["group.com.apple.unrelated.metadata-fixture","UndottedLegacyGroup"])
        let report=try await f.engine.scanApplication(f.app)
        XCTAssertTrue(report.selectableCandidates(includeUserData:true).contains{$0.path == root && $0.rule == rule},report.candidates.filter{$0.path == root}.compactMap(\.retentionReason).joined(separator:"; "))
    }
    func testCreatorInsideTheSelectedSignedPackageIsOwnedWithoutClaimingAnotherInstallation() async throws {
        let(f,root)=try fixture();defer{try? f.clean()}
        let staged=f.home + "/embedded-template.noindex",child=f.app + "/Contents/PlugIns/Owned Nested.app"
        try FileManager.default.copyItem(atPath:f.app,toPath:staged)
        try FileManager.default.createDirectory(atPath:f.app + "/Contents/PlugIns",withIntermediateDirectories:true)
        try FileManager.default.moveItem(atPath:staged,toPath:child)
        try sign(child,identifier:identifier + ".extension",home:f.home);try sign(f.app,identifier:identifier,home:f.home,groups:[])
        let metadata=root + "/.com.apple.containermanagerd.metadata.plist"
        var info=try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:metadata)),format:nil)as? [String:Any]);info["MCMMetadataCreator"]=identifier + ".extension"
        try PropertyListSerialization.data(fromPropertyList:info,format:.binary,options:0).write(to:URL(fileURLWithPath:metadata))
        let report=try await f.engine.scanApplication(f.app)
        let groupItem=try XCTUnwrap(report.selectableCandidates(includeUserData:true).first{$0.path == root && $0.rule == rule},report.candidates.filter{$0.path == root}.compactMap(\.retentionReason).joined(separator:"; "))
        let body=try XCTUnwrap(report.selectableCandidates(includeUserData:true).first{$0.category == .application})
        let plan=try await f.engine.makePlan(reportID:report.id,selected:[body.id,groupItem.id],includeUserData:true),batch=try await f.engine.execute(planID:plan.id);XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        let fresh=SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:rules),vaultPath:f.home + "/Library/Application Support/App Sweep/Recovery",fixture:false)
        let restored=try await fresh.restore(batchID:batch.id);XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:"; "))
        XCTAssertEqual(try String(contentsOfFile:root + "/sample.txt",encoding:.utf8),"independent original group data")
    }
    func testNativeGroupUsesDefaultUninstallAndOriginalGroupAPIReaderAfterFreshRestoration() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_GROUP_DATA_ACCEPTANCE"] == "AppSweep-General-20261016" else{throw XCTSkip("Registered real native app group only")}
        guard getuid() == 501,try SystemIdentity.home() == "/Users/localtest",try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).trimmingCharacters(in:.whitespacesAndNewlines) == "VirtualMac2,1" else{throw SweepError.denied("Requires registered disposable VM")}
        let task="/Users/localtest/AppSweepAcceptanceGeneral-20261016"
        let info=try XCTUnwrap(try JSONSerialization.jsonObject(with:SafeFilesystem.readMetadata(task + "/group-api-probe-current.json"))as? [String:Any])
        let id=try XCTUnwrap(info["id"]as? String),owned=try XCTUnwrap(info["owned"]as? String),app=try XCTUnwrap(info["application"]as? String),root=try XCTUnwrap(info["groupRoot"]as? String),bundle=try XCTUnwrap(info["identifier"]as? String)
        guard UUID(uuidString:id) != nil,owned == task + "/native-group-api-" + id + ".noindex",bundle == "org.example.disposable.groups." + id,app == "/Users/localtest/Applications/Disposable Group Data " + id + ".app",root == "/Users/localtest/Library/Group Containers/group." + bundle,!FileManager.default.fileExists(atPath:owned + "/result.json") else{throw SweepError.denied("Native group registration changed")}
        let before=try SafeFilesystem.snapshot(root,allowInternalLinks:true,purpose:.managedData),file=root + "/sample.txt",digest=try VerifiedFileStream.digest(SafeFilesystem.snapshot(file)),inode=try SafeFilesystem.snapshot(file).identity.inode
        let e=SweepEngine(),report=try await e.scanApplication(app)
        guard let groupItem=report.candidates.first(where:{$0.path == root && $0.rule == rule}),report.selectableCandidates(includeUserData:true).contains(where:{$0.id == groupItem.id}) else{XCTFail(report.candidates.filter{$0.path == root}.compactMap(\.retentionReason).joined(separator:"; "));return}
        XCTAssertTrue(groupItem.userData);XCTAssertFalse(groupItem.selectedByDefault)
        XCTAssertFalse(report.selectableCandidates(includeUserData:false).contains{$0.id == groupItem.id})
        let selected=report.selectableCandidates(includeUserData:true).filter{$0.category == .application || [rule,ContainerDataRule.name,ApplicationScriptsRule.name].contains($0.rule)}
        XCTAssertTrue(selected.contains{$0.category == .application});XCTAssertTrue(selected.contains{$0.rule == ContainerDataRule.name})
        let plan=try await e.makePlan(reportID:report.id,selected:Set(selected.map(\.id)),includeUserData:true),batch=try await e.execute(planID:plan.id)
        guard batch.status == .isolated else{XCTFail(batch.issue ?? "Native group uninstall failed");return}
        XCTAssertFalse(FileManager.default.fileExists(atPath:root))
        let restored=try await SweepEngine().restore(batchID:batch.id)
        guard restored.status == .restored else{XCTFail(restored.entries.compactMap(\.message).joined(separator:"; "));return}
        XCTAssertEqual(try SafeFilesystem.snapshot(root,allowInternalLinks:true,purpose:.managedData).identity.inode,before.identity.inode)
        XCTAssertEqual(try VerifiedFileStream.digest(SafeFilesystem.snapshot(file)),digest);XCTAssertEqual(try SafeFilesystem.snapshot(file).identity.inode,inode)
        let native=try BoundedProcess.capture(app + "/Contents/MacOS/group-api",arguments:["--read"],timeout:15,mergeStderr:false)
        XCTAssertEqual(native.status,0);let result=try XCTUnwrap(try JSONSerialization.jsonObject(with:try XCTUnwrap(native.text.data(using:.utf8)))as? [String:Any])
        XCTAssertEqual(result["location"]as? String,root);XCTAssertEqual(result["bytes"]as? Int,25)
        let receipt:[String:Any]=["application":app,"groupRoot":root,"groupRootInode":before.identity.inode,"sampleInode":inode,"sampleSHA256":digest,"batch":batch.id.uuidString,"entries":batch.entries.count,"state":"native class7 creator and signed declarations; default product explicit body and owned data/group isolation, fresh restore; original native group API read unchanged25bytes; ordinary GUI pending"]
        try JSONSerialization.data(withJSONObject:receipt,options:[.prettyPrinted,.sortedKeys]).write(to:URL(fileURLWithPath:owned + "/result.json"),options:.withoutOverwriting)
        print("DEFAULT_APPLICATION_GROUP_ACCEPTED " + String(data:try JSONSerialization.data(withJSONObject:receipt),encoding:.utf8)!)
    }
}
#endif
