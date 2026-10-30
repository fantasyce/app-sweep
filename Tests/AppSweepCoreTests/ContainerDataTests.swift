#if os(macOS)
import Foundation
import XCTest
import Darwin
@testable import AppSweepCore

final class ContainerDataTests: XCTestCase, @unchecked Sendable {
    private let rule="exclusive-application-container-v2"
    private let identifier="org.example.containerdata." + UUID().uuidString.lowercased()
    private var rules:Set<String>{[rule,ChosenApplicationRule.name,ChosenApplicationRule.largeName]}
    private func fixture(sandbox:Bool=true) throws -> NativeAcceptanceTests.NativeFixture {
        let f=try NativeAcceptanceTests.NativeFixture(additionalRules:rules),path=f.app + "/Contents/Info.plist"
        var info=try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:path)),format:nil)as? [String:Any])
        info["CFBundleIdentifier"]=identifier
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:path))
        var arguments=["--force","--sign","-"]
        if sandbox {
            let entitlements=f.home + "/sandbox.plist"
            try PropertyListSerialization.data(fromPropertyList:["com.apple.security.app-sandbox":true],format:.xml,options:0).write(to:URL(fileURLWithPath:entitlements));arguments += ["--entitlements",entitlements]
        }
        _=try BoundedProcess.run("/usr/bin/codesign",arguments:arguments + [f.app],timeout:10)
        return f
    }
    private func container(_ f:NativeAcceptanceTests.NativeFixture,associated:[String]?=nil) throws -> String {
        let root=f.home + "/Library/Containers/" + identifier
        try FileManager.default.createDirectory(atPath:root + "/Data/Documents",withIntermediateDirectories:true)
        try Data("original private container document".utf8).write(to:URL(fileURLWithPath:root + "/Data/Documents/document.txt"))
        var metadata:[String:Any]=["MCMMetadataIdentifier":identifier,"MCMMetadataContentClass":2,"MCMMetadataUserIdentity":["posixUID":getuid()],"MCMMetadataOwnership":["uid":getuid()]]
        if let associated{metadata["AssociatedBundleIdentifiers"]=associated}
        try PropertyListSerialization.data(fromPropertyList:metadata,format:.binary,options:0).write(to:URL(fileURLWithPath:root + "/.com.apple.containermanagerd.metadata.plist"))
        return root
    }
    private func fresh(_ f:NativeAcceptanceTests.NativeFixture) -> SweepEngine {
        SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:rules),vaultPath:f.home + "/Library/Application Support/App Sweep/Recovery",fixture:false)
    }
    func testExplicitContainerDataChoiceMovesWholeObjectAndRestoresOpaqueLinksWithoutExternalWrites() async throws {
        let f=try fixture();defer{try? f.clean()};let root=try container(f),external=f.home + "/Downloads"
        try FileManager.default.createDirectory(atPath:external,withIntermediateDirectories:true)
        try Data("external personal data must remain".utf8).write(to:URL(fileURLWithPath:external + "/sentinel"))
        try FileManager.default.createSymbolicLink(atPath:root + "/Data/Downloads",withDestinationPath:external)
        try FileManager.default.createDirectory(atPath:root + "/Data/Library",withIntermediateDirectories:true)
        try FileManager.default.createSymbolicLink(atPath:root + "/Data/Library/Keychains",withDestinationPath:external)
        let before=try SafeFilesystem.snapshot(root,allowInternalLinks:true,purpose:.managedData),report=try await f.engine.scanApplication(f.app)
        let item=report.candidates.first{$0.path == root && $0.rule == rule};XCTAssertNotNil(item)
        guard let item else{return}
        XCTAssertTrue(item.userData);XCTAssertFalse(item.selectedByDefault)
        XCTAssertFalse(report.selectableCandidates(includeUserData:false).contains{$0.id == item.id})
        XCTAssertTrue(report.selectableCandidates(includeUserData:true).contains{$0.id == item.id},item.retentionReason ?? "")
        let body=try XCTUnwrap(report.selectableCandidates(includeUserData:true).first{$0.category == .application})
        do{_=try await f.engine.makePlan(reportID:report.id,selected:[body.id,item.id],includeUserData:false);XCTFail("User data selected implicitly")}catch{}
        let plan=try await f.engine.makePlan(reportID:report.id,selected:[body.id,item.id],includeUserData:true),batch=try await f.engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        XCTAssertFalse(FileManager.default.fileExists(atPath:root));XCTAssertFalse(FileManager.default.fileExists(atPath:f.app))
        XCTAssertEqual(try String(contentsOfFile:external + "/sentinel",encoding:.utf8),"external personal data must remain")
        let restored=try await fresh(f).restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:"; "))
        XCTAssertEqual(try SafeFilesystem.snapshot(root,allowInternalLinks:true,purpose:.managedData).identity.inode,before.identity.inode)
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath:root + "/Data/Downloads"),external)
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath:root + "/Data/Library/Keychains"),external)
        XCTAssertEqual(try String(contentsOfFile:root + "/Data/Documents/document.txt",encoding:.utf8),"original private container document")
        XCTAssertEqual(try String(contentsOfFile:external + "/sentinel",encoding:.utf8),"external personal data must remain")
        XCTAssertTrue(AppInspector.signatureMatches(path:f.app,identifier:identifier))
    }
    func testSharedMetadataNonSandboxAndChangedOwnershipDoNotAuthorizeContainerData() async throws {
        for variant in ["shared","class","unsigned-sandbox","keychain-data","changed"] {
            let f=try fixture(sandbox:variant != "unsigned-sandbox");defer{try? f.clean()}
            let root=try container(f,associated:variant == "shared" ? [identifier,"org.example.other"] : nil),metadata=root + "/.com.apple.containermanagerd.metadata.plist"
            if variant == "class" {
                var info=try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:metadata)),format:nil)as? [String:Any]);info["MCMMetadataContentClass"]=7
                try PropertyListSerialization.data(fromPropertyList:info,format:.binary,options:0).write(to:URL(fileURLWithPath:metadata))
            }
            if variant == "keychain-data" {
                try FileManager.default.createDirectory(atPath:root + "/Data/Library/Keychains",withIntermediateDirectories:true)
                try Data("actual protected data must remain".utf8).write(to:URL(fileURLWithPath:root + "/Data/Library/Keychains/state"))
            }
            let report=try await f.engine.scanApplication(f.app)
            if variant == "changed" {
                guard let item=report.selectableCandidates(includeUserData:true).first(where:{$0.path == root && $0.rule == rule}),let body=report.selectableCandidates(includeUserData:true).first(where:{$0.category == .application}) else{XCTFail("Missing valid container before ownership change");continue}
                let plan=try await f.engine.makePlan(reportID:report.id,selected:[body.id,item.id],includeUserData:true)
                var info=try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:metadata)),format:nil)as? [String:Any]);info["AssociatedBundleIdentifiers"]=[identifier,"org.example.other"]
                try PropertyListSerialization.data(fromPropertyList:info,format:.binary,options:0).write(to:URL(fileURLWithPath:metadata))
                do{_=try await f.engine.execute(planID:plan.id);XCTFail("Changed ownership moved an application or its data")}catch{}
                XCTAssertTrue(FileManager.default.fileExists(atPath:f.app))
            }else{XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains{$0.path == root},variant)}
            XCTAssertEqual(try String(contentsOfFile:root + "/Data/Documents/document.txt",encoding:.utf8),"original private container document")
        }
    }
    func testRegeneratedContainerConflictsPreserveBothGenerations() async throws {
        let f=try fixture();defer{try? f.clean()};let root=try container(f),report=try await f.engine.scanApplication(f.app)
        guard let item=report.selectableCandidates(includeUserData:true).first(where:{$0.path == root && $0.rule == rule}) else{XCTFail("Container data cannot be selected");return}
        let body=try XCTUnwrap(report.selectableCandidates(includeUserData:true).first{$0.category == .application})
        let plan=try await f.engine.makePlan(reportID:report.id,selected:[body.id,item.id],includeUserData:true),batch=try await f.engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        try FileManager.default.createDirectory(atPath:root,withIntermediateDirectories:true)
        try Data("new generation".utf8).write(to:URL(fileURLWithPath:root + "/new.txt"))
        let e=fresh(f),conflict=try await e.restore(batchID:batch.id);XCTAssertEqual(conflict.status,.needsAttention)
        XCTAssertEqual(try String(contentsOfFile:root + "/new.txt",encoding:.utf8),"new generation")
        try FileManager.default.moveItem(atPath:root,toPath:f.home + "/preserved-new-container")
        let restored=try await e.restore(batchID:batch.id);XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        XCTAssertEqual(try String(contentsOfFile:root + "/Data/Documents/document.txt",encoding:.utf8),"original private container document")
    }
    func testLargeContainerUsesExistingFingerprintAndPurgeNeverFollowsOpaqueLinks() async throws {
        let f=try fixture();defer{try? f.clean()};let root=try container(f),external=f.home + "/external-sentinel"
        try Data("outside container".utf8).write(to:URL(fileURLWithPath:external))
        try FileManager.default.createSymbolicLink(atPath:root + "/Data/external",withDestinationPath:external)
        for n in 0...TreeFingerprint.inlineLimit{XCTAssertTrue(FileManager.default.createFile(atPath:root + "/Data/Documents/" + String(n),contents:Data()))}
        let report=try await f.engine.scanApplication(f.app)
        let item=try XCTUnwrap(report.selectableCandidates(includeUserData:true).first{$0.path == root && $0.rule == rule})
        let body=try XCTUnwrap(report.selectableCandidates(includeUserData:true).first{$0.category == .application})
        let plan=try await f.engine.makePlan(reportID:report.id,selected:[body.id,item.id],includeUserData:true),batch=try await f.engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        XCTAssertTrue(batch.entries.first(where:{$0.id == item.id})?.treeFingerprint?.validLargeTree == true)
        let e=fresh(f),batches=try await e.recoveryBatches();XCTAssertEqual(batches.map(\.id),[batch.id])
        let restored=try await e.restore(batchID:batch.id);XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:"; "))
        XCTAssertEqual(try String(contentsOfFile:external,encoding:.utf8),"outside container")
        let secondReport=try await f.engine.scanApplication(f.app),secondItems=secondReport.selectableCandidates(includeUserData:true).filter{$0.category == .application || $0.rule == rule}
        let secondPlan=try await f.engine.makePlan(reportID:secondReport.id,selected:Set(secondItems.map(\.id)),includeUserData:true),second=try await f.engine.execute(planID:secondPlan.id)
        XCTAssertEqual(second.status,.isolated,second.issue ?? "")
        let purged=try await fresh(f).purge(batchID:second.id,confirmation:"永久清空 " + second.id.uuidString)
        XCTAssertEqual(purged.status,.purged,purged.issue ?? "")
        XCTAssertEqual(try String(contentsOfFile:external,encoding:.utf8),"outside container")
    }
    func testNativeSandboxContainerUsesDefaultUninstallAndOriginalConsumerAfterRestoration() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_CONTAINER_DATA_ACCEPTANCE"] == "AppSweep-General-20261016" else{throw XCTSkip("Registered actual OS sandbox container only")}
        guard getuid() == 501,try SystemIdentity.home() == "/Users/localtest",try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).trimmingCharacters(in:.whitespacesAndNewlines) == "VirtualMac2,1" else{throw SweepError.denied("Requires disposable registered VM")}
        let task="/Users/localtest/AppSweepAcceptanceGeneral-20261016"
        let info=try XCTUnwrap(try JSONSerialization.jsonObject(with:SafeFilesystem.readMetadata(task + "/container-data-default-current.json"))as? [String:Any])
        let id=try XCTUnwrap(info["id"]as? String),bundle=try XCTUnwrap(info["identifier"]as? String),owned=try XCTUnwrap(info["owned"]as? String),app=try XCTUnwrap(info["application"]as? String),root=try XCTUnwrap(info["container"]as? String)
        guard UUID(uuidString:id) != nil,owned == task + "/native-container-data-" + id + ".noindex",app == "/Users/localtest/Applications/Disposable Container Data " + id + ".app",bundle == "org.example.disposable.container." + id,root == "/Users/localtest/Library/Containers/" + bundle,!FileManager.default.fileExists(atPath:owned + "/result.json") else{throw SweepError.denied("Native container fixture registration changed")}
        let original=try SafeFilesystem.snapshot(root,allowInternalLinks:true,purpose:.managedData),appBefore=try SafeFilesystem.snapshot(app,allowInternalLinks:true,purpose:.application)
        let file=root + "/Data/Documents/native-data.bin",document=try VerifiedFileStream.digest(SafeFilesystem.snapshot(file)),inode=try SafeFilesystem.snapshot(file).identity.inode
        let e=SweepEngine(),report=try await e.scanApplication(app)
        guard let item=report.candidates.first(where:{$0.path == root && $0.rule == rule}),report.selectableCandidates(includeUserData:true).contains(where:{$0.id == item.id}) else{XCTFail(report.candidates.filter{$0.path == root}.compactMap(\.retentionReason).joined(separator:"; "));return}
        XCTAssertTrue(item.userData);XCTAssertFalse(item.selectedByDefault)
        XCTAssertFalse(report.selectableCandidates(includeUserData:false).contains{$0.id == item.id})
        let body=try XCTUnwrap(report.selectableCandidates(includeUserData:true).first{$0.path == app && $0.category == .application})
        let plan=try await e.makePlan(reportID:report.id,selected:[body.id,item.id],includeUserData:true),batch=try await e.execute(planID:plan.id)
        guard batch.status == .isolated else{XCTFail(batch.issue ?? "Native whole-container uninstall failed");return}
        XCTAssertFalse(FileManager.default.fileExists(atPath:app));XCTAssertFalse(FileManager.default.fileExists(atPath:root))
        let restored=try await SweepEngine().restore(batchID:batch.id)
        guard restored.status == .restored else{XCTFail(restored.entries.compactMap(\.message).joined(separator:"; "));return}
        let beforeConsumer=try SafeFilesystem.snapshot(root,allowInternalLinks:true,purpose:.managedData)
        XCTAssertEqual(beforeConsumer.identity.inode,original.identity.inode);XCTAssertEqual(beforeConsumer.tree,original.tree)
        XCTAssertEqual(try SafeFilesystem.snapshot(app,allowInternalLinks:true,purpose:.application).identity.inode,appBefore.identity.inode)
        let read=try BoundedProcess.capture(app + "/Contents/MacOS/container-data",arguments:["--read"],timeout:15,mergeStderr:false)
        XCTAssertEqual(read.status,0)
        let data=try XCTUnwrap(read.text.data(using:.utf8)),consumer=try XCTUnwrap(try JSONSerialization.jsonObject(with:data)as? [String:Any])
        XCTAssertEqual(consumer["bytes"]as? Int,16384);XCTAssertEqual(consumer["home"]as? String,root + "/Data")
        XCTAssertEqual(try VerifiedFileStream.digest(SafeFilesystem.snapshot(file)),document);XCTAssertEqual(try SafeFilesystem.snapshot(file).identity.inode,inode)
        let result:[String:Any]=["application":app,"container":root,"containerInode":original.identity.inode,"documentInode":inode,"documentSHA256":document,"batch":batch.id.uuidString,"state":"OS-created App Sandbox container; default product uninstalled body+explicit whole user data, fresh engine restored original whole tree; original native consumer read all16384 bytes; ordinary GUI pending"]
        try JSONSerialization.data(withJSONObject:result,options:[.prettyPrinted,.sortedKeys]).write(to:URL(fileURLWithPath:owned + "/result.json"),options:.withoutOverwriting)
        print("DEFAULT_CONTAINER_DATA_ACCEPTED " + String(data:try JSONSerialization.data(withJSONObject:result),encoding:.utf8)!)
    }
}
#endif
