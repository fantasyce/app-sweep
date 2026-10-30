#if os(macOS)
import Foundation
import XCTest
import Darwin
@testable import AppSweepCore

final class XcodeArchiveTests: XCTestCase, @unchecked Sendable {
    private let rule="xcode-archive-management-v1"
    private func fixture() throws -> NativeAcceptanceTests.NativeFixture {try .init(additionalRules:[rule])}
    private func archive(_ f: NativeAcceptanceTests.NativeFixture) throws -> String {
        let root=f.home + "/Library/Developer/Xcode/Archives/2026-10-20/Disposable.xcarchive"
        try FileManager.default.createDirectory(atPath:root + "/Products",withIntermediateDirectories:true)
        try Data("original archived product".utf8).write(to:URL(fileURLWithPath:root + "/Products/data"))
        let info:[String:Any]=["ArchiveVersion":2,"CreationDate":Date(),"Name":"Disposable","SchemeName":"Fixture"]
        try PropertyListSerialization.data(fromPropertyList:info,format:.binary,options:0).write(to:URL(fileURLWithPath:root + "/Info.plist"))
        return root
    }
    func testWholeArchiveIsPersonalDataAndRequiresExplicitSelectionBeforeRestoration() async throws {
        let f=try fixture();defer{try? f.clean()};let root=try archive(f),before=try SafeFilesystem.snapshot(root)
        let report=try await f.engine.scanLegacyManagementFixture(),item=report.candidates.first{$0.path == root && $0.rule == rule}
        XCTAssertNotNil(item);guard let item else{return}
        XCTAssertTrue(item.userData);XCTAssertFalse(item.selectedByDefault)
        XCTAssertFalse(report.selectableCandidates(includeUserData:false).contains{$0.id == item.id})
        XCTAssertTrue(report.selectableCandidates(includeUserData:true).contains{$0.id == item.id})
        do{_=try await f.engine.makePlan(reportID:report.id,selected:[item.id],includeUserData:false);XCTFail("Archive selected without explicit data management")}catch{}
        let plan=try await f.engine.makePlan(reportID:report.id,selected:[item.id],includeUserData:true),batch=try await f.engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        let fresh=SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[rule]),vaultPath:f.home + "/Library/Application Support/App Sweep/Recovery",fixture:false)
        let restored=try await fresh.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        XCTAssertEqual(try SafeDirectory(path:root).ownIdentity.inode,before.identity.inode)
        XCTAssertEqual(try String(contentsOfFile:root + "/Products/data",encoding:.utf8),"original archived product")
    }
    func testMalformedSharedAndLinkedArchivesRemainWholeAndUnselectable() async throws {
        for mode in ["metadata","shared","link"]{
            let f=try fixture();defer{try? f.clean()};let root=try archive(f)
            if mode == "metadata"{try Data("not an archive metadata plist".utf8).write(to:URL(fileURLWithPath:root + "/Info.plist"))}
            if mode == "shared"{XCTAssertEqual(chmod(root + "/Products",0o777),0)}
            if mode == "link"{try FileManager.default.createSymbolicLink(atPath:root + "/Products/outside",withDestinationPath:f.home)}
            let report=try await f.engine.scanLegacyManagementFixture()
            XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains{$0.path == root},mode)
            XCTAssertTrue(FileManager.default.fileExists(atPath:root + "/Products/data"))
        }
    }
    func testUnreadableArchiveIsUnconfirmedWithoutBlockingIndependentArchiveOnSameDay() async throws {
        let f=try fixture();defer{try? f.clean()};let root=try archive(f),other=URL(fileURLWithPath:root).deletingLastPathComponent().path + "/Unreadable.xcarchive"
        try FileManager.default.copyItem(atPath:root,toPath:other)
        XCTAssertEqual(chmod(other + "/Info.plist",0),0)
        defer{_=chmod(other + "/Info.plist",0o644)}
        let report=try await f.engine.scanLegacyManagementFixture()
        XCTAssertFalse(report.complete,"Unreadable metadata is unconfirmed, not a successful empty/complete scan")
        XCTAssertFalse(report.unconfirmedIssues.isEmpty)
        XCTAssertTrue(report.selectableCandidates(includeUserData:true).contains{$0.path == root},"A separate validated archive must retain its own scope")
        XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains{$0.path == other})
    }
    func testNativeRegisteredArchiveUsesDefaultPolicyAndRestoredProductRuns() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_XCODE_ARCHIVE_ACCEPTANCE"] == "AppSweep-General-20261016" else{throw XCTSkip("Explicit registered disposable VM native archive only")}
        guard getuid() == 501,try SystemIdentity.home() == "/Users/localtest",
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).trimmingCharacters(in:.whitespacesAndNewlines) == "VirtualMac2,1" else{throw SweepError.denied("Requires registered disposable VM")}
        let task="/Users/localtest/AppSweepAcceptanceGeneral-20261016",home=try SystemIdentity.home()
        let info=try XCTUnwrap(try JSONSerialization.jsonObject(with:SafeFilesystem.readMetadata(task + "/xcode-archive-default-current.json"))as? [String:Any])
        let id=try XCTUnwrap(info["id"]as? String),owned=try XCTUnwrap(info["owned"]as? String),root=try XCTUnwrap(info["archive"]as? String)
        guard UUID(uuidString:id) != nil,owned == task + "/native-xcode-archive-" + id + ".noindex",
              root.hasPrefix(home + "/Library/Developer/Xcode/Archives/"),URL(fileURLWithPath:root).lastPathComponent == "App Sweep Fixture " + id + ".xcarchive",
              !FileManager.default.fileExists(atPath:owned + "/result.json") else{throw SweepError.denied("Archive registration changed")}
        let before=try SafeFilesystem.snapshot(root),product=root + "/Products/usr/local/bin/Fixture",digest=try VerifiedFileStream.digest(SafeFilesystem.snapshot(product))
        let e=SweepEngine(),report=try await e.scanLegacyManagementFixture()
        guard let item=report.candidates.first(where:{$0.path == root && $0.rule == rule}) else{XCTFail("Default product scan did not expose the registered native archive");return}
        XCTAssertFalse(item.selectedByDefault);XCTAssertTrue(item.userData)
        guard report.selectableCandidates(includeUserData:true).contains(where:{$0.id == item.id}) else{XCTFail(item.retentionReason ?? "Native archive cannot be selected");return}
        XCTAssertFalse(report.selectableCandidates(includeUserData:false).contains{$0.id == item.id})
        let plan=try await e.makePlan(reportID:report.id,selected:[item.id],includeUserData:true),batch=try await e.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        XCTAssertFalse(FileManager.default.fileExists(atPath:root))
        let restored=try await SweepEngine().restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        XCTAssertEqual(try SafeDirectory(path:root).ownIdentity.inode,before.identity.inode)
        XCTAssertEqual(try VerifiedFileStream.digest(SafeFilesystem.snapshot(product)),digest)
        XCTAssertEqual(try BoundedProcess.capture(product,arguments:[],timeout:3,mergeStderr:true).status,0)
        let result:[String:Any]=["archive":root,"archiveInode":before.identity.inode,"productSHA256":digest,"batch":batch.id.uuidString,"state":"native Xcode produced archive; default user policy requires explicit personal-data choice; whole archive isolated and fresh engine restored; original archived executable ran; ordinary GUI/Organizer still pending"]
        try JSONSerialization.data(withJSONObject:result,options:[.prettyPrinted,.sortedKeys]).write(to:URL(fileURLWithPath:owned + "/result.json"),options:.withoutOverwriting)
        print("DEFAULT_XCODE_ARCHIVE_ACCEPTED " + String(data:try JSONSerialization.data(withJSONObject:result),encoding:.utf8)!)
    }
}
#endif
