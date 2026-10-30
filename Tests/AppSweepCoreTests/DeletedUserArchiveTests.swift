#if os(macOS)
import Foundation
import XCTest
import Darwin
@testable import AppSweepCore

final class DeletedUserArchiveTests:XCTestCase,@unchecked Sendable {
    struct Fixture {
        let home:String
        let root:String
        let scope:SystemCleanupScope
        init()throws{
            guard let base=ProcessInfo.processInfo.environment["APP_SWEEP_FIXTURES"],base.hasPrefix(try SystemIdentity.home()+"/AppSweepAcceptance"),getuid() != 0 else{throw XCTSkip("Owned VM archive fixture only")}
            home=base + "/" + UUID().uuidString;root=home + "/MachineLibrary/Deleted Users"
            for path in [root,home + "/Applications",home + "/payload",home + "/mount",home + "/Library/Application Support"]{try FileManager.default.createDirectory(atPath:path,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])}
            scope=try .fixture(libraryRoot:home + "/MachineLibrary",applicationsRoot:home + "/Applications",userHome:home,requesterUID:getuid())
        }
        func image(_ name:String)throws->String{
            let path=root + "/" + name + ".dmg"
            try Data("only disposable archived home contents\n".utf8).write(to:URL(fileURLWithPath:home + "/payload/owned.txt"))
            _=try BoundedProcess.run("/usr/bin/hdiutil",arguments:["create","-srcfolder",home + "/payload","-fs","HFS+","-format","UDZO",path],timeout:30)
            return path
        }
        func readArchive(_ path:String)throws->Data{
            let mount=home + "/mount"
            _=try BoundedProcess.run("/usr/bin/hdiutil",arguments:["attach","-readonly","-nobrowse","-mountpoint",mount,path],timeout:30)
            do{let data=try Data(contentsOf:URL(fileURLWithPath:mount + "/owned.txt"));_=try BoundedProcess.run("/usr/bin/hdiutil",arguments:["detach",mount],timeout:15);return data}
            catch{_=try? BoundedProcess.run("/usr/bin/hdiutil",arguments:["detach",mount],timeout:15);throw error}
        }
        func clean()throws{try FileManager.default.removeItem(atPath:home)}
    }
    func testWholeNativeArchiveRequiresExplicitSelectionAndFreshRestoresReadableImage()async throws{
        let f=try Fixture();defer{try? f.clean()}
        let path=try f.image("appsweeparchive" + UUID().uuidString.replacingOccurrences(of:"-",with:"")),before=try SafeFilesystem.snapshot(path),bytes=try Data(contentsOf:URL(fileURLWithPath:path)),payload=try f.readArchive(path)
        guard let category=SystemCleanupCategory(rawValue:"deletedUserArchives")else{XCTFail("Missing dedicated deleted-account archive management");return}
        let engine=try SystemCleanupEngine(scope:f.scope),report=try await engine.scan(category)
        let item=try XCTUnwrap(report.selectableCandidates(includeUserData:true).first{$0.path == path},(report.unconfirmedIssues + report.candidates.filter{$0.path == path}.compactMap(\.retentionReason)).joined(separator:"; "))
        XCTAssertTrue(item.userData);XCTAssertFalse(item.selectedByDefault);XCTAssertFalse(report.selectableCandidates(includeUserData:false).contains{$0.id == item.id})
        let plan=try await engine.makePlan(reportID:report.id,selected:[item.id]),batch=try await engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "");guard batch.status == .isolated else{return}
        XCTAssertFalse(FileManager.default.fileExists(atPath:path))
        let restored=try await SystemCleanupEngine(scope:f.scope).restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:"; "))
        XCTAssertEqual(try SafeFilesystem.snapshot(path).identity.inode,before.identity.inode);XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:path)),bytes);XCTAssertEqual(try f.readArchive(path),payload)
    }
    func testUnverifiedRequesterCannotManageOtherAccountsPersonalArchives()async throws{
        let f=try Fixture();defer{try? f.clean()}
        let path=try f.image("appsweeparchive" + UUID().uuidString.replacingOccurrences(of:"-",with:""))
        guard let category=SystemCleanupCategory(rawValue:"deletedUserArchives")else{XCTFail("Missing archive category");return}
        let unverified=try SystemCleanupScope.fixture(libraryRoot:f.scope.libraryRoot,applicationsRoot:f.scope.applicationsRoot,userHome:f.home,requesterUID:65533)
        let report=try SystemScanner(scope:unverified,policy:SafetyPolicy(systemScope:unverified)).scan(category).report
        XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains{$0.path == path})
        XCTAssertTrue(report.candidates.first{$0.path == path}?.retentionReason?.contains("管理员") == true,"Managing deleted-account personal archives requires a verified administrator requester")
    }
    func testActiveAccountMountedImageAndNonImageRemainUnselectable()async throws{
        let f=try Fixture();defer{try? f.clean()}
        let username=NSUserName(),active=try f.image(username),mounted=try f.image("appsweeparchive" + UUID().uuidString.replacingOccurrences(of:"-",with:"")),invalid=f.root + "/notanaccount.dmg"
        try Data("ordinary data is not an account archive".utf8).write(to:URL(fileURLWithPath:invalid))
        guard let category=SystemCleanupCategory(rawValue:"deletedUserArchives")else{XCTFail("Missing dedicated archive retention decisions");return}
        let mount=f.home + "/mount"
        _=try BoundedProcess.run("/usr/bin/hdiutil",arguments:["attach","-readonly","-nobrowse","-mountpoint",mount,mounted],timeout:30)
        defer{_=try? BoundedProcess.run("/usr/bin/hdiutil",arguments:["detach",mount],timeout:15)}
        let report=try await SystemCleanupEngine(scope:f.scope).scan(category)
        XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains{[active,mounted,invalid].contains($0.path)})
        for path in [active,mounted,invalid]{XCTAssertNotNil(report.candidates.first{$0.path == path}?.retentionReason);XCTAssertTrue(FileManager.default.fileExists(atPath:path))}
    }
}
#endif
