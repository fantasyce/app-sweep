#if os(macOS)
import Foundation
import XCTest
import Darwin
@testable import AppSweepCore

final class DarwinCacheTests: XCTestCase, @unchecked Sendable {
    private let rule="cache-darwin-application-v1"
    private func fixture() throws -> (NativeAcceptanceTests.NativeFixture,DarwinCacheScope,String,SweepEngine) {
        let f=try NativeAcceptanceTests.NativeFixture(),id="org.example.darwin." + UUID().uuidString.lowercased(),file=f.app + "/Contents/Info.plist"
        var info=try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:file)),format:nil)as? [String:Any]);info["CFBundleIdentifier"]=id
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:file))
        _=try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-",f.app],timeout:10)
        let root=f.home + "/DarwinCache"
        try FileManager.default.createDirectory(atPath:root,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
        let scope=try DarwinCacheScope.fixture(home:f.home),namespace=root + "/" + id
        try FileManager.default.createDirectory(atPath:namespace + "/objects",withIntermediateDirectories:true)
        try Data("complete cache index".utf8).write(to:URL(fileURLWithPath:namespace + "/index"))
        try Data("regenerable cache bytes".utf8).write(to:URL(fileURLWithPath:namespace + "/objects/data"))
        let e=SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[rule],darwinScope:scope),vaultPath:f.home + "/Library/Application Support/App Sweep/Recovery",fixture:false)
        return(f,scope,id,e)
    }
    func testOSRootParserOnlyAcceptsTheBoundedCcacheShape() {
        let base="/private/var/folders/ab/0123456789012345678901234567/C"
        XCTAssertEqual(DarwinCacheScope.canonicalRoot("/var/folders/ab/0123456789012345678901234567/C/\n"),base)
        for path in ["/private/var/folders",base + "/org.example.app",base.replacingOccurrences(of:"/C",with:"/T"),base.replacingOccurrences(of:"/C",with:"/0"),base + "/../T",base.replacingOccurrences(of:"/ab/",with:"/ab//"),"/Users/test/C","/private/var/folders/ab/short/C"]{XCTAssertNil(DarwinCacheScope.canonicalRoot(path),path)}
    }
    func testWholeApplicationAndDarwinCacheShareOneRecoverableTransaction() async throws {
        let (f,scope,id,_) = try fixture(); defer { try? f.clean() }
        let e=SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[SelectedApplicationRule.name,rule],darwinScope:scope),vaultPath:f.home + "/Library/Application Support/App Sweep/Recovery",fixture:false)
        let root=scope.root + "/" + id
        let report=try await e.scanApplication(f.app)
        let items=report.selectableCandidates(includeUserData:false).filter{$0.category == .application || $0.rule == rule}
        XCTAssertEqual(items.filter{$0.rule == rule}.count,2)
        let plan=try await e.makePlan(reportID:report.id,selected:Set(items.map(\.id)),includeUserData:false)
        let moved=try await e.execute(planID:plan.id)
        XCTAssertEqual(moved.status,.isolated,moved.issue ?? "")
        XCTAssertFalse(FileManager.default.fileExists(atPath:f.app))
        XCTAssertTrue(try CacheDomainRule.members(root:root).isEmpty)
        let restored=try await e.restore(batchID:moved.id)
        XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:"; "))
        XCTAssertTrue(AppInspector.signatureMatches(path:f.app,identifier:id))
        XCTAssertEqual(try String(contentsOfFile:root + "/objects/data",encoding:.utf8),"regenerable cache bytes")
    }
    func testCapturedScopeDoesNotAuthorizeItsRootOtherDomainsOrAnotherHome() throws {
        let(f,scope,id,_)=try fixture();defer{try? f.clean()}
        let policy=SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[rule],darwinScope:scope)
        XCTAssertNil(policy.denial(path:scope.root + "/" + id + "/index",category:.cache,rule:rule))
        for path in [scope.root,scope.root + "/" + id,scope.root + "/com.apple.TCC/index",scope.root + "/" + id + "/keychains",scope.root + "/" + id + "/objects/data",scope.root + "/../T/" + id + "/index","/private/var/folders/ab/0123456789012345678901234567/C/" + id + "/index"]{XCTAssertNotNil(policy.denial(path:path,category:.cache,rule:rule),path)}
        XCTAssertNotNil(SafetyPolicy(home:f.home + "/other",acceptedPlatform:true,validatedRules:[rule],darwinScope:scope).denial(path:scope.root + "/" + id + "/index",category:.cache,rule:rule))
    }
    func testFixtureScopedCacheMovesTheWholeGroupAndRestoresWithoutMovingItsRoot() async throws {
        let(f,scope,id,e)=try fixture();defer{try? f.clean()};let root=scope.root + "/" + id,before=try SafeFilesystem.snapshot(root)
        let report=try await e.scanJunk(),items=report.selectableCandidates(includeUserData:false).filter{$0.rule == rule}
        XCTAssertEqual(Set(items.map(\.path)),[root + "/index",root + "/objects"]);guard let first=items.first else{return}
        XCTAssertTrue(items.allSatisfy{!$0.selectedByDefault})
        let plan=try await e.makePlan(reportID:report.id,selected:report.selectionIDs(for:first.id,includeUserData:false),includeUserData:false),batch=try await e.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        XCTAssertEqual(try SafeDirectory(path:root).ownIdentity.inode,before.identity.inode)
        let restored=try await e.restore(batchID:batch.id);XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        XCTAssertEqual(try String(contentsOfFile:root + "/objects/data",encoding:.utf8),"regenerable cache bytes")
    }
    func testNamespaceLinksBusyFilesAndSharedWritesRetainTheWholeCache() async throws {
        for mode in ["link","busy","shared"]{
            let(f,scope,id,e)=try fixture();defer{try? f.clean()};let root=scope.root + "/" + id
            var fd:Int32 = -1
            if mode == "link"{try FileManager.default.createSymbolicLink(atPath:root + "/escape",withDestinationPath:f.home)}
            if mode == "busy"{fd=open(root + "/index",O_RDONLY | O_NOFOLLOW | O_CLOEXEC)}
            if mode == "shared"{XCTAssertEqual(chmod(root,0o777),0)}
            defer{if fd >= 0{close(fd)}}
            let report=try await e.scanJunk();XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains{$0.rule == rule},mode)
            XCTAssertTrue(FileManager.default.fileExists(atPath:root + "/index"))
        }
    }
    func testReplacingOnlyThePrivateFixtureRootAfterPlanningStopsExecution() async throws {
        let(f,scope,id,e)=try fixture();defer{try? f.clean()};let report=try await e.scanJunk(),items=report.selectableCandidates(includeUserData:false).filter{$0.rule == rule}
        XCTAssertEqual(items.count,2);guard items.count == 2 else{return}
        let plan=try await e.makePlan(reportID:report.id,selected:Set(items.map(\.id)),includeUserData:false),saved=f.home + "/saved-DarwinCache"
        try FileManager.default.moveItem(atPath:scope.root,toPath:saved)
        try FileManager.default.createDirectory(atPath:scope.root,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
        XCTAssertThrowsError(try scope.verify())
        do{_=try await e.execute(planID:plan.id);XCTFail("Replaced captured scope was accepted")}catch{}
        XCTAssertEqual(try String(contentsOfFile:saved + "/" + id + "/index",encoding:.utf8),"complete cache index")
    }
    func testProtectedDirectMemberRetainsItsWholeDarwinNamespace() async throws {
        let(f,scope,id,e)=try fixture();defer{try? f.clean()};let root=scope.root + "/" + id
        try Data("protected cache member".utf8).write(to:URL(fileURLWithPath:root + "/com.apple.shared-index"))
        let report=try await e.scanJunk()
        XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains{$0.path.hasPrefix(root + "/")},"A required cache group cannot offer only its unprotected siblings")
    }
    func testChangedApplicationIdentityBeforeRecoveryKeepsDarwinCacheIsolated() async throws {
        let(f,scope,id,e)=try fixture();defer{try? f.clean()};let root=scope.root + "/" + id
        let report=try await e.scanJunk(),items=report.selectableCandidates(includeUserData:false).filter{$0.rule == rule}
        let plan=try await e.makePlan(reportID:report.id,selected:Set(items.map(\.id)),includeUserData:false),batch=try await e.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        let path=f.app + "/Contents/Info.plist",original=try Data(contentsOf:URL(fileURLWithPath:path))
        var info=try XCTUnwrap(try PropertyListSerialization.propertyList(from:original,format:nil)as? [String:Any]);info["CFBundleIdentifier"]="org.example.replaced." + UUID().uuidString.lowercased()
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:path))
        _=try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-",f.app],timeout:10)
        let rejected=try await e.restore(batchID:batch.id)
        XCTAssertEqual(rejected.status,.needsAttention,"Recovery must recheck current ownership before writing into the Darwin domain")
        XCTAssertFalse(FileManager.default.fileExists(atPath:root + "/index"))
        try original.write(to:URL(fileURLWithPath:path))
        _=try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-",f.app],timeout:10)
        let restored=try await e.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
    }
    func testDefaultPolicyMovesOnlyRegisteredDarwinApplicationCacheAndFreshEngineRestoresIt() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_DARWIN_CACHE_ACCEPTANCE"] == "AppSweep-General-20261016" else{throw XCTSkip("Explicit registered disposable VM Darwin cache consumer")}
        guard getuid() == 501,try SystemIdentity.home() == "/Users/localtest",
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).trimmingCharacters(in:.whitespacesAndNewlines) == "VirtualMac2,1" else{throw SweepError.denied("Requires the registered disposable VM")}
        let task="/Users/localtest/AppSweepAcceptanceGeneral-20261016"
        let info=try XCTUnwrap(try JSONSerialization.jsonObject(with:SafeFilesystem.readMetadata(task + "/darwin-cache-default-current.json"))as? [String:Any])
        let id=try XCTUnwrap(info["identifier"]as? String),app=try XCTUnwrap(info["application"]as? String),root=try XCTUnwrap(info["cache"]as? String),owned=try XCTUnwrap(info["owned"]as? String)
        guard id.hasPrefix("org.example.disposable.darwin."),let uuid=UUID(uuidString:String(id.dropFirst("org.example.disposable.darwin.".count))),
              app == "/Users/localtest/Applications/Disposable Darwin Cache " + uuid.uuidString.lowercased() + ".app",
              owned == task + "/native-darwin-cache-" + uuid.uuidString.lowercased() + ".noindex",
              root.hasPrefix("/private/var/folders/"),root.hasSuffix("/C/" + id),!FileManager.default.fileExists(atPath:owned + "/result.json") else{throw SweepError.denied("Registered Darwin fixture paths changed")}
        let before=try SafeFilesystem.snapshot(root),appBefore=try SafeFilesystem.snapshot(app,allowInternalLinks:true),base=URL(fileURLWithPath:root).deletingLastPathComponent().path,baseBefore=try SafeDirectory(path:base).ownIdentity
        func consume() throws {
            let output=try BoundedProcess.run(app + "/Contents/MacOS/consumer",arguments:["--read"],timeout:10)
            let value=try XCTUnwrap(try JSONSerialization.jsonObject(with:Data(output.utf8))as? [String:Any])
            XCTAssertEqual(value["bytes"]as? Int,524288);XCTAssertEqual(value["root"]as? String,root)
        }
        try consume()
        let e=SweepEngine(),report=try await e.scanJunk(),items=report.selectableCandidates(includeUserData:false).filter{$0.rule == rule && $0.path.hasPrefix(root + "/")}
        XCTAssertFalse(items.isEmpty,report.candidates.filter{$0.path == root || $0.path.hasPrefix(root + "/")}.compactMap(\.retentionReason).joined(separator:"; "))
        guard let first=items.first else{return}
        XCTAssertTrue(items.allSatisfy{!$0.selectedByDefault && $0.bundleIdentifier == id && $0.applicationPath == app})
        XCTAssertFalse(items.contains{$0.path == root || $0.path == base})
        let plan=try await e.makePlan(reportID:report.id,selected:report.selectionIDs(for:first.id,includeUserData:false),includeUserData:false),batch=try await e.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        XCTAssertTrue(try CacheDomainRule.members(root:root).isEmpty)
        let restored=try await SweepEngine().restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        XCTAssertEqual(try SafeDirectory(path:root).ownIdentity.inode,before.identity.inode)
        XCTAssertEqual(try SafeDirectory(path:base).ownIdentity.inode,baseBefore.inode)
        try consume();try SafeFilesystem.verify(appBefore)
        let result:[String:Any]=["application":app,"cache":root,"namespaceInode":before.identity.inode,"preexistingDarwinRoot":base,"preexistingDarwinRootInode":baseBefore.inode,"batch":batch.id.uuidString,"state":"default current-user engine isolated registered third-party Darwin cache members; fresh engine restored; native Foundation consumer verified every payload byte; namespace and preexisting OS cache root retained; ordinary GUI/reboot still pending"]
        try JSONSerialization.data(withJSONObject:result,options:[.prettyPrinted,.sortedKeys]).write(to:URL(fileURLWithPath:owned + "/result.json"),options:.withoutOverwriting)
        print("DEFAULT_DARWIN_CACHE_ACCEPTED " + String(data:try JSONSerialization.data(withJSONObject:result),encoding:.utf8)!)
    }
}
#endif
