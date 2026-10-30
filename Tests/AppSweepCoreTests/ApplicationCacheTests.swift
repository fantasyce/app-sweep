#if os(macOS)
import Foundation
import XCTest
import Darwin
@testable import AppSweepCore

final class ApplicationCacheTests: XCTestCase, @unchecked Sendable {
    private let appleRule = "cache-apple-application-v1"
    private let containerRule = "cache-application-container-v1"
    private let identifier = "org.example.container." + UUID().uuidString.lowercased()
    private func fixture(sandbox: Bool = true) throws -> NativeAcceptanceTests.NativeFixture {
        let f = try NativeAcceptanceTests.NativeFixture(additionalRules:[appleRule,containerRule])
        let file=f.app + "/Contents/Info.plist"
        var info=try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:file)),format:nil) as? [String:Any])
        info["CFBundleIdentifier"]=identifier
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:file))
        var arguments=["--force","--sign","-"]
        if sandbox {
            let entitlements=f.home + "/sandbox.plist"
            try PropertyListSerialization.data(fromPropertyList:["com.apple.security.app-sandbox":true],format:.xml,options:0).write(to:URL(fileURLWithPath:entitlements))
            arguments += ["--entitlements",entitlements]
        }
        _=try BoundedProcess.run("/usr/bin/codesign",arguments:arguments + [f.app],timeout:10)
        return f
    }
    private func cache(_ f: NativeAcceptanceTests.NativeFixture, identifier: String? = nil, container: Bool) throws -> String {
        let id=identifier ?? self.identifier
        let root=f.home + (container ? "/Library/Containers/" + id + "/Data/Library/Caches" : "/Library/Caches/" + id)
        try FileManager.default.createDirectory(atPath:root + "/objects",withIntermediateDirectories:true)
        try Data("independent regenerable payload".utf8).write(to:URL(fileURLWithPath:root + "/objects/data"))
        try Data("whole cache index".utf8).write(to:URL(fileURLWithPath:root + "/index"))
        if container {
            let base=f.home + "/Library/Containers/" + id
            let meta:[String:Any] = ["MCMMetadataIdentifier":id,"MCMMetadataContentClass":2,"MCMMetadataVersion":9,"MCMMetadataUserIdentity":["posixUID":getuid()],"MCMMetadataOwnership":["uid":getuid()]]
            try PropertyListSerialization.data(fromPropertyList:meta,format:.binary,options:0).write(to:URL(fileURLWithPath:base + "/.com.apple.containermanagerd.metadata.plist"))
            try Data("user documents must remain".utf8).write(to:URL(fileURLWithPath:base + "/Data/document.txt"))
        }
        return root
    }
    func testExactSandboxCacheGroupMovesAndFreshEngineRestoresWithoutContainerData() async throws {
        let f=try fixture();defer{try? f.clean()}
        let root=try cache(f,container:true),before=try SafeFilesystem.snapshot(root)
        let report=try await f.engine.scanJunk(),items=report.selectableCandidates(includeUserData:false).filter{$0.rule == containerRule && $0.path.hasPrefix(root + "/")}
        XCTAssertEqual(Set(items.map(\.path)),[root + "/index",root + "/objects"])
        guard items.count == 2 else{return}
        XCTAssertTrue(items.allSatisfy{!$0.selectedByDefault && $0.applicationPath == f.app && $0.bundleIdentifier == identifier})
        let plan=try await f.engine.makePlan(reportID:report.id,selected:report.selectionIDs(for:items[0].id,includeUserData:false),includeUserData:false)
        XCTAssertEqual(plan.items.count,2)
        let moved=try await f.engine.execute(planID:plan.id)
        XCTAssertEqual(moved.status,.isolated,moved.issue ?? "")
        XCTAssertTrue(try CacheDomainRule.members(root:root).isEmpty)
        XCTAssertEqual(try String(contentsOfFile:f.home + "/Library/Containers/" + identifier + "/Data/document.txt",encoding:.utf8),"user documents must remain")
        let fresh=SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[containerRule]),vaultPath:f.home + "/Library/Application Support/App Sweep/Recovery",fixture:false)
        let restored=try await fresh.restore(batchID:moved.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        XCTAssertEqual(try SafeDirectory(path:root).ownIdentity.inode,before.identity.inode)
        XCTAssertEqual(try String(contentsOfFile:root + "/objects/data",encoding:.utf8),"independent regenerable payload")
    }
    func testAppleApplicationUserCacheUsesAppleSignatureWithoutAuthorizingItsBody() async throws {
        let f=try fixture();defer{try? f.clean()}
        let app="/System/Applications/Chess.app",id="com.apple.Chess"
        let root=try cache(f,identifier:id,container:false)
        XCTAssertNoThrow(try ApplicationCacheRule.verifyRoot(home:f.home,identifier:id,applicationPath:app,rule:appleRule))
        let report=try await f.engine.scanJunk(),items=report.selectableCandidates(includeUserData:false).filter{$0.rule == appleRule && $0.path.hasPrefix(root + "/")}
        XCTAssertEqual(items.count,2,report.candidates.filter{$0.path == root || $0.path.hasPrefix(root + "/")}.map{$0.retentionReason ?? $0.rule}.joined(separator:"; ") + report.issues.joined(separator:"; "))
        guard items.count == 2 else{return}
        XCTAssertTrue(items.allSatisfy{$0.applicationPath == app && !$0.selectedByDefault})
        let policy=SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[appleRule])
        XCTAssertNotNil(policy.protectedDenial(app))
        XCTAssertNotNil(policy.lexicalDenial(root + "/index"))
        let plan=try await f.engine.makePlan(reportID:report.id,selected:Set(items.map(\.id)),includeUserData:false)
        let moved=try await f.engine.execute(planID:plan.id)
        XCTAssertEqual(moved.status,.isolated,moved.issue ?? "")
        let restored=try await f.engine.restore(batchID:moved.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        XCTAssertTrue(FileManager.default.fileExists(atPath:app))
    }
    func testMissingSandboxEntitlementMetadataMismatchAndSharedAssociationRetainCache() async throws {
        for mode in ["notSandboxed","wrongIdentifier","shared"] {
            let f=try fixture(sandbox:mode != "notSandboxed");defer{try? f.clean()}
            let root=try cache(f,container:true),meta=f.home + "/Library/Containers/" + identifier + "/.com.apple.containermanagerd.metadata.plist"
            var info=try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:meta)),format:nil) as? [String:Any])
            if mode == "wrongIdentifier"{info["MCMMetadataIdentifier"]="org.example.other"}
            if mode == "shared"{info["AssociatedBundleIdentifiers"]=[identifier,"org.example.other"]}
            try PropertyListSerialization.data(fromPropertyList:info,format:.binary,options:0).write(to:URL(fileURLWithPath:meta))
            let report=try await f.engine.scanJunk()
            XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains{$0.path.hasPrefix(root + "/")},mode)
            XCTAssertTrue(FileManager.default.fileExists(atPath:root + "/index"))
        }
    }
    func testNativeContainerMetadataWithoutOptionalOwnershipCanIsolateAndRestoreItsCache() async throws {
        let f=try fixture();defer{try? f.clean()}
        let root=try cache(f,container:true)
        let metadata=f.home + "/Library/Containers/" + identifier + "/.com.apple.containermanagerd.metadata.plist"
        var info=try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:metadata)),format:nil) as? [String:Any])
        // Native current-user containers can omit this additional ownership dictionary.
        info.removeValue(forKey:"MCMMetadataOwnership")
        try PropertyListSerialization.data(fromPropertyList:info,format:.binary,options:0).write(to:URL(fileURLWithPath:metadata))
        let report=try await f.engine.scanJunk()
        let items=report.selectableCandidates(includeUserData:false).filter{$0.rule == containerRule && $0.path.hasPrefix(root + "/")}
        XCTAssertEqual(Set(items.map(\.path)),[root + "/index",root + "/objects"])
        guard items.count == 2 else{return}
        let plan=try await f.engine.makePlan(reportID:report.id,selected:Set(items.map(\.id)),includeUserData:false)
        let moved=try await f.engine.execute(planID:plan.id)
        XCTAssertEqual(moved.status,.isolated,moved.issue ?? "")
        let restored=try await f.engine.restore(batchID:moved.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        XCTAssertEqual(try String(contentsOfFile:root + "/objects/data",encoding:.utf8),"independent regenerable payload")
        XCTAssertEqual(try String(contentsOfFile:f.home + "/Library/Containers/" + identifier + "/Data/document.txt",encoding:.utf8),"user documents must remain")
    }
    func testOptionalContainerOwnershipCannotOverrideTheNativeUserIdentity() throws {
        let invalidOwnerships:[Any] = [["uid":getuid() + 1],["uid":true],"unrecognized"]
        for ownership in invalidOwnerships {
            let f=try fixture();defer{try? f.clean()}
            _=try cache(f,container:true)
            let metadata=f.home + "/Library/Containers/" + identifier + "/.com.apple.containermanagerd.metadata.plist"
            var info=try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:metadata)),format:nil) as? [String:Any])
            info["MCMMetadataOwnership"]=ownership
            try PropertyListSerialization.data(fromPropertyList:info,format:.binary,options:0).write(to:URL(fileURLWithPath:metadata))
            XCTAssertThrowsError(try ApplicationCacheRule.verifyRoot(home:f.home,identifier:identifier,applicationPath:f.app,rule:containerRule))
        }
    }
    func testSpoofedAppleCacheAndCriticalDaemonNamespacesRemainProtected() async throws {
        let f=try fixture();defer{try? f.clean()}
        for id in ["com.apple.fake","com.apple.containermanagerd","com.apple.TCC"]{_=try cache(f,identifier:id,container:false)}
        let report=try await f.engine.scanJunk()
        XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains{$0.path.contains("/Caches/com.apple.")})
    }
    func testContainerLinkAndBusyFileRetainWholeCache() async throws {
        for mode in ["link","busy"]{
            let f=try fixture();defer{try? f.clean()};let root=try cache(f,container:true)
            var fd:Int32 = -1
            if mode == "link"{try FileManager.default.createSymbolicLink(atPath:root + "/escape",withDestinationPath:f.home)}
            else{fd=open(root + "/index",O_RDONLY | O_NOFOLLOW | O_CLOEXEC)}
            defer{if fd >= 0{close(fd)}}
            let report=try await f.engine.scanJunk()
            XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains{$0.path.hasPrefix(root + "/")},mode)
        }
    }
    func testProtectedDirectMemberKeepsItsEntireContainerCacheGroup() async throws {
        let f=try fixture();defer{try? f.clean()};let root=try cache(f,container:true)
        try Data("protected cache member".utf8).write(to:URL(fileURLWithPath:root + "/com.apple.shared-index"))
        let report=try await f.engine.scanJunk()
        XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains{$0.path.hasPrefix(root + "/")},"A required cache group cannot offer only its unprotected siblings")
    }
    func testContainerMetadataReplacementAfterPlanStopsBeforeMovingAnything() async throws {
        let f=try fixture();defer{try? f.clean()};let root=try cache(f,container:true)
        let report=try await f.engine.scanJunk(),items=report.selectableCandidates(includeUserData:false).filter{$0.rule == containerRule}
        XCTAssertEqual(items.count,2);guard items.count == 2 else{return}
        let plan=try await f.engine.makePlan(reportID:report.id,selected:Set(items.map(\.id)),includeUserData:false)
        let meta=f.home + "/Library/Containers/" + identifier + "/.com.apple.containermanagerd.metadata.plist"
        try PropertyListSerialization.data(fromPropertyList:["MCMMetadataIdentifier":"org.example.other"],format:.binary,options:0).write(to:URL(fileURLWithPath:meta))
        do{_=try await f.engine.execute(planID:plan.id);XCTFail("Changed container ownership was accepted")}catch{}
        XCTAssertTrue(FileManager.default.fileExists(atPath:root + "/index"))
        XCTAssertTrue(FileManager.default.fileExists(atPath:root + "/objects/data"))
    }
    func testTypedCacheAuthorityDoesNotExtendToContainerDataSystemStateOrNestedAppleDomains() throws {
        let home="/Users/test",policy=SafetyPolicy(home:home,acceptedPlatform:true,validatedRules:[appleRule,containerRule])
        XCTAssertNil(policy.denial(path:home + "/Library/Caches/com.apple.Chess/index",category:.cache,rule:appleRule))
        XCTAssertNil(policy.denial(path:home + "/Library/Containers/com.apple.Chess/Data/Library/Caches/index",category:.cache,rule:containerRule))
        for path in ["/System/Library/Caches/com.apple.Chess/index",home + "/Library/Containers/com.apple.Chess/Data/Documents/private",home + "/Library/Group Containers/com.apple.Chess/Data/Library/Caches/index",home + "/Library/Caches/com.apple.Chess/com.apple.TCC",home + "/Library/Caches/com.apple.Chess/../com.apple.TCC/index"] {
            for rule in [appleRule,containerRule] { XCTAssertNotNil(policy.denial(path:path,category:.cache,rule:rule),path) }
        }
    }
    func testRegisteredAppleBackgroundServiceKeepsItsCacheAndExplainsWhy() async throws {
        let f=try fixture();defer{try? f.clean()}
        let id="com.apple.Dictionary",root=try cache(f,identifier:id,container:false)
        let services=try BoundedProcess.run("/bin/launchctl",arguments:["print","gui/" + String(getuid())],timeout:3)
        guard services.contains("com.apple.DictionaryServiceHelper") else { throw XCTSkip("Native Dictionary helper registration not present on this platform") }
        let report=try await f.engine.scanJunk(),item=try XCTUnwrap(report.candidates.first{$0.path == root})
        XCTAssertFalse(item.allowed)
        XCTAssertTrue(item.retentionReason?.contains("后台服务") == true,item.retentionReason ?? "missing reason")
        XCTAssertTrue(FileManager.default.fileExists(atPath:root + "/index"))
    }
    func testActualSandboxConsumerUsesDefaultUserContextAndReadsRestoredGeneration() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_CONTAINER_CACHE_ACCEPTANCE"] == "AppSweep-General-20261016" else { throw XCTSkip("Explicit registered disposable VM sandbox consumer only") }
        guard getuid() == 501,try SystemIdentity.home() == "/Users/localtest",
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).trimmingCharacters(in:.whitespacesAndNewlines) == "VirtualMac2,1" else { throw SweepError.denied("Native container acceptance requires the registered disposable VM") }
        let task="/Users/localtest/AppSweepAcceptanceGeneral-20261016",home=try SystemIdentity.home()
        let info=try XCTUnwrap(try JSONSerialization.jsonObject(with:Data(contentsOf:URL(fileURLWithPath:task + "/native-container-cache-current.json"))) as? [String:Any])
        let id=try XCTUnwrap(info["identifier"] as? String),app=try XCTUnwrap(info["application"] as? String),stage=try XCTUnwrap(info["stage"] as? String)
        guard id.hasPrefix("org.example.disposable.cache."),UUID(uuidString:String(id.dropFirst("org.example.disposable.cache.".count))) != nil,
              app == home + "/Applications/Disposable Sandbox Cache " + String(id.dropFirst("org.example.disposable.cache.".count)) + ".app",
              stage.hasPrefix(task + "/native-container-cache-"),!stage.dropFirst(task.count + 1).contains("/") else { throw SweepError.denied("Native container fixture registration is invalid") }
        let root=home + "/Library/Containers/" + id + "/Data/Library/Caches",executable=app + "/Contents/MacOS/consumer"
        let appSnapshot=try SafeFilesystem.snapshot(app,allowInternalLinks:true)
        func consume(_ mode: String) throws -> Int {
            let output=try BoundedProcess.run(executable,arguments:[mode],timeout:10)
            let value=try XCTUnwrap(try JSONSerialization.jsonObject(with:Data(output.utf8)) as? [String:Any])
            guard value["cache"] as? String == root,value["identifier"] as? String == id else{throw SweepError.stale("Native consumer context changed")}
            return try XCTUnwrap(value["bytes"] as? Int)
        }
        // The registered fixture may be reused days later. Its HTTP response
        // expires after24h; refresh only this task's native cache before taking
        // the new baseline, rather than treating an expired response as damage.
        guard try consume("--generate") == 524288,try consume("--read") == 524288 else{throw SweepError.incomplete("Fresh native cache was not readable before cleanup")}
        let original=try SafeFilesystem.snapshot(root)
        let e=SweepEngine(),report=try await e.scanJunk(),items=report.selectableCandidates(includeUserData:false).filter{$0.rule == containerRule && $0.path.hasPrefix(root + "/")}
        guard !items.isEmpty else{throw SweepError.incomplete("Default policy did not expose native sandbox cache: " + report.candidates.filter{$0.path == root || $0.path.hasPrefix(root + "/")}.map{$0.retentionReason ?? $0.rule}.joined(separator:"; "))}
        XCTAssertTrue(items.allSatisfy{!$0.selectedByDefault})
        let plan=try await e.makePlan(reportID:report.id,selected:report.selectionIDs(for:items[0].id,includeUserData:false),includeUserData:false)
        let batch=try await e.execute(planID:plan.id)
        guard batch.status == .isolated else{throw SweepError.incomplete(batch.issue ?? "Native cache not isolated")}
        guard try consume("--generate") == 524288 else{throw SweepError.incomplete("Native cache did not regenerate")}
        let conflict=try await SweepEngine().restore(batchID:batch.id)
        guard conflict.status == .needsAttention,try consume("--read") == 524288 else{throw SweepError.incomplete("Regenerated native cache conflict was not preserved")}
        let generation=stage + "/regenerated-cache-" + batch.id.uuidString
        try FileManager.default.createDirectory(atPath:generation,withIntermediateDirectories:false)
        for name in try FileManager.default.contentsOfDirectory(atPath:root){try FileManager.default.moveItem(atPath:root + "/" + name,toPath:generation + "/" + name)}
        let restored=try await SweepEngine().restore(batchID:batch.id)
        guard restored.status == .restored,try consume("--read") == 524288 else{throw SweepError.incomplete(restored.issue ?? "Native cache restore/read failed")}
        XCTAssertEqual(try SafeDirectory(path:root).ownIdentity.inode,original.identity.inode)
        try SafeFilesystem.verify(appSnapshot)
        guard testRun?.failureCount == 0 else{throw SweepError.incomplete("Native assertions failed; no acceptance receipt")}
        let receipt:[String:Any] = ["identifier":id,"application":app,"cache":root,"cacheInode":original.identity.inode,"batches":[batch.id.uuidString],"regenerated":generation,"state":"fresh native App Sandbox cache; default policy isolation, regeneration, conflict refusal, fresh-engine restoration and native read passed; packaged GUI pending"]
        try JSONSerialization.data(withJSONObject:receipt,options:[.prettyPrinted,.sortedKeys]).write(to:URL(fileURLWithPath:stage + "/acceptance-" + batch.id.uuidString + ".json"),options:.withoutOverwriting)
        print("NATIVE_CONTAINER_CACHE_ACCEPTED " + String(data:try JSONSerialization.data(withJSONObject:receipt),encoding:.utf8)!)
    }
}
#endif
