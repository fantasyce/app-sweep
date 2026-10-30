#if os(macOS)
import Foundation
import XCTest
import Darwin
@testable import AppSweepCore

final class SimulatorCacheTests:XCTestCase,@unchecked Sendable {
    private let rule="registered-simulator-cache-v1"
    func testDeviceRootBindingAllowsChildChangesButRejectsReplacement()throws{
        let f=try NativeAcceptanceTests.NativeFixture();defer{try? f.clean()}
        let original=try SafeDirectory(path:f.home).ownIdentity
        try Data("new child".utf8).write(to:URL(fileURLWithPath:f.home+"/new-child"))
        XCTAssertTrue(SimulatorCacheRule.sameDataDirectory(try SafeDirectory(path:f.home).ownIdentity,original))
        XCTAssertFalse(SimulatorCacheRule.sameDataDirectory(try SafeDirectory(path:f.home+"/Applications").ownIdentity,original))
        XCTAssertEqual(chmod(f.home,0o750),0)
        XCTAssertFalse(SimulatorCacheRule.sameDataDirectory(try SafeDirectory(path:f.home).ownIdentity,original))
        XCTAssertEqual(chmod(f.home,0o700),0)
    }
    func testResumeExistingNativeRebuildConflictWithoutRepeatingConsumer()async throws{
        guard ProcessInfo.processInfo.environment["APP_SWEEP_SIMULATOR_RECOVERY_ACCEPTANCE"] == "AppSweep-General-20261016" else{throw XCTSkip("Exact registered native simulator batch resume only")}
        let task="/Users/localtest/AppSweepAcceptanceGeneral-20261016",home=try SystemIdentity.home()
        guard home == "/Users/localtest",getuid() == 501,try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).hasPrefix("VirtualMac") else{throw SweepError.denied("Registered VM only")}
        let info=try XCTUnwrap(try JSONSerialization.jsonObject(with:SafeFilesystem.readMetadata(task+"/simulator-cache-recovery-current.json"))as? [String:Any]),batchID=try XCTUnwrap(UUID(uuidString:try XCTUnwrap(info["batch"]as? String)))
        let current=SafetyPolicy.current,policy=SafetyPolicy(home:home,acceptedPlatform:true,validatedRules:NativeAcceptance.rules(for:PlatformStamp.current).union([rule]),darwinScope:current.darwinScope,darwinScopeIssue:current.darwinScopeIssue)
        let engine=SweepEngine(policy:policy,vaultPath:home+"/Library/Application Support/App Sweep/Recovery",fixture:false),before=try await engine.recoveryBatch(id:batchID)
        let entry=try XCTUnwrap(before.entries.first)
        guard before.entries.count == 1,entry.original.rule == rule,entry.original.path == info["source"]as? String,before.status == .needsAttention else{throw SweepError.denied("Native batch registration changed")}
        let restored=try await engine.restore(batchID:batchID)
        XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:"; "))
        guard restored.status == .restored else{return}
        let snapshot=try SafeFilesystem.snapshot(entry.original.path)
        XCTAssertEqual(snapshot.identity.inode,entry.original.identity?.inode)
        XCTAssertTrue(try entry.matchesContents(snapshot))
        print("NATIVE_SIMULATOR_EXISTING_BATCH_RESTORED "+batchID.uuidString)
    }
    func testNativeDirectoryModesRequirePrivateBarrierAndUnsharedCache()throws{
        let f=try NativeAcceptanceTests.NativeFixture();defer{try? f.clean()}
        let library=f.home+"/Library",data=library+"/Developer/CoreSimulator/Devices/"+UUID().uuidString+"/data",cache=data+"/Library/Caches/native-cache"
        try FileManager.default.createDirectory(atPath:cache,withIntermediateDirectories:true)
        try Data("regenerable".utf8).write(to:URL(fileURLWithPath:cache+"/data"))
        XCTAssertEqual(chmod(library,0o700),0);XCTAssertEqual(chmod(data,0o775),0);XCTAssertEqual(chmod(data+"/Library",0o775),0)
        XCTAssertNoThrow(try SimulatorCacheRule.verifyPrivateTree(SafeFilesystem.snapshot(cache),home:f.home))
        XCTAssertEqual(chmod(library,0o755),0)
        XCTAssertThrowsError(try SimulatorCacheRule.verifyPrivateTree(SafeFilesystem.snapshot(cache),home:f.home))
        XCTAssertEqual(chmod(library,0o700),0);XCTAssertEqual(chmod(cache,0o777),0)
        XCTAssertThrowsError(try SimulatorCacheRule.verifyPrivateTree(SafeFilesystem.snapshot(cache),home:f.home))
    }
    func testCatalogueCannotAuthorizeAliasesOtherUsersOrDuplicateDevices()throws{
        let home="/Users/example",id=UUID().uuidString,runtime="com.apple.CoreSimulator.SimRuntime.iOS-17-2"
        let row:[String:Any]=["udid":id,"dataPath":home+"/Library/Developer/CoreSimulator/Devices/"+id+"/data","deviceTypeIdentifier":"com.apple.CoreSimulator.SimDeviceType.iPhone-15","state":"Shutdown","isAvailable":true,"name":"Test"]
        func packet(_ rows:[[String:Any]])throws->Data{try JSONSerialization.data(withJSONObject:["devices":[runtime:rows]])}
        XCTAssertEqual(try SimulatorCacheRule.parse(packet([row]),home:home).count,1)
        XCTAssertThrowsError(try SimulatorCacheRule.parse(packet([row,row]),home:home))
        var other=row;other["dataPath"]="/Users/other/Library/Developer/CoreSimulator/Devices/"+id+"/data"
        XCTAssertThrowsError(try SimulatorCacheRule.parse(packet([other]),home:home))
        let root=home+"/Library/Developer/CoreSimulator/Devices/"+id+"/data/Library/Caches"
        XCTAssertNil(SimulatorCacheRule.deviceID(root,home:home))
        XCTAssertNil(SimulatorCacheRule.deviceID(root+"/../Keychains",home:home))
        XCTAssertNil(SimulatorCacheRule.deviceID(root+"/cache/nested",home:home))
        XCTAssertEqual(SimulatorCacheRule.deviceID(root+"/cache",home:home),id)
    }
    func testNativeRegisteredDeviceCacheIsManualAndRestoresWithoutDeviceData()async throws{
        guard ProcessInfo.processInfo.environment["APP_SWEEP_SIMULATOR_ACCEPTANCE"] == "AppSweep-General-20261016" else{throw XCTSkip("Registered disposable VM simulator only")}
        let home=try SystemIdentity.home(),task="/Users/localtest/AppSweepAcceptanceGeneral-20261016"
        guard home == "/Users/localtest",getuid() == 501,try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).hasPrefix("VirtualMac") else{throw SweepError.denied("Registered VM only")}
        let info=try XCTUnwrap(try JSONSerialization.jsonObject(with:SafeFilesystem.readMetadata(task+"/simulator-native-current.json"))as? [String:Any])
        let udid=try XCTUnwrap(info["udid"]as? String),root=try XCTUnwrap(info["path"]as? String)
        guard UUID(uuidString:udid) != nil,root == home+"/Library/Developer/CoreSimulator/Devices/"+udid,
              try SafeDirectory(path:root).ownIdentity.inode == info["inode"]as? UInt64 else{throw SweepError.denied("Device registration changed")}
        let cache=root+"/data/Library/Caches/com.apple.springboard",before=try SafeFilesystem.snapshot(cache)
        let userMarker=root+"/data/Library/Preferences/org.example.appsweep.simulatorprobe.plist",marker=try Data(contentsOf:URL(fileURLWithPath:userMarker))
        let current=SafetyPolicy.current
        let policy=SafetyPolicy(home:home,acceptedPlatform:true,validatedRules:NativeAcceptance.rules(for:PlatformStamp.current).union([rule]),darwinScope:current.darwinScope,darwinScopeIssue:current.darwinScopeIssue)
        let engine=SweepEngine(policy:policy,vaultPath:home+"/Library/Application Support/App Sweep/Recovery",fixture:false),report=try await engine.scanJunk()
        guard let item=report.candidates.first(where:{$0.path == cache && $0.rule == rule}) else{XCTFail("Registered simulator regenerable cache missing from ordinary product scan");return}
        XCTAssertFalse(item.userData);XCTAssertFalse(item.selectedByDefault)
        guard report.selectableCandidates(includeUserData:false).contains(where:{$0.id == item.id}) else{XCTFail(item.retentionReason ?? "Simulator cache unavailable");return}
        let plan=try await engine.makePlan(reportID:report.id,selected:[item.id],includeUserData:false),batch=try await engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        XCTAssertFalse(FileManager.default.fileExists(atPath:cache))
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:userMarker)),marker)
        print("SIMULATOR_CACHE_ISOLATED "+batch.id.uuidString)
        let boot=try BoundedProcess.capture(SimulatorCacheRule.tool,arguments:["boot",udid],timeout:15,mergeStderr:true)
        guard boot.status == 0 else{throw SweepError.incomplete("Owned simulator boot failed: "+boot.text)}
        var stopped=false
        defer{if !stopped{_=try? BoundedProcess.capture(SimulatorCacheRule.tool,arguments:["shutdown",udid],timeout:15,mergeStderr:true)}}
        XCTAssertThrowsError(try SimulatorCacheRule.ensureStopped(item,home:home))
        let deadline=ProcessInfo.processInfo.systemUptime+90
        var consumer=false
        while ProcessInfo.processInfo.systemUptime < deadline{
            let read=try? BoundedProcess.capture(SimulatorCacheRule.tool,arguments:["spawn",udid,"defaults","read","org.example.appsweep.simulatorprobe","marker"],timeout:3,mergeStderr:true)
            if read?.status == 0,FileManager.default.fileExists(atPath:cache){consumer=true;break}
            try await Task.sleep(nanoseconds:1_000_000_000)
        }
        XCTAssertTrue(consumer,"Original native consumer must start and recreate its cache without touching personal preferences")
        let shutdown=try BoundedProcess.capture(SimulatorCacheRule.tool,arguments:["shutdown",udid],timeout:15,mergeStderr:true)
        guard shutdown.status == 0 else{throw SweepError.incomplete("Owned simulator shutdown unconfirmed: "+shutdown.text)}
        stopped=true
        let regenerated=try SafeFilesystem.snapshot(cache)
        let fresh=SweepEngine(policy:policy,vaultPath:home+"/Library/Application Support/App Sweep/Recovery",fixture:false)
        let conflict=try await fresh.restore(batchID:batch.id)
        XCTAssertEqual(conflict.status,.needsAttention)
        try SafeFilesystem.verify(regenerated)
        let saved=try SafeDirectory(path:task).privateChild("simulator-cache-regenerated-"+batch.id.uuidString+".noindex")
        try saved.write(JSONSerialization.data(withJSONObject:["path":cache,"inode":regenerated.identity.inode,"volumeUUID":regenerated.identity.volumeUUID ?? "","batch":batch.id.uuidString]),name:"ownership.json")
        try SafeFilesystem.move(regenerated,into:saved,name:"cache")
        let restored=try await SweepEngine(policy:policy,vaultPath:home+"/Library/Application Support/App Sweep/Recovery",fixture:false).restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:"; "))
        guard restored.status == .restored else{return}
        XCTAssertEqual(try SafeDirectory(path:cache).ownIdentity.inode,before.identity.inode)
        XCTAssertEqual(try SafeFilesystem.snapshot(cache).tree,before.tree)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:userMarker)),marker)
        print("NATIVE_SIMULATOR_CACHE_ACCEPTED "+batch.id.uuidString)
    }
}
#endif
