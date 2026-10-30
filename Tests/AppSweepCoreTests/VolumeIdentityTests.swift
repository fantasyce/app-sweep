import Foundation
import XCTest
@testable import AppSweepCore

final class VolumeIdentityTests:XCTestCase,@unchecked Sendable {
    private let first="D6883EE6-049F-49DA-AFD5-E908CE6D51C9"
    private let second="DFBEE8C5-0906-46FB-AB78-1B9E2D125B3D"
    private func identity(device:UInt64,volume:String)throws->FileIdentity {
        let object:[String:Any]=["device":device,"inode":42,"mode":UInt32(0o100600),"owner":UInt32(501),"links":1,"size":7,"modifiedSeconds":100,"modifiedNanoseconds":0,"changedSeconds":100,"changedNanoseconds":0,"volumeUUID":volume]
        return try JSONDecoder().decode(FileIdentity.self,from:JSONSerialization.data(withJSONObject:object))
    }
    func testStableVolumeAndInodeSurviveNativeDeviceNumberReassignment()throws{
        let a=try identity(device:100,volume:first),b=try identity(device:200,volume:first)
        XCTAssertEqual(a,b);XCTAssertTrue(a.sameObject(as:b))
        let other=try identity(device:100,volume:second)
        XCTAssertNotEqual(a,other);XCTAssertFalse(a.sameObject(as:other))
    }
    #if canImport(CryptoKit)
    func testTreeCommitmentUsesStableVolumeRatherThanMountNumber()throws{
        let a=[TreeEntry(relative:"file",identity:try identity(device:100,volume:first))],b=[TreeEntry(relative:"file",identity:try identity(device:200,volume:first))]
        let hash=try TreeFingerprint.capture(a)
        XCTAssertTrue(try hash.matches(b))
        XCTAssertFalse(try hash.matches([TreeEntry(relative:"file",identity:try identity(device:100,volume:second))]))
    }
    #endif
    #if os(macOS)
    func testNativeSnapshotsPersistVolumeIdentityWithoutFollowingOpaqueLinks()throws{
        let f=try RecoveryTests.Fixture();defer{try? f.clean()}
        let path=f.source+"/opaque-link"
        try FileManager.default.createSymbolicLink(atPath:path,withDestinationPath:"/System")
        let snapshot=try SafeFilesystem.snapshot(f.source,allowInternalLinks:true),data=try JSONEncoder().encode(snapshot.identity)
        let value=try XCTUnwrap(try JSONSerialization.jsonObject(with:data)as? [String:Any]),uuid=try XCTUnwrap(value["volumeUUID"]as? String)
        XCTAssertNotNil(UUID(uuidString:uuid))
        let node=try XCTUnwrap(snapshot.tree.first{$0.relative == "opaque-link"}),link=try XCTUnwrap(try JSONSerialization.jsonObject(with:JSONEncoder().encode(node.identity))as? [String:Any])
        XCTAssertEqual(link["volumeUUID"]as? String,uuid)
    }
    #endif
    private func transform(_ value:Any,deviceOffset:UInt64,removeUUID:Bool=false)->Any {
        if let array=value as? [Any]{return array.map{transform($0,deviceOffset:deviceOffset,removeUUID:removeUUID)}}
        guard var object=value as? [String:Any] else{return value}
        for (key,child)in object{object[key]=transform(child,deviceOffset:deviceOffset,removeUUID:removeUUID)}
        if let device=object["device"]as? UInt64{object["device"]=device+deviceOffset}
        if removeUUID{object.removeValue(forKey:"volumeUUID")}
        return object
    }
    #if os(macOS)
    func testPersistedBatchRestoresAcrossMountNumberChangeWithStableVolumeProof()async throws{
        let f=try RecoveryTests.Fixture();defer{try? f.clean()};let engine=f.engine()
        let report=await engine.adoptFixture([f.candidate],snapshots:[f.candidate.id:f.snapshot]),plan=try await engine.makePlan(reportID:report.id,selected:[f.candidate.id],includeUserData:false),batch=try await engine.execute(planID:plan.id)
        let root=try SafeDirectory(path:f.vault+"/"+batch.id.uuidString),before=try root.read("manifest.json"),json=try JSONSerialization.jsonObject(with:before)
        try root.write(JSONSerialization.data(withJSONObject:transform(json,deviceOffset:1000)),name:"manifest.json")
        let restored=try await f.engine().restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:"; "))
        XCTAssertEqual(try String(contentsOfFile:f.source+"/data",encoding:.utf8),"regenerable")
    }
    func testOldRecordWithUnprovedChangedVolumeIsPreviewOnly()async throws{
        let f=try RecoveryTests.Fixture();defer{try? f.clean()};let engine=f.engine()
        let report=await engine.adoptFixture([f.candidate],snapshots:[f.candidate.id:f.snapshot]),plan=try await engine.makePlan(reportID:report.id,selected:[f.candidate.id],includeUserData:false),batch=try await engine.execute(planID:plan.id)
        let root=try SafeDirectory(path:f.vault+"/"+batch.id.uuidString),json=try JSONSerialization.jsonObject(with:root.read("manifest.json"))
        try root.write(JSONSerialization.data(withJSONObject:transform(json,deviceOffset:1000,removeUUID:true)),name:"manifest.json")
        let listed=try await f.engine().recoveryBatches(),preview=try XCTUnwrap(listed.first{$0.id == batch.id})
        let encoded=try XCTUnwrap(try JSONSerialization.jsonObject(with:JSONEncoder().encode(preview))as? [String:Any])
        XCTAssertNotNil(encoded["previewOnlyReason"])
        do{_=try await f.engine().restore(batchID:batch.id);XCTFail("Unproved old volume must not authorize recovery")}catch{}
        XCTAssertFalse(FileManager.default.fileExists(atPath:f.source))
    }
    func testIndependentCacheArchiveReconstructsAfterMountNumberChange()async throws{
        let f=try RecoveryTests.Fixture();defer{try? f.clean()};let engine=f.engine(),path=f.source+"/data",snapshot=try SafeFilesystem.snapshot(path)
        let item=Candidate(id:UUID(),path:path,category:.cache,bundleIdentifier:"org.example.fixture",evidence:[.init(kind:.validatedRule,detail:"owned cache member",verified:true)],rule:CacheDomainRule.name,identity:snapshot.identity,bytes:snapshot.bytes,retentionReason:nil)
        let report=await engine.adoptFixture([item],snapshots:[item.id:snapshot]),plan=try await engine.makePlan(reportID:report.id,selected:[item.id],includeUserData:false),batch=try await engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        let root=try SafeDirectory(path:f.vault+"/"+batch.id.uuidString),objects=try root.existingPrivateChild(batch.objectsDirectory),stored=try SafeFilesystem.snapshot(objects.path+"/"+item.id.uuidString)
        XCTAssertTrue(SafeFilesystem.removeVerified(in:objects,name:item.id.uuidString,identity:stored.identity,contents:stored.tree))
        let json=try JSONSerialization.jsonObject(with:root.read("manifest.json"))
        try root.write(JSONSerialization.data(withJSONObject:transform(json,deviceOffset:1000)),name:"manifest.json")
        let restored=try await f.engine().restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:"; "))
        XCTAssertEqual(try String(contentsOfFile:path,encoding:.utf8),"regenerable")
    }
    func testMatchingMountNumberDoesNotAuthorizeAnUnrelatedVolume()async throws{
        let f=try RecoveryTests.Fixture();defer{try? f.clean()};let engine=f.engine()
        let report=await engine.adoptFixture([f.candidate],snapshots:[f.candidate.id:f.snapshot]),plan=try await engine.makePlan(reportID:report.id,selected:[f.candidate.id],includeUserData:false),batch=try await engine.execute(planID:plan.id)
        let root=try SafeDirectory(path:f.vault+"/"+batch.id.uuidString)
        func replace(_ value:Any)->Any{
            if let array=value as? [Any]{return array.map(replace)}
            guard var object=value as? [String:Any]else{return value}
            for(key,child)in object{object[key]=replace(child)}
            if object["volumeUUID"] != nil{object["volumeUUID"]=second}
            return object
        }
        try root.write(JSONSerialization.data(withJSONObject:replace(JSONSerialization.jsonObject(with:root.read("manifest.json")))),name:"manifest.json")
        let restored=try await f.engine().restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.needsAttention)
        XCTAssertFalse(FileManager.default.fileExists(atPath:f.source))
        XCTAssertTrue(FileManager.default.fileExists(atPath:root.path+"/"+batch.objectsDirectory+"/"+f.candidate.id.uuidString))
    }
    #endif
}
