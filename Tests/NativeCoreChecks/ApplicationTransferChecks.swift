import Foundation
import Darwin
@testable import AppSweepCore

@MainActor private struct TransferFixture {
    let fixture: OwnedFixture
    let scope: SystemCleanupScope
    let batch: SafeDirectory
    let objects: SafeDirectory
    var manifest: RecoveryManifest
    let snapshot: FileSnapshot
    var entryID: UUID { manifest.entries[0].id }
    init() throws {
        fixture = try OwnedFixture()
        try fm.createDirectory(atPath: fixture.home + "/MachineLibrary", withIntermediateDirectories: false, attributes: [.posixPermissions:0o700])
        scope = try .fixture(libraryRoot:fixture.home + "/MachineLibrary",applicationsRoot:fixture.home + "/Applications",userHome:fixture.home,requesterUID:getuid())
        let support = try SafeDirectory(path:fixture.home + "/Library/Application Support").privateChild("App Sweep")
        let vault = try support.privateChild("Recovery"), id = UUID()
        batch = try vault.privateChild(id.uuidString)
        objects = try batch.privateChild("objects.noindex")
        _=try BoundedProcess.run("/usr/bin/xattr",arguments:["-w","org.appsweep.acceptance","retained-metadata",fixture.app],timeout:5)
        snapshot = try SafeFilesystem.snapshot(fixture.app,allowInternalLinks:true,purpose:.application,allowApplicationHardLinks:true)
        let item = Candidate(id:UUID(),path:fixture.app,category:.application,bundleIdentifier:fixture.identifier,applicationPath:fixture.app,evidence:[.init(kind:.validatedRule,detail:"owned transfer fixture",verified:true)],rule:SelectedApplicationRule.name,identity:snapshot.identity,bytes:snapshot.bytes,retentionReason:nil,executionAllowed:true)
        manifest = RecoveryManifest(schemaVersion:5,id:id,createdAt:Date(),status:.inProgress,entries:[RecoveryEntry(id:item.id,original:item,state:.prepared,message:nil,contents:snapshot.tree,originalAncestors:snapshot.ancestors)],issue:nil)
        try save()
    }
    func save() throws {
        let encoder=JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        try batch.write(encoder.encode(manifest),name:"manifest.json")
    }
    mutating func state(_ state:RecoveryEntry.State, status:RecoveryManifest.Status) throws {
        manifest.entries[0].state=state;manifest.status=status;try save()
    }
    func assertOriginal() throws {
        let actual=try SafeFilesystem.snapshot(fixture.app,allowInternalLinks:true,purpose:.application,allowApplicationHardLinks:true)
        try check(actual.identity.sameObject(as:snapshot.identity) && actual.tree == snapshot.tree,"Application identity/contents must be restored without changing ownership")
        let attribute=try BoundedProcess.run("/usr/bin/xattr",arguments:["-p","org.appsweep.acceptance",fixture.app],timeout:5)
        try check(attribute.contains("retained-metadata"),"Application extended attribute was changed")
    }
}

@MainActor private func transferReject(_ label:String,_ work:() async throws -> Void) async throws {
    do { try await work() } catch { print("PASS " + label);return }
    throw CheckFailure(label)
}

@MainActor func applicationTransferChecks() async throws {
    do {
        var f=try TransferFixture();defer{try? f.fixture.finish()}
        let client=Process();client.executableURL=URL(fileURLWithPath:"/bin/sh")
        client.arguments=["-c","while :; do sleep 1; done",f.fixture.app]
        try client.run();defer{if client.isRunning{client.terminate();client.waitUntilExit()}}
        let pid=client.processIdentifier
        let processList=try BoundedProcess.run("/bin/ps",arguments:["-ww","-axo","pid=,command="],timeout:3)
        try check(ActivityInspector.processes(processList,ownPID:getpid()).contains(where:{$0.pid == pid && $0.command.contains(f.fixture.app)}),"Owned inspection process must expose the application operand")
        try ActivityInspector.ensureStopped(bundleID:f.fixture.identifier,applicationPath:f.fixture.app,inspectionProcess:{$0 == pid})
        try reject("untrusted process arguments still block application activity") {
            try ActivityInspector.ensureStopped(bundleID:f.fixture.identifier,applicationPath:f.fixture.app)
        }
        try reject("expired inspection-client authentication blocks application activity") {
            try ActivityInspector.ensureStopped(bundleID:f.fixture.identifier,applicationPath:f.fixture.app,inspectionProcess:{_ in throw SweepError.denied("expired client")})
        }
        try check(client.isRunning,"Activity inspection must not terminate the client")
        print("PASS only freshly authenticated inspection-client operands are excluded from activity matching")
        let service=try ApplicationTransferService(scope:f.scope,inspectionProcess:{$0 == pid})
        let initial=try await service.prepare(batchID:f.manifest.id,itemID:f.entryID)
        let target=Process();target.executableURL=URL(fileURLWithPath:f.fixture.binary);target.arguments=["30"]
        try target.run();defer{if target.isRunning{target.terminate();target.waitUntilExit()}}
        try await transferReject("authenticated inspection cannot hide a target started after review") { _=try await service.commit(reviewID:initial.id) }
        try check(target.isRunning,"Transfer must not stop the target application")
        target.terminate();target.waitUntilExit()
        let reviewed=try await service.prepare(batchID:f.manifest.id,itemID:f.entryID)
        _=try await service.commit(reviewID:reviewed.id)
        try check(!fm.fileExists(atPath:f.fixture.app),"Client operand must not block the actual transfer")
        try f.state(.restorePrepared,status:.needsAttention)
        _=try await service.restore(batchID:f.manifest.id,itemID:f.entryID)
        try f.assertOriginal()
        print("PASS client-operand transfer and restoration preserve target running protection")
    }
    do {
        let f=try TransferFixture();defer{try? f.fixture.finish()}
        var item=f.manifest.entries[0].original
        var json=try JSONSerialization.jsonObject(with:JSONEncoder().encode(item)) as! [String:Any]
        var identity=json["identity"] as! [String:Any];identity["owner"]=0;json["identity"]=identity
        item=try JSONDecoder().decode(Candidate.self,from:JSONSerialization.data(withJSONObject:json))
        try check(!ApplicationTransferClient.required(for:item),"Writable administrator-owned app must retain ordinary execution")
        try fm.setAttributes([.posixPermissions:0o500],ofItemAtPath:f.fixture.app)
        try check(ApplicationTransferClient.required(for:item),"Read-only administrator-owned app needs the bounded service")
        try fm.setAttributes([.posixPermissions:0o700],ofItemAtPath:f.fixture.app)
        try fm.moveItem(atPath:f.fixture.app,toPath:f.objects.path + "/saved")
        try check(!ApplicationTransferClient.required(for:item,sourcePath:f.objects.path + "/saved"),"Recovery routing must inspect the stored bundle, not the missing original")
        let originalParent=URL(fileURLWithPath:f.fixture.app).deletingLastPathComponent().path
        try check(fm.contentsOfDirectory(atPath:originalParent).isEmpty,"Owned original parent should be empty")
        try fm.removeItem(atPath:originalParent)
        try check(!ApplicationTransferClient.required(for:item,sourcePath:f.objects.path + "/saved"),"Purge routing must not require the absent original installation directory")
        try check(ApplicationTransferClient.required(for:item,sourcePath:f.objects.path + "/saved",restoring:true),"Restoration must still account for its original destination")
        print("PASS writable administrator-owned apps retain ordinary execution and recovery")
    }
    let request=PrivilegedRequest(protocolVersion:1,id:UUID(),nonce:Data(repeating:42,count:32),sequence:1,action:.prepareApplicationTransfer(batchID:UUID(),itemID:UUID()))
    try check(PrivilegedFrame.decode(PrivilegedFrame.encode(request)) == request,"UUID-only transfer request should round-trip")
    do {
        var f=try TransferFixture();defer{try? f.fixture.finish()}
        try f.state(.prepared,status:.isolated)
        let peer=AuthenticatedLocalPeer(uid:getuid(),pid:getpid(),auditToken:Data(repeating:9,count:32))
        let nonce=Data(repeating:8,count:32)
        let session=try SystemServiceSession.fixture(scope:f.scope,peer:peer,nonce:nonce)
        let request=PrivilegedRequest(protocolVersion:1,id:UUID(),nonce:nonce,sequence:1,action:.prepareApplicationTransfer(batchID:f.manifest.id,itemID:f.entryID))
        let result:SystemServiceResult
        do { result=try await session.acceptFixture(request,peer:peer) }
        catch { throw CheckFailure("Authenticated transfer rejection must return its reason instead of dropping the connection: " + error.localizedDescription) }
        let reply=try SystemServiceReply.prepare(result,for:request)
        var reader=try SystemServiceReply.Reader(request:request),decoded:SystemServiceResult?
        for index in 0..<reply.partCount { decoded=try reader.append(reply.frame(at:index)) }
        guard let decoded else { throw CheckFailure("Transfer rejection reply was incomplete") }
        let encoded=try JSONEncoder().encode(decoded)
        try check(String(decoding:encoded,as:UTF8.self).contains("应用移动缺少已持久化的执行意图"),"Transfer rejection must preserve its exact cause")
        try f.assertOriginal()
        print("PASS authenticated transfer rejection returns an intact bounded reason without mutation")
    }
    do {
        var f=try TransferFixture();defer{try? f.fixture.finish()}
        let service=try ApplicationTransferService(scope:f.scope)
        let review=try await service.prepare(batchID:f.manifest.id,itemID:f.entryID)
        try check(review.originalPath == f.fixture.app && review.identity == f.snapshot.identity,"Review must bind independently inspected source")
        _=try await service.commit(reviewID:review.id)
        try check(!fm.fileExists(atPath:f.fixture.app) && fm.fileExists(atPath:f.objects.path + "/" + f.entryID.uuidString),"Application must be isolated in existing user batch")
        try await transferReject("privileged review cannot be replayed"){_=try await service.commit(reviewID:review.id)}
        let originalJournal=try f.batch.read("manifest.json")
        var forged=try JSONSerialization.jsonObject(with:originalJournal) as! [String:Any]
        var entries=forged["entries"] as! [[String:Any]], candidate=entries[0]["original"] as! [String:Any]
        candidate["path"]=f.fixture.home + "/outside.app";candidate["applicationPath"]=candidate["path"]
        entries[0]["original"]=candidate;forged["entries"]=entries
        try f.batch.write(JSONSerialization.data(withJSONObject:forged),name:"manifest.json")
        try await transferReject("forged user metadata cannot redirect privileged recovery"){_=try await service.restore(batchID:f.manifest.id,itemID:f.entryID)}
        try check(!fm.fileExists(atPath:f.fixture.home + "/outside.app"),"Forged target was written")
        try f.batch.write(originalJournal,name:"manifest.json")
        try f.state(.restorePrepared,status:.needsAttention)
        try fm.createDirectory(atPath:f.fixture.app,withIntermediateDirectories:false)
        try Data("new occupant".utf8).write(to:URL(fileURLWithPath:f.fixture.app + "/sentinel"))
        let fresh=try ApplicationTransferService(scope:f.scope)
        try await transferReject("restore never overwrites a new original path"){_=try await fresh.restore(batchID:f.manifest.id,itemID:f.entryID)}
        try check(String(contentsOfFile:f.fixture.app + "/sentinel",encoding:.utf8) == "new occupant","Conflict contents changed")
        try fm.moveItem(atPath:f.fixture.app,toPath:f.fixture.home + "/preserved-conflict")
        _=try await fresh.restore(batchID:f.manifest.id,itemID:f.entryID)
        try f.assertOriginal()
        print("PASS fresh-service restoration preserves application inode, contents and ownership")
    }
    do {
        var f=try TransferFixture();defer{try? f.fixture.finish()}
        let service=try ApplicationTransferService(scope:f.scope)
        let review=try await service.prepare(batchID:f.manifest.id,itemID:f.entryID)
        try f.state(.conflict,status:.needsAttention)
        try await transferReject("changed user journal revokes reviewed transfer"){_=try await service.commit(reviewID:review.id)}
        try f.assertOriginal()
    }
    do {
        let f=try TransferFixture();defer{try? f.fixture.finish()}
        let service=try ApplicationTransferService(scope:f.scope)
        let review=try await service.prepare(batchID:f.manifest.id,itemID:f.entryID)
        try fm.moveItem(atPath:f.objects.path,toPath:f.batch.path + "/original-objects")
        try fm.createDirectory(atPath:f.fixture.home + "/outside",withIntermediateDirectories:false)
        try fm.createSymbolicLink(atPath:f.objects.path,withDestinationPath:f.fixture.home + "/outside")
        try await transferReject("recovery-directory symlink substitution blocks transfer"){_=try await service.commit(reviewID:review.id)}
        try f.assertOriginal()
        try check(fm.contentsOfDirectory(atPath:f.fixture.home + "/outside").isEmpty,"Outside path was written")
    }
    do {
        var f=try TransferFixture();defer{try? f.fixture.finish()}
        let service=try ApplicationTransferService(scope:f.scope,failurePoint:.interruptAfterMove)
        let review=try await service.prepare(batchID:f.manifest.id,itemID:f.entryID)
        try await transferReject("interruption after root move retains recoverable intent"){_=try await service.commit(reviewID:review.id)}
        try check(!fm.fileExists(atPath:f.fixture.app),"Fault injection must follow actual move")
        try f.state(.restorePrepared,status:.needsAttention)
        _=try await ApplicationTransferService(scope:f.scope).restore(batchID:f.manifest.id,itemID:f.entryID)
        try f.assertOriginal()
        print("PASS durable root intent recovers a move with no success reply")
    }
    do {
        var f=try TransferFixture();defer{try? f.fixture.finish()}
        let service=try ApplicationTransferService(scope:f.scope)
        let review=try await service.prepare(batchID:f.manifest.id,itemID:f.entryID)
        _=try await service.commit(reviewID:review.id)
        try f.state(.purgePrepared,status:.purging)
        try await transferReject("application purge requires exact batch confirmation"){_=try await service.purge(batchID:f.manifest.id,itemID:f.entryID,confirmation:"yes")}
        _=try await service.purge(batchID:f.manifest.id,itemID:f.entryID,confirmation:"永久清空 " + f.manifest.id.uuidString)
        try check(!fm.fileExists(atPath:f.objects.path + "/" + f.entryID.uuidString),"Exact isolated bundle should be removed")
        print("PASS explicitly confirmed purge removes only the registered isolated application")
    }
    do {
        let f=try TransferFixture();defer{try? f.fixture.finish()}
        let scope=try SystemCleanupScope.fixture(libraryRoot:f.scope.libraryRoot,applicationsRoot:f.scope.applicationsRoot,userHome:f.fixture.home,requesterUID:getuid()+1)
        let service=try ApplicationTransferService(scope:scope)
        try await transferReject("another requester cannot use the user's recovery directory"){_=try await service.prepare(batchID:f.manifest.id,itemID:f.entryID)}
        try f.assertOriginal()
    }
    do {
        var f=try TransferFixture();defer{try? f.fixture.finish()}
        let service=try ApplicationTransferService(scope:f.scope)
        let review=try await service.prepare(batchID:f.manifest.id,itemID:f.entryID)
        _=try await service.commit(reviewID:review.id)
        let saved=f.objects.path + "/" + f.entryID.uuidString
        let external=f.fixture.home + "/preserved-linked-resource"
        try fm.linkItem(atPath:saved + "/Contents/Resources/asset",toPath:external)
        let bytes=try Data(contentsOf:URL(fileURLWithPath:external))
        try f.state(.purgePrepared,status:.purging)
        try await transferReject("privileged purge rejects restoration-only hard-link relaxation"){_=try await service.purge(batchID:f.manifest.id,itemID:f.entryID,confirmation:"永久清空 " + f.manifest.id.uuidString)}
        try check(fm.fileExists(atPath:saved) && Data(contentsOf:URL(fileURLWithPath:external)) == bytes,"Rejected purge must preserve both names")
        try f.state(.restorePrepared,status:.needsAttention)
        _=try await service.restore(batchID:f.manifest.id,itemID:f.entryID)
        try check(fm.fileExists(atPath:f.fixture.app) && Data(contentsOf:URL(fileURLWithPath:external)) == bytes,"Restoration must retain verified external alias")
        print("PASS strict privileged purge still permits safe linked application restoration")
    }
    do {
        let f=try TransferFixture();defer{try? f.fixture.finish()}
        let service=try ApplicationTransferService(scope:f.scope)
        let review=try await service.prepare(batchID:f.manifest.id,itemID:f.entryID)
        try fm.moveItem(atPath:f.fixture.app,toPath:f.fixture.home + "/preserved-original.fixture")
        try fm.createDirectory(atPath:f.fixture.app,withIntermediateDirectories:false)
        try Data("replacement".utf8).write(to:URL(fileURLWithPath:f.fixture.app + "/sentinel"))
        try await transferReject("replaced application blocks a previously reviewed transfer"){_=try await service.commit(reviewID:review.id)}
        try check(String(contentsOfFile:f.fixture.app + "/sentinel",encoding:.utf8) == "replacement","Replacement was modified")
        try check(fm.contentsOfDirectory(atPath:f.objects.path).isEmpty,"Replacement was isolated")
    }
    do {
        let f=try TransferFixture();defer{try? f.fixture.finish()}
        let process=Process();process.executableURL=URL(fileURLWithPath:f.fixture.binary);process.arguments=["60"]
        try process.run();defer{if process.isRunning{process.terminate()};process.waitUntilExit()}
        let service=try ApplicationTransferService(scope:f.scope)
        try await transferReject("administrator transfer refuses a running application"){_=try await service.prepare(batchID:f.manifest.id,itemID:f.entryID)}
        try f.assertOriginal()
    }
}
