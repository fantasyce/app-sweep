#if os(macOS)
import Foundation
import CryptoKit
import CFSafety

struct ApplicationTransferReview: Codable, Sendable {
    let id: UUID
    let batchID: UUID
    let itemID: UUID
    let originalPath: String
    let identity: FileIdentity
}
struct ApplicationTransferReceipt: Codable, Sendable {
    let batchID: UUID
    let itemID: UUID
    let state: RecoveryEntry.State
}

/// The user engine owns ordering and its recovery UI. This capability moves only
/// independently verified administrator-owned bundles; it never runs user-data
/// rules as root or accepts caller-supplied filesystem paths.
actor ApplicationTransferService {
    private nonisolated let legacyExecutor = LegacyFilesystemExecutor()
    private nonisolated let filesystemExecutor: (any SerialExecutor)? = {
        if #available(macOS 14.0, *) { return FilesystemExecutor() }
        return nil
    }()
    nonisolated var unownedExecutor: UnownedSerialExecutor {
        if #available(macOS 14.0, *), let filesystemExecutor { return filesystemExecutor.asUnownedSerialExecutor() }
        return legacyExecutor.unownedExecutor
    }
    private struct Record: Codable {
        let version: Int
        let uid: UInt32
        let batchID: UUID
        var entry: RecoveryEntry
        let destinationAncestors: [AncestorIdentity]
    }
    private struct Prepared {
        let review: ApplicationTransferReview
        let snapshot: FileSnapshot
        let record: Record
        let userJournalDigest: Data
        let deadline: TimeInterval
    }
    private struct UserBatch {
        let manifest: RecoveryManifest
        let entry: RecoveryEntry
        let objects: SafeDirectory
        let ancestors: [AncestorIdentity]
        let digest: Data
    }
    private let scope: SystemCleanupScope
    private let failurePoint: FailurePoint?
    private let inspectionProcess: (@Sendable (Int32) throws -> Bool)?
    private var prepared: [UUID: Prepared] = [:]
    init(scope: SystemCleanupScope, failurePoint: FailurePoint? = nil, inspectionProcess: (@Sendable (Int32) throws -> Bool)? = nil) throws {
        try scope.verify()
        guard scope.fixture || (failurePoint == nil && inspectionProcess != nil && SafetyPolicy(systemScope:scope).executionEnabled) else {
            throw SweepError.denied("当前平台尚未验收管理员应用卸载")
        }
        self.scope=scope;self.failurePoint=failurePoint;self.inspectionProcess=inspectionProcess
    }
    func prepare(batchID: UUID, itemID: UUID) throws -> ApplicationTransferReview {
        try scope.verify()
        let lease=try scope.operationLock();defer{as_close(lease)}
        try scope.ensureNoUnfinishedOperations()
        let user=try userBatch(batchID:batchID,itemID:itemID)
        guard user.manifest.status == .inProgress, user.entry.state == .prepared else { throw SweepError.denied("应用移动缺少已持久化的执行意图") }
        let candidate=user.entry.original
        try validateCandidate(candidate)
        let inventory=try scope.applicationInventory()
        guard inventory.issues.isEmpty,
              let application=inventory.applications.first(where:{$0.path == candidate.path && $0.bundleIdentifier == candidate.bundleIdentifier}) else {
            throw SweepError.incomplete("管理员应用的独立归属核对未完成")
        }
        try scope.verifyApplication(application,inventory:inventory.applications,inspectionProcess:inspectionProcess)
        let snapshot=try applicationSnapshot(candidate.path)
        guard snapshot.identity == candidate.identity, try user.entry.matchesContents(snapshot),
              user.entry.originalAncestors == snapshot.ancestors,
              snapshot.identity.sameVolume(as:try user.objects.ownIdentity),
              try !SafeFilesystem.presence(user.objects.path + "/" + itemID.uuidString) else { throw SweepError.stale("应用或恢复目标与已核对计划不一致") }
        let ignores=try CleanupIgnoreStore(home:scope.userHome,ownerUID:scope.requesterUID).read()
        guard ignores.reason(for:candidate) == nil else { throw SweepError.denied("此应用属于保留列表") }
        var entry=RecoveryEntry(id:itemID,original:candidate,state:.prepared,message:nil,
                                contents:snapshot.tree.count > TreeFingerprint.inlineLimit ? [] : snapshot.tree,
                                treeFingerprint:snapshot.tree.count > TreeFingerprint.inlineLimit ? try TreeFingerprint.capture(snapshot.tree) : nil,
                                originalAncestors:snapshot.ancestors)
        entry.applicationLinks=try ApplicationLinkRecovery.capture(snapshot)
        let review=ApplicationTransferReview(id:UUID(),batchID:batchID,itemID:itemID,originalPath:candidate.path,identity:snapshot.identity)
        prepared=prepared.filter{$0.value.deadline > ProcessInfo.processInfo.systemUptime}
        guard prepared.count < 16 else { throw SweepError.denied("管理员应用审查数量超限") }
        prepared[review.id]=Prepared(review:review,snapshot:snapshot,
            record:Record(version:1,uid:scope.requesterUID,batchID:batchID,entry:entry,destinationAncestors:user.ancestors),
            userJournalDigest:user.digest,deadline:ProcessInfo.processInfo.systemUptime + 60)
        return review
    }
    func commit(reviewID: UUID) throws -> ApplicationTransferReceipt {
        guard let review=prepared.removeValue(forKey:reviewID), review.deadline > ProcessInfo.processInfo.systemUptime else { throw SweepError.denied("管理员应用审查已使用或过期") }
        try scope.verify()
        let lease=try scope.operationLock();defer{as_close(lease)}
        try scope.ensureNoUnfinishedOperations()
        var record=review.record
        let user=try userBatch(batchID:record.batchID,itemID:record.entry.id)
        guard user.digest == review.userJournalDigest, user.ancestors == record.destinationAncestors else { throw SweepError.stale("应用执行记录或恢复目录已改变") }
        try validateCandidate(record.entry.original)
        let inventory=try scope.applicationInventory()
        guard inventory.issues.isEmpty,let application=inventory.applications.first(where:{$0.path == record.entry.original.path && $0.bundleIdentifier == record.entry.original.bundleIdentifier}) else { throw SweepError.incomplete("执行前应用归属复查未完成") }
        try scope.verifyApplication(application,inventory:inventory.applications,inspectionProcess:inspectionProcess)
        try validateBundle(review.snapshot)
        try stopped(record.entry.original,storedPath:review.snapshot.path)
        try SafeFilesystem.verify(review.snapshot)
        let journal=try ledger(batchID:record.batchID,create:true)
        let name=record.entry.id.uuidString + ".json"
        guard try !SafeFilesystem.presence(journal.path + "/" + name) else { throw SweepError.denied("已有管理员应用记录，不能重复执行") }
        try persist(record,in:journal) // Root-owned authority is durable before rename.
        try SafeFilesystem.move(review.snapshot,into:user.objects,name:record.entry.id.uuidString,targetAncestors:record.destinationAncestors)
        if failurePoint == .interruptAfterMove { throw SweepError.filesystem("注入：管理员应用移动后中断") }
        record.entry.isolatedIdentity=try user.objects.identity(record.entry.id.uuidString)
        record.entry.state = .moved;try persist(record,in:journal)
        return receipt(record)
    }
    func restore(batchID: UUID, itemID: UUID) throws -> ApplicationTransferReceipt {
        try scope.verify()
        let lease=try scope.operationLock();defer{as_close(lease)}
        let journal=try ledger(batchID:batchID,create:false)
        var record=try readRecord(journal,batchID:batchID,itemID:itemID)
        guard ![.purgePrepared,.purged].contains(record.entry.state) else { throw SweepError.denied("已开始永久清空的应用不能推断为可恢复") }
        let user=try checkedUser(record)
        let stored=user.objects.path + "/" + itemID.uuidString
        let original=record.entry.original.path
        if try SafeFilesystem.presence(stored) {
            guard try !SafeFilesystem.presence(original) else { throw SweepError.denied("原路径已存在，不覆盖；请先处理冲突") }
            let snapshot=try verifiedStored(record,path:stored)
            try stopped(record.entry.original,storedPath:stored)
            let url=URL(fileURLWithPath:original), parent=try SafeDirectory(path:url.deletingLastPathComponent().path)
            guard let ancestors=record.entry.originalAncestors,
                  try SafeFilesystem.ancestors(of:parent.path) == ancestors else { throw SweepError.stale("原应用安装目录身份已改变") }
            record.entry.state = .restorePrepared;try persist(record,in:journal)
            try SafeFilesystem.move(snapshot,into:parent,name:url.lastPathComponent,targetAncestors:ancestors)
        } else {
            // Reconcile a lost reply only against the sealed original object.
            _=try verifiedStored(record,path:original)
        }
        record.entry.state = .restored;try persist(record,in:journal)
        return receipt(record)
    }
    func purge(batchID: UUID, itemID: UUID, confirmation: String) throws -> ApplicationTransferReceipt {
        guard confirmation == "永久清空 " + batchID.uuidString else { throw SweepError.denied("管理员应用永久清空需要准确的批次确认") }
        try scope.verify()
        let lease=try scope.operationLock();defer{as_close(lease)}
        let journal=try ledger(batchID:batchID,create:false)
        var record=try readRecord(journal,batchID:batchID,itemID:itemID)
        guard record.entry.state == .moved else { throw SweepError.denied("管理员应用尚未完成隔离，不能永久清空") }
        let user=try checkedUser(record)
        guard user.manifest.status == .purging, user.entry.state == .purgePrepared else { throw SweepError.denied("缺少用户的永久清空记录") }
        let snapshot=try verifiedStored(record,path:user.objects.path + "/" + itemID.uuidString)
        // Alias churn may permit restoration, never irreversible deletion. The
        // privileged boundary independently enforces the sealed strict snapshot.
        guard snapshot.identity == record.entry.isolatedIdentity,try record.entry.matchesContents(snapshot) else {
            throw SweepError.stale("应用隔离后的身份或硬链接已改变，不能永久清空")
        }
        try stopped(record.entry.original,storedPath:snapshot.path)
        record.entry.state = .purgePrepared;try persist(record,in:journal)
        guard SafeFilesystem.removeVerified(in:user.objects,name:itemID.uuidString,identity:snapshot.identity,contents:snapshot.tree,allowApplicationHardLinks:true) else {
            throw SweepError.filesystem("管理员应用永久清空未完成，停止处理")
        }
        record.entry.state = .purged;try persist(record,in:journal)
        return receipt(record)
    }
    private func validateCandidate(_ item: Candidate) throws {
        let rules=[SelectedApplicationRule.name,ChosenApplicationRule.name,ChosenApplicationRule.largeName]
        guard item.category == .application,rules.contains(item.rule),item.path == item.applicationPath,
              item.identity?.owner == scope.ownerUID,item.identity?.isDirectory == true,
              item.bundleIdentifier.map(SystemCleanupScope.validIdentifier) == true,
              SafetyPolicy.contains(scope.applicationsRoot,item.path),item.path != scope.applicationsRoot,
              SelectedApplicationRule.matches(path:item.path,policy:SafetyPolicy(home:scope.userHome,acceptedPlatform:false)),
              item.component == nil,item.systemHelper == nil else { throw SweepError.denied("管理员能力仅允许已核对的第三方完整安装应用") }
    }
    private func applicationSnapshot(_ path:String) throws -> FileSnapshot {
        try SafeFilesystem.snapshot(path,allowInternalLinks:true,purpose:.application,allowApplicationHardLinks:true)
    }
    private func validateBundle(_ snapshot:FileSnapshot) throws {
        for node in [TreeEntry(relative:"",identity:snapshot.identity)] + snapshot.tree {
            guard node.identity.owner == scope.ownerUID else { throw SweepError.denied("管理员应用包含其他所有者，保留") }
            if !node.identity.isLink {
                let path=node.relative.isEmpty ? snapshot.path : snapshot.path + "/" + node.relative
                try scope.verifyUnsharedNode(path:path,identity:node.identity)
            }
        }
        try SafeFilesystem.verify(snapshot)
    }
    private func stopped(_ item:Candidate,storedPath:String) throws {
        guard let identifier=item.bundleIdentifier else { throw SweepError.denied("应用标识缺失") }
        try ChosenApplicationRule.verifyStored(path:storedPath,identifier:identifier,requireNoInstalledHelpers:true)
        guard AppInspector.signatureMatches(path:storedPath,identifier:identifier) else { throw SweepError.denied("管理员应用签名已改变") }
        for path in Set([item.path,storedPath]) {
            try ActivityInspector.ensureSystemServicesStopped(identifiers:[identifier],applicationPath:path)
            try ActivityInspector.ensureStopped(bundleID:identifier,applicationPath:path,userID:scope.requesterUID,inspectionProcess:inspectionProcess)
        }
        try BusyInspector.ensureUnused(applicationSnapshot(storedPath))
    }
    private func userBatch(batchID:UUID,itemID:UUID) throws -> UserBatch {
        try scope.verify()
        let base=scope.userHome + "/Library/Application Support/App Sweep"
        for path in [scope.userHome + "/Library",scope.userHome + "/Library/Application Support",base] {
            let directory=try SafeDirectory(path:path)
            guard as_unshared_node_descriptor(directory.fd,scope.requesterUID) == 1 else { throw SweepError.denied("用户恢复目录的归属或 ACL 未确认") }
        }
        let batchPath=base + "/Recovery/" + batchID.uuidString
        for path in [base + "/Recovery",batchPath,batchPath + "/objects.noindex"] {
            let directory=try SafeDirectory(path:path),identity=try directory.ownIdentity
            guard identity.mode & 0o077 == 0,as_unshared_node_descriptor(directory.fd,scope.requesterUID) == 1 else { throw SweepError.denied("恢复批次必须为请求用户私有") }
        }
        let path=batchPath + "/manifest.json",identity=try SafeDirectory(path:batchPath).identity("manifest.json")
        guard identity.owner == scope.requesterUID,identity.mode & 0o077 == 0 else { throw SweepError.denied("用户恢复日志权限未确认") }
        let data=try SafeFilesystem.readMetadata(path,maximumBytes:16*1024*1024)
        let decoder=JSONDecoder();decoder.dateDecodingStrategy = .iso8601
        let manifest=try decoder.decode(RecoveryManifest.self,from:data)
        guard manifest.schemaVersion == 5,manifest.id == batchID,manifest.requestingUserID == nil,
              manifest.entries.count <= 1000,Set(manifest.entries.map(\.id)).count == manifest.entries.count,
              let entry=manifest.entries.first(where:{$0.id == itemID}) else { throw SweepError.denied("用户恢复记录不能作为应用执行授权") }
        let objects=try SafeDirectory(path:batchPath + "/objects.noindex")
        return UserBatch(manifest:manifest,entry:entry,objects:objects,ancestors:try SafeFilesystem.ancestors(of:objects.path),digest:Data(SHA256.hash(data:data)))
    }
    private func checkedUser(_ record:Record) throws -> UserBatch {
        let user=try userBatch(batchID:record.batchID,itemID:record.entry.id)
        guard user.ancestors == record.destinationAncestors,user.entry.original == record.entry.original else { throw SweepError.stale("用户记录或恢复位置与管理员原始记录不一致") }
        return user
    }
    private func ledger(batchID:UUID,create:Bool) throws -> SafeDirectory {
        try scope.verify()
        let parent=try SafeDirectory(path:scope.fixture ? scope.libraryRoot : scope.libraryRoot + "/Application Support/App Sweep")
        let base=create ? try parent.privateChild("ApplicationTransfers.noindex") : try parent.existingPrivateChild("ApplicationTransfers.noindex")
        let user=create ? try base.privateChild(String(scope.requesterUID)) : try base.existingPrivateChild(String(scope.requesterUID))
        return create ? try user.privateChild(batchID.uuidString) : try user.existingPrivateChild(batchID.uuidString)
    }
    private func persist(_ record:Record,in journal:SafeDirectory) throws {
        let encoder=JSONEncoder();encoder.dateEncodingStrategy = .iso8601
        try journal.write(encoder.encode(record),name:record.entry.id.uuidString + ".json")
    }
    private func readRecord(_ journal:SafeDirectory,batchID:UUID,itemID:UUID) throws -> Record {
        let decoder=JSONDecoder();decoder.dateDecodingStrategy = .iso8601
        let record=try decoder.decode(Record.self,from:journal.read(itemID.uuidString + ".json"))
        guard record.version == 1,record.uid == scope.requesterUID,record.batchID == batchID,record.entry.id == itemID else { throw SweepError.denied("管理员恢复记录身份不一致") }
        try validateCandidate(record.entry.original)
        return record
    }
    private func verifiedStored(_ record:Record,path:String) throws -> FileSnapshot {
        let snapshot=try applicationSnapshot(path)
        guard let identity=record.entry.isolatedIdentity ?? record.entry.original.identity,
              snapshot.identity.sameObject(as:identity),try record.entry.matchesRestorationContents(snapshot) else { throw SweepError.stale("管理员应用与原始恢复记录不一致") }
        try validateBundle(snapshot)
        return snapshot
    }
    private func receipt(_ record:Record) -> ApplicationTransferReceipt {
        .init(batchID:record.batchID,itemID:record.entry.id,state:record.entry.state)
    }
}
#endif
