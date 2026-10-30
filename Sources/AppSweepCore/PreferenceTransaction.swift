#if os(macOS)
import Foundation
import CryptoKit
import CFSafety

/// The receipt binds an independent raw backup to the reviewed domain, original
/// file and app. JSON alone is never passed to a system preferences command.
enum PreferenceTransaction {
    static let format = "preference-domain-backup-v1"
    private struct Receipt: Codable {
        let schemaVersion: Int
        let id: UUID
        let path: String
        let identifier: String
        let applicationPath: String
        let identity: FileIdentity
        let ancestors: [AncestorIdentity]
        let rawDigest: String
        let valuesDigest: String
    }
    struct Prepared {
        let original: PreferenceDomainService.State
        let receipt: Data
        var digest: String { hash(receipt) }
        var requiredBytes: UInt64 { UInt64(original.bytes.count + receipt.count) + 128*1024 }
    }
    static func prepare(_ snapshot: FileSnapshot, candidate: Candidate, home: String) throws -> Prepared {
        guard candidate.rule == PreferenceRecoveryRecord.rule, candidate.category == .userData,
              let identifier=candidate.bundleIdentifier, let application=candidate.applicationPath else { throw SweepError.denied("偏好事务缺少应用归属") }
        let state=try PreferenceDomainService.inspect(path:candidate.path,home:home,identifier:identifier)
        guard let digest=snapshot.contentDigest, state.inspection.digest == digest,
              state.inspection.snapshot.identity.sameObject(as:snapshot.identity), state.inspection.snapshot.ancestors == snapshot.ancestors else { throw SweepError.stale("偏好扫描身份或完整内容已改变") }
        let receipt=Receipt(schemaVersion:1,id:candidate.id,path:candidate.path,identifier:identifier,applicationPath:application,identity:snapshot.identity,ancestors:snapshot.ancestors,rawDigest:state.inspection.digest,valuesDigest:state.valuesDigest)
        let encoder=PropertyListEncoder();encoder.outputFormat = .binary
        let encoded=try encoder.encode(receipt)
        guard encoded.count <= 128*1024 else { throw SweepError.incomplete("偏好恢复元数据超过已验证容量，尚未开始处理") }
        return Prepared(original:state,receipt:encoded)
    }
    static func create(_ prepared: Prepared, candidate: Candidate, in backups: SafeDirectory) throws -> FileSnapshot {
        guard backups.availableBytes > CacheBackup.freeSpaceReserve + prepared.requiredBytes,
              try !SafeFilesystem.presence(backups.path + "/" + candidate.id.uuidString) else { throw SweepError.denied("偏好备份空间不足或目标已存在") }
        let current=try PreferenceDomainService.refreshed(prepared.original)
        let directory=try backups.privateChild(candidate.id.uuidString)
        guard try FileManager.default.contentsOfDirectory(atPath:directory.path).isEmpty else { throw SweepError.stale("偏好备份目录不是独占空目录") }
        let copied=try VerifiedFileStream.copy(current.inspection.snapshot,into:directory,name:candidate.id.uuidString)
        guard copied.digest == prepared.original.inspection.digest else { throw SweepError.stale("偏好独立副本摘要不一致") }
        try directory.write(prepared.receipt,name:"receipt.plist")
        return try SafeFilesystem.snapshot(directory.path)
    }
    private static func read(_ entry: RecoveryEntry, in backups: SafeDirectory, home: String) throws -> (PreferenceDomainService.State,FileSnapshot,String) {
        try validateRecord(entry,home:home)
        let directory=try backups.existingPrivateChild(entry.id.uuidString)
        let snapshot=try SafeFilesystem.snapshot(directory.path)
        guard entry.backupIdentity.map({ $0 == snapshot.identity }) ?? (entry.backupPending == true),
              snapshot.tree.count == 2, Set(snapshot.tree.map(\.relative)) == [entry.id.uuidString,"receipt.plist"],
              snapshot.tree.allSatisfy({ $0.identity.owner == as_current_uid() && $0.identity.mode & 0o177777 == 0o100600 && $0.identity.links == 1 }),
              let digest=entry.backupDigest else { throw SweepError.denied("偏好备份结构或身份未确认") }
        let data=try directory.read("receipt.plist")
        guard hash(data) == digest else { throw SweepError.stale("偏好独立记录已改变") }
        let receipt=try PropertyListDecoder().decode(Receipt.self,from:data)
        guard receipt.schemaVersion == 1, receipt.id == entry.id, receipt.path == entry.original.path,
              receipt.identifier == entry.original.bundleIdentifier, receipt.applicationPath == entry.original.applicationPath,
              receipt.identity == entry.original.identity, receipt.ancestors == entry.originalAncestors,
              entry.preference?.originalRawDigest.map({ $0 == receipt.rawDigest }) ?? true,
              receipt.valuesDigest == entry.preference?.originalValuesDigest else { throw SweepError.denied("偏好备份与恢复目标不一致") }
        let payload=directory.path + "/" + entry.id.uuidString
        let bytes=try SafeFilesystem.readMetadata(payload,maximumBytes:8*1024*1024)
        let originalSnapshot=FileSnapshot(path:receipt.path,identity:receipt.identity,ancestors:receipt.ancestors,tree:[],bytes:receipt.identity.size,allowInternalLinks:false)
        let state=try PreferenceDomainService.recoveryOriginal(bytes:bytes,snapshot:originalSnapshot,home:home,identifier:receipt.identifier,rawDigest:receipt.rawDigest,expectedValues:receipt.valuesDigest)
        try SafeFilesystem.verify(snapshot)
        return (state,snapshot,payload)
    }
    static func verifiedSnapshot(_ entry: RecoveryEntry, in backups: SafeDirectory, home: String) throws -> FileSnapshot { try read(entry,in:backups,home:home).1 }
    struct RecoveryInput {
        let original: PreferenceDomainService.State
        let current: PreferenceDomainService.State
        let backupPath: String
        let alreadyRestored: Bool
    }
    static func recoveryInput(_ entry: RecoveryEntry, in backups: SafeDirectory, home: String) throws -> RecoveryInput {
        let (original,_,payload)=try read(entry,in:backups,home:home)
        let current=try PreferenceDomainService.inspect(path:entry.original.path,home:home,identifier:original.identifier)
        guard current.inspection.snapshot.ancestors == original.inspection.snapshot.ancestors else { throw SweepError.stale("偏好恢复目标祖先已改变") }
        if current.valuesDigest == original.valuesDigest {
            return RecoveryInput(original:original,current:current,backupPath:payload,alreadyRestored:true)
        }
        let empty=try PropertyListSerialization.data(fromPropertyList:[String:String](),format:.binary,options:0)
        guard current.valuesDigest == (try PreferenceDomainService.valuesDigest(empty)),
              let record=entry.preference, record.phase != .prepared else { throw SweepError.denied("应用已产生新设置或未确认的偏好状态，保留且不覆盖") }
        if let identity=record.emptyIdentity, !current.inspection.snapshot.identity.sameObject(as:identity) { throw SweepError.stale("清除后的空偏好文件已改变，不覆盖") }
        return RecoveryInput(original:original,current:current,backupPath:payload,alreadyRestored:false)
    }
    static func validateRecord(_ entry: RecoveryEntry, home: String) throws {
        guard entry.original.rule == PreferenceRecoveryRecord.rule, entry.original.category == .userData,
              let id=entry.original.bundleIdentifier, let app=entry.original.applicationPath,
              AppInspector.validIdentifier(id), !id.lowercased().hasPrefix("com.apple."),
              entry.original.path == home + "/Library/Preferences/" + id + ".plist",
              SelectedApplicationRule.matches(path:app,policy:SafetyPolicy(home:home,acceptedPlatform:false)),
              let identity=entry.original.identity, identity.owner == as_current_uid(), identity.links == 1,
              identity.mode & 0o170000 == 0o100000, identity.size >= 0, identity.size <= 8*1024*1024,
              entry.isolatedIdentity == nil, entry.contents.isEmpty, entry.treeFingerprint == nil,
              let ancestors=entry.originalAncestors, !ancestors.isEmpty,
              ancestors.last?.path == home + "/Library/Preferences",
              let record=entry.preference, validDigest(record.originalValuesDigest),
              record.originalRawDigest.map(validDigest) ?? true,
              entry.reconstructionPending != true, entry.reconstructedContents == nil else { throw SweepError.denied("偏好恢复记录结构或归属无效") }
        for current in [record.emptyIdentity,record.restoredIdentity].compactMap({$0}) {
            guard current.sameVolume(as:identity), current.owner == identity.owner, current.links == 1,
                  current.mode & 0o170000 == 0o100000, current.size >= 0, current.size <= 8*1024*1024 else { throw SweepError.denied("偏好阶段文件身份无效") }
        }
        if entry.backupDigest != nil {
            guard entry.backupFormat == format, entry.backupBytes.map({ $0 >= 0 && $0 <= 9*1024*1024 }) ?? (entry.backupPending == true) else { throw SweepError.denied("偏好备份格式或容量未登记") }
        } else {
            guard entry.backupFormat == nil, entry.backupBytes == nil,
                  (record.phase == .restored && entry.state == .restored) || (record.phase == .cleared && entry.state == .purged) else { throw SweepError.denied("偏好阶段缺少独立备份") }
        }
        switch record.phase {
        case .prepared: guard [.prepared,.conflict].contains(entry.state), record.emptyIdentity == nil else { throw SweepError.denied("偏好备份准备阶段无效") }
        case .clearing: guard [.prepared,.conflict].contains(entry.state), entry.backupPending != true else { throw SweepError.denied("偏好清除意图无效") }
        case .cleared: guard [.moved,.conflict,.purgePrepared,.purged].contains(entry.state), record.emptyIdentity != nil else { throw SweepError.denied("偏好清除结果未登记") }
        case .restoring: guard [.restorePrepared,.conflict].contains(entry.state) else { throw SweepError.denied("偏好恢复意图无效") }
        case .restored: guard [.restored,.purgePrepared,.conflict].contains(entry.state), record.restoredIdentity != nil else { throw SweepError.denied("偏好恢复结果未登记") }
        }
    }
    static func validDigest(_ value: String) -> Bool { value.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
    private static func hash(_ bytes: Data) -> String { SHA256.hash(data:bytes).map { String(format:"%02x",$0) }.joined() }
}
#endif
