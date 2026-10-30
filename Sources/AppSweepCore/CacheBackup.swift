import Foundation
import CFSafety
#if canImport(CryptoKit)
import CryptoKit
#endif
#if os(macOS)
import Darwin
#else
import Glibc
#endif

/// A byte archive with a new inode and no inherited cache attributes. Moving a
/// cache inode does not guarantee a consumer or cache service will leave it alone.
enum CacheBackup {
    static let maximumPayload = 8 * 1024 * 1024
    static let freeSpaceReserve: UInt64 = 64 * 1024 * 1024
    static func requiredBytes(_ snapshot: FileSnapshot) throws -> UInt64 {
        guard snapshot.identity.size >= 0, snapshot.identity.size <= maximumPayload else { throw SweepError.denied("响应文件超出独立备份容量") }
        // Bounded raw xattrs (64KiB), receipt and binary-plist overhead.
        return UInt64(snapshot.identity.size) + 128 * 1024
    }
    private struct Receipt: Codable {
        let schemaVersion: Int
        let id: UUID
        let path: String
        let rule: String
        let identity: FileIdentity
        let group: UInt32
        let attributes: Data
        let payload: Data
    }
    static func metadata(_ snapshot: FileSnapshot) throws -> (UInt32, Data) {
        guard !snapshot.identity.isDirectory, snapshot.identity.size >= 0, snapshot.identity.size <= maximumPayload else { throw SweepError.denied("响应文件超出已验证的独立备份范围，保留") }
        let url = URL(fileURLWithPath: snapshot.path), parent = try SafeDirectory(path: URL(fileURLWithPath: snapshot.path).deletingLastPathComponent().path)
        var expected = snapshot.identity.native, group: UInt32 = 0, count = 0
        var attributes = [UInt8](repeating: 0, count: 65536)
        guard as_cache_file_metadata(parent.fd, url.lastPathComponent, &expected, &group, &attributes, attributes.count, &count) == 0 else { throw SweepError.denied("缓存文件权限、标志或扩展属性不能可靠备份，保留") }
        try SafeFilesystem.verify(snapshot)
        return (group, Data(attributes.prefix(count)))
    }
    struct Prepared { let packet: Data; let digest: String }
    static func prepare(_ snapshot: FileSnapshot, candidate: Candidate) throws -> Prepared {
        let (group, attributes) = try metadata(snapshot)
        let payload = try SafeFilesystem.readMetadata(snapshot.path, maximumBytes: maximumPayload)
        try SafeFilesystem.verify(snapshot)
        let receipt = Receipt(schemaVersion: 1, id: candidate.id, path: candidate.path, rule: candidate.rule, identity: snapshot.identity, group: group, attributes: attributes, payload: payload)
        let encoder = PropertyListEncoder(); encoder.outputFormat = .binary
        let packet = try encoder.encode(receipt)
        return Prepared(packet: packet, digest: try digest(packet))
    }
    static func create(_ prepared: Prepared, snapshot: FileSnapshot, candidate: Candidate, in directory: SafeDirectory) throws -> FileIdentity {
        guard snapshot.identity.device == (try directory.ownIdentity).device else { throw SweepError.denied("独立备份不跨卷写入") }
        guard directory.availableBytes > freeSpaceReserve + (try requiredBytes(snapshot)) else { throw SweepError.denied("空间不足以保存独立恢复副本，停止移动") }
        try SafeFilesystem.verify(snapshot)
        let packet = prepared.packet
        let now = Date().timeIntervalSince1970
        var identity = snapshot.identity.native
        identity.mode = 0o100600; identity.owner = as_current_uid(); identity.links = 1; identity.size = Int64(packet.count)
        identity.modified_seconds = Int64(now); identity.modified_nanoseconds = 0
        let result = packet.withUnsafeBytes { as_write_recovered_regular(directory.fd, candidate.id.uuidString, $0.baseAddress, $0.count, &identity, getgid(), nil, 0) }
        guard result == 0 else { throw SweepError.filesystem("独立恢复备份未能持久保存，停止移动") }
        let saved = try SafeFilesystem.snapshot(directory.path + "/" + candidate.id.uuidString)
        guard try directory.read(candidate.id.uuidString) == packet else { throw SweepError.stale("独立备份核对失败") }
        return saved.identity
    }
    private static func read(_ entry: RecoveryEntry, in directory: SafeDirectory) throws -> (Receipt, FileSnapshot) {
        let snapshot = try SafeFilesystem.snapshot(directory.path + "/" + entry.id.uuidString)
        guard [CacheRule.name,CorruptPreferenceRule.name].contains(entry.original.rule), let digest = entry.backupDigest,
              entry.backupIdentity.map({ snapshot.identity == $0 }) ?? (entry.backupPending == true) else { throw SweepError.denied("独立备份身份未确认") }
        let packet = try directory.read(entry.id.uuidString)
        guard try Self.digest(packet) == digest else { throw SweepError.stale("独立备份摘要已改变") }
        let result = try PropertyListDecoder().decode(Receipt.self, from: packet)
        guard result.schemaVersion == 1, result.id == entry.id, result.path == entry.original.path,
              result.rule == entry.original.rule, result.identity == entry.original.identity,
              result.payload.count <= maximumPayload, result.identity.size == result.payload.count,
              result.attributes.count <= 65536 else { throw SweepError.denied("独立备份内容与原始记录不一致") }
        try SafeFilesystem.verify(snapshot)
        return (result, snapshot)
    }
    static func materialize(_ entry: RecoveryEntry, from directory: SafeDirectory, into objects: SafeDirectory) throws -> FileSnapshot {
        let receipt = try read(entry, in: directory).0
        guard receipt.identity.sameVolume(as:try objects.ownIdentity), entry.backupIdentity?.sameVolume(as:receipt.identity) == true else { throw SweepError.denied("独立备份恢复不跨卷写入") }
        guard objects.availableBytes > freeSpaceReserve + UInt64(receipt.payload.count) + 128 * 1024 else { throw SweepError.denied("空间不足以重建恢复副本，保留备份并停止恢复") }
        var expected = receipt.identity.native
        let result = receipt.payload.withUnsafeBytes { data in
            receipt.attributes.withUnsafeBytes { attributes in
                as_write_recovered_regular(objects.fd, entry.id.uuidString, data.baseAddress, data.count, &expected, receipt.group, attributes.baseAddress, attributes.count)
            }
        }
        guard result == 0 else { throw SweepError.filesystem("备份重建失败或目标存在，停止恢复") }
        let snapshot = try SafeFilesystem.snapshot(objects.path + "/" + entry.id.uuidString)
        guard try matches(snapshot, receipt: receipt) else { throw SweepError.stale("重建的缓存副本核对失败") }
        return snapshot
    }
    static func validatesReconstruction(_ snapshot: FileSnapshot, entry: RecoveryEntry, in directory: SafeDirectory) throws -> Bool {
        try matches(snapshot, receipt: read(entry, in: directory).0)
    }
    static func verifiedSnapshot(_ entry: RecoveryEntry, in directory: SafeDirectory) throws -> FileSnapshot {
        try read(entry, in: directory).1
    }
    private static func matches(_ snapshot: FileSnapshot, receipt: Receipt) throws -> Bool {
        let a = snapshot.identity, b = receipt.identity
        guard a.mode == b.mode, a.owner == b.owner, a.links == 1, a.size == b.size,
              a.modifiedSeconds == b.modifiedSeconds, a.modifiedNanoseconds == b.modifiedNanoseconds else { return false }
        let (group, attributes) = try metadata(snapshot)
        let payload = try SafeFilesystem.readMetadata(snapshot.path, maximumBytes: maximumPayload)
        return group == receipt.group && attributes == receipt.attributes && payload == receipt.payload
    }
    private static func digest(_ data: Data) throws -> String {
        #if canImport(CryptoKit)
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        #else
        throw SweepError.denied("当前平台未验证独立备份摘要")
        #endif
    }
}
