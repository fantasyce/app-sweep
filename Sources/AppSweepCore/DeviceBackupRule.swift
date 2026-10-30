import Foundation
import CoreFoundation
import CFSafety
#if os(macOS)
import Darwin
#else
import Glibc
#endif

/// Identifies a whole local device-backup directory. This is not an authority
/// to move it, nor a claim that its contents can restore or decrypt a device.
enum DeviceBackupRule {
    static let name = "local-device-backup-v1"
    static let largeName = "local-device-backup-large-v1"
    enum Format: String, Sendable { case database, legacyDatabase }
    struct Metadata: Sendable {
        let deviceName: String
        let date: Date
        let encrypted: Bool
        let format: Format
        let details: DeviceBackupDetails
    }
    static func root(home: String) -> String { home + "/Library/Application Support/MobileSync/Backup" }
    static func matches(path: String,home: String) -> Bool {
        guard home.hasPrefix("/"), !home.contains("\0"), !path.contains("\0"),
              home == URL(fileURLWithPath:home).standardizedFileURL.path,
              path == URL(fileURLWithPath:path).standardizedFileURL.path,
              URL(fileURLWithPath:path).deletingLastPathComponent().path == root(home:home) else { return false }
        return URL(fileURLWithPath:path).lastPathComponent.range(of:#"^(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16})(?:-[0-9]{8}-[0-9]{6})?$"#,options:.regularExpression) != nil
    }
    static func inspect(path: String,home: String) throws -> Metadata {
        guard matches(path:path,home:home), as_current_uid() != 0 else { throw SweepError.denied("不是当前用户的一份直接本地设备备份") }
        let ancestors = try SafeFilesystem.ancestors(of:path)
        try verifyAncestors(ancestors)
        let directory = try SafeDirectory(path:path), identity = try directory.ownIdentity
        guard identity.owner == as_current_uid(), as_unshared_node_descriptor(directory.fd,as_current_uid()) == 1,
              try identity.device == SafeDirectory(path:root(home:home)).ownIdentity.device else { throw SweepError.denied("备份目录所有者、共享权限或卷未确认") }
        let metadataIdentities = try Dictionary(uniqueKeysWithValues:["Info.plist","Status.plist","Manifest.plist"].map { ($0,try directory.identity($0)) })
        let info = try plist("Info.plist",in:directory)
        let status = try plist("Status.plist",in:directory)
        let manifest = try plist("Manifest.plist",in:directory)
        guard let identifier = info["Unique Identifier"] as? String,
              identifier.range(of:#"^(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16})$"#,options:.regularExpression) != nil else { throw SweepError.denied("备份设备标识未确认") }
        let leaf = URL(fileURLWithPath:path).lastPathComponent.lowercased(), id = identifier.lowercased()
        guard leaf == id || (leaf.hasPrefix(id) && String(leaf.dropFirst(id.count)).range(of:#"^-[0-9]{8}-[0-9]{6}$"#,options:.regularExpression) != nil) else { throw SweepError.denied("备份目录与设备标识不一致") }
        guard let deviceName = info["Device Name"] as? String, !deviceName.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty,
              deviceName.utf8.count <= 256, !deviceName.unicodeScalars.contains(where:CharacterSet.controlCharacters.contains),
              let date = info["Last Backup Date"] as? Date, date.timeIntervalSince1970 > 0, date <= Date().addingTimeInterval(86400),
              status["SnapshotState"] as? String == "finished",
              let version = status["Version"] as? String,
              version.range(of:#"^[23](?:\.[0-9]{1,2}){1,2}$"#,options:.regularExpression) != nil,
              let encryption = manifest["IsEncrypted"] as? NSNumber, CFGetTypeID(encryption) == CFBooleanGetTypeID() else { throw SweepError.denied("备份元数据不完整、代际未知或操作尚未结束") }
        let modern = try SafeFilesystem.presence(path + "/Manifest.db")
        let legacy = try SafeFilesystem.presence(path + "/Manifest.mbdb")
        guard modern != legacy else { throw SweepError.denied("备份数据库缺失或格式归属不明确") }
        let databaseName = modern ? "Manifest.db" : "Manifest.mbdb"
        let databaseIdentity = try directory.identity(databaseName)
        let encrypted = encryption.boolValue, format: Format
        if modern {
            let header = try read("Manifest.db",in:directory,maximum:16,prefix:true)
            guard encrypted || header == Data("SQLite format 3\0".utf8) else { throw SweepError.denied("备份数据库格式未确认") }
            format = .database
        } else {
            guard try read("Manifest.mbdb",in:directory,maximum:6,prefix:true) == Data([109,98,100,98,5,0]) else { throw SweepError.denied("旧备份数据库格式未确认") }
            format = .legacyDatabase
        }
        guard try SafeFilesystem.ancestors(of:path) == ancestors,
              try SafeDirectory(path:path).ownIdentity == identity,
              try directory.ownIdentity == identity else { throw SweepError.stale("备份目录在识别期间已改变") }
        for (name,expected) in metadataIdentities { guard try directory.identity(name) == expected else { throw SweepError.stale("备份元数据集合在识别期间已改变") } }
        guard try directory.identity(databaseName) == databaseIdentity else { throw SweepError.stale("备份数据库在识别期间已改变") }
        try verifyAncestors(ancestors)
        return .init(deviceName:deviceName,date:date,encrypted:encrypted,format:format,
                     details:DeviceBackupDetails(identifier:identifier,deviceName:deviceName,date:date,encrypted:encrypted))
    }
    /// Also applies to a verified private recovery object; never grants a path
    /// capability. Complete tree ownership is needed even for compact journals.
    static func verifyTree(_ snapshot: FileSnapshot) throws {
        guard as_current_uid() != 0, snapshot.identity.isDirectory, !snapshot.allowInternalLinks,
              !snapshot.allowInternalHardLinks else { throw SweepError.denied("备份必须是完整独立目录") }
        let deadline = ProcessInfo.processInfo.systemUptime + 300
        for index in -1..<snapshot.tree.count {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw SweepError.incomplete("备份权限检查超时，整份保留") }
            let entry = index == -1 ? TreeEntry(relative:"",identity:snapshot.identity) : snapshot.tree[index]
            guard entry.identity.owner == as_current_uid(), !entry.identity.isLink,
                  entry.identity.isDirectory || entry.identity.links == 1 else { throw SweepError.denied("备份包含链接或其他所有者") }
            let path = entry.relative.isEmpty ? snapshot.path : snapshot.path + "/" + entry.relative
            let url = URL(fileURLWithPath:path), parent = try SafeDirectory(path:url.deletingLastPathComponent().path)
            let fd = url.lastPathComponent.withCString { openat(parent.fd,$0,O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC) }
            guard fd >= 0 else { throw SweepError.denied("备份对象权限未确认") }
            defer { as_close(fd) }
            var raw = ASIdentity()
            guard as_identity_fd(fd,&raw) == 0, FileIdentity(raw) == entry.identity,
                  as_unshared_node_descriptor(fd,as_current_uid()) == 1,
                  try parent.identity(url.lastPathComponent) == entry.identity else { throw SweepError.stale("备份对象身份、共享写入或ACL未确认") }
        }
        try SafeFilesystem.verify(snapshot)
    }
    private static func verifyAncestors(_ ancestors: [AncestorIdentity]) throws {
        for node in ancestors {
            try Task.checkCancellation()
            let directory = try SafeDirectory(path:node.path)
            guard as_unshared_node_descriptor(directory.fd,node.owner) == 1 else { throw SweepError.denied("备份祖先目录可被其他用户改写") }
        }
    }
    private static func plist(_ name: String,in directory: SafeDirectory) throws -> [String:Any] {
        let bytes = try read(name,in:directory,maximum:8*1024*1024,prefix:false)
        guard let result = try PropertyListSerialization.propertyList(from:bytes,format:nil) as? [String:Any] else { throw SweepError.denied("备份元数据不是属性字典") }
        return result
    }
    private static func read(_ name: String,in directory: SafeDirectory,maximum: Int,prefix: Bool) throws -> Data {
        let expected = try directory.identity(name)
        guard expected.mode & 0o170000 == 0o100000, expected.owner == as_current_uid(), expected.links == 1,
              expected.size > 0, prefix ? expected.size >= maximum : expected.size <= maximum else { throw SweepError.denied("备份元数据类型、所有者或容量未确认") }
        let fd = name.withCString { openat(directory.fd,$0,O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC) }
        guard fd >= 0 else { throw SweepError.filesystem("无法安全打开备份元数据") }
        defer { as_close(fd) }
        var raw = ASIdentity()
        guard as_identity_fd(fd,&raw) == 0, FileIdentity(raw) == expected,
              as_unshared_node_descriptor(fd,as_current_uid()) == 1 else { throw SweepError.stale("备份元数据身份或共享权限已改变") }
        let handle = FileHandle(fileDescriptor:fd,closeOnDealloc:false)
        let count = prefix ? maximum : Int(expected.size)
        guard let bytes = try handle.read(upToCount:count), bytes.count == count,
              as_identity_fd(fd,&raw) == 0, FileIdentity(raw) == expected,
              try directory.identity(name) == expected,
              as_unshared_node_descriptor(fd,as_current_uid()) == 1 else { throw SweepError.stale("备份元数据在读取期间已改变") }
        return bytes
    }
}
