import Foundation
import CFSafety
#if os(macOS)
import Darwin
#else
import Glibc
#endif

/// Read-only input for a future service-managed preference transaction.
/// A format result supplies neither application ownership nor cleanup authority.
enum PreferenceFileInspector {
    enum Status: String, Sendable { case dictionary, nonDictionary, malformed }
    struct Inspection: Sendable {
        let status: Status
        let snapshot: FileSnapshot
        let digest: String
    }
    static func inspect(path: String, home: String, identifier: String) throws -> Inspection {
        guard as_current_uid() != 0, AppInspector.validIdentifier(identifier),
              !identifier.hasPrefix("."), !identifier.hasSuffix("."), !identifier.contains(".."),
              !identifier.lowercased().hasPrefix("com.apple."),
              !identifier.lowercased().contains("appsweep"), !identifier.lowercased().contains("app-sweep"),
              home != "/", home == URL(fileURLWithPath:home).standardizedFileURL.path,
              path == home + "/Library/Preferences/" + identifier + ".plist",
              SafetyPolicy(home:home,acceptedPlatform:false).lexicalDenial(path) == nil else {
            throw SweepError.denied("不是当前用户的独立第三方应用偏好域")
        }
        let snapshot = try SafeFilesystem.snapshot(path)
        guard snapshot.identity.mode & 0o170000 == 0o100000,
              snapshot.identity.owner == as_current_uid(), snapshot.identity.links == 1,
              snapshot.identity.size >= 0, snapshot.identity.size <= 8 * 1024 * 1024,
              snapshot.tree.isEmpty else { throw SweepError.incomplete("偏好文件类型、所有者或读取容量未确认") }
        try verifyPermissions(snapshot)
        // Reading and permission failures stay outside the format catch. They
        // must never turn into permission to reset a supposedly damaged domain.
        let bytes = try SafeFilesystem.readMetadata(path,maximumBytes:8*1024*1024)
        let status=try formatStatus(bytes)
        let digest = try VerifiedFileStream.digest(snapshot)
        try verifyPermissions(snapshot)
        try SafeFilesystem.verify(snapshot)
        return Inspection(status:status,snapshot:snapshot,digest:digest)
    }
    static func formatStatus(_ bytes:Data)throws->Status {
        if bytes.starts(with:Data("bplist".utf8)), !bytes.starts(with:Data("bplist00".utf8)) {
            throw SweepError.incomplete("未知二进制偏好格式版本，不能判断损坏")
        }
        let status: Status
        if bytes.isEmpty { status = .malformed }
        else {
            do {
                let value = try PropertyListSerialization.propertyList(from:bytes,format:nil)
                status = value is [String:Any] ? .dictionary : .nonDictionary
            } catch {
                let failure = error as NSError
                guard failure.domain == NSCocoaErrorDomain, failure.code == CocoaError.propertyListReadCorrupt.rawValue else {
                    throw SweepError.incomplete("偏好解析结果未确认，不能判断损坏")
                }
                status = .malformed
            }
        }
        return status
    }
    static func verifyUnchanged(_ original: Inspection, home: String, identifier: String) throws {
        try SafeFilesystem.verify(original.snapshot)
        let current = try inspect(path:original.snapshot.path,home:home,identifier:identifier)
        guard current.status == original.status, current.digest == original.digest,
              current.snapshot.identity == original.snapshot.identity,
              current.snapshot.ancestors == original.snapshot.ancestors else {
            throw SweepError.stale("偏好文件或祖先在核对后已改变")
        }
    }
    private static func verifyPermissions(_ snapshot: FileSnapshot) throws {
        for node in snapshot.ancestors {
            try Task.checkCancellation()
            let directory = try SafeDirectory(path:node.path)
            guard as_unshared_node_descriptor(directory.fd,node.owner) == 1 else {
                throw SweepError.incomplete("偏好祖先目录可被其他用户改写")
            }
        }
        let url = URL(fileURLWithPath:snapshot.path), directory = try SafeDirectory(path:url.deletingLastPathComponent().path)
        let fd = url.lastPathComponent.withCString { openat(directory.fd,$0,O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC) }
        guard fd >= 0 else { throw SweepError.incomplete("无法确认偏好读取权限") }
        defer { as_close(fd) }
        var identity = ASIdentity()
        guard as_identity_fd(fd,&identity) == 0, FileIdentity(identity) == snapshot.identity,
              as_unshared_node_descriptor(fd,as_current_uid()) == 1,
              try directory.identity(url.lastPathComponent) == snapshot.identity else {
            throw SweepError.incomplete("偏好文件身份或共享权限未确认")
        }
    }
}
