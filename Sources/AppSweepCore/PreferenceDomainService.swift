#if os(macOS)
import Foundation
import CoreFoundation
import CryptoKit
import Darwin
import CFSafety

/// Native domain adapter only; ownership, reviewed selection and durable recovery
/// authority belong to the transaction caller, never a decoded State.
enum PreferenceDomainService {
    static let rule = "cfpreferences-service-domain-v2"
    struct State: Sendable {
        let inspection: PreferenceFileInspector.Inspection
        let home: String
        let identifier: String
        let bytes: Data
        let valuesDigest: String
        fileprivate init(inspection: PreferenceFileInspector.Inspection, home: String, identifier: String, bytes: Data, valuesDigest: String) {
            self.inspection=inspection;self.home=home;self.identifier=identifier;self.bytes=bytes;self.valuesDigest=valuesDigest
        }
    }
    static func valuesDigest(_ bytes: Data) throws -> String {
        guard !bytes.isEmpty, bytes.count <= 8 * 1024 * 1024,
              !bytes.starts(with:Data("bplist".utf8)) || bytes.starts(with:Data("bplist00".utf8)),
              let values = try PropertyListSerialization.propertyList(from:bytes,format:nil) as? [String:Any] else {
            throw SweepError.incomplete("偏好值不是已确认的有界字典")
        }
        var encoding = TypedEncoding()
        try encoding.append(values,depth:0)
        return SHA256.hash(data:encoding.bytes).map { String(format:"%02x",$0) }.joined()
    }
    static func inspect(path: String, home: String, identifier: String) throws -> State {
        try inspect(path:path,home:home,identifier:identifier,serviceTimeout:10)
    }
    private static func inspect(path: String, home: String, identifier: String, serviceTimeout: TimeInterval) throws -> State {
        try checkedDomain(path:path,home:home,identifier:identifier)
        let inspection = try PreferenceFileInspector.inspect(path:path,home:home,identifier:identifier)
        guard inspection.status == .dictionary else { throw SweepError.incomplete("偏好文件不是已确认的字典，服务状态未确认") }
        let bytes = try SafeFilesystem.readMetadata(path,maximumBytes:8*1024*1024)
        let digest = try valuesDigest(bytes)
        let exported = try PreferenceDomainReader.read(home:home,identifier:identifier,timeout:serviceTimeout)
        guard try valuesDigest(exported) == digest else { throw SweepError.stale("偏好服务与文件值不一致，已停止") }
        try PreferenceFileInspector.verifyUnchanged(inspection,home:home,identifier:identifier)
        return State(inspection:inspection,home:home,identifier:identifier,bytes:bytes,valuesDigest:digest)
    }
    static func verify(_ original: State) throws {
        _ = try refreshed(original)
    }
    static func refreshed(_ original: State) throws -> State {
        let current = try inspect(path:original.inspection.snapshot.path,home:original.home,identifier:original.identifier)
        guard current.inspection.snapshot.identity.sameObject(as:original.inspection.snapshot.identity),
              current.inspection.snapshot.ancestors == original.inspection.snapshot.ancestors,
              current.inspection.digest == original.inspection.digest,
              current.bytes == original.bytes, current.valuesDigest == original.valuesDigest else {
            throw SweepError.stale("偏好文件或服务值在核对后已改变")
        }
        return current
    }
    static func clear(_ original: State) throws -> State {
        try verify(original)
        // import merges dictionaries; only a fixed whole-domain empty write
        // removes the selected domain's values. Never retry this mutation.
        _ = try service(home:original.home,arguments:["write",original.identifier,"{}"])
        let empty = try PropertyListSerialization.data(fromPropertyList:[String:String](),format:.binary,options:0)
        return try settled(original,expectedDigest:valuesDigest(empty))
    }
    static func restore(original: State, expectedEmpty: State, backupPath: String) throws -> State {
        let empty = try PropertyListSerialization.data(fromPropertyList:[String:String](),format:.binary,options:0)
        guard original.home == expectedEmpty.home, original.identifier == expectedEmpty.identifier,
              original.inspection.snapshot.path == expectedEmpty.inspection.snapshot.path,
              try expectedEmpty.valuesDigest == valuesDigest(empty) else { throw SweepError.denied("恢复目标不是同一已确认空偏好域") }
        let backup = try SafeFilesystem.snapshot(backupPath)
        let url = URL(fileURLWithPath:backupPath), parent = try SafeDirectory(path:url.deletingLastPathComponent().path)
        guard as_private_descriptor(parent.fd) == 1,
              backup.identity.mode & 0o170000 == 0o100000, backup.identity.mode & 0o7777 == 0o600,
              backup.identity.owner == getuid(), backup.identity.links == 1,
              backup.identity.sameVolume(as:original.inspection.snapshot.identity),
              backup.identity.size == original.bytes.count, backup.tree.isEmpty,
              try SafeFilesystem.readMetadata(backupPath,maximumBytes:8*1024*1024) == original.bytes,
              try VerifiedFileStream.digest(backup) == original.inspection.digest else {
            throw SweepError.stale("独立偏好备份身份、权限或内容未确认")
        }
        let fd = url.lastPathComponent.withCString { openat(parent.fd,$0,O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC) }
        guard fd >= 3 else { if fd >= 0 { as_close(fd) };throw SweepError.incomplete("无法安全打开独立偏好备份") }
        defer { as_close(fd) }
        var raw = ASIdentity()
        guard as_identity_fd(fd,&raw) == 0, FileIdentity(raw) == backup.identity else { throw SweepError.stale("偏好备份句柄身份已改变") }
        try verify(expectedEmpty)
        try SafeFilesystem.verify(backup)
        // Pass the verified open descriptor. defaults must never reopen an
        // absolute backup path, and settings must never appear in argv/logs.
        _ = try service(home:original.home,arguments:["import",original.identifier,"-"],inputFD:fd)
        let restored = try settled(original,expectedDigest:original.valuesDigest)
        guard as_identity_fd(fd,&raw) == 0, FileIdentity(raw) == backup.identity else { throw SweepError.stale("恢复期间独立偏好备份已改变") }
        try SafeFilesystem.verify(backup)
        return restored
    }
    private static func checkedDomain(path: String, home: String, identifier: String) throws {
        let lower = identifier.lowercased()
        guard getuid() != 0, getuid() == geteuid(), home == (try SystemIdentity.home()),
              identifier.count <= 255, identifier.contains("."),
              identifier.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 46 }),
              let first=identifier.utf8.first, first != 45, first != 46,
              !identifier.hasSuffix("."), !identifier.contains(".."),
              !lower.hasPrefix("com.apple."), !lower.contains("appsweep"), !lower.contains("app-sweep"),
              path == home + "/Library/Preferences/" + identifier + ".plist" else {
            throw SweepError.denied("偏好服务仅接受当前非 root 用户的精确第三方域")
        }
    }
    /// Reconstruct evidence only after the transaction validated its bound
    /// independent receipt. This cannot be decoded as execution authority.
    static func recoveryOriginal(bytes: Data, snapshot: FileSnapshot, home: String, identifier: String, rawDigest: String, expectedValues: String) throws -> State {
        try checkedDomain(path:snapshot.path,home:home,identifier:identifier)
        guard snapshot.identity.owner == getuid(), snapshot.identity.mode & 0o170000 == 0o100000,
              snapshot.identity.links == 1, snapshot.identity.size == bytes.count, snapshot.tree.isEmpty,
              SHA256.hash(data:bytes).map({ String(format:"%02x",$0) }).joined() == rawDigest,
              try valuesDigest(bytes) == expectedValues else { throw SweepError.denied("偏好恢复证据与独立备份不一致") }
        return State(inspection:.init(status:.dictionary,snapshot:snapshot,digest:rawDigest),home:home,identifier:identifier,bytes:bytes,valuesDigest:expectedValues)
    }
    static func nativeExport(identifier: String) throws -> String {
        let home=try SystemIdentity.home(),path=home + "/Library/Preferences/" + identifier + ".plist"
        try checkedDomain(path:path,home:home,identifier:identifier)
        let inspected=try PreferenceFileInspector.inspect(path:path,home:home,identifier:identifier)
        guard inspected.status == .dictionary,
              let values=CFPreferencesCopyMultiple(nil,identifier as CFString,kCFPreferencesCurrentUser,kCFPreferencesAnyHost) as? [String:Any] else { throw SweepError.incomplete("原生偏好域读取未确认") }
        // XML export rounds Date values to whole seconds. A fresh bounded
        // reader preserves the actual service value types in binary plist.
        let bytes=try PropertyListSerialization.data(fromPropertyList:values,format:.binary,options:0)
        _ = try valuesDigest(bytes)
        let encoded=bytes.base64EncodedString()
        guard encoded.utf8.count < 2*1024*1024-1024 else { throw SweepError.incomplete("原生偏好导出超过进程输出容量") }
        try PreferenceFileInspector.verifyUnchanged(inspected,home:home,identifier:identifier)
        return encoded
    }
    private static func service(home: String, arguments: [String], inputFD: Int32? = nil, timeout: TimeInterval = 10) throws -> CapturedProcess {
        try Task.checkCancellation()
        let result = try BoundedProcess.capture("/usr/bin/env",arguments:["-i","HOME=" + home,"PATH=/usr/bin:/bin","LANG=C","LC_ALL=C","/usr/bin/defaults"] + arguments,timeout:timeout,mergeStderr:false,inputFD:inputFD)
        guard result.status == 0 else { throw SweepError.incomplete("偏好服务调用失败，不能判断为空或完成") }
        return result
    }
    private static func settled(_ original: State, expectedDigest: String) throws -> State {
        let deadline = ProcessInfo.processInfo.systemUptime + 10
        while true {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw SweepError.incomplete("偏好服务与文件未在期限内收敛，需要恢复核对") }
            do {
                let remaining = deadline - ProcessInfo.processInfo.systemUptime
                guard remaining >= 0.001 else { throw SweepError.incomplete("偏好收敛核对超时") }
                let current = try inspect(path:original.inspection.snapshot.path,home:original.home,identifier:original.identifier,serviceTimeout:min(10,remaining))
                guard ProcessInfo.processInfo.systemUptime < deadline else { throw SweepError.incomplete("偏好收敛核对超时") }
                if current.valuesDigest == expectedDigest { return current }
            } catch SweepError.stale { /* A service write may precede disk convergence. */ }
            Thread.sleep(forTimeInterval:0.1)
        }
    }
    private struct TypedEncoding {
        var bytes = Data()
        var nodes = 0
        mutating func field(_ tag: UInt8, _ value: Data) throws {
            guard bytes.count <= 16*1024*1024-value.count-9 else { throw SweepError.incomplete("偏好值编码容量超限") }
            bytes.append(tag)
            var count = UInt64(value.count).bigEndian
            withUnsafeBytes(of:&count) { bytes.append(contentsOf:$0) }
            bytes.append(value)
        }
        mutating func append(_ value: Any, depth: Int) throws {
            nodes += 1
            guard depth <= 32, nodes <= 50_000 else { throw SweepError.incomplete("偏好值深度或节点数量超限") }
            if let dictionary = value as? [String:Any] {
                try field(1,Data(String(dictionary.count).utf8))
                for key in dictionary.keys.sorted() { try field(2,Data(key.utf8));try append(dictionary[key]!,depth:depth+1) }
            } else if let array = value as? [Any] {
                try field(3,Data(String(array.count).utf8))
                for item in array { try append(item,depth:depth+1) }
            } else if let data = value as? Data { try field(4,data) }
            else if let date = value as? Date {
                guard date.timeIntervalSinceReferenceDate.isFinite else { throw SweepError.incomplete("偏好日期未确认") }
                try field(5,Data(String(date.timeIntervalSinceReferenceDate.bitPattern).utf8))
            } else if let number = value as? NSNumber {
                if CFGetTypeID(number) == CFBooleanGetTypeID() { try field(6,Data([number.boolValue ? 1 : 0])) }
                else if ["f","d"].contains(String(cString:number.objCType)) {
                    guard number.doubleValue.isFinite else { throw SweepError.incomplete("偏好数值未确认") }
                    try field(7,Data(String(number.doubleValue.bitPattern).utf8))
                } else { try field(8,Data(number.stringValue.utf8)) }
            } else if let string = value as? String { try field(9,Data(string.utf8)) }
            else { throw SweepError.incomplete("偏好值类型未确认") }
        }
    }
}
/// Read-only entry for the packaged CLI's fixed child-process mode. It accepts
/// a current-user third-party domain, never an output path or a write command.
public enum NativePreferenceExport {
    public static func encodedDomain(_ identifier: String) throws -> String { try PreferenceDomainService.nativeExport(identifier:identifier) }
}
#endif
