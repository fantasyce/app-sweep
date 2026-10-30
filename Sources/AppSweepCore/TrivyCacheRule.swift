import Foundation
import CFSafety
import Darwin

/// The documented downloaded vulnerability database, not scan results, custom
/// policies, VEX data, or the entire tool directory. Metadata and DB move together.
enum TrivyCacheRule {
    static let name = "development-trivy-database-v1"
    static func verify(_ path: String, home: String) throws -> FileSnapshot {
        guard path == home + "/Library/Caches/trivy/db" else { throw SweepError.denied("不是已验证的 Trivy 下载数据库位置") }
        let snapshot = try SafeFilesystem.snapshot(path)
        try ContainerDataRule.verifyPrivateTree(snapshot, home: home)
        guard snapshot.identity.device == (try SafeDirectory(path: home).ownIdentity.device),
              Set(snapshot.tree.map(\.relative)) == ["metadata.json", "trivy.db"],
              snapshot.tree.allSatisfy({ $0.identity.mode & 0o170000 == 0o100000 && $0.identity.links == 1 }),
              let db = snapshot.tree.first(where: { $0.relative == "trivy.db" }) else { throw SweepError.denied("Trivy 数据库包含未知文件或共享内容") }
        let metadata = try SafeFilesystem.readMetadata(path + "/metadata.json", maximumBytes: 4096)
        guard let fields = try JSONSerialization.jsonObject(with: metadata) as? [String: Any],
              Set(fields.keys) == ["Version", "NextUpdate", "UpdatedAt", "DownloadedAt"], fields["Version"] as? Int == 2 else { throw SweepError.denied("Trivy 数据库版本或来源元数据未确认") }
        let iso = ISO8601DateFormatter(), fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        var dates: [String: Date] = [:]
        for key in ["NextUpdate", "UpdatedAt", "DownloadedAt"] {
            guard let value = fields[key] as? String, value.count <= 40, let date = fractional.date(from: value) ?? iso.date(from: value) else { throw SweepError.denied("Trivy 数据库时间元数据未确认") }
            dates[key] = date
        }
        guard dates["NextUpdate"]! >= dates["UpdatedAt"]!, dates["DownloadedAt"]! >= dates["UpdatedAt"]! else { throw SweepError.denied("Trivy 数据库时间顺序未确认") }
        let directory = try SafeDirectory(path: path), fd = openat(directory.fd, "trivy.db", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw SweepError.denied("Trivy 数据库无法安全读取") }; defer { as_close(fd) }
        var identity = ASIdentity()
        guard as_identity_fd(fd, &identity) == 0, FileIdentity(identity) == db.identity else { throw SweepError.stale("Trivy 数据库已改变") }
        func header(_ offset: Int64) throws -> [UInt8] {
            var bytes = [UInt8](repeating: 0, count: 80)
            guard pread(fd, &bytes, bytes.count, off_t(offset)) == bytes.count else { throw SweepError.denied("Trivy 数据库页不完整") }
            return bytes
        }
        func integer(_ bytes: [UInt8], _ offset: Int, _ width: Int) -> UInt64 {
            (0..<width).reduce(0) { $0 | UInt64(bytes[offset+$1]) << (8*$1) }
        }
        let first = try header(0), pageSize = integer(first, 24, 4)
        guard [4096,8192,16384,32768,65536].contains(pageSize), db.identity.size >= Int64(pageSize*4), UInt64(db.identity.size) % pageSize == 0 else { throw SweepError.denied("Trivy 数据库页布局未确认") }
        for (index, bytes) in [first, try header(Int64(pageSize))].enumerated() {
            let checksum = bytes[16..<72].reduce(UInt64(14695981039346656037)) { ($0 ^ UInt64($1)) &* 1099511628211 }
            let pages = integer(bytes,56,8)
            guard integer(bytes,0,8) == UInt64(index), integer(bytes,8,2) == 4, integer(bytes,10,6) == 0,
                  integer(bytes,16,4) == 0xed0cdaed, integer(bytes,20,4) == 2, integer(bytes,24,4) == pageSize,
                  integer(bytes,28,4) == 0, pages >= 4, pages <= UInt64(db.identity.size)/pageSize,
                  integer(bytes,32,8) >= 2, integer(bytes,32,8) < pages,
                  integer(bytes,48,8) == UInt64.max || integer(bytes,48,8) < pages,
                  integer(bytes,64,8) % 2 == UInt64(index), checksum == integer(bytes,72,8) else { throw SweepError.denied("Trivy 数据库类型或页校验不匹配") }
        }
        guard as_identity_fd(fd, &identity) == 0, FileIdentity(identity) == db.identity else { throw SweepError.stale("Trivy 数据库读取时已改变") }
        try SafeFilesystem.verify(snapshot)
        return snapshot
    }
}
