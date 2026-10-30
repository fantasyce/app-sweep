import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

/// A bounded, versioned commitment to a complete sorted metadata tree. It is not
/// a content backup and never authorizes a path independently of the original rule.
struct TreeFingerprint: Codable, Sendable, Equatable {
    static let inlineLimit = 20_000
    static let maximumEntries = 1_000_000
    let algorithm: String
    let count: Int
    let digest: String
    var validLargeApplication: Bool { validLargeTree }
    var validLargeTree: Bool {
        ["sha256-metadata-v1","sha256-volume-metadata-v2"].contains(algorithm) && count > Self.inlineLimit && count <= Self.maximumEntries &&
        digest.utf8.count == 64 && digest.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    var validCacheTree: Bool {
        ["sha256-metadata-v1","sha256-volume-metadata-v2"].contains(algorithm) && count >= 0 && count <= Self.inlineLimit &&
        digest.utf8.count == 64 && digest.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    static func capture(_ tree: [TreeEntry],algorithm requested:String?=nil) throws -> TreeFingerprint {
        let stable=tree.allSatisfy{$0.identity.volumeUUID.flatMap{UUID(uuidString:$0)?.uuidString} == $0.identity.volumeUUID && $0.identity.volumeUUID != nil}
        let algorithm=requested ?? (stable ? "sha256-volume-metadata-v2" : "sha256-metadata-v1")
        guard ["sha256-metadata-v1","sha256-volume-metadata-v2"].contains(algorithm),algorithm != "sha256-volume-metadata-v2" || stable else{throw SweepError.denied("目录摘要的卷身份未确认")}
        guard tree.count <= maximumEntries else { throw SweepError.incomplete("应用内容超过恢复校验容量") }
        #if canImport(CryptoKit)
        var hash = SHA256()
        hash.update(data: Data((algorithm == "sha256-metadata-v1" ? "AppSweep tree metadata v1\0" : "AppSweep volume tree metadata v2\0").utf8))
        var count = UInt64(tree.count).littleEndian
        withUnsafeBytes(of: &count) { hash.update(bufferPointer: $0) }
        var previous: String?
        for entry in tree {
            try Task.checkCancellation()
            let path = entry.relative, parts = path.split(separator: "/", omittingEmptySubsequences: false)
            guard !path.isEmpty, !path.hasPrefix("/"), !path.contains("\0"), path.utf8.count < 4096,
                  parts.count <= 128, parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }),
                  previous.map({ $0 < path }) ?? true else { throw SweepError.invalid("应用内容路径或排序未确认") }
            previous = path
            let s = entry.identity
            var fields: [UInt64] = [UInt64(path.utf8.count), algorithm == "sha256-metadata-v1" ? s.device : 0, s.inode, UInt64(s.mode), UInt64(s.owner), s.links,
                                    UInt64(bitPattern: s.size), UInt64(bitPattern: s.modifiedSeconds), UInt64(bitPattern: s.modifiedNanoseconds),
                                    UInt64(bitPattern: s.changedSeconds), UInt64(bitPattern: s.changedNanoseconds)].map(\.littleEndian)
            fields.withUnsafeMutableBytes { hash.update(bufferPointer: UnsafeRawBufferPointer($0)) }
            if algorithm == "sha256-volume-metadata-v2"{hash.update(data:Data(s.volumeUUID!.utf8))}
            hash.update(data: Data(path.utf8))
        }
        return TreeFingerprint(algorithm: algorithm, count: tree.count, digest: hash.finalize().map { String(format: "%02x", $0) }.joined())
        #else
        throw SweepError.denied("当前平台未提供已验收的目录摘要能力")
        #endif
    }
    func matches(_ tree: [TreeEntry]) throws -> Bool {
        guard count == tree.count else { return false }
        return self == (try Self.capture(tree,algorithm:algorithm))
    }
}
