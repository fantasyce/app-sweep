import Foundation

struct HardLinkContext: Sendable {
    let root: String
    let rootIdentity: FileIdentity
    let aliases: [String]
    func verify(_ identity: FileIdentity) throws {
        guard identity.links > 1, UInt64(aliases.count) == identity.links,
              Set(aliases).count == aliases.count,
              try SafeDirectory(path: root).ownIdentity == rootIdentity else { throw SweepError.stale("缓存硬链接的目录或引用数量已改变") }
        for path in aliases {
            guard path != root, SafetyPolicy.contains(root, path) else { throw SweepError.denied("缓存硬链接引用越界") }
            let url = URL(fileURLWithPath: path), parent = try SafeDirectory(path: url.deletingLastPathComponent().path)
            guard try parent.identity(url.lastPathComponent) == identity else { throw SweepError.stale("缓存硬链接引用身份已改变") }
        }
    }
}
enum ContainedHardLinks {
    static func key(_ identity: FileIdentity) -> String { "\(identity.device):\(identity.inode)" }
    static func groups(_ entries: [TreeEntry]) -> [String: [TreeEntry]] {
        Dictionary(grouping: entries.filter { $0.identity.mode & 0o170000 == 0o100000 }, by: { key($0.identity) })
    }
    static func validate(_ entries: [TreeEntry]) throws {
        guard Set(entries.map(\.relative)).count == entries.count else { throw SweepError.denied("缓存引用路径重复") }
        for group in groups(entries).values {
            guard let first = group.first, first.identity.links == UInt64(group.count),
                  group.allSatisfy({ $0.identity == first.identity }) else { throw SweepError.denied("缓存硬链接存在对象外引用或身份不一致，整项保留") }
        }
    }
}
