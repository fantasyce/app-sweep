import Foundation
import CFSafety

/// Derived only inside the service from its freshly authenticated kernel peer.
/// Never decoded from a request or supplied by the client's environment.
struct AuthenticatedUserContext: Sendable {
    let uid: UInt32
    let home: String
    let homeAncestors: [AncestorIdentity]
    var allowedSystemOwners: Set<UInt32> { [0, uid] }
    private init(uid: UInt32, home: String, homeAncestors: [AncestorIdentity]) {
        self.uid = uid; self.home = home; self.homeAncestors = homeAncestors
    }
    static func resolve(_ peer: AuthenticatedLocalPeer) throws -> Self {
        guard peer.uid >= 500, peer.uid < UInt32(Int32.max), peer.pid > 0, peer.auditToken.count == 32 else { throw SweepError.denied("系统或未确认账户不能创建用户清理上下文") }
        var buffer = [CChar](repeating: 0, count: 16_384)
        guard as_account_home_directory(peer.uid, &buffer, buffer.count) == 0 else { throw SweepError.denied("认证账户主目录查询失败") }
        let data = Data(buffer.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) })
        guard let home = String(data: data, encoding: .utf8), validLocalHome(home) else { throw SweepError.denied("认证账户主目录不是已确认的本地用户位置") }
        let users = try SafeDirectory(path: "/Users"), directory = try SafeDirectory(path: home)
        guard as_root_configuration_descriptor(users.fd, 1) == 1,
              try directory.ownIdentity.owner == peer.uid,
              try directory.ownIdentity.device == users.ownIdentity.device else { throw SweepError.denied("用户主目录所有者、祖先权限或卷未确认") }
        let context = Self(uid: peer.uid, home: home, homeAncestors: try SafeFilesystem.ancestors(of: home))
        try context.verifyUnchanged()
        return context
    }
    static func validLocalHome(_ path: String) -> Bool {
        let parts = path.split(separator: "/", omittingEmptySubsequences: false)
        return parts.count == 3 && parts[0].isEmpty && parts[1] == "Users" &&
            !parts[2].isEmpty && parts[2] != "." && parts[2] != ".." && parts[2].lowercased() != "shared" && !path.contains("\0")
    }
    func verifyUnchanged() throws {
        guard try SafeFilesystem.ancestors(of: home) == homeAncestors else { throw SweepError.stale("认证用户目录或祖先已改变") }
    }
}
