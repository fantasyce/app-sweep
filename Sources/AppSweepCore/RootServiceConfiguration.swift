import Foundation
import CFSafety
#if os(macOS)
import Darwin
#endif

struct RootServicePins: Codable, Sendable, Equatable {
    enum Role { case client, service }
    let schemaVersion: Int
    let serviceBuild: String
    let clientCodeHashes: [String]
    let serviceCodeHashes: [String]
    private func validate() throws {
        guard schemaVersion == 1, !serviceBuild.isEmpty, serviceBuild.utf8.count <= 128,
              serviceBuild.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [45,46,95].contains($0) }) else { throw SweepError.denied("系统执行者配置版本无效") }
        for values in [clientCodeHashes, serviceCodeHashes] {
            guard !values.isEmpty, values.count <= 4, Set(values).count == values.count,
                  values.allSatisfy({ $0.utf8.count == 40 && $0.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }) else { throw SweepError.denied("系统执行者代码摘要为空、重复或无效") }
        }
    }
    static func decode(_ data: Data) throws -> RootServicePins {
        let pins = try CanonicalControlJSON.decode(RootServicePins.self, from: data)
        try pins.validate(); return pins
    }
    func encode() throws -> Data { try validate(); return try CanonicalControlJSON.encode(self) }
    func requirement(for role: Role) throws -> String {
        try validate()
        return (role == .client ? clientCodeHashes : serviceCodeHashes).sorted().map { "(cdhash H\"" + $0 + "\")" }.joined(separator: " or ")
    }
}
struct LoadedRootServicePins: Sendable {
    let pins: RootServicePins
    let snapshot: FileSnapshot
    func verifyUnchanged() throws { try SafeFilesystem.verify(snapshot) }
}
enum RootServiceConfiguration {
    static let path = "/Library/Application Support/App Sweep/Service/config.json"
    static func load() throws -> LoadedRootServicePins {
        #if os(macOS)
        let library = try SafeDirectory(path: "/Library"), device = try library.ownIdentity.device
        for root in ["/", "/Library", "/Library/Application Support", "/Library/Application Support/App Sweep", "/Library/Application Support/App Sweep/Service"] {
            let directory = try SafeDirectory(path: root)
            let identity = try directory.ownIdentity
            guard as_root_configuration_descriptor(directory.fd, 1) == 1,
                  root == "/" || identity.device == device else { throw SweepError.denied("系统执行者配置祖先可被改写或位于未确认卷") }
        }
        let snapshot = try SafeFilesystem.snapshot(path)
        let parent = try SafeDirectory(path: URL(fileURLWithPath: path).deletingLastPathComponent().path)
        let fd = "config.json".withCString { openat(parent.fd, $0, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC) }
        guard fd >= 0 else { throw SweepError.denied("系统执行者配置无法安全读取") }
        defer { as_close(fd) }
        var native = ASIdentity()
        guard as_root_configuration_descriptor(fd, 0) == 1, as_identity_fd(fd, &native) == 0,
              FileIdentity(native) == snapshot.identity, snapshot.identity.device == device else { throw SweepError.denied("系统执行者配置所有者、权限或身份无效") }
        let pins = try RootServicePins.decode(SafeFilesystem.readMetadata(path, maximumBytes: CanonicalControlJSON.maximumBytes))
        try SafeFilesystem.verify(snapshot)
        return LoadedRootServicePins(pins: pins, snapshot: snapshot)
        #else
        throw SweepError.denied("当前平台未验收系统执行者配置")
        #endif
    }
}
