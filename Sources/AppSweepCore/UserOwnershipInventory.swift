import Foundation
import CryptoKit

/// Read-only ownership evidence from the exact authenticated client. It never
/// supplies a privileged write target: those remain derived from system roots.
struct UserOwnershipInventory: Codable, Equatable, Sendable {
    struct Entry: Codable, Equatable, Sendable {
        let path: String
        let identifier: String
        let unresolved: Bool
    }
    let entries: [Entry]
    let issues: [String]
    struct HelperCheck: Codable, Equatable, Sendable {
        let label: String
        let codeHash: Data
        let inspectedPaths: [String]
        let exclusive: Bool
        var inspectedPathsDigest: String? = nil
    }
    var helperChecks: [HelperCheck]? = nil

    static func collect(home: String, includeHelpers: Bool = false) throws -> Self {
        let inventory = try AppInspector.inventorySnapshot(home: home)
        var result = Self(entries: inventory.applications.map {
            Entry(path: $0.path, identifier: $0.bundleIdentifier, unresolved: $0.protectedReason != nil)
        }, issues: inventory.issues)
        if includeHelpers { result.helperChecks = try InstalledSystemHelperRule.userSideSharingChecks(inventory: inventory.applications) }
        try result.validate()
        return try result.compacted()
    }
    func validate() throws {
        guard entries.count <= 4096, issues.count <= 256,
              issues.allSatisfy({ $0.utf8.count <= 4096 && !$0.contains("\0") }) else {
            throw SweepError.incomplete("用户侧应用归属证据超限")
        }
        if let helperChecks {
            guard helperChecks.count <= 128, Set(helperChecks.map(\.label)).count == helperChecks.count else { throw SweepError.incomplete("组件归属证据重复或超限") }
            for check in helperChecks {
                if let digest = check.inspectedPathsDigest {
                    guard check.inspectedPaths.isEmpty, digest.utf8.count == 64,
                          digest.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw SweepError.incomplete("组件归属摘要无效") }
                }
                guard SystemCleanupScope.validIdentifier(check.label), !check.codeHash.isEmpty, check.codeHash.count <= 64,
                      check.inspectedPaths.count <= 4096, check.inspectedPaths.allSatisfy({ $0.isEmpty || (XcodeRule.canonical($0) && $0.utf8.count <= 4096) }) else { throw SweepError.incomplete("组件归属证据无效") }
            }
        }
        for item in entries {
            guard item.identifier.isEmpty || AppInspector.validIdentifier(item.identifier),
                  item.path.isEmpty || (XcodeRule.canonical(item.path) && item.path.utf8.count <= 4096) else {
                throw SweepError.incomplete("用户侧应用归属证据无效")
            }
        }
    }
    func provesExclusiveHelper(label: String, codeHash: Data, applicationsRoot: String) -> Bool {
        let expected = Set(entries.filter { !SafetyPolicy.contains(applicationsRoot, $0.path) }.map(\.path))
        guard let check = helperChecks?.first(where: { $0.label == label && $0.codeHash == codeHash }), check.exclusive else { return false }
        if let digest = check.inspectedPathsDigest { return digest == (try? Self.pathDigest(Array(expected))) }
        return Set(check.inspectedPaths) == expected && check.inspectedPaths.count == expected.count
    }
    // The entry list remains complete. Each helper binds that exact inspected
    // path list by digest instead of repeating thousands of path bytes on wire.
    // Missing, changed, duplicated or malformed coverage still fails closed.
    func compacted() throws -> Self {
        try validate()
        var result = self
        result.helperChecks = try helperChecks?.map { check in
            guard check.inspectedPathsDigest == nil else { return check }
            return HelperCheck(label: check.label, codeHash: check.codeHash, inspectedPaths: [],
                exclusive: check.exclusive, inspectedPathsDigest: try Self.pathDigest(check.inspectedPaths))
        }
        try result.validate()
        return result
    }
    private static func pathDigest(_ paths: [String]) throws -> String {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.withoutEscapingSlashes]
        return SHA256.hash(data: try encoder.encode(paths.sorted())).map { String(format: "%02x", $0) }.joined()
    }
    func combining(machine: ApplicationInventory, applicationsRoot: String) throws -> ApplicationInventory {
        try validate()
        var combined = machine.applications
        var failures = machine.issues + issues
        let machinePaths = Dictionary(grouping: machine.applications, by: \.path)
        for app in machine.applications {
            if !entries.contains(where: { $0.path == app.path && $0.identifier == app.bundleIdentifier }) {
                failures.append("用户与系统侧安装清单已改变，请重新核对")
            }
        }
        for hint in entries {
            if hint.identifier.isEmpty { failures.append("存在标识未确认的用户安装，不能排除共享归属") }
            if SafetyPolicy.contains(applicationsRoot, hint.path) {
                guard machinePaths[hint.path]?.contains(where: { $0.bundleIdentifier == hint.identifier }) == true else {
                    failures.append("用户侧系统安装线索未通过系统范围复查"); continue
                }
                if hint.unresolved && machinePaths[hint.path]?.allSatisfy({ $0.protectedReason == nil }) == true {
                    failures.append("用户侧系统安装的读取状态未确认")
                }
                continue
            }
            // Non-system locations only contribute possible competing owners.
            // The service never opens these paths or promotes them to targets.
            combined.append(.init(path: hint.path, name: hint.identifier, bundleIdentifier: hint.identifier,
                signed: false, protectedReason: "用户侧归属线索，仅用于保留共享对象"))
        }
        return .init(applications: combined, issues: Array(Set(failures)).sorted())
    }
}

/// Per authenticated connection, refreshed before each dependent operation.
/// Storage is shared with that connection's engine only, never across users.
final class UserOwnershipInventoryStore: @unchecked Sendable {
    private let lock = NSLock()
    private var value: UserOwnershipInventory?
    private var receivedAt: TimeInterval = 0
    func replace(_ value: UserOwnershipInventory, uptime: TimeInterval = ProcessInfo.processInfo.systemUptime) throws {
        try value.validate()
        lock.lock(); defer { lock.unlock() }
        self.value = value; receivedAt = uptime
    }
    func current(uptime: TimeInterval = ProcessInfo.processInfo.systemUptime) throws -> UserOwnershipInventory {
        lock.lock(); defer { lock.unlock() }
        guard let value, uptime >= receivedAt, uptime - receivedAt <= 120 else {
            throw SweepError.incomplete("缺少当前用户侧归属核对，请重新扫描或核对计划")
        }
        return value
    }
}
