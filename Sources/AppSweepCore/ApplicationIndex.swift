import Foundation
import CFSafety
#if os(macOS)
import Darwin
#endif

/// Supplemental discovery only. Index absence is never proof of file absence.
enum ApplicationIndex {
    typealias Lookup = @Sendable (String) throws -> [String]
    static func systemPaths(home: String) throws -> [String] {
        let root = try SafeDirectory(path: home)
        guard try root.ownIdentity.owner == as_current_uid() else { throw SweepError.denied("应用索引范围不是当前用户拥有的目录") }
        return try query(home:home)
    }
    /// A service can discover only the home bound to its authenticated peer,
    /// never a UID or path decoded from the request body.
    static func systemPaths(for user: AuthenticatedUserContext) throws -> [String] {
        #if os(macOS)
        guard getuid() == geteuid(), geteuid() == 0 || geteuid() == user.uid else { throw SweepError.denied("应用索引账户不是已认证请求账户") }
        try user.verifyUnchanged()
        guard try SafeDirectory(path:user.home).ownIdentity.owner == user.uid else { throw SweepError.denied("已认证应用索引目录所有者已改变") }
        let result = try query(home:user.home)
        try user.verifyUnchanged()
        return result
        #else
        throw SweepError.incomplete("当前平台未验收已认证用户应用索引")
        #endif
    }
    private static func query(home: String) throws -> [String] {
        let output = try BoundedProcess.run("/usr/bin/mdfind", arguments: ["-0", "-onlyin", home, "kMDItemContentTypeTree == \"com.apple.application-bundle\""], timeout: 5)
        try Task.checkCancellation()
        return try paths(output, home: home)
    }
    static func paths(_ output: String, home: String) throws -> [String] {
        guard !home.isEmpty, home != "/", home.hasPrefix("/"), output.utf8.count <= 2 * 1024 * 1024,
              output.isEmpty || output.last == "\0" else { throw SweepError.incomplete("应用索引结果截断或格式未确认") }
        let values = output.split(separator: "\0", omittingEmptySubsequences: true).map(String.init)
        guard values.count <= 10_000 else { throw SweepError.incomplete("应用索引结果超限") }
        for path in values {
            guard path.utf8.count <= 4096, SafetyPolicy.contains(home, path),
                  path == URL(fileURLWithPath: path).standardizedFileURL.path else { throw SweepError.incomplete("应用索引位置未确认") }
        }
        // Spotlight may classify ordinary service storage as an application
        // bundle. Such canonical in-scope metadata hits are irrelevant hints;
        // they must not discard every independently inspectable app result.
        return Array(Set(values.filter { $0.hasSuffix(".app") })).sorted()
    }
}
struct ApplicationInventory: Sendable {
    let applications: [ApplicationIdentity]
    let issues: [String]
}
