import Foundation
#if os(macOS)
import CoreServices
#endif

/// Public registration metadata adds discovery/conflict hints. It never grants
/// filesystem authority, and stale registrations never create fictional apps.
enum ApplicationRegistry {
    typealias Lookup = (String) throws -> [URL]
    struct Location: Hashable { let identifier: String; let path: String }
    static func systemLocations(_ identifier: String) throws -> [URL] {
        guard AppInspector.validIdentifier(identifier) else { throw SweepError.invalid("注册查询标识无效") }
        #if os(macOS)
        var failure: Unmanaged<CFError>?
        let found = LSCopyApplicationURLsForBundleIdentifier(identifier as CFString, &failure)
        let error = failure?.takeRetainedValue()
        if let found {
            guard error == nil, let urls = found.takeRetainedValue() as? [URL] else { throw SweepError.incomplete("应用注册信息无效，归属未确认") }
            return urls
        }
        if let error, CFErrorGetDomain(error) == kCFErrorDomainOSStatus, CFErrorGetCode(error) == Int(kLSApplicationNotFoundErr) { return [] }
        throw SweepError.incomplete("应用注册查询失败，不能视为没有其他安装")
        #else
        throw SweepError.incomplete("当前平台没有已验证的应用注册查询")
        #endif
    }
    static func locations(identifiers: Set<String>, lookup: Lookup = systemLocations) throws -> [Location] {
        guard identifiers.count <= 10_000, identifiers.allSatisfy(AppInspector.validIdentifier) else { throw SweepError.incomplete("应用注册查询范围无效或超限") }
        let deadline = ProcessInfo.processInfo.systemUptime + 20
        var result = Set<Location>()
        for identifier in identifiers.sorted() {
            try Task.checkCancellation()
            let urls = try lookup(identifier)
            guard ProcessInfo.processInfo.systemUptime < deadline, urls.count <= 10_000 else { throw SweepError.incomplete("应用注册查询超时或截断") }
            for url in urls {
                let path = url.path
                guard url.isFileURL, url.host == nil || url.host == "localhost", path.hasPrefix("/"), path.utf8.count <= 4096,
                      !path.contains("\0"), path != "/", path == url.standardizedFileURL.path,
                      !path.split(separator: "/").contains(where: { $0 == "." || $0 == ".." }) else { throw SweepError.incomplete("应用注册位置未确认") }
                // A moved bundle may be registered under our UUID recovery name.
                // Keep its exact URL as a conflict hint. Executable discovery still
                // applies SelectedApplicationRule; this does not authorize the URL.
                result.insert(Location(identifier: identifier, path: path))
                guard result.count <= 10_000 else { throw SweepError.incomplete("应用注册结果截断") }
            }
        }
        return result.sorted { ($0.path, $0.identifier) < ($1.path, $1.identifier) }
    }
}
