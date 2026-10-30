import Foundation
import CFSafety
#if os(macOS)
import Darwin
#endif

struct PlatformStamp: Codable, Sendable, Hashable {
    let major: Int
    let minor: Int
    let patch: Int
    let build: String
    let architecture: String
    static var current: PlatformStamp? {
        #if os(macOS)
        var bytes = [UInt8](repeating: 0, count: 128); var count = bytes.count
        let result = bytes.withUnsafeMutableBytes { sysctlbyname("kern.osversion", $0.baseAddress, &count, nil, 0) }
        guard result == 0, count > 1, count <= bytes.count, let build = String(bytes: bytes.prefix(count - 1), encoding: .utf8) else { return nil }
        let version = ProcessInfo.processInfo.operatingSystemVersion
        #if arch(arm64)
        let architecture = "arm64"
        #elseif arch(x86_64)
        let architecture = "x86_64"
        #else
        return nil
        #endif
        return PlatformStamp(major: version.majorVersion, minor: version.minorVersion, patch: version.patchVersion, build: build, architecture: architecture)
        #else
        return nil
        #endif
    }
}
enum NativeAcceptance {
    // Candidate matrix from independent native rule acceptance. Delivery additionally
    // requires the packaged candidate's workflow, reboot and accessibility report.
    // JSON, environment variables and CLI flags cannot change these compiled limits.
    private static let arm = PlatformStamp(major: 27, minor: 0, patch: 1, build: "26A434", architecture: "arm64")
    private static let intel = PlatformStamp(major: 13, minor: 7, patch: 8, build: "22H730", architecture: "x86_64")
    private static let common: Set<String> = [ChosenApplicationRule.name, ChosenApplicationRule.largeName, SelectedApplicationRule.name, SupportDomainRule.name, CacheDomainRule.name, LegacyCrashRule.name, "signed-application-v1", "cfpreferences-exact-domain-v1", "ips-third-party-30d-v1"]
    static let platforms: [PlatformStamp] = [arm, intel]
    // ARM optimization transactions have independent native consumer evidence;
    // their ordinary packaged UI remains a candidate acceptance requirement.
    static let validatedRules: [PlatformStamp: Set<String>] = [arm: common.union([FirefoxRule.name, FirefoxFormatRule.name, CacheRule.name, ApplicationLogRule.name, XcodeRule.name, PreferenceRecoveryRecord.rule, ApplicationOptimizationEngine.rule, ApplicationOptimizationEngine.languageRule, ApplicationOptimizationEngine.purgeRule, GodotCacheRule.name, UserCacheNamespaceRule.name, ApplicationLogRule.currentName, ApplicationCacheRule.appleName, ApplicationCacheRule.containerName, XcodeGeneratedRule.name, DarwinCacheRule.name, XcodeArchiveRule.name, XcodeDeviceSupportRule.name, ContainerDataRule.name, ApplicationScriptsRule.name,ApplicationGroupRule.name, StaleUserAgentRule.name, CorruptPreferenceRule.name, DeviceBackupRule.name, DeviceBackupRule.largeName, DocumentVersionRule.name, ApplicationAgentRule.name, SimulatorCacheRule.name, ToolCacheRule.name, ChromiumCacheRule.name, ChromiumProfileRule.name, LocalizedResourceReader.name]), intel: common]
    static func matches(_ stamp: PlatformStamp, accepted: [PlatformStamp]) -> Bool { accepted.contains(stamp) }
    static func rules(for stamp: PlatformStamp?) -> Set<String> {
        guard let stamp else{return []}
        var rules=validatedRules[stamp] ?? []
        // 2026-10-28: host publisher/namespace checks, native owned-cache
        // transaction and opt-in data journal/link regressions. WebKit C-cache
        // additionally passed shared junk/uninstall discovery, native recovery,
        // unique-owner and path-boundary checks. Intel unchanged.
        // Homebrew: real producer fetch, isolation, regeneration, conflict-safe
        // recovery and reuse of the restored original passed on this ARM host.
        // Generic HTTP/WebKit user data passed native opt-in and recovery checks.
        // npm and pnpm additionally passed independent producer regeneration and
        // reuse after byte-identical fresh-engine recovery on this ARM host.
        if stamp == arm {rules.formUnion([NamedApplicationRule.cacheName,NamedApplicationRule.dataName,WebKitCacheRule.name,ToolCacheRule.homebrewName,ApplicationStorageRule.name,ToolCacheRule.npmName,ToolCacheRule.pnpmName])}
        // Increment 49: independent native download transactions plus official
        // checksum-pinned upstream producer regeneration/offline reuse; exact T
        // blob transactions plus the current OS WebKit producer's regeneration.
        // These are backend results, not packaged UI/service acceptance.
        if stamp == arm {rules.formUnion([DownloadCacheRule.electronName,DownloadCacheRule.builderName,WebKitTemporaryRule.name])}
        // 2026-10-29: official Trivy producer download/regeneration, collision
        // protection, byte-identical recovery and offline database consumer.
        if stamp == arm {rules.insert(TrivyCacheRule.name)}
        // 2026-10-30: native manual-selection, real move, fresh-engine restore,
        // conflict/ACL/metadata/activity and out-of-scope preservation checks.
        // Personal data stays opt-in; the fixed diagnostic log stays manual.
        if stamp == arm {rules.formUnion([TrashEntryRule.name,MailDownloadRule.name,AIStorageRule.name,AIDiagnosticRule.name])}
        return rules
    }
    // Compiled ARM candidates. Cache/log root transactions have prior native
    // evidence; the archive root path and the final signed helper/ordinary GUI
    // must additionally pass the packaged candidate acceptance before delivery.
    static func systemRules(for stamp: PlatformStamp?) -> Set<String> {
        guard stamp == arm else { return [] }
        return [SystemDiagnosticRule.name, SystemDomainRule.cacheName, SystemDomainRule.logName, SystemDomainRule.currentLogName, DeletedUserArchiveRule.name,InstalledSystemHelperRule.name]
    }
}
enum SystemIdentity {
    static func home() throws -> String {
        var bytes = [CChar](repeating: 0, count: 4096)
        guard as_home_directory(&bytes, bytes.count) == 0 else { throw SweepError.denied("当前用户目录未确认") }
        let data = bytes.withUnsafeBytes { Data($0.prefix { $0 != 0 }) }
        guard let home = String(data: data, encoding: .utf8), home.hasPrefix("/"), home != "/" else { throw SweepError.denied("当前用户目录无效") }
        return home
    }
}
