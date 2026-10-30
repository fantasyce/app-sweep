import Foundation
import CFSafety

enum FirefoxFormatRule {
    static let name = "firefox-cache2-plaintext4-v1"
    static func verify(_ path: String, home: String, applicationPath: String, signaturePath: String? = nil) throws {
        guard let leaf = FirefoxRule.cacheLeaf(path, home: home), let architecture = PlatformStamp.current?.architecture else { throw SweepError.denied("不是已识别的 Firefox 配置档缓存") }
        let signed = signaturePath ?? applicationPath
        guard AppInspector.signatureMatches(path: signed, identifier: "org.mozilla.firefox"), AppInspector.signedByTeam(path: signed, team: "43AQ936H96") else { throw SweepError.denied("Firefox 官方签名未确认") }
        let data = try FirefoxRule.metadata(signed + "/Contents/Info.plist", requireOwner: false)
        guard let info = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { throw SweepError.denied("Firefox 应用元数据未知") }
        var installed = false
        for identifier in FirefoxRule.helperIdentifiers {
            if try SafeFilesystem.presence("/Library/PrivilegedHelperTools/" + identifier) { installed = true }
            if try SafeFilesystem.presence("/Library/LaunchDaemons/" + identifier + ".plist") { installed = true }
        }
        guard try FirefoxRule.cacheOnlyHelpersAllowed(info, installed: installed, systemExtensions: SafeFilesystem.presence(signed + "/Contents/Library/SystemExtensions")) else { throw SweepError.denied("辅助组件已安装或未确认，仅报告缓存") }
        let app = try FirefoxRule.metadata(signed + "/Contents/Resources/application.ini", requireOwner: false)
        let platform = try FirefoxRule.metadata(signed + "/Contents/Resources/platform.ini", requireOwner: false)
        let profileRoot = home + "/Library/Application Support/Firefox"
        guard FirefoxRule.ini(app)?["App"]?["Version"] == info["CFBundleShortVersionString"] as? String,
              try FirefoxRule.registeredLeaves(home: home).contains(leaf),
              compatible(try FirefoxRule.metadata(profileRoot + "/Profiles/" + leaf + "/compatibility.ini"), application: app, platform: platform, applicationPath: applicationPath, architecture: architecture) else { throw SweepError.denied("注册配置档与当前签名应用的构建或架构不一致") }
        let snapshot = try SafeFilesystem.snapshot(path)
        guard snapshot.identity.isDirectory, snapshot.identity.owner == as_current_uid(),
              snapshot.tree.allSatisfy({ $0.identity.owner == as_current_uid() }),
              FirefoxRule.cacheLayout(snapshot.tree.map { ($0.relative, $0.identity.isDirectory) }) else { throw SweepError.denied("Firefox 缓存含未知内容，保留") }
        var total: Int64 = 0, responses = 0
        let deadline = ProcessInfo.processInfo.systemUptime + 5
        for entry in snapshot.tree where !entry.identity.isDirectory {
            try Task.checkCancellation()
            total += entry.identity.size
            guard total <= 64 * 1024 * 1024, ProcessInfo.processInfo.systemUptime < deadline else { throw SweepError.incomplete("缓存格式扫描超时或超出本批验证容量") }
            let bytes = try SafeFilesystem.readMetadata(path + "/" + entry.relative, maximumBytes: 16 * 1024 * 1024)
            if entry.relative.hasPrefix("entries/") {
                guard FirefoxCacheFormat.permits(bytes, filename: URL(fileURLWithPath: entry.relative).lastPathComponent) else { throw SweepError.denied("缓存响应包含未知、加密、固定或损坏的格式，保留") }
                responses += 1
            } else {
                guard FirefoxCacheFormat.indexPermits(bytes, journal: entry.relative == "index.log") else { throw SweepError.denied("缓存索引或日志格式未确认，保留") }
            }
        }
        guard responses > 0 else { throw SweepError.denied("当前没有已确认的 HTTP 缓存响应") }
        try SafeFilesystem.verify(snapshot)
    }
    static func compatible(_ profile: Data, application: Data, platform: Data, applicationPath: String, architecture: String) -> Bool {
        guard let abi = ["arm64": "Darwin_aarch64-gcc3", "x86_64": "Darwin_x86_64-gcc3"][architecture],
              let app = FirefoxRule.ini(application)?["App"], let build = FirefoxRule.ini(platform)?["Build"],
              let version = app["Version"], !version.isEmpty, version.utf8.count <= 64,
              version.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [46,45].contains($0) }),
              let appBuild = app["BuildID"], let platformBuild = build["BuildID"],
              [appBuild, platformBuild].allSatisfy({ $0.utf8.count == 14 && $0.utf8.allSatisfy { (48...57).contains($0) } }),
              let values = FirefoxRule.ini(profile)?["Compatibility"] else { return false }
        return values["LastVersion"] == version + "_" + appBuild + "/" + platformBuild && values["LastOSABI"] == abi &&
            values["LastPlatformDir"] == applicationPath + "/Contents/Resources" &&
            values["LastAppDir"] == applicationPath + "/Contents/Resources/browser"
    }
}
