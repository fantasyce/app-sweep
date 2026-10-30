import Foundation
import CFSafety
import Darwin

/// Producer-documented downloads, independently recognized without executing
/// their contents. Mutable environments (notably Wine prefixes) are excluded.
enum DownloadCacheRule {
    static let electronName = "development-electron-download-v1"
    static let builderName = "development-builder-toolset-v1"
    private static let version = #"[0-9]+(?:\.[0-9]+){1,3}(?:-[A-Za-z0-9.]+)?"#
    private static func matches(_ value: String, _ pattern: String) -> Bool {
        value.range(of: "^(?:" + pattern + ")$", options: .regularExpression) != nil
    }
    static func electronArchive(_ leaf: String) -> Bool {
        matches(leaf, "electron-v" + version + #"-(?:darwin|mas|linux|win32)-(?:arm64|armv7l|x64|ia32)\.zip"#)
    }
    static func location(_ path: String, home: String) -> (root: String, producer: ToolCacheRule.Producer)? {
        let url = URL(fileURLWithPath: path), parent = url.deletingLastPathComponent().path, leaf = url.lastPathComponent
        let cache = home + "/Library/Caches/"
        if parent == cache + "electron", electronArchive(leaf) || matches(leaf, "[0-9a-f]{64}") { return (parent, .electron) }
        let builder = cache + "electron-builder"
        if parent == builder, matches(leaf, #"(?:nsis|nsis-resources|winCodeSign|7zip|appimage|fpm|squirrel\.windows)@"# + version) { return (parent, .electronBuilder) }
        if parent == builder + "/nsis", matches(leaf, "nsis(?:-resources)?-" + version + "(?:-nsis(?:-resources)?-" + version + ")?") { return (parent, .electronBuilder) }
        if parent == builder + "/winCodeSign", matches(leaf, "winCodeSign-" + version) { return (parent, .electronBuilder) }
        return nil
    }
    static func isFile(_ path: String) -> Bool { electronArchive(URL(fileURLWithPath: path).lastPathComponent) }
    /// Read only a bounded prefix through a verified descriptor. Archive payloads
    /// can be large; never load or extract them to decide whether they are caches.
    private static func prefix(_ path: String, identity: FileIdentity) throws -> [UInt8] {
        guard identity.mode & 0o170000 == 0o100000, identity.links == 1, identity.size >= 4 else { throw SweepError.denied("下载对象不是完整普通文件") }
        let url = URL(fileURLWithPath: path), parent = try SafeDirectory(path: url.deletingLastPathComponent().path)
        let fd = openat(parent.fd, url.lastPathComponent, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw SweepError.denied("下载对象无法安全读取") }
        defer { as_close(fd) }
        var raw = ASIdentity(), bytes = [UInt8](repeating: 0, count: min(64, Int(identity.size)))
        guard as_identity_fd(fd, &raw) == 0, FileIdentity(raw) == identity,
              pread(fd, &bytes, bytes.count, 0) == bytes.count,
              as_identity_fd(fd, &raw) == 0, FileIdentity(raw) == identity,
              try parent.identity(url.lastPathComponent) == identity else { throw SweepError.stale("下载对象读取时已改变") }
        return bytes
    }
    private static func archive(_ path: String, identity: FileIdentity) throws -> Bool {
        let bytes = try prefix(path, identity: identity)
        if path.hasSuffix(".zip") { return identity.size >= 22 && Array(bytes.prefix(4)) == [0x50,0x4b,3,4] }
        if path.hasSuffix(".7z") { return identity.size >= 32 && Array(bytes.prefix(6)) == [0x37,0x7a,0xbc,0xaf,0x27,0x1c] }
        if path.hasSuffix(".tar.gz") { return identity.size >= 18 && Array(bytes.prefix(3)) == [0x1f,0x8b,8] }
        return false
    }
    static func verify(_ path: String, home: String, producer: ToolCacheRule.Producer) throws -> FileSnapshot {
        let snapshot = try SafeFilesystem.snapshot(path, allowInternalLinks: producer == .electronBuilder)
        try ContainerDataRule.verifyPrivateTree(snapshot, home: home)
        guard snapshot.identity.device == (try SafeDirectory(path: home).ownIdentity.device) else { throw SweepError.denied("下载缓存跨卷") }
        if !snapshot.identity.isDirectory {
            guard producer == .electron, isFile(path), try archive(path, identity: snapshot.identity) else { throw SweepError.denied("不是已完成的 Electron 下载归档") }
        } else if producer == .electron {
            guard !snapshot.tree.isEmpty else { throw SweepError.denied("空下载目录") }
            for node in snapshot.tree {
                guard !node.relative.contains("/"), electronArchive(node.relative), try archive(path + "/" + node.relative, identity: node.identity) else { throw SweepError.denied("Electron 下载目录包含未确认内容") }
            }
        } else {
            try verifyBuilder(snapshot)
        }
        try SafeFilesystem.verify(snapshot)
        return snapshot
    }
    private static func verifyBuilder(_ snapshot: FileSnapshot) throws {
        let path = snapshot.path, leaf = URL(fileURLWithPath: path).lastPathComponent
        guard !snapshot.tree.isEmpty, !snapshot.tree.contains(where: { node in
            let name = URL(fileURLWithPath: node.relative).lastPathComponent.lowercased()
            return ["wine-home",".git","node_modules"].contains(name) || [".p12",".pfx",".pem",".key"].contains { name.hasSuffix($0) }
        }) else { throw SweepError.denied("构建工具目录含环境状态、凭据或未知资料") }
        for node in snapshot.tree where node.identity.isLink {
            let url = URL(fileURLWithPath: path + "/" + node.relative), parent = try SafeDirectory(path: url.deletingLastPathComponent().path)
            var bytes = [UInt8](repeating: 0, count: 4096)
            let count = readlinkat(parent.fd, url.lastPathComponent, &bytes, bytes.count)
            guard count > 0, count < bytes.count, let target = String(bytes: bytes.prefix(count), encoding: .utf8), !target.hasPrefix("/"),
                  SafetyPolicy.contains(path, URL(fileURLWithPath: url.deletingLastPathComponent().path + "/" + target).standardizedFileURL.path),
                  try parent.identity(url.lastPathComponent) == node.identity else { throw SweepError.denied("构建工具链接离开独立下载目录") }
        }
        if leaf.contains("@") {
            let family = String(leaf.prefix { $0 != "@" })
            for node in snapshot.tree {
                guard !node.relative.contains("/"), node.relative.hasPrefix(family + "-"), try archive(path + "/" + node.relative, identity: node.identity) else { throw SweepError.denied("构建工具下载格式尚未确认") }
            }
            return
        }
        let files = snapshot.tree.filter { !$0.identity.isDirectory }
        for node in snapshot.tree {
            if node.identity.isDirectory {
                guard files.contains(where: { $0.relative.hasPrefix(node.relative + "/") && legacyMember($0.relative, family: leaf) }) else { throw SweepError.denied("构建工具包含未登记的目录，整项保留") }
            } else {
                guard legacyMember(node.relative, family: leaf) else { throw SweepError.denied("构建工具包含未登记资料，整项保留") }
                if URL(fileURLWithPath: node.relative).lastPathComponent == ".DS_Store" {
                    let bytes = try prefix(path + "/" + node.relative, identity: node.identity)
                    guard Array(bytes.prefix(8)) == [0,0,0,1,0x42,0x75,0x64,0x31] else { throw SweepError.denied("工具目录中的 Finder 元数据格式未确认") }
                }
            }
        }
        let anchors: [String]
        if leaf.hasPrefix("nsis-resources-") {
            anchors = snapshot.tree.filter { $0.relative.hasPrefix("plugins/") && $0.relative.hasSuffix(".dll") }.map(\.relative)
        } else if leaf.hasPrefix("nsis-") { anchors = ["mac/makensis"] }
        else { anchors = ["rcedit-x64.exe", "darwin/osslsigncode"] }
        guard !anchors.isEmpty else { throw SweepError.denied("构建工具的原生格式标记缺失") }
        for relative in anchors {
            guard let entry = snapshot.tree.first(where: { $0.relative == relative }) else { throw SweepError.denied("构建工具下载不完整") }
            let bytes = try prefix(path + "/" + relative, identity: entry.identity)
            let signature = Array(bytes.prefix(4))
            guard Array(bytes.prefix(2)) == [0x4d,0x5a] || [[0xcf,0xfa,0xed,0xfe],[0xce,0xfa,0xed,0xfe],[0xca,0xfe,0xba,0xbe]].contains(signature) else { throw SweepError.denied("构建工具二进制格式不匹配") }
        }
    }
    /// Independent producer-layout grammar, not a list of installed apps or a
    /// blacklist of personal filenames. Every extracted file must be accounted
    /// for; new layouts are retained until separately validated.
    private static func legacyMember(_ path: String, family: String) -> Bool {
        if URL(fileURLWithPath:path).lastPathComponent == ".DS_Store" {
            // Finder metadata is ancillary only inside an established subtree.
            if !path.contains("/") { return true }
            let parent = path.split(separator: "/").dropLast().joined(separator: "/")
            if family.hasPrefix("nsis-resources-") { return matches(parent, #"plugins(?:/(?:x86|x64)-(?:ansi|unicode))?"#) }
            return false
        }
        let patterns: [String]
        if family.hasPrefix("nsis-resources-") {
            patterns = [#"plugins/(?:x86|x64)-(?:ansi|unicode)/[A-Za-z0-9_-]+\.dll"#]
        } else if family.hasPrefix("nsis-") {
            patterns = [
                #"(?:NSIS|makensis|elevate)\.exe|COPYING|nsisconf\.nsh"#,
                #"(?:mac|linux)/makensis"#,
                #"Bin/(?:makensis\.exe|zlib1\.dll)"#,
                #"Plugins/(?:x86|x64)-(?:ansi|unicode)/[A-Za-z0-9_-]+\.dll"#,
                #"Include/(?:Win/)?[A-Za-z0-9_-]+\.nsh"#,
                #"Stubs/(?:uninst|(?:zlib|bzip2|lzma)(?:_solid)?-x86-(?:ansi|unicode))"#,
                #"Contrib/(?:Modern UI(?: 2)?|zip2exe)(?:/Pages)?/[A-Za-z0-9 _-]+\.(?:nsh|ini)"#,
                #"Contrib/Graphics/(?:Checks|Wizard|Icons|Header)/[A-Za-z0-9_.+-]+\.(?:bmp|ico)"#,
                #"Contrib/UIs/[A-Za-z0-9_-]+\.exe"#,
                #"Contrib/Language files/(?:[A-Za-z0-9 _-]+\.(?:nsh|nlf)|SConscript)"#,
                #"Menu/(?:index\.html|notinstalled\.html|images/(?:header|line|site)\.gif)"#
            ]
        } else {
            patterns = [
                #"rcedit-(?:ia32|x64)\.exe"#,
                #"openssl-(?:ia32|x64)/(?:openssl\.exe|libeay32\.dll|ssleay32\.dll|OpenSSL License\.txt)"#,
                #"windows-(?:6|10)(?:/(?:ia32|x64|arm64))?/[A-Za-z0-9_.-]+\.(?:exe|dll)(?:\.manifest)?"#,
                #"linux/(?:Dockerfile|build\.sh|osslsigncode)"#,
                #"darwin/readme\.md|darwin(?:/(?:ci|[0-9]+\.[0-9]+))?/osslsigncode"#,
                #"darwin/[0-9]+\.[0-9]+/lib/lib(?:crypto|ssl)(?:\.[0-9.]+)?\.(?:a|dylib)"#,
                #"darwin/[0-9]+\.[0-9]+/lib/pkgconfig/(?:openssl|libssl|libcrypto)\.pc"#,
                #"darwin/[0-9]+\.[0-9]+/lib/engines/lib[A-Za-z0-9_-]+\.dylib"#,
                #"appxAssets/SampleAppx\.[0-9]+x[0-9]+\.png"#
            ]
        }
        return patterns.contains { matches(path, $0) }
    }
    static func isNodeRuntime(_ command: String) -> Bool {
        command.range(of: #"^(?:/[^\r\n]+/)?(?:node(?:js)?|bun|deno)(?:\s|$)"#, options: .regularExpression) != nil
    }
    static func isProducer(_ command: String) -> Bool {
        ToolCacheRule.isProducer(command: command, producer: .npm) || ToolCacheRule.isProducer(command: command, producer: .pnpm) ||
        command.range(of: #"(?:^|[\s/])(?:yarn|yarnpkg|electron-builder|app-builder(?:_(?:arm64|amd64))?|makensis|rcedit(?:-x64|-ia32)?(?:\.exe)?|osslsigncode|7za|7zz)(?:\s|$)|/(?:@electron/get|electron-download|electron-builder|app-builder-lib)/|/electron/install\.(?:js|cjs)(?:\s|$)"#, options: .regularExpression) != nil
    }
}
