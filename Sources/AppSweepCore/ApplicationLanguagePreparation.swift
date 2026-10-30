#if os(macOS)
import Foundation
import CoreFoundation
import Darwin
import CFSafety

/// Preparation proof only; it does not authorize publishing or changing an installed app.
enum ApplicationLanguagePreparation {
    struct Plan: Sendable {
        let source: FileSnapshot
        let omitted: [TreeEntry]
        let retained: [String]
        let identifier: String
        let architecture: String
        let nativeCodeHash: String
        let retainedFamilies: Set<String>
        var availableLanguages: [String] {
            let names = source.tree.compactMap { entry -> String? in
                guard entry.identity.isDirectory, entry.relative.hasPrefix(ApplicationLanguagePreparation.prefix) else { return nil }
                let name = entry.relative.dropFirst(ApplicationLanguagePreparation.prefix.count)
                guard !name.contains("/"), name.hasSuffix(".lproj") else { return nil }
                let language = String(name.dropLast(6))
                return ApplicationLanguagePreparation.family(language) == nil ? nil : language
            }
            return Array(Set(names)).sorted()
        }
        fileprivate init(source: FileSnapshot, omitted: [TreeEntry], retained: [String], identifier: String,
                         architecture: String, nativeCodeHash: String, retainedFamilies: Set<String>) {
            self.source = source; self.omitted = omitted; self.retained = retained
            self.identifier = identifier; self.architecture = architecture
            self.nativeCodeHash = nativeCodeHash; self.retainedFamilies = retainedFamilies
        }
        func verify(_ current: FileSnapshot) throws {
            guard current.path == source.path, current.identity == source.identity, current.ancestors == source.ancestors,
                  current.tree == source.tree, current.bytes == source.bytes, current.purpose == .application,
                  current.allowInternalLinks == source.allowInternalLinks,
                  current.allowInternalHardLinks == source.allowInternalHardLinks, current.hardLinkContext == nil else {
                throw SweepError.stale("语言分析与完整应用快照不一致")
            }
            try SafeFilesystem.verify(current)
        }
    }
    struct Result: Sendable { let snapshot: FileSnapshot; let savedBytes: Int64 }
    private static let prefix = "Contents/Resources/"
    private static func family(_ language: String) -> String? {
        if language == "English" { return "en" }
        let parts = language.replacingOccurrences(of:"_",with:"-").split(separator:"-",omittingEmptySubsequences:false)
        guard !parts.isEmpty, parts.count <= 8, language.utf8.count <= 64,
              parts.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 8 && $0.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) } }),
              let first = parts.first?.lowercased(), Locale.isoLanguageCodes.contains(first) else { return nil }
        return first
    }
    static func analyze(_ source: FileSnapshot, retaining languages: [String]) throws -> Plan {
        try Task.checkCancellation()
        guard getuid() != 0, getuid() == geteuid(), source.purpose == .application,
              source.identity.isDirectory, source.identity.owner == getuid(), source.hardLinkContext == nil,
              source.tree.allSatisfy({ $0.identity.owner == getuid() && $0.identity.device == source.identity.device }),
              !languages.isEmpty, languages.count <= 64 else { throw SweepError.denied("语言准备需要完整应用快照及明确的保留语言") }
        var families = Set<String>(["en"])
        for language in languages {
            guard let value = family(language) else { throw SweepError.denied("首选语言未确认，不能生成语言精简计划") }
            families.insert(value)
        }
        try ContainedHardLinks.validate(source.tree); try SafeFilesystem.verify(source)
        let deadline = ProcessInfo.processInfo.systemUptime + 300
        func check() throws {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw SweepError.incomplete("语言资源分析超时，原包保留") }
        }
        let (info,_) = try AppInspector.metadata(source.path,component:false)
        guard let identifier = info["CFBundleIdentifier"] as? String, AppInspector.validIdentifier(identifier),
              let development = info["CFBundleDevelopmentRegion"] as? String, let developmentFamily = family(development) else {
            throw SweepError.denied("应用标识或开发语言未确认，保留全部语言资源")
        }
        families.insert(developmentFamily)
        try ChosenApplicationRule.verifyStored(path:source.path,identifier:identifier)
        let architecture = try ApplicationArchitecturePreparation.nativeArchitecture().0
        let hash = try ApplicationArchitecturePreparation.signature(source.path,identifier:identifier,architecture:architecture)
        let sealPath = source.path + "/Contents/_CodeSignature/CodeResources"
        guard let sealEntry = source.tree.first(where:{ $0.relative == "Contents/_CodeSignature/CodeResources" }),
              sealEntry.identity.mode & 0o170000 == 0o100000, sealEntry.identity.links == 1,
              try SafeFilesystem.snapshot(sealPath).identity == sealEntry.identity else { throw SweepError.incomplete("应用资源封印身份未确认") }
        let seal = try PropertyListSerialization.propertyList(from:SafeFilesystem.readMetadata(sealPath,maximumBytes:16*1024*1024),format:nil)
        guard let object = seal as? [String:Any], let files = object["files2"] as? [String:Any], files.count <= TreeFingerprint.maximumEntries else {
            throw SweepError.incomplete("语言资源缺少已确认的新版封印")
        }
        var groups: [String:[TreeEntry]] = [:]
        for entry in source.tree where entry.relative.hasPrefix(prefix) {
            try check()
            let rest = entry.relative.dropFirst(prefix.count), parts = rest.split(separator:"/")
            guard let first = parts.first, first.hasSuffix(".lproj") else { continue }
            groups[prefix + first,default:[]].append(entry)
        }
        guard groups.count <= 256 else { throw SweepError.incomplete("语言资源分组超过检查上限") }
        // Language codes are not the complete fallback graph (for example,
        // macOS can serve no.lproj for nb-NO or nn-NO). Ask Foundation about
        // each available group independently so an exact match in a different
        // group cannot hide a fallback. English provides a known no-match
        // alternative; native negotiation may only expand retention.
        for group in groups.keys.sorted() {
            let language = String(group.dropFirst(prefix.count).dropLast(6))
            guard let value = family(language), !families.contains(value) else { continue }
            for preferred in languages + [development,"en"] {
                try check()
                let selected = Bundle.preferredLocalizations(from:["en",language],forPreferences:[preferred,"en"])
                if selected.contains(language) { families.insert(value); break }
            }
        }
        let links = try linkTargets(source)
        var omitted: [TreeEntry] = [], retained: [String] = []
        for (group,entries) in groups.sorted(by:{ $0.key < $1.key }) {
            try check()
            let language = String(group.dropFirst(prefix.count).dropLast(6))
            var reason: String?
            if language == "Base" { reason = "基础资源永久保留" }
            else if let value = family(language) {
                if families.contains(value) { reason = "保留首选、开发、系统回退语言及同语言地区变体" }
            } else { reason = "语言名称未确认，保留" }
            if reason == nil {
                guard entries.contains(where:{ $0.relative == group && $0.identity.isDirectory }) else {
                    retained.append(group + "：不是已确认的语言目录"); continue
                }
                let absolute = source.path + "/" + group
                if links.contains(where:{ SafetyPolicy.contains($0,absolute) || SafetyPolicy.contains(absolute,$0) }) {
                    reason = "存在包内链接引用，整组保留"
                }
                for entry in entries where reason == nil {
                    try check()
                    if entry.identity.isDirectory { continue }
                    guard entry.identity.mode & 0o170000 == 0o100000, entry.identity.links == 1,
                          entry.identity.mode & 0o7111 == 0 else { reason = "包含链接、可执行或特殊节点，整组保留"; break }
                    let key = String(entry.relative.dropFirst("Contents/".count))
                    guard let record = files[key] as? [String:Any], let optional = record["optional"] as? NSNumber,
                          CFGetTypeID(optional) == CFBooleanGetTypeID(), optional.boolValue,
                          (record["hash"] as? Data)?.count == 20 || (record["hash2"] as? Data)?.count == 32,
                          record["symlink"] == nil, record["cdhash"] == nil, record["requirement"] == nil else {
                        reason = "存在必需、代码或未知封印资源，整组保留"; break
                    }
                    if try hasCodeHeader(entry,source:source) { reason = "存在代码格式资源，整组保留" }
                }
            }
            if let reason { retained.append(group + "：" + reason) } else { omitted += entries }
        }
        guard omitted.contains(where:{ $0.identity.mode & 0o170000 == 0o100000 && $0.identity.size > 0 }) else {
            throw SweepError.invalid("没有可独立准备的可选语言资源")
        }
        try check(); try SafeFilesystem.verify(source)
        return Plan(source:source,omitted:omitted.sorted { $0.relative < $1.relative },retained:retained,
                    identifier:identifier,architecture:architecture,nativeCodeHash:hash,retainedFamilies:families)
    }
    static func prepare(_ plan: Plan, in parent: SafeDirectory, name: String) throws -> Result {
        try plan.verify(plan.source)
        guard try ApplicationArchitecturePreparation.nativeArchitecture().0 == plan.architecture,
              try ApplicationArchitecturePreparation.signature(plan.source.path,identifier:plan.identifier,architecture:plan.architecture) == plan.nativeCodeHash else {
            throw SweepError.stale("原始应用签名或执行架构已经改变")
        }
        let copied = try ApplicationTreeCopy.prepare(plan.source,in:parent,name:name,languagePlan:plan)
        guard try ApplicationArchitecturePreparation.signature(copied.path,identifier:plan.identifier,architecture:plan.architecture) == plan.nativeCodeHash else {
            throw SweepError.stale("语言准备包的原厂代码签名不一致；两份对象均保留")
        }
        try plan.verify(plan.source); try SafeFilesystem.verify(copied)
        return Result(snapshot:copied,savedBytes:plan.source.bytes-copied.bytes)
    }
    private static func hasCodeHeader(_ entry: TreeEntry, source: FileSnapshot) throws -> Bool {
        let url = URL(fileURLWithPath:source.path + "/" + entry.relative), parent = try SafeDirectory(path:url.deletingLastPathComponent().path)
        let fd = openat(parent.fd,url.lastPathComponent,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)
        guard fd >= 0 else { throw SweepError.incomplete("无法确认语言资源内容类型") }
        defer { as_close(fd) }
        var identity = ASIdentity(), bytes = [UInt8](repeating:0,count:4)
        guard as_identity_fd(fd,&identity) == 0, FileIdentity(identity) == entry.identity else { throw SweepError.stale("语言资源身份改变") }
        let count = bytes.withUnsafeMutableBytes { buffer in
            pread(fd,buffer.baseAddress,buffer.count,0)
        }
        guard count == min(4,entry.identity.size), as_identity_fd(fd,&identity) == 0, FileIdentity(identity) == entry.identity,
              try parent.identity(url.lastPathComponent) == entry.identity else { throw SweepError.stale("语言资源读取未确认") }
        if count >= 2, bytes[0] == 35, bytes[1] == 33 { return true }
        guard count == 4 else { return false }
        let magic = bytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        return [0xfeedface,0xcefaedfe,0xfeedfacf,0xcffaedfe,0xcafebabe,0xbebafeca,0xcafebabf,0xbfbafeca,0x7f454c46].contains(magic)
    }
    private static func linkTargets(_ source: FileSnapshot) throws -> [String] {
        var targets: [String] = []
        for entry in source.tree where entry.identity.isLink {
            try Task.checkCancellation()
            let url = URL(fileURLWithPath:source.path + "/" + entry.relative), parent = try SafeDirectory(path:url.deletingLastPathComponent().path)
            guard try parent.identity(url.lastPathComponent) == entry.identity else { throw SweepError.stale("包内链接身份改变") }
            var bytes = [UInt8](repeating:0,count:4097)
            let count = bytes.withUnsafeMutableBytes { buffer in
                readlinkat(parent.fd,url.lastPathComponent,buffer.baseAddress!.assumingMemoryBound(to:CChar.self),buffer.count)
            }
            guard count > 0, count <= 4096, let target = String(bytes:bytes.prefix(count),encoding:.utf8), !target.contains("\0"),
                  try parent.identity(url.lastPathComponent) == entry.identity else { throw SweepError.incomplete("包内链接内容未确认") }
            let absolute = target.hasPrefix("/") ? target : parent.path + "/" + target
            targets.append(URL(fileURLWithPath:absolute).standardizedFileURL.path)
        }
        return targets
    }
}
#endif
