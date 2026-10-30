#if os(macOS)
import Foundation
import Darwin
import CFSafety

/// Independent preparation only. Neither this analysis nor its private output
/// authorizes replacing an installed bundle or relaxing dependency checks.
enum ApplicationArchitecturePreparation {
    struct Change: Sendable {
        let relative: String
        let originalIdentity: FileIdentity
        let slice: MachOContainerIndex.Slice
        fileprivate init(relative: String, originalIdentity: FileIdentity, slice: MachOContainerIndex.Slice) {
            self.relative = relative; self.originalIdentity = originalIdentity; self.slice = slice
        }
    }
    struct Retained: Sendable {
        let relative: String
        let reason: String
        fileprivate init(relative: String, reason: String) { self.relative = relative; self.reason = reason }
    }
    /// Not Codable: decoded paths/ranges cannot become a preparation proof.
    struct Plan: Sendable {
        let source: FileSnapshot
        let identifier: String
        let architecture: String
        let nativeCodeHash: String
        let changes: [Change]
        let retained: [Retained]
        fileprivate init(source: FileSnapshot, identifier: String, architecture: String, nativeCodeHash: String, changes: [Change], retained: [Retained]) {
            self.source = source; self.identifier = identifier; self.architecture = architecture
            self.nativeCodeHash = nativeCodeHash; self.changes = changes
            self.retained = retained
        }
        func verify(_ current: FileSnapshot) throws {
            guard current.path == source.path, current.identity == source.identity, current.ancestors == source.ancestors,
                  current.tree == source.tree, current.bytes == source.bytes, current.purpose == .application,
                  current.allowInternalLinks == source.allowInternalLinks,
                  current.allowInternalHardLinks == source.allowInternalHardLinks, current.hardLinkContext == nil else {
                throw SweepError.stale("应用精简分析与完整来源快照不一致")
            }
            try SafeFilesystem.verify(current)
        }
    }
    struct Result: Sendable {
        let snapshot: FileSnapshot
        let changes: [Change]
        let savedBytes: Int64
        let architecture: String
        let retained: [Retained]
    }
    static func nativeArchitecture() throws -> (String,UInt32,UInt32) {
        #if arch(arm64)
        return ("arm64",0x0100000c,0)
        #elseif arch(x86_64)
        var translated: Int32 = 0, length = MemoryLayout<Int32>.size
        let result = sysctlbyname("sysctl.proc_translated",&translated,&length,nil,0), failure = errno
        guard (result == 0 && length == MemoryLayout<Int32>.size && translated == 0) || (result != 0 && failure == ENOENT) else {
            throw SweepError.denied("转译进程或本机架构状态未确认，不能选择精简架构")
        }
        return ("x86_64",0x01000007,3)
        #else
        throw SweepError.denied("当前本机架构未验收")
        #endif
    }
    static func analyze(_ source: FileSnapshot) throws -> Plan {
        try Task.checkCancellation()
        guard getuid() != 0, getuid() == geteuid(), source.purpose == .application,
              source.identity.isDirectory, source.identity.owner == getuid(), source.hardLinkContext == nil,
              source.tree.allSatisfy({ $0.identity.owner == getuid() && $0.identity.device == source.identity.device }) else {
            throw SweepError.denied("架构准备要求普通用户所有的完整同卷应用快照")
        }
        try ContainedHardLinks.validate(source.tree)
        try SafeFilesystem.verify(source)
        let deadline = ProcessInfo.processInfo.systemUptime + 300
        let (info,_) = try AppInspector.metadata(source.path,component:false)
        guard let identifier = info["CFBundleIdentifier"]as?String, AppInspector.validIdentifier(identifier),
              let executable = info["CFBundleExecutable"]as?String else { throw SweepError.denied("应用标识或入口未确认") }
        try ChosenApplicationRule.verifyStored(path:source.path,identifier:identifier)
        let (architecture,cpu,subtype) = try nativeArchitecture()
        let main = "Contents/MacOS/" + executable
        let hash = try signature(source.path,identifier:identifier,architecture:architecture)
        let layout = try sealedLayout(source)
        let knownCPUs: Set<UInt32> = [7,18,0x01000007,0x0100000c,0x01000012]
        var changes: [Change] = [], retained: [Retained] = [], foundMain = false
        for entry in source.tree where entry.identity.mode & 0o170000 == 0o100000 {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw SweepError.incomplete("应用架构分析超时，原包保留") }
            // The verified resource envelope, not a magic-byte collision,
            // distinguishes raw signed data from replaceable code. The main
            // executable is separately bound by its native code directory.
            guard !layout.resources.contains(entry.relative), entry.relative == main || layout.isCode(entry.relative) else { continue }
            guard let index = try index(entry,under:source.path) else {
                if entry.relative == main { throw SweepError.denied("应用入口不是已确认的原生Mach-O") }
                continue
            }
            let native = index.slices.filter { $0.cpuType == cpu }
            let supported = native.count == 1 && native[0].cpuSubtype & 0x00ffffff == subtype
            if entry.relative == main {
                guard supported else { throw SweepError.denied("应用入口缺少唯一的本机通用架构") }
                foundMain = true
            }
            guard supported, let selected = native.first else {
                // Foreign-only back-deployment runtimes and specialised CPU
                // variants may be deliberate. Absence is never deletion or
                // conversion authority; retain their exact bytes and signature.
                retained.append(Retained(relative:entry.relative,reason:native.isEmpty ? "此组件不含本机切片，整项原样保留" : "本机架构子类型不唯一或专用，整项原样保留"))
                continue
            }
            if index.kind == .universal32 || index.kind == .universal64 {
                guard index.slices.allSatisfy({ knownCPUs.contains($0.cpuType) }), entry.identity.links == 1,
                      selected.offset > 0, selected.size < UInt64(entry.identity.size) else {
                    if entry.relative == main { throw SweepError.denied("入口的未知架构、硬链接或切片范围不能变换") }
                    retained.append(Retained(relative:entry.relative,reason:"未知架构、硬链接或切片范围不能变换，整项原样保留"))
                    continue
                }
                // A one-entry fat wrapper has no redundant architecture.
                if index.slices.count > 1 { changes.append(Change(relative:entry.relative,originalIdentity:entry.identity,slice:selected)) }
            }
        }
        guard foundMain, !changes.isEmpty else { throw SweepError.invalid("没有可独立准备的冗余架构") }
        try SafeFilesystem.verify(source)
        guard ProcessInfo.processInfo.systemUptime < deadline else { throw SweepError.incomplete("应用架构签名分析超时") }
        return Plan(source:source,identifier:identifier,architecture:architecture,nativeCodeHash:hash,changes:changes.sorted { $0.relative < $1.relative },retained:retained.sorted { $0.relative < $1.relative })
    }
    /// Caller persists the UUID preparation intent first. Failure never removes
    /// the original or the attributable partial preparation.
    static func prepare(_ plan: Plan, in parent: SafeDirectory, name: String) throws -> Result {
        try plan.verify(plan.source)
        let (architecture,_,_) = try nativeArchitecture()
        guard plan.architecture == architecture,
              try signature(plan.source.path,identifier:plan.identifier,architecture:architecture) == plan.nativeCodeHash else {
            throw SweepError.stale("应用或本机架构已改变，不能复用分析结果")
        }
        let copied = try ApplicationTreeCopy.prepare(plan.source,in:parent,name:name,architecturePlan:plan)
        guard try signature(copied.path,identifier:plan.identifier,architecture:architecture) == plan.nativeCodeHash else {
            throw SweepError.stale("准备包的保留架构签名不一致；原包及准备包均保留")
        }
        try plan.verify(plan.source); try SafeFilesystem.verify(copied)
        return Result(snapshot:copied,changes:plan.changes,savedBytes:plan.source.bytes-copied.bytes,architecture:architecture,retained:plan.retained)
    }
    static func signature(_ path: String, identifier: String, architecture: String) throws -> String {
        guard AppInspector.signatureMatches(path:path,identifier:identifier) else { throw SweepError.denied("应用完整签名未确认，不能准备精简副本") }
        let verification = try BoundedProcess.capture("/usr/bin/codesign",arguments:["--verify","--deep","--strict","--all-architectures",path],timeout:20,mergeStderr:true)
        guard verification.status == 0 else { throw SweepError.denied("应用严格签名验证未通过，原包与已有准备对象保留") }
        let result = try BoundedProcess.capture("/usr/bin/codesign",arguments:["-d","--verbose=4","--arch",architecture,path],timeout:10,mergeStderr:true)
        let hashes = result.text.split(separator:"\n").filter { $0.hasPrefix("CDHash=") }.map { String($0.dropFirst(7)) }
        guard result.status == 0, hashes.count == 1, let hash = hashes.first, hash.utf8.count == 40,
              hash.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw SweepError.incomplete("保留架构的原始签名摘要未确认")
        }
        return hash
    }
    private struct CodeLayout {
        var resources = Set<String>()
        var code = Set<String>()
        func isCode(_ relative: String) -> Bool {
            var candidate = relative
            while !candidate.isEmpty {
                if code.contains(candidate) { return true }
                guard let separator = candidate.lastIndex(of:"/") else { break }
                candidate = String(candidate[..<separator])
            }
            return false
        }
    }
    /// Only excludes resources and discovers code membership inside the already
    /// signature-verified snapshot. No manifest name is used as a write path.
    private static func sealedLayout(_ source: FileSnapshot) throws -> CodeLayout {
        let suffix = "/_CodeSignature/CodeResources"
        let seals = source.tree.filter { $0.relative.hasSuffix(suffix) }.sorted {
            $0.relative.split(separator:"/").count < $1.relative.split(separator:"/").count
        }
        var result = CodeLayout()
        for entry in seals {
            try Task.checkCancellation()
            // A sealed data bundle may itself contain example signature files.
            // They are data, not another source of code classification.
            if result.resources.contains(entry.relative) { continue }
            let path = source.path + "/" + entry.relative
            guard entry.identity.mode & 0o170000 == 0o100000, entry.identity.links == 1,
                  try SafeFilesystem.snapshot(path).identity == entry.identity else {
                throw SweepError.incomplete("应用资源封印身份未确认：" + entry.relative)
            }
            let data = try SafeFilesystem.readMetadata(path,maximumBytes:16*1024*1024)
            let value: Any
            do { value = try PropertyListSerialization.propertyList(from:data,format:nil) }
            catch { throw SweepError.incomplete("应用资源封印格式未确认：" + entry.relative) }
            guard let object = value as?[String:Any] else { throw SweepError.incomplete("资源封印不是已确认的字典") }
            let files: [String:Any]
            if let current = object["files2"] {
                guard let dictionary = current as?[String:Any] else { throw SweepError.incomplete("未知新版资源封印格式") }
                files = dictionary
            } else {
                guard let dictionary = object["files"]as?[String:Any] else { throw SweepError.incomplete("缺少可确认的资源封印记录") }
                files = dictionary
            }
            guard files.count <= TreeFingerprint.maximumEntries else { throw SweepError.incomplete("资源封印条目超限") }
            let prefix = String(entry.relative.dropLast(suffix.count)) + "/"
            for (relative,record) in files {
                try Task.checkCancellation()
                guard !relative.isEmpty, !relative.hasPrefix("/"), !relative.hasSuffix("/"), !relative.contains("\0"),
                      !relative.contains("//"), !relative.split(separator:"/").contains(where:{ $0 == "." || $0 == ".." }) else {
                    throw SweepError.incomplete("资源封印的相对名称未确认")
                }
                if record is Data { result.resources.insert(prefix + relative); continue }
                guard let attributes = record as?[String:Any] else { throw SweepError.incomplete("未知资源封印条目格式") }
                if attributes["hash"]is Data || attributes["hash2"]is Data || attributes["symlink"]is String {
                    result.resources.insert(prefix + relative)
                } else if attributes["cdhash"]is Data, attributes["requirement"]is String {
                    result.code.insert(prefix + relative)
                } else { throw SweepError.incomplete("资源与代码封印类型未确认") }
            }
        }
        return result
    }
    private static func index(_ entry: TreeEntry, under root: String) throws -> MachOContainerIndex? {
        let url = URL(fileURLWithPath:root + "/" + entry.relative), parent = try SafeDirectory(path:url.deletingLastPathComponent().path)
        let fd = openat(parent.fd,url.lastPathComponent,O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw SweepError.incomplete("无法读取应用节点的格式头：" + entry.relative) }
        defer { as_close(fd) }
        func read(_ count: Int, at offset: UInt64 = 0) throws -> Data {
            var raw = ASIdentity()
            guard as_identity_fd(fd,&raw) == 0, FileIdentity(raw) == entry.identity, entry.identity.size >= 0,
                  offset <= UInt64(entry.identity.size), count > 0, count <= MachOContainerIndex.maximumHeaderBytes else {
                throw SweepError.stale("应用格式来源身份或区间已变化")
            }
            let amount = Int(min(UInt64(count),UInt64(entry.identity.size)-offset))
            var bytes = [UInt8](repeating:0,count:amount), cursor = 0
            while cursor < amount {
                try Task.checkCancellation()
                let n = bytes.withUnsafeMutableBytes { pread(fd,$0.baseAddress!.advanced(by:cursor),amount-cursor,off_t(offset+UInt64(cursor))) }
                if n < 0 && errno == EINTR { continue }
                guard n > 0 else { throw SweepError.incomplete("应用格式头读取截断或失败") }
                cursor += n
            }
            guard as_identity_fd(fd,&raw) == 0, FileIdentity(raw) == entry.identity,
                  try parent.identity(url.lastPathComponent) == entry.identity else { throw SweepError.stale("读取格式头时应用节点已变化") }
            return Data(bytes)
        }
        let header = try read(MachOContainerIndex.maximumHeaderBytes)
        guard header.count >= 4 else { return nil }
        let magic = header.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard [0xfeedface,0xcefaedfe,0xfeedfacf,0xcffaedfe,0xcafebabe,0xcafebabf,0xbebafeca,0xbfbafeca].contains(magic) else { return nil }
        let index = try MachOContainerIndex.parse(header:header,fileSize:UInt64(entry.identity.size))
        if index.kind == .universal32 || index.kind == .universal64 {
            for slice in index.slices {
                let inner = try MachOContainerIndex.parse(header:read(Int(min(UInt64(MachOContainerIndex.maximumHeaderBytes),slice.size)),at:slice.offset),fileSize:slice.size)
                guard inner.kind == .thin32 || inner.kind == .thin64, inner.slices.count == 1,
                      inner.slices[0].cpuType == slice.cpuType, inner.slices[0].cpuSubtype == slice.cpuSubtype else {
                    throw SweepError.denied("通用容器与实际代码切片不一致")
                }
            }
        }
        return index
    }
}
#endif
