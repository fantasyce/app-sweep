import Foundation
import CFSafety

/// Independently documented compiler/package caches. Fixed locations and native
/// layouts establish the cache producer; arbitrary writable directories do not.
enum ToolCacheRule {
    static let name="development-tool-cache-v1"
    static let homebrewName="development-homebrew-download-v1"
    static let npmName="development-npm-cache-v1"
    static let pnpmName="development-pnpm-metadata-v1"
    static let rules:Set<String>=[name,homebrewName,npmName,pnpmName,DownloadCacheRule.electronName,DownloadCacheRule.builderName,TrivyCacheRule.name]
    enum Producer: String, Sendable { case go, clang, pip, homebrew, npm, pnpm, electron, electronBuilder, trivy
        var title:String { switch self { case .go:"Go 构建缓存";case .clang:"Clang 模块缓存";case .pip:"pip 下载与构建缓存";case .homebrew:"Homebrew 下载缓存";case .npm:"npm 下载缓存与日志";case .pnpm:"pnpm 注册表元数据";case .electron:"Electron 下载缓存";case .electronBuilder:"electron-builder 工具下载";case .trivy:"Trivy 漏洞数据库下载" } }
        var rule:String { switch self { case .homebrew:ToolCacheRule.homebrewName;case .npm:ToolCacheRule.npmName;case .pnpm:ToolCacheRule.pnpmName;case .electron:DownloadCacheRule.electronName;case .electronBuilder:DownloadCacheRule.builderName;case .trivy:TrivyCacheRule.name;default:ToolCacheRule.name } }
    }
    static func roots(home:String) -> [(String,Producer)] {
        let cache=home + "/Library/Caches/"
        return [(cache + "go-build",.go),(cache + "clang/ModuleCache",.clang),
                (cache + "pip/http-v2",.pip),(cache + "pip/http",.pip),(cache + "pip/wheels",.pip),
                (cache + "Homebrew/downloads",.homebrew),(cache + "trivy",.trivy),
                (home + "/.npm/_cacache",.npm),(home + "/.npm/_logs",.npm),
                (cache + "electron",.electron),(cache + "electron-builder",.electronBuilder),
                (cache + "electron-builder/nsis",.electronBuilder),(cache + "electron-builder/winCodeSign",.electronBuilder)]
            + ["metadata-v1.3","metadata-full-v1.3","metadata-full-filtered-v1.3",
               "v11/metadata","v11/metadata-full","v11/metadata-full-filtered"].map { (cache + "pnpm/" + $0,.pnpm) }
    }
    static func location(_ path:String,home:String) -> (root:String,producer:Producer)? {
        guard XcodeRule.canonical(path),SafetyPolicy(home:home,acceptedPlatform:false).protectedDenial(path) == nil else{return nil}
        if let download = DownloadCacheRule.location(path, home: home) { return download }
        let parent=URL(fileURLWithPath:path).deletingLastPathComponent().path,leaf=URL(fileURLWithPath:path).lastPathComponent
        guard let (root,producer)=roots(home:home).first(where:{$0.0 == parent}) else{return nil}
        let pattern:String
        switch producer {
        case .go:pattern="^[0-9a-f]{2}$"
        case .clang:pattern="^[A-Z0-9]{2,64}$"
        case .pip:pattern=root.hasSuffix("/wheels") ? "^[0-9a-f]{2}$" : "^[0-9a-f]$"
        case .homebrew:
            guard !leaf.hasSuffix(".incomplete"), !leaf.hasSuffix(".lock"), !leaf.hasSuffix(".tmp") else{return nil}
            pattern="^[0-9a-f]{64}--[A-Za-z0-9][A-Za-z0-9._+@-]*$"
        case .npm:
            pattern = root.hasSuffix("/_logs") ? #"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}_[0-9]{2}_[0-9]{2}_[0-9]{3}Z-debug-[0-9]+\.log$"# : #"^(content-v2|index-v5)$"#
        case .pnpm:
            pattern = #"^[A-Za-z0-9][A-Za-z0-9._%+-]{0,254}$"#
        case .trivy: pattern = "^db$"
        case .electron, .electronBuilder: return nil
        }
        guard leaf.range(of:pattern,options:.regularExpression) != nil else{return nil}
        return(root,producer)
    }
    static func isProducer(command:String,producer:Producer) -> Bool {
        switch producer {
        case .go:return command.range(of:#"(?:^|/)(?:go|gopls|compile|link)(?:\s|$)"#,options:.regularExpression) != nil
        case .clang:
            return ActivityInspector.isBuildTool(command) || command.range(of:#"(?:^|/)(?:(?:clang(?:\+\+)?|gcc|g\+\+)(?:-[0-9]+(?:\.[0-9]+)*)?|cc|c\+\+)(?:\s|$)"#,options:.regularExpression) != nil
        case .pip:return command.range(of:#"(?:^|/)(?:pip|pip3|pip3\.[0-9]+)(?:\s|$)|\s-m\s+pip(?:\s|$)|/pip/__main__\.py(?:\s|$)"#,options:.regularExpression) != nil
        case .homebrew:return command.range(of:#"(?:^|/)(?:brew|brew\.rb)(?:\s|$)|/Homebrew/Library/Homebrew/|/homebrew/Library/Homebrew/"#,options:.regularExpression) != nil
        case .npm:return command.range(of:#"(?:^|[\s/])(?:npm|npx|npm-cli\.js|npx-cli\.js)(?:\s|$)"#,options:.regularExpression) != nil
        case .pnpm:return command.range(of:#"(?:^|[\s/])(?:pnpm|pnpx|pnpm\.(?:cjs|mjs|js)|pnpm-[0-9]+)(?:\s|$)"#,options:.regularExpression) != nil
        case .electron, .electronBuilder:return DownloadCacheRule.isProducer(command)
        case .trivy:return command.range(of:#"(?:^|[\s/])trivy(?:\s|$)"#,options:.regularExpression) != nil
        }
    }
    static func ensureStopped(_ producer:Producer, home: String? = nil) throws {
        try ScanCancellation.check()
        let output=try BoundedProcess.run("/bin/ps",arguments:["-ww","-axo","pid=,command="],timeout:3)
        for process in try ActivityInspector.processes(output,ownPID:ProcessInfo.processInfo.processIdentifier) where process.pid != ProcessInfo.processInfo.processIdentifier {
            try ScanCancellation.check()
            let download = producer == .electron || producer == .electronBuilder
            let runtime = download && (DownloadCacheRule.isNodeRuntime(process.command) || as_javascript_runtime(process.pid) == 1)
            let namedProducer=isProducer(command:process.command,producer:producer)
            let active=namedProducer || runtime
            #if DEBUG
            // Explicit native fixtures use private UUID homes, never the user's
            // default cache. Unrelated host Node services cannot use that cache
            // implicitly. A caller naming the fixture (including direct API
            // callers) still blocks it. Release/current-home checks always use
            // real runtime attribution; no public switch relaxes that check.
            if active, runtime, let home,
               home.hasPrefix(try SystemIdentity.home() + "/AppSweepAcceptance"),
               UUID(uuidString:URL(fileURLWithPath:home).lastPathComponent) != nil,
               XcodeRule.canonical(home), !process.command.contains(home),
               !DownloadCacheActivity.referencesFixture(pid:process.pid,home:home) { continue }
            #endif
            // Explicit tools remain a veto even if their script cannot be read.
            if namedProducer {throw SweepError.denied("请先结束相关工具任务，再核对" + producer.title + "；App Sweep 不会结束进程")}
            if runtime {
                let relation=DownloadCacheActivity.relation(pid: process.pid, home: try home ?? SystemIdentity.home())
                try ScanCancellation.check()
                switch relation {
                // Approved only for these completed download-cache formats:
                // an inconclusive generic script is not a confirmed user.
                // Target validation and BusyInspector still gate every move.
                case .unattributed, .unknown, .exited: continue
                case .related: throw SweepError.denied("相关下载工具或下载接口仍在运行（进程 " + String(process.pid) + "）；请先退出相关任务，App Sweep 不会结束进程")
                }
            }
        }
    }
    static func verify(_ path:String,home:String) throws -> FileSnapshot {
        guard let location=location(path,home:home) else{throw SweepError.denied("不是已登记工具缓存的独立子目录")}
        if location.producer == .trivy { return try TrivyCacheRule.verify(path,home:home) }
        if location.producer == .electron || location.producer == .electronBuilder {
            return try DownloadCacheRule.verify(path, home: home, producer: location.producer)
        }
        let device=try SafeDirectory(path:home).ownIdentity.device
        var ancestor=location.root
        while SafetyPolicy.contains(home,ancestor) {
            let directory=try SafeDirectory(path:ancestor),identity=try directory.ownIdentity
            guard identity.owner == as_current_uid(),identity.device == device,as_unshared_node_descriptor(directory.fd,as_current_uid()) == 1 else{throw SweepError.denied("工具缓存的祖先、卷或独占权限未确认")}
            ancestor=URL(fileURLWithPath:ancestor).deletingLastPathComponent().path
        }
        if location.producer == .go {
            let marker=try SafeFilesystem.readMetadata(location.root + "/README",maximumBytes:4096)
            guard String(data:marker,encoding:.utf8)?.hasPrefix("This directory holds cached build artifacts") == true else{throw SweepError.denied("Go 构建缓存标记未确认")}
        }
        if location.producer == .homebrew || (location.producer == .npm && location.root.hasSuffix("/_logs")) {
            let snapshot=try SafeFilesystem.snapshot(path)
            guard snapshot.identity.mode & 0o170000 == 0o100000,
                  snapshot.identity.links == 1, snapshot.identity.owner == as_current_uid(),
                  snapshot.identity.device == device, snapshot.bytes > 0,
                  !SupportDomainRule.containsProtectedContent([TreeEntry(relative:URL(fileURLWithPath:path).lastPathComponent,identity:snapshot.identity)]) else {
                throw SweepError.denied("工具缓存不是同卷独占的完整普通文件")
            }
            if location.producer == .npm { try ApplicationLogRule.verifyLogPayload(snapshot) }
            _ = try CacheNodeMetadata.read(snapshot)
            try SafeFilesystem.verify(snapshot)
            return snapshot
        }
        let snapshot=try CacheDomainRule.verifyPrivateDomain(root:path,memberLimit:20_000)
        guard snapshot.identity.device == device,!snapshot.tree.isEmpty else{throw SweepError.denied("工具缓存为空或跨卷")}
        for node in snapshot.tree {
            let leaf=URL(fileURLWithPath:node.relative).lastPathComponent
            let valid:Bool
            switch location.producer {
            case .go:
                valid = !node.identity.isDirectory && !node.relative.contains("/") && leaf.range(of:"^[0-9a-f]{64}-[ad]$",options:.regularExpression) != nil
            case .clang:
                valid = !node.identity.isDirectory && !node.relative.contains("/") && (leaf.hasSuffix(".pcm") || leaf.hasSuffix(".pcm.timestamp") || leaf == "modules.idx")
            case .pip:
                if node.identity.isDirectory {valid=leaf.range(of:"^[0-9a-f]{1,64}$",options:.regularExpression) != nil}
                else if location.root.hasSuffix("/wheels") {valid=leaf == "origin.json" || leaf.hasSuffix(".whl")}
                else {valid=leaf.range(of:"^[0-9a-f]{56}(?:\\.body)?$",options:.regularExpression) != nil}
            case .homebrew:valid=false // File-only branch above; never authorize a directory tree.
            case .npm: valid = npmNode(node, content: URL(fileURLWithPath: path).lastPathComponent == "content-v2")
            case .pnpm:
                valid = try pnpmNode(node, path: path, jsonLines: location.root.contains("/v11/"))
            case .electron, .electronBuilder, .trivy: valid = false // Independent verifier above.
            }
            guard valid else{throw SweepError.denied("工具缓存包含未登记内容，整项保留")}
        }
        try SafeFilesystem.verify(snapshot)
        return snapshot
    }
    static func kindMatches(_ identity: FileIdentity, path: String, home: String) -> Bool {
        guard let location = location(path, home: home) else { return false }
        let file = location.producer == .homebrew || (location.producer == .npm && location.root.hasSuffix("/_logs")) || (location.producer == .electron && DownloadCacheRule.isFile(path))
        return file ? identity.mode & 0o170000 == 0o100000 && identity.links == 1 : identity.isDirectory
    }
    private static func hex(_ text: String, count: Int) -> Bool {
        text.utf8.count == count && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    private static func npmNode(_ node: TreeEntry, content: Bool) -> Bool {
        let parts = node.relative.split(separator: "/").map(String.init)
        if content {
            let digestLengths = ["sha1":40,"sha256":64,"sha384":96,"sha512":128]
            guard let algorithm = parts.first, let length = digestLengths[algorithm] else { return false }
            if node.identity.isDirectory { return parts.count <= 3 && parts.dropFirst().allSatisfy { hex($0, count: 2) } }
            return parts.count == 4 && hex(parts[1], count: 2) && hex(parts[2], count: 2) && hex(parts[3], count: length - 4)
        }
        if node.identity.isDirectory { return parts.count <= 2 && parts.allSatisfy { hex($0, count: 2) } }
        return parts.count == 3 && hex(parts[0], count: 2) && hex(parts[1], count: 2) && hex(parts[2], count: 60)
    }
    private static func pnpmNode(_ node: TreeEntry, path: String, jsonLines: Bool) throws -> Bool {
        let parts = node.relative.split(separator: "/").map(String.init)
        if node.identity.isDirectory {
            return parts.count == 1 && parts[0].range(of: #"^@[a-z0-9][a-z0-9._-]*$"#, options: .regularExpression) != nil
        }
        let suffix = jsonLines ? ".jsonl" : ".json"
        // Long-lived registries have valid 8–16 MiB metadata. Keep the common
        // verified-read ceiling; a larger file remains unconfirmed.
        let maximumMetadataBytes = 16 * 1024 * 1024
        guard node.relative.hasSuffix(suffix), (1...2).contains(parts.count),
              node.identity.size > 0, node.identity.size <= maximumMetadataBytes else { return false }
        let package = String(node.relative.dropLast(suffix.count))
        guard package.range(of: #"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$"#, options: .regularExpression) != nil else { return false }
        var bytes = try SafeFilesystem.readMetadata(path + "/" + node.relative, maximumBytes: maximumMetadataBytes)
        if jsonLines {
            guard let separator = bytes.firstIndex(of: 10),
                  let headers = try? JSONSerialization.jsonObject(with: bytes.prefix(upTo: separator)) as? [String:Any],
                  Set(headers.keys).isSubset(of: ["etag","modified"]) else { return false }
            bytes = Data(bytes.suffix(from: bytes.index(after: separator)))
        }
        guard let metadata = try? JSONSerialization.jsonObject(with: bytes) as? [String:Any],
              metadata["name"] as? String == package,
              let versions = metadata["versions"] as? [String:Any], !versions.isEmpty else { return false }
        return true
    }
}
