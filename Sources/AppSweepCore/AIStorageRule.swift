import Foundation
import CoreFoundation
import CFSafety
import Darwin

/// Whole independent HF model repositories only. A snapshot or blob is never
/// independently selectable because multiple revisions can refer to it.
enum AIStorageRule {
    static let name = "ai-huggingface-local-repository-v1"
    static let provenance = "Hugging Face 独立本地模型仓库；全部引用位于仓库内，需主动选择，不保证可再次下载"
    static func root(home: String) -> String { home + "/.cache/huggingface/hub" }
    static func matches(path: String, home: String) -> Bool {
        guard XcodeRule.canonical(home), XcodeRule.canonical(path), home != "/",
              URL(fileURLWithPath: path).deletingLastPathComponent().path == root(home: home) else { return false }
        let parts = URL(fileURLWithPath: path).lastPathComponent.components(separatedBy: "--")
        return (parts.count == 2 || parts.count == 3) && parts[0] == "models" && parts.dropFirst().allSatisfy {
            !$0.isEmpty && $0 != "." && $0 != ".." && $0.range(of: #"^[A-Za-z0-9_][A-Za-z0-9._-]{0,95}$"#, options: .regularExpression) != nil
        }
    }
    static func verify(path: String, home: String) throws -> FileSnapshot {
        guard matches(path: path, home: home) else { throw SweepError.denied("不是标准位置中的完整模型仓库") }
        let snapshot = try SafeFilesystem.snapshot(path, allowInternalLinks: true, purpose: .managedData)
        try verifyContents(snapshot, home: home)
        return snapshot
    }
    /// Can check a journal-bound vault object after its whole repository moves.
    /// Links must remain relative and resolve inside that same moved object.
    static func verifyContents(_ snapshot: FileSnapshot, home: String) throws {
        guard as_current_uid() != 0, snapshot.identity.isDirectory, snapshot.allowInternalLinks,
              !snapshot.allowInternalHardLinks, !snapshot.allowApplicationHardLinks else {
            throw SweepError.denied("模型仓库不是完整独立目录")
        }
        try ContainerDataRule.verifyPrivateTree(snapshot, home: home)
        let entries = Dictionary(uniqueKeysWithValues: snapshot.tree.map { ($0.relative, $0) })
        guard entries["blobs"]?.identity.isDirectory == true, entries["snapshots"]?.identity.isDirectory == true else {
            throw SweepError.denied("模型仓库缺少已知 blobs/snapshots 布局")
        }
        var blobs = Set<String>(), referenced = Set<String>(), modelPayloads = Set<String>()
        var revisions = Set<String>(), links: [TreeEntry] = [], refs: [TreeEntry] = []
        for entry in snapshot.tree {
            try Task.checkCancellation()
            let parts = entry.relative.split(separator: "/").map(String.init)
            guard let first = parts.first, ["blobs", "snapshots", "refs"].contains(first) else {
                throw SweepError.denied("模型仓库含未确认布局或下载状态，整项保留")
            }
            if parts.count == 1 {
                guard entry.identity.isDirectory else { throw SweepError.denied("模型仓库顶层布局类型不符") }
                continue
            }
            if first == "blobs" {
                guard parts.count == 2, hash(parts[1], lengths: [40, 64]),
                      entry.identity.mode & 0o170000 == 0o100000, entry.identity.links == 1 else {
                    throw SweepError.denied("模型包含共享 blob、未完成下载或未知文件，整项保留")
                }
                blobs.insert(entry.relative)
            } else if first == "refs" {
                if !entry.identity.isDirectory {
                    guard entry.identity.mode & 0o170000 == 0o100000, entry.identity.links == 1 else { throw SweepError.denied("模型分支引用不是独立文件") }
                    refs.append(entry)
                }
            } else {
                guard hash(parts[1], lengths: [40]) else { throw SweepError.denied("模型快照修订标识未确认") }
                if parts.count == 2 {
                    guard entry.identity.isDirectory else { throw SweepError.denied("模型快照不是目录") }
                    revisions.insert(parts[1])
                } else if entry.identity.isLink { links.append(entry) }
                else if !entry.identity.isDirectory { throw SweepError.denied("模型快照含未知直存格式，整项保留") }
            }
        }
        guard !blobs.isEmpty, !revisions.isEmpty, !links.isEmpty, refs.count <= 1000 else { throw SweepError.denied("模型仓库内容不完整或超过引用核验上限") }
        for reference in refs {
            let data = try SafeFilesystem.readMetadata(snapshot.path + "/" + reference.relative, maximumBytes: 128)
            guard let revision = String(data: data, encoding: .utf8), hash(revision, lengths: [40]), revisions.contains(revision) else {
                throw SweepError.denied("模型分支引用缺失快照或格式未确认")
            }
        }
        for entry in links {
            let target = try linkTarget(snapshot.path + "/" + entry.relative, expected: entry.identity)
            guard !target.hasPrefix("/"), !target.contains("\0"), !target.contains("//") else { throw SweepError.denied("模型快照链接不是仓库内相对引用") }
            let parent = URL(fileURLWithPath: snapshot.path + "/" + entry.relative).deletingLastPathComponent().path
            let resolved = URL(fileURLWithPath: parent + "/" + target).standardizedFileURL.path
            let prefix = snapshot.path + "/"
            guard resolved.hasPrefix(prefix), blobs.contains(String(resolved.dropFirst(prefix.count))) else {
                throw SweepError.denied("模型快照引用共享或仓库外文件，整项保留")
            }
            let relative = String(resolved.dropFirst(prefix.count))
            let expectedTarget = String(repeating: "../", count: entry.relative.split(separator: "/").count - 1) + relative
            guard target == expectedTarget else { throw SweepError.denied("模型引用含非标准或未核验的中间路径") }
            referenced.insert(relative)
            if entry.relative.hasSuffix(".safetensors") { modelPayloads.insert(relative) }
        }
        guard referenced == blobs, !modelPayloads.isEmpty else { throw SweepError.denied("模型存在未确认引用或尚未验证的权重格式") }
        for relative in modelPayloads {
            guard let identity = entries[relative]?.identity else { throw SweepError.denied("模型权重标记已丢失") }
            try verifySafetensors(snapshot.path + "/" + relative, identity: identity)
        }
        try SafeFilesystem.verify(snapshot)
    }
    private static func hash(_ value: String, lengths: Set<Int>) -> Bool {
        lengths.contains(value.count) && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    private static func linkTarget(_ path: String, expected: FileIdentity) throws -> String {
        let url = URL(fileURLWithPath: path), parent = try SafeDirectory(path: url.deletingLastPathComponent().path)
        var bytes = [UInt8](repeating: 0, count: 4096)
        guard try parent.identity(url.lastPathComponent) == expected else { throw SweepError.stale("模型引用已改变") }
        let count = readlinkat(parent.fd, url.lastPathComponent, &bytes, bytes.count)
        guard count > 0, count < bytes.count, let result = String(bytes: bytes.prefix(count), encoding: .utf8),
              try parent.identity(url.lastPathComponent) == expected else { throw SweepError.stale("模型引用读取未完成或已经改变") }
        return result
    }
    private static func readPrefix(_ path: String, identity: FileIdentity, count: Int) throws -> Data {
        guard count > 0, count <= 1024 * 1024 + 8, identity.size >= count,
              identity.mode & 0o170000 == 0o100000, identity.links == 1 else { throw SweepError.denied("模型权重头部大小或文件类型未确认") }
        let url = URL(fileURLWithPath: path), parent = try SafeDirectory(path: url.deletingLastPathComponent().path)
        let fd = openat(parent.fd, url.lastPathComponent, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw SweepError.denied("模型权重不能安全读取") }
        defer { as_close(fd) }
        var raw = ASIdentity(), bytes = [UInt8](repeating: 0, count: count)
        guard as_identity_fd(fd, &raw) == 0, FileIdentity(raw) == identity,
              pread(fd, &bytes, count, 0) == count,
              as_identity_fd(fd, &raw) == 0, FileIdentity(raw) == identity,
              try parent.identity(url.lastPathComponent) == identity else { throw SweepError.stale("模型权重读取时已改变") }
        return Data(bytes)
    }
    private static func integer(_ value: Any?) -> Int64? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue >= 0, number.doubleValue < Double(Int64.max),
              Double(number.int64Value) == number.doubleValue else { return nil }
        return number.int64Value
    }
    private static func verifySafetensors(_ path: String, identity: FileIdentity) throws {
        let prefix = try readPrefix(path, identity: identity, count: 8)
        let length = prefix.enumerated().reduce(UInt64(0)) { $0 | UInt64($1.element) << ($1.offset * 8) }
        guard length > 1, length <= 1024 * 1024, identity.size > Int64(length) + 8,
              let header = try JSONSerialization.jsonObject(with: readPrefix(path, identity: identity, count: Int(length) + 8).dropFirst(8)) as? [String: Any] else {
            throw SweepError.denied("模型权重没有完整的有界 Safetensors 头部")
        }
        let widths: [String: Int64] = ["BOOL":1,"U8":1,"I8":1,"F8_E4M3":1,"F8_E5M2":1,"F8_E4M3FN":1,"I16":2,"U16":2,"F16":2,"BF16":2,"I32":4,"U32":4,"F32":4,"I64":8,"U64":8,"F64":8]
        var intervals: [(Int64, Int64)] = []
        for (name, value) in header {
            if name == "__metadata__" {
                guard value is [String: String] else { throw SweepError.denied("Safetensors 元数据格式未确认") }
                continue
            }
            guard let tensor = value as? [String: Any], let dtype = tensor["dtype"] as? String, let width = widths[dtype],
                  let shape = tensor["shape"] as? [Any], shape.count <= 32,
                  let offsets = tensor["data_offsets"] as? [Any], offsets.count == 2,
                  let start = integer(offsets[0]), let end = integer(offsets[1]), end >= start else {
                throw SweepError.denied("Safetensors 张量元数据未确认")
            }
            var elements: Int64 = 1
            for dimension in shape {
                guard let size = integer(dimension) else { throw SweepError.denied("模型张量维度无效") }
                let product = elements.multipliedReportingOverflow(by: size)
                guard !product.overflow else { throw SweepError.denied("模型张量尺寸溢出") }; elements = product.partialValue
            }
            let bytes = elements.multipliedReportingOverflow(by: width)
            guard !bytes.overflow, bytes.partialValue == end - start else { throw SweepError.denied("模型张量尺寸与数据范围不符") }
            intervals.append((start, end))
        }
        var offset: Int64 = 0
        for interval in intervals.sorted(by: { $0.0 == $1.0 ? $0.1 < $1.1 : $0.0 < $1.0 }) {
            guard interval.0 == offset else { throw SweepError.denied("模型权重含未确认的空洞或重叠数据") }; offset = interval.1
        }
        guard !intervals.isEmpty, offset == identity.size - Int64(length) - 8 else { throw SweepError.denied("模型权重下载不完整或含额外资料") }
    }
    static func isConsumer(_ command: String) -> Bool {
        command.range(of: #"(?:^|/)(?:hf|huggingface-cli|ollama|lms|lmstudio|llama-cli|llama-server|llama-run|mlx_lm(?:\.[A-Za-z_]+)?|vllm|text-generation-launcher)(?:\s|$)"#, options: [.regularExpression, .caseInsensitive]) != nil ||
        ["huggingface_hub", "transformers", "diffusers", "mlx-lm", "mlx_lm", "llama.cpp", "lm studio"].contains(where: command.lowercased().contains)
    }
    static func ensureStopped(path: String, home: String) throws {
        guard matches(path: path, home: home) else { throw SweepError.denied("模型活动检查超出已知仓库范围") }
        let ownPID = ProcessInfo.processInfo.processIdentifier
        let output = try BoundedProcess.run("/bin/ps", arguments: ["-ww", "-axo", "pid=,command="], timeout: 3)
        for process in try ActivityInspector.processes(output, ownPID: ownPID) where process.pid != ownPID {
            try Task.checkCancellation()
            let referencesRoot = process.command.contains(root(home: home))
            guard referencesRoot || isConsumer(process.command) else { continue }
            throw SweepError.denied("相关模型工具或明确引用模型位置的进程仍在运行，整仓保留；App Sweep 不会结束进程")
        }
        // A generic interpreter alone is not evidence of model consumption.
        // BusyInspector separately vetoes actual open files before each move;
        // no claim is made about a process's arbitrary future dynamic imports.
    }
}
