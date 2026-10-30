import Foundation
import CFSafety
#if os(macOS)
import Security
import Darwin
#endif

/// Evidence parser only: Apple identifiers in a report are untrusted until the
/// separate system-file and signing checks succeed. No report grants authority.
enum SystemDiagnosticRule {
    static let name = "system-apple-diagnostic-30d-v1"
    struct Metadata: Equatable {
        let identifier: String
        let executable: String
    }
    static func matches(_ path: String, libraryRoot: String) -> Bool {
        XcodeRule.canonical(path) && !path.contains("//") && !path.hasSuffix("/") &&
        URL(fileURLWithPath: path).deletingLastPathComponent().path == libraryRoot + "/Logs/DiagnosticReports" &&
        URL(fileURLWithPath: path).pathExtension == "ips"
    }
    static func metadata(_ data: Data) -> Metadata? {
        guard data.count <= 2 * 1024 * 1024, let newline = data.firstIndex(of: 10),
              let header = try? JSONSerialization.jsonObject(with: data[..<newline]) as? [String: Any],
              let body = try? JSONSerialization.jsonObject(with: data[data.index(after: newline)...]) as? [String: Any],
              header["bug_type"] as? String == "309", body["bug_type"] as? String == "309",
              let identifier = header["bundleID"] as? String, AppInspector.validIdentifier(identifier), identifier.hasPrefix("com.apple."),
              let bundle = body["bundleInfo"] as? [String: Any], bundle["CFBundleIdentifier"] as? String == identifier,
              body["codeSigningID"] as? String == identifier,
              let incident = header["incident_id"] as? String, UUID(uuidString: incident) != nil, body["incident"] as? String == incident,
              let threads = body["threads"] as? [[String: Any]], !threads.isEmpty,
              let images = body["usedImages"] as? [[String: Any]], !images.isEmpty,
              let executable = body["procPath"] as? String, XcodeRule.canonical(executable),
              !executable.contains("//"), !executable.hasSuffix("/"), !executable.contains("<"), !executable.contains(">"),
              executable.hasPrefix("/System/Library/") || executable.hasPrefix("/System/Applications/") else { return nil }
        return Metadata(identifier: identifier, executable: executable)
    }
    static func scan(scope: SystemCleanupScope, builder: inout Scanner.Builder) throws {
        let root = scope.libraryRoot + "/Logs/DiagnosticReports"
        var paths: [String] = []
        var directoryIdentity: FileIdentity?
        // Discovery and per-file checks are sibling scopes. Nested scopes would
        // assign each candidate twice, correctly making the plan reject it.
        try builder.scoped(root: root) { _ in
            guard try SafeFilesystem.presence(root) else { return }
            let directory = try SafeDirectory(path: root), before = try directory.ownIdentity
            let names = try FileManager.default.contentsOfDirectory(atPath: root)
            guard names.count <= 5000 else { throw SweepError.incomplete("系统诊断报告枚举超限") }
            guard try directory.ownIdentity == before else { throw SweepError.stale("系统诊断报告目录在扫描时改变") }
            directoryIdentity = before
            paths = names.filter { $0.hasSuffix(".ips") }.sorted().map { root + "/" + $0 }
        }
        for path in paths {
            try Task.checkCancellation()
            try builder.scoped(root: path) { part in
                guard try SafeDirectory(path: root).ownIdentity == directoryIdentity else { throw SweepError.stale("系统诊断报告目录已改变") }
                guard let metadata = metadata(try SafeFilesystem.readMetadata(path)) else { return }
                var reason: String?
                do {
                    _ = try inspect(path, scope: scope)
                    try ActivityInspector.ensureSystemServicesStopped(identifiers: [metadata.identifier], applicationPath: nil)
                    try ActivityInspector.ensureStopped(bundleID: metadata.identifier, applicationPath: nil, userID: scope.requesterUID)
                } catch is CancellationError { throw CancellationError() }
                catch { reason = error.localizedDescription }
                try part.add(path, category: .log, bundleID: metadata.identifier, rule: name,
                    evidence: [.init(kind: .signature, detail: "系统签名、报告生产者与完整 IPS 结构核对", verified: reason == nil),
                               .init(kind: .validatedRule, detail: "超过30天的独立系统诊断报告；不处理系统状态或日志数据库", verified: reason == nil)],
                    reason: reason, applicationPath: nil)
            }
        }
    }
    static func inspect(_ path: String, scope: SystemCleanupScope) throws -> Metadata {
        try scope.verify()
        guard matches(path, libraryRoot: scope.libraryRoot) else { throw SweepError.denied("不是独立系统诊断报告") }
        let snapshot = try SafeFilesystem.snapshot(path)
        guard snapshot.identity.owner == scope.ownerUID, snapshot.identity.links == 1,
              snapshot.identity.mode & 0o170000 == 0o100000, snapshot.identity.mode & 0o022 == 0,
              snapshot.identity.size > 0, snapshot.identity.size <= 2 * 1024 * 1024,
              snapshot.identity.sameVolume(as: try SafeDirectory(path: scope.libraryRoot).ownIdentity),
              Attribution.oldLog(modified: Date(timeIntervalSince1970: Double(snapshot.identity.modifiedSeconds)), now: Date()) else {
            throw SweepError.denied("近期、共享或身份未确认的系统报告已保留")
        }
        let root = scope.libraryRoot + "/Logs/DiagnosticReports"
        for ancestor in [scope.libraryRoot + "/Logs", root] {
            let identity = try SafeDirectory(path: ancestor).ownIdentity
            guard identity.owner == scope.ownerUID, identity.sameVolume(as: snapshot.identity) else { throw SweepError.denied("诊断报告目录所有权未确认") }
            if !scope.fixture && ancestor == root {
                let directory = try SafeDirectory(path: ancestor)
                guard try directory.ownIdentity == identity, trustedSystemReportDirectory(directory.fd) else { throw SweepError.denied("系统分析报告目录权限未确认") }
            } else {
                try scope.verifyUnsharedNode(path: ancestor, identity: identity)
            }
        }
        try scope.verifyUnsharedNode(path: path, identity: snapshot.identity)
        guard let evidence = metadata(try SafeFilesystem.readMetadata(path)) else { throw SweepError.denied("诊断报告格式或归属不完整") }
        try verifyAppleExecutable(evidence)
        try BusyInspector.ensureUnused(snapshot)
        try SafeFilesystem.verify(snapshot)
        return evidence
    }
    /// macOS uses root:_analyticsusers 0770 for this one report directory.
    /// Group writers can add/replace entries, so each selected file must still
    /// be root-owned, unshared, immutable to that group and rechecked on move.
    /// This exception never applies to source files, other roots or recovery.
    static func trustedSystemReportDirectory(_ fd: Int32) -> Bool {
        #if os(macOS)
        var info = stat(), group = Darwin.group(), found: UnsafeMutablePointer<Darwin.group>?
        var buffer = [CChar](repeating: 0, count: 16 * 1024)
        guard fstat(fd, &info) == 0, info.st_uid == 0,
              info.st_mode & S_IFMT == S_IFDIR, [mode_t(0o700), mode_t(0o750), mode_t(0o770)].contains(info.st_mode & 0o7777),
              getgrnam_r("_analyticsusers", &group, &buffer, buffer.count, &found) == 0, found != nil,
              info.st_gid == group.gr_gid, as_no_grant_acl_descriptor(fd) == 1 else { return false }
        return true
        #else
        return false
        #endif
    }
    private static func verifyAppleExecutable(_ evidence: Metadata) throws {
        #if os(macOS)
        // A report-controlled path never becomes a mutation target. Descriptor
        // walking rejects aliases before Security verifies the actual Apple code.
        let executable = try SafeFilesystem.snapshot(evidence.executable)
        guard executable.identity.owner == 0, executable.identity.mode & 0o170000 == 0o100000,
              executable.identity.mode & 0o022 == 0 else { throw SweepError.denied("系统报告生产者身份未确认") }
        var code: SecStaticCode?, requirement: SecRequirement?, raw: CFDictionary?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: evidence.executable) as CFURL, [], &code) == errSecSuccess, let code,
              SecRequirementCreateWithString("anchor apple" as CFString, [], &requirement) == errSecSuccess, let requirement,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), requirement) == errSecSuccess,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &raw) == errSecSuccess,
              let signing = raw as? [String: Any], signing[kSecCodeInfoIdentifier as String] as? String == evidence.identifier else {
            throw SweepError.denied("系统报告生产者的 Apple 签名与标识不一致")
        }
        try SafeFilesystem.verify(executable)
        #else
        throw SweepError.denied("当前平台未核验系统报告签名")
        #endif
    }

}
