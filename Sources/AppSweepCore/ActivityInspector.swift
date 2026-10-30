import Foundation
import CFSafety
#if os(macOS)
import AppKit
import Darwin
#else
import Glibc
#endif

enum ActivityInspector {
    struct Entry { let pid: Int32; let command: String }
    static func ensureUnattributedCacheStopped(namespace: String) throws {
        #if os(macOS)
        let output = try BoundedProcess.run("/bin/ps",arguments:["-ww","-axo","pid=,command="],timeout:3)
        for entry in try processes(output,ownPID:ProcessInfo.processInfo.processIdentifier) where entry.pid != ProcessInfo.processInfo.processIdentifier {
            if let app = NSRunningApplication(processIdentifier:entry.pid), app.activationPolicy != .prohibited,
               let path = app.bundleURL?.path,
               !SafetyPolicy.contains("/System",path) {
                let label = String((app.localizedName ?? URL(fileURLWithPath:path).lastPathComponent).unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }.prefix(64))
                throw SweepError.denied("未关联应用的缓存需先正常退出第三方应用（" + label + "）；App Sweep 不会结束进程")
            }
            if entry.command.contains(namespace) { throw SweepError.denied("缓存相关进程仍在运行，整组保留") }
        }
        let services = try BoundedProcess.run("/bin/launchctl",arguments:["print","gui/" + String(getuid())],timeout:3)
        guard !services.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty else { throw SweepError.incomplete("缓存后台活动未确认") }
        let leaf = URL(fileURLWithPath:namespace).lastPathComponent
        if services.contains(namespace) || (leaf.count >= 4 && services.contains(leaf)) { throw SweepError.denied("缓存关联后台服务仍已注册，整组保留") }
        #else
        throw SweepError.denied("当前平台未验收通用缓存活动检查")
        #endif
    }
    static func isBuildTool(_ command: String) -> Bool {
        command.range(of: #"(?:^|/)(?:xcodebuild|XCBBuildService|clang|clang\+\+|swiftc|swift-frontend|ld|ibtool|ibtoold|actool|metal|make|ninja)(?:\s|$)"#, options: .regularExpression) != nil
    }
    static func ensureBuildToolsStopped() throws {
        let ownPID = ProcessInfo.processInfo.processIdentifier
        let output = try BoundedProcess.run("/bin/ps", arguments: ["-ww", "-axo", "pid=,command="], timeout: 3)
        guard try !processes(output, ownPID: ownPID).contains(where: { $0.pid != ownPID && isBuildTool($0.command) }) else { throw SweepError.denied("构建工具仍在运行，已保留开发中间文件") }
    }
    static func ensureDeviceBackupsStopped() throws {
        let ownPID = ProcessInfo.processInfo.processIdentifier
        let output = try BoundedProcess.run("/bin/ps",arguments:["-ww","-axo","pid=,command="],timeout:3)
        let pattern = #"(?:^|/)(?:BackupAgent|BackupAgent2|MobileBackup|mobilebackup|idevicebackup|idevicebackup2)(?:\s|$)"#
        guard try !processes(output,ownPID:ownPID).contains(where:{ $0.pid != ownPID && $0.command.range(of:pattern,options:.regularExpression) != nil }) else {
            throw SweepError.denied("设备备份工具仍在运行；请结束备份/同步并断开设备后重新核对")
        }
    }
    static func processes(_ output: String, ownPID: Int32) throws -> [Entry] {
        var entries: [Entry] = []; var seen = Set<Int32>()
        for line in output.split(separator: "\n") where !line.trimmingCharacters(in: .whitespaces).isEmpty {
            let fields = line.split(maxSplits: 1, whereSeparator: { $0 == " " || $0 == "\t" })
            guard fields.count == 2, let pid = Int32(fields[0]), pid > 0, seen.insert(pid).inserted,
                  !fields[1].isEmpty, !fields[1].contains("\0"), !fields[1].contains("\r") else { throw SweepError.incomplete("进程列表格式未确认") }
            entries.append(Entry(pid: pid, command: String(fields[1])))
        }
        guard seen.contains(ownPID) else { throw SweepError.incomplete("进程列表为空或不完整，运行状态未确认") }
        return entries
    }
    static func ensureSystemServicesStopped(identifiers: [String], applicationPath: String?) throws {
        #if os(macOS)
        guard !identifiers.isEmpty, identifiers.count <= 33, identifiers.allSatisfy({ !$0.isEmpty }) else { throw SweepError.denied("系统后台依赖未确认") }
        let services = try BoundedProcess.run("/bin/launchctl", arguments: ["print", "system"], timeout: 3)
        guard !services.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw SweepError.incomplete("系统后台服务列表为空，状态未确认") }
        if identifiers.contains(where: { services.contains($0) }) || (applicationPath != nil && services.contains(applicationPath!)) { throw SweepError.denied("关联系统服务仍已注册，请先完成服务停用") }
        #endif
    }
    static func ensureStopped(bundleID: String?, applicationPath: String?, additionalIdentifiers: [String] = [], userID: UInt32? = nil, userHome:String? = nil, inspectionProcess:(@Sendable (Int32) throws -> Bool)? = nil) throws {
        guard let bundleID, !bundleID.isEmpty else { throw SweepError.denied("应用运行状态无法确认") }
        let identifiers = [bundleID] + additionalIdentifiers
        guard identifiers.count <= 33, identifiers.allSatisfy({ !$0.isEmpty }) else { throw SweepError.denied("关联组件标识未确认") }
        let output = try BoundedProcess.run("/bin/ps", arguments: ["-ww", "-axo", "pid=,command="], timeout: 3)
        let ownPID = ProcessInfo.processInfo.processIdentifier
        for entry in try processes(output, ownPID: ownPID) where entry.pid != ownPID {
            #if os(macOS)
            // An installed body path is unavailable during data recovery. The
            // public running-app identity also catches another launch location;
            // command names and paths alone cannot establish that it has stopped.
            if let actual = NSRunningApplication(processIdentifier: entry.pid)?.bundleIdentifier?.lowercased(),
               identifiers.contains(where: { $0.hasSuffix(".") ? actual.hasPrefix($0.lowercased()) : actual == $0.lowercased() }) {
                throw SweepError.denied("请先彻底关闭目标应用及关联后台组件，再重新核对；App Sweep 不会结束进程")
            }
            #endif
            if identifiers.contains(where: { entry.command.contains($0) }) || (applicationPath != nil && entry.command.lowercased().contains(applicationPath!.lowercased())) {
                // A privileged transfer sees its CLI caller's target operand.
                // Only that freshly authenticated caller may be excluded from
                // argument matching. Running-app identity above still wins.
                if try inspectionProcess?(entry.pid) == true { continue }
                throw SweepError.denied("请先彻底关闭目标应用及关联后台组件，再重新核对；App Sweep 不会结束进程")
            }
        }
        // Background services may be registered without a visible process. Ambiguous registrations block execution.
        #if os(macOS)
        let services = try BoundedProcess.run("/bin/launchctl", arguments: ["print", "gui/" + String(userID ?? getuid())], timeout: 3)
        guard !services.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw SweepError.incomplete("后台服务列表为空，运行状态未确认") }
        var unresolved=services
        if let applicationPath,(userID ?? getuid()) == getuid(),
           userHome != nil || NativeAcceptance.rules(for:PlatformStamp.current).contains(ApplicationAgentRule.name),
           identifiers.contains(where:{services.contains($0)}) || services.contains(applicationPath) {
            let app=try AppInspector.inspect(applicationPath),home=try userHome ?? SystemIdentity.home()
            // Only exact verified dormant rows may be removed from this check.
            // Process checks above remain unconditional, and an unknown job
            // containing the same vendor/identifier still blocks execution.
            let declarations=try ApplicationAgentRule.dormantDeclarations(home:home,application:applicationPath,identifier:app.bundleIdentifier)
            let labels=Set(declarations.map(\.label))
            unresolved=services.split(separator:"\n",omittingEmptySubsequences:false).filter{line in
                let fields=line.split(whereSeparator:{$0 == " " || $0 == "\t"})
                return !(fields.count == 3 && fields[0] == "0" && (fields[1] == "-" || Int(fields[1]) != nil) && labels.contains(String(fields[2])))
            }.joined(separator:"\n")
        }
        if identifiers.contains(where: { unresolved.contains($0) }) || (applicationPath != nil && unresolved.contains(applicationPath!)) { throw SweepError.denied("关联后台服务仍已注册，运行状态未确认") }
        #endif
    }
}
struct CapturedProcess { let status: Int32; let text: String }
enum BoundedProcess {
    static func run(_ executable: String, arguments: [String], timeout: TimeInterval) throws -> String {
        let output = try capture(executable, arguments: arguments, timeout: timeout, mergeStderr: false)
        guard output.status == 0 else { throw SweepError.denied("子进程错误，结果未确认") }
        return output.text
    }
    static func capture(_ executable: String, arguments: [String], timeout: TimeInterval, mergeStderr: Bool, inputFD: Int32? = nil) throws -> CapturedProcess {
        if let inputFD, inputFD < 3 { throw SweepError.invalid("子进程输入句柄无效") }
        guard !executable.contains("\0"), !arguments.contains(where: { $0.contains("\0") }), timeout > 0, timeout <= 30 else { throw SweepError.invalid("子进程参数无效") }
        let strings = ([executable] + arguments).map { strdup($0) }
        defer { strings.forEach { free($0) } }
        let argv = strings + [nil]
        var output = [CChar](repeating: 0, count: 2 * 1024 * 1024); var count = 0; var status: Int32 = -1
        let result = argv.withUnsafeBufferPointer {
            if let inputFD { return as_run_process_with_input(executable,$0.baseAddress,&output,output.count,Int32(timeout*1000),&count,mergeStderr ? 1 : 0,&status,inputFD) }
            return as_run_process(executable,$0.baseAddress,&output,output.count,Int32(timeout*1000),&count,mergeStderr ? 1 : 0,&status)
        }
        guard result == 0 else { throw SweepError.denied(result == -2 ? "子进程超时，结果未确认" : (result == -3 ? "子进程输出截断，结果未确认" : "子进程错误，结果未确认")) }
        let data = output.withUnsafeBytes { Data($0.prefix(count)) }
        guard let text = String(data: data, encoding: .utf8) else { throw SweepError.denied("子进程输出无法读取，结果未确认") }
        return CapturedProcess(status: status, text: text)
    }
}
enum BusyInspector {
    static func ensureUnused(_ output: CapturedProcess) throws {
        if output.status == 1 && output.text.isEmpty { return }
        // lsof may return1 while still reporting open descriptors. A positive
        // process record always blocks; a warning alone remains unconfirmed.
        let reportsProcess = output.text.components(separatedBy: "\0").contains { field in
            let record = field.trimmingCharacters(in: .newlines)
            return record.first == "p" && record.dropFirst().allSatisfy(\.isNumber) && (Int32(record.dropFirst()) ?? 0) > 0
        }
        if (output.status == 0 && !output.text.isEmpty) || reportsProcess {
            var processRecord = false, names = Set<String>()
            for field in output.text.components(separatedBy: "\0") {
                let record = field.trimmingCharacters(in: .newlines)
                if record.first == "p" { processRecord = (Int32(record.dropFirst()) ?? 0) > 0 }
                else if processRecord && record.first == "c" {
                    let clean = String(record.dropFirst().unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }).trimmingCharacters(in: .whitespaces)
                    if !clean.isEmpty { names.insert(String(clean.prefix(48))) }
                }
            }
            let owner = names.isEmpty ? "" : "（" + names.sorted().prefix(3).joined(separator: "、") + "）"
            // This list changes advice only, never permission or occupancy rules.
            let systemReaders: Set<String> = ["mdworker", "mdworker_shared", "mds", "mds_stores", "iconservicesagent", "iconservicesd", "lsd", "cfprefsd", "nsurlstoraged", "pluginkit"]
            let advice = !names.isEmpty && names.allSatisfy({ systemReaders.contains($0.lowercased()) })
                ? "系统组件仍在读取，请稍后重新扫描，不要结束系统服务"
                : "请正常退出相关应用后重新扫描，App Sweep 不会替你结束进程"
            throw SweepError.denied("文件仍被进程使用" + owner + "，已停止整个批次；" + advice)
        }
        throw SweepError.incomplete("文件占用状态未确认，已停止整个批次。请稍后重新核对。")
    }
    static func ensureUnused(_ snapshot: FileSnapshot, allowReadOnlyLocalization: Bool = false) throws {
        #if os(macOS)
        let mayProveMapping = allowReadOnlyLocalization && snapshot.purpose == .application
        let args = [mayProveMapping ? "-F0pcfatDin" : "-F0pcn"] + (snapshot.identity.isDirectory ? ["+D", snapshot.path] : ["--", snapshot.path])
        let output = try BoundedProcess.capture("/usr/sbin/lsof", arguments: args, timeout: snapshot.purpose == .application ? 30 : 3, mergeStderr: true)
        if mayProveMapping, !(output.status == 1 && output.text.isEmpty) {
            do {
                try LocalizedResourceReader.verify(snapshot:snapshot,references:LocalizedResourceReader.references(output))
                return
            } catch is CancellationError { throw CancellationError() }
            catch { } // Unsafe/unknown references keep the strict occupancy stop.
        }
        try ensureUnused(output)
        #else
        throw SweepError.denied("当前平台未验收文件占用检查")
        #endif
    }
}
