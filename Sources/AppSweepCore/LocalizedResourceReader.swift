import Foundation
import CFSafety
#if os(macOS)
import Security
#endif

/// A narrow occupancy proof. It grants no target, plan, move or purge authority.
enum LocalizedResourceReader {
    static let name = "apple-private-readonly-localization-v1"
    struct Reference: Sendable {
        let pid: Int32
        let device: UInt64
        let inode: UInt64
        let path: String
    }
    static func references(_ output: CapturedProcess) throws -> [Reference] {
        guard [0,1].contains(output.status), !output.text.isEmpty, output.text.utf8.count <= 2*1024*1024,
              output.text.hasSuffix("\0") || output.text.hasSuffix("\0\n") else { throw SweepError.incomplete("系统资源引用记录不完整") }
        var result: [Reference] = [], pid: Int32?, label = false, processes = Set<Int32>(), fields: [Character:String] = [:]
        func flush() throws {
            guard !fields.isEmpty else { return }
            guard let pid, label, Set(fields.keys) == Set("fatDin"), fields["f"] == "txt", fields["t"] == "REG",
                  [" ","r"].contains(fields["a"] ?? ""),
                  let rawDevice = fields["D"], rawDevice.hasPrefix("0x"), let device = UInt64(rawDevice.dropFirst(2),radix:16), device > 0,
                  let rawInode = fields["i"], let inode = UInt64(rawInode), inode > 0, String(inode) == rawInode,
                  let path = fields["n"], path.hasPrefix("/") else { throw SweepError.incomplete("系统资源引用含打开文件、歧义或未知字段") }
            result.append(Reference(pid:pid,device:device,inode:inode,path:path)); fields = [:]
            guard result.count <= 256 else { throw SweepError.incomplete("系统资源引用超出容量") }
        }
        for raw in output.text.components(separatedBy:"\0") {
            var token = raw
            while token.first == "\n" { token.removeFirst() }
            if token.isEmpty { continue }
            guard let key = token.first else { continue }
            let value = String(token.dropFirst())
            switch key {
            case "p":
                try flush()
                if let pid { guard result.contains(where: { $0.pid == pid }) else { throw SweepError.incomplete("系统进程缺少完整资源记录") } }
                guard let next = Int32(value), next > 1, String(next) == value, processes.insert(next).inserted, processes.count <= 16 else { throw SweepError.incomplete("系统资源进程身份重复或未知") }
                pid = next; label = false
            case "c":
                guard pid != nil, !label, fields.isEmpty, !value.isEmpty,
                      !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { throw SweepError.incomplete("系统进程记录不完整") }
                label = true // Presentation only; never used as authentication.
            case "f":
                try flush(); guard pid != nil, label else { throw SweepError.incomplete("系统资源缺少进程身份") }
                fields["f"] = value
            case "a","t","D","i","n":
                guard fields["f"] != nil, fields[key] == nil else { throw SweepError.incomplete("系统资源字段重复或截断") }
                fields[key] = value
            default: throw SweepError.incomplete("系统资源查询含告警或未知输出")
            }
        }
        try flush()
        guard !result.isEmpty else { throw SweepError.incomplete("没有完整的系统资源映射证据") }
        return result
    }
    static func verify(snapshot: FileSnapshot, references: [Reference]) throws {
        #if os(macOS)
        try Task.checkCancellation()
        guard snapshot.purpose == .application, snapshot.identity.isDirectory, !references.isEmpty, references.count <= 256 else { throw SweepError.denied("此证明只适用于完整应用包") }
        try SafeFilesystem.verify(snapshot)
        let info = try AppInspector.metadata(snapshot.path,component:false).0
        guard let identifier = info["CFBundleIdentifier"] as? String, info["CFBundlePackageType"] as? String == "APPL",
              AppInspector.signatureMatches(path:snapshot.path,identifier:identifier) else { throw SweepError.denied("应用包签名未确认，不能采用系统资源映射证明") }
        let deadline = ProcessInfo.processInfo.systemUptime + 5
        for reference in references {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline, reference.path.hasPrefix(snapshot.path + "/") else { throw SweepError.incomplete("系统资源范围或核对时限未确认") }
            let relative = String(reference.path.dropFirst(snapshot.path.count + 1)), parts = relative.split(separator:"/").map(String.init)
            guard parts.count >= 4, Array(parts.suffix(4).prefix(2)) == ["Contents","Resources"],
                  parts[parts.count-2].hasSuffix(".lproj"), parts.last == "InfoPlist.strings",
                  parts.count == 4 || parts[parts.count-5].hasSuffix(".app") else { throw SweepError.denied("被占用对象不是封存的本地化元数据") }
            let file = try SafeFilesystem.fileSnapshot(reference.path,in:snapshot)
            guard file.identity.mode & 0o170000 == 0o100000, file.identity.links == 1,
                  file.identity.size > 0, file.identity.size <= 2*1024*1024,
                  file.identity.device == reference.device, file.identity.inode == reference.inode else { throw SweepError.stale("被占用资源与可信应用树不一致") }
            let bytes = try SafeFilesystem.readMetadata(reference.path)
            guard (try? PropertyListSerialization.propertyList(from:bytes,format:nil)) is [String:String] else { throw SweepError.denied("本地化资源内容未确认") }
            var birth = ASProcessBirth()
            guard as_process_birth(reference.pid,&birth) == 0 else { throw SweepError.incomplete("系统读取者身份未确认") }
            let role = as_system_resource_reader_image(reference.pid,&birth)
            let requirementText: CFString
            if role == 1 { requirementText = "anchor apple and identifier \"com.apple.usernoted\"" as CFString }
            else if role == 2 { requirementText = "anchor apple and identifier \"com.apple.notificationcenterui\"" as CFString }
            else { throw SweepError.denied("占用进程不是已验证的系统通知读取者") }
            var requirement: SecRequirement?, code: SecCode?
            guard SecRequirementCreateWithString(requirementText,[],&requirement) == errSecSuccess, let requirement,
                  SecCodeCopyGuestWithAttributes(nil,[kSecGuestAttributePid:NSNumber(value:reference.pid)] as CFDictionary,[],&code) == errSecSuccess, let code,
                  SecCodeCheckValidity(code,SecCSFlags(rawValue:kSecCSStrictValidate),requirement) == errSecSuccess else { throw SweepError.denied("系统读取者的实时Apple签名未确认") }
            var expected = file.identity.native
            guard as_private_readonly_resource_mappings(reference.pid,&expected,&birth) == 1,
                  as_system_resource_reader_image(reference.pid,&birth) == role,
                  SecCodeCheckValidity(code,SecCSFlags(rawValue:kSecCSStrictValidate),requirement) == errSecSuccess,
                  ProcessInfo.processInfo.systemUptime < deadline else { throw SweepError.incomplete("系统资源映射可写、可执行、共享或状态未确认") }
            try SafeFilesystem.verify(file)
        }
        try SafeFilesystem.verify(snapshot)
        #else
        throw SweepError.denied("当前平台未验收系统资源映射")
        #endif
    }
}
