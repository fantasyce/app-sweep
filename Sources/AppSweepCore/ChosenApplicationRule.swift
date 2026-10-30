import Foundation

/// A user's explicit choice authorizes this complete bundle, never its neighbouring data.
/// Signing and exclusive installation remain separate requirements for associated data.
enum ChosenApplicationRule {
    static let name = "chosen-application-v1"
    static let largeName = "chosen-application-large-v1"
    static func matches(path: String, home: String) -> Bool {
        guard path == URL(fileURLWithPath: path).standardizedFileURL.path, path.hasSuffix(".app") else { return false }
        for root in ["/Applications", home + "/Applications"] where SafetyPolicy.contains(root, path) && root != path {
            let relative = path.dropFirst(root.count + 1).split(separator: "/")
            return !relative.dropLast().contains { $0.lowercased().hasSuffix(".app") }
        }
        return false
    }
    static func verify(path: String, home: String, identifier: String) throws {
        guard matches(path: path, home: home) else { throw SweepError.denied("嵌入其他应用包的组件不能单独处理，请选择完整应用") }
        try verifyStored(path: path, identifier: identifier, requireNoInstalledHelpers: true)
    }
    /// Recovery names are UUIDs. The original location is separately checked by the
    /// registered rule; never infer ownership from the storage directory's name.
    static func verifyStored(path: String, identifier: String, requireNoInstalledHelpers: Bool = false, allowOptionalApple: Bool = false) throws {
        let (info, _) = try AppInspector.metadata(path, component: false)
        guard let declared = info["CFBundleIdentifier"] as? String, declared == identifier, AppInspector.validIdentifier(declared),
              AppInspector.protection(identifier: declared, info: info, path: path, considerPrivilegedDeclaration: false, protectAppleIdentity: !allowOptionalApple) == nil else { throw SweepError.denied("应用主体标识或系统依赖未确认") }
        if requireNoInstalledHelpers { try UninstallDependencies.ensureNoInstalledPrivilegedHelpers(info: info) }
        guard
              info["CFBundlePackageType"] as? String == "APPL",
              let executable = info["CFBundleExecutable"] as? String,
              !executable.isEmpty, executable.utf8.count <= 255, executable != ".", executable != "..",
              !executable.contains("/"), !executable.contains("\0") else { throw SweepError.denied("应用结构或可执行文件声明未确认") }
        let binary = try SafeDirectory(path: path + "/Contents/MacOS").identity(executable)
        guard !binary.isLink, binary.links >= 1, binary.mode & 0o170000 == 0o100000,
              binary.mode & 0o111 != 0, binary.size > 0 else { throw SweepError.denied("应用可执行文件不是独立的普通可执行文件") }
        if binary.links > 1, !AppInspector.signatureMatches(path: path, identifier: identifier) {
            throw SweepError.denied("含硬链接的应用必须通过完整包签名核对")
        }
    }
    static func dependencyLabels(path: String) throws -> [String] {
        try UninstallDependencies.declaredLabels(info: AppInspector.metadata(path, component: false).0)
    }
}
