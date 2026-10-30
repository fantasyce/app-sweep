import Foundation
import CFSafety

enum XcodeRule {
    static let name = "xcode-intermediates-v1"
    static func derivedDirectory(_ path: String, home: String) -> String? {
        let prefix = home + "/Library/Developer/Xcode/DerivedData/"
        guard canonical(path), path.hasPrefix(prefix) else { return nil }
        let parts = path.dropFirst(prefix.count).split(separator: "/")
        guard parts.count == 3, parts[1] == "Build", parts[2] == "Intermediates.noindex" else { return nil }
        return prefix + parts[0]
    }
    static func workspace(_ data: Data) -> String? {
        guard data.count <= 2 * 1024 * 1024,
              let info = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let path = info["WorkspacePath"] as? String, canonical(path),
              path.hasSuffix(".xcodeproj") || path.hasSuffix(".xcworkspace") else { return nil }
        return path
    }
    static func verify(_ path: String, home: String) throws {
        guard let derived = derivedDirectory(path, home: home) else { throw SweepError.denied("不是已登记的 Xcode 中间目录") }
        try verifyWorkspace(derived)
        _ = try SafeDirectory(path: path)
    }
    static func verifyWorkspace(_ derived: String) throws {
        let info = try SafeFilesystem.snapshot(derived + "/info.plist")
        guard !info.identity.isDirectory, !info.identity.isLink, info.identity.links == 1,
              info.identity.owner == as_current_uid(), info.identity.size <= 2 * 1024 * 1024,
              let workspace = workspace(try SafeFilesystem.readMetadata(info.path)) else { throw SweepError.denied("Xcode 工作区归属未确认") }
        try SafeFilesystem.verify(info)
        _ = try SafeDirectory(path: workspace)
        let project = try SafeFilesystem.snapshot(workspace + (workspace.hasSuffix(".xcodeproj") ? "/project.pbxproj" : "/contents.xcworkspacedata"))
        guard !project.identity.isDirectory, !project.identity.isLink, project.identity.links == 1,
              project.identity.owner == as_current_uid(), project.identity.size <= 2 * 1024 * 1024 else { throw SweepError.denied("项目元数据无法确认") }
    }
    static func canonical(_ path: String) -> Bool {
        path.hasPrefix("/") && !path.hasSuffix("/") && !path.contains("//") && !path.contains("\0") &&
        !path.split(separator: "/").contains(where: { $0 == "." || $0 == ".." })
    }
}
