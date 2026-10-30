import Foundation
import Darwin
import AppSweepCore

@main
struct AppSweepServiceInstallerMain {
    static func main() async {
        let arguments = Array(CommandLine.arguments.dropFirst())
        let removalID = arguments.count == 2 && arguments[0] == "restore-removal" ? UUID(uuidString:arguments[1]) : nil
        guard (arguments.count == 1 && ["recover","remove"].contains(arguments[0])) ||
              (arguments.count == 2 && arguments[0] == "install" && !arguments[1].isEmpty) ||
              (arguments.count == 2 && arguments[0] == "restore-removal" && removalID?.uuidString == arguments[1]) else {
            FileHandle.standardError.write(Data("Usage: AppSweepServiceInstaller install <authenticated-package-root> | recover | remove | restore-removal <batch-UUID>\n".utf8))
            exit(64)
        }
        guard getuid() == 0, geteuid() == 0 else {
            FileHandle.standardError.write(Data("系统组件操作需要完成独立管理员认证。\n".utf8))
            exit(77)
        }
        do {
            let result: ServiceDeploymentResult
            if arguments[0] == "install" { result = try await SystemServiceInstallation.install(packageRoot:arguments[1]) }
            else if arguments[0] == "remove" { result = try await SystemServiceInstallation.remove() }
            else if let removalID { result = try await SystemServiceInstallation.restoreRemoval(removalID) }
            else { result = try await SystemServiceInstallation.recover() }
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys,.withoutEscapingSlashes]
            FileHandle.standardOutput.write(try encoder.encode(result) + Data([10]))
            if result.status == .needsAttention { exit(1) }
            if arguments[0] == "install" && result.status != .installed { exit(1) }
            if arguments[0] == "remove" && result.status != .removed { exit(1) }
            if arguments[0] == "restore-removal" && result.status != .rolledBack { exit(1) }
        } catch {
            FileHandle.standardError.write(Data(("组件操作未完成：" + error.localizedDescription + "\n").utf8))
            exit(1)
        }
    }
}
