import Foundation
import Darwin
import AppSweepCore
import OSLog

@main
struct AppSweepSystemServiceMain {
    static func main() async {
        guard CommandLine.arguments.count == 1 else { exit(64) }
        let lifecycle = Logger(subsystem:"org.appsweep.system-service",category:"lifecycle")
        lifecycle.notice("System service process entered its fixed launchd entry point")
        do { try await SystemServiceHost.run() }
        catch {
            // Only fixed startup/configuration failures reach this boundary.
            // Session errors stay inside the host and never expose user data.
            lifecycle.error("System service stopped: \(String(describing:error),privacy:.public)")
            FileHandle.standardError.write(Data("App Sweep system service stopped; verify the installed configuration.\n".utf8))
            exit(78)
        }
    }
}
