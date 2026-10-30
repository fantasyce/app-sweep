#if os(macOS)
import Foundation
import Darwin
import CFSafety

/// Fixed launchd entry point. It never binds, unlinks, or accepts a caller path.
public enum SystemServiceHost {
    public static func run() async throws {
        guard getuid() == 0, geteuid() == 0 else { throw SweepError.denied("系统服务必须由安装后的系统任务启动") }
        let pins = try RootServiceConfiguration.load()
        let listener = as_activate_system_listener()
        guard listener >= 0 else { throw SweepError.denied("系统服务未取得登记的启动套接字（错误 \(errno)）") }
        defer { as_close(listener) }
        try await withThrowingTaskGroup(of:Void.self) { group in
            var outstanding = 0
            defer { group.cancelAll() }
            while !Task.isCancelled {
                // Idle authenticated users must not monopolize the listener.
                // Filesystem mutation remains serialized by the engine's lock.
                if outstanding == 8 {
                    _ = try await group.next(); outstanding -= 1
                }
                try pins.verifyUnchanged()
                let connected = as_accept_system_peer(listener,1000)
                if connected == -2 { await Task.yield(); continue }
                guard connected >= 0 else { throw SweepError.denied("系统服务监听状态已改变") }
                outstanding += 1
                group.addTask {
                    defer { as_close(connected) }
                    do {
                        if try SystemServiceHealth.serveIfInstallationPeer(socket:connected) { return }
                        let session = try SystemServiceSession.authenticated(socket:connected)
                        try await session.serve()
                    } catch {
                        // Persistent transactions survive a failed connection;
                        // a later authenticated connection can inspect them.
                    }
                }
            }
        }
    }
}
#endif
