#if os(macOS)
import Foundation
import Darwin

/// launchd can return before its socket exists or its listener accepts. The
/// connector checks the fixed root-owned socket before connecting; absence and
/// a refused connection can be transient, never unsafe metadata or identity.
enum ServiceStartupReadiness {
    static func connect(timeout: TimeInterval, attempt: (Int32) -> (descriptor: Int32, error: Int32)) async throws -> Int32 {
        guard timeout.isFinite, timeout > 0, timeout <= 5 else { throw SweepError.invalid("系统组件就绪时限无效") }
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        while true {
            try Task.checkCancellation()
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            guard remaining > 0 else { throw SweepError.incomplete("等待系统组件连接端点超时") }
            let result = attempt(Int32(max(1,min(5000,ceil(remaining*1000)))))
            if result.descriptor >= 0 {
                // Never hand an unowned late descriptor to a cancelled caller.
                do {
                    try Task.checkCancellation()
                    guard ProcessInfo.processInfo.systemUptime < deadline else { throw SweepError.incomplete("系统组件连接超过就绪时限") }
                    return result.descriptor
                } catch { close(result.descriptor); throw error }
            }
            guard result.error == ENOENT || result.error == ECONNREFUSED else { throw SweepError.incomplete("新组件没有提供安全的本机连接（错误 \(result.error)）") }
            let delay = min(0.05,deadline - ProcessInfo.processInfo.systemUptime)
            guard delay > 0 else { throw SweepError.incomplete("等待系统组件连接端点超时") }
            try await Task.sleep(nanoseconds:UInt64(delay*1_000_000_000))
        }
    }
}
#endif
