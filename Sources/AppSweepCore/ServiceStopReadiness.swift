#if os(macOS)
import Foundation

/// A successful bootout can precede removal of the launchd registration. Wait
/// only on confirmed observations; never issue a second stop or infer absence
/// from a query error, cancellation, or expired deadline.
enum ServiceStopReadiness {
    static func wait(timeout: TimeInterval, query: (TimeInterval) throws -> Bool) async throws {
        guard timeout.isFinite, timeout > 0, timeout <= 5 else { throw SweepError.invalid("系统组件停止时限无效") }
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        while true {
            try Task.checkCancellation()
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            guard remaining > 0 else { throw SweepError.incomplete("等待系统组件停止超时") }
            let registered = try query(remaining)
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw SweepError.incomplete("系统组件停止核对超过时限") }
            if !registered { return }
            let delay = min(0.05,deadline - ProcessInfo.processInfo.systemUptime)
            guard delay > 0 else { throw SweepError.incomplete("等待系统组件停止超时") }
            try await Task.sleep(nanoseconds:UInt64(delay*1_000_000_000))
        }
    }
}
#endif
