import Foundation
import CFSafety

/// Borrows a connected local socket. Closing and peer authentication belong to
/// the caller; a received frame alone grants no filesystem authority.
enum LocalControlChannel {
    private static func milliseconds(_ timeout: TimeInterval) throws -> Int32 {
        guard timeout >= 0.001, timeout <= 10 else { throw SweepError.invalid("本机控制连接时限无效") }
        return Int32(timeout * 1000)
    }
    /// Idle waiting never consumes a header. Once readable, the entire frame
    /// must still arrive within its short transfer deadline.
    static func wait(socket: Int32, timeout: TimeInterval = 1) throws -> Bool {
        let result = try as_wait_control_frame(socket,milliseconds(timeout))
        guard result == 0 || result == -2 else { throw SweepError.denied("本机控制连接已断开或无效") }
        return result == 0
    }
    private static let waitQueue = DispatchQueue(label:"org.appsweep.control-wait",qos:.utility,attributes:.concurrent)
    private static func waitWithoutBlockingExecutor(socket: Int32, timeout: TimeInterval) async throws -> Bool {
        try await withCheckedThrowingContinuation { continuation in
            waitQueue.async {
                do { continuation.resume(returning:try wait(socket:socket,timeout:timeout)) }
                catch { continuation.resume(throwing:error) }
            }
        }
    }
    static func readWhenReady(socket: Int32, deadline: TimeInterval) async throws -> Data {
        while true {
            try Task.checkCancellation()
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            guard remaining >= 0.001 else { throw SweepError.denied("本机控制连接已到期") }
            if try await waitWithoutBlockingExecutor(socket:socket,timeout:min(1,remaining)) {
                try Task.checkCancellation()
                let transfer = deadline - ProcessInfo.processInfo.systemUptime
                guard transfer >= 0.001 else { throw SweepError.denied("本机控制连接已到期") }
                return try read(socket:socket,timeout:min(5,transfer))
            }
        }
    }
    static func read(socket: Int32, timeout: TimeInterval = 5) throws -> Data {
        var buffer = [UInt8](repeating: 0, count: PrivilegedFrame.maximumPayload + 8), count = 0
        guard try as_read_control_frame(socket, &buffer, buffer.count, milliseconds(timeout), &count) == 0,
              count >= 8, count <= buffer.count else { throw SweepError.denied("本机控制消息超时、截断或连接无效") }
        return Data(buffer.prefix(count))
    }
    static func write(_ frame: Data, socket: Int32, timeout: TimeInterval = 5) throws {
        let limit = try milliseconds(timeout)
        let result = frame.withUnsafeBytes { as_write_control_frame(socket, $0.baseAddress, $0.count, limit) }
        guard result == 0 else { throw SweepError.denied("本机控制消息无法完整发送") }
    }
}
