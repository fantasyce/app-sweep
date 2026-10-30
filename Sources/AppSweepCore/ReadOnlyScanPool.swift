import Foundation

/// A native filesystem call cannot reliably be interrupted by Task cancellation.
/// Only read-only discovery may use this pool. A timed-out stage loses all of its
/// result/feedback authority; its native call may still be awaiting the OS. Keep
/// at most two such jobs alive rather than leaking a new job on every retry.
final class ReadOnlyScanPool: @unchecked Sendable {
    static let shared = ReadOnlyScanPool()
    private let lock = NSLock()
    private var running = 0
    private let maximum: Int
    init(maximum: Int = 2) { precondition((1...2).contains(maximum)); self.maximum = maximum }
    private func reserve() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard running < maximum else { return false }
        running += 1; return true
    }
    private func release() { lock.lock(); running -= 1; lock.unlock() }

    func run<Value: Sendable>(stage: String, timeout: TimeInterval = 30, maximumDuration: TimeInterval = 300,
                             progress: (@Sendable (ScanProgress) -> Void)? = nil,
                             operation: @escaping @Sendable (@escaping @Sendable (ScanProgress) -> Void) throws -> Value) throws -> Value {
        try Task.checkCancellation()
        guard timeout > 0, timeout.isFinite, maximumDuration >= timeout, maximumDuration.isFinite else { throw SweepError.invalid("扫描等待期限无效") }
        guard reserve() else { throw SweepError.incomplete(stage + "：已有文件访问仍在等待系统返回，此范围保留；可稍后重试或重新打开 App Sweep") }
        let state = ReadOnlyScanState<Value>(timeout:timeout,maximumDuration:maximumDuration)
        // Native I/O must not consume Swift's cooperative executor: a caller
        // synchronously awaiting its child there can starve the child itself.
        DispatchQueue.global(qos:.utility).async { [self] in
            let dictionary = Thread.current.threadDictionary
            let previous = dictionary[ScanCancellation.key]
            dictionary[ScanCancellation.key] = ScanReadContext(cancellation:state.cancellation,activity:{ state.didRead() },commit:{ action in state.commit(action) })
            defer {
                if let previous { dictionary[ScanCancellation.key] = previous }
                else { dictionary.removeObject(forKey:ScanCancellation.key) }
            }
            let result = Result {
                try ScanCancellation.check()
                let value = try operation { state.emit($0) }
                try ScanCancellation.check()
                return value
            }
            release()
            state.complete(result)
        }
        // A task group would wait for the blocked native call during teardown.
        // Only the owner of this wait cancels this read-only job; never kill an
        // application or system service to make discovery complete.
        do {
            while true {
                try Task.checkCancellation()
                state.condition.lock()
                let now = ProcessInfo.processInfo.systemUptime
                let deadline = state.deadline
                if now >= deadline {
                    state.abandoned = true; state.result = nil; state.condition.unlock()
                    throw SweepError.incomplete(stage + "：文件访问超时，此范围未确认并保留；其他范围继续核对")
                }
                let updates = state.pending
                state.pending.removeAll(keepingCapacity:true)
                let result = state.result
                if result != nil || !updates.isEmpty {
                    if result != nil { state.abandoned = true; state.result = nil }
                    state.condition.unlock()
                    // Caller feedback runs in the original scanning task, never
                    // under a native worker's lock or after this wait returns.
                    for update in updates { try Task.checkCancellation(); progress?(update); try Task.checkCancellation() }
                    if let result { try Task.checkCancellation(); return try result.get() }
                    continue
                }
                _ = state.condition.wait(until:Date().addingTimeInterval(min(0.05,deadline-now)))
                state.condition.unlock()
            }
        } catch {
            state.abandon(); throw error
        }
    }
}

private final class ReadOnlyScanState<Value: Sendable>: @unchecked Sendable {
    let condition = NSCondition()
    var lastActivity = ProcessInfo.processInfo.systemUptime
    var result: Result<Value,Error>?
    var pending: [ScanProgress] = []
    var abandoned = false
    let cancellation = ScanCancellationToken()
    let timeout: TimeInterval
    let absoluteDeadline: TimeInterval
    var deadline: TimeInterval { min(absoluteDeadline,lastActivity + timeout) }
    init(timeout: TimeInterval, maximumDuration: TimeInterval) {
        self.timeout = timeout; absoluteDeadline = lastActivity + maximumDuration
    }
    func didRead() {
        condition.lock(); defer { condition.unlock() }
        let now = ProcessInfo.processInfo.systemUptime
        guard !abandoned, now < deadline else { return }
        lastActivity = now
    }
    func commit(_ action: @Sendable () -> Void) {
        condition.lock(); defer { condition.unlock() }
        guard !abandoned, ProcessInfo.processInfo.systemUptime < deadline else { return }
        action()
    }
    func emit(_ value: ScanProgress) {
        condition.lock(); defer { condition.unlock() }
        guard !abandoned, ProcessInfo.processInfo.systemUptime < deadline else { return }
        lastActivity = ProcessInfo.processInfo.systemUptime
        // Coalesce repeated heartbeats and bound display-only feedback. This
        // queue never holds candidate/snapshot authority.
        if let last = pending.last, last.stage == value.stage, last.detail == value.detail { pending[pending.count-1] = value }
        else {
            if pending.count == 1024 { pending.removeFirst() }
            pending.append(value)
        }
        condition.signal()
    }
    func complete(_ value: Result<Value,Error>) {
        condition.lock(); defer { condition.unlock() }
        guard !abandoned else { return }
        result = value; condition.signal()
    }
    func abandon() {
        condition.lock(); abandoned = true; result = nil; pending.removeAll(); condition.unlock()
        cancellation.cancel()
    }
}

/// The caller's Swift task and the read-only native worker share cancellation,
/// including on macOS versions without custom task-executor support.
enum ScanCancellation {
    fileprivate static let key = "org.appsweep.read-only-scan-cancellation"
    static func check() throws {
        try Task.checkCancellation()
        if let context = Thread.current.threadDictionary[key] as? ScanReadContext { try context.cancellation.check() }
    }
}
/// Successful native read checkpoints renew inactivity, without inventing UI
/// findings or authorizing a partial result. Outside a bounded read-only scan,
/// this is a no-op: execution and recovery do not acquire timeout behavior.
enum ScanReadActivity {
    static func completed() {
        (Thread.current.threadDictionary[ScanCancellation.key] as? ScanReadContext)?.activity()
    }
    /// Completed read-only scopes share the worker's deadline authority. A
    /// scope finishing after timeout/cancellation cannot enter a partial report.
    static func commit(_ action: @Sendable () -> Void) {
        if let context=Thread.current.threadDictionary[ScanCancellation.key] as? ScanReadContext { context.commit(action) }
        else { action() }
    }
}
private final class ScanReadContext: NSObject {
    let cancellation: ScanCancellationToken
    let activity: @Sendable () -> Void
    let commit: @Sendable (@Sendable () -> Void) -> Void
    init(cancellation:ScanCancellationToken,activity:@escaping @Sendable () -> Void,commit:@escaping @Sendable (@Sendable () -> Void) -> Void) {
        self.cancellation = cancellation; self.activity = activity; self.commit=commit
    }
}
private final class ScanCancellationToken: NSObject, @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    func cancel() { lock.lock(); cancelled = true; lock.unlock() }
    func check() throws {
        lock.lock(); let value = cancelled; lock.unlock()
        if value { throw CancellationError() }
    }
}
