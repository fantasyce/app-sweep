#if os(macOS)
import Foundation
import Darwin
import CFSafety

/// Controls this product's one fixed daemon. It cannot target another label,
/// disable system protections, or terminate an unrelated process.
struct LaunchdServiceLifecycle: ServiceDeploymentLifecycle {
    private static let target = "system/org.appsweep.system-service"
    private static let declaration = "/Library/LaunchDaemons/org.appsweep.system-service.plist"
    init() throws { try Self.requireRoot() }
    private static func requireRoot() throws {
        guard getuid() == 0, geteuid() == 0 else { throw SweepError.denied("系统组件生命周期要求管理员安装认证") }
    }
    private static func query(timeout: TimeInterval = 5) throws -> Bool {
        guard timeout.isFinite, timeout > 0, timeout <= 5 else { throw SweepError.invalid("系统组件注册核对时限无效") }
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        let result = try BoundedProcess.capture("/bin/launchctl",arguments:["print",target],timeout:timeout,mergeStderr:true)
        if result.status == 0 { return true }
        // ESRCH is not inferred from arbitrary command failures. Also establish
        // that launchd's system domain is available before accepting absence.
        guard result.status == 113 else { throw SweepError.incomplete("系统组件注册状态未确认") }
        let remaining = deadline - ProcessInfo.processInfo.systemUptime
        guard remaining > 0 else { throw SweepError.incomplete("系统组件注册核对超过时限") }
        _ = try BoundedProcess.run("/bin/launchctl",arguments:["print","system"],timeout:remaining)
        return false
    }
    func stop() async throws {
        try Self.requireRoot()
        if try Self.query() {
            _ = try BoundedProcess.run("/bin/launchctl",arguments:["bootout",Self.target],timeout:10)
        }
        try await ServiceStopReadiness.wait(timeout:5) { try Self.query(timeout:$0) }
        let processes = try ActivityInspector.processes(BoundedProcess.run("/bin/ps",arguments:["-ww","-axo","pid=,command="],timeout:5),ownPID:getpid())
        let program = "/Library/Application Support/App Sweep/Service/AppSweepSystemService"
        guard !processes.contains(where: { $0.pid != getpid() && $0.command.contains(program) }) else { throw SweepError.incomplete("系统组件仍有运行实例，不能替换程序") }
    }
    func start() async throws {
        try Self.requireRoot()
        guard try !Self.query() else { throw SweepError.denied("系统组件已注册，不能盲目重复安装") }
        let pins = try RootServiceConfiguration.load()
        _ = try BoundedProcess.run("/bin/launchctl",arguments:["bootstrap","system",Self.declaration],timeout:10)
        // A socket-activated job is healthy only after the actual daemon has
        // produced a bounded challenge and its running code identity is pinned.
        let fd = try await ServiceStartupReadiness.connect(timeout:5) { remaining in
            let fd = as_connect_system_service_health(remaining)
            return (fd,fd < 0 ? errno : 0)
        }
        defer { as_close(fd) }
        let health = try await LocalControlChannel.readWhenReady(socket:fd,deadline:ProcessInfo.processInfo.systemUptime + 10)
        try SystemServiceHealth.validate(health)
        _ = try LocalPeerAuthentication.authenticateRootService(socket:fd,requirement:pins.pins.requirement(for:.service))
        try pins.verifyUnchanged()
        try LocalControlChannel.write(SystemServiceHealth.acknowledgement(for:health),socket:fd)
    }
}
#endif
