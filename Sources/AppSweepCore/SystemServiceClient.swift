#if os(macOS)
import Foundation
import Darwin
import CFSafety

private final class OwnedControlSocket: @unchecked Sendable {
    let fd: Int32
    init(_ fd: Int32) { self.fd = fd }
    func stop() { _ = shutdown(fd,SHUT_RDWR) }
    deinit { as_close(fd) }
}

/// A connection to the fixed installed service. There are no caller-supplied
/// paths, credentials or executable plans, and failed operations are never retried.
public actor SystemServiceClient {
    private var connection: OwnedControlSocket?
    private let nonce: Data
    private let pins: LoadedRootServicePins?
    private let deadline: TimeInterval
    private var sequence: UInt64 = 1
    private var inFlight = false
    private var needsHelperOwnership = false

    private init(connection: OwnedControlSocket, nonce: Data, pins: LoadedRootServicePins?) {
        self.connection = connection; self.nonce = nonce; self.pins = pins
        deadline = ProcessInfo.processInfo.systemUptime + 600
    }
    public static func connect() async throws -> SystemServiceClient {
        guard getuid() != 0, geteuid() == getuid() else { throw SweepError.denied("请从普通用户应用连接系统服务") }
        let pins = try RootServiceConfiguration.load(), fd = as_connect_system_service(5000)
        guard fd >= 0 else { throw SweepError.denied("系统清理服务未安装、未运行或连接不安全") }
        let connection = OwnedControlSocket(fd)
        // A launchd-created listener can initially identify launchd as its peer.
        // Accept no business result or request until the daemon has sent its
        // bounded challenge and its exact live code identity is verified.
        var peer = ASPeerIdentity()
        guard as_peer_identity(fd,&peer) == 0, peer.real_uid == 0, peer.effective_uid == 0 else { throw SweepError.denied("系统握手端点不属于root") }
        try pins.verifyUnchanged()
        let nonce = try SystemServiceReply.helloNonce(await LocalControlChannel.readWhenReady(socket:fd,deadline:ProcessInfo.processInfo.systemUptime + 10))
        try authenticate(connection,pins:pins)
        return SystemServiceClient(connection:connection,nonce:nonce,pins:pins)
    }
    private static func authenticate(_ connection: OwnedControlSocket, pins: LoadedRootServicePins) throws {
        try pins.verifyUnchanged()
        _ = try LocalPeerAuthentication.authenticateRootService(socket:connection.fd,requirement:pins.pins.requirement(for:.service))
        try pins.verifyUnchanged()
    }
    #if DEBUG
    /// Test transport only, inside the current non-root process. This cannot
    /// select a production endpoint or grant the service any execution authority.
    static func fixture(socket: Int32) async throws -> SystemServiceClient {
        let connection = OwnedControlSocket(socket)
        var peer = ASPeerIdentity()
        guard getuid() != 0, geteuid() == getuid(), as_peer_identity(socket,&peer) == 0,
              peer.effective_uid == getuid(), peer.real_uid == getuid(), peer.pid == getpid() else { throw SweepError.denied("客户端传输夹具必须是当前普通用户进程的本机套接字") }
        let nonce = try SystemServiceReply.helloNonce(await LocalControlChannel.readWhenReady(socket:socket,deadline:ProcessInfo.processInfo.systemUptime + 5))
        return SystemServiceClient(connection:connection,nonce:nonce,pins:nil)
    }
    #endif
    public func close() { connection?.stop(); connection = nil }
    var hasActiveConnection: Bool { connection != nil }
    public func status(maximumDuration:TimeInterval=10) async throws -> SystemServiceStatus {
        guard maximumDuration > 0,maximumDuration <= 10,maximumDuration.isFinite else { throw SweepError.invalid("状态等待期限无效") }
        guard case .status(let value) = try await send(.status,maximumDuration:maximumDuration) else { throw SweepError.invalid("系统状态回复类型无效") }
        return value
    }
    public func scan(_ category: SystemCleanupCategory, maximumDuration: TimeInterval = 120) async throws -> ScanReport {
        guard maximumDuration > 0, maximumDuration <= 120, maximumDuration.isFinite else { throw SweepError.invalid("扫描等待期限无效") }
        guard case .scan(let value) = try await send(.scan(category:category),maximumDuration:maximumDuration) else { throw SweepError.invalid("系统扫描回复类型无效") }
        return value
    }
    public func review(scanID: UUID, candidateIDs: [UUID]) async throws -> CleanupPlan {
        guard case .plan(let value) = try await send(.review(scanID:scanID,candidateIDs:candidateIDs)) else { throw SweepError.invalid("系统计划回复类型无效") }
        return value
    }
    public func execute(planID: UUID) async throws -> RecoveryManifest {
        guard case .batch(let value) = try await send(.execute(planID:planID)) else { throw SweepError.invalid("系统执行回复类型无效") }
        return value
    }
    public func recoveryPage(after cursor: UUID? = nil) async throws -> RecoveryBatchPage {
        let action: PrivilegedAction = cursor.map { .nextBatches(after:$0) } ?? .batches
        guard case .batches(let value) = try await send(action) else { throw SweepError.invalid("系统恢复列表回复类型无效") }
        return value
    }
    public func recoveryBatch(id: UUID) async throws -> RecoveryManifest {
        guard case .batch(let value) = try await send(.batch(batchID:id)) else { throw SweepError.invalid("系统恢复详情回复类型无效") }
        return value
    }
    public func restore(batchID: UUID) async throws -> RecoveryManifest {
        guard case .batch(let value) = try await send(.restore(batchID:batchID)) else { throw SweepError.invalid("系统恢复回复类型无效") }
        return value
    }
    public func purge(batchID: UUID, confirmation: String) async throws -> RecoveryManifest {
        guard case .batch(let value) = try await send(.purge(batchID:batchID,confirmation:confirmation)) else { throw SweepError.invalid("系统清空回复类型无效") }
        return value
    }
    func send(_ action: PrivilegedAction, maximumDuration: TimeInterval? = nil) async throws -> SystemServiceResult {
        guard !inFlight else { throw SweepError.denied("系统连接正在处理另一个操作") }
        inFlight = true
        defer { inFlight = false }
        let started = ProcessInfo.processInfo.systemUptime
        if case .scan(.applicationHelpers) = action { needsHelperOwnership = true }
        if case .restore = action { needsHelperOwnership = true }
        if pins != nil {
            switch action {
            case .scan(let category) where category != .deletedUserArchives:
                try await refreshUserOwnership()
            case .review, .execute, .restore, .prepareApplicationTransfer, .commitApplicationTransfer:
                try await refreshUserOwnership()
            default: break
            }
        }
        try Task.checkCancellation()
        let remaining = maximumDuration.map { $0 - (ProcessInfo.processInfo.systemUptime - started) }
        if let remaining, remaining <= 0 { throw SweepError.incomplete("用户侧归属核对已用完本次扫描预算") }
        return try await exchange(action, maximumDuration: remaining)
    }
    private func refreshUserOwnership() async throws {
        // The enclosing operation owns the actor reservation across both the
        // read and acknowledgement. Cancellation also reaches the read worker.
        let includeHelpers = needsHelperOwnership
        let task = Task.detached { try UserOwnershipInventory.collect(home: SystemIdentity.home(), includeHelpers: includeHelpers) }
        let evidence = try await withTaskCancellationHandler(operation: { try await task.value }, onCancel: { task.cancel() })
        try Task.checkCancellation()
        guard case .ownershipAccepted = try await exchange(.ownership(evidence)) else {
            throw SweepError.denied("用户侧归属核对未被接受")
        }
    }
    private func exchange(_ action: PrivilegedAction, maximumDuration: TimeInterval? = nil) async throws -> SystemServiceResult {
        guard let connection else { throw SweepError.denied("系统连接已失效，请重新连接并核对操作状态") }
        do {
            try Task.checkCancellation()
            var requestDeadline=deadline
            if let maximumDuration {
                guard maximumDuration > 0,maximumDuration <= 120,maximumDuration.isFinite else { throw SweepError.invalid("只读等待期限无效") }
                switch action {
                case .scan,.status:requestDeadline=min(deadline,ProcessInfo.processInfo.systemUptime + maximumDuration)
                default:throw SweepError.denied("事务操作不能使用扫描等待期限")
                }
            }
            guard sequence <= 4096, ProcessInfo.processInfo.systemUptime < deadline else { throw SweepError.denied("系统连接已到期，请重新扫描和审查计划") }
            if let pins { try Self.authenticate(connection,pins:pins) }
            let request = PrivilegedRequest(protocolVersion:1,id:UUID(),nonce:nonce,sequence:sequence,action:action)
            let remaining = requestDeadline - ProcessInfo.processInfo.systemUptime
            guard remaining >= 0.001 else { throw SweepError.denied("系统连接已到期") }
            try LocalControlChannel.write(PrivilegedFrame.encode(request),socket:connection.fd,timeout:min(5,remaining))
            var reader = try SystemServiceReply.Reader(request:request)
            for _ in 0..<(SystemServiceReply.maximumBodyBytes / SystemServiceReply.chunkBytes) {
                let frame = try await LocalControlChannel.readWhenReady(socket:connection.fd,deadline:requestDeadline)
                if let value = try reader.append(frame) {
                    try Task.checkCancellation()
                    guard self.connection === connection else { throw SweepError.denied("系统连接已经关闭") }
                    if let pins { try Self.authenticate(connection,pins:pins) }
                    try validate(value,for:action)
                    sequence += 1
                    return value
                }
            }
            throw SweepError.denied("系统回复未在登记的分片数内完成")
        } catch {
            // The request may already have committed. A new connection must
            // inspect persistent batches instead of repeating it automatically.
            connection.stop(); self.connection = nil
            throw error
        }
    }
    private func validate(_ value: SystemServiceResult, for action: PrivilegedAction) throws {
        switch (action,value) {
        case (.prepareApplicationTransfer,.applicationTransferFailure(let message)),
             (.commitApplicationTransfer,.applicationTransferFailure(let message)),
             (.restoreApplicationTransfer,.applicationTransferFailure(let message)),
             (.purgeApplicationTransfer,.applicationTransferFailure(let message)):
            guard !message.isEmpty,message.utf8.count <= 4096,!message.contains("\0") else { throw SweepError.denied("管理员应用处理错误回复无效") }
            throw SweepError.denied(message)
        case (.ownership,.ownershipAccepted): break
        case (.status,.status(let status)):
            guard status.protocolVersion == 1, status.ruleVersion == SweepEngine.ruleVersion else { throw SweepError.denied("系统服务版本与客户端不一致") }
        case (.scan,.scan(let report)):
            guard report.ruleVersion == SweepEngine.ruleVersion else { throw SweepError.denied("系统扫描规则版本不一致") }
        case (.review(let scanID,let ids),.plan(let plan)):
            guard plan.reportID == scanID, plan.ruleVersion == SweepEngine.ruleVersion, Set(plan.items.map(\.id)) == Set(ids) else { throw SweepError.denied("系统审查计划与选择不一致") }
        case (.batches,.batches),(.nextBatches,.batches): break
        case (.batch(let id),.batch(let batch)),(.restore(let id),.batch(let batch)),(.purge(let id,_),.batch(let batch)):
            guard batch.id == id, batch.schemaVersion == RecoveryManifest.systemSchemaVersion, batch.requestingUserID == getuid() else { throw SweepError.denied("系统批次与请求或用户不一致") }
        case (.execute,.batch(let batch)):
            guard batch.schemaVersion == RecoveryManifest.systemSchemaVersion, batch.requestingUserID == getuid() else { throw SweepError.denied("系统执行结果与用户不一致") }
        case (.prepareApplicationTransfer(let batchID,let itemID),.applicationTransferReview(let review)):
            guard review.batchID == batchID,review.itemID == itemID else { throw SweepError.denied("应用管理员审查属于其他项目") }
        case (.commitApplicationTransfer,.applicationTransferReceipt(let receipt)):
            guard receipt.state == .moved else { throw SweepError.denied("应用管理员移动未完成") }
        case (.restoreApplicationTransfer(let batchID,let itemID),.applicationTransferReceipt(let receipt)):
            guard receipt.batchID == batchID,receipt.itemID == itemID,receipt.state == .restored else { throw SweepError.denied("应用管理员恢复回复不一致") }
        case (.purgeApplicationTransfer(let batchID,let itemID,_),.applicationTransferReceipt(let receipt)):
            guard receipt.batchID == batchID,receipt.itemID == itemID,receipt.state == .purged else { throw SweepError.denied("应用管理员清空回复不一致") }
        default: throw SweepError.denied("系统回复与当前操作不一致")
        }
    }
}
#endif
