#if os(macOS)
import Foundation
import Security

public struct SystemServiceStatus: Codable, Sendable {
    public let protocolVersion: Int
    public let ruleVersion: String
    public let executionEnabled: Bool
    public let limitation: String?
    public let accessProbe: AccessReadiness.Result?
    public let accessSubject: String?
    public init(protocolVersion: Int, ruleVersion: String, executionEnabled: Bool, limitation: String?, accessProbe: AccessReadiness.Result? = nil, accessSubject: String? = nil) {
        self.protocolVersion = protocolVersion; self.ruleVersion = ruleVersion
        self.executionEnabled = executionEnabled; self.limitation = limitation
        self.accessProbe = accessProbe; self.accessSubject = accessSubject
    }
}
enum SystemServiceResult: Codable, Sendable {
    case status(SystemServiceStatus)
    case ownershipAccepted
    case scan(ScanReport)
    case plan(CleanupPlan)
    case batches(RecoveryBatchPage)
    case batch(RecoveryManifest)
    case applicationTransferReview(ApplicationTransferReview)
    case applicationTransferReceipt(ApplicationTransferReceipt)
    case applicationTransferFailure(message: String)
}

/// One authenticated connection owns its scans and one-use executable plans.
/// Socket lifetime belongs to the server; no request supplies credentials or paths.
actor SystemServiceSession {
    nonisolated let nonce: Data
    private let scope: SystemCleanupScope
    private let engine: SystemCleanupEngine
    private let socket: Int32?
    private let pins: LoadedRootServicePins?
    private let deadline: TimeInterval
    private var session: PrivilegedSession
    private var plans: PrivilegedPlanRegistry
    private var inFlight = false
    private var serving = false
    private var applicationTransfers: ApplicationTransferService?

    private init(scope: SystemCleanupScope, peer: AuthenticatedLocalPeer, nonce: Data,
                 socket: Int32?, pins: LoadedRootServicePins?) throws {
        guard peer.uid == scope.requesterUID, nonce.count == 32 else { throw SweepError.denied("系统连接与认证用户不一致") }
        try scope.verify()
        self.scope = scope; self.nonce = nonce; self.socket = socket; self.pins = pins
        engine = try SystemCleanupEngine(scope:scope)
        session = PrivilegedSession(peer:peer,nonce:nonce)
        plans = try PrivilegedPlanRegistry(peer:peer,nonce:nonce)
        deadline = ProcessInfo.processInfo.systemUptime + 600
    }
    static func authenticated(socket: Int32) throws -> SystemServiceSession {
        let pins = try RootServiceConfiguration.load()
        let peer = try LocalPeerAuthentication.authenticate(socket:socket,requirement:pins.pins.requirement(for:.client))
        let scope = try SystemCleanupScope.authenticated(peer)
        var nonce = Data(count:32)
        let status = nonce.withUnsafeMutableBytes { bytes in SecRandomCopyBytes(kSecRandomDefault,bytes.count,bytes.baseAddress!) }
        guard status == errSecSuccess else { throw SweepError.denied("系统连接随机挑战生成失败") }
        try pins.verifyUnchanged()
        return try Self(scope:scope,peer:peer,nonce:nonce,socket:socket,pins:pins)
    }
    #if DEBUG
    static func fixture(scope: SystemCleanupScope, peer: AuthenticatedLocalPeer, nonce: Data) throws -> SystemServiceSession {
        guard scope.fixture else { throw SweepError.denied("普通会话夹具不能授予系统权限") }
        return try Self(scope:scope,peer:peer,nonce:nonce,socket:nil,pins:nil)
    }
    func acceptFixture(_ request: PrivilegedRequest, peer: AuthenticatedLocalPeer) async throws -> SystemServiceResult {
        guard scope.fixture, socket == nil, pins == nil else { throw SweepError.denied("不能向生产系统连接注入身份") }
        return try await perform(request,peer:peer)
    }
    #endif
    func accept(_ request: PrivilegedRequest) async throws -> SystemServiceResult {
        let peer = try authenticatedPeer()
        return try await perform(request,peer:peer)
    }
    private func authenticatedPeer() throws -> AuthenticatedLocalPeer {
        guard let socket, let pins, !scope.fixture else { throw SweepError.denied("缺少实际认证套接字") }
        try pins.verifyUnchanged()
        let peer = try LocalPeerAuthentication.authenticate(socket:socket,requirement:pins.pins.requirement(for:.client))
        try pins.verifyUnchanged()
        return peer
    }
    func serve() async throws {
        guard !serving, let socket else { throw SweepError.denied("系统连接缺少套接字或已在处理") }
        serving = true
        defer { serving = false }
        _ = try authenticatedPeer()
        try LocalControlChannel.write(SystemServiceReply.hello(nonce:nonce),socket:socket)
        for _ in 0..<4096 {
            try Task.checkCancellation()
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            guard remaining >= 0.001 else { throw SweepError.denied("系统连接已到期") }
            let frame = try await LocalControlChannel.readWhenReady(socket:socket,deadline:deadline)
            let request = try PrivilegedFrame.decode(frame)
            let result = try await accept(request)
            _ = try authenticatedPeer()
            let reply = try SystemServiceReply.prepare(result,for:request)
            for index in 0..<reply.partCount {
                let remaining = deadline - ProcessInfo.processInfo.systemUptime
                guard remaining >= 0.001 else { throw SweepError.denied("系统连接已到期，未发送完整结果") }
                try LocalControlChannel.write(reply.frame(at:index),socket:socket,timeout:min(5,remaining))
            }
        }
    }
    private func perform(_ request: PrivilegedRequest, peer: AuthenticatedLocalPeer) async throws -> SystemServiceResult {
        guard !inFlight, ProcessInfo.processInfo.systemUptime < deadline else { throw SweepError.denied("系统连接正在处理操作或已经到期，请重新连接") }
        inFlight = true
        defer { inFlight = false }
        try Task.checkCancellation()
        try scope.verify()
        try session.accept(request,authenticatedPeer:peer)
        do { switch request.action {
        case .ownership(let evidence):
            try scope.userInventory.replace(evidence)
            return .ownershipAccepted
        case .status:
            let policy = SafetyPolicy(systemScope:scope)
            return .status(.init(protocolVersion:1,ruleVersion:SweepEngine.ruleVersion,executionEnabled:policy.executionEnabled,
                                 limitation:policy.executionEnabled ? nil : "系统清理规则尚未通过当前平台的管理员验收",
                                 accessProbe:scope.fixture ? nil : AccessPreparationProbe.system(), accessSubject:pins?.pins.serviceBuild))
        case .scan(let category):
            let report: ScanReport
            do { report = try await engine.scan(category) }
            catch is CancellationError { throw CancellationError() }
            catch {
                // A read-only discovery failure is a result, not a broken wire.
                // No report is registered and no plan can use this identifier.
                try scope.verify()
                return .scan(ScanReport(schemaVersion: 1, id: UUID(), createdAt: Date(),
                    ruleVersion: SweepEngine.ruleVersion, applicationPath: nil, candidates: [],
                    complete: false, issues: [String(error.localizedDescription.prefix(4096))], platformLimitation: nil))
            }
            try plans.register(report,peer:peer,nonce:nonce,uptime:ProcessInfo.processInfo.systemUptime)
            return .scan(report)
        case .review(let scanID,let ids):
            try plans.verifyReview(scanID:scanID,selected:ids,peer:peer,nonce:nonce,uptime:ProcessInfo.processInfo.systemUptime)
            let plan = try await engine.makePlan(reportID:scanID,selected:Set(ids))
            try plans.registerReviewed(plan,peer:peer,nonce:nonce,uptime:ProcessInfo.processInfo.systemUptime)
            return .plan(plan)
        case .execute(let id):
            let plan = try plans.consume(planID:id,peer:peer,nonce:nonce,uptime:ProcessInfo.processInfo.systemUptime)
            return .batch(try await engine.execute(planID:plan.id))
        case .batches: return .batches(try await engine.recoveryPage(after:nil))
        case .nextBatches(let cursor): return .batches(try await engine.recoveryPage(after:cursor))
        case .batch(let id): return .batch(try await engine.recoveryBatch(id:id))
        case .restore(let id): return .batch(try await engine.restore(batchID:id))
        case .purge(let id,let confirmation): return .batch(try await engine.purge(batchID:id,confirmation:confirmation))
        case .prepareApplicationTransfer(let batchID,let itemID):
            return .applicationTransferReview(try await transferService().prepare(batchID:batchID,itemID:itemID))
        case .commitApplicationTransfer(let id):
            return .applicationTransferReceipt(try await transferService().commit(reviewID:id))
        case .restoreApplicationTransfer(let batchID,let itemID):
            return .applicationTransferReceipt(try await transferService().restore(batchID:batchID,itemID:itemID))
        case .purgeApplicationTransfer(let batchID,let itemID,let confirmation):
            return .applicationTransferReceipt(try await transferService().purge(batchID:batchID,itemID:itemID,confirmation:confirmation))
        } } catch is CancellationError { throw CancellationError() }
        catch {
            // Authentication/sequence checks above still fail closed. An
            // authenticated transfer failure is not a broken connection or a
            // success receipt; the caller must reconcile its durable journal.
            switch request.action {
            case .prepareApplicationTransfer,.commitApplicationTransfer,.restoreApplicationTransfer,.purgeApplicationTransfer:
                return .applicationTransferFailure(message:String(error.localizedDescription.prefix(1024)))
            default: throw error
            }
        }
    }
    private func transferService() throws -> ApplicationTransferService {
        if let applicationTransfers { return applicationTransfers }
        var inspectionProcess: (@Sendable (Int32) throws -> Bool)?
        if let socket,let pins {
            let original=session.peer
            inspectionProcess={ pid in
                guard pid == original.pid else { return false }
                // Reauthenticate at the point of excluding a command operand;
                // neither a supplied PID nor a reused PID grants this exception.
                try pins.verifyUnchanged()
                let actual=try LocalPeerAuthentication.authenticate(socket:socket,requirement:pins.pins.requirement(for:.client))
                guard actual.uid == original.uid,actual.pid == original.pid,actual.auditToken == original.auditToken else {
                    throw SweepError.denied("应用检查客户端身份已改变")
                }
                return true
            }
        }
        let service=try ApplicationTransferService(scope:scope,inspectionProcess:inspectionProcess)
        applicationTransfers=service;return service
    }
}
#endif
