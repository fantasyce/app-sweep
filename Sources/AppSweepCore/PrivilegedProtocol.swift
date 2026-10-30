import Foundation

public enum SystemCleanupCategory: String, Codable, Sendable { case caches, logs, deletedUserArchives, applicationHelpers }
enum PrivilegedAction: Codable, Sendable, Equatable {
    case status
    case ownership(UserOwnershipInventory)
    case scan(category: SystemCleanupCategory)
    case review(scanID: UUID, candidateIDs: [UUID])
    case execute(planID: UUID)
    case batches
    case nextBatches(after: UUID)
    case batch(batchID: UUID)
    case restore(batchID: UUID)
    case purge(batchID: UUID, confirmation: String)
    #if os(macOS)
    case prepareApplicationTransfer(batchID: UUID, itemID: UUID)
    case commitApplicationTransfer(reviewID: UUID)
    case restoreApplicationTransfer(batchID: UUID, itemID: UUID)
    case purgeApplicationTransfer(batchID: UUID, itemID: UUID, confirmation: String)
    #endif
}
struct PrivilegedRequest: Codable, Sendable, Equatable {
    let protocolVersion: Int
    let id: UUID
    let nonce: Data
    let sequence: UInt64
    let action: PrivilegedAction
}
enum PrivilegedFrame {
    static let maximumPayload = 64 * 1024
    static func validate(_ request: PrivilegedRequest) throws {
        guard request.protocolVersion == 1, request.nonce.count == 32, request.sequence > 0 else { throw SweepError.denied("系统请求版本、会话或顺序无效") }
        switch request.action {
        case .ownership(let evidence): try evidence.validate()
        case .review(_, let ids):
            guard !ids.isEmpty, ids.count <= 1000, Set(ids).count == ids.count else { throw SweepError.denied("系统计划选择为空、重复或超限") }
        case .purge(_, let confirmation):
            guard !confirmation.isEmpty, confirmation.utf8.count <= 256, !confirmation.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { throw SweepError.denied("永久清空确认无效") }
        #if os(macOS)
        case .purgeApplicationTransfer(let batchID, _, let confirmation):
            guard confirmation == "永久清空 " + batchID.uuidString else { throw SweepError.denied("应用永久清空确认无效") }
        #endif
        default: break
        }
    }
    private static func payload(_ request: PrivilegedRequest) throws -> Data {
        try validate(request)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(request)
        guard !data.isEmpty, data.count <= maximumPayload else { throw SweepError.denied("系统请求超过协议容量") }
        return data
    }
    static func encode(_ request: PrivilegedRequest) throws -> Data {
        let body = try payload(request), count = UInt32(body.count)
        return Data([65, 83, 87, 80, UInt8(truncatingIfNeeded: count >> 24), UInt8(truncatingIfNeeded: count >> 16), UInt8(truncatingIfNeeded: count >> 8), UInt8(truncatingIfNeeded: count)]) + body
    }
    static func decode(_ frame: Data) throws -> PrivilegedRequest {
        guard frame.count >= 8, frame.count <= maximumPayload + 8 else { throw SweepError.denied("系统消息截断或超限") }
        let bytes = [UInt8](frame.prefix(8))
        guard bytes.prefix(4) == [65,83,87,80] else { throw SweepError.denied("不是已登记的系统消息") }
        let length = bytes[4...7].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard length > 0, Int(length) == frame.count - 8 else { throw SweepError.denied("系统消息长度不一致") }
        let body = Data(frame.dropFirst(8))
        let request = try CanonicalControlJSON.decode(PrivilegedRequest.self, from: body)
        try validate(request)
        return request
    }
}
/// Shared request/configuration decoder with one bounded wire representation.
enum CanonicalControlJSON {
    static let maximumBytes = 64 * 1024
    static func encode<Value: Encodable>(_ value: Value) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(value)
        guard !data.isEmpty, data.count <= maximumBytes else { throw SweepError.denied("控制数据超过容量") }
        return data
    }
    static func decode<Value: Codable>(_ type: Value.Type, from data: Data) throws -> Value {
        guard !data.isEmpty, data.count <= maximumBytes else { throw SweepError.denied("控制数据为空或超限") }
        var depth = 0, inString = false, escaped = false
        for byte in data {
            if inString {
                if escaped { escaped = false }
                else if byte == 92 { escaped = true }
                else if byte == 34 { inString = false }
            } else if byte == 34 { inString = true }
            else if byte == 123 || byte == 91 {
                depth += 1
                guard depth <= 8 else { throw SweepError.denied("控制数据嵌套超限") }
            } else if byte == 125 || byte == 93 {
                depth -= 1
                guard depth >= 0 else { throw SweepError.denied("控制数据结构无效") }
            }
        }
        guard depth == 0, !inString, !escaped else { throw SweepError.denied("控制数据未完成") }
        let value = try JSONDecoder().decode(type, from: data)
        guard try encode(value) == data else { throw SweepError.denied("控制数据不是唯一规范编码") }
        return value
    }
}

struct PrivilegedSession {
    let peer: AuthenticatedLocalPeer
    let nonce: Data
    private(set) var nextSequence: UInt64 = 1
    private var acceptedIDs = Set<UUID>()
    init(peer: AuthenticatedLocalPeer, nonce: Data) { self.peer = peer; self.nonce = nonce }
    mutating func accept(_ request: PrivilegedRequest, authenticatedPeer: AuthenticatedLocalPeer) throws {
        try PrivilegedFrame.validate(request)
        guard peer.uid != 0, peer.pid > 0, nonce.count == 32, request.nonce == nonce,
              authenticatedPeer.uid == peer.uid, authenticatedPeer.pid == peer.pid,
              peer.auditToken.count == 32, authenticatedPeer.auditToken == peer.auditToken,
              request.sequence == nextSequence, acceptedIDs.count < 4096,
              !acceptedIDs.contains(request.id) else { throw SweepError.denied("系统会话身份、顺序或请求已改变，请重新建立连接") }
        acceptedIDs.insert(request.id); nextSequence += 1
    }
}
