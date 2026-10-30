#if os(macOS)
import Foundation

/// Invoked only at the existing user engine's durable mutation points. Each
/// operation uses the fixed authenticated endpoint; lost replies are never retried.
enum ApplicationTransferClient {
    static func required(for item:Candidate,sourcePath:String?=nil,restoring:Bool=false) -> Bool {
        guard item.category == .application,item.identity?.owner == 0 else { return false }
        // Ownership alone is not a need for elevation. Preserve the existing
        // ordinary route for administrator-owned but user-writable bundles,
        // including their recovery from a location where the original is absent.
        let source=sourcePath ?? item.path
        var parents=Set([URL(fileURLWithPath:source).deletingLastPathComponent().path])
        if restoring { parents.insert(URL(fileURLWithPath:item.path).deletingLastPathComponent().path) }
        return !FileManager.default.isWritableFile(atPath:source) || parents.contains{!FileManager.default.isWritableFile(atPath:$0)}
    }
    static func preflight() async throws {
        let client=try await SystemServiceClient.connect()
        do {
            let status=try await client.status()
            guard status.executionEnabled else { throw SweepError.denied(status.limitation ?? "管理员应用处理未启用") }
            await client.close()
        } catch { await client.close();throw error }
    }
    static func isolate(batchID:UUID,itemID:UUID,snapshot:FileSnapshot) async throws {
        let client=try await SystemServiceClient.connect()
        do {
            guard case .applicationTransferReview(let review)=try await client.send(.prepareApplicationTransfer(batchID:batchID,itemID:itemID)),
                  review.originalPath == snapshot.path,review.identity == snapshot.identity,
                  review.batchID == batchID,review.itemID == itemID else { throw SweepError.stale("管理员审查与用户核对的应用不一致") }
            guard case .applicationTransferReceipt(let receipt)=try await client.send(.commitApplicationTransfer(reviewID:review.id)),
                  receipt.batchID == batchID,receipt.itemID == itemID,receipt.state == .moved else { throw SweepError.denied("管理员应用移动未确认") }
            await client.close()
        } catch { await client.close();throw error }
    }
    static func restore(batchID:UUID,itemID:UUID) async throws {
        try await complete(.restoreApplicationTransfer(batchID:batchID,itemID:itemID))
    }
    static func purge(batchID:UUID,itemID:UUID,confirmation:String) async throws {
        try await complete(.purgeApplicationTransfer(batchID:batchID,itemID:itemID,confirmation:confirmation))
    }
    private static func complete(_ action:PrivilegedAction) async throws {
        let client=try await SystemServiceClient.connect()
        do {
            guard case .applicationTransferReceipt = try await client.send(action) else { throw SweepError.denied("管理员应用处理回复无效") }
            await client.close()
        } catch { await client.close();throw error }
    }
}
#endif
