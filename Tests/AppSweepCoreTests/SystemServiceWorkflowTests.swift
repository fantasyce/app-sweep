#if os(macOS)
import Foundation
import Darwin
import XCTest
@testable import AppSweepCore

/// Exercises the API used by the CLI/UI against the actual service session and
/// transaction engine. Only owned non-root VM/Intel fixtures may be used here.
final class SystemServiceWorkflowTests: XCTestCase, @unchecked Sendable {
    func testClientWorkflowPreservesTheReviewedPlanAndSupportsRecoveryAndExplicitPurge() async throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let library = f.home + "/MachineLibrary", domain = library + "/Caches/org.example.sweepfixture"
        try FileManager.default.createDirectory(atPath:domain,withIntermediateDirectories:true)
        let path = domain + "/payload", bytes = Data("actual service workflow".utf8)
        try bytes.write(to:URL(fileURLWithPath:path))
        let scope = try SystemCleanupScope.fixture(libraryRoot:library,applicationsRoot:f.home + "/Applications",userHome:f.home,requesterUID:getuid())
        let peer = AuthenticatedLocalPeer(uid:getuid(),pid:getpid(),auditToken:Data(repeating:4,count:32)), nonce = Data(repeating:2,count:32)
        let service = try SystemServiceSession.fixture(scope:scope,peer:peer,nonce:nonce)
        var sockets: [Int32] = [-1,-1]
        guard socketpair(AF_UNIX,SOCK_STREAM,0,&sockets) == 0 else { throw SweepError.filesystem("socketpair") }
        let serverSocket = sockets[0], clientSocket = sockets[1]
        let server = Task.detached {
            defer { close(serverSocket) }
            try LocalControlChannel.write(SystemServiceReply.hello(nonce:nonce),socket:serverSocket)
            var actions: [PrivilegedAction] = []
            for _ in 0..<9 {
                let request = try PrivilegedFrame.decode(await LocalControlChannel.readWhenReady(socket:serverSocket,deadline:ProcessInfo.processInfo.systemUptime + 20))
                actions.append(request.action)
                let result = try await service.acceptFixture(request,peer:peer)
                let reply = try SystemServiceReply.prepare(result,for:request)
                for index in 0..<reply.partCount { try LocalControlChannel.write(reply.frame(at:index),socket:serverSocket) }
            }
            return actions
        }
        let client = try await SystemServiceClient.fixture(socket:clientSocket)
        do {
            let status = try await client.status(); XCTAssertTrue(status.executionEnabled)
            let report = try await client.scan(.caches)
            let ids = report.selectableCandidates(includeUserData:false).map(\.id)
            XCTAssertEqual(report.selectableCandidates(includeUserData:false).map(\.path),[path])
            let plan = try await client.review(scanID:report.id,candidateIDs:ids)
            XCTAssertEqual(plan.reportID,report.id); XCTAssertEqual(plan.items.map(\.path),[path])
            let batch = try await client.execute(planID:plan.id)
            XCTAssertEqual(batch.status,.isolated); XCTAssertFalse(FileManager.default.fileExists(atPath:path))
            let page = try await client.recoveryPage()
            XCTAssertEqual(page.items.map(\.id),[batch.id]); XCTAssertNil(page.nextCursor)
            let detail = try await client.recoveryBatch(id:batch.id)
            XCTAssertEqual(detail.entries.map(\.original.path),[path])
            let end = try await client.recoveryPage(after:batch.id)
            XCTAssertTrue(end.items.isEmpty); XCTAssertNil(end.nextCursor)
            let restored = try await client.restore(batchID:batch.id)
            XCTAssertEqual(restored.status,.restored); XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:path)),bytes)
            let purged = try await client.purge(batchID:batch.id,confirmation:"永久清空 " + batch.id.uuidString)
            XCTAssertEqual(purged.status,.purged); XCTAssertFalse(purged.hasIndependentBackups)
            XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:path)),bytes,"Purging restored recovery copies must preserve the restored source")
            await client.close()
            let actions = try await server.value
            XCTAssertEqual(actions.count,9)
        } catch {
            await client.close(); _ = try? await server.value
            throw error
        }
    }
}
#endif
