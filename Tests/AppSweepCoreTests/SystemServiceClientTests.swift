#if os(macOS)
import Foundation
import Darwin
import XCTest
@testable import AppSweepCore

final class SystemServiceClientTests: XCTestCase, @unchecked Sendable {
    private func pair() throws -> [Int32] {
        var sockets = [Int32](repeating:-1,count:2)
        guard socketpair(AF_UNIX,SOCK_STREAM,0,&sockets) == 0 else { throw SweepError.filesystem("socketpair") }
        return sockets
    }
    func testTypedClientBindsServerChallengeAndSequencesMultipleRequests() async throws {
        let sockets = try pair(), nonce = Data(repeating:2,count:32)
        let server = Task.detached {
            defer { close(sockets[0]) }
            try LocalControlChannel.write(SystemServiceReply.hello(nonce:nonce),socket:sockets[0])
            var requests: [PrivilegedRequest] = []
            for _ in 0..<2 {
                let request = try PrivilegedFrame.decode(LocalControlChannel.read(socket:sockets[0]))
                requests.append(request)
                let result: SystemServiceResult
                if case .status = request.action {
                    result = .status(.init(protocolVersion:1,ruleVersion:SweepEngine.ruleVersion,executionEnabled:false,limitation:String(repeating:"纸",count:40000)))
                } else { result = .batches(.init(items:[],nextCursor:nil)) }
                let reply = try SystemServiceReply.prepare(result,for:request)
                for index in 0..<reply.partCount { try LocalControlChannel.write(reply.frame(at:index),socket:sockets[0]) }
            }
            return requests
        }
        let client = try await SystemServiceClient.fixture(socket:sockets[1])
        let first: SystemServiceResult
        do { first = try await client.send(.status) }
        catch { _ = try await server.value; throw error }
        guard case .status(let status) = first else { return XCTFail("Expected typed status") }
        XCTAssertFalse(status.executionEnabled); XCTAssertEqual(status.limitation?.count,40000)
        let second: SystemServiceResult
        do { second = try await client.send(.batches) }
        catch { _ = try await server.value; throw error }
        guard case .batches(let page) = second else { return XCTFail("Expected history page") }
        XCTAssertTrue(page.items.isEmpty)
        await client.close()
        let requests = try await server.value
        XCTAssertEqual(requests.map(\.sequence),[1,2]); XCTAssertEqual(Set(requests.map(\.id)).count,2)
        XCTAssertTrue(requests.allSatisfy { $0.nonce == nonce })
    }
    func testWrongResponseTypeClosesConnectionAndNeverRetriesAnOperation() async throws {
        let sockets = try pair()
        let server = Task.detached {
            defer { close(sockets[0]) }
            try LocalControlChannel.write(SystemServiceReply.hello(nonce:Data(repeating:3,count:32)),socket:sockets[0])
            let request = try PrivilegedFrame.decode(LocalControlChannel.read(socket:sockets[0]))
            let reply = try SystemServiceReply.prepare(.batches(.init(items:[],nextCursor:nil)),for:request)
            try LocalControlChannel.write(reply.frame(at:0),socket:sockets[0])
            do { _ = try LocalControlChannel.read(socket:sockets[0],timeout:0.1); return false } catch { return true }
        }
        let client = try await SystemServiceClient.fixture(socket:sockets[1])
        do { _ = try await client.send(.status); XCTFail("A response for the wrong action is not usable") } catch { }
        do { _ = try await client.send(.status); XCTFail("An invalidated connection must not retry") } catch { }
        let closed = try await server.value; XCTAssertTrue(closed)
    }
    func testConcurrentRequestIsRejectedWhileFirstRequestWaitsForReply() async throws {
        let sockets = try pair()
        let (ready,signal) = AsyncStream<Bool>.makeStream()
        let server = Task.detached {
            defer { close(sockets[0]); signal.finish() }
            try LocalControlChannel.write(SystemServiceReply.hello(nonce:Data(repeating:5,count:32)),socket:sockets[0])
            let request = try PrivilegedFrame.decode(LocalControlChannel.read(socket:sockets[0]))
            signal.yield(true)
            try await Task.sleep(nanoseconds:1_000_000_000)
            let result = SystemServiceResult.status(.init(protocolVersion:1,ruleVersion:SweepEngine.ruleVersion,executionEnabled:false,limitation:nil))
            let reply = try SystemServiceReply.prepare(result,for:request)
            try LocalControlChannel.write(reply.frame(at:0),socket:sockets[0])
        }
        let client = try await SystemServiceClient.fixture(socket:sockets[1])
        let first = Task { try await client.send(.status) }
        for await _ in ready { break }
        let start = ProcessInfo.processInfo.systemUptime
        do { _ = try await client.send(.batches); XCTFail("Overlapping operations must not queue or reuse the same sequence") } catch { }
        XCTAssertLessThan(ProcessInfo.processInfo.systemUptime - start,0.5,"An idle request must not block the client actor")
        guard case .status = try await first.value else { return XCTFail("First request should complete normally") }
        await client.close(); try await server.value
    }
    func testCloseInterruptsPendingReplyWithoutClosingAReusedDescriptor() async throws {
        let sockets = try pair(), (ready,signal) = AsyncStream<Bool>.makeStream()
        let server = Task.detached {
            defer { close(sockets[0]); signal.finish() }
            try LocalControlChannel.write(SystemServiceReply.hello(nonce:Data(repeating:6,count:32)),socket:sockets[0])
            _ = try PrivilegedFrame.decode(LocalControlChannel.read(socket:sockets[0]))
            signal.yield(true)
            do { _ = try LocalControlChannel.read(socket:sockets[0],timeout:2); return false } catch { return true }
        }
        let client = try await SystemServiceClient.fixture(socket:sockets[1])
        let pending = Task { try await client.send(.status) }
        for await _ in ready { break }
        let start = ProcessInfo.processInfo.systemUptime
        await client.close()
        do { _ = try await pending.value; XCTFail("Closing a waiting client must not publish a result") } catch { }
        XCTAssertLessThan(ProcessInfo.processInfo.systemUptime - start,1.5)
        do { _ = try await client.send(.status); XCTFail("Closed connection must not be reused") } catch { }
        let closed = try await server.value; XCTAssertTrue(closed)
    }
    func testReadOnlyScanUsesItsOwnDeadlineWithoutRetryingTheRequest() async throws {
        let sockets=try pair()
        let server=Task.detached {
            defer{close(sockets[0])}
            try LocalControlChannel.write(SystemServiceReply.hello(nonce:Data(repeating:9,count:32)),socket:sockets[0])
            let request=try PrivilegedFrame.decode(LocalControlChannel.read(socket:sockets[0]))
            try await Task.sleep(for:.seconds(1))
            return request
        }
        let client=try await SystemServiceClient.fixture(socket:sockets[1])
        let began=ProcessInfo.processInfo.systemUptime
        do{_=try await client.scan(.caches,maximumDuration:0.15);XCTFail("An unanswered read cannot return a report")}catch{}
        XCTAssertLessThan(ProcessInfo.processInfo.systemUptime-began,0.7,"Discovery must not wait for the 600-second transaction connection deadline")
        await client.close()
        let request=try await server.value
        guard case .scan(.caches)=request.action else{return XCTFail("Expected the one requested scan")}
        XCTAssertEqual(request.sequence,1)
    }
    func testBatchResponseCannotSubstituteAnotherUserOrBatchID() async throws {
        for foreignUser in [false,true] {
            let sockets = try pair(), requested = UUID()
            let server = Task.detached {
                defer { close(sockets[0]) }
                try LocalControlChannel.write(SystemServiceReply.hello(nonce:Data(repeating:7,count:32)),socket:sockets[0])
                let request = try PrivilegedFrame.decode(LocalControlChannel.read(socket:sockets[0]))
                var record = RecoveryManifest(schemaVersion:RecoveryManifest.systemSchemaVersion,id:foreignUser ? requested : UUID(),createdAt:Date(),status:.restored,entries:[],issue:nil)
                record.requestingUserID = getuid() + (foreignUser ? 1 : 0)
                let reply = try SystemServiceReply.prepare(.batch(record),for:request)
                for index in 0..<reply.partCount { try LocalControlChannel.write(reply.frame(at:index),socket:sockets[0]) }
            }
            let client = try await SystemServiceClient.fixture(socket:sockets[1])
            do { _ = try await client.send(.batch(batchID:requested)); XCTFail("Wrong batch or requesting UID must fail") } catch { }
            await client.close(); try await server.value
        }
    }
    func testProductionConnectionCannotUseAnOrdinaryTestSocketAsRootService() async throws {
        // No service is installed by this test, and no caller can supply its path.
        do {
            let client = try await SystemServiceClient.connect()
            await client.close()
            XCTFail("An uninstalled/unverified service must not connect")
        } catch { }
    }
}
#endif
