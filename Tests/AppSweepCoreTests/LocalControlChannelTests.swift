#if os(macOS)
import Foundation
import Darwin
import XCTest
@testable import AppSweepCore

final class LocalControlChannelTests: XCTestCase {
    private func frame(_ sequence: UInt64 = 1) throws -> Data {
        try PrivilegedFrame.encode(PrivilegedRequest(protocolVersion: 1, id: UUID(), nonce: Data(repeating: 3, count: 32), sequence: sequence, action: .status))
    }
    private func pair() throws -> [Int32] {
        var sockets: [Int32] = [-1,-1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0 else { throw SweepError.filesystem("Native socketpair failed") }
        return sockets
    }
    func testIdleResponseMayArriveAfterTheShortFrameTransferTimeout() async throws {
        let sockets = try pair(); defer { sockets.forEach { close($0) } }
        let value = try frame()
        let server = Task.detached {
            try await Task.sleep(nanoseconds:5_200_000_000)
            try LocalControlChannel.write(value,socket:sockets[0])
        }
        let start = ProcessInfo.processInfo.systemUptime
        let received = try await LocalControlChannel.readWhenReady(socket:sockets[1],deadline:start + 8)
        XCTAssertEqual(received,value)
        XCTAssertGreaterThan(ProcessInfo.processInfo.systemUptime - start,5)
        try await server.value
        do { _ = try await LocalControlChannel.readWhenReady(socket:sockets[1],deadline:ProcessInfo.processInfo.systemUptime + 0.03); XCTFail("An idle connection must still have a total deadline") } catch { }
    }
    func testIdleWaitDoesNotConsumeFramesAndDistinguishesTimeoutFromBrokenPeer() throws {
        let sockets = try pair(); defer { close(sockets[0]); close(sockets[1]) }
        XCTAssertFalse(try LocalControlChannel.wait(socket:sockets[1],timeout:0.03))
        let value = try frame()
        try LocalControlChannel.write(value,socket:sockets[0])
        XCTAssertTrue(try LocalControlChannel.wait(socket:sockets[1],timeout:0.03))
        XCTAssertEqual(try LocalControlChannel.read(socket:sockets[1]),value)
        XCTAssertThrowsError(try LocalControlChannel.wait(socket:-1,timeout:0.03))
    }
    func testCompleteQueuedFrameRemainsReadableAfterThePeerCloses() throws {
        let sockets = try pair(); defer { close(sockets[1]) }
        let value = try frame()
        do {
            defer { close(sockets[0]) }
            try LocalControlChannel.write(value,socket:sockets[0])
        }
        XCTAssertTrue(try LocalControlChannel.wait(socket:sockets[1],timeout:0.1))
        XCTAssertEqual(try LocalControlChannel.read(socket:sockets[1]),value)
        XCTAssertThrowsError(try LocalControlChannel.read(socket:sockets[1],timeout:0.03))
    }
    func testFramesRoundtripAndCoalescedRequestsRemainSeparate() throws {
        let sockets = try pair(); defer { sockets.forEach { close($0) } }
        let first = try frame(), second = try frame(2)
        try LocalControlChannel.write(first, socket: sockets[0])
        try LocalControlChannel.write(second, socket: sockets[0])
        XCTAssertEqual(try LocalControlChannel.read(socket: sockets[1]), first)
        XCTAssertEqual(try LocalControlChannel.read(socket: sockets[1]), second)
    }
    func testTimeoutUsesATotalDeadlineAndTruncatedPayloadIsRefused() throws {
        let sockets = try pair(); defer { sockets.forEach { close($0) } }
        let start = ProcessInfo.processInfo.systemUptime
        XCTAssertThrowsError(try LocalControlChannel.read(socket: sockets[1], timeout: 0.03))
        XCTAssertLessThan(ProcessInfo.processInfo.systemUptime - start, 1)
        let header = Data([65,83,87,80,0,0,0,100])
        _ = header.withUnsafeBytes { send(sockets[0], $0.baseAddress, $0.count, 0) }
        XCTAssertThrowsError(try LocalControlChannel.read(socket: sockets[1], timeout: 0.03))
    }
    func testBrokenPeerDoesNotKillTheProcessAndNonLocalDescriptorsAreRefused() throws {
        let sockets = try pair(); close(sockets[1]); defer { close(sockets[0]) }
        XCTAssertThrowsError(try LocalControlChannel.write(frame(), socket: sockets[0]))
        let tcp = socket(AF_INET, SOCK_STREAM, 0); defer { if tcp >= 0 { close(tcp) } }
        XCTAssertThrowsError(try LocalControlChannel.write(frame(), socket: tcp))
        XCTAssertThrowsError(try LocalControlChannel.read(socket: -1, timeout: 0.01))
    }
    func testOversizedHeaderAndNonFrameWritesAreRefused() throws {
        let sockets = try pair(); defer { sockets.forEach { close($0) } }
        let oversized = Data([65,83,87,80,0,1,0,1])
        _ = oversized.withUnsafeBytes { send(sockets[0], $0.baseAddress, $0.count, 0) }
        XCTAssertThrowsError(try LocalControlChannel.read(socket: sockets[1], timeout: 0.03))
        XCTAssertThrowsError(try LocalControlChannel.write(Data(repeating: 0, count: 8), socket: sockets[0]))
    }
}
#endif
