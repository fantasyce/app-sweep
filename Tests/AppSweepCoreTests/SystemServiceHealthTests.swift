#if os(macOS)
import Foundation
import Darwin
import XCTest
import CFSafety
@testable import AppSweepCore

final class SystemServiceHealthTests: XCTestCase, @unchecked Sendable {
    func testHealthConnectionStaysAliveUntilPeerVerificationAcknowledgement() async throws {
        var pair:[Int32] = [-1,-1]
        XCTAssertEqual(socketpair(AF_UNIX,SOCK_STREAM,0,&pair),0)
        let serverFD = pair[0], clientFD = pair[1]
        defer { close(clientFD) }
        let server = Task.detached {
            defer { close(serverFD) }
            try SystemServiceHealth.exchange(nonce:Data(repeating:7,count:32),socket:serverFD,timeout:1)
        }
        defer { server.cancel() }
        let received = try await LocalControlChannel.readWhenReady(socket:clientFD,deadline:ProcessInfo.processInfo.systemUptime + 1)
        try SystemServiceHealth.validate(received)
        // Model signature/credential checks after reading the reply. A
        // write-and-close health server loses its kernel peer identity here.
        try await Task.sleep(nanoseconds:50_000_000)
        var peer = ASPeerIdentity()
        XCTAssertEqual(as_peer_identity(clientFD,&peer),0)
        XCTAssertEqual(peer.pid,getpid())
        try LocalControlChannel.write(SystemServiceHealth.acknowledgement(for:received),socket:clientFD,timeout:0.5)
        try await server.value
    }
    func testHealthExchangeRefusesBusinessOrDifferentChallengeAcknowledgement() async throws {
        for wrong in [try SystemServiceReply.hello(nonce:Data(repeating:7,count:32)),try SystemServiceHealth.acknowledgement(for:SystemServiceHealth.frame(nonce:Data(repeating:8,count:32)))] {
            var pair:[Int32] = [-1,-1]
            XCTAssertEqual(socketpair(AF_UNIX,SOCK_STREAM,0,&pair),0)
            let serverFD = pair[0], clientFD = pair[1]
            defer { close(clientFD) }
            let server = Task.detached {
                defer { close(serverFD) }
                try SystemServiceHealth.exchange(nonce:Data(repeating:7,count:32),socket:serverFD,timeout:0.5)
            }
            let received = try await LocalControlChannel.readWhenReady(socket:clientFD,deadline:ProcessInfo.processInfo.systemUptime + 1)
            try SystemServiceHealth.validate(received)
            try LocalControlChannel.write(wrong,socket:clientFD,timeout:0.5)
            do { try await server.value; XCTFail("Health acknowledgement must bind its own purpose and challenge") } catch { }
        }
    }
    func testHealthCodecHasItsOwnPurposeAndCannotAcceptBusinessHelloOrMalformedNonce() throws {
        let nonce = Data(repeating:9,count:32)
        let frame = try SystemServiceHealth.frame(nonce:nonce)
        XCTAssertNoThrow(try SystemServiceHealth.validate(frame))
        XCTAssertThrowsError(try SystemServiceHealth.validate(SystemServiceReply.hello(nonce:nonce)))
        XCTAssertThrowsError(try SystemServiceReply.helloNonce(frame))
        for size in [0,31,33,4096] { XCTAssertThrowsError(try SystemServiceHealth.frame(nonce:Data(count:size))) }
        let text = try XCTUnwrap(String(data:frame,encoding:.utf8))
        XCTAssertThrowsError(try SystemServiceHealth.validate(Data((" " + text).utf8)))
    }
    func testOrdinaryUserCannotUseRootHealthConnectorOrReceiveHealthReply() throws {
        XCTAssertNotEqual(getuid(),0)
        XCTAssertLessThan(as_connect_system_service_health(10),0)
        var sockets: [Int32] = [-1,-1]
        XCTAssertEqual(socketpair(AF_UNIX,SOCK_STREAM,0,&sockets),0)
        defer { sockets.forEach { if $0 >= 0 { close($0) } } }
        XCTAssertFalse(try SystemServiceHealth.serveIfInstallationPeer(socket:sockets[0]))
        XCTAssertThrowsError(try LocalControlChannel.read(socket:sockets[1],timeout:0.01))
        XCTAssertThrowsError(try SystemServiceHealth.serveIfInstallationPeer(socket:-1))
    }
    func testHealthReplyTraversesTheActualBoundedControlChannel() throws {
        var sockets: [Int32] = [-1,-1]
        XCTAssertEqual(socketpair(AF_UNIX,SOCK_STREAM,0,&sockets),0)
        defer { sockets.forEach { if $0 >= 0 { close($0) } } }
        let frame = try SystemServiceHealth.frame(nonce:Data(repeating:7,count:32))
        try LocalControlChannel.write(frame,socket:sockets[0],timeout:0.1)
        let received = try LocalControlChannel.read(socket:sockets[1],timeout:0.1)
        XCTAssertEqual(received,frame)
        XCTAssertNoThrow(try SystemServiceHealth.validate(received))
    }
}
#endif
