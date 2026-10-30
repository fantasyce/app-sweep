import Foundation
import XCTest
@testable import AppSweepCore

final class PrivilegedProtocolTests: XCTestCase {
    private let nonce = Data(repeating: 77, count: 32)
    private func request(_ action: PrivilegedAction = .status, sequence: UInt64 = 1, id: UUID = UUID(), nonce: Data? = nil, version: Int = 1) -> PrivilegedRequest {
        PrivilegedRequest(protocolVersion: version, id: id, nonce: nonce ?? self.nonce, sequence: sequence, action: action)
    }
    private func rawFrame(_ payload: Data) -> Data {
        let count = UInt32(payload.count)
        return Data([65,83,87,80,UInt8(truncatingIfNeeded:count >> 24),UInt8(truncatingIfNeeded:count >> 16),UInt8(truncatingIfNeeded:count >> 8),UInt8(truncatingIfNeeded:count)]) + payload
    }
    func testTypedActionsRoundtripWithoutAnyPathOrCommandParameter() throws {
        let actions: [PrivilegedAction] = [.status, .scan(category: .caches), .scan(category: .logs), .scan(category:.deletedUserArchives), .review(scanID: UUID(), candidateIDs: [UUID()]), .execute(planID: UUID()), .batches, .nextBatches(after: UUID()), .batch(batchID: UUID()), .restore(batchID: UUID()), .purge(batchID: UUID(), confirmation: "explicit fixture confirmation")]
        for action in actions {
            let value = request(action)
            XCTAssertEqual(try PrivilegedFrame.decode(PrivilegedFrame.encode(value)), value)
        }
    }
    func testTruncatedOversizedTrailingAndWrongMagicFramesAreRefused() throws {
        let frame = try PrivilegedFrame.encode(request())
        for invalid in [Data(), Data(frame.dropLast()), frame + Data([0]), Data(repeating: 0, count: 8), rawFrame(Data(repeating: 32, count: PrivilegedFrame.maximumPayload + 1))] {
            XCTAssertThrowsError(try PrivilegedFrame.decode(invalid))
        }
    }
    func testDuplicateJSONKeysUnknownFieldsAndAlternativeEncodingsAreRefused() throws {
        let frame = try PrivilegedFrame.encode(request())
        let text = try XCTUnwrap(String(data: frame.dropFirst(8), encoding: .utf8))
        let tail = String(text.dropFirst())
        let duplicateID = "{\"id\":\"" + UUID().uuidString + "\"," + tail
        let variants: [String] = [" " + text, "{\"arbitraryPath\":\"/System\"," + tail, "{\"protocolVersion\":1," + tail, duplicateID]
        for body in variants {
            XCTAssertThrowsError(try PrivilegedFrame.decode(rawFrame(Data(body.utf8))))
        }
    }
    func testExcessiveNestingAndMalformedStringsAreRefusedBeforeDecoding() {
        let deep = String(repeating: "[", count: 1000) + "0" + String(repeating: "]", count: 1000)
        for text in [deep, "{\"a\":\"unterminated", "{]", "{}{}"] {
            XCTAssertThrowsError(try PrivilegedFrame.decode(rawFrame(Data(text.utf8))))
        }
    }
    func testUnsupportedVersionsInvalidNoncesAndExcessiveSelectionsAreRefused() {
        for invalid in [request(version: 2), request(sequence: 0), request(nonce: Data()), request(.review(scanID: UUID(), candidateIDs: [])), request(.review(scanID: UUID(), candidateIDs: Array(repeating: UUID(), count: 2))), request(.review(scanID: UUID(), candidateIDs: (0..<1001).map { _ in UUID() })), request(.purge(batchID: UUID(), confirmation: ""))] {
            XCTAssertThrowsError(try PrivilegedFrame.encode(invalid))
        }
    }
    func testSessionBindsKernelPeerNonceSequenceAndUniqueRequestID() throws {
        let peer = AuthenticatedLocalPeer(uid: 501, pid: 120, auditToken: Data(repeating: 8, count: 32))
        var session = PrivilegedSession(peer: peer, nonce: nonce)
        let first = request()
        try session.accept(first, authenticatedPeer: peer)
        XCTAssertEqual(session.nextSequence, 2)
        XCTAssertThrowsError(try session.accept(first, authenticatedPeer: peer))
        let other = AuthenticatedLocalPeer(uid: 502, pid: 120, auditToken: peer.auditToken)
        XCTAssertThrowsError(try session.accept(request(sequence: 2), authenticatedPeer: other))
        let reusedPID = AuthenticatedLocalPeer(uid: peer.uid, pid: peer.pid, auditToken: Data(repeating: 9, count: 32))
        XCTAssertThrowsError(try session.accept(request(sequence: 2), authenticatedPeer: reusedPID))
        XCTAssertThrowsError(try session.accept(request(sequence: 2, nonce: Data(repeating: 0, count: 32)), authenticatedPeer: peer))
        XCTAssertThrowsError(try session.accept(request(sequence: 2, id: first.id), authenticatedPeer: peer))
        XCTAssertEqual(session.nextSequence, 2, "Rejected requests cannot advance or poison the session")
        try session.accept(request(sequence: 2), authenticatedPeer: peer)
        XCTAssertEqual(session.nextSequence, 3)
    }
}
