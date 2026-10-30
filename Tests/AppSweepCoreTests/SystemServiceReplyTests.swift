#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

final class SystemServiceReplyTests: XCTestCase {
    func testHelloOnlyAcceptsTheExactVersionedServerChallenge() throws {
        let nonce = Data(repeating:6,count:32), frame = try SystemServiceReply.hello(nonce:nonce)
        XCTAssertEqual(try SystemServiceReply.helloNonce(frame),nonce)
        XCTAssertThrowsError(try SystemServiceReply.hello(nonce:Data()))
        XCTAssertThrowsError(try SystemServiceReply.helloNonce(changed(frame,{$0["protocolVersion"] = 2})))
        XCTAssertThrowsError(try SystemServiceReply.helloNonce(changed(frame,{$0["nonce"] = Data(repeating:6,count:31).base64EncodedString()})))
        XCTAssertThrowsError(try SystemServiceReply.helloNonce(changed(frame,{$0["unexpected"] = true})))
        XCTAssertThrowsError(try SystemServiceReply.helloNonce(Data(frame.dropLast())))
    }
    private func request() -> PrivilegedRequest { .init(protocolVersion:1,id:UUID(),nonce:Data(repeating:4,count:32),sequence:7,action:.status) }
    private func status(_ text: String) -> SystemServiceResult { .status(.init(protocolVersion:1,ruleVersion:SweepEngine.ruleVersion,executionEnabled:false,limitation:text)) }
    private func changed(_ frame: Data, _ edit: (inout [String:Any]) -> Void) throws -> Data {
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with:Data(frame.dropFirst(8))) as? [String:Any])
        edit(&object)
        let body = try JSONSerialization.data(withJSONObject:object,options:[.sortedKeys,.withoutEscapingSlashes]), n = UInt32(body.count)
        return Data([65,83,87,80,UInt8(truncatingIfNeeded:n >> 24),UInt8(truncatingIfNeeded:n >> 16),UInt8(truncatingIfNeeded:n >> 8),UInt8(truncatingIfNeeded:n)]) + body
    }
    func testUnicodeReplySpansBoundedFramesAndPublishesOnlyWhenComplete() throws {
        let request = request(), text = String(repeating:"纸面缓存核对",count:10000)
        let reply = try SystemServiceReply.prepare(status(text),for:request)
        XCTAssertGreaterThan(reply.partCount,1)
        var reader = try SystemServiceReply.Reader(request:request)
        for index in 0..<reply.partCount {
            let frame = try reply.frame(at:index)
            XCTAssertLessThanOrEqual(frame.count,PrivilegedFrame.maximumPayload + 8)
            let result = try reader.append(frame)
            if index + 1 < reply.partCount { XCTAssertNil(result) }
            else {
                guard case .status(let decoded) = result else { return XCTFail("Only the full typed result may be delivered") }
                XCTAssertEqual(decoded.limitation,text)
                XCTAssertFalse(decoded.executionEnabled)
            }
        }
        XCTAssertThrowsError(try reader.append(reply.frame(at:0)))
        XCTAssertThrowsError(try reply.frame(at:-1))
        XCTAssertThrowsError(try reply.frame(at:reply.partCount))
    }
    func testOutOfOrderDuplicateAndAnotherRequestCannotProduceAResult() throws {
        let request = request(), reply = try SystemServiceReply.prepare(status(String(repeating:"x",count:70000)),for:request)
        var outOfOrder = try SystemServiceReply.Reader(request:request)
        XCTAssertThrowsError(try outOfOrder.append(reply.frame(at:1)))
        XCTAssertThrowsError(try outOfOrder.append(reply.frame(at:0)),"A failed assembly is poisoned")
        var duplicate = try SystemServiceReply.Reader(request:request)
        XCTAssertNil(try duplicate.append(reply.frame(at:0)))
        XCTAssertThrowsError(try duplicate.append(reply.frame(at:0)))
        let otherRequests = [self.request(),PrivilegedRequest(protocolVersion:1,id:request.id,nonce:Data(repeating:5,count:32),sequence:request.sequence,action:.status),PrivilegedRequest(protocolVersion:1,id:request.id,nonce:request.nonce,sequence:8,action:.status)]
        for other in otherRequests {
            var reader = try SystemServiceReply.Reader(request:other)
            XCTAssertThrowsError(try reader.append(reply.frame(at:0)))
        }
    }
    func testOversizedUnknownAndTruncatedPacketsAreRejectedBeforeAssembly() throws {
        let request = request(), reply = try SystemServiceReply.prepare(status("bounded reply"),for:request), frame = try reply.frame(at:0)
        for malformed in [try changed(frame,{$0["bodyBytes"] = SystemServiceReply.maximumBodyBytes + 1}),try changed(frame,{$0["partCount"] = 2000}),try changed(frame,{$0["unexpected"] = "path"}),Data(frame.dropLast())] {
            var reader = try SystemServiceReply.Reader(request:request)
            XCTAssertThrowsError(try reader.append(malformed))
        }
    }
    func testAlteredBytesNeverPublishAPartialOrCompletedValue() throws {
        let request = request(), reply = try SystemServiceReply.prepare(status(String(repeating:"y",count:70000)),for:request)
        let first = try changed(reply.frame(at:0)) { object in
            var bytes = Data(base64Encoded:object["payload"] as! String)!
            bytes[0] ^= 1
            object["payload"] = bytes.base64EncodedString()
        }
        var reader = try SystemServiceReply.Reader(request:request)
        XCTAssertNil(try reader.append(first))
        for index in 1..<(reply.partCount - 1) { XCTAssertNil(try reader.append(reply.frame(at:index))) }
        XCTAssertThrowsError(try reader.append(reply.frame(at:reply.partCount - 1)))
    }
    func testHistoryReplyRejectsAnUnboundedPageBeforeEncodingAndRoundtripsSummaries() throws {
        let record = RecoveryManifest(schemaVersion:RecoveryManifest.systemSchemaVersion,id:UUID(),createdAt:Date(),status:.restored,entries:[],issue:nil)
        let summary = RecoveryBatchSummary(record), request = request()
        let excess = RecoveryBatchPage(items:Array(repeating:summary,count:17),nextCursor:nil)
        XCTAssertThrowsError(try SystemServiceReply.prepare(.batches(excess),for:request))
        let page = RecoveryBatchPage(items:[summary],nextCursor:summary.id)
        let reply = try SystemServiceReply.prepare(.batches(page),for:request)
        var reader = try SystemServiceReply.Reader(request:request)
        guard case .batches(let decoded) = try reader.append(reply.frame(at:0)) else { return XCTFail("Expected bounded history page") }
        XCTAssertEqual(decoded.items.map(\.id),[record.id]); XCTAssertEqual(decoded.nextCursor,record.id)
    }
    func testEncodingCannotExceedTheTotalResponseBudget() throws {
        XCTAssertThrowsError(try SystemServiceReply.prepare(status(String(repeating:"x",count:SystemServiceReply.maximumBodyBytes)),for:request()))
    }
}
#endif
