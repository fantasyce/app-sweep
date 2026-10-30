import Foundation
import XCTest
@testable import AppSweepCore

final class RecoveryListingTests:XCTestCase,@unchecked Sendable {
    func testCancelledPageLoadDoesNotReadAndPublishHistory() async throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let vault = try SafeDirectory(path:f.home).privateChild("vault")
        let record = RecoveryManifest(schemaVersion:RecoveryManifest.currentSchemaVersion,id:UUID(),createdAt:Date(),status:.restored,entries:[],issue:nil)
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        try vault.privateChild(record.id.uuidString).write(encoder.encode(record),name:"manifest.json")
        let engine = f.engine()
        let operation = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await engine.recoveryPage(after:nil)
        }
        do { _ = try await operation.value; XCTFail("Cancelled history must not publish a page") }
        catch is CancellationError { }
    }

    func testNewestBatchesRemainFirstAfterReopeningWithStablePages() async throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let vault = try SafeDirectory(path:f.home).privateChild("vault")
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        func id(_ number: Int) -> UUID { UUID(uuidString:String(format:"00000000-0000-0000-0000-%012d",number))! }
        func write(_ number: Int, at time: TimeInterval) throws {
            let record = RecoveryManifest(schemaVersion:RecoveryManifest.currentSchemaVersion,id:id(number),createdAt:Date(timeIntervalSince1970:time),status:.restored,entries:[],issue:nil)
            try vault.privateChild(record.id.uuidString).write(encoder.encode(record),name:"manifest.json")
        }
        for number in 1...18 { try write(number,at:number == 2 ? 1 : Double(number)) }
        let first = try await f.engine().recoveryPage(after:nil)
        XCTAssertEqual(first.items.map(\.id),[18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3].map(id))
        XCTAssertEqual(first.nextCursor,id(3))

        // A newer batch added ahead of the cursor must not duplicate older rows.
        try write(99,at:1000)
        let second = try await f.engine().recoveryPage(after:first.nextCursor)
        XCTAssertEqual(second.items.map(\.id),[id(1),id(2)])
        XCTAssertNil(second.nextCursor)
        XCTAssertEqual(Set(first.items.map(\.id) + second.items.map(\.id)).count,18)
        let reopened = try await f.engine().recoveryPage(after:nil)
        XCTAssertEqual(reopened.items.first?.id,id(99))
        XCTAssertEqual(reopened.items.dropFirst().map(\.id),[18,17,16,15,14,13,12,11,10,9,8,7,6,5,4].map(id))
    }

    func testOneInvalidRecordDoesNotHideIndependentRecoverableBatches()async throws{
        let f=try RecoveryTests.Fixture();defer{try? f.clean()};let engine=f.engine()
        let report=await engine.adoptFixture([f.candidate],snapshots:[f.candidate.id:f.snapshot]),plan=try await engine.makePlan(reportID:report.id,selected:[f.candidate.id],includeUserData:false),batch=try await engine.execute(planID:plan.id)
        let invalidID=UUID(),directory=try SafeDirectory(path:f.vault).privateChild(invalidID.uuidString)
        try directory.write(Data("invalid record".utf8),name:"manifest.json")
        let list=try await engine.recoveryBatches(),placeholder=try XCTUnwrap(list.first{$0.id == invalidID})
        XCTAssertEqual(list.count,2);XCTAssertEqual(placeholder.status,.needsAttention);XCTAssertTrue(placeholder.entries.isEmpty)
        XCTAssertNotNil(placeholder.issue);XCTAssertTrue(placeholder.hasUnconfirmedObjects);XCTAssertFalse(placeholder.canPurge)
        let page=try await engine.recoveryPage(after:nil)
        XCTAssertEqual(Set(page.items.map(\.id)),Set([batch.id,invalidID]))
        do{_=try await engine.restore(batchID:invalidID);XCTFail("Placeholder is not restore authority")}catch{}
        do{_=try await engine.purge(batchID:invalidID,confirmation:"永久清空 "+invalidID.uuidString);XCTFail("Placeholder is not purge authority")}catch{}
        let restored=try await engine.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored)
        XCTAssertEqual(try String(contentsOfFile:f.source+"/data",encoding:.utf8),"regenerable")
    }
}
