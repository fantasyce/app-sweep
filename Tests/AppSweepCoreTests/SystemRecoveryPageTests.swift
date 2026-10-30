#if os(macOS)
import Foundation
import Darwin
import XCTest
@testable import AppSweepCore

final class SystemRecoveryPageTests: XCTestCase, @unchecked Sendable {
    private func fixture() throws -> (NativeAcceptanceTests.NativeFixture, SystemCleanupScope) {
        let f = try NativeAcceptanceTests.NativeFixture(), root = f.home + "/MachineLibrary"
        try FileManager.default.createDirectory(atPath:root,withIntermediateDirectories:true)
        return (f,try .fixture(libraryRoot:root,applicationsRoot:f.home + "/Applications",userHome:f.home,requesterUID:getuid()))
    }
    private func write(_ manifest: RecoveryManifest, scope: SystemCleanupScope) throws {
        let batch = try scope.openVault(create:true).privateChild(manifest.id.uuidString)
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        try batch.write(encoder.encode(manifest),name:"manifest.json")
    }
    private func manifest(_ scope: SystemCleanupScope, createdAt: Date = Date()) -> RecoveryManifest {
        var value = RecoveryManifest(schemaVersion:RecoveryManifest.systemSchemaVersion,id:UUID(),createdAt:createdAt,status:.restored,entries:[],issue:nil)
        value.requestingUserID = scope.requesterUID
        return value
    }
    func testSummaryPagesDiscoverEveryBatchAndDetailReadsOnlyTheSelectedBatch() async throws {
        let (f,scope) = try fixture(); defer { try? f.clean() }
        let engine = try SystemCleanupEngine(scope:scope)
        let empty = try await engine.recoveryPage(after:nil)
        XCTAssertTrue(empty.items.isEmpty); XCTAssertNil(empty.nextCursor)
        let records = (0..<35).map { manifest(scope,createdAt:Date(timeIntervalSince1970:Double(1000 + $0))) }
        for record in records { try write(record,scope:scope) }
        var found: [UUID] = [], cursor: UUID?
        repeat {
            let page = try await engine.recoveryPage(after:cursor)
            XCTAssertLessThanOrEqual(page.items.count,16)
            XCTAssertTrue(page.items.allSatisfy { $0.status == .restored && $0.entryCount == 0 && $0.isolatedBytes == 0 && !$0.hasIndependentBackups })
            found += page.items.map(\.id); cursor = page.nextCursor
        } while cursor != nil
        XCTAssertEqual(found,records.reversed().map(\.id))
        XCTAssertEqual(Set(found).count,35)
        let reopened = try await SystemCleanupEngine(scope:scope).recoveryPage(after:nil)
        XCTAssertEqual(reopened.items.first?.id,records.last?.id)
        let selected = try await engine.recoveryBatch(id:records[0].id)
        XCTAssertEqual(selected.id,records[0].id)
        do { _ = try await engine.recoveryPage(after:UUID()); XCTFail("Unknown cursor must not silently skip history") } catch { }
        do { _ = try await engine.recoveryBatch(id:UUID()); XCTFail("Unknown batch must not read another namespace") } catch { }
    }
    func testUnconfirmedSummaryDoesNotHideValidPagesOrAuthorizeAnotherUser() async throws {
        let (f,scope) = try fixture(); defer { try? f.clean() }
        let records = (0..<17).map { _ in manifest(scope) }.sorted { $0.id.uuidString < $1.id.uuidString }
        for record in records { try write(record,scope:scope) }
        let last = try XCTUnwrap(records.last), engine = try SystemCleanupEngine(scope:scope)
        let batch = try scope.openVault(create:false).existingPrivateChild(last.id.uuidString)
        try batch.write(Data("unread invalid record".utf8),name:"manifest.json")
        let page = try await engine.recoveryPage(after:nil)
        XCTAssertEqual(page.items.count,16)
        let remainder = try await engine.recoveryPage(after:page.nextCursor)
        XCTAssertEqual(remainder.items.count,1); XCTAssertNil(remainder.nextCursor)
        let summaries = page.items + remainder.items
        XCTAssertEqual(Set(summaries.map(\.id)),Set(records.map(\.id)))
        let failed = try XCTUnwrap(summaries.first { $0.id == last.id })
        XCTAssertEqual(failed.status,.needsAttention)
        XCTAssertTrue(failed.hasUnconfirmedObjects);XCTAssertNotNil(failed.issue)
        do{_=try await engine.recoveryBatch(id:last.id);XCTFail("An uncertain summary cannot authorize detail or recovery")}catch{}
        var foreign = last; foreign.requestingUserID = scope.requesterUID + 1
        try write(foreign,scope:scope)
        do { _ = try await engine.recoveryBatch(id:last.id); XCTFail("Detail must enforce the recorded requesting UID") } catch { }
        let valid = try await engine.recoveryBatch(id:records[0].id)
        XCTAssertEqual(valid.id,records[0].id)
    }
    func testLegacySystemRecordWithChangedUnprovedVolumeCanBePreviewedButNeverRestored()async throws{
        let(f,scope)=try fixture();defer{try? f.clean()}
        let identifier="org.example.systemfixture",path=scope.libraryRoot+"/Caches/"+identifier+"/leaf"
        try FileManager.default.createDirectory(atPath:URL(fileURLWithPath:path).deletingLastPathComponent().path,withIntermediateDirectories:true)
        try Data("registered old system sample".utf8).write(to:URL(fileURLWithPath:path))
        let snapshot=try SafeFilesystem.snapshot(path)
        var object=try XCTUnwrap(try JSONSerialization.jsonObject(with:JSONEncoder().encode(snapshot.identity))as? [String:Any])
        object.removeValue(forKey:"volumeUUID");object["device"]=snapshot.identity.device+1000
        let legacy=try JSONDecoder().decode(FileIdentity.self,from:JSONSerialization.data(withJSONObject:object))
        let candidate=Candidate(id:UUID(),path:path,category:.cache,bundleIdentifier:identifier,applicationPath:scope.applicationsRoot+"/Fixture.app",evidence:[.init(kind:.validatedRule,detail:"owned legacy system sample",verified:true)],rule:SystemDomainRule.cacheName,identity:legacy,bytes:legacy.size,retentionReason:nil)
        var record=manifest(scope)
        record.status = .isolated
        record.entries=[RecoveryEntry(id:candidate.id,original:candidate,state:.moved,message:nil,isolatedIdentity:legacy,contents:[],originalAncestors:snapshot.ancestors)]
        try write(record,scope:scope)
        let engine=try SystemCleanupEngine(scope:scope),preview=try await engine.recoveryBatch(id:record.id)
        XCTAssertEqual(preview.entries.count,1);XCTAssertNotNil(preview.previewOnlyReason)
        do{_=try await engine.restore(batchID:record.id);XCTFail("Unproved old volume cannot authorize a root restore")}catch{}
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:path)),Data("registered old system sample".utf8))
    }
}
#endif
