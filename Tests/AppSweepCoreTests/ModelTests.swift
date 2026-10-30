import XCTest
@testable import AppSweepCore

final class ModelTests: XCTestCase {
    func testInterruptedRestoreOrConflictCannotOfferPermanentPurgeAsAnIsolatedBatch() throws {
        let f=try RecoveryTests.Fixture();defer { try? f.clean() }
        for (state,allowed) in [(RecoveryEntry.State.moved,true),(.restored,false),(.conflict,false),(.prepared,false),(.restorePrepared,false),(.purgePrepared,false),(.purged,false)] {
            let entry=RecoveryEntry(id:f.candidate.id,original:f.candidate,state:state,message:nil)
            let manifest=RecoveryManifest(schemaVersion:RecoveryManifest.currentSchemaVersion,id:UUID(),createdAt:Date(),status:.isolated,entries:[entry],issue:nil)
            XCTAssertEqual(manifest.canPurge,allowed,"A final batch status not yet committed must not enable destructive cleanup")
        }
    }
    func testPlanCannotExceedRecoverableManifestCapacity() async throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let items = (0..<1001).map { number in
            Candidate(id:UUID(),path:f.home + "/Applications/Sample-\(number).app",category:.application,bundleIdentifier:"org.example.sample.\(number)",evidence:[.init(kind:.validatedRule,detail:"owned sample",verified:true)],rule:"signed-application-v1",identity:f.snapshot.identity,bytes:0,retentionReason:nil)
        }
        let engine = f.engine()
        let report = await engine.adoptFixture(items,snapshots:Dictionary(uniqueKeysWithValues:items.map { ($0.id,f.snapshot) }))
        do { _ = try await engine.makePlan(reportID:report.id,selected:Set(items.map(\.id)),includeUserData:false); XCTFail("An un-restorable oversized manifest must never become a plan") } catch { }
        XCTAssertTrue(FileManager.default.fileExists(atPath:f.source + "/data"))
        XCTAssertFalse(FileManager.default.fileExists(atPath:f.vault))
    }
    func testReportSerializesDefaultSelectionAndAllowedActions() throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let encoded = try JSONEncoder().encode(f.candidate)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String:Any])
        XCTAssertEqual(object["selectedByDefault"] as? Bool, false)
        XCTAssertEqual(object["allowedActions"] as? [String], ["report", "reviewPlan"])
        XCTAssertEqual(try JSONDecoder().decode(Candidate.self, from: encoded), f.candidate)
    }
}
