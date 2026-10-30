#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

final class DocumentHistoryScanRegressionTests: XCTestCase, @unchecked Sendable {
    func testBoundedDiscoveryStillPlansRestoresAndPurgesNativeHistoryWithoutMovingDocument() async throws {
        // NativeFixture confines compilation and every file to the registered
        // disposable VM. No historical one-shot inode or host document is reused.
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let documents = f.home + "/Documents", support = f.home + "/Library/Application Support"
        try FileManager.default.createDirectory(atPath:documents,withIntermediateDirectories:true)
        let document = URL(fileURLWithPath:documents + "/Owned History.txt")
        let version = URL(fileURLWithPath:f.home + "/owned-historical-payload.txt")
        let current = Data("current document remains untouched".utf8), historical = Data("independent historical bytes".utf8)
        try current.write(to:document); try historical.write(to:version)
        _ = try NSFileVersion.addOfItem(at:document,withContentsOf:version,options:[])
        defer { try? NSFileVersion.removeOtherVersionsOfItem(at:document) }
        let identity = try SafeFilesystem.snapshot(document.path).identity
        let policy = SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[DocumentVersionRule.name])
        let vault = support + "/App Sweep/Recovery", engine = SweepEngine(policy:policy,vaultPath:vault,fixture:false)
        let report = try await engine.scanLegacyManagementFixture()
        let item = try XCTUnwrap(report.selectableCandidates(includeUserData:true).first { $0.path == document.path && $0.rule == DocumentVersionRule.name },report.unconfirmedIssues.joined(separator:"; "))
        XCTAssertFalse(item.selectedByDefault)
        XCTAssertFalse(report.selectableCandidates(includeUserData:false).contains { $0.id == item.id })
        let plan = try await engine.makePlan(reportID:report.id,selected:[item.id],includeUserData:true)
        let isolated = try await engine.execute(planID:plan.id)
        XCTAssertEqual(isolated.status,.isolated,isolated.issue ?? "")
        XCTAssertEqual(try Data(contentsOf:document),current)
        XCTAssertEqual(NSFileVersion.otherVersionsOfItem(at:document)?.count,0)
        let fresh = SweepEngine(policy:policy,vaultPath:vault,fixture:false)
        let restored = try await fresh.restore(batchID:isolated.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        let restoredHistory = try XCTUnwrap(NSFileVersion.otherVersionsOfItem(at:document))
        XCTAssertEqual(restoredHistory.count,1)
        var coordination: NSError?, failure: Error?, restoredBytes: Data?
        NSFileCoordinator(filePresenter:nil).coordinate(readingItemAt:try XCTUnwrap(restoredHistory.first).url,options:[],error:&coordination) { url in
            do { restoredBytes = try Data(contentsOf:url) } catch { failure = error }
        }
        if let coordination { throw coordination }; if let failure { throw failure }
        XCTAssertEqual(restoredBytes,historical)
        XCTAssertEqual(try SafeFilesystem.snapshot(document.path).identity.inode,identity.inode)
        XCTAssertEqual(try Data(contentsOf:document),current)
        let purged = try await fresh.purge(batchID:isolated.id,confirmation:"永久清空 " + isolated.id.uuidString)
        XCTAssertEqual(purged.status,.purged,purged.issue ?? "")
        XCTAssertEqual(try Data(contentsOf:document),current)
        XCTAssertEqual(NSFileVersion.otherVersionsOfItem(at:document)?.count,1)
    }
}
#endif
