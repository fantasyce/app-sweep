#if os(macOS)
import Foundation
import Darwin
import XCTest
@testable import AppSweepCore

/// Only the previously registered official Firefox updater conflict in the
/// disposable VM. Default regression never acknowledges a real application.
final class ApplicationOptimizationUpdateAcceptanceTests: XCTestCase, @unchecked Sendable {
    private func snapshot(_ path: String) throws -> FileSnapshot {
        try SafeFilesystem.snapshot(path,allowInternalLinks:true,purpose:.application,allowInternalHardLinks:true)
    }
    func testRegisteredOfficialFirefoxUpdateKeepsBothVersionsWithoutOverwrite() async throws {
        guard let request = ProcessInfo.processInfo.environment["APP_SWEEP_FIREFOX_UPDATE_ACCEPTANCE"] else {
            throw XCTSkip("Explicit registered official Firefox updater conflict only")
        }
        let resuming = request == "AppSweep-General-20261016:resume-keep-current"
        guard ["AppSweep-General-20261016:keep-current","AppSweep-General-20261016:resume-keep-current"].contains(request), getuid() == 501,
              try SystemIdentity.home() == "/Users/localtest",
              PlatformStamp.current == .init(major:27,minor:0,patch:1,build:"26A434",architecture:"arm64"),
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:5).hasPrefix("VirtualMac") else {
            throw SweepError.denied("Wrong registered update conflict scope")
        }
        let app = "/Users/localtest/Applications/Firefox.app"
        let id = UUID(uuidString:"00EDE94D-3724-4A26-A51B-04E3D579C64F")!
        let storedPath = "/Users/localtest/Library/Application Support/App Sweep/Optimization.noindex/" + id.uuidString + "/" + id.uuidString
        let expectedHash = "d16810dfc759aae5b6ae30a493e2908fe56b2c0f"
        guard try snapshot(app).identity.inode == 7697962, try snapshot(storedPath).identity.inode == 290231,
              AppInspector.signedByTeam(path:app,team:"43AQ936H96"), AppInspector.signedByTeam(path:storedPath,team:"43AQ936H96"),
              try ApplicationArchitecturePreparation.signature(app,identifier:"org.mozilla.firefox",architecture:"arm64") == expectedHash else {
            throw SweepError.stale("Registered current or retained official distribution changed")
        }
        let priorCase = try SafeDirectory(path:"/Users/localtest/AppSweepAcceptanceGeneral-20261016/official-optimization.noindex").existingPrivateChild("firefox158-preparation-20261020")
        let observation = try JSONSerialization.jsonObject(with:priorCase.read("restored-observation.json")) as? [String:Any]
        guard observation?["functionalAccepted"] as? Bool == true, observation?["normalMenuQuitRequested"] as? Bool == true,
              observation?["nativeHash"] as? String == expectedHash, observation?["sourceInode"] as? Int == 7697962,
              observation?["runningProcesses"] as? [String] == [] else { throw SweepError.incomplete("Current updated consumer has no healthy actual baseline") }
        let root = try SafeDirectory(path:"/Users/localtest/AppSweepAcceptanceGeneral-20261016/official-optimization.noindex")
        let encoder = JSONEncoder();encoder.dateEncodingStrategy = .iso8601;encoder.outputFormatting = [.sortedKeys]
        let decoder = JSONDecoder();decoder.dateDecodingStrategy = .iso8601
        let engine = ApplicationOptimizationEngine(policy:SafetyPolicy(home:"/Users/localtest",acceptedPlatform:true))
        let history = try await engine.history(), record = try XCTUnwrap(history.first { $0.id == id })
        guard record.schemaVersion == 2, record.nativeCodeHash == "ed526c2a600dd9c380d4070d81443645834a63c0" else { throw SweepError.stale("Registered old batch changed") }
        let evidence: SafeDirectory, currentObject: ApplicationOptimizationRecord.Object, originalObject: ApplicationOptimizationRecord.Object
        if resuming {
            evidence = try root.existingPrivateChild("firefox157-update-conflict-20261020")
            guard try evidence.ownIdentity.inode == 10058242, record.status == .needsAttention,
                  try !SafeFilesystem.presence(evidence.path + "/retained-record.json"),
                  Set(try FileManager.default.contentsOfDirectory(atPath:evidence.path)) == ["before.json"] else { throw SweepError.denied("No automatic replay of an acknowledged or unknown case") }
            let before = try decoder.decode([String:ApplicationOptimizationRecord.Object].self,from:evidence.read("before.json"))
            currentObject = try XCTUnwrap(before["current"]);originalObject = try XCTUnwrap(before["retainedOriginal"])
            //1039 independently found only before.json and needsAttention after
            //the refused undo. This explicit phase creates a fresh live review;
            //it never replays an old token, exchange or failed confirmation.
        } else {
            guard record.status == .published, try !SafeFilesystem.presence(root.path + "/firefox157-update-conflict-20261020") else { throw SweepError.denied("No replay of registered real acknowledgement") }
            evidence = try root.privateChild("firefox157-update-conflict-20261020")
            currentObject = try .init(snapshot(app));originalObject = try .init(snapshot(storedPath))
            try evidence.write(encoder.encode(["current":currentObject,"retainedOriginal":originalObject]),name:"before.json")
            do { _ = try await engine.undo(batchID:id);XCTFail("Official158 overwritten by old157 undo") } catch { }
            let conflicted = try await engine.history();XCTAssertEqual(conflicted.first { $0.id == id }?.status,.needsAttention)
        }
        guard try currentObject.matches(snapshot(app)), try originalObject.matches(snapshot(storedPath)), try record.original.matches(snapshot(storedPath)) else { throw SweepError.stale("Current or original no longer matches independent commitments") }
        let choice = try await engine.reviewKeepingCurrent(batchID:id), kept = try await engine.keepCurrent(reviewID:choice.id)
        try evidence.write(encoder.encode(kept),name:"retained-record.json")
        XCTAssertEqual(kept.status.rawValue,"retained");XCTAssertFalse(kept.status.unfinished)
        XCTAssertTrue(try currentObject.matches(snapshot(app)));XCTAssertTrue(try originalObject.matches(snapshot(storedPath)))
        try ActivityInspector.ensureStopped(bundleID:"org.mozilla.firefox",applicationPath:app)
        XCTAssertEqual(try ApplicationArchitecturePreparation.signature(app,identifier:"org.mozilla.firefox",architecture:"arm64"),expectedHash)
        print("OFFICIAL_FIREFOX_UPDATE_CONFLICT_RETAINED=" + id.uuidString + "; current158 and retained157 unchanged; no app move, delete or released-space claim")
    }
}
#endif
