#if os(macOS)
import Foundation
import Darwin
import XCTest
@testable import AppSweepCore

/// Fixed, opt-in staged acceptance. Default tests never launch or mutate Firefox.
final class FirefoxPreparationAcceptanceTests: XCTestCase, @unchecked Sendable {
    private let app = "/Users/localtest/Applications/Firefox.app"
    private let nativeHash = "d16810dfc759aae5b6ae30a493e2908fe56b2c0f"
    private struct Trial: Codable {
        let original: ApplicationOptimizationRecord.Object
        var batch: ApplicationOptimizationRecord
        let profilesBeforePublish: [String:String]
        var state: String
    }
    private func snapshot(_ path: String) throws -> FileSnapshot {
        try SafeFilesystem.snapshot(path,allowInternalLinks:true,purpose:.application,allowInternalHardLinks:true)
    }
    private func profiles() throws -> [String:String] {
        let roots = ["/Users/localtest/AppSweepAcceptanceGeneral-20261016/official-optimization.noindex/firefox/profile",
                     "/Users/localtest/Library/Application Support/Firefox","/Users/localtest/Library/Preferences/org.mozilla.firefox.plist"]
        var values: [String:String] = [:]
        for root in roots {
            guard try SafeFilesystem.presence(root) else { values[root + "#presence"] = "absent"; continue }
            let tree = try snapshot(root)
            values[root + "#presence"] = tree.identity.isDirectory ? "directory" : "file"
            let files = tree.identity.isDirectory ? tree.tree.filter { $0.identity.mode & 0o170000 == 0o100000 }.map { root + "/" + $0.relative } : [root]
            for file in files {
                let item = try SafeFilesystem.fileSnapshot(file,in:tree)
                guard item.identity.size <= 128*1024*1024 else { throw SweepError.incomplete("Registered profile file exceeds fingerprint bound") }
                values[file] = try VerifiedFileStream.digest(item)
            }
            try SafeFilesystem.verify(tree)
        }
        return values
    }
    func testRegisteredFirefoxPreparationPhase() async throws {
        guard let request = ProcessInfo.processInfo.environment["APP_SWEEP_FIREFOX_PREPARATION_ACCEPTANCE"] else {
            throw XCTSkip("Explicit staged registered Firefox preparation acceptance only")
        }
        guard ["AppSweep-General-20261016:publish","AppSweep-General-20261016:restore"].contains(request),
              getuid() == 501, try SystemIdentity.home() == "/Users/localtest",
              PlatformStamp.current == .init(major:27,minor:0,patch:1,build:"26A434",architecture:"arm64"),
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:5).hasPrefix("VirtualMac") else {
            throw SweepError.denied("Wrong explicit registered consumer scope")
        }
        let publishing = request.hasSuffix(":publish")
        let directory = try SafeDirectory(path:"/Users/localtest/AppSweepAcceptanceGeneral-20261016/official-optimization.noindex")
            .existingPrivateChild("firefox158-preparation-20261020")
        let observation = try JSONSerialization.jsonObject(with:directory.read(publishing ? "baseline-observation.json" : "optimized-observation.json")) as? [String:Any]
        guard observation?["functionalAccepted"] as? Bool == true, observation?["normalMenuQuitRequested"] as? Bool == true,
              observation?["nativeHash"] as? String == nativeHash, observation?["runningProcesses"] as? [String] == [] else {
            throw SweepError.incomplete("Actual registered browser body, refresh and normal shutdown have not been observed")
        }
        guard AppInspector.signedByTeam(path:app,team:"43AQ936H96"),
              try ApplicationArchitecturePreparation.signature(app,identifier:"org.mozilla.firefox",architecture:"arm64") == nativeHash else {
            throw SweepError.stale("Registered publisher or current application version changed")
        }
        try ActivityInspector.ensureStopped(bundleID:"org.mozilla.firefox",applicationPath:app)
        let engine = ApplicationOptimizationEngine(policy:SafetyPolicy(home:"/Users/localtest",acceptedPlatform:true,validatedRules:[ApplicationOptimizationEngine.rule,LocalizedResourceReader.name]))
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601; encoder.outputFormatting = [.sortedKeys]
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        if publishing {
            guard try !SafeFilesystem.presence(directory.path + "/trial.json") else { throw SweepError.denied("Registered trial already exists; no silent replay") }
            let source = try snapshot(app)
            guard source.identity.inode == 7697962 else { throw SweepError.stale("Registered original replaced") }
            let original = try ApplicationOptimizationRecord.Object(source), before = try profiles()
            try directory.write(encoder.encode(original),name:"original-before-publish.json")
            let review = try await engine.review(app), published = try await engine.execute(reviewID:review.id)
            let trial = Trial(original:original,batch:published,profilesBeforePublish:before,state:"published; actual optimized function pending")
            try directory.write(encoder.encode(trial),name:"trial.json")
            XCTAssertEqual(published.status,.published)
            XCTAssertEqual(try profiles(),before,"Body-only preparation must not alter persistent profiles")
            XCTAssertLessThan(try snapshot(app).bytes,source.bytes)
            print("FIREFOX_PREPARATION_PUBLISHED=" + published.id.uuidString + "; original retained; no released bytes or actual-function claim")
        } else {
            var trial = try decoder.decode(Trial.self,from:directory.read("trial.json"))
            guard trial.batch.applicationPath == app, trial.batch.identifier == "org.mozilla.firefox", trial.batch.nativeCodeHash == nativeHash,
                  trial.original.identity.inode == 7697962, trial.state.hasPrefix("published;") else { throw SweepError.denied("Trial batch identity differs from registered consumer") }
            let before = try profiles()
            trial.batch = try await engine.undo(batchID:trial.batch.id)
            trial.state = "restored; actual restored function pending"
            try directory.write(encoder.encode(trial),name:"trial.json")
            XCTAssertEqual(trial.batch.status,.restored)
            XCTAssertTrue(try trial.original.matches(snapshot(app)))
            XCTAssertEqual(try profiles(),before,"Undo must retain profile data produced during optimized use")
            print("FIREFOX_PREPARATION_RESTORED=" + trial.batch.id.uuidString + "; original identity/content and latest profiles verified; actual restored function pending")
        }
    }
}
#endif
