#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

final class RealGodotCacheUseTests: XCTestCase, @unchecked Sendable {
    func testInstalledGodotUninstallDiscoversExistingCacheRuleReadOnly() throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_GODOT_READONLY"] == "1" else {
            throw XCTSkip("Explicit installed-app read-only comparison only")
        }
        let home=try SystemIdentity.home()
        let policy=SafetyPolicy(home:home,acceptedPlatform:true,validatedRules:[SelectedApplicationRule.name,GodotCacheRule.name])
        let report=try Scanner(policy:policy).application("/Applications/Godot.app").report
        let items=report.candidates.filter { $0.rule == GodotCacheRule.name }
        XCTAssertFalse(items.isEmpty,"The existing named cache rule must also be discovered during uninstall")
        for item in items where item.retentionReason == nil {
            XCTAssertEqual(item.applicationPath,"/Applications/Godot.app")
            XCTAssertTrue(GodotCacheRule.matches(item.path,home:home))
        }
    }
    func testRestoreInterruptedVendorAcceptance() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_GODOT_RESUME"] == "AppSweep-General-20261016",
              try SystemIdentity.home() == "/Users/localtest",
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).hasPrefix("VirtualMac2,1") else { throw XCTSkip("Explicit registered interrupted vendor run only") }
        let home="/Users/localtest",stage=home + "/AppSweepAcceptanceGeneral-20261016/build36-use-fixes/real-godot.noindex"
        let recorded=try JSONDecoder().decode(RecoveryManifest.self,from:Data(contentsOf:URL(fileURLWithPath:stage + "/batch-1.json")))
        let engine=SweepEngine(policy:SafetyPolicy(home:home,acceptedPlatform:true,validatedRules:[GodotCacheRule.name]),vaultPath:stage + "/Recovery",fixture:false)
        let restored=try await engine.restore(batchID:recorded.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        print("INTERRUPTED_VENDOR_RUN_RESTORED",recorded.id)
    }
    func testOfficialGeneratedCachesRestoreRegenerateAndLeaveProjectIntact() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_REAL_GODOT_ACCEPTANCE"] == "AppSweep-General-20261016" else { throw XCTSkip("Explicit disposable VM vendor acceptance only") }
        let home=try SystemIdentity.home()
        guard home == "/Users/localtest",try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).trimmingCharacters(in:.whitespacesAndNewlines) == "VirtualMac2,1" else { throw SweepError.denied("Registered disposable VM only") }
        let stage=home + "/AppSweepAcceptanceGeneral-20261016/build36-use-fixes"
        let receipt=try XCTUnwrap(try JSONSerialization.jsonObject(with:Data(contentsOf:URL(fileURLWithPath:stage + "/godot-ownership.json"))) as? [String:Any])
        let app=home + "/Applications/AppSweep-Test-Godot.app",root=home + "/Library/Caches/Godot",project=stage + "/godot-project"
        XCTAssertEqual(receipt["cacheBefore"] as? String,"absent")
        XCTAssertEqual(receipt["app"] as? String,app)
        XCTAssertEqual((receipt["appInode"] as? NSNumber)?.uint64Value,try SafeDirectory(path:app).ownIdentity.inode)
        guard AppInspector.signatureMatches(path:app,identifier:GodotCacheRule.identifier) else { throw SweepError.denied("Original Godot publisher identity required") }
        let privateRoot=try SafeDirectory(path:stage).privateChild("real-godot-" + UUID().uuidString + ".noindex")
        func fresh() -> SweepEngine { SweepEngine(policy:SafetyPolicy(home:home,acceptedPlatform:true,validatedRules:[GodotCacheRule.name]),vaultPath:privateRoot.path + "/Recovery",fixture:false) }
        let projectBytes=try Data(contentsOf:URL(fileURLWithPath:project + "/project.godot")),asset=try Data(contentsOf:URL(fileURLWithPath:project + "/fixture.svg"))
        let original=try CacheDomainRule.members(root:root).filter{GodotCacheRule.matches($0,home:home)}
        XCTAssertTrue(original.contains{$0.contains("editor_doc_cache-")})
        XCTAssertTrue(original.contains{GodotCacheRule.thumbnailKey($0) != nil},"The vendor editor must generate real resource previews before enabling their rule")
        guard original.contains(where:{GodotCacheRule.thumbnailKey($0) != nil}) else{return}
        let bytes=try Dictionary(uniqueKeysWithValues:original.map{($0,try Data(contentsOf:URL(fileURLWithPath:$0)))})
        for round in 0..<2 {
            try GodotCacheRule.ensureStopped(application:app)
            let engine=fresh(),report=try await engine.scanJunk()
            let items=report.selectableCandidates(includeUserData:false).filter{$0.rule == GodotCacheRule.name}
            XCTAssertEqual(Set(items.map(\.path)),original,report.candidates.filter{$0.path.hasPrefix(root)}.compactMap(\.retentionReason).joined(separator:";"))
            let plan=try await engine.makePlan(reportID:report.id,selected:Set(items.map(\.id)),includeUserData:false)
            let started=Date()
            let moved=try await engine.execute(planID:plan.id)
            print("GODOT_EXECUTION_SECONDS",Date().timeIntervalSince(started),"ITEMS",items.count)
            XCTAssertEqual(moved.status,.isolated,moved.issue ?? "")
            guard moved.status == .isolated else { return }
            try JSONEncoder().encode(moved).write(to:URL(fileURLWithPath:privateRoot.path + "/batch-" + String(round) + ".json"),options:.withoutOverwriting)
            for path in original{XCTAssertFalse(FileManager.default.fileExists(atPath:path))}
            XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:project + "/project.godot")),projectBytes)
            XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:project + "/fixture.svg")),asset)
            if round == 1 {
                let output=try BoundedProcess.run(app + "/Contents/MacOS/Godot",arguments:["--editor","--path",project,"--quit-after","60"],timeout:30)
                print("VENDOR_REGENERATION",output.suffix(500))
                for path in original{XCTAssertTrue(FileManager.default.fileExists(atPath:path),path)}
                let regenerated=try Dictionary(uniqueKeysWithValues:original.map{($0,try Data(contentsOf:URL(fileURLWithPath:$0)))})
                let conflict=try await fresh().restore(batchID:moved.id)
                XCTAssertEqual(conflict.status,.needsAttention,"Regenerated files must never be overwritten")
                for(path,data)in regenerated{XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:path)),data)}
                let saved=try privateRoot.privateChild("regenerated")
                for path in original{try FileManager.default.moveItem(atPath:path,toPath:saved.path + "/" + URL(fileURLWithPath:path).lastPathComponent)}
            }
            var restored=try await fresh().restore(batchID:moved.id)
            for _ in 0..<12 where restored.status != .restored {
                try await Task.sleep(for:.milliseconds(500));restored=try await fresh().restore(batchID:moved.id)
            }
            XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
            for(path,data)in bytes{XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:path)),data)}
        }
        XCTAssertTrue(AppInspector.signatureMatches(path:app,identifier:GodotCacheRule.identifier))
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:project + "/project.godot")),projectBytes)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:project + "/fixture.svg")),asset)
        print("GODOT_VENDOR_CACHE_ACCEPTED: original 4.7.2 editor; real documentation and preview cache roundtrip; regeneration; no-overwrite conflict; project preserved")
    }
}
#endif
