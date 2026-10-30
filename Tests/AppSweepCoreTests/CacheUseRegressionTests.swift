#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

final class CacheUseRegressionTests: XCTestCase, @unchecked Sendable {
    private let rule = "cache-godot-generated-v1"
    private func prepared() throws -> (NativeAcceptanceTests.NativeFixture, SweepEngine, String, String) {
        let f = try NativeAcceptanceTests.NativeFixture(additionalRules:[rule])
        let metadata = f.app + "/Contents/Info.plist"
        var info = try AppInspector.metadata(f.app,component:false).0
        info["CFBundleIdentifier"] = "org.godotengine.godot"
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:metadata))
        _ = try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-",f.app],timeout:10)
        let root=f.home + "/Library/Caches/Godot"
        try FileManager.default.createDirectory(atPath:root,withIntermediateDirectories:true)
        let first=root + "/editor_doc_cache-4.7.res", second=root + "/editor_doc_cache-4.6.res"
        try Data("regenerable documentation one".utf8).write(to:URL(fileURLWithPath:first))
        try Data("regenerable documentation two".utf8).write(to:URL(fileURLWithPath:second))
        return (f,f.engine,first,second)
    }
    func testKnownGeneratedFileCanBeSelectedAloneAndRestoredWithoutTouchingSibling() async throws {
        let (f,e,first,second)=try prepared();defer{try? f.clean()}
        let report=try await e.scanJunk()
        let item=try XCTUnwrap(report.selectableCandidates(includeUserData:false).first{$0.path==first},report.candidates.compactMap(\.retentionReason).joined(separator:";"))
        XCTAssertNil(item.selectionGroupID)
        XCTAssertEqual(report.selectionIDs(for:item.id,includeUserData:false),[item.id])
        let plan=try await e.makePlan(reportID:report.id,selected:[item.id],includeUserData:false)
        let batch=try await e.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        XCTAssertFalse(FileManager.default.fileExists(atPath:first))
        XCTAssertEqual(try String(contentsOfFile:second,encoding:.utf8),"regenerable documentation two")
        try await f.waitForIsolatedObjects(batch)
        let restored=try await e.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        XCTAssertEqual(try String(contentsOfFile:first,encoding:.utf8),"regenerable documentation one")
        XCTAssertTrue(FileManager.default.fileExists(atPath:f.app))
    }
    func testRunningOwnerBlocksReviewBeforeAnyExecution() async throws {
        let (f,e,first,_)=try prepared();defer{try? f.clean()}
        let report=try await e.scanJunk()
        let item=try XCTUnwrap(report.selectableCandidates(includeUserData:false).first{$0.path==first},report.candidates.compactMap(\.retentionReason).joined(separator:";"))
        let process=Process();process.executableURL=URL(fileURLWithPath:f.executable);process.arguments=["--wait",f.home]
        try process.run()
        defer { if process.isRunning { process.terminate() } }
        for _ in 0..<80 { if FileManager.default.fileExists(atPath:f.home + "/wait-ready"){break};try await Task.sleep(for:.milliseconds(100)) }
        XCTAssertTrue(process.isRunning)
        do { _=try await e.makePlan(reportID:report.id,selected:[item.id],includeUserData:false);XCTFail("Running target must be refused before execution") }
        catch { XCTAssertTrue(error.localizedDescription.contains("关闭") || error.localizedDescription.contains("退出"),error.localizedDescription) }
        XCTAssertTrue(FileManager.default.fileExists(atPath:first))
        try Data().write(to:URL(fileURLWithPath:f.home + "/release-wait"))
        for _ in 0..<40 { if !process.isRunning { break };try await Task.sleep(for:.milliseconds(50)) }
        XCTAssertFalse(process.isRunning)
    }
    func testThumbnailSidecarsFormOnlyTheirOwnGroup() async throws {
        let (f,e,first,second)=try prepared();defer{try? f.clean()}
        let root=f.home + "/Library/Caches/Godot/",stem="resthumb-" + String(repeating:"a",count:32)
        for suffix in [".png","_small.png",".txt"] { try Data("preview".utf8).write(to:URL(fileURLWithPath:root+stem+suffix)) }
        let report=try await e.scanJunk(),items=report.selectableCandidates(includeUserData:false)
        let thumbnail=try XCTUnwrap(items.first{$0.path==root+stem+".png"},report.candidates.compactMap(\.retentionReason).joined(separator:";"))
        let selection=report.selectionIDs(for:thumbnail.id,includeUserData:false)
        XCTAssertEqual(selection.count,3)
        XCTAssertFalse(items.filter{$0.path==first || $0.path==second}.contains{selection.contains($0.id)})
        do { _=try await e.makePlan(reportID:report.id,selected:[thumbnail.id],includeUserData:false);XCTFail("Preview index and image are coupled") } catch { }
        let plan=try await e.makePlan(reportID:report.id,selected:selection,includeUserData:false)
        let batch=try await e.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        XCTAssertTrue(FileManager.default.fileExists(atPath:first))
        try await f.waitForIsolatedObjects(batch)
        let restored=try await e.restore(batchID:batch.id);XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
    }
    func testUnrelatedRunningApplicationDoesNotBlockKnownCache() async throws {
        let (f,e,first,_)=try prepared();defer{try? f.clean()}
        let other=try NativeAcceptanceTests.NativeFixture();defer{try? other.clean()}
        let process=Process();process.executableURL=URL(fileURLWithPath:other.executable);process.arguments=["--wait",other.home];try process.run()
        defer { if process.isRunning { process.terminate() } }
        for _ in 0..<80 { if FileManager.default.fileExists(atPath:other.home + "/wait-ready"){break};try await Task.sleep(for:.milliseconds(100)) }
        XCTAssertTrue(process.isRunning)
        let report=try await e.scanJunk(),item=try XCTUnwrap(report.selectableCandidates(includeUserData:false).first{$0.path==first},report.candidates.compactMap(\.retentionReason).joined(separator:";"))
        let plan=try await e.makePlan(reportID:report.id,selected:[item.id],includeUserData:false)
        let batch=try await e.execute(planID:plan.id);XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        XCTAssertTrue(process.isRunning,"App Sweep must not quit the unrelated application")
        try Data().write(to:URL(fileURLWithPath:other.home + "/release-wait"))
        for _ in 0..<40 { if !process.isRunning { break };try await Task.sleep(for:.milliseconds(50)) }
        XCTAssertFalse(process.isRunning)
        try await f.waitForIsolatedObjects(batch)
        let restored=try await e.restore(batchID:batch.id);XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
    }
    func testUnexpectedFilesAndSymlinksNeverBecomeGodotCache() async throws {
        let (f,e,_,_)=try prepared();defer{try? f.clean()}
        let root=f.home + "/Library/Caches/Godot",path=root + "/project.godot"
        try Data("user project".utf8).write(to:URL(fileURLWithPath:path))
        let report=try await e.scanJunk()
        XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains{$0.path==path})
        try FileManager.default.createSymbolicLink(atPath:root + "/editor_doc_cache-9.0.res",withDestinationPath:path)
        let linked=try await e.scanJunk()
        XCTAssertFalse(linked.selectableCandidates(includeUserData:true).contains{$0.path.hasPrefix(root + "/")})
        XCTAssertEqual(try String(contentsOfFile:path,encoding:.utf8),"user project")
    }
    func testIndependentFileRemainsUsableInNamespaceLargerThanOnePlan() async throws {
        let (f,e,first,_)=try prepared();defer{try? f.clean()}
        let root=f.home + "/Library/Caches/Godot/"
        for number in 0..<1001 { try Data("cache".utf8).write(to:URL(fileURLWithPath:root + "editor_doc_cache-3." + String(number) + ".res")) }
        let report=try await e.scanJunk()
        let item=try XCTUnwrap(report.selectableCandidates(includeUserData:false).first{$0.path == first},report.candidates.compactMap(\.retentionReason).joined(separator:";"))
        let all=Set(report.selectableCandidates(includeUserData:false).filter{$0.rule == rule}.map(\.id))
        XCTAssertGreaterThan(all.count,1000)
        do { _=try await e.makePlan(reportID:report.id,selected:all,includeUserData:false);XCTFail("Per-plan capacity remains bounded") } catch { }
        let plan=try await e.makePlan(reportID:report.id,selected:[item.id],includeUserData:false)
        let batch=try await e.execute(planID:plan.id);XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        XCTAssertTrue(FileManager.default.fileExists(atPath:root + "editor_doc_cache-3.1000.res"))
        try await f.waitForIsolatedObjects(batch)
        let restored=try await e.restore(batchID:batch.id);XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
    }
    func testExecutionProofRejectsNewRegisteredOwnerAndChangedApplication() throws {
        let (f,_,first,_)=try prepared();defer{try? f.clean()}
        let proof=GodotCacheRule.OwnerProof(application:f.app,snapshot:try SafeFilesystem.snapshot(f.app,allowInternalLinks:true))
        try GodotCacheRule.verify(proof,home:f.home,registryLookup:{_ in [URL(fileURLWithPath:f.app)]})
        let other=try NativeAcceptanceTests.NativeFixture();defer{try? other.clean()}
        XCTAssertThrowsError(try GodotCacheRule.verify(proof,home:f.home,registryLookup:{_ in [URL(fileURLWithPath:other.app)]}))
        XCTAssertThrowsError(try GodotCacheRule.verify(proof,home:f.home,registryLookup:{_ in throw SweepError.incomplete("registry unavailable")}))
        try Data("application changed".utf8).write(to:URL(fileURLWithPath:f.app + "/Contents/changed-after-proof"))
        XCTAssertThrowsError(try GodotCacheRule.verify(proof,home:f.home,registryLookup:{_ in []}))
        XCTAssertTrue(FileManager.default.fileExists(atPath:first))
    }
    func testUnconfirmedNamespaceDoesNotAdvertiseExecutableCandidates() throws {
        let f=try RecoveryTests.Fixture();defer{try? f.clean()}
        let root=f.home + "/Library/Caches/Unknown Editor"
        try FileManager.default.createDirectory(atPath:root,withIntermediateDirectories:true)
        try Data("unknown owner".utf8).write(to:URL(fileURLWithPath:root + "/data"))
        let result=try Scanner(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:["cache-user-namespace-v1"])).junk(indexLookup:{_ in []})
        XCTAssertFalse(result.report.selectableCandidates(includeUserData:false).contains{$0.path.hasPrefix(root + "/")})
    }
}
#endif
