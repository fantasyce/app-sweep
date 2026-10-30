#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

final class ApplicationComponentTests: XCTestCase, @unchecked Sendable {
    func testMalformedOptionalDockMetadataDoesNotInvalidateTheBodyPlan() async throws {
        let f=try NativeAcceptanceTests.NativeFixture();defer{try? f.clean()}
        let dock=f.home + "/Library/Preferences/com.apple.dock.plist"
        try FileManager.default.createDirectory(atPath:f.home + "/Library/Preferences",withIntermediateDirectories:true)
        try Data("invalid owned fixture".utf8).write(to:URL(fileURLWithPath:dock))
        let engine=SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[SelectedApplicationRule.name]),vaultPath:f.home + "/Library/Application Support/App Sweep/Recovery",fixture:false)
        let report=try await engine.scanApplication(f.app)
        let body=try XCTUnwrap(report.selectableCandidates(includeUserData:false).first{$0.path == f.app})
        XCTAssertTrue(report.scopes?.contains{$0.root == dock && !$0.complete} == true)
        XCTAssertFalse(report.scopes?.contains{$0.root == f.app && !$0.complete} == true)
        let plan=try await engine.makePlan(reportID:report.id,selected:[body.id],includeUserData:false)
        XCTAssertEqual(plan.items.count,1)
    }
    func testNestedDataRequiresOuterBundleAndRestoresWithIt() async throws {
        let f=try NativeAcceptanceTests.NativeFixture();defer{try? f.clean()}
        let childID="org.example.sweepfixture.worker",relative="Contents/Helpers/Worker.app",child=f.app + "/" + relative
        try FileManager.default.createDirectory(atPath:f.app + "/Contents/Helpers",withIntermediateDirectories:true)
        try FileManager.default.copyItem(atPath:f.app,toPath:f.home + "/worker-template.app")
        try FileManager.default.moveItem(atPath:f.home + "/worker-template.app",toPath:child)
        let file=child + "/Contents/Info.plist"
        var info=try XCTUnwrap(PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:file)),format:nil) as? [String:Any])
        info["CFBundleIdentifier"]=childID
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:file))
        for path in [child,f.app] {_=try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-",path],timeout:10)}
        let cache=f.home + "/Library/Caches/" + childID,support=f.home + "/Library/Application Support/" + childID
        for path in [cache,support] {
            try FileManager.default.createDirectory(atPath:path,withIntermediateDirectories:true)
            try Data("preserved component data".utf8).write(to:URL(fileURLWithPath:path + "/data"))
        }
        let engine=SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[SelectedApplicationRule.name,CacheDomainRule.name,SupportDomainRule.name]),vaultPath:f.home + "/Library/Application Support/App Sweep/Recovery",fixture:false)
        let report=try await engine.scanApplication(f.app)
        let data=try XCTUnwrap(report.selectableCandidates(includeUserData:true).first{$0.path == support})
        XCTAssertEqual(data.component?.relativePath,relative)
        XCTAssertFalse(data.selectedByDefault)
        XCTAssertFalse(report.selectableCandidates(includeUserData:false).contains{$0.path == support})
        let items=report.selectableCandidates(includeUserData:true)
        let plan=try await engine.makePlan(reportID:report.id,selected:Set(items.map(\.id)),includeUserData:true)
        let moved=try await engine.execute(planID:plan.id)
        XCTAssertEqual(moved.status,.isolated,moved.issue ?? "")
        let restored=try await engine.restore(batchID:moved.id)
        XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:"; "))
        XCTAssertEqual(try String(contentsOfFile:support + "/data",encoding:.utf8),"preserved component data")
        try FileManager.default.copyItem(atPath:child,toPath:f.home + "/Applications/Other.app")
        let shared=try await engine.scanApplication(f.app)
        XCTAssertFalse(shared.selectableCandidates(includeUserData:true).contains{$0.path == support || $0.path.hasPrefix(cache + "/")})
    }
    func testComponentReferenceCannotEscapeOrBorrowAnAppleIdentity() {
        for path in ["/Other.app","Contents/../../Other.app","Contents//Other.app","Contents/Worker.app/..","Contents/file"] {
            XCTAssertFalse(ApplicationComponentRule.valid(.init(ownerIdentifier:"org.example.parent",relativePath:path)))
        }
        XCTAssertFalse(ApplicationComponentRule.valid(.init(ownerIdentifier:"com.apple.finder",relativePath:"Contents/Helpers/Worker.app")))
    }
    func testDockReferenceMatchesAnExactApplicationURL() throws {
        let data=try PropertyListSerialization.data(fromPropertyList:["persistent-apps":[["tile-data":["file-data":["_CFURLString":"file:///Applications/Example.app/"]]]]],format:.binary,options:0)
        XCTAssertTrue(try UninstallRelatedReferences.dockReferences(data,application:"/Applications/Example.app"))
        XCTAssertFalse(try UninstallRelatedReferences.dockReferences(data,application:"/Applications/Example Helper.app"))
    }
}
#endif
