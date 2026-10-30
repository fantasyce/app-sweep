#if os(macOS)
import Foundation
import XCTest
import Darwin
@testable import AppSweepCore

final class XcodeGeneratedTests: XCTestCase, @unchecked Sendable {
    private let rule="xcode-generated-data-v1"
    private func fixture() throws -> NativeAcceptanceTests.NativeFixture { try .init(additionalRules:[rule]) }
    private func derived(_ f: NativeAcceptanceTests.NativeFixture) throws -> String {
        let project=f.home + "/Fixture.xcodeproj",root=f.home + "/Library/Developer/Xcode/DerivedData/Fixture-test"
        try FileManager.default.createDirectory(atPath:project,withIntermediateDirectories:true)
        try FileManager.default.copyItem(atPath:NativeAcceptanceTests.NativeFixture.resource("BuildFixture",extension:"pbxproj").path,toPath:project + "/project.pbxproj")
        try FileManager.default.copyItem(atPath:NativeAcceptanceTests.NativeFixture.resource("BuildFixture",extension:"c").path,toPath:f.home + "/main.c")
        try FileManager.default.createDirectory(atPath:root,withIntermediateDirectories:true)
        try PropertyListSerialization.data(fromPropertyList:["WorkspacePath":project],format:.xml,options:0).write(to:URL(fileURLWithPath:root + "/info.plist"))
        return root
    }
    func testDerivedProductsAndIndexesAreManualAndRestoreWithoutProjectOrPackages() async throws {
        let f=try fixture();defer{try? f.clean()};let root=try derived(f)
        for leaf in ["Build/Products","Index.noindex","SourcePackages"] {
            try FileManager.default.createDirectory(atPath:root + "/" + leaf,withIntermediateDirectories:true)
            try Data("independent generated fixture".utf8).write(to:URL(fileURLWithPath:root + "/" + leaf + "/data"))
        }
        let source=try Data(contentsOf:URL(fileURLWithPath:f.home + "/main.c")),report=try await f.engine.scanJunk()
        let items=report.selectableCandidates(includeUserData:false).filter{$0.rule == rule}
        XCTAssertEqual(Set(items.map(\.path)),[root + "/Build/Products",root + "/Index.noindex"])
        XCTAssertTrue(items.allSatisfy{!$0.selectedByDefault})
        guard items.count == 2 else{return}
        let plan=try await f.engine.makePlan(reportID:report.id,selected:Set(items.map(\.id)),includeUserData:false)
        let moved=try await f.engine.execute(planID:plan.id)
        XCTAssertEqual(moved.status,.isolated,moved.issue ?? "")
        XCTAssertTrue(FileManager.default.fileExists(atPath:root + "/SourcePackages/data"))
        let restored=try await f.engine.restore(batchID:moved.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:f.home + "/main.c")),source)
    }
    func testUnboundWorkspaceLinksAndSharedPermissionsCannotAuthorizeGeneratedData() async throws {
        for mode in ["missingProject","link","shared"] {
            let f=try fixture();defer{try? f.clean()};let root=try derived(f),target=root + "/Index.noindex"
            try FileManager.default.createDirectory(atPath:target,withIntermediateDirectories:true)
            try Data("generated index".utf8).write(to:URL(fileURLWithPath:target + "/data"))
            if mode == "missingProject"{try FileManager.default.moveItem(atPath:f.home + "/Fixture.xcodeproj",toPath:f.home + "/saved-project")}
            if mode == "link"{try FileManager.default.createSymbolicLink(atPath:target + "/escape",withDestinationPath:f.home)}
            if mode == "shared"{XCTAssertEqual(chmod(target,0o777),0)}
            let report=try await f.engine.scanJunk()
            XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains{$0.rule == rule && $0.path == target},mode)
        }
    }
    func testNativeClangModuleCacheRegeneratesAndRestoresWithoutOverwritingNewGeneration() async throws {
        let f=try fixture();defer{try? f.clean()}
        let root=f.home + "/Library/Developer/Xcode/DerivedData/ModuleCache.noindex",source=f.home + "/module.m",executable=f.home + "/module-consumer"
        try Data("@import Foundation; int main(void) { @autoreleasepool { return NSClassFromString(@\"NSString\") ? 0 : 1; } }\n".utf8).write(to:URL(fileURLWithPath:source))
        let clang=try XCTUnwrap(ProcessInfo.processInfo.environment["APP_SWEEP_CLANG"]),sdk=try XCTUnwrap(ProcessInfo.processInfo.environment["APP_SWEEP_SDK"])
        func build() throws {
            let result=try BoundedProcess.capture(clang,arguments:["-fobjc-arc","-fmodules","-fmodules-cache-path=" + root,"-isysroot",sdk,"-framework","Foundation",source,"-o",executable],timeout:30,mergeStderr:true)
            guard result.status == 0 else {throw SweepError.incomplete("Native module consumer failed: " + String(result.text.prefix(4000)))}
            XCTAssertEqual(try BoundedProcess.capture(executable,arguments:[],timeout:3,mergeStderr:true).status,0)
        }
        try build()
        XCTAssertFalse(try SafeFilesystem.snapshot(root).tree.isEmpty)
        let before=try VerifiedFileStream.digest(SafeFilesystem.snapshot(source)),report=try await f.engine.scanJunk()
        let item=report.selectableCandidates(includeUserData:false).first{$0.rule == rule && $0.path == root}
        XCTAssertNotNil(item,report.candidates.filter{$0.path == root}.compactMap(\.retentionReason).joined(separator:"; "))
        guard let item else{return}
        let plan=try await f.engine.makePlan(reportID:report.id,selected:[item.id],includeUserData:false),batch=try await f.engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        try build()
        let conflict=try await f.engine.restore(batchID:batch.id)
        XCTAssertEqual(conflict.status,.needsAttention)
        let generation=f.home + "/regenerated-module-cache"
        try FileManager.default.moveItem(atPath:root,toPath:generation)
        let restored=try await f.engine.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        try build()
        XCTAssertEqual(try VerifiedFileStream.digest(SafeFilesystem.snapshot(source)),before)
        XCTAssertTrue(FileManager.default.fileExists(atPath:generation))
    }
    func testNativeXcodeProductsRestoreAsRunnableBuildOutputAndPreserveRegeneration() async throws {
        let f=try fixture();defer{try? f.clean()};let root=try derived(f)
        let developer=try XCTUnwrap(ProcessInfo.processInfo.environment["DEVELOPER_DIR"])
        let arguments=["-project",f.home + "/Fixture.xcodeproj","-scheme","Fixture","-derivedDataPath",root,"-configuration","Debug","CODE_SIGNING_ALLOWED=NO","build"]
        func build() throws {
            let result=try BoundedProcess.capture(developer + "/usr/bin/xcodebuild",arguments:arguments,timeout:30,mergeStderr:true)
            guard result.status == 0,result.text.contains("BUILD SUCCEEDED") else {throw SweepError.incomplete("Native Xcode build failed: " + String(result.text.prefix(4000)))}
        }
        try build()
        let product=root + "/Build/Products/Debug/Fixture",source=try VerifiedFileStream.digest(SafeFilesystem.snapshot(f.home + "/main.c"))
        XCTAssertEqual(try BoundedProcess.capture(product,arguments:[],timeout:3,mergeStderr:true).status,0)
        let report=try await f.engine.scanJunk(),item=try XCTUnwrap(report.selectableCandidates(includeUserData:false).first{$0.rule == rule && $0.path == root + "/Build/Products"},report.candidates.filter{$0.path == root + "/Build/Products"}.compactMap(\.retentionReason).joined(separator:"; "))
        XCTAssertFalse(item.selectedByDefault)
        let plan=try await f.engine.makePlan(reportID:report.id,selected:[item.id],includeUserData:false),batch=try await f.engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        try build()
        XCTAssertEqual(try BoundedProcess.capture(product,arguments:[],timeout:3,mergeStderr:true).status,0)
        let conflict=try await f.engine.restore(batchID:batch.id)
        XCTAssertEqual(conflict.status,.needsAttention)
        try FileManager.default.moveItem(atPath:root + "/Build/Products",toPath:f.home + "/regenerated-products")
        let restored=try await f.engine.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        XCTAssertEqual(try BoundedProcess.capture(product,arguments:[],timeout:3,mergeStderr:true).status,0)
        XCTAssertEqual(try VerifiedFileStream.digest(SafeFilesystem.snapshot(f.home + "/main.c")),source)
    }
    func testGeneratedScopeCannotAuthorizeArchivesSDKsSourcesOrAliases() {
        let home="/Users/test",root=home + "/Library/Developer/Xcode"
        XCTAssertTrue(XcodeGeneratedRule.matches(root + "/DerivedData/ModuleCache.noindex",home:home))
        for path in [root + "/Archives/Example.xcarchive",root + "/iOS DeviceSupport/17/Symbols",root + "/DerivedData/ModuleCache.noindex/child",root + "/DerivedData/Fixture/SourcePackages",root + "/DerivedData/../SDKs",root + "/DerivedData/Fixture//Index.noindex",root + "/DerivedData/Fixture/Build/Intermediates.noindex"] {
            XCTAssertFalse(XcodeGeneratedRule.matches(path,home:home),path)
        }
    }
}
#endif
