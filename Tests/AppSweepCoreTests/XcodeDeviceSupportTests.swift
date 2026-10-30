#if os(macOS)
import Foundation
import XCTest
import Darwin
@testable import AppSweepCore

final class XcodeDeviceSupportTests: XCTestCase, @unchecked Sendable {
    private let rule="xcode-device-symbols-v1"
    private func symbols(_ f: NativeAcceptanceTests.NativeFixture) throws -> String {
        let root=f.home + "/Library/Developer/Xcode/iOS DeviceSupport/17.2 (21C62) arm64/Symbols"
        try FileManager.default.createDirectory(atPath:root + "/usr/lib",withIntermediateDirectories:true)
        let source=f.home + "/symbol.c",product=root + "/usr/lib/libDisposable.dylib"
        try Data("int disposable_symbol(void) { return 42; }\n".utf8).write(to:URL(fileURLWithPath:source))
        let clang=try XCTUnwrap(ProcessInfo.processInfo.environment["APP_SWEEP_CLANG"]),developer=try XCTUnwrap(ProcessInfo.processInfo.environment["DEVELOPER_DIR"])
        let build=try BoundedProcess.capture(clang,arguments:["-target","arm64-apple-ios15.0","-isysroot",developer + "/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk","-g","-dynamiclib","-Wl,-install_name,/usr/lib/libDisposable.dylib",source,"-o",product],timeout:30,mergeStderr:true)
        guard build.status == 0 else{throw SweepError.incomplete("Independent device-symbol fixture build failed: " + build.text)}
        return root
    }
    private func nativeSymbols(_ root:String) throws -> String {
        let developer=try XCTUnwrap(ProcessInfo.processInfo.environment["DEVELOPER_DIR"])
        return try BoundedProcess.run(developer + "/Toolchains/XcodeDefault.xctoolchain/usr/bin/nm",arguments:[root + "/usr/lib/libDisposable.dylib"],timeout:5)
    }
    func testNativeDeviceSymbolsArePersonalDataAndRestoreForNativeSymbolConsumer() async throws {
        let f=try NativeAcceptanceTests.NativeFixture(additionalRules:[rule]);defer{try? f.clean()}
        let root=try symbols(f),original=try SafeFilesystem.snapshot(root),before=try nativeSymbols(root)
        XCTAssertTrue(before.contains("_disposable_symbol"))
        let image=URL(fileURLWithPath:root).deletingLastPathComponent().path + "/DeveloperDiskImage.dmg"
        try Data("keep developer disk image".utf8).write(to:URL(fileURLWithPath:image))
        let report=try await f.engine.scanLegacyManagementFixture(),candidate=report.candidates.first{$0.path == root && $0.rule == rule}
        XCTAssertNotNil(candidate,"Device symbol management is a separate Xcode mechanism")
        guard let candidate else{return}
        XCTAssertTrue(candidate.userData);XCTAssertFalse(candidate.selectedByDefault)
        XCTAssertFalse(report.selectableCandidates(includeUserData:false).contains{$0.id == candidate.id})
        XCTAssertTrue(report.selectableCandidates(includeUserData:true).contains{$0.id == candidate.id},candidate.retentionReason ?? "")
        let plan=try await f.engine.makePlan(reportID:report.id,selected:[candidate.id],includeUserData:true),batch=try await f.engine.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        XCTAssertEqual(try String(contentsOfFile:image,encoding:.utf8),"keep developer disk image")
        let fresh=SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[rule]),vaultPath:f.home + "/Library/Application Support/App Sweep/Recovery",fixture:false)
        let restored=try await fresh.restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        XCTAssertEqual(try SafeFilesystem.snapshot(root).identity.inode,original.identity.inode)
        XCTAssertEqual(try SafeFilesystem.snapshot(root).tree,original.tree)
        XCTAssertEqual(try nativeSymbols(root),before)
    }
    func testUnknownLayoutSharedAndLinkedSymbolsAreRetained() async throws {
        for variant in ["shared","link","unknown"] {
            let f=try NativeAcceptanceTests.NativeFixture(additionalRules:[rule]);defer{try? f.clean()};let root=try symbols(f)
            if variant == "shared"{XCTAssertEqual(chmod(root + "/usr/lib",0o777),0)}
            if variant == "link"{try FileManager.default.createSymbolicLink(atPath:root + "/external",withDestinationPath:f.home)}
            if variant == "unknown"{try FileManager.default.moveItem(atPath:URL(fileURLWithPath:root).deletingLastPathComponent().path,toPath:f.home + "/Library/Developer/Xcode/iOS DeviceSupport/unknown")}
            let report=try await f.engine.scanLegacyManagementFixture()
            XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains{$0.rule == rule},variant)
        }
    }
    func testDeviceSupportRuleCannotSelectSDKImagesArchivesOrWholeVersionDirectory() async throws {
        let f=try NativeAcceptanceTests.NativeFixture(additionalRules:[rule]);defer{try? f.clean()};let root=try symbols(f)
        for path in [URL(fileURLWithPath:root).deletingLastPathComponent().path,root + "/usr/lib/libDisposable.dylib",f.home + "/Library/Developer/Xcode/iOS DeviceSupport",f.home + "/Library/Developer/Xcode/SDKs/iPhoneOS.sdk",f.home + "/Library/Developer/CoreSimulator/Devices"] {
            XCTAssertNotNil(SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[rule]).denial(path:path,category:.userData,rule:rule),path)
        }
    }
    func testRegisteredNativeSymbolsUseDefaultUserPolicyAndFreshRestoration() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_DEVICE_SYMBOL_ACCEPTANCE"] == "AppSweep-General-20261016" else{throw XCTSkip("Registered disposable VM device-symbol sample only")}
        guard getuid() == 501,try SystemIdentity.home() == "/Users/localtest",try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).trimmingCharacters(in:.whitespacesAndNewlines) == "VirtualMac2,1" else{throw SweepError.denied("Requires registered VM")}
        let task="/Users/localtest/AppSweepAcceptanceGeneral-20261016"
        let record=try XCTUnwrap(try JSONSerialization.jsonObject(with:SafeFilesystem.readMetadata(task + "/device-symbols-default-current.json"))as? [String:Any])
        let id=try XCTUnwrap(record["id"]as? String),owned=try XCTUnwrap(record["owned"]as? String),root=try XCTUnwrap(record["symbols"]as? String)
        guard UUID(uuidString:id) != nil,owned == task + "/native-device-symbols-" + id + ".noindex",
              root == "/Users/localtest/Library/Developer/Xcode/iOS DeviceSupport/AppSweep" + id.replacingOccurrences(of:"-",with:"") + ",1 17.2 (21C62) arm64/Symbols",
              !FileManager.default.fileExists(atPath:owned + "/result.json") else{throw SweepError.denied("Native device-symbol registration changed")}
        let before=try SafeFilesystem.snapshot(root),nativeBefore=try nativeSymbols(root),digest=try VerifiedFileStream.digest(SafeFilesystem.snapshot(root + "/usr/lib/libDisposable.dylib"))
        let e=SweepEngine(),report=try await e.scanLegacyManagementFixture()
        guard let item=report.candidates.first(where:{$0.path == root && $0.rule == rule}) else{XCTFail("Default scan lacks device-symbol management");return}
        guard report.selectableCandidates(includeUserData:true).contains(where:{$0.id == item.id}) else{XCTFail(item.retentionReason ?? "Default platform rule missing");return}
        XCTAssertTrue(item.userData);XCTAssertFalse(item.selectedByDefault)
        XCTAssertFalse(report.selectableCandidates(includeUserData:false).contains{$0.id == item.id})
        let plan=try await e.makePlan(reportID:report.id,selected:[item.id],includeUserData:true),batch=try await e.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        let restored=try await SweepEngine().restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        XCTAssertEqual(try SafeFilesystem.snapshot(root).identity.inode,before.identity.inode)
        XCTAssertEqual(try nativeSymbols(root),nativeBefore)
        XCTAssertEqual(try VerifiedFileStream.digest(SafeFilesystem.snapshot(root + "/usr/lib/libDisposable.dylib")),digest)
        let result:[String:Any]=["symbols":root,"inode":before.identity.inode,"batch":batch.id.uuidString,"productSHA256":digest,"state":"native iOS Mach-O symbol consumer; default user policy explicit personal-data selection, whole isolation/fresh restoration; ordinary GUI pending; no physical device producer claim"]
        try JSONSerialization.data(withJSONObject:result,options:[.prettyPrinted,.sortedKeys]).write(to:URL(fileURLWithPath:owned + "/result.json"),options:.withoutOverwriting)
        print("DEFAULT_DEVICE_SYMBOLS_ACCEPTED " + String(data:try JSONSerialization.data(withJSONObject:result),encoding:.utf8)!)
    }
}
#endif
