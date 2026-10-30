#if os(macOS)
import Foundation
import Darwin
import XCTest
import CFSafety
@testable import AppSweepCore

final class ApplicationArchitecturePreparationTests: XCTestCase, @unchecked Sendable {
    private var native: String {
        #if arch(arm64)
        "arm64"
        #else
        "x86_64"
        #endif
    }
    private func fixture(architectures: [String] = ["arm64","x86_64"]) throws -> NativeAcceptanceTests.NativeFixture {
        let f = try NativeAcceptanceTests.NativeFixture()
        do {
            let code = f.home + "/disposable.c"
            try Data("int main(void) { return 0; }\n".utf8).write(to:URL(fileURLWithPath:code))
            let sdk = try XCTUnwrap(ProcessInfo.processInfo.environment["APP_SWEEP_SDK"])
            let clang = try XCTUnwrap(ProcessInfo.processInfo.environment["APP_SWEEP_CLANG"])
            for architecture in architectures {
                let compilation = try BoundedProcess.capture(clang,arguments:["-arch",architecture,"-isysroot",sdk,"-mmacosx-version-min=12.0",code,"-o",f.home + "/" + architecture],timeout:30,mergeStderr:true)
                XCTAssertEqual(compilation.status,0,compilation.text)
                guard compilation.status == 0 else { throw SweepError.incomplete("Disposable architecture compilation failed") }
            }
            _ = try BoundedProcess.run("/usr/bin/lipo",arguments:["-create"] + architectures.map { f.home + "/" + $0 } + ["-output",f.executable],timeout:10)
            _ = try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-",f.app],timeout:10)
            return f
        } catch { try? f.clean(); throw error }
    }
    private func snapshot(_ f: NativeAcceptanceTests.NativeFixture) throws -> FileSnapshot {
        try SafeFilesystem.snapshot(f.app,allowInternalLinks:true,purpose:.application,allowInternalHardLinks:true)
    }
    private func codeHash(_ path: String) throws -> String {
        let result = try BoundedProcess.capture("/usr/bin/codesign",arguments:["-d","--verbose=4","--arch",native,path],timeout:10,mergeStderr:true)
        XCTAssertEqual(result.status,0,result.text)
        let hashes = result.text.split(separator:"\n").filter { $0.hasPrefix("CDHash=") }
        XCTAssertEqual(hashes.count,1)
        return String(try XCTUnwrap(hashes.first).dropFirst(7))
    }
    private func intent(_ f: NativeAcceptanceTests.NativeFixture, name: String) throws -> SafeDirectory {
        let parent = try SafeDirectory(path:f.home).privateChild("architecture-preparation")
        try parent.write(Data(name.utf8),name:"preparation-intent.txt")
        return parent
    }
    func testPreparesCompleteNativeAppWithoutResigningOrChangingOriginal() throws {
        let f = try fixture(); defer { try? f.clean() }
        let source = try snapshot(f), bytes = try SafeFilesystem.readMetadata(f.executable), hash = try codeHash(f.app)
        let plan = try ApplicationArchitecturePreparation.analyze(source)
        let name = UUID().uuidString, parent = try intent(f,name:name)
        let result = try ApplicationArchitecturePreparation.prepare(plan,in:parent,name:name)
        XCTAssertEqual(result.architecture,native)
        XCTAssertEqual(result.changes.map(\.relative),["Contents/MacOS/fixture"])
        XCTAssertGreaterThan(result.savedBytes,0)
        XCTAssertEqual(result.snapshot.bytes,source.bytes-result.savedBytes)
        XCTAssertNotEqual(result.snapshot.identity.inode,source.identity.inode)
        XCTAssertEqual(result.snapshot.tree.map(\.relative),source.tree.map(\.relative))
        let signature = try BoundedProcess.capture("/usr/bin/codesign",arguments:["--verify","--deep","--strict","--all-architectures",result.snapshot.path],timeout:15,mergeStderr:true)
        XCTAssertEqual(signature.status,0,signature.text)
        XCTAssertEqual(try codeHash(result.snapshot.path),hash)
        let executable = result.snapshot.path + "/Contents/MacOS/fixture"
        let run = try BoundedProcess.capture(executable,arguments:[],timeout:5,mergeStderr:true)
        XCTAssertEqual(run.status,0,run.text)
        XCTAssertNoThrow(try SafeFilesystem.verify(source))
        XCTAssertEqual(try SafeFilesystem.readMetadata(f.executable),bytes)
        XCTAssertEqual(try codeHash(f.app),hash)
    }
    func testNoRedundancyAndMissingNativeArchitectureDoNotCreatePreparation() throws {
        for architectures in [[native],[native == "arm64" ? "x86_64" : "arm64"]] {
            let f = try fixture(architectures:architectures); defer { try? f.clean() }
            let source = try snapshot(f)
            XCTAssertThrowsError(try ApplicationArchitecturePreparation.analyze(source))
            XCTAssertFalse(FileManager.default.fileExists(atPath:f.home + "/architecture-preparation"))
            XCTAssertNoThrow(try SafeFilesystem.verify(source))
        }
    }
    func testChangedSourceCannotReuseAnalysisOrCreatePreparedBundle() throws {
        let f = try fixture(); defer { try? f.clean() }
        let source = try snapshot(f), plan = try ApplicationArchitecturePreparation.analyze(source)
        let name = UUID().uuidString, parent = try intent(f,name:name)
        let resource = f.app + "/Contents/new-version.txt"
        try Data("preserve new version".utf8).write(to:URL(fileURLWithPath:resource))
        XCTAssertThrowsError(try ApplicationArchitecturePreparation.prepare(plan,in:parent,name:name))
        XCTAssertThrowsError(try parent.identity(name))
        XCTAssertEqual(try SafeFilesystem.readMetadata(resource),Data("preserve new version".utf8))
    }
    func testProtectedIdentityRemainsUnchanged() throws {
        for identifier in ["com.apple.disposable.optimization","org.appsweep.app"] {
            let f = try fixture(); defer { try? f.clean() }
            let infoPath = f.app + "/Contents/Info.plist"
            var info = try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:infoPath)),format:nil)as?[String:Any])
            info["CFBundleIdentifier"] = identifier
            try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:infoPath))
            let signed = try BoundedProcess.capture("/usr/bin/codesign",arguments:["--force","--sign","-",f.app],timeout:10,mergeStderr:true)
            XCTAssertEqual(signed.status,0,"Fixture signing \(identifier): " + signed.text)
            guard signed.status == 0 else { continue }
            let source = try snapshot(f)
            XCTAssertThrowsError(try ApplicationArchitecturePreparation.analyze(source))
            XCTAssertNoThrow(try SafeFilesystem.verify(source))
        }
    }
    func testSignatureSealedDataIsNeverTreatedAsCodeByMagic() throws {
        for useActualUniversalBytes in [false,true] {
            let f = try fixture(); defer { try? f.clean() }
            let resources = f.app + "/Contents/Resources"
            try FileManager.default.createDirectory(atPath:resources,withIntermediateDirectories:true)
            let value = useActualUniversalBytes ? try SafeFilesystem.readMetadata(f.executable) : Data([0xca,0xfe,0xba,0xbe,0,0,0,2])
            let resource = resources + "/sealed-data.bin"
            try value.write(to:URL(fileURLWithPath:resource))
            let example = resources + "/example/_CodeSignature"
            try FileManager.default.createDirectory(atPath:example,withIntermediateDirectories:true)
            let fakeSeal = try PropertyListSerialization.data(fromPropertyList:["files2":["../../outside":["cdhash":Data(repeating:0,count:20),"requirement":"identifier imaginary"]]],format:.xml,options:0)
            try fakeSeal.write(to:URL(fileURLWithPath:example + "/CodeResources"))
            let signed = try BoundedProcess.capture("/usr/bin/codesign",arguments:["--force","--sign","-",f.app],timeout:10,mergeStderr:true)
            XCTAssertEqual(signed.status,0,signed.text); guard signed.status == 0 else { continue }
            let source = try snapshot(f), hash = try codeHash(f.app)
            let plan = try ApplicationArchitecturePreparation.analyze(source)
            XCTAssertEqual(plan.changes.map(\.relative),["Contents/MacOS/fixture"],"Signature-sealed resource bytes are not interchangeable code, even if their magic is a complete valid fat binary")
            let name = UUID().uuidString, parent = try intent(f,name:name)
            let result = try ApplicationArchitecturePreparation.prepare(plan,in:parent,name:name)
            XCTAssertEqual(try SafeFilesystem.readMetadata(result.snapshot.path + "/Contents/Resources/sealed-data.bin"),value)
            XCTAssertEqual(try SafeFilesystem.readMetadata(result.snapshot.path + "/Contents/Resources/example/_CodeSignature/CodeResources"),fakeSeal,"A signature example sealed as data must not supply code membership or paths")
            XCTAssertEqual(try codeHash(result.snapshot.path),hash)
            XCTAssertEqual(try SafeFilesystem.readMetadata(resource),value)
            XCTAssertNoThrow(try SafeFilesystem.verify(source))
        }
    }
    func testSignedNestedCodeKeepsItsOwnNativeSignatureAndRuns() throws {
        let f = try fixture(); defer { try? f.clean() }
        let helper = f.app + "/Contents/MacOS/Helper"
        _ = try BoundedProcess.run("/usr/bin/lipo",arguments:["-create",f.home + "/arm64",f.home + "/x86_64","-output",helper],timeout:10)
        _ = try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-","--identifier","org.example.sweepfixture.helper",helper],timeout:10)
        _ = try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-",f.app],timeout:10)
        let source = try snapshot(f), original = try codeHash(helper), outer = try codeHash(f.app)
        let plan = try ApplicationArchitecturePreparation.analyze(source)
        XCTAssertEqual(plan.changes.map(\.relative),["Contents/MacOS/Helper","Contents/MacOS/fixture"])
        let name = UUID().uuidString, parent = try intent(f,name:name)
        let result = try ApplicationArchitecturePreparation.prepare(plan,in:parent,name:name)
        let target = result.snapshot.path + "/Contents/MacOS/Helper"
        XCTAssertEqual(try codeHash(target),original); XCTAssertEqual(try codeHash(result.snapshot.path),outer)
        let run = try BoundedProcess.capture(target,arguments:[],timeout:5,mergeStderr:true)
        XCTAssertEqual(run.status,0,run.text)
        XCTAssertNoThrow(try SafeFilesystem.verify(source))
    }
    func testForeignOnlyNestedRuntimeIsPreservedWithoutBlockingNativeAppPreparation() throws {
        let f = try fixture(); defer { try? f.clean() }
        let other = native == "arm64" ? "x86_64" : "arm64"
        let helper = f.app + "/Contents/MacOS/BackDeploymentRuntime"
        try FileManager.default.copyItem(atPath:f.home + "/" + other,toPath:helper)
        _ = try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-","--identifier","org.example.sweepfixture.foreign",helper],timeout:10)
        _ = try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-",f.app],timeout:10)
        let source = try snapshot(f), bytes = try SafeFilesystem.readMetadata(helper), hash = try codeHash(f.app)
        let plan = try ApplicationArchitecturePreparation.analyze(source)
        XCTAssertEqual(plan.changes.map(\.relative),["Contents/MacOS/fixture"])
        XCTAssertTrue(plan.retained.contains { $0.relative == "Contents/MacOS/BackDeploymentRuntime" && !$0.reason.isEmpty })
        let token = UUID().uuidString, parent = try intent(f,name:token)
        let result = try ApplicationArchitecturePreparation.prepare(plan,in:parent,name:token)
        XCTAssertTrue(result.retained.contains { $0.relative == "Contents/MacOS/BackDeploymentRuntime" && !$0.reason.isEmpty })
        XCTAssertEqual(try SafeFilesystem.readMetadata(result.snapshot.path + "/Contents/MacOS/BackDeploymentRuntime"),bytes,"An existing foreign-only fallback runtime is copied unchanged; absence of a native slice is not permission to delete or rewrite it")
        XCTAssertEqual(try codeHash(result.snapshot.path),hash)
        let signature = try BoundedProcess.capture("/usr/bin/codesign",arguments:["--verify","--deep","--strict","--all-architectures",result.snapshot.path],timeout:15,mergeStderr:true)
        XCTAssertEqual(signature.status,0,signature.text)
        XCTAssertNoThrow(try SafeFilesystem.verify(source))
    }
    func testOfficialApplicationPrivatePreparationKeepsSourceAndNativeSignature() throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_REAL_ARCHITECTURE_ACCEPTANCE"] == "AppSweep-General-20261016",
              NSHomeDirectory() == "/Users/localtest",
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).hasPrefix("VirtualMac") else { throw XCTSkip("Prepared disposable VM official-app architecture inputs only") }
        for (name,identifier,team) in [("IINA","com.colliderli.iina","67CQ77V27R"),("Vienna","uk.co.opencommunity.vienna2","KUU2LM7U9K")] {
            let f = try fixture(); defer { try? f.clean() }
            let path = NSHomeDirectory() + "/Applications/" + name + ".app"
            guard AppInspector.signatureMatches(path:path,identifier:identifier), AppInspector.signedByTeam(path:path,team:team) else { throw SweepError.denied("Registered official source identity changed") }
            try ActivityInspector.ensureStopped(bundleID:identifier,applicationPath:path)
            let source = try SafeFilesystem.snapshot(path,allowInternalLinks:true,purpose:.application,allowInternalHardLinks:true)
            let hash = try codeHash(path), plan = try ApplicationArchitecturePreparation.analyze(source)
            let token = UUID().uuidString, parent = try intent(f,name:token)
            try parent.write(JSONSerialization.data(withJSONObject:["source":path,"sourceInode":source.identity.inode,"sourceDevice":source.identity.device,"target":parent.path + "/" + token,"sourceNativeCodeHash":hash,"purpose":"private architecture-prepared copy only; original read-only; no installed swap/launch/update acceptance"],options:[.sortedKeys]),name:"official-source-intent.json")
            let result = try ApplicationArchitecturePreparation.prepare(plan,in:parent,name:token)
            XCTAssertGreaterThan(result.savedBytes,0); XCTAssertEqual(result.snapshot.bytes,source.bytes-result.savedBytes)
            XCTAssertFalse(result.changes.isEmpty)
            XCTAssertEqual(result.snapshot.tree.map(\.relative),source.tree.map(\.relative))
            XCTAssertEqual(try codeHash(result.snapshot.path),hash); XCTAssertEqual(try codeHash(path),hash)
            let verification = try BoundedProcess.capture("/usr/bin/codesign",arguments:["--verify","--deep","--strict","--all-architectures",result.snapshot.path],timeout:30,mergeStderr:true)
            XCTAssertEqual(verification.status,0,verification.text)
            for change in result.changes {
                let copied = try XCTUnwrap(result.snapshot.tree.first { $0.relative == change.relative })
                XCTAssertEqual(copied.identity.size,Int64(change.slice.size)); XCTAssertEqual(copied.identity.owner,change.originalIdentity.owner)
                XCTAssertEqual(copied.identity.mode,change.originalIdentity.mode)
                XCTAssertEqual(copied.identity.modifiedSeconds,change.originalIdentity.modifiedSeconds)
                XCTAssertEqual(copied.identity.modifiedNanoseconds,change.originalIdentity.modifiedNanoseconds)
            }
            XCTAssertNoThrow(try SafeFilesystem.verify(source))
            print("OFFICIAL_ARCHITECTURE_PREPARATION=" + String(decoding:try JSONSerialization.data(withJSONObject:["application":name,"identifier":identifier,"team":team,"sourceInode":source.identity.inode,"copyInode":result.snapshot.identity.inode,"transformedNodes":result.changes.count,"smallerCopyBytes":result.savedBytes,"nativeCodeHash":hash,"sourceUnchanged":true,"strictDeepAllArchitectures":verification.status == 0,"installedSwap":false,"realLaunchOrUpdateAcceptance":false],options:[.sortedKeys]),as:UTF8.self))
        }
    }
}
#endif
