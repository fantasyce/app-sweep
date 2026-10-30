#if os(macOS)
import Foundation
import Darwin
import XCTest
import CFSafety
@testable import AppSweepCore

final class ApplicationTreeCopyTests: XCTestCase, @unchecked Sendable {
    private struct Fixture {
        let parent: SafeDirectory, root: SafeDirectory, app: SafeDirectory, prepared: SafeDirectory
        let identity: FileIdentity, name: String
        init() throws {
            guard getuid() != 0, let base = ProcessInfo.processInfo.environment["APP_SWEEP_FIXTURES"], base.hasPrefix(NSHomeDirectory() + "/AppSweepAcceptance") else { throw XCTSkip("Explicit isolated task fixtures only") }
            parent = try SafeDirectory(path:base); name = UUID().uuidString
            guard mkdirat(parent.fd,name,0o700) == 0 else { throw SweepError.denied("New fixture required") }
            root = try parent.existingPrivateChild(name); identity = try root.ownIdentity
            app = try root.privateChild("Source.app"); prepared = try root.privateChild("prepared")
            let contents = try app.privateChild("Contents"), code = try contents.privateChild("MacOS"), resources = try contents.privateChild("Resources")
            try code.write(Data("#!/bin/sh\nexit 0\n".utf8),name:"main")
            XCTAssertEqual(chmod(code.path + "/main",0o755),0)
            try resources.write(Data("keep resource".utf8),name:"data")
            XCTAssertEqual(chmod(app.path,0o755),0)
            print("APPLICATION_TREE_COPY_FIXTURE=" + String(decoding:try JSONSerialization.data(withJSONObject:["path":root.path,"inode":identity.inode,"device":identity.device,"owner":identity.owner,"state":"created"],options:[.sortedKeys]),as:UTF8.self))
        }
        func snapshot() throws -> FileSnapshot {
            try SafeFilesystem.snapshot(app.path,allowInternalLinks:true,purpose:.application,allowInternalHardLinks:true)
        }
        func clean() {
            do {
                let snapshot = try SafeFilesystem.snapshot(root.path,allowInternalLinks:true,purpose:.application,allowInternalHardLinks:true)
                guard snapshot.identity.inode == identity.inode, snapshot.identity.device == identity.device,
                      SafeFilesystem.removeVerified(in:parent,name:name,identity:snapshot.identity,contents:snapshot.tree,allowInternalHardLinks:true) else { throw SweepError.stale("Fixture retained") }
                print("APPLICATION_TREE_COPY_FIXTURE=" + String(decoding:try JSONSerialization.data(withJSONObject:["path":root.path,"inode":identity.inode,"state":"removed-after-identity-check"],options:[.sortedKeys]),as:UTF8.self))
            } catch { XCTFail("Application-copy fixture retained: " + root.path) }
        }
    }
    func testCopiesCompleteTreeWithExecutableAndFrameworkLinkWithoutChangingSource() throws {
        let f = try Fixture(); defer { f.clean() }
        let framework = try SafeDirectory(path:f.app.path + "/Contents").privateChild("Frameworks").privateChild("Demo.framework").privateChild("Versions")
        try framework.privateChild("A").write(Data("framework bytes".utf8),name:"Demo")
        XCTAssertEqual(symlinkat("A",framework.fd,"Current"),0)
        let source = try f.snapshot(), token = UUID().uuidString
        let result = try ApplicationTreeCopy.prepare(source,in:f.prepared,name:token)
        XCTAssertEqual(result.path,f.prepared.path + "/" + token)
        XCTAssertNotEqual(result.identity.inode,source.identity.inode)
        XCTAssertEqual(result.identity.mode & 0o777,0o755)
        XCTAssertEqual(Set(result.tree.map(\.relative)),Set(source.tree.map(\.relative)))
        XCTAssertEqual(try SafeFilesystem.readMetadata(result.path + "/Contents/MacOS/main"),Data("#!/bin/sh\nexit 0\n".utf8))
        XCTAssertEqual(try SafeDirectory(path:result.path + "/Contents/MacOS").identity("main").mode & 0o777,0o755)
        XCTAssertEqual(try SafeFilesystem.readMetadata(result.path + "/Contents/Resources/data"),Data("keep resource".utf8))
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath:result.path + "/Contents/Frameworks/Demo.framework/Versions/Current"),"A")
        XCTAssertNoThrow(try SafeFilesystem.verify(source))
    }
    func testClosedHardLinksAreRecreatedWithinCopyWithIndependentSourceInode() throws {
        let f = try Fixture(); defer { f.clean() }
        let resources = try SafeDirectory(path:f.app.path + "/Contents/Resources")
        XCTAssertEqual(linkat(resources.fd,"data",resources.fd,"alias",0),0)
        let source = try f.snapshot()
        let result = try ApplicationTreeCopy.prepare(source,in:f.prepared,name:UUID().uuidString)
        let target = try SafeDirectory(path:result.path + "/Contents/Resources")
        let a = try target.identity("data"), b = try target.identity("alias")
        XCTAssertEqual(a.inode,b.inode); XCTAssertEqual(a.links,2)
        XCTAssertNotEqual(a.inode,try resources.identity("data").inode)
        XCTAssertNoThrow(try SafeFilesystem.verify(source))
    }
    func testExternalLinkIsCopiedAsTextAndExternalObjectIsUntouched() throws {
        let f = try Fixture(); defer { f.clean() }
        try f.root.write(Data("external marker".utf8),name:"neighbour")
        let before = try f.root.identity("neighbour"), resources = try SafeDirectory(path:f.app.path + "/Contents/Resources")
        XCTAssertEqual(symlinkat("../../../neighbour",resources.fd,"external-link"),0)
        let result = try ApplicationTreeCopy.prepare(f.snapshot(),in:f.prepared,name:UUID().uuidString)
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath:result.path + "/Contents/Resources/external-link"),"../../../neighbour")
        XCTAssertEqual(try f.root.identity("neighbour"),before)
        XCTAssertEqual(try SafeFilesystem.readMetadata(f.root.path + "/neighbour"),Data("external marker".utf8))
    }
    func testExistingPreparationAndInvalidNamesCannotOverwriteAnything() throws {
        let f = try Fixture(); defer { f.clean() }
        let source = try f.snapshot(), token = UUID().uuidString, existing = try f.prepared.privateChild(token)
        try existing.write(Data("keep existing".utf8),name:"sentinel")
        XCTAssertThrowsError(try ApplicationTreeCopy.prepare(source,in:f.prepared,name:token))
        for name in ["","../escape","/absolute","nested/name","copy.app"] {
            XCTAssertThrowsError(try ApplicationTreeCopy.prepare(source,in:f.prepared,name:name))
        }
        XCTAssertEqual(try SafeFilesystem.readMetadata(existing.path + "/sentinel"),Data("keep existing".utf8))
        XCTAssertNoThrow(try SafeFilesystem.verify(source))
    }
    func testSourceChangedSinceScanIsRefusedBeforePreparationAppears() throws {
        let f = try Fixture(); defer { f.clean() }
        let source = try f.snapshot(), token = UUID().uuidString
        try SafeDirectory(path:f.app.path + "/Contents/Resources").write(Data("new version".utf8),name:"data")
        XCTAssertThrowsError(try ApplicationTreeCopy.prepare(source,in:f.prepared,name:token))
        XCTAssertThrowsError(try f.prepared.identity(token))
        XCTAssertEqual(try SafeFilesystem.readMetadata(f.app.path + "/Contents/Resources/data"),Data("new version".utf8))
    }
    func testNonClosedHardLinksCannotAuthorizeCopyEvenWithForgedSnapshot() throws {
        let f = try Fixture(); defer { f.clean() }
        let original = try f.snapshot(), resources = try SafeDirectory(path:f.app.path + "/Contents/Resources")
        XCTAssertEqual(linkat(resources.fd,"data",f.root.fd,"outside-alias",0),0)
        let current = try resources.identity("data")
        let entries = original.tree.map { $0.relative == "Contents/Resources/data" ? TreeEntry(relative:$0.relative,identity:current) : $0 }
        let forged = FileSnapshot(path:original.path,identity:original.identity,ancestors:original.ancestors,tree:entries,bytes:original.bytes,allowInternalLinks:true,purpose:.application,allowInternalHardLinks:true)
        let token = UUID().uuidString
        XCTAssertThrowsError(try ApplicationTreeCopy.prepare(forged,in:f.prepared,name:token))
        XCTAssertThrowsError(try f.prepared.identity(token))
        XCTAssertEqual(try f.root.identity("outside-alias").inode,current.inode)
    }
    func testOrdinarySnapshotSharedParentAndNestedPreparationAreRefused() throws {
        let f = try Fixture(); defer { f.clean() }
        let token = UUID().uuidString
        XCTAssertThrowsError(try ApplicationTreeCopy.prepare(SafeFilesystem.snapshot(f.app.path),in:f.prepared,name:token))
        let source = try f.snapshot()
        XCTAssertEqual(fchmod(f.prepared.fd,0o755),0)
        XCTAssertThrowsError(try ApplicationTreeCopy.prepare(source,in:f.prepared,name:token))
        XCTAssertEqual(fchmod(f.prepared.fd,0o700),0)
        XCTAssertThrowsError(try ApplicationTreeCopy.prepare(source,in:SafeDirectory(path:f.app.path + "/Contents/Resources"),name:token))
        XCTAssertThrowsError(try f.prepared.identity(token))
    }
    func testSourceAliasReplacementDoesNotReadThroughReplacement() throws {
        let f = try Fixture(); defer { f.clean() }
        let source = try f.snapshot(), token = UUID().uuidString, outside = try f.root.privateChild("external")
        try outside.write(Data("outside".utf8),name:"sentinel")
        XCTAssertEqual(renameat(f.root.fd,"Source.app",f.root.fd,"previous-source.app"),0)
        XCTAssertEqual(symlinkat("external",f.root.fd,"Source.app"),0)
        XCTAssertThrowsError(try ApplicationTreeCopy.prepare(source,in:f.prepared,name:token))
        XCTAssertThrowsError(try f.prepared.identity(token))
        XCTAssertEqual(try SafeFilesystem.readMetadata(outside.path + "/sentinel"),Data("outside".utf8))
    }
    func testMetadataAndResourceForkArePreservedAcrossWholeTree() throws {
        let f = try Fixture(); defer { f.clean() }
        let path = f.app.path + "/Contents/Resources/data"
        _ = try BoundedProcess.run("/usr/bin/xattr",arguments:["-w","org.appsweep.tree-copy-test","keep attribute",path],timeout:3)
        _ = try BoundedProcess.run("/usr/bin/xattr",arguments:["-wx","com.apple.ResourceFork","0102030405",path],timeout:3)
        _ = try BoundedProcess.run("/bin/chmod",arguments:["+a","everyone deny write",path],timeout:3)
        let source = try f.snapshot(), result = try ApplicationTreeCopy.prepare(source,in:f.prepared,name:UUID().uuidString)
        let destination = result.path + "/Contents/Resources/data"
        XCTAssertEqual(try BoundedProcess.run("/usr/bin/xattr",arguments:["-p","org.appsweep.tree-copy-test",destination],timeout:3).trimmingCharacters(in:.whitespacesAndNewlines),"keep attribute")
        XCTAssertEqual(try BoundedProcess.run("/usr/bin/xattr",arguments:["-px","com.apple.ResourceFork",destination],timeout:3).filter { !$0.isWhitespace },"0102030405")
        XCTAssertTrue(try BoundedProcess.run("/bin/ls",arguments:["-le",destination],timeout:3).contains("everyone deny write"))
        XCTAssertNoThrow(try SafeFilesystem.verify(source))
    }
    func testForgedByteTotalIsRefusedBeforePreparation() throws {
        let f = try Fixture(); defer { f.clean() }
        let original = try f.snapshot(), token = UUID().uuidString
        let forged = FileSnapshot(path:original.path,identity:original.identity,ancestors:original.ancestors,tree:original.tree,bytes:0,allowInternalLinks:true,purpose:.application,allowInternalHardLinks:true)
        XCTAssertThrowsError(try ApplicationTreeCopy.prepare(forged,in:f.prepared,name:token))
        XCTAssertThrowsError(try f.prepared.identity(token))
        XCTAssertNoThrow(try SafeFilesystem.verify(original))
    }
    func testReadFailureRetainsPartialPreparationAndOriginalUnchanged() throws {
        let f = try Fixture(); defer { f.clean() }
        let path = f.app.path + "/Contents/Resources/data", token = UUID().uuidString
        XCTAssertEqual(chmod(path,0),0)
        defer { _ = chmod(path,0o600) }
        let original = try f.snapshot()
        XCTAssertThrowsError(try ApplicationTreeCopy.prepare(original,in:f.prepared,name:token))
        let partial = try f.prepared.existingPrivateChild(token)
        XCTAssertEqual(try SafeFilesystem.readMetadata(partial.path + "/Contents/MacOS/main"),Data("#!/bin/sh\nexit 0\n".utf8))
        XCTAssertThrowsError(try SafeDirectory(path:partial.path + "/Contents/Resources").identity("data"))
        XCTAssertNoThrow(try SafeFilesystem.verify(original))
    }
    func testNativeLowSpaceVolumeRefusesBeforeCreatingPreparation() throws {
        let env = ProcessInfo.processInfo.environment
        guard let path = env["APP_SWEEP_LOW_SPACE_ACCEPTANCE"], env["APP_SWEEP_FIXTURES"] == path,
              NSHomeDirectory() == "/Users/localtest",
              path.hasPrefix(NSHomeDirectory() + "/AppSweepAcceptanceGeneral-20261016/space-probes.noindex/"),
              path.hasSuffix("/mounted.noindex/fixtures.noindex"),
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).hasPrefix("VirtualMac") else { throw XCTSkip("Explicit isolated small-volume acceptance only") }
        let f = try Fixture(); defer { f.clean() }
        let source = try f.snapshot(), token = UUID().uuidString
        XCTAssertGreaterThan(f.prepared.availableBytes,1024*1024)
        XCTAssertLessThan(f.prepared.availableBytes,1024*1024*1024)
        XCTAssertEqual(try f.prepared.ownIdentity.device,source.identity.device)
        XCTAssertEqual(as_private_descriptor(f.prepared.fd),1)
        XCTAssertEqual(source.identity.owner,getuid())
        XCTAssertEqual(source.bytes,30)
        do { _ = try ApplicationTreeCopy.prepare(source,in:f.prepared,name:token); XCTFail("A genuinely small volume must preserve the safety reserve") }
        catch SweepError.denied { }
        catch { XCTFail("Unexpected low-space outcome: \(error)") }
        XCTAssertThrowsError(try f.prepared.identity(token))
        XCTAssertNoThrow(try SafeFilesystem.verify(source))
        print("NATIVE_APPLICATION_COPY_LOW_SPACE_REFUSED_BEFORE_OUTPUT")
    }
    func testCancellationDuringPreparationRetainsOwnedPartialAndOriginal() async throws {
        let f = try Fixture(); defer { f.clean() }
        let resources = f.app.path + "/Contents/Resources", payload = Data(repeating:7,count:64*1024)
        for index in 0..<1000 { try payload.write(to:URL(fileURLWithPath:resources + String(format:"/part-%04d",index))) }
        let source = try f.snapshot(), parentPath = f.prepared.path, token = UUID().uuidString
        let task = Task.detached {
            try ApplicationTreeCopy.prepare(source,in:SafeDirectory(path:parentPath),name:token)
        }
        var observedCopy = false
        for _ in 0..<500 {
            if FileManager.default.fileExists(atPath:parentPath + "/" + token + "/Contents/MacOS/main") {
                observedCopy = true; task.cancel(); break
            }
            try await Task.sleep(nanoseconds:10_000_000)
        }
        if !observedCopy { task.cancel() }
        do { _ = try await task.value; XCTFail("Cancelled preparation cannot be returned as ready") }
        catch is CancellationError { }
        catch { XCTFail("Unexpected cancelled-copy error: \(error)") }
        XCTAssertTrue(observedCopy,"The test must observe actual copied content before cancellation")
        XCTAssertTrue(try f.prepared.identity(token).isDirectory,"Partial preparation must remain attributable")
        XCTAssertNoThrow(try SafeFilesystem.verify(source))
    }
    func testPreparedOfficialApplicationCopiesKeepStrictAllArchitectureSignatures() throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_REAL_APP_COPY_ACCEPTANCE"] == "AppSweep-General-20261016",
              NSHomeDirectory() == "/Users/localtest",
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).hasPrefix("VirtualMac") else { throw XCTSkip("Prepared disposable VM official-app copy acceptance only") }
        func codeHash(_ path: String,_ architecture: String) throws -> String {
            let result = try BoundedProcess.capture("/usr/bin/codesign",arguments:["-d","--verbose=4","--arch",architecture,path],timeout:10,mergeStderr:true)
            guard result.status == 0, let line = result.text.split(separator:"\n").first(where:{ $0.hasPrefix("CDHash=") }) else { throw SweepError.incomplete("Native code hash not confirmed") }
            return String(line)
        }
        for (name,identifier,team) in [("IINA","com.colliderli.iina","67CQ77V27R"),("Vienna","uk.co.opencommunity.vienna2","KUU2LM7U9K")] {
            let f = try Fixture(); defer { f.clean() }
            let path = NSHomeDirectory() + "/Applications/" + name + ".app", token = UUID().uuidString
            guard AppInspector.signatureMatches(path:path,identifier:identifier), AppInspector.signedByTeam(path:path,team:team) else { throw SweepError.denied("Registered official test app identity changed") }
            try ActivityInspector.ensureStopped(bundleID:identifier,applicationPath:path)
            let verify = try BoundedProcess.capture("/usr/bin/codesign",arguments:["--verify","--deep","--strict","--all-architectures",path],timeout:30,mergeStderr:true)
            XCTAssertEqual(verify.status,0,verify.text)
            guard verify.status == 0 else { return }
            let original = try SafeFilesystem.snapshot(path,allowInternalLinks:true,purpose:.application,allowInternalHardLinks:true)
            let arm = try codeHash(path,"arm64"), intel = try codeHash(path,"x86_64")
            try f.root.write(JSONSerialization.data(withJSONObject:["source":path,"sourceInode":original.identity.inode,"sourceDevice":original.identity.device,"target":f.prepared.path + "/" + token,"createdFromAbsent":true,"purpose":"complete independent official app copy; original read only"],options:[.sortedKeys]),name:"copy-intent.json")
            let copy = try ApplicationTreeCopy.prepare(original,in:f.prepared,name:token)
            let checked = try BoundedProcess.capture("/usr/bin/codesign",arguments:["--verify","--deep","--strict","--all-architectures",copy.path],timeout:30,mergeStderr:true)
            XCTAssertEqual(checked.status,0,checked.text)
            XCTAssertEqual(try codeHash(copy.path,"arm64"),arm)
            XCTAssertEqual(try codeHash(copy.path,"x86_64"),intel)
            XCTAssertEqual(try codeHash(path,"arm64"),arm)
            XCTAssertEqual(try codeHash(path,"x86_64"),intel)
            XCTAssertNotEqual(copy.identity.inode,original.identity.inode)
            XCTAssertEqual(copy.tree.count,original.tree.count)
            XCTAssertNoThrow(try SafeFilesystem.verify(original))
            let sourceAfter = try BoundedProcess.capture("/usr/bin/codesign",arguments:["--verify","--deep","--strict","--all-architectures",path],timeout:30,mergeStderr:true)
            XCTAssertEqual(sourceAfter.status,0,sourceAfter.text)
            print("REAL_APPLICATION_TREE_COPY=" + String(decoding:try JSONSerialization.data(withJSONObject:["application":name,"identifier":identifier,"team":team,"sourceInode":original.identity.inode,"copyInode":copy.identity.inode,"device":copy.identity.device,"entries":copy.tree.count,"arm64":arm,"x86_64":intel,"strictDeepAllArchitectures":checked.status == 0,"sourceUnchanged":true,"source":"official task-installed app; read only","scope":"copy only; no optimization, installed swap, launch or update acceptance"],options:[.sortedKeys]),as:UTF8.self))
        }
    }
    func testCancellationBeforeCopyCreatesNoPreparation() async throws {
        let f = try Fixture(); defer { f.clean() }
        let source = try f.snapshot(), parentPath = f.prepared.path, token = UUID().uuidString
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try ApplicationTreeCopy.prepare(source,in:SafeDirectory(path:parentPath),name:token)
        }
        do { _ = try await task.value; XCTFail("Cancelled copy cannot return a prepared app") }
        catch is CancellationError { }
        catch { XCTFail("Unexpected cancellation result: \(error)") }
        XCTAssertThrowsError(try f.prepared.identity(token))
        XCTAssertNoThrow(try SafeFilesystem.verify(source))
    }
}
#endif
