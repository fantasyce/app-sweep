#if os(macOS)
import Foundation
import Darwin
import XCTest
import CFSafety
@testable import AppSweepCore

// Catch byte-only copies, link following, stale inputs, overwrite and unbounded metadata.
final class NodeCopyTests: XCTestCase {
    private struct Fixture {
        let parent: SafeDirectory, root: SafeDirectory, source: SafeDirectory, output: SafeDirectory
        let identity: FileIdentity, name: String
        init() throws {
            guard getuid() != 0, let base = ProcessInfo.processInfo.environment["APP_SWEEP_FIXTURES"], base.hasPrefix(NSHomeDirectory() + "/AppSweepAcceptance") else { throw XCTSkip("Explicit isolated fixture root required") }
            parent = try SafeDirectory(path:base); name = UUID().uuidString
            guard mkdirat(parent.fd,name,0o700) == 0 else { throw SweepError.denied("New task fixture required") }
            root = try parent.existingPrivateChild(name); identity = try root.ownIdentity
            source = try root.privateChild("source"); output = try root.privateChild("output")
            print("NODE_COPY_FIXTURE=" + String(decoding:try JSONSerialization.data(withJSONObject:["path":root.path,"inode":identity.inode,"device":identity.device,"owner":identity.owner,"state":"created"],options:[.sortedKeys]),as:UTF8.self))
        }
        func clean() {
            do {
                let snapshot = try SafeFilesystem.snapshot(root.path,allowInternalLinks:true)
                guard snapshot.identity.inode == identity.inode, snapshot.identity.device == identity.device,
                      SafeFilesystem.removeVerified(in:parent,name:name,identity:snapshot.identity,contents:snapshot.tree) else { throw SweepError.stale("Fixture retained") }
                print("NODE_COPY_FIXTURE=" + String(decoding:try JSONSerialization.data(withJSONObject:["path":root.path,"inode":identity.inode,"state":"removed-after-identity-check"],options:[.sortedKeys]),as:UTF8.self))
            } catch { XCTFail("Node-copy fixture retained: " + root.path) }
        }
    }
    private func digest(_ directory: SafeDirectory,_ name: String, bytes: UInt64 = 1024*1024) throws -> Data {
        var identity = try directory.identity(name).native, result = [UInt8](repeating:0,count:32)
        let status = as_owned_node_digest(directory.fd,name,&identity,bytes,5000,&result)
        guard status == 0 else { throw SweepError.denied("Node digest errno=\(errno)") }
        return Data(result)
    }
    // Application root verification must retain ACLs, mode and every ordinary
    // attribute even when rename changes ctime and OS-managed access metadata.
    func testApplicationRootDigestRetainsOrdinaryMetadataAndRefusesStaleOrNonDirectoryInput() throws {
        let f = try Fixture(); defer { f.clean() }
        let node = try f.source.privateChild("application")
        func rootDigest(expected: FileIdentity? = nil, name: String = "application") throws -> Data {
            var identity = try (expected ?? f.source.identity(name)).native
            var bytes = [UInt8](repeating:0,count:32)
            guard as_owned_application_root_digest(f.source.fd,name,&identity,5000,&bytes) == 0 else {
                throw SweepError.denied("Root metadata was not verified")
            }
            return Data(bytes)
        }
        let initial = try rootDigest(), old = try f.source.identity("application")
        XCTAssertEqual(chmod(node.path,0o700),0)
        XCTAssertEqual(try rootDigest(),initial,"ctime alone is not stable across rename")
        _ = try BoundedProcess.run("/usr/bin/xattr",arguments:["-w","org.appsweep.root-test","preserve",node.path],timeout:3)
        let attributed = try rootDigest()
        XCTAssertNotEqual(attributed,initial,"Do not exclude arbitrary extended attributes")
        XCTAssertThrowsError(try rootDigest(expected:old))
        _ = try BoundedProcess.run("/bin/chmod",arguments:["+a","everyone deny write",node.path],timeout:3)
        XCTAssertNotEqual(try rootDigest(),attributed,"ACLs are part of the commitment")
        XCTAssertEqual(chmod(node.path,0o750),0)
        XCTAssertNotEqual(try rootDigest(),attributed)
        XCTAssertEqual(chmod(node.path,0o700),0)
        try f.source.write(Data("regular file".utf8),name:"regular")
        XCTAssertThrowsError(try rootDigest(name:"regular"))
        XCTAssertEqual(symlinkat("application",f.source.fd,"alias"),0)
        XCTAssertThrowsError(try rootDigest(name:"alias"))
        XCTAssertEqual(try BoundedProcess.run("/usr/bin/xattr",arguments:["-p","org.appsweep.root-test",node.path],timeout:3),"preserve\n")
    }
    // The application-root copy has its own narrowly scoped comparison. It
    // still copies all metadata through the OS; ordinary attributes/ACL remain.
    func testApplicationRootCopyPreservesMetadataAndRejectsNonDirectoryOrUsedDestination() throws {
        let f = try Fixture(); defer { f.clean() }
        let source = try f.source.privateChild("application"), target = try f.output.privateChild("copy")
        _ = try BoundedProcess.run("/usr/bin/xattr",arguments:["-w","org.appsweep.root-copy","must survive",source.path],timeout:3)
        _ = try BoundedProcess.run("/bin/chmod",arguments:["+a","everyone deny write",source.path],timeout:3)
        XCTAssertEqual(chmod(source.path,0o755),0)
        let original = try f.source.identity("application"), commitment = try digest(f.source,"application")
        var expected = original.native, created = ASIdentity()
        XCTAssertEqual(as_copy_owned_application_root(f.source.fd,"application",&expected,f.output.fd,"copy",5000,&created),0,"errno=\(errno)")
        XCTAssertEqual(try digest(f.output,"copy"),commitment)
        XCTAssertEqual(try f.source.identity("application"),original)
        XCTAssertEqual(try digest(f.source,"application"),commitment)
        XCTAssertEqual(try target.ownIdentity,FileIdentity(created))
        let targetBefore = try f.output.identity("copy")
        XCTAssertEqual(as_copy_owned_application_root(f.source.fd,"application",&expected,f.output.fd,"copy",5000,&created),-1,"Already published permissions must not be reused as private preparation")
        try f.source.write(Data("keep file".utf8),name:"regular")
        XCTAssertEqual(symlinkat("application",f.source.fd,"alias"),0)
        for name in ["regular","alias"] {
            var invalid = try f.source.identity(name).native
            XCTAssertEqual(as_copy_owned_application_root(f.source.fd,name,&invalid,f.output.fd,"copy",5000,&created),-1)
        }
        XCTAssertEqual(try f.output.identity("copy"),targetBefore)
    }
    func testApplicationRootCopyBoundsReadOnlyStabilizationAndRejectsChangedMetadata() throws {
        guard let source = ProcessInfo.processInfo.environment["APP_SWEEP_SOURCE_ROOT"],
              source.hasPrefix(NSHomeDirectory() + "/AppSweep"), let sdk = ProcessInfo.processInfo.environment["APP_SWEEP_SDK"] else { throw XCTSkip("Isolated source and SDK required") }
        for fault in ["plain","once","continuous","attribute","mode","generic","source-after"] {
            let f = try Fixture(); defer { f.clean() }
            let input = try f.source.privateChild("application")
            _ = try f.output.privateChild("copy")
            XCTAssertEqual(chmod(input.path,0o755),0)
            let executable = f.root.path + "/root-copy-probe"
            let compiled = try BoundedProcess.capture(ProcessInfo.processInfo.environment["APP_SWEEP_CLANG"] ?? "/usr/bin/clang",arguments:["-isysroot",sdk,"-mmacosx-version-min=12.0","-I",source + "/Sources/CFSafety/include",source + "/Tests/AppSweepCoreTests/Fixtures/NodeCopyRootStabilityProbe.c",source + "/Sources/CFSafety/node_copy.c",source + "/Sources/CFSafety/root_configuration.c","-o",executable],timeout:20,mergeStderr:true)
            XCTAssertEqual(compiled.status,0,compiled.text); guard compiled.status == 0 else { return }
            let result = try BoundedProcess.capture(executable,arguments:[f.root.path,fault],timeout:10,mergeStderr:true)
            XCTAssertEqual(result.status,0,fault + ": " + result.text)
            XCTAssertTrue(result.text.contains("COPIES=1"),result.text)
        }
    }
    private func copy(_ f: Fixture,_ name: String = "input", to: String = "copy", expected: FileIdentity? = nil, bytes: UInt64 = 1024*1024, timeout: Int32 = 5000) throws -> Int32 {
        var expected = try (expected ?? f.source.identity(name)).native, created = ASIdentity()
        return as_copy_owned_node(f.source.fd,name,&expected,f.output.fd,to,bytes,timeout,&created)
    }
    private func copyRange(_ f: Fixture, offset: UInt64, length: UInt64, name: String = "input", to: String = "slice", expected: FileIdentity? = nil) throws -> Int32 {
        var identity = try (expected ?? f.source.identity(name)).native, created = ASIdentity()
        return as_copy_owned_regular_range(f.source.fd,name,&identity,f.output.fd,to,offset,length,32*1024*1024,10000,&created)
    }
    func testRangeCopyPreservesOriginalAndCompleteSelectedBytesAndMetadata() throws {
        let f = try Fixture(); defer { f.clean() }
        let bytes = Data((0..<200_123).map { UInt8($0 % 251) })
        try f.source.write(bytes,name:"input")
        let path = f.source.path + "/input"
        XCTAssertEqual(chmod(path,0o755),0)
        _ = try BoundedProcess.run("/usr/bin/xattr",arguments:["-w","org.appsweep.copy-test","range-value",path],timeout:3)
        _ = try BoundedProcess.run("/usr/bin/xattr",arguments:["-wx","com.apple.ResourceFork","010203040506",path],timeout:3)
        _ = try BoundedProcess.run("/bin/chmod",arguments:["+a","everyone deny write",path],timeout:3)
        let before = try f.source.identity("input"), originalDigest = try digest(f.source,"input")
        XCTAssertEqual(try copyRange(f,offset:17,length:150_019),0,"errno=\(errno)")
        XCTAssertEqual(try SafeFilesystem.readMetadata(f.output.path + "/slice"),bytes.subdata(in:17..<150_036))
        let after = try f.output.identity("slice")
        XCTAssertNotEqual(after.inode,before.inode); XCTAssertEqual(after.owner,before.owner)
        XCTAssertEqual(after.mode,before.mode); XCTAssertEqual(after.modifiedSeconds,before.modifiedSeconds)
        XCTAssertEqual(after.modifiedNanoseconds,before.modifiedNanoseconds)
        var original = stat(), copied = stat()
        XCTAssertEqual(lstat(path,&original),0); XCTAssertEqual(lstat(f.output.path + "/slice",&copied),0)
        XCTAssertEqual(copied.st_gid,original.st_gid); XCTAssertEqual(copied.st_flags,original.st_flags)
        XCTAssertTrue(try BoundedProcess.run("/bin/ls",arguments:["-le",f.output.path + "/slice"],timeout:3).contains("everyone deny write"))
        for key in ["org.appsweep.copy-test","com.apple.ResourceFork"] {
            XCTAssertEqual(try BoundedProcess.run("/usr/bin/xattr",arguments:["-px",key,path],timeout:3),try BoundedProcess.run("/usr/bin/xattr",arguments:["-px",key,f.output.path + "/slice"],timeout:3))
        }
        XCTAssertEqual(try f.source.identity("input"),before)
        XCTAssertEqual(try digest(f.source,"input"),originalDigest)
    }
    func testRangeBoundsAliasesAndExistingOutputNeverChangeOriginalOrNeighbour() throws {
        let f = try Fixture(); defer { f.clean() }
        try f.source.write(Data("source bytes".utf8),name:"input")
        let original = try digest(f.source,"input")
        for (offset,length) in [(UInt64(0),UInt64(0)),(12,1),(11,2),(UInt64.max,1),(1,UInt64.max)] {
            XCTAssertEqual(try copyRange(f,offset:offset,length:length),-1)
            XCTAssertThrowsError(try f.output.identity("slice"))
        }
        for name in ["../escape","nested/name","/absolute",""] {
            XCTAssertEqual(try copyRange(f,offset:0,length:1,to:name),-1)
        }
        try f.output.write(Data("keep neighbour".utf8),name:"slice")
        XCTAssertEqual(try copyRange(f,offset:1,length:5),-1)
        XCTAssertEqual(try SafeFilesystem.readMetadata(f.output.path + "/slice"),Data("keep neighbour".utf8))
        XCTAssertEqual(try digest(f.source,"input"),original)
    }
    func testRangeCopyRefusesStaleSharedLinkedUnreadableAndElevatedSources() throws {
        let f = try Fixture(); defer { f.clean() }
        try f.source.write(Data("keep original".utf8),name:"input")
        let path = f.source.path + "/input", before = try f.source.identity("input")
        XCTAssertEqual(chmod(path,0o755),0)
        XCTAssertEqual(try copyRange(f,offset:0,length:4,expected:before),-1)
        XCTAssertEqual(fchmod(f.output.fd,0o755),0)
        XCTAssertEqual(try copyRange(f,offset:0,length:4),-1)
        XCTAssertEqual(fchmod(f.output.fd,0o700),0)
        XCTAssertEqual(linkat(f.source.fd,"input",f.source.fd,"alias",0),0)
        XCTAssertEqual(try copyRange(f,offset:0,length:4),-1)
        XCTAssertEqual(unlinkat(f.source.fd,"alias",0),0)
        XCTAssertEqual(symlinkat("input",f.source.fd,"link"),0)
        XCTAssertEqual(try copyRange(f,offset:0,length:4,name:"link"),-1)
        for mode in [mode_t(0),mode_t(0o4700)] {
            XCTAssertEqual(chmod(path,mode),0)
            XCTAssertEqual(try copyRange(f,offset:0,length:4),-1)
        }
        XCTAssertEqual(chmod(path,0o600),0)
        XCTAssertThrowsError(try f.output.identity("slice"))
        XCTAssertEqual(try SafeFilesystem.readMetadata(path),Data("keep original".utf8))
    }
    func testOriginalSignedMachOSliceCopiesWithoutResigningOrChangingUniversalInput() throws {
        let f = try Fixture(); defer { f.clean() }
        guard let sdk = ProcessInfo.processInfo.environment["APP_SWEEP_SDK"],
              let clang = ProcessInfo.processInfo.environment["APP_SWEEP_CLANG"] else { throw XCTSkip("Existing isolated SDK and clang required") }
        try f.source.write(Data("int main(void) { return 0; }\n".utf8),name:"fixture.c")
        for arch in ["arm64","x86_64"] {
            let compiled = try BoundedProcess.capture(clang,arguments:["-arch",arch,"-isysroot",sdk,"-mmacosx-version-min=12.0",f.source.path + "/fixture.c","-o",f.source.path + "/" + arch],timeout:30,mergeStderr:true)
            XCTAssertEqual(compiled.status,0,compiled.text)
        }
        _ = try BoundedProcess.run("/usr/bin/lipo",arguments:["-create",f.source.path + "/arm64",f.source.path + "/x86_64","-output",f.source.path + "/input"],timeout:10)
        _ = try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--options","runtime","--sign","-",f.source.path + "/input"],timeout:10)
        #if arch(arm64)
        let arch = "arm64", cpu: UInt32 = 0x0100000c
        #else
        let arch = "x86_64", cpu: UInt32 = 0x01000007
        #endif
        func codeHash(_ path: String) throws -> String {
            let result = try BoundedProcess.capture("/usr/bin/codesign",arguments:["-d","--verbose=4","--arch",arch,path],timeout:10,mergeStderr:true)
            XCTAssertEqual(result.status,0,result.text)
            let hashes = result.text.split(separator:"\n").filter { $0.hasPrefix("CDHash=") }
            XCTAssertEqual(hashes.count,1)
            return String(try XCTUnwrap(hashes.first).dropFirst(7))
        }
        let input = f.source.path + "/input", output = f.output.path + "/slice"
        let bytes = try SafeFilesystem.readMetadata(input), before = try f.source.identity("input")
        let originalDigest = try digest(f.source,"input"), originalHash = try codeHash(input)
        let index = try MachOContainerIndex.parse(header:Data(bytes.prefix(4096)),fileSize:UInt64(bytes.count))
        XCTAssertEqual(Set(index.slices.map(\.cpuType)),[0x0100000c,0x01000007])
        let slice = try XCTUnwrap(index.slices.first { $0.cpuType == cpu })
        XCTAssertEqual(try copyRange(f,offset:slice.offset,length:slice.size),0,"errno=\(errno)")
        let validation = try BoundedProcess.capture("/usr/bin/codesign",arguments:["--verify","--strict","--all-architectures",output],timeout:10,mergeStderr:true)
        XCTAssertEqual(validation.status,0,validation.text)
        XCTAssertEqual(try codeHash(output),originalHash,"The original retained architecture signature must remain unchanged; only the disposable original fixture is ever signed")
        let thinBytes = try SafeFilesystem.readMetadata(output)
        let thin = try MachOContainerIndex.parse(header:Data(thinBytes.prefix(4096)),fileSize:UInt64(thinBytes.count))
        XCTAssertEqual(thin.kind,.thin64); XCTAssertEqual(thin.slices.count,1)
        XCTAssertEqual(thin.slices.first?.cpuType,cpu); XCTAssertEqual(thin.slices.first?.cpuSubtype,slice.cpuSubtype)
        XCTAssertEqual(try f.source.identity("input"),before); XCTAssertEqual(try digest(f.source,"input"),originalDigest)
        let run = try BoundedProcess.capture(output,arguments:[],timeout:5,mergeStderr:true)
        XCTAssertEqual(run.status,0,run.text)
    }
    func testPreservesExecutableBytesXattrResourceForkOwnerGroupModeAndMtime() throws {
        let f = try Fixture(); defer { f.clean() }
        try f.source.write(Data([0,1,255,42]),name:"input")
        let path = f.source.path + "/input"
        XCTAssertEqual(chmod(path,0o755),0)
        _ = try BoundedProcess.run("/usr/bin/xattr",arguments:["-w","org.appsweep.copy-test","test-value",path],timeout:3)
        _ = try BoundedProcess.run("/usr/bin/xattr",arguments:["-wx","com.apple.ResourceFork","010203040506",path],timeout:3)
        let before = try f.source.identity("input")
        XCTAssertEqual(try copy(f),0,"errno=\(errno)")
        XCTAssertEqual(try SafeFilesystem.readMetadata(f.output.path + "/copy"),Data([0,1,255,42]))
        let result = try f.output.identity("copy")
        XCTAssertEqual(result.mode & 0o777,0o755); XCTAssertEqual(result.owner,getuid())
        XCTAssertNotEqual(result.inode,before.inode)
        XCTAssertEqual(result.modifiedSeconds,before.modifiedSeconds); XCTAssertEqual(result.modifiedNanoseconds,before.modifiedNanoseconds)
        XCTAssertEqual(try BoundedProcess.run("/usr/bin/xattr",arguments:["-px","com.apple.ResourceFork",f.output.path + "/copy"],timeout:3).filter { !$0.isWhitespace },"010203040506")
        XCTAssertEqual(try BoundedProcess.run("/usr/bin/xattr",arguments:["-p","org.appsweep.copy-test",f.output.path + "/copy"],timeout:3).trimmingCharacters(in:.whitespacesAndNewlines),"test-value")
        XCTAssertEqual(try f.source.identity("input"),before)
        XCTAssertEqual(try digest(f.source,"input"),try digest(f.output,"copy"))
    }
    func testDigestDetectsPayloadModeAndAttributeChanges() throws {
        let f = try Fixture(); defer { f.clean() }
        try f.source.write(Data("aaaa".utf8),name:"input")
        let original = try digest(f.source,"input")
        XCTAssertEqual(chmod(f.source.path + "/input",0o755),0)
        let mode = try digest(f.source,"input"); XCTAssertNotEqual(original,mode)
        _ = try BoundedProcess.run("/usr/bin/xattr",arguments:["-w","org.appsweep.copy-test","changed",f.source.path + "/input"],timeout:3)
        let attribute = try digest(f.source,"input"); XCTAssertNotEqual(mode,attribute)
        let fd = openat(f.source.fd,"input",O_WRONLY|O_NOFOLLOW)
        XCTAssertGreaterThanOrEqual(fd,0); defer { if fd >= 0 { close(fd) } }
        XCTAssertEqual(pwrite(fd,"bbbb",4,0),4)
        XCTAssertNotEqual(attribute,try digest(f.source,"input"))
    }
    func testCopiesLinkTextWithoutReadingOrChangingExternalNeighbour() throws {
        let f = try Fixture(); defer { f.clean() }
        try f.root.write(Data("outside neighbour".utf8),name:"neighbour")
        let neighbour = try f.root.identity("neighbour")
        XCTAssertEqual(symlinkat("../neighbour",f.source.fd,"input"),0)
        XCTAssertEqual(try copy(f),0,"errno=\(errno)")
        XCTAssertTrue(try f.output.identity("copy").isLink)
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath:f.output.path + "/copy"),"../neighbour")
        XCTAssertEqual(try f.root.identity("neighbour"),neighbour)
        XCTAssertEqual(try SafeFilesystem.readMetadata(f.root.path + "/neighbour"),Data("outside neighbour".utf8))
        XCTAssertEqual(try digest(f.source,"input"),try digest(f.output,"copy"))
    }
    func testDirectoryMetadataAppliedAfterChildrenWithoutCopyingEntries() throws {
        let f = try Fixture(); defer { f.clean() }
        let source = try f.source.privateChild("input"), target = try f.output.privateChild("copy")
        try source.write(Data("not traversed".utf8),name:"source-only")
        try target.write(Data("already copied".utf8),name:"prepared-child")
        XCTAssertEqual(chmod(source.path,0o755),0)
        _ = try BoundedProcess.run("/usr/bin/xattr",arguments:["-w","org.appsweep.copy-test","directory",source.path],timeout:3)
        XCTAssertEqual(try copy(f),0,"errno=\(errno)")
        XCTAssertEqual(try f.output.identity("copy").mode & 0o777,0o755)
        XCTAssertEqual(try digest(f.source,"input"),try digest(f.output,"copy"))
        XCTAssertEqual(try SafeFilesystem.readMetadata(target.path + "/prepared-child"),Data("already copied".utf8))
        XCTAssertThrowsError(try target.identity("source-only"))
        XCTAssertEqual(chmod(target.path,0o700),0); XCTAssertEqual(chmod(source.path,0o700),0)
    }
    func testStaleIdentityAndExistingOutputDoNotOverwriteAnything() throws {
        let f = try Fixture(); defer { f.clean() }
        try f.source.write(Data("original".utf8),name:"input")
        let old = try f.source.identity("input")
        XCTAssertEqual(chmod(f.source.path + "/input",0o755),0)
        XCTAssertEqual(try copy(f,expected:old),-1)
        XCTAssertThrowsError(try f.output.identity("copy"))
        try f.output.write(Data("keep".utf8),name:"copy")
        XCTAssertEqual(try copy(f),-1)
        XCTAssertEqual(try SafeFilesystem.readMetadata(f.output.path + "/copy"),Data("keep".utf8))
    }
    func testSharedParentAndInvalidLimitsRefusedBeforeOutput() throws {
        let f = try Fixture(); defer { f.clean() }
        try f.source.write(Data(repeating:7,count:32),name:"input")
        XCTAssertEqual(fchmod(f.output.fd,0o755),0)
        XCTAssertEqual(try copy(f),-1)
        XCTAssertEqual(fchmod(f.output.fd,0o700),0)
        XCTAssertEqual(try copy(f,bytes:16),-1)
        XCTAssertEqual(try copy(f,timeout:0),-1)
        XCTAssertThrowsError(try f.output.identity("copy"))
        var identity = try f.source.identity("input").native, out = ASIdentity()
        for name in ["../escape","/absolute","nested/name",".",""] {
            XCTAssertEqual(as_copy_owned_node(f.source.fd,"input",&identity,f.output.fd,name,1000,5000,&out),-1)
        }
    }
    func testUnreadableSourceAndElevatedModeAreRefusedWithoutCreatingCopy() throws {
        let f = try Fixture(); defer { f.clean() }
        try f.source.write(Data("keep original".utf8),name:"input")
        let path = f.source.path + "/input"
        defer { _ = chmod(path,0o600) }
        XCTAssertEqual(chmod(path,0),0)
        XCTAssertEqual(try copy(f),-1)
        XCTAssertThrowsError(try f.output.identity("copy"))
        XCTAssertEqual(chmod(path,0o4700),0)
        XCTAssertEqual(try copy(f),-1)
        XCTAssertThrowsError(try f.output.identity("copy"))
        XCTAssertEqual(chmod(path,0o600),0)
        XCTAssertEqual(try SafeFilesystem.readMetadata(path),Data("keep original".utf8))
    }
    func testInvalidSourceNameAndUnknownIdentityCannotReadThroughAlias() throws {
        let f = try Fixture(); defer { f.clean() }
        try f.root.write(Data("outside marker".utf8),name:"neighbour")
        try f.source.write(Data("source".utf8),name:"input")
        var expected = try f.source.identity("input").native, out = ASIdentity()
        var result = [UInt8](repeating:0,count:32)
        for name in ["../neighbour","/neighbour","nested/name",""] {
            XCTAssertEqual(as_copy_owned_node(f.source.fd,name,&expected,f.output.fd,"copy",1000,5000,&out),-1)
            XCTAssertEqual(as_owned_node_digest(f.source.fd,name,&expected,1000,5000,&result),-1)
        }
        XCTAssertEqual(as_copy_owned_node(f.source.fd,"input",nil,f.output.fd,"copy",1000,5000,&out),-1)
        XCTAssertEqual(as_owned_node_digest(f.source.fd,"input",nil,1000,5000,&result),-1)
        XCTAssertThrowsError(try f.output.identity("copy"))
        XCTAssertEqual(try SafeFilesystem.readMetadata(f.root.path + "/neighbour"),Data("outside marker".utf8))
    }
    func testSpecialFilesAndLinkDestinationAreRejected() throws {
        let f = try Fixture(); defer { f.clean() }
        XCTAssertEqual(mkfifoat(f.source.fd,"pipe",0o600),0)
        XCTAssertEqual(try copy(f,"pipe"),-1)
        XCTAssertEqual(unlinkat(f.source.fd,"pipe",0),0)
        try f.source.write(Data("original".utf8),name:"input")
        try f.root.write(Data("neighbour".utf8),name:"neighbour")
        XCTAssertEqual(symlinkat("../neighbour",f.output.fd,"copy"),0)
        XCTAssertEqual(try copy(f),-1)
        XCTAssertEqual(try SafeFilesystem.readMetadata(f.root.path + "/neighbour"),Data("neighbour".utf8))
    }
    func testOversizedResourceForkIsRejectedBeforeCreatingOutput() throws {
        let f = try Fixture(); defer { f.clean() }
        try f.source.write(Data("payload".utf8),name:"input")
        let fork = f.source.path + "/input/..namedfork/rsrc"
        try Data(repeating:7,count:17*1024*1024).write(to:URL(fileURLWithPath:fork))
        XCTAssertEqual(try copy(f),-1)
        XCTAssertEqual(errno,E2BIG)
        XCTAssertEqual(try copyRange(f,offset:0,length:1),-1)
        XCTAssertEqual(errno,E2BIG)
        XCTAssertThrowsError(try f.output.identity("slice"))
        XCTAssertThrowsError(try f.output.identity("copy"))
        XCTAssertEqual(try SafeFilesystem.readMetadata(f.source.path + "/input"),Data("payload".utf8))
    }
    func testNativeCopyFailureRetainsPartialOutputAndOriginal() throws {
        let f = try Fixture(); defer { f.clean() }
        try f.source.write(Data("original retained".utf8),name:"input")
        guard let source = ProcessInfo.processInfo.environment["APP_SWEEP_SOURCE_ROOT"],
              source.hasPrefix(NSHomeDirectory() + "/AppSweep"), let sdk = ProcessInfo.processInfo.environment["APP_SWEEP_SDK"] else { throw XCTSkip("Isolated source and SDK required") }
        let clang = ProcessInfo.processInfo.environment["APP_SWEEP_CLANG"] ?? "/usr/bin/clang"
        let executable = f.root.path + "/fault-probe"
        let sources = [source + "/Tests/AppSweepCoreTests/Fixtures/NodeCopyFaultProbe.c", source + "/Sources/CFSafety/node_copy.c", source + "/Sources/CFSafety/filesystem.c",source + "/Sources/CFSafety/root_configuration.c"]
        let compiled = try BoundedProcess.capture(clang,arguments:["-isysroot",sdk,"-mmacosx-version-min=12.0","-I",source + "/Sources/CFSafety/include"] + sources + ["-o",executable],timeout:20,mergeStderr:true)
        XCTAssertEqual(compiled.status,0,compiled.text); guard compiled.status == 0 else { return }
        let result = try BoundedProcess.capture(executable,arguments:[f.root.path],timeout:5,mergeStderr:true)
        XCTAssertEqual(result.status,0,result.text)
        XCTAssertTrue(result.text.contains("PARTIAL_COPY_RETAINED_WITHOUT_OVERWRITE_OR_BLIND_RETRY"))
        XCTAssertTrue(result.text.contains("PARTIAL_RANGE_RETAINED_AND_EXISTING_OUTPUT_REFUSES_RETRY"))
        XCTAssertEqual(try SafeFilesystem.readMetadata(f.source.path + "/input"),Data("original retained".utf8))
        XCTAssertEqual(try SafeFilesystem.readMetadata(f.output.path + "/partial"),Data("partial".utf8))
        XCTAssertEqual(try SafeFilesystem.readMetadata(f.output.path + "/range-partial"),Data("partial".utf8))
    }
    func testACLIsPreservedAndParticipatesInFingerprint() throws {
        let f = try Fixture(); defer { f.clean() }
        try f.source.write(Data("acl".utf8),name:"input")
        let plain = try digest(f.source,"input")
        _ = try BoundedProcess.run("/bin/chmod",arguments:["+a","everyone deny write",f.source.path + "/input"],timeout:3)
        XCTAssertNotEqual(plain,try digest(f.source,"input"))
        XCTAssertEqual(try copy(f),0,"errno=\(errno)")
        let acl = try BoundedProcess.run("/bin/ls",arguments:["-le",f.output.path + "/copy"],timeout:3)
        XCTAssertTrue(acl.contains("everyone deny write"),acl)
        XCTAssertEqual(try digest(f.source,"input"),try digest(f.output,"copy"))
    }
}
#endif
