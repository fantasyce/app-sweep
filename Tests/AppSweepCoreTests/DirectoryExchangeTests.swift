#if os(macOS)
import Foundation
import Darwin
import XCTest
import CFSafety
@testable import AppSweepCore

final class DirectoryExchangeTests: XCTestCase {
    private struct Fixture {
        let parent: SafeDirectory
        let root: SafeDirectory
        let installed: SafeDirectory
        let prepared: SafeDirectory
        let identity: FileIdentity
        let name: String
        init() throws {
            guard getuid() != 0, let base = ProcessInfo.processInfo.environment["APP_SWEEP_FIXTURES"],
                  base.hasPrefix(NSHomeDirectory() + "/AppSweepAcceptance") else { throw XCTSkip("Explicit isolated task fixture root required") }
            parent = try SafeDirectory(path:base)
            name = UUID().uuidString
            guard mkdirat(parent.fd,name,0o700) == 0 else { throw SweepError.denied("Directory exchange fixture is not new") }
            root = try parent.existingPrivateChild(name); identity = try root.ownIdentity
            print("DIRECTORY_EXCHANGE_FIXTURE=" + String(decoding:try JSONSerialization.data(withJSONObject:["path":root.path,"inode":identity.inode,"device":identity.device,"owner":identity.owner,"createdFromAbsent":true,"state":"created"],options:[.sortedKeys]),as:UTF8.self))
            installed = try root.privateChild("installed"); prepared = try root.privateChild("prepared")
            let a = try installed.privateChild("Application.app"), b = try prepared.privateChild("replacement")
            try a.write(Data("original".utf8),name:"payload")
            try b.write(Data("optimized".utf8),name:"payload")
            try installed.write(Data("unselected".utf8),name:"neighbour")
        }
        func clean() {
            var state = "retained"
            do {
                let snapshot = try SafeFilesystem.snapshot(root.path,allowInternalLinks:true)
                guard snapshot.identity.inode == identity.inode, snapshot.identity.device == identity.device,
                      snapshot.identity.owner == getuid(), SafeFilesystem.removeVerified(in:parent,name:name,identity:snapshot.identity,contents:snapshot.tree) else {
                    throw SweepError.stale("Exact directory-exchange fixture retained")
                }
                state = "removed-after-identity-check"
            } catch { XCTFail("Task fixture retained after teardown conflict: " + root.path) }
            print("DIRECTORY_EXCHANGE_FIXTURE=" + String(decoding:(try? JSONSerialization.data(withJSONObject:["path":root.path,"inode":identity.inode,"device":identity.device,"state":state],options:[.sortedKeys])) ?? Data(),as:UTF8.self))
        }
        func assertOriginal(file: StaticString = #filePath, line: UInt = #line) throws {
            XCTAssertEqual(try SafeFilesystem.readMetadata(installed.path + "/Application.app/payload"),Data("original".utf8),file:file,line:line)
            XCTAssertEqual(try SafeFilesystem.readMetadata(prepared.path + "/replacement/payload"),Data("optimized".utf8),file:file,line:line)
            XCTAssertEqual(try SafeFilesystem.readMetadata(installed.path + "/neighbour"),Data("unselected".utf8),file:file,line:line)
        }
    }
    private func exchange(_ f: Fixture, firstName: String = "Application.app", secondName: String = "replacement",
                          firstObject: FileIdentity? = nil, firstParent: FileIdentity? = nil,
                          secondObject: FileIdentity? = nil, secondParent: FileIdentity? = nil) throws -> Int32 {
        var a = try (firstObject ?? f.installed.identity("Application.app")).native
        var ap = try (firstParent ?? f.installed.ownIdentity).native
        var b = try (secondObject ?? f.prepared.identity("replacement")).native
        var bp = try (secondParent ?? f.prepared.ownIdentity).native
        return as_exchange_owned_directories(f.installed.fd,firstName,&a,&ap,f.prepared.fd,secondName,&b,&bp)
    }
    func testSwapsCompleteDirectoriesAndExplicitlyRestoresWithFreshIdentities() throws {
        let f = try Fixture(); defer { f.clean() }
        let source = f.installed.path + "/Application.app/payload"
        XCTAssertEqual(chmod(source,0o640),0)
        _ = try BoundedProcess.run("/usr/bin/xattr",arguments:["-w","org.appsweep.exchange-acceptance","preserved-on-original-inode",source],timeout:3)
        let original = try SafeFilesystem.snapshot(f.installed.path + "/Application.app")
        let replacement = try SafeFilesystem.snapshot(f.prepared.path + "/replacement")
        XCTAssertEqual(try exchange(f),0)
        XCTAssertEqual(try SafeFilesystem.readMetadata(f.installed.path + "/Application.app/payload"),Data("optimized".utf8))
        XCTAssertEqual(try SafeFilesystem.readMetadata(f.prepared.path + "/replacement/payload"),Data("original".utf8))
        XCTAssertTrue(try f.installed.identity("Application.app").sameObject(as:replacement.identity))
        XCTAssertTrue(try f.prepared.identity("replacement").sameObject(as:original.identity))
        XCTAssertEqual(try SafeFilesystem.snapshot(f.installed.path + "/Application.app").tree,replacement.tree)
        XCTAssertEqual(try SafeFilesystem.snapshot(f.prepared.path + "/replacement").tree,original.tree)
        XCTAssertEqual(try BoundedProcess.run("/usr/bin/xattr",arguments:["-p","org.appsweep.exchange-acceptance",f.prepared.path + "/replacement/payload"],timeout:3).trimmingCharacters(in:.whitespacesAndNewlines),"preserved-on-original-inode")
        XCTAssertEqual(try exchange(f),0)
        try f.assertOriginal()
    }
    func testFailedSyncReportsAnAlreadySwappedStateWithoutBlindRetry() throws {
        try exerciseFault()
    }
    func testRenameIOFailureIsIndeterminateEvenWhenSyscallReportedFailure() throws {
        try exerciseFault(mode:"rename-eio")
    }
    func testRenameIOFailureWithoutSwapStillRequiresReconciliation() throws {
        try exerciseFault(mode:"rename-eio-before")
    }
    private func exerciseFault(mode: String? = nil) throws {
        let f = try Fixture(); defer { f.clean() }
        guard let source = ProcessInfo.processInfo.environment["APP_SWEEP_SOURCE_ROOT"],
              source.hasPrefix(NSHomeDirectory() + "/AppSweep"),
              let sdk = ProcessInfo.processInfo.environment["APP_SWEEP_SDK"] else { throw XCTSkip("Isolated source and SDK required for test-only sync failure probe") }
        let clang = ProcessInfo.processInfo.environment["APP_SWEEP_CLANG"] ?? "/usr/bin/clang"
        let executable = f.root.path + "/fault-probe"
        let sources = [source + "/Tests/AppSweepCoreTests/Fixtures/DirectoryExchangeFaultProbe.c",
                       source + "/Sources/CFSafety/directory_exchange.c",source + "/Sources/CFSafety/filesystem.c",
                       source + "/Sources/CFSafety/root_configuration.c"]
        let compiled = try BoundedProcess.capture(clang,arguments:["-isysroot",sdk,"-mmacosx-version-min=12.0","-I",source + "/Sources/CFSafety/include"] + sources + ["-o",executable],timeout:20,mergeStderr:true)
        XCTAssertEqual(compiled.status,0,compiled.text)
        guard compiled.status == 0 else { return }
        let result = try BoundedProcess.capture(executable,arguments:[f.root.path] + (mode.map { [$0] } ?? []),timeout:5,mergeStderr:true)
        XCTAssertEqual(result.status,0,result.text)
        XCTAssertTrue(result.text.contains("INDETERMINATE_EXCHANGE_RECONCILED_WITHOUT_BLIND_RETRY"))
        try f.assertOriginal()
    }
    func testStaleObjectsAndStaleParentsCannotBecomeASwap() throws {
        let f = try Fixture(); defer { f.clean() }
        let oldA = try f.installed.identity("Application.app"), oldB = try f.prepared.identity("replacement")
        let oldAP = try f.installed.ownIdentity, oldBP = try f.prepared.ownIdentity
        try SafeDirectory(path:f.installed.path + "/Application.app").write(Data("added".utf8),name:"later")
        XCTAssertEqual(try exchange(f,firstObject:oldA),-1)
        try SafeDirectory(path:f.prepared.path + "/replacement").write(Data("added".utf8),name:"later")
        XCTAssertEqual(try exchange(f,secondObject:oldB),-1)
        try f.installed.write(Data("change parent".utf8),name:"later")
        XCTAssertEqual(try exchange(f,firstParent:oldAP),-1)
        try f.prepared.write(Data("change parent".utf8),name:"later")
        XCTAssertEqual(try exchange(f,secondParent:oldBP),-1)
        try f.assertOriginal()
    }
    func testSymlinksAndRegularFilesAreRefusedWithoutFollowingTargets() throws {
        let f = try Fixture(); defer { f.clean() }
        try FileManager.default.createSymbolicLink(atPath:f.installed.path + "/alias",withDestinationPath:f.prepared.path + "/replacement")
        let link = try f.installed.identity("alias")
        XCTAssertEqual(try exchange(f,firstName:"alias",firstObject:link),-1)
        try f.installed.write(Data("not a bundle directory".utf8),name:"regular")
        XCTAssertEqual(try exchange(f,firstName:"regular",firstObject:f.installed.identity("regular")),-1)
        try f.assertOriginal()
    }
    func testMissingTargetAndUnsafeNamesLeaveOriginalPositions() throws {
        let f = try Fixture(); defer { f.clean() }
        for name in ["",".","..","../Application.app","/Application.app","nested/Application.app"] {
            XCTAssertEqual(try exchange(f,firstName:name),-1)
            XCTAssertEqual(try exchange(f,secondName:name),-1)
        }
        XCTAssertEqual(try exchange(f,secondName:"missing"),-1)
        try f.assertOriginal()
    }
    func testNullIdentitiesAndInvalidDescriptorsFailBeforeMutation() throws {
        let f = try Fixture(); defer { f.clean() }
        var a = try f.installed.identity("Application.app").native, ap = try f.installed.ownIdentity.native
        var b = try f.prepared.identity("replacement").native, bp = try f.prepared.ownIdentity.native
        XCTAssertEqual(as_exchange_owned_directories(f.installed.fd,"Application.app",nil,&ap,f.prepared.fd,"replacement",&b,&bp),-1)
        XCTAssertEqual(as_exchange_owned_directories(f.installed.fd,"Application.app",&a,nil,f.prepared.fd,"replacement",&b,&bp),-1)
        XCTAssertEqual(as_exchange_owned_directories(f.installed.fd,"Application.app",&a,&ap,f.prepared.fd,"replacement",nil,&bp),-1)
        XCTAssertEqual(as_exchange_owned_directories(f.installed.fd,"Application.app",&a,&ap,f.prepared.fd,"replacement",&b,nil),-1)
        XCTAssertEqual(as_exchange_owned_directories(-1,"Application.app",&a,&ap,f.prepared.fd,"replacement",&b,&bp),-1)
        try f.assertOriginal()
    }
    func testSameObjectAndFalseDeviceOrOwnerAreRefused() throws {
        let f = try Fixture(); defer { f.clean() }
        var a = try f.installed.identity("Application.app").native, ap = try f.installed.ownIdentity.native
        XCTAssertEqual(as_exchange_owned_directories(f.installed.fd,"Application.app",&a,&ap,f.installed.fd,"Application.app",&a,&ap),-1)
        let realB = try f.prepared.identity("replacement")
        var b = realB.native, bp = try f.prepared.ownIdentity.native
        b.device ^= 1
        XCTAssertEqual(as_exchange_owned_directories(f.installed.fd,"Application.app",&a,&ap,f.prepared.fd,"replacement",&b,&bp),-1)
        b = realB.native; b.owner = 0
        XCTAssertEqual(as_exchange_owned_directories(f.installed.fd,"Application.app",&a,&ap,f.prepared.fd,"replacement",&b,&bp),-1)
        try f.assertOriginal()
    }
    func testSharedOrNonPrivateParentPermissionsAreNotAccepted() throws {
        let f = try Fixture(); defer { f.clean() }
        XCTAssertEqual(fchmod(f.prepared.fd,0o755),0)
        XCTAssertEqual(try exchange(f),-1)
        XCTAssertEqual(fchmod(f.prepared.fd,0o700),0)
        XCTAssertEqual(fchmod(f.installed.fd,0o770),0)
        XCTAssertEqual(try exchange(f),-1)
        XCTAssertEqual(fchmod(f.installed.fd,0o700),0)
        try f.assertOriginal()
    }
    func testGrantACLOnParentIsRejectedEvenWhenUnixModeIsPrivate() throws {
        let f = try Fixture(); defer { f.clean() }
        for path in [f.installed.path,f.prepared.path] {
            _ = try BoundedProcess.run("/bin/chmod",arguments:["+a","everyone allow write,add_file,add_subdirectory",path],timeout:3)
            defer { _ = try? BoundedProcess.run("/bin/chmod",arguments:["-N",path],timeout:3) }
            XCTAssertEqual(try exchange(f),-1)
            try f.assertOriginal()
        }
    }
    func testSpecialPermissionBitsOnEitherObjectOrParentAreRefused() throws {
        let f = try Fixture(); defer { f.clean() }
        for path in [f.installed.path,f.prepared.path,f.installed.path + "/Application.app",f.prepared.path + "/replacement"] {
            let directory = try SafeDirectory(path:path)
            let specials: [mode_t] = [0o1000,0o2000,0o4000]
            for special in specials {
                XCTAssertEqual(fchmod(directory.fd,0o700 | special),0)
                XCTAssertEqual(try exchange(f),-1)
                XCTAssertEqual(fchmod(directory.fd,0o700),0)
                try f.assertOriginal()
            }
        }
    }
    func testGrantACLOrSharedModeOnAnObjectIsRejected() throws {
        let f = try Fixture(); defer { f.clean() }
        for path in [f.installed.path + "/Application.app",f.prepared.path + "/replacement"] {
            let directory = try SafeDirectory(path:path)
            XCTAssertEqual(fchmod(directory.fd,0o777),0)
            XCTAssertEqual(try exchange(f),-1)
            XCTAssertEqual(fchmod(directory.fd,0o700),0)
            _ = try BoundedProcess.run("/bin/chmod",arguments:["+a","everyone allow write,add_file",path],timeout:3)
            defer { _ = try? BoundedProcess.run("/bin/chmod",arguments:["-N",path],timeout:3) }
            XCTAssertEqual(try exchange(f),-1)
            try f.assertOriginal()
        }
    }
}
#endif
