#if os(macOS)
import Foundation
import Darwin
import CFSafety
import XCTest
@testable import AppSweepCore

final class LocalizedResourceReaderTests: XCTestCase, @unchecked Sendable {
    private let sample = "/owned/Example.app/Contents/Resources/en.lproj/InfoPlist.strings"
    private func record(pid: Int32 = 42, fd: String = "txt", path: String? = nil) -> String {
        "p\(pid)\0cNotificationCenter\0\nf\(fd)\0a \0tREG\0D0x100000c\0i5466052\0n\(path ?? sample)\0\n"
    }
    func testCompleteTypedMappingsArePositiveEvenWithStatusOne() throws {
        for status: Int32 in [0,1] {
            let refs = try LocalizedResourceReader.references(CapturedProcess(status:status,text:record() + record(pid:43)))
            XCTAssertEqual(refs.count,2); XCTAssertEqual(refs[0].pid,42)
            XCTAssertEqual(refs[0].device,16777228); XCTAssertEqual(refs[0].inode,5466052)
            XCTAssertEqual(refs[0].path,sample)
        }
    }
    func testWarningsPartialRecordsAndOrdinaryDescriptorsNeverQualify() {
        let bad = ["", "lsof: permission denied\n" + record(), record(fd:"3"),
                   record().replacingOccurrences(of:"i5466052\0",with:""),
                   record().replacingOccurrences(of:"tREG\0",with:"tDIR\0"),
                   record().replacingOccurrences(of:"D0x100000c\0",with:"Dunknown\0"),
                   record().replacingOccurrences(of:"i5466052\0",with:"i5466052\0i5466053\0"),
                   record().replacingOccurrences(of:"\0\n",with:"\n")]
        for text in bad { XCTAssertThrowsError(try LocalizedResourceReader.references(CapturedProcess(status:1,text:text)),text) }
        XCTAssertThrowsError(try LocalizedResourceReader.references(CapturedProcess(status:2,text:record())))
    }
    private final class Consumer {
        let fixture: NativeAcceptanceTests.NativeFixture
        let resource: String
        let binary: String
        let process: Process
        private(set) var mappingDescription = ""
        private let input = Pipe(), output = Pipe()
        init(mode: String = "private") throws {
            fixture = try NativeAcceptanceTests.NativeFixture()
            resource = fixture.app + "/Contents/Resources/en.lproj/InfoPlist.strings"
            binary = fixture.home + "/mapped-reader"
            try FileManager.default.createDirectory(atPath:URL(fileURLWithPath:resource).deletingLastPathComponent().path,withIntermediateDirectories:true)
            try PropertyListSerialization.data(fromPropertyList:["CFBundleName":"Disposable resource"],format:.xml,options:0).write(to:URL(fileURLWithPath:resource))
            _ = try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-",fixture.app],timeout:10)
            let source = try NativeAcceptanceTests.NativeFixture.resource("LocalizedResourceConsumer",extension:"c")
            let sdk = try XCTUnwrap(ProcessInfo.processInfo.environment["APP_SWEEP_SDK"])
            let clang = ProcessInfo.processInfo.environment["APP_SWEEP_CLANG"] ?? "/usr/bin/clang"
            _ = try BoundedProcess.run(clang,arguments:["-isysroot",sdk,"-mmacosx-version-min=12.0",source.path,"-o",binary],timeout:30)
            _ = try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-",binary],timeout:10)
            process = Process(); process.executableURL = URL(fileURLWithPath:binary); process.arguments = [mode,resource]
            process.standardInput = input; process.standardOutput = output; process.standardError = Pipe()
            try process.run()
            try? output.fileHandleForWriting.close()
            do {
                guard try line() == "READY" else { throw SweepError.incomplete("Owned mapping child did not become ready") }
                mappingDescription = try line()
            } catch { close(); throw error }
        }
        func line() throws -> String {
            var bytes = Data()
            let deadline = ProcessInfo.processInfo.systemUptime + 5
            while bytes.count < 128 {
                let remaining = deadline - ProcessInfo.processInfo.systemUptime
                guard remaining > 0 else { throw SweepError.incomplete("Owned mapping child output timed out") }
                var descriptor = pollfd(fd:output.fileHandleForReading.fileDescriptor,events:Int16(POLLIN | POLLHUP),revents:0)
                guard poll(&descriptor,1,Int32(max(1,min(5000,remaining*1000)))) > 0,
                      let next = try output.fileHandleForReading.read(upToCount:1), !next.isEmpty else { throw SweepError.incomplete("Owned mapping child output unavailable") }
                if next.first == 10 { return String(decoding:bytes,as:UTF8.self) }
                bytes.append(next)
            }
            throw SweepError.incomplete("Owned mapping child output incomplete")
        }
        func verifyBytes() throws -> String {
            try input.fileHandleForWriting.write(contentsOf:Data("verify\n".utf8))
            return try line()
        }
        func birth() throws -> ASProcessBirth {
            var value = ASProcessBirth()
            guard as_process_birth(process.processIdentifier,&value) == 0 else { throw SweepError.incomplete("Owned mapping child identity unavailable") }
            return value
        }
        func close() {
            try? input.fileHandleForWriting.close()
            if process.isRunning { process.waitUntilExit() }
            try? fixture.clean()
        }
    }
    func testKernelConfirmsExactPrivateReadonlyVnodeAndRejectsAnotherIdentity() throws {
        let child = try Consumer(); defer { child.close() }
        var file = try SafeFilesystem.snapshot(child.resource).identity.native, birth = try child.birth()
        XCTAssertEqual(as_private_readonly_resource_mappings(child.process.processIdentifier,&file,&birth),1,child.mappingDescription)
        file.inode += 1
        XCTAssertEqual(as_private_readonly_resource_mappings(child.process.processIdentifier,&file,&birth),0)
    }
    func testPrivateWritableAndSharedWritableMappingsAreUnsafe() throws {
        for mode in ["private-write","shared-write"] {
            let child = try Consumer(mode:mode); defer { child.close() }
            var file = try SafeFilesystem.snapshot(child.resource).identity.native, birth = try child.birth()
            XCTAssertEqual(as_private_readonly_resource_mappings(child.process.processIdentifier,&file,&birth),0,mode)
        }
    }
    func testCurrentlyReadonlyMappingThatCanBecomeExecutableRemainsUnsafe() throws {
        let child = try Consumer(mode:"private-executable-capable"); defer { child.close() }
        guard child.mappingDescription.contains("max=7") else { throw XCTSkip("Platform cannot create this optional executable-capable mapping: " + child.mappingDescription) }
        var file = try SafeFilesystem.snapshot(child.resource).identity.native, birth = try child.birth()
        XCTAssertEqual(as_private_readonly_resource_mappings(child.process.processIdentifier,&file,&birth),0,child.mappingDescription)
    }
    func testExecutingImageAndChangedProcessBirthCannotQualify() throws {
        let child = try Consumer(); defer { child.close() }
        var file = try SafeFilesystem.snapshot(child.binary).identity.native, birth = try child.birth()
        XCTAssertEqual(as_private_readonly_resource_mappings(child.process.processIdentifier,&file,&birth),0)
        file = try SafeFilesystem.snapshot(child.resource).identity.native
        birth.started_microseconds += 1
        XCTAssertEqual(as_private_readonly_resource_mappings(child.process.processIdentifier,&file,&birth),-1)
    }
    func testPrivateReaderKeepsExactBytesAfterWholeBundleMoveAndResourceUnlink() throws {
        let child = try Consumer(); defer { child.close() }
        let body = try SafeFilesystem.snapshot(child.fixture.app,allowInternalLinks:true,purpose:.application)
        let destination = try SafeDirectory(path:child.fixture.home).privateChild("held.noindex")
        try SafeFilesystem.move(body,into:destination,name:"original-bundle")
        let moved = destination.path + "/original-bundle/Contents/Resources/en.lproj/InfoPlist.strings"
        let current = try SafeFilesystem.snapshot(moved)
        XCTAssertEqual(try child.verifyBytes(),"UNCHANGED")
        let parent = try SafeDirectory(path:URL(fileURLWithPath:moved).deletingLastPathComponent().path)
        XCTAssertTrue(SafeFilesystem.removeVerified(in:parent,name:"InfoPlist.strings",identity:current.identity,contents:[]))
        XCTAssertEqual(try child.verifyBytes(),"UNCHANGED")
    }
    func testSimilarProcessLabelAndValidTargetSignatureDoNotGrantAppleReaderAuthority() throws {
        let child = try Consumer(); defer { child.close() }
        let snapshot = try SafeFilesystem.snapshot(child.fixture.app,allowInternalLinks:true,purpose:.application)
        let file = try SafeFilesystem.snapshot(child.resource).identity
        let text = "p\(child.process.processIdentifier)\0cNotificationCenter\0\nftxt\0a \0tREG\0D0x\(String(file.device,radix:16))\0i\(file.inode)\0n\(child.resource)\0\n"
        let refs = try LocalizedResourceReader.references(CapturedProcess(status:1,text:text))
        XCTAssertThrowsError(try LocalizedResourceReader.verify(snapshot:snapshot,references:refs),"Our signed child is not an authenticated system notification reader")
        XCTAssertThrowsError(try BusyInspector.ensureUnused(snapshot,allowReadOnlyLocalization:true), "A private map and a system-like process label cannot enable whole-bundle execution")
    }
    func testOriginalTaskBrowserMappingsHaveFullLiveAppleProof() throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_LOCALIZED_READER_ACCEPTANCE"] == "1",
              try SystemIdentity.home() == "/Users/localtest",
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).hasPrefix("VirtualMac2,1") else { throw XCTSkip("Explicit original browser mapping inspection in disposable VM") }
        let app = "/Users/localtest/Applications/Brave Browser.app"
        let record = try JSONSerialization.jsonObject(with:SafeFilesystem.readMetadata("/Users/localtest/AppSweepAcceptanceGeneral-20261016/brave-consumer.noindex/default-consumer-ownership.json")) as? [String:Any]
        guard let inode = record?["sourceInode"] as? UInt64,
              try SafeDirectory(path:app).ownIdentity.inode == inode,
              record?["identifier"] as? String == "com.brave.Browser",
              AppInspector.signedByTeam(path:app,team:"KL8N8XSYF4") else { throw SweepError.denied("Original task-owned browser identity not confirmed") }
        try ActivityInspector.ensureStopped(bundleID:"com.brave.Browser",applicationPath:app)
        let snapshot = try SafeFilesystem.snapshot(app,allowInternalLinks:true,purpose:.application)
        let output = try BoundedProcess.capture("/usr/sbin/lsof",arguments:["-F0pcfatDin","+D",app],timeout:30,mergeStderr:true)
        let references = try LocalizedResourceReader.references(output)
        XCTAssertFalse(references.isEmpty,"This positive must exercise actual held resources")
        try LocalizedResourceReader.verify(snapshot:snapshot,references:references)
        print("Exact original browser resources passed typed vnode, target seal, live Apple code/birth and complete private-readonly mapping proof; no product move or guard integration; references=" + String(references.count))
    }
}
#endif
