#if os(macOS)
import Foundation
import Darwin
import XCTest
@testable import AppSweepCore

final class OptimizationPreparationStabilityTests: XCTestCase, @unchecked Sendable {
    private func snapshot(_ path: String) throws -> FileSnapshot {
        try SafeFilesystem.snapshot(path,allowInternalLinks:true,purpose:.application,allowInternalHardLinks:true)
    }
    private func rootCTimeTransition(_ path: String) throws {
        _ = try BoundedProcess.run("/usr/bin/xattr",arguments:["-w","org.appsweep.preparation-probe","temporary fixture metadata",path],timeout:5)
        _ = try BoundedProcess.run("/usr/bin/xattr",arguments:["-d","org.appsweep.preparation-probe",path],timeout:5)
    }
    // The committed non-MACL metadata and complete tree, not ctime alone, authorize a repeated read.
    func testPreparedRootCTimeOnlyTransitionCanBeCapturedAgainstIndependentMetadata() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let before = try snapshot(f.app), committed = try ApplicationOptimizationRecord.Object(before)
        try rootCTimeTransition(f.app)
        let current = try snapshot(f.app)
        XCTAssertNotEqual(before.identity,current.identity); XCTAssertTrue(before.identity.sameObject(as:current.identity))
        XCTAssertEqual(before.tree,current.tree)
        XCTAssertThrowsError(try ApplicationOptimizationRecord.Object(before),"The ordinary constructor must remain strict")
        let captured = try ApplicationOptimizationRecord.Object.capturePrepared(before,matchingRootMetadata:XCTUnwrap(committed.rootMetadata))
        XCTAssertTrue(try captured.matches(current))
        XCTAssertEqual(captured.rootMetadata,committed.rootMetadata)
    }
    func testPreparedReadDoesNotBlessChangedRootMetadataDescendantsOrIdentity() throws {
        for mutation in ["root-attribute","descendant-attribute","contents","permissions","replacement"] {
            let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
            let before = try snapshot(f.app), committed = try ApplicationOptimizationRecord.Object(before)
            try rootCTimeTransition(f.app)
            switch mutation {
            case "root-attribute": _ = try BoundedProcess.run("/usr/bin/xattr",arguments:["-w","org.appsweep.must-retain","changed",f.app],timeout:5)
            case "descendant-attribute": _ = try BoundedProcess.run("/usr/bin/xattr",arguments:["-w","org.appsweep.must-retain","changed",f.executable],timeout:5)
            case "contents": try Data("changed resource".utf8).write(to:URL(fileURLWithPath:f.app + "/Contents/changed"))
            case "permissions": try FileManager.default.setAttributes([.posixPermissions:0o700],ofItemAtPath:f.app)
            default:
                try FileManager.default.moveItem(atPath:f.app,toPath:f.app + ".retained")
                try FileManager.default.copyItem(atPath:f.app + ".retained",toPath:f.app)
            }
            let current = try snapshot(f.app)
            XCTAssertThrowsError(try ApplicationOptimizationRecord.Object.capturePrepared(before,matchingRootMetadata:XCTUnwrap(committed.rootMetadata)),mutation)
            XCTAssertNoThrow(try SafeFilesystem.verify(current),"A read refusal must not write or exchange either object")
        }
    }
    func testPreparedReadRequiresThePrecommittedRootMetadataEvenWithoutCTimeChange() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let before = try snapshot(f.app)
        XCTAssertThrowsError(try ApplicationOptimizationRecord.Object.capturePrepared(before,matchingRootMetadata:String(repeating:"0",count:64)))
        XCTAssertNoThrow(try SafeFilesystem.verify(before))
    }
    func testDelayedRetryChild() throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_PREPARATION_RETRY_PROBE"] == "AppSweep-General-20261016" else { throw XCTSkip("Isolated test-only delay child") }
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let before = try snapshot(f.app), committed = try ApplicationOptimizationRecord.Object(before)
        try rootCTimeTransition(f.app)
        var thread: UInt64 = 0;XCTAssertEqual(pthread_threadid_np(nil,&thread),0)
        setenv("APP_SWEEP_RETRY_DELAY_THREAD",String(thread),1)
        defer { unsetenv("APP_SWEEP_RETRY_DELAY_THREAD");unsetenv("APP_SWEEP_RETRY_DELAY_HIT") }
        var failure: Error?
        do { _ = try ApplicationOptimizationRecord.Object.capturePrepared(before,matchingRootMetadata:XCTUnwrap(committed.rootMetadata)) } catch { failure = error }
        XCTAssertEqual(ProcessInfo.processInfo.environment["APP_SWEEP_RETRY_DELAY_HIT"],"1","The real retry delay must have been injected")
        XCTAssertNotNil(failure,"A delayed scheduler must not start a fresh scan after the retry window")
        print("PREPARATION_RETRY_DELAY_PROBE_COMPLETE")
    }
    func testSchedulerDelayCannotStartAReadAfterTheRetryWindow() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let source = try NativeAcceptanceTests.NativeFixture.resource("PreparationReadDelay",extension:"c")
        let clang = try XCTUnwrap(ProcessInfo.processInfo.environment["APP_SWEEP_CLANG"]), sdk = try XCTUnwrap(ProcessInfo.processInfo.environment["APP_SWEEP_SDK"])
        let library = f.home + "/preparation-read-delay.dylib"
        let compiled = try BoundedProcess.capture(clang,arguments:["-dynamiclib","-isysroot",sdk,"-mmacosx-version-min=12.0",source.path,"-o",library],timeout:30,mergeStderr:true)
        guard compiled.status == 0 else { throw SweepError.incomplete(compiled.text) }
        let developer = try XCTUnwrap(ProcessInfo.processInfo.environment["DEVELOPER_DIR"])
        let result = try BoundedProcess.capture("/usr/bin/env",arguments:["DYLD_INSERT_LIBRARIES=" + library,"APP_SWEEP_PREPARATION_RETRY_PROBE=AppSweep-General-20261016",developer + "/usr/bin/xctest","-XCTest","AppSweepCoreTests.OptimizationPreparationStabilityTests/testDelayedRetryChild",Bundle(for:Self.self).bundlePath],timeout:30,mergeStderr:true)
        XCTAssertEqual(result.status,0,result.text)
        XCTAssertTrue(result.text.contains("PREPARATION_RETRY_DELAY_PROBE_COMPLETE"),result.text)
    }
    func testActualStoppedFirefoxPreparationMetadataDiagnostic() throws {
        guard let scope = ProcessInfo.processInfo.environment["APP_SWEEP_PREPARED_ROOT_DIAGNOSTIC"] else {
            throw XCTSkip("Explicit read-only diagnostic of this VM's stopped preparation only")
        }
        guard scope == "AppSweep-General-20261016", getuid() == 501, try SystemIdentity.home() == "/Users/localtest",
              PlatformStamp.current == .init(major:27,minor:0,patch:1,build:"26A434",architecture:"arm64"),
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:5).hasPrefix("VirtualMac") else {
            throw SweepError.denied("Wrong explicit prepared-root diagnostic environment")
        }
        let id = "65F46E09-9DEC-4CC1-9A7B-7AF760927EB4"
        let root = "/Users/localtest/Library/Application Support/App Sweep/Optimization.noindex/" + id
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        let record = try decoder.decode(ApplicationOptimizationRecord.self,from:SafeFilesystem.readMetadata(root + "/optimization.json",maximumBytes:128*1024))
        guard record.id.uuidString == id, record.status == .stopped, record.prepared == nil,
              record.applicationPath == "/Users/localtest/Applications/Firefox.app", record.original.identity.inode == 7697962 else {
            throw SweepError.denied("Stopped registered source does not match diagnostic")
        }
        let source = try snapshot(record.applicationPath), prepared = try snapshot(root + "/" + id)
        guard source.identity.inode == 7697962, prepared.identity.inode == 7700148 else { throw SweepError.stale("Registered diagnostic objects changed") }
        XCTAssertTrue(try record.original.matches(source),"The installed original must still match the pre-operation commitment")
        let observed = try ApplicationOptimizationRecord.Object(prepared)
        XCTAssertNotNil(record.original.rootMetadata)
        XCTAssertEqual(observed.rootMetadata,record.original.rootMetadata,"A root metadata difference would disprove the ctime-only preparation hypothesis")
        XCTAssertEqual(try ApplicationArchitecturePreparation.signature(prepared.path,identifier:"org.mozilla.firefox",architecture:"arm64"),"d16810dfc759aae5b6ae30a493e2908fe56b2c0f")
        print("READ_ONLY_PREPARED_ROOT_METADATA_MATCHES_ORIGINAL; original installed and partial retained; no publication or recovery write")
    }
}
#endif
