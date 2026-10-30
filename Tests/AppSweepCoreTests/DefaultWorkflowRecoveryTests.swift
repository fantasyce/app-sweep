#if os(macOS)
import Foundation
import XCTest
import Darwin
@testable import AppSweepCore

/// Only this test's newly created files can be selected. No overridden home,
/// accepted-platform flag or fixture engine can make this acceptance pass.
final class DefaultWorkflowRecoveryTests: XCTestCase, @unchecked Sendable {
    func testDefaultEngineIsolatesOnlyChosenOwnedLogAndFreshEngineRestoresIt() async throws {
        let task = "/Users/localtest/AppSweepAcceptanceGeneral-20261016"
        guard getuid() == 501, geteuid() == 501, NSHomeDirectory() == "/Users/localtest",
              ProcessInfo.processInfo.environment["APP_SWEEP_DEFAULT_RECOVERY_ACCEPTANCE"] == "AppSweep-General-20261016" else {
            throw XCTSkip("Explicit disposable VM default-context recovery acceptance only")
        }
        guard try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3)
            .trimmingCharacters(in:.whitespacesAndNewlines) == "VirtualMac2,1" else {
            throw SweepError.denied("Default recovery acceptance requires the disposable VM")
        }
        let application = try AppInspector.inspect("/Users/localtest/Applications/IINA.app")
        guard application.signed, application.bundleIdentifier == "com.colliderli.iina" else {
            throw SweepError.denied("Prepared signed test application is missing")
        }
        let receipt = try SafeDirectory(path:task).privateChild("default-workflow-acceptance.noindex").privateChild(UUID().uuidString)
        let logs = try SafeDirectory(path:"/Users/localtest/Library/Logs")
        let domainName = application.bundleIdentifier
        let createdDomain = try !SafeFilesystem.presence(logs.path + "/" + domainName)
        try receipt.write(JSONSerialization.data(withJSONObject:[
            "schemaVersion":1,"domainPath":logs.path + "/" + domainName,
            "domainCreatedFromAbsent":createdDomain,"purpose":"new default-context acceptance samples only"
        ],options:[.sortedKeys]),name:"preparation.json")
        if createdDomain {
            guard mkdirat(logs.fd,domainName,0o700) == 0 else { throw SweepError.filesystem("Cannot create test log domain") }
        }
        let domain = try SafeDirectory(path:logs.path + "/" + domainName)
        let domainIdentity = try domain.ownIdentity
        guard domainIdentity.owner == getuid() else { throw SweepError.denied("Unexpected log-domain owner") }
        let name = "appsweep-default-" + UUID().uuidString
        let folder = try domain.privateChild(name), identity = try folder.ownIdentity
        try receipt.write(JSONSerialization.data(withJSONObject:[
            "schemaVersion":1,"createdFromAbsent":true,"path":folder.path,
            "inode":identity.inode,"device":identity.device,"owner":identity.owner,
            "domainCreatedFromAbsent":createdDomain,"domainInode":domainIdentity.inode,
            "domainDevice":domainIdentity.device,"state":"prepared; failures retain exact fixture and evidence"
        ],options:[.sortedKeys]),name:"ownership.json")
        let payload = Data("App Sweep owned default-context acceptance log\n".utf8)
        for file in ["chosen.log","neighbour.log"] {
            try folder.write(payload,name:file)
            let fd = openat(folder.fd,file,O_RDWR | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw SweepError.filesystem("Cannot age owned log") }
            defer { close(fd) }
            let seconds = Int(Date().timeIntervalSince1970) - 31 * 24 * 60 * 60
            var times = [timeval(tv_sec:seconds,tv_usec:0),timeval(tv_sec:seconds,tv_usec:0)]
            guard futimes(fd,&times) == 0 else { throw SweepError.filesystem("Cannot age owned log") }
        }
        let chosenPath = folder.path + "/chosen.log", neighbourPath = folder.path + "/neighbour.log"
        let original = try SafeFilesystem.snapshot(chosenPath), neighbour = try SafeFilesystem.snapshot(neighbourPath)
        let engine = SweepEngine(), report = try await engine.scanJunk()
        let selectable = report.selectableCandidates(includeUserData:false)
        let chosen = try XCTUnwrap(selectable.first { $0.path == chosenPath })
        XCTAssertTrue(selectable.contains { $0.path == neighbourPath },"The unselected neighbour must also be eligible to prove that explicit selection is respected")
        XCTAssertEqual(report.selectionIDs(for:chosen.id,includeUserData:false),[chosen.id])
        let plan = try await engine.makePlan(reportID:report.id,selected:[chosen.id],includeUserData:false)
        XCTAssertEqual(plan.items.map(\.path),[chosenPath])
        let isolated = try await engine.execute(planID:plan.id)
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        try receipt.write(encoder.encode(isolated),name:"isolated.json")
        guard isolated.status == .isolated else { XCTFail("Default transaction did not isolate: " + (isolated.issue ?? "")); return }
        XCTAssertFalse(try SafeFilesystem.presence(chosenPath))
        try SafeFilesystem.verify(neighbour)
        let fresh = SweepEngine(), restored = try await fresh.restore(batchID:isolated.id)
        try receipt.write(encoder.encode(restored),name:"restored.json")
        guard restored.status == .restored else { XCTFail("Fresh default-engine recovery failed: " + restored.entries.compactMap(\.message).joined(separator:"; ")); return }
        let current = try SafeFilesystem.snapshot(chosenPath)
        XCTAssertTrue(current.identity.sameObject(as:original.identity))
        XCTAssertEqual(try SafeFilesystem.readMetadata(chosenPath),payload)
        try SafeFilesystem.verify(neighbour)
        // End-of-test removal applies solely to the newly created, restored
        // samples, through exact verified descriptors. Recovery history stays.
        guard current.identity.sameObject(as:original.identity),
              try SafeFilesystem.readMetadata(chosenPath) == payload else { throw SweepError.stale("Restored sample changed; retain fixture") }
        for file in ["chosen.log","neighbour.log"] {
            let snapshot = try SafeFilesystem.snapshot(folder.path + "/" + file)
            guard snapshot.identity.owner == getuid(), snapshot.tree.isEmpty,
                  SafeFilesystem.removeVerified(in:folder,name:file,identity:snapshot.identity,contents:[]) else {
                throw SweepError.filesystem("Owned test sample retained after teardown conflict")
            }
        }
        let empty = try SafeFilesystem.snapshot(folder.path)
        guard empty.identity.device == identity.device, empty.identity.inode == identity.inode, empty.tree.isEmpty,
              SafeFilesystem.removeVerified(in:domain,name:name,identity:empty.identity,contents:[]) else {
            throw SweepError.stale("Owned log fixture directory retained")
        }
        if createdDomain {
            let emptyDomain = try SafeFilesystem.snapshot(domain.path)
            guard emptyDomain.identity.device == domainIdentity.device, emptyDomain.identity.inode == domainIdentity.inode,
                  emptyDomain.tree.isEmpty, SafeFilesystem.removeVerified(in:logs,name:domainName,identity:emptyDomain.identity,contents:[]) else {
                throw SweepError.stale("Created log domain retained after concurrent use")
            }
        }
        try receipt.write(Data("Only the selected new log was isolated; fresh default engine restored bytes, identity and permissions; unselected neighbour preserved; exact created samples removed; recovery history and evidence retained.".utf8),name:"completed.txt")
        print("Actual default-context isolate and fresh-engine undo passed for one explicitly selected, newly owned log; eligible neighbour unchanged: " + receipt.path)
    }
}
#endif
