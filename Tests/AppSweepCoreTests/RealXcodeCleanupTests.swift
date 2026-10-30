#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

final class RealXcodeCleanupTests: XCTestCase, @unchecked Sendable {
    func testDefaultGeneratedProductsMoveAndRestoreAsRunnableNativeOutput() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_XCODE_GENERATED_ACCEPTANCE"] == "AppSweep-General-20261016" else {throw XCTSkip("Explicit registered disposable VM Xcode generated-data acceptance")}
        guard getuid() == 501,try SystemIdentity.home() == "/Users/localtest",
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).trimmingCharacters(in:.whitespacesAndNewlines) == "VirtualMac2,1" else {throw SweepError.denied("Requires the registered disposable VM")}
        let home=try SystemIdentity.home(),task=home + "/AppSweepAcceptanceGeneral-20261016"
        let info=try XCTUnwrap(try JSONSerialization.jsonObject(with:SafeFilesystem.readMetadata(task + "/xcode-generated-default-current.json")) as? [String:Any])
        let id=try XCTUnwrap(info["id"] as? String),owned=try XCTUnwrap(info["owned"] as? String),derived=try XCTUnwrap(info["derived"] as? String)
        guard UUID(uuidString:id) != nil,owned == task + "/native-xcode-generated-" + id + ".noindex",
              derived == home + "/Library/Developer/Xcode/DerivedData/AppSweepGenerated-" + id else {throw SweepError.denied("Invalid native generated-data registration")}
        let target=derived + "/Build/Products",product=target + "/Debug/Fixture",source=owned + "/main.c"
        let before=try SafeFilesystem.snapshot(target),bytes=try VerifiedFileStream.digest(SafeFilesystem.snapshot(product)),sourceBytes=try VerifiedFileStream.digest(SafeFilesystem.snapshot(source))
        let e=SweepEngine(),report=try await e.scanJunk()
        guard let item=report.selectableCandidates(includeUserData:false).first(where:{$0.path == target && $0.rule == "xcode-generated-data-v1"}) else {XCTFail("Default policy did not expose registered native products: " + report.candidates.filter{$0.path == target}.compactMap(\.retentionReason).joined(separator:"; "));return}
        XCTAssertFalse(item.selectedByDefault)
        let plan=try await e.makePlan(reportID:report.id,selected:[item.id],includeUserData:false),batch=try await e.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        XCTAssertFalse(FileManager.default.fileExists(atPath:target))
        let restored=try await SweepEngine().restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        XCTAssertEqual(try SafeDirectory(path:target).ownIdentity.inode,before.identity.inode)
        XCTAssertEqual(try VerifiedFileStream.digest(SafeFilesystem.snapshot(product)),bytes)
        XCTAssertEqual(try VerifiedFileStream.digest(SafeFilesystem.snapshot(source)),sourceBytes)
        XCTAssertEqual(try BoundedProcess.capture(product,arguments:[],timeout:3,mergeStderr:true).status,0)
        let result:[String:Any] = ["owned":owned,"derived":derived,"targetInode":before.identity.inode,"productSHA256":bytes,"sourceSHA256":sourceBytes,"batch":batch.id.uuidString,"state":"default current-user production policy moved native Xcode products and fresh engine restored original bytes; restored executable ran; ordinary packaged GUI still pending"]
        try JSONSerialization.data(withJSONObject:result,options:[.prettyPrinted,.sortedKeys]).write(to:URL(fileURLWithPath:owned + "/result-" + batch.id.uuidString + ".json"),options:.withoutOverwriting)
        print("DEFAULT_XCODE_GENERATED_ACCEPTED " + String(data:try JSONSerialization.data(withJSONObject:result),encoding:.utf8)!)
    }
    func testPublicEngineBuildIntermediatesRestoreAndRegenerate() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_PUBLIC_XCODE_ACCEPTANCE"] == "1",
              try BoundedProcess.run("/usr/sbin/sysctl", arguments: ["-n", "hw.model"], timeout: 3).hasPrefix("VirtualMac") else { throw XCTSkip("Explicit disposable VM native Xcode consumer") }
        let home = try SystemIdentity.home(), task = home + "/AppSweepAcceptanceGeneral-20261016", id = UUID().uuidString
        let owned = task + "/xcode-public.noindex/" + id, project = owned + "/Fixture.xcodeproj"
        let derived = home + "/Library/Developer/Xcode/DerivedData/AppSweepAcceptance-" + id
        guard try !SafeFilesystem.presence(owned), try !SafeFilesystem.presence(derived) else { throw SweepError.denied("Owned Xcode acceptance paths already exist") }
        let fm = FileManager.default
        try fm.createDirectory(atPath: project, withIntermediateDirectories: true)
        let receipt: [String: String] = ["taskRoot": owned, "derivedData": derived, "createdFromAbsent":"true", "purpose":"public native Xcode cache acceptance; retain until acceptance cleanup"]
        try JSONSerialization.data(withJSONObject: receipt, options: [.sortedKeys]).write(to: URL(fileURLWithPath: owned + "/ownership.json"))
        try fm.copyItem(atPath: NativeAcceptanceTests.NativeFixture.resource("BuildFixture", extension: "pbxproj").path, toPath: project + "/project.pbxproj")
        try fm.copyItem(atPath: NativeAcceptanceTests.NativeFixture.resource("BuildFixture", extension: "c").path, toPath: owned + "/main.c")
        let developer = try XCTUnwrap(ProcessInfo.processInfo.environment["DEVELOPER_DIR"])
        let arguments = ["-project", project, "-scheme", "Fixture", "-derivedDataPath", derived, "-configuration", "Debug", "CODE_SIGNING_ALLOWED=NO", "build"]
        func build() throws {
            let result = try BoundedProcess.capture(developer + "/usr/bin/xcodebuild", arguments: arguments, timeout: 30, mergeStderr: true)
            guard result.status == 0, result.text.contains("BUILD SUCCEEDED") else { throw SweepError.incomplete("Owned native Xcode build failed: " + String(result.text.prefix(4000))) }
        }
        try build()
        let source = try VerifiedFileStream.digest(SafeFilesystem.snapshot(owned + "/main.c")), product = derived + "/Build/Products/Debug/Fixture"
        let productDigest = try VerifiedFileStream.digest(SafeFilesystem.snapshot(product))
        let target = derived + "/Build/Intermediates.noindex", engine = SweepEngine()
        let report = try await engine.scanJunk()
        let candidate = report.selectableCandidates(includeUserData: false).first { $0.path == target && $0.rule == XcodeRule.name }
        XCTAssertNotNil(candidate, report.candidates.filter { $0.path == target }.compactMap(\.retentionReason).joined(separator: "; ") + report.issues.joined(separator: "; "))
        guard let candidate else { print("Owned Xcode public-gate RED fixture: " + owned + "; derived=" + derived); return }
        let plan = try await engine.makePlan(reportID: report.id, selected: [candidate.id], includeUserData: false)
        let batch = try await engine.execute(planID: plan.id)
        XCTAssertEqual(batch.status, .isolated, batch.issue ?? "")
        guard batch.status == .isolated else { return }
        XCTAssertFalse(fm.fileExists(atPath: target))
        XCTAssertEqual(try VerifiedFileStream.digest(SafeFilesystem.snapshot(product)), productDigest)
        let fresh = SweepEngine(), restored = try await fresh.restore(batchID: batch.id)
        XCTAssertEqual(restored.status, .restored, restored.entries.compactMap(\.message).joined(separator: "; "))
        XCTAssertEqual(try VerifiedFileStream.digest(SafeFilesystem.snapshot(owned + "/main.c")), source)
        let next = try await fresh.scanJunk(), nextItem = try XCTUnwrap(next.selectableCandidates(includeUserData: false).first { $0.path == target })
        let nextPlan = try await fresh.makePlan(reportID: next.id, selected: [nextItem.id], includeUserData: false), movedAgain = try await fresh.execute(planID: nextPlan.id)
        XCTAssertEqual(movedAgain.status, .isolated, movedAgain.issue ?? "")
        guard movedAgain.status == .isolated else { return }
        try build()
        XCTAssertTrue(fm.fileExists(atPath: target))
        XCTAssertEqual(try VerifiedFileStream.digest(SafeFilesystem.snapshot(owned + "/main.c")), source)
        XCTAssertEqual(try BoundedProcess.capture(product, arguments: [], timeout: 3, mergeStderr: true).status, 0)
        let conflict = try await fresh.restore(batchID: movedAgain.id)
        XCTAssertEqual(conflict.status, .needsAttention)
        try await finishOwnedConflict(owned: owned, target: target, batch: conflict, engine: fresh)
        try build()
        print("Public native Xcode roundtrip/rebuild/conflict passed; source/product retained; ownership=" + owned + "/ownership.json; derived=" + derived)
    }
    func testResolvePreviouslyOwnedPublicConflictThroughNormalRecovery() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_RESOLVE_XCODE_PUBLIC"] == "1" else { throw XCTSkip("Explicit existing owned public-Xcode conflict") }
        let home = try SystemIdentity.home(), id = "E78DA8F9-EC9E-4FE5-9958-8C6EE7413735"
        let owned = home + "/AppSweepAcceptanceGeneral-20261016/xcode-public.noindex/" + id
        let target = home + "/Library/Developer/Xcode/DerivedData/AppSweepAcceptance-" + id + "/Build/Intermediates.noindex"
        let engine = SweepEngine(), batches = try await engine.recoveryBatches()
        let pending = batches.filter { $0.status == .needsAttention && !$0.entries.isEmpty && $0.entries.allSatisfy { $0.original.path == target && $0.original.rule == XcodeRule.name } }
        XCTAssertLessThanOrEqual(pending.count, 1)
        for batch in pending { try await finishOwnedConflict(owned: owned, target: target, batch: batch, engine: engine) }
        let after = try await engine.recoveryBatches()
        XCTAssertFalse(after.contains { $0.status == .needsAttention && $0.entries.contains { $0.original.path == target } })
    }
    private struct ConflictReceipt: Codable {
        let source: String
        let preserved: String
        let batchID: UUID
        let identity: FileIdentity
        let tree: TreeFingerprint
        var status: String
    }
    private func finishOwnedConflict(owned: String, target: String, batch: RecoveryManifest, engine: SweepEngine) async throws {
        let home = try SystemIdentity.home(), task = home + "/AppSweepAcceptanceGeneral-20261016"
        let id = URL(fileURLWithPath: owned).lastPathComponent
        guard UUID(uuidString: id) != nil, owned == task + "/xcode-public.noindex/" + id,
              target == home + "/Library/Developer/Xcode/DerivedData/AppSweepAcceptance-" + id + "/Build/Intermediates.noindex",
              !batch.entries.isEmpty, batch.entries.allSatisfy({ $0.original.path == target && $0.original.rule == XcodeRule.name && $0.original.identity?.owner == getuid() }) else { throw SweepError.denied("Only exact task-owned Xcode conflict data may be preserved") }
        let owner = try XCTUnwrap(try JSONSerialization.jsonObject(with: SafeFilesystem.readMetadata(owned + "/ownership.json")) as? [String:String])
        guard owner["taskRoot"] == owned, owner["createdFromAbsent"] == "true", owner["derivedData"] == URL(fileURLWithPath: target).deletingLastPathComponent().deletingLastPathComponent().path else { throw SweepError.denied("Xcode ownership receipt changed") }
        try ActivityInspector.ensureBuildToolsStopped()
        let snapshot = try SafeFilesystem.snapshot(target)
        guard snapshot.identity.owner == getuid(), snapshot.tree.allSatisfy({ $0.identity.owner == getuid() }) else { throw SweepError.denied("Regenerated cache owner changed") }
        try BusyInspector.ensureUnused(snapshot)
        let operation = try SafeDirectory(path: owned).privateChild("regenerated.noindex").privateChild(UUID().uuidString)
        var receipt = ConflictReceipt(source: target, preserved: operation.path + "/Intermediates.noindex", batchID: batch.id, identity: snapshot.identity, tree: try TreeFingerprint.capture(snapshot.tree), status: "prepared")
        try operation.write(JSONEncoder().encode(receipt), name: "receipt.json")
        try SafeFilesystem.move(snapshot, into: operation, name: "Intermediates.noindex")
        receipt.status = "regenerated-cache-preserved"; try operation.write(JSONEncoder().encode(receipt), name: "receipt.json")
        let restored = try await engine.restore(batchID: batch.id)
        XCTAssertEqual(restored.status, .restored, restored.entries.compactMap(\.message).joined(separator: "; "))
        guard restored.status == .restored else { throw SweepError.incomplete("Owned original Xcode batch still needs recovery") }
        receipt.status = "original-restored-regenerated-cache-retained"; try operation.write(JSONEncoder().encode(receipt), name: "receipt.json")
        print("Owned Xcode conflict resolved through normal recovery; regenerated data preserved: " + operation.path + "/receipt.json")
    }

}
#endif
