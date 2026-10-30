#if os(macOS)
import Foundation
import CryptoKit
import CFSafety
import Darwin
import XCTest
@testable import AppSweepCore

/// Explicit opt-in for a task-private copy of the publisher's research backup.
/// No sample payloads or device identifiers are distributed with the product.
final class PublicDeviceBackupTests: XCTestCase, @unchecked Sendable {
    private struct Preparation: Decodable {
        let schemaVersion: Int
        let complete: Bool
        let uid: UInt32
        let home: String
        let homeDevice: UInt64
        let homeInode: UInt64
        let backupLeaf: String
        let archiveSHA256: String
        let archiveBytes: Int64
        let recordsSHA256: String
        let outerETag: String
        let fileCount: Int
        let uncompressedBytes: Int64
    }
    private struct Record: Decodable, Equatable {
        let bytes: Int64
        let permissions: Int
        let owner: UInt32
        let inode: UInt64
        let device: UInt64
        let digest: String?
    }
    private func records(_ root: String) throws -> [String:Record] {
        guard let iterator = FileManager.default.enumerator(atPath:root) else { throw SweepError.incomplete("Research backup enumeration unavailable") }
        let deadline = ProcessInfo.processInfo.systemUptime + 300
        let rootAttributes = try FileManager.default.attributesOfItem(atPath:root)
        guard let rootMode = rootAttributes[.posixPermissions] as? NSNumber,
              let rootOwner = rootAttributes[.ownerAccountID] as? NSNumber,
              let rootInode = rootAttributes[.systemFileNumber] as? NSNumber,
              let rootDevice = rootAttributes[.systemNumber] as? NSNumber else { throw SweepError.incomplete("Research backup root metadata unavailable") }
        var result: [String:Record] = [".":Record(bytes:0,permissions:rootMode.intValue,owner:rootOwner.uint32Value,inode:rootInode.uint64Value,device:rootDevice.uint64Value,digest:nil)], total: Int64 = 0
        for case let relative as String in iterator {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline, result.count < 100_000,
                  !relative.hasPrefix("/"), !relative.split(separator:"/").contains("..") else { throw SweepError.incomplete("Research backup digest bound exceeded") }
            let path = root + "/" + relative
            let attributes = try FileManager.default.attributesOfItem(atPath:path)
            guard let type = attributes[.type] as? FileAttributeType, type == .typeRegular || type == .typeDirectory,
                  let owner = attributes[.ownerAccountID] as? NSNumber, owner.uint32Value == getuid(),
                  let mode = attributes[.posixPermissions] as? NSNumber,
                  let inode = attributes[.systemFileNumber] as? NSNumber, let device = attributes[.systemNumber] as? NSNumber else { throw SweepError.denied("Research backup contains an unowned or special object") }
            let size = (attributes[.size] as? NSNumber)?.int64Value ?? 0
            var digest: String?
            if type == .typeRegular {
                total += size
                guard size >= 0, total <= 2*1024*1024*1024 else { throw SweepError.incomplete("Research backup byte budget exceeded") }
                let input = try FileHandle(forReadingFrom:URL(fileURLWithPath:path))
                defer { try? input.close() }
                var hash = SHA256(), read: Int64 = 0
                while let block = try input.read(upToCount:1024*1024), !block.isEmpty {
                    try Task.checkCancellation()
                    guard ProcessInfo.processInfo.systemUptime < deadline else { throw SweepError.incomplete("Research backup digest timed out") }
                    read += Int64(block.count); guard read <= size else { throw SweepError.stale("Research sample grew during hashing") }
                    hash.update(data:block)
                }
                guard read == size else { throw SweepError.stale("Research sample changed while hashing") }
                digest = hash.finalize().map { String(format:"%02x",$0) }.joined()
            }
            result[relative] = Record(bytes:type == .typeRegular ? size : 0,permissions:mode.intValue,owner:owner.uint32Value,inode:inode.uint64Value,device:device.uint64Value,digest:digest)
        }
        return result
    }
    func testStandardPublicBackupUsesDefaultProductAndRealWriterBlocksBeforeMove() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_NATIVE_DEVICE_BACKUP_ACCEPTANCE"] == "AppSweep-General-20261016",getuid() == 501,try SystemIdentity.home() == "/Users/localtest",try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).hasPrefix("VirtualMac") else{throw XCTSkip("Existing registered standard VM research backup only")}
        let task="/Users/localtest/AppSweepAcceptanceGeneral-20261016",home="/Users/localtest"
        let marker=try XCTUnwrap(try JSONSerialization.jsonObject(with:SafeFilesystem.readMetadata(task + "/native-device-backup-current.json"))as? [String:Any])
        let stage=try XCTUnwrap(marker["stage"]as? String),path=try XCTUnwrap(marker["proposedTarget"]as? String),source=try XCTUnwrap(marker["source"]as? String)
        guard stage == task + "/native-device-backup-stage-7A3BA07F-7EA3-45BB-96D0-E27165BC2066.noindex",try SafeDirectory(path:stage).ownIdentity.inode == 10738233,path == DeviceBackupRule.root(home:home) + "/c623fbd7e91b041e07a68f8523f53a35973e475d",source.hasPrefix(task + "/public-device-backup.noindex/"),try SafeDirectory(path:source).ownIdentity.inode == 4262456,try !SafeFilesystem.presence(stage + "/default-result.json") else{throw SweepError.denied("Native registered backup changed or already completed")}
        let original=try records(path),sourceBefore=try records(source)
        XCTAssertEqual(Set(original.keys),Set(sourceBefore.keys))
        for (relative,value) in original{
            let expected=try XCTUnwrap(sourceBefore[relative]);XCTAssertEqual(value.bytes,expected.bytes);XCTAssertEqual(value.digest,expected.digest);XCTAssertEqual(value.permissions,expected.permissions);XCTAssertEqual(value.owner,expected.owner)
        }
        XCTAssertEqual(original.values.filter{$0.digest != nil}.count,3079)
        XCTAssertEqual(original.values.reduce(Int64(0)){$0+$1.bytes},395880031)
        let engine=SweepEngine(),report=try await engine.scanJunk()
        guard let item=report.selectableCandidates(includeUserData:true).first(where:{$0.path == path && $0.rule == DeviceBackupRule.name})else{XCTFail("Standard public backup is not executable through default product policy: " + report.candidates.filter{$0.path == path}.compactMap(\.retentionReason).joined(separator:"; "));return}
        XCTAssertTrue(item.userData);XCTAssertFalse(item.selectedByDefault)
        XCTAssertFalse(report.selectableCandidates(includeUserData:false).contains{$0.id == item.id})
        let reviewed=try await engine.makePlan(reportID:report.id,selected:[item.id],includeUserData:true)
        let oldBatches=Set(try await engine.recoveryBatches().map(\.id))
        let member=try XCTUnwrap(original.keys.sorted().first{relative in relative != "." && URL(fileURLWithPath:relative).lastPathComponent.range(of:#"^[0-9a-f]{40}$"#,options:.regularExpression) != nil && (original[relative]?.bytes ?? 0)>0})
        let file=path + "/" + member,reader=try FileHandle(forReadingFrom:URL(fileURLWithPath:file)),first=try XCTUnwrap(reader.read(upToCount:1));try reader.close()
        let output=try FileHandle(forWritingTo:URL(fileURLWithPath:file)),input=Pipe(),writer=Process(),ended=expectation(description:"Original native tee writer receives EOF and exits naturally")
        writer.executableURL=URL(fileURLWithPath:"/usr/bin/tee");writer.standardInput=input;writer.standardOutput=output;writer.standardError=FileHandle.nullDevice;writer.terminationHandler={_ in ended.fulfill()}
        try writer.run();try output.close();try input.fileHandleForWriting.write(contentsOf:first)
        var refusal:Error?
        do{_=try await engine.execute(planID:reviewed.id);XCTFail("Real native backup writer must block this plan")}catch{refusal=error}
        XCTAssertNotNil(refusal);XCTAssertTrue(writer.isRunning,"Product cannot terminate the writer")
        XCTAssertTrue(FileManager.default.fileExists(atPath:path))
        try input.fileHandleForWriting.close();await fulfillment(of:[ended],timeout:10)
        guard !writer.isRunning,writer.terminationStatus == 0 else{throw SweepError.incomplete("Retain backup fixture with unfinished writer")}
        let afterRefusal=Set(try await engine.recoveryBatches().map(\.id))
        XCTAssertEqual(afterRefusal,oldBatches,"Refusal must occur before a cleanup journal starts")
        XCTAssertEqual(try records(path),original,"Writing the same first byte is disposable activity without changing any sample payload")
        let fresh=SweepEngine(),next=try await fresh.scanJunk(),chosen=try XCTUnwrap(next.selectableCandidates(includeUserData:true).first{$0.path == path})
        let plan=try await fresh.makePlan(reportID:next.id,selected:[chosen.id],includeUserData:true),batch=try await fresh.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        guard batch.status == .isolated else{return}
        XCTAssertFalse(FileManager.default.fileExists(atPath:path))
        let restored=try await SweepEngine().restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.entries.compactMap(\.message).joined(separator:"; "))
        XCTAssertEqual(try records(path),original);XCTAssertEqual(try records(source),sourceBefore)
        let result:[String:Any]=["path":path,"batch":batch.id.uuidString,"files":3079,"bytes":395880031,"rootInode":original["."]!.inode,"state":"default public backup explicit selection; real native inherited write descriptor blocks; writer not terminated; fresh whole tree restore; original source unchanged; ordinary GUI pending"]
        try JSONSerialization.data(withJSONObject:result,options:[.sortedKeys]).write(to:URL(fileURLWithPath:stage + "/default-result.json"),options:.withoutOverwriting)
        print("DEFAULT_DEVICE_BACKUP_ACCEPTED " + String(data:try JSONSerialization.data(withJSONObject:result),encoding:.utf8)!)
    }
    func testPublishedBackupWholeDirectoryRestoresOriginalTreeAndBytes() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_PUBLIC_DEVICE_BACKUP_ACCEPTANCE"] == "1",
              getuid() == 501, try SystemIdentity.home() == "/Users/localtest",
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).hasPrefix("VirtualMac") else { throw XCTSkip("Explicit prepared public-backup VM only") }
        let task = "/Users/localtest/AppSweepAcceptanceGeneral-20261016"
        let preparation = try JSONDecoder().decode(Preparation.self,from:SafeFilesystem.readMetadata(task + "/public-device-backup-current.json",maximumBytes:64*1024))
        let prefix = task + "/public-device-backup.noindex/"
        guard preparation.schemaVersion == 1, preparation.complete, preparation.uid == getuid(),
              preparation.home.hasPrefix(prefix), preparation.home.hasSuffix("/home"),
              preparation.archiveBytes == 396533126,
              preparation.outerETag == "\"d75b42b1ad461ea27a693564867921d4-1065\"",
              preparation.archiveSHA256 == "9022c2e890ce18117bc566ed919dd0ead487dcd61ead00f8458f1b5808bf8c65",
              preparation.fileCount > 0, preparation.fileCount <= 100_000,
              preparation.uncompressedBytes > 0, preparation.uncompressedBytes <= 2*1024*1024*1024 else { throw SweepError.denied("Public research input receipt not confirmed") }
        let components = preparation.home.dropFirst(prefix.count).split(separator:"/")
        guard components.count == 2, UUID(uuidString:String(components[0]))?.uuidString == String(components[0]), components[1] == "home" else { throw SweepError.denied("Research fixture home outside exact task namespace") }
        let home = try SafeDirectory(path:preparation.home), identity = try home.ownIdentity
        guard identity.device == preparation.homeDevice, identity.inode == preparation.homeInode,
              identity.owner == getuid(), as_private_descriptor(home.fd) == 1 else { throw SweepError.stale("Research fixture home identity changed") }
        let path = DeviceBackupRule.root(home:preparation.home) + "/" + preparation.backupLeaf
        guard DeviceBackupRule.matches(path:path,home:preparation.home) else { throw SweepError.denied("Research backup location unconfirmed") }
        _ = try DeviceBackupRule.inspect(path:path,home:preparation.home)
        let inputRecords = try SafeFilesystem.readMetadata(URL(fileURLWithPath:preparation.home).deletingLastPathComponent().path + "/input-records.json",maximumBytes:16*1024*1024)
        guard SHA256.hash(data:inputRecords).map({ String(format:"%02x",$0) }).joined() == preparation.recordsSHA256 else { throw SweepError.stale("Research input digest receipt changed") }
        let expected = try JSONDecoder().decode([String:Record].self,from:inputRecords)
        let before = try records(path)
        XCTAssertEqual(before,expected,"Input must still match the ZIP-verified preparation before any product operation")
        guard before == expected else { throw SweepError.stale("Research input differs from verified archive; retained without mutation") }
        XCTAssertEqual(before.values.filter { $0.digest != nil }.count,preparation.fileCount)
        XCTAssertEqual(before.values.reduce(Int64(0)) { $0 + $1.bytes },preparation.uncompressedBytes)
        let policy = SafetyPolicy(home:preparation.home,acceptedPlatform:true,validatedRules:[DeviceBackupRule.name,DeviceBackupRule.largeName])
        let vault = preparation.home + "/Library/Application Support/App Sweep/Recovery"
        let engine = SweepEngine(policy:policy,vaultPath:vault,fixture:false)
        let report = try await engine.scanJunk()
        let item = try XCTUnwrap(report.selectableCandidates(includeUserData:true).first { $0.category == .deviceBackup && $0.path == path })
        XCTAssertFalse(item.selectedByDefault)
        XCTAssertFalse(report.selectableCandidates(includeUserData:false).contains { $0.id == item.id })
        let plan = try await engine.makePlan(reportID:report.id,selected:[item.id],includeUserData:true)
        let moved = try await engine.execute(planID:plan.id)
        XCTAssertEqual(moved.status,.isolated,moved.issue ?? "")
        guard moved.status == .isolated else { throw SweepError.incomplete("Published research backup not isolated; retained for inspection") }
        XCTAssertFalse(FileManager.default.fileExists(atPath:path))
        let restored = try await SweepEngine(policy:policy,vaultPath:vault,fixture:false).restore(batchID:moved.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        guard restored.status == .restored else { throw SweepError.incomplete("Published research recovery needs attention; sample retained") }
        XCTAssertEqual(try records(path),before,"All source bytes, names, permissions and owners must survive the roundtrip")
        print("Public research backup whole-directory byte/permission roundtrip verified; files=\(preparation.fileCount), bytes=\(preparation.uncompressedBytes), batch=\(moved.id); device restoration not performed; no purge")
    }
}
#endif
