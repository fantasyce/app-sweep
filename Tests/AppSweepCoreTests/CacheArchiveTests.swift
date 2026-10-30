#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

final class CacheArchiveTests: XCTestCase {
    func testForgedSpecialFileMetadataCannotBeAppliedToPrivateRegularFile() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let path = f.home + "/private-output"
        try Data("owned bytes".utf8).write(to: URL(fileURLWithPath: path))
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
        let snapshot = try SafeFilesystem.snapshot(path), a = snapshot.identity
        let forged = FileIdentity(device: a.device, inode: a.inode, mode: 0o010600, owner: a.owner, links: a.links, size: a.size, modifiedSeconds: a.modifiedSeconds, modifiedNanoseconds: a.modifiedNanoseconds, changedSeconds: a.changedSeconds, changedNanoseconds: a.changedNanoseconds)
        let metadata = try CacheNodeMetadata.read(snapshot)
        XCTAssertThrowsError(try metadata.apply(to: snapshot, original: forged))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path)), Data("owned bytes".utf8))
    }
    func testCorruptedIndependentBytesNeverCreateARecoveryObject() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }; try f.generate()
        let path = f.home + "/Library/Caches/org.example.sweepfixture/payload", snapshot = try SafeFilesystem.snapshot(path), id = UUID()
        let item = Candidate(id: id, path: path, category: .cache, bundleIdentifier: "org.example.sweepfixture", evidence: [.init(kind: .validatedRule, detail: "owned sample", verified: true)], rule: CacheDomainRule.name, identity: snapshot.identity, bytes: snapshot.bytes, retentionReason: nil)
        let parent = try SafeDirectory(path: f.home), backups = try parent.privateChild("archive.noindex"), objects = try parent.privateChild("rebuilt.noindex")
        let prepared = try CacheArchive.prepare(snapshot, candidate: item), archive = try CacheArchive.create(prepared, snapshot: snapshot, candidate: item, in: backups)
        let entry = RecoveryEntry(id: id, original: item, state: .moved, contents: snapshot.tree, backupDigest: prepared.digest, backupIdentity: archive.identity, backupFormat: CacheArchive.format)
        let blob = try XCTUnwrap(archive.tree.first { UUID(uuidString: $0.relative) != nil })
        let writer = try FileHandle(forWritingTo: URL(fileURLWithPath: archive.path + "/" + blob.relative))
        try writer.write(contentsOf: Data([0xff])); try writer.close()
        XCTAssertThrowsError(try CacheArchive.materialize(entry, from: backups, into: objects))
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: objects.path).isEmpty)
        XCTAssertEqual(try String(contentsOfFile: path, encoding: .utf8), "HTTP fixture content")
    }
    func testIndependentDirectoryArchiveRebuildsLargeBytesPermissionsAndAttributes() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let root = f.home + "/Library/Caches/org.example.sweepfixture/tree"
        try FileManager.default.createDirectory(atPath: root + "/nested", withIntermediateDirectories: true, attributes: [.posixPermissions: 0o750])
        let path = root + "/nested/payload", bytes = Data(repeating: 0x37, count: 32 * 1024 * 1024)
        try bytes.write(to: URL(fileURLWithPath: path))
        try FileManager.default.setAttributes([.posixPermissions: 0o600, .modificationDate: Date(timeIntervalSince1970: 1_600_000_000)], ofItemAtPath: path)
        _ = try BoundedProcess.run("/usr/bin/xattr", arguments: ["-w", "org.appsweep.fixture", "owned-attribute", path], timeout: 3)
        let snapshot = try SafeFilesystem.snapshot(root), id = UUID()
        let item = Candidate(id: id, path: root, category: .cache, bundleIdentifier: "org.example.sweepfixture", evidence: [.init(kind: .validatedRule, detail: "owned native sample", verified: true)], rule: CacheDomainRule.name, identity: snapshot.identity, bytes: snapshot.bytes, retentionReason: nil)
        let parent = try SafeDirectory(path: f.home), backups = try parent.privateChild("archive.noindex"), objects = try parent.privateChild("rebuilt.noindex")
        let prepared = try CacheArchive.prepare(snapshot, candidate: item)
        let archive = try CacheArchive.create(prepared, snapshot: snapshot, candidate: item, in: backups)
        XCTAssertNotEqual(archive.identity.inode, snapshot.identity.inode)
        let entry = RecoveryEntry(id: id, original: item, state: .moved, contents: snapshot.tree, backupDigest: prepared.digest, backupIdentity: archive.identity, backupFormat: CacheArchive.format)
        let rebuilt = try CacheArchive.materialize(entry, from: backups, into: objects)
        XCTAssertNotEqual(rebuilt.identity.inode, snapshot.identity.inode)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: rebuilt.path + "/nested/payload")), bytes)
        XCTAssertEqual(try SafeFilesystem.snapshot(rebuilt.path + "/nested/payload").identity.mode & 0o777, 0o600)
        XCTAssertEqual(try SafeDirectory(path: rebuilt.path + "/nested").ownIdentity.mode & 0o777, 0o750)
        XCTAssertEqual(try BoundedProcess.run("/usr/bin/xattr", arguments: ["-p", "org.appsweep.fixture", rebuilt.path + "/nested/payload"], timeout: 3).trimmingCharacters(in: .whitespacesAndNewlines), "owned-attribute")
        XCTAssertEqual(try SafeFilesystem.snapshot(path).identity, snapshot.tree.first { $0.relative == "nested/payload" }?.identity)
        XCTAssertThrowsError(try CacheArchive.materialize(entry, from: backups, into: objects), "Never replace a reconstruction")
    }
}
#endif
