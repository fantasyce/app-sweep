#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

final class VerifiedFileStreamTests: XCTestCase {
    func testReadOnlyDigestBindsTheExpectedOwnerAndRetainsFreshIdentityChecks() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let path = f.home + "/owned-comparison"
        try Data("abc".utf8).write(to: URL(fileURLWithPath: path))
        let source = try SafeFilesystem.snapshot(path), owner = source.identity.owner
        XCTAssertEqual(try VerifiedFileStream.digest(source, ownedBy: owner), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        XCTAssertEqual(try VerifiedFileStream.digest(source), try VerifiedFileStream.digest(source, ownedBy: owner))
        XCTAssertThrowsError(try VerifiedFileStream.digest(source, ownedBy: owner == 0 ? 501 : 0))
        try Data("replacement".utf8).write(to: URL(fileURLWithPath: path), options: .atomic)
        XCTAssertThrowsError(try VerifiedFileStream.digest(source, ownedBy: owner))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path)), Data("replacement".utf8))
    }
    func testStreamsLargeBytesToIndependentPrivateInodeAndVerifiesDigest() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let source = f.home + "/large-owned-cache", name = UUID().uuidString
        XCTAssertTrue(FileManager.default.createFile(atPath: source, contents: nil))
        let writer = try FileHandle(forWritingTo: URL(fileURLWithPath: source))
        let block = Data(repeating: 0x5a, count: 256 * 1024)
        for _ in 0..<128 { try writer.write(contentsOf: block) }
        try writer.close()
        let snapshot = try SafeFilesystem.snapshot(source)
        let output = try SafeDirectory(path: f.home).privateChild("stream-output.noindex")
        let copied = try VerifiedFileStream.copy(snapshot, into: output, name: name)
        XCTAssertNotEqual(copied.identity.inode, snapshot.identity.inode)
        XCTAssertEqual(copied.identity.size, 32 * 1024 * 1024)
        XCTAssertEqual(copied.identity.mode & 0o777, 0o600)
        XCTAssertEqual(copied.digest, try VerifiedFileStream.digest(snapshot))
        XCTAssertEqual(copied.digest, try VerifiedFileStream.digest(SafeFilesystem.snapshot(output.path + "/" + name)))
        XCTAssertThrowsError(try VerifiedFileStream.copy(snapshot, into: output, name: name), "Never overwrite an archive")
        XCTAssertEqual(try VerifiedFileStream.digest(snapshot), copied.digest)
    }
    func testStaleSourceAndUncontrolledOutputAreRefusedBeforeCopy() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let source = f.home + "/owned-cache"
        try Data("original".utf8).write(to: URL(fileURLWithPath: source))
        let snapshot = try SafeFilesystem.snapshot(source)
        try Data("replacement".utf8).write(to: URL(fileURLWithPath: source), options: .atomic)
        let output = try SafeDirectory(path: f.home).privateChild("stream-output.noindex")
        XCTAssertThrowsError(try VerifiedFileStream.copy(snapshot, into: output, name: UUID().uuidString))
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: output.path).isEmpty)
        XCTAssertThrowsError(try VerifiedFileStream.copy(SafeFilesystem.snapshot(source), into: output, name: "../escape"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.home + "/escape"))
    }
}
#endif
