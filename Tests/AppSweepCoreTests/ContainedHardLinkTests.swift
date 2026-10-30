#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

final class ContainedHardLinkTests: XCTestCase {
    func testExternalReferenceAndLaterAliasChangesCannotAuthorizeStreaming() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let root = f.home + "/closed-cache"
        try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
        let a = root + "/a", b = root + "/b", outside = f.home + "/outside"
        try Data("owned shared bytes".utf8).write(to: URL(fileURLWithPath: a))
        try FileManager.default.linkItem(atPath: a, toPath: b)
        XCTAssertThrowsError(try SafeFilesystem.snapshot(root), "Ordinary rules remain strict")
        let snapshot = try SafeFilesystem.snapshot(root, allowInternalHardLinks: true)
        let input = try SafeFilesystem.fileSnapshot(a, in: snapshot)
        XCTAssertEqual(snapshot.bytes, Int64("owned shared bytes".utf8.count))
        XCTAssertEqual(try VerifiedFileStream.digest(input), try VerifiedFileStream.digest(SafeFilesystem.fileSnapshot(b, in: snapshot)))
        try FileManager.default.linkItem(atPath: a, toPath: outside)
        XCTAssertThrowsError(try SafeFilesystem.snapshot(root, allowInternalHardLinks: true))
        let output = try SafeDirectory(path: f.home).privateChild("output.noindex")
        XCTAssertThrowsError(try VerifiedFileStream.copy(input, into: output, name: UUID().uuidString))
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: output.path).isEmpty)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: outside)), Data("owned shared bytes".utf8))
    }
    func testDuplicateMissingOrInconsistentReferenceRecordsAreRejected() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let root = f.home + "/closed-cache"
        try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
        try Data("owned".utf8).write(to: URL(fileURLWithPath: root + "/a"))
        try FileManager.default.linkItem(atPath: root + "/a", toPath: root + "/b")
        let snapshot = try SafeFilesystem.snapshot(root, allowInternalHardLinks: true)
        XCTAssertNoThrow(try ContainedHardLinks.validate(snapshot.tree))
        XCTAssertThrowsError(try ContainedHardLinks.validate(Array(snapshot.tree.prefix(1))))
        XCTAssertThrowsError(try ContainedHardLinks.validate([snapshot.tree[0], snapshot.tree[0]]))
        var raw = snapshot.tree[1].identity.native; raw.owner += 1
        XCTAssertThrowsError(try ContainedHardLinks.validate([snapshot.tree[0], TreeEntry(relative: "b", identity: FileIdentity(raw))]))
    }
}
#endif
