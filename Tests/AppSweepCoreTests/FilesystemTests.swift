import XCTest
@testable import AppSweepCore
#if os(macOS)
import Darwin
#else
import Glibc
#endif

final class FilesystemTests: XCTestCase {
    var root: URL!
    override func setUpWithError() throws {
        guard let base = ProcessInfo.processInfo.environment["APP_SWEEP_FIXTURES"] else { throw XCTSkip("Requires an explicit isolated fixture root") }
        root = URL(fileURLWithPath: base).appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    }
    override func tearDownWithError() throws { try FileManager.default.removeItem(at: root) }
    func testAncestorSymlinkIsRejected() throws {
        let actual = root.appendingPathComponent("actual")
        try FileManager.default.createDirectory(at: actual, withIntermediateDirectories: false)
        try Data("retain".utf8).write(to: actual.appendingPathComponent("item"))
        try FileManager.default.createSymbolicLink(atPath: root.appendingPathComponent("alias").path, withDestinationPath: actual.path)
        XCTAssertThrowsError(try SafeFilesystem.snapshot(root.appendingPathComponent("alias/item").path))
        XCTAssertEqual(try String(contentsOf: actual.appendingPathComponent("item"), encoding: .utf8), "retain")
    }
    func testBoundedMetadataReaderRejectsSpecialAndReplacedObjects() throws {
        let fifo = root.appendingPathComponent("metadata-fifo")
        XCTAssertEqual(mkfifo(fifo.path, 0o600), 0)
        XCTAssertThrowsError(try SafeFilesystem.readMetadata(fifo.path, maximumBytes: 1024))
        XCTAssertThrowsError(try SafeFilesystem.readMetadata(root.path, maximumBytes: 1024))
        let file = root.appendingPathComponent("metadata")
        try Data("regular metadata".utf8).write(to: file)
        XCTAssertEqual(try SafeFilesystem.readMetadata(file.path, maximumBytes: 1024), Data("regular metadata".utf8))
        XCTAssertThrowsError(try SafeFilesystem.readMetadata(file.path, maximumBytes: 2))
        let link = root.appendingPathComponent("alias")
        try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: file.path)
        XCTAssertThrowsError(try SafeFilesystem.readMetadata(link.path, maximumBytes: 1024))
        try FileManager.default.linkItem(at: file, to: root.appendingPathComponent("hard-link"))
        XCTAssertThrowsError(try SafeFilesystem.readMetadata(file.path, maximumBytes: 1024))
    }
    #if os(macOS)
    func testRecoveryDirectoriesAndJournalsRejectExtendedACLs() throws {
        let parent = try SafeDirectory(path: root.path)
        let vault = try parent.privateChild("private")
        try vault.write(Data("owned journal".utf8), name: "manifest.json")
        _ = try BoundedProcess.run("/bin/chmod", arguments: ["+a", "everyone allow read", vault.path + "/manifest.json"], timeout: 3)
        XCTAssertEqual((try vault.identity("manifest.json")).mode & 0o777, 0o600)
        XCTAssertThrowsError(try vault.read("manifest.json"))
        XCTAssertThrowsError(try vault.write(Data("replacement".utf8), name: "manifest.json"))
        _ = try BoundedProcess.run("/bin/chmod", arguments: ["+a", "everyone allow list,search", vault.path], timeout: 3)
        XCTAssertEqual((try vault.ownIdentity).mode & 0o777, 0o700)
        XCTAssertThrowsError(try parent.existingPrivateChild("private"))
        XCTAssertThrowsError(try parent.privateChild("private"))
        let listing = try BoundedProcess.run("/bin/ls", arguments: ["-lde", vault.path], timeout: 3)
        XCTAssertTrue(listing.contains("everyone allow"), "The product must not silently rewrite pre-existing ACLs")
    }
    #endif
    func testReplacementAfterScanNeverMovesNewObject() throws {
        let item = root.appendingPathComponent("item")
        try Data("original".utf8).write(to: item)
        let snapshot = try SafeFilesystem.snapshot(item.path)
        try FileManager.default.moveItem(at: item, to: root.appendingPathComponent("old"))
        try Data("replacement".utf8).write(to: item)
        let target = try SafeDirectory(path: root.path)
        XCTAssertThrowsError(try SafeFilesystem.move(snapshot, into: target, name: "isolated"))
        XCTAssertEqual(try String(contentsOf: item, encoding: .utf8), "replacement")
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent("isolated").path))
    }
    func testRestoreConflictNeverOverwrites() throws {
        let item = root.appendingPathComponent("item"), target = root.appendingPathComponent("occupied")
        try Data("source".utf8).write(to: item); try Data("retain".utf8).write(to: target)
        let snapshot = try SafeFilesystem.snapshot(item.path)
        XCTAssertThrowsError(try SafeFilesystem.move(snapshot, into: SafeDirectory(path: root.path), name: "occupied"))
        XCTAssertEqual(try String(contentsOf: target, encoding: .utf8), "retain")
        XCTAssertTrue(FileManager.default.fileExists(atPath: item.path))
    }
    func testHardLinkedFileIsRejected() throws {
        let item = root.appendingPathComponent("item")
        try Data("shared".utf8).write(to: item)
        try FileManager.default.linkItem(at: item, to: root.appendingPathComponent("shared"))
        XCTAssertThrowsError(try SafeFilesystem.snapshot(item.path))
    }
    func testPackageInternalLinkIsNotFollowed() throws {
        let app = root.appendingPathComponent("Example.app")
        try FileManager.default.createDirectory(at: app, withIntermediateDirectories: false)
        let outside = root.appendingPathComponent("outside")
        try Data("retain".utf8).write(to: outside)
        try FileManager.default.createSymbolicLink(atPath: app.appendingPathComponent("link").path, withDestinationPath: outside.path)
        let snapshot = try SafeFilesystem.snapshot(app.path, allowInternalLinks: true)
        try SafeFilesystem.move(snapshot, into: SafeDirectory(path: root.path), name: "isolated")
        XCTAssertEqual(try String(contentsOf: outside, encoding: .utf8), "retain")
    }
}
