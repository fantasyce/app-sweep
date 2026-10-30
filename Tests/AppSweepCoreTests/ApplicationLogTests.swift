#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

final class ApplicationLogTests: XCTestCase, @unchecked Sendable {
    private let rule = "third-party-namespace-log-30d-v1"
    private let identifier = "org.example.logs." + UUID().uuidString.lowercased()
    private let currentRule = "third-party-user-log-v2"
    private func fixture(rules: Set<String>? = nil) throws -> NativeAcceptanceTests.NativeFixture {
        let f=try NativeAcceptanceTests.NativeFixture(additionalRules:rules ?? [rule])
        let path=f.app + "/Contents/Info.plist"
        var info=try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:path)),format:nil) as? [String:Any])
        info["CFBundleIdentifier"]=identifier
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:path))
        _=try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-",f.app],timeout:10)
        return f
    }
    func testRecentLogOrForgedNamespaceCannotAuthorize() throws {
        let f = try fixture(); defer { try? f.clean() }
        let recent = try log(f.home + "/Library/Logs/" + identifier, name: "recent.log", old: false)
        XCTAssertThrowsError(try ApplicationLogRule.verify(path: recent, home: f.home, identifier: identifier))
        XCTAssertFalse(ApplicationLogRule.matches(path: recent, home: f.home, identifier: "org.example"))
        XCTAssertFalse(ApplicationLogRule.matches(path: f.home + "/Library/Logs/" + identifier + "/../private.log", home: f.home, identifier: identifier))
        XCTAssertTrue(ApplicationLogRule.matches(path: f.home + "/Library/Logs/" + identifier + "/session-main.123.moz_log", home: f.home, identifier: identifier))
    }
    private func log(_ root: String, name: String, old: Bool = true) throws -> String {
        let path = root + "/" + name
        try FileManager.default.createDirectory(atPath: URL(fileURLWithPath: path).deletingLastPathComponent().path, withIntermediateDirectories: true)
        try Data("independently generated log\n".utf8).write(to: URL(fileURLWithPath: path))
        if old { try FileManager.default.setAttributes([.modificationDate: Date().addingTimeInterval(-31 * 86400)], ofItemAtPath: path) }
        return path
    }
    func testOnlyOwnedOldLogsMoveAndRestoreWithoutTouchingRecentOrUnknownFiles() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let root = f.home + "/Library/Logs/" + identifier
        let old = try log(root, name: "session/old.log")
        let rotated = try log(root, name: "old.log.2.gz")
        let recent = try log(root, name: "recent.log", old: false)
        let unknown = try log(root, name: "personal.pdf")
        let neighbour = try log(f.home + "/Library/Logs/org.example", name: "shared.log")
        let bytes = try Data(contentsOf: URL(fileURLWithPath: old)), identity = try SafeFilesystem.snapshot(old).identity
        let report = try await f.engine.scanJunk()
        let items = report.selectableCandidates(includeUserData: false).filter { $0.rule == rule }
        XCTAssertEqual(Set(items.map(\.path)), [old, rotated])
        guard items.count == 2 else { return }
        let plan = try await f.engine.makePlan(reportID: report.id, selected: Set(items.map(\.id)), includeUserData: false)
        let moved = try await f.engine.execute(planID: plan.id)
        XCTAssertEqual(moved.status, .isolated, moved.issue ?? "")
        for path in [recent, unknown, neighbour] { XCTAssertTrue(FileManager.default.fileExists(atPath: path)) }
        let restored = try await f.restoreWhenUnused(moved)
        XCTAssertEqual(restored.status, .restored, restored.entries.compactMap(\.message).joined(separator: "; "))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: old)), bytes)
        XCTAssertTrue(try SafeFilesystem.snapshot(old).identity.sameObject(as: identity))
    }
    func testSharedOrUnsignedApplicationsCannotAuthorizeLogs() async throws {
        for mode in ["unsigned", "duplicate"] {
            let f = try fixture(); defer { try? f.clean() }
            let path = try log(f.home + "/Library/Logs/" + identifier, name: "old.log")
            if mode == "unsigned" { _ = try BoundedProcess.run("/usr/bin/codesign", arguments: ["--remove-signature", f.app], timeout: 10) }
            else { try FileManager.default.copyItem(atPath: f.app, toPath: f.home + "/Applications/Second.app") }
            let report = try await f.engine.scanJunk()
            XCTAssertFalse(report.selectableCandidates(includeUserData: false).contains { $0.path == path })
            XCTAssertTrue(FileManager.default.fileExists(atPath: path))
        }
    }
    func testLogLinksCannotAuthorizeOutsideData() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let root = f.home + "/Library/Logs/" + identifier
        let outside = try log(f.home, name: "outside.log")
        try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: root + "/alias.log", withDestinationPath: outside)
        try FileManager.default.linkItem(atPath: outside, toPath: root + "/hard.log")
        let report = try await f.engine.scanJunk()
        XCTAssertFalse(report.selectableCandidates(includeUserData: false).contains { $0.rule == rule })
        XCTAssertEqual(try String(contentsOfFile: outside, encoding: .utf8), "independently generated log\n")
    }
    func testCurrentRuleOffersRecentLogsManuallyAndPreservesTheOldRecommendation() async throws {
        let f=try fixture(rules:[currentRule]);defer { try? f.clean() }
        let root=f.home + "/Library/Logs/" + identifier
        let old=try log(root,name:"old.log"),recent=try log(root,name:"recent.log",old:false)
        let report=try await f.engine.scanJunk()
        let items=report.selectableCandidates(includeUserData:false).filter { $0.rule == currentRule }
        XCTAssertEqual(Set(items.map(\.path)),[old,recent])
        let oldItem=try XCTUnwrap(items.first { $0.path == old }),recentItem=try XCTUnwrap(items.first { $0.path == recent })
        XCTAssertTrue(oldItem.selectedByDefault);XCTAssertFalse(recentItem.selectedByDefault)
        XCTAssertEqual(recentItem.recommendation,.manual)
        let before=try SafeFilesystem.snapshot(recent)
        let plan=try await f.engine.makePlan(reportID:report.id,selected:[recentItem.id],includeUserData:false)
        let moved=try await f.engine.execute(planID:plan.id)
        XCTAssertEqual(moved.status,.isolated,moved.issue ?? "")
        XCTAssertTrue(FileManager.default.fileExists(atPath:old))
        let restored=try await f.restoreWhenUnused(moved)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        XCTAssertTrue(try SafeFilesystem.snapshot(recent).identity.sameObject(as:before.identity))
        XCTAssertEqual(try String(contentsOfFile:recent,encoding:.utf8),"independently generated log\n")
    }
    func testExactLooseLogAndRotationsDoNotCaptureAnotherApplicationPrefix() async throws {
        let f=try fixture(rules:[currentRule]);defer { try? f.clean() }
        let root=f.home + "/Library/Logs"
        let exact=try log(root,name:identifier + ".log",old:false),rotation=try log(root,name:identifier + ".log.2.gz")
        let neighbour=try log(root,name:identifier + ".helper.log"),unknown=try log(root,name:"shared.log")
        let report=try await f.engine.scanJunk(),items=report.selectableCandidates(includeUserData:false).filter { $0.rule == currentRule }
        XCTAssertEqual(Set(items.map(\.path)),[exact,rotation])
        guard items.count == 2 else { return }
        let plan=try await f.engine.makePlan(reportID:report.id,selected:Set(items.map(\.id)),includeUserData:false)
        let moved=try await f.engine.execute(planID:plan.id)
        XCTAssertEqual(moved.status,.isolated,moved.issue ?? "")
        for path in [neighbour,unknown] { XCTAssertEqual(try String(contentsOfFile:path,encoding:.utf8),"independently generated log\n") }
        let restored=try await f.restoreWhenUnused(moved)
        XCTAssertEqual(restored.status,.restored)
    }
    func testCurrentRuleRetainsAnOpenLogAndADatabaseDisguisedAsALog() async throws {
        let f=try fixture(rules:[currentRule]);defer { try? f.clean() }
        let root=f.home + "/Library/Logs/" + identifier,opened=try log(root,name:"open.log",old:false)
        let database=try log(root,name:"state.log",old:false)
        try (Data("SQLite format 3\0".utf8)+Data(repeating:0,count:64)).write(to:URL(fileURLWithPath:database))
        let handle=try FileHandle(forReadingFrom:URL(fileURLWithPath:opened));defer { try? handle.close() }
        let report=try await f.engine.scanJunk()
        XCTAssertFalse(report.selectableCandidates(includeUserData:false).contains { $0.path == opened || $0.path == database })
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:database)).prefix(16),Data("SQLite format 3\0".utf8))
    }
}
#endif
