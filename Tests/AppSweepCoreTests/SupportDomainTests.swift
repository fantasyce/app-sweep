#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

final class SupportDomainTests: XCTestCase, @unchecked Sendable {
    private let rule = "support-exact-domain-v1"
    private let identifier = "org.example.sweepfixture"
    private func fixture() throws -> NativeAcceptanceTests.NativeFixture {
        try .init(additionalRules: [ChosenApplicationRule.name, rule])
    }
    func testExplicitDataChoiceIncludesWholeDomainAndRestoresEveryFile() async throws {
        let f = try fixture(); defer { try? f.clean() }; try f.generate()
        let root = f.home + "/Library/Application Support/" + identifier
        let neighbour = f.home + "/Library/Application Support/org.example"
        try FileManager.default.createDirectory(atPath: root + "/plugins", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: neighbour, withIntermediateDirectories: true)
        let bytes = Data((0..<10000).map { UInt8($0 % 256) })
        try bytes.write(to: URL(fileURLWithPath: root + "/personal.db"))
        try Data("own plugin".utf8).write(to: URL(fileURLWithPath: root + "/plugins/custom.plugin"))
        try Data("shared vendor data".utf8).write(to: URL(fileURLWithPath: neighbour + "/keep"))
        let before = try SafeFilesystem.snapshot(root)
        let report = try await f.engine.scanApplication(f.app)
        let support = try XCTUnwrap(report.selectableCandidates(includeUserData: true).first { $0.path == root })
        XCTAssertEqual(support.rule, rule)
        XCTAssertTrue(support.userData)
        XCTAssertFalse(support.selectedByDefault)
        XCTAssertFalse(report.selectableCandidates(includeUserData: false).contains { $0.path == root })
        do { _ = try await f.engine.makePlan(reportID: report.id, selected: [support.id], includeUserData: false); XCTFail("Data choice is mandatory") } catch { }
        let selected = Set(report.selectableCandidates(includeUserData: true).map(\.id))
        let plan = try await f.engine.makePlan(reportID: report.id, selected: selected, includeUserData: true)
        XCTAssertTrue(plan.items.contains { $0.id == support.id })
        let moved = try await f.engine.execute(planID: plan.id)
        XCTAssertEqual(moved.status, .isolated, moved.issue ?? "")
        XCTAssertFalse(FileManager.default.fileExists(atPath: root))
        XCTAssertEqual(try String(contentsOfFile: neighbour + "/keep", encoding: .utf8), "shared vendor data")
        let restored = try await f.restoreWhenUnused(moved)
        XCTAssertEqual(restored.status, .restored, restored.entries.compactMap(\.message).joined(separator: "; "))
        let after = try SafeFilesystem.snapshot(root)
        XCTAssertTrue(after.identity.sameObject(as: before.identity))
        XCTAssertEqual(after.tree, before.tree)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: root + "/personal.db")), bytes)
    }
    func testUnsignedOrSharedApplicationCannotClaimTheDomain() async throws {
        for mode in ["unsigned", "duplicate"] {
            let f = try fixture(); defer { try? f.clean() }
            let root = f.home + "/Library/Application Support/" + identifier
            try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
            try Data("user data".utf8).write(to: URL(fileURLWithPath: root + "/keep"))
            if mode == "unsigned" {
                _ = try BoundedProcess.run("/usr/bin/codesign", arguments: ["--remove-signature", f.app], timeout: 10)
            } else {
                try FileManager.default.copyItem(atPath: f.app, toPath: f.home + "/Applications/Second.app")
            }
            let report = try await f.engine.scanApplication(f.app)
            let item = try XCTUnwrap(report.candidates.first { $0.path == root })
            XCTAssertFalse(item.allowed, mode)
            XCTAssertEqual(try String(contentsOfFile: root + "/keep", encoding: .utf8), "user data")
        }
    }
    func testLinksAndHardLinkedContentDoNotAuthorizeOutsideFiles() async throws {
        for mode in ["root-link", "child-link", "hard-link"] {
            let f = try fixture(); defer { try? f.clean() }
            let root = f.home + "/Library/Application Support/" + identifier
            let outside = f.home + "/outside.txt"
            try Data("preserve".utf8).write(to: URL(fileURLWithPath: outside))
            if mode == "root-link" {
                try FileManager.default.createSymbolicLink(atPath: root, withDestinationPath: outside)
            } else {
                try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
                if mode == "child-link" { try FileManager.default.createSymbolicLink(atPath: root + "/alien", withDestinationPath: outside) }
                else { try FileManager.default.linkItem(atPath: outside, toPath: root + "/alien") }
            }
            let report = try await f.engine.scanApplication(f.app)
            let item = try XCTUnwrap(report.candidates.first { $0.path == root })
            XCTAssertFalse(item.allowed, mode)
            do { _ = try await f.engine.makePlan(reportID: report.id, selected: [item.id], includeUserData: true); XCTFail("Unconfirmed namespace entered a plan") } catch { }
            XCTAssertEqual(try String(contentsOfFile: outside, encoding: .utf8), "preserve")
        }
    }
    func testKeychainInsideSupportDomainIsRetained() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let root = f.home + "/Library/Application Support/" + identifier
        try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
        try Data("preserve keychain".utf8).write(to: URL(fileURLWithPath: root + "/Credentials.keychain-db"))
        let report = try await f.engine.scanApplication(f.app)
        let item = try XCTUnwrap(report.candidates.first { $0.path == root })
        XCTAssertFalse(item.allowed)
        XCTAssertEqual(try String(contentsOfFile: root + "/Credentials.keychain-db", encoding: .utf8), "preserve keychain")
    }
    func testRuleCannotBeReusedForAVendorDirectory() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let vendor = f.home + "/Library/Application Support/org.example"
        try FileManager.default.createDirectory(atPath: vendor, withIntermediateDirectories: true)
        try Data("shared".utf8).write(to: URL(fileURLWithPath: vendor + "/keep"))
        let snapshot = try SafeFilesystem.snapshot(vendor)
        var item = Candidate(id: UUID(), path: vendor, category: .userData, bundleIdentifier: identifier,
                             evidence: [.init(kind: .validatedRule, detail: "forged namespace", verified: true)],
                             rule: rule, identity: snapshot.identity, bytes: snapshot.bytes, retentionReason: nil)
        item.applicationPath = f.app
        let report = await f.engine.adoptFixture([item], snapshots: [item.id: snapshot], applicationPath: nil)
        do { _ = try await f.engine.makePlan(reportID: report.id, selected: [item.id], includeUserData: true); XCTFail("The rule must not authorize a shared vendor directory") } catch { }
        XCTAssertEqual(try String(contentsOfFile: vendor + "/keep", encoding: .utf8), "shared")
    }
}
#endif
