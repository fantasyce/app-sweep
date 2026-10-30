#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

final class SelectedApplicationTests: XCTestCase, @unchecked Sendable {
    private let rule = "selected-application-v2"
    private func fixture() throws -> NativeAcceptanceTests.NativeFixture { try .init(additionalRules: [rule]) }
    private func engine(_ f: NativeAcceptanceTests.NativeFixture) -> SweepEngine {
        SweepEngine(policy: SafetyPolicy(home: f.home, acceptedPlatform: true, validatedRules: [rule]), vaultPath: f.home + "/Library/Application Support/App Sweep/Recovery", fixture: false)
    }
    func testChosenPortableApplicationDoesNotAuthorizeNeighbouringFiles() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let folder = f.home + "/Downloads"
        try FileManager.default.createDirectory(atPath: folder, withIntermediateDirectories: true)
        let target = folder + "/Portable.app", neighbour = folder + "/retain.txt"
        try FileManager.default.copyItem(atPath: f.app, toPath: target)
        try Data("retain".utf8).write(to: URL(fileURLWithPath: neighbour))
        let report = try await f.engine.scanApplication(target)
        let body = try XCTUnwrap(report.selectableCandidates(includeUserData: false).first { $0.category == .application })
        let plan = try await f.engine.makePlan(reportID: report.id, selected: [body.id], includeUserData: false)
        let moved = try await f.engine.execute(planID: plan.id)
        XCTAssertEqual(moved.status, .isolated, moved.issue ?? "")
        XCTAssertTrue(FileManager.default.fileExists(atPath: f.app))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: neighbour)), Data("retain".utf8))
        let restored = try await engine(f).restore(batchID: moved.id)
        XCTAssertEqual(restored.status, .restored)
        XCTAssertEqual(try BoundedProcess.capture(target + "/Contents/MacOS/fixture", arguments: ["--generate", f.home], timeout: 10, mergeStderr: true).status, 0)
    }
    func testPortableApplicationCanExplicitlyIncludeItsVerifiedData() async throws {
        let f = try NativeAcceptanceTests.NativeFixture(additionalRules: [rule, SupportDomainRule.name, CacheDomainRule.name]); defer { try? f.clean() }; try f.generate()
        let downloads = f.home + "/Downloads", target = downloads + "/Portable.app"
        try FileManager.default.createDirectory(atPath: downloads, withIntermediateDirectories: true)
        try FileManager.default.moveItem(atPath: f.app, toPath: target)
        let data = f.home + "/Library/Application Support/org.example.sweepfixture"
        try FileManager.default.createDirectory(atPath: data, withIntermediateDirectories: true)
        try Data("personal portable data".utf8).write(to: URL(fileURLWithPath: data + "/keep.txt"))
        let report = try await f.engine.scanApplication(target)
        XCTAssertFalse(report.selectableCandidates(includeUserData: false).contains { $0.path == data })
        let selected = report.selectableCandidates(includeUserData: true)
        XCTAssertTrue(selected.contains { $0.path == data }, report.candidates.compactMap(\.retentionReason).joined(separator: "; "))
        guard selected.contains(where: { $0.path == data }) else { return }
        let plan = try await f.engine.makePlan(reportID: report.id, selected: Set(selected.map(\.id)), includeUserData: true)
        let batch = try await f.engine.execute(planID: plan.id)
        XCTAssertEqual(batch.status, .isolated, batch.issue ?? "")
        XCTAssertFalse(FileManager.default.fileExists(atPath: target))
        XCTAssertFalse(FileManager.default.fileExists(atPath: data))
        let fresh = SweepEngine(policy: SafetyPolicy(home: f.home, acceptedPlatform: true, validatedRules: [rule, SupportDomainRule.name, CacheDomainRule.name, "cfpreferences-exact-domain-v1"]), vaultPath: f.home + "/Library/Application Support/App Sweep/Recovery", fixture: false)
        let restored = try await fresh.restore(batchID: batch.id)
        XCTAssertEqual(restored.status, .restored, restored.entries.compactMap(\.message).joined(separator: "; "))
        XCTAssertEqual(try String(contentsOfFile: data + "/keep.txt", encoding: .utf8), "personal portable data")
        XCTAssertTrue(AppInspector.signatureMatches(path: target, identifier: "org.example.sweepfixture"))
    }
    func testNewDuplicateAfterPortablePlanStopsBeforeAnyMove() async throws {
        let f = try NativeAcceptanceTests.NativeFixture(additionalRules: [rule, SupportDomainRule.name]); defer { try? f.clean() }
        let target = f.home + "/Downloads/Portable.app"
        try FileManager.default.createDirectory(atPath: f.home + "/Downloads", withIntermediateDirectories: true)
        try FileManager.default.moveItem(atPath: f.app, toPath: target)
        let data = f.home + "/Library/Application Support/org.example.sweepfixture"
        try FileManager.default.createDirectory(atPath: data, withIntermediateDirectories: true)
        try Data("preserve shared data".utf8).write(to: URL(fileURLWithPath: data + "/note"))
        let report = try await f.engine.scanApplication(target)
        let items = report.selectableCandidates(includeUserData: true)
        XCTAssertTrue(items.contains { $0.path == data })
        let plan = try await f.engine.makePlan(reportID: report.id, selected: Set(items.map(\.id)), includeUserData: true)
        try FileManager.default.copyItem(atPath: target, toPath: f.app)
        do { _ = try await f.engine.execute(planID: plan.id); XCTFail("New duplicate must prevent the transaction") } catch { }
        XCTAssertTrue(FileManager.default.fileExists(atPath: target))
        XCTAssertTrue(FileManager.default.fileExists(atPath: f.app))
        XCTAssertEqual(try String(contentsOfFile: data + "/note", encoding: .utf8), "preserve shared data")
    }
    func testAppleIdentifierInChosenUserBundleCannotAuthorizeApplePreferences() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let identifier = "com.apple.dt.disposablefixture"
        let infoURL = URL(fileURLWithPath: f.app + "/Contents/Info.plist")
        var info = try XCTUnwrap(try PropertyListSerialization.propertyList(from: Data(contentsOf: infoURL), format: nil) as? [String: Any])
        info["CFBundleIdentifier"] = identifier
        try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: infoURL)
        _ = try BoundedProcess.run("/usr/bin/codesign", arguments: ["--force", "--sign", "-", f.app], timeout: 10)
        let preferences = f.home + "/Library/Preferences/" + identifier + ".plist"
        try FileManager.default.createDirectory(atPath: URL(fileURLWithPath: preferences).deletingLastPathComponent().path, withIntermediateDirectories: true)
        let data = try PropertyListSerialization.data(fromPropertyList: ["retain": true], format: .xml, options: 0)
        try data.write(to: URL(fileURLWithPath: preferences))
        let report = try await f.engine.scanApplication(f.app)
        let body = try XCTUnwrap(report.selectableCandidates(includeUserData: false).first { $0.category == .application })
        XCTAssertFalse(report.selectableCandidates(includeUserData: true).contains { $0.path == preferences })
        let plan = try await f.engine.makePlan(reportID: report.id, selected: [body.id], includeUserData: false)
        let moved = try await f.engine.execute(planID: plan.id)
        XCTAssertEqual(moved.status, .isolated, moved.issue ?? "")
        let restored = try await engine(f).restore(batchID: moved.id)
        XCTAssertEqual(restored.status, .restored)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: preferences)), data)
    }
    func testSelectedPathCannotEscapeThroughLinksOrIntoProtectedState() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let alias = f.home + "/alias"
        try FileManager.default.createSymbolicLink(atPath: alias, withDestinationPath: f.home + "/Applications")
        let keychains = f.home + "/Library/Keychains"
        try FileManager.default.createDirectory(atPath: keychains, withIntermediateDirectories: true)
        try FileManager.default.copyItem(atPath: f.app, toPath: keychains + "/LooksLikeAnApp.app")
        for path in [alias + "/Disposable Fixture.app", keychains + "/LooksLikeAnApp.app", "/System/Applications/Calculator.app", "/Users/another-account/Applications/Foreign.app"] {
            do {
                let report = try await f.engine.scanApplication(path)
                XCTAssertTrue(report.selectableCandidates(includeUserData: true).isEmpty, path)
            } catch { }
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: f.app))
        XCTAssertTrue(FileManager.default.fileExists(atPath: keychains + "/LooksLikeAnApp.app"))
    }
    func testApplicationEmbeddedInsideAnotherPackageCannotBeSelectedAlone() async throws {
        let f = try fixture(); defer { try? f.clean() }
        let outer = f.home + "/Documents/Host.app"
        try FileManager.default.createDirectory(atPath: outer + "/Contents/Helpers", withIntermediateDirectories: true)
        let target = outer + "/Contents/Helpers/Embedded.app"
        try FileManager.default.copyItem(atPath: f.app, toPath: target)
        do {
            let report = try await f.engine.scanApplication(target)
            XCTAssertTrue(report.selectableCandidates(includeUserData: true).isEmpty)
        } catch { }
        XCTAssertTrue(FileManager.default.fileExists(atPath: target))
    }
}
#endif
