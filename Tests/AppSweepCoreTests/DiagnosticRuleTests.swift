import XCTest
@testable import AppSweepCore

final class DiagnosticRuleTests: XCTestCase {
    private let app = "/Applications/Example.app"
    private let identifier = "org.example.app"
    private func report(headerID: String = "org.example.app", bodyID: String = "org.example.app", path: String = "/Applications/Example.app/Contents/MacOS/example", type: String = "309") throws -> Data {
        let header = try JSONSerialization.data(withJSONObject: ["bundleID":headerID,"bug_type":type])
        let body = try JSONSerialization.data(withJSONObject: ["bundleInfo":["CFBundleIdentifier":bodyID],"procPath":path])
        return header + Data([10]) + body
    }
    func testStructuredApplicationCrashHasMatchingOwnership() throws {
        XCTAssertTrue(DiagnosticRule.owns(try report(), identifier: identifier, applicationPath: app))
    }
    func testNameOrHeaderAloneCannotAuthorizeLog() throws {
        XCTAssertFalse(DiagnosticRule.owns(Data("{\"bundleID\":\"org.example.app\"}".utf8), identifier: identifier, applicationPath: app))
        XCTAssertFalse(DiagnosticRule.owns(try report(bodyID: "org.example.other"), identifier: identifier, applicationPath: app))
        XCTAssertFalse(DiagnosticRule.owns(try report(path: "/Applications/Example.app.sibling/Contents/MacOS/example"), identifier: identifier, applicationPath: app))
        XCTAssertFalse(DiagnosticRule.owns(try report(type: "other"), identifier: identifier, applicationPath: app))
    }
    func testAliasedAndAppleReportsAreRetained() throws {
        XCTAssertFalse(DiagnosticRule.owns(try report(path: app + "/Contents/../private/file"), identifier: identifier, applicationPath: app))
        XCTAssertFalse(DiagnosticRule.owns(try report(headerID: "com.apple.finder", bodyID: "com.apple.finder"), identifier: "com.apple.finder", applicationPath: app))
    }
}
