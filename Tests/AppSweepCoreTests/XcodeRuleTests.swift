import XCTest
@testable import AppSweepCore

final class XcodeRuleTests: XCTestCase {
    func testOnlyExactIntermediateDirectoryIsEligible() {
        let home = "/Users/fixture"
        let root = home + "/Library/Developer/Xcode/DerivedData"
        XCTAssertEqual(XcodeRule.derivedDirectory(root + "/Example-hash/Build/Intermediates.noindex", home: home), root + "/Example-hash")
        for path in [root, root + "/Example-hash/Build/Products", root + "/../Archives/Build/Intermediates.noindex", root + "/Example-hash/Build/Intermediates.noindex/child", root + "/Example-hash/SourcePackages/Intermediates.noindex", root + "//Example/Build/Intermediates.noindex"] {
            XCTAssertNil(XcodeRule.derivedDirectory(path, home: home), path)
        }
    }
    func testUnknownOrAliasedWorkspaceCannotAuthorize() throws {
        for path in ["/Users/fixture/Project", "/Users/fixture/../Other.xcodeproj", "relative.xcodeproj", "/Users/fixture/Project.xcodeproj/"] {
            let info = try PropertyListSerialization.data(fromPropertyList: ["WorkspacePath":path], format: .xml, options: 0)
            XCTAssertNil(XcodeRule.workspace(info))
        }
        let info = try PropertyListSerialization.data(fromPropertyList: ["WorkspacePath":"/Users/fixture/Example.xcodeproj"], format: .xml, options: 0)
        XCTAssertEqual(XcodeRule.workspace(info), "/Users/fixture/Example.xcodeproj")
    }
}
