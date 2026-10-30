import Foundation
import XCTest
@testable import AppSweepCore

final class FirefoxFormatRuleTests: XCTestCase {
    func testCompatibilityUsesSignedApplicationBuildInsteadOfProductWhitelist() {
        let path = "/fixture-home/Applications/Firefox.app"
        for version in ["157.0", "158.0", "200.0.7"] {
            let app = Data("[App]\nVersion=\(version)\nBuildID=20261007201254\n".utf8)
            let platform = Data("[Build]\nBuildID=20261007201255\n".utf8)
            for (architecture, abi) in [("arm64", "Darwin_aarch64-gcc3"), ("x86_64", "Darwin_x86_64-gcc3")] {
                let profile = Data("[Compatibility]\nLastVersion=\(version)_20261007201254/20261007201255\nLastOSABI=\(abi)\nLastPlatformDir=\(path)/Contents/Resources\nLastAppDir=\(path)/Contents/Resources/browser\n".utf8)
                XCTAssertTrue(FirefoxFormatRule.compatible(profile, application: app, platform: platform, applicationPath: path, architecture: architecture))
                XCTAssertFalse(FirefoxFormatRule.compatible(profile, application: app, platform: platform, applicationPath: path + "-other", architecture: architecture))
                XCTAssertFalse(FirefoxFormatRule.compatible(profile, application: app, platform: Data("[Build]\nBuildID=20261007201256\n".utf8), applicationPath: path, architecture: architecture))
                XCTAssertFalse(FirefoxFormatRule.compatible(profile, application: app, platform: platform, applicationPath: path, architecture: "unknown"))
            }
        }
    }
    func testMissingDuplicateAndMalformedBuildEvidenceIsRetained() {
        let path="/fixture/Firefox.app"
        let profile=Data("[Compatibility]\nLastVersion=158.0_20261007201254/20261007201254\nLastOSABI=Darwin_aarch64-gcc3\nLastPlatformDir=\(path)/Contents/Resources\nLastAppDir=\(path)/Contents/Resources/browser\n".utf8)
        let platform=Data("[Build]\nBuildID=20261007201254\n".utf8)
        for app in ["", "[App]\nVersion=158.0\nBuildID=bad\n", "[App]\nVersion=158.0\nVersion=157.0\nBuildID=20261007201254\n"] {
            XCTAssertFalse(FirefoxFormatRule.compatible(profile, application:Data(app.utf8), platform:platform, applicationPath:path, architecture:"arm64"))
        }
    }
}
