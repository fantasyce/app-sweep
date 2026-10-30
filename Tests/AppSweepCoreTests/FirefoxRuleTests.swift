import XCTest
@testable import AppSweepCore

final class FirefoxRuleTests: XCTestCase {
    func testContainedFamilyComponentsAreNotExternalOwners() {
        let app="/Applications/Firefox.app"
        let main=ApplicationIdentity(path:app,name:"Firefox",bundleIdentifier:"org.mozilla.firefox",signed:true,protectedReason:nil)
        let helper=ApplicationIdentity(path:app + "/Contents/Helpers/Plugin.app",name:"Plugin",bundleIdentifier:"org.mozilla.plugincontainer",signed:true,protectedReason:"component")
        let peer=ApplicationIdentity(path:"/Applications/Other.app/Contents/Helpers/Mozilla.app",name:"Other",bundleIdentifier:"org.mozilla.other",signed:true,protectedReason:"component")
        XCTAssertTrue(FirefoxRule.externalFamilyOwners(applicationPath:app,inventory:[main,helper]).isEmpty)
        XCTAssertEqual(FirefoxRule.externalFamilyOwners(applicationPath:app,inventory:[main,helper,peer]).map(\.path),[peer.path])
    }
    func testOnlyExactRegisteredCacheAndValidatedFirefoxBuildCanAuthorize() {
        let home = "/fixture-home/user"
        let app = home + "/Applications/Firefox.app"
        let cache = home + "/Library/Caches/Firefox/Profiles/abcdefgh.default-release/cache2"
        let compatibility = Data("[Compatibility]\nLastVersion=158.0_20261007201254/20261007201254\nLastOSABI=Darwin_aarch64-gcc3\nLastPlatformDir=\(app)/Contents/Resources\nLastAppDir=\(app)/Contents/Resources/browser\n".utf8)
        XCTAssertEqual(FirefoxRule.cacheLeaf(cache, home: home), "abcdefgh.default-release")
        XCTAssertTrue(FirefoxRule.compatible(compatibility, applicationPath: app, architecture: "arm64"))
        XCTAssertFalse(FirefoxRule.compatible(compatibility, applicationPath: home + "/Applications/Other.app", architecture: "arm64"))
        XCTAssertFalse(FirefoxRule.compatible(compatibility, applicationPath: app, architecture: "x86_64"))
        for suffix in ["/../cache2", "/cache2/entries", "/startupCache", "/cache2/", "/cache2//"] {
            XCTAssertNil(FirefoxRule.cacheLeaf(home + "/Library/Caches/Firefox/Profiles/abcdefgh.default-release" + suffix, home: home))
        }
        for version in ["159.0", "158.0_20261007201255/20261007201255"] {
            let changed = Data(String(decoding: compatibility, as: UTF8.self).replacingOccurrences(of: "158.0_20261007201254/20261007201254", with: version).utf8)
            XCTAssertFalse(FirefoxRule.compatible(changed, applicationPath: app, architecture: "arm64"))
        }
    }
    func testCacheLayoutRejectsUnknownFilesAndPersistentProfileContent() {
        XCTAssertTrue(FirefoxRule.cacheLayout([("entries", true), ("entries/" + String(repeating: "A", count: 40), false), ("doomed", true)]))
        for contents in [[("places.sqlite", false)], [("entries", true), ("entries/bookmarks", false)], [("entries", true), ("entries/" + String(repeating: "a", count: 40), false)], [("entries", true), ("entries/nested", true)], [("index", true)], [("doomed", true), ("doomed/unknown", false)]] {
            XCTAssertFalse(FirefoxRule.cacheLayout(contents))
        }
    }
    func testDeclaredUpdaterNeverAuthorizesInstalledOrUnknownHelpers() {
        let info: [String: Any] = ["SMPrivilegedExecutables": ["org.mozilla.updater": "signed requirement", "org.mozilla.dmgInstallHelper": "signed requirement"]]
        XCTAssertTrue(FirefoxRule.cacheOnlyHelpersAllowed(info, installed: false, systemExtensions: false))
        XCTAssertFalse(FirefoxRule.cacheOnlyHelpersAllowed(info, installed: true, systemExtensions: false))
        XCTAssertFalse(FirefoxRule.cacheOnlyHelpersAllowed(info, installed: false, systemExtensions: true))
        XCTAssertFalse(FirefoxRule.cacheOnlyHelpersAllowed(["SMPrivilegedExecutables": ["other.helper": "requirement"]], installed: false, systemExtensions: false))
        XCTAssertFalse(FirefoxRule.cacheOnlyHelpersAllowed(["SMPrivilegedExecutables": "unknown"], installed: false, systemExtensions: false))
    }
    func testOnlyExplicitRelativeProfilesMapToCacheLeaves() {
        let ini = "[General]\nVersion=2\n[Profile0]\nName=default-release\nIsRelative=1\nPath=Profiles/abcdefgh.default-release\nDefault=1\n[InstallA123]\nDefault=Profiles/abcdefgh.default-release\nLocked=1\n"
        XCTAssertEqual(FirefoxRule.profileLeaves(Data(ini.utf8)), ["abcdefgh.default-release"])
    }
    func testCustomSharedMalformedAndAliasedProfilesRemainUnconfirmed() {
        for ini in ["[Profile0]\nIsRelative=0\nPath=/some/profile\n", "[Profile0]\nIsRelative=1\nPath=Profiles/../other\n", "[Profile0]\nIsRelative=1\nPath=Profiles/a\nPath=Profiles/b\n", "[Profile0]\nIsRelative=1\nPath=Profiles/a\n[Profile1]\nIsRelative=1\nPath=Profiles/a\n", "[Profile0]\nIsRelative=1\nPath=Profiles/a\n[Profile0]\nPath=Profiles/b\n"] {
            XCTAssertNil(FirefoxRule.profileLeaves(Data(ini.utf8)), ini)
        }
        XCTAssertNil(FirefoxRule.profileLeaves(Data([0xff, 0xfe, 0x01])))
    }
}
