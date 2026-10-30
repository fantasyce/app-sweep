#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

final class ChromiumBrandingTests: XCTestCase, @unchecked Sendable {
    private func write(_ info: [String:Any], app: String, sign: Bool) throws {
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:app + "/Contents/Info.plist"))
        if sign { _ = try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-",app],timeout:10) }
    }
    func testExplicitRuntimeNamespaceComesFromTheSecuredSignedDictionary() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        var info = try AppInspector.metadata(f.app,component:false).0
        info["CrProductDirName"] = "Independent/Runtime"
        try write(info,app:f.app,sign:true)
        XCTAssertEqual(try ChromiumCacheRule.runtimeNamespace(path:f.app,identifier:"org.example.sweepfixture"),"Independent/Runtime")
        info["CrProductDirName"] = "Foreign/Runtime"
        try write(info,app:f.app,sign:false)
        XCTAssertThrowsError(try ChromiumCacheRule.runtimeNamespace(path:f.app,identifier:"org.example.sweepfixture"),"An unsealed metadata change must not introduce authority over another namespace")
    }
    func testSelfDeclaredGoogleBrandingCannotAuthorizeTheImplicitDefault() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        var info = try AppInspector.metadata(f.app,component:false).0
        info["CFBundleIdentifier"] = "com.google.Chrome"
        info["KSProductID"] = "com.google.Chrome"
        try write(info,app:f.app,sign:true)
        XCTAssertTrue(AppInspector.signatureMatches(path:f.app,identifier:"com.google.Chrome"),"Fixture must be a valid sealed app, not merely an unsigned negative")
        XCTAssertThrowsError(try ChromiumCacheRule.runtimeNamespace(path:f.app,identifier:"com.google.Chrome"),"Bundle ID and branding fields alone cannot take ownership of Google's implicit cache namespace")
    }
    func testOfficialOriginalChromeResolvesItsImplicitBrandingDefault() throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_GOOGLE_BRANDING_ACCEPTANCE"] == "1",
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).hasPrefix("VirtualMac"),
              try SystemIdentity.home() == "/Users/localtest" else { throw XCTSkip("Explicit original official image inspection in disposable VM only") }
        let path = "/Users/localtest/AppSweepAcceptanceGeneral-20261016/chrome-default.noindex/read-only-mount/Google Chrome.app"
        let info = try AppInspector.metadata(path,component:false).0
        XCTAssertNil(info["CrProductDirName"],"This native positive must exercise the actual missing-field format")
        XCTAssertEqual(try ChromiumCacheRule.runtimeNamespace(path:path,identifier:"com.google.Chrome"),"Google/Chrome")
    }
}
#endif
