import XCTest
@testable import AppSweepCore

final class UninstallDependenciesTests: XCTestCase {
    func testInstalledSystemComponentDirectsToVendorUninstallerInsteadOfRemovedManagementPage() throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let library = f.home + "/DependencyLibrary", root = library + "/PrivilegedHelperTools"
        try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
        try Data("independent owned helper".utf8).write(to: URL(fileURLWithPath: root + "/" + label))
        XCTAssertThrowsError(try UninstallDependencies.ensureNoInstalledPrivilegedHelpers(info: info, libraryRoot: library)) { error in
            XCTAssertTrue(error.localizedDescription.contains("官方卸载器"))
            XCTAssertFalse(error.localizedDescription.contains("系统清理的"))
        }
    }
    private let label = "org.example.disposable-helper"
    private var info: [String: Any] { ["SMPrivilegedExecutables": [label: "identifier \"" + label + "\""]] }
    func testAbsentDeclarationsAreNotInstalledDependencies() throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        try UninstallDependencies.ensureNoInstalledPrivilegedHelpers(info: info, libraryRoot: f.home + "/DependencyLibrary")
    }
    func testInstalledHelperAndDaemonAndAliasesRemainBlocked() throws {
        for (index, relative) in ["PrivilegedHelperTools/" + label, "LaunchDaemons/" + label + ".plist", "PrivilegedHelperTools/" + label].enumerated() {
            let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
            let library = f.home + "/DependencyLibrary", target = library + "/" + relative
            try FileManager.default.createDirectory(atPath: URL(fileURLWithPath: target).deletingLastPathComponent().path, withIntermediateDirectories: true)
            if index == 2 {
                try FileManager.default.createSymbolicLink(atPath: target, withDestinationPath: f.home + "/absent-outside-target")
            } else { try Data("owned daemon".utf8).write(to: URL(fileURLWithPath: target)) }
            XCTAssertThrowsError(try UninstallDependencies.ensureNoInstalledPrivilegedHelpers(info: info, libraryRoot: library))
        }
    }
    func testUnreadableDependencyLocationIsNotAbsence() throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let library = f.home + "/DependencyLibrary", root = library + "/PrivilegedHelperTools"
        try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: root)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root) }
        XCTAssertThrowsError(try UninstallDependencies.ensureNoInstalledPrivilegedHelpers(info: info, libraryRoot: library))
    }
    func testSingleComponentApplicationIDDoesNotRelaxPrivilegedHelperLabels() {
        XCTAssertTrue(AppInspector.validIdentifier("newMaonoLinkMacOS"),"Real single-component application IDs remain discoverable")
        XCTAssertThrowsError(try UninstallDependencies.declaredLabels(info:["SMPrivilegedExecutables":["newMaonoLinkMacOS":"requirement"]]),"Privileged helper declarations retain their separate strict label contract")
        XCTAssertEqual(try UninstallDependencies.declaredLabels(info:info),[label])
    }
    func testMalformedDeclarationsCannotCreateFilesystemPaths() {
        for raw: Any in [["../../escape": "requirement"], [label: ""], ["not-an-identifier": "requirement"], [label], "not a dictionary"] {
            XCTAssertThrowsError(try UninstallDependencies.ensureNoInstalledPrivilegedHelpers(info: ["SMPrivilegedExecutables": raw]))
        }
    }
}
