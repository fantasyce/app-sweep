#if os(macOS)
import Foundation
import Darwin
import XCTest
@testable import AppSweepCore

final class ServiceInstallerEntryTests: XCTestCase {
    private func executable() throws -> String {
        let path = Bundle(for:Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("AppSweepServiceInstaller").path
        return try XCTUnwrap(FileManager.default.isExecutableFile(atPath:path) ? path : nil,"The isolated build must produce a concrete installer executable")
    }
    func testUnknownOrIncompleteInstallerArgumentsFailBeforeAuthentication() throws {
        let path = try executable()
        for arguments in [[],["install"],["recover","/System"],["remove","--yes"],["install","/System","--force"]] {
            let result = try BoundedProcess.capture(path,arguments:arguments,timeout:5,mergeStderr:true)
            XCTAssertEqual(result.status,64)
        }
    }
    func testNormalUserCannotRemoveOrRestoreAServiceRemoval() throws {
        XCTAssertNotEqual(getuid(),0)
        let path = try executable()
        for arguments in [["remove"],["restore-removal","642AC98E-58B2-40FE-9270-9CB7E1096046"]] {
            let result = try BoundedProcess.capture(path,arguments:arguments,timeout:5,mergeStderr:true)
            XCTAssertEqual(result.status,77)
        }
        for arguments in [["remove","/Library"],["restore-removal"],["restore-removal","/System"],["restore-removal","642ac98e-58b2-40fe-9270-9cb7e1096046"]] {
            let result = try BoundedProcess.capture(path,arguments:arguments,timeout:5,mergeStderr:true)
            XCTAssertEqual(result.status,64)
        }
    }
    func testNormalUserCannotInstallOrRecoverSystemComponents() throws {
        XCTAssertNotEqual(getuid(),0)
        let path = try executable()
        for arguments in [["install","/System"],["recover"]] {
            let result = try BoundedProcess.capture(path,arguments:arguments,timeout:5,mergeStderr:true)
            XCTAssertEqual(result.status,77)
            XCTAssertFalse(result.text.isEmpty)
        }
    }
}
#endif
