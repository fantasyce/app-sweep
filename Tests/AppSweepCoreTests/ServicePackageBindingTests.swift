#if os(macOS)
import Foundation
import CryptoKit
import Darwin
import XCTest
@testable import AppSweepCore

final class ServicePackageBindingTests: XCTestCase {
    func testInstallerUsesCapturedPackageBytesWhenOriginalUserFileIsReplaced() throws {
        let fixture = try RecoveryTests.Fixture(); defer { try? fixture.clean() }
        let root = try SafeDirectory(path:fixture.home), source = try root.privateChild("source"), staging = try root.privateChild("staging")
        let reviewed = Data("reviewed package fixture bytes".utf8)
        try source.write(reviewed,name:"candidate.pkg")
        let digest = SHA256.hash(data:reviewed).map { String(format:"%02x",$0) }.joined()
        let result = try PrivilegedServiceDeploymentTests.stageReviewedPackage(path:source.path + "/candidate.pkg",owner:getuid(),digest:digest,destination:staging)
        try source.write(Data("replacement after initial verification".utf8),name:"candidate.pkg")
        XCTAssertEqual(result,staging.path + "/reviewed-service.pkg")
        XCTAssertEqual(try SafeFilesystem.readMetadata(result),reviewed)
        let identity = try SafeFilesystem.snapshot(result).identity
        XCTAssertEqual(identity.owner,getuid()); XCTAssertEqual(identity.mode & 0o7777,0o600)
    }
}
#endif
