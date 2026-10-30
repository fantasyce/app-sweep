#if os(macOS)
import Foundation
import Darwin
import XCTest
@testable import AppSweepCore

final class AuthenticatedUserContextTests: XCTestCase {
    func testKernelUIDResolvesAccountHomeAndPreservesItsIdentity() throws {
        guard getuid() >= 500 else { throw XCTSkip("Isolated ordinary local account required") }
        let peer = AuthenticatedLocalPeer(uid: getuid(), pid: getpid(), auditToken: Data(repeating: 1, count: 32))
        let context = try AuthenticatedUserContext.resolve(peer)
        XCTAssertEqual(context.uid, getuid())
        XCTAssertEqual(context.home, try SystemIdentity.home())
        XCTAssertEqual(context.allowedSystemOwners, [0, getuid()])
        XCTAssertFalse(context.allowedSystemOwners.contains(getuid() + 1))
        XCTAssertEqual(context.homeAncestors.last?.owner, getuid())
        try context.verifyUnchanged()
    }
    func testResolvedOwnAccountContextCanQueryItsBoundedApplicationIndex() throws {
        guard getuid() >= 500 else { throw XCTSkip("Isolated ordinary local account required") }
        let context = try AuthenticatedUserContext.resolve(.init(uid:getuid(),pid:getpid(),auditToken:Data(repeating:1,count:32)))
        let paths = try ApplicationIndex.systemPaths(for:context)
        XCTAssertTrue(paths.allSatisfy { SafetyPolicy.contains(context.home,$0) && $0.hasSuffix(".app") })
        try context.verifyUnchanged()
    }
    func testRootSystemMissingAccountsAndInvalidPeerCannotCreateUserContext() throws {
        for uid in [UInt32(0), 1, 99, UInt32.max] {
            XCTAssertThrowsError(try AuthenticatedUserContext.resolve(.init(uid: uid, pid: 123, auditToken: Data(repeating: 1, count: 32))))
        }
        XCTAssertThrowsError(try AuthenticatedUserContext.resolve(.init(uid: getuid(), pid: 0, auditToken: Data(repeating: 1, count: 32))))
        XCTAssertThrowsError(try AuthenticatedUserContext.resolve(.init(uid: getuid(), pid: getpid(), auditToken: Data())))
    }
    func testAliasesSharedAndSystemHomesCannotBecomeUserContext() {
        for home in ["/", "/var/root", "/Users", "/Users/Shared", "/Users/shared", "/Users/../other", "/Users/a/", "/Users//a", "/Users/.", "/Users/..", "/Volumes/Disk/Users/a", "/Users/a\0b"] {
            XCTAssertFalse(AuthenticatedUserContext.validLocalHome(home), home)
        }
        XCTAssertTrue(AuthenticatedUserContext.validLocalHome("/Users/localtest"))
        XCTAssertTrue(AuthenticatedUserContext.validLocalHome("/Users/测试"))
    }
}
#endif
